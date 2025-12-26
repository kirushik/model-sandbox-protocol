//! Session lifecycle management.
//!
//! This module provides the `SessionManager` type for creating, retrieving,
//! destroying, and cleaning up sessions.
//!
//! # Session Acquisition
//!
//! Before using a session for sandbox execution, it must be acquired using
//! `acquire_session()`. This ensures exclusive access and prevents concurrent
//! use of the same session. When done, call `release_session()` to allow
//! future use.
//!
//! # Mount Preparation
//!
//! Before sandbox execution, call `prepare_session_mounts()` to validate and
//! prepare the session's filesystem structure. This ensures the overlay
//! directories are properly set up.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tracing::{debug, instrument, trace, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::error::SessionError;
use crate::session::storage::ensure_base_dir;
use crate::session::{Session, SessionConfig, SessionId, SessionMetadata, SessionPaths};

/// Directory permissions: owner read/write/execute only (0700).
const DIR_PERMISSIONS: u32 = 0o700;

/// Manages the lifecycle of sandbox sessions.
///
/// The `SessionManager` is responsible for:
/// - Creating new sessions with unique IDs
/// - Loading existing sessions from disk
/// - Acquiring/releasing sessions for exclusive use
/// - Preparing session mounts for sandbox execution
/// - Destroying sessions and cleaning up resources
/// - Detecting and cleaning up expired/orphaned sessions
///
/// # Example
///
/// ```no_run
/// use model_sandbox_protocol::session::{SessionManager, SessionConfig};
///
/// let config = SessionConfig::default();
/// let manager = SessionManager::new(config);
///
/// // Create a new session
/// let session = manager.create_session().unwrap();
///
/// // Acquire for exclusive use
/// let session = manager.acquire_session(session.id).unwrap();
///
/// // Use the session for sandbox execution...
///
/// // Release when done
/// manager.release_session(session.id).unwrap();
///
/// // Later, clean up
/// manager.destroy_session(session.id).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SessionManager {
    config: SessionConfig,
}

/// Result of preparing a session's mounts.
///
/// This struct contains validated paths ready for overlay mounting.
#[derive(Debug, Clone)]
pub struct PreparedSession {
    /// The session that was prepared.
    pub session: Session,
    /// Whether upper and work directories are on the same filesystem.
    pub same_filesystem: bool,
    /// Whether the work directory was emptied during preparation.
    pub work_emptied: bool,
}

impl SessionManager {
    /// Creates a new `SessionManager` with the given configuration.
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Creates a new session with a unique ID.
    ///
    /// This creates the session directory structure and initializes metadata.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if directory creation fails.
    #[instrument(skip(self), fields(base_dir = %self.config.base_dir.display()))]
    pub fn create_session(&self) -> Result<Session, SessionError> {
        // Ensure base directory exists
        ensure_base_dir(&self.config.base_dir)?;

        // Generate unique session ID
        let id = Uuid::new_v4();
        debug!(%id, "Creating new session");

        // Create session paths
        let paths = SessionPaths::new(&self.config.base_dir, id);

        // Create directory structure
        paths.create_directories()?;
        trace!("Created session directories");

        // Create metadata
        let metadata = SessionMetadata::new(id, self.config.ttl);
        metadata.save(&paths.meta_file)?;
        trace!("Saved session metadata");

        // Write PID file (empty for now, will be updated when sandbox runs)
        self.write_pid_file(&paths.pid_file, None)?;

        let session = Session {
            id,
            paths,
            metadata,
        };

        debug!(%id, "Session created successfully");
        Ok(session)
    }

    /// Retrieves an existing session by ID.
    ///
    /// Returns `None` if the session does not exist.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidSession` if the session exists but is corrupted.
    #[instrument(skip(self), fields(%id))]
    pub fn get_session(&self, id: SessionId) -> Result<Option<Session>, SessionError> {
        let paths = SessionPaths::new(&self.config.base_dir, id);

        if !paths.exists() {
            trace!("Session not found");
            return Ok(None);
        }

        // Validate directory structure
        paths.validate()?;

        // Load metadata
        let metadata = SessionMetadata::load(&paths.meta_file)?;

        // Verify ID matches
        if metadata.id != id {
            return Err(SessionError::InvalidSession {
                reason: format!("metadata ID mismatch: expected {}, got {}", id, metadata.id),
            });
        }

        debug!("Session loaded successfully");
        Ok(Some(Session {
            id,
            paths,
            metadata,
        }))
    }

    /// Acquires a session for exclusive use.
    ///
    /// This checks if the session is already in use (by checking if a PID
    /// exists and the process is still alive), and if not, marks it as
    /// active with the current process's PID.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `SessionError::NotFound` if the session does not exist
    /// - `SessionError::InUse` if the session is already being used
    /// - `SessionError::Expired` if the session has expired
    /// - `SessionError::IoError` if metadata cannot be updated
    #[instrument(skip(self), fields(%id))]
    pub fn acquire_session(&self, id: SessionId) -> Result<Session, SessionError> {
        let session = self
            .get_session(id)?
            .ok_or_else(|| SessionError::NotFound { id: id.to_string() })?;

        // Check if session is expired
        if session.metadata.is_expired() {
            return Err(SessionError::Expired { id: id.to_string() });
        }

        // Check if session is already in use
        if let Some(pid) = session.metadata.pid {
            if process_exists(pid) {
                debug!(%id, pid, "Session is already in use");
                return Err(SessionError::InUse { id: id.to_string() });
            }
            // PID exists but process is dead - we can take over
            debug!(%id, pid, "Session had stale PID, taking over");
        }

        // Mark session as active with our PID
        let mut metadata = session.metadata.clone();
        let our_pid = std::process::id();
        metadata.set_active(our_pid);
        metadata.save(&session.paths.meta_file)?;

        // Write PID file
        self.write_pid_file(&session.paths.pid_file, Some(our_pid))?;

        debug!(%id, pid = our_pid, "Session acquired");
        Ok(Session {
            id: session.id,
            paths: session.paths,
            metadata,
        })
    }

    /// Releases a session after use.
    ///
    /// This clears the PID from metadata and the PID file, allowing
    /// the session to be acquired again.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if metadata cannot be updated.
    #[instrument(skip(self), fields(%id))]
    pub fn release_session(&self, id: SessionId) -> Result<(), SessionError> {
        let paths = SessionPaths::new(&self.config.base_dir, id);

        if !paths.exists() {
            debug!("Session does not exist, nothing to release");
            return Ok(());
        }

        // Load and update metadata
        if let Ok(mut metadata) = SessionMetadata::load(&paths.meta_file) {
            metadata.pid = None;
            metadata.last_accessed = chrono::Utc::now();
            // Keep state as Active (session is still valid, just not in use)
            metadata.save(&paths.meta_file)?;
        }

        // Clear PID file
        self.write_pid_file(&paths.pid_file, None)?;

        debug!(%id, "Session released");
        Ok(())
    }

    /// Prepares a session's mounts for sandbox execution.
    ///
    /// This validates and prepares the session's filesystem structure:
    /// - Ensures upper/ and work/ directories exist with correct permissions
    /// - Empties the work/ directory (required by OverlayFS)
    /// - Verifies upper/ and work/ are on the same filesystem
    ///
    /// # Note
    ///
    /// This does NOT actually mount the OverlayFS. The actual mount must
    /// occur inside the sandbox's mount namespace. This function prepares
    /// the prerequisites.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if preparation fails.
    #[instrument(skip(self), fields(%id))]
    pub fn prepare_session_mounts(&self, id: SessionId) -> Result<PreparedSession, SessionError> {
        let session = self
            .get_session(id)?
            .ok_or_else(|| SessionError::NotFound { id: id.to_string() })?;

        debug!("Preparing session mounts");

        // Ensure upper directory exists with correct permissions
        ensure_dir_with_permissions(&session.paths.upper, DIR_PERMISSIONS)?;

        // Ensure work directory exists with correct permissions
        ensure_dir_with_permissions(&session.paths.work, DIR_PERMISSIONS)?;

        // Empty the work directory (required by OverlayFS before mount)
        let work_emptied = empty_directory(&session.paths.work)?;
        if work_emptied {
            trace!("Emptied work directory");
        }

        // Ensure merged directory exists
        ensure_dir_with_permissions(&session.paths.merged, DIR_PERMISSIONS)?;

        // Verify upper and work are on the same filesystem
        let same_filesystem = check_same_filesystem(&session.paths.upper, &session.paths.work)?;
        if !same_filesystem {
            warn!(
                upper = %session.paths.upper.display(),
                work = %session.paths.work.display(),
                "Upper and work directories are on different filesystems - OverlayFS may fail"
            );
        }

        debug!("Session mounts prepared successfully");
        Ok(PreparedSession {
            session,
            same_filesystem,
            work_emptied,
        })
    }

    /// Checks if the session's merged directory is an overlay mount.
    ///
    /// This parses /proc/mounts to verify that the merged directory
    /// is actually an overlay mount point.
    #[must_use]
    pub fn is_overlay_mounted(&self, id: SessionId) -> bool {
        let paths = SessionPaths::new(&self.config.base_dir, id);
        is_overlay_mount(&paths.merged)
    }

    /// Destroys a session and cleans up all its resources.
    ///
    /// This unmounts any active mounts and removes the session directory.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if cleanup fails.
    /// Returns `SessionError::InUse` if the session has active mounts that
    /// cannot be unmounted.
    #[instrument(skip(self), fields(%id))]
    pub fn destroy_session(&self, id: SessionId) -> Result<(), SessionError> {
        let paths = SessionPaths::new(&self.config.base_dir, id);

        if !paths.exists() {
            debug!("Session already destroyed or never existed");
            return Ok(());
        }

        // Check if merged directory has an active mount
        if is_overlay_mount(&paths.merged) {
            debug!("Attempting to unmount overlay before destruction");
            // Try to unmount - if this fails, we'll return an error
            if let Err(e) = unmount_overlay(&paths.merged) {
                warn!(error = %e, "Failed to unmount overlay");
                return Err(SessionError::InUse {
                    id: format!("{} (overlay still mounted: {})", id, e),
                });
            }
        }

        // Update metadata to cleaned state (if possible)
        if let Ok(mut metadata) = SessionMetadata::load(&paths.meta_file) {
            metadata.set_cleaned();
            let _ = metadata.save(&paths.meta_file);
        }

        // Remove the session directory
        paths.cleanup()?;

        debug!("Session destroyed successfully");
        Ok(())
    }

    /// Lists all session IDs in the base directory.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if reading the directory fails.
    #[instrument(skip(self))]
    pub fn list_sessions(&self) -> Result<Vec<SessionId>, SessionError> {
        if !self.config.base_dir.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.config.base_dir).map_err(|e| SessionError::IoError {
            context: format!(
                "failed to read base directory: {}",
                self.config.base_dir.display()
            ),
            source: e,
        })?;

        let mut session_ids = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| SessionError::IoError {
                context: "failed to read directory entry".to_string(),
                source: e,
            })?;

            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Ok(id) = Uuid::parse_str(name) {
                        session_ids.push(id);
                    }
                }
            }
        }

        trace!(count = session_ids.len(), "Found sessions");
        Ok(session_ids)
    }

    /// Cleans up all expired sessions.
    ///
    /// Returns the number of sessions that were cleaned up.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if cleanup fails. Note that partial cleanup
    /// may have occurred even if an error is returned.
    #[instrument(skip(self))]
    pub fn cleanup_expired(&self) -> Result<usize, SessionError> {
        let session_ids = self.list_sessions()?;
        let mut cleaned_count = 0;

        for id in session_ids {
            let paths = SessionPaths::new(&self.config.base_dir, id);

            // Try to load metadata
            match SessionMetadata::load(&paths.meta_file) {
                Ok(metadata) => {
                    if metadata.is_expired() {
                        debug!(%id, "Cleaning up expired session");
                        match self.destroy_session(id) {
                            Ok(()) => cleaned_count += 1,
                            Err(e) => warn!(%id, error = %e, "Failed to clean up expired session"),
                        }
                    }
                }
                Err(e) => {
                    // Corrupted session - clean it up
                    warn!(%id, error = %e, "Session metadata corrupted, cleaning up");
                    match self.destroy_session(id) {
                        Ok(()) => cleaned_count += 1,
                        Err(e) => warn!(%id, error = %e, "Failed to clean up corrupted session"),
                    }
                }
            }
        }

        debug!(cleaned_count, "Expired session cleanup complete");
        Ok(cleaned_count)
    }

    /// Detects and cleans up orphaned sessions.
    ///
    /// A session is considered orphaned if:
    /// - It has a PID file with a PID that no longer exists
    /// - It has been in "Active" state but the process is dead
    ///
    /// Returns the number of orphaned sessions cleaned up.
    #[instrument(skip(self))]
    pub fn cleanup_orphaned(&self) -> Result<usize, SessionError> {
        let session_ids = self.list_sessions()?;
        let mut cleaned_count = 0;

        for id in session_ids {
            let paths = SessionPaths::new(&self.config.base_dir, id);

            if let Ok(metadata) = SessionMetadata::load(&paths.meta_file) {
                // Check if session has a PID that no longer exists
                if let Some(pid) = metadata.pid {
                    if !process_exists(pid) {
                        debug!(%id, pid, "Cleaning up orphaned session (dead PID)");
                        match self.destroy_session(id) {
                            Ok(()) => cleaned_count += 1,
                            Err(e) => warn!(%id, error = %e, "Failed to clean up orphaned session"),
                        }
                    }
                }
            }
        }

        debug!(cleaned_count, "Orphaned session cleanup complete");
        Ok(cleaned_count)
    }

    /// Performs full cleanup: both expired and orphaned sessions.
    ///
    /// Returns the total number of sessions cleaned up.
    #[instrument(skip(self))]
    pub fn cleanup_all(&self) -> Result<usize, SessionError> {
        let expired = self.cleanup_expired()?;
        let orphaned = self.cleanup_orphaned()?;
        Ok(expired + orphaned)
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Writes a PID file for the session.
    fn write_pid_file(&self, path: &Path, pid: Option<u32>) -> Result<(), SessionError> {
        let content = match pid {
            Some(p) => p.to_string(),
            None => String::new(),
        };

        let mut file = fs::File::create(path).map_err(|e| SessionError::IoError {
            context: format!("failed to create PID file: {}", path.display()),
            source: e,
        })?;

        file.write_all(content.as_bytes())
            .map_err(|e| SessionError::IoError {
                context: format!("failed to write PID file: {}", path.display()),
                source: e,
            })?;

        Ok(())
    }

    /// Scans for incomplete/corrupted sessions on startup.
    ///
    /// This is useful for recovering from crashes or system reboots.
    /// Returns the number of corrupted sessions found and cleaned.
    #[instrument(skip(self))]
    pub fn cleanup_corrupted(&self) -> Result<usize, SessionError> {
        if !self.config.base_dir.exists() {
            return Ok(0);
        }

        let mut cleaned_count = 0;

        for entry in WalkDir::new(&self.config.base_dir)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip the base directory itself
            if path == self.config.base_dir {
                continue;
            }

            // Only process directories
            if !path.is_dir() {
                continue;
            }

            // Try to parse as UUID
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(id) = Uuid::parse_str(name) {
                    let paths = SessionPaths::new(&self.config.base_dir, id);

                    // Check for corruption indicators
                    let is_corrupted =
                        // Missing required directories
                        !paths.upper.exists() ||
                        !paths.work.exists() ||
                        !paths.merged.exists() ||
                        // Missing metadata
                        !paths.meta_file.exists() ||
                        // Metadata cannot be loaded
                        SessionMetadata::load(&paths.meta_file).is_err();

                    if is_corrupted {
                        warn!(%id, "Found corrupted session, cleaning up");
                        // Force cleanup even without valid metadata
                        if let Err(e) = fs::remove_dir_all(&paths.root) {
                            warn!(%id, error = %e, "Failed to remove corrupted session directory");
                        } else {
                            cleaned_count += 1;
                        }
                    }
                }
            }
        }

        debug!(cleaned_count, "Corrupted session cleanup complete");
        Ok(cleaned_count)
    }
}

/// Checks if a process with the given PID exists.
fn process_exists(pid: u32) -> bool {
    // Check if /proc/{pid} exists (Linux-specific)
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Ensures a directory exists with the specified permissions.
fn ensure_dir_with_permissions(path: &Path, mode: u32) -> Result<(), SessionError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| SessionError::IoError {
            context: format!("failed to create directory: {}", path.display()),
            source: e,
        })?;
    }

    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions).map_err(|e| SessionError::IoError {
        context: format!("failed to set permissions on: {}", path.display()),
        source: e,
    })?;

    Ok(())
}

/// Empties a directory by removing and recreating it.
///
/// Returns true if the directory had contents that were removed.
fn empty_directory(path: &Path) -> Result<bool, SessionError> {
    if !path.exists() {
        return Ok(false);
    }

    let had_contents = fs::read_dir(path)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);

    if had_contents {
        fs::remove_dir_all(path).map_err(|e| SessionError::IoError {
            context: format!("failed to remove directory: {}", path.display()),
            source: e,
        })?;

        fs::create_dir_all(path).map_err(|e| SessionError::IoError {
            context: format!("failed to recreate directory: {}", path.display()),
            source: e,
        })?;

        let permissions = fs::Permissions::from_mode(DIR_PERMISSIONS);
        fs::set_permissions(path, permissions).map_err(|e| SessionError::IoError {
            context: format!("failed to set permissions: {}", path.display()),
            source: e,
        })?;
    }

    Ok(had_contents)
}

/// Checks if two paths are on the same filesystem.
fn check_same_filesystem(path1: &Path, path2: &Path) -> Result<bool, SessionError> {
    use std::os::unix::fs::MetadataExt;

    let meta1 = fs::metadata(path1).map_err(|e| SessionError::IoError {
        context: format!("failed to get metadata for: {}", path1.display()),
        source: e,
    })?;

    let meta2 = fs::metadata(path2).map_err(|e| SessionError::IoError {
        context: format!("failed to get metadata for: {}", path2.display()),
        source: e,
    })?;

    // Compare device IDs - same device means same filesystem
    Ok(meta1.dev() == meta2.dev())
}

/// Checks if a path is an overlay mount point.
fn is_overlay_mount(path: &Path) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };

    let path_str = path.to_string_lossy();

    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            // Format: device mount_point fs_type options...
            let mount_point = fields[1];
            let fs_type = fields[2];

            if mount_point == path_str && fs_type == "overlay" {
                return true;
            }
        }
    }

    false
}

/// Attempts to unmount an overlay filesystem.
fn unmount_overlay(path: &Path) -> Result<(), std::io::Error> {
    use nix::mount::{MntFlags, umount2};

    umount2(path, MntFlags::empty()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> SessionConfig {
        let base_dir = std::env::temp_dir()
            .join("mcp-test-lifecycle")
            .join(Uuid::new_v4().to_string());
        SessionConfig::default().with_base_dir(base_dir)
    }

    #[test]
    fn test_session_config_defaults() {
        let config = SessionConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(3600));
        assert_eq!(config.tmp_size_mb, 100);
    }

    #[test]
    fn test_session_manager_create() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");

        assert!(session.paths.root.exists());
        assert!(session.paths.upper.exists());
        assert!(session.paths.work.exists());
        assert!(session.paths.merged.exists());
        assert!(session.paths.meta_file.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_get_session() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let retrieved = manager
            .get_session(session.id)
            .expect("failed to get session")
            .expect("session not found");

        assert_eq!(retrieved.id, session.id);

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_get_nonexistent() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let result = manager
            .get_session(Uuid::new_v4())
            .expect("get_session failed");
        assert!(result.is_none());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_destroy() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let session_root = session.paths.root.clone();

        assert!(session_root.exists());

        manager
            .destroy_session(session.id)
            .expect("failed to destroy session");

        assert!(!session_root.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_list() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        // Create multiple sessions
        let s1 = manager
            .create_session()
            .expect("failed to create session 1");
        let s2 = manager
            .create_session()
            .expect("failed to create session 2");
        let s3 = manager
            .create_session()
            .expect("failed to create session 3");

        let sessions = manager.list_sessions().expect("failed to list sessions");

        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains(&s1.id));
        assert!(sessions.contains(&s2.id));
        assert!(sessions.contains(&s3.id));

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_cleanup_expired() {
        let config = test_config();
        // Create manager with very short TTL
        let short_ttl_config = config.clone().with_ttl(Duration::from_millis(1));
        let manager = SessionManager::new(short_ttl_config);

        // Create a session
        let _session = manager.create_session().expect("failed to create session");

        // Wait for it to expire
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup expired
        let cleaned = manager
            .cleanup_expired()
            .expect("failed to cleanup expired");
        assert_eq!(cleaned, 1);

        // Verify no sessions left
        let sessions = manager.list_sessions().expect("failed to list sessions");
        assert!(sessions.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_manager_destroy_idempotent() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let id = session.id;

        // First destroy should succeed
        manager.destroy_session(id).expect("first destroy failed");

        // Second destroy should also succeed (idempotent)
        manager.destroy_session(id).expect("second destroy failed");

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_acquire_release() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let id = session.id;

        // Acquire the session
        let acquired = manager.acquire_session(id).expect("failed to acquire");
        assert!(acquired.metadata.pid.is_some());
        assert_eq!(acquired.metadata.pid, Some(std::process::id()));

        // Release the session
        manager.release_session(id).expect("failed to release");

        // Verify PID is cleared
        let released = manager
            .get_session(id)
            .expect("failed to get")
            .expect("session not found");
        assert!(released.metadata.pid.is_none());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_session_in_use_guard() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let id = session.id;

        // Acquire the session
        let _acquired = manager.acquire_session(id).expect("failed to acquire");

        // Try to acquire again - should fail with InUse
        let result = manager.acquire_session(id);
        assert!(result.is_err());
        match result {
            Err(SessionError::InUse { .. }) => {}
            other => panic!("expected InUse error, got {:?}", other),
        }

        // Release and try again - should succeed
        manager.release_session(id).expect("failed to release");
        let _acquired2 = manager.acquire_session(id).expect("failed to re-acquire");

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_prepare_session_mounts() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let id = session.id;

        // Prepare mounts
        let prepared = manager
            .prepare_session_mounts(id)
            .expect("failed to prepare mounts");

        assert!(prepared.same_filesystem);
        assert!(prepared.session.paths.upper.exists());
        assert!(prepared.session.paths.work.exists());
        assert!(prepared.session.paths.merged.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }

    #[test]
    fn test_prepare_session_empties_work() {
        let config = test_config();
        let manager = SessionManager::new(config.clone());

        let session = manager.create_session().expect("failed to create session");
        let id = session.id;

        // Create a file in work directory
        let test_file = session.paths.work.join("test.txt");
        fs::write(&test_file, "test").expect("failed to write test file");
        assert!(test_file.exists());

        // Prepare mounts - should empty work directory
        let prepared = manager
            .prepare_session_mounts(id)
            .expect("failed to prepare mounts");

        assert!(prepared.work_emptied);
        assert!(!test_file.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&config.base_dir);
    }
}
