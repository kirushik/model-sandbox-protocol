//! Filesystem layout for session storage.
//!
//! This module manages the directory structure for sessions, including
//! creation, validation, and cleanup of session directories.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::SessionError;
use crate::session::SessionId;

/// Directory permissions: owner read/write/execute only (0700).
const DIR_PERMISSIONS: u32 = 0o700;

/// Paths for a session's filesystem structure.
///
/// Each session has a dedicated directory structure:
///
/// ```text
/// {base_dir}/{session-id}/
/// ├── upper/      # OverlayFS upper layer (writable changes)
/// ├── work/       # OverlayFS work directory (internal)
/// ├── merged/     # Mount point (sandbox root filesystem)
/// ├── meta.json   # Session metadata
/// └── pid         # PID file for orphan detection
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPaths {
    /// Root directory for this session (`~/.mcp-sandboxes/{session-id}/`).
    pub root: PathBuf,
    /// OverlayFS upper layer (writable).
    pub upper: PathBuf,
    /// OverlayFS work directory (internal kernel use).
    pub work: PathBuf,
    /// OverlayFS merged mount point.
    pub merged: PathBuf,
    /// Session metadata JSON file.
    pub meta_file: PathBuf,
    /// PID file for orphan detection.
    pub pid_file: PathBuf,
}

impl SessionPaths {
    /// Creates a new `SessionPaths` for the given base directory and session ID.
    ///
    /// This only computes the paths; it does not create any directories.
    /// Use `create_directories()` to actually create the directory structure.
    #[must_use]
    pub fn new(base_dir: &Path, session_id: SessionId) -> Self {
        let root = base_dir.join(session_id.to_string());
        Self {
            upper: root.join("upper"),
            work: root.join("work"),
            merged: root.join("merged"),
            meta_file: root.join("meta.json"),
            pid_file: root.join("pid"),
            root,
        }
    }

    /// Creates all required directories for this session.
    ///
    /// Creates the session root, upper, work, and merged directories
    /// with appropriate permissions (0700).
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if directory creation fails.
    pub fn create_directories(&self) -> Result<(), SessionError> {
        // Create all directories with restricted permissions
        for dir in [&self.root, &self.upper, &self.work, &self.merged] {
            fs::create_dir_all(dir).map_err(|e| SessionError::IoError {
                context: format!("failed to create directory: {}", dir.display()),
                source: e,
            })?;

            // Set permissions to 0700 (owner only)
            let permissions = fs::Permissions::from_mode(DIR_PERMISSIONS);
            fs::set_permissions(dir, permissions).map_err(|e| SessionError::IoError {
                context: format!("failed to set permissions on: {}", dir.display()),
                source: e,
            })?;
        }

        Ok(())
    }

    /// Removes all session directories and files.
    ///
    /// This performs a recursive removal of the session root directory.
    /// Should only be called after ensuring no mounts are active.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if removal fails.
    pub fn cleanup(&self) -> Result<(), SessionError> {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).map_err(|e| SessionError::IoError {
                context: format!(
                    "failed to remove session directory: {}",
                    self.root.display()
                ),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Checks if this session's directory structure exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.root.exists()
    }

    /// Validates that all required directories exist with correct permissions.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidSession` if validation fails.
    pub fn validate(&self) -> Result<(), SessionError> {
        // Check all required directories exist
        for (name, dir) in [
            ("root", &self.root),
            ("upper", &self.upper),
            ("work", &self.work),
            ("merged", &self.merged),
        ] {
            if !dir.exists() {
                return Err(SessionError::InvalidSession {
                    reason: format!("missing {} directory: {}", name, dir.display()),
                });
            }

            if !dir.is_dir() {
                return Err(SessionError::InvalidSession {
                    reason: format!("{} is not a directory: {}", name, dir.display()),
                });
            }

            // Verify permissions are restrictive
            let metadata = fs::metadata(dir).map_err(|e| SessionError::IoError {
                context: format!("failed to read metadata for: {}", dir.display()),
                source: e,
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != DIR_PERMISSIONS {
                return Err(SessionError::InvalidSession {
                    reason: format!(
                        "incorrect permissions on {}: expected {:o}, got {:o}",
                        dir.display(),
                        DIR_PERMISSIONS,
                        mode
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Returns the default base directory for session storage.
///
/// Uses `XDG_DATA_HOME` if set, otherwise falls back to `~/.mcp-sandboxes/`.
#[must_use]
pub fn get_default_base_dir() -> PathBuf {
    // Check XDG_DATA_HOME first
    if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg_data).join("mcp-sandboxes");
    }

    // Fall back to ~/.mcp-sandboxes/
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".mcp-sandboxes");
    }

    // Last resort: use /tmp
    PathBuf::from("/tmp/mcp-sandboxes")
}

/// Ensures the base directory exists with correct permissions.
///
/// # Errors
///
/// Returns `SessionError::IoError` if directory creation fails.
pub fn ensure_base_dir(base_dir: &Path) -> Result<(), SessionError> {
    if !base_dir.exists() {
        fs::create_dir_all(base_dir).map_err(|e| SessionError::IoError {
            context: format!("failed to create base directory: {}", base_dir.display()),
            source: e,
        })?;

        let permissions = fs::Permissions::from_mode(DIR_PERMISSIONS);
        fs::set_permissions(base_dir, permissions).map_err(|e| SessionError::IoError {
            context: format!(
                "failed to set permissions on base directory: {}",
                base_dir.display()
            ),
            source: e,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use uuid::Uuid;

    #[test]
    fn test_session_paths_new() {
        let base_dir = PathBuf::from("/tmp/test-sandboxes");
        let session_id = Uuid::new_v4();
        let paths = SessionPaths::new(&base_dir, session_id);

        assert_eq!(paths.root, base_dir.join(session_id.to_string()));
        assert_eq!(paths.upper, paths.root.join("upper"));
        assert_eq!(paths.work, paths.root.join("work"));
        assert_eq!(paths.merged, paths.root.join("merged"));
        assert_eq!(paths.meta_file, paths.root.join("meta.json"));
        assert_eq!(paths.pid_file, paths.root.join("pid"));
    }

    #[test]
    fn test_session_paths_create_and_cleanup() {
        let base_dir = std::env::temp_dir().join("mcp-test-storage");
        let session_id = Uuid::new_v4();
        let paths = SessionPaths::new(&base_dir, session_id);

        // Create directories
        paths
            .create_directories()
            .expect("failed to create directories");

        // Verify they exist
        assert!(paths.root.exists());
        assert!(paths.upper.exists());
        assert!(paths.work.exists());
        assert!(paths.merged.exists());
        assert!(paths.exists());

        // Verify permissions
        let metadata = fs::metadata(&paths.root).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, DIR_PERMISSIONS);

        // Create a file to test recursive cleanup
        File::create(&paths.meta_file).expect("failed to create test file");

        // Cleanup
        paths.cleanup().expect("failed to cleanup");
        assert!(!paths.exists());

        // Clean up base dir
        let _ = fs::remove_dir(&base_dir);
    }

    #[test]
    fn test_session_paths_validate() {
        let base_dir = std::env::temp_dir().join("mcp-test-validate");
        let session_id = Uuid::new_v4();
        let paths = SessionPaths::new(&base_dir, session_id);

        // Should fail before creation
        assert!(paths.validate().is_err());

        // Create and validate
        paths
            .create_directories()
            .expect("failed to create directories");
        paths.validate().expect("validation should pass");

        // Cleanup
        paths.cleanup().expect("failed to cleanup");
        let _ = fs::remove_dir(&base_dir);
    }

    #[test]
    fn test_get_default_base_dir() {
        let base_dir = get_default_base_dir();
        assert!(
            base_dir.to_string_lossy().contains("mcp-sandboxes"),
            "base dir should contain 'mcp-sandboxes': {}",
            base_dir.display()
        );
    }
}
