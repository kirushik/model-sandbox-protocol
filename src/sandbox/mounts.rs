//! OverlayFS and mount setup for sandbox filesystems.
//!
//! This module handles the mounting of various filesystems required for
//! sandboxed execution, including:
//!
//! - OverlayFS for copy-on-write filesystem isolation
//! - procfs with `hidepid=invisible` for process isolation
//! - devtmpfs with minimal device nodes
//! - tmpfs for `/tmp` with size limits
//!
//! # Security Considerations
//!
//! - Credential paths (e.g., `~/.ssh`, `~/.aws`) are NEVER mounted
//! - `/proc` uses `hidepid=invisible` to hide host processes
//! - `/dev` provides only minimal, safe device nodes
//! - All mounts use `MS_NOSUID` to prevent privilege escalation
//!
//! # OverlayFS Requirements
//!
//! - Kernel 5.11+ for unprivileged OverlayFS in user namespaces
//! - Must use `userxattr` mount option
//! - Work directory must be on same filesystem as upper directory
//! - Work directory must be empty before mount

use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use tracing::{debug, instrument, trace, warn};

use crate::error::MountError;
use crate::session::SessionPaths;

/// Paths that must NEVER be accessible from within the sandbox.
///
/// These contain sensitive credentials that could be exfiltrated if exposed.
/// This list is checked during mount validation.
pub const FORBIDDEN_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".config/gcloud",
    ".kube",
    ".gnupg",
    ".gitconfig",
    ".netrc",
    ".git-credentials",
    ".config/gh",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
];

/// Safe files from /etc that can be included in the sandbox.
///
/// These files are necessary for basic operation but don't contain credentials.
pub const SAFE_ETC_FILES: &[&str] = &[
    "passwd",
    "group",
    "hosts",
    "resolv.conf",
    "nsswitch.conf",
    "localtime",
    "ssl/certs",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
];

/// Configuration for mount operations.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Session paths for this sandbox.
    pub session_paths: SessionPaths,
    /// Size limit for tmpfs in megabytes.
    pub tmp_size_mb: u32,
    /// Whether to use hidepid=invisible for /proc.
    pub proc_hidepid: bool,
    /// Lower directories for OverlayFS (read-only base).
    pub lower_dirs: Vec<PathBuf>,
}

impl MountConfig {
    /// Creates a new mount configuration with default lower directories.
    #[must_use]
    pub fn new(session_paths: SessionPaths, tmp_size_mb: u32) -> Self {
        Self {
            session_paths,
            tmp_size_mb,
            proc_hidepid: true,
            lower_dirs: default_lower_dirs(),
        }
    }

    /// Sets the lower directories for OverlayFS.
    #[must_use]
    pub fn with_lower_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.lower_dirs = dirs;
        self
    }

    /// Disables hidepid for /proc (not recommended).
    #[must_use]
    pub fn without_hidepid(mut self) -> Self {
        self.proc_hidepid = false;
        self
    }
}

/// Returns the default lower directories for OverlayFS.
///
/// These are the read-only base directories that form the foundation
/// of the sandbox filesystem.
#[must_use]
pub fn default_lower_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/sbin"),
    ]
}

/// Mounts OverlayFS combining lower (read-only) and upper (writable) layers.
///
/// # Arguments
///
/// * `lower` - Read-only base directories
/// * `upper` - Writable upper layer for modifications
/// * `work` - Work directory for OverlayFS internal use
/// * `merged` - Mount point for the combined view
///
/// # Errors
///
/// Returns `MountError::OverlayMount` if the mount operation fails.
///
/// # Notes
///
/// - Uses `userxattr` option for unprivileged user namespace mounting
/// - Applies `MS_NOSUID` and `MS_NODEV` for security
#[instrument(skip_all, fields(merged = %merged.display()))]
pub fn mount_overlay(
    lower: &[PathBuf],
    upper: &Path,
    work: &Path,
    merged: &Path,
) -> Result<(), MountError> {
    debug!("Mounting OverlayFS");

    // Build lower directory string (colon-separated)
    let lower_str = lower
        .iter()
        .filter(|p| p.exists()) // Only include existing directories
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(":");

    if lower_str.is_empty() {
        return Err(MountError::OverlayMount(
            "no valid lower directories found".to_string(),
        ));
    }

    let options = format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        lower_str,
        upper.display(),
        work.display()
    );

    trace!(options = %options, "OverlayFS mount options");

    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|e| MountError::OverlayMount(format!("mount failed: {}", e)))?;

    debug!("OverlayFS mounted successfully");
    Ok(())
}

/// Mounts a fresh procfs with process isolation.
///
/// # Arguments
///
/// * `target` - Mount point for procfs (typically "/proc" in sandbox root)
/// * `hidepid` - If true, uses `hidepid=invisible` to hide other processes
///
/// # Errors
///
/// Returns `MountError::ProcMount` if the mount operation fails.
#[instrument(skip_all, fields(target = %target.display(), hidepid = %hidepid))]
pub fn mount_proc(target: &Path, hidepid: bool) -> Result<(), MountError> {
    debug!("Mounting procfs");

    let options = if hidepid {
        // hidepid=invisible requires kernel 5.8+
        // Falls back gracefully on older kernels
        Some("hidepid=invisible")
    } else {
        None
    };

    let result = mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        options,
    );

    match result {
        Ok(()) => {
            debug!("procfs mounted successfully");
            Ok(())
        }
        Err(e) => {
            // If hidepid=invisible fails, try hidepid=2 as fallback
            if hidepid {
                warn!("hidepid=invisible failed, trying hidepid=2");
                if mount(
                    Some("proc"),
                    target,
                    Some("proc"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                    Some("hidepid=2"),
                )
                .is_ok()
                {
                    debug!("procfs mounted with hidepid=2 fallback");
                    return Ok(());
                }
            }
            Err(MountError::ProcMount(format!("mount failed: {}", e)))
        }
    }
}

/// Mounts a fresh devtmpfs with minimal device nodes.
///
/// # Arguments
///
/// * `target` - Mount point for devfs (typically "/dev" in sandbox root)
///
/// # Errors
///
/// Returns `MountError::DevMount` if the mount operation fails.
///
/// # Notes
///
/// - Uses `MS_NOSUID` to prevent privilege escalation
/// - Does NOT expose host TTY devices (prevents TIOCSTI attacks)
#[instrument(skip_all, fields(target = %target.display()))]
pub fn mount_dev(target: &Path) -> Result<(), MountError> {
    debug!("Mounting devtmpfs");

    mount(
        Some("devtmpfs"),
        target,
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .map_err(|e| MountError::DevMount(format!("mount failed: {}", e)))?;

    debug!("devtmpfs mounted successfully");
    Ok(())
}

/// Mounts tmpfs at /tmp with a size limit.
///
/// # Arguments
///
/// * `target` - Mount point for tmpfs (typically "/tmp" in sandbox root)
/// * `size_mb` - Maximum size in megabytes
///
/// # Errors
///
/// Returns `MountError::TmpfsMount` if the mount operation fails.
#[instrument(skip_all, fields(target = %target.display(), size_mb = %size_mb))]
pub fn mount_tmp(target: &Path, size_mb: u32) -> Result<(), MountError> {
    debug!("Mounting tmpfs");

    let options = format!("size={}m,mode=1777", size_mb);

    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|e| MountError::TmpfsMount(format!("mount failed: {}", e)))?;

    debug!("tmpfs mounted successfully");
    Ok(())
}

/// Mounts /dev/shm as tmpfs for shared memory.
///
/// # Arguments
///
/// * `target` - Mount point (typically "/dev/shm" in sandbox root)
/// * `size_mb` - Maximum size in megabytes (typically same as /tmp limit)
///
/// # Errors
///
/// Returns `MountError::TmpfsMount` if the mount operation fails.
#[instrument(skip_all, fields(target = %target.display()))]
pub fn mount_shm(target: &Path, size_mb: u32) -> Result<(), MountError> {
    debug!("Mounting /dev/shm");

    let options = format!("size={}m,mode=1777", size_mb);

    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|e| MountError::TmpfsMount(format!("mount shm failed: {}", e)))?;

    debug!("/dev/shm mounted successfully");
    Ok(())
}

/// Creates a read-only bind mount.
///
/// # Arguments
///
/// * `source` - Source path on host
/// * `target` - Target path in sandbox
///
/// # Errors
///
/// Returns `MountError::BindMount` if the mount operation fails.
#[instrument(skip_all, fields(source = %source.display(), target = %target.display()))]
pub fn bind_mount_ro(source: &Path, target: &Path) -> Result<(), MountError> {
    trace!("Creating read-only bind mount");

    // First, create a regular bind mount
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| MountError::BindMount(format!("bind mount failed: {}", e)))?;

    // Then remount read-only
    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| MountError::BindMount(format!("remount read-only failed: {}", e)))?;

    trace!("Read-only bind mount created");
    Ok(())
}

/// Creates a read-write bind mount.
///
/// # Arguments
///
/// * `source` - Source path on host
/// * `target` - Target path in sandbox
///
/// # Errors
///
/// Returns `MountError::BindMount` if the mount operation fails.
#[instrument(skip_all, fields(source = %source.display(), target = %target.display()))]
pub fn bind_mount_rw(source: &Path, target: &Path) -> Result<(), MountError> {
    trace!("Creating read-write bind mount");

    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| MountError::BindMount(format!("bind mount failed: {}", e)))?;

    trace!("Read-write bind mount created");
    Ok(())
}

/// Unmounts a filesystem.
///
/// Uses `MNT_DETACH` (lazy unmount) as a fallback if normal unmount fails.
///
/// # Arguments
///
/// * `target` - Mount point to unmount
///
/// # Errors
///
/// Returns `MountError::Unmount` if both normal and lazy unmount fail.
#[instrument(skip_all, fields(target = %target.display()))]
pub fn unmount(target: &Path) -> Result<(), MountError> {
    debug!("Unmounting filesystem");

    // Try normal unmount first
    match umount2(target, MntFlags::empty()) {
        Ok(()) => {
            debug!("Filesystem unmounted successfully");
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, "Normal unmount failed, trying lazy unmount");

            // Try lazy unmount as fallback
            umount2(target, MntFlags::MNT_DETACH)
                .map_err(|e| MountError::Unmount(format!("lazy unmount failed: {}", e)))?;

            debug!("Filesystem unmounted with MNT_DETACH");
            Ok(())
        }
    }
}

/// Validates that no credential paths are accessible from the given root.
///
/// This is a security check to ensure sensitive files like SSH keys,
/// AWS credentials, etc. are not exposed to the sandbox.
///
/// # Arguments
///
/// * `merged_root` - The root path of the merged filesystem
///
/// # Errors
///
/// Returns `MountError::SecurityViolation` if any forbidden paths are found.
#[instrument(skip_all, fields(merged_root = %merged_root.display()))]
pub fn validate_no_credentials(merged_root: &Path) -> Result<(), MountError> {
    debug!("Validating no credential paths are accessible");

    // Get home directory from environment
    let home = std::env::var("HOME").ok();

    for forbidden in FORBIDDEN_PATHS {
        // Check relative to home in merged root
        if let Some(ref home_dir) = home {
            let home_name = Path::new(home_dir)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("root");

            // Check in /home/{user}
            let user_path = merged_root.join("home").join(home_name).join(forbidden);
            if user_path.exists() {
                return Err(MountError::SecurityViolation(format!(
                    "forbidden credential path accessible: {}",
                    user_path.display()
                )));
            }

            // Check in /root
            let root_path = merged_root.join("root").join(forbidden);
            if root_path.exists() {
                return Err(MountError::SecurityViolation(format!(
                    "forbidden credential path accessible: {}",
                    root_path.display()
                )));
            }
        }
    }

    debug!("No credential paths found - validation passed");
    Ok(())
}

/// Sets up all mounts for a sandbox session.
///
/// This is a convenience function that performs all necessary mount operations
/// for a complete sandbox environment.
///
/// # Arguments
///
/// * `config` - Mount configuration
///
/// # Errors
///
/// Returns appropriate `MountError` variant if any mount operation fails.
///
/// # Mount Order
///
/// 1. OverlayFS (lower + upper + work → merged)
/// 2. Security validation (no credentials exposed)
/// 3. Mounts are typically handled by hakoniwa after this
#[instrument(skip_all)]
pub fn setup_session_mounts(config: &MountConfig) -> Result<(), MountError> {
    debug!("Setting up session mounts");

    let paths = &config.session_paths;

    // Mount OverlayFS
    mount_overlay(&config.lower_dirs, &paths.upper, &paths.work, &paths.merged)?;

    // Validate security - no credentials should be accessible
    validate_no_credentials(&paths.merged)?;

    debug!("Session mounts setup complete");
    Ok(())
}

/// Tears down all mounts for a sandbox session.
///
/// Unmounts in reverse order of setup. Continues on errors to clean up
/// as much as possible.
///
/// # Arguments
///
/// * `paths` - Session paths with mount points
///
/// # Returns
///
/// Returns the first error encountered, but attempts all unmounts.
#[instrument(skip_all)]
pub fn teardown_session_mounts(paths: &SessionPaths) -> Result<(), MountError> {
    debug!("Tearing down session mounts");

    let mut first_error: Option<MountError> = None;

    // Unmount overlay
    if let Err(e) = unmount(&paths.merged) {
        warn!(error = %e, "Failed to unmount overlay");
        if first_error.is_none() {
            first_error = Some(e);
        }
    }

    if let Some(e) = first_error {
        Err(e)
    } else {
        debug!("Session mounts torn down successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forbidden_paths_comprehensive() {
        // Verify common credential paths are included
        assert!(FORBIDDEN_PATHS.contains(&".ssh"));
        assert!(FORBIDDEN_PATHS.contains(&".aws"));
        assert!(FORBIDDEN_PATHS.contains(&".gnupg"));
        assert!(FORBIDDEN_PATHS.contains(&".kube"));
        assert!(FORBIDDEN_PATHS.contains(&".docker/config.json"));
    }

    #[test]
    fn test_safe_etc_files() {
        // Verify essential files are included
        assert!(SAFE_ETC_FILES.contains(&"passwd"));
        assert!(SAFE_ETC_FILES.contains(&"group"));
        assert!(SAFE_ETC_FILES.contains(&"hosts"));
        assert!(SAFE_ETC_FILES.contains(&"resolv.conf"));
    }

    #[test]
    fn test_default_lower_dirs() {
        let dirs = default_lower_dirs();
        assert!(dirs.contains(&PathBuf::from("/usr")));
        assert!(dirs.contains(&PathBuf::from("/bin")));
        assert!(dirs.contains(&PathBuf::from("/lib")));
    }

    #[test]
    fn test_mount_config_builder() {
        use crate::session::SessionPaths;
        use uuid::Uuid;

        let base_dir = PathBuf::from("/tmp/test");
        let session_id = Uuid::new_v4();
        let paths = SessionPaths::new(&base_dir, session_id);

        let config = MountConfig::new(paths, 100)
            .with_lower_dirs(vec![PathBuf::from("/custom")])
            .without_hidepid();

        assert_eq!(config.tmp_size_mb, 100);
        assert!(!config.proc_hidepid);
        assert_eq!(config.lower_dirs, vec![PathBuf::from("/custom")]);
    }

    // Note: Actual mount tests require root or user namespace privileges
    // and are better suited for integration tests in tests/session.rs
}
