//! Workspace mounting and validation for sandbox containers.
//!
//! This module handles secure mounting of host directories into the sandbox
//! as a workspace, with comprehensive security validation to prevent
//! credential exposure.
//!
//! # Security Model
//!
//! Before any workspace directory is mounted into a sandbox:
//! 1. Path must be absolute (no relative paths)
//! 2. Path is canonicalized to resolve any symlinks
//! 3. Path is checked against forbidden credential directories
//! 4. Path must be a directory (not a file or symlink at top level)
//! 5. World-writable directories are logged as warnings
//!
//! # Mount Point
//!
//! The workspace is always mounted at `/workspace` inside the sandbox.
//! If `working_dir` is not specified in `SandboxConfig`, it defaults to
//! `/workspace` when a workspace is mounted.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tracing::{debug, instrument, warn};

use crate::error::MountError;
use crate::sandbox::security::MountPolicyGuard;

/// The fixed mount point for workspaces inside the sandbox.
pub const WORKSPACE_MOUNT_POINT: &str = "/workspace";

/// Configuration for workspace mounting.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Host path to mount as workspace.
    pub host_path: PathBuf,
    /// Whether to mount read-only (default: false, read-write).
    pub read_only: bool,
    /// Allow world-writable directories (default: false).
    pub allow_world_writable: bool,
}

impl WorkspaceConfig {
    /// Creates a new workspace configuration for a read-write mount.
    #[must_use]
    pub fn new(host_path: impl Into<PathBuf>) -> Self {
        Self {
            host_path: host_path.into(),
            read_only: false,
            allow_world_writable: false,
        }
    }

    /// Creates a new workspace configuration for a read-only mount.
    #[must_use]
    pub fn new_readonly(host_path: impl Into<PathBuf>) -> Self {
        Self {
            host_path: host_path.into(),
            read_only: true,
            allow_world_writable: false,
        }
    }

    /// Allow world-writable directories (use with caution).
    #[must_use]
    pub fn allow_world_writable(mut self) -> Self {
        self.allow_world_writable = true;
        self
    }
}

/// Validated and prepared workspace ready for mounting.
#[derive(Debug, Clone)]
pub struct PreparedWorkspace {
    /// Canonicalized host path.
    pub canonical_path: PathBuf,
    /// Whether to mount read-only.
    pub read_only: bool,
    /// The mount point inside the sandbox.
    pub mount_point: &'static str,
}

impl PreparedWorkspace {
    /// Returns the mount point path.
    #[must_use]
    pub fn mount_point(&self) -> &str {
        self.mount_point
    }
}

/// Validates and prepares a workspace for mounting.
///
/// This performs comprehensive security checks before allowing
/// a directory to be mounted into the sandbox.
///
/// # Arguments
///
/// * `config` - Workspace configuration with host path and options
///
/// # Returns
///
/// Returns `PreparedWorkspace` with canonicalized path ready for mounting.
///
/// # Errors
///
/// Returns `MountError::SecurityViolation` if:
/// - Path is not absolute
/// - Path is a symlink at top level
/// - Path resolves to a forbidden credential directory
/// - Path is not a directory
/// - Path is world-writable (unless `allow_world_writable` is set)
#[instrument(skip(config), fields(host_path = %config.host_path.display()))]
pub fn prepare_workspace(config: &WorkspaceConfig) -> Result<PreparedWorkspace, MountError> {
    let path = &config.host_path;
    debug!("Validating workspace path");

    // 1. Reject non-absolute paths
    if !path.is_absolute() {
        return Err(MountError::SecurityViolation(format!(
            "workspace path must be absolute: {}",
            path.display()
        )));
    }

    // 2. Reject if top-level path is a symlink
    if path.is_symlink() {
        return Err(MountError::SecurityViolation(format!(
            "workspace path cannot be a symlink: {}",
            path.display()
        )));
    }

    // 3. Validate with MountPolicyGuard (canonicalize + forbidden path checks)
    let guard = MountPolicyGuard::new();
    let canonical = guard.validate_workspace(path)?;

    debug!(canonical = %canonical.display(), "Workspace path canonicalized");

    // 4. Verify it's a directory
    if !canonical.is_dir() {
        return Err(MountError::SecurityViolation(format!(
            "workspace must be a directory: {}",
            canonical.display()
        )));
    }

    // 5. Check for world-writable (warning or error depending on config)
    let metadata = fs::metadata(&canonical).map_err(|e| {
        MountError::SecurityViolation(format!(
            "cannot read workspace metadata {}: {}",
            canonical.display(),
            e
        ))
    })?;

    let mode = metadata.permissions().mode();
    if (mode & 0o002) != 0 {
        if config.allow_world_writable {
            warn!(
                path = %canonical.display(),
                mode = format!("{:o}", mode),
                "Workspace is world-writable (allowed by config)"
            );
        } else {
            return Err(MountError::SecurityViolation(format!(
                "workspace is world-writable (mode {:o}): {}. \
                 Use allow_world_writable() to override.",
                mode & 0o777,
                canonical.display()
            )));
        }
    }

    debug!("Workspace validation passed");
    Ok(PreparedWorkspace {
        canonical_path: canonical,
        read_only: config.read_only,
        mount_point: WORKSPACE_MOUNT_POINT,
    })
}

/// Checks if a path would be rejected as a workspace.
///
/// This is a convenience function for testing if a path is valid
/// without the full validation overhead.
#[must_use]
pub fn is_valid_workspace_path(path: &Path) -> bool {
    if !path.is_absolute() || path.is_symlink() {
        return false;
    }

    let guard = MountPolicyGuard::new();
    guard.validate_workspace(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::TempDir;

    #[test]
    fn test_workspace_config_new() {
        let config = WorkspaceConfig::new("/tmp/workspace");
        assert_eq!(config.host_path, PathBuf::from("/tmp/workspace"));
        assert!(!config.read_only);
        assert!(!config.allow_world_writable);
    }

    #[test]
    fn test_workspace_config_readonly() {
        let config = WorkspaceConfig::new_readonly("/tmp/workspace");
        assert!(config.read_only);
    }

    #[test]
    fn test_workspace_mount_point_constant() {
        assert_eq!(WORKSPACE_MOUNT_POINT, "/workspace");
    }

    #[test]
    fn test_prepare_workspace_rejects_relative_path() {
        let config = WorkspaceConfig::new("relative/path");
        let result = prepare_workspace(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be absolute"));
    }

    #[test]
    fn test_prepare_workspace_accepts_valid_directory() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config = WorkspaceConfig::new(temp_dir.path());
        let result = prepare_workspace(&config);
        assert!(result.is_ok());
        let prepared = result.unwrap();
        assert_eq!(prepared.mount_point, WORKSPACE_MOUNT_POINT);
        assert!(!prepared.read_only);
    }

    #[test]
    fn test_prepare_workspace_rejects_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = temp_dir.path().join("file.txt");
        File::create(&file_path).expect("failed to create file");

        let config = WorkspaceConfig::new(&file_path);
        let result = prepare_workspace(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be a directory"));
    }

    #[test]
    fn test_prepare_workspace_rejects_symlink() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let target = temp_dir.path().join("target");
        fs::create_dir(&target).expect("failed to create target dir");
        let link = temp_dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("failed to create symlink");

        let config = WorkspaceConfig::new(&link);
        let result = prepare_workspace(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn test_is_valid_workspace_path() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        assert!(is_valid_workspace_path(temp_dir.path()));
        assert!(!is_valid_workspace_path(Path::new("relative/path")));
    }
}
