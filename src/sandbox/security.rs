//! Security policy enforcement for sandbox mounts.
//!
//! This module provides pre-mount policy validation to ensure no sensitive
//! credential paths are ever exposed to sandboxed processes.
//!
//! # Security Model
//!
//! The primary defense is **pre-mount validation**: any host path that will be
//! bind-mounted into the sandbox is validated BEFORE the mount occurs. This is
//! stronger than post-mount checks because it prevents the mount from ever happening.
//!
//! Secondary defense is **post-mount audit**: after mounts are set up, we can
//! parse `/proc/self/mountinfo` to verify no forbidden paths were mounted.
//!
//! # Forbidden Paths
//!
//! These credential directories/files are NEVER allowed to be mounted:
//! - `~/.ssh` - SSH keys and config
//! - `~/.aws` - AWS credentials
//! - `~/.gnupg` - GPG keys
//! - `~/.kube` - Kubernetes credentials
//! - `~/.config/gh` - GitHub CLI credentials
//! - `~/.docker` - Docker credentials
//! - `~/.netrc` - Network credentials
//! - `~/.git-credentials` - Git credential cache
//! - `~/.cargo/credentials*` - Cargo/crates.io credentials
//! - `~/.npmrc` - NPM credentials
//! - `~/.pypirc` - PyPI credentials
//! - `/etc/ssh` - System SSH config
//! - `/run/user/*/keyring*` - User keyrings
//! - `/run/secrets` - Container secrets

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{debug, instrument, warn};

use crate::error::MountError;

/// Forbidden path prefixes relative to home directory.
///
/// These are checked after canonicalizing the home directory.
const FORBIDDEN_HOME_PREFIXES: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".config/gh",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".gitconfig",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".npmrc",
    ".pypirc",
    ".config/gcloud",
];

/// Forbidden absolute path prefixes (not under home).
const FORBIDDEN_ABSOLUTE_PREFIXES: &[&str] = &[
    "/etc/ssh",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/run/secrets",
];

/// Forbidden path patterns that match anywhere in the path.
const FORBIDDEN_PATTERNS: &[&str] = &["keyring", "secret", "credential", "token"];

/// Policy guard for validating paths before mounting.
///
/// Use this to validate any host path before it is bind-mounted into a sandbox.
#[derive(Debug, Clone)]
pub struct MountPolicyGuard {
    /// Canonicalized home directory.
    /// Reserved for future use in path resolution.
    #[allow(dead_code)]
    home_dir: Option<PathBuf>,
    /// Canonicalized forbidden prefixes under home.
    forbidden_home_paths: Vec<PathBuf>,
    /// Canonicalized forbidden absolute paths.
    forbidden_absolute_paths: Vec<PathBuf>,
}

impl MountPolicyGuard {
    /// Creates a new policy guard, resolving forbidden paths.
    #[must_use]
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME").ok().map(PathBuf::from);

        let forbidden_home_paths = if let Some(ref home) = home_dir {
            FORBIDDEN_HOME_PREFIXES
                .iter()
                .map(|p| home.join(p))
                .filter_map(|p| fs::canonicalize(&p).ok().or(Some(p)))
                .collect()
        } else {
            Vec::new()
        };

        let forbidden_absolute_paths = FORBIDDEN_ABSOLUTE_PREFIXES
            .iter()
            .map(PathBuf::from)
            .filter_map(|p| fs::canonicalize(&p).ok().or(Some(p)))
            .collect();

        Self {
            home_dir,
            forbidden_home_paths,
            forbidden_absolute_paths,
        }
    }

    /// Validates a path is safe to mount into a sandbox.
    ///
    /// # Arguments
    ///
    /// * `path` - The host path to validate
    ///
    /// # Errors
    ///
    /// Returns `MountError::SecurityViolation` if the path is forbidden.
    #[instrument(skip(self), fields(path = %path.display()))]
    pub fn validate_mount_source(&self, path: &Path) -> Result<PathBuf, MountError> {
        // Reject non-absolute paths
        if !path.is_absolute() {
            return Err(MountError::SecurityViolation(format!(
                "mount source must be absolute path: {}",
                path.display()
            )));
        }

        // Reject if path is a symlink at the top level
        if path.is_symlink() {
            return Err(MountError::SecurityViolation(format!(
                "mount source cannot be a symlink: {}",
                path.display()
            )));
        }

        // Canonicalize the path to resolve any symlinks in the chain
        let canonical = fs::canonicalize(path).map_err(|e| {
            MountError::SecurityViolation(format!(
                "cannot canonicalize mount source {}: {}",
                path.display(),
                e
            ))
        })?;

        debug!(canonical = %canonical.display(), "Canonicalized mount source");

        // Check against forbidden home prefixes
        for forbidden in &self.forbidden_home_paths {
            if canonical.starts_with(forbidden) {
                return Err(MountError::SecurityViolation(format!(
                    "mount source is under forbidden credential path: {}",
                    forbidden.display()
                )));
            }
        }

        // Check against forbidden absolute prefixes
        for forbidden in &self.forbidden_absolute_paths {
            if canonical.starts_with(forbidden) {
                return Err(MountError::SecurityViolation(format!(
                    "mount source is under forbidden system path: {}",
                    forbidden.display()
                )));
            }
        }

        // Check for forbidden patterns in path
        let path_str = canonical.to_string_lossy().to_lowercase();
        for pattern in FORBIDDEN_PATTERNS {
            if path_str.contains(pattern) {
                warn!(
                    pattern = pattern,
                    path = %canonical.display(),
                    "Mount source contains forbidden pattern"
                );
                return Err(MountError::SecurityViolation(format!(
                    "mount source contains forbidden pattern '{}': {}",
                    pattern,
                    canonical.display()
                )));
            }
        }

        // Check for world-writable directories (potential security risk)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&canonical) {
                let mode = metadata.permissions().mode();
                if metadata.is_dir() && (mode & 0o002) != 0 {
                    warn!(
                        path = %canonical.display(),
                        mode = format!("{:o}", mode),
                        "Mount source is world-writable"
                    );
                    // This is a warning, not a hard failure - some use cases may need it
                    // But we log it prominently
                }
            }
        }

        Ok(canonical)
    }

    /// Validates a workspace path with stricter checks.
    ///
    /// This is a stricter version of `validate_mount_source` specifically for
    /// workspace directories that will be mounted read-write.
    #[instrument(skip(self), fields(path = %path.display()))]
    pub fn validate_workspace(&self, path: &Path) -> Result<PathBuf, MountError> {
        // First do standard validation
        let canonical = self.validate_mount_source(path)?;

        // Additional workspace-specific checks
        if !canonical.is_dir() {
            return Err(MountError::SecurityViolation(format!(
                "workspace must be a directory: {}",
                canonical.display()
            )));
        }

        // Ensure workspace is not under /tmp or other world-writable locations
        // that might be used for symlink attacks
        let suspicious_prefixes = ["/tmp", "/var/tmp", "/dev/shm"];
        for prefix in suspicious_prefixes {
            if canonical.starts_with(prefix) {
                warn!(
                    path = %canonical.display(),
                    prefix = prefix,
                    "Workspace is under potentially unsafe location"
                );
                // Allow it but log warning - some CI systems use /tmp
            }
        }

        Ok(canonical)
    }

    /// Audits current mounts by parsing /proc/self/mountinfo.
    ///
    /// This is a secondary check to verify no forbidden paths were mounted.
    /// It should be called after mounts are set up in the sandbox namespace.
    ///
    /// # Errors
    ///
    /// Returns `MountError::SecurityViolation` if a forbidden mount is detected.
    #[instrument(skip(self))]
    pub fn audit_current_mounts(&self) -> Result<(), MountError> {
        self.audit_mountinfo("/proc/self/mountinfo")
    }

    /// Audits mounts from a mountinfo file (for testing).
    pub fn audit_mountinfo(&self, mountinfo_path: &str) -> Result<(), MountError> {
        let content = match fs::read_to_string(mountinfo_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Could not read mountinfo for audit");
                return Ok(()); // Don't fail if we can't read mountinfo
            }
        };

        for line in content.lines() {
            // mountinfo format: id parent_id major:minor root mount_point options...
            // Field 4 is the root of the mount (source path)
            // Field 5 is the mount point
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }

            let mount_root = fields[3];
            let mount_point = fields[4];

            // Check if mount root is a forbidden path
            let root_path = PathBuf::from(mount_root);
            for forbidden in &self.forbidden_home_paths {
                if root_path.starts_with(forbidden) {
                    return Err(MountError::SecurityViolation(format!(
                        "forbidden credential path is mounted: {} at {}",
                        mount_root, mount_point
                    )));
                }
            }

            for forbidden in &self.forbidden_absolute_paths {
                if root_path.starts_with(forbidden) {
                    return Err(MountError::SecurityViolation(format!(
                        "forbidden system path is mounted: {} at {}",
                        mount_root, mount_point
                    )));
                }
            }
        }

        debug!("Mount audit passed");
        Ok(())
    }
}

impl Default for MountPolicyGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates a path is not under any credential directory.
///
/// This is a convenience function for quick checks without creating a guard.
pub fn is_path_forbidden(path: &Path) -> bool {
    let guard = MountPolicyGuard::new();
    guard.validate_mount_source(path).is_err()
}

/// Returns the canonical home directory, if available.
pub fn get_home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .and_then(|p| fs::canonicalize(&p).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_policy_guard_creation() {
        let guard = MountPolicyGuard::new();
        assert!(guard.home_dir.is_some() || std::env::var("HOME").is_err());
    }

    #[test]
    fn test_rejects_ssh_directory() {
        let guard = MountPolicyGuard::new();

        if let Some(home) = &guard.home_dir {
            let ssh_path = home.join(".ssh");
            let result = guard.validate_mount_source(&ssh_path);
            assert!(result.is_err(), "should reject .ssh directory");

            if let Err(MountError::SecurityViolation(msg)) = result {
                assert!(
                    msg.contains("forbidden"),
                    "error should mention forbidden: {}",
                    msg
                );
            }
        }
    }

    #[test]
    fn test_rejects_aws_directory() {
        let guard = MountPolicyGuard::new();

        if let Some(home) = &guard.home_dir {
            let aws_path = home.join(".aws");
            let result = guard.validate_mount_source(&aws_path);
            assert!(result.is_err(), "should reject .aws directory");
        }
    }

    #[test]
    fn test_rejects_non_absolute_path() {
        let guard = MountPolicyGuard::new();

        let result = guard.validate_mount_source(Path::new("relative/path"));
        assert!(result.is_err(), "should reject relative path");

        if let Err(MountError::SecurityViolation(msg)) = result {
            assert!(msg.contains("absolute"), "error should mention absolute");
        }
    }

    #[test]
    fn test_accepts_valid_path() {
        let guard = MountPolicyGuard::new();

        // /usr should be a safe path
        let result = guard.validate_mount_source(Path::new("/usr"));
        if Path::new("/usr").exists() {
            assert!(result.is_ok(), "should accept /usr: {:?}", result);
        }
    }

    #[test]
    fn test_rejects_etc_shadow() {
        let guard = MountPolicyGuard::new();

        let result = guard.validate_mount_source(Path::new("/etc/shadow"));
        // This may fail to canonicalize if file doesn't exist, but that's fine
        if Path::new("/etc/shadow").exists() {
            assert!(result.is_err(), "should reject /etc/shadow");
        }
    }

    #[test]
    fn test_workspace_validation_requires_directory() {
        let guard = MountPolicyGuard::new();

        // A regular file should be rejected as workspace
        let temp_file = std::env::temp_dir().join("test_workspace_file");
        if let Ok(mut f) = std::fs::File::create(&temp_file) {
            let _ = f.write_all(b"test");

            let result = guard.validate_workspace(&temp_file);
            assert!(result.is_err(), "should reject file as workspace");

            let _ = std::fs::remove_file(&temp_file);
        }
    }

    #[test]
    fn test_workspace_accepts_valid_directory() {
        let guard = MountPolicyGuard::new();

        // /tmp should be a valid workspace directory
        let result = guard.validate_workspace(Path::new("/tmp"));
        if Path::new("/tmp").exists() && Path::new("/tmp").is_dir() {
            assert!(
                result.is_ok(),
                "should accept /tmp as workspace: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_mountinfo_audit_detects_forbidden() {
        let guard = MountPolicyGuard::new();

        // Create a mock mountinfo with a forbidden path
        let temp_file = std::env::temp_dir().join("test_mountinfo");
        if let Some(home) = &guard.home_dir {
            let mock_content = format!(
                "1 0 8:1 {} /mnt/secret rw,relatime - ext4 /dev/sda1 rw\n",
                home.join(".ssh").display()
            );

            if let Ok(mut f) = std::fs::File::create(&temp_file) {
                let _ = f.write_all(mock_content.as_bytes());

                let result = guard.audit_mountinfo(&temp_file.to_string_lossy());
                assert!(
                    result.is_err(),
                    "should detect forbidden mount in mountinfo"
                );

                let _ = std::fs::remove_file(&temp_file);
            }
        }
    }

    #[test]
    fn test_mountinfo_audit_passes_clean() {
        let guard = MountPolicyGuard::new();

        // Create a mock mountinfo with only safe paths
        let temp_file = std::env::temp_dir().join("test_mountinfo_clean");
        let mock_content = "1 0 8:1 /usr /usr rw,relatime - ext4 /dev/sda1 rw\n\
                           2 0 8:1 /var /var rw,relatime - ext4 /dev/sda1 rw\n";

        if let Ok(mut f) = std::fs::File::create(&temp_file) {
            let _ = f.write_all(mock_content.as_bytes());

            let result = guard.audit_mountinfo(&temp_file.to_string_lossy());
            assert!(result.is_ok(), "should pass with safe mounts: {:?}", result);

            let _ = std::fs::remove_file(&temp_file);
        }
    }

    #[test]
    fn test_is_path_forbidden_helper() {
        if let Some(home) = get_home_dir() {
            assert!(is_path_forbidden(&home.join(".ssh")));
            assert!(is_path_forbidden(&home.join(".aws")));
            assert!(!is_path_forbidden(Path::new("/usr")));
        }
    }
}
