//! System requirements checking implementation.

#![allow(unsafe_code)]
// Phase 0 note: we allow unsafe in this module for low-level OS probing (e.g. fork/unshare).
// We’ll tighten/centralize unsafe usage during Phase 4 (Security Hardening).

use crate::error::{Result, SystemRequirementsError};
use std::fs;
use std::path::Path;

/// Minimum required kernel version (major, minor).
pub const MIN_KERNEL_VERSION: (u32, u32) = (6, 7);

/// Minimum required Landlock ABI version.
pub const MIN_LANDLOCK_ABI: i32 = 6;

/// Results of all system requirements checks.
#[derive(Debug, Clone)]
pub struct SystemRequirements {
    /// Kernel version string (e.g., "6.7.0")
    pub kernel_version: String,
    /// Parsed kernel major version
    pub kernel_major: u32,
    /// Parsed kernel minor version
    pub kernel_minor: u32,
    /// System architecture
    pub architecture: String,
    /// Landlock ABI version (0 if unavailable)
    pub landlock_abi: i32,
    /// Whether cgroups v2 is available
    pub cgroups_v2: bool,
    /// Whether unprivileged user namespaces are enabled
    pub user_namespaces: bool,
}

impl SystemRequirements {
    /// Check if all requirements are met.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        (self.kernel_major > MIN_KERNEL_VERSION.0
            || (self.kernel_major == MIN_KERNEL_VERSION.0
                && self.kernel_minor >= MIN_KERNEL_VERSION.1))
            && self.architecture == "x86_64"
            && self.landlock_abi >= MIN_LANDLOCK_ABI
            && self.cgroups_v2
            && self.user_namespaces
    }
}

/// Check all system requirements and return detailed results.
///
/// Returns `Ok(SystemRequirements)` with all check results, or
/// `Err` with the first failing requirement.
pub fn check_all() -> Result<SystemRequirements> {
    let (kernel_version, kernel_major, kernel_minor) = check_kernel_version()?;
    let architecture = check_architecture()?;
    let landlock_abi = check_landlock_abi()?;
    let cgroups_v2 = check_cgroups_v2()?;
    let user_namespaces = check_user_namespaces()?;

    Ok(SystemRequirements {
        kernel_version,
        kernel_major,
        kernel_minor,
        architecture,
        landlock_abi,
        cgroups_v2,
        user_namespaces,
    })
}

/// Check kernel version is >= 6.7.
///
/// Parses the kernel version from `uname -r` output.
///
/// # Returns
///
/// Tuple of (version_string, major, minor) on success.
///
/// # Errors
///
/// Returns error if kernel version cannot be read or is below minimum.
pub fn check_kernel_version() -> Result<(String, u32, u32)> {
    let uname = nix::sys::utsname::uname().map_err(|e| SystemRequirementsError::ReadFailed {
        context: "uname syscall".to_string(),
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    let release = uname.release().to_string_lossy().to_string();
    let (major, minor) = parse_kernel_version(&release)?;

    if major < MIN_KERNEL_VERSION.0
        || (major == MIN_KERNEL_VERSION.0 && minor < MIN_KERNEL_VERSION.1)
    {
        return Err(SystemRequirementsError::KernelTooOld {
            found: release,
            required: format!("{}.{}", MIN_KERNEL_VERSION.0, MIN_KERNEL_VERSION.1),
        }
        .into());
    }

    Ok((release, major, minor))
}

/// Parse kernel version string into (major, minor).
fn parse_kernel_version(version: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();

    if parts.len() < 2 {
        return Err(SystemRequirementsError::ReadFailed {
            context: format!("Failed to parse kernel version: {version}"),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid kernel version format",
            ),
        }
        .into());
    }

    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| SystemRequirementsError::ReadFailed {
            context: format!("Failed to parse kernel major version: {}", parts[0]),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid major version"),
        })?;

    // Minor version might have suffix like "7-generic", extract just the number
    let minor_str = parts[1]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or("0");
    let minor = minor_str
        .parse::<u32>()
        .map_err(|_| SystemRequirementsError::ReadFailed {
            context: format!("Failed to parse kernel minor version: {}", parts[1]),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid minor version"),
        })?;

    Ok((major, minor))
}

/// Check system architecture is x86_64.
///
/// # Errors
///
/// Returns error if architecture is not x86_64.
pub fn check_architecture() -> Result<String> {
    let uname = nix::sys::utsname::uname().map_err(|e| SystemRequirementsError::ReadFailed {
        context: "uname syscall".to_string(),
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    let machine = uname.machine().to_string_lossy().to_string();

    if machine != "x86_64" {
        return Err(SystemRequirementsError::UnsupportedArchitecture { found: machine }.into());
    }

    Ok(machine)
}

/// Check Landlock ABI version is >= 6.
///
/// Uses the `landlock` crate to detect the current Landlock ABI version.
///
/// # Errors
///
/// Returns error if Landlock is unavailable or ABI version is too old.
pub fn check_landlock_abi() -> Result<i32> {
    let current_abi = detect_landlock_abi();

    match current_abi {
        abi if abi <= 0 => Err(SystemRequirementsError::LandlockUnavailable.into()),
        abi if abi < MIN_LANDLOCK_ABI => Err(SystemRequirementsError::LandlockAbiTooOld {
            found: abi,
            required: MIN_LANDLOCK_ABI,
        }
        .into()),
        abi => Ok(abi),
    }
}

/// Detect the current Landlock ABI version.
///
/// Returns 0 if Landlock is not available.
///
/// Note: the `landlock` crate does not expose a public API to query the current
/// kernel ABI directly (its internal detection uses a syscall). For now, we
/// detect availability by attempting to create a ruleset for the minimum ABI.
/// This stays within the crate’s safe, public API surface.
fn detect_landlock_abi() -> i32 {
    // The landlock crate intentionally keeps “current ABI detection” internal.
    // For Phase 0 we only need to validate that the kernel supports the minimum
    // ABI we require (v6+). We do that via the safe, public Ruleset builder API.
    //
    // If the kernel does not support Landlock (or it is disabled), `create()`
    // will fail and we treat it as unavailable.
    use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr};

    let required = ABI::V6;
    let access_all = AccessFs::from_all(required);

    let can_create = Ruleset::default()
        .handle_access(access_all)
        .and_then(|r| r.create())
        .is_ok();

    if can_create { required as i32 } else { 0 }
}

/// Check cgroups v2 is available.
///
/// Verifies that `/sys/fs/cgroup/cgroup.controllers` exists, indicating
/// cgroups v2 unified hierarchy is mounted.
///
/// # Errors
///
/// Returns error if cgroups v2 is not available.
pub fn check_cgroups_v2() -> Result<bool> {
    let controllers_path = Path::new("/sys/fs/cgroup/cgroup.controllers");

    if !controllers_path.exists() {
        return Err(SystemRequirementsError::CgroupsV2Unavailable.into());
    }

    // Verify we can read it (permissions check)
    fs::read_to_string(controllers_path).map_err(|e| SystemRequirementsError::ReadFailed {
        context: "cgroups v2 controllers file".to_string(),
        source: e,
    })?;

    Ok(true)
}

/// Check unprivileged user namespaces are enabled.
///
/// Reads `/proc/sys/kernel/unprivileged_userns_clone` if it exists.
/// On some systems (Ubuntu), this file doesn't exist and user namespaces
/// are always enabled, so we fall back to actually testing the capability.
///
/// # Errors
///
/// Returns error if user namespaces are disabled.
pub fn check_user_namespaces() -> Result<bool> {
    let userns_path = Path::new("/proc/sys/kernel/unprivileged_userns_clone");

    // If the file doesn't exist, user namespaces are assumed to be available
    // (this is the case on Ubuntu and some other distros)
    if !userns_path.exists() {
        // Try to actually create a user namespace to verify
        return verify_userns_by_clone();
    }

    let content =
        fs::read_to_string(userns_path).map_err(|e| SystemRequirementsError::ReadFailed {
            context: "unprivileged_userns_clone".to_string(),
            source: e,
        })?;

    let value = content.trim().parse::<u32>().unwrap_or(0);

    if value != 1 {
        return Err(SystemRequirementsError::UserNamespacesDisabled.into());
    }

    Ok(true)
}

/// Verify user namespaces by attempting to clone with CLONE_NEWUSER.
fn verify_userns_by_clone() -> Result<bool> {
    use nix::sched::{CloneFlags, unshare};

    // Fork a child to test user namespace creation
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            // Wait for child
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, 0)) => Ok(true),
                _ => Err(SystemRequirementsError::UserNamespacesDisabled.into()),
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            // Try to create a user namespace
            let result = unshare(CloneFlags::CLONE_NEWUSER);
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        Err(_) => Err(SystemRequirementsError::ReadFailed {
            context: "fork for userns test".to_string(),
            source: std::io::Error::last_os_error(),
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version_standard() {
        let (major, minor) = parse_kernel_version("6.7.0").expect("should parse");
        assert_eq!(major, 6);
        assert_eq!(minor, 7);
    }

    #[test]
    fn test_parse_kernel_version_with_suffix() {
        let (major, minor) = parse_kernel_version("6.8.0-generic").expect("should parse");
        assert_eq!(major, 6);
        assert_eq!(minor, 8);
    }

    #[test]
    fn test_parse_kernel_version_ubuntu_style() {
        let (major, minor) = parse_kernel_version("6.7.0-8-generic").expect("should parse");
        assert_eq!(major, 6);
        assert_eq!(minor, 7);
    }

    #[test]
    fn test_parse_kernel_version_old() {
        let (major, minor) = parse_kernel_version("5.15.0-generic").expect("should parse");
        assert_eq!(major, 5);
        assert_eq!(minor, 15);
    }

    #[test]
    fn test_check_kernel_version_real() {
        let result = check_kernel_version();
        // On a 6.7+ kernel, this should succeed
        assert!(result.is_ok(), "Kernel check failed: {result:?}");
        let (version, major, minor) = result.expect("already checked is_ok");
        assert!(
            major > 6 || (major == 6 && minor >= 7),
            "Kernel {version} is too old"
        );
    }

    #[test]
    fn test_check_architecture_real() {
        let result = check_architecture();
        assert!(result.is_ok(), "Architecture check failed: {result:?}");
        assert_eq!(result.expect("already checked is_ok"), "x86_64");
    }

    #[test]
    fn test_check_landlock_abi_real() {
        let result = check_landlock_abi();
        assert!(result.is_ok(), "Landlock check failed: {result:?}");
        assert!(
            result.expect("already checked is_ok") >= MIN_LANDLOCK_ABI,
            "Landlock ABI too old"
        );
    }

    #[test]
    fn test_check_cgroups_v2_real() {
        let result = check_cgroups_v2();
        assert!(result.is_ok(), "cgroups v2 check failed: {result:?}");
    }

    #[test]
    fn test_check_user_namespaces_real() {
        let result = check_user_namespaces();
        assert!(result.is_ok(), "User namespaces check failed: {result:?}");
    }

    #[test]
    fn test_check_all_real() {
        let result = check_all();
        assert!(
            result.is_ok(),
            "System requirements check failed: {result:?}"
        );
        let reqs = result.expect("already checked is_ok");
        assert!(
            reqs.is_satisfied(),
            "System requirements not satisfied: {reqs:?}"
        );
    }
}
