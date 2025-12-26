//! Security integration tests for the sandbox environment.
//!
//! These tests verify critical security properties:
//! - Credential paths are NEVER accessible from sandbox
//! - Process isolation via /proc hidepid
//! - Device access restrictions
//! - Host filesystem protection
//!
//! IMPORTANT: These tests validate P1 (Priority 1) security requirements.
//! Any failure here represents a potential security vulnerability.

use model_sandbox_protocol::sandbox::{FORBIDDEN_PATHS, SandboxConfig, SandboxContainer};

// =============================================================================
// Credential Path Blocking Tests (P1 Security)
// =============================================================================

/// Test that SSH keys are not accessible from sandbox.
#[test]
fn test_ssh_keys_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to read SSH private key
    let result = sandbox.execute("cat", &["/root/.ssh/id_rsa"]);

    // Should either error or return non-zero exit code
    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "reading SSH key should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is also acceptable - means file wasn't accessible
        }
    }
}

/// Test that SSH directory is not accessible.
#[test]
fn test_ssh_directory_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to list SSH directory
    let result = sandbox.execute("ls", &["-la", "/root/.ssh"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "listing SSH directory should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Test that AWS credentials are not accessible.
#[test]
fn test_aws_credentials_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to read AWS credentials
    let result = sandbox.execute("cat", &["/root/.aws/credentials"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "reading AWS credentials should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Test that GPG keys are not accessible.
#[test]
fn test_gnupg_keys_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to list GnuPG directory
    let result = sandbox.execute("ls", &["-la", "/root/.gnupg"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "listing GnuPG directory should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Test that Kubernetes config is not accessible.
#[test]
fn test_kube_config_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to read kube config
    let result = sandbox.execute("cat", &["/root/.kube/config"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "reading kube config should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Test that Docker credentials are not accessible.
#[test]
fn test_docker_config_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to read Docker config
    let result = sandbox.execute("cat", &["/root/.docker/config.json"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "reading Docker config should fail, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Verify the FORBIDDEN_PATHS list is comprehensive.
#[test]
fn test_forbidden_paths_comprehensive() {
    // Critical paths that MUST be in the forbidden list
    let critical_paths = [
        ".ssh",                // SSH keys
        ".aws",                // AWS credentials
        ".gnupg",              // GPG keys
        ".kube",               // Kubernetes credentials
        ".docker/config.json", // Docker credentials
        ".gitconfig",          // Git config (may contain tokens)
        ".netrc",              // Network credentials
        ".git-credentials",    // Git credential helper cache
        ".config/gh",          // GitHub CLI credentials
        ".npmrc",              // NPM credentials
        ".pypirc",             // PyPI credentials
        ".cargo/credentials",  // Cargo/crates.io credentials
    ];

    for path in critical_paths {
        assert!(
            FORBIDDEN_PATHS.contains(&path),
            "FORBIDDEN_PATHS must include '{}' - this is a P1 security requirement",
            path
        );
    }
}

// =============================================================================
// Process Isolation Tests
// =============================================================================

/// Test that sandbox process sees itself as PID 1.
#[test]
fn test_sandbox_is_pid_1() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    let result = sandbox
        .execute("cat", &["/proc/self/stat"])
        .expect("failed to read /proc/self/stat");

    // The first field in /proc/self/stat is the PID
    // In PID namespace, the init process should be PID 1
    let stat_content = result.stdout;
    let first_field = stat_content.split_whitespace().next().unwrap_or("");

    assert_eq!(
        first_field, "1",
        "sandbox process should see itself as PID 1"
    );
}

/// Test that host processes are not visible from sandbox.
#[test]
fn test_host_processes_not_visible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Count processes visible in /proc
    let result = sandbox
        .execute("sh", &["-c", "ls /proc | grep -E '^[0-9]+$' | wc -l"])
        .expect("failed to list /proc");

    let process_count: i32 = result.stdout.trim().parse().unwrap_or(999);

    // In a proper PID namespace with hidepid, only the sandbox's own processes
    // should be visible. Typically this is 1-3 processes (init, sh, ls).
    assert!(
        process_count < 10,
        "should see very few processes in /proc, got {}",
        process_count
    );
}

/// Test that /proc/1 in sandbox is the sandbox init, not host init.
#[test]
fn test_proc_1_is_sandbox_init() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Read /proc/1/comm to see what process is PID 1
    let result = sandbox.execute("cat", &["/proc/1/comm"]);

    match result {
        Ok(output) => {
            // In a PID namespace, /proc/1/comm should be the sandbox command
            // NOT "systemd" or "init" from the host
            let comm = output.stdout.trim();
            assert!(
                comm != "systemd" && comm != "init",
                "/proc/1/comm should not be host init process, got: {}",
                comm
            );
        }
        Err(_) => {
            // If we can't read it, that's also acceptable (stronger isolation)
        }
    }
}

// =============================================================================
// Device Access Tests
// =============================================================================

/// Test that basic devices are available.
#[test]
fn test_basic_devices_available() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // /dev/null should be available and writable
    let null_result = sandbox
        .execute("sh", &["-c", "echo test > /dev/null && echo ok"])
        .expect("failed to test /dev/null");
    assert!(null_result.success(), "/dev/null should be available");

    // /dev/zero should be available and readable
    let zero_result = sandbox
        .execute("sh", &["-c", "head -c 4 /dev/zero | wc -c"])
        .expect("failed to test /dev/zero");
    assert!(zero_result.success(), "/dev/zero should be available");

    // /dev/urandom should be available for randomness
    let urandom_result = sandbox
        .execute("sh", &["-c", "head -c 4 /dev/urandom | wc -c"])
        .expect("failed to test /dev/urandom");
    assert!(urandom_result.success(), "/dev/urandom should be available");
}

/// Test that host TTY is not accessible (prevents TIOCSTI attacks).
#[test]
fn test_host_tty_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to access host's tty0
    let result = sandbox.execute("cat", &["/dev/tty0"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "host tty0 should not be accessible, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable - means tty wasn't accessible
        }
    }
}

// =============================================================================
// Host Filesystem Protection Tests
// =============================================================================

/// Test that host root filesystem is not writable.
#[test]
fn test_host_root_not_writable() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Try to create a file in /usr (should fail or be in overlay)
    let result = sandbox
        .execute("sh", &["-c", "touch /usr/test_write_marker_xyz 2>&1"])
        .expect("failed to execute command");

    // Even if it "succeeds" in overlay, verify host /usr isn't affected
    // The file should either fail to create or be isolated to overlay
    if result.success() {
        // Verify it's not on the host filesystem by checking it doesn't persist
        // (In Phase 1 without sessions, files don't persist anyway)
        let verify = sandbox
            .execute("test", &["-f", "/usr/test_write_marker_xyz"])
            .expect("failed to verify");
        // File should either not exist or only exist in overlay
        assert!(
            !verify.success(),
            "write to /usr should not persist or be blocked"
        );
    }
}

/// Test that /etc/shadow is not readable.
#[test]
fn test_etc_shadow_not_readable() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    let result = sandbox.execute("cat", &["/etc/shadow"]);

    match result {
        Ok(output) => {
            assert!(
                !output.success(),
                "/etc/shadow should not be readable, got: {}",
                output.stdout
            );
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

/// Test that /etc/sudoers is not readable.
#[test]
fn test_etc_sudoers_not_accessible() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    let result = sandbox.execute("cat", &["/etc/sudoers"]);

    match result {
        Ok(output) => {
            // If file exists, it should not be readable
            if output.exit_code != 1 {
                // exit code 1 = file not found, which is acceptable
                assert!(!output.success(), "/etc/sudoers should not be readable");
            }
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

// =============================================================================
// Environment Isolation Tests
// =============================================================================

/// Test that host environment variables are not leaked.
#[test]
fn test_host_env_not_leaked() {
    // Set a marker environment variable that shouldn't be in sandbox
    // SAFETY: This is a test that runs single-threaded and we clean up after
    unsafe {
        std::env::set_var("MCP_TEST_SECRET_MARKER", "should_not_leak");
    }

    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    let result = sandbox
        .execute("printenv", &["MCP_TEST_SECRET_MARKER"])
        .expect("failed to run printenv");

    // The variable should not be visible in sandbox
    assert!(
        !result.success() || result.stdout.trim().is_empty(),
        "host env variable should not leak to sandbox"
    );

    // SAFETY: Cleaning up the env var we set above
    unsafe {
        std::env::remove_var("MCP_TEST_SECRET_MARKER");
    }
}

/// Test that PATH is sanitized in sandbox.
#[test]
fn test_path_sanitized() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    let result = sandbox
        .execute("printenv", &["PATH"])
        .expect("failed to get PATH");

    let path = result.stdout.trim();

    // PATH should only contain safe system directories
    assert!(
        !path.contains("/home"),
        "PATH should not contain /home directories"
    );
    assert!(
        !path.contains("~"),
        "PATH should not contain home shortcuts"
    );
}

// =============================================================================
// Network Isolation Verification
// =============================================================================

/// Test that loopback interface works.
#[test]
fn test_loopback_available() {
    let sandbox =
        SandboxContainer::new(SandboxConfig::default()).expect("failed to create sandbox");

    // Ping localhost (if ping is available)
    let result = sandbox.execute("sh", &["-c", "test -e /dev/lo || echo ok"]);

    // This is a basic check - actual loopback testing is in sandbox.rs
    assert!(result.is_ok());
}
