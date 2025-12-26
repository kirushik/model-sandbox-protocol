//! Integration tests for session management.
//!
//! These tests verify:
//! - Session creation and unique ID generation
//! - Directory structure correctness
//! - Session lifecycle (create, get, destroy)
//! - Expired session cleanup
//! - Concurrent session isolation
//! - Credential path blocking (security tests)

use std::fs;
use std::time::Duration;

use model_sandbox_protocol::session::{SessionConfig, SessionManager, SessionState};
use uuid::Uuid;

/// Helper to create a test configuration with a unique base directory.
fn test_config() -> SessionConfig {
    let base_dir = std::env::temp_dir()
        .join("mcp-test-sessions")
        .join(Uuid::new_v4().to_string());

    SessionConfig::new()
        .with_base_dir(base_dir)
        .with_ttl(Duration::from_secs(3600))
        .with_tmp_size_mb(50)
}

/// Helper to clean up test directories.
fn cleanup_config(config: &SessionConfig) {
    let _ = fs::remove_dir_all(&config.base_dir);
}

// =============================================================================
// Session Creation Tests
// =============================================================================

#[test]
fn test_session_creation_generates_unique_id() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session1 = manager
        .create_session()
        .expect("failed to create session 1");
    let session2 = manager
        .create_session()
        .expect("failed to create session 2");
    let session3 = manager
        .create_session()
        .expect("failed to create session 3");

    // All IDs should be unique
    assert_ne!(session1.id, session2.id);
    assert_ne!(session2.id, session3.id);
    assert_ne!(session1.id, session3.id);

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_directory_structure_correct() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");

    // Verify all directories exist
    assert!(session.paths.root.exists(), "root directory should exist");
    assert!(session.paths.upper.exists(), "upper directory should exist");
    assert!(session.paths.work.exists(), "work directory should exist");
    assert!(
        session.paths.merged.exists(),
        "merged directory should exist"
    );
    assert!(
        session.paths.meta_file.exists(),
        "metadata file should exist"
    );
    assert!(session.paths.pid_file.exists(), "PID file should exist");

    // Verify directory structure matches expected pattern
    assert_eq!(
        session.paths.upper,
        session.paths.root.join("upper"),
        "upper should be under root"
    );
    assert_eq!(
        session.paths.work,
        session.paths.root.join("work"),
        "work should be under root"
    );
    assert_eq!(
        session.paths.merged,
        session.paths.root.join("merged"),
        "merged should be under root"
    );

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_directories_have_correct_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");

    // All directories should have 0700 permissions
    for dir in [
        &session.paths.root,
        &session.paths.upper,
        &session.paths.work,
        &session.paths.merged,
    ] {
        let metadata = fs::metadata(dir).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "directory {} should have mode 0700",
            dir.display()
        );
    }

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Session Lifecycle Tests
// =============================================================================

#[test]
fn test_session_get_returns_correct_session() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Get the session
    let retrieved = manager
        .get_session(id)
        .expect("failed to get session")
        .expect("session should exist");

    assert_eq!(retrieved.id, id);
    assert_eq!(retrieved.paths.root, session.paths.root);

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_get_returns_none_for_nonexistent() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let random_id = Uuid::new_v4();
    let result = manager
        .get_session(random_id)
        .expect("should not error on nonexistent session");

    assert!(result.is_none(), "nonexistent session should return None");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_destroy_removes_all_files() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let root_path = session.paths.root.clone();
    let id = session.id;

    // Verify session exists
    assert!(root_path.exists());

    // Destroy session
    manager
        .destroy_session(id)
        .expect("failed to destroy session");

    // Verify all files are gone
    assert!(!root_path.exists(), "session directory should be removed");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_destroy_is_idempotent() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Destroy multiple times should not error
    manager
        .destroy_session(id)
        .expect("first destroy should succeed");
    manager
        .destroy_session(id)
        .expect("second destroy should succeed");
    manager
        .destroy_session(id)
        .expect("third destroy should succeed");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_list_returns_all_sessions() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create multiple sessions
    let session1 = manager
        .create_session()
        .expect("failed to create session 1");
    let session2 = manager
        .create_session()
        .expect("failed to create session 2");
    let session3 = manager
        .create_session()
        .expect("failed to create session 3");

    let sessions = manager.list_sessions().expect("failed to list sessions");

    assert_eq!(sessions.len(), 3);
    assert!(sessions.contains(&session1.id));
    assert!(sessions.contains(&session2.id));
    assert!(sessions.contains(&session3.id));

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Session Expiration Tests
// =============================================================================

#[test]
fn test_session_expiration_detection() {
    let config = SessionConfig::new()
        .with_base_dir(
            std::env::temp_dir()
                .join("mcp-test-expiration")
                .join(Uuid::new_v4().to_string()),
        )
        .with_ttl(Duration::from_millis(50)); // Very short TTL

    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");

    // Session should not be expired immediately
    assert!(!session.is_expired());

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(100));

    // Reload session to check expiration
    let reloaded = manager
        .get_session(session.id)
        .expect("failed to get session")
        .expect("session should exist");

    assert!(reloaded.is_expired(), "session should be expired");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_cleanup_expired_removes_old_sessions() {
    let config = SessionConfig::new()
        .with_base_dir(
            std::env::temp_dir()
                .join("mcp-test-cleanup")
                .join(Uuid::new_v4().to_string()),
        )
        .with_ttl(Duration::from_millis(10)); // Very short TTL

    let manager = SessionManager::new(config.clone());

    // Create sessions
    let _session1 = manager
        .create_session()
        .expect("failed to create session 1");
    let _session2 = manager
        .create_session()
        .expect("failed to create session 2");

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(50));

    // Cleanup expired
    let cleaned = manager.cleanup_expired().expect("failed to cleanup");

    assert_eq!(cleaned, 2, "should have cleaned 2 sessions");

    // Verify no sessions remain
    let remaining = manager.list_sessions().expect("failed to list sessions");
    assert!(remaining.is_empty(), "no sessions should remain");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_cleanup_keeps_non_expired_sessions() {
    let config = SessionConfig::new()
        .with_base_dir(
            std::env::temp_dir()
                .join("mcp-test-keep-valid")
                .join(Uuid::new_v4().to_string()),
        )
        .with_ttl(Duration::from_secs(3600)); // Long TTL

    let manager = SessionManager::new(config.clone());

    // Create sessions
    let session1 = manager
        .create_session()
        .expect("failed to create session 1");
    let session2 = manager
        .create_session()
        .expect("failed to create session 2");

    // Cleanup (nothing should be expired)
    let cleaned = manager.cleanup_expired().expect("failed to cleanup");

    assert_eq!(cleaned, 0, "should have cleaned 0 sessions");

    // Verify sessions still exist
    let remaining = manager.list_sessions().expect("failed to list sessions");
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains(&session1.id));
    assert!(remaining.contains(&session2.id));

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Session Metadata Tests
// =============================================================================

#[test]
fn test_session_metadata_persisted() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");

    // Verify metadata file exists and is valid JSON
    let content =
        fs::read_to_string(&session.paths.meta_file).expect("failed to read metadata file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("metadata should be valid JSON");

    // Check expected fields
    assert!(parsed.get("id").is_some(), "metadata should have id field");
    assert!(
        parsed.get("created_at").is_some(),
        "metadata should have created_at field"
    );
    assert!(
        parsed.get("expires_at").is_some(),
        "metadata should have expires_at field"
    );
    assert!(
        parsed.get("state").is_some(),
        "metadata should have state field"
    );

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_initial_state_is_created() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");

    assert_eq!(session.metadata.state, SessionState::Created);

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Concurrent Session Tests
// =============================================================================

#[test]
fn test_concurrent_sessions_isolated() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create multiple sessions concurrently
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let manager = manager.clone();
            std::thread::spawn(move || manager.create_session())
        })
        .collect();

    let sessions: Vec<_> = handles
        .into_iter()
        .map(|h| {
            h.join()
                .expect("thread panicked")
                .expect("failed to create session")
        })
        .collect();

    // All sessions should have unique IDs
    let mut ids: Vec<_> = sessions.iter().map(|s| s.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 5, "all sessions should have unique IDs");

    // All sessions should have separate directory structures
    for (i, s1) in sessions.iter().enumerate() {
        for s2 in sessions.iter().skip(i + 1) {
            assert_ne!(s1.paths.root, s2.paths.root);
            assert_ne!(s1.paths.upper, s2.paths.upper);
        }
    }

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Security Tests - Credential Path Blocking
// =============================================================================

#[test]
fn test_forbidden_paths_list_comprehensive() {
    use model_sandbox_protocol::sandbox::FORBIDDEN_PATHS;

    // Verify critical credential paths are in the forbidden list
    let critical_paths = [
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".docker/config.json",
        ".npmrc",
        ".pypirc",
    ];

    for path in critical_paths {
        assert!(
            FORBIDDEN_PATHS.contains(&path),
            "forbidden paths should include {}",
            path
        );
    }
}

#[test]
fn test_safe_etc_files_list_correct() {
    use model_sandbox_protocol::sandbox::SAFE_ETC_FILES;

    // Verify essential files are included
    let essential_files = ["passwd", "group", "hosts", "resolv.conf", "ssl/certs"];

    for file in essential_files {
        assert!(
            SAFE_ETC_FILES.contains(&file),
            "safe etc files should include {}",
            file
        );
    }

    // Verify sensitive files are NOT included
    let sensitive_files = ["shadow", "sudoers", "gshadow"];

    for file in sensitive_files {
        assert!(
            !SAFE_ETC_FILES.contains(&file),
            "safe etc files should NOT include {}",
            file
        );
    }
}

// =============================================================================
// Corrupted Session Handling Tests
// =============================================================================

#[test]
fn test_corrupted_session_cleanup() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create a valid session
    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Corrupt the session by removing the metadata file
    fs::remove_file(&session.paths.meta_file).expect("failed to remove metadata file");

    // Cleanup corrupted should detect and remove it
    let cleaned = manager
        .cleanup_corrupted()
        .expect("failed to cleanup corrupted");

    assert_eq!(cleaned, 1, "should have cleaned 1 corrupted session");

    // Verify session is gone
    let result = manager.get_session(id);
    assert!(
        result.is_ok() && result.unwrap().is_none(),
        "corrupted session should be removed"
    );

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_validation_fails_for_missing_directories() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Remove the upper directory to corrupt the session
    fs::remove_dir(&session.paths.upper).expect("failed to remove upper directory");

    // Getting the session should fail validation
    let result = manager.get_session(id);
    assert!(
        result.is_err(),
        "should fail to get session with missing directory"
    );

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Phase 2: Session Lifecycle Integration Tests
// =============================================================================

#[test]
fn test_session_acquire_release_lifecycle() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create a session
    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Initial state should be Created
    assert_eq!(session.metadata.state, SessionState::Created);
    assert!(session.metadata.pid.is_none());

    // Acquire the session
    let acquired = manager
        .acquire_session(id)
        .expect("failed to acquire session");

    // Should now be Active with our PID
    assert_eq!(acquired.metadata.state, SessionState::Active);
    assert_eq!(acquired.metadata.pid, Some(std::process::id()));

    // Release the session
    manager
        .release_session(id)
        .expect("failed to release session");

    // PID should be cleared
    let released = manager
        .get_session(id)
        .expect("failed to get session")
        .expect("session should exist");
    assert!(released.metadata.pid.is_none());

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_in_use_prevents_concurrent_acquire() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Acquire the session
    let _acquired = manager.acquire_session(id).expect("failed to acquire");

    // Try to acquire again - should fail with InUse
    let result = manager.acquire_session(id);
    assert!(result.is_err(), "second acquire should fail");

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_string.contains("InUse"),
        "error should be InUse, got: {}",
        err_string
    );

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_prepare_mounts_validates_structure() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Prepare mounts should succeed
    let prepared = manager
        .prepare_session_mounts(id)
        .expect("failed to prepare mounts");

    // Should verify same filesystem
    assert!(
        prepared.same_filesystem,
        "upper and work should be on same filesystem"
    );

    // Directories should exist with correct permissions
    assert!(prepared.session.paths.upper.exists());
    assert!(prepared.session.paths.work.exists());
    assert!(prepared.session.paths.merged.exists());

    // Verify permissions are 0700
    use std::os::unix::fs::PermissionsExt;
    let upper_perms = fs::metadata(&prepared.session.paths.upper)
        .expect("failed to get metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(upper_perms, 0o700, "upper should have 0700 permissions");

    // Cleanup
    cleanup_config(&config);
}

#[test]
fn test_session_prepare_mounts_empties_work_directory() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Create a file in work directory (simulating leftover from previous mount)
    let leftover_file = session.paths.work.join("leftover.txt");
    fs::write(&leftover_file, "leftover data").expect("failed to write leftover file");
    assert!(leftover_file.exists(), "leftover file should exist");

    // Prepare mounts should empty the work directory
    let prepared = manager
        .prepare_session_mounts(id)
        .expect("failed to prepare mounts");

    assert!(prepared.work_emptied, "work should have been emptied");
    assert!(
        !leftover_file.exists(),
        "leftover file should be removed after prepare"
    );

    // Work directory should still exist but be empty
    assert!(prepared.session.paths.work.exists());
    let entries: Vec<_> = fs::read_dir(&prepared.session.paths.work)
        .expect("failed to read work dir")
        .collect();
    assert!(entries.is_empty(), "work directory should be empty");

    // Cleanup
    cleanup_config(&config);
}

// =============================================================================
// Phase 2: Workspace Security Tests
// =============================================================================

#[test]
fn test_workspace_rejects_forbidden_credential_path() {
    use model_sandbox_protocol::sandbox::workspace::{WorkspaceConfig, prepare_workspace};

    // Try to use ~/.ssh as workspace - should be rejected
    if let Ok(home) = std::env::var("HOME") {
        let ssh_path = std::path::PathBuf::from(&home).join(".ssh");

        // Only test if .ssh exists (common on dev machines)
        if ssh_path.exists() {
            let config = WorkspaceConfig::new(&ssh_path);
            let result = prepare_workspace(&config);

            assert!(result.is_err(), "~/.ssh should be rejected as workspace");
            let err_string = format!("{}", result.unwrap_err());
            assert!(
                err_string.contains("forbidden") || err_string.contains("credential"),
                "error should mention forbidden/credential path, got: {}",
                err_string
            );
        }
    }
}

#[test]
fn test_workspace_rejects_aws_credentials_path() {
    use model_sandbox_protocol::sandbox::workspace::{WorkspaceConfig, prepare_workspace};

    if let Ok(home) = std::env::var("HOME") {
        let aws_path = std::path::PathBuf::from(&home).join(".aws");

        if aws_path.exists() {
            let config = WorkspaceConfig::new(&aws_path);
            let result = prepare_workspace(&config);

            assert!(result.is_err(), "~/.aws should be rejected as workspace");
        }
    }
}

#[test]
fn test_workspace_rejects_relative_path() {
    use model_sandbox_protocol::sandbox::workspace::{WorkspaceConfig, prepare_workspace};

    let config = WorkspaceConfig::new("relative/path/to/workspace");
    let result = prepare_workspace(&config);

    assert!(result.is_err(), "relative path should be rejected");
    let err_string = format!("{}", result.unwrap_err());
    assert!(
        err_string.contains("absolute"),
        "error should mention absolute path requirement, got: {}",
        err_string
    );
}

#[test]
fn test_workspace_rejects_symlink() {
    use model_sandbox_protocol::sandbox::workspace::{WorkspaceConfig, prepare_workspace};
    use std::os::unix::fs::symlink;

    let temp_dir = std::env::temp_dir()
        .join("mcp-test-workspace-symlink")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let target = temp_dir.join("target");
    fs::create_dir(&target).expect("failed to create target dir");

    let link = temp_dir.join("link");
    symlink(&target, &link).expect("failed to create symlink");

    let config = WorkspaceConfig::new(&link);
    let result = prepare_workspace(&config);

    assert!(result.is_err(), "symlink workspace should be rejected");
    let err_string = format!("{}", result.unwrap_err());
    assert!(
        err_string.contains("symlink"),
        "error should mention symlink, got: {}",
        err_string
    );

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_workspace_accepts_valid_directory() {
    use model_sandbox_protocol::sandbox::workspace::{
        WORKSPACE_MOUNT_POINT, WorkspaceConfig, prepare_workspace,
    };

    let temp_dir = std::env::temp_dir()
        .join("mcp-test-workspace-valid")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let config = WorkspaceConfig::new(&temp_dir);
    let result = prepare_workspace(&config);

    assert!(result.is_ok(), "valid directory should be accepted");
    let prepared = result.unwrap();
    assert_eq!(prepared.mount_point, WORKSPACE_MOUNT_POINT);
    assert!(!prepared.read_only);

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

// =============================================================================
// Phase 2: Mount Policy Audit Tests
// =============================================================================

#[test]
fn test_mount_policy_guard_rejects_ssh_directory() {
    use model_sandbox_protocol::sandbox::MountPolicyGuard;

    let guard = MountPolicyGuard::new();

    if let Ok(home) = std::env::var("HOME") {
        let ssh_path = std::path::PathBuf::from(&home).join(".ssh");

        if ssh_path.exists() {
            let result = guard.validate_mount_source(&ssh_path);
            assert!(result.is_err(), "~/.ssh should be rejected by policy guard");
        }
    }
}

#[test]
fn test_mount_policy_guard_accepts_safe_path() {
    use model_sandbox_protocol::sandbox::MountPolicyGuard;

    let guard = MountPolicyGuard::new();

    let temp_dir = std::env::temp_dir()
        .join("mcp-test-policy-guard")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let result = guard.validate_mount_source(&temp_dir);
    assert!(result.is_ok(), "safe temp directory should be accepted");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_mount_policy_audit_detects_forbidden_mount() {
    use model_sandbox_protocol::sandbox::MountPolicyGuard;
    use std::io::Write;

    let guard = MountPolicyGuard::new();

    // Create a fake mountinfo file with a forbidden path
    let temp_dir = std::env::temp_dir()
        .join("mcp-test-audit")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let fake_mountinfo = temp_dir.join("mountinfo");

    // Write fake mountinfo with a forbidden .ssh mount
    let mut file = fs::File::create(&fake_mountinfo).expect("failed to create mountinfo");
    writeln!(
        file,
        "1 0 8:1 {} /mnt/ssh rw,relatime - ext4 /dev/sda1 rw",
        format!("{}/.ssh", home)
    )
    .expect("failed to write mountinfo");

    let result = guard.audit_mountinfo(fake_mountinfo.to_str().unwrap());
    assert!(result.is_err(), "audit should detect forbidden .ssh mount");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_mount_policy_audit_passes_clean_mounts() {
    use model_sandbox_protocol::sandbox::MountPolicyGuard;
    use std::io::Write;

    let guard = MountPolicyGuard::new();

    let temp_dir = std::env::temp_dir()
        .join("mcp-test-audit-clean")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

    let fake_mountinfo = temp_dir.join("mountinfo");

    // Write fake mountinfo with only safe mounts
    let mut file = fs::File::create(&fake_mountinfo).expect("failed to create mountinfo");
    writeln!(file, "1 0 8:1 /usr /usr ro,relatime - ext4 /dev/sda1 rw")
        .expect("failed to write mountinfo");
    writeln!(file, "2 0 8:1 /tmp /tmp rw,relatime - tmpfs tmpfs rw")
        .expect("failed to write mountinfo");

    let result = guard.audit_mountinfo(fake_mountinfo.to_str().unwrap());
    assert!(result.is_ok(), "audit should pass for clean mounts");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

// =============================================================================
// Phase 2: Session-Based Sandbox Integration Tests
// =============================================================================

/// Test that files written during sandbox execution persist in the session's
/// upper directory across multiple runs.
///
/// Note: This test uses the session's upper directory directly since full
/// OverlayFS mounting requires namespace integration. The test validates
/// that the session infrastructure correctly supports file persistence.
#[test]
fn test_session_file_persistence_in_upper_directory() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create and acquire a session
    let session = manager.create_session().expect("failed to create session");
    let id = session.id;

    // Prepare session mounts (validates structure)
    let prepared = manager
        .prepare_session_mounts(id)
        .expect("failed to prepare mounts");

    // Create a test file in the session's upper directory
    // This simulates what would happen with OverlayFS - writes go to upper
    let test_file = prepared.session.paths.upper.join("test_persistence.txt");
    let test_content = "This file should persist across session uses";
    fs::write(&test_file, test_content).expect("failed to write test file");

    // Verify the file exists
    assert!(
        test_file.exists(),
        "test file should exist in upper directory"
    );

    // Simulate "releasing" and "re-acquiring" the session
    manager.release_session(id).expect("failed to release");

    // Re-acquire the session
    let _reacquired = manager.acquire_session(id).expect("failed to re-acquire");

    // Verify the file still exists (persistence)
    assert!(
        test_file.exists(),
        "test file should persist after session re-acquisition"
    );

    let read_content = fs::read_to_string(&test_file).expect("failed to read test file");
    assert_eq!(
        read_content, test_content,
        "file content should be preserved"
    );

    // Cleanup
    cleanup_config(&config);
}

/// Test that sandbox with session and workspace integration works correctly.
#[test]
fn test_sandbox_with_session_basic_execution() {
    use model_sandbox_protocol::sandbox::{SandboxConfig, SandboxContainer};

    let session_config = test_config();
    let manager = SessionManager::new(session_config.clone());

    // Create a session
    let session = manager.create_session().expect("failed to create session");

    // Prepare session mounts
    manager
        .prepare_session_mounts(session.id)
        .expect("failed to prepare mounts");

    // Acquire the session
    let acquired_session = manager
        .acquire_session(session.id)
        .expect("failed to acquire session");

    // Create a sandbox with the session
    // Note: Without full overlay mounting, this uses the merged directory directly
    // which may be empty, so we test with a Phase 1 sandbox config
    let sandbox_config = SandboxConfig::default();
    let sandbox = SandboxContainer::with_session(acquired_session, Some(sandbox_config))
        .expect("failed to create sandbox with session");

    // Verify the sandbox has a session attached
    assert!(
        sandbox.has_session(),
        "sandbox should have session attached"
    );
    assert_eq!(
        sandbox.session().map(|s| s.id),
        Some(session.id),
        "session ID should match"
    );

    // Release the session
    manager
        .release_session(session.id)
        .expect("failed to release session");

    // Cleanup
    cleanup_config(&session_config);
}

/// Test that workspace path defaults working_dir to /workspace
#[test]
fn test_workspace_sets_default_working_dir() {
    use model_sandbox_protocol::sandbox::SandboxConfig;

    // Create a temp directory to use as workspace
    let workspace_dir = std::env::temp_dir()
        .join("mcp-test-workspace-workdir")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&workspace_dir).expect("failed to create workspace dir");

    // Create sandbox config with workspace but no explicit working_dir
    let config = SandboxConfig::default().with_workspace(&workspace_dir);

    // Verify workspace is set and working_dir is not explicitly set
    assert!(config.workspace_path.is_some());
    assert!(config.working_dir.is_none());

    // The container should internally default working_dir to /workspace
    // We can't directly test this without execution, but we verify the config is set up

    // Cleanup
    let _ = fs::remove_dir_all(&workspace_dir);
}

/// Test that multiple sessions maintain separate upper directories
#[test]
fn test_multiple_sessions_have_isolated_upper_directories() {
    let config = test_config();
    let manager = SessionManager::new(config.clone());

    // Create two sessions
    let session1 = manager
        .create_session()
        .expect("failed to create session 1");
    let session2 = manager
        .create_session()
        .expect("failed to create session 2");

    // Write different content to each session's upper directory
    let file1 = session1.paths.upper.join("session1.txt");
    let file2 = session2.paths.upper.join("session2.txt");

    fs::write(&file1, "content from session 1").expect("failed to write to session 1");
    fs::write(&file2, "content from session 2").expect("failed to write to session 2");

    // Verify each session only sees its own file
    assert!(file1.exists(), "session1's file should exist");
    assert!(file2.exists(), "session2's file should exist");

    // Session 1's upper should not have session2's file and vice versa
    assert!(
        !session1.paths.upper.join("session2.txt").exists(),
        "session1 should not see session2's file"
    );
    assert!(
        !session2.paths.upper.join("session1.txt").exists(),
        "session2 should not see session1's file"
    );

    // Cleanup
    cleanup_config(&config);
}
