//! Integration tests for Phase 3 MCP tools (server-side helpers + basic flows).
//!
//! These tests intentionally focus on the server layer's public API surface
//! (tool request/response structs + helper functions), plus a minimal
//! end-to-end-ish flow by calling the server methods directly.
//!
//! Note: We do NOT spin up stdio JSON-RPC transport here. That's covered by
//! rmcp itself; our responsibility is tool semantics and integration with
//! SessionManager/SandboxContainer.
//!
//! Important: These tests require a Linux environment that satisfies project
//! system requirements (user namespaces, etc.) for the execute flow.

use std::time::Duration;

use model_sandbox_protocol::server::SandboxServer;
use model_sandbox_protocol::server::{
    CreateParams, DestroyParams, ExecuteParams, ReadFileParams, WriteFileParams, WriteStrategy,
    parse_session_id, resolve_session_path,
};
use rmcp::handler::server::wrapper::Parameters;

fn make_server() -> SandboxServer {
    // Use defaults; these tests should not assume a particular base_dir on disk,
    // only that session creation works.
    SandboxServer::with_defaults()
}

#[test]
fn test_parse_session_id_roundtrip() {
    let id = uuid::Uuid::new_v4();
    let parsed = parse_session_id(&id.to_string()).expect("should parse UUID string");
    assert_eq!(parsed, id);
}

#[tokio::test]
async fn test_create_list_destroy_basic_flow() {
    let server = make_server();

    // Create a session with a short TTL override (just to exercise the field).
    let create = server
        .sandbox_create(Parameters(CreateParams {
            name: Some("mcp-tools-test".to_string()),
            workspace_path: None,
            timeout_seconds: Some(30),
        }))
        .await
        .expect("sandbox_create should succeed")
        .0; // Unwrap Json wrapper

    let session_id = parse_session_id(&create.session_id).expect("created session id should parse");

    // list should include our session (best-effort: may include others too)
    let list = server
        .sandbox_list()
        .await
        .expect("sandbox_list should succeed")
        .0; // Unwrap Json wrapper

    assert!(
        list.sessions
            .iter()
            .any(|s| s.session_id == create.session_id),
        "sandbox_list should include created session_id"
    );

    // destroy should succeed
    let destroy = server
        .sandbox_destroy(Parameters(DestroyParams {
            session_id: create.session_id.clone(),
        }))
        .await
        .expect("sandbox_destroy should succeed")
        .0; // Unwrap Json wrapper

    assert!(destroy.success);
    assert_eq!(destroy.session_id, session_id.to_string());

    // second destroy should be idempotent-ish at tool level (SessionManager destroy is idempotent)
    let destroy2 = server
        .sandbox_destroy(Parameters(DestroyParams {
            session_id: create.session_id.clone(),
        }))
        .await
        .expect("sandbox_destroy should be idempotent")
        .0; // Unwrap Json wrapper

    assert!(destroy2.success);
}

#[tokio::test]
async fn test_write_then_read_file_in_session_upper() {
    let server = make_server();

    let create = server
        .sandbox_create(Parameters(CreateParams {
            name: None,
            workspace_path: None,
            timeout_seconds: Some(60),
        }))
        .await
        .expect("sandbox_create should succeed")
        .0; // Unwrap Json wrapper

    let session_id = create.session_id.clone();

    // Write a file under the session's upper layer path semantics.
    let write = server
        .sandbox_write_file(Parameters(WriteFileParams {
            session_id: session_id.clone(),
            path: "notes/hello.txt".to_string(),
            content: "hello world".to_string(),
        }))
        .await
        .expect("sandbox_write_file should succeed")
        .0; // Unwrap Json wrapper

    assert!(write.success);
    assert_eq!(write.bytes_written, "hello world".as_bytes().len());
    assert_eq!(write.path, "notes/hello.txt");

    // Read it back (sandbox_read_file returns String, not Json<T>).
    let read = server
        .sandbox_read_file(Parameters(ReadFileParams {
            session_id: session_id.clone(),
            path: "notes/hello.txt".to_string(),
        }))
        .await
        .expect("sandbox_read_file should succeed");

    assert_eq!(read, "hello world");

    // Cleanup
    let _ = server
        .sandbox_destroy(Parameters(DestroyParams { session_id }))
        .await
        .expect("sandbox_destroy should succeed");
}

#[tokio::test]
async fn test_execute_echo_smoke() {
    let server = make_server();

    let create = server
        .sandbox_create(Parameters(CreateParams {
            name: None,
            workspace_path: None,
            timeout_seconds: Some(60),
        }))
        .await
        .expect("sandbox_create should succeed")
        .0; // Unwrap Json wrapper

    // Keep args empty to avoid depending on anything beyond /bin/echo.
    let exec = server
        .sandbox_execute(Parameters(ExecuteParams {
            session_id: create.session_id.clone(),
            command: "echo".to_string(),
            args: Some(vec!["hello".to_string()]),
            working_dir: None,
        }))
        .await
        .expect("sandbox_execute should succeed")
        .0; // Unwrap Json wrapper

    assert!(exec.success);
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout.trim(), "hello");

    // Cleanup
    let _ = server
        .sandbox_destroy(Parameters(DestroyParams {
            session_id: create.session_id.clone(),
        }))
        .await
        .expect("sandbox_destroy should succeed");
}

#[test]
fn test_resolve_session_path_validation() {
    // This test exercises the helper in a realistic way by creating a real session.
    let server = make_server();
    let mgr = server.session_manager();

    let session = mgr.create_session().expect("create_session should succeed");

    // Reject absolute
    assert!(resolve_session_path(&session, "/etc/passwd").is_err());

    // Reject traversal
    assert!(resolve_session_path(&session, "../secrets").is_err());

    // Accept normal path
    let p = resolve_session_path(&session, "a/b/c.txt").expect("should resolve");
    assert!(p.starts_with(&session.paths.upper));
    assert!(p.ends_with("a/b/c.txt"));

    // Cleanup
    mgr.destroy_session(session.id)
        .expect("destroy_session should succeed");
}

// A tiny sanity test: tool TTL override should affect metadata expiry.
#[tokio::test]
async fn test_create_ttl_override_affects_expires_at() {
    let server = make_server();

    let create = server
        .sandbox_create(Parameters(CreateParams {
            name: None,
            workspace_path: None,
            timeout_seconds: Some(1),
        }))
        .await
        .expect("sandbox_create should succeed")
        .0; // Unwrap Json wrapper

    let id = parse_session_id(&create.session_id).expect("parse");

    // Fetch session and ensure expires_at is close to now + 1s.
    let mgr = server.session_manager();
    let session = mgr
        .get_session(id)
        .expect("get_session should succeed")
        .expect("session should exist");

    // We just assert it's within a small window around 1s from now
    // (avoid being too strict on CI timing).
    let now = chrono::Utc::now();
    let diff = session.metadata.expires_at - now;

    assert!(
        diff.num_seconds() <= 10 && diff.num_seconds() >= -10,
        "expires_at should be near now for very short TTL override; got diff={}s",
        diff.num_seconds()
    );

    // Cleanup
    let _ = server
        .sandbox_destroy(Parameters(DestroyParams {
            session_id: create.session_id,
        }))
        .await
        .expect("sandbox_destroy should succeed");

    // Give background tasks a moment if they exist; not required but avoids flakes if running in parallel.
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_write_file_fallback_strategy() {
    // This test forces the shell fallback path (cat > "$1") which had a bug.
    let server =
        SandboxServer::with_defaults().with_write_strategy(WriteStrategy::ForceShellFallback);

    let create = server
        .sandbox_create(Parameters(CreateParams {
            name: Some("fallback-test".to_string()),
            workspace_path: None,
            timeout_seconds: Some(60),
        }))
        .await
        .expect("create")
        .0;

    let session_id = create.session_id;

    let write_res = server
        .sandbox_write_file(Parameters(WriteFileParams {
            session_id: session_id.clone(),
            path: "fallback.txt".to_string(),
            content: "fallback content".to_string(),
        }))
        .await;

    // Cleanup regardless of result
    let _ = server
        .sandbox_destroy(Parameters(DestroyParams {
            session_id: session_id.clone(),
        }))
        .await;

    let write = write_res
        .expect("write should succeed even with fallback")
        .0;
    assert!(write.success);
    assert_eq!(write.bytes_written, "fallback content".len());
}
