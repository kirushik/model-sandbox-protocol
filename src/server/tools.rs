#![allow(clippy::module_name_repetitions)]
//! MCP tool parameter/result types and helper utilities.
//!
//! This module defines the request/response payloads for Phase 3 MCP tools plus
//! shared helpers for:
//! - mapping internal errors to MCP JSON-RPC errors
//! - parsing session IDs
//! - safely resolving user-supplied paths within a session/workspace
//!
//! See `PHASE3_EXECUTION_PLAN.md` for the expected behavior.

use std::path::{Component, Path, PathBuf};

use rmcp::ErrorData as McpError;
use rmcp::schemars;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{MountError, SandboxError, SessionError};
use crate::session::Session;

/// Maximum file size for read operations (10 MB).
pub const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;

// ===============================
// Tool parameter structs
// ===============================

/// Parameters for the `sandbox_create` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateParams {
    /// Optional human-readable name for logging/debugging.
    #[schemars(description = "Optional human-readable name for the session")]
    pub name: Option<String>,

    /// Host directory to mount as `/workspace` in the sandbox.
    ///
    /// Must be an absolute path when provided.
    #[schemars(description = "Absolute path to host directory to mount as /workspace")]
    pub workspace_path: Option<String>,

    /// Session TTL in seconds (default: 3600).
    ///
    /// NOTE: This is about session lifetime (storage TTL), not per-command timeout.
    #[schemars(description = "Session time-to-live in seconds (default: 3600)")]
    pub timeout_seconds: Option<u32>,
}

/// Parameters for the `sandbox_execute` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteParams {
    /// Session ID returned by `sandbox_create`.
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    /// Command to execute (e.g. `python`, `cargo`).
    #[schemars(description = "Command to execute")]
    pub command: String,

    /// Arguments to pass to the command.
    #[schemars(description = "Command arguments as array")]
    pub args: Option<Vec<String>>,

    /// Working directory inside sandbox.
    ///
    /// Default behavior:
    /// - `/workspace` when workspace is mounted
    /// - `/` otherwise
    #[schemars(description = "Working directory inside sandbox")]
    pub working_dir: Option<String>,
}

/// Parameters for the `sandbox_read_file` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFileParams {
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    /// File path relative to the workspace root (or `/` if no workspace).
    #[schemars(description = "File path relative to workspace root")]
    pub path: String,
}

/// Parameters for the `sandbox_write_file` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteFileParams {
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    /// File path relative to the workspace root (or `/` if no workspace).
    #[schemars(description = "File path relative to workspace root")]
    pub path: String,

    /// File content to write.
    #[schemars(description = "File content to write")]
    pub content: String,
}

/// Parameters for the `sandbox_destroy` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DestroyParams {
    #[schemars(description = "Session ID to destroy")]
    pub session_id: String,
}

// ===============================
// Tool result structs
// ===============================

/// Result returned by `sandbox_create`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CreateResult {
    pub session_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub workspace_mounted: bool,
    pub workspace_path: Option<String>,
}

/// Result returned by `sandbox_execute`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecuteResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
    pub timed_out: bool,
}

/// Result returned by `sandbox_write_file`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct WriteFileResult {
    pub success: bool,
    pub bytes_written: usize,
    pub path: String,
}

/// Session info entry for `sandbox_list`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub state: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_expired: bool,
    pub has_workspace: bool,
}

/// Result returned by `sandbox_list`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListResult {
    pub sessions: Vec<SessionInfo>,
    pub total: usize,
}

/// Result returned by `sandbox_destroy`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct DestroyResult {
    pub success: bool,
    pub session_id: String,
}

// ===============================
// Error mapping helpers
// ===============================

/// Convert `SessionError` to an MCP JSON-RPC error payload.
///
/// Mapping notes:
/// - `NotFound` / `Expired` are treated as invalid parameters
/// - `InUse` and internal corruption are treated as internal errors
pub fn session_error_to_mcp(e: SessionError) -> McpError {
    match e {
        SessionError::NotFound { id } => {
            McpError::invalid_params(format!("Session not found: {id}"), None)
        }
        SessionError::Expired { id } => {
            McpError::invalid_params(format!("Session expired: {id}"), None)
        }
        SessionError::InUse { id } => {
            McpError::internal_error(format!("Session in use: {id}"), None)
        }
        SessionError::InvalidSession { reason } => {
            McpError::internal_error(format!("Invalid session: {reason}"), None)
        }
        SessionError::IoError { context, .. } => {
            McpError::internal_error(format!("I/O error: {context}"), None)
        }
        SessionError::AlreadyExists { id } => {
            McpError::internal_error(format!("Session already exists: {id}"), None)
        }
    }
}

/// Convert `SandboxError` to an MCP JSON-RPC error payload.
pub fn sandbox_error_to_mcp(e: SandboxError) -> McpError {
    match e {
        SandboxError::InvalidCommand(msg) => {
            McpError::invalid_params(format!("Invalid command: {msg}"), None)
        }
        SandboxError::Timeout { timeout_seconds } => {
            McpError::internal_error(format!("Timeout after {timeout_seconds}s"), None)
        }
        SandboxError::Session(session_err) => session_error_to_mcp(session_err),
        SandboxError::Mount(mount_err) => mount_error_to_mcp(mount_err),
        other => McpError::internal_error(other.to_string(), None),
    }
}

/// Convert `MountError` to an MCP JSON-RPC error payload.
pub fn mount_error_to_mcp(e: MountError) -> McpError {
    McpError::invalid_params(format!("Mount error: {e}"), None)
}

// ===============================
// Path + ID helpers
// ===============================

/// Resolve a user-supplied *relative* path within the session.
///
/// Security/ergonomics:
/// - rejects absolute paths
/// - rejects any `..` components
/// - rejects NUL bytes (defense-in-depth for OS/path APIs)
///
/// The returned path is anchored in `session.paths.upper`, which is the host-side
/// writable layer for the session.
pub fn resolve_session_path(session: &Session, user_path: &str) -> Result<PathBuf, McpError> {
    if user_path.contains('\0') {
        return Err(McpError::invalid_params(
            "Path contains NUL byte".to_string(),
            None,
        ));
    }

    let p = Path::new(user_path);

    if p.is_absolute() || user_path.starts_with('/') {
        return Err(McpError::invalid_params(
            "Path must be relative to workspace root, not absolute".to_string(),
            None,
        ));
    }

    // Reject traversal and other oddities by validating components.
    for c in p.components() {
        match c {
            Component::ParentDir => {
                return Err(McpError::invalid_params(
                    "Path traversal (..) not allowed".to_string(),
                    None,
                ));
            }
            Component::CurDir | Component::Normal(_) => {}
            // For a relative path we should never see RootDir/Prefix.
            Component::RootDir | Component::Prefix(_) => {
                return Err(McpError::invalid_params(
                    "Path must be relative".to_string(),
                    None,
                ));
            }
        }
    }

    Ok(session.paths.upper.join(p))
}

/// Parse a session ID string into a UUID.
pub fn parse_session_id(id: &str) -> Result<uuid::Uuid, McpError> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| McpError::invalid_params(format!("Invalid session ID format: {id}"), None))
}

// ===============================
// Tests
// ===============================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionConfig, SessionManager};
    use std::time::Duration;

    #[test]
    fn test_parse_session_id_valid() {
        let id = uuid::Uuid::new_v4().to_string();
        let parsed = parse_session_id(&id).expect("should parse valid uuid");
        assert_eq!(parsed.to_string(), id);
    }

    #[test]
    fn test_parse_session_id_invalid() {
        let err = parse_session_id("not-a-uuid").unwrap_err();
        let s = err.to_string();
        assert!(s.contains("Invalid session ID format"), "got: {s}");
    }

    #[test]
    fn test_session_error_mapping() {
        let e = SessionError::NotFound {
            id: "abc".to_string(),
        };
        let m = session_error_to_mcp(e);
        let s = m.to_string();
        assert!(s.contains("Session not found"), "got: {s}");
    }

    #[test]
    fn test_resolve_session_path_rejects_absolute() {
        let config = SessionConfig::default().with_ttl(Duration::from_secs(60));
        let mgr = SessionManager::new(config);
        let session = mgr.create_session().expect("create_session");

        let err = resolve_session_path(&session, "/etc/passwd").unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("not absolute") || s.contains("relative"),
            "got: {s}"
        );
    }

    #[test]
    fn test_resolve_session_path_rejects_parent_dir() {
        let config = SessionConfig::default().with_ttl(Duration::from_secs(60));
        let mgr = SessionManager::new(config);
        let session = mgr.create_session().expect("create_session");

        let err = resolve_session_path(&session, "../secrets").unwrap_err();
        let s = err.to_string();
        assert!(s.contains("not allowed"), "got: {s}");
    }

    #[test]
    fn test_resolve_session_path_joins_upper() {
        let config = SessionConfig::default().with_ttl(Duration::from_secs(60));
        let mgr = SessionManager::new(config);
        let session = mgr.create_session().expect("create_session");

        let resolved = resolve_session_path(&session, "foo/bar.txt").expect("resolve");
        assert!(
            resolved.starts_with(&session.paths.upper),
            "resolved path should be under session upper: {resolved:?} vs upper {:?}",
            session.paths.upper
        );
        assert!(
            resolved.ends_with("foo/bar.txt"),
            "expected suffix foo/bar.txt, got: {resolved:?}"
        );
    }
}
