# Phase 3: MCP Tools - Detailed Execution Plan

A comprehensive step-by-step implementation plan for the MCP tool interface with session lifecycle management.

## Overview

**Goal**: Implement 6 MCP tools plus background tasks for TTL enforcement and orphan cleanup.

| Tool | Purpose |
|------|---------|
| `sandbox_create` | Create new sandbox session with optional workspace mounting |
| `sandbox_execute` | Execute command in sandbox |
| `sandbox_read_file` | Read file from session workspace |
| `sandbox_write_file` | Write file to session workspace |
| `sandbox_list` | List all active sessions |
| `sandbox_destroy` | Destroy session and cleanup |

**Background Tasks**:
- TTL enforcement (every 60s)
- Orphan/corrupted cleanup on startup

---

## Files to Modify/Create

| File | Action | Purpose |
|------|--------|---------|
| `Cargo.toml` | Modify | Add schemars dependency |
| `src/server/tools.rs` | Create | Parameter/result structs, helpers |
| `src/server/handler.rs` | Modify | Tool implementations, background tasks |
| `src/server/mod.rs` | Modify | Update exports |
| `tests/mcp_tools.rs` | Create | Integration tests |

---

## Step 1: Add schemars Dependency

**File**: `Cargo.toml`

```toml
[dependencies]
# ... existing deps ...
schemars = "0.8"
```

**Verification**: `cargo check --quiet`

---

## Step 2: Create `src/server/tools.rs`

### 2.1 Parameter Structs

```rust
//! Tool parameter and result types for MCP tools.

use std::path::PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use rmcp::ErrorData as McpError;
use crate::error::{SessionError, SandboxError};
use crate::session::Session;

/// Parameters for sandbox_create tool
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateParams {
    /// Human-readable session name (for logging/debugging)
    #[schemars(description = "Optional human-readable name for the session")]
    pub name: Option<String>,

    /// Host directory to mount as /workspace in sandbox
    #[schemars(description = "Absolute path to host directory to mount as /workspace")]
    pub workspace_path: Option<String>,

    /// Session TTL in seconds (default: 3600)
    #[schemars(description = "Session time-to-live in seconds (default: 3600)")]
    pub timeout_seconds: Option<u32>,
}

/// Parameters for sandbox_execute tool
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteParams {
    /// Session ID returned by sandbox_create
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    /// Command to execute (e.g., "python", "cargo")
    #[schemars(description = "Command to execute")]
    pub command: String,

    /// Arguments to pass to the command
    #[schemars(description = "Command arguments as array")]
    pub args: Option<Vec<String>>,

    /// Working directory inside sandbox (default: /workspace if mounted, else /)
    #[schemars(description = "Working directory inside sandbox")]
    pub working_dir: Option<String>,
}

/// Parameters for sandbox_read_file tool
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFileParams {
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    #[schemars(description = "File path relative to session's upper layer")]
    pub path: String,
}

/// Parameters for sandbox_write_file tool
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteFileParams {
    #[schemars(description = "Session ID from sandbox_create")]
    pub session_id: String,

    #[schemars(description = "File path relative to session's upper layer")]
    pub path: String,

    #[schemars(description = "File content to write")]
    pub content: String,
}

/// Parameters for sandbox_destroy tool
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DestroyParams {
    #[schemars(description = "Session ID to destroy")]
    pub session_id: String,
}
```

### 2.2 Result Structs

```rust
/// Result from sandbox_create
#[derive(Debug, Serialize)]
pub struct CreateResult {
    pub session_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub workspace_mounted: bool,
    pub workspace_path: Option<String>,
}

/// Result from sandbox_execute
#[derive(Debug, Serialize)]
pub struct ExecuteResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
    pub timed_out: bool,
}

/// Result from sandbox_write_file
#[derive(Debug, Serialize)]
pub struct WriteFileResult {
    pub success: bool,
    pub bytes_written: usize,
    pub path: String,
}

/// Session info for sandbox_list
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub state: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_expired: bool,
    pub has_workspace: bool,
}

/// Result from sandbox_list
#[derive(Debug, Serialize)]
pub struct ListResult {
    pub sessions: Vec<SessionInfo>,
    pub total: usize,
}

/// Result from sandbox_destroy
#[derive(Debug, Serialize)]
pub struct DestroyResult {
    pub success: bool,
    pub session_id: String,
}
```

### 2.3 Error Mapping Helpers

```rust
/// Convert SessionError to McpError
pub fn session_error_to_mcp(e: SessionError) -> McpError {
    match e {
        SessionError::NotFound { id } =>
            McpError::invalid_params(format!("Session not found: {}", id), None),
        SessionError::Expired { id } =>
            McpError::invalid_params(format!("Session expired: {}", id), None),
        SessionError::InUse { id } =>
            McpError::internal_error(format!("Session in use: {}", id), None),
        SessionError::InvalidSession { reason } =>
            McpError::internal_error(format!("Invalid session: {}", reason), None),
        SessionError::IoError { context, .. } =>
            McpError::internal_error(format!("I/O error: {}", context), None),
    }
}

/// Convert SandboxError to McpError
pub fn sandbox_error_to_mcp(e: SandboxError) -> McpError {
    match e {
        SandboxError::InvalidCommand(msg) =>
            McpError::invalid_params(format!("Invalid command: {}", msg), None),
        SandboxError::Timeout { timeout_seconds } =>
            McpError::internal_error(format!("Timeout after {}s", timeout_seconds), None),
        SandboxError::Session(e) => session_error_to_mcp(e),
        other => McpError::internal_error(other.to_string(), None),
    }
}

/// Convert MountError to McpError
pub fn mount_error_to_mcp(e: crate::error::MountError) -> McpError {
    McpError::invalid_params(format!("Mount error: {}", e), None)
}
```

### 2.4 Path Resolution Helper

```rust
/// Maximum file size for read operations (10 MB)
pub const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;

/// Resolve a user-provided path to a safe path within the session's upper layer
pub fn resolve_session_path(session: &Session, user_path: &str) -> Result<PathBuf, McpError> {
    // Reject absolute paths
    if user_path.starts_with('/') {
        return Err(McpError::invalid_params(
            "Path must be relative to workspace root, not absolute".to_string(),
            None,
        ));
    }

    // Reject path traversal attempts
    if user_path.contains("..") {
        return Err(McpError::invalid_params(
            "Path traversal (..) not allowed".to_string(),
            None,
        ));
    }

    // Build the full path within upper layer
    Ok(session.paths.upper.join(user_path))
}

/// Parse a session ID string into UUID
pub fn parse_session_id(id: &str) -> Result<uuid::Uuid, McpError> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| McpError::invalid_params(format!("Invalid session ID format: {}", id), None))
}
```

### 2.5 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_session_id_valid() {
        let result = parse_session_id("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_session_id_invalid() {
        let result = parse_session_id("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_error_mapping() {
        let err = SessionError::NotFound { id: "test".into() };
        let mcp_err = session_error_to_mcp(err);
        // Verify it's converted properly
        assert!(mcp_err.message.contains("not found"));
    }
}
```

---

## Step 3: Update `src/server/handler.rs`

### 3.1 Update Imports

```rust
use std::sync::Arc;
use std::time::Duration;
use std::path::PathBuf;

use rmcp::{
    ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    ErrorData as McpError,
    transport::stdio,
};
use tracing::{debug, info, warn};

use crate::error::ServerError;
use crate::sandbox::{SandboxConfig, SandboxContainer};
use crate::sandbox::workspace::{WorkspaceConfig, prepare_workspace, WORKSPACE_MOUNT_POINT};
use crate::session::{Session, SessionConfig, SessionManager, SessionId};

use super::tools::*;
```

### 3.2 Persisted Session Metadata (workspace + TTL)

**Problem to fix:** In-memory `SessionState` storage of `workspace_path` / `custom_ttl` will be lost on server restart.

**Change:** Extend persisted `SessionMetadata` (in `src/session/meta.rs`) to include:

- `workspace_path: Option<String>` — original host workspace path (canonicalized), if configured
- `custom_ttl_seconds: Option<u32>` — if provided at create-time; otherwise `None` means “use server default TTL”

**Implementation notes:**

- Keep backward compatibility: add `#[serde(default)]` for new fields so old `meta.json` loads.
- Prefer storing `workspace_path` as a string in metadata for JSON stability; convert to `PathBuf` when constructing `SandboxConfig`.
- Remove the redundant `SessionState` in-memory map, or make it a pure cache populated from metadata.

### 3.3 Constructor

```rust
impl SandboxServer {
    pub fn new(session_config: SessionConfig) -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new(session_config)),
            session_state: Arc::new(RwLock::new(HashMap::new())),
            tool_router: Self::tool_router(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SessionConfig::default())
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }
}
```

---

## Step 4: Implement `sandbox_create` (with workspace & custom TTL)

```rust
#[tool(description = "Create a new isolated sandbox session for code execution. Optionally mount a host directory as /workspace.")]
async fn sandbox_create(&self, params: Parameters<CreateParams>) -> Result<CallToolResult, McpError> {
    let params = params.0;
    debug!(name = ?params.name, workspace = ?params.workspace_path, "Creating sandbox session");

    // Validate workspace path if provided
    let prepared_workspace = if let Some(ref ws_path) = params.workspace_path {
        let path = PathBuf::from(ws_path);
        let ws_config = WorkspaceConfig::new(&path);
        let prepared = prepare_workspace(&ws_config).map_err(mount_error_to_mcp)?;
        Some(prepared)
    } else {
        None
    };

    // Handle custom TTL
    let session = if let Some(timeout) = params.timeout_seconds {
        let custom_config = self.session_manager.config().clone()
            .with_ttl(Duration::from_secs(timeout as u64));
        let temp_manager = SessionManager::new(custom_config);
        temp_manager.create_session().map_err(session_error_to_mcp)?
    } else {
        self.session_manager.create_session().map_err(session_error_to_mcp)?
    };

    // Store workspace info in session state
    let workspace_mounted = prepared_workspace.is_some();
    {
        let mut state = self.session_state.write().await;
        state.insert(session.id, SessionState {
            workspace_path: prepared_workspace.map(|w| w.canonical_path),
            custom_ttl: params.timeout_seconds.map(|t| Duration::from_secs(t as u64)),
        });
    }

    let result = CreateResult {
        session_id: session.id.to_string(),
        created_at: session.metadata.created_at.to_rfc3339(),
        expires_at: session.metadata.expires_at.to_rfc3339(),
        workspace_mounted,
        workspace_path: params.workspace_path,
    };

    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::success(vec![Content::text(json)]))
}
```

---

## Step 5: Implement `sandbox_execute` (rootless OverlayFS + workspace)

### 5.1 Early system check (fail fast if userns/mount not available)

Before attempting any session mount, ensure the host supports **unprivileged user namespaces** at runtime.

- If userns creation is blocked (e.g., AppArmor restriction), return a clear MCP error telling the user what to enable.
- Document the AppArmor sysctl in `docs/SYSTEM_REQUIREMENTS.md`.

*(Implementation detail: reuse the existing system requirements checks in `src/system/requirements.rs`; add a targeted error message when userns is blocked.)*

### 5.2 Ensure overlay is mounted inside the sandbox mount namespace

**Critical fix:** the plan must explicitly mount OverlayFS.

Architecture decision (rootless):

- `SessionManager::prepare_session_mounts()` only prepares directories.
- The actual overlay mount must happen **inside the sandbox mount namespace**.

**Implementation change required:**

- Update the sandbox/container setup to call `setup_session_mounts()` (from `src/sandbox/mounts.rs`) *during sandbox namespace setup*, before executing the command.
- Use OverlayFS mount option `userxattr` (already implemented in `mount_overlay()`).

**Note:** Since the overlay mount lives in the sandbox mount namespace, host paths like `session.paths.merged` must not be assumed to contain a mounted view from the host.

### 5.3 Workspace mount behavior

When a `workspace_path` is configured:

- Configure it via `SandboxConfig::with_workspace(...)` so it is bind-mounted into the sandbox at `/workspace`.
- Default working directory:
  - If `working_dir` is not specified by the tool call: use `/workspace` when workspace is mounted, otherwise `/`.

## Step 6: Implement `sandbox_read_file` (inside sandbox namespace)

**Architecture decision:** Because OverlayFS is mounted inside the sandbox mount namespace, `sandbox_read_file` must read files by executing *inside the sandbox*.

### 6.1 Path semantics (ergonomics)

This project treats the sandbox as a thin “jail” around an existing workspace.

- If a workspace is mounted, `path` is interpreted as **relative to `/workspace`**.
  - Example: `path: "src/main.rs"` reads `/workspace/src/main.rs`.
- If no workspace is mounted, `path` is interpreted as **relative to `/`**.
  - Example: `path: "etc/hosts"` reads `/etc/hosts`.

### 6.2 Behavior

- Reads the resolved file path inside the session’s filesystem.
- Enforce a maximum read size (`MAX_READ_SIZE`) and return a clear error if exceeded.

### 6.3 Implementation strategy

- Implement `sandbox_read_file` by running a safe helper command inside the sandbox (e.g., `cat`) and capturing stdout.
- Apply strict path validation:
  - Reject NUL bytes
  - Reject absolute paths in `path` (to keep semantics consistent)
  - Reject paths that contain `..`
- Return content as string (UTF-8); if non-UTF8 is encountered, return an error (MCP tools are text-oriented).

*(This avoids host-side access to `merged/` entirely.)*

## Step 7: Implement `sandbox_write_file` (inside sandbox namespace)

**Architecture decision:** Because OverlayFS is mounted inside the sandbox mount namespace, `sandbox_write_file` must write files by executing *inside the sandbox*.

### 7.1 Path semantics (ergonomics)

- If a workspace is mounted, `path` is interpreted as **relative to `/workspace`**.
- If no workspace is mounted, `path` is interpreted as **relative to `/`**.

### 7.2 Behavior

- Writes `content` to the resolved file path inside the session.
- Create parent directories if needed.

### 7.3 Implementation strategy

- Prefer a non-shell write path to avoid injection:
  - Recommended: add a small internal write helper in Rust (Phase 3) that opens the resolved path with safe flags and writes bytes.
  - Acceptable fallback: use `tee` with stdin piping **without invoking a shell**.

### 7.4 Output

- Return `{ success, bytes_written, path }`.

## Step 8: Implement `sandbox_list`

```rust
#[tool(description = "List all active sandbox sessions with their metadata")]
async fn sandbox_list(&self) -> Result<CallToolResult, McpError> {
    debug!("Listing sandbox sessions");

    let session_ids = self.session_manager.list_sessions().map_err(session_error_to_mcp)?;
    let state = self.session_state.read().await;

    let mut sessions = Vec::new();
    for id in session_ids {
        if let Ok(Some(session)) = self.session_manager.get_session(id) {
            let has_workspace = state.get(&id).map(|s| s.workspace_path.is_some()).unwrap_or(false);
            sessions.push(SessionInfo {
                session_id: session.id.to_string(),
                state: format!("{:?}", session.metadata.state),
                created_at: session.metadata.created_at.to_rfc3339(),
                expires_at: session.metadata.expires_at.to_rfc3339(),
                is_expired: session.is_expired(),
                has_workspace,
            });
        }
    }

    let result = ListResult { total: sessions.len(), sessions };
    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::success(vec![Content::text(json)]))
}
```

---

## Step 9: Implement `sandbox_destroy`

```rust
#[tool(description = "Destroy a sandbox session and clean up all associated resources")]
async fn sandbox_destroy(&self, params: Parameters<DestroyParams>) -> Result<CallToolResult, McpError> {
    let session_id = parse_session_id(&params.0.session_id)?;

    debug!(%session_id, "Destroying sandbox session");

    self.session_manager.destroy_session(session_id).map_err(session_error_to_mcp)?;

    // Clean up session state
    {
        let mut state = self.session_state.write().await;
        state.remove(&session_id);
    }

    let result = DestroyResult { success: true, session_id: params.0.session_id };
    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::success(vec![Content::text(json)]))
}
```

---

## Step 10: Update ServerHandler

```rust
#[tool_handler]
impl rmcp::ServerHandler for SandboxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Model Sandbox Protocol - Secure sandboxed code execution for AI agents. \
                 Use sandbox_create to start a session (optionally mounting a workspace), \
                 sandbox_execute to run commands, sandbox_read_file/sandbox_write_file for file I/O, \
                 sandbox_list to view sessions, and sandbox_destroy to cleanup.".into()
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
```

---

## Step 11: Add Background Tasks to `run()`

```rust
pub async fn run() -> crate::error::Result<()> {
    run_with_config(SessionConfig::default()).await
}

pub async fn run_with_config(session_config: SessionConfig) -> crate::error::Result<()> {
    info!("Starting Model Sandbox Protocol server");
    debug!("Using stdio transport");

    let server = SandboxServer::new(session_config);

    // Startup cleanup: orphaned + corrupted sessions
    info!("Cleaning up stale sessions on startup");
    match server.session_manager().cleanup_all() {
        Ok(count) if count > 0 => info!(count, "Cleaned up stale sessions"),
        Ok(_) => debug!("No stale sessions to clean up"),
        Err(e) => warn!(error = %e, "Failed to clean up stale sessions"),
    }

    // Spawn background TTL enforcement task (every 60 seconds)
    let cleanup_manager = Arc::clone(server.session_manager());
    let cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match cleanup_manager.cleanup_expired() {
                Ok(count) if count > 0 => {
                    info!(count, "Background cleanup removed expired sessions");
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "Background cleanup failed");
                }
            }
        }
    });

    let service = server
        .serve(stdio())
        .await
        .map_err(|e| ServerError::InitializationFailed(e.to_string()))?;

    info!("Server initialized, waiting for requests");

    let result = service.waiting().await;

    // Cancel background task on shutdown
    cleanup_task.abort();

    result.map_err(|e| ServerError::Transport(e.to_string()))?;

    info!("Server shutdown complete");
    Ok(())
}
```

---

## Step 12: Update `src/server/mod.rs`

```rust
//! MCP server implementation.

mod handler;
mod tools;

pub use handler::{SandboxServer, run, run_with_config};
pub use tools::{
    CreateParams, CreateResult, DestroyParams, DestroyResult,
    ExecuteParams, ExecuteResult, ListResult, ReadFileParams,
    SessionInfo, WriteFileParams, WriteFileResult,
};
```

---

## Step 13: Verification

```bash
cargo check --quiet && cargo clippy
cargo test
```

---

## Testing Strategy

### Automated Tests

#### Unit Tests (`src/server/tools.rs`)

| Test | Purpose |
|------|---------|
| `test_parse_session_id_valid` | Valid UUID parsing |
| `test_parse_session_id_invalid` | Invalid UUID rejection |
| `test_resolve_path_rejects_absolute` | Absolute path rejection |
| `test_resolve_path_rejects_traversal` | Path traversal rejection |
| `test_session_error_mapping` | Error conversion |

#### Integration Tests (`tests/mcp_tools.rs`)

| Test | Purpose |
|------|---------|
| `test_full_mcp_flow` | create → execute → read → write → list → destroy |
| `test_session_with_workspace` | Workspace mounting and execution |
| `test_custom_ttl` | Per-session TTL support |
| `test_concurrent_sessions` | Multiple sessions in parallel |
| `test_expired_session_rejected` | Expired session error handling |
| `test_invalid_session_id` | Non-existent ID error handling |
| `test_path_traversal_blocked` | "../" paths rejected |
| `test_file_size_limit` | Large file read rejection |

### Manual Testing Flow

1. **Start server**:
   ```bash
   cargo run
   ```

2. **Create session with workspace**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_create","arguments":{"workspace_path":"/tmp/test-workspace","timeout_seconds":600}},"id":1}
   ```

3. **Execute command**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_execute","arguments":{"session_id":"<uuid>","command":"ls","args":["-la"]}},"id":2}
   ```

4. **Write file**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_write_file","arguments":{"session_id":"<uuid>","path":"hello.txt","content":"Hello, World!"}},"id":3}
   ```

5. **Read file**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_read_file","arguments":{"session_id":"<uuid>","path":"hello.txt"}},"id":4}
   ```

6. **List sessions**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_list","arguments":{}},"id":5}
   ```

7. **Destroy session**:
   ```json
   {"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_destroy","arguments":{"session_id":"<uuid>"}},"id":6}
   ```

8. **Test TTL expiration**:
   - Create session with `timeout_seconds: 5`
   - Wait 10 seconds
   - Verify execute returns "Session expired" error

9. **Test background cleanup**:
   - Create session with short TTL
   - Wait for background task (60s)
   - Verify session is auto-cleaned

---

## Acceptance Criteria

| Criterion | Verification Method |
|-----------|---------------------|
| Full MCP flow: create → execute → read/write → destroy | Integration test |
| Workspace mounting works | Integration test with actual directory |
| Per-session TTL supported | Test with custom timeout_seconds |
| Session list returns all active sessions | JSON structure validation |
| Expired sessions automatically cleaned | Short TTL + background task |
| Orphan sessions cleaned on startup | Kill server, restart, verify |
| Concurrent sessions work | Parallel session test |
| Invalid session_id returns appropriate error | Unit test |
| Path traversal blocked | Unit test |
| All tests pass | `cargo test` |
| No clippy warnings | `cargo clippy` |

---

## Key Design Decisions

1. **Server runs unprivileged (no host root).**
2. **OverlayFS is mounted inside the sandbox mount namespace (rootless OverlayFS).**
   - Requires kernel >= 5.11 and OverlayFS mounted with `userxattr`.
   - Host must allow unprivileged user namespaces at runtime.
   - Ubuntu/Debian derivatives may additionally require `kernel.apparmor_restrict_unprivileged_userns=0` unless an AppArmor profile is installed.
3. **MCP file tools run inside the sandbox.**
   - `sandbox_read_file` and `sandbox_write_file` do not access host `merged/`.
4. **Session persistence across server restarts is metadata-driven.**
   - Persist `workspace_path` and per-session TTL in `SessionMetadata` (disk), not only in-memory.

## Implementation Order Summary

1. Add `schemars` dependency.
2. Implement tool structs + helpers (`src/server/tools.rs`).
3. Update session metadata to include `workspace_path` + `custom_ttl_seconds` with backward-compatible serde defaults.
4. Update server handler to use persisted metadata (remove in-memory `SessionState` or make it a cache).
5. Update sandbox namespace setup to mount OverlayFS via `setup_session_mounts()` inside mount namespace.
6. Implement MCP file tools by executing inside the sandbox namespace.
7. Add background tasks for TTL + orphan cleanup.
8. Add integration tests.


| Decision | Rationale |
|----------|-----------|
| `Arc<SessionManager>` (no Mutex) | SessionManager methods take `&self`; per-session locking via PID files |
| `Arc<RwLock<HashMap>>` for session state | Store workspace info not persisted to disk |
| `spawn_blocking` for sandbox execution | Prevents blocking tokio runtime |
| File I/O on `session.paths.upper` | Upper layer contains writable changes |
| JSON results for structured tools | Consistent, parseable for AI agents |
| Raw text for `sandbox_read_file` | File content returned directly |
| 60-second cleanup interval | Balance between responsiveness and overhead |
| MAX_READ_SIZE = 10MB | Prevent memory exhaustion |
| Workspace validated via `prepare_workspace()` | Reuse existing security validation |

---

## Implementation Order Summary

1. Add `schemars = "0.8"` to Cargo.toml
2. Create `src/server/tools.rs` with parameter/result structs and helpers
3. Update `SandboxServer` struct with `session_state` field
4. Implement `sandbox_create` with workspace + TTL support
5. Implement `sandbox_execute` with workspace support
6. Implement `sandbox_read_file`
7. Implement `sandbox_write_file`
8. Implement `sandbox_list`
9. Implement `sandbox_destroy`
10. Update `get_info()` to enable tools capability
11. Add background cleanup task to `run()`
12. Add orphan cleanup on startup
13. Update `src/server/mod.rs` exports
14. Write unit tests in tools.rs
15. Create `tests/mcp_tools.rs` integration tests
16. Run `cargo check --quiet && cargo clippy`
17. Run `cargo test`

----


## Phase 3 follow-up checklist (after main implementation)

Implementation-level:
- [x] Replace “best-effort” masking with a thoroughly designed blocklist of paths and patterns (including symlink edge cases).
- [x] Add integration tests asserting key secrets are not readable from inside sandbox (`~/.ssh`, `~/.aws`, etc.), and that `/proc` is namespaced.
- [x] Add tests asserting common tools exist in sandbox (`/bin/sh`, `mkdir`, `cat`, `tee`, `env`, etc.) and that `sandbox_execute` works reliably.
- [x] Ensure read-only enforcement for host mounts (attempt writes to host-mounted paths must fail).
- [x] Add documentation for AI agents: what filesystem is visible, what is writable, what is masked (prompts / tool specs).
- [x] Add logging/auditing notes: log what is mounted/masked per session (without leaking user secrets).
