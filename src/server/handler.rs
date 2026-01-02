//! MCP server handler implementation (Phase 3: MCP Tools).
//!
//! Implements the MCP tools described in `PHASE3_EXECUTION_PLAN.md`:
//! - sandbox_create
//! - sandbox_execute
//! - sandbox_read_file
//! - sandbox_write_file
//! - sandbox_list
//! - sandbox_destroy
//!
//! Plus background cleanup tasks:
//! - TTL enforcement (cleanup_expired)
//! - orphan/corrupted cleanup on startup (cleanup_orphaned / cleanup_corrupted)

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::ServerError;
use crate::sandbox::SandboxContainer;
use crate::server::tools::{
    CreateParams, CreateResult, DestroyParams, DestroyResult, ExecuteParams, ExecuteResult,
    ListResult, ReadFileParams, SessionInfo, WriteFileParams, WriteFileResult, parse_session_id,
    sandbox_error_to_mcp, session_error_to_mcp,
};
use crate::session::{SessionConfig, SessionId, SessionManager};
use chrono::{DateTime, Utc};
use rmcp::{
    ErrorData as McpError, Json, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use std::fs;

use tokio::time;
use tracing::{debug, info, instrument, warn};

/// The MCP server for sandbox operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WriteStrategy {
    Auto,
    ForceShellFallback,
}

#[derive(Clone)]
pub struct SandboxServer {
    tool_router: ToolRouter<Self>,
    session_manager: Arc<SessionManager>,
    default_ttl: Duration,
    write_strategy: WriteStrategy,
}

impl SandboxServer {
    /// Create a new sandbox server with explicit config.
    #[must_use]
    pub fn new(session_config: SessionConfig) -> Self {
        let default_ttl = session_config.ttl;

        Self {
            tool_router: Self::tool_router(),
            session_manager: Arc::new(SessionManager::new(session_config)),
            default_ttl,
            write_strategy: WriteStrategy::Auto,
        }
    }

    #[doc(hidden)]
    pub fn with_write_strategy(mut self, strategy: WriteStrategy) -> Self {
        self.write_strategy = strategy;
        self
    }

    /// Create a new sandbox server using default session config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Access the session manager (primarily for tests).
    #[must_use]
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.session_manager)
    }

    fn ttl_from_params(&self, timeout_seconds: Option<u32>) -> Duration {
        timeout_seconds
            .map(|s| Duration::from_secs(u64::from(s)))
            .unwrap_or(self.default_ttl)
    }

    fn format_ts(ts: DateTime<Utc>) -> String {
        ts.to_rfc3339()
    }

    fn session_has_workspace_marker(session_root: &Path) -> bool {
        session_root.join("workspace.txt").exists()
    }

    fn write_workspace_marker(session_root: &Path, workspace_path: &str) -> Result<(), McpError> {
        let marker = session_root.join("workspace.txt");
        fs::write(&marker, workspace_path).map_err(|e| {
            McpError::internal_error(format!("Failed to persist workspace marker: {e}"), None)
        })
    }

    fn session_dir(&self, id: SessionId) -> PathBuf {
        self.session_manager.config().base_dir.join(id.to_string())
    }

    fn load_workspace_marker(&self, id: SessionId) -> Option<String> {
        let p = self.session_dir(id).join("workspace.txt");
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn to_session_info(&self, session_id: SessionId) -> Result<SessionInfo, McpError> {
        let session = self
            .session_manager
            .get_session(session_id)
            .map_err(session_error_to_mcp)?
            .ok_or_else(|| {
                McpError::invalid_params(format!("Session not found: {session_id}"), None)
            })?;

        let created_at = session.metadata.created_at;
        let expires_at = session.metadata.expires_at;
        let is_expired = session.metadata.is_expired();

        let has_workspace = SandboxServer::session_has_workspace_marker(&session.paths.root);

        Ok(SessionInfo {
            session_id: session.id.to_string(),
            state: format!("{:?}", session.metadata.state),
            created_at: Self::format_ts(created_at),
            expires_at: Self::format_ts(expires_at),
            is_expired,
            has_workspace,
        })
    }

    fn validate_relative_path(path: &str) -> Result<(), McpError> {
        if path.contains('\0') {
            return Err(McpError::invalid_params(
                "Path contains NUL byte".to_string(),
                None,
            ));
        }
        if path.starts_with('/') {
            return Err(McpError::invalid_params(
                "Path must be relative to workspace root, not absolute".to_string(),
                None,
            ));
        }
        if path.contains("..") {
            return Err(McpError::invalid_params(
                "Path traversal (..) not allowed".to_string(),
                None,
            ));
        }
        Ok(())
    }
}

// ===============================
// Tool implementations (MCP-exposed)
// ===============================

#[tool_router]
impl SandboxServer {
    /// Create a new sandbox session with optional workspace path and custom TTL.
    #[tool(
        description = "Create a new isolated sandbox session for code execution. Optionally mount a host directory as /workspace."
    )]
    #[instrument(skip(self), fields(name = ?params.name, workspace_path = ?params.workspace_path, timeout_seconds = ?params.timeout_seconds))]
    pub async fn sandbox_create(
        &self,
        Parameters(params): Parameters<CreateParams>,
    ) -> Result<Json<CreateResult>, McpError> {
        let ttl = self.ttl_from_params(params.timeout_seconds);

        // Create session with default manager TTL, then touch to requested TTL.
        let mut session = self
            .session_manager
            .create_session()
            .map_err(session_error_to_mcp)?;

        session.touch(ttl);
        // Persist updated TTL (expires_at) back into meta.json
        session
            .metadata
            .save(&session.paths.meta_file)
            .map_err(session_error_to_mcp)?;

        // Persist workspace marker (host path) for later operations if provided.
        let (workspace_mounted, workspace_path) = if let Some(ws) = params.workspace_path.as_deref()
        {
            // Workspace validation occurs later when actually executing/mounting. Here we just persist.
            Self::write_workspace_marker(&session.paths.root, ws)?;
            (true, Some(ws.to_string()))
        } else {
            (false, None)
        };

        let created_at = session.metadata.created_at;
        let expires_at = session.metadata.expires_at;

        Ok(Json(CreateResult {
            session_id: session.id.to_string(),
            created_at: Self::format_ts(created_at),
            expires_at: Self::format_ts(expires_at),
            workspace_mounted,
            workspace_path,
        }))
    }

    /// Execute a command in the sandbox.
    #[tool(description = "Execute a command in an existing sandbox session")]
    #[instrument(skip(self), fields(session_id = %params.session_id, command = %params.command))]
    pub async fn sandbox_execute(
        &self,
        Parameters(params): Parameters<ExecuteParams>,
    ) -> Result<Json<ExecuteResult>, McpError> {
        let id = parse_session_id(&params.session_id)?;

        // Acquire session for exclusive use.
        let session = self
            .session_manager
            .acquire_session(id)
            .map_err(session_error_to_mcp)?;

        // Prepare session directories for overlay mount inside sandbox namespace.
        let _prepared = self
            .session_manager
            .prepare_session_mounts(id)
            .map_err(session_error_to_mcp)?;

        // Determine workspace (optional).
        let workspace_path = self.load_workspace_marker(id);

        // Build sandbox config for this execution.
        let mut config = crate::sandbox::SandboxConfig::default()
            .with_session_id(id)
            .with_timeout(Duration::from_secs(30)); // per-command timeout remains Phase 1 default

        // Working dir semantics:
        // - caller override wins
        // - else: /workspace when a workspace is mounted
        // - else: session filesystem mountpoint (denylist strategy)
        if let Some(wd) = params.working_dir.as_deref() {
            config = config.with_working_dir(wd);
        } else if workspace_path.is_some() {
            config = config.with_working_dir(crate::sandbox::WORKSPACE_MOUNT_POINT);
        } else {
            config = config.with_working_dir(crate::sandbox::SESSION_MOUNT_POINT);
        }

        // Apply workspace mount if present.
        if let Some(ws) = workspace_path.as_deref() {
            config = config.with_workspace(ws);
        }

        let sandbox = SandboxContainer::with_session(session.clone(), Some(config))
            .map_err(sandbox_error_to_mcp)?;

        let args_vec: Vec<String> = params.args.unwrap_or_default();
        let args_ref: Vec<&str> = args_vec.iter().map(String::as_str).collect();

        let timed_out = false;
        let output = sandbox
            .execute(&params.command, &args_ref)
            .map_err(sandbox_error_to_mcp)?;

        // Release session after execution.
        self.session_manager
            .release_session(id)
            .map_err(session_error_to_mcp)?;

        let success = output.success();
        let exit_code = output.exit_code;
        let stdout = output.stdout;
        let stderr = output.stderr;

        Ok(Json(ExecuteResult {
            stdout,
            stderr,
            exit_code,
            success,
            timed_out,
        }))
    }

    /// Read a file from the session workspace.
    ///
    /// Phase 3 requirement: perform file IO inside the sandbox namespace.
    ///
    /// Implementation strategy:
    /// - Validate user path is relative and traversal-safe.
    /// - Execute `stat -c %s <path>` inside the sandbox to check size.
    /// - Execute `cat <path>` inside the sandbox to read content.
    /// - Working dir semantics match `sandbox_execute`.
    #[tool(description = "Read a file from the sandbox session workspace")]
    #[instrument(skip(self), fields(session_id = %params.session_id, path = %params.path))]
    pub async fn sandbox_read_file(
        &self,
        Parameters(params): Parameters<ReadFileParams>,
    ) -> Result<String, McpError> {
        let id = parse_session_id(&params.session_id)?;

        // Acquire session for exclusive use.
        let session = self
            .session_manager
            .acquire_session(id)
            .map_err(session_error_to_mcp)?;

        // Ensure session mounts are prepared.
        let _prepared = self
            .session_manager
            .prepare_session_mounts(id)
            .map_err(session_error_to_mcp)?;

        if session.metadata.is_expired() {
            self.session_manager
                .release_session(id)
                .map_err(session_error_to_mcp)?;
            return Err(McpError::invalid_params(
                format!("Session expired: {id}"),
                None,
            ));
        }

        Self::validate_relative_path(&params.path)?;

        // Determine workspace (optional).
        let workspace_path = self.load_workspace_marker(id);

        // Build sandbox config for this execution.
        let mut config = crate::sandbox::SandboxConfig::default()
            .with_session_id(id)
            .with_timeout(Duration::from_secs(30));

        // Working dir semantics:
        // - default to /workspace if workspace is mounted
        // - otherwise default to the session filesystem mountpoint (denylist strategy)
        if workspace_path.is_some() {
            config = config.with_working_dir(crate::sandbox::WORKSPACE_MOUNT_POINT);
        } else {
            config = config.with_working_dir(crate::sandbox::SESSION_MOUNT_POINT);
        }

        // Apply workspace mount if present.
        if let Some(ws) = workspace_path.as_deref() {
            config = config.with_workspace(ws);
        }

        let sandbox = SandboxContainer::with_session(session.clone(), Some(config))
            .map_err(sandbox_error_to_mcp)?;

        // Check file size inside sandbox using `stat`.
        // We use `stat -c %s` which prints size in bytes.
        // If file doesn't exist, stat will fail.
        let stat_args: Vec<&str> = vec!["-c", "%s", params.path.as_str()];
        let stat_out = sandbox
            .execute("stat", &stat_args)
            .map_err(sandbox_error_to_mcp)?;

        if !stat_out.success() {
            self.session_manager
                .release_session(id)
                .map_err(session_error_to_mcp)?;
            return Err(McpError::internal_error(
                format!(
                    "Failed to stat file (exit {}): {}",
                    stat_out.exit_code, stat_out.stderr
                ),
                None,
            ));
        }

        let size_str = stat_out.stdout.trim();
        let size: u64 = size_str.parse().map_err(|_| {
            // Release session before error
            let _ = self.session_manager.release_session(id);
            McpError::internal_error(format!("Invalid size output from stat: {size_str}"), None)
        })?;

        if size > crate::server::tools::MAX_READ_SIZE {
            self.session_manager
                .release_session(id)
                .map_err(session_error_to_mcp)?;
            return Err(McpError::invalid_params(
                format!(
                    "File too large to read ({} bytes, max {})",
                    size,
                    crate::server::tools::MAX_READ_SIZE
                ),
                None,
            ));
        }

        let args_ref: Vec<&str> = vec![params.path.as_str()];
        let output = sandbox
            .execute("cat", &args_ref)
            .map_err(sandbox_error_to_mcp)?;

        // Release session after execution.
        self.session_manager
            .release_session(id)
            .map_err(session_error_to_mcp)?;

        if !output.success() {
            return Err(McpError::internal_error(
                format!(
                    "Failed to read file (exit {}): {}",
                    output.exit_code, output.stderr
                ),
                None,
            ));
        }

        Ok(output.stdout)
    }

    /// Write a file into the session workspace.
    ///
    /// Phase 3 requirement: perform file IO inside the sandbox namespace.
    ///
    /// Implementation strategy:
    /// - Validate user path is relative and traversal-safe.
    /// - Ensure destination parent directories exist (inside sandbox) via `mkdir -p`.
    /// - Use `sh -lc 'cat > ""' -- <path>` so that we avoid embedding paths in a shell string.
    ///
    /// Note: We currently do not support binary payloads; content is UTF-8 text.
    #[tool(description = "Write a file to the sandbox session workspace")]
    #[instrument(skip(self), fields(session_id = %params.session_id, path = %params.path, bytes = params.content.len()))]
    pub async fn sandbox_write_file(
        &self,
        Parameters(params): Parameters<WriteFileParams>,
    ) -> Result<Json<WriteFileResult>, McpError> {
        let id = parse_session_id(&params.session_id)?;

        // Acquire session for exclusive use.
        let session = self
            .session_manager
            .acquire_session(id)
            .map_err(session_error_to_mcp)?;

        // Ensure session mounts are prepared.
        let _prepared = self
            .session_manager
            .prepare_session_mounts(id)
            .map_err(session_error_to_mcp)?;

        if session.metadata.is_expired() {
            self.session_manager
                .release_session(id)
                .map_err(session_error_to_mcp)?;
            return Err(McpError::invalid_params(
                format!("Session expired: {id}"),
                None,
            ));
        }

        Self::validate_relative_path(&params.path)?;

        // Determine workspace (optional).
        let workspace_path = self.load_workspace_marker(id);

        // Build sandbox config for this execution.
        let mut config = crate::sandbox::SandboxConfig::default()
            .with_session_id(id)
            .with_timeout(Duration::from_secs(30));

        // Working dir semantics:
        // - default to /workspace if workspace is mounted
        // - otherwise default to the session filesystem mountpoint (denylist strategy)
        if workspace_path.is_some() {
            config = config.with_working_dir(crate::sandbox::WORKSPACE_MOUNT_POINT);
        } else {
            config = config.with_working_dir(crate::sandbox::SESSION_MOUNT_POINT);
        }

        // Apply workspace mount if present.
        if let Some(ws) = workspace_path.as_deref() {
            config = config.with_workspace(ws);
        }

        let sandbox = SandboxContainer::with_session(session.clone(), Some(config))
            .map_err(sandbox_error_to_mcp)?;

        // Ensure parent directories exist (inside sandbox).
        // Prefer BusyBox-style invocation because hakoniwa's rootfs may not include coreutils
        // under `/usr/bin/*` in all environments.
        let parent_dir = std::path::Path::new(&params.path)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(".");

        // Try `busybox mkdir -p <dir>` first, then fall back to plain `mkdir -p <dir>`.
        let mkdir_out = {
            let bb_args: Vec<&str> = vec!["mkdir", "-p", parent_dir];
            let out = sandbox.execute("busybox", &bb_args);
            match out {
                Ok(o) if o.success() => Ok(o),
                _ => {
                    let mkdir_args: Vec<&str> = vec!["-p", parent_dir];
                    sandbox.execute("mkdir", &mkdir_args)
                }
            }
        }
        .map_err(sandbox_error_to_mcp)?;

        if !mkdir_out.success() {
            self.session_manager
                .release_session(id)
                .map_err(session_error_to_mcp)?;
            return Err(McpError::internal_error(
                format!(
                    "Failed to create parent directories (exit {}): {}",
                    mkdir_out.exit_code, mkdir_out.stderr
                ),
                None,
            ));
        }

        // Write content fully inside the sandbox.
        //
        // Helper closure to write bytes via tee/cat redirection.
        let write_one = |target_path: &str| {
            // Preferred approach: stdin piping into `tee`, discarding stdout so we don't echo content back.
            // Fallback: shell redirection `cat > file` in case `tee` is unavailable.

            if self.write_strategy != WriteStrategy::ForceShellFallback {
                // 1) Try BusyBox `tee` applet first.
                let bb_args: Vec<&str> = vec!["tee", target_path];
                let out = sandbox.execute_with_stdin(
                    "busybox",
                    &bb_args,
                    Some(params.content.as_bytes()),
                );
                if let Ok(o) = &out {
                    if o.success() {
                        return Ok(o.clone());
                    }
                }

                // 2) Try plain `tee`.
                let tee_args: Vec<&str> = vec![target_path];
                let out =
                    sandbox.execute_with_stdin("tee", &tee_args, Some(params.content.as_bytes()));
                if let Ok(o) = &out {
                    if o.success() {
                        return Ok(o.clone());
                    }
                }
            }

            // 3) Fallback to shell redirection without interpolating the path into the script.
            // We pass the path as `` so it is not subject to shell parsing.
            //
            // NOTE: Requires `sh` and `cat` inside the sandbox rootfs.
            let script = r#"cat > "$1""#;
            let sh_args: Vec<&str> = vec!["-lc", script, "--", target_path];
            sandbox.execute_with_stdin("sh", &sh_args, Some(params.content.as_bytes()))
        };

        // Write to tool path (relative contract).
        let write_out = write_one(params.path.as_str()).map_err(sandbox_error_to_mcp)?;

        // Release session after execution.
        self.session_manager
            .release_session(id)
            .map_err(session_error_to_mcp)?;

        if !write_out.success() {
            return Err(McpError::internal_error(
                format!(
                    "Failed to write file: tee/cat returned non-zero (exit {}), stderr: {}",
                    write_out.exit_code, write_out.stderr
                ),
                None,
            ));
        }

        Ok(Json(WriteFileResult {
            success: true,
            bytes_written: params.content.len(),
            path: params.path,
        }))
    }

    /// List sessions under the base directory.
    #[tool(description = "List all active sandbox sessions")]
    #[instrument(skip(self))]
    pub async fn sandbox_list(&self) -> Result<Json<ListResult>, McpError> {
        let ids = self
            .session_manager
            .list_sessions()
            .map_err(session_error_to_mcp)?;

        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            // Best-effort: ignore sessions that became corrupted between listing and load.
            match self.to_session_info(id) {
                Ok(info) => sessions.push(info),
                Err(e) => {
                    warn!(session_id = %id, error = %e, "Skipping session in list due to error");
                }
            }
        }

        Ok(Json(ListResult {
            total: sessions.len(),
            sessions,
        }))
    }

    /// Destroy a session.
    #[tool(description = "Destroy a sandbox session and cleanup resources")]
    #[instrument(skip(self), fields(session_id = %params.session_id))]
    pub async fn sandbox_destroy(
        &self,
        Parameters(params): Parameters<DestroyParams>,
    ) -> Result<Json<DestroyResult>, McpError> {
        let id = parse_session_id(&params.session_id)?;

        self.session_manager
            .destroy_session(id)
            .map_err(session_error_to_mcp)?;

        Ok(Json(DestroyResult {
            success: true,
            session_id: id.to_string(),
        }))
    }
}

// ===============================
// Tool handler wiring
// ===============================

#[tool_handler]
impl rmcp::ServerHandler for SandboxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Model Sandbox Protocol - Secure sandboxed code execution for AI agents.".into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ===============================
// Background tasks + run()
// ===============================

async fn run_background_tasks(session_manager: Arc<SessionManager>) {
    // Startup cleanup: orphaned + corrupted.
    // These are best-effort; failures are logged and do not abort server startup.
    if let Err(e) = session_manager.cleanup_orphaned() {
        warn!(error = %e, "Failed to cleanup orphaned sessions on startup");
    }
    if let Err(e) = session_manager.cleanup_corrupted() {
        warn!(error = %e, "Failed to cleanup corrupted sessions on startup");
    }

    // TTL enforcement loop.
    let mut interval = time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        match session_manager.cleanup_expired() {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "Cleaned up expired sessions");
                }
            }
            Err(e) => warn!(error = %e, "Failed to cleanup expired sessions"),
        }
    }
}

/// Run the MCP server with default config.
pub async fn run() -> crate::error::Result<()> {
    run_with_config(SessionConfig::default()).await
}

/// Run the MCP server with an explicit session config.
pub async fn run_with_config(session_config: SessionConfig) -> crate::error::Result<()> {
    info!("Starting Model Sandbox Protocol server");
    debug!("Using stdio transport");

    let server = SandboxServer::new(session_config);

    // Spawn background maintenance tasks.
    tokio::spawn(run_background_tasks(server.session_manager()));

    let service = server
        .serve(stdio())
        .await
        .map_err(|e| ServerError::InitializationFailed(e.to_string()))?;

    info!("Server initialized, waiting for requests");

    service
        .waiting()
        .await
        .map_err(|e| ServerError::Transport(e.to_string()))?;

    info!("Server shutdown complete");
    Ok(())
}
