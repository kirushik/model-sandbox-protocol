//! MCP server handler implementation.

use crate::error::ServerError;
use rmcp::{
    ServiceExt,
    handler::server::router::tool::ToolRouter,
    model::{ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
    transport::stdio,
};
use tracing::{debug, info};

/// The MCP server for sandbox operations.
///
/// In Phase 0, this is a minimal server that just handles initialization.
/// Tools will be added in Phase 3.
#[derive(Clone)]
pub struct SandboxServer {
    tool_router: ToolRouter<Self>,
}

impl SandboxServer {
    /// Create a new sandbox server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for SandboxServer {
    fn default() -> Self {
        Self::new()
    }
}

// Empty tool router for Phase 0 - tools will be added in Phase 3
#[tool_router]
impl SandboxServer {}

#[tool_handler]
impl rmcp::ServerHandler for SandboxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Model Sandbox Protocol - Secure sandboxed code execution for AI agents. \
                 Tools will be available after Phase 3 implementation."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder()
                // Tools will be enabled in Phase 3
                // .enable_tools()
                .build(),
            ..Default::default()
        }
    }
}

/// Run the MCP server.
///
/// This function starts the server with stdio transport and waits for it to complete.
///
/// # Errors
///
/// Returns error if server initialization or transport fails.
pub async fn run() -> crate::error::Result<()> {
    info!("Starting Model Sandbox Protocol server");
    debug!("Using stdio transport");

    let server = SandboxServer::new();

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
