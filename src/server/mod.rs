//! MCP server implementation.
//!
//! This module provides the MCP server that handles tool calls from AI agents.

mod handler;

pub use handler::{SandboxServer, run};
