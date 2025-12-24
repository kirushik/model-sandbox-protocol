//! Model Sandbox Protocol - Namespace-based sandboxing MCP server.
//!
//! This crate provides a secure sandbox environment for executing AI agent code
//! using Linux namespaces, Landlock LSM, seccomp-BPF, and cgroups v2.
//!
//! # Platform Requirements
//!
//! - Linux kernel 6.7+ (for Landlock ABI v6 with IPC scoping)
//! - x86_64 architecture
//! - cgroups v2 (unified hierarchy)
//! - Unprivileged user namespaces enabled
//!
//! # Example
//!
//! ```no_run
//! use model_sandbox_protocol::{system, server};
//!
//! #[tokio::main]
//! async fn main() -> miette::Result<()> {
//!     // Validate system requirements
//!     system::check_all()?;
//!
//!     // Start MCP server
//!     server::run().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod sandbox;
pub mod server;
pub mod system;

// Re-export commonly used types
pub use error::{Error, Result};
pub use sandbox::{CommandOutput, SandboxConfig, SandboxContainer};
