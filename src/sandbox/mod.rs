//! Sandbox container implementation using Linux namespaces via hakoniwa.
//!
//! This module provides secure sandboxed execution of commands using Linux
//! namespace isolation including user, mount, PID, network, IPC, and UTS namespaces.
//!
//! # Example
//!
//! ```no_run
//! use model_sandbox_protocol::sandbox::{SandboxConfig, SandboxContainer};
//!
//! let config = SandboxConfig::default()
//!     .with_hostname("my-sandbox")
//!     .with_env("PATH", "/bin:/usr/bin");
//!
//! let sandbox = SandboxContainer::new(config).unwrap();
//! let output = sandbox.execute("echo", &["hello"]).unwrap();
//!
//! assert!(output.success());
//! println!("Output: {}", output.stdout);
//! ```

mod config;
mod container;
pub mod mounts;
pub mod security;
pub mod workspace;

pub use config::SandboxConfig;
pub use container::{CommandOutput, SandboxContainer};
pub use mounts::{FORBIDDEN_PATHS, MountConfig, SAFE_ETC_FILES};
pub use security::MountPolicyGuard;
pub use workspace::{PreparedWorkspace, WORKSPACE_MOUNT_POINT, WorkspaceConfig, prepare_workspace};
