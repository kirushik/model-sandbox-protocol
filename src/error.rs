//! Error types for the Model Sandbox Protocol.
//!
//! Uses thiserror for deriving std::error::Error and miette for rich diagnostics.

// Phase 0 note: we do not treat `unsafe` usage as a hard policy violation yet
// because some low-level Linux primitives (namespaces, fork/exec probing, etc.)
// may temporarily require it. We will tighten this in Phase 4 (Security Hardening).
#![allow(unsafe_code)]
#![allow(unused_assignments)]

use miette::Diagnostic;
use thiserror::Error;

/// Top-level error type for the application.
#[derive(Error, Debug, Diagnostic)]
pub enum Error {
    /// System requirements not met
    #[error("System requirements check failed")]
    #[diagnostic(code(msp::system::requirements))]
    SystemRequirements(#[from] SystemRequirementsError),

    /// MCP server error
    #[error("MCP server error")]
    #[diagnostic(code(msp::server))]
    Server(#[from] ServerError),

    /// Sandbox error
    #[error("Sandbox error")]
    #[diagnostic(code(msp::sandbox))]
    Sandbox(#[from] SandboxError),

    /// Session error
    #[error("Session error")]
    #[diagnostic(code(msp::session))]
    Session(#[from] SessionError),

    /// Mount error
    #[error("Mount error")]
    #[diagnostic(code(msp::mount))]
    Mount(#[from] MountError),

    /// I/O error
    #[error("I/O error: {0}")]
    #[diagnostic(code(msp::io))]
    Io(#[from] std::io::Error),
}

/// Errors related to system requirements validation.
#[derive(Error, Debug, Diagnostic)]
pub enum SystemRequirementsError {
    /// Kernel version too old
    #[error("Kernel version {found} is below minimum required {required}")]
    #[diagnostic(
        code(msp::system::kernel_version),
        help("Upgrade to kernel 6.7 or later for Landlock IPC scoping support")
    )]
    KernelTooOld { found: String, required: String },

    /// Unsupported architecture
    #[error("Architecture {found} is not supported, only x86_64 is supported")]
    #[diagnostic(
        code(msp::system::architecture),
        help("This software only runs on x86_64 Linux systems")
    )]
    UnsupportedArchitecture { found: String },

    /// Landlock not available or ABI too old
    #[error("Landlock ABI version {found} is below minimum required {required}")]
    #[diagnostic(
        code(msp::system::landlock),
        help("Kernel 6.7+ provides Landlock ABI v6 with IPC scoping")
    )]
    LandlockAbiTooOld { found: i32, required: i32 },

    /// Landlock not available at all
    #[error("Landlock is not available on this system")]
    #[diagnostic(
        code(msp::system::landlock_unavailable),
        help("Ensure kernel has CONFIG_SECURITY_LANDLOCK=y")
    )]
    LandlockUnavailable,

    /// cgroups v2 not available
    #[error("cgroups v2 is not available")]
    #[diagnostic(
        code(msp::system::cgroups),
        help("Mount cgroups v2 with: mount -t cgroup2 none /sys/fs/cgroup")
    )]
    CgroupsV2Unavailable,

    /// Unprivileged user namespaces not enabled
    #[error("Unprivileged user namespaces are not enabled")]
    #[diagnostic(
        code(msp::system::userns),
        help("Enable with: sysctl -w kernel.unprivileged_userns_clone=1")
    )]
    UserNamespacesDisabled,

    /// Failed to read system information
    #[error("Failed to read system information: {context}")]
    #[diagnostic(code(msp::system::read_failed))]
    ReadFailed {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

/// Errors related to the MCP server.
#[derive(Error, Debug, Diagnostic)]
pub enum ServerError {
    /// Failed to initialize server
    #[error("Failed to initialize MCP server: {0}")]
    #[diagnostic(code(msp::server::init))]
    InitializationFailed(String),

    /// Transport error
    #[error("Transport error: {0}")]
    #[diagnostic(code(msp::server::transport))]
    Transport(String),
}

/// Errors related to sandbox operations.
#[derive(Error, Debug, Diagnostic)]
pub enum SandboxError {
    /// Failed to create sandbox container
    #[error("Failed to create sandbox container: {0}")]
    #[diagnostic(code(msp::sandbox::creation))]
    CreationFailed(String),

    /// Failed to execute command in sandbox
    #[error("Failed to execute command in sandbox: {0}")]
    #[diagnostic(code(msp::sandbox::execution))]
    ExecutionFailed(String),

    /// Command timed out
    #[error("Command timed out after {timeout_seconds} seconds")]
    #[diagnostic(code(msp::sandbox::timeout))]
    Timeout { timeout_seconds: u64 },

    /// Invalid command
    #[error("Invalid command: {0}")]
    #[diagnostic(code(msp::sandbox::invalid_command))]
    InvalidCommand(String),

    /// Failed to decode command output as UTF-8
    #[error("Failed to decode command output as UTF-8: {context}")]
    #[diagnostic(code(msp::sandbox::encoding))]
    OutputEncodingError { context: String },

    /// Mount-related error
    #[error("Mount error")]
    #[diagnostic(code(msp::sandbox::mount))]
    Mount(#[from] MountError),

    /// Session-related error
    #[error("Session error")]
    #[diagnostic(code(msp::sandbox::session))]
    Session(#[from] SessionError),
}

/// Errors related to session management.
#[derive(Error, Debug, Diagnostic)]
pub enum SessionError {
    /// Session not found
    #[error("Session not found: {id}")]
    #[diagnostic(code(msp::session::not_found))]
    NotFound { id: String },

    /// Session already exists
    #[error("Session already exists: {id}")]
    #[diagnostic(code(msp::session::exists))]
    AlreadyExists { id: String },

    /// Session has expired
    #[error("Session has expired: {id}")]
    #[diagnostic(code(msp::session::expired))]
    Expired { id: String },

    /// Invalid session state or data
    #[error("Invalid session: {reason}")]
    #[diagnostic(code(msp::session::invalid))]
    InvalidSession { reason: String },

    /// I/O error during session operations
    #[error("Session I/O error: {context}")]
    #[diagnostic(code(msp::session::io))]
    IoError {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// Session is in use and cannot be modified
    #[error("Session is in use: {id}")]
    #[diagnostic(code(msp::session::in_use))]
    InUse { id: String },
}

/// Errors related to mount operations.
#[derive(Error, Debug, Diagnostic)]
pub enum MountError {
    /// Failed to mount OverlayFS
    #[error("Failed to mount OverlayFS: {0}")]
    #[diagnostic(
        code(msp::mount::overlay),
        help("Ensure kernel 5.11+ with unprivileged OverlayFS support")
    )]
    OverlayMount(String),

    /// Failed to mount procfs
    #[error("Failed to mount procfs: {0}")]
    #[diagnostic(code(msp::mount::proc))]
    ProcMount(String),

    /// Failed to mount devfs
    #[error("Failed to mount devfs: {0}")]
    #[diagnostic(code(msp::mount::dev))]
    DevMount(String),

    /// Failed to mount tmpfs
    #[error("Failed to mount tmpfs: {0}")]
    #[diagnostic(code(msp::mount::tmpfs))]
    TmpfsMount(String),

    /// Failed to unmount filesystem
    #[error("Failed to unmount: {0}")]
    #[diagnostic(code(msp::mount::unmount))]
    Unmount(String),

    /// Failed to create bind mount
    #[error("Failed to create bind mount: {0}")]
    #[diagnostic(code(msp::mount::bind))]
    BindMount(String),

    /// Security validation failed
    #[error("Security validation failed: {0}")]
    #[diagnostic(
        code(msp::mount::security),
        help("Credential paths must never be accessible from sandbox")
    )]
    SecurityViolation(String),
}

/// Result type alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

// Re-export error types for convenience
pub use MountError as MountErr;
pub use SessionError as SessionErr;
