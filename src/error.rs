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

/// Result type alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
