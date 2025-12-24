//! Model Sandbox Protocol - Entry Point
//!
//! This is the main entry point for the MCP server binary.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing::{Level, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use model_sandbox_protocol::{server, system};

/// Model Sandbox Protocol - Secure sandboxed code execution for AI agents.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Skip system requirements checks (NOT RECOMMENDED - may cause undefined behavior)
    #[arg(long, default_value = "false")]
    skip_checks: bool,

    /// Enable verbose logging
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    // MCP requires that logs go to stderr (stdout is for JSON-RPC)
    let filter = if args.verbose {
        EnvFilter::from_default_env().add_directive(Level::DEBUG.into())
    } else {
        EnvFilter::from_default_env().add_directive(Level::INFO.into())
    };

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    info!("Model Sandbox Protocol v{}", env!("CARGO_PKG_VERSION"));

    // Check system requirements unless skipped
    if args.skip_checks {
        warn!("Skipping system requirements checks (--skip-checks). This is NOT recommended!");
        warn!("Running on an unsupported system may cause undefined behavior or security issues.");
    } else {
        info!("Checking system requirements...");

        match system::check_all() {
            Ok(reqs) => {
                info!(
                    "System requirements satisfied: kernel {}, Landlock ABI v{}, cgroups v2: {}, userns: {}",
                    reqs.kernel_version, reqs.landlock_abi, reqs.cgroups_v2, reqs.user_namespaces
                );
            }
            Err(e) => {
                error!("System requirements check failed");
                return Err(e).into_diagnostic();
            }
        }
    }

    // Run the MCP server
    server::run().await.into_diagnostic()
}
