//! Sandbox container implementation using Linux namespaces via hakoniwa.
//!
//! This module provides the core sandboxing functionality using:
//! - User namespace (UID/GID mapping)
//! - Mount namespace (isolated filesystem view)
//! - PID namespace (process isolation)
//! - Network namespace (loopback only by default)
//! - IPC namespace (isolated System V IPC)
//! - UTS namespace (isolated hostname)
//!
//! # Filesystem model
//!
//! ## Phase 1 (without sessions)
//!
//! Uses hakoniwa's `rootfs("/")` convenience, which bind-mounts a limited set of host
//! directories (`/bin`, `/etc`, `/lib`, `/lib64`, `/lib32`, `/sbin`, `/usr`) read-only into the new
//! mount namespace.
//!
//! ## Phase 2 (with sessions)
//!
//! When a `Session` is provided, the sandbox uses OverlayFS to create an isolated,
//! persistent filesystem:
//! - Lower layer: Read-only host directories
//! - Upper layer: Per-session writable layer (persists across executions)
//! - Merged view: Combined filesystem presented to sandboxed process
//!
//! # Future: Network Egress (Item 1.7)
//!
//! For future implementation of network egress:
//! - CLI flag: `--enable-network-egress`
//! - Use hakoniwa's Pasta integration for network connectivity
//! - Implement domain allowlist filtering
//! - See `docs/SECURITY_MODEL.md` P2 mitigations
//!
//! # Notes on stdout/stderr capture and timeouts
//!
//! Do not read stdout/stderr only after process exit: if the child writes enough data to fill a pipe,
//! the child can block forever and never exit (deadlock).
//!
//! We enforce timeouts ourselves with millisecond precision and a hard kill (SIGKILL) to avoid any
//! dependency on hakoniwa’s `Command::wait_timeout(seconds)` semantics.
//!
//! Historical note (debugging pointer):
//! - We previously attempted to use hakoniwa's `Command::wait_timeout(seconds)` by converting the
//!   configured `Duration` into whole seconds. That introduced a subtle test/runtime regression:
//!   sub-second timeouts (e.g. 100ms) became >= 1s (or 0s), and under parallel test execution this
//!   sometimes manifested as "has been running for over 60 seconds" warnings and hangs in CI/local.
//! - If slow or stuck tests re-emerge, first verify timeout enforcement behavior and whether any
//!   change reintroduced second-granularity timeouts or output-drain deadlocks.
//!
//! We still drain `stdout`/`stderr` concurrently to avoid deadlocks in case of large outputs.

use std::io::Read;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::thread;

use hakoniwa::{Container, Namespace, Stdio};
use tracing::{debug, instrument, trace, warn};

use super::SandboxConfig;
use super::workspace::{WORKSPACE_MOUNT_POINT, WorkspaceConfig, prepare_workspace};
use crate::error::SandboxError;
use crate::session::Session;

/// Global semaphore to serialize namespace/mount creation during sandbox setup.
///
/// Creating user namespaces, mounting procfs, and performing bind mounts can contend
/// on global kernel locks when done at high concurrency. This causes intermittent
/// timeouts in parallel test execution.
///
/// By serializing only the setup phase (container build + spawn), we eliminate this
/// contention while still allowing concurrent command execution after spawn.
///
/// See `docs/troubleshooting/PARALLEL_SANDBOX_FLAKINESS.md` for detailed analysis.
static SETUP_SEMAPHORE: OnceLock<Mutex<()>> = OnceLock::new();

/// Returns the global setup semaphore for serializing namespace-heavy operations.
fn setup_semaphore() -> &'static Mutex<()> {
    SETUP_SEMAPHORE.get_or_init(|| Mutex::new(()))
}

/// Output from a command executed in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
    /// Exit code from the command (0 typically indicates success).
    pub exit_code: i32,
}

impl CommandOutput {
    /// Returns `true` if the command exited successfully (exit code 0).
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// A sandboxed container for executing commands in isolation.
///
/// The container uses Linux namespaces to provide:
/// - Process isolation (PID namespace)
/// - Network isolation (Network namespace with loopback only)
/// - Filesystem isolation (Mount namespace)
/// - IPC isolation (IPC namespace)
/// - Hostname isolation (UTS namespace)
///
/// # Example
///
/// ```no_run
/// use model_sandbox_protocol::sandbox::{SandboxConfig, SandboxContainer};
///
/// let config = SandboxConfig::default();
/// let sandbox = SandboxContainer::new(config).unwrap();
///
/// let output = sandbox.execute("echo", &["hello", "world"]).unwrap();
/// assert_eq!(output.stdout.trim(), "hello world");
/// assert!(output.success());
/// ```
pub struct SandboxContainer {
    config: SandboxConfig,
    /// Optional session for persistent filesystem state.
    session: Option<Session>,
}

impl SandboxContainer {
    /// Creates a new sandbox container with the given configuration.
    ///
    /// This creates a sandbox without session support. Files written during
    /// execution will not persist after the sandbox exits.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CreationFailed` if the sandbox cannot be initialized.
    #[instrument(skip(config), fields(session_id = ?config.session_id))]
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        debug!("Creating new sandbox container (no session)");
        Ok(Self {
            config,
            session: None,
        })
    }

    /// Creates a new sandbox container with session support.
    ///
    /// When a session is provided, the sandbox uses the session's OverlayFS
    /// filesystem, allowing files to persist across multiple executions.
    ///
    /// # Arguments
    ///
    /// * `session` - The session to use for persistent storage
    /// * `config` - Optional configuration overrides (defaults applied if None)
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CreationFailed` if the sandbox cannot be initialized.
    #[instrument(skip(session, config), fields(session_id = %session.id))]
    pub fn with_session(
        session: Session,
        config: Option<SandboxConfig>,
    ) -> Result<Self, SandboxError> {
        debug!("Creating sandbox container with session");

        let config = config.unwrap_or_default();

        Ok(Self {
            config,
            session: Some(session),
        })
    }

    /// Returns a reference to the session, if any.
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Returns true if this sandbox has a session attached.
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Builds a hakoniwa container with the configured namespace isolation.
    ///
    /// Note: Container is rebuilt for each `execute()` call because hakoniwa
    /// consumes it when creating a Command.
    ///
    /// # Setup Pipeline
    ///
    /// The sandbox setup follows this order:
    /// 1. Namespace creation (user, mount, pid, net, ipc, uts)
    /// 2. Filesystem setup (rootfs or session merged directory)
    /// 3. Standard mounts (/proc, /dev, /tmp)
    /// 4. Workspace bind mount (if configured)
    ///
    /// ## Phase 4 TODO: Security Hardening
    ///
    /// After filesystem setup and before exec, Phase 4 will add:
    /// 1. Close inherited file descriptors (except stdin/stdout/stderr)
    /// 2. Apply Landlock filesystem restrictions on merged root
    /// 3. Set PR_SET_NO_NEW_PRIVS
    /// 4. Drop all capabilities
    /// 5. Apply seccomp-bpf filter
    ///
    /// These must be applied in this exact order for correct security.
    #[instrument(skip(self))]
    fn build_container(&self) -> Result<Container, SandboxError> {
        trace!("Building hakoniwa container");
        let mut container = Container::new();

        // ===== Phase 1: Namespace Isolation =====
        // Additional namespace isolation beyond hakoniwa defaults
        container
            .unshare(Namespace::Ipc) // IPC isolation (System V IPC, POSIX message queues)
            .unshare(Namespace::Network) // Network isolation (loopback only)
            .unshare(Namespace::Uts); // Hostname isolation

        container.hostname(&self.config.hostname);

        // ===== Phase 2: Filesystem Setup =====
        // Configure filesystem based on whether we have a session
        if let Some(session) = &self.session {
            // Phase 2: Use session's merged directory as root
            // Note: For full OverlayFS support, the overlay should be mounted
            // in the child's mount namespace. Currently we use the session's
            // merged directory directly (which works if overlay is pre-mounted
            // or for testing with the upper directory as workspace).
            //
            // TODO: Integrate overlay mounting into namespace setup for proper
            // unprivileged OverlayFS in user namespace.
            trace!(merged_path = %session.paths.merged.display(), "Using session filesystem");

            container.rootdir(&session.paths.merged);
        } else {
            // Phase 1 compatibility: Use hakoniwa's rootfs helper
            // IMPORTANT: When host_path is "/", hakoniwa only bind-mounts:
            // `/bin`, `/etc`, `/lib`, `/lib64`, `/lib32`, `/sbin`, `/usr`.
            container
                .rootfs("/")
                .map_err(|e| SandboxError::CreationFailed(format!("failed to set rootfs: {e}")))?;
        }

        // ===== Phase 3: Standard Mounts =====
        // Fresh mounts for dev/tmp. We also mount proc explicitly so the mount point is guaranteed,
        // regardless of kernel/host behavior (even though Container::new mounts /proc already).
        // Note: hakoniwa's procfsmount does not support hidepid option directly.
        // TODO: For hidepid=invisible support, we may need to mount proc manually
        // after namespace setup using our mount_proc() helper.
        container
            .procfsmount("/proc")
            .devfsmount("/dev")
            .tmpfsmount("/tmp");

        // ===== Phase 4: Workspace Mount =====
        // If a workspace path is configured, validate and bind-mount it
        if let Some(workspace_path) = &self.config.workspace_path {
            let workspace_config = WorkspaceConfig::new(workspace_path);

            match prepare_workspace(&workspace_config) {
                Ok(prepared) => {
                    debug!(
                        host_path = %prepared.canonical_path.display(),
                        mount_point = %prepared.mount_point,
                        "Mounting workspace"
                    );

                    // Use hakoniwa's bind mount helper
                    // bindmount_rw mounts the host path at the specified location in sandbox
                    let host_path_str = prepared.canonical_path.to_string_lossy();
                    container.bindmount_rw(&host_path_str, WORKSPACE_MOUNT_POINT);

                    trace!("Workspace bind mount configured");
                }
                Err(e) => {
                    // Workspace validation failed - this is a security-critical error
                    return Err(SandboxError::Mount(e));
                }
            }
        }

        // ===== Phase 4 TODO: Security Hardening (not yet implemented) =====
        // The following security measures will be added in Phase 4:
        //
        // 1. FD Closing: Close all file descriptors > 2 to prevent FD leaks
        //    container.close_fds_above(2);
        //
        // 2. Landlock: Apply filesystem access restrictions
        //    let ruleset = landlock::Ruleset::new()
        //        .handle_access(AccessFs::Execute | AccessFs::ReadFile | ...)?
        //        .create()?;
        //    ruleset.add_rule(PathBeneath::new(merged_root, access))?;
        //    ruleset.restrict_self()?;
        //
        // 3. No New Privs: Prevent privilege escalation via setuid/setgid
        //    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        //
        // 4. Capability Dropping: Drop all capabilities
        //    caps::clear(None, CapSet::Permitted)?;
        //    caps::clear(None, CapSet::Effective)?;
        //
        // 5. Seccomp: Apply syscall filter
        //    seccomp::apply_filter(&SANDBOX_SECCOMP_POLICY)?;

        trace!("Container build complete");
        Ok(container)
    }

    /// Resolves a command name to its full path by searching a fixed PATH list.
    ///
    /// If the command already contains a '/', it's returned as-is.
    /// Otherwise, returns the first matching absolute path from a fixed list.
    ///
    /// Note: this is intentionally *policy-like* and does not consult host `$PATH`.
    fn resolve_command(command: &str) -> Option<String> {
        if command.contains('/') {
            return Some(command.to_string());
        }

        // Prefer canonical system locations. We intentionally do not search `$HOME/bin`, etc.
        let path_dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

        for dir in path_dirs {
            let full_path = format!("{}/{}", dir, command);
            if Path::new(&full_path).exists() {
                return Some(full_path);
            }
        }

        None
    }

    /// Builds default environment variables for commands.
    ///
    /// These are merged with user-provided env vars, with user vars taking precedence.
    fn default_env_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            ("HOME", "/tmp"),
            ("TERM", "xterm"),
        ]
    }

    /// Executes a command in the sandbox and returns its output.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute (e.g., "echo", "/bin/ls")
    /// * `args` - Arguments to pass to the command
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `SandboxError::InvalidCommand` if the command is empty
    /// - `SandboxError::ExecutionFailed` if the command cannot be spawned
    /// - `SandboxError::Timeout` if the command exceeds the configured timeout
    /// - `SandboxError::OutputEncodingError` if stdout/stderr are not valid UTF-8
    #[instrument(skip(self, args), fields(command = %command, timeout_ms = %self.config.timeout.as_millis()))]
    pub fn execute(&self, command: &str, args: &[&str]) -> Result<CommandOutput, SandboxError> {
        if command.is_empty() {
            return Err(SandboxError::InvalidCommand(
                "command cannot be empty".to_string(),
            ));
        }

        // Resolve command to full path
        let resolved_command = Self::resolve_command(command).ok_or_else(|| {
            SandboxError::InvalidCommand(format!("command not found: {}", command))
        })?;
        debug!(resolved = %resolved_command, "Resolved command path");

        // Acquire setup semaphore to serialize namespace/mount creation.
        // This prevents kernel-level contention that causes intermittent timeouts.
        // The lock is held only during setup (build_container + spawn), not during
        // command execution, so parallel execution is still possible after spawn.
        trace!("Acquiring setup semaphore");
        // Allow expect here: Mutex::lock only fails if another thread panicked while
        // holding the lock. In that case, the sandbox system is in an unrecoverable
        // state and panicking is the correct behavior.
        #[allow(clippy::expect_used)]
        let setup_guard = setup_semaphore()
            .lock()
            .expect("setup semaphore poisoned - another thread panicked during setup");
        trace!("Setup semaphore acquired");

        let container = self.build_container()?;

        let mut cmd = container.command(&resolved_command);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Set working directory
        // Default to /workspace if workspace is mounted and no explicit working_dir
        let effective_workdir = self.config.working_dir.clone().or_else(|| {
            if self.config.workspace_path.is_some() {
                Some(std::path::PathBuf::from(WORKSPACE_MOUNT_POINT))
            } else {
                None
            }
        });

        if let Some(workdir) = &effective_workdir {
            cmd.current_dir(workdir);
        }

        // Add default environment variables first
        for (key, value) in Self::default_env_vars() {
            cmd.env(key, value);
        }

        // Add user-provided environment variables (these override defaults)
        for (key, value) in &self.config.env_vars {
            cmd.env(key, value);
        }

        trace!("Spawning child process");
        let mut child = cmd
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(format!("failed to spawn command: {e}")))?;

        // Brief delay to allow child process to complete mount namespace setup.
        // After spawn() returns, the child is still setting up mounts (newns).
        // Multiple children doing concurrent mount operations cause kernel contention.
        // This small delay staggers the mount-heavy phase across sandboxes.
        std::thread::sleep(std::time::Duration::from_millis(5));

        // Release setup semaphore now that spawn and initial mount setup are done.
        drop(setup_guard);
        trace!("Setup semaphore released, child process running");

        // Drain stdout/stderr concurrently so the child can't deadlock on full pipes.
        let mut stdout_reader = child.stdout.take();
        let mut stderr_reader = child.stderr.take();

        let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>();
        let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();

        let stdout_join = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = stdout_reader.take() {
                let _ = r.read_to_end(&mut buf);
            }
            let _ = stdout_tx.send(buf);
        });

        let stderr_join = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr_reader.take() {
                let _ = r.read_to_end(&mut buf);
            }
            let _ = stderr_tx.send(buf);
        });

        // Wait for process completion with a millisecond-precision timeout. On timeout, hard-kill
        // the child (SIGKILL) and wait for it to exit.
        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() > self.config.timeout {
                        debug!(elapsed_ms = %start.elapsed().as_millis(), "Command timed out, sending SIGKILL");
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = stdout_join.join();
                        let _ = stderr_join.join();
                        return Err(SandboxError::Timeout {
                            timeout_seconds: self.config.timeout.as_secs(),
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    let _ = stdout_join.join();
                    let _ = stderr_join.join();
                    return Err(SandboxError::ExecutionFailed(format!(
                        "failed to wait for command: {e}"
                    )));
                }
            }
        };

        let stdout_bytes = stdout_rx.recv().unwrap_or_default();
        let stderr_bytes = stderr_rx.recv().unwrap_or_default();

        let _ = stdout_join.join();
        let _ = stderr_join.join();

        let stdout =
            String::from_utf8(stdout_bytes).map_err(|_| SandboxError::OutputEncodingError {
                context: "stdout contains invalid UTF-8".to_string(),
            })?;

        let stderr =
            String::from_utf8(stderr_bytes).map_err(|_| SandboxError::OutputEncodingError {
                context: "stderr contains invalid UTF-8".to_string(),
            })?;

        debug!(exit_code = status.code, elapsed_ms = %start.elapsed().as_millis(), "Command completed");
        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code: status.code,
        })
    }

    /// Convenience method that executes a command and returns whether it succeeded.
    ///
    /// This is a simpler alternative to `execute()` when you only care about
    /// success/failure and don't need the output.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    /// * `args` - Arguments to pass to the command
    ///
    /// # Errors
    ///
    /// Returns the same errors as `execute()`.
    pub fn run(&self, command: &str, args: &[&str]) -> Result<bool, SandboxError> {
        self.execute(command, args).map(|output| output.success())
    }

    /// Returns a reference to the sandbox configuration.
    #[must_use]
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

impl std::fmt::Debug for SandboxContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxContainer")
            .field("config", &self.config)
            .field("has_session", &self.session.is_some())
            .field("session_id", &self.session.as_ref().map(|s| s.id))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_command_output_success() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        assert!(output.success());

        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
        };
        assert!(!output.success());
    }

    #[test]
    fn test_sandbox_container_creation() {
        let config = SandboxConfig::default();
        let result = SandboxContainer::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_empty_command() {
        let config = SandboxConfig::default();
        let sandbox = SandboxContainer::new(config).unwrap();

        let result = sandbox.execute("", &[]);
        assert!(matches!(result, Err(SandboxError::InvalidCommand(_))));
    }

    #[test]
    fn test_config_accessor() {
        let config = SandboxConfig::default()
            .with_hostname("test-host")
            .with_timeout(Duration::from_secs(60));

        let sandbox = SandboxContainer::new(config).unwrap();

        assert_eq!(sandbox.config().hostname, "test-host");
        assert_eq!(sandbox.config().timeout, Duration::from_secs(60));
    }
}
