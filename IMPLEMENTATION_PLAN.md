# Model Sandbox Protocol - Implementation Plan

A namespace-based sandboxing MCP server for safe AI agent code execution.
**Platform:** Rust, x86_64 Linux only, kernel 6.7+ required.

## Quick Reference

| Resource | Path |
|----------|------|
| Security requirements | `docs/SECURITY_MODEL.md` |
| Architecture design | `docs/ARCHITECTURE.md` |
| Library decisions | `docs/LIBRARY_CHOICES.md` |
| System requirements | `docs/SYSTEM_REQUIREMENTS.md` |
| Early research | `Implementation notes.md` |

## Project Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Sandbox library | hakoniwa | Integrated solution: namespaces + seccomp + Landlock |
| Network | Isolated (loopback only) | Maximum security; egress via future CLI flag |
| Scope | Full implementation | All features before first release |

---

## Phase 0: Foundation

**Goal:** Project structure, dependencies, system requirements validation, basic MCP server

### Checklist

- [x] **0.1** Update `Cargo.toml` with all dependencies
- [x] **0.2** Create `src/lib.rs` with module structure
- [x] **0.3** Create `src/error.rs` with error types (thiserror + miette)
- [x] **0.4** Create `src/system/mod.rs` and `src/system/requirements.rs`
- [x] **0.5** Implement kernel version check (>= 6.7)
- [x] **0.6** Implement Landlock ABI v6 check
- [x] **0.7** Implement cgroups v2 check
- [x] **0.8** Implement unprivileged user namespaces check
- [x] **0.9** Create `src/server/mod.rs` and `src/server/handler.rs`
- [x] **0.10** Implement basic ServerHandler (no tools yet)
- [x] **0.11** Replace `src/main.rs` with CLI and server startup
- [x] **0.12** Run `cargo check --quiet && cargo clippy`
- [x] **0.13** Write unit tests for system requirements

### Files to Create/Modify

```
Cargo.toml                      # Add dependencies
src/lib.rs                      # Library root
src/error.rs                    # Error types
src/main.rs                     # Entry point (replace hello world)
src/system/mod.rs               # System module
src/system/requirements.rs      # Kernel/Landlock/cgroups checks
src/server/mod.rs               # Server module
src/server/handler.rs           # Basic ServerHandler
```

### Dependencies (Cargo.toml)

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rmcp = { version = "0.5", features = ["server", "macros"] }
hakoniwa = "1.2"
nix = { version = "0.29", features = ["user", "mount", "sched", "signal", "process"] }
landlock = "0.4"
caps = "0.5"
thiserror = "2"
miette = { version = "7", features = ["fancy"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
clap = { version = "4", features = ["derive"] }

[dev-dependencies]
tokio-test = "0.4"
```

### Acceptance Criteria

- [x] `cargo check --quiet` passes
- [x] `cargo clippy` passes with no warnings
- [x] Server starts and responds to MCP `initialize` request
- [x] On unsupported systems (kernel < 6.7), server exits with clear error message
- [x] System requirements check returns structured diagnostics (pass/fail per check)
- [x] Unit tests pass: `cargo test`

---

## Phase 1: Sandbox Container

**Goal:** Hakoniwa-based sandbox with namespace isolation

### Checklist

- [x] **1.1** Create `src/sandbox/mod.rs` with public API
- [x] **1.2** Create `src/sandbox/config.rs` with SandboxConfig struct
- [x] **1.3** Create `src/sandbox/container.rs` with SandboxContainer
- [x] **1.4** Implement namespace creation (user, mount, PID, network, IPC, UTS)
- [x] **1.5** Implement `execute()` method to run commands
- [x] **1.6** Capture stdout/stderr from sandboxed commands
- [x] **1.7** Document network egress pathway (future CLI flag)
- [x] **1.8** Write integration tests for basic sandbox

### Files to Create

```
src/sandbox/mod.rs              # Sandbox module public API
src/sandbox/config.rs           # SandboxConfig struct
src/sandbox/container.rs        # Hakoniwa Container wrapper
```

### Key Implementation

```rust
// src/sandbox/container.rs
pub struct SandboxContainer {
    container: hakoniwa::Container,
    session_id: String,
}

impl SandboxContainer {
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError>;
    pub fn execute(&self, command: &str, args: &[&str]) -> Result<CommandOutput, SandboxError>;
}

pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}
```

### Network Egress Pathway (Document for Future)

```rust
// Future implementation via CLI flag: --enable-network-egress
// Would require:
// 1. VethNetworkConfig in SandboxConfig
// 2. sandbox_network_allow_domain(session_id, domain) MCP tool
// 3. SNI-filtering proxy or iptables-based domain allowlist
// Reference: docs/SECURITY_MODEL.md P2 mitigations
```

### Acceptance Criteria

- [x] Can run `echo hello` in sandbox, receive "hello" output
- [x] Can run `cat /proc/self/status` and verify PID namespace (PID 1)
- [x] Network is isolated (external connections fail)
- [x] IPC is isolated (cannot connect to host abstract sockets)
- [x] Integration tests pass

---

## Phase 2: Filesystem & Sessions

**Goal:** OverlayFS workspaces with session persistence

### Checklist

- [ ] **2.1** Create `src/session/mod.rs` with public API
- [ ] **2.2** Create `src/session/storage.rs` with filesystem layout
- [ ] **2.3** Create `src/session/meta.rs` with metadata struct
- [ ] **2.4** Create `src/session/lifecycle.rs` with create/cleanup logic
- [ ] **2.5** Create `src/sandbox/mounts.rs` with OverlayFS setup
- [ ] **2.6** Implement session directory structure at `~/.mcp-sandboxes/`
- [ ] **2.7** Implement minimal /etc (sanitized, no credentials)
- [ ] **2.8** Implement fresh /proc with `hidepid=invisible`
- [ ] **2.9** Implement minimal /dev (devtmpfs)
- [ ] **2.10** Implement tmpfs /tmp with size limit
- [ ] **2.11** Verify credential paths are NEVER mounted (P1 security)
- [ ] **2.12** Write integration tests for session persistence

### Files to Create

```
src/session/mod.rs              # Session module public API
src/session/storage.rs          # ~/.mcp-sandboxes/ layout
src/session/meta.rs             # Session metadata JSON
src/session/lifecycle.rs        # TTL, cleanup, orphan detection
src/sandbox/mounts.rs           # OverlayFS and mount setup
```

### Session Storage Layout

```
~/.mcp-sandboxes/
└── {session-uuid}/
    ├── upper/                  # OverlayFS upper layer (writable)
    ├── work/                   # OverlayFS work directory
    ├── merged/                 # Mount point (sandbox root)
    ├── meta.json               # Session metadata
    └── pid                     # PID file for orphan detection
```

### Credential Paths to NEVER Mount (P1 Security)

```rust
const FORBIDDEN_PATHS: &[&str] = &[
    "~/.ssh/",
    "~/.aws/",
    "~/.config/gcloud/",
    "~/.kube/",
    "~/.gnupg/",
    "~/.gitconfig",
    "~/.netrc",
    "~/.git-credentials",
];
```

### Acceptance Criteria

- [ ] Session directory created with correct structure
- [ ] Files written in sandbox appear in upper layer
- [ ] Host filesystem remains unchanged
- [ ] `/proc` shows only sandbox processes
- [ ] `~/.ssh/*` is not accessible from sandbox
- [ ] `~/.aws/*` is not accessible from sandbox
- [ ] Session persists across multiple execute calls
- [ ] Session metadata (JSON) is correctly written/read

---

## Phase 3: MCP Tools

**Goal:** Complete MCP tool interface with session lifecycle

### Checklist

- [ ] **3.1** Create `src/server/tools.rs` with tool definitions
- [ ] **3.2** Create `src/server/session_manager.rs` with actor pattern
- [ ] **3.3** Implement `sandbox_create` tool
- [ ] **3.4** Implement `sandbox_execute` tool
- [ ] **3.5** Implement `sandbox_read_file` tool
- [ ] **3.6** Implement `sandbox_write_file` tool
- [ ] **3.7** Implement `sandbox_list` tool
- [ ] **3.8** Implement `sandbox_destroy` tool
- [ ] **3.9** Wire tools into ServerHandler
- [ ] **3.10** Implement TTL enforcement background task
- [ ] **3.11** Implement orphan cleanup on startup
- [ ] **3.12** Write integration tests for full MCP flow

### Files to Create/Modify

```
src/server/tools.rs             # MCP tool definitions
src/server/session_manager.rs   # Session state management
src/server/handler.rs           # Wire up tools (modify)
```

### Tool Signatures

```rust
#[tool_router]
impl SandboxServer {
    #[tool(description = "Create a new sandbox session")]
    async fn sandbox_create(
        &self,
        name: Option<String>,              // Human-readable name
        workspace_path: Option<String>,    // Initial workspace content
        timeout_seconds: Option<u32>,      // TTL (default: 3600)
    ) -> Result<CallToolResult, McpError>;

    #[tool(description = "Execute command in sandbox session")]
    async fn sandbox_execute(
        &self,
        session_id: String,
        command: String,
        args: Option<Vec<String>>,
        working_dir: Option<String>,
    ) -> Result<CallToolResult, McpError>;

    #[tool(description = "Read file from sandbox workspace")]
    async fn sandbox_read_file(
        &self,
        session_id: String,
        path: String,
    ) -> Result<CallToolResult, McpError>;

    #[tool(description = "Write file to sandbox workspace")]
    async fn sandbox_write_file(
        &self,
        session_id: String,
        path: String,
        content: String,
    ) -> Result<CallToolResult, McpError>;

    #[tool(description = "List active sandbox sessions")]
    async fn sandbox_list(&self) -> Result<CallToolResult, McpError>;

    #[tool(description = "Destroy sandbox session and cleanup")]
    async fn sandbox_destroy(
        &self,
        session_id: String,
    ) -> Result<CallToolResult, McpError>;
}
```

### Acceptance Criteria

- [ ] Full MCP flow works: create → execute → read/write → destroy
- [ ] Session list returns all active sessions with metadata
- [ ] Expired sessions are automatically cleaned up
- [ ] Orphan sessions (dead PIDs) are cleaned on startup
- [ ] Concurrent sessions work correctly
- [ ] Invalid session_id returns appropriate error
- [ ] Integration tests pass

---

## Phase 4: Security Hardening

**Goal:** Implement all security controls from SECURITY_MODEL.md

### Checklist

- [ ] **4.0** Audit and minimize `unsafe` usage across the codebase (Phase 0–3), consolidate unavoidable `unsafe` into well-reviewed modules, and tighten linting (goal: no `unsafe` outside sandbox/security boundaries)
- [ ] **4.1** Create `src/sandbox/security.rs` with security primitives
- [ ] **4.2** Create `src/sandbox/cgroups.rs` with resource limits
- [ ] **4.3** Implement setsid() for new session (TIOCSTI protection)
- [ ] **4.4** Implement FD hygiene (close all except 0,1,2 and comm pipes)
- [ ] **4.5** Implement Landlock rules on MERGED path (not underlying)
- [ ] **4.6** Implement Landlock IPC scoping (kernel 6.7+)
- [ ] **4.7** Implement NO_NEW_PRIVS
- [ ] **4.8** Implement capability dropping (caps crate)
- [ ] **4.9** Verify hakoniwa seccomp filter is last
- [ ] **4.10** Implement cgroups v2 memory limit
- [ ] **4.11** Implement cgroups v2 PID limit
- [ ] **4.12** Implement cgroups v2 CPU limit
- [ ] **4.13** Create `tests/integration/security.rs`
- [ ] **4.14** Write TIOCSTI blocking test
- [ ] **4.15** Write credential inaccessibility test
- [ ] **4.16** Write capability verification test
- [ ] **4.17** Write FD inheritance audit test
- [ ] **4.18** Write IPC isolation test
- [ ] **4.19** Write resource limit enforcement tests
- [ ] **4.20** Write CVE regression tests

### Files to Create

```
src/sandbox/security.rs         # FD hygiene, caps, Landlock
src/sandbox/cgroups.rs          # cgroups v2 resource limits
tests/integration/security.rs   # Security regression tests
```

### Security Implementation Order (CRITICAL)

Per `docs/SECURITY_MODEL.md`, this order MUST be followed:

```
1. Create namespaces (user, mount, PID, network, IPC, UTS)
2. setsid() - New session to prevent TIOCSTI terminal injection
3. Configure mounts (OverlayFS, bind mounts, /proc, /dev)
4. Close unnecessary FDs (iterate /proc/self/fd)
5. Apply Landlock rules (to MERGED overlay path)
6. Landlock IPC scoping (required for kernel 6.7+)
7. Set NO_NEW_PRIVS (prctl)
8. Drop all capabilities (caps crate)
9. Install seccomp filter (LAST - hakoniwa handles this)
```

### FD Hygiene Implementation

```rust
pub fn close_unnecessary_fds(keep: &[RawFd]) -> Result<(), SandboxError> {
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let fd: RawFd = entry?.file_name().to_str()?.parse()?;
        if !keep.contains(&fd) {
            nix::unistd::close(fd).ok(); // Ignore errors
        }
    }
    Ok(())
}
```

### Landlock on Merged Path

```rust
use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, ABI};

pub fn apply_landlock_rules(workspace_path: &Path) -> Result<(), SandboxError> {
    Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V6))?
        .create()?
        // Read-only system paths
        .add_rule(PathBeneath::new(PathFd::new("/usr")?, AccessFs::from_read(ABI::V6)))?
        .add_rule(PathBeneath::new(PathFd::new("/lib")?, AccessFs::from_read(ABI::V6)))?
        .add_rule(PathBeneath::new(PathFd::new("/lib64")?, AccessFs::from_read(ABI::V6)))?
        // Read-write workspace
        .add_rule(PathBeneath::new(PathFd::new(workspace_path)?, AccessFs::from_all(ABI::V6)))?
        .restrict_self()?;
    Ok(())
}
```

### Resource Limits

```rust
pub struct ResourceLimits {
    pub memory_max_bytes: u64,   // Default: 512MB
    pub pids_max: u32,           // Default: 100
    pub cpu_max_percent: u32,    // Default: 50%
}
```

### CVE Regression Tests

| CVE | Attack | Test |
|-----|--------|------|
| CVE-2017-5226 | TIOCSTI terminal injection | Verify ioctl blocked |
| CVE-2024-1086 | netfilter privilege escalation | Verify network isolated |
| CVE-2023-2640 | OverlayFS capability bypass | Verify caps dropped |
| CVE-2025-31133 | Symlink races | Verify O_NOFOLLOW used |

### Acceptance Criteria

- [ ] TIOCSTI ioctl has no effect (terminal injection blocked)
- [ ] Credential paths return ENOENT or EACCES
- [ ] Network connections to external hosts fail
- [ ] `capsh --print` shows empty capability set
- [ ] Blocked syscalls return EPERM or SIGSYS
- [ ] Abstract Unix socket connections fail (IPC isolated)
- [ ] `/proc/self/fd/` shows only expected FDs
- [ ] Fork bomb is killed by PID limit
- [ ] Memory-excessive process is OOM killed
- [ ] All CVE regression tests pass

---

## Phase 5: Polish & Production

**Goal:** Error handling, logging, documentation, CI

### Checklist

- [ ] **5.1** Review all error paths use miette for rich diagnostics
- [ ] **5.2** Add structured logging with tracing throughout
- [ ] **5.3** Implement configurable log levels via RUST_LOG
- [ ] **5.4** Ensure all logs go to stderr (MCP requirement)
- [ ] **5.5** Implement graceful shutdown with session cleanup
- [ ] **5.6** Update `docs/ARCHITECTURE.md` with implementation details
- [ ] **5.7** Add usage examples to README
- [ ] **5.8** Add inline documentation (rustdoc) to public API
- [ ] **5.9** Run `cargo fmt --all` and verify formatting
- [ ] **5.10** Run `cargo clippy` and fix all warnings
- [ ] **5.11** Run full test suite and verify 100% pass
- [ ] **5.12** Create security audit checklist document

### Acceptance Criteria

- [ ] All errors have clear, actionable messages
- [ ] Logs are structured and filterable
- [ ] `RUST_LOG=debug` produces verbose output
- [ ] Server shuts down cleanly, cleaning up sessions
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo test` passes 100%
- [ ] Documentation is complete and accurate

---

## Security Rules (ALWAYS Follow)

From `AGENTS.md`:

1. **Never weaken security stance without discussion.** Document rationale in `docs/SECURITY_MODEL.md`.
2. **Never write non-trivial code without tests.** Unit tests for modules, integration tests for sandbox behavior.
3. **Never trust user inputs.** Validate all inputs at system boundaries.
4. **Never use `unwrap()`.** Use `expect("explanation")` or propagate with `?`.

---

## Module Structure (Final)

```
src/
├── main.rs                     # Entry point, CLI, server startup
├── lib.rs                      # Library root with module re-exports
├── error.rs                    # Error types (thiserror + miette)
├── server/
│   ├── mod.rs
│   ├── handler.rs              # ServerHandler implementation
│   ├── tools.rs                # MCP tool definitions
│   └── session_manager.rs      # Actor pattern session management
├── sandbox/
│   ├── mod.rs
│   ├── container.rs            # Hakoniwa Container wrapper
│   ├── config.rs               # SandboxConfig struct
│   ├── mounts.rs               # OverlayFS and mount setup
│   ├── security.rs             # FD hygiene, caps, Landlock
│   └── cgroups.rs              # cgroups v2 resource limits
├── session/
│   ├── mod.rs
│   ├── storage.rs              # ~/.mcp-sandboxes/ layout
│   ├── meta.rs                 # Session metadata JSON
│   └── lifecycle.rs            # TTL, cleanup, orphan detection
└── system/
    ├── mod.rs
    └── requirements.rs         # Kernel/Landlock/cgroups checks
```

---

## Commands Reference

```bash
cargo check --quiet      # Verify compilation
cargo clippy             # Lint (must pass before commit)
cargo test               # Run tests (requires kernel 6.7+)
cargo fmt --all          # Format code
cargo run                # Run MCP server
```
