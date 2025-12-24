# Building a sandboxed code execution MCP server in Rust

A production-grade MCP server for AI agent code execution is best built using Rust's **rmcp** SDK (official, actively maintained), combined with native Linux namespaces for isolation, native OverlayFS for unprivileged CoW filesystems, and layered security via seccomp-bpf, Landlock, and capability dropping. This architecture provides strong isolation without requiring root privileges, making it suitable for deployment alongside AI agents. Requires kernel 6.7+ (for Landlock IPC scoping).

## MCP protocol fundamentals and Rust SDK options

The Model Context Protocol uses **JSON-RPC 2.0** over newline-delimited messages, supporting three server primitives: **Tools** (executable functions), **Resources** (contextual data), and **Prompts** (templated workflows). The stdio transport reads JSON from stdin and writes to stdout, with logging strictly to stderr.

The official **rmcp** crate provides everything needed for Rust implementations. It offers procedural macros for tool definitions, async tokio integration, and multiple transport options (stdio, SSE, streamable HTTP). Supports protocol versions 2024-11-05, 2025-03-26, and 2025-06-18. A basic sandboxed execution server structure:

```rust
use rmcp::{ServerHandler, tool, tool_router};
use rmcp::model::{ServerCapabilities, ServerInfo};

#[derive(Clone)]
pub struct SandboxServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SandboxServer {
    #[tool(description = "Execute code in a sandboxed environment")]
    async fn execute(&self, code: String, language: String) -> Result<CallToolResult, ErrorData> {
        // Spawn sandboxed process...
    }
}
```

No mature Rust MCP servers with sandboxed code execution currently exist—the ecosystem has shell execution servers in Python/TypeScript but nothing combining Rust's safety with proper sandboxing. This represents a significant opportunity.

## Bubblewrap architecture and namespace isolation

Bubblewrap creates sandboxes by establishing a new, empty mount namespace backed by tmpfs, then constructing the sandbox filesystem through bind mounts and virtual filesystems. It leverages Linux namespaces—user, mount, PID, network, IPC, UTS, and cgroup—without requiring root privileges when unprivileged user namespaces are enabled (`kernel.unprivileged_userns_clone=1`).

Key CLI patterns for code execution sandboxing:

```bash
bwrap \
    --ro-bind /usr /usr \
    --symlink usr/lib64 /lib64 \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --unshare-all \
    --share-net \           # Keep network if needed
    --new-session \         # Required: prevents TIOCSTI escape
    --die-with-parent \     # Cleanup on parent exit
    --seccomp FD \          # Load BPF filter from file descriptor
    -- python3 script.py
```

**Critical security considerations**: Always use `--new-session` or apply seccomp filtering for TIOCSTI to prevent terminal injection escapes (CVE-2017-5226). Binding D-Bus sockets without filtering allows escape via systemd; use xdg-dbus-proxy for filtering.

### Alternative sandboxing tools comparison

| Tool | Strengths | Best for |
|------|-----------|----------|
| **nsjail** (Google) | Kafel BPF language, Protobuf configs, cgroups integration | Production code execution, CTF hosting |
| **Firejail** | 800+ pre-built profiles, desktop integration | Desktop application sandboxing |
| **Podman rootless** | Full OCI compatibility, mature ecosystem | Container workloads |
| **systemd-nspawn** | Deep systemd integration | System containers (requires root) |

For a custom sandboxing server, **nsjail** offers the best balance of features and configurability, while **Bubblewrap** provides more granular control with a smaller attack surface (~5k lines of C).

## Copy-on-write filesystem strategies

OverlayFS combines a read-only lower layer with a writable upper layer, presenting a unified view at the merged mountpoint. The **work directory** is mandatory for writable overlays—it stages atomic operations during copy-up.

**Privilege requirements**: Native OverlayFS requires `CAP_SYS_ADMIN`, but kernel 5.11+ allows mounting within user namespaces using the `userxattr` option. Since we require kernel 6.7+ (for Landlock IPC scoping), native OverlayFS is always available.

Recommended directory structure for ephemeral sandboxes:

```
/sandboxes/
├── base/                    # Read-only shared rootfs
│   └── rootfs/
└── sessions/
    └── session-{uuid}/
        ├── upper/           # Per-session writable layer
        ├── work/            # Overlay work directory (must be empty)
        └── merged/          # Mount point
```

**Mount command in user namespace** (kernel 5.11+):
```bash
unshare -m -U -r mount -t overlay overlay \
  -o userxattr,lowerdir=/base/rootfs,upperdir=/upper,workdir=/work \
  /merged
```

For **crash recovery**, running sandboxes in dedicated mount namespaces provides automatic cleanup—when the namespace is destroyed (all member processes exit), all mounts are implicitly unmounted. On server restart, scan for orphaned session directories, attempt lazy unmount (`umount -l`) of any remaining mounts, then remove the directories.

The `volatile` mount option improves performance but creates a crash indicator at `$workdir/work/incompat/volatile`—detect this on startup and discard corrupted sessions.

## Network egress filtering approaches

Network namespace isolation starts sandboxes with only a loopback interface. For controlled egress, create a **veth pair** connecting the sandbox namespace to the host, then apply filtering.

**Domain-based filtering challenges**: For HTTPS, the Server Name Indication (SNI) extension in TLS ClientHello is transmitted in plaintext, allowing domain identification without decryption. A transparent proxy (Squid) with SNI peek-and-splice can whitelist domains like pypi.org and crates.io without MITM decryption:

```squid
acl allowed_https_sites ssl::server_name "/etc/squid/whitelist.txt"
ssl_bump peek step1 all
ssl_bump splice step3 allowed_https_sites
ssl_bump terminate step2 all  # Block non-whitelisted
```

**Limitations**: TLS 1.3 with Encrypted Client Hello (ECH) defeats SNI inspection. IP-based bypass remains possible. For maximum security, consider full network isolation with allowed traffic passing through a forward proxy.

**Landlock network restrictions** (kernel 6.4+, ABI v4) only restrict TCP bind/connect operations—UDP, ICMP, and other protocols are NOT restricted. This makes Landlock insufficient as a standalone network filter.

## Defense-in-depth security layers

A robust sandbox combines multiple protection mechanisms, each addressing different attack vectors:

### Seccomp-BPF syscall filtering

Seccomp filters intercept syscalls before kernel execution, returning actions like ALLOW, KILL_PROCESS, or ERRNO. Docker's default profile blocks ~44 dangerous syscalls while allowing 300+. For interpreted code (Python, Node.js), typically allow:

```
read, write, openat, close, fstat, mmap, mprotect, munmap, brk,
futex, clock_gettime, rt_sigaction, clone, wait4, socket, connect,
sendto, recvfrom, poll, select, getrandom, exit_group
```

**Note**: The socket/connect syscalls are allowed because network isolation is handled by namespaces. In an isolated network namespace, these syscalls succeed but have no external connectivity. If network access is enabled via veth pairs, the allowlist should align with the network policy.

In Rust, use `seccompiler` (rust-vmm, no C dependencies) for custom filters:

```rust
use seccompiler::{SeccompAction, SeccompFilter};

let filter = SeccompFilter::new(
    allowed_syscalls.into_iter().collect(),
    SeccompAction::Trap,   // Default: trap on disallowed
    SeccompAction::Allow,  // Match action
    ARCH,
)?;
seccompiler::apply_filter(&filter.try_into()?)?;
```

### Landlock filesystem sandboxing

Landlock (kernel 5.13+) provides unprivileged filesystem access control that complements namespaces:

```rust
use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, ABI};

Ruleset::default()
    .handle_access(AccessFs::from_all(ABI::V4))?
    .create()?
    .add_rule(PathBeneath::new(PathFd::new("/usr")?, AccessFs::from_read(ABI::V4)))?
    .add_rule(PathBeneath::new(PathFd::new("/tmp/sandbox")?, 
              AccessFs::ReadFile | AccessFs::WriteFile))?
    .restrict_self()?;
```

**Critical: Landlock and OverlayFS interaction**

Landlock rules applied to OverlayFS upper/lower layers do NOT automatically apply to the merged view. From kernel documentation: "A policy restricting an OverlayFS layer will not restrict the resulted merged hierarchy, and vice versa."

Always apply Landlock rules to the **merged mount path** that the sandboxed process actually accesses.

### File descriptor hygiene

Landlock and other LSMs only restrict operations on **newly opened** files. File descriptors opened before `landlock_restrict_self()` retain their original permissions.

**Requirements before sandbox entry**:
1. Close all non-essential FDs inherited from parent
2. Set `O_CLOEXEC` on any FDs that must remain open (e.g., for communication)
3. Audit FD inheritance in sandbox entry code path
4. Never pass host FDs (config files, sockets) to sandboxed process

### Capability management

Drop all capabilities, especially `CAP_SYS_ADMIN` (near-root access), `CAP_SYS_PTRACE` (sandbox escape vector), and `CAP_NET_ADMIN`. Always set `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation via setuid binaries.

### Security implementation order

The order of applying security controls is critical. Incorrect ordering can either prevent sandbox setup (by blocking required syscalls too early) or leave security gaps.

**Correct order**:
1. Create namespaces (user, mount, PID, network, IPC, UTS)
2. Configure network (veth pairs if egress needed)
3. Set up mounts (overlay, bind mounts, /proc, /dev)
4. Close unnecessary file descriptors
5. Apply Landlock rules (to merged paths, not underlying layers)
6. Set `NO_NEW_PRIVS` (prevents setuid escalation)
7. Drop all capabilities
8. Install seccomp filter (**LAST** — must not block setup syscalls)

**Why seccomp last**: The seccomp filter blocks syscalls. If applied too early, it may block syscalls needed for the setup steps above (mount, setns, prctl, etc.).

## Prior art and production approaches

### Isolation technology spectrum

| Approach | Startup | Memory | Kernel isolation | Use case |
|----------|---------|--------|------------------|----------|
| **Namespaces + seccomp** | ~10ms | Minimal | Shared kernel | Trusted-ish code, fast startup |
| **gVisor (runsc)** | ~50ms | ~20MB | User-space kernel | Untrusted code, kernel exploit protection |
| **Firecracker microVM** | ~125ms | ~5MB | Separate kernel | Multi-tenant hostile workloads |

**gVisor** reimplements Linux syscalls in a Go-based user-space kernel (Sentry), protecting against kernel vulnerabilities at the cost of ~2× syscall latency. Used by GKE Sandbox, Cloud Run, and Cloud Functions.

**Firecracker** provides hardware-level isolation via KVM microVMs with a minimal attack surface (only 5 emulated devices). Powers AWS Lambda and Fargate. The companion **Jailer** applies additional namespace/seccomp isolation.

**nsjail** offers the best ROI for custom sandboxes—Fly.io notes: "if I wasn't hosting hostile code, I would probably tune an nsjail configuration before I bought into a containerization strategy."

### AI agent sandboxing projects

**E2B** (e2b.dev) provides Firecracker-based sandboxes with ~150ms startup, used by 88% of Fortune 100 companies for AI agent workflows. **Daytona** offers Docker-based sandboxes with <90ms creation. For self-hosted solutions, **Arrakis** uses cloud-hypervisor microVMs with snapshot-and-restore capabilities.

Existing MCP sandbox servers include **code-sandbox-mcp** (Docker-based), **Phil Schmid's sandbox** (uses llm-sandbox), and **QuickJS sandbox** (WebAssembly isolation). None combine Rust with comprehensive Linux sandboxing.

## Rust ecosystem and implementation patterns

### Essential crates

| Crate | Purpose | Maturity |
|-------|---------|----------|
| **nix** (15M+ downloads) | Safe Unix syscalls, namespace operations | Production |
| **caps** (8M+ downloads) | Pure Rust capability management | Production |
| **landlock** | Official Landlock LSM bindings | Production |
| **seccompiler** | Native BPF compilation (rust-vmm) | Production |
| **hakoniwa** | Integrated sandbox (namespaces + Landlock + seccomp + resource limits) | Production (v1.2+) |

**Note on hakoniwa**: The `hakoniwa` crate provides an integrated sandboxing solution that combines namespaces, resource limits, Landlock, and seccomp. It uses `libseccomp` (C bindings) for seccomp filtering. For custom seccomp filters outside hakoniwa's scope, prefer pure-Rust `seccompiler`.

**Rust vs Go for sandboxing**: Rust's explicit threading model handles namespaces cleanly, while Go's M:N goroutine scheduling causes subtle bugs after `unshare()`/`clone()` when namespace changes don't propagate to all goroutines. The youki developers note: "The container runtime requires system calls with special handling in Go. This is tricky; with Rust, it's not that tricky."

### Async patterns for MCP servers

Use `tokio::task::spawn_blocking` for namespace/mount operations (blocking syscalls):

```rust
async fn create_sandbox(config: SandboxConfig) -> Result<SandboxHandle> {
    let sandbox = task::spawn_blocking(move || {
        hakoniwa::Sandbox::new()
            .unshare(Namespace::Pid | Namespace::Mount | Namespace::Net)
            .rootfs(&config.rootfs)
            .spawn()
    }).await??;
    
    Ok(SandboxHandle { child: sandbox })
}
```

For managing multiple sessions, use an actor pattern with message passing:

```rust
enum SessionMessage {
    Execute { command: String, reply: oneshot::Sender<Result<Output>> },
    Cleanup { reply: oneshot::Sender<()> },
}

async fn session_actor(mut rx: mpsc::Receiver<SessionMessage>, sandbox: Sandbox) {
    while let Some(msg) = rx.recv().await {
        match msg {
            SessionMessage::Execute { command, reply } => {
                let result = sandbox.execute(&command).await;
                let _ = reply.send(result);
            }
            SessionMessage::Cleanup { reply } => {
                sandbox.cleanup().await;
                let _ = reply.send(());
                break;
            }
        }
    }
}
```

### Lifecycle management strategies

Store session state at `~/.mcp-sandboxes/{session-id}/` with PID files for crash detection. Implement three cleanup mechanisms:

1. **TTL expiration**: Background task checks `last_accessed` timestamps
2. **Startup cleanup**: Scan for orphaned sessions where PID no longer exists
3. **Reference counting**: `SessionHandle` implements `Drop` to decrement refcount

For orphaned mounts, sort by depth (deepest first) and apply lazy unmount:

```rust
async fn cleanup_orphaned_session(path: &Path) -> Result<()> {
    let mounts = get_mounts_under(path)?;
    for mount in mounts.iter().rev() {
        nix::mount::umount2(mount, MntFlags::MNT_DETACH)?;
    }
    fs::remove_dir_all(path)?;
    Ok(())
}
```

## Recommended architecture

For a production MCP sandbox server:

1. **Use rmcp** for MCP protocol with stdio transport
2. **Use hakoniwa** for integrated sandboxing (namespaces + Landlock + seccomp + resource limits)
3. **Native OverlayFS** with `userxattr` for CoW filesystems (requires kernel 5.13+, satisfied by our 6.7+ minimum)
4. **Layer security in correct order**: namespaces → network → mounts → close FDs → Landlock → NO_NEW_PRIVS → drop caps → seccomp (last)
5. **Session persistence**: Directory structure at `~/.mcp-sandboxes/{session-id}/workspace` accessible to both host and sandbox
6. **Network**: Default isolated; if egress needed, veth pair with SNI-filtering transparent proxy

For hostile multi-tenant workloads, consider **Firecracker microVMs**—the 125ms startup cost is acceptable for the hardware isolation boundary. For single-tenant AI agent use cases, namespace-based isolation with comprehensive seccomp filtering provides sufficient security with faster startup.
