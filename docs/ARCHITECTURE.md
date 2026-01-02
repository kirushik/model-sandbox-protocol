# Architecture

This document describes the high-level architecture of the model-sandbox-protocol MCP server.

> **Status**: Early development. This document will evolve as implementation progresses.

## Overview

A bubblewrap-based sandboxing MCP server for safe execution of code and tools by AI agents.

## Components

_To be documented as implementation progresses._

### MCP Server Layer

Handles JSON-RPC 2.0 protocol over stdio transport using the rmcp SDK.

### Sandbox Manager

Manages sandbox lifecycle: creation, execution, cleanup.

### Isolation Layer

Combines multiple Linux security mechanisms:
- User/mount/PID/network namespaces
- Landlock filesystem restrictions
- Seccomp-BPF syscall filtering
- Capability dropping

### Session Persistence

Copy-on-write filesystem layer for ephemeral workspaces.

#### Rootless OverlayFS lifecycle

- The server runs **unprivileged** (no host root).
- For session-backed sandboxes, OverlayFS is mounted **inside the sandbox mount namespace** (not on the host).
- Requirements:
  - Linux kernel **>= 5.11** OverlayFS user namespace support (`FS_USERNS_MOUNT`)
  - OverlayFS mounted with the `userxattr` option
  - Unprivileged user namespaces must be usable at runtime
    - On some systems (notably Ubuntu/Debian derivatives), AppArmor may restrict this via `kernel.apparmor_restrict_unprivileged_userns`.

**Implication:** the session `merged/` mount is **namespaced**. Host-side code must not assume `session.paths.merged` is a mounted view.

#### Workspace mounts

A sandbox is intended to be a thin “jail” wrapper around an existing project folder.

- If a `workspace_path` is provided at session creation time, the sandbox bind-mounts it into the sandbox at **`/workspace`**.
- If no workspace is provided, the sandbox operates with `/` as the default working directory.

Default working directory behavior:

- `sandbox_execute`: if the caller does not provide `working_dir`, default to:
  - `/workspace` when a workspace is mounted
  - `/` otherwise

#### MCP file tool contract

MCP defines file tools (`sandbox_read_file`, `sandbox_write_file`) as part of a general “sandboxed agent” experience.
In this project we interpret them relative to the mounted workspace for ergonomics:

- If a workspace is mounted, `path` is interpreted as **relative to `/workspace`**.
  - Example: `path: "src/main.rs"` reads `/workspace/src/main.rs`.
- If no workspace is mounted, `path` is interpreted as **relative to `/`**.
  - Example: `path: "etc/hosts"` reads `/etc/hosts`.

For safety and consistency, tool implementations should reject:
- absolute paths
- paths containing `..`
- NUL bytes

All file tool operations must execute **inside the sandbox namespace**, not by reading host `merged/`.

## Design Decisions

Architectural decisions should be documented here with rationale. For library-specific choices, see [LIBRARY_CHOICES.md](./LIBRARY_CHOICES.md).

### Root Filesystem Strategy: Host OS Exposure via Denylist (Phase 3)

**Decision**: For Phase 3, the sandbox filesystem view will aim to expose a “mostly-complete” host OS userland (so common tools like `echo`, `mkdir`, `cat`, `tee`, language runtimes, package managers, etc. are available), while preventing access to sensitive host configuration and credentials using a **denylist / masking** approach inside the sandbox mount namespace.

This is motivated by developer ergonomics and compatibility: we want a sandbox that behaves like a real machine and can execute common toolchains without bundling a separate rootfs image.

**How it works (high-level)**:
- The sandbox mount namespace bind-mounts large portions of the host filesystem as **read-only** (e.g. `/usr`, `/bin`, `/lib*`, etc.) so installed tools are usable.
- Sensitive paths are “masked” in the sandbox namespace by over-mounting them with empty directories/tmpfs or by omitting them entirely (denylist).
- Session persistence (OverlayFS) continues to provide a writable layer for sandbox changes without allowing mutation of the read-only host base.

**Why denylist (and why now)**:
- Phase 3 needs reliable in-sandbox implementations for file tools and command execution without requiring a packaged rootfs.
- Host environments vary; exposing the host userland reduces failed executions due to missing tools.

**Security trade-offs / drawbacks**:
- A denylist is inherently riskier than an allowlist: missed paths can cause **secret leakage** (P1) or increase blast radius on a sandbox escape (P0).
- Larger visible userland increases attack surface (more binaries, more parsers, more dynamic loaders, etc.).
- Non-hermetic behavior: sandbox behavior can change when host packages update.

**Mitigations / constraints (Phase 3)**:
- Host mounts must be read-only inside the sandbox mount namespace.
- Sensitive host directories must never be accessible from the sandbox, especially:
  - `$HOME` and common credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.kube`, `~/.netrc`)
  - Host service sockets (e.g. D-Bus)
  - `/proc` must be a fresh procfs mount; do not expose host `/proc`
- File tools must still resolve relative to `/workspace` when mounted, and operate inside namespace.

**Future direction**:
- Phase 4 security hardening (Landlock, seccomp, caps drop, FD hygiene, etc.) becomes more important under this strategy, and should be treated as mandatory follow-up.

### Timeout Enforcement Policy (Hard Kill)

Sandbox execution timeouts are enforced with a **hard kill** policy:

- When the configured timeout elapses, the sandbox runner terminates the child process with **SIGKILL** (no graceful shutdown).
- Rationale:
  - Deterministic behavior for tests and automation (no long “grace periods”).
  - Avoids relying on library-specific timeout semantics (e.g., second-granularity `wait_timeout(seconds)` APIs).
  - Avoids hangs caused by commands that ignore SIGTERM or spawn child processes that linger.

If you observe slow or stuck test runs (e.g., “has been running for over 60 seconds”), first check timeout enforcement logic and ensure it is not being inadvertently converted to second-granularity timeouts.

### Kernel Requirements

We require a minimum kernel version of **6.7**. This is a hard requirement — the sandbox will refuse to start on older kernels.

| Feature | Kernel | Status |
|---------|--------|--------|
| Landlock filesystem (ABI v1) | 5.13 | Included |
| OverlayFS in userns | 5.11 | Included |
| Landlock TCP (ABI v4) | 6.4 | Included |
| Landlock IPC scoping (ABI v6) | 6.7 | **Required** |
| cgroups v2 | — | **Required** |

**Why 6.7?** Landlock IPC scoping is essential for proper sandbox isolation. Without it, sandboxed processes could communicate via abstract Unix sockets or send signals to other processes.

It's a goal to support a wider range of kernels in the future, but for now we prioritize security and simplicity.

See [SYSTEM_REQUIREMENTS.md](./SYSTEM_REQUIREMENTS.md) for distribution compatibility and verification steps.

## References

- [Implementation notes.md](../Implementation%20notes.md) — initial technical research
- [SECURITY_MODEL.md](./SECURITY_MODEL.md) — threat model and security policy
- [SYSTEM_REQUIREMENTS.md](./SYSTEM_REQUIREMENTS.md) — kernel and host OS requirements
