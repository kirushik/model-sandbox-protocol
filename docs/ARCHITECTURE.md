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

## Design Decisions

Architectural decisions should be documented here with rationale. For library-specific choices, see [LIBRARY_CHOICES.md](./LIBRARY_CHOICES.md).

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
