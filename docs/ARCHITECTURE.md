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

### Kernel Feature Fallbacks

We require a minimum kernel version of **5.13** (for Landlock). Features unavailable on older kernels degrade gracefully:

| Feature | Minimum Kernel | Fallback Behavior |
|---------|---------------|-------------------|
| Landlock filesystem | 5.13 | **Hard requirement** — no fallback |
| OverlayFS in userns | 5.11 | Satisfied by 5.13 requirement |
| Landlock TCP (ABI v4) | 6.4 | Network namespace isolation only |
| Landlock IPC scoping (ABI v6) | 6.7 | IPC namespace isolation only |

**Recommended kernel: 6.7+** for full set of Landlock restrictions.

> **TODO**: Implement runtime ABI detection and graceful degradation.
> 
> The sandbox manager should:
> 1. Detect Landlock ABI version at startup via `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
> 2. Log available security features
> 3. Apply the maximum available protections for the detected ABI
> 4. Warn (but continue) if running below recommended kernel version


## References

- [Implementation notes.md](../Implementation%20notes.md) — initial technical research
- [SECURITY_MODEL.md](./SECURITY_MODEL.md) — threat model and security policy
- [SYSTEM_REQUIREMENTS.md](./SYSTEM_REQUIREMENTS.md) — kernel and host OS requirements
