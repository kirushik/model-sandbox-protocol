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

## References

- [Implementation notes.md](../Implementation%20notes.md) — initial technical research
- [SECURITY.md](./SECURITY.md) — threat model and security policy