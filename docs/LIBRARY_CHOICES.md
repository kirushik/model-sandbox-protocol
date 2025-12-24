# Library Choices

This document captures crate selection decisions and their rationale.

## Versioning Policy

**Default**: Use the latest stable release of libraries published on crates.io.

When a specific version is pinned or a newer version is explicitly avoided, document:
1. The reason for the override
2. A review date (TTL) to reconsider the decision

## Selection Principles

When choosing dependencies:

1. **Prefer lean, small, newer, Linux-only alternatives** when they meet our needs
2. **Fall back to mainstream, well-maintained crates** when no suitable lean alternative exists
3. **Minimize dependency tree** — fewer transitive dependencies means smaller attack surface

## Core Dependencies

### Async Runtime: `tokio`

The standard async runtime for Rust. Required by `rmcp` (the MCP SDK), so we use it directly rather than adding a compatibility layer with an alternative runtime.

### Error Handling: `miette` + `thiserror`

- `thiserror` for defining error types with derive macros
- `miette` for rich diagnostic output (useful for CLI/MCP error reporting)

This is the modern Rust error handling stack.

### MCP Protocol: `rmcp`

The official Rust MCP SDK. No mature alternatives exist. Actively maintained with support for multiple protocol versions (2024-11-05, 2025-03-26, 2025-06-18).

### Sandboxing & Linux APIs

| Purpose | Crate | Notes |
|---------|-------|-------|
| Unix syscalls | `nix` | Safe wrappers, very mature (15M+ downloads) |
| Capabilities | `caps` | Pure Rust, no C dependencies |
| Landlock LSM | `landlock` | Official bindings |
| Seccomp BPF | `seccompiler` | rust-vmm, no C dependencies |
| Integrated sandbox | `hakoniwa` | Namespaces + Landlock + seccomp + resource limits |

**Note on hakoniwa**: This crate provides an integrated sandboxing solution combining namespaces, resource limits, Landlock, and seccomp. It uses `libseccomp` (C bindings) rather than pure-Rust `seccompiler`. We accept this trade-off for the integrated functionality. For custom seccomp filters outside hakoniwa's scope, prefer `seccompiler`.

### Filesystem

For CoW overlay filesystems:
- Native OverlayFS with `userxattr` option (requires kernel 5.13+, which is our minimum)

## Crates to Avoid

- `libc` directly — prefer `nix` for safety
- `unshare` — unmaintained since 2021; use `hakoniwa` instead

## Adding New Dependencies

Before adding a crate, consider:

1. Is there a simpler solution using existing dependencies?
2. How many transitive dependencies does it pull in?
3. Is it actively maintained?
4. Does it have a good security track record?

Document significant dependency additions in this file.