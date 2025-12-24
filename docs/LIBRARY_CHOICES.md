# Library Choices

This document captures crate selection decisions and their rationale.

## Selection Principles

When choosing dependencies:

1. **Prefer lean, small, newer, Linux-only alternatives** when they meet our needs
2. **Fall back to mainstream, well-maintained crates** when no suitable lean alternative exists
3. **Minimize dependency tree** — fewer transitive dependencies means smaller attack surface

## Core Dependencies

### Async Runtime: `smol`

Lightweight async runtime instead of full tokio. Appropriate for a lean, local-only tool.

### Error Handling: `miette` + `thiserror`

- `thiserror` for defining error types with derive macros
- `miette` for rich diagnostic output (useful for CLI/MCP error reporting)

This is the modern Rust error handling stack as of late 2025.

### MCP Protocol: `rmcp`

The official Rust MCP SDK. No mature alternatives exist.

### Sandboxing & Linux APIs

| Purpose | Crate | Notes |
|---------|-------|-------|
| Unix syscalls | `nix` | Safe wrappers, very mature (15M+ downloads) |
| Capabilities | `caps` | Pure Rust, no C dependencies |
| Landlock LSM | `landlock` | Official bindings |
| Seccomp BPF | `seccompiler` | rust-vmm, no C dependencies |
| Namespace spawning | `unshare` | Consider `hakoniwa` if it matures |

### Filesystem

For CoW overlay filesystems:
- Native overlayfs with `userxattr` on kernel 5.11+
- `fuse-overlayfs` fallback for older kernels (when we come around to supporting them)

## Crates to Avoid

- `tokio` — too heavy for our use case; use `smol`
- `libc` directly — prefer `nix` for safety
- `libseccomp` bindings — prefer pure Rust `seccompiler`

## Adding New Dependencies

Before adding a crate, consider:

1. Is there a simpler solution using existing dependencies?
2. How many transitive dependencies does it pull in?
3. Is it actively maintained?
4. Does it have a good security track record?

Document significant dependency additions in this file.
