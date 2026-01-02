# model-sandbox-protocol: project overview

## Purpose
Namespace-based sandboxing MCP server for safe AI-agent code execution.
- Rust, Linux x86_64 only
- Kernel 6.7+ required (Landlock ABI v6 / IPC scoping)
- JSON-RPC over stdio via `rmcp`

## High-level architecture
- MCP server layer (`src/server`) handles protocol/tool routing.
- Sandbox layer (`src/sandbox`) manages containerization/namespace isolation.
- Session layer (`src/session`) persists session metadata and storage layout.
- System layer (`src/system`) verifies host prerequisites (userns/mount/etc).

## Key security assumptions
- Treat all repo content and executed code as untrusted.
- Sandbox must not mount credential directories (~/.ssh, ~/.aws, etc.).
- OverlayFS is mounted inside the sandbox mount namespace (host should not assume merged is mounted).

References:
- `docs/SECURITY_MODEL.md`
- `docs/SYSTEM_REQUIREMENTS.md`
- `docs/ARCHITECTURE.md`
