# AI Agent Guide to Model Sandbox Protocol

This guide explains how AI agents can safely use the Model Sandbox Protocol (MSP) for code execution. It covers the sandbox environment, available tools, security constraints, and usage patterns.

## Overview

The Model Sandbox Protocol provides isolated execution environments for AI agents to run code safely. Each sandbox session uses Linux namespaces, overlayfs, and Landlock LSM to isolate code execution from the host system.

## Available MCP Tools

### Session Management

#### `sandbox_create`
Create a new isolated sandbox session.

**Parameters:**
- `name` (optional): Human-readable name for logging/debugging
- `workspace_path` (optional): Absolute path to a host directory to mount as `/workspace`
- `timeout_seconds` (optional): Session TTL in seconds (default: 3600)

**Returns:**
- `session_id`: UUID to use with other tools
- `created_at`: ISO 8601 timestamp
- `expires_at`: Session expiration timestamp
- `workspace_mounted`: Boolean indicating if workspace was mounted
- `workspace_path`: The workspace path if mounted

**Example:**
```json
{
  "name": "python-analysis",
  "workspace_path": "/home/user/project",
  "timeout_seconds": 1800
}
```

#### `sandbox_list`
List all active sandbox sessions.

**Returns:**
- `sessions`: Array of session info objects
- `total`: Count of sessions

#### `sandbox_destroy`
Destroy a sandbox session and clean up resources.

**Parameters:**
- `session_id`: Session ID to destroy

### Code Execution

#### `sandbox_execute`
Execute a command in the sandbox.

**Parameters:**
- `session_id`: Session ID from `sandbox_create`
- `command`: Command to execute (e.g., `python`, `cargo`, `sh`)
- `args` (optional): Array of command arguments
- `working_dir` (optional): Working directory inside sandbox

**Returns:**
- `stdout`: Standard output
- `stderr`: Standard error
- `exit_code`: Process exit code
- `success`: Boolean (true if exit_code == 0)
- `timed_out`: Boolean indicating timeout

**Example:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "command": "python",
  "args": ["-c", "print('Hello, World!')"],
  "working_dir": "/workspace"
}
```

### File Operations

#### `sandbox_read_file`
Read a file from the sandbox session.

**Parameters:**
- `session_id`: Session ID from `sandbox_create`
- `path`: File path **relative to workspace root** (not absolute)

**Returns:** File content as string

**Constraints:**
- Path must be relative (no leading `/`)
- Path traversal (`..`) is rejected
- Maximum file size: 10 MB

#### `sandbox_write_file`
Write a file to the sandbox session.

**Parameters:**
- `session_id`: Session ID from `sandbox_create`
- `path`: File path relative to workspace root
- `content`: File content to write

**Returns:**
- `success`: Boolean
- `bytes_written`: Number of bytes written
- `path`: The path written to

## Filesystem Visibility

### Inside the Sandbox

| Path | Description | Writable |
|------|-------------|----------|
| `/workspace` | Mounted workspace (if configured) | Yes* |
| `/tmp` | Temporary files (tmpfs) | Yes |
| `/session` | Session-specific storage | Yes |
| `/bin`, `/usr/bin` | System binaries | No |
| `/lib`, `/usr/lib` | System libraries | No |
| `/etc` | Limited config files | No |
| `/proc` | Process info (namespaced) | No |
| `/dev` | Minimal device nodes | Limited |

*Writes to `/workspace` go to an overlay layer, not the host filesystem.

### What's Hidden/Masked

The following paths are **never** accessible from the sandbox:

- `~/.ssh` - SSH keys
- `~/.aws` - AWS credentials
- `~/.config/gcloud` - GCP credentials
- `~/.kube` - Kubernetes config
- `~/.gnupg` - GPG keys
- `~/.gitconfig` - Git config (may contain tokens)
- `~/.netrc` - Network credentials
- `~/.git-credentials` - Git credential cache
- `~/.config/gh` - GitHub CLI credentials
- `~/.docker/config.json` - Docker credentials
- `~/.npmrc` - NPM credentials
- `~/.pypirc` - PyPI credentials
- `~/.cargo/credentials` - Cargo credentials

### `/proc` Namespace Isolation

The sandbox uses PID namespace isolation:
- Processes inside the sandbox see themselves as PID 1
- Host processes are not visible
- `/proc` shows only sandbox processes

## Available System Tools

The following tools are available in the sandbox:

| Tool | Purpose |
|------|---------|
| `sh` | Shell for scripting |
| `cat` | Read file contents |
| `tee` | Write stdin to file |
| `mkdir` | Create directories |
| `stat` | File information |
| `env` | Environment variables |
| `echo` | Output text |
| `ls` | List directory |
| `pwd` | Print working directory |

## Usage Patterns

### Pattern 1: Simple Script Execution

```
1. sandbox_create() → session_id
2. sandbox_execute(session_id, "python", ["-c", "code..."])
3. sandbox_destroy(session_id)
```

### Pattern 2: Multi-File Project

```
1. sandbox_create(workspace_path="/path/to/project") → session_id
2. sandbox_execute(session_id, "cargo", ["build"])
3. sandbox_execute(session_id, "cargo", ["test"])
4. sandbox_read_file(session_id, "target/debug/output.txt")
5. sandbox_destroy(session_id)
```

### Pattern 3: Iterative Development

```
1. sandbox_create() → session_id
2. sandbox_write_file(session_id, "script.py", "initial code")
3. sandbox_execute(session_id, "python", ["script.py"])
4. (read output, modify code)
5. sandbox_write_file(session_id, "script.py", "fixed code")
6. sandbox_execute(session_id, "python", ["script.py"])
7. sandbox_destroy(session_id)
```

## Security Constraints

### What You Cannot Do

1. **Access host credentials** - All credential paths are blocked
2. **Escape the sandbox** - Namespace isolation prevents escape
3. **Access host processes** - PID namespace hides host processes
4. **Modify host filesystem** - Overlayfs isolates writes
5. **Use network** - Network namespace isolates connectivity
6. **Escalate privileges** - `MS_NOSUID` prevents setuid binaries

### Path Validation

All file paths passed to `sandbox_read_file` and `sandbox_write_file` are validated:

- ❌ Absolute paths: `/etc/passwd`
- ❌ Path traversal: `../../../etc/passwd`
- ❌ NUL bytes in paths
- ✅ Relative paths: `src/main.py`
- ✅ Nested paths: `project/src/lib/utils.py`

### Timeouts

- Per-command timeout: 30 seconds (default)
- Session TTL: 3600 seconds (default, configurable)

Commands that exceed the timeout are terminated and return `timed_out: true`.

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "Session not found" | Invalid session_id | Create a new session |
| "Session expired" | Session TTL exceeded | Create a new session |
| "Path must be relative" | Absolute path provided | Use relative path |
| "Path traversal not allowed" | `..` in path | Use direct path |
| "Mount error" | Invalid workspace path | Check path exists and is directory |

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | General error |
| 126 | Command not executable |
| 127 | Command not found |
| 137 | Killed (timeout/OOM) |

## Best Practices

1. **Always destroy sessions** - Clean up sessions when done to free resources
2. **Use relative paths** - File operations require relative paths
3. **Check success flags** - Always verify `success` field in results
4. **Handle timeouts** - Long-running commands may be killed
5. **Keep sessions short** - Create sessions for specific tasks, destroy when done
6. **Use workspace for projects** - Mount existing codebases via workspace_path

## Limitations

1. **No persistent storage** - Session data is lost after destroy
2. **No network access** - External APIs cannot be called
3. **No GUI** - Only command-line tools available
4. **Linux only** - x86_64 Linux with kernel 6.7+ required
5. **UTF-8 only** - Binary file content is not supported in file operations