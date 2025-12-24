# Model Sandbox Protocol

Namespace-based sandboxing MCP server for safe AI agent code execution. Rust, x86_64 Linux only, kernel 6.7+ required. See `docs/SYSTEM_REQUIREMENTS.md` for full requirements.

## Development Environment Assumptions

For now, we assume the development environment (and CI, if any) **meets the full system requirements**:
- x86_64 Linux
- Kernel 6.7+
- Landlock enabled with ABI v6+ support
- cgroups v2 mounted (unified hierarchy)
- Unprivileged user namespaces enabled

This impacts tests and developer workflows: system requirement checks and “real system” tests are allowed to hard-fail when these assumptions are violated.

## Documentation

- `docs/ARCHITECTURE.md` — system design and component breakdown
- `docs/LIBRARY_CHOICES.md` — crate decisions, error handling, async runtime
- `docs/SECURITY_MODEL.md` — threat model and security policy
- `docs/SYSTEM_REQUIREMENTS.md` — kernel versions, cgroups, host prerequisites
- `Implementation notes.md` — early technical research (docs/ takes precedence)

## Available MCP Tools

Use `resolve-library-id` then `get-library-docs` from context7 to fetch up-to-date crate documentation.

Use `sequentialthinking` for complex problem breakdown, security analysis, or multi-step planning.

## Commands

```bash
cargo check --quiet      # verify compilation (prefer over build)
cargo clippy             # lint
cargo test               # run tests (requires unprivileged user namespaces)
cargo fmt --all          # format
```

## Workflow

Run `cargo check --quiet && cargo clippy` before committing. Code must compile and pass lints.

## Security Rules

- Never weaken security stance without discussion. If necessary, document rationale in `docs/SECURITY_MODEL.md` and reference it in code comments.
- Never write non-trivial code without tests. Add unit tests for new functionality, integration tests for sandbox behavior.
- Never trust user inputs. Validate all inputs at system boundaries.
- Never use `unwrap()`. Use `expect("explanation why this cannot fail")` or propagate errors with `?`.
