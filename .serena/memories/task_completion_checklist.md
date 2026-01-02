# Task completion checklist

Before you consider a change complete:
- `cargo fmt --all`
- `cargo check --quiet`
- `cargo clippy`
- `cargo test`

Security-sensitive changes:
- Ensure inputs are validated.
- Prefer running operations inside sandbox namespace (not via host FS shortcuts).
- Add/extend tests (unit + integration).
