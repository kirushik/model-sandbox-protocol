# Style & conventions

## Rust edition / tooling
- Rust edition: 2024 (`Cargo.toml`)
- Clippy lints: `unwrap_used = deny`, `expect_used = warn`.
- Prefer `cargo check --quiet` over `cargo build`.

## Code rules
- Avoid `unwrap()` entirely.
- Use `expect("reason")` only when truly impossible; otherwise propagate with `?`.
- Add tests for non-trivial code.
- Validate all user inputs at boundaries (MCP tool params).

## Project docs
- Security stance must not be weakened without discussion; document rationale in `docs/SECURITY_MODEL.md` and reference in code comments.

