# Suggested commands

## Build / check / lint / fmt
- `cargo check --quiet`
- `cargo clippy`
- `cargo fmt --all`

## Tests
- `cargo test`
  - Requires unprivileged user namespaces enabled.
  - Assumes host meets `docs/SYSTEM_REQUIREMENTS.md`.

## Useful system checks
- `uname -r` (kernel version)
- `sysctl kernel.unprivileged_userns_clone`
- `mount | grep cgroup2`
