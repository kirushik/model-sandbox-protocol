# System Requirements

This document specifies the host system requirements for running the model-sandbox-protocol MCP server.

## Kernel Version Requirements

| Version | Status | Features Available |
|---------|--------|-------------------|
| **5.13** | Minimum | Landlock ABI v1 (filesystem sandboxing) |
| **6.4** | Recommended | Landlock ABI v4 (TCP network restrictions) |
| **6.7+** | Optimal | Landlock ABI v6 (IPC scoping) |

### Minimum: Linux 5.13

The absolute minimum kernel version is **5.13**. This is a hard requirement because:
- Landlock LSM (ABI v1) was introduced in 5.13
- Landlock is essential to our security model for unprivileged filesystem sandboxing
- Native OverlayFS in user namespaces requires 5.11+ (satisfied by 5.13 requirement)

**We do not support kernels older than 5.13.**

### Recommended: Linux 6.4

Kernel 6.4 adds Landlock ABI v4, enabling TCP network restrictions (bind/connect). Without this, network isolation relies solely on network namespaces.

**Note:** Landlock network restrictions only cover TCP bind/connect operations. UDP, ICMP, and other protocols are NOT restricted by Landlock. Network namespace isolation remains the primary network control.

### Optimal: Linux 6.7+

Kernel 6.7+ provides Landlock ABI v6 with IPC scoping:
- `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — Restricts connections to abstract Unix sockets
- `LANDLOCK_SCOPE_SIGNAL` — Restricts signal delivery to processes in the same/nested Landlock domain

These features improve inter-sandbox isolation.

## Verification

```bash
# Check kernel version
uname -r

# Check Landlock is enabled
dmesg | grep landlock  # Should show "landlock: Up and running"

# Or programmatically check Landlock ABI version
# (returns ABI version number, or error if unsupported)
```

**Reference:** [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)

## Landlock ABI Version Reference

| ABI | Kernel | Features Added |
|-----|--------|----------------|
| v1 | 5.13 | Basic filesystem restrictions |
| v2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER` (cross-directory rename/link) |
| v3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| v4 | 6.4 | TCP network restrictions (bind/connect) |
| v5 | 6.6 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| v6 | 6.7 | IPC scoping (abstract Unix sockets, signals) |

**Reference:** [Landlock ABI versions](https://docs.kernel.org/userspace-api/landlock.html#landlock-abi-versions)

## Kernel Configuration

### Unprivileged User Namespaces

User namespaces must be enabled for unprivileged users. Check and enable:

```bash
# Check current setting
sysctl kernel.unprivileged_userns_clone

# Enable (requires root)
sysctl -w kernel.unprivileged_userns_clone=1

# Persist across reboots
echo 'kernel.unprivileged_userns_clone=1' >> /etc/sysctl.d/99-userns.conf
```

**Note:** Some distributions (Debian, Ubuntu) have this enabled by default. Others (RHEL/CentOS, Arch) may require explicit enablement.

**Security consideration:** Enabling unprivileged user namespaces increases kernel attack surface. This is a known trade-off for unprivileged containerization. Keep kernel updated to mitigate namespace-related CVEs.

### cgroups v2 (Unified Hierarchy)

Resource limits require cgroups v2 in unified hierarchy mode.

**Verification:**
```bash
# Check if cgroups v2 is mounted
mount | grep cgroup2
# Or check for unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers
```

**Enabling cgroups v2:**

Most modern distributions (Ubuntu 21.10+, Fedora 31+, Debian 11+) use cgroups v2 by default. For older systems, add to kernel command line:
```
systemd.unified_cgroup_hierarchy=1
```

**Reference:** [cgroups v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

## Architecture

Only **x86_64** (amd64) Linux is supported. This is due to:
- Seccomp BPF filter architecture specificity (syscall numbers differ by architecture)
- Testing and validation scope

ARM64 support may be added in the future but is not currently tested.

## Host Tools and Packages

### Required

| Tool | Purpose | Verification |
|------|---------|--------------|
| None | All sandboxing uses kernel APIs directly via Rust crates | — |

### Optional (Development/Testing)

| Tool | Purpose | Installation |
|------|---------|--------------|
| `capsh` | Verify capability dropping | `apt install libcap2-bin` / `dnf install libcap` |
| `strace` | Debug syscall filtering | `apt install strace` / `dnf install strace` |

## Runtime Requirements

### File Descriptors

The sandbox manager may need elevated file descriptor limits for managing many concurrent sessions:

```bash
# Check current limits
ulimit -n

# Increase if needed (in shell)
ulimit -n 65536
```

### /proc and /sys Access

The MCP server process needs read access to:
- `/proc/self/` — For namespace operations
- `/sys/fs/cgroup/` — For resource limit configuration (if cgroups enabled)

## Compatibility Matrix

| Distribution | Default Kernel | User NS | cgroups v2 | Notes |
|--------------|----------------|---------|------------|-------|
| Ubuntu 22.04 LTS | 5.15 | ✓ | ✓ | Minimum supported LTS |
| Ubuntu 24.04 LTS | 6.8 | ✓ | ✓ | Full Landlock support |
| Debian 12 | 6.1 | ✓ | ✓ | Good support |
| Fedora 39+ | 6.5+ | ✓ | ✓ | Full Landlock support |
| RHEL 9 | 5.14 | Config | ✓ | Enable userns manually |
| Arch Linux | Rolling | Config | ✓ | Enable userns manually |

## Checking System Compatibility

Run this script to verify system compatibility:

```bash
#!/bin/bash
set -e

echo "=== System Requirements Check ==="

# Kernel version
KERNEL=$(uname -r)
MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)
echo "Kernel: $KERNEL"

if [ "$MAJOR" -lt 5 ] || { [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 13 ]; }; then
    echo "ERROR: Kernel 5.13+ required (Landlock support)"
    exit 1
fi

if [ "$MAJOR" -lt 6 ] || { [ "$MAJOR" -eq 6 ] && [ "$MINOR" -lt 4 ]; }; then
    echo "WARNING: Kernel 6.4+ recommended for Landlock network restrictions"
fi

# Landlock
if dmesg 2>/dev/null | grep -q "landlock: Up and running"; then
    echo "Landlock: Enabled"
else
    echo "WARNING: Landlock not detected (check dmesg or kernel config)"
fi

# User namespaces
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    USERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone)
    if [ "$USERNS" -eq 1 ]; then
        echo "Unprivileged user namespaces: Enabled"
    else
        echo "ERROR: Unprivileged user namespaces disabled"
        exit 1
    fi
else
    echo "Unprivileged user namespaces: Not applicable (always enabled)"
fi

# cgroups v2
if mount | grep -q "cgroup2"; then
    echo "cgroups v2: Mounted"
else
    echo "WARNING: cgroups v2 not mounted (resource limits unavailable)"
fi

# Architecture
ARCH=$(uname -m)
echo "Architecture: $ARCH"
if [ "$ARCH" != "x86_64" ]; then
    echo "ERROR: Only x86_64 is supported"
    exit 1
fi

echo "=== Check complete ==="
```

---

*Last updated: 2025-12-24*