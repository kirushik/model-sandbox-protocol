# System Requirements

This document specifies the host system requirements for running the model-sandbox-protocol MCP server.

## Kernel Version Requirements

| Version | Status | Features Available |
|---------|--------|-------------------|
| **5.13** | Minimum | Landlock ABI v1 (filesystem sandboxing) |
| **6.4** | Recommended | Landlock ABI v4 (TCP network restrictions) |
| **6.7+** | Optimal | Landlock ABI v6 (IPC scoping) |

### Currently chosen target: Linux 6.7+

The currently supported minimum kernel version is **6.7**. This is a hard requirement because:
- Landlock IPC scoping (ABI v6) is required for inter-sandbox isolation
- Abstract Unix socket scoping prevents cross-sandbox communication
- Signal scoping prevents signal injection attacks
- All earlier Landlock features (filesystem, TCP network) are included

**Support for kernels older than 6.7 is planned, but can take a while.**

### Why 6.7?

We chose 6.7 as the minimum because Landlock IPC scoping (ABI v6) is essential for proper sandbox isolation. Without it, sandboxed processes could communicate via abstract Unix sockets or send signals to other processes. Kernel 6.7 includes all earlier Landlock features (filesystem, TCP network).

**Note:** Landlock network restrictions (ABI v4) only cover TCP bind/connect operations. UDP, ICMP, and other protocols are NOT restricted by Landlock. Network namespace isolation remains the primary network control.

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

| ABI | Kernel | Features Added | Status |
|-----|--------|----------------|--------|
| v1 | 5.13 | Basic filesystem restrictions | Included |
| v2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER` (cross-directory rename/link) | Included |
| v3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` | Included |
| v4 | 6.4 | TCP network restrictions (bind/connect) | Included |
| v5 | 6.6 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` | Included |
| v6 | 6.7 | IPC scoping (abstract Unix sockets, signals) | **Required** |

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

**cgroups v2 is required.** The sandbox will refuse to start if cgroups v2 is not available, as resource limits are essential for preventing denial-of-service attacks.

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
| Ubuntu 24.04 LTS | 6.8 | ✓ | ✓ | **Recommended** — meets all requirements |
| Ubuntu 25.10 | 6.17 | ✓ | ✓ | Full support |
| Fedora 39+ | 6.5+ | ✓ | ✓ | Fedora 40+ (kernel 6.8+) recommended |
| Debian 13 (trixie) | 6.x | ✓ | ✓ | When released |
| Arch Linux | Rolling | Config | ✓ | Enable userns manually |
| Ubuntu 22.04 LTS | 5.15 | ✓ | ✓ | ❌ Kernel too old |
| Debian 12 | 6.1 | ✓ | ✓ | ❌ Kernel too old |
| RHEL 9 | 5.14 | Config | ✓ | ❌ Kernel too old |

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

if [ "$MAJOR" -lt 6 ] || { [ "$MAJOR" -eq 6 ] && [ "$MINOR" -lt 7 ]; }; then
    echo "ERROR: Kernel 6.7+ required (Landlock IPC scoping)"
    exit 1
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
