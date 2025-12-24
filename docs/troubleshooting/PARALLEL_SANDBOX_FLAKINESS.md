# Parallel Sandbox Flakiness: Intermittent Test Timeouts (Research + Fix Plan)

## Resolution (Implemented)

**Status: FIXED**

The issue was resolved by implementing **Fix Class B: Setup phase serialization** from the candidate fixes below, with an additional post-spawn delay to account for child process mount operations.

### Implementation Summary

A global setup semaphore was added to `src/sandbox/container.rs` that serializes the namespace/mount creation phase:

1. **Setup semaphore**: A static `Mutex<()>` (`SETUP_SEMAPHORE`) gates the critical section
2. **Critical section**: Lock is acquired before `build_container()` and held through `cmd.spawn()`
3. **Post-spawn delay**: A 5ms delay after `spawn()` allows the child process to complete mount operations (`newns`) before releasing the semaphore
4. **Release point**: Lock is released after the delay, before the wait loop
5. **Parallel execution**: Commands still run in parallel after setup; only the setup phase is serialized

### Root Cause Analysis

The initial fix (semaphore only) reduced but did not eliminate flakiness. Investigation revealed:

- `spawn()` forks and returns quickly, but the child process continues setup
- After `spawn()` returns, the child calls `newns()` which performs mount operations
- Multiple children doing concurrent mount operations caused kernel-level contention
- The 5ms post-spawn delay staggers the mount-heavy phase, eliminating contention

This is a pragmatic fix that works within hakoniwa's fork-based architecture without requiring upstream changes.

### Validation

- Added `test_parallel_sandbox_stress` integration test (32 threads × 4 iterations = 128 concurrent executions)
- All existing tests pass consistently
- Stress test passes reliably across 50+ consecutive runs

### Instrumentation Added

Tracing instrumentation was added (gated behind `RUST_LOG`) for future debugging:
- Container creation and build phases
- Command resolution and execution
- Setup semaphore acquisition/release
- Timeout and completion events

---

## Problem Statement

We intermittently observe sandbox integration tests timing out under parallel execution. A representative failure looks like:

- `test_tmp_writable` times out running a simple shell write to `/tmp`
- `test_working_directory` times out running `pwd` in `/tmp`
- `SandboxError::Timeout { timeout_seconds: 30 }` bubbles up after the full timeout
- Rust test harness sometimes emits: “has been running for over 60 seconds”

This is unacceptable long-term because:
- The product must support multiple sandboxes in parallel (e.g., multiple agents).
- “Make tests serial” is not a real fix; it masks concurrency failures and provides false confidence.

This document proposes a concrete troubleshooting and remediation plan, with OS + library context and recommended instrumentation.

## Current Implementation Context (Phase 1)

### Sandbox lifecycle shape today
- Each `SandboxContainer::execute()` builds a fresh `hakoniwa::Container`.
- `Container::new()` creates: mount namespace, user namespace (maps current user), PID namespace, and mounts `/proc`.
- We additionally unshare: IPC, Network, UTS.
- We use `rootfs("/")` which bind-mounts a limited set of host dirs (`/bin`, `/etc`, `/lib`, `/lib64`, `/lib32`, `/sbin`, `/usr`) read-only into the new mount namespace.
- We mount `/dev` (hakoniwa minimal device set), tmpfs `/tmp`, and procfs `/proc` (explicitly).

### Execution and output capture
- We pipe stdout/stderr and drain them concurrently in helper threads.
- We enforce timeout in-process with millisecond precision:
  - poll `try_wait()`
  - on timeout: hard kill (SIGKILL) + wait.
- This hard-kill policy is documented in `docs/ARCHITECTURE.md`.

### Why the failures are suspicious
When failures occur, they are “simple command never completes.” This points to:
- sandbox setup occasionally getting stuck before the command runs,
- deadlocking in mount namespace setup,
- hanging in a kernel interaction (procfs mount, bind mount, etc.),
- or a resource contention / throttling effect under parallel userns/mount operations.

It is **not** consistent with stdout/stderr deadlocks (those typically require large output). The failing commands (`pwd`, writing a tiny file) should produce negligible output.

## Hypotheses (Ranked)

### H1: Kernel-level contention or throttling in concurrent userns+mount namespace creation
Creating user namespaces, mounting procfs, and performing bind mounts/temporary root operations can contend on global kernel locks or per-user limits when done at high concurrency.

Possible constraints:
- `max_user_namespaces`
- per-user process limits (`RLIMIT_NPROC`)
- cgroup PID limits (if applicable)
- mount namespace / procfs mount patterns
- system-level LSM hooks (AppArmor/SELinux/Landlock) slow paths

Symptom match:
- Only manifests under parallelism
- Commands time out without producing output
- “sometimes” behavior

### H2: Hakoniwa internal implementation uses global tempdirs / shared paths
If hakoniwa uses tempdirs under `/tmp` for rootdir, and we mount tmpfs `/tmp` in the container, there may be a race between parent and child, or between multiple sandboxes if paths collide or cleanup interferes.

What to check:
- whether hakoniwa uses `tempfile` with unique directories (it should),
- whether `rootdir` defaults are truly per-container and isolated,
- whether cleanup happens in a way that can interfere with concurrent setups.

### H3: Process group / PID namespace teardown interactions (reaping, zombies)
If sandboxes spawn children or use PID namespaces, and we terminate a process on timeout, we need to ensure the namespace is properly reaped. Under concurrency, leakiness can cause:
- accumulating zombies,
- PID exhaustion,
- blocking waits.

However, in our failures, “tiny commands” time out, suggesting they never started or they’re stuck in setup.

### H4: /etc bind-mount and NSS/resolution stalls under no network namespace
Some commands can trigger NSS lookups (e.g., username lookups), which can hang if `nsswitch.conf` points to network-based services and the environment is partially configured.

But `pwd` and `echo` should not require NSS. `sh` might do some resolution depending on prompt or environment, but the commands are non-interactive. This is a lower-priority hypothesis.

### H5: Our timeout loop is masking “wait never returns because pipes aren’t drained”
We drain pipes concurrently, which should prevent deadlocks. But if the child never execs and never closes pipes cleanly, the readers might block. That said, we kill the child on timeout, which should close pipes.

This is less likely, but we should confirm with instrumentation.

## Immediate Goal

Reproduce deterministically and identify the exact wait point:
- Is the child process actually spawned?
- Does it exec the intended program?
- Is it blocked in sandbox setup (namespaces/mounts)?
- Is it blocked in the program itself?
- Is it blocked in I/O or waiting?

## Reproduction Plan

### 1) Controlled high-parallelism reproduction
Create a stress test that spawns many concurrent sandbox executions, e.g.:
- N = 64 or 128
- Each runs `/bin/sh -c 'pwd; echo hi >
 /tmp/x; cat /tmp/x'`
- Timeout set to something strict but not tiny (e.g. 2s)
- Run this several times in a loop (e.g. 100 iterations) to surface flakiness.

This should be an integration test or a dedicated stress test binary (preferred) that can be run locally and in CI.

### 2) Record concurrency-dependent environment metrics
Before and after the stress run, collect:
- `sysctl kernel.unprivileged_userns_clone`
- `sysctl user.max_user_namespaces`
- `ulimit -u` / `RLIMIT_NPROC`
- `/proc/sys/user/max_user_namespaces`
- `/proc/sys/kernel/pid_max`
- current process count for the user
- cgroup v2 pids controller status (if used)

Store those in test logs (or a debug mode output).

### 3) Compare: single-thread vs parallel
Run the same workload:
- serial (baseline)
- parallel with increasing concurrency
Measure:
- median runtime
- tail latency (p95/p99)
- failure rate

## Instrumentation Plan (Code Changes)

Add targeted debug logging around the exact phases of sandbox execution. Requirements:
- Must not spam by default; gated behind `RUST_LOG` / tracing env filter.
- Each sandbox execution should have a unique “exec_id” to correlate events.

Suggested trace points:
1. `build_container()` start/end
2. `container.rootfs("/")` start/end
3. devfs/tmpfs/procfs mount start/end
4. `container.command(...)` creation
5. `cmd.spawn()` start/end (log PID if available)
6. stdout/stderr drain threads started
7. wait loop iterations with elapsed time
8. timeout path: “sending SIGKILL”, “wait after kill done”
9. join drain threads completed

Also log:
- resolved program path
- working dir
- timeout duration

### Extra: long-running watchdog state dump
If elapsed time > (timeout / 2), collect and log:
- child PID and `State:` line from `/proc/<pid>/status` (if accessible from host)
- `wchan` (wait channel) if allowed
- `cmdline`

This is extremely helpful in diagnosing kernel-hang vs userland hang.

## Candidate Fixes (After Root Cause Identified)

### Fix Class A: Make sandbox setup less contentious
- Reuse a “base container template” and only vary per-exec config.
  - Caveat: hakoniwa container is consumed by command creation; but we can store a “base config” and clone a container if supported (hakoniwa `Container` is `Clone`).
- Reduce mount work per exec (Phase 2 will inevitably centralize this via session roots; that may help).
- Avoid mounting procfs redundantly (we currently mount `/proc` explicitly even though `Container::new()` mounts it; confirm whether this adds contention. If redundant, remove explicit procfsmount if safe.)

### Fix Class B: Use a worker pool for namespace-heavy setup
Even if product supports parallel sandboxes, creating *namespaces and mounts* at high concurrency may be the contentious part. We could:
- throttle only the “setup phase” with a semaphore (e.g. max 4/8 in parallel),
- then let commands run concurrently after setup.

This is not “forcing serial tests”; it is applying a resource-aware concurrency limit for a kernel-heavy operation. The product could still run many sandboxes concurrently, but creation could be staged.

### Fix Class C: Pre-create session roots / overlay mounts (Phase 2 direction)
Phase 2 introduces session directory structure and overlay roots. That can:
- move expensive mount operations to session creation (done once),
- make `execute()` cheap (just run command in already-prepared environment),
- reduce the chance of concurrent mount namespace and root assembly operations.

This is likely the “real” long-term fix.

### Fix Class D: Harden kill + teardown
Ensure no leaked processes:
- after SIGKILL, re-wait reliably
- ensure PID namespace reaping (if there’s an init process) is not blocked
- consider killing process groups (if hakoniwa spawns wrappers)

### Fix Class E: Remove host-dependent command resolution
Not directly tied to this flake, but it reduces surprises:
- require absolute paths or allowlist mapping
- avoid host filesystem existence checks in hot path

## Test Strategy Upgrades (Without Forcing Serial)

To validate parallel correctness, we should add a dedicated parallel stress test that:
- runs many sandbox executions concurrently
- uses a short timeout (e.g. 2s)
- asserts 0 failures for multiple iterations
- measures tail latency

We should keep the existing behavioral tests, but add this stress test as the regression harness. This ensures we “test what we ship”.

## References

- `docs/SECURITY_MODEL.md`: threat model and controls (namespaces, Landlock, etc.)
- `docs/ARCHITECTURE.md`: includes timeout hard-kill policy decision
- hakoniwa docs (Container):
  - `Container::new()` unshares mount/user/PID and mounts `/proc`
  - `rootfs("/")` binds only `/bin`, `/etc`, `/lib`, `/lib64`, `/lib32`, `/sbin`, `/usr`
- hakoniwa docs (Command):
  - `Command::wait_timeout(seconds)` exists but is second-granularity; we avoid it to maintain millisecond timeouts.

## Next Actions (Concrete Checklist)

1. Add an explicit parallel stress test (or bin) to reproduce the flake.
2. Add tracing/instrumentation to `SandboxContainer::execute()` + `build_container()`.
3. On timeout, dump child `/proc/<pid>/status` / `wchan` if possible.
4. Identify whether hangs occur:
   - before spawn (setup hang),
   - during spawn/exec,
   - during wait (child blocked),
   - during teardown (kill/wait).
5. Based on findings, implement the smallest effective fix:
   - remove redundant proc mount if present,
   - limit setup-concurrency with a semaphore (setup only),
   - move to persistent session roots (Phase 2),
   - or patch teardown handling.

## Non-Goals

- We do not “solve” kernel 0-days or system misconfiguration here.
- We do not permanently disable parallel execution in tests.
- We do not rely on second-granularity timeouts.
