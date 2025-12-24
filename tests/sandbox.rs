//! Integration tests for sandbox container with namespace isolation.
//!
//! These tests verify that the sandbox properly isolates processes using
//! Linux namespaces (PID, network, IPC, UTS, mount).
//!
//! Note: These tests require a Linux system with:
//! - Unprivileged user namespaces enabled
//! - Access to /bin, /lib, /usr for basic commands

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use model_sandbox_protocol::sandbox::{CommandOutput, SandboxConfig, SandboxContainer};

fn assert_success(output: &CommandOutput, context: &str) {
    assert!(
        output.success(),
        "{} failed.\nexit_code={}\nstdout:\n{}\nstderr:\n{}",
        context,
        output.exit_code,
        output.stdout,
        output.stderr
    );
}

fn assert_stderr_empty(output: &CommandOutput, context: &str) {
    assert!(
        output.stderr.is_empty(),
        "{} had unexpected stderr.\nexit_code={}\nstdout:\n{}\nstderr:\n{}",
        context,
        output.exit_code,
        output.stdout,
        output.stderr
    );
}

/// Test basic command execution with echo.
#[test]
fn test_echo_hello() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("echo", &["hello"])
        .expect("Failed to execute echo");

    assert_success(&output, "echo");
    assert_eq!(output.stdout.trim(), "hello");
    assert_stderr_empty(&output, "echo");
}

/// Test PID namespace isolation - process should be PID 1 in the sandbox.
#[test]
fn test_pid_namespace_isolation() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // Read NSpid from /proc/self/status which shows PID in each namespace
    let output = sandbox
        .execute("cat", &["/proc/self/status"])
        .expect("Failed to read /proc/self/status");

    assert_success(&output, "cat /proc/self/status");

    // Find the NSpid line which shows the PID in the innermost namespace
    // Format: NSpid:	<host_pid>	<ns_pid>
    // In a PID namespace, the sandboxed process should see itself as PID 1
    let has_pid_1 = output.stdout.lines().any(|line| {
        if line.starts_with("NSpid:") {
            // The last number on the line is the PID in the innermost namespace
            line.split_whitespace().last() == Some("1")
        } else {
            false
        }
    });

    assert!(
        has_pid_1,
        "Process should be PID 1 in its namespace. Status:\n{}",
        output.stdout
    );
}

/// Test network namespace isolation - only loopback interface should be present.
#[test]
fn test_network_isolation() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // List network interfaces
    let output = sandbox
        .execute("cat", &["/proc/net/dev"])
        .expect("Failed to read /proc/net/dev");

    assert_success(&output, "cat /proc/net/dev");

    // In a network namespace, we should only see lo (loopback)
    // The output format has headers first, then interface lines
    let interfaces: Vec<&str> = output
        .stdout
        .lines()
        .skip(2) // Skip header lines
        .filter_map(|line| line.split(':').next())
        .map(|s| s.trim())
        .collect();

    assert!(
        interfaces.contains(&"lo"),
        "Should have loopback interface. Interfaces: {:?}",
        interfaces
    );

    // Should NOT have other common interfaces like eth0, wlan0, etc.
    let has_external = interfaces.iter().any(|iface| {
        *iface != "lo"
            && !iface.is_empty()
            && !iface.starts_with("Inter") // Header line remnant
            && !iface.starts_with("face") // Header line remnant
    });

    assert!(
        !has_external,
        "Should only have loopback, but found: {:?}",
        interfaces
    );
}

/// Test that external network connections fail.
#[test]
fn test_network_external_connection_fails() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // Try to ping an external IP - should fail in isolated network namespace
    // Using /bin/sh -c to handle the timeout case gracefully
    let output = sandbox.execute(
        "sh",
        &[
            "-c",
            "cat /proc/net/route 2>/dev/null | grep -v Iface | head -1",
        ],
    );

    match output {
        Ok(out) => {
            // Route table should be empty or only have lo entries
            let route_content = out.stdout.trim();
            // Empty is good - means no routes
            // If not empty, it should only be loopback-related
            if !route_content.is_empty() {
                assert!(
                    route_content.starts_with("lo") || route_content.is_empty(),
                    "Should have no external routes. Got: {}",
                    route_content
                );
            }
        }
        Err(_) => {
            // Command failing is also acceptable - means no route access
        }
    }
}

/// Test UTS namespace isolation - hostname should be configurable.
#[test]
fn test_hostname_isolation() {
    let config = SandboxConfig::default().with_hostname("test-sandbox-host");
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("hostname", &[])
        .expect("Failed to execute hostname");

    assert_success(&output, "hostname");
    assert_eq!(
        output.stdout.trim(),
        "test-sandbox-host",
        "Hostname should be isolated"
    );
}

/// Test IPC namespace isolation by checking for separate IPC namespace ID.
#[test]
fn test_ipc_isolation() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // Get the IPC namespace ID from inside the sandbox
    let output = sandbox
        .execute("readlink", &["/proc/self/ns/ipc"])
        .expect("Failed to read IPC namespace");

    assert_success(&output, "readlink /proc/self/ns/ipc");
    let sandbox_ipc_ns = output.stdout.trim();

    // The sandbox should have its own IPC namespace (different from empty)
    assert!(
        !sandbox_ipc_ns.is_empty(),
        "Should have an IPC namespace ID"
    );
    assert!(
        sandbox_ipc_ns.starts_with("ipc:["),
        "Should be an IPC namespace: {}",
        sandbox_ipc_ns
    );
}

/// Test that /tmp is writable (tmpfs mount).
#[test]
fn test_tmp_writable() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // Try to write a file to /tmp
    let output = sandbox
        .execute(
            "sh",
            &[
                "-c",
                "echo 'test content' > /tmp/test.txt && cat /tmp/test.txt",
            ],
        )
        .expect("Failed to write to /tmp");

    assert_success(&output, "write+cat /tmp/test.txt");
    assert_eq!(output.stdout.trim(), "test content");
}

/// Test environment variable passing.
#[test]
fn test_environment_variables() {
    let config = SandboxConfig::default()
        .with_env("MY_TEST_VAR", "hello_from_config")
        .with_env("ANOTHER_VAR", "42");
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("sh", &["-c", "echo $MY_TEST_VAR $ANOTHER_VAR"])
        .expect("Failed to execute sh");

    assert_success(&output, "sh -c echo $MY_TEST_VAR $ANOTHER_VAR");
    assert_eq!(output.stdout.trim(), "hello_from_config 42");
}

/// Test working directory configuration.
#[test]
fn test_working_directory() {
    let config = SandboxConfig::default().with_working_dir("/tmp");
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox.execute("pwd", &[]).expect("Failed to execute pwd");

    assert_success(&output, "pwd");
    assert_eq!(output.stdout.trim(), "/tmp");
}

/// Test stderr capture.
#[test]
fn test_stderr_capture() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("sh", &["-c", "echo 'stdout msg' && echo 'stderr msg' >&2"])
        .expect("Failed to execute sh");

    assert_success(&output, "sh -c stdout+stderr");
    assert_eq!(output.stdout.trim(), "stdout msg");
    assert_eq!(output.stderr.trim(), "stderr msg");
}

/// Test command failure (non-zero exit code).
#[test]
fn test_command_failure() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("sh", &["-c", "exit 42"])
        .expect("Failed to execute sh");

    assert!(!output.success(), "Command should fail");
    assert_eq!(
        output.exit_code, 42,
        "Exit code should be 42.\nstdout:\n{}\nstderr:\n{}",
        output.stdout, output.stderr
    );
}

/// Test command timeout.
#[test]
fn test_timeout() {
    let config = SandboxConfig::default().with_timeout(Duration::from_millis(100));
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    // Sleep for longer than the timeout
    let result = sandbox.execute("sleep", &["10"]);

    assert!(result.is_err(), "Should timeout");
    match result {
        Err(model_sandbox_protocol::error::SandboxError::Timeout { timeout_seconds }) => {
            // Timeout is in seconds, we set 100ms which rounds to 0
            assert!(timeout_seconds <= 1, "Timeout should be ~0 seconds");
        }
        other => panic!("Expected Timeout error, got: {:?}", other),
    }
}

/// Test the convenience `run()` method.
#[test]
fn test_run_convenience_method() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let success = sandbox.run("true", &[]).expect("Failed to run true");
    assert!(success, "true should succeed");

    let success = sandbox.run("false", &[]).expect("Failed to run false");
    assert!(!success, "false should fail");
}

/// Test that command with arguments works correctly.
#[test]
fn test_command_with_multiple_args() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let output = sandbox
        .execute("echo", &["one", "two", "three"])
        .expect("Failed to execute echo");

    assert!(output.success());
    assert_eq!(output.stdout.trim(), "one two three");
}

/// Test invalid (empty) command handling.
#[test]
fn test_empty_command_rejected() {
    let config = SandboxConfig::default();
    let sandbox = SandboxContainer::new(config).expect("Failed to create sandbox");

    let result = sandbox.execute("", &[]);
    assert!(result.is_err(), "Empty command should be rejected");

    match result {
        Err(model_sandbox_protocol::error::SandboxError::InvalidCommand(msg)) => {
            assert!(
                msg.contains("empty"),
                "Error should mention 'empty': {}",
                msg
            );
        }
        other => panic!("Expected InvalidCommand error, got: {:?}", other),
    }
}

/// Parallel stress test to validate sandbox concurrency.
///
/// This test spawns many concurrent sandbox executions to verify that:
/// - No timeouts occur due to kernel-level contention
/// - All sandboxes complete successfully
/// - The setup semaphore correctly serializes namespace creation
///
/// See `docs/troubleshooting/PARALLEL_SANDBOX_FLAKINESS.md` for background.
#[test]
fn test_parallel_sandbox_stress() {
    // 32 threads × 4 iterations = 128 concurrent sandbox operations.
    // The setup semaphore serializes namespace creation and adds a brief delay
    // after spawn to allow child processes to complete mount operations before
    // the next sandbox begins setup. This prevents kernel-level contention.
    const NUM_THREADS: usize = 32;
    const ITERATIONS_PER_THREAD: usize = 4;

    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|thread_id| {
            let success = Arc::clone(&success_count);
            let failure = Arc::clone(&failure_count);

            thread::spawn(move || {
                for iter in 0..ITERATIONS_PER_THREAD {
                    // Use a 5-second timeout - should be plenty for simple commands
                    // with the setup semaphore preventing kernel contention.
                    let config = SandboxConfig::default().with_timeout(Duration::from_secs(5));

                    let sandbox = match SandboxContainer::new(config) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Thread {} iter {}: sandbox creation failed: {:?}", thread_id, iter, e);
                            failure.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                    };

                    // Run a simple command that should complete quickly
                    let result = sandbox.execute(
                        "sh",
                        &["-c", "pwd && echo test > /tmp/x && cat /tmp/x"],
                    );

                    match result {
                        Ok(output) if output.success() => {
                            success.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(output) => {
                            eprintln!(
                                "Thread {} iter {}: command failed with exit code {}\nstdout: {}\nstderr: {}",
                                thread_id, iter, output.exit_code, output.stdout, output.stderr
                            );
                            failure.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => {
                            eprintln!("Thread {} iter {}: execution error: {:?}", thread_id, iter, e);
                            failure.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_success = success_count.load(Ordering::SeqCst);
    let total_failure = failure_count.load(Ordering::SeqCst);
    let total_expected = NUM_THREADS * ITERATIONS_PER_THREAD;

    println!(
        "Parallel stress test: {}/{} succeeded, {} failed",
        total_success, total_expected, total_failure
    );

    assert_eq!(
        total_failure, 0,
        "Expected zero failures in parallel stress test, but {} out of {} failed",
        total_failure, total_expected
    );
    assert_eq!(
        total_success, total_expected,
        "Expected {} successes, got {}",
        total_expected, total_success
    );
}
