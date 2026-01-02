//! MCP protocol-level integration tests.
//!
//! These tests verify that the tools are correctly exposed via the MCP JSON-RPC protocol,
//! complementing the direct method call tests in `mcp_tools.rs`.
//!
//! The tests spawn the server and communicate via stdin/stdout pipes to verify:
//! - `tools/list` returns all 6 expected tools
//! - Tool schemas are valid and complete

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

/// Expected tool names that should be exposed via MCP.
const EXPECTED_TOOLS: &[&str] = &[
    "sandbox_create",
    "sandbox_execute",
    "sandbox_read_file",
    "sandbox_write_file",
    "sandbox_list",
    "sandbox_destroy",
];

/// Send a JSON-RPC message to the server and read the response.
fn send_and_receive(
    stdin: &mut impl Write,
    stdout: &mut BufReader<impl std::io::Read>,
    request: &Value,
) -> serde_json::Result<Value> {
    let msg = serde_json::to_string(request).expect("serialize request");
    writeln!(stdin, "{}", msg).expect("write to stdin");
    stdin.flush().expect("flush stdin");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read from stdout");
    serde_json::from_str(&line)
}

/// Send a notification (no response expected).
fn send_notification(stdin: &mut impl Write, notification: &Value) {
    let msg = serde_json::to_string(notification).expect("serialize notification");
    writeln!(stdin, "{}", msg).expect("write to stdin");
    stdin.flush().expect("flush stdin");
}

#[test]
fn test_tools_list_returns_all_tools() {
    // Build the binary first to ensure it's up to date.
    let build_status = Command::new("cargo")
        .args(["build", "--quiet"])
        .status()
        .expect("failed to build");
    assert!(build_status.success(), "cargo build failed");

    // Spawn the server process.
    let mut child = Command::new("cargo")
        .args(["run", "--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // Suppress log output
        .spawn()
        .expect("failed to spawn server");

    let mut stdin = child.stdin.take().expect("failed to get stdin");
    let stdout = child.stdout.take().expect("failed to get stdout");
    let mut reader = BufReader::new(stdout);

    // Step 1: Initialize
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0"
            }
        },
        "id": 1
    });

    let init_response: Value = send_and_receive(&mut stdin, &mut reader, &init_request)
        .expect("failed to parse init response");

    // Verify initialization succeeded.
    assert!(
        init_response.get("result").is_some(),
        "init should return result, got: {}",
        init_response
    );
    assert!(
        init_response["result"]["capabilities"]["tools"].is_object(),
        "server should have tools capability"
    );

    // Step 2: Send initialized notification
    let initialized_notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send_notification(&mut stdin, &initialized_notification);

    // Small delay to let the server process the notification.
    std::thread::sleep(Duration::from_millis(50));

    // Step 3: Request tools/list
    let list_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });

    let list_response: Value = send_and_receive(&mut stdin, &mut reader, &list_request)
        .expect("failed to parse tools/list response");

    // Verify we got a result (not an error).
    assert!(
        list_response.get("result").is_some(),
        "tools/list should return result, got: {}",
        list_response
    );

    let tools = list_response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");

    // Verify we have exactly 6 tools.
    assert_eq!(
        tools.len(),
        EXPECTED_TOOLS.len(),
        "expected {} tools, got {}",
        EXPECTED_TOOLS.len(),
        tools.len()
    );

    // Collect tool names.
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool should have name"))
        .collect();

    // Verify all expected tools are present.
    for expected in EXPECTED_TOOLS {
        assert!(
            tool_names.contains(expected),
            "missing expected tool: {}, found: {:?}",
            expected,
            tool_names
        );
    }

    // Verify each tool has required fields.
    for tool in tools {
        let name = tool["name"].as_str().expect("tool should have name");
        assert!(
            tool["description"].is_string(),
            "tool {} should have description",
            name
        );
        assert!(
            tool["inputSchema"].is_object(),
            "tool {} should have inputSchema",
            name
        );
    }

    // Clean up: close stdin to signal EOF, then wait for process.
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_tool_schemas_are_valid() {
    // Build the binary first.
    let build_status = Command::new("cargo")
        .args(["build", "--quiet"])
        .status()
        .expect("failed to build");
    assert!(build_status.success(), "cargo build failed");

    // Spawn the server process.
    let mut child = Command::new("cargo")
        .args(["run", "--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn server");

    let mut stdin = child.stdin.take().expect("failed to get stdin");
    let stdout = child.stdout.take().expect("failed to get stdout");
    let mut reader = BufReader::new(stdout);

    // Initialize and get tools list.
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1.0" }
        },
        "id": 1
    });
    let _ = send_and_receive(&mut stdin, &mut reader, &init_request).expect("init");

    send_notification(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    std::thread::sleep(Duration::from_millis(50));

    let list_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });
    let list_response: Value =
        send_and_receive(&mut stdin, &mut reader, &list_request).expect("tools/list");

    let tools = list_response["result"]["tools"]
        .as_array()
        .expect("tools array");

    // Verify specific tool schemas.
    for tool in tools {
        let name = tool["name"].as_str().expect("name");
        let input_schema = &tool["inputSchema"];

        match name {
            "sandbox_create" => {
                // sandbox_create has optional params.
                assert_eq!(input_schema["type"], "object");
                assert!(input_schema["properties"]["workspace_path"].is_object());
                assert!(input_schema["properties"]["timeout_seconds"].is_object());
                assert!(input_schema["properties"]["name"].is_object());
            }
            "sandbox_execute" => {
                // sandbox_execute requires session_id and command.
                let required = input_schema["required"].as_array().expect("required array");
                let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
                assert!(
                    required_strs.contains(&"session_id"),
                    "sandbox_execute should require session_id"
                );
                assert!(
                    required_strs.contains(&"command"),
                    "sandbox_execute should require command"
                );
            }
            "sandbox_read_file" | "sandbox_write_file" => {
                // Both require session_id and path.
                let required = input_schema["required"].as_array().expect("required array");
                let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
                assert!(required_strs.contains(&"session_id"));
                assert!(required_strs.contains(&"path"));
            }
            "sandbox_destroy" => {
                // Requires session_id.
                let required = input_schema["required"].as_array().expect("required array");
                let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
                assert!(required_strs.contains(&"session_id"));
            }
            "sandbox_list" => {
                // No required params.
                assert_eq!(input_schema["type"], "object");
            }
            _ => panic!("unexpected tool: {}", name),
        }
    }

    drop(stdin);
    let _ = child.wait();
}
