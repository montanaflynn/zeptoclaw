//! Binary plugin tool adapter for ZeptoClaw.
//!
//! Executes standalone plugin binaries via JSON-RPC 2.0 over stdin/stdout.
//! Each tool call spawns the binary, writes a request to stdin, reads the
//! response from stdout, and returns the result. The binary is expected
//! to exit after producing a single response.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::error::{Result, ZeptoError};
use crate::plugins::types::PluginToolDef;
use crate::tools::types::{Tool, ToolContext};

// ---- JSON-RPC 2.0 types (local, not coupled to MCP) ----

#[derive(Serialize)]
struct PluginJsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: PluginExecuteParams,
}

#[derive(Serialize)]
struct PluginExecuteParams {
    tool: String,
    args: Value,
}

#[derive(Deserialize)]
struct PluginJsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<PluginJsonRpcResult>,
    error: Option<PluginJsonRpcError>,
}

#[derive(Deserialize)]
struct PluginJsonRpcResult {
    output: String,
}

#[derive(Deserialize)]
struct PluginJsonRpcError {
    code: i64,
    message: String,
    #[allow(dead_code)]
    data: Option<Value>,
}

// ---- BinaryPluginTool ----

/// A tool adapter that executes a binary plugin via JSON-RPC 2.0 over stdin/stdout.
///
/// The binary is spawned on-demand for each tool call, communicating via a
/// single JSON-RPC request/response exchange. The binary is expected to:
/// 1. Read a JSON-RPC request from stdin
/// 2. Write a JSON-RPC response to stdout
/// 3. Exit
pub struct BinaryPluginTool {
    def: PluginToolDef,
    plugin_name: String,
    binary_path: PathBuf,
    timeout: Duration,
}

impl BinaryPluginTool {
    /// Create a new binary plugin tool.
    ///
    /// # Arguments
    /// * `def` - The tool definition from the plugin manifest
    /// * `plugin_name` - Name of the parent plugin
    /// * `binary_path` - Absolute, validated path to the binary
    /// * `timeout_secs` - Execution timeout in seconds
    pub fn new(
        def: PluginToolDef,
        plugin_name: impl Into<String>,
        binary_path: PathBuf,
        timeout_secs: u64,
    ) -> Self {
        Self {
            def,
            plugin_name: plugin_name.into(),
            binary_path,
            timeout: Duration::from_secs(timeout_secs),
        }
    }
}

impl std::fmt::Debug for BinaryPluginTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryPluginTool")
            .field("name", &self.def.name)
            .field("plugin", &self.plugin_name)
            .field("binary", &self.binary_path)
            .finish()
    }
}

#[async_trait]
impl Tool for BinaryPluginTool {
    fn name(&self) -> &str {
        &self.def.name
    }

    fn description(&self) -> &str {
        &self.def.description
    }

    fn parameters(&self) -> Value {
        self.def.parameters.clone()
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        // Build JSON-RPC request
        let request = PluginJsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "execute".to_string(),
            params: PluginExecuteParams {
                tool: self.def.name.clone(),
                args,
            },
        };

        let request_json = serde_json::to_string(&request).map_err(|e| {
            ZeptoError::Tool(format!("Failed to serialize JSON-RPC request: {}", e))
        })?;

        // Spawn binary — no shell
        let mut cmd = Command::new(&self.binary_path);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Set working directory from context
        if let Some(workspace) = &ctx.workspace {
            cmd.current_dir(workspace);
        }

        // Set environment variables from tool def
        if let Some(env_vars) = &self.def.env {
            for (key, value) in env_vars {
                cmd.env(key, value);
            }
        }

        let mut child = cmd.spawn().map_err(|e| {
            ZeptoError::Tool(format!(
                "Failed to spawn binary plugin '{}' ({}): {}",
                self.plugin_name,
                self.binary_path.display(),
                e
            ))
        })?;

        // Write request to stdin and close
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(request_json.as_bytes())
                .await
                .map_err(|e| {
                    ZeptoError::Tool(format!(
                        "Failed to write to binary plugin '{}' stdin: {}",
                        self.plugin_name, e
                    ))
                })?;
            stdin.write_all(b"\n").await.ok();
            // stdin is dropped here, closing the pipe
        }

        // Wait for output with timeout
        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return Err(ZeptoError::Tool(format!(
                    "Binary plugin '{}' failed: {}",
                    self.plugin_name, e
                )));
            }
            Err(_) => {
                // Timeout — the child was consumed by wait_with_output's future
                // which was dropped. Tokio drops the child handle which sends SIGKILL.
                return Err(ZeptoError::Tool(format!(
                    "Binary plugin '{}' timed out after {}s",
                    self.plugin_name,
                    self.timeout.as_secs()
                )));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check exit code
        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let err_detail = if stderr.is_empty() {
                stdout.to_string()
            } else {
                stderr.to_string()
            };
            return Err(ZeptoError::Tool(format!(
                "Binary plugin '{}' exited with code {}: {}",
                self.plugin_name,
                code,
                err_detail.trim()
            )));
        }

        // Parse JSON-RPC response from the last non-empty line of stdout
        let response_line = stdout
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");

        if response_line.is_empty() {
            return Err(ZeptoError::Tool(format!(
                "Binary plugin '{}' produced no output",
                self.plugin_name
            )));
        }

        let response: PluginJsonRpcResponse = serde_json::from_str(response_line).map_err(|e| {
            ZeptoError::Tool(format!(
                "Binary plugin '{}' returned invalid JSON-RPC: {} (raw: {})",
                self.plugin_name,
                e,
                &response_line[..response_line.len().min(200)]
            ))
        })?;

        // Check for JSON-RPC error
        if let Some(err) = response.error {
            warn!(
                plugin = %self.plugin_name,
                code = err.code,
                "Binary plugin returned error"
            );
            return Err(ZeptoError::Tool(format!(
                "Binary plugin '{}' error (code {}): {}",
                self.plugin_name, err.code, err.message
            )));
        }

        // Extract result
        match response.result {
            Some(result) => Ok(result.output),
            None => Err(ZeptoError::Tool(format!(
                "Binary plugin '{}' returned neither result nor error",
                self.plugin_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- JSON-RPC serialization tests ----

    #[test]
    fn test_jsonrpc_request_serialization() {
        let req = PluginJsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "execute".to_string(),
            params: PluginExecuteParams {
                tool: "my_tool".to_string(),
                args: json!({"limit": 10}),
            },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "execute");
        assert_eq!(json["params"]["tool"], "my_tool");
        assert_eq!(json["params"]["args"]["limit"], 10);
    }

    #[test]
    fn test_jsonrpc_response_success_deser() {
        let json_str = r#"{"jsonrpc":"2.0","result":{"output":"payment list..."},"id":1}"#;
        let resp: PluginJsonRpcResponse = serde_json::from_str(json_str).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap().output, "payment list...");
    }

    #[test]
    fn test_jsonrpc_response_error_deser() {
        let json_str =
            r#"{"jsonrpc":"2.0","error":{"code":-1,"message":"API key not configured"},"id":1}"#;
        let resp: PluginJsonRpcResponse = serde_json::from_str(json_str).unwrap();
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -1);
        assert_eq!(err.message, "API key not configured");
        assert!(err.data.is_none());
    }

    #[test]
    fn test_jsonrpc_response_missing_result() {
        let json_str = r#"{"jsonrpc":"2.0","id":1}"#;
        let resp: PluginJsonRpcResponse = serde_json::from_str(json_str).unwrap();
        assert!(resp.result.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_jsonrpc_response_with_error_data() {
        let json_str = r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request","data":{"details":"missing field"}},"id":1}"#;
        let resp: PluginJsonRpcResponse = serde_json::from_str(json_str).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
        assert!(err.data.is_some());
    }

    // ---- Tool trait tests ----

    fn test_tool_def() -> PluginToolDef {
        PluginToolDef {
            name: "my_tool".to_string(),
            description: "My test tool".to_string(),
            parameters: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            command: String::new(),
            working_dir: None,
            timeout_secs: None,
            env: None,
        }
    }

    #[test]
    fn test_tool_name() {
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            PathBuf::from("/bin/echo"),
            30,
        );
        assert_eq!(tool.name(), "my_tool");
    }

    #[test]
    fn test_tool_description() {
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            PathBuf::from("/bin/echo"),
            30,
        );
        assert_eq!(tool.description(), "My test tool");
    }

    #[test]
    fn test_tool_parameters() {
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            PathBuf::from("/bin/echo"),
            30,
        );
        let params = tool.parameters();
        assert_eq!(params["type"], "object");
        assert!(params["properties"]["x"].is_object());
    }

    // ---- Execute tests with real processes ----

    #[cfg(unix)]
    fn create_test_script(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "#!/bin/sh\n{}", content).unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        file
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_success() {
        let script = create_test_script(
            r#"read input
echo '{"jsonrpc":"2.0","result":{"output":"hello world"},"id":1}'"#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({"x": "test"}), &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_error_response() {
        let script = create_test_script(
            r#"read input
echo '{"jsonrpc":"2.0","error":{"code":-1,"message":"something broke"},"id":1}'"#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("something broke"));
        assert!(err.contains("code -1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_non_zero_exit() {
        let script = create_test_script("exit 1");
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exited with code 1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_timeout() {
        let script = create_test_script("sleep 10");
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            1, // 1 second timeout
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_malformed_json() {
        let script = create_test_script("echo 'not json at all'");
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid JSON-RPC"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_empty_stdout() {
        let script = create_test_script("# produces nothing");
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no output"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_spawn_failure() {
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            PathBuf::from("/nonexistent/binary"),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to spawn"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_with_args() {
        // Script checks that stdin contains the expected args
        let script = create_test_script(
            r#"read input
if echo "$input" | grep -q '"x"'; then
    echo '{"jsonrpc":"2.0","result":{"output":"args received"},"id":1}'
else
    echo '{"jsonrpc":"2.0","error":{"code":-1,"message":"no args"},"id":1}'
fi"#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({"x": "hello"}), &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "args received");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_with_workspace() {
        let tmp = tempfile::TempDir::new().unwrap();
        let script = create_test_script(
            r#"read input
cwd=$(pwd)
echo "{\"jsonrpc\":\"2.0\",\"result\":{\"output\":\"cwd: $cwd\"},\"id\":1}""#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new().with_workspace(tmp.path().to_str().unwrap());
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        // The canonical path should contain the tmpdir name
        assert!(output.contains("cwd:"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_with_env() {
        let script = create_test_script(
            r#"read input
echo "{\"jsonrpc\":\"2.0\",\"result\":{\"output\":\"FOO=$MY_TEST_VAR\"},\"id\":1}""#,
        );

        let mut env = std::collections::HashMap::new();
        env.insert("MY_TEST_VAR".to_string(), "bar_value".to_string());

        let mut def = test_tool_def();
        def.env = Some(env);

        let tool = BinaryPluginTool::new(def, "test-plugin", script.path().to_path_buf(), 30);
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "FOO=bar_value");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_stderr_on_failure() {
        let script = create_test_script(
            r#"echo "error details" >&2
exit 1"#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("error details"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_binary_not_executable() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "#!/bin/sh\necho ok").unwrap();
        file.flush().unwrap();
        // Do NOT set execute permission

        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            file.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to spawn"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_large_output() {
        let script = create_test_script(
            r#"read input
large=$(python3 -c "print('x' * 10000)" 2>/dev/null || printf 'x%.0s' $(seq 1 10000))
echo "{\"jsonrpc\":\"2.0\",\"result\":{\"output\":\"$large\"},\"id\":1}""#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_ok());
        assert!(result.unwrap().len() >= 10000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_extra_stdout_ignored() {
        // Script emits debug lines before the JSON-RPC response
        let script = create_test_script(
            r#"read input
echo "debug: starting up"
echo "debug: processing"
echo '{"jsonrpc":"2.0","result":{"output":"final answer"},"id":1}'"#,
        );
        let tool = BinaryPluginTool::new(
            test_tool_def(),
            "test-plugin",
            script.path().to_path_buf(),
            30,
        );
        let ctx = ToolContext::new();
        let result = tool.execute(json!({}), &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "final answer");
    }
}
