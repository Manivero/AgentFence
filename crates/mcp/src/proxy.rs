//! MCP proxy for AgentFence.
//!
//! Evaluates tool calls before forwarding them to MCP servers.
//! Never trusts tool metadata blindly.
//!
//! Architecture:
//! Agent -> AgentFence MCP Proxy -> MCP Server
//!
//! The proxy intercepts JSON-RPC messages over stdio, evaluates tool calls
//! against policy, and forwards allowed calls to the MCP server.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, warn};

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;
use agentfence_secrets::detector::SecretDetector;

use crate::types::{JsonRpcRequest, JsonRpcResponse, ToolsCallParams};

/// MCP tool call request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub tool: String,
    pub arguments: Value,
    pub server: Option<String>,
}

/// MCP proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub server_name: String,
    pub server_command: String,
    pub server_args: Vec<String>,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub audit_store:
        Option<std::sync::Arc<std::sync::Mutex<agentfence_audit::sqlite_store::SqliteStore>>>,
}

/// MCP proxy.
///
/// Evaluates tool calls against policy before forwarding.
/// Never trusts tool metadata blindly.
pub struct McpProxy {
    pdp: Pdp,
    config: ProxyConfig,
    secret_detector: SecretDetector,
}

impl McpProxy {
    /// Create a new MCP proxy with the given PDP and configuration.
    pub fn new(pdp: Pdp, config: ProxyConfig) -> Self {
        Self {
            pdp,
            config,
            secret_detector: SecretDetector::new(),
        }
    }

    /// Check if a tool call contains secrets.
    ///
    /// Returns a list of detected secrets (without raw values).
    /// Never logs or returns raw secret values.
    pub fn check_secrets(
        &self,
        call: &McpToolCall,
    ) -> Vec<agentfence_secrets::detector::DetectedSecret> {
        let args_str = serde_json::to_string(&call.arguments).unwrap_or_default();
        self.secret_detector.detect(&args_str, "mcp")
    }

    /// Evaluate a tool call.
    ///
    /// Returns a decision record with full explanation.
    pub fn evaluate(&self, call: &McpToolCall) -> DecisionRecord {
        let action = Action {
            id: ActionId::new(),
            session_id: self.config.session_id.clone(),
            agent_id: self.config.agent_id.clone(),
            task_id: None,
            action_type: ActionType::Mcp,
            tool: call.tool.clone(),
            target: call.server.clone().unwrap_or_else(|| "unknown".to_string()),
            args_hash: hash_args(&call.arguments),
            context: Default::default(),
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a tool call is allowed.
    pub fn is_allowed(&self, call: &McpToolCall) -> bool {
        let record = self.evaluate(call);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }

    /// Forward a tool call to the MCP server via stdio.
    ///
    /// Returns the server response as a JSON value.
    /// This method assumes the call has already been authorized.
    pub fn forward_to_server(&self, call: &McpToolCall) -> Result<Value, std::io::Error> {
        use serde_json::json;

        let mut child = self.spawn_server()?;
        let mut server_stdin = child.stdin.take().unwrap();
        let server_stdout = child.stdout.take().unwrap();

        // Send tool call request
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": call.tool,
                "arguments": call.arguments,
            }
        });
        writeln!(server_stdin, "{}", request)?;
        server_stdin.flush()?;

        // Read response
        let mut reader = BufReader::new(server_stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let response: Value = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let _ = child.wait();
        Ok(response)
    }

    /// Forward a non-tool-call request to the MCP server via stdio.
    ///
    /// Returns the server response as a JSON value.
    pub fn forward_non_tool_call(&self, request: &JsonRpcRequest) -> Result<Value, std::io::Error> {
        let mut child = self.spawn_server()?;
        let mut server_stdin = child.stdin.take().unwrap();
        let server_stdout = child.stdout.take().unwrap();

        // Forward request
        writeln!(
            server_stdin,
            "{}",
            serde_json::to_string(request)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        )?;
        server_stdin.flush()?;

        // Read response
        let mut reader = BufReader::new(server_stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let response: Value = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let _ = child.wait();
        Ok(response)
    }

    /// Run the proxy loop.
    ///
    /// Reads JSON-RPC requests from stdin, evaluates tool calls,
    /// and forwards allowed requests to the MCP server.
    /// Server responses are forwarded back to the agent via a background thread.
    pub fn run(&self) -> Result<(), std::io::Error> {
        self.run_inner(false)
    }

    /// Run the proxy loop with graceful shutdown on SIGINT/SIGTERM.
    ///
    /// On shutdown signal, the proxy will:
    /// 1. Stop reading new requests
    /// 2. Kill the MCP server child process
    /// 3. Wait for the server response thread to finish
    pub fn run_with_shutdown(&self) -> Result<(), std::io::Error> {
        self.run_inner(true)
    }

    /// Inner proxy loop shared by `run()` and `run_with_shutdown()`.
    fn run_inner(&self, graceful_shutdown: bool) -> Result<(), std::io::Error> {
        if graceful_shutdown {
            info!(
                "Starting MCP proxy for server '{}' (graceful shutdown enabled)",
                self.config.server_name
            );
        } else {
            info!(
                "Starting MCP proxy for server '{}'",
                self.config.server_name
            );
        }

        let mut child = self.spawn_server()?;
        let mut server_stdin = child.stdin.take().unwrap();
        let server_stdout = child.stdout.take().unwrap();

        // Forward server responses back to the agent in a background thread
        let server_reader = BufReader::new(server_stdout);
        let stdout_handle = std::thread::spawn(move || {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for line in server_reader.lines() {
                match line {
                    Ok(l) => {
                        let _ = writeln!(out, "{}", l);
                        let _ = out.flush();
                    }
                    Err(e) => {
                        error!("Failed to read server response: {}", e);
                        break;
                    }
                }
            }
        });

        // Set up shutdown signal handler if graceful shutdown is enabled
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        if graceful_shutdown {
            let shutdown_clone = shutdown.clone();
            let _ = ctrlc::set_handler(move || {
                info!("Shutdown signal received, stopping proxy...");
                shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            });
        }

        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let stdout = std::io::stdout();

        loop {
            if graceful_shutdown && shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutdown requested, exiting");
                break;
            }

            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    info!("Agent disconnected");
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
                        Ok(req) => req,
                        Err(e) => {
                            warn!("Failed to parse request: {}", e);
                            let response = JsonRpcResponse::error(
                                None,
                                crate::types::JsonRpcError::PARSE_ERROR,
                                "Parse error",
                            );
                            let mut out = stdout.lock();
                            let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
                            let _ = out.flush();
                            continue;
                        }
                    };

                    if request.method == "tools/call" {
                        let params: ToolsCallParams = match request.params.clone() {
                            Some(p) => match serde_json::from_value(p) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("Failed to parse tool call params: {}", e);
                                    let response = JsonRpcResponse::error(
                                        request.id,
                                        crate::types::JsonRpcError::INVALID_PARAMS,
                                        "Invalid params",
                                    );
                                    let mut out = stdout.lock();
                                    let _ = writeln!(
                                        out,
                                        "{}",
                                        serde_json::to_string(&response).unwrap()
                                    );
                                    let _ = out.flush();
                                    continue;
                                }
                            },
                            None => {
                                let response = JsonRpcResponse::error(
                                    request.id,
                                    crate::types::JsonRpcError::INVALID_PARAMS,
                                    "Missing params",
                                );
                                let mut out = stdout.lock();
                                let _ =
                                    writeln!(out, "{}", serde_json::to_string(&response).unwrap());
                                let _ = out.flush();
                                continue;
                            }
                        };

                        let call = McpToolCall {
                            tool: params.name,
                            arguments: params.arguments,
                            server: Some(self.config.server_name.clone()),
                        };

                        let record = self.evaluate(&call);

                        // Record audit event
                        if let Some(ref store) = self.config.audit_store {
                            let event = agentfence_audit::event::AuditEvent::new(
                                self.config.session_id.clone(),
                                self.config.agent_id.clone(),
                                None,
                                ActionId::new(),
                                None,
                                "mcp",
                                &call.tool,
                                format!("{:?}", call.arguments),
                                hash_args(&call.arguments),
                                record.decision,
                                record.risk_level,
                                &record.rule_id,
                                &record.policy_version,
                                "",
                                "",
                            );
                            if let Ok(store) = store.lock() {
                                let _ = store.record_event(&event);
                            }
                        }

                        match record.decision {
                            agentfence_core::types::Decision::Allow => {
                                info!("ALLOWED: {} (rule: {})", call.tool, record.rule_id);
                                let _ = writeln!(server_stdin, "{}", trimmed);
                                let _ = server_stdin.flush();
                            }
                            agentfence_core::types::Decision::Deny => {
                                warn!("DENIED: {} (rule: {})", call.tool, record.rule_id);
                                let response = JsonRpcResponse::error(
                                    request.id,
                                    crate::types::JsonRpcError::INVALID_REQUEST,
                                    format!("Denied by policy: {}", record.reason),
                                );
                                let mut out = stdout.lock();
                                let _ =
                                    writeln!(out, "{}", serde_json::to_string(&response).unwrap());
                                let _ = out.flush();
                            }
                            agentfence_core::types::Decision::Ask => {
                                warn!("ASK: {} (rule: {})", call.tool, record.reason);
                                let response = JsonRpcResponse::error(
                                    request.id,
                                    crate::types::JsonRpcError::INVALID_REQUEST,
                                    format!("Requires approval: {}", record.reason),
                                );
                                let mut out = stdout.lock();
                                let _ =
                                    writeln!(out, "{}", serde_json::to_string(&response).unwrap());
                                let _ = out.flush();
                            }
                        }
                    } else {
                        // Non-tool-call requests must also be authorized.
                        // Only allow safe MCP protocol methods (initialize, notifications, etc.)
                        // All other methods require explicit policy authorization.
                        let is_safe_method = request.method == "initialize"
                            || request.method == "initialized"
                            || request.method == "ping"
                            || request.method.starts_with("notifications/")
                            || request.method == "tools/list"
                            || request.method == "resources/list"
                            || request.method == "prompts/list";

                        if is_safe_method {
                            debug!("Forwarding safe non-tool-call request: {}", request.method);
                            let _ = writeln!(server_stdin, "{}", trimmed);
                            let _ = server_stdin.flush();
                        } else {
                            // Evaluate against policy
                            let call = McpToolCall {
                                tool: request.method.clone(),
                                arguments: request.params.clone().unwrap_or(serde_json::json!({})),
                                server: Some(self.config.server_name.clone()),
                            };
                            let record = self.evaluate(&call);

                            // Record audit event
                            if let Some(ref store) = self.config.audit_store {
                                let event = agentfence_audit::event::AuditEvent::new(
                                    self.config.session_id.clone(),
                                    self.config.agent_id.clone(),
                                    None,
                                    ActionId::new(),
                                    None,
                                    "mcp",
                                    &request.method,
                                    format!("{:?}", call.arguments),
                                    hash_args(&call.arguments),
                                    record.decision,
                                    record.risk_level,
                                    &record.rule_id,
                                    &record.policy_version,
                                    "",
                                    "",
                                );
                                if let Ok(store) = store.lock() {
                                    let _ = store.record_event(&event);
                                }
                            }

                            match record.decision {
                                agentfence_core::types::Decision::Allow => {
                                    info!("ALLOWED: {} (rule: {})", request.method, record.rule_id);
                                    let _ = writeln!(server_stdin, "{}", trimmed);
                                    let _ = server_stdin.flush();
                                }
                                agentfence_core::types::Decision::Deny => {
                                    warn!("DENIED: {} (rule: {})", request.method, record.rule_id);
                                    let response = JsonRpcResponse::error(
                                        request.id,
                                        crate::types::JsonRpcError::INVALID_REQUEST,
                                        format!("Denied by policy: {}", record.reason),
                                    );
                                    let mut out = stdout.lock();
                                    let _ = writeln!(
                                        out,
                                        "{}",
                                        serde_json::to_string(&response).unwrap()
                                    );
                                    let _ = out.flush();
                                }
                                agentfence_core::types::Decision::Ask => {
                                    warn!("ASK: {} (rule: {})", request.method, record.reason);
                                    let response = JsonRpcResponse::error(
                                        request.id,
                                        crate::types::JsonRpcError::INVALID_REQUEST,
                                        format!("Requires approval: {}", record.reason),
                                    );
                                    let mut out = stdout.lock();
                                    let _ = writeln!(
                                        out,
                                        "{}",
                                        serde_json::to_string(&response).unwrap()
                                    );
                                    let _ = out.flush();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from stdin: {}", e);
                    break;
                }
            }
        }

        // Graceful shutdown: kill child process
        info!("Shutting down MCP server...");
        let _ = child.kill();
        let _ = child.wait();
        drop(server_stdin);
        let _ = stdout_handle.join();
        info!("MCP proxy shutdown complete");
        Ok(())
    }

    fn spawn_server(&self) -> Result<Child, std::io::Error> {
        let child = Command::new(&self.config.server_command)
            .args(&self.config.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn();

        match child {
            Ok(c) => {
                info!(
                    "MCP server '{}' spawned (PID: {:?})",
                    self.config.server_name,
                    c.id()
                );
                Ok(c)
            }
            Err(e) => {
                error!(
                    "Failed to spawn MCP server '{}': command='{}' args={:?} error={}",
                    self.config.server_name, self.config.server_command, self.config.server_args, e
                );
                Err(e)
            }
        }
    }

    /// Check if the MCP server process is still running.
    pub fn is_server_running(&self, child: &mut Child) -> bool {
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                warn!(
                    "MCP server '{}' exited with status: {}",
                    self.config.server_name, status
                );
                false
            }
            Err(e) => {
                error!(
                    "Failed to check MCP server '{}' status: {}",
                    self.config.server_name, e
                );
                false
            }
        }
    }
}

pub fn hash_args(args: &Value) -> String {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_string(args).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;
    use agentfence_policy::parser::parse_policy;

    fn test_pdp() -> Pdp {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
mcp:
  allow:
    - github
    - filesystem
  deny:
    - shell
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    fn test_config() -> ProxyConfig {
        ProxyConfig {
            server_name: "github".to_string(),
            server_command: "npx".to_string(),
            server_args: vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-github".to_string(),
            ],
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            audit_store: None,
        }
    }

    #[test]
    fn test_mcp_allow() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"repo": "example/repo"}),
            server: Some("github".to_string()),
        };

        let record = proxy.evaluate(&call);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_mcp_deny() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "shell.execute".to_string(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
            server: Some("shell".to_string()),
        };

        let record = proxy.evaluate(&call);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_mcp_default_deny() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "unknown.tool".to_string(),
            arguments: serde_json::json!({}),
            server: Some("unknown".to_string()),
        };

        let record = proxy.evaluate(&call);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_is_allowed() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"repo": "example/repo"}),
            server: Some("github".to_string()),
        };

        assert!(proxy.is_allowed(&call));
    }

    #[test]
    fn test_is_not_allowed() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "shell.execute".to_string(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
            server: Some("shell".to_string()),
        };

        assert!(!proxy.is_allowed(&call));
    }

    #[test]
    fn test_spawn_server_failure() {
        let mut config = test_config();
        config.server_command = "nonexistent_command_xyz".to_string();
        let proxy = McpProxy::new(test_pdp(), config);
        let result = proxy.spawn_server();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_server_running() {
        let mut config = test_config();
        config.server_command = "cat".to_string();
        config.server_args = vec![];
        let proxy = McpProxy::new(test_pdp(), config);
        let mut child = proxy.spawn_server().unwrap();
        assert!(proxy.is_server_running(&mut child));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!proxy.is_server_running(&mut child));
    }

    #[test]
    fn test_spawn_server_with_invalid_command() {
        let mut config = test_config();
        config.server_command = "definitely_not_a_real_command_12345".to_string();
        let proxy = McpProxy::new(test_pdp(), config);
        let result = proxy.spawn_server();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_server_running_after_exit() {
        let mut config = test_config();
        config.server_command = "echo".to_string();
        config.server_args = vec!["hello".to_string()];
        let proxy = McpProxy::new(test_pdp(), config);
        let mut child = proxy.spawn_server().unwrap();
        let _ = child.wait();
        assert!(!proxy.is_server_running(&mut child));
    }

    #[test]
    fn test_secret_detection_in_tool_call() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"token": "ghp_1234567890abcdef"}),
            server: Some("github".to_string()),
        };
        let secrets = proxy.check_secrets(&call);
        assert!(!secrets.is_empty());
        assert!(secrets
            .iter()
            .any(|s| s.category == agentfence_secrets::detector::SecretCategory::GitHubToken));
    }

    #[test]
    fn test_no_secrets_in_normal_tool_call() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"title": "Bug report", "body": "Something is broken"}),
            server: Some("github".to_string()),
        };
        let secrets = proxy.check_secrets(&call);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_secret_fingerprint_not_raw() {
        let proxy = McpProxy::new(test_pdp(), test_config());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"token": "ghp_1234567890abcdef"}),
            server: Some("github".to_string()),
        };
        let secrets = proxy.check_secrets(&call);
        for secret in &secrets {
            assert!(!secret.fingerprint.contains("ghp_1234567890abcdef"));
        }
    }
}
