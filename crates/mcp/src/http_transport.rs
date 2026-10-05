//! HTTP/SSE transport for MCP proxy.
//!
//! Extends the stdio-based MCP proxy with HTTP transport support.
//! Agents can connect via HTTP POST (JSON-RPC) or SSE (streaming).
//!
//! Architecture:
//! Agent -> HTTP POST -> AgentFence MCP HTTP Proxy -> MCP Server (stdio)
//! Agent <- SSE stream <- AgentFence MCP HTTP Proxy <- MCP Server (stdio)

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use tracing::{error, info, warn};

use agentfence_core::types::{ActionId, AgentId, SessionId};
use agentfence_policy::pdp::Pdp;

use crate::proxy::{hash_args, McpProxy, ProxyConfig};
use crate::types::{JsonRpcRequest, JsonRpcResponse, ToolsCallParams};

/// HTTP transport configuration.
#[derive(Clone)]
pub struct HttpTransportConfig {
    pub listen_addr: String,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub pdp: Pdp,
    pub proxy_config: ProxyConfig,
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    /// SSE keep-alive interval in seconds
    pub sse_keepalive_secs: u64,
}

/// HTTP MCP transport server.
pub struct HttpTransport {
    config: HttpTransportConfig,
}

impl HttpTransport {
    /// Create a new HTTP transport server.
    pub fn new(config: HttpTransportConfig) -> Self {
        Self { config }
    }

    /// Run the HTTP transport server.
    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)?;
        info!(
            "MCP HTTP transport listening on {}",
            self.config.listen_addr
        );

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let config = self.config.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = handle_http_connection(stream, &config) {
                            error!("HTTP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Handle a single HTTP connection.
fn handle_http_connection(
    mut stream: TcpStream,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = BufReader::new(stream.try_clone()?);

    // Read HTTP request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return send_http_response(&mut stream, 400, "Bad Request", "Invalid request line");
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut headers = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if line.to_lowercase().starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
        }
        headers.push_str(&line);
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        if content_length > config.max_body_size {
            return send_http_response(&mut stream, 413, "Payload Too Large", "Body too large");
        }
        reader.read_exact(&mut body)?;
    }

    let body_str = String::from_utf8_lossy(&body);

    // Route based on method and path
    match (method, path) {
        ("POST", "/mcp") => handle_mcp_post(&mut stream, &body_str, config),
        ("GET", "/mcp/sse") => handle_sse_stream(&mut stream, config),
        ("GET", "/health") => send_http_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#),
        _ => send_http_response(&mut stream, 404, "Not Found", "Unknown endpoint"),
    }
}

/// Handle MCP JSON-RPC POST request.
fn handle_mcp_post(
    stream: &mut TcpStream,
    body: &str,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    // Parse JSON-RPC request
    let request: JsonRpcRequest = match serde_json::from_str(body) {
        Ok(req) => req,
        Err(e) => {
            warn!("Failed to parse JSON-RPC request: {}", e);
            let response = JsonRpcResponse::error(
                None,
                crate::types::JsonRpcError::PARSE_ERROR,
                "Parse error",
            );
            let body = serde_json::to_string(&response).unwrap();
            return send_http_response(stream, 200, "OK", &body);
        }
    };

    // Handle tools/call
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
                    let body = serde_json::to_string(&response).unwrap();
                    return send_http_response(stream, 200, "OK", &body);
                }
            },
            None => {
                let response = JsonRpcResponse::error(
                    request.id,
                    crate::types::JsonRpcError::INVALID_PARAMS,
                    "Missing params",
                );
                let body = serde_json::to_string(&response).unwrap();
                return send_http_response(stream, 200, "OK", &body);
            }
        };

        let call = crate::proxy::McpToolCall {
            tool: params.name,
            arguments: params.arguments,
            server: Some(config.proxy_config.server_name.clone()),
        };

        let proxy = McpProxy::new(config.pdp.clone(), config.proxy_config.clone());
        let record = proxy.evaluate(&call);

        // Record audit event
        if let Some(ref store) = config.proxy_config.audit_store {
            let event = agentfence_audit::event::AuditEvent::new(
                config.session_id.clone(),
                config.agent_id.clone(),
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

        let response_body = match record.decision {
            agentfence_core::types::Decision::Allow => {
                info!("ALLOWED: {} (rule: {})", call.tool, record.rule_id);
                // Forward to MCP server via stdio proxy
                let proxy = McpProxy::new(config.pdp.clone(), config.proxy_config.clone());
                match proxy.forward_to_server(&call) {
                    Ok(result) => {
                        serde_json::to_string(&JsonRpcResponse::success(request.id, result))
                            .unwrap()
                    }
                    Err(e) => {
                        error!("Failed to forward to MCP server: {}", e);
                        serde_json::to_string(&JsonRpcResponse::error(
                            request.id,
                            crate::types::JsonRpcError::INTERNAL_ERROR,
                            format!("Internal error: {}", e),
                        ))
                        .unwrap()
                    }
                }
            }
            agentfence_core::types::Decision::Deny => {
                warn!("DENIED: {} (rule: {})", call.tool, record.rule_id);
                serde_json::to_string(&JsonRpcResponse::error(
                    request.id,
                    crate::types::JsonRpcError::INVALID_REQUEST,
                    format!("Denied by policy: {}", record.reason),
                ))
                .unwrap()
            }
            agentfence_core::types::Decision::Ask => {
                warn!("ASK: {} (rule: {})", call.tool, record.reason);
                serde_json::to_string(&JsonRpcResponse::error(
                    request.id,
                    crate::types::JsonRpcError::INVALID_REQUEST,
                    format!("Requires approval: {}", record.reason),
                ))
                .unwrap()
            }
        };

        return send_http_response(stream, 200, "OK", &response_body);
    }

    // Forward other methods (initialize, tools/list, etc.)
    let proxy = McpProxy::new(config.pdp.clone(), config.proxy_config.clone());
    let response_body = match proxy.forward_non_tool_call(&request) {
        Ok(result) => serde_json::to_string(&JsonRpcResponse::success(request.id, result)).unwrap(),
        Err(e) => {
            error!("Failed to forward request: {}", e);
            serde_json::to_string(&JsonRpcResponse::error(
                request.id,
                crate::types::JsonRpcError::INTERNAL_ERROR,
                format!("Internal error: {}", e),
            ))
            .unwrap()
        }
    };

    send_http_response(stream, 200, "OK", &response_body)
}

/// Handle SSE stream connection.
fn handle_sse_stream(stream: &mut TcpStream, config: &HttpTransportConfig) -> std::io::Result<()> {
    // Send SSE headers
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(headers.as_bytes())?;
    stream.flush()?;

    info!("SSE stream opened");

    // Send keep-alive comments periodically
    let keepalive = config.sse_keepalive_secs;
    loop {
        std::thread::sleep(Duration::from_secs(keepalive));
        let comment = ": keep-alive\n\n";
        if stream.write_all(comment.as_bytes()).is_err() {
            info!("SSE stream closed by client");
            break;
        }
        if stream.flush().is_err() {
            break;
        }
    }

    Ok(())
}

/// Send HTTP response with JSON body.
fn send_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn test_proxy_config() -> ProxyConfig {
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
    fn test_http_transport_creation() {
        let config = HttpTransportConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            pdp: test_pdp(),
            proxy_config: test_proxy_config(),
            max_body_size: 1024 * 1024,
            sse_keepalive_secs: 15,
        };
        let transport = HttpTransport::new(config);
        assert_eq!(transport.config.listen_addr, "127.0.0.1:0");
    }

    #[test]
    fn test_send_http_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        send_http_response(&mut client, 200, "OK", r#"{"status":"ok"}"#).unwrap();

        let response = server.join().unwrap();
        assert!(response.contains("200 OK"));
        assert!(response.contains("application/json"));
        assert!(response.contains(r#"{"status":"ok"}"#));
    }
}
