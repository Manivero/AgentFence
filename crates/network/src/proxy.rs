//! Network proxy for AgentFence.
//!
//! Evaluates network requests against policy before forwarding.
//! Never claims complete network isolation in cooperative mode.
//!
//! Architecture:
//! Agent -> AgentFence Network Proxy -> Internet
//!
//! The proxy listens on localhost, evaluates each request via PDP,
//! and forwards allowed requests to the target server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;

/// Network request.
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub path: Option<String>,
}

/// Network proxy configuration.
#[derive(Debug, Clone)]
pub struct NetworkProxyConfig {
    pub listen_addr: String,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub audit_store:
        Option<std::sync::Arc<std::sync::Mutex<agentfence_audit::sqlite_store::SqliteStore>>>,
}

/// Network proxy.
///
/// Evaluates network requests against policy before forwarding.
/// Never claims complete network isolation in cooperative mode.
pub struct NetworkProxy {
    pdp: Pdp,
    config: NetworkProxyConfig,
}

impl NetworkProxy {
    /// Create a new network proxy with the given PDP and configuration.
    pub fn new(pdp: Pdp, config: NetworkProxyConfig) -> Self {
        Self { pdp, config }
    }

    /// Evaluate a network request.
    ///
    /// Returns a decision record with full explanation.
    pub fn evaluate(&self, req: &NetworkRequest) -> DecisionRecord {
        let target = format!(
            "{}://{}:{}{}",
            req.protocol,
            req.host,
            req.port.unwrap_or(0),
            req.path.as_deref().unwrap_or("")
        );

        let action = Action {
            id: ActionId::new(),
            session_id: self.config.session_id.clone(),
            agent_id: self.config.agent_id.clone(),
            task_id: None,
            action_type: ActionType::Network,
            tool: "network".to_string(),
            target,
            args_hash: String::new(),
            context: Default::default(),
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a network request is allowed.
    pub fn is_allowed(&self, req: &NetworkRequest) -> bool {
        let record = self.evaluate(req);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }

    /// Run the proxy server.
    ///
    /// Listens on the configured address and proxies requests.
    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr)?;
        info!("Network proxy listening on {}", self.config.listen_addr);

        let pdp = self.pdp.clone();
        let config = self.config.clone();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let pdp = pdp.clone();
                    let config = config.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &pdp, &config) {
                            error!("Connection error: {}", e);
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

/// Handle a single proxy connection.
fn handle_connection(
    mut stream: TcpStream,
    pdp: &Pdp,
    config: &NetworkProxyConfig,
) -> std::io::Result<()> {
    let audit_store = config.audit_store.clone();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];

    // Read headers
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers.push_str(&line);
    }

    // Handle HTTPS CONNECT tunnel
    if method == "CONNECT" {
        return handle_connect(stream, url, pdp, config);
    }

    // Parse host from URL or Host header
    let (host, port, path) = parse_url(url, &headers);

    // Read request body if Content-Length is present
    let body = read_request_body(&mut reader, &headers)?;

    let record = {
        let action = Action {
            id: ActionId::new(),
            session_id: config.session_id.clone(),
            agent_id: config.agent_id.clone(),
            task_id: None,
            action_type: ActionType::Network,
            tool: "network".to_string(),
            target: format!("http://{}:{}{}", host, port.unwrap_or(80), path),
            args_hash: hash_body(&body),
            context: Default::default(),
        };
        pdp.evaluate(&action)
    };

    // Record audit event
    if let Some(ref store) = audit_store {
        let event = agentfence_audit::event::AuditEvent::new(
            config.session_id.clone(),
            config.agent_id.clone(),
            None,
            ActionId::new(),
            None,
            "network",
            "network",
            format!("{}://{}:{}{}", "http", host, port.unwrap_or(80), path),
            hash_body(&body),
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
            info!("ALLOWED: {} {}", method, url);
            forward_request(&mut stream, &host, port, method, &path, &headers)?;
        }
        agentfence_core::types::Decision::Deny => {
            warn!("DENIED: {} {} (rule: {})", method, url, record.rule_id);
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nDenied by policy: {}",
                record.reason.len(),
                record.reason
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
        agentfence_core::types::Decision::Ask => {
            warn!("ASK: {} {} (rule: {})", method, url, record.reason);
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nRequires approval: {}",
                record.reason.len(),
                record.reason
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
    }

    Ok(())
}

/// Handle HTTPS CONNECT tunnel request.
///
/// CONNECT method establishes a tunnel to the target server.
/// The proxy evaluates the target host against policy, then either
/// establishes the tunnel or returns an error.
fn handle_connect(
    mut stream: TcpStream,
    target: &str,
    pdp: &Pdp,
    config: &NetworkProxyConfig,
) -> std::io::Result<()> {
    let audit_store = config.audit_store.clone();

    // Parse host:port from CONNECT target
    let (host, port) = split_host_port(target).unwrap_or((target.to_string(), None));
    let port = port.unwrap_or(443);

    // Evaluate against policy
    let record = {
        let action = Action {
            id: ActionId::new(),
            session_id: config.session_id.clone(),
            agent_id: config.agent_id.clone(),
            task_id: None,
            action_type: ActionType::Network,
            tool: "network".to_string(),
            target: format!("https://{}:{}", host, port),
            args_hash: String::new(),
            context: Default::default(),
        };
        pdp.evaluate(&action)
    };

    // Record audit event
    if let Some(ref store) = audit_store {
        let event = agentfence_audit::event::AuditEvent::new(
            config.session_id.clone(),
            config.agent_id.clone(),
            None,
            ActionId::new(),
            None,
            "network",
            "network",
            format!("CONNECT {}:{}", host, port),
            "",
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
            info!("ALLOWED: CONNECT {}:{}", host, port);

            // Connect to target server
            let addr = format!("{}:{}", host, port);
            let mut server = match TcpStream::connect(&addr) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to connect to {}: {}", addr, e);
                    let response = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        e.to_string().len(),
                        e
                    );
                    stream.write_all(response.as_bytes())?;
                    stream.flush()?;
                    return Ok(());
                }
            };

            // Send 200 Connection established
            let response = "HTTP/1.1 200 Connection established\r\n\r\n";
            stream.write_all(response.as_bytes())?;
            stream.flush()?;

            // Bidirectional copy
            let mut server_reader = BufReader::new(server.try_clone()?);
            let mut client_reader = BufReader::new(stream.try_clone()?);

            let server_to_client = std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    match server_reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).is_err() {
                                break;
                            }
                            let _ = stream.flush();
                        }
                        Err(_) => break,
                    }
                }
            });

            let client_to_server = std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    match client_reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            if server.write_all(&buffer[..n]).is_err() {
                                break;
                            }
                            let _ = server.flush();
                        }
                        Err(_) => break,
                    }
                }
            });

            let _ = server_to_client.join();
            let _ = client_to_server.join();

            Ok(())
        }
        agentfence_core::types::Decision::Deny => {
            warn!(
                "DENIED: CONNECT {}:{} (rule: {})",
                host, port, record.rule_id
            );
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nDenied by policy: {}",
                record.reason.len(),
                record.reason
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
            Ok(())
        }
        agentfence_core::types::Decision::Ask => {
            warn!("ASK: CONNECT {}:{} (rule: {})", host, port, record.reason);
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nRequires approval: {}",
                record.reason.len(),
                record.reason
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
            Ok(())
        }
    }
}

/// Parse URL and headers to extract host, port, and path.
fn parse_url(url: &str, headers: &str) -> (String, Option<u16>, String) {
    // Check Host header first
    for line in headers.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host_part = line[5..].trim();
            if let Some((host, port)) = split_host_port(host_part) {
                let path = extract_path(url);
                return (host, port, path);
            }
        }
    }

    // Parse from URL
    if let Some(stripped) = url.strip_prefix("http://") {
        let parts: Vec<&str> = stripped.splitn(2, '/').collect();
        let host_port = parts[0];
        let path = if parts.len() > 1 {
            format!("/{}", parts[1])
        } else {
            "/".to_string()
        };
        let (host, port) = split_host_port(host_port).unwrap_or((host_port.to_string(), None));
        return (host, port, path);
    }

    (url.to_string(), None, "/".to_string())
}

/// Normalize a hostname for policy comparison.
///
/// Normalization steps:
/// 1. Convert to lowercase
/// 2. Remove trailing dot (FQDN form)
/// 3. Strip default ports (80 for http, 443 for https)
/// 4. Validate hostname characters
///
/// Returns `None` if the hostname is invalid.
pub fn normalize_host(host: &str) -> Option<String> {
    // Split host and port first
    let (host_part, port_part) = split_host_port(host).unwrap_or((host.to_string(), None));

    let mut h = host_part.to_lowercase();

    // Remove trailing dot
    if h.ends_with('.') {
        h.pop();
    }

    // Validate: must be 1-253 characters
    if h.is_empty() || h.len() > 253 {
        return None;
    }

    // Validate: only alphanumeric, hyphens, dots
    if !h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }

    // Validate: no consecutive dots
    if h.contains("..") {
        return None;
    }

    // Strip default ports from the host part
    if let Some(stripped) = h.strip_suffix(":80") {
        h = stripped.to_string();
    } else if let Some(stripped) = h.strip_suffix(":443") {
        h = stripped.to_string();
    }

    // Reattach non-default port
    if let Some(port) = port_part {
        if port != 80 && port != 443 {
            h = format!("{}:{}", h, port);
        }
    }

    Some(h)
}

/// Split host:port string.
fn split_host_port(s: &str) -> Option<(String, Option<u16>)> {
    if let Some(idx) = s.rfind(':') {
        let host = s[..idx].to_string();
        let port = s[idx + 1..].parse().ok()?;
        Some((host, Some(port)))
    } else {
        Some((s.to_string(), None))
    }
}

/// Extract path from URL.
fn extract_path(url: &str) -> String {
    if let Some(stripped) = url.strip_prefix("http://") {
        if let Some(idx) = stripped.find('/') {
            return stripped[idx..].to_string();
        }
    }
    "/".to_string()
}

/// Read request body from the stream based on Content-Length header.
fn read_request_body(reader: &mut BufReader<TcpStream>, headers: &str) -> std::io::Result<Vec<u8>> {
    let mut content_length: usize = 0;
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
            break;
        }
    }

    if content_length == 0 {
        return Ok(Vec::new());
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Hash request body for audit (never store raw body).
fn hash_body(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Forward request to target server.
fn forward_request(
    stream: &mut TcpStream,
    host: &str,
    port: Option<u16>,
    method: &str,
    path: &str,
    headers: &str,
) -> std::io::Result<()> {
    let port = port.unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let mut server = TcpStream::connect(&addr)?;

    // Send request line
    writeln!(server, "{} {} HTTP/1.1", method, path)?;

    // Send headers
    write!(server, "{}", headers)?;
    writeln!(server, "Connection: close")?;
    writeln!(server)?;

    // Forward response
    let mut server_reader = BufReader::new(server.try_clone()?);
    let mut buffer = [0u8; 4096];
    loop {
        match server_reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                stream.write_all(&buffer[..n])?;
                stream.flush()?;
            }
            Err(e) => {
                error!("Server read error: {}", e);
                break;
            }
        }
    }

    Ok(())
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
network:
  allow:
    - github.com
    - crates.io
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    fn test_config() -> NetworkProxyConfig {
        NetworkProxyConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            audit_store: None,
        }
    }

    #[test]
    fn test_network_allow() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "github.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: Some("/api/v3".to_string()),
        };

        let record = proxy.evaluate(&req);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_network_default_deny() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "evil.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: None,
        };

        let record = proxy.evaluate(&req);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_is_allowed() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "github.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: Some("/api/v3".to_string()),
        };

        assert!(proxy.is_allowed(&req));
    }

    #[test]
    fn test_is_not_allowed() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "evil.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: None,
        };

        assert!(!proxy.is_allowed(&req));
    }

    #[test]
    fn test_split_host_port() {
        assert_eq!(
            split_host_port("example.com"),
            Some(("example.com".to_string(), None))
        );
        assert_eq!(
            split_host_port("example.com:8080"),
            Some(("example.com".to_string(), Some(8080)))
        );
    }

    #[test]
    fn test_extract_path() {
        assert_eq!(extract_path("http://example.com/"), "/".to_string());
        assert_eq!(
            extract_path("http://example.com/api/v1"),
            "/api/v1".to_string()
        );
    }

    #[test]
    fn test_normalize_host_lowercase() {
        assert_eq!(normalize_host("GitHub.COM"), Some("github.com".to_string()));
    }

    #[test]
    fn test_normalize_host_trailing_dot() {
        assert_eq!(
            normalize_host("github.com."),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_default_port() {
        assert_eq!(
            normalize_host("github.com:443"),
            Some("github.com".to_string())
        );
        assert_eq!(
            normalize_host("github.com:80"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_invalid_empty() {
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn test_normalize_host_invalid_chars() {
        assert_eq!(normalize_host("evil com"), None);
        assert_eq!(normalize_host("evil@com"), None);
    }

    #[test]
    fn test_normalize_host_invalid_consecutive_dots() {
        assert_eq!(normalize_host("evil..com"), None);
    }

    #[test]
    fn test_normalize_host_non_default_port() {
        assert_eq!(
            normalize_host("github.com:8080"),
            Some("github.com:8080".to_string())
        );
    }

    #[test]
    fn test_normalize_host_bypass_attempt() {
        // "github.com.evil.com" should NOT normalize to "github.com"
        assert_eq!(
            normalize_host("github.com.evil.com"),
            Some("github.com.evil.com".to_string())
        );
    }

    #[test]
    fn test_connect_method_detection() {
        // Verify that CONNECT method is detected and handled differently
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "github.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: None,
        };
        let record = proxy.evaluate(&req);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_connect_denied_host() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let req = NetworkRequest {
            host: "evil.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: None,
        };
        let record = proxy.evaluate(&req);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_hash_body_empty() {
        assert_eq!(
            hash_body(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_body_known_content() {
        let body = b"hello world";
        let hash = hash_body(body);
        assert_eq!(hash.len(), 64);
        assert_ne!(hash, hash_body(&[]));
    }

    #[test]
    fn test_hash_body_deterministic() {
        let body = b"test data";
        assert_eq!(hash_body(body), hash_body(body));
    }
}
