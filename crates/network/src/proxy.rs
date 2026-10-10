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
use agentfence_secrets::detector::SecretDetector;

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
    /// Maximum requests per second per client (0 = unlimited)
    pub rate_limit: u32,
    /// Maximum number of pooled connections per target host (0 = no pooling)
    pub pool_size: u32,
    /// Connection idle timeout in seconds
    pub pool_timeout: u64,
}

/// Connection pool entry.
#[derive(Debug)]
struct PooledConnection {
    stream: TcpStream,
    last_used: std::time::Instant,
}

/// Connection pool for reusing TCP connections to target hosts.
#[derive(Debug)]
struct ConnectionPool {
    connections: std::collections::HashMap<String, Vec<PooledConnection>>,
    max_size: u32,
    timeout: std::time::Duration,
}

impl ConnectionPool {
    fn new(max_size: u32, timeout_secs: u64) -> Self {
        Self {
            connections: std::collections::HashMap::new(),
            max_size,
            timeout: std::time::Duration::from_secs(timeout_secs),
        }
    }

    /// Get a connection from the pool or create a new one.
    fn get(&mut self, host: &str, port: u16) -> Option<TcpStream> {
        let key = format!("{}:{}", host, port);
        if let Some(conns) = self.connections.get_mut(&key) {
            // Remove expired connections
            conns.retain(|c| c.last_used.elapsed() < self.timeout);
            if let Some(conn) = conns.pop() {
                return Some(conn.stream);
            }
        }
        None
    }

    /// Return a connection to the pool.
    fn put(&mut self, host: &str, port: u16, stream: TcpStream) {
        if self.max_size == 0 {
            return; // Pooling disabled
        }
        let key = format!("{}:{}", host, port);
        let conns = self.connections.entry(key).or_default();
        if conns.len() < self.max_size as usize {
            conns.push(PooledConnection {
                stream,
                last_used: std::time::Instant::now(),
            });
        }
    }

    /// Clean up expired connections.
    #[allow(dead_code)] // Used in tests; will be used by periodic cleanup task
    fn cleanup(&mut self) {
        for conns in self.connections.values_mut() {
            conns.retain(|c| c.last_used.elapsed() < self.timeout);
        }
        self.connections.retain(|_, conns| !conns.is_empty());
    }
}

/// Network proxy.
///
/// Evaluates network requests against policy before forwarding.
/// Never claims complete network isolation in cooperative mode.
pub struct NetworkProxy {
    pdp: Pdp,
    config: NetworkProxyConfig,
    secret_detector: SecretDetector,
}

impl NetworkProxy {
    /// Create a new network proxy with the given PDP and configuration.
    pub fn new(pdp: Pdp, config: NetworkProxyConfig) -> Self {
        Self {
            pdp,
            config,
            secret_detector: SecretDetector::new(),
        }
    }

    /// Check if request headers contain secrets.
    ///
    /// Returns a list of detected secrets (without raw values).
    /// Never logs or returns raw secret values.
    pub fn check_secrets_in_headers(
        &self,
        headers: &str,
    ) -> Vec<agentfence_secrets::detector::DetectedSecret> {
        self.secret_detector.detect(headers, "network.headers")
    }

    /// Check if request body contains secrets.
    ///
    /// Returns a list of detected secrets (without raw values).
    /// Never logs or returns raw secret values.
    pub fn check_secrets_in_body(
        &self,
        body: &[u8],
    ) -> Vec<agentfence_secrets::detector::DetectedSecret> {
        let body_str = String::from_utf8_lossy(body);
        self.secret_detector.detect(&body_str, "network.body")
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

/// Rate limiter state (token bucket algorithm).
#[derive(Debug)]
struct RateLimiter {
    /// Maximum requests per second
    max_rps: u32,
    /// Current token count
    tokens: u32,
    /// Last refill time
    last_refill: std::time::Instant,
}

impl RateLimiter {
    fn new(max_rps: u32) -> Self {
        Self {
            max_rps,
            tokens: max_rps,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    fn try_consume(&mut self) -> bool {
        if self.max_rps == 0 {
            return true; // Unlimited
        }

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let tokens_to_add = (elapsed.as_secs_f64() * self.max_rps as f64) as u32;

        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.max_rps);
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Handle a single proxy connection.
fn handle_connection(
    mut stream: TcpStream,
    pdp: &Pdp,
    config: &NetworkProxyConfig,
) -> std::io::Result<()> {
    let audit_store = config.audit_store.clone();
    let rate_limit = config.rate_limit;
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

    // Rate limiting check
    if rate_limit > 0 {
        let mut limiter = RateLimiter::new(rate_limit);
        if !limiter.try_consume() {
            warn!("RATE LIMITED: {} {}", method, url);
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nRate limit exceeded: {} requests per second",
                format!("Rate limit exceeded: {} requests per second", rate_limit).len(),
                rate_limit
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
            return Ok(());
        }
    }

    let mut pool = ConnectionPool::new(config.pool_size, config.pool_timeout);

    match record.decision {
        agentfence_core::types::Decision::Allow => {
            info!("ALLOWED: {} {}", method, url);
            forward_request(&mut stream, &host, port, method, &path, &headers, &mut pool)?;
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
/// 5. Normalize IPv6 addresses (including IPv4-mapped IPv6)
///
/// Returns `None` if the hostname is invalid.
pub fn normalize_host(host: &str) -> Option<String> {
    // Split host and port first
    let (host_part, port_part) = split_host_port(host).unwrap_or((host.to_string(), None));

    let h = host_part.to_lowercase();

    // Check for IPv6 address
    if h.starts_with('[') && h.ends_with(']') {
        // IPv6 in brackets: [::1]
        let ipv6 = &h[1..h.len() - 1];
        return normalize_ipv6(ipv6, port_part);
    }

    // Check for IPv4-mapped IPv6: ::ffff:127.0.0.1
    if let Some(ipv4_part) = h.strip_prefix("::ffff:") {
        if ipv4_part.parse::<std::net::Ipv4Addr>().is_ok() {
            // Normalize to IPv4 for policy comparison
            let mut result = ipv4_part.to_string();
            if let Some(port) = port_part {
                if port != 80 && port != 443 {
                    result = format!("{}:{}", result, port);
                }
            }
            return Some(result);
        }
    }

    // Check for bare IPv6 address (no brackets)
    if h.contains(':') && !h.contains('.') {
        // Try to parse as IPv6
        if let Ok(addr) = h.parse::<std::net::Ipv6Addr>() {
            return normalize_ipv6(&addr.to_string(), port_part);
        }
    }

    // Regular hostname
    let mut h = h;

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

/// Normalize an IPv6 address for policy comparison.
///
/// Handles:
/// - IPv4-mapped IPv6 (::ffff:127.0.0.1) → converts to IPv4
/// - Compressed forms (::1) → expands to full form
/// - Loopback addresses (::1) → 127.0.0.1
fn normalize_ipv6(addr: &str, port: Option<u16>) -> Option<String> {
    // Try to parse as IPv6
    let ipv6 = match addr.parse::<std::net::Ipv6Addr>() {
        Ok(a) => a,
        Err(_) => return None,
    };

    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
        let mut result = ipv4.to_string();
        if let Some(p) = port {
            if p != 80 && p != 443 {
                result = format!("{}:{}", result, p);
            }
        }
        return Some(result);
    }

    // Check for loopback (::1)
    if ipv6.is_loopback() {
        let mut result = "127.0.0.1".to_string();
        if let Some(p) = port {
            if p != 80 && p != 443 {
                result = format!("{}:{}", result, p);
            }
        }
        return Some(result);
    }
    let _ = addr; // suppress unused warning

    // For other IPv6 addresses, return the compressed form
    let mut result = ipv6.to_string();
    if let Some(p) = port {
        if p != 80 && p != 443 {
            result = format!("{}:{}", result, p);
        }
    }
    Some(result)
}

/// Split host:port string.
///
/// Handles IPv4, hostnames, and IPv6 in brackets:
/// - "example.com:8080" → ("example.com", Some(8080))
/// - "[::1]:8080" → ("[::1]", Some(8080))
/// - "[::1]" → ("[::1]", None)
/// - "::1" → ("::1", None)
/// - "2001:db8::1" → ("2001:db8::1", None)
fn split_host_port(s: &str) -> Option<(String, Option<u16>)> {
    // IPv6 in brackets: [::1] or [::1]:port
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let host = s[..=close].to_string();
            let rest = &s[close + 1..];
            if rest.is_empty() {
                return Some((host, None));
            }
            if let Some(stripped) = rest.strip_prefix(':') {
                let port = stripped.parse().ok()?;
                return Some((host, Some(port)));
            }
            return Some((host, None));
        }
    }

    // IPv4-mapped IPv6 with port: ::ffff:127.0.0.1:8080
    if let Some(rest) = s.strip_prefix("::ffff:") {
        if let Some(idx) = rest.rfind(':') {
            let ipv4_part = &rest[..idx];
            if ipv4_part.parse::<std::net::Ipv4Addr>().is_ok() {
                let port = rest[idx + 1..].parse().ok()?;
                return Some((s[..idx + 7].to_string(), Some(port)));
            }
        }
    }

    // Bare IPv6 address (contains multiple colons, no brackets)
    // Without brackets, port cannot be parsed reliably
    let colon_count = s.matches(':').count();
    if colon_count > 1 {
        return Some((s.to_string(), None));
    }

    // IPv4 or hostname with port (single colon)
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
    pool: &mut ConnectionPool,
) -> std::io::Result<()> {
    let port = port.unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    // Try to get a connection from the pool
    let mut server = match pool.get(host, port) {
        Some(conn) => conn,
        None => TcpStream::connect(&addr)?,
    };

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

    // Return connection to pool
    pool.put(host, port, server);

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
            rate_limit: 0,
            pool_size: 0,
            pool_timeout: 60,
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
    fn test_normalize_ipv6_loopback() {
        // ::1 should normalize to 127.0.0.1
        assert_eq!(normalize_host("::1"), Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_normalize_ipv6_loopback_bracketed() {
        // [::1] should normalize to 127.0.0.1
        assert_eq!(normalize_host("[::1]"), Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_normalize_ipv6_loopback_with_port() {
        // [::1]:8080 should normalize to 127.0.0.1:8080
        assert_eq!(
            normalize_host("[::1]:8080"),
            Some("127.0.0.1:8080".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 should normalize to 127.0.0.1
        assert_eq!(
            normalize_host("::ffff:127.0.0.1"),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv4_mapped_ipv6_with_port() {
        // ::ffff:127.0.0.1:8080 should normalize to 127.0.0.1:8080
        assert_eq!(
            normalize_host("::ffff:127.0.0.1:8080"),
            Some("127.0.0.1:8080".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv4_mapped_ipv6_github() {
        // ::ffff:140.82.121.4 should normalize to 140.82.121.4
        assert_eq!(
            normalize_host("::ffff:140.82.121.4"),
            Some("140.82.121.4".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv6_full_address() {
        // Full IPv6 address should be normalized to compressed form
        assert_eq!(
            normalize_host("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some("2001:db8:85a3::8a2e:370:7334".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv6_compressed() {
        // Already compressed IPv6 should stay compressed
        assert_eq!(
            normalize_host("2001:db8::1"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv6_bracketed_with_port() {
        // [2001:db8::1]:443 should normalize to 2001:db8::1 (default port stripped)
        assert_eq!(
            normalize_host("[2001:db8::1]:443"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_normalize_ipv6_bracketed_with_non_default_port() {
        // [2001:db8::1]:8080 should normalize to 2001:db8::1:8080
        assert_eq!(
            normalize_host("[2001:db8::1]:8080"),
            Some("2001:db8::1:8080".to_string())
        );
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed() {
        assert_eq!(
            split_host_port("[::1]:8080"),
            Some(("[::1]".to_string(), Some(8080)))
        );
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed_no_port() {
        assert_eq!(split_host_port("[::1]"), Some(("[::1]".to_string(), None)));
    }

    #[test]
    fn test_split_host_port_ipv6_bare() {
        assert_eq!(split_host_port("::1"), Some(("::1".to_string(), None)));
    }

    #[test]
    fn test_normalize_ipv6_bypass_attempt() {
        // ::ffff:github.com is not a valid IPv6 address and should be rejected
        assert_eq!(normalize_host("::ffff:github.com"), None);
    }

    #[test]
    fn test_normalize_ipv6_loopback_bypass() {
        // ::1 should normalize to 127.0.0.1, not stay as ::1
        let result = normalize_host("::1");
        assert_eq!(result, Some("127.0.0.1".to_string()));
        // Verify it doesn't stay as ::1
        assert_ne!(result, Some("::1".to_string()));
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

    #[test]
    fn test_rate_limiter_unlimited() {
        let mut limiter = RateLimiter::new(0);
        for _ in 0..100 {
            assert!(limiter.try_consume());
        }
    }

    #[test]
    fn test_rate_limiter_allows_up_to_limit() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.try_consume());
        }
        assert!(!limiter.try_consume());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.try_consume());
        assert!(limiter.try_consume());
        assert!(!limiter.try_consume());
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(limiter.try_consume());
    }

    #[test]
    fn test_connection_pool_disabled() {
        let mut pool = ConnectionPool::new(0, 60);
        assert!(pool.get("example.com", 80).is_none());
    }

    #[test]
    fn test_connection_pool_put_and_get() {
        let mut pool = ConnectionPool::new(5, 60);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        pool.put("127.0.0.1", addr.port(), stream);
        assert!(pool.get("127.0.0.1", addr.port()).is_some());
    }

    #[test]
    fn test_connection_pool_max_size() {
        let mut pool = ConnectionPool::new(2, 60);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        for _ in 0..3 {
            let stream = std::net::TcpStream::connect(addr).unwrap();
            pool.put("127.0.0.1", addr.port(), stream);
        }
        assert_eq!(
            pool.connections
                .get(&format!("127.0.0.1:{}", addr.port()))
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn test_connection_pool_cleanup() {
        let mut pool = ConnectionPool::new(5, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        pool.put("127.0.0.1", addr.port(), stream);
        pool.cleanup();
        assert!(pool.connections.is_empty());
    }

    #[test]
    fn test_secret_detection_in_headers() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let headers =
            "Authorization: Bearer ghp_1234567890abcdef\r\nContent-Type: application/json";
        let secrets = proxy.check_secrets_in_headers(headers);
        assert!(!secrets.is_empty());
        assert!(secrets
            .iter()
            .any(|s| s.category == agentfence_secrets::detector::SecretCategory::BearerToken));
    }

    #[test]
    fn test_secret_detection_in_body() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let body = br#"{"token": "ghp_1234567890abcdef"}"#;
        let secrets = proxy.check_secrets_in_body(body);
        assert!(!secrets.is_empty());
        assert!(secrets
            .iter()
            .any(|s| s.category == agentfence_secrets::detector::SecretCategory::GitHubToken));
    }

    #[test]
    fn test_no_secrets_in_normal_request() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let headers = "Content-Type: application/json\r\nAccept: */*";
        let body = br#"{"query": "hello world"}"#;
        let header_secrets = proxy.check_secrets_in_headers(headers);
        let body_secrets = proxy.check_secrets_in_body(body);
        assert!(header_secrets.is_empty());
        assert!(body_secrets.is_empty());
    }

    #[test]
    fn test_secret_fingerprint_not_raw() {
        let proxy = NetworkProxy::new(test_pdp(), test_config());
        let headers = "Authorization: Bearer ghp_1234567890abcdef";
        let secrets = proxy.check_secrets_in_headers(headers);
        for secret in &secrets {
            assert!(!secret.fingerprint.contains("ghp_1234567890abcdef"));
        }
    }
}
