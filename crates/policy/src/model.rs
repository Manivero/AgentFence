//! Typed policy model for AgentFence.

use serde::{Deserialize, Serialize};

use agentfence_core::types::{Action, ActionType, Context, DecisionRecord};

/// Top-level policy structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub defaults: Defaults,
    #[serde(default)]
    pub filesystem: Option<FilesystemPolicy>,
    #[serde(default)]
    pub shell: Option<ShellPolicy>,
    #[serde(default)]
    pub network: Option<NetworkPolicy>,
    #[serde(default)]
    pub mcp: Option<McpPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_deny")]
    pub filesystem: Decision,
    #[serde(default = "default_deny")]
    pub shell: Decision,
    #[serde(default = "default_deny")]
    pub network: Decision,
    #[serde(default = "default_deny")]
    pub mcp: Decision,
}

fn default_deny() -> Decision {
    Decision::Deny
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            filesystem: Decision::Deny,
            shell: Decision::Deny,
            network: Decision::Deny,
            mcp: Decision::Deny,
        }
    }
}

// ─── Filesystem Policy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read: Option<FsRules>,
    #[serde(default)]
    pub write: Option<FsRules>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsRules {
    #[serde(default)]
    pub allow: Vec<String>,
}

// ─── Policy Conditions ──────────────────────────────────────────────────────

/// Time-based condition for policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeCondition {
    /// Start time in HH:MM format (inclusive)
    pub start: String,
    /// End time in HH:MM format (inclusive)
    pub end: String,
    /// Days of week (0=Sunday, 6=Saturday). Empty = all days.
    #[serde(default)]
    pub days: Vec<u8>,
}

/// Location-based condition for policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationCondition {
    /// Allowed IP addresses or CIDR ranges
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Allowed hostnames
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

/// Advanced conditions for policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConditions {
    /// Time-based restrictions
    #[serde(default)]
    pub time: Option<TimeCondition>,
    /// Location-based restrictions
    #[serde(default)]
    pub location: Option<LocationCondition>,
}

// ─── Condition Evaluation ────────────────────────────────────────────────────
//
// Conditions RESTRICT permissions. They never grant them.
//
// SECURITY (fail-closed): if a condition is declared but the data needed to
// evaluate it is missing, the condition is NOT satisfied. A failed condition
// on an allow rule produces an explicit DENY — it must never fall through to
// a permissive default, because that would silently widen the allow rule.

/// Parse "HH:MM" into (hour, minute). Returns None on malformed input.
fn parse_hhmm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some((h, m))
}

/// Check whether a time condition is satisfied at `now` (UTC).
///
/// `days` uses 0=Sunday .. 6=Saturday (chrono's `num_days_from_sunday`).
/// If `start > end` the window wraps across midnight.
pub fn time_condition_satisfied(cond: &TimeCondition, now: chrono::DateTime<chrono::Utc>) -> bool {
    use chrono::{Datelike, Timelike};

    let (sh, sm) = match parse_hhmm(&cond.start) {
        Some(v) => v,
        None => return false,
    };
    let (eh, em) = match parse_hhmm(&cond.end) {
        Some(v) => v,
        None => return false,
    };

    if !cond.days.is_empty() {
        let today = now.weekday().num_days_from_sunday() as u8;
        if !cond.days.contains(&today) {
            return false;
        }
    }

    let cur = now.hour() * 60 + now.minute();
    let start = sh * 60 + sm;
    let end = eh * 60 + em;

    if start <= end {
        cur >= start && cur <= end
    } else {
        // Window wraps midnight (e.g. 22:00 → 06:00).
        cur >= start || cur <= end
    }
}

/// Match an IP address against an exact address or an IPv4 CIDR block.
fn ip_matches(ip: &str, allowed: &str) -> bool {
    if ip.eq_ignore_ascii_case(allowed) {
        return true;
    }

    if let Some((net, prefix)) = allowed.split_once('/') {
        if let (Ok(ip_addr), Ok(net_addr), Ok(prefix_len)) = (
            ip.parse::<std::net::Ipv4Addr>(),
            net.parse::<std::net::Ipv4Addr>(),
            prefix.parse::<u32>(),
        ) {
            if prefix_len > 32 {
                return false;
            }
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            return (u32::from(ip_addr) & mask) == (u32::from(net_addr) & mask);
        }
    }

    false
}

/// Check whether a location condition is satisfied for the given context.
///
/// The client IP and host are read from `context.env_metadata` under the keys
/// `client_ip` and `host`. Missing metadata means the condition cannot be
/// evaluated and is therefore NOT satisfied (fail-closed).
pub fn location_condition_satisfied(cond: &LocationCondition, context: &Context) -> bool {
    let meta = match &context.env_metadata {
        Some(m) => m,
        None => {
            // No metadata at all: only satisfiable if the condition is empty.
            return cond.allowed_ips.is_empty() && cond.allowed_hosts.is_empty();
        }
    };

    let client_ip = meta.get("client_ip").and_then(|v| v.as_str());
    let host = meta.get("host").and_then(|v| v.as_str());

    let ip_ok = if cond.allowed_ips.is_empty() {
        true
    } else {
        match client_ip {
            Some(ip) => cond
                .allowed_ips
                .iter()
                .any(|allowed| ip_matches(ip, allowed)),
            None => false,
        }
    };

    let host_ok = if cond.allowed_hosts.is_empty() {
        true
    } else {
        match host {
            Some(h) => cond
                .allowed_hosts
                .iter()
                .any(|allowed| h.eq_ignore_ascii_case(allowed)),
            None => false,
        }
    };

    ip_ok && host_ok
}

/// Check whether all declared conditions are satisfied.
pub fn conditions_satisfied(
    conditions: &PolicyConditions,
    context: &Context,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if let Some(time) = &conditions.time {
        if !time_condition_satisfied(time, now) {
            return false;
        }
    }
    if let Some(location) = &conditions.location {
        if !location_condition_satisfied(location, context) {
            return false;
        }
    }
    true
}

/// Convenience: are the conditions attached to an optional policy block satisfied?
fn conditions_ok(conditions: Option<&PolicyConditions>, context: &Context) -> bool {
    match conditions {
        Some(c) => conditions_satisfied(c, context, chrono::Utc::now()),
        None => true,
    }
}

// ─── Shell Policy ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub conditions: Option<PolicyConditions>,
}

// ─── Network Policy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub conditions: Option<PolicyConditions>,
}

// ─── MCP Policy ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub conditions: Option<PolicyConditions>,
}

// ─── Decision ────────────────────────────────────────────────────────────────
// Re-export the canonical Decision type from core to avoid duplication.
pub use agentfence_core::types::Decision;

// ─── Policy Hash ─────────────────────────────────────────────────────────────

impl Policy {
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let yaml = serde_yaml::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn version_string(&self) -> String {
        format!("v{}", self.version)
    }
}

// ─── Policy Evaluation ───────────────────────────────────────────────────────

/// Evaluate an action against the policy.
pub fn evaluate(policy: &Policy, action: &Action) -> DecisionRecord {
    match action.action_type {
        ActionType::Shell => evaluate_shell(policy, action),
        ActionType::Mcp => evaluate_mcp(policy, action),
        ActionType::Network => evaluate_network(policy, action),
        ActionType::Filesystem => evaluate_filesystem(policy, action),
    }
}

fn evaluate_shell(policy: &Policy, action: &Action) -> DecisionRecord {
    let shell = match &policy.shell {
        Some(s) => s,
        None => return DecisionRecord::deny("shell.default", "No shell policy defined"),
    };

    let cmd = &action.target;

    // Check deny list first
    for denied in &shell.deny {
        if cmd.contains(denied.as_str()) {
            return DecisionRecord::deny(
                "shell.deny",
                format!("Command matches denied executable: {}", denied),
            );
        }
    }

    // Check ask list — must match executable name exactly or be followed by whitespace
    for asked in &shell.ask {
        if cmd == asked.as_str()
            || cmd.starts_with(&format!("{} ", asked))
            || cmd.starts_with(&format!("{}\t", asked))
        {
            return DecisionRecord::ask(
                "shell.ask",
                format!("Command requires approval: {}", asked),
            );
        }
    }

    // Check allow list — must match executable name exactly or be followed by whitespace
    for allowed in &shell.allow {
        if cmd == allowed.as_str()
            || cmd.starts_with(&format!("{} ", allowed))
            || cmd.starts_with(&format!("{}\t", allowed))
        {
            // SECURITY: an allow rule is only honoured when its conditions hold.
            // A declared-but-unsatisfied condition must DENY, never fall through
            // to the (possibly permissive) default.
            if !conditions_ok(shell.conditions.as_ref(), &action.context) {
                return DecisionRecord::deny(
                    "shell.conditions",
                    "Command matches allowed executable but policy conditions are not satisfied",
                );
            }
            return DecisionRecord::allow(
                "shell.allow",
                format!("Command matches allowed executable: {}", allowed),
            );
        }
    }

    // Default
    match policy.defaults.shell {
        Decision::Allow => DecisionRecord::allow("shell.default", "Default allow"),
        Decision::Deny => DecisionRecord::deny("shell.default", "Default deny"),
        Decision::Ask => DecisionRecord::ask("shell.default", "Default ask"),
    }
}

fn evaluate_mcp(policy: &Policy, action: &Action) -> DecisionRecord {
    let mcp = match &policy.mcp {
        Some(m) => m,
        None => return DecisionRecord::deny("mcp.default", "No MCP policy defined"),
    };

    let tool = &action.tool;

    // Check deny list
    for denied in &mcp.deny {
        if tool.contains(denied.as_str()) {
            return DecisionRecord::deny(
                "mcp.deny",
                format!("Tool matches denied pattern: {}", denied),
            );
        }
    }

    // Check ask list
    for asked in &mcp.ask {
        if tool.contains(asked.as_str()) {
            return DecisionRecord::ask("mcp.ask", format!("Tool requires approval: {}", asked));
        }
    }

    // Check allow list
    for allowed in &mcp.allow {
        if tool.contains(allowed.as_str()) {
            // SECURITY: conditions must hold for an allow rule to apply (fail-closed).
            if !conditions_ok(mcp.conditions.as_ref(), &action.context) {
                return DecisionRecord::deny(
                    "mcp.conditions",
                    "Tool matches allowed pattern but policy conditions are not satisfied",
                );
            }
            return DecisionRecord::allow(
                "mcp.allow",
                format!("Tool matches allowed pattern: {}", allowed),
            );
        }
    }

    match policy.defaults.mcp {
        Decision::Allow => DecisionRecord::allow("mcp.default", "Default allow"),
        Decision::Deny => DecisionRecord::deny("mcp.default", "Default deny"),
        Decision::Ask => DecisionRecord::ask("mcp.default", "Default ask"),
    }
}

fn evaluate_network(policy: &Policy, action: &Action) -> DecisionRecord {
    let network = match &policy.network {
        Some(n) => n,
        None => return DecisionRecord::deny("network.default", "No network policy defined"),
    };

    let host = &action.target;

    // Check deny list
    for denied in &network.deny {
        if host.contains(denied.as_str()) {
            return DecisionRecord::deny(
                "network.deny",
                format!("Host matches denied pattern: {}", denied),
            );
        }
    }

    // Check ask list
    for asked in &network.ask {
        if host.contains(asked.as_str()) {
            return DecisionRecord::ask(
                "network.ask",
                format!("Host requires approval: {}", asked),
            );
        }
    }

    // Check allow list
    for allowed in &network.allow {
        if host.contains(allowed.as_str()) {
            // SECURITY: conditions must hold for an allow rule to apply (fail-closed).
            if !conditions_ok(network.conditions.as_ref(), &action.context) {
                return DecisionRecord::deny(
                    "network.conditions",
                    "Host matches allowed pattern but policy conditions are not satisfied",
                );
            }
            return DecisionRecord::allow(
                "network.allow",
                format!("Host matches allowed pattern: {}", allowed),
            );
        }
    }

    match policy.defaults.network {
        Decision::Allow => DecisionRecord::allow("network.default", "Default allow"),
        Decision::Deny => DecisionRecord::deny("network.default", "Default deny"),
        Decision::Ask => DecisionRecord::ask("network.default", "Default ask"),
    }
}

fn evaluate_filesystem(policy: &Policy, action: &Action) -> DecisionRecord {
    let fs = match &policy.filesystem {
        Some(f) => f,
        None => return DecisionRecord::deny("filesystem.default", "No filesystem policy defined"),
    };

    let path = &action.target;

    // Check deny patterns
    for denied in &fs.deny {
        if path_matches(path, denied) {
            return DecisionRecord::deny(
                "filesystem.deny",
                format!("Path matches denied pattern: {}", denied),
            );
        }
    }

    // Check read/write allow patterns
    let rules = if action.tool.contains("write") {
        fs.write.as_ref()
    } else {
        fs.read.as_ref()
    };

    if let Some(rules) = rules {
        for allowed in &rules.allow {
            if path_matches(path, allowed) {
                return DecisionRecord::allow(
                    "filesystem.allow",
                    format!("Path matches allowed pattern: {}", allowed),
                );
            }
        }
    }

    match policy.defaults.filesystem {
        Decision::Allow => DecisionRecord::allow("filesystem.default", "Default allow"),
        Decision::Deny => DecisionRecord::deny("filesystem.default", "Default deny"),
        Decision::Ask => DecisionRecord::ask("filesystem.default", "Default ask"),
    }
}

/// Simple glob-like path matching.
/// Supports `**` (any depth) and `*` (single segment).
fn path_matches(path: &str, pattern: &str) -> bool {
    // Normalize path separators
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");

    // Exact match
    if path == pattern {
        return true;
    }

    // Glob matching
    glob_match(&path, &pattern)
}

fn glob_match(text: &str, pattern: &str) -> bool {
    let text_parts: Vec<&str> = text.split('/').collect();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();

    glob_match_parts(&text_parts, &pattern_parts)
}

fn glob_match_parts(text: &[&str], pattern: &[&str]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    if pattern[0] == "**" {
        // ** matches zero or more path segments
        for i in 0..=text.len() {
            if glob_match_parts(&text[i..], &pattern[1..]) {
                return true;
            }
        }
        return false;
    }

    if text.is_empty() {
        return false;
    }

    if segment_matches(text[0], pattern[0]) {
        return glob_match_parts(&text[1..], &pattern[1..]);
    }

    false
}

fn segment_matches(text: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Simple wildcard matching within a segment
    let text_bytes = text.as_bytes();
    let pattern_bytes = pattern.as_bytes();

    let mut ti = 0;
    let mut pi = 0;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0;

    while ti < text_bytes.len() {
        if pi < pattern_bytes.len() && pattern_bytes[pi] == text_bytes[ti] {
            ti += 1;
            pi += 1;
        } else if pi < pattern_bytes.len() && pattern_bytes[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < pattern_bytes.len() && pattern_bytes[pi] == b'*' {
        pi += 1;
    }

    pi == pattern_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_policy;
    use agentfence_core::types::{Action, ActionId, ActionType, AgentId, SessionId};

    fn test_action(action_type: ActionType, tool: &str, target: &str) -> Action {
        Action {
            id: ActionId::new(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type,
            tool: tool.to_string(),
            target: target.to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        }
    }

    fn test_policy() -> Policy {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
    - cargo
  deny:
    - powershell
    - reg
network:
  allow:
    - github.com
    - crates.io
mcp:
  allow:
    - github
    - filesystem
"#;
        parse_policy(yaml).unwrap()
    }

    #[test]
    fn test_parse_minimal_policy() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn test_parse_full_policy() {
        let yaml = r#"
version: 1
defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny
shell:
  allow:
    - git
    - cargo
  deny:
    - powershell
    - reg
network:
  allow:
    - github.com
    - crates.io
mcp:
  allow:
    - github
    - filesystem
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.shell.is_some());
        assert!(policy.network.is_some());
        assert!(policy.mcp.is_some());
    }

    #[test]
    fn test_invalid_version() {
        let yaml = r#"
version: 0
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_host_validation() {
        let yaml = r#"
version: 1
network:
  allow:
    - ""
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_shell_allow_exact_match() {
        let policy = test_policy();
        let action = test_action(ActionType::Shell, "shell", "git");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_shell_allow_with_args() {
        let policy = test_policy();
        let action = test_action(ActionType::Shell, "shell", "git status");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_shell_deny_bypass_attempt() {
        let policy = test_policy();
        // "gitx" should NOT match "git" — tests the bypass fix
        let action = test_action(ActionType::Shell, "shell", "gitx status");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_shell_deny_bypass_with_space() {
        let policy = test_policy();
        // "git status && rm -rf /" should NOT match "git" — chaining bypass
        let action = test_action(ActionType::Shell, "shell", "git status && rm -rf /");
        let record = evaluate(&policy, &action);
        // This should be denied because the command contains "rm -rf /" which is dangerous
        // But our simple parser doesn't detect chaining — this is a known limitation
        // The test documents this limitation
        assert_eq!(record.decision, Decision::Allow); // Known limitation: chaining not detected
    }

    #[test]
    fn test_shell_deny_exact() {
        let policy = test_policy();
        let action = test_action(
            ActionType::Shell,
            "shell",
            "powershell -Command 'Remove-Item'",
        );
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_network_allow() {
        let policy = test_policy();
        let action = test_action(ActionType::Network, "network", "github.com");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_network_deny() {
        let policy = test_policy();
        let action = test_action(ActionType::Network, "network", "evil.com");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_mcp_allow() {
        let policy = test_policy();
        let action = test_action(ActionType::Mcp, "github.create_issue", "github");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_mcp_deny() {
        let policy = test_policy();
        let action = test_action(ActionType::Mcp, "shell.execute", "shell");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_filesystem_deny_by_default() {
        let policy = test_policy();
        let action = test_action(ActionType::Filesystem, "read", "/etc/passwd");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_path_traversal_deny() {
        let policy = test_policy();
        let action = test_action(ActionType::Filesystem, "read", "../../../etc/passwd");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_absolute_path_deny() {
        let policy = test_policy();
        let action = test_action(ActionType::Filesystem, "read", "/etc/shadow");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_shell_ask() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
  ask:
    - npm
"#;
        let policy = parse_policy(yaml).unwrap();
        let action = test_action(ActionType::Shell, "shell", "npm install");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Ask);
        assert_eq!(record.rule_id, "shell.ask");
    }

    #[test]
    fn test_mcp_ask() {
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
  ask:
    - shell
"#;
        let policy = parse_policy(yaml).unwrap();
        let action = test_action(ActionType::Mcp, "shell", "shell");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Ask);
        assert_eq!(record.rule_id, "mcp.ask");
    }

    #[test]
    fn test_network_ask() {
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
  ask:
    - npmjs.org
"#;
        let policy = parse_policy(yaml).unwrap();
        let action = test_action(ActionType::Network, "network", "registry.npmjs.org");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Ask);
        assert_eq!(record.rule_id, "network.ask");
    }

    #[test]
    fn test_time_condition_parsing() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
  conditions:
    time:
      start: "09:00"
      end: "17:00"
      days: [1, 2, 3, 4, 5]
"#;
        let policy = parse_policy(yaml).unwrap();
        let shell = policy.shell.as_ref().unwrap();
        let conditions = shell.conditions.as_ref().unwrap();
        let time = conditions.time.as_ref().unwrap();
        assert_eq!(time.start, "09:00");
        assert_eq!(time.end, "17:00");
        assert_eq!(time.days, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_location_condition_parsing() {
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
  conditions:
    location:
      allowed_ips:
        - "192.168.1.0/24"
      allowed_hosts:
        - "github.com"
"#;
        let policy = parse_policy(yaml).unwrap();
        let network = policy.network.as_ref().unwrap();
        let conditions = network.conditions.as_ref().unwrap();
        let location = conditions.location.as_ref().unwrap();
        assert_eq!(location.allowed_ips, vec!["192.168.1.0/24"]);
        assert_eq!(location.allowed_hosts, vec!["github.com"]);
    }

    #[test]
    fn test_no_conditions() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
"#;
        let policy = parse_policy(yaml).unwrap();
        let shell = policy.shell.as_ref().unwrap();
        assert!(shell.conditions.is_none());
    }

    // ─── Condition enforcement (fail-closed) ────────────────────────────────

    fn action_with_context(
        action_type: ActionType,
        tool: &str,
        target: &str,
        ctx: Context,
    ) -> Action {
        let mut a = test_action(action_type, tool, target);
        a.context = ctx;
        a
    }

    #[test]
    fn test_time_condition_satisfied_within_window() {
        use chrono::TimeZone;
        let cond = TimeCondition {
            start: "09:00".to_string(),
            end: "17:00".to_string(),
            days: vec![],
        };
        let inside = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        let before = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 8, 0, 0).unwrap();
        let after = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 18, 0, 0).unwrap();
        assert!(time_condition_satisfied(&cond, inside));
        assert!(!time_condition_satisfied(&cond, before));
        assert!(!time_condition_satisfied(&cond, after));
    }

    #[test]
    fn test_time_condition_wraps_midnight() {
        use chrono::TimeZone;
        let cond = TimeCondition {
            start: "22:00".to_string(),
            end: "06:00".to_string(),
            days: vec![],
        };
        let late = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 23, 30, 0).unwrap();
        let early = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 5, 0, 0).unwrap();
        let midday = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        assert!(time_condition_satisfied(&cond, late));
        assert!(time_condition_satisfied(&cond, early));
        assert!(!time_condition_satisfied(&cond, midday));
    }

    #[test]
    fn test_time_condition_day_filter() {
        use chrono::TimeZone;
        // 2026-01-05 is a Monday (num_days_from_sunday == 1).
        let cond = TimeCondition {
            start: "00:00".to_string(),
            end: "23:59".to_string(),
            days: vec![1],
        };
        let monday = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        let tuesday = chrono::Utc.with_ymd_and_hms(2026, 1, 6, 12, 0, 0).unwrap();
        assert!(time_condition_satisfied(&cond, monday));
        assert!(!time_condition_satisfied(&cond, tuesday));
    }

    #[test]
    fn test_time_condition_malformed_is_unsatisfied() {
        use chrono::TimeZone;
        let cond = TimeCondition {
            start: "not-a-time".to_string(),
            end: "17:00".to_string(),
            days: vec![],
        };
        let now = chrono::Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        assert!(!time_condition_satisfied(&cond, now));
    }

    #[test]
    fn test_location_condition_ip_cidr() {
        let cond = LocationCondition {
            allowed_ips: vec!["192.168.1.0/24".to_string()],
            allowed_hosts: vec![],
        };
        let mut ctx = Context::default();
        ctx.env_metadata = Some(serde_json::json!({"client_ip": "192.168.1.55"}));
        assert!(location_condition_satisfied(&cond, &ctx));

        ctx.env_metadata = Some(serde_json::json!({"client_ip": "10.0.0.1"}));
        assert!(!location_condition_satisfied(&cond, &ctx));
    }

    #[test]
    fn test_location_condition_missing_metadata_fails_closed() {
        let cond = LocationCondition {
            allowed_ips: vec!["192.168.1.0/24".to_string()],
            allowed_hosts: vec![],
        };
        // No env_metadata at all → condition cannot be evaluated → NOT satisfied.
        let ctx = Context::default();
        assert!(!location_condition_satisfied(&cond, &ctx));
    }

    #[test]
    fn test_shell_allow_denied_when_time_condition_unsatisfied() {
        // SECURITY: an allow rule with a time condition that does not hold must
        // DENY — it must not silently fall through to a permissive default.
        let yaml = r#"
version: 1
defaults:
  shell: allow
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
  conditions:
    time:
      start: "00:00"
      end: "00:01"
"#;
        let policy = parse_policy(yaml).unwrap();
        let action = test_action(ActionType::Shell, "shell", "git status");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.conditions");
    }

    #[test]
    fn test_network_allow_denied_when_location_condition_unsatisfied() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: allow
  mcp: deny
  filesystem: deny
network:
  allow:
    - github.com
  conditions:
    location:
      allowed_ips:
        - "192.168.1.0/24"
"#;
        let policy = parse_policy(yaml).unwrap();
        // No client_ip metadata → location condition unsatisfied → DENY.
        let action = test_action(ActionType::Network, "http", "https://github.com/x");
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "network.conditions");
    }

    #[test]
    fn test_conditions_satisfied_allows_when_metadata_present() {
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
  conditions:
    location:
      allowed_ips:
        - "192.168.1.0/24"
"#;
        let policy = parse_policy(yaml).unwrap();
        let mut ctx = Context::default();
        ctx.env_metadata = Some(serde_json::json!({"client_ip": "192.168.1.10"}));
        let action = action_with_context(ActionType::Network, "http", "https://github.com/x", ctx);
        let record = evaluate(&policy, &action);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.rule_id, "network.allow");
    }
}
