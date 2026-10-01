//! Typed policy model for AgentFence.

use serde::{Deserialize, Serialize};

use agentfence_core::types::{Action, ActionType, DecisionRecord};

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

// ─── Shell Policy ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

// ─── Network Policy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

// ─── MCP Policy ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

// ─── Decision ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Ask => write!(f, "ASK"),
        }
    }
}

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

    // Check allow list
    for allowed in &shell.allow {
        if cmd.starts_with(allowed.as_str()) {
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

    // Check allow list
    for allowed in &mcp.allow {
        if tool.contains(allowed.as_str()) {
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

    // Check allow list
    for allowed in &network.allow {
        if host.contains(allowed.as_str()) {
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
