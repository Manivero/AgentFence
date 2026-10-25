//! Shell gateway for AgentFence.
//!
//! Evaluates shell commands against policy before execution.
//! Never uses naive substring checks as the security model.

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;
use agentfence_secrets::detector::SecretDetector;

use crate::command::ShellCommand;
use crate::trusted::{TrustedContextToken, TrustedShellContext};

/// Shell gateway.
///
/// Evaluates shell commands against policy before execution.
/// Never uses naive substring checks as the security model.
pub struct ShellGateway {
    pdp: Pdp,
    secret_detector: SecretDetector,
}

impl ShellGateway {
    /// Create a new shell gateway with the given PDP.
    pub fn new(pdp: Pdp) -> Self {
        Self {
            pdp,
            secret_detector: SecretDetector::new(),
        }
    }

    /// Check if a command contains secrets.
    ///
    /// Returns a list of detected secrets (without raw values).
    /// Never logs or returns raw secret values.
    pub fn check_secrets(
        &self,
        cmd: &ShellCommand,
    ) -> Vec<agentfence_secrets::detector::DetectedSecret> {
        self.secret_detector.detect(&cmd.raw, "shell")
    }

    /// Mint a capability token for the trusted integration layer.
    ///
    /// SECURITY: this method is `pub`, so **any crate holding a `ShellGateway`
    /// can mint a token**. The boundary is architectural, not visibility-based:
    ///
    /// - no untrusted component is handed a gateway — `PluginContext` exposes no
    ///   gateway or PDP, and the MCP/Network proxies hold a `Pdp` directly;
    /// - `ShellGateway::new` is public, so in-process code that can construct a
    ///   `Pdp` can also construct a gateway. In cooperative mode such code can
    ///   bypass AgentFence entirely; this API does not claim otherwise.
    ///
    /// What the token does guarantee: untrusted *data* cannot assert a location.
    /// `evaluate_with_context` is unreachable for a caller that cannot build a
    /// `TrustedShellContext`, and `cmd.raw` is never parsed for a location.
    pub fn issue_trusted_context_token(&self) -> TrustedContextToken {
        TrustedContextToken::new()
    }

    /// Evaluate a shell command with no verified location metadata.
    ///
    /// Returns a decision record with full explanation.
    ///
    /// This is the path untrusted callers must use: no `host`/`client_ip` is
    /// supplied, so a location condition that requires them fails closed (DENY)
    /// rather than being silently satisfied.
    ///
    /// SECURITY — context provenance:
    ///
    /// `client_ip` and `host` come only from [`TrustedShellContext`], which
    /// cannot be built without a [`TrustedContextToken`]. They are never
    /// derived from `cmd.raw`, because the raw command string is
    /// caller-controlled: a command that merely names a host must not
    /// authorise itself.
    pub fn evaluate(
        &self,
        cmd: &ShellCommand,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> DecisionRecord {
        self.evaluate_with_context(cmd, &TrustedShellContext::empty(), session_id, agent_id)
    }

    /// Evaluate a shell command with verified location metadata.
    ///
    /// SECURITY: `trusted` must be built through [`TrustedShellContext::new`]
    /// with a [`TrustedContextToken`]. That constructor's token argument can
    /// only be produced by [`Self::issue_trusted_context_token`], so this path
    /// is unreachable for untrusted input. Passing an empty context (the
    /// untrusted case) is impossible for external callers: `empty()` is
    /// crate-private.
    pub fn evaluate_with_context(
        &self,
        cmd: &ShellCommand,
        trusted: &TrustedShellContext,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> DecisionRecord {
        let secrets = self.check_secrets(cmd);
        if !secrets.is_empty() {
            tracing::warn!(
                "Shell command contains {} secret(s): {:?}",
                secrets.len(),
                secrets
                    .iter()
                    .map(|s| s.category.clone())
                    .collect::<Vec<_>>()
            );
        }

        // Verified location data. Sourced exclusively from the trusted context;
        // `cmd.raw` is never inspected for a location.
        let client_ip = trusted.client_ip().map(str::to_string);
        let host = trusted.host().map(str::to_string);

        let action = Action {
            id: ActionId::new(),
            session_id: session_id.clone(),
            agent_id: agent_id.clone(),
            task_id: None,
            action_type: ActionType::Shell,
            tool: "shell".to_string(),
            target: cmd.raw.clone(),
            args_hash: hash_args(&cmd.raw),
            context: agentfence_core::types::Context {
                cwd: std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from)),
                session_id: Some(session_id.clone()),
                client_ip,
                host,
                ..Default::default()
            },
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a shell command is allowed.
    pub fn is_allowed(
        &self,
        cmd: &ShellCommand,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> bool {
        let record = self.evaluate(cmd, session_id, agent_id);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }
}

fn hash_args(args: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(args.as_bytes());
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
shell:
  allow:
    - git
    - cargo
  deny:
    - powershell
    - reg
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    #[test]
    fn test_shell_allow() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("git status").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_shell_deny() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd =
            ShellCommand::parse("powershell -Command 'Remove-Item -Recurse -Force C:\'").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_shell_default_deny() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("unknown-command --flag").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_secret_detection_in_command() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("echo ghp_1234567890abcdef").unwrap();
        let secrets = gateway.check_secrets(&cmd);
        assert!(!secrets.is_empty());
        assert!(secrets
            .iter()
            .any(|s| s.category == agentfence_secrets::detector::SecretCategory::GitHubToken));
    }

    #[test]
    fn test_no_secrets_in_normal_command() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("git status").unwrap();
        let secrets = gateway.check_secrets(&cmd);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_secret_fingerprint_not_raw() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("echo ghp_12...cdef").unwrap();
        let secrets = gateway.check_secrets(&cmd);
        for secret in &secrets {
            assert!(!secret.fingerprint.contains("ghp_12...cdef"));
        }
    }

    #[test]
    fn test_evaluate_detects_secrets_and_returns_decision() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("echo ghp_12...cdef").unwrap();
        let record = gateway.evaluate(&cmd, &SessionId::new(), &AgentId::new("test"));
        assert!(matches!(
            record.decision,
            agentfence_core::types::Decision::Allow | agentfence_core::types::Decision::Deny
        ));
    }

    // ── Location context propagation ─────────────────────────────────────────

    fn pdp_with_host_location() -> Pdp {
        let yaml = r#"
version: 1
defaults:
  shell: deny
shell:
  allow:
    - git
  conditions:
    location:
      allowed_hosts:
        - build-server-01
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    fn pdp_with_ip_location() -> Pdp {
        let yaml = r#"
version: 1
defaults:
  shell: deny
shell:
  allow:
    - git
  conditions:
    location:
      allowed_ips:
        - "10.0.0.0/8"
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    /// Build a verified context exactly the way the trusted integration layer
    /// does: mint a token from the gateway, then construct the context.
    fn verified_context(
        gateway: &ShellGateway,
        host: Option<&str>,
        client_ip: Option<&str>,
    ) -> TrustedShellContext {
        let token = gateway.issue_trusted_context_token();
        TrustedShellContext::new(
            token,
            host.map(str::to_string),
            client_ip.map(str::to_string),
        )
    }

    #[test]
    fn test_location_host_from_verified_context_allowed() {
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let ctx = verified_context(&gateway, Some("build-server-01"), None);
        let record =
            gateway.evaluate_with_context(&cmd, &ctx, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_location_host_without_context_fails_closed() {
        // The untrusted path supplies no location data, so the condition fails
        // closed even though the command is otherwise allowed.
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let record = gateway.evaluate(&cmd, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.conditions");
    }

    #[test]
    fn test_location_host_not_derived_from_command() {
        // A command that merely names a host must not authorise itself:
        // `cmd.raw` is caller-controlled and is never a location source.
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git build-server-01").unwrap();
        let record = gateway.evaluate(&cmd, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.conditions");
    }

    #[test]
    fn test_location_host_wrong_value_denied() {
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let ctx = verified_context(&gateway, Some("evil.example.com"), None);
        let record =
            gateway.evaluate_with_context(&cmd, &ctx, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_location_verified_context_without_values_fails_closed() {
        // A capability token is not a free pass: a context built with it but
        // carrying no values still fails closed.
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let ctx = verified_context(&gateway, None, None);
        let record =
            gateway.evaluate_with_context(&cmd, &ctx, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.conditions");
    }

    #[test]
    fn test_location_client_ip_from_verified_context_allowed() {
        let gateway = ShellGateway::new(pdp_with_ip_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let ctx = verified_context(&gateway, None, Some("10.1.2.3"));
        let record =
            gateway.evaluate_with_context(&cmd, &ctx, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_location_client_ip_outside_range_denied() {
        let gateway = ShellGateway::new(pdp_with_ip_location());
        let cmd = ShellCommand::parse("git status").unwrap();
        let ctx = verified_context(&gateway, None, Some("192.168.1.5"));
        let record =
            gateway.evaluate_with_context(&cmd, &ctx, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_untrusted_path_ignores_command_host_like_arguments() {
        // End-to-end proof of the trust boundary: even a command that spells
        // out the allowed host and IP cannot influence the untrusted path.
        let gateway = ShellGateway::new(pdp_with_host_location());
        let cmd = ShellCommand::parse("git build-server-01 --from 10.0.0.5").unwrap();
        let record = gateway.evaluate(&cmd, &SessionId::new(), &AgentId::new("test"));
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.conditions");
    }

    #[test]
    fn test_untrusted_path_ignores_metadata_like_command_content() {
        // Every plausible way a command could try to smuggle location metadata
        // into the untrusted path must be ignored. `cmd.raw` is never parsed for
        // a location and `evaluate()` never reads a trusted context, so none of
        // these encodings can satisfy the condition.
        let gateway = ShellGateway::new(pdp_with_host_location());
        let payloads = [
            "git status --host=build-server-01",
            "git status?host=build-server-01",
            "git status -H build-server-01",
            "git status {\"host\":\"build-server-01\"}",
            "git status $HOST=build-server-01",
            "git status export HOST=build-server-01",
            "git status --from 10.0.0.5 --to build-server-01",
            "git status; echo host=build-server-01",
        ];

        let mut evaluated = 0;
        for raw in payloads {
            // Some payloads are not valid shell words; those are skipped, not
            // silently treated as a pass.
            let Ok(cmd) = ShellCommand::parse(raw) else {
                continue;
            };
            evaluated += 1;
            let record = gateway.evaluate(&cmd, &SessionId::new(), &AgentId::new("test"));
            assert_eq!(
                record.decision,
                Decision::Deny,
                "command {raw:?} must not satisfy a location condition"
            );
            assert_eq!(record.rule_id, "shell.conditions");
        }
        assert!(
            evaluated >= 5,
            "test lost coverage: only {evaluated} payloads were parseable"
        );
    }
}
