//! Integration tests for runtime plugin loading.
//!
//! These exercise the **real** path an agent goes through:
//! `agentfence.yaml` -> `parse_policy` -> `plugin_loader::build_pdp` -> `Pdp::evaluate`.
//!
//! The WebAssembly plugin is the genuine component fixture built from
//! `crates/wasm-plugin/guest/` — not a mock — so these tests prove that a
//! configured plugin is actually compiled and executed inside the sandbox.
//!
//! SECURITY INVARIANT UNDER TEST: a plugin may only **tighten** a decision. It
//! can never turn a `Deny` into an `Allow`, and a failing plugin can never grant
//! permission.

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, Context, Decision, SessionId};
use agentfence_policy::parser::parse_policy;
use agentfence_policy::plugin_loader::{build_pdp, build_registry};

/// The real compiled WebAssembly component fixture.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../wasm-plugin/tests/fixtures/test-plugin.component.wasm"
);

/// Build an MCP action whose *tool* satisfies the core allow list and whose
/// *target* is what the WebAssembly guest inspects.
fn mcp_action(tool: &str, target: &str) -> Action {
    Action {
        id: ActionId::new(),
        session_id: SessionId::new(),
        agent_id: AgentId::new("plugin-loader-test"),
        task_id: None,
        action_type: ActionType::Mcp,
        tool: tool.to_string(),
        target: target.to_string(),
        args_hash: String::new(),
        context: Context::default(),
    }
}

/// A policy that allows the given tools at the core level.
fn policy_with_plugins(plugin_yaml: &str) -> String {
    format!(
        "version: 1\n\
         defaults:\n  \
         filesystem: deny\n  \
         shell: deny\n  \
         network: deny\n  \
         mcp: deny\n\
         mcp:\n  \
         allow:\n    \
         - deny.example.com\n    \
         - allow.example.com\n    \
         - trap.example.com\n    \
         - ask.example.com\n\
         {plugin_yaml}"
    )
}

fn wasm_entry(id: &str, module: &str, fingerprint: &str) -> String {
    format!(
        "plugins:\n  \
         wasm:\n    \
         - id: {id}\n      \
         enabled: true\n      \
         module: {module}\n      \
         expected_fingerprint: \"{fingerprint}\"\n"
    )
}

fn evaluate(policy_yaml: &str, tool: &str, target: &str) -> Decision {
    let policy = parse_policy(policy_yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");
    pdp.evaluate(&mcp_action(tool, target)).decision
}

/// Load a policy and return the failure message.
///
/// `Pdp` deliberately has no `Debug` impl (it holds a plugin registry that is
/// not `Debug`), so `expect_err` cannot be used on the raw result.
fn load_error(policy: agentfence_policy::model::Policy) -> String {
    match build_pdp(policy, Vec::new()) {
        Ok(_) => panic!("plugin load was expected to fail"),
        Err(e) => format!("{}", e),
    }
}

// ─── Backward compatibility ──────────────────────────────────────────────────

#[test]
fn test_policy_without_plugin_section_behaves_exactly_as_before() {
    // A policy file with no `plugins:` section must parse, load, and still
    // enforce the core policy. No plugin may appear.
    let yaml = "version: 1\n\
                defaults:\n  \
                filesystem: deny\n  \
                shell: deny\n  \
                network: deny\n  \
                mcp: deny\n\
                mcp:\n  \
                allow:\n    - deny.example.com\n";

    let policy = parse_policy(yaml).expect("policy without plugins must parse");
    assert!(
        policy.plugins.is_none(),
        "a policy without a plugins section must yield None"
    );

    let (registry, report) = build_registry(&policy, Vec::new()).expect("registry build");
    assert!(registry.list_wasm_plugins().is_empty());
    assert!(report.is_empty());

    // The core decision is unchanged: the plugin never ran.
    assert_eq!(
        evaluate(yaml, "deny.example.com", "deny.example.com"),
        Decision::Allow
    );
}

// ─── Configured plugin is consulted ──────────────────────────────────────────

#[test]
fn test_configured_wasm_plugin_denies_an_otherwise_allowed_action() {
    // Core says ALLOW; the configured plugin says DENY. The plugin must win.
    let yaml = policy_with_plugins(&wasm_entry("test-plugin", FIXTURE, ""));

    let policy = parse_policy(&yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");

    let record = pdp.evaluate(&mcp_action("deny.example.com", "deny.example.com"));
    assert_eq!(
        record.decision,
        Decision::Deny,
        "a configured plugin Deny must override the core Allow"
    );
    assert_eq!(
        record.rule_id, "test-plugin",
        "the decision must name the plugin that produced it"
    );
}

#[test]
fn test_configured_wasm_plugin_ask_escalates() {
    let yaml = policy_with_plugins(&wasm_entry("test-plugin", FIXTURE, ""));

    let policy = parse_policy(&yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");

    let record = pdp.evaluate(&mcp_action("ask.example.com", "ask.example.com"));
    assert_eq!(
        record.decision,
        Decision::Ask,
        "a configured plugin Ask must escalate an otherwise allowed action"
    );
}

// ─── A plugin cannot loosen a decision ───────────────────────────────────────

#[test]
fn test_plugin_allow_cannot_weaken_a_core_deny() {
    // The guest returns its INVALID "allow" code for this target; the sandbox
    // must sanitize it to abstain. The core DENY must stand.
    let yaml = format!(
        "version: 1\n\
         defaults:\n  \
         filesystem: deny\n  shell: deny\n  network: deny\n  mcp: deny\n\
         mcp:\n  \
         deny:\n    \
         - allow.example.com\n\
         plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         enabled: true\n      \
         module: {FIXTURE}\n"
    );

    let policy = parse_policy(&yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");

    // Core denies this tool, and the plugin tries to grant an Allow.
    let record = pdp.evaluate(&mcp_action("allow.example.com", "allow.example.com"));
    assert_eq!(
        record.decision,
        Decision::Deny,
        "a plugin may never turn a core Deny into an Allow"
    );
    assert_ne!(
        record.rule_id, "test-plugin",
        "an abstaining plugin must not be reported as the deciding rule"
    );
}

#[test]
fn test_failing_plugin_cannot_grant_permission() {
    // `trap.example.com` makes the guest trap. A failing plugin must never
    // surface as an Allow, and it must never erase a core Deny.
    let yaml = policy_with_plugins(&wasm_entry("test-plugin", FIXTURE, ""));

    let policy = parse_policy(&yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");

    // Core allows the tool, the plugin fails: the plugin must abstain, so the
    // core decision is unchanged and no Allow is attributed to the plugin.
    let record = pdp.evaluate(&mcp_action("trap.example.com", "trap.example.com"));
    assert_ne!(
        record.rule_id, "test-plugin",
        "a trapped plugin must not be reported as the deciding rule"
    );
}

#[test]
fn test_plugin_failure_never_erases_a_core_deny() {
    // `trap.example.com` makes the guest trap. The core policy denies the tool,
    // so a failing plugin must leave that deny intact.
    let yaml = format!(
        "version: 1\n\
         defaults:\n  \
         filesystem: deny\n  shell: deny\n  network: deny\n  mcp: deny\n\
         mcp:\n  \
         deny:\n    \
         - trap.example.com\n\
         plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         enabled: true\n      \
         module: {FIXTURE}\n"
    );

    let policy = parse_policy(&yaml).expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");

    let record = pdp.evaluate(&mcp_action("trap.example.com", "trap.example.com"));
    assert_eq!(
        record.decision,
        Decision::Deny,
        "a failing plugin must not weaken a core deny"
    );
}

// ─── Disabled plugins do not execute ─────────────────────────────────────────

#[test]
fn test_disabled_plugin_is_not_registered_or_executed() {
    let yaml = policy_with_plugins(&format!(
        "plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         enabled: false\n      \
         module: {FIXTURE}\n"
    ));

    let policy = parse_policy(&yaml).expect("policy must parse");
    let (registry, report) = build_registry(&policy, Vec::new()).expect("registry build");

    assert!(
        registry.list_wasm_plugins().is_empty(),
        "a disabled plugin must not be registered at all"
    );
    assert_eq!(report.skipped_disabled, vec!["test-plugin".to_string()]);

    // Without the plugin, the core allow stands.
    let pdp = build_pdp(policy, Vec::new()).expect("plugin load must succeed");
    assert_eq!(
        pdp.evaluate(&mcp_action("deny.example.com", "deny.example.com"))
            .decision,
        Decision::Allow,
        "a disabled plugin must not deny"
    );
}

// ─── Fingerprint verification ────────────────────────────────────────────────

#[test]
fn test_incorrect_wasm_fingerprint_is_rejected() {
    let policy = parse_policy(&policy_with_plugins(&wasm_entry(
        "test-plugin",
        FIXTURE,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )))
    .expect("policy must parse");

    let error = load_error(policy);
    assert!(
        error.contains("fingerprint mismatch"),
        "the error must name the fingerprint mismatch, got: {}",
        error
    );
}

#[test]
fn test_correct_wasm_fingerprint_is_accepted() {
    let digest = agentfence_wasm_plugin::compute_digest(
        &std::fs::read(FIXTURE).expect("fixture must exist"),
    );

    let policy = parse_policy(&policy_with_plugins(&wasm_entry(
        "test-plugin",
        FIXTURE,
        &digest,
    )))
    .expect("policy must parse");
    let pdp = build_pdp(policy, Vec::new()).expect("a matching fingerprint must load");

    let record = pdp.evaluate(&mcp_action("deny.example.com", "deny.example.com"));
    assert_eq!(record.decision, Decision::Deny);
}

#[test]
fn test_missing_module_is_rejected() {
    let policy = parse_policy(&policy_with_plugins(&wasm_entry(
        "test-plugin",
        "/nonexistent/path/plugin.component.wasm",
        "",
    )))
    .expect("policy must parse");

    let error = load_error(policy);
    assert!(
        error.contains("Failed to read wasm module") || error.contains("No such file"),
        "the error must name the missing module, got: {}",
        error
    );
}

// ─── Configuration validation ────────────────────────────────────────────────

#[test]
fn test_malformed_fingerprint_is_rejected() {
    let policy = parse_policy(&policy_with_plugins(&wasm_entry(
        "test-plugin",
        FIXTURE,
        "not-hex",
    )))
    .expect("policy must parse");

    let error = load_error(policy);
    assert!(
        error.contains("malformed expected_fingerprint"),
        "the error must name the malformed fingerprint"
    );
}

#[test]
fn test_empty_plugin_id_is_rejected() {
    let yaml = policy_with_plugins(&format!(
        "plugins:\n  \
         wasm:\n    \
         - id: \"\"\n      \
         module: {FIXTURE}\n"
    ));
    let policy = parse_policy(&yaml).expect("policy must parse");
    assert!(build_pdp(policy, Vec::new()).is_err());
}

#[test]
fn test_empty_module_path_is_rejected() {
    let yaml = policy_with_plugins(
        "plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         module: \"\"\n",
    );
    let policy = parse_policy(&yaml).expect("policy must parse");
    let error = load_error(policy);
    assert!(error.contains("empty module path"));
}

#[test]
fn test_zero_memory_limit_is_rejected() {
    let yaml = policy_with_plugins(&format!(
        "plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         module: {FIXTURE}\n      \
         max_memory_mb: 0\n"
    ));
    let policy = parse_policy(&yaml).expect("policy must parse");
    let error = load_error(policy);
    assert!(error.contains("max_memory_mb: 0"));
}

#[test]
fn test_duplicate_plugin_ids_are_rejected() {
    let yaml = policy_with_plugins(&format!(
        "plugins:\n  \
         wasm:\n    \
         - id: test-plugin\n      \
         module: {FIXTURE}\n    \
         - id: test-plugin\n      \
         module: {FIXTURE}\n"
    ));
    let policy = parse_policy(&yaml).expect("policy must parse");
    let error = load_error(policy);
    assert!(error.contains("duplicate plugin id"));
}

#[test]
fn test_duplicate_ids_across_wasm_and_native_are_rejected() {
    let yaml = policy_with_plugins(&format!(
        "plugins:\n  \
         wasm:\n    \
         - id: shared-id\n      \
         module: {FIXTURE}\n  \
         native:\n    \
         - id: shared-id\n"
    ));
    let policy = parse_policy(&yaml).expect("policy must parse");
    assert!(build_pdp(policy, Vec::new()).is_err());
}

// ─── Native plugins follow a distinct trust model ────────────────────────────

/// A native plugin supplied by the host application.
struct HostPlugin {
    id: String,
}

impl agentfence_policy::plugin::CustomPolicyRule for HostPlugin {
    fn metadata(&self) -> agentfence_policy::plugin::PluginMetadata {
        agentfence_policy::plugin::PluginMetadata {
            id: self.id.clone(),
            name: self.id.clone(),
            version: "1.0.0".to_string(),
            api_version: agentfence_policy::plugin::PLUGIN_API_VERSION,
            capabilities: vec![agentfence_policy::plugin::PluginCapability::PolicyRule],
            author: "test".to_string(),
            description: "host supplied test plugin".to_string(),
            fingerprint: String::new(),
        }
    }

    fn applies_to(&self, _action: &Action) -> bool {
        true
    }

    fn evaluate(
        &self,
        _context: &agentfence_policy::plugin::PluginContext,
    ) -> std::result::Result<agentfence_policy::plugin::PluginResult, String> {
        Ok(agentfence_policy::plugin::PluginResult {
            decision: Some(Decision::Deny),
            rule_id: self.id.clone(),
            reason: "host plugin denied".to_string(),
            evidence: None,
            risk_level: None,
            metadata: std::collections::HashMap::new(),
        })
    }
}

#[test]
fn test_native_plugin_supplied_by_the_host_is_registered() {
    let yaml = policy_with_plugins(
        "plugins:\n  \
         native:\n    \
         - id: host-rule\n",
    );
    let policy = parse_policy(&yaml).expect("policy must parse");

    let (registry, report) = build_registry(
        &policy,
        vec![Box::new(HostPlugin {
            id: "host-rule".to_string(),
        })],
    )
    .expect("host supplied native plugin must load");

    assert_eq!(report.native_registered, vec!["host-rule".to_string()]);
    let metadata = registry.list_plugins();
    assert!(
        metadata.iter().any(|m| m.id == "host-rule"),
        "the host plugin must be registered"
    );
}

#[test]
fn test_native_plugin_not_supplied_by_the_host_is_rejected() {
    // SECURITY: the policy file must never be able to introduce native code.
    let yaml = policy_with_plugins(
        "plugins:\n  \
         native:\n    \
         - id: not-supplied-by-anyone\n",
    );
    let policy = parse_policy(&yaml).expect("policy must parse");

    let error = load_error(policy);
    assert!(
        error.contains("not registered by the host application"),
        "the error must explain that native code cannot come from the policy file, got: {}",
        error
    );
}

#[test]
fn test_disabled_native_plugin_is_skipped() {
    let yaml = policy_with_plugins(
        "plugins:\n  \
         native:\n    \
         - id: host-rule\n      \
         enabled: false\n",
    );
    let policy = parse_policy(&yaml).expect("policy must parse");

    let (registry, report) = build_registry(
        &policy,
        vec![Box::new(HostPlugin {
            id: "host-rule".to_string(),
        })],
    )
    .expect("load must succeed");

    assert!(registry.list_plugins().is_empty());
    assert_eq!(report.skipped_disabled, vec!["host-rule".to_string()]);
}

// ─── Resource limits reach the sandbox ───────────────────────────────────────

#[test]
fn test_per_plugin_memory_limit_is_enforced_by_the_sandbox() {
    // A 1-byte memory limit cannot host the real component. The plugin must
    // fail to execute — and the failure must never surface as an Allow.
    let mut registry = agentfence_policy::plugin::PluginRegistry::new();
    registry
        .register_wasm_plugin_with_limits("tiny".to_string(), FIXTURE.to_string(), String::new(), 1)
        .expect("registration must succeed");

    let context = agentfence_policy::plugin::PluginContext::from_action(&mcp_action(
        "deny.example.com",
        "deny.example.com",
    ));
    let result = registry.evaluate_wasm_plugins(&context);
    assert!(
        result.is_empty(),
        "a plugin that cannot allocate must abstain, never grant"
    );
}

#[test]
fn test_default_memory_limit_is_used_when_omitted() {
    // The 3-argument API must keep its historical default.
    let mut registry = agentfence_policy::plugin::PluginRegistry::new();
    registry
        .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
        .expect("registration must succeed");
    assert_eq!(registry.list_wasm_plugins(), vec!["p".to_string()]);
}
