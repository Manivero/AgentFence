//! Runtime plugin loading — the single initialization boundary.
//!
//! Every enforcement entry point (CLI `exec`/`run`/`mcp`/`network`, the Hermes
//! wrapper) must build its PDP through [`build_pdp`] so that plugins configured
//! in `agentfence.yaml` are actually consulted.
//!
//! SECURITY: there is exactly **one** registry-construction path. Building a
//! `Pdp` with `Pdp::new` directly consults no plugin at all — that stays
//! available for callers with no configuration (tests, embeddings) and it never
//! weakens the core policy, because the core policy always decides. Loading a
//! plugin can only *tighten* a decision; it can never produce an effective
//! `Allow`.
//!
//! Native plugins follow a distinct trust model: the policy file can only
//! *reference* a plugin that the embedding application registered
//! programmatically. A `native:` entry naming anything else is an error, and
//! native code is never loaded from a path in the policy file.

use std::collections::HashSet;
use std::sync::Arc;

use agentfence_core::error::{AgentFenceError, Result};
use tracing::{info, warn};

use crate::model::Policy;
use crate::pdp::Pdp;
use crate::plugin::{BoxedPlugin, PluginConfig, PluginRegistry, PluginSection};

/// What happened while loading the configured plugins.
#[derive(Debug, Default, Clone)]
pub struct PluginLoadReport {
    /// WebAssembly plugins registered and enabled.
    pub loaded: Vec<String>,
    /// Native plugins supplied by the host and registered.
    pub native_registered: Vec<String>,
    /// Plugins present in the configuration but disabled — never registered, so
    /// they cannot execute.
    pub skipped_disabled: Vec<String>,
}

impl PluginLoadReport {
    /// True when nothing was loaded and nothing was skipped.
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
            && self.native_registered.is_empty()
            && self.skipped_disabled.is_empty()
    }
}

/// Returns `true` when `s` is a lowercase-or-uppercase hex SHA-256 digest.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate the `plugins:` section before anything is loaded.
///
/// Fails on an empty id, an empty module path, a malformed fingerprint, a zero
/// memory limit, or a duplicate id (within `wasm`, within `native`, or across
/// both). Duplicated ids are rejected because a rule id identifies the plugin
/// that produced a decision and must be unambiguous.
pub fn validate_plugin_section(section: &PluginSection) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();

    for spec in &section.wasm {
        if spec.id.trim().is_empty() {
            return Err(AgentFenceError::Config(
                "wasm plugin entry has an empty id".to_string(),
            ));
        }
        if spec.module.trim().is_empty() {
            return Err(AgentFenceError::Config(format!(
                "wasm plugin '{}' has an empty module path",
                spec.id
            )));
        }
        if !spec.expected_fingerprint.is_empty() && !is_sha256_hex(&spec.expected_fingerprint) {
            return Err(AgentFenceError::Config(format!(
                "wasm plugin '{}' has a malformed expected_fingerprint \
                 (expected 64 hex characters)",
                spec.id
            )));
        }
        if spec.max_memory_mb == 0 {
            return Err(AgentFenceError::Config(format!(
                "wasm plugin '{}' has max_memory_mb: 0",
                spec.id
            )));
        }
        if !seen.insert(spec.id.as_str()) {
            return Err(AgentFenceError::Config(format!(
                "duplicate plugin id '{}'",
                spec.id
            )));
        }
    }

    for spec in &section.native {
        if spec.id.trim().is_empty() {
            return Err(AgentFenceError::Config(
                "native plugin entry has an empty id".to_string(),
            ));
        }
        if spec.timeout_ms == 0 {
            return Err(AgentFenceError::Config(format!(
                "native plugin '{}' has timeout_ms: 0",
                spec.id
            )));
        }
        if !seen.insert(spec.id.as_str()) {
            return Err(AgentFenceError::Config(format!(
                "duplicate plugin id '{}'",
                spec.id
            )));
        }
    }

    Ok(())
}

/// Build the plugin registry from the policy's `plugins:` section.
///
/// `native_plugins` are the native rules the embedding application chose to
/// trust. They are the **only** source of native code.
///
/// SECURITY: loading an enabled plugin that fails (missing module, fingerprint
/// mismatch, unknown native id) is a hard error. Starting enforcement with a
/// partially-loaded plugin set would silently drop the restrictions the
/// administrator configured, so the caller is told to fix the configuration.
pub fn build_registry(
    policy: &Policy,
    mut native_plugins: Vec<BoxedPlugin>,
) -> Result<(PluginRegistry, PluginLoadReport)> {
    let Some(section) = policy.plugins.as_ref() else {
        return Ok((PluginRegistry::new(), PluginLoadReport::default()));
    };

    validate_plugin_section(section)?;

    let mut registry = PluginRegistry::new();
    let mut report = PluginLoadReport::default();

    for spec in &section.wasm {
        if !spec.enabled {
            report.skipped_disabled.push(spec.id.clone());
            continue;
        }

        let max_memory_bytes = (spec.max_memory_mb as usize).saturating_mul(1024 * 1024);

        registry
            .register_wasm_plugin_with_limits(
                spec.id.clone(),
                spec.module.clone(),
                spec.expected_fingerprint.clone(),
                max_memory_bytes,
            )
            .map_err(AgentFenceError::Config)?;

        report.loaded.push(spec.id.clone());
    }

    for spec in &section.native {
        if !spec.enabled {
            report.skipped_disabled.push(spec.id.clone());
            continue;
        }

        // SECURITY: only a plugin the host supplied may be registered. The
        // policy file can never introduce native code.
        let position = native_plugins
            .iter()
            .position(|plugin| plugin.metadata().id == spec.id)
            .ok_or_else(|| {
                AgentFenceError::Config(format!(
                    "native plugin '{}' was not registered by the host application; \
                     agentfence.yaml cannot load native code",
                    spec.id
                ))
            })?;

        let plugin = native_plugins.remove(position);
        let config = PluginConfig {
            enabled: true,
            settings: std::collections::HashMap::new(),
            timeout_ms: spec.timeout_ms,
            max_memory_mb: spec.max_memory_mb,
            expected_fingerprint: String::new(),
        };

        registry
            .register(plugin, config)
            .map_err(AgentFenceError::Config)?;

        report.native_registered.push(spec.id.clone());
    }

    Ok((registry, report))
}

/// Build the PDP used by the enforcement gateways.
///
/// This is the shared initialization boundary: every gateway that evaluates
/// actions must call it, so configured plugins are consulted everywhere rather
/// than in one gateway only.
///
/// When no plugin is configured the returned PDP is exactly `Pdp::new(policy)`,
/// so the no-plugin behaviour is unchanged.
pub fn build_pdp(policy: Policy, native_plugins: Vec<BoxedPlugin>) -> Result<Pdp> {
    let (registry, report) = build_registry(&policy, native_plugins)?;

    let loaded_count = report.loaded.len() + report.native_registered.len();
    if loaded_count > 0 {
        info!(
            "Loaded {} policy plugin(s): {}",
            loaded_count,
            report
                .loaded
                .iter()
                .chain(report.native_registered.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !report.skipped_disabled.is_empty() {
        warn!(
            "Skipped {} disabled policy plugin(s): {}",
            report.skipped_disabled.len(),
            report.skipped_disabled.join(", ")
        );
    }

    if loaded_count == 0 {
        Ok(Pdp::new(policy))
    } else {
        Ok(Pdp::with_plugin_registry(policy, Arc::new(registry)))
    }
}
