//! Trusted execution context for shell actions.
//!
//! SECURITY — this module is the enforcement point for metadata provenance.
//!
//! `ShellCommand` is **untrusted input**: it is parsed from a raw command string
//! that an agent controls. It must never carry location metadata.
//!
//! [`TrustedShellContext`] is the **only** way to supply `host` / `client_ip`
//! to policy evaluation for a shell action. Its fields are private and its only
//! constructor requires a [`TrustedContextToken`], so a caller that cannot
//! obtain a token cannot make a location condition pass.
//!
//! The token's constructor is private to this module, so the token cannot be
//! forged directly. It is minted by
//! [`crate::gateway::ShellGateway::issue_trusted_context_token`], which is `pub`.
//!
//! ## What the boundary actually guarantees
//!
//! Stated precisely, because the visibility rules alone do not say it:
//!
//! - **Untrusted data cannot assert a location.** A command string never
//!   reaches `evaluate_with_context` with attacker-selected metadata, and
//!   `cmd.raw` is never parsed for a location. This is the property the API
//!   exists to provide, and it holds regardless of who holds a gateway.
//! - **No untrusted component is handed a gateway.** `PluginContext` exposes no
//!   gateway and no PDP, so a native plugin cannot mint a token. The MCP and
//!   Network proxies hold a `Pdp` directly and never construct a
//!   `ShellGateway`.
//! - **This is not a sandbox for in-process code.** `ShellGateway::new` and
//!   `Pdp::new` are public, so any code running in the process can construct a
//!   gateway and mint tokens. In cooperative mode such code can equally bypass
//!   AgentFence entirely (see `SECURITY.md`, Cooperative Mode). The token stops
//!   untrusted *data* from asserting a location; it does not stop untrusted
//!   *code* from acting.

/// Capability token proving the holder is the trusted integration layer.
///
/// SECURITY: the constructor is private to this module, so the token cannot be
/// forged by other crates. It is a capability marker, not a cryptographic
/// proof: its strength comes from the fact that only holders of a
/// `ShellGateway` can mint one, and no untrusted component is given a gateway.
#[derive(Debug, Clone, Copy)]
pub struct TrustedContextToken(());

impl TrustedContextToken {
    /// Create a token. Private to this module.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Verified execution context for a shell action.
///
/// SECURITY: fields are private and there is no public `Default`, so a caller
/// without a [`TrustedContextToken`] can never produce a context that carries a
/// `host` or `client_ip`. An empty context (no location data) is only
/// constructible inside this crate, via [`TrustedShellContext::empty`], and is
/// what the untrusted evaluation path uses — location conditions then fail
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedShellContext {
    host: Option<String>,
    client_ip: Option<String>,
}

impl TrustedShellContext {
    /// Build a verified context from values the trusted integration layer has
    /// checked.
    ///
    /// SECURITY: `_token` is the capability proof. Consuming it is what makes
    /// the construction auditable: there is no other way to reach this
    /// constructor with a non-empty value.
    pub fn new(
        _token: TrustedContextToken,
        host: Option<String>,
        client_ip: Option<String>,
    ) -> Self {
        Self { host, client_ip }
    }

    /// The empty context: no verified location metadata.
    ///
    /// Used by the untrusted evaluation path. Produces no `host`/`client_ip`,
    /// so any location condition that requires them fails closed.
    pub(crate) fn empty() -> Self {
        Self {
            host: None,
            client_ip: None,
        }
    }

    /// The verified host, if one was supplied.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The verified client IP, if one was supplied.
    pub fn client_ip(&self) -> Option<&str> {
        self.client_ip.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_context_has_no_location() {
        let ctx = TrustedShellContext::empty();
        assert_eq!(ctx.host(), None);
        assert_eq!(ctx.client_ip(), None);
    }

    #[test]
    fn test_token_gated_constructor_carries_values() {
        let token = TrustedContextToken::new();
        let ctx = TrustedShellContext::new(
            token,
            Some("build-server-01".to_string()),
            Some("10.0.0.5".to_string()),
        );
        assert_eq!(ctx.host(), Some("build-server-01"));
        assert_eq!(ctx.client_ip(), Some("10.0.0.5"));
    }

    #[test]
    fn test_token_gated_constructor_accepts_missing_values() {
        let token = TrustedContextToken::new();
        let ctx = TrustedShellContext::new(token, None, None);
        assert_eq!(ctx.host(), None);
        assert_eq!(ctx.client_ip(), None);
    }
}
