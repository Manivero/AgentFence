//! Best-effort credential redaction for text that is displayed or persisted.
//!
//! SECURITY: redaction is **defence in depth, not an authorization control**.
//! It masks high-confidence credential *shapes*; it cannot recognise a secret
//! that does not match a known pattern, and it does not make the surrounding
//! text safe to publish. The policy decision is always taken over the original
//! action and is never influenced by redaction.
//!
//! The matcher is deliberately conservative: it only masks strings whose shape
//! is unambiguous (a recognised prefix followed by the exact character class
//! and length that the real credential format uses). A false negative is
//! accepted; a false positive would make an approval prompt misleading, so
//! patterns are kept narrow.

use crate::detector::SecretCategory;

/// Result of redacting a piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    /// The text with every matched credential replaced by `[REDACTED]`.
    pub text: String,
    /// Categories that were masked, sorted and deduplicated.
    pub masked: Vec<SecretCategory>,
}

impl Redaction {
    pub fn was_masked(&self) -> bool {
        !self.masked.is_empty()
    }
}

const PLACEHOLDER: &str = "[REDACTED]";

/// A masked byte range.
struct Span {
    start: usize,
    end: usize,
    category: SecretCategory,
}

/// Redact known credential shapes from `input`.
pub fn redact(input: &str) -> Redaction {
    let mut spans: Vec<Span> = Vec::new();

    // Ordered: more specific patterns first so a private-key block is not also
    // partially matched as a bearer token.
    mask_private_key_block(input, &mut spans);
    mask_jwt(input, &mut spans);
    mask_bearer(input, &mut spans);
    mask_prefixed(input, &mut spans);

    spans.sort_by_key(|s| (s.start, s.end));
    // Drop overlapping spans, keeping the longest (the earlier sort put the
    // earliest start first; on a tie the shorter end comes first, so keep the
    // later, longer one).
    let mut kept: Vec<Span> = Vec::new();
    for span in spans {
        match kept.last_mut() {
            Some(last) if span.start < last.end => {
                if span.end > last.end {
                    *last = span;
                }
            }
            _ => kept.push(span),
        }
    }

    let mut masked: Vec<SecretCategory> = kept.iter().map(|s| s.category.clone()).collect();
    masked.sort_by_key(|c| c.to_string());
    masked.dedup();

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for span in &kept {
        out.push_str(&input[cursor..span.start]);
        out.push_str(PLACEHOLDER);
        cursor = span.end;
    }
    out.push_str(&input[cursor..]);

    Redaction { text: out, masked }
}

/// `-----BEGIN ... PRIVATE KEY-----` through the matching `END` line.
fn mask_private_key_block(input: &str, spans: &mut Vec<Span>) {
    let mut rest = input;
    while let Some(i) = rest.find("-----BEGIN ") {
        let abs = input.len() - rest.len() + i;
        let after = &rest[i..];
        if let Some(end_rel) = after.find("PRIVATE KEY-----") {
            let end_marker_end = abs + end_rel + "PRIVATE KEY-----".len();
            if let Some(stop_rel) = after.find("-----END ") {
                if let Some(stop_end_rel) = after[stop_rel..].find("-----") {
                    let block_end = abs + stop_rel + stop_end_rel + 5;
                    spans.push(Span {
                        start: abs,
                        end: block_end,
                        category: SecretCategory::PrivateKey,
                    });
                    rest = &after[stop_rel + stop_end_rel + 5..];
                    continue;
                }
            }
            let _ = end_marker_end;
        }
        rest = &rest[i + 1..];
    }
}

/// `eyJ<_header>.eyJ<payload>.<signature>` JSON Web Token.
fn mask_jwt(input: &str, spans: &mut Vec<Span>) {
    for (i, _) in input.match_indices("eyJ") {
        let tail = &input[i..];
        let mut parts = tail.split('.');
        let h = parts.next().unwrap_or("");
        let p = parts.next().unwrap_or("");
        let s = parts.next().unwrap_or("");
        if h.len() >= 4
            && h.starts_with("eyJ")
            && p.starts_with("eyJ")
            && !s.is_empty()
            && s.len() >= 8
            && parts.next().is_none()
            && tail
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            spans.push(Span {
                start: i,
                end: i + h.len() + 1 + p.len() + 1 + s.len(),
                category: SecretCategory::Jwt,
            });
        }
    }
}

/// `Bearer <token>` in a header or argument.
fn mask_bearer(input: &str, spans: &mut Vec<Span>) {
    let lower = input.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("bearer ") {
        let start = search_from + rel + "bearer ".len();
        let bytes = &input.as_bytes()[start..];
        let mut end = 0;
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '=' {
                end += 1;
            } else {
                break;
            }
        }
        if end >= 16 {
            spans.push(Span {
                start,
                end: start + end,
                category: SecretCategory::BearerToken,
            });
        }
        search_from = start + end;
    }
}

/// Recognised fixed prefixes followed by the exact character class and length
/// that the real credential format uses.
fn mask_prefixed(input: &str, spans: &mut Vec<Span>) {
    const PATTERNS: &[(&str, usize, usize, SecretCategory, &str)] = &[
        // (prefix, min total, max total, category, allowed chars)
        ("ghp_", 40, 40, SecretCategory::GitHubToken, "alnum"),
        ("gho_", 40, 40, SecretCategory::GitHubToken, "alnum"),
        ("ghu_", 40, 40, SecretCategory::GitHubToken, "alnum"),
        ("ghs_", 40, 40, SecretCategory::GitHubToken, "alnum"),
        ("ghr_", 40, 40, SecretCategory::GitHubToken, "alnum"),
        ("npm_", 40, 40, SecretCategory::AccessToken, "alnum"),
        ("AKIA", 20, 20, SecretCategory::AwsAccessKey, "upper_alnum"),
        ("sk_live_", 40, 200, SecretCategory::AccessToken, "alnum"),
        ("rk_live_", 40, 200, SecretCategory::AccessToken, "alnum"),
        ("xoxb-", 40, 200, SecretCategory::AccessToken, "alnum_dash"),
        ("xoxp-", 40, 200, SecretCategory::AccessToken, "alnum_dash"),
        ("AIza", 39, 39, SecretCategory::ApiKey, "alnum_dash"),
    ];

    for (prefix, min, max, category, charset) in PATTERNS {
        let mut search_from = 0;
        while let Some(rel) = input[search_from..].find(prefix) {
            let start = search_from + rel;
            let token_start = start + prefix.len();
            let bytes = &input.as_bytes()[token_start..];
            let mut len = 0;
            while len < bytes.len() {
                let c = bytes[len] as char;
                let ok = match *charset {
                    "alnum" => c.is_ascii_alphanumeric(),
                    "upper_alnum" => c.is_ascii_uppercase() || c.is_ascii_digit(),
                    "alnum_dash" => c.is_ascii_alphanumeric() || c == '_' || c == '-',
                    _ => false,
                };
                if ok {
                    len += 1;
                } else {
                    break;
                }
            }
            let total = prefix.len() + len;
            if total >= *min && total <= *max && len > 0 {
                spans.push(Span {
                    start,
                    end: token_start + len,
                    category: category.clone(),
                });
            }
            search_from = token_start + len.max(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(s: &str) -> String {
        redact(s).text
    }

    #[test]
    fn github_token_is_masked() {
        let t =
            "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789\" https://x";
        let out = masked(t);
        assert!(
            !out.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            "{}",
            out
        );
        assert!(out.contains("[REDACTED]"), "{}", out);
        // The decision-relevant parts survive.
        assert!(out.contains("curl"), "{}", out);
        assert!(out.contains("https://x"), "{}", out);
    }

    #[test]
    fn aws_access_key_is_masked() {
        let t = "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE";
        assert!(!masked(t).contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn bearer_header_is_masked() {
        let t = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop";
        let out = masked(t);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{}", out);
    }

    #[test]
    fn private_key_block_is_masked_whole() {
        let t = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----";
        let out = masked(t);
        assert!(!out.contains("MIIEowIBAAKCAQEA1234567890"), "{}", out);
        assert_eq!(out.matches("[REDACTED]").count(), 1, "{}", out);
    }

    #[test]
    fn ordinary_commands_are_untouched() {
        let t = "git push --force origin main";
        assert_eq!(masked(t), t);
        assert!(!redact(t).was_masked());
    }

    #[test]
    fn paths_and_flags_are_untouched() {
        let t = "cargo build --release --target wasm32-unknown-unknown";
        assert_eq!(masked(t), t);
    }

    #[test]
    fn short_ambiguous_strings_are_not_masked() {
        // Too short to be a real credential: masking these would make approval
        // prompts misleading.
        assert_eq!(masked("echo ghp_abc"), "echo ghp_abc");
        assert_eq!(masked("AKIA123"), "AKIA123");
    }

    #[test]
    fn redacted_output_never_contains_the_secret() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let out = redact(&format!("cmd --token {}", secret));
        assert!(!out.text.contains(secret));
        assert_eq!(out.masked, vec![SecretCategory::GitHubToken]);
    }

    #[test]
    fn unicode_is_preserved() {
        let t = "echo \"привет мир\" ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let out = masked(t);
        assert!(out.contains("привет мир"), "{}", out);
        assert!(!out.contains("ghp_"), "{}", out);
    }
}
