//! Hash chain for tamper-evident audit logs.
//!
//! Each event contains the hash of the previous event, forming a chain.
//! Verification detects tampering by recomputing hashes.

use sha2::{Digest, Sha256};

/// Compute a hash chain verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    Invalid { event_id: String, reason: String },
    Incomplete { expected: usize, found: usize },
}

/// Verify a chain of events.
///
/// Each event's `previous_hash` must match the previous event's `current_hash`.
/// Each event's `current_hash` must match its computed hash.
pub fn verify_chain(events: &[super::event::AuditEvent]) -> VerificationResult {
    if events.is_empty() {
        return VerificationResult::Incomplete {
            expected: 1,
            found: 0,
        };
    }

    for (i, event) in events.iter().enumerate() {
        // Verify event's own hash
        if !event.verify() {
            return VerificationResult::Invalid {
                event_id: event.event_id.clone(),
                reason: format!("Event {} has invalid hash", i),
            };
        }

        // Verify chain link (except for first event)
        if i > 0 {
            let prev = &events[i - 1];
            if event.previous_hash != prev.current_hash {
                return VerificationResult::Invalid {
                    event_id: event.event_id.clone(),
                    reason: format!(
                        "Chain broken at event {}: expected previous_hash {}, got {}",
                        i, prev.current_hash, event.previous_hash
                    ),
                };
            }
        }
    }

    VerificationResult::Valid
}

/// Compute the next hash in the chain.
pub fn compute_next_hash(previous_hash: &str, event_data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(event_data.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;
    use agentfence_core::types::*;

    fn create_event(prev_hash: &str) -> AuditEvent {
        AuditEvent::new(
            SessionId::new(),
            AgentId::new("test"),
            None,
            ActionId::new(),
            None,
            "shell",
            "shell",
            "git status",
            "hash",
            Decision::Allow,
            RiskLevel::Low,
            "test.rule",
            "v1",
            "policy_hash",
            prev_hash,
        )
    }

    #[test]
    fn test_verify_empty_chain() {
        let result = verify_chain(&[]);
        assert!(matches!(result, VerificationResult::Incomplete { .. }));
    }

    #[test]
    fn test_verify_valid_chain() {
        let event1 = create_event("");
        let event2 = create_event(&event1.current_hash);
        let events = vec![event1, event2];
        let result = verify_chain(&events);
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn test_verify_broken_chain() {
        let event1 = create_event("");
        let mut event2 = create_event(&event1.current_hash);
        event2.current_hash = "tampered".to_string();
        let events = vec![event1, event2];
        let result = verify_chain(&events);
        assert!(matches!(result, VerificationResult::Invalid { .. }));
    }
}
