//! Argument hashing.
//!
//! SECURITY: audit records store a hash of the action arguments, never the
//! arguments themselves. This is the single implementation shared by the
//! gateway (which hashes the `Action` it builds) and by callers that write
//! audit events, so the recorded hash cannot drift from the enforced one.

use sha2::{Digest, Sha256};

/// SHA-256 of `args`, hex-encoded.
pub fn hash_args(args: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(args.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_is_stable_and_hex() {
        let a = hash_args("git status");
        let b = hash_args("git status");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_differs_for_different_args() {
        assert_ne!(hash_args("git status"), hash_args("git push"));
    }

    #[test]
    fn test_hash_is_not_the_plaintext() {
        // The audit record must never contain the raw arguments.
        let h = hash_args("echo hunter2");
        assert!(!h.contains("hunter2"));
    }
}
