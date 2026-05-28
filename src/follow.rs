use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::KeystoneError,
    identity::{Identity, SignedMessage},
};

/// The semantic payload inside a follow record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowPayload {
    pub follower: String, // public key hex of who is following
    pub followee: String, // public key hex of who is being followed
    pub timestamp: u64,   // unix seconds
}

/// A follow record is just a signed message whose content is a FollowPayload.
/// Reuses Week 1's primitive — no new cryptography needed.
pub type FollowRecord = SignedMessage;

/// Create and sign a follow relationship.
pub fn create_follow(identity: &Identity, followee_pubkey: &str) -> FollowRecord {
    let payload = FollowPayload {
        follower: identity.public_key_hex(),
        followee: followee_pubkey.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    identity.sign(&serde_json::to_string(&payload).unwrap())
}

/// The payload inside a revocation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPayload {
    pub revoked_key: String, // public key hex being revoked
    pub reason: String,
    pub timestamp: u64,
}

/// A revocation record is a SignedMessage whose content is a RevocationPayload.
/// The key holder signs their own key out of existence — proves they authorized it.
pub type RevocationRecord = SignedMessage;

/// Sign a revocation for your own key.
pub fn create_revocation(identity: &Identity, reason: &str) -> RevocationRecord {
    let payload = RevocationPayload {
        revoked_key: identity.public_key_hex(),
        reason: reason.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    identity.sign(&serde_json::to_string(&payload).unwrap())
}

/// DHT key format for revocation records.
pub fn revocation_dht_key(pubkey_hex: &str) -> String {
    format!("revoked:{pubkey_hex}")
}

/// In-memory store for follow records. Week 4 will persist this to disk.
#[derive(Default)]
pub struct FollowStore {
    records: Vec<FollowRecord>,
}

impl FollowStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a follow record — verifies the signature before accepting it.
    pub fn add(&mut self, record: FollowRecord) -> Result<(), KeystoneError> {
        record.verify()?;
        self.records.push(record);
        Ok(())
    }

    pub fn all(&self) -> &[FollowRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_signature_verifies() {
        let identity = Identity::generate();
        let record = create_revocation(&identity, "test revocation");
        assert!(record.verify().is_ok());
    }

    #[test]
    fn revocation_payload_contains_correct_key() {
        let identity = Identity::generate();
        let record = create_revocation(&identity, "compromised");
        let payload: RevocationPayload = serde_json::from_str(&record.content).unwrap();
        assert_eq!(payload.revoked_key, identity.public_key_hex());
        assert_eq!(payload.reason, "compromised");
    }

    #[test]
    fn tampered_revocation_fails_verification() {
        let identity = Identity::generate();
        let mut record = create_revocation(&identity, "legit");
        // Swap in a different key's signature
        let other = Identity::generate();
        record.author = other.public_key_hex();
        assert!(record.verify().is_err());
    }

    #[test]
    fn revocation_dht_key_has_correct_format() {
        let key = revocation_dht_key("abc123");
        assert_eq!(key, "revoked:abc123");
    }
}
