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
