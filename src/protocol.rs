use serde::{Deserialize, Serialize};

use crate::identity::SignedMessage;

/// Sent by a peer that wants another peer's follow list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowRequest;

/// The response — a list of signed follow records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowResponse {
    pub records: Vec<SignedMessage>,
}

/// Sent by a peer that wants a specific file by its Blake3 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentRequest {
    pub hash: String,
}

/// The response — raw file bytes, or None if the peer doesn't have it.
/// Uses CBOR (binary) encoding so large files don't bloat to JSON arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentResponse {
    pub data: Option<Vec<u8>>,
}
