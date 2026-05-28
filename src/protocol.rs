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

/// Request one chunk of a file by hash and chunk index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub hash: String,
    pub chunk_index: u64,
}

/// One chunk of a file. Carries total_size and chunk_size so the receiver
/// can set up their ContentRecord from the first response alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkResponse {
    pub hash: String,
    pub chunk_index: u64,
    pub total_size: u64,
    pub chunk_size: u64,
    pub data: Option<Vec<u8>>,
}
