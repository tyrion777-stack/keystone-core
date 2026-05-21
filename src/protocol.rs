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
