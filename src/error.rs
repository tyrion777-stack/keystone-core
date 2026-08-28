use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeystoneError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Key storage error: {0}")]
    KeyStorage(String),

    #[error("Invalid content hash: {0}")]
    InvalidHash(String),

    #[error("Invalid chunk parameter: {0}")]
    InvalidChunk(String),
}
