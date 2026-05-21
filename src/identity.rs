use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;

/// A Keystone identity. The signing_key is the private half — never share it.
/// The public key (verifying_key) is your permanent, portable identity on the network.
pub struct Identity {
    signing_key: SigningKey,
}

/// A message with a cryptographic proof of authorship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// Hex-encoded public key of the author.
    pub author: String,
    /// The raw content that was signed.
    pub content: String,
    /// Blake3 hash of the content — tamper-proof content address.
    pub content_hash: String,
    /// Hex-encoded Ed25519 signature over the content hash.
    pub signature: String,
}

impl Identity {
    /// Generate a brand new keypair using OS-level randomness.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Restore an identity from a previously exported private key (hex string).
    pub fn from_private_key_hex(hex_str: &str) -> Result<Self, KeystoneError> {
        let bytes = hex::decode(hex_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeystoneError::InvalidPrivateKey("must be 32 bytes".into()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    /// The public key as a hex string — this is your Keystone identity.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Export the private key as hex for secure backup.
    /// Treat this like a password — whoever has it controls the identity.
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Sign a string message. Hashes the content with Blake3 first,
    /// then signs the hash. The hash is the content's permanent address.
    pub fn sign(&self, content: &str) -> SignedMessage {
        let content_hash = blake3::hash(content.as_bytes());
        let hash_hex = content_hash.to_hex().to_string();

        let signature: Signature = self.signing_key.sign(hash_hex.as_bytes());

        SignedMessage {
            author: self.public_key_hex(),
            content: content.to_string(),
            content_hash: hash_hex,
            signature: hex::encode(signature.to_bytes()),
        }
    }
}

impl SignedMessage {
    /// Verify this message's signature against its claimed author.
    /// Returns Ok(()) if authentic, Err if tampered or forged.
    pub fn verify(&self) -> Result<(), KeystoneError> {
        // Decode the author's public key
        let key_bytes = hex::decode(&self.author)?;
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| KeystoneError::InvalidPublicKey("must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| KeystoneError::InvalidPublicKey(e.to_string()))?;

        // Re-derive the content hash and confirm it matches the stored hash
        let recomputed_hash = blake3::hash(self.content.as_bytes());
        let recomputed_hex = recomputed_hash.to_hex().to_string();
        if recomputed_hex != self.content_hash {
            return Err(KeystoneError::InvalidSignature);
        }

        // Decode and verify the signature
        let sig_bytes = hex::decode(&self.signature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| KeystoneError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(self.content_hash.as_bytes(), &signature)
            .map_err(|_| KeystoneError::InvalidSignature)
    }

    /// Serialize to JSON — this is what you'd send over the wire.
    pub fn to_json(&self) -> Result<String, KeystoneError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON — what a receiving node does.
    pub fn from_json(json: &str) -> Result<Self, KeystoneError> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_has_keys() {
        let id = Identity::generate();
        assert_eq!(id.public_key_hex().len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(id.private_key_hex().len(), 64);
    }

    #[test]
    fn sign_and_verify_succeeds() {
        let id = Identity::generate();
        let msg = id.sign("hello keystone");
        assert!(msg.verify().is_ok());
    }

    #[test]
    fn tampered_content_fails_verification() {
        let id = Identity::generate();
        let mut msg = id.sign("hello keystone");
        msg.content = "hello TAMPERED".to_string();
        assert!(msg.verify().is_err());
    }

    #[test]
    fn wrong_signature_fails_verification() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let mut msg = id1.sign("hello keystone");
        // Swap the signature with one from a different identity
        let other = id2.sign("hello keystone");
        msg.signature = other.signature;
        assert!(msg.verify().is_err());
    }

    #[test]
    fn identity_survives_export_import() {
        let id = Identity::generate();
        let pubkey = id.public_key_hex();
        let privkey = id.private_key_hex();

        let restored = Identity::from_private_key_hex(&privkey).unwrap();
        assert_eq!(restored.public_key_hex(), pubkey);

        // Messages signed by restored key verify correctly
        let msg = restored.sign("restored identity works");
        assert!(msg.verify().is_ok());
    }

    #[test]
    fn signed_message_roundtrips_json() {
        let id = Identity::generate();
        let msg = id.sign("content that will travel over the wire");
        let json = msg.to_json().unwrap();
        let restored = SignedMessage::from_json(&json).unwrap();
        assert!(restored.verify().is_ok());
    }
}
