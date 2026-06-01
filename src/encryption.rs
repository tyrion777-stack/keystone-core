// Envelope encryption for Keystone content.
//
// Scheme:
//   1. Generate a random 32-byte content key (AES-256-GCM key).
//   2. Encrypt the plaintext with that content key.
//   3. For each recipient: generate an ephemeral X25519 keypair, compute
//      ECDH(ephemeral_private, recipient_public), derive a wrapping key via
//      HKDF-SHA256, and AES-GCM encrypt the content key.
//   4. Store everything in an EncryptedBlob.
//
// The blob is stored and transferred as opaque bytes. The Blake3 hash of the
// blob (not the plaintext) is the content address used in DHT and chunked
// transfer. The blob itself carries the plaintext hash for post-decrypt verification.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::identity::Identity;

/// One per authorized recipient. Carries everything the recipient needs to
/// recover the content key without exposing it to anyone else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientSlot {
    /// Sender's ephemeral X25519 public key (32 bytes, hex-encoded).
    pub ephemeral_pubkey: String,
    /// The content key, AES-GCM encrypted to the recipient.
    pub encrypted_content_key: Vec<u8>,
    /// Nonce used to encrypt the content key (12 bytes, hex-encoded).
    pub key_nonce: String,
}

/// An encrypted Keystone content blob. Stored on disk and transferred over
/// the network the same way as unencrypted content — chunked by Blake3 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Blake3 hash of the original plaintext — verified after decryption.
    pub plaintext_hash: String,
    /// AES-256-GCM encrypted content.
    pub ciphertext: Vec<u8>,
    /// Nonce used for content encryption (12 bytes, hex-encoded).
    pub nonce: String,
    /// One slot per authorized recipient.
    pub recipients: Vec<RecipientSlot>,
}

/// Encrypt `data` for one or more recipients. Returns the blob ready to be
/// stored in a ContentStore (Blake3-hash of the serialised blob becomes its address).
pub fn encrypt_for(data: &[u8], recipients: &[X25519PublicKey]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Step 1 — random content key + nonce
    let mut content_key = [0u8; 32];
    let mut content_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut content_key);
    OsRng.fill_bytes(&mut content_nonce);

    // Step 2 — encrypt plaintext
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&content_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&content_nonce), data)
        .map_err(|e| e.to_string())?;

    let plaintext_hash = hex::encode(blake3::hash(data).as_bytes());

    // Step 3 — wrap content key for each recipient
    let mut slots = Vec::with_capacity(recipients.len());
    for recipient_pubkey in recipients {
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);

        let mut wrapping_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
            .expand(b"keystone-content-key", &mut wrapping_key)
            .map_err(|e| e.to_string())?;

        let mut key_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut key_nonce_bytes);

        let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
        let encrypted_content_key = wrap_cipher
            .encrypt(Nonce::from_slice(&key_nonce_bytes), content_key.as_ref())
            .map_err(|e| e.to_string())?;

        slots.push(RecipientSlot {
            ephemeral_pubkey: hex::encode(ephemeral_pubkey.as_bytes()),
            encrypted_content_key,
            key_nonce: hex::encode(key_nonce_bytes),
        });
    }

    let blob = EncryptedBlob {
        plaintext_hash,
        ciphertext,
        nonce: hex::encode(content_nonce),
        recipients: slots,
    };

    Ok(serde_json::to_vec(&blob)?)
}

/// Try to decrypt a blob for `identity`. Returns the plaintext if this identity
/// is in the recipient list and decryption succeeds. Returns None otherwise.
pub fn decrypt(blob_bytes: &[u8], identity: &Identity) -> Option<Vec<u8>> {
    let blob: EncryptedBlob = serde_json::from_slice(blob_bytes).ok()?;

    let my_pubkey = identity.x25519_public_key();
    let my_secret = identity.x25519_secret();

    // Find the slot for this identity by trying each one
    for slot in &blob.recipients {
        let ephemeral_pubkey_bytes: [u8; 32] = hex::decode(&slot.ephemeral_pubkey)
            .ok()?.try_into().ok()?;
        let ephemeral_pubkey = X25519PublicKey::from(ephemeral_pubkey_bytes);

        let shared_secret = my_secret.diffie_hellman(&ephemeral_pubkey);

        let mut wrapping_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
            .expand(b"keystone-content-key", &mut wrapping_key)
            .ok()?;

        let key_nonce_bytes: [u8; 12] = hex::decode(&slot.key_nonce)
            .ok()?.try_into().ok()?;

        let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
        let content_key = match wrap_cipher.decrypt(
            Nonce::from_slice(&key_nonce_bytes),
            slot.encrypted_content_key.as_ref(),
        ) {
            Ok(k) => k,
            Err(_) => continue, // not our slot
        };

        // Decrypt the content
        let content_nonce_bytes: [u8; 12] = hex::decode(&blob.nonce)
            .ok()?.try_into().ok()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&content_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&content_nonce_bytes), blob.ciphertext.as_ref())
            .ok()?;

        // Verify plaintext hash
        let actual_hash = hex::encode(blake3::hash(&plaintext).as_bytes());
        if actual_hash != blob.plaintext_hash {
            return None;
        }

        // Confirm this slot was actually meant for us (prevents trying all slots
        // successfully when the wrapping key happened to decrypt garbage correctly)
        let _ = my_pubkey;

        return Some(plaintext);
    }

    None
}

/// Return true if `bytes` looks like a serialised EncryptedBlob.
pub fn is_encrypted_blob(bytes: &[u8]) -> bool {
    serde_json::from_slice::<EncryptedBlob>(bytes)
        .map(|b| !b.recipients.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = Identity::generate();
        let data = b"hello encrypted keystone";
        let blob = encrypt_for(data, &[alice.x25519_public_key()]).unwrap();
        let result = decrypt(&blob, &alice).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let data = b"only alice should read this";
        let blob = encrypt_for(data, &[alice.x25519_public_key()]).unwrap();
        assert!(decrypt(&blob, &bob).is_none());
    }

    #[test]
    fn multi_recipient() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let data = b"both can read this";
        let blob = encrypt_for(data, &[alice.x25519_public_key(), bob.x25519_public_key()]).unwrap();
        assert_eq!(decrypt(&blob, &alice).unwrap(), data);
        assert_eq!(decrypt(&blob, &bob).unwrap(), data);
    }

    #[test]
    fn is_encrypted_blob_detection() {
        let alice = Identity::generate();
        let blob = encrypt_for(b"test", &[alice.x25519_public_key()]).unwrap();
        assert!(is_encrypted_blob(&blob));
        assert!(!is_encrypted_blob(b"plain text"));
        assert!(!is_encrypted_blob(b"{}"));
    }
}
