use std::path::{Path, PathBuf};

use crate::error::KeystoneError;

/// Stores files on disk addressed by their Blake3 hash.
/// The hash is the file's permanent address — same bytes always produce the same hash.
pub struct ContentStore {
    dir: PathBuf,
}

impl ContentStore {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, KeystoneError> {
        std::fs::create_dir_all(&dir)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        Ok(Self { dir: dir.as_ref().to_path_buf() })
    }

    /// Hash the bytes, save to disk, return the hex hash (the file's address).
    /// If we already have the file, skip the write — content is immutable.
    pub fn store(&self, bytes: &[u8]) -> Result<String, KeystoneError> {
        let hash = hex::encode(blake3::hash(bytes).as_bytes());
        let path = self.dir.join(&hash);
        if !path.exists() {
            std::fs::write(&path, bytes)
                .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        }
        Ok(hash)
    }

    /// Retrieve file bytes by hash. Returns None if we don't have it.
    pub fn get(&self, hash: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(hash)).ok()
    }

    pub fn has(&self, hash: &str) -> bool {
        self.dir.join(hash).exists()
    }
}

/// DHT key format for content records: content:<blake3_hex>
pub fn content_dht_key(hash: &str) -> String {
    format!("content:{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn store_and_retrieve() {
        let dir = temp_dir().join("keystone_content_test");
        let store = ContentStore::new(&dir).unwrap();
        let data = b"hello keystone";
        let hash = store.store(data).unwrap();
        assert_eq!(store.get(&hash).unwrap(), data);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_content_same_hash() {
        let dir = temp_dir().join("keystone_content_test2");
        let store = ContentStore::new(&dir).unwrap();
        let h1 = store.store(b"same data").unwrap();
        let h2 = store.store(b"same data").unwrap();
        assert_eq!(h1, h2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn different_content_different_hash() {
        let dir = temp_dir().join("keystone_content_test3");
        let store = ContentStore::new(&dir).unwrap();
        let h1 = store.store(b"file a").unwrap();
        let h2 = store.store(b"file b").unwrap();
        assert_ne!(h1, h2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_hash_returns_none() {
        let dir = temp_dir().join("keystone_content_test4");
        let store = ContentStore::new(&dir).unwrap();
        assert!(store.get("doesnotexist").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn content_dht_key_format() {
        assert_eq!(content_dht_key("abc123"), "content:abc123");
    }
}
