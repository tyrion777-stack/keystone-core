use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;

/// Chunk size is decided once from the file size and stored in the ContentRecord.
/// Larger files get larger chunks to keep the request count manageable.
pub fn calc_chunk_size(file_size: u64) -> u64 {
    if file_size > 100 * MB      { 4 * MB }
    else if file_size > 25 * MB  { 2 * MB }
    else                         { 512 * KB }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkState {
    Pending,
    Complete,
}

/// Tracks the fetch state for a file being downloaded in chunks.
/// Persisted to disk as a `.meta` sidecar so transfers survive restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentRecord {
    pub hash: String,
    pub size: u64,
    pub chunk_size: u64,
    pub chunks: Vec<ChunkState>,
}

impl ContentRecord {
    pub fn pending_chunks(&self) -> Vec<u64> {
        self.chunks.iter().enumerate()
            .filter(|(_, s)| matches!(s, ChunkState::Pending))
            .map(|(i, _)| i as u64)
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|s| matches!(s, ChunkState::Complete))
    }
}

/// Require exactly 64 lowercase hex characters. Rejects path traversal,
/// absolute paths, empty strings, wrong-case hex, and wrong-length inputs.
pub fn validate_hash(hash: &str) -> Result<(), KeystoneError> {
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(KeystoneError::InvalidHash(hash.to_string()));
    }
    Ok(())
}

/// Stores files on disk addressed by their Blake3 hash.
/// Complete files have no sidecar. In-progress files have a `.meta` sidecar
/// tracking which chunks are done — that's the resume state.
pub struct ContentStore {
    dir: PathBuf,
}

impl ContentStore {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, KeystoneError> {
        std::fs::create_dir_all(&dir)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        Ok(Self { dir: dir.as_ref().to_path_buf() })
    }

    /// Hash bytes, save to disk, return the hex hash. Idempotent — skips write
    /// if we already have it.
    pub fn store(&self, bytes: &[u8]) -> Result<String, KeystoneError> {
        let hash = hex::encode(blake3::hash(bytes).as_bytes());
        let path = self.dir.join(&hash);
        if !path.exists() {
            std::fs::write(&path, bytes)
                .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        }
        Ok(hash)
    }

    /// Retrieve complete file bytes by hash.
    pub fn get(&self, hash: &str) -> Option<Vec<u8>> {
        validate_hash(hash).ok()?;
        std::fs::read(self.dir.join(hash)).ok()
    }

    pub fn has(&self, hash: &str) -> bool {
        validate_hash(hash).is_ok() && self.dir.join(hash).exists()
    }

    pub fn file_size(&self, hash: &str) -> Option<u64> {
        validate_hash(hash).ok()?;
        std::fs::metadata(self.dir.join(hash)).ok().map(|m| m.len())
    }

    // --- Serving chunks to remote peers ---

    /// Read a specific chunk from a complete local file for sending to a peer.
    /// Returns (chunk_bytes, total_size, chunk_size) so the response carries
    /// everything the receiver needs to set up their ContentRecord.
    pub fn serve_chunk(&self, hash: &str, chunk_index: u64) -> Option<(Vec<u8>, u64, u64)> {
        validate_hash(hash).ok()?;
        let total_size = self.file_size(hash)?;
        let chunk_size = calc_chunk_size(total_size);
        let offset = chunk_index * chunk_size;
        if offset >= total_size { return None; }

        let mut file = std::fs::File::open(self.dir.join(hash)).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;

        let remaining = total_size - offset;
        let to_read = remaining.min(chunk_size) as usize;
        let mut buf = vec![0u8; to_read];
        file.read_exact(&mut buf).ok()?;

        Some((buf, total_size, chunk_size))
    }

    // --- Receiving chunks from remote peers ---

    /// Start a chunked fetch. Pre-allocates the full file on disk immediately
    /// so chunks can be written at their seek positions in any order.
    /// Resumes an existing in-progress fetch if a .meta sidecar already exists.
    pub fn begin_fetch(&self, hash: &str, total_size: u64, chunk_size: u64) -> Result<ContentRecord, KeystoneError> {
        validate_hash(hash)?;
        // Resume if we have an existing partial fetch
        if let Some(record) = self.load_meta(hash) {
            return Ok(record);
        }

        let num_chunks = (total_size + chunk_size - 1) / chunk_size;
        let record = ContentRecord {
            hash: hash.to_string(),
            size: total_size,
            chunk_size,
            chunks: vec![ChunkState::Pending; num_chunks as usize],
        };

        // Pre-allocate the full file before writing any chunk
        let file = std::fs::File::create(self.dir.join(hash))
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        file.set_len(total_size)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;

        self.save_meta(&record)?;
        Ok(record)
    }

    /// Write one chunk at its correct offset and mark it Complete in the record.
    pub fn write_chunk(&self, record: &mut ContentRecord, chunk_index: u64, data: &[u8]) -> Result<(), KeystoneError> {
        let offset = chunk_index * record.chunk_size;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.dir.join(&record.hash))
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        file.write_all(data)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;

        record.chunks[chunk_index as usize] = ChunkState::Complete;
        self.save_meta(record)?;
        Ok(())
    }

    /// Blake3 the assembled file and check it matches the requested hash.
    /// This is the integrity check — if it fails, the file must be discarded.
    pub fn verify_complete(&self, record: &ContentRecord) -> Result<bool, KeystoneError> {
        let data = std::fs::read(self.dir.join(&record.hash))
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        let actual = hex::encode(blake3::hash(&data).as_bytes());
        Ok(actual == record.hash)
    }

    /// Remove the .meta sidecar once a fetch is complete and verified.
    /// After this, the file looks identical to one stored via publish().
    pub fn finish_fetch(&self, record: &ContentRecord) {
        let _ = std::fs::remove_file(self.dir.join(format!("{}.meta", record.hash)));
    }

    pub fn load_meta(&self, hash: &str) -> Option<ContentRecord> {
        validate_hash(hash).ok()?;
        let data = std::fs::read(self.dir.join(format!("{hash}.meta"))).ok()?;
        serde_json::from_slice(&data).ok()
    }

    fn save_meta(&self, record: &ContentRecord) -> Result<(), KeystoneError> {
        let path = self.dir.join(format!("{}.meta", record.hash));
        let json = serde_json::to_vec(record)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| KeystoneError::KeyStorage(e.to_string()))
    }
}

/// DHT key format for content announcements: content:<blake3_hex>
pub fn content_dht_key(hash: &str) -> String {
    format!("content:{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn tmp(name: &str) -> PathBuf { temp_dir().join(name) }

    #[test]
    fn store_and_retrieve() {
        let dir = tmp("ks_ct1");
        let store = ContentStore::new(&dir).unwrap();
        let hash = store.store(b"hello keystone").unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"hello keystone");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_content_same_hash() {
        let dir = tmp("ks_ct2");
        let store = ContentStore::new(&dir).unwrap();
        assert_eq!(store.store(b"x").unwrap(), store.store(b"x").unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn different_content_different_hash() {
        let dir = tmp("ks_ct3");
        let store = ContentStore::new(&dir).unwrap();
        assert_ne!(store.store(b"a").unwrap(), store.store(b"b").unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_hash_returns_none() {
        let dir = tmp("ks_ct4");
        let store = ContentStore::new(&dir).unwrap();
        assert!(store.get("doesnotexist").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn content_dht_key_format() {
        assert_eq!(content_dht_key("abc123"), "content:abc123");
    }

    #[test]
    fn calc_chunk_size_tiers() {
        assert_eq!(calc_chunk_size(1),               512 * KB);
        assert_eq!(calc_chunk_size(26 * MB),         2 * MB);
        assert_eq!(calc_chunk_size(101 * MB),        4 * MB);
    }

    #[test]
    fn chunked_roundtrip() {
        let dir = tmp("ks_ct5");
        let store = ContentStore::new(&dir).unwrap();

        // "Publish" — store the source file
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let hash = store.store(&data).unwrap();

        // Simulate serving chunk 0 to a peer
        let (chunk, total, csz) = store.serve_chunk(&hash, 0).unwrap();
        assert_eq!(chunk, data); // whole file fits in one chunk at this size

        // "Fetch" — begin, write, verify
        let mut record = store.begin_fetch(&hash, total, csz).unwrap();
        store.write_chunk(&mut record, 0, &chunk).unwrap();
        assert!(record.is_complete());
        assert!(store.verify_complete(&record).unwrap());

        store.finish_fetch(&record);
        assert!(store.load_meta(&hash).is_none()); // sidecar gone
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pending_chunks_tracks_state() {
        let dir = tmp("ks_ct6");
        let store = ContentStore::new(&dir).unwrap();
        let data: Vec<u8> = vec![42u8; 512]; // small file, one chunk
        let hash = store.store(&data).unwrap();
        let mut record = store.begin_fetch(&hash, 512, 512 * KB).unwrap();
        assert_eq!(record.pending_chunks(), vec![0]);
        store.write_chunk(&mut record, 0, &data).unwrap();
        assert!(record.pending_chunks().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- Hash validation ---

    #[test]
    fn validate_hash_accepts_real_blake3() {
        let h = hex::encode(blake3::hash(b"keystone").as_bytes());
        assert_eq!(h.len(), 64);
        assert!(validate_hash(&h).is_ok());
    }

    #[test]
    fn validate_hash_rejects_absolute_path() {
        assert!(validate_hash("/etc/passwd").is_err());
    }

    #[test]
    fn validate_hash_rejects_path_traversal() {
        assert!(validate_hash("../../../etc/passwd").is_err());
    }

    #[test]
    fn validate_hash_rejects_empty_string() {
        assert!(validate_hash("").is_err());
    }

    #[test]
    fn validate_hash_rejects_uppercase_hex() {
        // 64 chars but uppercase — not canonical lowercase hex
        assert!(validate_hash("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789").is_err());
    }

    #[test]
    fn validate_hash_rejects_63_chars() {
        assert!(validate_hash(&"a".repeat(63)).is_err());
    }

    #[test]
    fn validate_hash_rejects_65_chars() {
        assert!(validate_hash(&"a".repeat(65)).is_err());
    }

    #[test]
    fn validate_hash_rejects_non_hex_chars() {
        // 64 chars but contains '!' — not a valid hex digit
        let bad: String = std::iter::once('!').chain("a".repeat(63).chars()).collect();
        assert_eq!(bad.len(), 64);
        assert!(validate_hash(&bad).is_err());
    }

    #[test]
    fn store_methods_reject_traversal_hash() {
        let dir = tmp("ks_ct_sec");
        let store = ContentStore::new(&dir).unwrap();
        let bad = "../../../etc/passwd";
        assert!(store.get(bad).is_none());
        assert!(!store.has(bad));
        assert!(store.file_size(bad).is_none());
        assert!(store.serve_chunk(bad, 0).is_none());
        assert!(store.begin_fetch(bad, 100, 100).is_err());
        assert!(store.load_meta(bad).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
