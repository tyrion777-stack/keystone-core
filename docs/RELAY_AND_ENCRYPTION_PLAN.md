# Relay Nodes + Content Encryption — Implementation Plan

Phase 5 items 2 and 3. Relay first (pure network plumbing), encryption second (touches Identity, ContentStore, and the chunk protocol).

---

## Part 1 — Relay Nodes

### Problem

Peers behind NAT (home routers, mobile) can't accept inbound connections. Without relay, Keystone only works reliably when at least one peer has a public IP.

### Solution — two-step libp2p approach

**Step 1: Circuit Relay v2**
Joe (NAT) connects to the bootstrap relay server and reserves a slot.
Joe advertises a relay address in the DHT:
```
/ip4/124.43.78.112/tcp/9000/p2p/<bootstrap-peer-id>/p2p-circuit/p2p/<joe-peer-id>
```
Sarah dials that address. Traffic flows Sarah ↔ relay ↔ Joe. Neither peer's real IP is exposed.

**Step 2: DCUtR (hole punching)**
Once the relayed connection is established, both peers attempt simultaneous UDP hole-punching through the relay (works on most NAT types with QUIC). If successful, they upgrade to a direct QUIC connection and the relay is no longer needed.

### What changes

**`Cargo.toml`** — add features:
```toml
libp2p = { ..., features = [..., "relay", "dcutr"] }
```

**`src/network.rs`** — add to `KeystoneBehaviour`:
```rust
pub relay_client: relay::client::Behaviour,
pub dcutr: dcutr::Behaviour,
```
Add to swarm builder chain:
```rust
.with_relay_client()?
```
`dcutr::Behaviour` wires up automatically once relay client is present.

**`src/bin/node.rs`** — after connecting to bootstrap:
1. Request a relay reservation: `swarm.listen_on(relay_circuit_addr)`
2. Handle `relay::client::Event::ReservationReqAccepted` — relay address is live
3. Store relay address in DHT alongside TCP/QUIC addresses

**`src/bin/bootstrap.rs`** — enable relay server:
```rust
pub relay: relay::Behaviour,
```
Add `relay::Behaviour::new(peer_id, relay::Config::default())` to behaviour.
Relay server handles reservation requests from NAT'd peers automatically.

### Deployment

Bootstrap node (`124.43.78.112:9000`) must be redeployed after bootstrap.rs changes.
No new infrastructure — bootstrap doubles as relay.

### Subtasks

- [ ] Add `relay`, `dcutr` to Cargo.toml features
- [ ] Add `relay::client::Behaviour` + `dcutr::Behaviour` to `KeystoneBehaviour`
- [ ] Wire `.with_relay_client()?` into swarm builder
- [ ] `node.rs`: request relay reservation post-bootstrap, advertise relay addr in DHT
- [ ] `bootstrap.rs`: add relay server behaviour
- [ ] Redeploy bootstrap node

---

## Part 2 — Content Encryption

### Problem

Any peer who learns a Blake3 hash can fetch the content. The hash is the only access control — effectively a public CDN.

### Solution — envelope encryption

**Content key**: a random 32-byte symmetric key, unique per file.
- Used to AES-256-GCM encrypt the file content (ciphertext stored on disk and transferred).

**Key distribution**: the content key is wrapped (encrypted) separately for each authorized recipient using X25519 ECDH.
- Sender generates ephemeral X25519 keypair
- Shared secret = ECDH(ephemeral_private, recipient_x25519_public)
- Derived key = HKDF-SHA256(shared_secret)
- Encrypted content key = AES-256-GCM(derived_key, content_key)

On-wire / on-disk format:
```rust
struct EncryptedBlob {
    plaintext_hash: Blake3Hash,         // hash of original plaintext (stable identifier)
    ciphertext: Vec<u8>,                // AES-256-GCM encrypted content
    nonce: [u8; 12],
    recipients: Vec<RecipientSlot>,
}

struct RecipientSlot {
    ephemeral_pubkey: [u8; 32],         // sender's ephemeral X25519 pubkey
    recipient_pubkey: [u8; 32],         // recipient's X25519 pubkey (for lookup)
    encrypted_content_key: Vec<u8>,     // wrapped content key
    key_nonce: [u8; 12],
}
```

**Blake3 hash addresses the plaintext.** The hash is the stable content identifier regardless of who encrypted it. Encrypted and unencrypted content coexist in the same store — encryption is opt-in.

### X25519 keys

Separate X25519 keypair per identity — not derived from Ed25519. Cleaner separation: Ed25519 signs, X25519 encrypts.

Both keys stored in the existing identity file (already Argon2id + AES-256-GCM protected).

Identity file gains two new fields:
```json
{
  "x25519_private_hex": "...",
  "x25519_public_hex": "..."
}
```

DHT peer records gain the X25519 public key so senders can look up any peer's encryption key by their Keystone identity.

### What changes

**`src/identity.rs`** — add X25519 keypair to `Identity`, generate on `new()`, load/save in key file.

**`src/content.rs`** (or new `src/encryption.rs`):
- `encrypt_for(data, recipients: &[X25519PublicKey]) -> EncryptedBlob`
- `decrypt(blob: &EncryptedBlob, identity: &Identity) -> Option<Vec<u8>>`
- `ContentStore::store_encrypted(data, recipients) -> Blake3Hash`

**`src/protocol.rs`** — `ChunkResponse` carries `encrypted: bool` flag; chunk data is ciphertext when set.

**`src/network.rs`** — DHT `put_record` for peer includes X25519 public key.

**`src/bin/node.rs`** — when serving content: check if stored blob is encrypted; send ciphertext chunks as-is (recipient decrypts on reassembly). When fetching: reassemble chunks, then decrypt.

### Scope for Phase 5

- Single recipient (direct private files): fully implemented
- Public content: unencrypted, unchanged
- Group/broadcast (one file, N recipients): RecipientSlot list supports it structurally, but key distribution to a dynamic group is Phase 6

### Subtasks

- [ ] Add X25519 keypair to `Identity` — generate, load, save
- [ ] Update DHT records to include X25519 public key
- [ ] `encrypt_for` / `decrypt` functions
- [ ] `ContentStore::store_encrypted` — stores ciphertext, returns plaintext hash
- [ ] `ChunkResponse`: add `encrypted` flag
- [ ] `node.rs`: serve encrypted blobs correctly, decrypt on fetch completion
- [ ] Test: roundtrip encrypt → store → fetch → decrypt → verify Blake3

---

## Sequencing

```
Relay (network only, no protocol changes)
    → Encryption (Identity + ContentStore + chunk protocol)
```

Relay on its own doesn't change any content-handling code. Clean base for encryption to build on.
