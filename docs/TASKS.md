# Keystone — Task List by Phase

---

## Phase 1 — Foundation ✓ DONE
*Goal: prove the primitives work*

- [x] Ed25519 keypair generation
- [x] Sign any content → SignedMessage wire format
- [x] Verify signatures offline, anywhere
- [x] Blake3 content hashing
- [x] Encrypted key storage (Argon2id + AES-256-GCM)
- [x] JSON serialization for wire transport
- [x] 8 tests passing

---

## Phase 2 — Network ✓ DONE
*Goal: peers find each other and exchange signed data*

- [x] TCP transport with Noise encryption and Yamux multiplexing
- [x] mDNS — zero-config local peer discovery
- [x] Kademlia DHT — distributed peer routing
- [x] Follow records travel peer-to-peer and verify on receipt
- [x] Bootstrap node live on Server 1 (124.43.78.112:9000)
- [x] Internet-wide peer discovery working
- [x] Published on crates.io (v0.1.2) and GitHub

---

## Phase 3 — Identity on the Network ✓ DONE
*Goal: your keypair IS your presence on the network — not a random peer ID*

- [x] Node loads identity from disk on startup (not a throwaway keypair)
- [x] Node announces Keystone public key via the identify protocol
- [x] DHT stores public key → network address mapping
      (look someone up by their public key, not just a peer ID)
- [x] Follow records served by a node are tied to its real identity
- [x] DHT revocation records
      (publish signed notice when a key is compromised — verifiers check before accepting)
- [ ] Per-app subkeys — DEFERRED to Phase 5
      Considered and deliberately pushed back. Subkeys fragment Joe's identity —
      his follow graph no longer travels automatically between platforms, which
      breaks the core promise ("enter the network once, be part of it everywhere").
      The privacy problem subkeys solve (platforms cross-correlating users) is
      real but better addressed through selective disclosure in Phase 5, not
      identity fragmentation. Subkeys remain the right answer for high-risk users
      (activists, whistleblowers) — not the default for Joe, Pete, or Maria.

---

## Phase 4 — Content Layer ← CURRENT
*Goal: files stored and retrieved by hash — no server, no URL that can break*

- [x] ContentStore — store blobs by Blake3 hash on disk
- [x] Publish content to DHT (hash → peer address mapping)
- [x] Query content by hash — retrieve from any peer holding it
- [x] Send arbitrary files between peers
- [ ] Chunked transfer for large files (BitTorrent-style)
- [ ] Resume interrupted transfers
- [ ] Latency benchmark vs plain HTTP

---

## Phase 5 — Transport & Security Hardening
*Goal: production-grade performance and privacy*

- [ ] QUIC transport (replace TCP — faster handshakes, better on mobile)
- [ ] Relay nodes (neither peer exposes their IP to the other)
- [ ] Session keys (forward secrecy — past messages safe if key leaks later)
- [ ] Content encryption (X25519 — signing proves authenticity, encryption proves privacy)
- [ ] Key rotation protocol (migrate to new keypair if compromised)
- [ ] Cross-device sync (encrypted key blob via QR code or P2P)
- [ ] WebAuthn / hardware binding (key lives in device secure enclave)
- [ ] Multiple bootstrap nodes (redundancy — no single point of failure)

---

## Phase 6 — Ecosystem
*Goal: Keystone identities work everywhere, not just Keystone apps*

- [ ] Nostr NIP-01 compatibility
      (Keystone identities interoperable with the entire Nostr ecosystem)
- [ ] JavaScript SDK
      (web apps get everything without writing Rust — wraps sidecar pattern,
       WebCrypto key storage, WebAuthn unlock)
- [ ] Cross-platform trust / chain of trust
      (Platform A issues credentials that Platform B can verify and trust)
- [ ] Credential revocation API for platform developers

---

## Phase 7 — Economics Layer
*Goal: portable reputation and value — no platform owns it*

- [ ] Signed credentials as transferable tokens
- [ ] Pay-to-follow, paid content — verifiable without a payment processor
- [ ] Lightning Network integration for payments (keeps identity layer clean)
- [ ] Portable reputation — follow graph and credentials travel with you
- [ ] Creator monetisation primitives

---

## Live Integrations

| App | Type | Status |
|---|---|---|
| DeltaType | SvelteKit + Rust sidecar, multi-tenant | Production |
| elrquiz | Rust/Axum, signed score credentials | Planned |

---

## Infrastructure

| Thing | Status |
|---|---|
| Bootstrap node | Live — 124.43.78.112:9000 |
| Peer ID | 12D3KooWCruYnFTDrFoNPtHpaGPcWm4NvfzjyS7uVqWCBimievS2 |
| crates.io | keystone-core v0.1.2 |
| GitHub | github.com/tyrion777-stack/keystone-core |
