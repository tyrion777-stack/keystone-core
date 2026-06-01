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

## Phase 4 — Content Layer ✓ DONE
*Goal: files stored and retrieved by hash — no server, no URL that can break*

- [x] ContentStore — store blobs by Blake3 hash on disk
- [x] Publish content to DHT (hash → peer address mapping)
- [x] Query content by hash — retrieve from any peer holding it
- [x] Send arbitrary files between peers
- [x] Chunked transfer for large files — dynamic chunk size, pre-allocated,
      any-order writes, Blake3 verified on completion
- [x] Resume interrupted transfers — .meta sidecar tracks ChunkState per chunk,
      restart requests only Pending chunks
- [x] Latency benchmark vs plain HTTP
      Results (loopback, release, 3-trial median):
        100 KB : Keystone  0.4 MB/s | HTTP 136 MB/s   — handshake dominates
        1 MB   : Keystone  2.5 MB/s | HTTP 1026 MB/s  — handshake still dominates
        10 MB  : Keystone 26.7 MB/s | HTTP 1244 MB/s  — 2% of raw TCP
        50 MB  : Keystone 75.6 MB/s | HTTP 1368 MB/s  — 6% of raw TCP
      HTTP is unencrypted loopback (kernel memory-copy speed, not real-world).
      Key finding: connection setup (Noise XX + Yamux + multistream) costs ~250ms.
      QUIC's 1-RTT handshake will close most of the gap on small files.
      Throughput at 50 MB (75 MB/s) already exceeds typical internet bandwidth.

---

## Phase 5 — Transport & Security Hardening ← CURRENT
*Goal: production-grade performance and privacy*

- [x] QUIC transport (TCP kept as fallback, nodes now listen on both)
      Benchmark results vs TCP (loopback, release, 3-trial median):
        100 KB : TCP  0.5 MB/s → QUIC  1.0 MB/s  (2× faster,  handshake wins)
        1 MB   : TCP  2.6 MB/s → QUIC  5.8 MB/s  (2.25× faster)
        10 MB  : TCP 29.5 MB/s → QUIC 31.8 MB/s  (1.08× faster)
        50 MB  : TCP 67.4 MB/s → QUIC 95.9 MB/s  (1.42× faster)
      QUIC wins hardest on small files (handshake is ~2× cheaper than
      Noise XX + Yamux + multistream negotiation). Throughput also wins at
      50 MB because QUIC's stream multiplexing has less head-of-line blocking.
- [x] Relay nodes (neither peer exposes their IP to the other)
      Bootstrap node acts as circuit relay server. Regular nodes request a reservation
      on startup. DCUtR attempts hole-punch to direct QUIC; falls back to relayed traffic.
- [ ] Session keys (forward secrecy — past messages safe if key leaks later)
- [x] Content encryption (X25519 — signing proves authenticity, encryption proves privacy)
      Envelope encryption: random content key per file, wrapped per-recipient via
      ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM. Each Identity now carries
      an X25519 keypair. Encrypted blobs stored and transferred identically to
      unencrypted content. Old key files load cleanly (X25519 derived from Ed25519 seed).
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
