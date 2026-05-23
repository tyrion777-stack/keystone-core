# Keystone Roadmap

## Goal

Free, serverless file sharing between any two devices — owned by no platform, verifiable by anyone.

A user generates a keypair. Their identity is that keypair — no email, no account, no central server.
They can share files directly with another peer. The file's address is its Blake3 hash, so the
content is self-verifying: it doesn't matter who hands it to you, the math proves it's intact.

---

## What's Done

### Week 1 — Identity
- Ed25519 keypair generation (no seed, no server)
- Sign any content → `SignedMessage` wire format
- Verify signatures — works offline, works anywhere
- Blake3 content hashing — content addresses that can't be faked

### Week 2 — Peer Discovery
- TCP transport with Noise encryption and Yamux multiplexing
- mDNS — zero-config discovery on a local network
- Kademlia DHT — distributed peer routing, no central directory
- Two machines find each other automatically

### Week 3 — Follow Graph (P2P Data Transfer)
- Signed follow records — who follows whom, cryptographically proven
- `request_response` protocol — one peer requests, another responds
- Records verified end-to-end on receipt
- Proved that arbitrary signed data can travel between peers reliably

---

## What's Next

### Real-World Integration ✓ DONE — DeltaType
- [x] Add `keystone-core` as dependency in a production app
- [x] DB migration: `keystone_public_key` column on users table
- [x] Challenge/response auth endpoints (alternative to existing login)
- [ ] Credential endpoint: signed records issued on user actions
- [ ] App keypair encrypted at rest with Argon2id + AES-256-GCM

First external app running Keystone auth in production.
The quiz app (elrquiz) follows the same pattern.

### Week 4 — Content Layer
- [ ] `ContentStore` — store and retrieve blobs by Blake3 hash
- [ ] Publish content to the DHT (hash → peer address mapping)
- [ ] Query content by hash — retrieve from any peer holding it
- [ ] Latency benchmark vs plain HTTP on Server 2

### Bootstrap Node (internet-wide discovery)
- [ ] Deploy a persistent Keystone node on Server 2
- [ ] Peers provide bootstrap addresses at startup to seed DHT
- [ ] mDNS stays for LAN; bootstrap handles WAN
- [ ] Opens firewall port for Keystone (TCP, later UDP for QUIC)

### File Transfer
- [ ] Send arbitrary files (not just JSON records) between peers
- [ ] File addressed by hash — recipient verifies automatically
- [ ] Chunked transfer for large files (BitTorrent-style)
- [ ] Resume interrupted transfers

### Transport Upgrade — QUIC
- [ ] Replace TCP with QUIC (quinn) for faster handshakes
- [ ] Better performance on mobile and unreliable connections
- [ ] UDP firewall rule needed on Server 1

### Identity Hardening
- [ ] Private key encryption at rest — Argon2id + AES-256-GCM
- [ ] Key rotation protocol — what happens when a key is compromised
- [ ] NIP-01 / Nostr compatibility — interoperate with the Nostr ecosystem

### Economics Layer (Phase 4)
- [ ] Signed credentials as transferable tokens
- [ ] Pay-to-follow, paid content — verifiable without a payment processor
- [ ] Portable reputation — follow graph and credentials travel with you

---

## The Stack

| Layer | Technology | Status |
|---|---|---|
| Identity | Ed25519 (ed25519-dalek 2.x) | Done |
| Content addressing | Blake3 | Done (hashing); content store pending |
| Transport | TCP + Noise + Yamux | Done |
| Peer discovery (LAN) | mDNS | Done |
| Peer discovery (WAN) | Kademlia DHT + bootstrap | DHT done; bootstrap node pending |
| Data transfer | request-response (libp2p 0.53) | Done |
| Transport v2 | QUIC (quinn) | Planned |
| Identity standard | Nostr NIP-01 | Planned |
| Key storage | Argon2id + AES-256-GCM | Planned |
