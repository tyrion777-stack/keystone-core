# Keystone — Security & Privacy Hardening Plan

This document identifies every known weakness in the current Keystone design,
explains why it matters, and describes the fix with an implementation approach.

---

## 1. IP / Location Exposure in P2P Mode

### Problem
When two peers connect directly, both parties see each other's IP address.
When a peer announces itself to the Kademlia DHT, its IP is stored in
routing tables visible to any node querying the DHT. The bootstrap node
on Server 2 sees the IP of every peer that connects to it.

This is not a flaw specific to Keystone — BitTorrent, IPFS, and every
other P2P protocol has the same property. But it is a real exposure.

### Why it matters
IP address reveals approximate location (city level). In adversarial
environments — censorship, targeted surveillance — this is a meaningful risk.

### Does not affect client-server integrations
If a platform uses keystone-core purely for auth (challenge/response over
HTTPS), users connect only to the platform's server. No P2P connection is
made and no IP is exposed beyond what a normal web app exposes.
Location leakage is a P2P-layer concern only.

### Fix — Relay Nodes
A relay node sits between two peers. Neither peer connects directly to the
other — both connect to the relay, which forwards traffic. Neither side
learns the other's IP.

```
Peer A  →  relay.keystone.network  →  Peer B
           (neither A nor B sees the other's IP)
```

**Implementation approach:**
- libp2p has a built-in `relay` protocol (`libp2p-relay`)
- Peers that cannot reach each other directly (NAT, firewall) use a relay
- Relay nodes can be run by anyone — decentralised, no single point of failure
- Add `relay` to `KeystoneBehaviour` in `network.rs`

**Complexity:** Medium. libp2p relay is well-documented.

---

## 2. Public Key Linkability

### Problem
Your public key is your identity. If you use the same keypair on every
platform, every app that uses Keystone can see it's the same person.
An observer can build a cross-platform profile of you — which apps you
use, how often, who you interact with.

Portable identity and traceable identity are the same thing by default.

### Fix — Per-App Subkeys (HD Key Derivation)

Derive a unique keypair per application from a single master keypair,
using a deterministic derivation function (similar to BIP32 in Bitcoin).

```
Master keypair  (never shared, never transmitted)
    ↓
App-specific seed  =  BLAKE3(master_private_key + app_domain)
    ↓
App keypair  (different per app, but all controlled by master key)
```

You have one identity. Each platform sees a different public key.
No platform can correlate you with another platform without your consent.
But you can prove all subkeys belong to the same master — selectively,
when you choose to link accounts.

**Implementation approach:**
- Add `Identity::derive_subkey(domain: &str) -> Identity` method
- Use BLAKE3 keyed hash of master private key bytes + domain string as seed
- Subkey is a full Ed25519 keypair, used exactly like a regular identity

**Complexity:** Low. A few lines of crypto code.

---

## 3. No Content Encryption

### Problem
Keystone signs content to prove authenticity and integrity.
It does not encrypt content.

Any signed message transmitted between peers or stored on a server
is readable by anyone who intercepts or accesses it. Signing proves
it came from you — it does not hide what you said.

### Fix — X25519 Key Exchange + AES-256-GCM Encryption

Ed25519 keys (signing) and X25519 keys (encryption) are related but
separate. Add an encryption keypair alongside the signing keypair.

```
Alice wants to send Bob a private message:

1. Alice has Bob's X25519 public key
2. Alice performs Diffie-Hellman: shared_secret = Alice_private × Bob_public
3. Alice encrypts content with AES-256-GCM using shared_secret
4. Only Bob can decrypt — Bob_private × Alice_public = same shared_secret
5. Alice signs the encrypted payload with her Ed25519 key
   → proves it came from Alice AND is unreadable to anyone else
```

**Implementation approach:**
- Add `x25519-dalek` dependency
- Add `encryption_public_key_hex()` and `encrypt_for(recipient_pubkey, content)` to `Identity`
- Add `decrypt(ciphertext)` to `Identity`
- Wire into the request-response protocol for private peer messages

**Complexity:** Medium. Well-understood crypto, good Rust libraries available.

---

## 4. No Credential Revocation

### Problem
Once a signed credential is issued, there is no built-in way to
invalidate it. A leaked or compromised credential is valid forever.

If a user's keypair is stolen, the attacker can use all credentials
issued to that key indefinitely.

### Fix — DHT Revocation Records

Publish a signed revocation notice to the Kademlia DHT when a key
or credential is compromised. Any platform verifying credentials
checks the DHT for revocations before accepting.

```
Revocation record content:
{
  "revoked_key": "<public_key>",
  "reason":      "compromised",
  "revoked_at":  <timestamp>,
  "successor":   "<new_public_key>"   // optional
}

Signed by: the key being revoked (proves the owner is revoking it)
           OR by the platform that issued the credential
```

**Implementation approach:**
- Add `RevocationRecord` to `protocol.rs`
- On `FollowStore` and credential verification — check DHT for revocation before accepting
- Store revocation records in `kad::Behaviour` under the key's hash
- Platforms maintain a local revocation cache with TTL

**Complexity:** Medium. DHT is already running, just need to define the record type.

---

## 5. No Forward Secrecy

### Problem
All content signed with a keypair is permanently attributable to that key.
If the private key leaks in the future, an adversary can retroactively
attribute every signed message you ever sent.

### Fix — Session Keys

Generate a fresh temporary keypair for each session. Sign session
content with the session key. Sign the session key itself with the
master key to prove it belongs to you.

```
Master key   →  signs  →  session key (valid for this connection only)
Session key  →  signs  →  all messages in this session

Session key is discarded after the session ends.
If master key leaks later, past session content cannot be decrypted
or linked — the session keys no longer exist.
```

**Implementation approach:**
- Add `Identity::new_session_key() -> (Identity, SignedMessage)` — returns a
  fresh ephemeral keypair and a master-signed certificate binding it
- Recipients verify the certificate before trusting session signatures
- Session keys are in-memory only, never persisted

**Complexity:** Medium.

---

## 6. Cross-Device Sync

### Problem
A Keystone identity lives on one device. If you log into DeltaType on
your phone, you cannot use the same identity on your laptop without
manually copying the private key file — which is insecure if done naively.

### Fix — Encrypted Key Backup + Sync Protocol

**Backup:**
Wrap the private key with Argon2id + AES-256-GCM using a user-chosen
password. The encrypted blob can be stored anywhere — cloud, USB, email —
and is useless without the password.

```
encrypted_key = AES-256-GCM(
    key    = Argon2id(password, salt),
    data   = private_key_bytes
)
```

**Sync — two approaches:**

Option A: **QR code / local transfer**
- Device A displays a QR code containing the encrypted key blob
- Device B scans it, prompts for password, decrypts locally
- No server involved, no network exposure
- Simple to implement, good enough for most users

Option B: **P2P sync over Keystone**
- Device A and Device B are both running Keystone nodes (e.g. on the same local network via mDNS)
- Device A encrypts the key for Device B using X25519 (see fix #3)
- Transmits over the encrypted P2P channel
- Device B decrypts and stores locally
- Requires fix #3 (content encryption) to be implemented first

**Implementation approach:**
- Add `Identity::to_encrypted_blob(password: &str) -> Vec<u8>`
- Add `Identity::from_encrypted_blob(blob: &[u8], password: &str) -> Result<Identity>`
- Add `argon2` and `aes-gcm` dependencies (argon2 already planned)
- QR code generation can be a thin CLI tool or app feature

**Complexity:** Low for encrypted blob. Medium for P2P sync.

---

## 7. Hardware Binding (WebAuthn Integration)

### Problem
The Keystone private key is software-stored bytes. A fully compromised
device (malware, physical access) can extract it. There is no hardware
barrier between an attacker and the key.

### Fix — WebAuthn / Secure Enclave Integration

Use the platform's hardware secure enclave (Apple Secure Enclave,
Windows TPM, Android StrongBox) to generate and store the keypair.
The private key is generated inside the hardware and physically
cannot be exported — not even by the OS.

```
User opens app → biometric prompt (Face ID / fingerprint)
              → secure enclave signs the Keystone challenge internally
              → private key never enters software
```

For web platforms, the browser WebAuthn API exposes this same hardware
through a standard interface.

**Implementation approach:**
- On mobile/desktop apps: use platform SDK (iOS Security framework,
  Android Keystore, Windows CNG) to generate Ed25519 key in hardware
- For web: use WebAuthn (navigator.credentials.create) to generate
  a hardware-backed keypair, use it for Keystone challenge/response
- keystone-core library remains unchanged — it works with any Ed25519
  keypair regardless of where it's stored
- The app layer handles key generation and storage, keystone-core
  handles signing and verification

**Complexity:** High — platform-specific native code required.
  Highest priority for any production-facing user-facing app.

---

## Priority Order

| Fix | Impact | Complexity | Priority |
|---|---|---|---|
| Encrypted key backup (cross-device sync) | High | Low | **1 — do now** |
| Per-app subkeys (linkability) | High | Low | **2** |
| DHT revocation | High | Medium | **3** |
| Content encryption (X25519) | Medium | Medium | **4** |
| Relay nodes (IP exposure) | Medium | Medium | **5** |
| Session keys (forward secrecy) | Medium | Medium | **6** |
| WebAuthn / hardware binding | Very high | High | **7 — before public launch** |

---

## Cross-Platform Admin

Keystone does not automatically propagate admin roles across platforms.
Each platform independently controls its own permissions. The same keypair
is recognised on every platform where it has been registered — but the
role granted is per-platform.

**Pattern for a developer who runs multiple platforms:**

```rust
// In each platform's config or first-run setup:
const ADMIN_PUBLIC_KEY: &str = "your_master_public_key_hex_here";

// On login, after verifying the challenge signature:
if verified_public_key == ADMIN_PUBLIC_KEY {
    grant_role("admin");
}
```

Same key, all platforms recognise it, each grants its own roles.

**Future: cross-platform trust (chain of trust)**
Platform A can issue a signed credential saying "this key is a trusted admin."
Platform B can choose to accept credentials signed by Platform A's key.
This is a PKI (Public Key Infrastructure) model — buildable on top of
Keystone's existing SignedMessage primitive, not yet formalised.
