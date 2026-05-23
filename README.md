# keystone-core

Portable identity and signed credentials for Rust applications.

A developer adds `keystone-core` as a dependency and gets:
- **Passwordless sign-in** — users prove identity with a keypair, no password stored anywhere
- **Signed credentials** — issue tamper-proof role and permission records users carry with them
- **Verifiable anywhere** — any service can verify a credential without calling your server

---

## Installation

```toml
[dependencies]
keystone-core = "0.1.0"
```

---

## Core Concepts

### Identity

A Keystone identity is an Ed25519 keypair. There is no username, email, or password — the keypair *is* the identity.

```rust
use keystone_core::Identity;

// Generate a new identity
let identity = Identity::generate();

// The public key is the user's address — store this in your database
println!("{}", identity.public_key_hex());

// Save to disk, locked with a password — safe to store anywhere
identity.save_encrypted("/path/to/keystone.key", "user-password")?;

// Later — restore from disk with the same password
let identity = Identity::load_encrypted("/path/to/keystone.key", "user-password")?;

// Wrong password returns an error — the file is useless without it
```

**What `save_encrypted` does under the hood:**
1. Generates a random salt and nonce
2. Runs the password through Argon2id (slow by design — defeats brute force)
3. Encrypts the private key with AES-256-GCM
4. Writes `salt + nonce + ciphertext` to disk — 76 bytes total

The user never sees a hex string. The app calls `save_encrypted` on registration
and `load_encrypted` on login.

### Signing and Verification

Any piece of content can be signed. The signature proves:
1. The content came from the holder of a specific keypair
2. The content has not been modified since it was signed

> **Important for non-Rust integrations:** The signature is computed over
> `content_hash.as_bytes()` — the UTF-8 bytes of the Blake3 hex string, not
> the raw content bytes. When reimplementing verification in JavaScript,
> Python, or any other language, sign and verify the hex string's bytes,
> not the original content's bytes. Getting this wrong produces a valid-looking
> flow that fails verification with no obvious error.

```rust
use keystone_core::Identity;

let identity = Identity::generate();

// Sign any string content
let signed = identity.sign("hello world");

// Verify — works with just the public key, no private key needed
match signed.verify() {
    Ok(()) => println!("Valid"),
    Err(e) => println!("Invalid: {e}"),
}

// Serialize for storage or transmission
let json = signed.to_json()?;
let restored = SignedMessage::from_json(&json)?;
```

---

## Sign-In Integration

Keystone auth is a challenge/response flow. Your server never sees a password.

**How it works:**
1. User submits their public key
2. Your server issues a random challenge string
3. User signs the challenge with their private key
4. Your server verifies the signature against the stored public key
5. Issue your session token (JWT or otherwise)

**Step 1 — Store the user's public key on registration**

```sql
ALTER TABLE users ADD COLUMN keystone_public_key TEXT UNIQUE;
```

**Step 2 — Challenge endpoint**

```rust
use keystone_core::Identity;

// Generate a random challenge and store it temporarily (cache or DB)
// with a short TTL (e.g. 60 seconds)
let challenge = hex::encode(rand::random::<[u8; 32]>());
store_challenge(&user_id, &challenge).await?;

// Return it to the client
Ok(Json(json!({ "challenge": challenge })))
```

**Step 3 — Verify endpoint**

```rust
use keystone_core::{Identity, SignedMessage};

// Client sends back: { public_key, signed_challenge }
let signed: SignedMessage = serde_json::from_str(&body.signed_challenge)?;

// 1. Check the signed content matches the challenge you issued
let stored_challenge = get_challenge(&user_id).await?;
if signed.content != stored_challenge {
    return Err(AuthError::ChallengeMismatch);
}

// 2. Verify the signature
signed.verify()?;

// 3. Check the public key matches what's in your database
let user = db.get_user_by_public_key(&body.public_key).await?;

// 4. Issue your session token
let token = create_jwt(&user);
Ok(Json(json!({ "token": token })))
```

---

## Signed Credentials

A credential is a signed record that describes a role or permission. Your platform signs it — the user holds it — anyone can verify it.

**Your platform needs its own keypair:**

```rust
use keystone_core::Identity;

// Generate once, store the private key encrypted at rest
let platform = Identity::generate();
println!("Platform public key: {}", platform.public_key_hex());
// Publish the public key — it's how others verify your credentials
```

**Issue a credential:**

```rust
use keystone_core::Identity;
use serde_json::json;

let credential_content = json!({
    "subject":    user_public_key,
    "role":       "admin",           // or "editor", "viewer", etc.
    "platform":   "myapp.com",
    "issued_at":  unix_timestamp(),
}).to_string();

let credential = platform_identity.sign(&credential_content);
let credential_json = credential.to_json()?;

// Store it and/or return it to the user — they own it now
```

**Verify a credential on incoming requests:**

```rust
use keystone_core::SignedMessage;
use serde_json::Value;

// User presents their credential with the request
let credential = SignedMessage::from_json(&presented_credential)?;

// 1. Verify the signature — proves it came from your platform and wasn't modified
credential.verify()?;

// 2. Parse the content
let claims: Value = serde_json::from_str(&credential.content)?;

// 3. Check it was issued by your platform
assert_eq!(claims["platform"], "myapp.com");

// 4. Extract the role and allow/deny
let role = claims["role"].as_str().unwrap_or("viewer");
match role {
    "admin"  => allow_admin_action(),
    "editor" => allow_edit(),
    _        => deny(),
}
```

---

## Follow Graph

Keystone includes a signed social graph — who follows whom, cryptographically proven.

```rust
use keystone_core::follow::{create_follow, FollowStore};

let mut store = FollowStore::new();

// Create a signed follow record
let record = create_follow(&follower_identity, &followee_public_key);
store.add(record)?; // add() verifies the signature before accepting

// Retrieve all follow records
for record in store.all() {
    record.verify()?;
}
```

Follow records travel peer-to-peer — no central database required.

---

## Integration Patterns

### Rust sidecar (non-Rust backends)

If your main app is not Rust (SvelteKit, Django, Rails, etc.), run keystone-core
as a small Axum HTTP sidecar — a separate process/container on the internal network.
Your app calls it over HTTP, never exposes it publicly.

```
Browser  →  your app (SvelteKit/etc)  →  keystone sidecar (Rust/Axum, internal only)
                                              ↓
                                        challenge/verify endpoints
                                        SignedMessage::verify()
                                        session cookie issued on success
```

The sidecar handles only two things: issue challenges and verify signed responses.
Everything else (sessions, DB, business logic) stays in your main app.

In multi-tenant setups, run one sidecar container per client stack — each isolated,
each on its own internal Docker network.

### Browser-side key storage (JavaScript)

Replicate `save_encrypted` / `load_encrypted` using the browser's WebCrypto API:
- Argon2id (via a WASM port) + AES-256-GCM, same algorithm as the Rust implementation
- Store the encrypted blob in `localStorage` or `IndexedDB`
- Keys are device-bound — one keypair per device
- Enrol new devices via a one-time link from an already-authenticated session

---

## What keystone-core Does Not Do (Yet)

| Feature | Status |
|---|---|
| Credential revocation | Not yet — you need a revocation list in your own DB |
| Key recovery | Not yet — losing the private key means losing the identity |
| Key rotation | Not yet — no protocol for migrating to a new keypair |
| Content encryption | Not yet — signing proves authenticity, not privacy |
| P2P file transfer | Planned — content layer in progress |
| QUIC transport | Planned — replacing TCP for mobile/unreliable networks |
| Nostr / NIP-01 compatibility | Planned |

---

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full build plan toward P2P file sharing and the economics layer.

---

## License

MIT
