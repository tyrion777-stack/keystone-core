use keystone_core::{Identity, SignedMessage};

fn main() {
    println!("=== Keystone Week 1 Demo ===\n");

    // --- DEVICE A: create identity and sign a message ---
    println!("[ Device A ] Generating identity...");
    let identity_a = Identity::generate();
    println!("  Public key : {}", identity_a.public_key_hex());
    println!("  Private key: {} (keep secret!)\n", identity_a.private_key_hex());

    let content = "Hello from Device A — I authored this.";
    println!("[ Device A ] Signing message: {:?}", content);
    let signed = identity_a.sign(content);

    let json = signed.to_json().unwrap();
    println!("\n[ Wire ] Signed message (JSON):\n{}\n", json);

    // --- DEVICE B: receive the JSON, verify without knowing the private key ---
    println!("[ Device B ] Received message. Verifying...");
    let received = SignedMessage::from_json(&json).unwrap();

    match received.verify() {
        Ok(()) => println!("  Signature valid. Message is authentic.\n"),
        Err(e) => println!("  VERIFICATION FAILED: {}\n", e),
    }

    // --- Show what happens with tampered content ---
    println!("[ Attacker ] Tampering with message content...");
    let mut tampered = SignedMessage::from_json(&json).unwrap();
    tampered.content = "Hello from Device A — INJECTED PAYLOAD.".to_string();

    match tampered.verify() {
        Ok(()) => println!("  Signature valid. (This should not happen!)"),
        Err(e) => println!("  Tamper detected: {}", e),
    }

    println!("\n[ Done ] Week 1 primitive works.");
}
