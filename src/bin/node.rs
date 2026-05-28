use std::{collections::HashSet, path::PathBuf};

use futures::StreamExt;
use keystone_core::{
    follow::{create_follow, FollowPayload, FollowStore},
    identity::Identity,
    network::{build_swarm_with_keypair, keypair_from_identity, KeystoneBehaviourEvent},
    protocol::{FollowRequest, FollowResponse},
};
use libp2p::{identify, mdns, request_response, swarm::SwarmEvent, Multiaddr, PeerId};

const BOOTSTRAP_ADDR: &str = "/ip4/124.43.78.112/tcp/9000/p2p/12D3KooWCruYnFTDrFoNPtHpaGPcWm4NvfzjyS7uVqWCBimievS2";
const DEFAULT_KEY_FILE: &str = "keystone.key";

/// Load identity from disk, or create a new one if no key file exists yet.
/// Either way, the user types a password — never stored anywhere, only used
/// to encrypt/decrypt the key file.
fn load_or_create_identity(path: &PathBuf) -> Result<Identity, Box<dyn std::error::Error>> {
    if path.exists() {
        // Key file found — ask for password to unlock it
        let password = rpassword::prompt_password("Enter password: ")?;
        let identity = Identity::load_encrypted(path, &password)?;
        println!("Identity loaded.");
        Ok(identity)
    } else {
        // First run — generate a new identity and save it
        println!("No identity found at {}.", path.display());
        println!("Creating a new identity...");

        // Ask for a password twice to avoid typos
        // rpassword reads from the terminal without showing what's typed
        let password = rpassword::prompt_password("Set a password: ")?;
        let confirm  = rpassword::prompt_password("Confirm password: ")?;

        if password != confirm {
            // Return an error — in Rust, Box<dyn Error> is a catch-all error type
            // that can hold any kind of error
            return Err("Passwords do not match.".into());
        }

        let identity = Identity::generate();
        identity.save_encrypted(path, &password)?;
        println!("New identity created and saved to {}.", path.display());
        Ok(identity)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let query_mode = std::env::args().any(|a| a == "--query");

    // Key file path — use first argument if provided, otherwise default
    let key_path = std::env::args()
        .nth(1)
        .filter(|a| !a.starts_with("--"))  // ignore flags like --query
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));

    // Load or create the identity — this is the real YOU on the network
    let identity = load_or_create_identity(&key_path)?;

    // Convert our Keystone identity into a libp2p keypair so the swarm can use it.
    // Same Ed25519 key underneath — the swarm's peer ID is now derived from YOUR key,
    // not a random throwaway. That means your peer ID is stable and tied to your identity.
    let libp2p_keypair = keypair_from_identity(&identity)?;

    // Broadcast our Keystone public key to every peer we connect with.
    // The identify protocol sends this string on every handshake — peers
    // read it and know who they're talking to.
    let agent = format!("keystone/1.0/{}", identity.public_key_hex());
    let mut swarm = build_swarm_with_keypair(libp2p_keypair, &agent)?;
    let mut store = FollowStore::new();
    let mut dialed: HashSet<PeerId> = HashSet::new();
    let mut requested: HashSet<PeerId> = HashSet::new();

    println!("\n=== Keystone Node ===");
    println!("Public key : {}", identity.public_key_hex());
    // Peer ID is now derived from your public key — stable across restarts
    println!("Peer ID    : {}", swarm.local_peer_id());

    if !query_mode {
        let demo_followee = Identity::generate();
        let record = create_follow(&identity, &demo_followee.public_key_hex());
        store.add(record).unwrap();
        println!(
            "\n[f] Follow created : {} → {}",
            &identity.public_key_hex()[..12],
            &demo_followee.public_key_hex()[..12]
        );
        println!("    Serving {} follow record(s). Waiting for peers...\n", store.len());
    } else {
        println!("\n[?] Query mode — will request follows from any discovered peer\n");
    }

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Dial the bootstrap node to seed the DHT
    let bootstrap: Multiaddr = BOOTSTRAP_ADDR.parse()?;
    match swarm.dial(bootstrap) {
        Ok(_)  => println!("[b] Dialing bootstrap node..."),
        Err(e) => println!("[b] Bootstrap dial failed: {e} (continuing with mDNS only)"),
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let s = address.to_string();
                if s.starts_with("/ip4/127.") || s.starts_with("/ip4/192.") || s.starts_with("/ip4/100.64") {
                    println!("Listening  : {}/p2p/{}", address, swarm.local_peer_id());
                }
            }

            SwarmEvent::Behaviour(event) => match event {
                KeystoneBehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                    for (peer_id, addr) in peers {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                        swarm.add_peer_address(peer_id, addr.clone());
                        if query_mode && dialed.insert(peer_id) {
                            println!("[m] Discovered peer  : {peer_id}");
                            let _ = swarm.dial(addr);
                        }
                    }
                }

                KeystoneBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                    for addr in &info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }

                    // Parse the peer's Keystone public key from their agent_version.
                    // Format is "keystone/1.0/<pubkey_hex>" — we split on '/' and take
                    // the last part. If it's a bootstrap node or unknown, we skip it.
                    let peer_keystone_key = info.agent_version
                        .strip_prefix("keystone/1.0/")
                        .map(|s| s.to_string());

                    if let Some(ref pubkey) = peer_keystone_key {
                        println!("[i] Peer identity  : {}", &pubkey[..16]);
                    }

                    // Seed the DHT routing table and publish our own
                    // public key → peer ID record so others can find us by identity.
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                    let record = libp2p::kad::Record::new(
                        libp2p::kad::RecordKey::new(&identity.public_key_hex()),
                        swarm.local_peer_id().to_bytes(),
                    );
                    let _ = swarm.behaviour_mut().kad.put_record(record, libp2p::kad::Quorum::One);

                    if query_mode && requested.insert(peer_id) {
                        println!("[>] Connection ready, requesting follows from {peer_id}");
                        swarm.behaviour_mut().follows.send_request(&peer_id, FollowRequest);
                    }
                }

                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Request { channel, .. },
                }) => {
                    println!("[<] Follow request from {peer}");
                    let response = FollowResponse { records: store.all().to_vec() };
                    swarm.behaviour_mut().follows.send_response(channel, response).ok();
                    println!("[>] Sent {} record(s)", store.len());
                }

                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => {
                    println!("\n[<] Received {} follow record(s) from {peer}", response.records.len());
                    for record in &response.records {
                        match record.verify() {
                            Ok(()) => {
                                println!("  [✓] Signature valid");
                                if let Ok(p) = serde_json::from_str::<FollowPayload>(&record.content) {
                                    println!("      follower : {}", &p.follower[..16]);
                                    println!("      followee : {}", &p.followee[..16]);
                                }
                            }
                            Err(e) => println!("  [✗] Invalid signature: {e}"),
                        }
                    }
                    println!();
                }

                KeystoneBehaviourEvent::Follows(request_response::Event::OutboundFailure {
                    peer, error, ..
                }) => {
                    println!("[!] Request to {peer} failed: {error}");
                }

                _ => {}
            },
            _ => {}
        }
    }
}
