use std::path::PathBuf;

use futures::StreamExt;
use keystone_core::network::{build_swarm_with_keypair, KeystoneBehaviourEvent};
use libp2p::{identify, identity::Keypair, kad, swarm::SwarmEvent};

// Where the keypair is saved on disk — stable across restarts.
// Pass a custom path as the first argument if needed.
const DEFAULT_KEY_PATH: &str = "bootstrap.key";

fn load_or_create_keypair(path: &PathBuf) -> Keypair {
    if path.exists() {
        let bytes = std::fs::read(path).expect("could not read keypair file");
        Keypair::from_protobuf_encoding(&bytes).expect("keypair file is corrupt — delete it to regenerate")
    } else {
        let keypair = Keypair::generate_ed25519();
        let bytes = keypair.to_protobuf_encoding().expect("failed to encode keypair");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, &bytes).expect("could not write keypair file");
        println!("[*] New keypair generated and saved to {}", path.display());
        keypair
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_PATH));

    let keypair = load_or_create_keypair(&key_path);
    let mut swarm = build_swarm_with_keypair(keypair)?;

    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/tcp/9000".parse()?)?;

    println!("=== Keystone Bootstrap Node ===");
    println!("Peer ID  : {}", swarm.local_peer_id());
    println!("Key file : {}", key_path.display());
    println!();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let s = address.to_string();
                // Only print routable addresses
                if !s.contains("127.0.0.1") {
                    println!(
                        "Listening : {}/p2p/{}",
                        address,
                        swarm.local_peer_id()
                    );
                    println!();
                    println!("Hardcode the line above as the bootstrap address in other nodes.");
                    println!();
                }
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("[+] Connected    : {peer_id}");
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                println!("[-] Disconnected : {peer_id}  ({cause:?})");
            }

            SwarmEvent::Behaviour(event) => {
                if let KeystoneBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                ) = event
                {
                    println!("[i] Identified   : {peer_id}  protocol={}", info.protocol_version);
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
            }

            _ => {}
        }
    }
}
