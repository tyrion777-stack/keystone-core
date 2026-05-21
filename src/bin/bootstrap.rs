use futures::StreamExt;
use keystone_core::network::build_swarm;
use libp2p::{kad, swarm::SwarmEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut swarm = build_swarm()?;

    // Bootstrap node runs Kademlia in server mode — it actively answers DHT queries
    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));

    swarm.listen_on("/ip4/0.0.0.0/tcp/9000".parse()?)?;

    println!("=== Keystone Bootstrap Node ===");
    println!("Peer ID : {}", swarm.local_peer_id());

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "Listening : {}/p2p/{}",
                    address,
                    swarm.local_peer_id()
                );
                println!("\nPaste the line above as the argument to `cargo run --bin peer`\n");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("[+] Peer connected    : {peer_id}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("[-] Peer disconnected : {peer_id}");
            }
            SwarmEvent::Behaviour(event) => {
                // Log identify events so we can see what peers announce themselves as
                use keystone_core::network::KeystoneBehaviourEvent;
                if let KeystoneBehaviourEvent::Identify(
                    libp2p::identify::Event::Received { peer_id, info, .. },
                ) = event
                {
                    println!(
                        "[i] Identified peer   : {peer_id}  protocol={}",
                        info.protocol_version
                    );
                    // Add this peer to our Kademlia routing table
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
            }
            _ => {}
        }
    }
}
