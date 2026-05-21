use std::collections::HashSet;

use futures::StreamExt;
use keystone_core::{
    follow::{create_follow, FollowPayload, FollowStore},
    identity::Identity,
    network::{build_swarm, KeystoneBehaviourEvent},
    protocol::{FollowRequest, FollowResponse},
};
use libp2p::{identify, mdns, request_response, swarm::SwarmEvent, PeerId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let query_mode = std::env::args().any(|a| a == "--query");

    let mut swarm = build_swarm()?;
    let mut store = FollowStore::new();
    // Peers we've dialed (once per peer ID — mDNS fires once per address)
    let mut dialed: HashSet<PeerId> = HashSet::new();
    // Peers we've sent a follow request to (only ever once)
    let mut requested: HashSet<PeerId> = HashSet::new();

    let identity = Identity::generate();
    println!("=== Keystone Node ===");
    println!("Identity : {}", identity.public_key_hex());
    println!("Peer ID  : {}", swarm.local_peer_id());

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

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                // Only print the meaningful addresses — skip the link-local noise
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

                        // Dial once per peer — request comes later, after identify confirms
                        // the connection is stable
                        if query_mode && dialed.insert(peer_id) {
                            println!("[m] Discovered peer  : {peer_id}");
                            let _ = swarm.dial(addr);
                        }
                    }
                }

                // Identify fires after the full handshake — the connection is settled and
                // both sides know each other's protocols. Safe to send a request now.
                KeystoneBehaviourEvent::Identify(identify::Event::Received { peer_id, .. }) => {
                    if query_mode && requested.insert(peer_id) {
                        println!("[>] Connection ready, requesting follows from {peer_id}");
                        swarm.behaviour_mut().follows.send_request(&peer_id, FollowRequest);
                    }
                }

                // Incoming follow request — serve our store
                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Request { channel, .. },
                }) => {
                    println!("[<] Follow request from {peer}");
                    let response = FollowResponse {
                        records: store.all().to_vec(),
                    };
                    swarm.behaviour_mut().follows.send_response(channel, response).ok();
                    println!("[>] Sent {} record(s)", store.len());
                }

                // Received a follow response — verify every record
                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => {
                    println!(
                        "\n[<] Received {} follow record(s) from {peer}",
                        response.records.len()
                    );
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
