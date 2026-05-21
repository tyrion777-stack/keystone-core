use futures::StreamExt;
use keystone_core::network::{build_swarm, KeystoneBehaviourEvent};
use libp2p::{kad, mdns, multiaddr::Protocol, swarm::SwarmEvent, Multiaddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First arg is the bootstrap node's full multiaddr, e.g.:
    // /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...
    let bootstrap_addr: Multiaddr = std::env::args()
        .nth(1)
        .expect("Usage: peer <bootstrap-multiaddr>")
        .parse()
        .expect("Invalid multiaddr — copy the full address printed by the bootstrap node");

    // Extract the peer ID from the end of the multiaddr (/p2p/<id>)
    let bootstrap_peer_id = bootstrap_addr
        .iter()
        .find_map(|p| {
            if let Protocol::P2p(id) = p {
                Some(id)
            } else {
                None
            }
        })
        .expect("Bootstrap address must include /p2p/<peer-id>");

    let mut swarm = build_swarm()?;

    // Listen on a random port (OS picks one — avoids clashes when running two peers locally)
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Tell Kademlia where the bootstrap node is, then start discovery
    swarm
        .behaviour_mut()
        .kad
        .add_address(&bootstrap_peer_id, bootstrap_addr.clone());
    swarm.behaviour_mut().kad.bootstrap()?;

    // Dial the bootstrap node to initiate the connection
    swarm.dial(bootstrap_addr)?;

    println!("=== Keystone Peer ===");
    println!("My peer ID : {}", swarm.local_peer_id());
    println!("Connecting to bootstrap...\n");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "Listening on : {}/p2p/{}",
                    address,
                    swarm.local_peer_id()
                );
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if peer_id == bootstrap_peer_id {
                    println!("[+] Connected to bootstrap node");
                } else {
                    println!("[+] Connected to peer : {peer_id}");
                }
            }
            SwarmEvent::Behaviour(event) => match event {
                // mDNS found a peer on the local network — dial them directly
                KeystoneBehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                    for (peer_id, addr) in peers {
                        if peer_id == bootstrap_peer_id {
                            continue; // skip bootstrap, already connected
                        }
                        println!("[m] mDNS found peer  : {peer_id}");
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                        let _ = swarm.dial(addr);
                    }
                }
                KeystoneBehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                    for (peer_id, _) in peers {
                        println!("[m] mDNS peer expired: {peer_id}");
                    }
                }
                KeystoneBehaviourEvent::Identify(libp2p::identify::Event::Received {
                    peer_id,
                    info,
                    ..
                }) => {
                    if peer_id != bootstrap_peer_id {
                        println!("[i] Identified peer  : {peer_id}");
                    }
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
                KeystoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                    ..
                }) => {
                    if num_remaining == 0 {
                        println!("[✓] Bootstrap complete — routing table populated");
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}
