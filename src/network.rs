use std::time::Duration;

use libp2p::{
    identify, identity, kad,
    kad::store::MemoryStore,
    mdns, noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    tcp, yamux, Swarm, SwarmBuilder, StreamProtocol,
};

use crate::{identity::Identity, protocol::{FollowRequest, FollowResponse}};

pub const PROTOCOL: &str = "/keystone/1.0.0";
pub const FOLLOWS_PROTOCOL: &str = "/keystone/follows/1.0";

/// Everything a Keystone node knows how to do on the network.
#[derive(NetworkBehaviour)]
pub struct KeystoneBehaviour {
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub kad: kad::Behaviour<MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub follows: request_response::json::Behaviour<FollowRequest, FollowResponse>,
}

/// Convert a Keystone identity into a libp2p keypair.
///
/// Both are Ed25519 under the hood — same bytes, different Rust types.
/// This bridge lets the swarm use your real identity instead of a random one.
pub fn keypair_from_identity(id: &Identity) -> Result<identity::Keypair, Box<dyn std::error::Error>> {
    let mut bytes = hex::decode(id.private_key_hex())?;
    let secret = identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(identity::Keypair::from(identity::ed25519::Keypair::from(secret)))
}

pub fn build_swarm() -> Result<Swarm<KeystoneBehaviour>, Box<dyn std::error::Error>> {
    build_swarm_with_keypair(
        libp2p::identity::Keypair::generate_ed25519(),
        "keystone/ephemeral",
    )
}

/// Build a swarm with a specific keypair — used by the bootstrap node so its
/// peer ID stays stable across restarts.
///
/// `agent_version` is broadcast to every peer on connect via the identify protocol.
/// For real nodes, pass `format!("keystone/1.0/{}", identity.public_key_hex())`.
/// This is how peers learn each other's Keystone public keys.
pub fn build_swarm_with_keypair(
    keypair: libp2p::identity::Keypair,
    agent_version: &str,
) -> Result<Swarm<KeystoneBehaviour>, Box<dyn std::error::Error>> {
    let agent = agent_version.to_string();
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            let store = MemoryStore::new(peer_id);

            Ok(KeystoneBehaviour {
                identify: identify::Behaviour::new(
                    identify::Config::new(PROTOCOL.to_string(), key.public())
                        .with_agent_version(agent.clone()),
                ),
                ping: ping::Behaviour::default(),
                kad: kad::Behaviour::new(peer_id, store),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?,
                follows: request_response::json::Behaviour::new(
                    [(
                        StreamProtocol::new(FOLLOWS_PROTOCOL),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                ),
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    Ok(swarm)
}
