use std::time::Duration;

use libp2p::{
    identify, kad,
    kad::store::MemoryStore,
    mdns, noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    tcp, yamux, Swarm, SwarmBuilder, StreamProtocol,
};

use crate::protocol::{FollowRequest, FollowResponse};

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

pub fn build_swarm() -> Result<Swarm<KeystoneBehaviour>, Box<dyn std::error::Error>> {
    let swarm = SwarmBuilder::with_new_identity()
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
                identify: identify::Behaviour::new(identify::Config::new(
                    PROTOCOL.to_string(),
                    key.public(),
                )),
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
