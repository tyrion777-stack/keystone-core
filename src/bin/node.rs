use std::{collections::{HashMap, HashSet}, path::PathBuf};

use futures::StreamExt;
use keystone_core::{
    content::{content_dht_key, ContentStore},
    follow::{create_follow, create_revocation, revocation_dht_key, FollowPayload, FollowStore, RevocationPayload},
    identity::{Identity, SignedMessage},
    network::{build_swarm_with_keypair, keypair_from_identity, KeystoneBehaviourEvent},
    protocol::{ContentRequest, ContentResponse, FollowRequest, FollowResponse},
};
use libp2p::{identify, kad, mdns, request_response, swarm::SwarmEvent, Multiaddr, PeerId};

const BOOTSTRAP_ADDR: &str = "/ip4/124.43.78.112/tcp/9000/p2p/12D3KooWCruYnFTDrFoNPtHpaGPcWm4NvfzjyS7uVqWCBimievS2";
const DEFAULT_KEY_FILE: &str = "keystone.key";
const CONTENT_DIR: &str = "content";

fn load_or_create_identity(path: &PathBuf) -> Result<Identity, Box<dyn std::error::Error>> {
    if path.exists() {
        let password = rpassword::prompt_password("Enter password: ")?;
        let identity = Identity::load_encrypted(path, &password)?;
        println!("Identity loaded.");
        Ok(identity)
    } else {
        println!("No identity found at {}.", path.display());
        println!("Creating a new identity...");
        let password = rpassword::prompt_password("Set a password: ")?;
        let confirm  = rpassword::prompt_password("Confirm password: ")?;
        if password != confirm {
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
    let args: Vec<String> = std::env::args().collect();

    let query_mode  = args.iter().any(|a| a == "--query");
    let revoke_mode = args.iter().any(|a| a == "--revoke");

    let find_key: Option<String> = args.windows(2)
        .find(|w| w[0] == "--find")
        .map(|w| w[1].clone());

    let follow_key: Option<String> = args.windows(2)
        .find(|w| w[0] == "--follow")
        .map(|w| w[1].clone());

    // --publish <filepath>  →  hash file, store locally, announce to DHT
    let publish_path: Option<PathBuf> = args.windows(2)
        .find(|w| w[0] == "--publish")
        .map(|w| PathBuf::from(&w[1]));

    // --fetch <hash>  →  find who has it via DHT, pull the bytes, save to file
    let fetch_hash: Option<String> = args.windows(2)
        .find(|w| w[0] == "--fetch")
        .map(|w| w[1].clone());

    let key_path = args.iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));

    let identity = load_or_create_identity(&key_path)?;
    let libp2p_keypair = keypair_from_identity(&identity)?;
    let agent = format!("keystone/1.0/{}", identity.public_key_hex());
    let mut swarm = build_swarm_with_keypair(libp2p_keypair, &agent)?;
    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));

    let content_store = ContentStore::new(CONTENT_DIR)?;
    let mut follow_store = FollowStore::new();
    let mut dialed: HashSet<PeerId> = HashSet::new();
    let mut requested: HashSet<PeerId> = HashSet::new();

    let mut find_query_id: Option<kad::QueryId> = None;
    let mut revocation_checks: HashMap<kad::QueryId, String> = HashMap::new();
    let mut revoke_published = false;

    // content:<hash> DHT lookup → we need the hash back when result arrives
    let mut content_fetch_queries: HashMap<kad::QueryId, String> = HashMap::new();
    // peer we need to fetch from once connected: peer_id → [hashes]
    let mut pending_fetches: HashMap<PeerId, Vec<String>> = HashMap::new();

    println!("\n=== Keystone Node ===");
    println!("Public key : {}", identity.public_key_hex());
    println!("Peer ID    : {}", swarm.local_peer_id());

    // Publish a file if --publish was passed.
    // We do this before connecting to the network — the file is stored
    // locally now and announced to the DHT once we have peers.
    let publish_hash: Option<String> = if let Some(ref path) = publish_path {
        let bytes = std::fs::read(path)?;
        let hash = content_store.store(&bytes)?;
        println!("\n[+] Stored locally : {hash}");
        println!("    File           : {}", path.display());
        println!("    Size           : {} bytes", bytes.len());
        println!("    Will announce to DHT once connected...");
        Some(hash)
    } else {
        None
    };

    if let Some(ref followee_pubkey) = follow_key {
        let record = create_follow(&identity, followee_pubkey);
        follow_store.add(record).unwrap();
        println!(
            "\n[f] Follow recorded : {} → {}",
            &identity.public_key_hex()[..12],
            &followee_pubkey[..12.min(followee_pubkey.len())]
        );
    }

    if revoke_mode {
        println!("\n[!] Revoke mode — will publish revocation once DHT is reachable.");
    }

    if let Some(ref hash) = fetch_hash {
        println!("\n[?] Will fetch content: {}...", &hash[..16.min(hash.len())]);
    }

    if query_mode {
        println!("\n[?] Query mode — will request follows from any discovered peer\n");
    } else {
        println!("    Serving {} follow record(s). Waiting for peers...\n", follow_store.len());
    }

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

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

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                // If we were waiting to fetch content from this peer, send the requests now.
                if let Some(hashes) = pending_fetches.remove(&peer_id) {
                    for hash in hashes {
                        println!("[>] Requesting content {hash} from {peer_id}");
                        swarm.behaviour_mut().content.send_request(&peer_id, ContentRequest { hash });
                    }
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

                    let peer_keystone_key = info.agent_version
                        .strip_prefix("keystone/1.0/")
                        .map(|s| s.to_string());

                    if let Some(ref pubkey) = peer_keystone_key {
                        println!("[i] Peer identity  : {}", &pubkey[..16]);
                    }

                    let _ = swarm.behaviour_mut().kad.bootstrap();

                    // Publish identity record: pubkey → peer ID
                    let id_record = libp2p::kad::Record::new(
                        libp2p::kad::RecordKey::new(&identity.public_key_hex()),
                        swarm.local_peer_id().to_bytes(),
                    );
                    let _ = swarm.behaviour_mut().kad.put_record(id_record, libp2p::kad::Quorum::One);

                    // Announce content to DHT now that we have routing
                    if let Some(ref hash) = publish_hash {
                        let content_record = libp2p::kad::Record::new(
                            libp2p::kad::RecordKey::new(&content_dht_key(hash)),
                            swarm.local_peer_id().to_bytes(),
                        );
                        let _ = swarm.behaviour_mut().kad.put_record(content_record, libp2p::kad::Quorum::One);
                        println!("[+] Content announced to DHT: {}...", &hash[..16]);
                    }

                    if revoke_mode && !revoke_published {
                        let revocation = create_revocation(&identity, "Key compromised by owner");
                        let value = serde_json::to_vec(&revocation).unwrap_or_default();
                        let rev_record = libp2p::kad::Record::new(
                            libp2p::kad::RecordKey::new(&revocation_dht_key(&identity.public_key_hex())),
                            value,
                        );
                        let _ = swarm.behaviour_mut().kad.put_record(rev_record, libp2p::kad::Quorum::One);
                        println!("[!] Revocation published to DHT. Keep this node running briefly to propagate.");
                        revoke_published = true;
                    }

                    if let Some(ref key) = find_key {
                        if find_query_id.is_none() {
                            let dht_key = libp2p::kad::RecordKey::new(key);
                            find_query_id = Some(swarm.behaviour_mut().kad.get_record(dht_key));
                            println!("[?] DHT query fired — waiting for result...");
                        }
                    }

                    // Fire content fetch DHT lookup once we have routing
                    if let Some(ref hash) = fetch_hash {
                        if content_fetch_queries.values().all(|h| h != hash) {
                            let dht_key = libp2p::kad::RecordKey::new(&content_dht_key(hash));
                            let qid = swarm.behaviour_mut().kad.get_record(dht_key);
                            content_fetch_queries.insert(qid, hash.clone());
                            println!("[?] Looking up content on DHT...");
                        }
                    }

                    if query_mode && requested.insert(peer_id) {
                        println!("[>] Connection ready, requesting follows from {peer_id}");
                        swarm.behaviour_mut().follows.send_request(&peer_id, FollowRequest);
                    }
                }

                // --- Follow protocol ---

                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Request { channel, .. },
                }) => {
                    println!("[<] Follow request from {peer}");
                    let response = FollowResponse { records: follow_store.all().to_vec() };
                    swarm.behaviour_mut().follows.send_response(channel, response).ok();
                    println!("[>] Sent {} record(s)", follow_store.len());
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

                                    let fk = libp2p::kad::RecordKey::new(&revocation_dht_key(&p.follower));
                                    let qid = swarm.behaviour_mut().kad.get_record(fk);
                                    revocation_checks.insert(qid, p.follower.clone());

                                    let fk = libp2p::kad::RecordKey::new(&revocation_dht_key(&p.followee));
                                    let qid = swarm.behaviour_mut().kad.get_record(fk);
                                    revocation_checks.insert(qid, p.followee.clone());

                                    println!("      [~] Checking revocation status...");
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
                    println!("[!] Follow request to {peer} failed: {error}");
                }

                // --- Content protocol ---

                KeystoneBehaviourEvent::Content(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Request { request, channel, .. },
                }) => {
                    println!("[<] Content request from {peer} : {}", &request.hash[..16.min(request.hash.len())]);
                    let data = content_store.get(&request.hash);
                    let found = data.is_some();
                    swarm.behaviour_mut().content.send_response(channel, ContentResponse { data }).ok();
                    if found {
                        println!("[>] Sent content");
                    } else {
                        println!("[>] Don't have it");
                    }
                }

                KeystoneBehaviourEvent::Content(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => {
                    match response.data {
                        Some(bytes) => {
                            let hash = hex::encode(blake3::hash(&bytes).as_bytes());
                            // Save to disk via content store to verify hash integrity
                            match content_store.store(&bytes) {
                                Ok(stored_hash) if stored_hash == hash => {
                                    println!("\n[✓] Content received from {peer}");
                                    println!("    Hash    : {hash}");
                                    println!("    Size    : {} bytes", bytes.len());
                                    println!("    Saved to: {CONTENT_DIR}/{hash}\n");
                                }
                                _ => println!("[!] Content hash mismatch — discarded"),
                            }
                        }
                        None => println!("[!] Peer {peer} does not have the requested content"),
                    }
                }

                KeystoneBehaviourEvent::Content(request_response::Event::OutboundFailure {
                    peer, error, ..
                }) => {
                    println!("[!] Content request to {peer} failed: {error}");
                }

                // --- DHT results ---

                KeystoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                    id,
                    result: kad::QueryResult::GetRecord(result),
                    step,
                    ..
                }) => {
                    match result {
                        Ok(kad::GetRecordOk::FoundRecord(record)) => {
                            if let Some(pubkey) = revocation_checks.remove(&id) {
                                println!("\n  [!] WARNING: key {}... may be REVOKED", &pubkey[..16]);
                                if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&record.record.value) {
                                    if signed.verify().is_ok() {
                                        if let Ok(p) = serde_json::from_str::<RevocationPayload>(&signed.content) {
                                            println!("      Reason    : {}", p.reason);
                                            println!("      Revoked at: {} (unix)", p.timestamp);
                                        }
                                    } else {
                                        println!("      (revocation signature invalid — record ignored)");
                                    }
                                }
                            } else if let Some(hash) = content_fetch_queries.remove(&id) {
                                // DHT told us who has the content — now connect and fetch
                                match PeerId::from_bytes(&record.record.value) {
                                    Ok(publisher_peer_id) => {
                                        println!("[✓] Content found on DHT — publisher: {publisher_peer_id}");
                                        if publisher_peer_id == *swarm.local_peer_id() {
                                            // We published it ourselves
                                            println!("[i] We are the publisher — file is in {CONTENT_DIR}/{hash}");
                                        } else {
                                            pending_fetches
                                                .entry(publisher_peer_id)
                                                .or_default()
                                                .push(hash);
                                            let _ = swarm.dial(publisher_peer_id);
                                        }
                                    }
                                    Err(_) => println!("[!] Found content record but could not decode peer ID"),
                                }
                            } else if find_query_id == Some(id) {
                                find_query_id = None;
                                match PeerId::from_bytes(&record.record.value) {
                                    Ok(found_peer_id) => {
                                        let key_str = String::from_utf8_lossy(record.record.key.as_ref());
                                        println!("\n[✓] Identity found on network!");
                                        println!("    Public key : {}...", &key_str[..16.min(key_str.len())]);
                                        println!("    Peer ID    : {found_peer_id}");
                                        println!("    → Connect to this peer to interact with them.\n");
                                    }
                                    Err(_) => println!("[!] Found record but could not decode peer ID."),
                                }
                            }
                        }

                        Ok(_) => {
                            if step.last {
                                revocation_checks.remove(&id);
                                content_fetch_queries.remove(&id);
                            }
                        }

                        Err(kad::GetRecordError::NotFound { .. }) if step.last => {
                            if let Some(hash) = content_fetch_queries.remove(&id) {
                                println!("[✗] Content not found on the network: {hash}");
                                println!("    The publisher may be offline or hasn't announced yet.");
                            } else if revocation_checks.remove(&id).is_none() && find_query_id == Some(id) {
                                println!("[✗] Identity not found on the network.");
                                println!("    They may be offline or haven't published yet.");
                            }
                        }

                        Err(e) if step.last => println!("[!] DHT lookup error: {e:?}"),

                        _ => {}
                    }
                }

                _ => {}
            },
            _ => {}
        }
    }
}
