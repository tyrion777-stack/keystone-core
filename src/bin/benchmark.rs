// Measures Keystone P2P throughput vs plain HTTP on loopback.
// Keystone: TCP + Noise encryption + Yamux multiplexing + CBOR framing
// HTTP    : plain TCP, minimal HTTP/1.1 framing (no TLS)
// 3 trials per size, median reported.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use futures::StreamExt;
use keystone_core::{
    content::{ContentRecord, ContentStore},
    network::{build_swarm, KeystoneBehaviourEvent},
    protocol::{ChunkRequest, ChunkResponse},
};
use libp2p::{request_response, swarm::SwarmEvent, Multiaddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

static RUN_ID: AtomicUsize = AtomicUsize::new(0);

const TRIALS: usize = 3;
const SIZES: &[(usize, &str)] = &[
    (100_000,    "100 KB"),
    (1_000_000,  "1 MB"),
    (10_000_000, "10 MB"),
    (50_000_000, "50 MB"),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nKeystone vs HTTP — Throughput Benchmark (loopback, {} trials/size)", TRIALS);
    println!("Keystone: TCP + Noise + Yamux + CBOR  |  HTTP: plain TCP, no TLS\n");

    println!("{:<10}  {:>14}  {:>14}  {:>8}", "Size", "Keystone", "HTTP (no TLS)", "KS/HTTP");
    println!("{}", "─".repeat(54));

    for &(size, label) in SIZES {
        let data: Vec<u8> = (0u8..=255).cycle().take(size).collect();
        let mut ks_times: Vec<Duration> = Vec::new();
        let mut http_times: Vec<Duration> = Vec::new();

        for t in 0..TRIALS {
            print!("  {} trial {}/{}  ", label, t + 1, TRIALS);
            let k = bench_keystone(&data).await?;
            let h = bench_http(&data).await?;
            println!("ks={}ms  http={}ms", k.as_millis(), h.as_millis());
            ks_times.push(k);
            http_times.push(h);
        }

        ks_times.sort();
        http_times.sort();
        let ks = ks_times[TRIALS / 2];
        let http = http_times[TRIALS / 2];

        let ks_mbs   = size as f64 / ks.as_secs_f64()   / 1_000_000.0;
        let http_mbs = size as f64 / http.as_secs_f64() / 1_000_000.0;
        let ratio    = ks_mbs / http_mbs * 100.0;

        println!(
            "{:<10}  {:>14}  {:>14}  {:>7.0}%",
            label,
            format!("{:.1} MB/s", ks_mbs),
            format!("{:.1} MB/s", http_mbs),
            ratio,
        );
        println!();
    }

    println!("100% = same speed as unencrypted HTTP. QUIC will narrow the gap on small files.");
    Ok(())
}

// ── Keystone benchmark ────────────────────────────────────────────────────────
// Two in-process swarms connected over loopback.
// Times from swarm.dial() call to Blake3 verify_complete().

async fn bench_keystone(data: &[u8]) -> Result<Duration, Box<dyn std::error::Error>> {
    let id = RUN_ID.fetch_add(1, Ordering::SeqCst);
    let pub_dir = format!("/tmp/ks_bench_{id}_pub");
    let fet_dir = format!("/tmp/ks_bench_{id}_fet");

    // Publisher — store the file
    let pub_store = ContentStore::new(&pub_dir)?;
    let hash = pub_store.store(data)?;

    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let pub_dir2 = pub_dir.clone();
    let pub_task = tokio::spawn(async move {
        let store = ContentStore::new(&pub_dir2).unwrap();
        let mut swarm = build_swarm().unwrap();
        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let mut addr_tx = Some(addr_tx);
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if let Some(tx) = addr_tx.take() {
                        let _ = tx.send(address);
                    }
                }
                SwarmEvent::Behaviour(KeystoneBehaviourEvent::Chunks(
                    request_response::Event::Message {
                        message: request_response::Message::Request { request, channel, .. },
                        ..
                    },
                )) => {
                    let resp = match store.serve_chunk(&request.hash, request.chunk_index) {
                        Some((chunk, total, csz)) => ChunkResponse {
                            hash: request.hash.clone(),
                            chunk_index: request.chunk_index,
                            total_size: total,
                            chunk_size: csz,
                            data: Some(chunk),
                        },
                        None => ChunkResponse {
                            hash: request.hash.clone(),
                            chunk_index: request.chunk_index,
                            total_size: 0,
                            chunk_size: 0,
                            data: None,
                        },
                    };
                    swarm.behaviour_mut().chunks.send_response(channel, resp).ok();
                }
                _ => {}
            }
        }
    });

    // Fetcher — dial and time the transfer
    let pub_addr = addr_rx.await?;
    let mut swarm = build_swarm()?;
    // Fetcher only dials out — no listener needed.

    let start = std::time::Instant::now();
    swarm.dial(pub_addr)?;

    let fet_store = ContentStore::new(&fet_dir)?;
    let mut active: Option<ContentRecord> = None;
    let mut pub_peer: Option<libp2p::PeerId> = None;

    let elapsed = loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                pub_peer = Some(peer_id);
                swarm.behaviour_mut().chunks.send_request(
                    &peer_id,
                    ChunkRequest { hash: hash.clone(), chunk_index: 0 },
                );
            }

            SwarmEvent::Behaviour(KeystoneBehaviourEvent::Chunks(
                request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                },
            )) => {
                let ChunkResponse { hash: h, chunk_index, total_size, chunk_size, data } = response;
                if let Some(bytes) = data {
                    if active.is_none() {
                        let rec = fet_store.begin_fetch(&h, total_size, chunk_size)?;
                        let n = rec.chunks.len();
                        active = Some(rec);
                        // Fire all remaining chunk requests immediately
                        if n > 1 {
                            let p = pub_peer.unwrap();
                            for i in 1..n as u64 {
                                swarm.behaviour_mut().chunks.send_request(
                                    &p,
                                    ChunkRequest { hash: h.clone(), chunk_index: i },
                                );
                            }
                        }
                    }
                    let rec = active.as_mut().unwrap();
                    fet_store.write_chunk(rec, chunk_index, &bytes)?;
                    if rec.is_complete() {
                        let elapsed = start.elapsed();
                        assert!(fet_store.verify_complete(rec)?, "Blake3 mismatch in benchmark");
                        fet_store.finish_fetch(rec);
                        break elapsed;
                    }
                }
            }

            _ => {}
        }
    };

    // Abort and wait — ensures the publisher swarm is fully dropped before
    // the next benchmark run starts, preventing leftover TCP sockets.
    pub_task.abort();
    let _ = pub_task.await;
    let _ = std::fs::remove_dir_all(&pub_dir);
    let _ = std::fs::remove_dir_all(&fet_dir);

    Ok(elapsed)
}

// ── HTTP benchmark ────────────────────────────────────────────────────────────
// Minimal tokio HTTP/1.1 server + client.
// Times from TcpStream::connect() to last byte of body received.

async fn bench_http(data: &[u8]) -> Result<Duration, Box<dyn std::error::Error>> {
    let body = data.to_vec();
    let len  = body.len();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            // Read the request before responding. Dropping with unread data in
            // the receive buffer causes the kernel to send RST instead of FIN,
            // which the client sees as ConnectionReset on large transfers.
            let mut req_buf = vec![0u8; 512];
            let _ = conn.read(&mut req_buf).await;
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
            let _ = conn.write_all(header.as_bytes()).await;
            let _ = conn.write_all(&body).await;
            let _ = conn.shutdown().await;
        }
    });

    let start = std::time::Instant::now();
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await?;
    conn.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;

    let mut raw: Vec<u8> = Vec::with_capacity(len + 64);
    let mut buf = vec![0u8; 65536];
    let mut body_start: Option<usize> = None;

    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 { break; }
        raw.extend_from_slice(&buf[..n]);
        if body_start.is_none() {
            if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                body_start = Some(p + 4);
            }
        }
        if let Some(bs) = body_start {
            if raw.len().saturating_sub(bs) >= len { break; }
        }
    }

    Ok(start.elapsed())
}
