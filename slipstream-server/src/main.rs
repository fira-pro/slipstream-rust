//! slipstream-server — DNS tunnel server
//!
//! Architecture:
//!   1. A DNS UDP socket (port 53) receives queries from clients.
//!   2. Queries are decoded (base32 QNAME → raw QUIC bytes) and injected
//!      into a quinn QUIC endpoint via an internal loopback UDP socket pair.
//!   3. Quinn processes the QUIC bytes and delivers streams to our accept loop.
//!   4. Each QUIC stream is proxied bidirectionally to the TCP upstream service.
//!   5. QUIC responses from quinn are intercepted, encoded as DNS responses,
//!      and sent back to the original DNS client address.
//!
//! The DNS ↔ QUIC bridge runs as two tasks:
//!   - DNS→QUIC injector: reads DNS queries, decodes them, feeds raw QUIC to quinn.
//!   - QUIC→DNS responder: reads quinn's outgoing QUIC packets, encodes them as
//!     DNS responses, sends to the original requester.
//!
//! Key improvements over original C:
//! - No pthreads, no pipes, no file descriptor leaks
//! - Each QUIC stream handled by a tokio task (zero FD cost)
//! - Correct cleanup on connection drop via async drop/RAII

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, EndpointConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use slipstream_core::{
    codec::{encode_dns_response, max_resp_chunk_size},
    config::{ALPN_PROTOCOL, SERVER_SNI},
};
use rand::Rng;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    select,
};
use tracing::{debug, info, warn};

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-server",
    about = "A high-performance covert channel over DNS (server)"
)]
struct Args {
    /// UDP port to listen on for DNS queries (default: 53)
    #[arg(long, default_value_t = 53)]
    dns_listen_port: u16,

    /// Listen on IPv6 instead of IPv4
    #[arg(long, default_value_t = false)]
    dns_listen_ipv6: bool,

    /// TCP address of the service to forward connections to
    #[arg(long, default_value = "127.0.0.1:5201")]
    target_address: String,

    /// Domain name this server is authoritative for (REQUIRED)
    #[arg(long, short = 'd')]
    domain: String,

    /// TLS certificate file (PEM)
    #[arg(long, default_value = "certs/cert.pem")]
    cert: PathBuf,

    /// TLS private key file (PEM)
    #[arg(long, default_value = "certs/key.pem")]
    key: PathBuf,

    /// Generate and use a self-signed certificate (ignores --cert/--key)
    #[arg(long, default_value_t = false)]
    self_signed: bool,
}

// ── TLS/QUIC configuration ─────────────────────────────────────────────────────

fn load_tls_config(cert_path: &PathBuf, key_path: &PathBuf, domain: &str) -> Result<ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading key {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<std::result::Result<_, _>>()
            .context("parsing certificate PEM")?;

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parsing private key PEM")?
        .context("no private key found")?;

    build_server_config(certs, key, domain)
}

fn self_signed_config(domain: &str) -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_SNI.to_string()])
        .context("generating self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("serializing key: {e}"))?;
    build_server_config(vec![cert_der], key_der, domain)
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    domain: &str,
) -> Result<ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS config")?;
    tls.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let qc = QuicServerConfig::try_from(tls).context("building QUIC server config")?;
    let mut config = ServerConfig::with_crypto(Arc::new(qc));

    let mut transport = quinn::TransportConfig::default();

    // ── Idle / keepalive ──────────────────────────────────────────────────────
    transport.max_idle_timeout(Some(Duration::from_secs(300).try_into()?));
    // Use a longer keepalive to avoid flooding the ISP resolver with server-side
    // pings (client keepalives already keep the path alive every ~100ms).
    transport.keep_alive_interval(Some(Duration::from_secs(2)));

    // ── Congestion control ─────────────────────────────────────────────────
    // BBR; C code uses cwin=UINT64_MAX (no CC) which quinn doesn't expose.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // ── Window sizes ─────────────────────────────────────────────────────────
    transport.send_window(512 * 1024);
    transport.receive_window(quinn::VarInt::from_u32(512 * 1024));
    transport.stream_receive_window(quinn::VarInt::from_u32(256 * 1024));

    // ── MTU: sized so every DNS response fits in 512 bytes ────────────────
    //
    // ISP recursive resolvers commonly cap DNS UDP responses at 512 bytes
    // (the pre-EDNS limit) before relaying to clients. If a DNS TXT response
    // carrying a QUIC packet exceeds 512 bytes it is silently dropped, stalling
    // the QUIC handshake.
    //
    // The DNS response echoes back the CLIENT's query QNAME, whose wire size
    // is determined by how much QUIC data the client packs per query:
    //
    //   client_chunk  = max_quic_chunk_size(domain)          (≈ 145 bytes for t.game.et)
    //   frag_bytes    = client_chunk + 4 (FRAG_HEADER_LEN)   (≈ 149)
    //   b32_len       = ceil(frag_bytes * 8 / 5)             (≈ 239 chars)
    //   label_count   = ceil(b32_len / 63)                    (= 4 labels)
    //   subdomain_wire = label_count (length bytes) + b32_len (chars) (= 4+239 = 243)
    //   domain_wire   = sum of (1 + label.len) + 1 root       (= 11 for t.game.et)
    //   qname_wire    = subdomain_wire + domain_wire           (≈ 254 bytes!)
    //
    // DNS response overhead:
    //   12  header
    //   qname_wire  question QNAME (the big one)
    //    4  QTYPE + QCLASS
    //    2  answer name (compression pointer)
    //   10  answer TYPE+CLASS+TTL+RDLENGTH
    //   11  EDNS OPT RR
    //    1  TXT string length prefix
    //   20  safety margin
    //  ─────────────────────────────────────────────────────
    //   60 + qname_wire ≈ 314 bytes fixed → leaves 198 bytes for QUIC payload
    //
    // `initial_mtu` applies from the very first QUIC packet flight, including
    // Initial/Handshake (ServerHello, cert fragments) — this is the key.
    let tunnel_mtu: u16 = {
        // Replicate max_quic_chunk_size formula (capped at 200 bytes):
        let avail_chars = 200usize.saturating_sub(domain.len() + 1);
        let b32_max = avail_chars * 63 / 64;
        let client_chunk = (b32_max * 5 / 8).saturating_sub(4); // FRAG_HEADER_LEN = 4
        let frag_bytes = client_chunk + 4;
        // ceil(frag_bytes * 8 / 5)
        let b32_len = (frag_bytes * 8 + 4) / 5;
        // ceil(b32_len / 63)
        let label_count = (b32_len + 62) / 63;
        // wire: each label has a 1-byte length prefix
        let subdomain_wire = label_count + b32_len;
        // domain wire: each label as (len_byte + chars) + root
        let domain_wire: usize = domain.split('.')
            .map(|l| 1 + l.len())
            .sum::<usize>() + 1;
        let qname_wire = subdomain_wire + domain_wire;
        
        // Response overhead (fixed part)
        // 12 (header) + qname_wire (Question) + 4 (QTYPE/CLASS) 
        // + 2 (compressed Answer NAME) + 10 (Answer TYPE/CLASS/TTL/RDLENGTH) 
        // + 11 (EDNS0) + 1 (TXT length prefix) + 20 (safety margin)
        let overhead = 12 + qname_wire + 4 + 2 + 10 + 11 + 1 + 20;
        let available = 512usize.saturating_sub(overhead);
        (available as u16).max(60).min(250)
    };

    info!(
        domain,
        tunnel_mtu,
        "computed tunnel MTU for ISP-friendly 512-byte DNS responses"
    );

    transport.initial_mtu(tunnel_mtu);

    let mut mtu_cfg = quinn::MtuDiscoveryConfig::default();
    mtu_cfg.upper_bound(tunnel_mtu);
    transport.mtu_discovery_config(Some(mtu_cfg));

    // ── Multiplexing ─────────────────────────────────────────────────────────
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(256));

    // ── Initial RTT estimate ─────────────────────────────────────────────────
    // Set a generous initial RTT — DNS-over-ISP-resolver can be 400-800 ms.
    transport.initial_rtt(Duration::from_millis(800));

    config.transport_config(Arc::new(transport));

    Ok(config)
}



// ── Loopback socket pair ───────────────────────────────────────────────────────

/// Create two connected UDP sockets on loopback.
/// `quinn_sock` is used as quinn's UDP socket (quinn reads/writes to it).
/// `bridge_sock` is used by our bridge task to inject/extract QUIC packets.
async fn make_loopback_pair() -> Result<(std::net::UdpSocket, UdpSocket)> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    a.connect(b_addr).await?;
    b.connect(a_addr).await?;

    // Convert quinn side to std for Endpoint::new
    let a_std = a.into_std()?;
    a_std.set_nonblocking(true)?;
    Ok((a_std, b))
}

// ── DNS ↔ QUIC bridge ─────────────────────────────────────────────────────────

use std::collections::HashMap;

struct FragState {
    chunks: HashMap<u8, Vec<u8>>,
    total: u8,
    /// Instant when this fragment group was first seen — used for GC.
    created_at: std::time::Instant,
}

/// Bridge task: DNS UDP socket ↔ quinn loopback socket.
///
/// ## Architecture change (output-queue model):
///
/// PREVIOUS MODEL (broken for external resolvers):
///   DNS query arrives → saved in pending_queue → wait for quinn → respond
///   Problem: recursive resolvers time out (2-5s) waiting for quinn.
///   Problem: stale pending entries corrupt new connections on reconnect.
///
/// NEW MODEL (output-queue):
///   quinn produces QUIC packet → saved in output_queue (bounded ring buffer)
///   DNS query arrives → immediately respond with front of output_queue OR NXDOMAIN
///
///   Benefits:
///   - DNS query is ALWAYS answered instantly (resolver never times out)
///   - No persistent state between connections (reconnect just works)
///   - NXDOMAIN responses are fine: client's keepalive loop retries in 50ms
async fn run_bridge(
    dns_sock: Arc<UdpSocket>,
    bridge_sock: Arc<UdpSocket>,
    domain: String,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut dns_buf = vec![0u8; 4096];
    let mut quic_buf = vec![0u8; 65536];
    let mut reassembly: HashMap<u16, FragState> = HashMap::new();

    // Outbound QUIC packets from quinn, waiting for a DNS query to carry them.
    // Bounded to avoid unbounded growth; oldest packets dropped if full.
    // Larger queue helps with bursts of QUIC handshake packets.
    let mut output_q: VecDeque<Vec<u8>> = VecDeque::new();
    const MAX_OUTPUT_Q: usize = 64;
    /// Stale fragment reassembly entries older than this are purged.
    const FRAG_TTL_SECS: u64 = 10;

    loop {
        select! {
            _ = shutdown.recv() => {
                info!("bridge shutting down");
                break;
            }

            // --- DNS query arrived → inject QUIC payload → reply immediately ---
            result = dns_sock.recv_from(&mut dns_buf) => {
                match result {
                    Err(e) => { warn!(%e, "DNS recv_from error"); continue; }
                    Ok((n, client_addr)) => {
                        let wire = dns_buf[..n].to_vec();
                        trace_packet("dns→bridge", n, client_addr);

                        match slipstream_core::codec::decode_dns_query_frag(&wire, &domain) {
                            Err(e) => {
                                debug!(%e, %client_addr, "ignoring non-tunnel DNS query");
                                if let Ok(resp) = encode_dns_response(&wire, &[]) {
                                    let _ = dns_sock.send_to(&resp, client_addr).await;
                                }
                            }
                            Ok((frag_id, seq, total, chunk)) => {
                                // ── Stale fragment GC ─────────────────────────────
                                let now = std::time::Instant::now();
                                reassembly.retain(|_, st| {
                                    now.duration_since(st.created_at).as_secs() < FRAG_TTL_SECS
                                });

                                // ── Step 1: inject incoming QUIC data into quinn ──
                                if !chunk.is_empty() {
                                    if total == 1 {
                                        info!(
                                            %client_addr, frag_id,
                                            quic_bytes = chunk.len(),
                                            "bridge: ← QUIC single-frag from ISP resolver, injecting"
                                        );
                                        if let Err(e) = bridge_sock.send(&chunk).await {
                                            warn!(%e, "bridge: inject failed");
                                        }
                                    } else {
                                        // Multi-fragment — reassemble first
                                        info!(
                                            %client_addr, frag_id, seq, total,
                                            chunk_bytes = chunk.len(),
                                            "bridge: ← QUIC fragment from ISP resolver"
                                        );
                                        let entry = reassembly.entry(frag_id).or_insert_with(|| FragState {
                                            chunks: HashMap::new(),
                                            total,
                                            created_at: std::time::Instant::now(),
                                        });
                                        entry.chunks.insert(seq, chunk);

                                        if entry.chunks.len() == entry.total as usize {
                                            let mut assembled = Vec::new();
                                            let mut ok = true;
                                            for i in 0..entry.total {
                                                match entry.chunks.get(&i) {
                                                    Some(c) => assembled.extend_from_slice(c),
                                                    None => { ok = false; break; }
                                                }
                                            }
                                            if ok {
                                                info!(
                                                    frag_id, total,
                                                    bytes = assembled.len(),
                                                    "bridge: ← reassembled complete QUIC packet, injecting into quinn"
                                                );
                                                if let Err(e) = bridge_sock.send(&assembled).await {
                                                    warn!(%e, "bridge: inject assembled failed");
                                                }
                                            }
                                            reassembly.remove(&frag_id);
                                        } else {
                                            debug!(
                                                frag_id, seq, total,
                                                got = entry.chunks.len(),
                                                "bridge: waiting for more fragments"
                                            );
                                        }
                                    }
                                } else {
                                    debug!(%client_addr, "bridge: keepalive poll (no QUIC data)");
                                }

                                // ── Step 2: respond immediately ───────────────────
                                let quic_out = output_q.pop_front();
                                let resp_data: &[u8] = quic_out.as_deref().unwrap_or(&[]);
                                match encode_dns_response(&wire, resp_data) {
                                    Err(e) => warn!(%e, "bridge: encode response failed"),
                                    Ok(resp) => {
                                        if resp_data.is_empty() {
                                            debug!(%client_addr, "bridge: → NXDOMAIN (no queued QUIC)");
                                        } else {
                                            info!(
                                                %client_addr,
                                                quic_bytes = resp_data.len(),
                                                dns_resp_bytes = resp.len(),
                                                q_remaining = output_q.len(),
                                                "bridge: → QUIC response via DNS TXT"
                                            );
                                        }
                                        if let Err(e) = dns_sock.send_to(&resp, client_addr).await {
                                            warn!(%e, "bridge: send response failed");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // --- QUIC packet from quinn → fragment and push to output_q ---
            // quinn cannot produce Initial packets smaller than 1200 bytes.
            // We split each quinn packet into resp_chunk_size-byte pieces.
            // Each piece gets a 4-byte resp-frag header prepended:
            //   [resp_frag_id_hi, resp_frag_id_lo, seq, total]
            // The client bridge reads this header, buffers fragments, and
            // reassembles them before injecting into its local QUIC loopback.
            result = bridge_sock.recv(&mut quic_buf) => {
                match result {
                    Err(e) => { warn!(%e, "bridge: QUIC recv error"); continue; }
                    Ok(n) => {
                        let quic_packet = quic_buf[..n].to_vec();
                        let total_bytes = quic_packet.len();
                        let resp_frag_id: u16 = rand::thread_rng().gen();
                        let chunks: Vec<&[u8]> = quic_packet.chunks(resp_chunk_size).collect();
                        let total_frags = chunks.len().min(255) as u8;

                        for (seq, chunk) in chunks.iter().enumerate() {
                            if seq >= 255 { break; }
                            let mut item = Vec::with_capacity(4 + chunk.len());
                            item.extend_from_slice(&resp_frag_id.to_be_bytes());
                            item.push(seq as u8);
                            item.push(total_frags);
                            item.extend_from_slice(chunk);
                            if output_q.len() >= MAX_OUTPUT_Q {
                                output_q.pop_front();
                                warn!(q_len = MAX_OUTPUT_Q, "bridge: output_q overflow, dropped oldest chunk");
                            }
                            output_q.push_back(item);
                        }

                        info!(
                            q_len = output_q.len(),
                            quic_bytes = total_bytes,
                            chunks = total_frags,
                            "bridge: ← quinn packet split into {} DNS chunks", total_frags
                        );
                    }
                }
            }
        }
    }
}



fn trace_packet(dir: &str, n: usize, addr: SocketAddr) {
    tracing::trace!(direction = dir, bytes = n, %addr, "packet");
}

// ── Per-connection handler ─────────────────────────────────────────────────────

/// Accept QUIC streams from a connection and proxy each to TCP upstream.
async fn handle_connection(conn: quinn::Connection, target_addr: SocketAddr) {
    info!(remote = %conn.remote_address(), "new QUIC connection");

    loop {
        match conn.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                info!(remote = %conn.remote_address(), "connection closed");
                return;
            }
            Err(e) => {
                warn!(%e, remote = %conn.remote_address(), "connection error");
                return;
            }
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(e) = proxy_stream(send, recv, target_addr).await {
                        debug!(%e, "stream closed with error");
                    }
                });
            }
        }
    }
}

/// Bidirectional proxy between a QUIC stream and a TCP upstream socket.
async fn proxy_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    target_addr: SocketAddr,
) -> Result<()> {
    let tcp = TcpStream::connect(target_addr)
        .await
        .with_context(|| format!("connecting to upstream {}", target_addr))?;
    debug!(%target_addr, "upstream TCP connected");

    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    let q2t = tokio::spawn(async move {
        let r = tokio::io::copy(&mut quic_recv, &mut tcp_tx).await;
        let _ = tcp_tx.shutdown().await;
        r
    });

    let t2q = tokio::spawn(async move {
        let r = tokio::io::copy(&mut tcp_rx, &mut quic_send).await;
        let _ = quic_send.finish();
        r
    });

    let (r1, r2) = tokio::join!(q2t, t2q);
    if let Ok(Err(e)) = r1 { debug!(%e, "quic→tcp ended"); }
    if let Ok(Err(e)) = r2 { debug!(%e, "tcp→quic ended"); }
    Ok(())
}

// ── Main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    // Resolve target
    let target_addr: SocketAddr = tokio::net::lookup_host(&args.target_address)
        .await
        .with_context(|| format!("resolving '{}'", args.target_address))?
        .next()
        .with_context(|| format!("no address for '{}'", args.target_address))?;

    info!(
        dns_port = args.dns_listen_port,
        target = %target_addr,
        domain = %args.domain,
        "slipstream-server starting"
    );

    // TLS config
    let server_config = if args.self_signed {
        info!("using auto-generated self-signed certificate");
        self_signed_config(&args.domain)?
    } else {
        match load_tls_config(&args.cert, &args.key, &args.domain) {
            Ok(c) => c,
            Err(e) => {
                warn!(%e, "cert/key load failed, falling back to self-signed");
                self_signed_config(&args.domain)?
            }
        }
    };

    // DNS UDP socket
    let dns_bind: SocketAddr = if args.dns_listen_ipv6 {
        format!("[::]:{}", args.dns_listen_port).parse()?
    } else {
        format!("0.0.0.0:{}", args.dns_listen_port).parse()?
    };

    let dns_sock = bind_reuse(dns_bind).await?;
    let dns_sock = Arc::new(dns_sock);
    info!(%dns_bind, "DNS UDP socket bound");

    // Quinn loopback pair
    let (quinn_std_sock, bridge_tokio_sock) = make_loopback_pair().await?;
    let bridge_sock = Arc::new(bridge_tokio_sock);

    // Quinn endpoint (server)
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        quinn_std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    info!("QUIC endpoint ready");

    // Shutdown broadcast
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(4);

    // Spawn bridge task
    {
        let dns_sock = Arc::clone(&dns_sock);
        let bridge_sock = Arc::clone(&bridge_sock);
        let domain = args.domain.clone();
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_bridge(dns_sock, bridge_sock, domain, rx).await;
        });
    }

    // Accept QUIC connections
    let endpoint_clone = endpoint.clone();
    let mut shutdown_rx_accept = shutdown_tx.subscribe();
    tokio::spawn(async move {
        loop {
            select! {
                _ = shutdown_rx_accept.recv() => {
                    info!("accept loop: shutdown");
                    break;
                }
                incoming = endpoint_clone.accept() => {
                    match incoming {
                        None => { info!("endpoint closed"); break; }
                        Some(inc) => {
                            match inc.await {
                                Ok(conn) => {
                                    tokio::spawn(handle_connection(conn, target_addr));
                                }
                                Err(e) => warn!(%e, "failed to accept QUIC connection"),
                            }
                        }
                    }
                }
            }
        }
    });

    // Wait for shutdown
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    info!("shutting down");
    let _ = shutdown_tx.send(());
    endpoint.close(0u32.into(), b"server shutdown");
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}

// ── Socket binding with SO_REUSEADDR ──────────────────────────────────────────

async fn bind_reuse(addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}
