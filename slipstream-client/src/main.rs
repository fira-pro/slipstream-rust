//! slipstream-client — DNS tunnel client
//!
//! Architecture:
//!   1. A loopback socket pair bridges quinn ↔ a DNS bridge task.
//!   2. The DNS bridge task reads raw QUIC from quinn (via loopback),
//!      encodes it as DNS TXT queries, and sends to the server's DNS port.
//!   3. The bridge receives DNS responses, decodes them to raw QUIC,
//!      and injects them back to quinn via the loopback.
//!   4. Quinn sees a stable "server" address = the loopback bridge address.
//!   5. TCP connections are accepted locally and relayed over QUIC streams.
//!
//! This mirrors the server's exact architecture (loopback + bridge), fixing the
//! original bug where the client sent raw QUIC directly to the DNS port.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint};
use slipstream_core::{
    codec::{decode_dns_response, encode_dns_queries, encode_dns_query},
    config::{ALPN_PROTOCOL, SERVER_SNI},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    select,
    sync::RwLock,
    time::{sleep, interval},
};
use tracing::{debug, error, info, warn};
use rand::Rng;

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "A high-performance covert channel over DNS (client)"
)]
struct Args {
    /// Local TCP port for incoming connections (default: 5201)
    #[arg(long, default_value_t = 5201)]
    tcp_listen_port: u16,

    /// DNS server/resolver address (e.g. 1.1.1.1:53). Repeatable.
    #[arg(long, short = 'r', required = true)]
    resolver: Vec<String>,

    /// Domain name for the tunnel (REQUIRED)
    #[arg(long, short = 'd')]
    domain: String,

    /// Keep-alive interval in milliseconds (0 = disabled, default: 400)
    #[arg(long, default_value_t = 400)]
    keep_alive_interval: u64,

    /// Skip TLS certificate verification (required for --self-signed server)
    #[arg(long, default_value_t = false)]
    accept_insecure: bool,
}

// ── TLS/QUIC config ────────────────────────────────────────────────────────────

fn build_client_config(accept_insecure: bool, keep_alive_ms: u64) -> Result<ClientConfig> {
    let tls = if accept_insecure {
        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        cfg
    } else {
        let root_store = rustls::RootCertStore::empty();
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        cfg
    };

    let qc = QuicClientConfig::try_from(tls).context("building QUIC client config")?;
    let mut config = ClientConfig::new(Arc::new(qc));

    let mut transport = quinn::TransportConfig::default();

    // ── Idle / keepalive ──────────────────────────────────────────────────────
    transport.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
    if keep_alive_ms > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(keep_alive_ms)));
    }

    // ── Congestion control ───────────────────────────────────────────────────
    // BBR probes for bandwidth and RTT rather than reacting to loss signals.
    // DNS tunnels see a lot of "loss" that is actually NXDOMAIN responses
    // or resolver deduplication — BBR handles this far better than NewReno.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // ── Window sizes ─────────────────────────────────────────────────────────
    transport.send_window(8 * 1024 * 1024);                               // 8 MB
    transport.receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));   // 8 MB
    transport.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024)); // 4 MB per stream

    // ── MTU discovery ────────────────────────────────────────────────────────
    // DNS path MTU is fixed by our encoding (~512 bytes per query).
    // PMTUD probes will always appear to fail — disable them.
    transport.mtu_discovery_config(None);

    // ── Multiplexing ─────────────────────────────────────────────────────────
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(256));

    // ── Initial RTT estimate ──────────────────────────────────────────────────
    // Start with a realistic guess for DNS tunnel latency (resolver + auth server).
    // This avoids QUIC being overly conservative in the first few seconds.
    transport.initial_rtt(Duration::from_millis(400));

    config.transport_config(Arc::new(transport));

    Ok(config)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dh_params: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dh_params: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

// ── DNS bridge (client side) ───────────────────────────────────────────────────

/// Client DNS bridge: mirrors the server's run_bridge, but in reverse.
///
/// ## QUIC → DNS (outgoing):
///   - Reads raw QUIC packet from `bridge_loopback_sock` (sent there by quinn).
///   - Encodes as a DNS TXT query.
///   - Sends to the real DNS server via `dns_sock`.
///
/// ## DNS → QUIC (incoming):
///   - Receives DNS response on `dns_sock`.
///   - Decodes to raw QUIC packet.
///   - Injects back into quinn via `bridge_loopback_sock`.
async fn run_client_bridge(
    bridge_loopback_sock: Arc<UdpSocket>,
    dns_sock: Arc<UdpSocket>,
    domain: String,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut quic_buf = vec![0u8; 65536];
    let mut dns_buf = vec![0u8; 4096];

    loop {
        select! {
            _ = shutdown.recv() => {
                info!("client bridge: shutting down");
                break;
            }

            // QUIC → DNS (quinn sent a packet to bridge_loopback_sock)
            result = bridge_loopback_sock.recv(&mut quic_buf) => {
                match result {
                    Err(e) => { warn!(%e, "bridge: loopback recv error"); continue; }
                    Ok(n) => {
                        tracing::trace!(bytes = n, "client bridge: QUIC → DNS");
                        match encode_dns_queries(&quic_buf[..n], &domain) {
                            Err(e) => warn!(%e, "bridge: encode_dns_queries failed"),
                            Ok(queries) => {
                                for query in &queries {
                                    if let Err(e) = dns_sock.send(query).await {
                                        warn!(%e, "bridge: dns_sock send failed");
                                        break;
                                    }
                                }
                                if queries.len() > 1 {
                                    tracing::trace!(frags = queries.len(), "bridge: sent fragmented QUIC packet");
                                }
                            }
                        }
                    }
                }
            }

            // DNS → QUIC (got a DNS response from the server)
            result = dns_sock.recv(&mut dns_buf) => {
                match result {
                    Err(e) => { warn!(%e, "bridge: dns_sock recv error"); continue; }
                    Ok(n) => {
                        tracing::trace!(bytes = n, "client bridge: DNS → QUIC");
                        match decode_dns_response(&dns_buf[..n]) {
                            Err(e) => { debug!(%e, "bridge: decode_dns_response failed"); }
                            Ok(None) => { debug!("bridge: empty/NXDOMAIN response (server has no data)"); }
                            Ok(Some(quic_data)) => {
                                if let Err(e) = bridge_loopback_sock.send(&quic_data).await {
                                    warn!(%e, "bridge: loopback inject failed");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Keepalive polling ─────────────────────────────────────────────────────────

/// Periodically send empty DNS queries to the server.
/// Each empty query adds one slot to the server's pending_queue, giving it
/// space to push QUIC handshake/data packets back to us without waiting for
/// our next real QUIC query. This is essential over high-latency links.
async fn run_keepalive(
    dns_sock: Arc<UdpSocket>,
    domain: String,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    // Send a keepalive every 20ms (50/sec). At 400ms DNS RTT this maintains
    // ~20 outstanding query slots at any moment — enough to sustain throughput
    // without hitting resolver rate limits.
    let mut tick = interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        select! {
            _ = shutdown.recv() => break,
            _ = tick.tick() => {
                // Keepalive payload: 4-byte frag header (seq=0, total=1) + 0 bytes of QUIC.
                // The server recognises empty chunk → enqueues slot, doesn't inject to quinn.
                let frag_id: u16 = rand::thread_rng().gen();
                let payload = [
                    (frag_id >> 8) as u8,
                    (frag_id & 0xFF) as u8,
                    0u8, // seq = 0
                    1u8, // total = 1
                ];
                if let Ok(q) = encode_dns_query(&payload, &domain) {
                    let _ = dns_sock.send(&q).await;
                }
            }
        }
    }
}

// ── Loopback socket pair ───────────────────────────────────────────────────────

/// Create two connected UDP sockets on loopback.
/// quinn uses the returned `std::net::UdpSocket`; our bridge uses the `UdpSocket`.
async fn make_loopback_pair() -> Result<(std::net::UdpSocket, UdpSocket)> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    a.connect(b_addr).await?;
    b.connect(a_addr).await?;

    let a_std = a.into_std()?;
    a_std.set_nonblocking(true)?;
    Ok((a_std, b))
}

// ── Shared connection ──────────────────────────────────────────────────────────

type SharedConn = Arc<RwLock<Option<Connection>>>;

// ── Connection manager ─────────────────────────────────────────────────────────

struct ConnectionManager {
    endpoint: Endpoint,
    /// Address quinn "connects" to — this is the bridge loopback address!
    bridge_addr: SocketAddr,
    conn: SharedConn,
}

impl ConnectionManager {
    async fn try_connect(&self) -> Result<Connection> {
        let conn = self
            .endpoint
            .connect(self.bridge_addr, SERVER_SNI)
            .with_context(|| format!("creating QUIC connection via bridge {}", self.bridge_addr))?
            .await
            .context("QUIC handshake")?;
        Ok(conn)
    }

    async fn connect_with_retry(&self) -> Connection {
        let mut delay = Duration::from_millis(500);
        loop {
            match self.try_connect().await {
                Ok(c) => {
                    info!("QUIC connection established (via DNS bridge)");
                    return c;
                }
                Err(e) => {
                    warn!(%e, delay_ms = delay.as_millis(), "connection failed, retrying");
                    sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    async fn run(self, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        loop {
            let conn = self.connect_with_retry().await;
            {
                let mut g = self.conn.write().await;
                *g = Some(conn.clone());
            }

            select! {
                _ = shutdown.recv() => {
                    info!("connection manager: shutdown");
                    let g = self.conn.read().await;
                    if let Some(c) = g.as_ref() {
                        c.close(0u32.into(), b"client shutdown");
                    }
                    return;
                }
                reason = conn.closed() => {
                    {
                        let mut g = self.conn.write().await;
                        *g = None;
                    }
                    match reason {
                        quinn::ConnectionError::LocallyClosed => {
                            info!("connection closed locally");
                            return;
                        }
                        e => {
                            warn!(%e, "QUIC connection dropped, reconnecting");
                        }
                    }
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
}

// ── Per-TCP-connection handler ─────────────────────────────────────────────────

async fn handle_tcp_connection(tcp: TcpStream, peer: SocketAddr, shared: SharedConn) {
    info!(%peer, "accepted TCP connection");

    let conn = {
        let g = shared.read().await;
        match g.as_ref() {
            Some(c) => c.clone(),
            None => {
                warn!(%peer, "no QUIC connection available, dropping TCP");
                return;
            }
        }
    };

    let (mut quic_send, mut quic_recv) = match conn.open_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(%e, %peer, "failed to open QUIC stream");
            return;
        }
    };
    debug!(%peer, stream = quic_send.id().index(), "QUIC stream opened");

    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    let t2q = tokio::spawn(async move {
        let r = tokio::io::copy(&mut tcp_rx, &mut quic_send).await;
        let _ = quic_send.finish();
        r
    });

    let q2t = tokio::spawn(async move {
        let r = tokio::io::copy(&mut quic_recv, &mut tcp_tx).await;
        let _ = tcp_tx.shutdown().await;
        r
    });

    let (r1, r2) = tokio::join!(t2q, q2t);
    if let Ok(Ok(n)) = r1 { debug!(%peer, bytes=n, "tcp→quic done"); }
    if let Ok(Ok(n)) = r2 { debug!(%peer, bytes=n, "quic→tcp done"); }
    info!(%peer, "TCP connection closed");
}

// ── Address parsing ────────────────────────────────────────────────────────────

fn parse_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() { return Ok(a); }
    // Bare IPv6 (multiple colons)
    if s.contains(':') && !s.starts_with('[') && s.matches(':').count() > 1 {
        let ip: std::net::IpAddr = s.parse()
            .with_context(|| format!("parsing IPv6 '{}'", s))?;
        return Ok(SocketAddr::new(ip, 53));
    }
    // Bare IPv4 / hostname → default port 53
    format!("{}:53", s).parse::<SocketAddr>()
        .with_context(|| format!("cannot parse resolver address '{}'", s))
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
    if args.resolver.is_empty() {
        bail!("at least one --resolver address is required");
    }

    // Use only first resolver for now (multi-resolver support: future work)
    let server_dns_addr = parse_addr(&args.resolver[0])
        .with_context(|| format!("parsing --resolver '{}'", args.resolver[0]))?;

    println!("Adding {}", server_dns_addr);
    info!(
        domain = %args.domain,
        tcp_port = args.tcp_listen_port,
        server = %server_dns_addr,
        "slipstream-client starting"
    );

    // ── Loopback pair: quinn_sock ↔ bridge_loopback_sock ──────────────────────
    // quinn uses quinn_std_sock (one end).
    // bridge_loopback_sock (the other end) is what the bridge task uses to
    // inject/extract raw QUIC packets on quinn's behalf.
    let (quinn_std_sock, bridge_loopback_sock) = make_loopback_pair().await?;
    let bridge_addr = bridge_loopback_sock.local_addr()?;
    let bridge_loopback_sock = Arc::new(bridge_loopback_sock);

    // ── DNS UDP socket: bridge ↔ slipstream server ────────────────────────────
    let local_bind: SocketAddr = if server_dns_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let dns_sock = UdpSocket::bind(local_bind).await?;
    dns_sock.connect(server_dns_addr).await?;
    let dns_sock = Arc::new(dns_sock);

    // ── Quinn endpoint ────────────────────────────────────────────────────────
    let client_config = build_client_config(args.accept_insecure, args.keep_alive_interval)?;
    quinn_std_sock.set_nonblocking(true)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        quinn_std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    // ── Shutdown channel ──────────────────────────────────────────────────────
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(4);

    // ── Spawn DNS bridge task ─────────────────────────────────────────────────
    {
        let blsock = Arc::clone(&bridge_loopback_sock);
        let dsock = Arc::clone(&dns_sock);
        let domain = args.domain.clone();
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_client_bridge(blsock, dsock, domain, rx).await;
        });
    }

    // ── Spawn keepalive polling task ──────────────────────────────────────────
    {
        let dsock = Arc::clone(&dns_sock);
        let domain = args.domain.clone();
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_keepalive(dsock, domain, rx).await;
        });
    }

    // ── Connection manager: QUIC connects to bridge_addr (loopback) ──────────
    println!("Starting connection to {} (via DNS bridge)", server_dns_addr.ip());
    let shared_conn: SharedConn = Arc::new(RwLock::new(None));
    let mgr = ConnectionManager {
        endpoint: endpoint.clone(),
        bridge_addr,     // <-- loopback addr, NOT the real server addr
        conn: Arc::clone(&shared_conn),
    };
    let shutdown_tx_mgr = shutdown_tx.clone();
    let mgr_task = tokio::spawn(async move { mgr.run(shutdown_tx_mgr.subscribe()).await });

    // Wait for initial connection
    loop {
        if shared_conn.read().await.is_some() { break; }
        // Check if connection manager failed (e.g. can't reach server at all)
        sleep(Duration::from_millis(100)).await;
    }
    println!("Connection established.");

    // ── TCP listener ──────────────────────────────────────────────────────────
    let listen_addr: SocketAddr = format!("0.0.0.0:{}", args.tcp_listen_port).parse()?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding TCP on {}", listen_addr))?;
    println!("Listening on port {}...", args.tcp_listen_port);
    info!(%listen_addr, "TCP listener ready");

    let mut shutdown_accept = shutdown_tx.subscribe();

    loop {
        select! {
            result = listener.accept() => {
                match result {
                    Ok((tcp, peer)) => {
                        let conn = Arc::clone(&shared_conn);
                        tokio::spawn(handle_tcp_connection(tcp, peer, conn));
                    }
                    Err(e) => {
                        error!(%e, "TCP accept error");
                        sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = shutdown_accept.recv() => {
                info!("accept loop: shutdown");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down");
                let _ = shutdown_tx.send(());
                break;
            }
        }
    }

    endpoint.close(0u32.into(), b"client shutdown");
    let _ = mgr_task.await;
    info!("client exited");
    Ok(())
}
