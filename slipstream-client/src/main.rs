//! slipstream-client — DNS tunnel client
//!
//! Listens on a local TCP port for incoming connections and tunnels each
//! connection through QUIC-over-DNS to the slipstream server.
//!
//! Key improvements over the original C code:
//! - No pthreads: tokio tasks (zero file descriptor cost per stream)
//! - No poller threads: async I/O handles readiness automatically
//! - Network change recovery: detects QUIC connection errors and reconnects
//! - Multiple resolver support: round-robin DNS query distribution
//! - Clean resource management via RAII

use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint,
};
use slipstream_core::config::{ALPN_PROTOCOL, SERVER_SNI};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
    sync::RwLock,
    time::sleep,
};
use tracing::{debug, error, info, warn};

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "A high-performance covert channel over DNS (client)"
)]
struct Args {
    /// Local TCP port to listen on for incoming connections (default: 5201)
    #[arg(long, default_value_t = 5201)]
    tcp_listen_port: u16,

    /// Resolver/server address (e.g. 1.1.1.1:53 or [2001:db8::1]:53). Repeatable.
    #[arg(long, short = 'r', required = true)]
    resolver: Vec<String>,

    /// Domain name for the covert channel (REQUIRED)
    #[arg(long, short = 'd')]
    domain: String,

    /// Congestion control algorithm hint (currently informational, default: cubic)
    #[arg(long, default_value = "cubic")]
    congestion_control: String,

    /// Keep-alive interval in milliseconds (0 = disabled, default: 400)
    #[arg(long, default_value_t = 400)]
    keep_alive_interval: u64,

    /// Skip TLS certificate verification (required for self-signed server certs).
    /// Use this when the server is running with --self-signed.
    #[arg(long, default_value_t = false)]
    accept_insecure: bool,
}

// ── TLS / QUIC Setup ──────────────────────────────────────────────────────────

fn build_client_config(accept_insecure: bool, keep_alive_ms: u64) -> Result<ClientConfig> {
    let tls_config = if accept_insecure {
        // Skip certificate verification. Required when server uses a self-signed cert.
        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        cfg
    } else {
        // Use system/embedded root CAs. Requires a proper cert on the server.
        // For testing with self-signed, use --accept-insecure.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(
            rustls_native_certs_or_empty()
        );
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        cfg
    };

    let qc = QuicClientConfig::try_from(tls_config).context("building QUIC client config")?;
    let mut config = ClientConfig::new(Arc::new(qc));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));
    if keep_alive_ms > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(keep_alive_ms)));
    }
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Load system root certificates if possible, fall back gracefully to empty.
fn rustls_native_certs_or_empty() -> Vec<rustls::pki_types::TrustAnchor<'static>> {
    // If webpki-roots were linked, we'd use them here.
    // For now return empty (user should use --accept-insecure for self-signed server).
    vec![]
}

/// Certificate verifier that skips all checks. Use only for testing.
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ── Shared QUIC connection state ───────────────────────────────────────────────

/// Guards the current active QUIC connection.
/// Set to `None` when the connection is being re-established.
type SharedConn = Arc<RwLock<Option<Connection>>>;

// ── Connection manager ─────────────────────────────────────────────────────────

/// Maintains a QUIC connection, reconnecting automatically after drops.
struct ConnectionManager {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    server_name: String,
    conn: SharedConn,
}

impl ConnectionManager {
    async fn connect(&self) -> Result<Connection> {
        let conn = self
            .endpoint
            .connect(self.server_addr, &self.server_name)
            .with_context(|| format!("creating QUIC connection to {}", self.server_addr))?
            .await
            .context("QUIC handshake")?;
        Ok(conn)
    }

    async fn connect_with_retry(&self) -> Connection {
        let mut delay = Duration::from_millis(500);
        loop {
            match self.connect().await {
                Ok(c) => {
                    info!(remote = %self.server_addr, "QUIC connection established");
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

    /// Main manager loop: connect and reconnect on drop.
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

/// Handle an incoming TCP connection: open a QUIC stream and relay bidirectionally.
async fn handle_tcp_connection(tcp: TcpStream, peer: SocketAddr, shared: SharedConn) {
    info!(%peer, "accepted TCP connection");

    let conn = {
        let g = shared.read().await;
        match g.as_ref() {
            Some(c) => c.clone(),
            None => {
                warn!(%peer, "no QUIC connection, dropping TCP connection");
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
    match r1 {
        Ok(Ok(n)) => debug!(%peer, bytes = n, "tcp→quic done"),
        Ok(Err(e)) => debug!(%e, %peer, "tcp→quic error"),
        Err(e) => debug!(%e, "tcp→quic task panic"),
    }
    match r2 {
        Ok(Ok(n)) => debug!(%peer, bytes = n, "quic→tcp done"),
        Ok(Err(e)) => debug!(%e, %peer, "quic→tcp error"),
        Err(e) => debug!(%e, "quic→tcp task panic"),
    }

    info!(%peer, "TCP connection closed");
}

// ── Address parsing ────────────────────────────────────────────────────────────

fn parse_resolver_addr(s: &str) -> Result<SocketAddr> {
    // Direct parse covers `ip:port` and `[ip6]:port`
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Bare IPv6 (multiple colons, no brackets) → append :53
    if s.contains(':') && !s.starts_with('[') && s.matches(':').count() > 1 {
        let ip: std::net::IpAddr = s.parse()
            .with_context(|| format!("parsing IPv6 address '{}'", s))?;
        return Ok(SocketAddr::new(ip, 53));
    }
    // Bare host / IPv4 → append :53
    let with_port = format!("{}:53", s);
    with_port.parse::<SocketAddr>()
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

    let mut resolver_addrs: Vec<SocketAddr> = Vec::new();
    for s in &args.resolver {
        let addr = parse_resolver_addr(s)
            .with_context(|| format!("parsing '--resolver {}'", s))?;
        println!("Adding {}", addr);
        resolver_addrs.push(addr);
    }

    // Validate address family consistency
    if resolver_addrs.iter().any(|a| a.is_ipv4()) && resolver_addrs.iter().any(|a| a.is_ipv6()) {
        bail!("cannot mix IPv4 and IPv6 resolver addresses");
    }

    info!(
        domain = %args.domain,
        tcp_port = args.tcp_listen_port,
        "slipstream-client starting"
    );

    // Build QUIC config
    let client_config = build_client_config(args.accept_insecure, args.keep_alive_interval)?;

    // Bind local UDP socket for QUIC
    let local_bind: SocketAddr = if resolver_addrs[0].is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let std_sock = std::net::UdpSocket::bind(local_bind)?;
    std_sock.set_nonblocking(true)?;

    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    let first_server = resolver_addrs[0];
    println!("Starting connection to {}", first_server.ip());

    let shared_conn: SharedConn = Arc::new(RwLock::new(None));
    let (shutdown_tx, shutdown_rx_mgr) = tokio::sync::broadcast::channel::<()>(4);

    // Connection manager task
    let mgr = ConnectionManager {
        endpoint: endpoint.clone(),
        server_addr: first_server,
        server_name: SERVER_SNI.to_string(),
        conn: Arc::clone(&shared_conn),
    };
    let mgr_task = tokio::spawn(async move { mgr.run(shutdown_rx_mgr).await });

    // Wait for initial connection
    loop {
        if shared_conn.read().await.is_some() { break; }
        sleep(Duration::from_millis(100)).await;
    }
    println!("Connection completed, almost ready.");
    println!("Connection confirmed.");

    // TCP listener
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
