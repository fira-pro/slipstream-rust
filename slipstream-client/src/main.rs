//! slipstream-client — TQUIC branch
//!
//! CLI entry point. Starts the TQUIC mio event loop on a dedicated thread,
//! then accepts TCP connections and arms each with a QUIC stream.
//!
//! Usage:
//!   slipstream-client --resolver 8.8.8.8:53 --resolver 1.1.1.1:53 \
//!     --domain t.game.et --accept-insecure --tcp-listen-port 7001

mod dns_bridge;
mod handler;
mod tquic_loop;

use std::{
    net::SocketAddr,
    sync::mpsc,
};

use anyhow::{Context, Result};
use clap::Parser;
use handler::{QuicToTcp, TcpToQuic};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tquic::TlsConfig;
use tracing::{debug, info, warn};

const ALPN: &[u8] = b"slipstream";

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "slipstream-client", about = "Slipstream DNS tunnel client (TQUIC branch)")]
struct Args {
    /// DNS resolver address(es) — repeat for multipath (e.g. --resolver 8.8.8.8:53 --resolver 1.1.1.1:53)
    #[arg(long, required = true, num_args = 1..)]
    resolver: Vec<SocketAddr>,

    /// Tunnel domain (must match server)
    #[arg(long)]
    domain: String,

    /// Local TCP port to listen on for proxy clients
    #[arg(long, default_value = "7001")]
    tcp_listen_port: u16,

    /// Accept self-signed / untrusted server certificates
    #[arg(long)]
    accept_insecure: bool,

    /// QUIC keepalive interval in ms (default 200ms = QUIC protocol keepalive)
    #[arg(long, default_value = "200")]
    keep_alive_interval: u64,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── TLS ────────────────────────────────────────────────────────────────────────

fn make_client_tls(sni: &str, accept_insecure: bool) -> Result<TlsConfig> {
    let mut tls = TlsConfig::new_client_config(
        &[ALPN.to_vec()],
        false, // no early data (0-RTT)
    )
    .context("TlsConfig::new_client_config")?;

    if accept_insecure {
        tls.set_verify_peer(false);
    }
    Ok(tls)
}

// ── TCP connection handler (Tokio task) ────────────────────────────────────────

/// Handle one incoming TCP proxy connection.
/// Opens a QUIC stream via the event loop and bridges TCP↔QUIC.
async fn handle_tcp(
    tcp: TcpStream,
    peer: SocketAddr,
    tcp_tx: mpsc::SyncSender<TcpToQuic>,
) {
    info!(%peer, "TCP connection accepted");

    // Request a new QUIC stream
    let (reply_tx, reply_rx) = mpsc::sync_channel::<QuicToTcp>(128);
    if tcp_tx.send(TcpToQuic::NewStream { reply_tx: reply_tx.clone() }).is_err() {
        warn!(%peer, "TQUIC event loop gone");
        return;
    }

    // Wait for connection confirmation and stream_id
    let stream_id = match reply_rx.recv() {
        Ok(QuicToTcp::Connected) => {
            // Connection is ready — we'll get the stream_id from the loop
            // For now, block until data or the event loop assigns a stream
            // In a full impl, the event loop sends the stream_id back here
            0u64 // placeholder
        }
        Ok(QuicToTcp::Disconnected) | Err(_) => {
            warn!(%peer, "QUIC not connected");
            return;
        }
        _ => 0,
    };

    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let tcp_tx2 = tcp_tx.clone();

    // TCP→QUIC task
    let t2q = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => {
                    debug!(%peer, stream_id, "TCP EOF → QUIC FIN");
                    let _ = tcp_tx2.send(TcpToQuic::Fin { stream_id });
                    break;
                }
                Ok(n) => {
                    if tcp_tx2
                        .send(TcpToQuic::Data {
                            stream_id,
                            data: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    debug!(%peer, stream_id, %e, "TCP read error → QUIC RESET");
                    let _ = tcp_tx2.send(TcpToQuic::Reset { stream_id });
                    break;
                }
            }
        }
    });

    // QUIC→TCP: drain reply_rx
    let q2t = tokio::spawn(async move {
        // We use a blocking thread to read from the sync channel
        // and forward data to the async tcp writer.
        // In a production impl, this would use tokio::sync::mpsc.
        // For this PoC we use std::sync::mpsc with blocking recv in a spawn_blocking.
        loop {
            let msg = tokio::task::spawn_blocking({
                let rx = reply_tx.clone(); // workaround: can't move reply_rx across tasks easily
                // NOTE: this is a design simplification — in a full impl we'd use
                // tokio::sync::mpsc::channel for the reply channel.
                move || None::<QuicToTcp>
            })
            .await;
            // Simplified — real impl drains reply_rx
            break;
        }
    });

    let _ = tokio::join!(t2q, q2t);
    info!(%peer, "TCP connection closed");
}

// ── Main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap()),
        )
        .init();

    info!(
        resolvers = ?args.resolver,
        domain = %args.domain,
        tcp_port = args.tcp_listen_port,
        "slipstream-client (TQUIC branch) starting"
    );

    let sni = args.domain.clone(); // use domain as TLS SNI
    let tls_config = make_client_tls(&sni, args.accept_insecure)?;

    // Channels between Tokio and the TQUIC thread
    let (tcp_tx, tcp_rx): (mpsc::SyncSender<TcpToQuic>, mpsc::Receiver<TcpToQuic>) =
        mpsc::sync_channel(1024);
    let (ctrl_tx, ctrl_rx): (mpsc::SyncSender<QuicToTcp>, mpsc::Receiver<QuicToTcp>) =
        mpsc::sync_channel(64);

    // Launch TQUIC event loop thread
    let loop_args = tquic_loop::LoopArgs {
        resolvers: args.resolver.clone(),
        server_sni: sni.clone(),
        domain: args.domain.clone(),
        tls_config,
        tcp_rx,
        ctrl_tx,
    };
    std::thread::spawn(move || {
        if let Err(e) = tquic_loop::run(loop_args) {
            tracing::error!(%e, "TQUIC event loop crashed");
            std::process::exit(1);
        }
    });

    // Wait for initial connection
    info!("waiting for QUIC connection...");
    match ctrl_rx.recv() {
        Ok(QuicToTcp::Connected) => info!("QUIC connection established!"),
        Ok(QuicToTcp::Disconnected) | Err(_) => {
            anyhow::bail!("QUIC connection failed before first connect");
        }
        _ => {}
    }

    // TCP listener
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", args.tcp_listen_port)
        .parse()
        .unwrap();
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding TCP on {listen_addr}"))?;
    info!(%listen_addr, "TCP proxy listening");

    // Accept loop
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let tx = tcp_tx.clone();
                tokio::spawn(handle_tcp(tcp, peer, tx));
            }
            Err(e) => warn!(%e, "TCP accept error"),
        }
    }
}
