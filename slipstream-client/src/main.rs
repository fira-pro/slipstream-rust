//! slipstream-client — TQUIC branch

mod dns_bridge;
mod handler;
mod tquic_loop;

use std::{net::SocketAddr, sync::mpsc};

use anyhow::{Context, Result};
use clap::Parser;
use handler::{QuicToTcp, TcpToQuic};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tquic::TlsConfig;
use tracing::{info, warn};

const ALPN: &[u8] = b"slipstream";

#[derive(Parser, Debug)]
#[command(name = "slipstream-client", about = "Slipstream DNS tunnel client (TQUIC branch)")]
struct Args {
    /// DNS resolvers — repeat for multipath: --resolver 8.8.8.8:53 --resolver 1.1.1.1:53
    #[arg(long, required = true, num_args = 1..)]
    resolver: Vec<SocketAddr>,

    #[arg(long)]
    domain: String,

    #[arg(long, default_value = "7001")]
    tcp_listen_port: u16,

    #[arg(long)]
    accept_insecure: bool,

    #[arg(long, default_value = "info")]
    log_level: String,
}

fn make_client_tls(accept_insecure: bool) -> Result<TlsConfig> {
    let mut tls = TlsConfig::new_client_config(
        vec![ALPN.to_vec()],
        false,
    )
    .context("TlsConfig::new_client_config")?;

    if accept_insecure {
        tls.set_verify(false);
    }
    Ok(tls)
}

// ── Per-TCP-connection handler (Tokio task) ────────────────────────────────────

async fn handle_tcp(tcp: TcpStream, peer: SocketAddr, tcp_tx: mpsc::SyncSender<TcpToQuic>) {
    info!(%peer, "TCP connection accepted");

    // Request a QUIC bidi stream; the event loop will reply with StreamAssigned.
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<QuicToTcp>(128);
    if tcp_tx.send(TcpToQuic::NewStream { reply_tx }).is_err() {
        warn!(%peer, "TQUIC event loop gone");
        return;
    }

    // Wait for the real stream_id before piping data
    let stream_id = match reply_rx.recv().await {
        Some(QuicToTcp::StreamAssigned { stream_id }) => {
            info!(%peer, stream_id, "QUIC stream assigned");
            stream_id
        }
        _ => {
            warn!(%peer, "QUIC stream assignment failed");
            return;
        }
    };

    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let tcp_tx2 = tcp_tx.clone();

    // TCP→QUIC
    let t2q = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => {
                    let _ = tcp_tx2.send(TcpToQuic::Fin { stream_id });
                    break;
                }
                Ok(n) => {
                    if tcp_tx2
                        .send(TcpToQuic::Data { stream_id, data: buf[..n].to_vec() })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    warn!(stream_id, %e, "TCP read error");
                    let _ = tcp_tx2.send(TcpToQuic::Reset { stream_id });
                    break;
                }
            }
        }
    });

    // QUIC→TCP
    let q2t = tokio::spawn(async move {
        loop {
            match reply_rx.recv().await {
                Some(QuicToTcp::Data { data }) => {
                    if let Err(e) = tcp_w.write_all(&data).await {
                        warn!(stream_id, %e, "TCP write error");
                        break;
                    }
                }
                Some(QuicToTcp::Fin) | None => {
                    let _ = tcp_w.shutdown().await;
                    break;
                }
                Some(QuicToTcp::StreamAssigned { .. }) => {} // ignore unexpected
            }
        }
    });

    let _ = tokio::join!(t2q, q2t);
    info!(%peer, stream_id, "TCP connection closed");
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

    info!(resolvers = ?args.resolver, domain = %args.domain,
          tcp_port = args.tcp_listen_port, "slipstream-client (TQUIC branch) starting");

    let tls_config = make_client_tls(args.accept_insecure)?;

    let (tcp_tx, tcp_rx) = mpsc::sync_channel::<TcpToQuic>(1024);
    let (ctrl_tx, ctrl_rx) = mpsc::sync_channel::<()>(4);

    let loop_args = tquic_loop::LoopArgs {
        resolvers:  args.resolver.clone(),
        server_sni: args.domain.clone(),
        domain:     args.domain.clone(),
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

    info!("waiting for QUIC connection...");
    match ctrl_rx.recv() {
        Ok(()) => info!("QUIC connection established!"),
        Err(_) => anyhow::bail!("QUIC event loop exited before handshake"),
    }

    let listen_addr: SocketAddr = format!("127.0.0.1:{}", args.tcp_listen_port).parse().unwrap();
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding TCP on {listen_addr}"))?;
    info!(%listen_addr, "TCP proxy listening — connect your apps here");

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
