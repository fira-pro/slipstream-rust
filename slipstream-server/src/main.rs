//! slipstream-server — TQUIC branch
//!
//! CLI entry point. Starts the TQUIC mio event loop on a dedicated thread,
//! then serves TCP proxy connections from the target side.
//!
//! Architecture:
//!   - Main thread: CLI parsing, TLS setup, channel creation
//!   - TQUIC thread: mio event loop drives DNS ↔ QUIC bridge
//!   - TCP forwarder threads: one per active QUIC stream, forward TCP↔QUIC

mod dns_bridge;
mod handler;
mod tquic_loop;

use std::{net::SocketAddr, sync::mpsc, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use handler::{TcpTx, TcpRx};
use tquic::TlsConfig;
use tracing::info;

const ALPN: &[u8] = b"slipstream";

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "slipstream-server", about = "Slipstream DNS tunnel server (TQUIC branch)")]
struct Args {
    /// Domain name for the DNS tunnel (e.g. t.game.et)
    #[arg(long, default_value = "tunnel.example.com")]
    domain: String,

    /// Address:port to listen for DNS queries on
    #[arg(long, default_value = "0.0.0.0:53")]
    dns_listen: SocketAddr,

    /// Upstream TCP target to proxy to (e.g. SOCKS5 server or direct target)
    #[arg(long, default_value = "127.0.0.1:1080")]
    upstream: SocketAddr,

    /// TLS certificate PEM file (optional, uses self-signed if omitted)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key PEM file (optional, uses self-signed if omitted)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Force self-signed certificate even if cert/key are provided
    #[arg(long)]
    self_signed: bool,

    /// DNS listen port override (convenience, overrides --dns-listen port)
    #[arg(long)]
    dns_listen_port: Option<u16>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── TLS helpers ────────────────────────────────────────────────────────────────

fn make_tls_config_self_signed(domain: &str) -> Result<TlsConfig> {
    // Generate a self-signed cert using rcgen
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string(), "localhost".to_string()])
        .context("generating self-signed cert")?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let mut tls = TlsConfig::new_server_config(
        &[ALPN.to_vec()],
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        false, // disable client auth
    )
    .context("TlsConfig::new_server_config")?;
    Ok(tls)
}

fn make_tls_config_from_files(cert_path: &PathBuf, key_path: &PathBuf) -> Result<TlsConfig> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {:?}", cert_path))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading key {:?}", key_path))?;

    TlsConfig::new_server_config(
        &[ALPN.to_vec()],
        &cert_pem,
        &key_pem,
        false,
    )
    .context("TlsConfig::new_server_config")
}

// ── Main ───────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap()),
        )
        .init();

    let mut dns_listen = args.dns_listen;
    if let Some(port) = args.dns_listen_port {
        dns_listen.set_port(port);
    }

    info!(
        %dns_listen,
        upstream = %args.upstream,
        domain = %args.domain,
        "slipstream-server (TQUIC branch) starting"
    );

    // Build TLS config
    let tls_config = if args.self_signed || (args.cert.is_none() && args.key.is_none()) {
        info!("using auto-generated self-signed certificate");
        make_tls_config_self_signed(&args.domain)?
    } else {
        let cert = args.cert.as_ref().context("--cert required")?;
        let key = args.key.as_ref().context("--key required")?;
        make_tls_config_from_files(cert, key).unwrap_or_else(|e| {
            tracing::warn!(%e, "cert/key load failed, falling back to self-signed");
            make_tls_config_self_signed(&args.domain).expect("self-signed fallback failed")
        })
    };

    // Channel: TCP forwarder threads → TQUIC event loop (tcp data / FIN)
    let (tcp_tx, tcp_rx): (TcpTx, TcpRx) = mpsc::sync_channel(1024);

    // Launch TQUIC event loop on a dedicated thread
    let domain = args.domain.clone();
    let upstream = args.upstream;
    std::thread::spawn(move || {
        if let Err(e) = tquic_loop::run(dns_listen, upstream, domain, tls_config, tcp_tx, tcp_rx) {
            tracing::error!(%e, "TQUIC event loop crashed");
            std::process::exit(1);
        }
    });

    // Block the main thread (the TQUIC loop thread is the real workhorse)
    // In future: add Ctrl-C signal handler here.
    info!("server running — press Ctrl-C to stop");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
