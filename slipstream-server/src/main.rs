//! slipstream-server — TQUIC branch

mod dns_bridge;
mod handler;
mod tquic_loop;

use std::{net::SocketAddr, path::PathBuf, sync::mpsc};

use anyhow::{Context, Result};
use clap::Parser;
use handler::{TcpRx, TcpTx};
use tquic::TlsConfig;
use tracing::info;

const ALPN: &[u8] = b"slipstream";

#[derive(Parser, Debug)]
#[command(name = "slipstream-server", about = "Slipstream DNS tunnel server (TQUIC branch)")]
struct Args {
    #[arg(long, default_value = "tunnel.example.com")]
    domain: String,

    #[arg(long, default_value = "0.0.0.0:53")]
    dns_listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:1080")]
    upstream: SocketAddr,

    #[arg(long)]
    cert: Option<PathBuf>,

    #[arg(long)]
    key: Option<PathBuf>,

    #[arg(long)]
    self_signed: bool,

    /// Override just the port of --dns-listen
    #[arg(long)]
    dns_listen_port: Option<u16>,

    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── TLS helpers ────────────────────────────────────────────────────────────────
// TlsConfig::new_server_config(cert_pem: &str, key_pem: &str, alpn: Vec<Vec<u8>>, verify_client: bool)

fn make_tls_self_signed(domain: &str) -> Result<TlsConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![
        domain.to_string(),
        "localhost".to_string(),
    ])
    .context("generating self-signed cert")?;

    let cert_pem = cert.cert.pem();
    let key_pem  = cert.key_pair.serialize_pem();

    TlsConfig::new_server_config(
        &cert_pem,
        &key_pem,
        vec![ALPN.to_vec()],
        false, // no client auth
    )
    .context("TlsConfig::new_server_config (self-signed)")
}

fn make_tls_from_files(cert_path: &PathBuf, key_path: &PathBuf) -> Result<TlsConfig> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading cert {cert_path:?}"))?;
    let key_pem  = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading key {key_path:?}"))?;

    TlsConfig::new_server_config(
        &cert_pem,
        &key_pem,
        vec![ALPN.to_vec()],
        false,
    )
    .context("TlsConfig::new_server_config (from files)")
}

// ── Main ───────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

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

    info!(%dns_listen, upstream = %args.upstream, domain = %args.domain,
          "slipstream-server (TQUIC branch) starting");

    let tls_config = if args.self_signed || (args.cert.is_none() && args.key.is_none()) {
        info!("using auto-generated self-signed certificate");
        make_tls_self_signed(&args.domain)?
    } else {
        let cert = args.cert.as_ref().context("--cert required")?;
        let key  = args.key.as_ref().context("--key required")?;
        make_tls_from_files(cert, key).unwrap_or_else(|e| {
            tracing::warn!(%e, "cert/key load failed, falling back to self-signed");
            make_tls_self_signed(&args.domain).expect("self-signed fallback failed")
        })
    };

    let (tcp_tx, tcp_rx): (TcpTx, TcpRx) = mpsc::sync_channel(1024);

    let domain   = args.domain.clone();
    let upstream = args.upstream;
    std::thread::spawn(move || {
        if let Err(e) = tquic_loop::run(dns_listen, upstream, domain, tls_config, tcp_tx, tcp_rx) {
            tracing::error!(%e, "TQUIC event loop crashed");
            std::process::exit(1);
        }
    });

    info!("server running — press Ctrl-C to stop");
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}
