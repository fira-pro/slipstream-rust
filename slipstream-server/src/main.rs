//! slipstream-server — TQUIC branch

mod dns_bridge;
mod handler;
mod tquic_loop;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use handler::{TcpRx, TcpTx};
use tquic::{CongestionControlAlgorithm, TlsConfig};
use tracing::info;

const ALPN: &[u8] = b"slipstream";

/// Congestion-control algorithm (CLI value)
#[derive(Clone, Debug, ValueEnum)]
pub enum CcArg {
    Copa,
    Bbr,
    Cubic,
}

impl From<CcArg> for CongestionControlAlgorithm {
    fn from(v: CcArg) -> Self {
        match v {
            CcArg::Copa  => CongestionControlAlgorithm::Copa,
            CcArg::Bbr   => CongestionControlAlgorithm::Bbr,
            CcArg::Cubic => CongestionControlAlgorithm::Cubic,
        }
    }
}

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

    /// Congestion-control algorithm: copa, bbr, cubic
    #[arg(long, default_value = "copa")]
    cc: CcArg,

    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── TLS helpers ────────────────────────────────────────────────────────────────

fn make_tls_self_signed(domain: &str) -> Result<TlsConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![
        domain.to_string(),
        "localhost".to_string(),
    ])
    .context("generating self-signed cert")?;

    let cert_path = format!("/tmp/slipstream-cert-{}.pem", std::process::id());
    let key_path  = format!("/tmp/slipstream-key-{}.pem",  std::process::id());

    std::fs::write(&cert_path, cert.cert.pem())
        .with_context(|| format!("writing cert to {cert_path}"))?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())
        .with_context(|| format!("writing key to {key_path}"))?;

    TlsConfig::new_server_config(
        &cert_path,
        &key_path,
        vec![ALPN.to_vec()],
        false,
    )
    .context("TlsConfig::new_server_config (self-signed)")
}

fn make_tls_from_files(cert_path: &PathBuf, key_path: &PathBuf) -> Result<TlsConfig> {
    TlsConfig::new_server_config(
        cert_path.to_str().context("cert path not UTF-8")?,
        key_path.to_str().context("key path not UTF-8")?,
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
          cc = ?args.cc, "slipstream-server (TQUIC branch) starting");

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

    let cc: CongestionControlAlgorithm = args.cc.into();

    let (tcp_tx, tcp_rx): (TcpTx, TcpRx) = std::sync::mpsc::sync_channel(1024);

    let domain   = args.domain.clone();
    let upstream = args.upstream;
    std::thread::spawn(move || {
        if let Err(e) = tquic_loop::run(dns_listen, upstream, domain, tls_config, cc, tcp_tx, tcp_rx) {
            tracing::error!(%e, "TQUIC event loop crashed");
            std::process::exit(1);
        }
    });

    info!("server running — press Ctrl-C to stop");
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}
