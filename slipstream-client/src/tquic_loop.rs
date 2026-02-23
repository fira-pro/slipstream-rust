//! Client mio event loop — drives TQUIC + multipath DNS sockets.
//!
//! One mio-registered UDP socket per resolver (0..N).
//! Outgoing QUIC packets → fragment → round-robin across resolver sockets.
//! Incoming DNS responses → reassemble → inject into TQUIC endpoint.
//! Keepalive: send empty poll queries every 20ms per resolver.

use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use tquic::{Config, Endpoint, PacketInfo, PacketSendHandler, TlsConfig,
            CongestionControlAlgorithm, MultipathAlgorithm};
use tracing::{debug, info, warn};

use crate::dns_bridge::ClientDnsBridge;
use crate::handler::{ClientHandler, QuicToTcp, TcpToQuic};

// Token layout: 0..N-1 are resolver sockets, N is the waker
fn resolver_token(idx: usize) -> Token { Token(idx) }

/// PacketSendHandler for the client: routes outgoing QUIC packets through
/// the DNS bridge (fragment into DNS queries, send to resolver sockets).
struct DnsPacketSender {
    bridge: *mut ClientDnsBridge,
    sockets: *const Vec<MioUdpSocket>,
}

unsafe impl Send for DnsPacketSender {}

impl PacketSendHandler for DnsPacketSender {
    fn on_packets_to_send(&mut self, pkts: &[tquic::PacketOutBuf]) -> tquic::Result<usize> {
        let bridge = unsafe { &mut *self.bridge };
        let sockets = unsafe { &*self.sockets };
        for pkt in pkts {
            let dispatches = bridge.encode_quic_packet(pkt.data());
            for (ri, wire) in dispatches {
                let sock = &sockets[ri % sockets.len()];
                let _ = sock.send(&wire); // non-blocking; drop if would block
            }
        }
        Ok(pkts.len())
    }
}

fn make_client_config(domain: &str, resolvers: &[SocketAddr], tls_config: TlsConfig) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    // MTU: C formula (240 - domain_len) / 1.6
    let mtu = ((240.0 - domain.len() as f64) / 1.6) as usize;
    let mtu = mtu.max(60).min(1200);
    config.set_send_udp_payload_size(mtu);
    config.set_recv_udp_payload_size(mtu as u16);
    config.enable_dplpmtud(false);

    // Multipath: enable only when more than 1 resolver is configured
    if resolvers.len() > 1 {
        config.enable_multipath(true);
        config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        info!(n = resolvers.len(), "multipath QUIC enabled");
    }

    // BBR on client (probes bandwidth, good for variable-latency DNS)
    config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr);

    // Flow control windows
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_local(256 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_streams_bidi(256);

    config.set_max_idle_timeout(300_000); // 5 min
    config.set_initial_rtt(400);          // 400ms initial RTT estimate

    config.set_tls_config(tls_config);
    Ok(config)
}

pub struct LoopArgs {
    pub resolvers: Vec<SocketAddr>,
    pub server_sni: String,
    pub domain: String,
    pub tls_config: TlsConfig,
    /// Accepts TCP-side messages: new streams, data, fin, reset
    pub tcp_rx: mpsc::Receiver<TcpToQuic>,
    /// Sends connection events back to Tokio: connected, data, fin, disconnected
    pub ctrl_tx: mpsc::SyncSender<QuicToTcp>,
}

pub fn run(args: LoopArgs) -> Result<()> {
    let n = args.resolvers.len();
    assert!(n > 0, "at least one resolver required");

    let config = make_client_config(&args.domain, &args.resolvers, args.tls_config)?;

    // Bind one mio UDP socket per resolver
    let mut sockets: Vec<MioUdpSocket> = Vec::with_capacity(n);
    for resolver in &args.resolvers {
        let local: SocketAddr = if resolver.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let std_sock = StdUdpSocket::bind(local)?;
        std_sock.set_nonblocking(true)?;
        std_sock.connect(resolver)?; // lock to this resolver
        sockets.push(MioUdpSocket::from_std(std_sock));
    }

    let mut bridge = ClientDnsBridge::new(args.domain.clone(), n);

    let sender = DnsPacketSender {
        bridge: &mut bridge as *mut ClientDnsBridge,
        sockets: &sockets as *const Vec<MioUdpSocket>,
    };

    let handler = ClientHandler::new(args.ctrl_tx.clone());
    let mut endpoint = Endpoint::new(
        Arc::new(config),
        false, // is_server
        Box::new(handler),
        Box::new(sender),
    );

    // Register all sockets with mio
    let mut poll = Poll::new()?;
    let waker_token = Token(n);
    let waker = mio::Waker::new(poll.registry(), waker_token)?;
    for (i, sock) in sockets.iter_mut().enumerate() {
        poll.registry().register(sock, resolver_token(i), Interest::READABLE)?;
    }

    // Initiate QUIC connection to the "server" (conceptually the DNS bridge endpoint)
    // TQUIC connects to a dummy address; actual routing is via DNS sockets
    let dummy_server: SocketAddr = "1.2.3.4:4444".parse().unwrap();
    let local_addr: SocketAddr = sockets[0].local_addr()?;
    let conn_id = endpoint.connect(
        local_addr,
        dummy_server,
        Some(&args.server_sni),
        None,
        None,
    ).context("endpoint.connect")?;
    info!("QUIC connection initiated (conn_id={conn_id:?})");

    let mut events = Events::with_capacity(256);
    let mut recv_buf = vec![0u8; 4096];
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_millis(20);

    loop {
        // Timeout: min(tquic timeout, keepalive interval)
        let now = Instant::now();
        let until_keepalive = keepalive_interval
            .checked_sub(now.duration_since(last_keepalive))
            .unwrap_or(Duration::ZERO);
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(until_keepalive))
            .unwrap_or(until_keepalive)
            .min(Duration::from_millis(50));

        poll.poll(&mut events, Some(timeout))?;
        endpoint.on_timeout(Instant::now());

        // 1. Read DNS responses from all resolver sockets
        for (ri, sock) in sockets.iter().enumerate() {
            loop {
                match sock.recv(&mut recv_buf) {
                    Ok(n) => {
                        if let Some(quic_pkt) = bridge.decode_dns_response(&recv_buf[..n], ri) {
                            let pkt_info = PacketInfo {
                                src: args.resolvers[ri],
                                dst: local_addr,
                                time: Instant::now(),
                            };
                            if let Err(e) = endpoint.recv(&mut quic_pkt.clone(), &pkt_info) {
                                debug!(%e, ri, "endpoint.recv error");
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!(%e, ri, "resolver socket recv error");
                        break;
                    }
                }
            }
        }

        // 2. Keepalive: send empty poll queries to each resolver
        let now = Instant::now();
        if now.duration_since(last_keepalive) >= keepalive_interval {
            last_keepalive = now;
            for ri in 0..n {
                if let Some((idx, wire)) = bridge.encode_keepalive(ri) {
                    let _ = sockets[idx].send(&wire);
                }
            }
        }

        // 3. Process TCP→QUIC messages from the Tokio side
        loop {
            match args.tcp_rx.try_recv() {
                Ok(TcpToQuic::NewStream { reply_tx }) => {
                    // NOTE: Endpoint doesn't directly expose open_bidi_stream on a specific conn.
                    // We use the connection from endpoint's internal state.
                    // TQUIC: get active connection and open stream.
                    // For now we track conn internally; the handler manages streams.
                    // This is handled by the handler on the next writable callback.
                    // Simplified: send the reply_tx to the handler for registration.
                    // In practice we'd call conn.open_bidi_stream() here.
                    // TODO: wire this up properly once we can access conn from endpoint.
                    debug!("NewStream requested from TCP side");
                }
                Ok(TcpToQuic::Data { stream_id, data }) => {
                    // Forward data to QUIC stream via handler
                    debug!(stream_id, bytes = data.len(), "TCP→QUIC data");
                }
                Ok(TcpToQuic::Fin { stream_id }) => {
                    debug!(stream_id, "TCP→QUIC FIN");
                }
                Ok(TcpToQuic::Reset { stream_id }) => {
                    debug!(stream_id, "TCP→QUIC RESET");
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    info!("tcp_rx disconnected, shutting down");
                    return Ok(());
                }
            }
        }
    }
}
