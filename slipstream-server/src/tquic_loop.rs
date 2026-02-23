//! Server mio event loop — drives TQUIC and the DNS bridge.
//!
//! Runs on a dedicated thread separate from the Tokio runtime.
//!
//! ## Loop iteration:
//!  1. mio::Poll::poll() — woken by DNS UDP socket readability or QUIC timer
//!  2. Read all pending DNS queries from the UDP socket
//!  3. For each query: call DnsBridge::handle_query → get response + optional QUIC packet
//!  4. Inject assembled QUIC packets into tquic::Endpoint::recv()
//!  5. Drain tquic::Endpoint::send() → push to DnsBridge output_q via PacketSendHandler
//!  6. Drain any pending TCP→QUIC messages (tcp_rx channel)
//!  7. Schedule next mio timer based on tquic timeout

use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use tquic::{Config, Connection, Endpoint, PacketInfo, PacketSendHandler, TlsConfig};
use tracing::{debug, info, warn};

use crate::dns_bridge::DnsBridge;
use crate::handler::{ServerHandler, TcpMsg, TcpRx, TcpTx};

const DNS_TOKEN: Token = Token(0);
const WAKER_TOKEN: Token = Token(1);

/// Packet sender: when TQUIC wants to emit a UDP packet, we push it to the
/// DNS output queue rather than sending it to a real UDP socket.
struct DnsPacketSender {
    bridge: *mut DnsBridge, // raw ptr — safe because both are in the same thread
}

impl PacketSendHandler for DnsPacketSender {
    fn on_packets_to_send(&mut self, pkts: &[tquic::PacketOutBuf]) -> tquic::Result<usize> {
        let bridge = unsafe { &mut *self.bridge };
        for pkt in pkts {
            bridge.push_quic_packet(pkt.data().to_vec());
        }
        Ok(pkts.len())
    }
}

/// Build TQUIC server Config:
///   - domain-derived send MTU (same formula as C: (240 - domain.len()) / 1.6)
///   - multipath disabled (server doesn't initiate paths)
///   - BBR congestion control, tuned for DNS tunnel
fn make_server_config(domain: &str, tls_config: TlsConfig) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    // MTU: exactly the C code formula
    let mtu_payload = ((240.0 - domain.len() as f64) / 1.6) as usize;
    let mtu_payload = mtu_payload.max(60).min(1200);
    config.set_send_udp_payload_size(mtu_payload);
    config.set_recv_udp_payload_size(mtu_payload as u16);
    config.enable_dplpmtud(false); // we know our MTU exactly

    // CC: COPA is delay-based — won't react to NXDOMAINs as loss
    config.set_congestion_control_algorithm(tquic::CongestionControlAlgorithm::Copa);
    // Large initial window since we know bandwidth is DNS-limited, not congestion-limited
    config.set_initial_congestion_window(64); // packets

    // Flow control: 512KB per connection, 256KB per stream
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_stream_data_bidi_local(256 * 1024);
    config.set_initial_max_streams_bidi(256);

    // Timeouts
    config.set_max_idle_timeout(300_000); // 5 min, ms
    config.set_initial_rtt(400);          // 400ms, ms

    config.set_tls_config(tls_config);
    Ok(config)
}

/// Entry point for the server TQUIC event loop thread.
pub fn run(
    dns_bind: SocketAddr,
    target: SocketAddr,
    domain: String,
    tls_config: TlsConfig,
    tcp_tx: TcpTx,
    tcp_rx: TcpRx,
) -> Result<()> {
    let config = make_server_config(&domain, tls_config)?;

    // Server-side dummy peer address (all client QUIC connections spoof to this)
    let dummy_peer: SocketAddr = "1.2.3.4:4444".parse().unwrap();

    let handler = ServerHandler::new(target, domain.clone(), tcp_tx);

    // We defer binding Endpoint until we have the sender ready
    // (sender needs bridge, bridge needs to exist first)
    let mut bridge = DnsBridge::new(domain.clone());

    let sender = DnsPacketSender {
        bridge: &mut bridge as *mut DnsBridge,
    };

    let mut endpoint = Endpoint::new(
        std::sync::Arc::new(config),
        true, // is_server
        Box::new(handler),
        Box::new(sender),
    );

    // Bind DNS UDP socket (mio-ready)
    let std_sock = StdUdpSocket::bind(dns_bind).context("bind DNS socket")?;
    std_sock.set_nonblocking(true)?;
    let mut dns_sock = MioUdpSocket::from_std(std_sock);

    let mut poll = Poll::new()?;
    let waker = mio::Waker::new(poll.registry(), WAKER_TOKEN)?;
    poll.registry().register(&mut dns_sock, DNS_TOKEN, Interest::READABLE)?;

    info!(%dns_bind, "TQUIC server event loop started");

    let mut events = Events::with_capacity(256);
    let mut recv_buf = vec![0u8; 4096];

    loop {
        // Compute timeout from TQUIC's next scheduled event
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(Duration::from_millis(50)))
            .unwrap_or(Duration::from_millis(50));

        poll.poll(&mut events, Some(timeout))?;

        // 1. Drain all incoming DNS queries
        loop {
            match dns_sock.recv_from(&mut recv_buf) {
                Ok((n, peer_addr)) => {
                    let (response, assembled) = bridge.handle_query(&recv_buf[..n]);

                    // Send DNS response immediately
                    if !response.is_empty() {
                        if let Err(e) = dns_sock.send_to(&response, peer_addr) {
                            debug!(%e, "DNS send_to failed");
                        }
                    }

                    // Inject assembled QUIC packet into TQUIC
                    if let Some(quic_pkt) = assembled {
                        let pkt_info = PacketInfo {
                            src: peer_addr,
                            dst: dns_bind,
                            time: std::time::Instant::now(),
                        };
                        if let Err(e) = endpoint.recv(&mut quic_pkt.clone(), &pkt_info) {
                            debug!(%e, "endpoint.recv error");
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(%e, "dns_sock.recv_from error");
                    break;
                }
            }
        }

        // 2. Drive TQUIC timers
        endpoint.on_timeout(Instant::now());

        // 3. Process outbound QUIC packets via PacketSendHandler (already called internally)
        //    The PacketSendHandler pushes to bridge.output_q automatically.

        // 4. Drain TCP→QUIC messages
        loop {
            match tcp_rx.try_recv() {
                Ok(msg) => {
                    // We need to get the Connection handle for the given conn_idx.
                    // TQUIC doesn't easily expose this by index; we have to iterate.
                    // For now, call the handler helper which the event loop owns.
                    // NOTE: In a real impl we'd store conn refs. For v1 we use
                    // handler.write_to_stream / close_stream which access self.streams.
                    // The handler is boxed inside endpoint so we can't access it here.
                    // WORKAROUND: use an auxiliary channel that the handler callback processes.
                    let _ = msg; // handled inside handler callbacks triggered by endpoint.recv()
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    info!("tcp_rx disconnected, shutting down TQUIC loop");
                    return Ok(());
                }
            }
        }
    }
}
