//! Server mio event loop — drives TQUIC and the DNS bridge.

use std::{
    cell::RefCell,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use tquic::{Config, CongestionControlAlgorithm, Endpoint, PacketInfo, PacketSendHandler, TlsConfig};
use tracing::{debug, info, warn};

use crate::dns_bridge::DnsBridge;
use crate::handler::{ServerHandler, TcpRx, TcpTx};

const DNS_TOKEN: Token = Token(0);

/// Packet sender: pushes TQUIC outbound packets into the DNS output queue.
/// Uses Rc<RefCell<>> for shared access on the same thread.
struct DnsPacketSender {
    bridge: Rc<RefCell<DnsBridge>>,
}

impl PacketSendHandler for DnsPacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut bridge = self.bridge.borrow_mut();
        for (data, _info) in pkts {
            bridge.push_quic_packet(data.clone());
        }
        Ok(pkts.len())
    }
}

fn make_server_config(domain: &str, tls_config: TlsConfig) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    // MTU: C formula (240 - domain_len) / 1.6
    let mtu_payload = ((240.0 - domain.len() as f64) / 1.6) as usize;
    let mtu_payload = mtu_payload.max(60).min(1200);
    config.set_send_udp_payload_size(mtu_payload);
    config.set_recv_udp_payload_size(mtu_payload as u16);
    config.enable_dplpmtud(false);

    // Copa CC: delay-based, won't treat NXDOMAINs as loss
    config.set_congestion_control_algorithm(CongestionControlAlgorithm::Copa);
    config.set_initial_congestion_window(64);

    // Flow control
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_stream_data_bidi_local(256 * 1024);
    config.set_initial_max_streams_bidi(256);

    config.set_max_idle_timeout(300_000);
    config.set_initial_rtt(400);

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

    let bridge = Rc::new(RefCell::new(DnsBridge::new(domain.clone())));

    let sender: Rc<dyn PacketSendHandler> = Rc::new(DnsPacketSender {
        bridge: bridge.clone(),
    });

    let handler = ServerHandler::new(target, domain.clone(), tcp_tx);

    let mut endpoint = Endpoint::new(
        Box::new(config),
        true, // is_server
        Box::new(handler),
        sender,
    );

    // Bind DNS UDP socket via mio
    let std_sock = StdUdpSocket::bind(dns_bind).context("bind DNS socket")?;
    std_sock.set_nonblocking(true)?;
    let mut dns_sock = MioUdpSocket::from_std(std_sock);

    let mut poll = Poll::new()?;
    poll.registry().register(&mut dns_sock, DNS_TOKEN, Interest::READABLE)?;

    info!(%dns_bind, "TQUIC server event loop started");

    let mut events = Events::with_capacity(256);
    let mut recv_buf = vec![0u8; 4096];

    loop {
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(Duration::from_millis(50)))
            .unwrap_or(Duration::from_millis(50));

        poll.poll(&mut events, Some(timeout))?;

        // 1. Drain incoming DNS queries
        loop {
            match dns_sock.recv_from(&mut recv_buf) {
                Ok((n, peer_addr)) => {
                    let (response, assembled) = bridge.borrow_mut().handle_query(&recv_buf[..n]);

                    if !response.is_empty() {
                        if let Err(e) = dns_sock.send_to(&response, peer_addr) {
                            debug!(%e, "DNS send_to failed");
                        }
                    }

                    if let Some(mut quic_pkt) = assembled {
                        let pkt_info = PacketInfo {
                            src: peer_addr,
                            dst: dns_bind,
                            time: Instant::now(),
                        };
                        if let Err(e) = endpoint.recv(&mut quic_pkt, &pkt_info) {
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

        // 2. Drive timers
        endpoint.on_timeout(Instant::now());

        // 3. Drain TCP→QUIC messages
        // (handler manages the actual stream writes via on_stream_writable callbacks)
        loop {
            match tcp_rx.try_recv() {
                Ok(_msg) => {
                    // Data forwarding: handled inside ServerHandler via shared pending write map
                    // on_stream_writable callbacks drain the pending data
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
