//! Server mio event loop — drives TQUIC and the DNS bridge.

use std::{
    cell::RefCell,
    collections::HashMap,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use tquic::{
    Config, CongestionControlAlgorithm, Endpoint, PacketInfo, PacketSendHandler, TlsConfig,
};
use tracing::{debug, info, warn};

use crate::dns_bridge::DnsBridge;
use crate::handler::{ServerHandler, TcpMsg, TcpRx, TcpTx};

const DNS_TOKEN: Token = Token(0);

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

fn make_server_config(
    _domain: &str,
    tls_config: TlsConfig,
    cc: CongestionControlAlgorithm,
) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    // Disable MTU discovery — our transport is DNS, not raw UDP.
    config.enable_dplpmtud(false);

    config.set_congestion_control_algorithm(cc);
    config.set_initial_congestion_window(64);
    config.set_initial_max_data(128 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(16 * 1024 * 1024);
    config.set_initial_max_streams_bidi(256);
    config.set_max_idle_timeout(300_000);
    config.set_initial_rtt(400);
    config.set_tls_config(tls_config);
    Ok(config)
}

pub fn run(
    dns_bind: SocketAddr,
    target: SocketAddr,
    domain: String,
    tls_config: TlsConfig,
    cc: CongestionControlAlgorithm,
    tcp_tx: TcpTx,
    tcp_rx: TcpRx,
) -> Result<()> {
    let config = make_server_config(&domain, tls_config, cc)?;
    let bridge = Rc::new(RefCell::new(DnsBridge::new(domain.clone())));

    let sender: Rc<dyn PacketSendHandler> = Rc::new(DnsPacketSender { bridge: bridge.clone() });
    let handler = ServerHandler::new(target, domain.clone(), tcp_tx);

    let mut endpoint = Endpoint::new(Box::new(config), true, Box::new(handler), sender);

    let std_sock = StdUdpSocket::bind(dns_bind).context("bind DNS socket")?;
    std_sock.set_nonblocking(true)?;
    let mut dns_sock = MioUdpSocket::from_std(std_sock);

    let mut poll = Poll::new()?;
    poll.registry().register(&mut dns_sock, DNS_TOKEN, Interest::READABLE)?;

    info!(%dns_bind, "TQUIC server event loop started");

    // Fixed virtual client address — prevents path migration on every DNS query
    // (external resolvers change src port/IP between queries).
    let virtual_client: SocketAddr = "100.64.0.1:4444".parse().unwrap();

    let local_bind: SocketAddr = if dns_bind.ip().is_unspecified() {
        let ip = if dns_bind.is_ipv6() {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        };
        SocketAddr::new(ip, dns_bind.port())
    } else {
        dns_bind
    };

    let mut events   = Events::with_capacity(256);
    let mut recv_buf = vec![0u8; 4096];
    // server_pending: data that couldn't be written to a QUIC stream because
    // the stream's flow-control window was full.
    let mut server_pending: HashMap<(usize, u64), Vec<u8>> = HashMap::new();

    loop {
        // Cap at 20ms to keep the loop responsive for both directions.
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(Duration::from_millis(20)))
            .unwrap_or(Duration::from_millis(20));

        poll.poll(&mut events, Some(timeout))?;
        endpoint.on_timeout(Instant::now());
        endpoint.process_connections()?;

        // ── 1. Drain incoming DNS queries ─────────────────────────────────
        //
        // KEY: always inject with a fixed virtual client address so TQUIC
        // sees a stable single path and doesn't trigger PATH_CHALLENGE frames.
        loop {
            match dns_sock.recv_from(&mut recv_buf) {
                Ok((n, peer_addr)) => {
                    let (raw_query, assembled) =
                        bridge.borrow_mut().decode_query(&recv_buf[..n]);

                    if let Some(mut quic_pkt) = assembled {
                        let pkt_info = PacketInfo {
                            src:  virtual_client,
                            dst:  local_bind,
                            time: Instant::now(),
                        };
                        if let Err(e) = endpoint.recv(&mut quic_pkt, &pkt_info) {
                            debug!(%e, "endpoint.recv error");
                        }
                    }

                    // Flush TQUIC send path BEFORE building the response, so
                    // any TCP→QUIC data written since the last recv appears
                    // in output_q and can be packed into this DNS response.
                    let _ = endpoint.process_connections();

                    // encode_response packs multiple queued QUIC packets into
                    // one TXT record (2-byte length-prefix framing).
                    let response = bridge.borrow_mut().encode_response(&raw_query);
                    if !response.is_empty() {
                        if let Err(e) = dns_sock.send_to(&response, peer_addr) {
                            debug!(%e, "DNS send_to failed");
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => { warn!(%e, "dns_sock.recv_from error"); break; }
            }
        }

        // ── 2. TCP→QUIC: drain messages from TCP forwarder threads ────────────
        let mut tcp_msgs_drained = false;
        loop {
            match tcp_rx.try_recv() {
                Ok(TcpMsg::Data { conn_idx, stream_id, data }) => {
                    tcp_msgs_drained = true;
                    if let Some(conn) = endpoint.conn_get_mut(conn_idx as u64) {
                        let payload = if let Some(mut prev) = server_pending.remove(&(conn_idx, stream_id)) {
                            prev.extend_from_slice(&data);
                            prev
                        } else {
                            data
                        };
                        match conn.stream_write(stream_id, Bytes::copy_from_slice(&payload), false) {
                            Ok(n) if n < payload.len() => {
                                server_pending.insert((conn_idx, stream_id), payload[n..].to_vec());
                                let _ = conn.stream_want_write(stream_id, true);
                                debug!(conn_idx, stream_id, n, total = payload.len(), "tcp→quic partial");
                            }
                            Ok(n) => debug!(conn_idx, stream_id, n, "tcp→quic"),
                            Err(tquic::Error::Done) => {
                                debug!(conn_idx, stream_id, "stream window full, buffering");
                                server_pending.insert((conn_idx, stream_id), payload);
                                let _ = conn.stream_want_write(stream_id, true);
                            }
                            Err(e) => debug!(conn_idx, stream_id, %e, "stream_write error (stream closed?)"),
                        }
                    }
                }
                Ok(TcpMsg::Fin { conn_idx, stream_id }) => {
                    tcp_msgs_drained = true;
                    server_pending.remove(&(conn_idx, stream_id));
                    if let Some(conn) = endpoint.conn_get_mut(conn_idx as u64) {
                        let _ = conn.stream_write(stream_id, Bytes::new(), true);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    info!("tcp_rx disconnected, shutting down");
                    return Ok(());
                }
            }
        }

        // Retry buffered data for streams whose window re-opened.
        if !server_pending.is_empty() {
            let pending_keys: Vec<(usize, u64)> = server_pending.keys().cloned().collect();
            for (ci, sid) in pending_keys {
                if let Some(data) = server_pending.remove(&(ci, sid)) {
                    if let Some(conn) = endpoint.conn_get_mut(ci as u64) {
                        match conn.stream_write(sid, Bytes::copy_from_slice(&data), false) {
                            Ok(n) if n < data.len() => {
                                server_pending.insert((ci, sid), data[n..].to_vec());
                                let _ = conn.stream_want_write(sid, true);
                            }
                            Ok(_) => {}
                            Err(tquic::Error::Done) => {
                                server_pending.insert((ci, sid), data);
                                let _ = conn.stream_want_write(sid, true);
                            }
                            Err(_) => {} // stream closed — discard
                        }
                    }
                }
            }
        }

        // Flush any stream data written above so the next incoming DNS query
        // can carry it back to the client.
        if tcp_msgs_drained {
            let _ = endpoint.process_connections();
        }
    }
}
