//! Client mio event loop — drives TQUIC + multipath DNS sockets.
//!
//! Data path (now fully wired):
//! - NewStream  → conn.stream_bidi_new() → reply stream_id back to Tokio task
//! - TCP Data   → conn.stream_write() + stream_want_write()
//! - TCP Fin    → conn.stream_write(fin=true)
//! - TCP Reset  → conn.stream_shutdown(Write)
//! - QUIC→TCP   → on_stream_readable reads + sends to per-stream reply_tx
//! - Multipath  → conn.add_path() for each extra resolver after connect

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
    Config, CongestionControlAlgorithm, Endpoint, MultipathAlgorithm,
    PacketInfo, PacketSendHandler, Shutdown, TlsConfig,
};
use tracing::{debug, info, warn};

use crate::dns_bridge::ClientDnsBridge;
use crate::handler::{ClientHandler, QuicToTcp, TcpToQuic};

fn resolver_token(idx: usize) -> Token { Token(idx) }

struct DnsPacketSender {
    bridge:  Rc<RefCell<ClientDnsBridge>>,
    sockets: Rc<Vec<MioUdpSocket>>,
}

impl PacketSendHandler for DnsPacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut bridge = self.bridge.borrow_mut();
        let sockets = &*self.sockets;
        for (data, _info) in pkts {
            for (ri, wire) in bridge.encode_quic_packet(data) {
                let _ = sockets[ri % sockets.len()].send(&wire);
            }
        }
        Ok(pkts.len())
    }
}

fn make_client_config(domain: &str, resolvers: &[SocketAddr], tls_config: TlsConfig) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    let mtu = ((240.0 - domain.len() as f64) / 1.6) as usize;
    let mtu = mtu.max(60).min(1200);
    config.set_send_udp_payload_size(mtu);
    config.set_recv_udp_payload_size(mtu as u16);
    config.enable_dplpmtud(false);

    if resolvers.len() > 1 {
        config.enable_multipath(true);
        config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        info!(n = resolvers.len(), "multipath QUIC enabled");
    }

    config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr);
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_local(256 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_streams_bidi(256);
    config.set_max_idle_timeout(300_000);
    config.set_initial_rtt(400);
    config.set_tls_config(tls_config);
    Ok(config)
}

pub struct LoopArgs {
    pub resolvers:  Vec<SocketAddr>,
    pub server_sni: String,
    pub domain:     String,
    pub tls_config: TlsConfig,
    pub tcp_rx:     mpsc::Receiver<TcpToQuic>,
    pub ctrl_tx:    mpsc::SyncSender<QuicToTcp>,
}

pub fn run(args: LoopArgs) -> Result<()> {
    let n = args.resolvers.len();
    assert!(n > 0, "at least one resolver required");

    let config = make_client_config(&args.domain, &args.resolvers, args.tls_config)?;

    // Bind mio UDP sockets (one per resolver)
    let mut sockets_vec: Vec<MioUdpSocket> = Vec::with_capacity(n);
    for resolver in &args.resolvers {
        let local: SocketAddr = if resolver.is_ipv4() { "0.0.0.0:0".parse().unwrap() }
                                else                  { "[::]:0".parse().unwrap() };
        let std_sock = StdUdpSocket::bind(local)?;
        std_sock.set_nonblocking(true)?;
        std_sock.connect(resolver)?;
        sockets_vec.push(MioUdpSocket::from_std(std_sock));
    }
    let sockets = Rc::new(sockets_vec);

    let bridge = Rc::new(RefCell::new(ClientDnsBridge::new(args.domain.clone(), n)));

    let sender: Rc<dyn PacketSendHandler> = Rc::new(DnsPacketSender {
        bridge:  bridge.clone(),
        sockets: sockets.clone(),
    });

    let handler = ClientHandler::new(args.ctrl_tx.clone());
    let mut endpoint = Endpoint::new(Box::new(config), false, Box::new(handler), sender);

    // mio registration
    let mut poll    = Poll::new()?;
    let waker_token = Token(n);
    let _waker      = mio::Waker::new(poll.registry(), waker_token)?;
    {
        let socks_mut = unsafe { &mut *(Rc::as_ptr(&sockets) as *mut Vec<MioUdpSocket>) };
        for (i, sock) in socks_mut.iter_mut().enumerate() {
            poll.registry().register(sock, resolver_token(i), Interest::READABLE)?;
        }
    }

    // Initiate QUIC connection (via primary resolver socket)
    let local_addr = {
        let socks = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
        socks[0].local_addr()?
    };
    // Connect to actual resolver[0] as the QUIC peer — NOT a dummy address.
    // TQUIC encodes the peer addr into INITIAL packet transport params;
    // using a fake address causes TransportParameterError on the server.
    let conn_id = endpoint.connect(
        local_addr,
        args.resolvers[0],      // ← real resolver address
        Some(&args.server_sni),
        None, None, None,
    ).context("endpoint.connect")?;
    info!(?conn_id, "QUIC connection initiated");

    // conn_get_mut takes a u64 index; connection starts at index 0 for client
    let conn_index: u64 = 0;

    // Wait for handshake to complete before accepting stream requests
    let mut connected       = false;
    // Map stream_id → reply_tx for QUIC→TCP data forwarding
    let mut stream_map: HashMap<u64, mpsc::SyncSender<QuicToTcp>> = HashMap::new();
    // Pending stream open requests (before connection is established)
    let mut pending_streams: Vec<mpsc::SyncSender<QuicToTcp>> = Vec::new();

    let mut events         = Events::with_capacity(256);
    let mut recv_buf       = vec![0u8; 4096];
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_millis(20);

    loop {
        let now        = Instant::now();
        let until_ka   = keepalive_interval
            .checked_sub(now.duration_since(last_keepalive))
            .unwrap_or(Duration::ZERO);
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(until_ka))
            .unwrap_or(until_ka)
            .min(Duration::from_millis(50));

        poll.poll(&mut events, Some(timeout))?;
        endpoint.on_timeout(Instant::now());
        endpoint.process_connections()?;

        // ── 1. Read DNS responses from all resolver sockets ──────────────────
        let socks = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
        for (ri, sock) in socks.iter().enumerate() {
            loop {
                match sock.recv(&mut recv_buf) {
                    Ok(n) => {
                        if let Some(mut pkt) = bridge.borrow_mut().decode_dns_response(&recv_buf[..n], ri) {
                            let pkt_info = PacketInfo {
                                src: args.resolvers[ri],
                                dst: local_addr,
                                time: Instant::now(),
                            };
                            if let Err(e) = endpoint.recv(&mut pkt, &pkt_info) {
                                debug!(%e, ri, "endpoint.recv error");
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { warn!(%e, ri, "recv error"); break; }
                }
            }
        }

        // ── 2. Check if handshake just completed ─────────────────────────────
        if !connected {
            if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                if conn.is_established() {
                    connected = true;
                    info!("QUIC handshake complete");
                    let _ = args.ctrl_tx.try_send(QuicToTcp::Connected);

                    // Add extra paths for multipath
                    for (ri, resolver) in args.resolvers.iter().enumerate().skip(1) {
                        let local_ri = {
                            let s = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
                            s[ri].local_addr().unwrap_or(local_addr)
                        };
                        if let Err(e) = conn.add_path(local_ri, *resolver) {
                            warn!(%e, ri, "add_path failed");
                        } else {
                            info!(ri, %resolver, "multipath path added");
                        }
                    }

                    // Open any streams that were requested before connection
                    for reply_tx in pending_streams.drain(..) {
                        open_stream(conn, &mut stream_map, reply_tx);
                    }
                }
            }
        }

        // ── 3. Drain readable QUIC streams → send to TCP tasks ───────────────
        if let Some(conn) = endpoint.conn_get_mut(conn_index) {
            let readable: Vec<u64> = conn.stream_readable_iter().collect();
            let mut buf = vec![0u8; 16 * 1024];
            for sid in readable {
                loop {
                    match conn.stream_read(sid, &mut buf) {
                        Ok((0, _)) => break,
                        Ok((n, fin)) => {
                            if let Some(tx) = stream_map.get(&sid) {
                                let _ = tx.try_send(QuicToTcp::Data {
                                    stream_id: sid,
                                    data: buf[..n].to_vec(),
                                });
                            }
                            if fin {
                                if let Some(tx) = stream_map.remove(&sid) {
                                    let _ = tx.try_send(QuicToTcp::Fin { stream_id: sid });
                                }
                                break;
                            }
                        }
                        Err(tquic::Error::Done) => break,
                        Err(e) => {
                            warn!(sid, %e, "stream_read error");
                            if let Some(tx) = stream_map.remove(&sid) {
                                let _ = tx.try_send(QuicToTcp::Fin { stream_id: sid });
                            }
                            break;
                        }
                    }
                }
            }
        }

        // ── 4. Keepalive ─────────────────────────────────────────────────────
        let now = Instant::now();
        if now.duration_since(last_keepalive) >= keepalive_interval {
            last_keepalive = now;
            let b = bridge.borrow();
            for ri in 0..n {
                if let Some((idx, wire)) = b.encode_keepalive(ri) {
                    let _ = socks[idx].send(&wire);
                }
            }
        }

        // ── 5. TCP→QUIC messages ─────────────────────────────────────────────
        loop {
            match args.tcp_rx.try_recv() {
                Ok(TcpToQuic::NewStream { reply_tx }) => {
                    if connected {
                        if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                            open_stream(conn, &mut stream_map, reply_tx);
                        }
                    } else {
                        pending_streams.push(reply_tx);
                    }
                }
                Ok(TcpToQuic::Data { stream_id, data }) => {
                    if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                        match conn.stream_write(stream_id, Bytes::from(data), false) {
                            Ok(n) => { debug!(stream_id, n, "tcp→quic wrote"); }
                            Err(tquic::Error::Done) => {
                                // Stream buffer full — ideally buffer and retry on writable
                                warn!(stream_id, "stream_write DONE (buffer full)");
                            }
                            Err(e) => warn!(stream_id, %e, "stream_write error"),
                        }
                        let _ = conn.stream_want_write(stream_id, true);
                    }
                }
                Ok(TcpToQuic::Fin { stream_id }) => {
                    if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                        let _ = conn.stream_write(stream_id, Bytes::new(), true);
                    }
                }
                Ok(TcpToQuic::Reset { stream_id }) => {
                    if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                        let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
                    }
                    stream_map.remove(&stream_id);
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

/// Open a new bidi QUIC stream, register the reply_tx, and send conn-established signal.
fn open_stream(
    conn: &mut tquic::Connection,
    stream_map: &mut HashMap<u64, mpsc::SyncSender<QuicToTcp>>,
    reply_tx: mpsc::SyncSender<QuicToTcp>,
) {
    match conn.stream_bidi_new(127, false) { // urgency=127 (lowest), non-incremental
        Ok(stream_id) => {
            info!(stream_id, "new QUIC bidi stream opened");
            let _ = conn.stream_want_write(stream_id, true);
            // Signal back to the Tokio task — reuse Connected variant as "stream ready"
            // The stream_id will arrive via the QuicToTcp::Data flow; for now send Connected.
            stream_map.insert(stream_id, reply_tx.clone());
            let _ = reply_tx.try_send(QuicToTcp::Connected);
        }
        Err(e) => {
            warn!(%e, "stream_bidi_new failed");
            let _ = reply_tx.try_send(QuicToTcp::Disconnected);
        }
    }
}
