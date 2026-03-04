//! Client mio event loop — drives TQUIC + multipath DNS sockets.

use std::{
    cell::RefCell,
    collections::HashMap,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    rc::Rc,
    sync::mpsc as std_mpsc,
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

struct DnsPacketSender {
    bridge:  Rc<RefCell<ClientDnsBridge>>,
    sockets: Rc<Vec<MioUdpSocket>>,
}

impl PacketSendHandler for DnsPacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut bridge = self.bridge.borrow_mut();
        for (data, _info) in pkts {
            for (ri, wire) in bridge.encode_quic_packet(data) {
                let _ = self.sockets[ri % self.sockets.len()].send(&wire);
            }
        }
        Ok(pkts.len())
    }
}

fn make_client_config(resolvers: &[SocketAddr], tls_config: TlsConfig) -> Result<Config> {
    let mut config = Config::new().context("Config::new")?;

    // QUIC uses standard >=1200 byte packets; DNS fragmentation is transparent.
    // Disable MTU discovery — DNS transport cannot carry large probe packets.
    config.enable_dplpmtud(false);

    if resolvers.len() > 1 {
        config.enable_multipath(true);
        config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        info!(n = resolvers.len(), "multipath QUIC enabled");
    }

    config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr);
    config.set_initial_max_data(10 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1 * 1024 * 1024);
    config.set_initial_max_streams_bidi(256);
    config.set_max_idle_timeout(300_000);
    config.set_initial_rtt(500);
    config.set_tls_config(tls_config);
    Ok(config)
}

pub struct LoopArgs {
    pub resolvers:  Vec<SocketAddr>,
    pub server_sni: String,
    pub domain:     String,
    pub tls_config: TlsConfig,
    pub tcp_rx:     std_mpsc::Receiver<TcpToQuic>,
    pub ctrl_tx:    std_mpsc::SyncSender<()>,
}

pub fn run(args: LoopArgs) -> Result<()> {
    let n = args.resolvers.len();
    assert!(n > 0, "at least one resolver required");

    let config = make_client_config(&args.resolvers, args.tls_config)?;

    // Bind one UDP socket per resolver
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

    // Register sockets with mio
    let mut poll = Poll::new()?;
    {
        let socks_mut = unsafe { &mut *(Rc::as_ptr(&sockets) as *mut Vec<MioUdpSocket>) };
        for (i, sock) in socks_mut.iter_mut().enumerate() {
            poll.registry().register(sock, Token(i), Interest::READABLE)?;
        }
    }

    // Connect to resolver[0] as the QUIC peer
    let local_addr = {
        let s = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
        s[0].local_addr()?
    };
    endpoint.connect(
        local_addr,
        args.resolvers[0],
        Some(&args.server_sni),
        None, None, None,
    ).context("endpoint.connect")?;
    info!("QUIC connection initiated → {}", args.resolvers[0]);

    let conn_index: u64 = 0; // first (and only) client connection
    let mut connected  = false;
    // stream_id → reply channel for QUIC→TCP forwarding
    let mut stream_map: HashMap<u64, tokio::sync::mpsc::Sender<QuicToTcp>> = HashMap::new();
    // NewStream requests queued before handshake completes
    let mut pending: Vec<tokio::sync::mpsc::Sender<QuicToTcp>> = Vec::new();
    // Pending outbound writes: stream_id → queued bytes (when stream not yet writable)
    let mut pending_writes: HashMap<u64, Vec<u8>> = HashMap::new();

    let mut events         = Events::with_capacity(256);
    let mut recv_buf       = vec![0u8; 8192];
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_millis(20);

    loop {
        let now       = Instant::now();
        let until_ka  = keepalive_interval
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

        // ── 1. Read DNS responses ─────────────────────────────────────────────
        let socks = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
        for (ri, sock) in socks.iter().enumerate() {
            loop {
                match sock.recv(&mut recv_buf) {
                    Ok(n) => {
                        if let Some(mut pkt) = bridge.borrow_mut().decode_dns_response(&recv_buf[..n], ri) {
                            let pkt_info = PacketInfo {
                                src:  args.resolvers[ri],
                                dst:  local_addr,
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
        endpoint.process_connections()?;

        // ── 2. Check if handshake completed ──────────────────────────────────
        if !connected {
            if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                if conn.is_established() {
                    connected = true;
                    info!("QUIC handshake complete ✓");

                    // Add extra paths for multipath
                    for (ri, resolver) in args.resolvers.iter().enumerate().skip(1) {
                        let local_ri = socks[ri].local_addr().unwrap_or(local_addr);
                        match conn.add_path(local_ri, *resolver) {
                            Ok(_) => info!(ri, %resolver, "multipath path added"),
                            Err(e) => warn!(%e, ri, "add_path failed"),
                        }
                    }

                    // Flush pending stream opens
                    for reply_tx in pending.drain(..) {
                        open_stream(conn, &mut stream_map, reply_tx);
                    }
                }
            }
        }

        // ── 3. Drain readable QUIC streams → TCP ─────────────────────────────
        if let Some(conn) = endpoint.conn_get_mut(conn_index) {
            let readable: Vec<u64> = conn.stream_readable_iter().collect();
            let mut buf = vec![0u8; 16 * 1024];
            for sid in readable {
                loop {
                    match conn.stream_read(sid, &mut buf) {
                        Ok((0, _)) => break,
                        Ok((n, fin)) => {
                            if let Some(tx) = stream_map.get(&sid) {
                                let _ = tx.try_send(QuicToTcp::Data { data: buf[..n].to_vec() });
                            }
                            if fin {
                                if let Some(tx) = stream_map.remove(&sid) {
                                    let _ = tx.try_send(QuicToTcp::Fin);
                                }
                                break;
                            }
                        }
                        Err(tquic::Error::Done) => break,
                        Err(e) => {
                            warn!(sid, %e, "stream_read error");
                            if let Some(tx) = stream_map.remove(&sid) { let _ = tx.try_send(QuicToTcp::Fin); }
                            break;
                        }
                    }
                }
            }
        }

        // ── 4. Drain writable streams with pending writes ─────────────────────
        if !pending_writes.is_empty() {
            if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                let writable: Vec<u64> = conn.stream_writable_iter().collect();
                for sid in writable {
                    if let Some(data) = pending_writes.remove(&sid) {
                        stream_write_with_pending(conn, sid, data, false, &mut pending_writes);
                    }
                }
            }
        }

        // ── 5. Keepalive ─────────────────────────────────────────────────────
        let now = Instant::now();
        if now.duration_since(last_keepalive) >= keepalive_interval {
            last_keepalive = now;
            let b = bridge.borrow();
            for ri in 0..n {
                if let Some((idx, wire)) = b.encode_keepalive(ri) {
                    let _ = socks[idx % socks.len()].send(&wire);
                }
            }
        }

        // ── 6. TCP→QUIC messages ─────────────────────────────────────────────
        loop {
            match args.tcp_rx.try_recv() {
                Ok(TcpToQuic::NewStream { reply_tx }) => {
                    if connected {
                        if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                            open_stream(conn, &mut stream_map, reply_tx);
                        }
                    } else {
                        pending.push(reply_tx);
                    }
                }
                Ok(TcpToQuic::Data { stream_id, data }) => {
                    if let Some(conn) = endpoint.conn_get_mut(conn_index) {
                        stream_write_with_pending(conn, stream_id, data, false, &mut pending_writes);
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
                        // RST_STREAM: stop sending client→server
                        let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
                        // STOP_SENDING: ask server to stop sending server→client
                        let _ = conn.stream_shutdown(stream_id, Shutdown::Read, 0);
                    }
                    stream_map.remove(&stream_id);
                    pending_writes.remove(&stream_id);
                }
                Err(std_mpsc::TryRecvError::Empty) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    info!("tcp_rx disconnected, shutting down");
                    return Ok(());
                }
            }
        }
    }
}

fn open_stream(
    conn: &mut tquic::Connection,
    stream_map: &mut HashMap<u64, tokio::sync::mpsc::Sender<QuicToTcp>>,
    reply_tx: tokio::sync::mpsc::Sender<QuicToTcp>,
) {
    match conn.stream_bidi_new(127, false) {
        Ok(stream_id) => {
            info!(stream_id, "QUIC bidi stream opened");
            let _ = conn.stream_want_write(stream_id, true);
            // Tell the Tokio task which stream_id it owns
            let _ = reply_tx.try_send(QuicToTcp::StreamAssigned { stream_id });
            stream_map.insert(stream_id, reply_tx);
        }
        Err(e) => {
            warn!(%e, "stream_bidi_new failed");
            let _ = reply_tx.try_send(QuicToTcp::Fin);
        }
    }
}

fn stream_write_with_pending(
    conn: &mut tquic::Connection,
    stream_id: u64,
    mut data: Vec<u8>,
    fin: bool,
    pending: &mut HashMap<u64, Vec<u8>>,
) {
    // Prepend any previously un-sent bytes
    if let Some(prev) = pending.remove(&stream_id) {
        let mut full = prev;
        full.extend_from_slice(&data);
        data = full;
    }
    match conn.stream_write(stream_id, Bytes::from(data.clone()), fin) {
        Ok(n) if n < data.len() => {
            pending.insert(stream_id, data[n..].to_vec());
        }
        Ok(_) => {}
        Err(tquic::Error::Done) => {
            pending.insert(stream_id, data);
        }
        Err(e) => warn!(stream_id, %e, "stream_write error"),
    }
}
