//! Client mio event loop — drives TQUIC + multipath DNS sockets.

use std::{
    cell::RefCell,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use tquic::{
    Config, CongestionControlAlgorithm, Endpoint, MultipathAlgorithm,
    PacketInfo, PacketSendHandler, TlsConfig,
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
        let mut bridge  = self.bridge.borrow_mut();
        let sockets = &*self.sockets;
        for (data, _info) in pkts {
            let dispatches = bridge.encode_quic_packet(data);
            for (ri, wire) in dispatches {
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

    // Bind one non-blocking UDP socket per resolver, stored in Rc<Vec<>>
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

    let mut endpoint = Endpoint::new(
        Box::new(config),
        false, // is_server
        Box::new(handler),
        sender,
    );

    // Register sockets with mio
    let mut poll       = Poll::new()?;
    let waker_token    = Token(n);
    let _waker         = mio::Waker::new(poll.registry(), waker_token)?;
    // Temporarily take sockets out of Rc to register (Rc unwrap after all refs dropped)
    // We'll register via a raw pointer borrow:
    {
        // Safety: sockets is only accessed from this thread (Rc, !Send)
        let socks_mut = unsafe { &mut *(Rc::as_ptr(&sockets) as *mut Vec<MioUdpSocket>) };
        for (i, sock) in socks_mut.iter_mut().enumerate() {
            poll.registry().register(sock, resolver_token(i), Interest::READABLE)?;
        }
    }

    // Initial connect — dummy server addr, actual routing via DNS sockets
    let dummy_server: SocketAddr = "1.2.3.4:4444".parse().unwrap();
    let local_addr = {
        let socks = unsafe { &*(Rc::as_ptr(&sockets) as *const Vec<MioUdpSocket>) };
        socks[0].local_addr()?
    };

    endpoint.connect(
        local_addr,
        dummy_server,
        Some(&args.server_sni),
        None,
        None,
        None, // Option<&Config>
    )
    .context("endpoint.connect")?;
    info!("QUIC connection initiated");

    let mut events         = Events::with_capacity(256);
    let mut recv_buf       = vec![0u8; 4096];
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_millis(20);

    loop {
        let now             = Instant::now();
        let until_ka        = keepalive_interval
            .checked_sub(now.duration_since(last_keepalive))
            .unwrap_or(Duration::ZERO);
        let timeout = endpoint
            .timeout()
            .map(|d| d.min(until_ka))
            .unwrap_or(until_ka)
            .min(Duration::from_millis(50));

        poll.poll(&mut events, Some(timeout))?;
        endpoint.on_timeout(Instant::now());

        // 1. Read DNS responses from all resolver sockets
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
                    Err(e) => { warn!(%e, ri, "resolver socket recv error"); break; }
                }
            }
        }

        // 2. Keepalive: send empty poll queries to each resolver
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

        // 3. TCP→QUIC messages
        loop {
            match args.tcp_rx.try_recv() {
                Ok(TcpToQuic::NewStream { reply_tx }) => {
                    debug!("NewStream from TCP side (TODO: open bidi stream)");
                    // TODO: call conn.open_bidi_stream() once TQUIC exposes connection access
                    let _ = reply_tx; // suppress unused warning
                }
                Ok(TcpToQuic::Data { stream_id, data }) => {
                    debug!(stream_id, bytes = data.len(), "TCP→QUIC data (TODO: write to stream)");
                }
                Ok(TcpToQuic::Fin { stream_id }) => { debug!(stream_id, "TCP→QUIC FIN"); }
                Ok(TcpToQuic::Reset { stream_id }) => { debug!(stream_id, "TCP→QUIC RESET"); }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    info!("tcp_rx disconnected, shutting down");
                    return Ok(());
                }
            }
        }
    }
}
