//! Custom async UDP sockets that wrap DNS encode/decode for quinn.
//!
//! ## Client side (`ClientDnsSocket`)
//! - `send_to`: encodes raw QUIC packet as a DNS TXT query, sends to one of N resolvers.
//! - `recv_from`: polls all resolver UDP sockets, decodes DNS TXT responses → raw QUIC bytes,
//!   returns with a fixed dummy peer address so quinn sees a stable remote endpoint.
//!
//! ## Server side (`ServerDnsSocket`)
//! - `recv_from`: receives DNS TXT queries, decodes QNAME → QUIC bytes, spoofs peer address to
//!   dummy IP, remembers original (peer, dns_id) in a table keyed by message order.
//! - `send_to`: encodes raw QUIC packet as a DNS TXT response, sends to original requester.
//!
//! The "dummy address trick" is the same as the original C code: QUIC tracks connections by
//! connection ID, not by address, so we can safely lie about the peer address.

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::codec::{decode_dns_query, decode_dns_response, encode_dns_query, encode_dns_response};
use crate::config::{DUMMY_PEER_IP, DUMMY_PEER_PORT};

// ── Shared helpers ─────────────────────────────────────────────────────────────

/// The fixed dummy peer address we report to quinn on the server side.
pub fn dummy_peer_addr() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(DUMMY_PEER_IP.parse().unwrap()),
        DUMMY_PEER_PORT,
    )
}

// ── Pending query tracking (server side) ──────────────────────────────────────

/// Metadata saved for each DNS query received by the server, so we can
/// send the response back to the correct client address.
#[derive(Debug, Clone)]
pub struct PendingQuery {
    /// Original UDP source address of the DNS client (resolver or client).
    pub peer_addr: SocketAddr,
    /// Original DNS message ID, echoed back in the response.
    pub dns_id_wire: [u8; 2],
    /// The raw DNS query wire bytes (needed to reconstruct the response question section).
    pub query_wire: Vec<u8>,
}

// ── ClientDnsSocket ───────────────────────────────────────────────────────────

/// Client-side DNS socket state (shared between the send and receive halves).
#[derive(Debug)]
pub struct ClientDnsSocketInner {
    /// One UDP socket per resolver address.
    pub resolvers: Vec<(UdpSocket, SocketAddr)>,
    /// Round-robin index for outgoing queries.
    pub rr_index: usize,
    /// Domain name for encoding queries.
    pub domain: String,
}

/// A handle to the shared client socket state.
pub type ClientDnsSocket = Arc<Mutex<ClientDnsSocketInner>>;

impl ClientDnsSocketInner {
    /// Create a new client DNS socket set.
    ///
    /// Binds one local UDP socket per resolver (so QUIC can use them as separate paths).
    pub async fn new(resolvers: Vec<SocketAddr>, domain: String) -> Result<Self> {
        let mut socks = Vec::with_capacity(resolvers.len());
        for resolver in resolvers {
            // Bind on any available local port, same address family as resolver
            let local: SocketAddr = if resolver.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let sock = UdpSocket::bind(local).await?;
            // "Connect" the socket so we only receive from this resolver
            sock.connect(resolver).await?;
            socks.push((sock, resolver));
        }
        Ok(Self {
            resolvers: socks,
            rr_index: 0,
            domain,
        })
    }

    /// Send a QUIC packet encoded as a DNS query to the next resolver (round-robin).
    pub fn send_encoded(&mut self, quic_data: &[u8]) -> io::Result<()> {
        if self.resolvers.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no resolvers"));
        }
        let idx = self.rr_index % self.resolvers.len();
        self.rr_index = self.rr_index.wrapping_add(1);

        let dns_packet = encode_dns_query(quic_data, &self.domain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Use blocking try_send; if would block, we drop (QUIC will retransmit)
        match self.resolvers[idx].0.try_send(&dns_packet) {
            Ok(n) if n == dns_packet.len() => {
                trace!(bytes = n, resolver = %self.resolvers[idx].1, "client sent DNS query");
                Ok(())
            }
            Ok(n) => {
                warn!(sent = n, expected = dns_packet.len(), "partial DNS query send");
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!("client DNS send would block, dropping packet");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Poll all resolver sockets for incoming DNS responses.
    /// Returns `Some((quic_bytes, resolver_addr))` if a valid response is found.
    pub fn try_recv_any(&self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        let mut buf = vec![0u8; 4096];
        for (sock, resolver_addr) in &self.resolvers {
            match sock.try_recv(&mut buf) {
                Ok(n) => {
                    trace!(bytes = n, resolver = %resolver_addr, "client received DNS response");
                    match decode_dns_response(&buf[..n]) {
                        Ok(Some(data)) => {
                            return Ok(Some((data, *resolver_addr)));
                        }
                        Ok(None) => {
                            // NXDOMAIN or empty — server has nothing to send, continue polling
                            debug!(resolver = %resolver_addr, "received NXDOMAIN/empty DNS response");
                            continue;
                        }
                        Err(e) => {
                            warn!(%e, resolver = %resolver_addr, "failed to decode DNS response");
                            continue;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}

// ── ServerDnsSocket ───────────────────────────────────────────────────────────

/// Server-side DNS socket inner state (shared between tasks).
#[derive(Debug)]
pub struct ServerDnsSocketInner {
    /// The bound UDP socket listening for DNS queries.
    pub socket: UdpSocket,
    /// Domain name for decoding queries.
    pub domain: String,
    /// Queue of decoded incoming QUIC packets (from DNS queries).
    /// Each entry contains the raw QUIC bytes and the original peer info.
    pub incoming_quic: VecDeque<(Vec<u8>, PendingQuery)>,
    /// Queue of pending DNS queries waiting for QUIC responses.
    /// The server uses the FIFO order to match queries with responses.
    pub pending_queries: VecDeque<PendingQuery>,
}

pub type ServerDnsSocket = Arc<Mutex<ServerDnsSocketInner>>;

impl ServerDnsSocketInner {
    pub async fn new(bind_addr: SocketAddr, domain: String) -> Result<Self> {
        // Use socket2 to set SO_REUSEPORT on Linux for better performance
        let socket = bind_udp_server(bind_addr).await?;
        Ok(Self {
            socket,
            domain,
            incoming_quic: VecDeque::new(),
            pending_queries: VecDeque::new(),
        })
    }

    /// Try to receive a DNS query and decode it.
    /// Returns Ok(Some((quic_bytes, peer_info))) or Ok(None) if no data available.
    pub fn try_recv_query(&mut self) -> io::Result<Option<(Vec<u8>, PendingQuery)>> {
        let mut buf = vec![0u8; 4096];
        match self.socket.try_recv_from(&mut buf) {
            Ok((n, peer)) => {
                trace!(bytes = n, %peer, "server received DNS query");
                let wire = &buf[..n];
                match decode_dns_query(wire, &self.domain) {
                    Ok((_, quic_bytes)) => {
                        let pending = PendingQuery {
                            peer_addr: peer,
                            dns_id_wire: [wire[0], wire[1]],
                            query_wire: wire.to_vec(),
                        };
                        Ok(Some((quic_bytes, pending)))
                    }
                    Err(e) => {
                        // Not a valid tunnel query — might be a real DNS query from a resolver
                        // probing us, or a malformed packet. Send NXDOMAIN and ignore.
                        debug!(%e, %peer, "received non-tunnel DNS query, sending NXDOMAIN");
                        let _ = self.send_nxdomain(wire, peer);
                        Ok(None)
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Send a DNS response wrapping `quic_data` back to the `pending` requester.
    pub fn send_response(&self, quic_data: &[u8], pending: &PendingQuery) -> io::Result<()> {
        match encode_dns_response(&pending.query_wire, quic_data) {
            Ok(dns_resp) => {
                match self.socket.try_send_to(&dns_resp, pending.peer_addr) {
                    Ok(n) => {
                        trace!(bytes = n, peer = %pending.peer_addr, "server sent DNS response");
                        Ok(())
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        warn!("server DNS send would block, dropping response");
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => {
                warn!(%e, "failed to encode DNS response");
                Ok(())
            }
        }
    }

    /// Send NXDOMAIN for a non-tunnel query so DNS resolvers probing us get a valid response.
    fn send_nxdomain(&self, query_wire: &[u8], peer: SocketAddr) -> io::Result<()> {
        match encode_dns_response(query_wire, &[]) {
            Ok(resp) => {
                let _ = self.socket.try_send_to(&resp, peer);
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }
}

// ── Socket binding helpers ─────────────────────────────────────────────────────

/// Bind a UDP socket for the DNS server with SO_REUSEADDR.
async fn bind_udp_server(addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn dummy_addr_parses() {
        let addr = dummy_peer_addr();
        assert_eq!(addr.port(), DUMMY_PEER_PORT);
        assert_eq!(
            addr.ip(),
            IpAddr::V4(DUMMY_PEER_IP.parse::<std::net::Ipv4Addr>().unwrap())
        );
    }
}
