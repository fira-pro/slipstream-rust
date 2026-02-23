//! DNS ↔ TQUIC bridge — client side.
//!
//! Handles:
//! 1. **Fragmentation**: large QUIC packets → multiple DNS TXT queries (one per resolver, round-robin)
//! 2. **Keepalive polling**: empty DNS queries maintain a flow of "slots" for the server to respond into
//! 3. **Reassembly**: incoming DNS TXT responses → QUIC packets injected into TQUIC
//!
//! **Multipath**: with N resolvers we maintain N mio-registered UDP sockets.
//! Outgoing fragments are sent round-robin across all resolvers.
//! Each resolver has its own fragment reassembly state (since they may deliver out of order).

use std::{
    collections::HashMap,
    net::SocketAddr,
};

use slipstream_core::{decode_dns_response, encode_dns_queries, encode_dns_query, FRAG_HEADER_LEN};
use tracing::{debug, trace, warn};

/// Inbound fragment reassembly state per (resolver, frag_id).
struct FragBuf {
    total: u8,
    chunks: HashMap<u8, Vec<u8>>,
}

pub struct ClientDnsBridge {
    domain: String,
    /// Round-robin index for outgoing fragment dispatch.
    rr_idx: usize,
    /// Total number of resolver sockets (indexed 0..N).
    n_resolvers: usize,
    /// Fragment reassembly state per (resolver_idx, frag_id).
    frag_map: HashMap<(usize, u16), FragBuf>,
}

impl ClientDnsBridge {
    pub fn new(domain: String, n_resolvers: usize) -> Self {
        Self {
            domain,
            rr_idx: 0,
            n_resolvers,
            frag_map: HashMap::new(),
        }
    }

    /// Encode a QUIC packet into one or more DNS query wire blobs.
    ///
    /// Returns a `Vec<(resolver_idx, dns_wire)>` — each fragment dispatched
    /// to a specific resolver socket index (round-robin across all).
    pub fn encode_quic_packet(&mut self, quic_data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        let fragments = match encode_dns_queries(quic_data, &self.domain) {
            Ok(f) => f,
            Err(e) => {
                warn!(%e, "encode_dns_queries failed");
                return Vec::new();
            }
        };

        let n = self.n_resolvers.max(1);
        let mut out = Vec::with_capacity(fragments.len());
        for frag in fragments {
            let resolver_idx = self.rr_idx % n;
            self.rr_idx = self.rr_idx.wrapping_add(1);
            out.push((resolver_idx, frag));
        }
        out
    }

    /// Build an empty DNS keepalive/poll query (seq=0, total=1, no QUIC payload).
    pub fn encode_keepalive(&self, resolver_idx: usize) -> Option<(usize, Vec<u8>)> {
        // 4-byte frag header: random id, seq=0, total=1 (empty payload signals keepalive)
        let frag_id: u16 = rand::random();
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&frag_id.to_be_bytes());
        payload.push(0); // seq
        payload.push(1); // total=1 (single "empty" fragment)
        // Note: no actual QUIC data appended

        match encode_dns_query(&payload, &self.domain) {
            Ok(wire) => Some((resolver_idx, wire)),
            Err(e) => {
                warn!(%e, "encode keepalive failed");
                None
            }
        }
    }

    /// Process an incoming DNS response from a resolver.
    ///
    /// Returns `Some(quic_packet)` if a reassembled QUIC packet is ready.
    pub fn decode_dns_response(&mut self, wire: &[u8], resolver_idx: usize) -> Option<Vec<u8>> {
        match decode_dns_response(wire) {
            Ok(Some(data)) => {
                // data includes the frag header (if any)
                self.try_reassemble(&data, resolver_idx)
            }
            Ok(None) => {
                // NXDOMAIN — server has no data, keepalive was acknowledged
                trace!(resolver_idx, "NXDOMAIN response (server empty)");
                None
            }
            Err(e) => {
                debug!(%e, resolver_idx, "DNS response decode failed");
                None
            }
        }
    }

    fn try_reassemble(&mut self, data: &[u8], resolver_idx: usize) -> Option<Vec<u8>> {
        if data.len() < FRAG_HEADER_LEN {
            // Bare data (no header) — shouldn't happen in our protocol
            return Some(data.to_vec());
        }
        let frag_id = u16::from_be_bytes([data[0], data[1]]);
        let seq = data[2];
        let total = data[3];
        let chunk = data[FRAG_HEADER_LEN..].to_vec();

        if total == 0 {
            return None; // keepalive echo
        }
        if total == 1 {
            return Some(chunk); // single fragment fast path
        }

        let key = (resolver_idx, frag_id);
        let entry = self.frag_map.entry(key).or_insert_with(|| FragBuf {
            total,
            chunks: HashMap::new(),
        });
        entry.chunks.insert(seq, chunk);

        if entry.chunks.len() as u8 == entry.total {
            let t = entry.total;
            let mut out = Vec::new();
            for i in 0..t {
                if let Some(c) = entry.chunks.get(&i) {
                    out.extend_from_slice(c);
                }
            }
            self.frag_map.remove(&key);
            Some(out)
        } else {
            None
        }
    }
}
