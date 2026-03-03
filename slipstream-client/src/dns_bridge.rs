//! DNS ↔ TQUIC bridge — client side.
//!
//! Client→Server: large QUIC packets are fragmented into small DNS queries
//! using encode_dns_queries (adds [frag_id:2][seq:1][total:1] header per query).
//!
//! Server→Client: one complete raw QUIC packet per DNS TXT response, no header.
//! Simply call decode_dns_response and return the bytes directly.

use slipstream_core::{decode_dns_response, encode_dns_queries, encode_dns_query};
use tracing::{debug, trace, warn};

pub struct ClientDnsBridge {
    domain:      String,
    rr_idx:      usize,
    n_resolvers: usize,
}

impl ClientDnsBridge {
    pub fn new(domain: String, n_resolvers: usize) -> Self {
        Self { domain, rr_idx: 0, n_resolvers }
    }

    /// Encode a QUIC packet into one or more `(resolver_idx, dns_wire)` pairs.
    /// Large packets are fragmented; each fragment becomes one DNS query.
    pub fn encode_quic_packet(&mut self, quic_data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        let fragments: Vec<Vec<u8>> = match encode_dns_queries(quic_data, &self.domain) {
            Ok(f)  => f,
            Err(e) => { warn!(%e, "encode_dns_queries failed"); return Vec::new(); }
        };
        let n = self.n_resolvers.max(1);
        let mut out = Vec::with_capacity(fragments.len());
        for frag in fragments {
            let ri = self.rr_idx % n;
            self.rr_idx = self.rr_idx.wrapping_add(1);
            out.push((ri, frag));
        }
        out
    }

    /// Build a keepalive/poll DNS query for the given resolver index.
    /// Sends a one-fragment query with empty payload so the server can
    /// return any queued QUIC packets in the response.
    pub fn encode_keepalive(&self, resolver_idx: usize) -> Option<(usize, Vec<u8>)> {
        let frag_id: u16 = rand::random();
        let mut payload  = Vec::with_capacity(4);
        payload.extend_from_slice(&frag_id.to_be_bytes());
        payload.push(0); // seq = 0
        payload.push(1); // total = 1 (single empty fragment)
        match encode_dns_query(&payload, &self.domain) {
            Ok(wire) => Some((resolver_idx, wire)),
            Err(e)   => { warn!(%e, "encode_keepalive failed"); None }
        }
    }

    /// Decode a DNS response → raw QUIC packet (or None for empty responses).
    ///
    /// Server→client: one complete QUIC packet per response, no fragmentation header.
    pub fn decode_dns_response(&self, wire: &[u8], resolver_idx: usize) -> Option<Vec<u8>> {
        match decode_dns_response(wire) {
            Ok(Some(data)) => {
                debug!(resolver_idx, bytes = data.len(), "DNS response: QUIC data");
                Some(data)
            }
            Ok(None) => {
                trace!(resolver_idx, "DNS response: empty (server has no data yet)");
                None
            }
            Err(e) => {
                debug!(%e, resolver_idx, "DNS response decode failed");
                None
            }
        }
    }
}
