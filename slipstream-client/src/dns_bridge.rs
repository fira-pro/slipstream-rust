//! DNS ↔ TQUIC bridge — client side.

use std::collections::HashMap;

use slipstream_core::{decode_dns_response, encode_dns_queries, encode_dns_query, FRAG_HEADER_LEN};
use tracing::{debug, trace, warn};

struct FragBuf {
    total:  u8,
    chunks: HashMap<u8, Vec<u8>>,
}

pub struct ClientDnsBridge {
    domain:      String,
    rr_idx:      usize,
    n_resolvers: usize,
    frag_map:    HashMap<(usize, u16), FragBuf>,
}

impl ClientDnsBridge {
    pub fn new(domain: String, n_resolvers: usize) -> Self {
        Self { domain, rr_idx: 0, n_resolvers, frag_map: HashMap::new() }
    }

    /// Encode a QUIC packet into one or more `(resolver_idx, dns_wire)` pairs.
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

    /// Build an empty keepalive/poll DNS query for the given resolver index.
    pub fn encode_keepalive(&self, resolver_idx: usize) -> Option<(usize, Vec<u8>)> {
        let frag_id: u16 = rand::random();
        let mut payload  = Vec::with_capacity(4);
        payload.extend_from_slice(&frag_id.to_be_bytes());
        payload.push(0); // seq
        payload.push(1); // total=1 (single empty fragment)
        match encode_dns_query(&payload, &self.domain) {
            Ok(wire) => Some((resolver_idx, wire)),
            Err(e)   => { warn!(%e, "encode keepalive failed"); None }
        }
    }

    /// Decode an incoming DNS response from a resolver → raw QUIC packet.
    ///
    /// Server→client direction: one complete QUIC packet per DNS response,
    /// embedded directly in a TXT record with NO fragmentation header.
    /// Simply decode and return — no reassembly needed.
    pub fn decode_dns_response(&mut self, wire: &[u8], resolver_idx: usize) -> Option<Vec<u8>> {
        match decode_dns_response(wire) {
            Ok(Some(data)) => {
                debug!(resolver_idx, bytes = data.len(), "DNS response: got QUIC data");
                Some(data)
            }
            Ok(None) => {
                trace!(resolver_idx, "DNS response: NXDOMAIN (server empty)");
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
            return Some(data.to_vec()); // unfragmented bare data
        }
        let frag_id = u16::from_be_bytes([data[0], data[1]]);
        let seq     = data[2];
        let total   = data[3];
        let chunk   = data[FRAG_HEADER_LEN..].to_vec();

        if total == 0 { return None; }
        if total == 1 { return Some(chunk); }

        let key   = (resolver_idx, frag_id);
        let entry = self.frag_map.entry(key).or_insert_with(|| FragBuf { total, chunks: HashMap::new() });
        entry.chunks.insert(seq, chunk);

        if entry.chunks.len() as u8 == entry.total {
            let t = entry.total;
            let mut out = Vec::new();
            for i in 0..t {
                if let Some(c) = entry.chunks.get(&i) { out.extend_from_slice(c); }
            }
            self.frag_map.remove(&key);
            Some(out)
        } else {
            None
        }
    }
}
