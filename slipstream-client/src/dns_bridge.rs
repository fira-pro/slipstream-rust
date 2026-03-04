//! DNS ↔ TQUIC bridge — client side.
//!
//! Client→Server: large QUIC packets are fragmented into small DNS queries
//! using encode_dns_queries (adds [frag_id:2][seq:1][total:1] header per query).
//!
//! Server→Client: one or more raw QUIC packets per DNS TXT response, packed
//! using 2-byte big-endian length-prefix framing:
//!   `[len_hi][len_lo][packet bytes] [len_hi][len_lo][packet bytes] ...`
//! We unpack each and return them separately for injection into TQUIC.

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
        payload.push(0); // total = 0 → server reassemble() returns None (pure poll)
        match encode_dns_query(&payload, &self.domain) {
            Ok(wire) => Some((resolver_idx, wire)),
            Err(e)   => { warn!(%e, "encode_keepalive failed"); None }
        }
    }

    /// Decode a DNS response → zero or more raw QUIC packets.
    ///
    /// Server→client responses carry one or more QUIC packets packed with
    /// 2-byte big-endian length-prefix framing.  We unpack all of them.
    /// Returns an empty Vec for NXDOMAIN / empty / malformed responses.
    pub fn decode_dns_response(&self, wire: &[u8], resolver_idx: usize) -> Vec<Vec<u8>> {
        match decode_dns_response(wire) {
            Ok(Some(data)) => {
                let pkts = unpack_framed(&data);
                debug!(resolver_idx, n_pkts = pkts.len(), bytes = data.len(), "DNS response: QUIC data");
                pkts
            }
            Ok(None) => {
                trace!(resolver_idx, "DNS response: empty (server has no data yet)");
                Vec::new()
            }
            Err(e) => {
                debug!(%e, resolver_idx, "DNS response decode failed");
                Vec::new()
            }
        }
    }
}

/// Unpack `[u16-BE len][bytes] ...` framing into individual packets.
///
/// Falls back to treating the entire payload as a single raw packet if the
/// framing doesn't parse correctly (e.g. connecting to an older server build).
fn unpack_framed(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() {
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            // Malformed frame — treat whole remaining slice as one raw packet
            // (backwards-compat with unframed servers)
            if out.is_empty() {
                out.push(data.to_vec());
            } else {
                warn!(pos, len, total = data.len(), "framed DNS response: truncated packet, dropping tail");
            }
            return out;
        }
        out.push(data[pos..pos + len].to_vec());
        pos += len;
    }

    if out.is_empty() && !data.is_empty() {
        // No frames decoded — either empty or old unframed format
        out.push(data.to_vec());
    }

    out
}
