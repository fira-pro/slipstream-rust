//! DNS ↔ TQUIC bridge — server side.
//!
//! ## Output-queue model:
//!
//! QUIC packets from TQUIC (via `PacketSendHandler::on_packets_to_send`) are
//! pushed into a bounded `output_q`.  Every incoming DNS query immediately
//! pops the oldest entry and wraps it in a TXT response.  If nothing is queued
//! we send NXDOMAIN — the client keepalive polls again within ~20ms.
//!
//! Fragment reassembly: clients may split large QUIC Initial packets across
//! multiple DNS queries.  We buffer them by frag_id until all chunks arrive,
//! then yield the assembled QUIC packet to the caller.

use std::collections::{HashMap, VecDeque};

use slipstream_core::{decode_dns_query_frag, encode_dns_response};
use tracing::{debug, warn};

/// Maximum outbound QUIC packets buffered before oldest is dropped.
pub const MAX_Q: usize = 16;

pub struct DnsBridge {
    /// Outbound QUIC packets waiting for a DNS query to carry them.
    output_q: VecDeque<Vec<u8>>,
    /// Inbound fragment reassembly: frag_id → (total, seq→chunk)
    frag_map: HashMap<u16, FragBuf>,
    /// Domain name used for QNAME decoding
    domain: String,
}

struct FragBuf {
    total: u8,
    chunks: HashMap<u8, Vec<u8>>,
}

impl DnsBridge {
    pub fn new(domain: String) -> Self {
        Self {
            output_q: VecDeque::new(),
            frag_map: HashMap::new(),
            domain,
        }
    }

    /// Push an outbound QUIC packet (from TQUIC's send handler) into the queue.
    pub fn push_quic_packet(&mut self, data: Vec<u8>) {
        if self.output_q.len() >= MAX_Q {
            self.output_q.pop_front(); // drop oldest
            debug!("output_q full — dropped oldest QUIC packet");
        }
        self.output_q.push_back(data);
    }

    /// Handle an incoming raw DNS query UDP datagram from the network.
    ///
    /// Returns:
    /// - `response_wire` — DNS wire bytes to send back to `src` (always present)
    /// - `Option<Vec<u8>>` — fully reassembled QUIC packet to inject into TQUIC
    #[allow(dead_code)]
    pub fn handle_query(&mut self, wire: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        // 1. Decode and reassemble.
        let assembled = match decode_dns_query_frag(wire, &self.domain) {
            Ok((frag_id, seq, total, chunk)) => {
                self.reassemble(frag_id, seq, total, chunk)
            }
            Err(e) => {
                // Not a tunnel query (e.g. resolver health check) or malformed.
                debug!(%e, "decode_dns_query_frag failed — sending NXDOMAIN");
                None
            }
        };

        // 2. Build DNS response: pop queued QUIC data, or NXDOMAIN (empty slice).
        let quic_payload = self.output_q.pop_front();
        let payload_ref: &[u8] = quic_payload.as_deref().unwrap_or(&[]);

        let response = match encode_dns_response(wire, payload_ref) {
            Ok(r) => r,
            Err(e) => {
                warn!(%e, "encode_dns_response failed");
                Vec::new()
            }
        };

        (response, assembled)
    }

    /// Step 1 of the split API: decode DNS query → return (raw_wire, reassembled_quic_packet).
    /// The raw_wire is kept so encode_response() can mirror the DNS transaction ID.
    pub fn decode_query(&mut self, wire: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        let assembled = match decode_dns_query_frag(wire, &self.domain) {
            Ok((frag_id, seq, total, chunk)) => {
                tracing::debug!(frag_id, seq, total, chunk_len = chunk.len(), "DNS query fragment");
                self.reassemble(frag_id, seq, total, chunk)
            }
            Err(e) => {
                tracing::debug!(%e, "decode_dns_query_frag failed (keepalive or non-tunnel query)");
                None
            }
        };
        if let Some(ref pkt) = assembled {
            tracing::info!(bytes = pkt.len(), "QUIC packet assembled from DNS fragments → inject into TQUIC");
        }
        (wire.to_vec(), assembled)
    }

    /// Step 2 of the split API: pop queued QUIC output and encode a DNS response.
    /// Call AFTER endpoint.recv() + process_connections() so the output_q is populated.
    pub fn encode_response(&mut self, raw_query: &[u8]) -> Vec<u8> {
        let quic_payload = self.output_q.pop_front();
        if let Some(ref p) = quic_payload {
            tracing::info!(bytes = p.len(), q_remaining = self.output_q.len(), "Sending QUIC packet back to client via DNS response");
        }
        let payload_ref: &[u8] = quic_payload.as_deref().unwrap_or(&[]);
        match encode_dns_response(raw_query, payload_ref) {
            Ok(r) => r,
            Err(e) => { warn!(%e, "encode_dns_response failed"); Vec::new() }
        }
    }

    fn reassemble(&mut self, frag_id: u16, seq: u8, total: u8, chunk: Vec<u8>) -> Option<Vec<u8>> {
        if total == 0 {
            // Keepalive / empty poll — no data
            return None;
        }
        if total == 1 {
            // Fast path: single-fragment packet
            return Some(chunk);
        }

        let entry = self.frag_map.entry(frag_id).or_insert_with(|| FragBuf {
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
            self.frag_map.remove(&frag_id);
            Some(out)
        } else {
            None
        }
    }
}
