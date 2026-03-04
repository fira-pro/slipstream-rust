//! DNS ↔ TQUIC bridge — server side.
//!
//! ## Output-queue model:
//!
//! QUIC packets from TQUIC (via `PacketSendHandler::on_packets_to_send`) are
//! pushed into a bounded `output_q`.  Every incoming DNS query immediately
//! pops as many entries as fit in the DNS TXT payload and wraps them in a
//! single TXT response.  If nothing is queued we send NXDOMAIN — the client
//! keepalive polls again within ~20ms.
//!
//! ## Multi-packet framing (server→client):
//!
//! To maximise throughput each DNS TXT response may carry multiple QUIC
//! packets encoded as:
//!   `[len_hi][len_lo][packet bytes] ...`
//! up to ~MAX_RESP_PAYLOAD bytes.  The client splits them apart and feeds
//! each one to TQUIC individually.  A single-packet response is still
//! framed this way for consistency.
//!
//! ## Fragment reassembly (client→server):
//!
//! Clients may split large QUIC Initial packets across multiple DNS queries.
//! We buffer them by frag_id until all chunks arrive, then yield the
//! assembled QUIC packet to the caller.

use std::collections::{HashMap, VecDeque};

use slipstream_core::{decode_dns_query_frag, encode_dns_response};
use tracing::{debug, warn};

/// Maximum outbound QUIC packets buffered before oldest is dropped.
/// Must be large enough to absorb the QUIC handshake burst (Server Hello,
/// cert chain, Finished, ACKs) without dropping packets.
pub const MAX_Q: usize = 512;

/// Maximum QUIC payload bytes we pack into a single DNS TXT response.
/// EDNS0 UDP payload is 1232 bytes (RFC 9210 recommendation), minus DNS
/// headers (~60 bytes) gives ~1170 bytes of TXT content.
/// With external resolvers the practical limit is even lower (~900-1000 bytes
/// after resolver overhead), so we conservatively cap at 1100 bytes to keep
/// both paths working.
const MAX_RESP_PAYLOAD: usize = 1100;

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

    /// Step 1 of the split API: decode DNS query → return (raw_wire, reassembled_quic_packet).
    /// The raw_wire is kept so encode_response() can mirror the DNS transaction ID.
    pub fn decode_query(&mut self, wire: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        let assembled = match decode_dns_query_frag(wire, &self.domain) {
            Ok((frag_id, seq, total, chunk)) => self.reassemble(frag_id, seq, total, chunk),
            Err(e) => {
                debug!(%e, "decode_dns_query_frag failed — NXDOMAIN");
                None
            }
        };
        (wire.to_vec(), assembled)
    }

    /// Step 2 of the split API: pop queued QUIC output and encode a DNS response.
    ///
    /// Packs as many complete QUIC packets as fit within `MAX_RESP_PAYLOAD`
    /// into a single TXT record using 2-byte length-prefix framing:
    ///   `[len_hi][len_lo][packet_bytes] ...`
    ///
    /// Call AFTER endpoint.recv() + process_connections() so the output_q is populated.
    pub fn encode_response(&mut self, raw_query: &[u8]) -> Vec<u8> {
        let payload = self.pop_packed_payload();
        match encode_dns_response(raw_query, &payload) {
            Ok(r) => r,
            Err(e) => {
                warn!(%e, "encode_dns_response failed");
                Vec::new()
            }
        }
    }

    /// Drain output_q, packing packets into a framed buffer up to MAX_RESP_PAYLOAD.
    ///
    /// Format: repeated `[u16 big-endian length][packet bytes]`.
    /// Returns empty slice if queue is empty (→ NXDOMAIN response).
    fn pop_packed_payload(&mut self) -> Vec<u8> {
        if self.output_q.is_empty() {
            return Vec::new();
        }

        let mut payload: Vec<u8> = Vec::with_capacity(MAX_RESP_PAYLOAD);

        while let Some(pkt) = self.output_q.front() {
            // 2-byte length header + packet must fit in remaining budget
            let frame_len = 2 + pkt.len();
            if !payload.is_empty() && payload.len() + frame_len > MAX_RESP_PAYLOAD {
                break; // leave for next query
            }
            // pkt is too big on its own — send it alone (shouldn't happen for QUIC pkts)
            if pkt.len() > MAX_RESP_PAYLOAD - 2 {
                if payload.is_empty() {
                    let pkt = self.output_q.pop_front().unwrap();
                    let len = pkt.len() as u16;
                    payload.extend_from_slice(&len.to_be_bytes());
                    payload.extend_from_slice(&pkt);
                }
                break;
            }
            let pkt = self.output_q.pop_front().unwrap();
            let len = pkt.len() as u16;
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(&pkt);
        }

        debug!(
            packed = payload.len(),
            queue_remaining = self.output_q.len(),
            "packed DNS response"
        );

        payload
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
