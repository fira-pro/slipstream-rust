//! DNS encode/decode for DNS tunnel.
//!
//! **Client → Server** (upstream):
//!   raw QUIC bytes → base32 → dotified labels → DNS TXT query QNAME
//!
//! **Server → Client** (downstream):
//!   raw QUIC bytes → DNS TXT response RDATA (binary, NOT base32)
//!
//! This closely mirrors the original C slipstream encoding with these improvements:
//!   - Thread-safe random query IDs (rand::thread_rng)
//!   - Proper error propagation (no silent failures)
//!   - No global mutable state

use anyhow::{bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use rand::Rng;

// DNS wire format constants
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_OPT: u16 = 41;
const DNS_CLASS_IN: u16 = 1;

/// Maximum number of bytes in a DNS label (RFC 1035 §2.3.4).
const MAX_LABEL: usize = 63;

// ── Dotify / Undotify ─────────────────────────────────────────────────────────

/// Insert dots every 63 characters so the string forms valid DNS labels.
/// Returns the resulting string. Mirrors `slipstream_inline_dotify`.
pub fn dotify(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / MAX_LABEL + 1);
    for (i, ch) in s.char_indices() {
        if i > 0 && i % MAX_LABEL == 0 {
            out.push('.');
        }
        out.push(ch);
    }
    out
}

/// Remove all dots from the string. Mirrors `slipstream_inline_undotify`.
pub fn undotify(s: &str) -> String {
    s.chars().filter(|&c| c != '.').collect()
}

// ── DNS Message Wire Encoding Helpers ─────────────────────────────────────────

/// Write a DNS name (sequence of labels) into `buf`, advancing `pos`.
/// Name is a dot-separated string like `"abc.def.example.com"`.
fn write_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0u8); // root label
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encode `quic_data` as a DNS TXT query targeting `<b32-subdomain>.<domain>`.
///
/// Returns the raw DNS wire-format query bytes.
/// `quic_data` must be ≤ `Config::client_mtu` bytes (the caller is responsible).
pub fn encode_dns_query(quic_data: &[u8], domain: &str) -> Result<Vec<u8>> {
    // Base32-encode (no padding, uppercase)
    let encoded = BASE32_NOPAD.encode(quic_data);

    // Add dots every 63 chars to form valid labels
    let dotted = dotify(&encoded);

    // Full QNAME: <dotted-b32>.<domain>
    let qname = format!("{}.{}.", dotted, domain);

    // Sanity check: QNAME must be ≤ 253 chars (DNS limit)
    if qname.len() > 253 + 1 {
        // +1 for trailing dot
        bail!(
            "encode_dns_query: QNAME too long ({} bytes): '{}'",
            qname.len(),
            &qname[..60.min(qname.len())]
        );
    }

    let id: u16 = rand::thread_rng().gen();
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    // DNS header (12 bytes)
    write_u16(&mut buf, id); // ID
    write_u16(&mut buf, 0x0100u16); // Flags: QR=0, Opcode=0, RD=1
    write_u16(&mut buf, 1); // QDCOUNT
    write_u16(&mut buf, 0); // ANCOUNT
    write_u16(&mut buf, 0); // NSCOUNT
    write_u16(&mut buf, 1); // ARCOUNT (EDNS0 OPT)

    // Question section
    write_name(&mut buf, &qname);
    write_u16(&mut buf, DNS_TYPE_TXT); // QTYPE
    write_u16(&mut buf, DNS_CLASS_IN); // QCLASS

    // Additional: EDNS0 OPT pseudo-RR
    buf.push(0); // empty name (root)
    write_u16(&mut buf, DNS_TYPE_OPT); // TYPE = OPT (41)
    write_u16(&mut buf, 1232); // CLASS = requestor's UDP payload size
    write_u32(&mut buf, 0); // TTL = extended RCODE (0) + version (0) + flags (0)
    write_u16(&mut buf, 0); // RDLENGTH = 0 (no options)

    Ok(buf)
}

/// Decode a DNS TXT query, extracting the base32-encoded QUIC payload from QNAME.
///
/// Returns `(query_id, quic_bytes)` so the server can match the response.
/// The `domain` suffix is stripped from the QNAME before decoding.
pub fn decode_dns_query(wire: &[u8], domain: &str) -> Result<(u16, Vec<u8>)> {
    if wire.len() < 12 {
        bail!("decode_dns_query: packet too short ({} bytes)", wire.len());
    }

    let id = u16::from_be_bytes([wire[0], wire[1]]);
    let flags = u16::from_be_bytes([wire[2], wire[3]]);

    // QR bit must be 0 (query)
    if flags & 0x8000 != 0 {
        bail!("decode_dns_query: packet is a response, not a query");
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    if qdcount != 1 {
        bail!("decode_dns_query: expected 1 question, got {}", qdcount);
    }

    // Parse QNAME starting at offset 12
    let (qname, after_qname) = parse_name(wire, 12)?;

    // Check QTYPE == TXT
    if after_qname + 4 > wire.len() {
        bail!("decode_dns_query: truncated question section");
    }
    let qtype = u16::from_be_bytes([wire[after_qname], wire[after_qname + 1]]);
    if qtype != DNS_TYPE_TXT {
        bail!("decode_dns_query: QTYPE is {} (expected TXT=16)", qtype);
    }

    // Extract subdomain part: strip ".<domain>." suffix
    let suffix = format!(".{}.", domain);
    let suffix_upper = suffix.to_ascii_uppercase();
    let qname_upper = qname.to_ascii_uppercase();

    let subdomain = if qname_upper.ends_with(&suffix_upper) {
        &qname[..qname.len() - suffix.len()]
    } else if qname_upper.ends_with(&format!(".{}",domain.to_ascii_uppercase())) {
        &qname[..qname.len() - domain.len() - 1]
    } else {
        bail!(
            "decode_dns_query: QNAME '{}' does not end with domain '{}'",
            qname,
            domain
        );
    };

    // Remove dots (label separators) inserted by dotify
    let undotted = undotify(subdomain);

    // Base32 decode
    let quic_bytes = BASE32_NOPAD
        .decode(undotted.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("decode_dns_query: base32 decode failed for '{}'", undotted))?;

    Ok((id, quic_bytes))
}

/// Encode `quic_data` as a DNS TXT response to the given `query_wire`.
///
/// Mirrors the original C `server_encode`: copies the question section from the
/// query and puts the raw QUIC bytes directly in a TXT RDATA.
/// If `quic_data` is empty, returns NXDOMAIN (RCODE_NAME_ERROR) as original does.
pub fn encode_dns_response(query_wire: &[u8], quic_data: &[u8]) -> Result<Vec<u8>> {
    if query_wire.len() < 12 {
        bail!("encode_dns_response: query too short");
    }

    let id = u16::from_be_bytes([query_wire[0], query_wire[1]]);
    let query_flags = u16::from_be_bytes([query_wire[2], query_wire[3]]);
    let rd = (query_flags & 0x0100) != 0;
    let cd = (query_flags & 0x0010) != 0;

    let qdcount = u16::from_be_bytes([query_wire[4], query_wire[5]]);
    if qdcount < 1 {
        bail!("encode_dns_response: no questions in query");
    }

    // Re-parse the QNAME for including in the answer
    let (qname, after_qname) = parse_name(query_wire, 12)?;
    if after_qname + 4 > query_wire.len() {
        bail!("encode_dns_response: truncated question");
    }
    let qtype = u16::from_be_bytes([query_wire[after_qname], query_wire[after_qname + 1]]);
    let qclass = u16::from_be_bytes([query_wire[after_qname + 2], query_wire[after_qname + 3]]);

    // Response flags: QR=1, AA=1, RD=copy, CD=copy
    let mut rflags: u16 = 0x8400; // QR=1, AA=1
    if rd {
        rflags |= 0x0100;
    }
    if cd {
        rflags |= 0x0010;
    }

    let (ancount, rcode): (u16, u16) = if quic_data.is_empty() {
        (0, 3) // NXDOMAIN
    } else {
        (1, 0) // NOERROR
    };

    rflags |= rcode & 0x000F;

    let mut buf: Vec<u8> = Vec::with_capacity(512);

    // Header
    write_u16(&mut buf, id);
    write_u16(&mut buf, rflags);
    write_u16(&mut buf, 1); // QDCOUNT
    write_u16(&mut buf, ancount); // ANCOUNT
    write_u16(&mut buf, 0); // NSCOUNT
    write_u16(&mut buf, 1); // ARCOUNT (EDNS0)

    // Question (echo back)
    write_name(&mut buf, &qname);
    write_u16(&mut buf, qtype);
    write_u16(&mut buf, qclass);

    // Answer (if we have data)
    if !quic_data.is_empty() {
        write_name(&mut buf, &qname);
        write_u16(&mut buf, DNS_TYPE_TXT);
        write_u16(&mut buf, DNS_CLASS_IN);
        write_u32(&mut buf, 60); // TTL

        // TXT RDATA: length-prefixed strings
        // We use a single string per TXT record. DNS TXT strings are
        // prefixed by a 1-byte length. Max per string is 255 bytes.
        // For large payloads we chunk into 255-byte strings.
        let chunks: Vec<&[u8]> = quic_data.chunks(255).collect();
        let rdata_len: usize = chunks.iter().map(|c| 1 + c.len()).sum();
        write_u16(&mut buf, rdata_len as u16); // RDLENGTH

        for chunk in &chunks {
            buf.push(chunk.len() as u8); // string length prefix
            buf.extend_from_slice(chunk);
        }
    }

    // EDNS0 OPT
    buf.push(0); // root name
    write_u16(&mut buf, DNS_TYPE_OPT);
    write_u16(&mut buf, 1232); // max UDP payload
    write_u32(&mut buf, 0); // extended RCODE + version + flags
    write_u16(&mut buf, 0); // RDLENGTH

    Ok(buf)
}

/// Decode a DNS TXT response, extracting the raw QUIC payload from the TXT RDATA.
///
/// Returns the raw bytes. Returns `Ok(None)` if RCODE=NXDOMAIN (server has no data).
/// Returns `Err` on malformed packets.
pub fn decode_dns_response(wire: &[u8]) -> Result<Option<Vec<u8>>> {
    if wire.len() < 12 {
        bail!("decode_dns_response: packet too short ({} bytes)", wire.len());
    }

    let flags = u16::from_be_bytes([wire[2], wire[3]]);

    // QR bit must be 1 (response)
    if flags & 0x8000 == 0 {
        bail!("decode_dns_response: packet is a query, not a response");
    }

    let rcode = flags & 0x000F;
    if rcode == 3 {
        // NXDOMAIN — server has nothing to send, that's fine
        return Ok(None);
    }
    if rcode != 0 {
        // Any other non-zero RCODE is unexpected but we log and skip
        tracing::debug!("decode_dns_response: non-zero RCODE={}, treating as empty", rcode);
        return Ok(None);
    }

    let ancount = u16::from_be_bytes([wire[6], wire[7]]);
    if ancount == 0 {
        return Ok(None);
    }

    // Skip question section
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_, after) = parse_name(wire, pos)?;
        pos = after + 4; // skip QTYPE + QCLASS
        if pos > wire.len() {
            bail!("decode_dns_response: truncated question section");
        }
    }

    // Parse answer records until we find a TXT
    for _ in 0..ancount {
        let (_, after_name) = parse_name(wire, pos)?;
        if after_name + 10 > wire.len() {
            bail!("decode_dns_response: truncated answer RR");
        }
        let rtype = u16::from_be_bytes([wire[after_name], wire[after_name + 1]]);
        let rdlength = u16::from_be_bytes([wire[after_name + 8], wire[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start + rdlength;

        if rdata_end > wire.len() {
            bail!("decode_dns_response: RR RDATA extends past packet");
        }

        pos = rdata_end;

        if rtype != DNS_TYPE_TXT {
            continue;
        }

        // TXT RDATA: one or more length-prefixed strings; concatenate them.
        let mut data = Vec::with_capacity(rdlength);
        let mut rpos = rdata_start;
        while rpos < rdata_end {
            let slen = wire[rpos] as usize;
            rpos += 1;
            if rpos + slen > rdata_end {
                bail!("decode_dns_response: TXT string extends past RDATA");
            }
            data.extend_from_slice(&wire[rpos..rpos + slen]);
            rpos += slen;
        }

        return Ok(Some(data));
    }

    // No TXT record found in answers
    Ok(None)
}

// ── DNS Name Parser ───────────────────────────────────────────────────────────

/// Parse a DNS name at `offset` in `wire`. Returns `(name_string, next_offset)`.
/// Handles message compression pointers.
fn parse_name(wire: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut end_pos = 0;
    let mut jumps = 0;

    loop {
        if pos >= wire.len() {
            bail!("parse_name: offset {} out of bounds (len={})", pos, wire.len());
        }
        let byte = wire[pos];

        // Compression pointer (top 2 bits = 11)
        if byte & 0xC0 == 0xC0 {
            if pos + 1 >= wire.len() {
                bail!("parse_name: truncated compression pointer at {}", pos);
            }
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            let ptr = (((byte & 0x3F) as usize) << 8) | wire[pos + 1] as usize;
            pos = ptr;
            jumps += 1;
            if jumps > 128 {
                bail!("parse_name: too many compression pointers (loop?)");
            }
            continue;
        }

        // Length byte
        let len = byte as usize;
        pos += 1;

        if len == 0 {
            // Root label: end of name
            if !jumped {
                end_pos = pos;
            }
            break;
        }

        if pos + len > wire.len() {
            bail!("parse_name: label extends past end of packet at {}", pos);
        }

        let label = std::str::from_utf8(&wire[pos..pos + len])
            .with_context(|| format!("parse_name: label not valid UTF-8 at {}", pos))?;
        labels.push(label.to_string());
        pos += len;
    }

    Ok((labels.join("."), end_pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dotify_undotify_roundtrip() {
        let original = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABC";
        let dotted = dotify(original);
        let restored = undotify(&dotted);
        assert_eq!(original, restored);
        // Every 63rd character should precede a dot
        for (i, ch) in dotted.char_indices() {
            if ch == '.' {
                // The preceding group should be exactly 63 chars
                let prev_dot = dotted[..i].rfind('.').map(|p| p + 1).unwrap_or(0);
                assert_eq!(i - prev_dot, 63);
            }
        }
    }

    #[test]
    fn test_encode_decode_query_roundtrip() {
        let domain = "test.com";
        let payload = b"Hello, slipstream!";
        let wire = encode_dns_query(payload, domain).unwrap();
        let (_id, decoded) = decode_dns_query(&wire, domain).unwrap();
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn test_encode_decode_response_roundtrip() {
        let domain = "test.com";
        let payload: Vec<u8> = (0u8..200).collect(); // 200 bytes of QUIC data
        let query = encode_dns_query(&[0u8; 10], domain).unwrap();
        let response = encode_dns_response(&query, &payload).unwrap();
        let decoded = decode_dns_response(&response).unwrap();
        assert_eq!(decoded, Some(payload));
    }

    #[test]
    fn test_empty_response_is_nxdomain() {
        let domain = "test.com";
        let query = encode_dns_query(&[0u8; 10], domain).unwrap();
        let response = encode_dns_response(&query, &[]).unwrap();
        let decoded = decode_dns_response(&response).unwrap();
        assert_eq!(decoded, None);
    }

    #[test]
    fn test_large_payload_chunking() {
        // TXT strings max 255 bytes each; test a 600-byte payload
        let domain = "example.com";
        let payload: Vec<u8> = (0u8..=255).cycle().take(600).collect();
        let query = encode_dns_query(&payload[..10], domain).unwrap(); // just need a query for response
        let response = encode_dns_response(&query, &payload).unwrap();
        let decoded = decode_dns_response(&response).unwrap();
        assert_eq!(decoded, Some(payload));
    }
}
