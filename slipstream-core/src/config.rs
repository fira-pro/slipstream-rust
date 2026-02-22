/// Global configuration constants and MTU helpers.

/// Max DNS QNAME length in bytes (labels + dots + root).
pub const MAX_QNAME_LEN: usize = 253;

/// Max length of a single DNS label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum DNS query wire size we allow ourselves to produce.
pub const MAX_DNS_QUERY_SIZE: usize = 512;

/// Maximum DNS response wire size (EDNS0 allows up to 65535 but resolvers cap at 1232 or 1452).
pub const MAX_DNS_RESPONSE_SIZE: usize = 1232;

/// ALPN protocol identifier.
pub const ALPN_PROTOCOL: &[u8] = b"slipstream";

/// Server-side SNI (used by client when connecting, can be anything).
pub const SERVER_SNI: &str = "slipstream.internal";

/// QUIC connection/stream error codes.
pub const ERR_INTERNAL: u32 = 0x101;
pub const ERR_STREAM_CANCELLED: u32 = 0x105;

/// Dummy IPv4 address injected as the QUIC peer for all server-side packets.
/// This prevents QUIC from getting confused about changing source addresses
/// as DNS queries may arrive from different resolver source ports/IPs.
pub const DUMMY_PEER_IP: &str = "192.0.2.1";
pub const DUMMY_PEER_PORT: u16 = 12345;

/// Configuration for this slipstream session.
#[derive(Debug, Clone)]
pub struct Config {
    /// The domain name used as the DNS tunnel base (e.g., "test.com").
    pub domain: String,
    /// Computed max QUIC packet payload bytes for client→server direction.
    /// Based on how many base32 characters fit in a QNAME of 240 chars after
    /// reserving space for the domain name and dots.
    pub client_mtu: usize,
}

impl Config {
    /// Create a new config, computing MTU from the domain name length.
    pub fn new(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        // Available chars for base32-encoded subdomain part:
        //   240 - domain.len() - 1 (for separator dot)
        // base32 expansion factor is 8/5 = 1.6, so:
        //   mtu = available_chars / 1.6
        let available_chars = 240usize.saturating_sub(domain.len() + 1);
        let client_mtu = (available_chars as f64 / 1.6) as usize;
        // Cap at a reasonable maximum
        let client_mtu = client_mtu.min(150).max(20);
        Self { domain, client_mtu }
    }
}
