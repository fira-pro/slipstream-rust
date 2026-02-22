pub mod codec;
pub mod config;
pub mod dns_socket;

pub use codec::{decode_dns_query, decode_dns_response, encode_dns_query, encode_dns_response};
pub use config::Config;
pub use dns_socket::dummy_peer_addr;
