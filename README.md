# slipstream-rust

A Rust rewrite of [slipstream](https://github.com/...) — a DNS tunnel leveraging QUIC as the transport protocol.

## Architecture

```
slipstream-client  ←→  DNS (UDP)  ←→  slipstream-server  ←→  TCP upstream
```

- **Client**: accepts local TCP connections, tunnels them through QUIC-over-DNS
- **Server**: receives DNS queries, decodes them as QUIC, proxies each QUIC stream to an upstream TCP service
- **Transport**: QUIC packets encoded as DNS TXT queries (base32 in QNAME) / responses (raw TXT RDATA)

## Building

```bash
cargo build --release
```

Produces:
- `target/release/slipstream-client`
- `target/release/slipstream-server`

## Quick Start (direct connection test)

```bash
# Terminal 1: fake upstream
nc -l -p 5201

# Terminal 2: server (self-signed cert, port 8853)
./target/release/slipstream-server \
  --dns-listen-port=8853 \
  --target-address=127.0.0.1:5201 \
  --domain=test.com \
  --self-signed

# Terminal 3: client
./target/release/slipstream-client \
  --tcp-listen-port=7000 \
  --resolver=127.0.0.1:8853 \
  --domain=test.com \
  --accept-insecure

# Terminal 4: test data
echo "hello slipstream" | nc 127.0.0.1 7000
```

## CLI Reference

### slipstream-server

| Flag | Default | Description |
|------|---------|-------------|
| `--dns-listen-port` | `53` | UDP port for DNS queries |
| `--dns-listen-ipv6` | false | Listen on IPv6 |
| `--target-address` | `127.0.0.1:5201` | TCP service to proxy to |
| `--domain` | (required) | Authoritative domain |
| `--cert` | `certs/cert.pem` | TLS certificate |
| `--key` | `certs/key.pem` | TLS private key |
| `--self-signed` | false | Auto-generate self-signed cert |

### slipstream-client

| Flag | Default | Description |
|------|---------|-------------|
| `--tcp-listen-port` | `5201` | Local TCP port |
| `--resolver` | (required) | DNS resolver/server address (repeatable) |
| `--domain` | (required) | Tunnel domain |
| `--keep-alive-interval` | `400` | Keep-alive interval (ms, 0=off) |
| `--accept-insecure` | false | Skip TLS cert verification (for self-signed) |

## Improvements over Original C Code

| Issue | Original C | Rust rewrite |
|-------|-----------|--------------|
| Thread-per-poller explosion | Spawns a detached pthread whenever no data available | Tokio async I/O — zero threads |
| Pipe fd leaks | `pipefd[0/1]` not always closed on reset | No pipes — direct async channel |
| Bad file descriptor errors | Double-close on stream reset | RAII/owned resources |
| Thread leak | New thread per connection per poll cycle | Tasks with structured lifetime |
| Network change recovery | Not handled | Auto-reconnect with exponential backoff |
| Non-thread-safe `rand()` | Used for DNS query IDs | `rand::thread_rng()` |
| fd limit exhaustion | 3 FDs per connection (socket + pipe) | 1 FD per connection |
