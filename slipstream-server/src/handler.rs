//! TQUIC TransportHandler for the server.
//!
//! Architecture: each QUIC stream gets two mpsc channels:
//!   quic→tcp:  server reads QUIC stream data → sends to TCP thread via `qtx`
//!   tcp→quic:  TCP thread reads data → sends via shared `tcp_tx` to event loop
//!
//! The event loop at the top level drains both channels on every iteration.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    sync::mpsc,
};

use tquic::{Connection, Shutdown, TransportHandler};
use tracing::{debug, info, warn};

/// Message from a TCP-forwarder thread back into the TQUIC mio event loop.
pub enum TcpMsg {
    /// Data from TCP target to write to QUIC stream.
    Data {
        conn_idx: usize,
        stream_id: u64,
        data: Vec<u8>,
    },
    /// TCP target closed — FIN the QUIC stream.
    Fin {
        conn_idx: usize,
        stream_id: u64,
    },
}

/// Sender end for TCP→QUIC messages (shared by all forwarder threads).
pub type TcpTx = mpsc::SyncSender<TcpMsg>;
/// Receiver end for TCP→QUIC messages (owned by the event loop).
pub type TcpRx = mpsc::Receiver<TcpMsg>;

struct StreamState {
    /// Channel to send QUIC stream data to the TCP write thread.
    qtx: mpsc::SyncSender<Vec<u8>>,
    /// Buffered data we couldn't write to QUIC yet (stream was full).
    pending: Vec<u8>,
}

pub struct ServerHandler {
    target: SocketAddr,
    domain: String,
    /// Sender for TCP→QUIC messages (cloned into each forwarder thread).
    tcp_tx: TcpTx,
    /// Map: (conn_ptr, stream_id) → StreamState
    streams: HashMap<(usize, u64), StreamState>,
    /// Map: conn_ptr → conn_idx (stable index used in TcpMsg)
    conn_idx_map: HashMap<usize, usize>,
    next_conn_idx: usize,
}

impl ServerHandler {
    pub fn new(target: SocketAddr, domain: String, tcp_tx: TcpTx) -> Self {
        Self {
            target,
            domain,
            tcp_tx,
            streams: HashMap::new(),
            conn_idx_map: HashMap::new(),
            next_conn_idx: 0,
        }
    }

    fn conn_ptr(conn: &Connection) -> usize {
        conn as *const Connection as usize
    }

    fn conn_idx(&mut self, conn: &Connection) -> usize {
        let ptr = Self::conn_ptr(conn);
        if let Some(&idx) = self.conn_idx_map.get(&ptr) {
            return idx;
        }
        let idx = self.next_conn_idx;
        self.next_conn_idx += 1;
        self.conn_idx_map.insert(ptr, idx);
        idx
    }

    /// Called from the event loop: forward TCP data to the QUIC stream.
    pub fn write_to_stream(
        &mut self,
        conn: &mut Connection,
        conn_idx: usize,
        stream_id: u64,
        data: Vec<u8>,
    ) {
        let key = (conn_idx, stream_id); // Note: use conn_idx here, not ptr
        // Find stream by conn_idx
        let key_ptr = self.streams.keys()
            .find(|(ci, si)| {
                *si == stream_id
                    && self.conn_idx_map.values().any(|&i| i == conn_idx)
                    && *ci == conn_idx
            })
            .copied();

        // Simpler: store by (conn_idx, stream_id) directly
        if let Some(s) = self.streams.get_mut(&(conn_idx, stream_id)) {
            let mut buf = std::mem::take(&mut s.pending);
            buf.extend_from_slice(&data);
            match conn.stream_write(stream_id, &buf, false) {
                Ok(n) if n < buf.len() => s.pending = buf[n..].to_vec(),
                Ok(_) => {}
                Err(e) => {
                    warn!(conn_idx, stream_id, %e, "stream_write error");
                    let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
                }
            }
        }
    }

    /// Called from the event loop: stream FIN from TCP side.
    pub fn close_stream(&mut self, conn: &mut Connection, conn_idx: usize, stream_id: u64) {
        if self.streams.remove(&(conn_idx, stream_id)).is_some() {
            let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
        }
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        let idx = self.conn_idx(conn);
        debug!(conn_idx = idx, "QUIC connection created");
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        let idx = self.conn_idx(conn);
        info!(conn_idx = idx, "QUIC connection established");
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let ptr = Self::conn_ptr(conn);
        if let Some(idx) = self.conn_idx_map.remove(&ptr) {
            info!(conn_idx = idx, "QUIC connection closed");
            // Remove all streams belonging to this connection
            self.streams.retain(|(ci, _), _| *ci != idx);
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        debug!(conn_idx, stream_id, "QUIC stream created → spawning TCP forwarder");

        // QUIC→TCP channel (buffered so the event loop doesn't block)
        let (qtx, qrx) = mpsc::sync_channel::<Vec<u8>>(64);
        self.streams.insert((conn_idx, stream_id), StreamState {
            qtx,
            pending: Vec::new(),
        });

        let target = self.target;
        let tcp_tx = self.tcp_tx.clone();

        std::thread::spawn(move || {
            // Connect to TCP target
            let tcp = match std::net::TcpStream::connect(target) {
                Ok(s) => s,
                Err(e) => {
                    warn!(%e, %target, conn_idx, stream_id, "TCP connect failed");
                    let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id });
                    return;
                }
            };
            info!(conn_idx, stream_id, %target, "TCP connected to target");
            let mut tcp_w = tcp.try_clone().expect("clone TcpStream");
            let mut tcp_r = tcp;

            // Writer thread: QUIC→TCP (reads from qrx, writes to tcp_w)
            std::thread::spawn(move || {
                for data in qrx {
                    if let Err(e) = tcp_w.write_all(&data) {
                        warn!(%e, conn_idx, stream_id, "TCP write error");
                        return;
                    }
                }
                let _ = tcp_w.shutdown(std::net::Shutdown::Write);
            });

            // Reader: TCP→QUIC (reads from tcp_r, sends to tcp_tx)
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match tcp_r.read(&mut buf) {
                    Ok(0) => {
                        debug!(conn_idx, stream_id, "TCP target closed");
                        let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id });
                        return;
                    }
                    Ok(n) => {
                        if tcp_tx
                            .send(TcpMsg::Data {
                                conn_idx,
                                stream_id,
                                data: buf[..n].to_vec(),
                            })
                            .is_err()
                        {
                            return; // event loop gone
                        }
                    }
                    Err(e) => {
                        warn!(%e, conn_idx, stream_id, "TCP read error");
                        let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id });
                        return;
                    }
                }
            }
        });
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        let key = (conn_idx, stream_id);

        // Read all available data from QUIC stream
        let mut total_read = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((0, _)) => break,
                Ok((n, fin)) => {
                    total_read += n;
                    // Forward to TCP writer thread via qtx
                    if let Some(s) = self.streams.get(&key) {
                        let _ = s.qtx.try_send(buf[..n].to_vec());
                    }
                    if fin {
                        // QUIC stream FIN → close TCP write side by dropping qtx
                        self.streams.remove(&key);
                        break;
                    }
                }
                Err(tquic::Error::Done) => break,
                Err(e) => {
                    warn!(conn_idx, stream_id, %e, "stream_read error");
                    self.streams.remove(&key);
                    break;
                }
            }
        }
        debug!(conn_idx, stream_id, bytes = total_read, "quic→tcp forwarded");
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        let key = (conn_idx, stream_id);
        if let Some(s) = self.streams.get_mut(&key) {
            if s.pending.is_empty() {
                return;
            }
            let data = std::mem::take(&mut s.pending);
            match conn.stream_write(stream_id, &data, false) {
                Ok(n) if n < data.len() => {
                    s.pending = data[n..].to_vec();
                }
                Ok(_) => {}
                Err(e) => warn!(conn_idx, stream_id, %e, "stream_write on writable failed"),
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        debug!(conn_idx, stream_id, "QUIC stream closed");
        self.streams.remove(&(conn_idx, stream_id));
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
