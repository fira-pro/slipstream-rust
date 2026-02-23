//! TQUIC TransportHandler for the server.
//!
//! Each QUIC stream gets two channels:
//!   qtx (QUIC→TCP): event loop reads QUIC, sends data to TCP writer thread
//!   tcp_tx (TCP→QUIC): TCP reader thread sends data; event loop stores in pending_writes;
//!                       on_stream_writable drains pending_writes to the QUIC stream.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    sync::mpsc,
};

use bytes::Bytes;
use tquic::{Connection, Shutdown, TransportHandler};
use tracing::{debug, info, warn};

/// Message from a TCP-forwarder thread back into the TQUIC mio event loop.
pub enum TcpMsg {
    Data { conn_idx: usize, stream_id: u64, data: Vec<u8> },
    Fin  { conn_idx: usize, stream_id: u64 },
}

pub type TcpTx = mpsc::SyncSender<TcpMsg>;
pub type TcpRx = mpsc::Receiver<TcpMsg>;

struct StreamState {
    /// Send QUIC→TCP data to the TCP writer thread.
    qtx: mpsc::SyncSender<Vec<u8>>,
    /// Pending TCP→QUIC data waiting for on_stream_writable.
    pending: Vec<u8>,
}

pub struct ServerHandler {
    target: SocketAddr,
    tcp_tx: TcpTx,
    streams: HashMap<(usize, u64), StreamState>,
    conn_idx_map: HashMap<usize, usize>,
    next_conn_idx: usize,
}

impl ServerHandler {
    pub fn new(target: SocketAddr, _domain: String, tcp_tx: TcpTx) -> Self {
        Self {
            target,
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
        if let Some(&idx) = self.conn_idx_map.get(&ptr) { return idx; }
        let idx = self.next_conn_idx;
        self.next_conn_idx += 1;
        self.conn_idx_map.insert(ptr, idx);
        idx
    }

    fn stream_write(conn: &mut Connection, stream_id: u64, data: &[u8], fin: bool) {
        match conn.stream_write(stream_id, Bytes::copy_from_slice(data), fin) {
            Ok(_) => {}
            Err(e) => warn!(stream_id, %e, "stream_write error"),
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
            self.streams.retain(|(ci, _), _| *ci != idx);
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        debug!(conn_idx, stream_id, "QUIC stream created → spawning TCP forwarder");

        let (qtx, qrx) = mpsc::sync_channel::<Vec<u8>>(64);
        self.streams.insert((conn_idx, stream_id), StreamState { qtx, pending: Vec::new() });

        let target = self.target;
        let tcp_tx = self.tcp_tx.clone();

        std::thread::spawn(move || {
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

            // Writer thread: QUIC→TCP
            std::thread::spawn(move || {
                for data in qrx {
                    if let Err(e) = tcp_w.write_all(&data) {
                        warn!(%e, conn_idx, stream_id, "TCP write error");
                        return;
                    }
                }
                let _ = tcp_w.shutdown(std::net::Shutdown::Write);
            });

            // Reader: TCP→QUIC
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match tcp_r.read(&mut buf) {
                    Ok(0) => { let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id }); return; }
                    Ok(n) => {
                        if tcp_tx.send(TcpMsg::Data { conn_idx, stream_id, data: buf[..n].to_vec() }).is_err() { return; }
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
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((0, _)) => break,
                Ok((n, fin)) => {
                    if let Some(s) = self.streams.get(&key) {
                        let _ = s.qtx.try_send(buf[..n].to_vec());
                    }
                    if fin { self.streams.remove(&key); break; }
                }
                Err(tquic::Error::Done) => break,
                Err(e) => { warn!(conn_idx, stream_id, %e, "stream_read error"); break; }
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        let key = (conn_idx, stream_id);
        if let Some(s) = self.streams.get_mut(&key) {
            if s.pending.is_empty() { return; }
            let data = std::mem::take(&mut s.pending);
            match conn.stream_write(stream_id, Bytes::copy_from_slice(&data), false) {
                Ok(n) if n < data.len() => s.pending = data[n..].to_vec(),
                Ok(_) => {}
                Err(e) => warn!(conn_idx, stream_id, %e, "stream_write on writable failed"),
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        self.streams.remove(&(conn_idx, stream_id));
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
