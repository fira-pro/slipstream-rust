//! TQUIC TransportHandler for the server.
//!
//! Per-stream data flow:
//!   QUIC readable → on_stream_readable → qtx → writer thread → TCP target
//!   TCP target → reader thread → tcp_tx (TcpMsg::Data) → event loop →
//!     conn.stream_write() [buffered in server_pending if Done] → QUIC → client
//!
//! Stream teardown:
//!   on_stream_closed / on_conn_closed calls tcp_shutdown.shutdown(Both),
//!   which interrupts the blocked tcp_r.read() so threads exit promptly.
//!   Dropping qtx stops the writer thread via channel closure.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        mpsc,
        Arc, Mutex,
    },
};

use bytes::Bytes;
use tquic::{Connection, TransportHandler};
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
    /// Unbounded so the mio event loop never blocks and never drops data.
    /// Backpressure comes from TQUIC's per-stream flow-control window.
    qtx: mpsc::Sender<Vec<u8>>,
    /// Pending TCP→QUIC data (buffered when stream_write returns Done).
    pending: Vec<u8>,
    /// For interrupting the reader thread on stream close.
    tcp_shutdown: Arc<Mutex<Option<TcpStream>>>,
}

impl StreamState {
    fn shutdown_tcp(&self) {
        if let Ok(mut guard) = self.tcp_shutdown.lock() {
            if let Some(ref tcp) = *guard {
                let _ = tcp.shutdown(Shutdown::Both);
            }
            *guard = None;
        }
    }
}

pub struct ServerHandler {
    target:        SocketAddr,
    tcp_tx:        TcpTx,
    streams:       HashMap<(usize, u64), StreamState>,
    conn_idx_map:  HashMap<usize, usize>,
    next_conn_idx: usize,
}

impl ServerHandler {
    pub fn new(target: SocketAddr, _domain: String, tcp_tx: TcpTx) -> Self {
        Self {
            target,
            tcp_tx,
            streams:       HashMap::new(),
            conn_idx_map:  HashMap::new(),
            next_conn_idx: 0,
        }
    }

    fn conn_ptr(conn: &Connection) -> usize { conn as *const _ as usize }

    fn conn_idx(&mut self, conn: &Connection) -> usize {
        let ptr = Self::conn_ptr(conn);
        if let Some(&idx) = self.conn_idx_map.get(&ptr) { return idx; }
        let idx = self.next_conn_idx;
        self.next_conn_idx += 1;
        self.conn_idx_map.insert(ptr, idx);
        idx
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!(conn_idx = self.conn_idx(conn), "QUIC connection created");
    }
    fn on_conn_established(&mut self, conn: &mut Connection) {
        info!(conn_idx = self.conn_idx(conn), "QUIC connection established");
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let ptr = Self::conn_ptr(conn);
        if let Some(idx) = self.conn_idx_map.remove(&ptr) {
            info!(conn_idx = idx, "QUIC connection closed");
            self.streams.retain(|(ci, _), s| {
                if *ci == idx { s.shutdown_tcp(); false } else { true }
            });
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        debug!(conn_idx, stream_id, "QUIC stream created → spawning TCP forwarder");

        let (qtx, qrx) = mpsc::channel::<Vec<u8>>();  // unbounded — no data loss

        // Shared slot: the spawned thread fills this with the live TcpStream
        // clone once connect() succeeds. on_stream_closed uses it to interrupt
        // the reader thread's blocking read().
        let tcp_shutdown: Arc<Mutex<Option<TcpStream>>> =
            Arc::new(Mutex::new(None));

        self.streams.insert(
            (conn_idx, stream_id),
            StreamState { qtx, pending: Vec::new(), tcp_shutdown: tcp_shutdown.clone() },
        );

        let target = self.target;
        let tcp_tx = self.tcp_tx.clone();

        std::thread::spawn(move || {
            let tcp = match TcpStream::connect(target) {
                Ok(s)  => s,
                Err(e) => {
                    warn!(%e, %target, conn_idx, stream_id, "TCP connect failed");
                    let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id });
                    return;
                }
            };
            info!(conn_idx, stream_id, %target, "TCP connected to target");

            // Fill shutdown slot so on_stream_closed can interrupt us.
            let shutdown_clone = tcp.try_clone().expect("clone for shutdown");
            if let Ok(mut g) = tcp_shutdown.lock() { *g = Some(shutdown_clone); }

            let mut tcp_w = tcp.try_clone().expect("clone for writer");
            let mut tcp_r = tcp;

            // Writer sub-thread: receives chunks from the QUIC event loop
            // and writes them to the upstream TCP connection.
            std::thread::spawn(move || {
                for chunk in qrx {
                    if let Err(e) = tcp_w.write_all(&chunk) {
                        debug!(%e, conn_idx, stream_id, "TCP writer stopped");
                        return;
                    }
                }
                // qtx was dropped (stream closed) → send graceful FIN to target.
                let _ = tcp_w.shutdown(Shutdown::Write);
            });

            // Reader: forwards upstream TCP data → QUIC stream.
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match tcp_r.read(&mut buf) {
                    Ok(0) => {
                        let _ = tcp_tx.send(TcpMsg::Fin { conn_idx, stream_id });
                        return;
                    }
                    Ok(n) => {
                        if tcp_tx
                            .send(TcpMsg::Data {
                                conn_idx, stream_id,
                                data: buf[..n].to_vec(),
                            })
                            .is_err()
                        {
                            return; // event loop shut down
                        }
                    }
                    Err(e) => {
                        // Interrupted by shutdown(Both) from on_stream_closed, or
                        // real network error — either way, stop cleanly.
                        debug!(%e, conn_idx, stream_id, "TCP reader stopped");
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
                Ok((0, _))    => break,
                Ok((n, fin))  => {
                    if let Some(s) = self.streams.get(&key) {
                        // send() on unbounded channel never blocks and never fails
                        // unless the writer thread has exited (channel disconnected).
                        let _ = s.qtx.send(buf[..n].to_vec());
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
                Ok(_)  => {}
                Err(e) => warn!(conn_idx, stream_id, %e, "stream_write in writable cb failed"),
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let conn_idx = self.conn_idx(conn);
        if let Some(s) = self.streams.remove(&(conn_idx, stream_id)) {
            // Calling shutdown(Both) interrupts tcp_r.read() in the reader
            // thread so it exits instead of blocking until the remote closes.
            s.shutdown_tcp();
            debug!(conn_idx, stream_id, "QUIC stream closed, upstream TCP shut down");
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
