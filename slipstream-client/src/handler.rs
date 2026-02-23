//! TQUIC TransportHandler for the client.
//!
//! The client originates QUIC streams (one per proxied TCP connection).
//! Callbacks here:
//!   - `on_conn_established`: signal to Tokio that QUIC is ready to take streams
//!   - `on_stream_readable`: QUIC→TCP forward (copy data to the TCP client socket)
//!   - `on_stream_writable`: drain pending TCP writes to a newly-writable stream
//!   - `on_stream_closed`: close the TCP client socket

use std::{
    collections::HashMap,
    io::Write,
    net::SocketAddr,
    sync::mpsc,
};

use tquic::{Connection, Shutdown, TransportHandler};
use tracing::{debug, info, warn};

/// Message from the event loop to the Tokio/TCP side.
pub enum QuicToTcp {
    /// QUIC connection is ready — Tokio can now open QUIC streams.
    Connected,
    /// Data from QUIC stream to write to TCP client.
    Data {
        stream_id: u64,
        data: Vec<u8>,
    },
    /// QUIC stream closed — shut down TCP client side.
    Fin { stream_id: u64 },
    /// QUIC connection dropped — trigger reconnect.
    Disconnected,
}

/// Message from a TCP connection (Tokio) to the TQUIC event loop.
pub enum TcpToQuic {
    /// New TCP connection arrived — open a new QUIC stream.
    NewStream {
        /// Sender back to the Tokio TCP task for this connection.
        reply_tx: mpsc::SyncSender<QuicToTcp>,
    },
    /// Data from TCP client to write to QUIC stream.
    Data {
        stream_id: u64,
        data: Vec<u8>,
    },
    /// TCP client closed cleanly → FIN the QUIC stream.
    Fin { stream_id: u64 },
    /// TCP client error → RESET the QUIC stream (stop server drain immediately).
    Reset { stream_id: u64 },
}

struct StreamState {
    /// Channel to send QUIC→TCP data back to the Tokio task.
    reply_tx: mpsc::SyncSender<QuicToTcp>,
    /// Buffered data we couldn't write to QUIC yet (stream was full).
    pending: Vec<u8>,
    /// Whether a FIN/RESET is pending after draining pending data.
    fin_pending: bool,
}

pub struct ClientHandler {
    /// Sender for connection-level events to the Tokio control task.
    ctrl_tx: mpsc::SyncSender<QuicToTcp>,
    /// Per-stream state: stream_id → StreamState
    streams: HashMap<u64, StreamState>,
}

impl ClientHandler {
    pub fn new(ctrl_tx: mpsc::SyncSender<QuicToTcp>) -> Self {
        Self {
            ctrl_tx,
            streams: HashMap::new(),
        }
    }

    /// Register a new stream (called from the event loop after conn.open_bidi_stream()).
    pub fn register_stream(&mut self, stream_id: u64, reply_tx: mpsc::SyncSender<QuicToTcp>) {
        self.streams.insert(stream_id, StreamState {
            reply_tx,
            pending: Vec::new(),
            fin_pending: false,
        });
    }

    /// Write TCP data to a QUIC stream, buffering any unsent remainder.
    pub fn tcp_data_to_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        mut data: Vec<u8>,
        fin: bool,
        reset: bool,
    ) {
        if reset {
            let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
            self.streams.remove(&stream_id);
            return;
        }

        if let Some(s) = self.streams.get_mut(&stream_id) {
            // Prepend any existing pending data
            if !s.pending.is_empty() {
                let mut full = std::mem::take(&mut s.pending);
                full.extend_from_slice(&data);
                data = full;
            }
            match conn.stream_write(stream_id, &data, fin) {
                Ok(n) if n < data.len() => {
                    s.pending = data[n..].to_vec();
                    s.fin_pending = fin;
                }
                Ok(_) => {
                    if fin {
                        self.streams.remove(&stream_id);
                    }
                }
                Err(e) => {
                    warn!(stream_id, %e, "stream_write failed");
                    let _ = conn.stream_shutdown(stream_id, Shutdown::Write, 0);
                    self.streams.remove(&stream_id);
                }
            }
        }
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, _conn: &mut Connection) {
        debug!("QUIC client connection created");
    }

    fn on_conn_established(&mut self, _conn: &mut Connection) {
        info!("QUIC client connection established");
        let _ = self.ctrl_tx.try_send(QuicToTcp::Connected);
    }

    fn on_conn_closed(&mut self, _conn: &mut Connection) {
        info!("QUIC client connection closed");
        // Notify all open streams
        for (_, s) in self.streams.drain() {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id: 0 });
        }
        let _ = self.ctrl_tx.try_send(QuicToTcp::Disconnected);
    }

    fn on_stream_created(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "QUIC client stream created");
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((0, _)) => break,
                Ok((n, fin)) => {
                    if let Some(s) = self.streams.get(&stream_id) {
                        let _ = s.reply_tx.try_send(QuicToTcp::Data {
                            stream_id,
                            data: buf[..n].to_vec(),
                        });
                    }
                    if fin {
                        if let Some(s) = self.streams.remove(&stream_id) {
                            let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id });
                        }
                        break;
                    }
                }
                Err(tquic::Error::Done) => break,
                Err(e) => {
                    warn!(stream_id, %e, "stream_read error");
                    if let Some(s) = self.streams.remove(&stream_id) {
                        let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id });
                    }
                    break;
                }
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            if s.pending.is_empty() {
                return;
            }
            let data = std::mem::take(&mut s.pending);
            let fin = s.fin_pending;
            match conn.stream_write(stream_id, &data, fin) {
                Ok(n) if n < data.len() => {
                    s.pending = data[n..].to_vec();
                }
                Ok(_) => {
                    if fin {
                        self.streams.remove(&stream_id);
                    }
                }
                Err(e) => warn!(stream_id, %e, "stream_write on writable failed"),
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "QUIC client stream closed");
        if let Some(s) = self.streams.remove(&stream_id) {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id });
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
