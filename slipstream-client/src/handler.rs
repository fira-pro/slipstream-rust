//! TQUIC TransportHandler — client side.
//!
//! QuicToTcp messages are sent from the TQUIC mio thread → Tokio TCP tasks
//! via tokio::sync::mpsc (bounded, async-friendly).

use std::collections::HashMap;

use bytes::Bytes;
use tquic::{Connection, Shutdown, TransportHandler};
use tracing::{debug, info, warn};

/// Messages from TQUIC mio thread → Tokio TCP task (per-stream channel).
#[derive(Debug)]
pub enum QuicToTcp {
    /// The QUIC bidi stream has been opened; this is the real stream_id.
    StreamAssigned { stream_id: u64 },
    /// Data from server to write to the TCP client socket.
    Data { data: Vec<u8> },
    /// Server closed the stream cleanly.
    Fin,
}

/// Messages from Tokio TCP task → TQUIC mio thread.
pub enum TcpToQuic {
    /// New TCP connection arrived — open a QUIC bidi stream.
    NewStream {
        /// Channel to send QuicToTcp back to this TCP task.
        reply_tx: tokio::sync::mpsc::Sender<QuicToTcp>,
    },
    Data  { stream_id: u64, data: Vec<u8> },
    Fin   { stream_id: u64 },
    Reset { stream_id: u64 },
}

struct StreamState {
    reply_tx: tokio::sync::mpsc::Sender<QuicToTcp>,
}

pub struct ClientHandler {
    ctrl_tx: std::sync::mpsc::SyncSender<()>, // signals "connected" to main
    streams: HashMap<u64, StreamState>,
}

impl ClientHandler {
    pub fn new(ctrl_tx: std::sync::mpsc::SyncSender<()>) -> Self {
        Self { ctrl_tx, streams: HashMap::new() }
    }

    pub fn register_stream(&mut self, stream_id: u64, reply_tx: tokio::sync::mpsc::Sender<QuicToTcp>) {
        self.streams.insert(stream_id, StreamState { reply_tx });
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, _conn: &mut Connection) {
        debug!("QUIC client connection created");
    }

    fn on_conn_established(&mut self, _conn: &mut Connection) {
        info!("QUIC client connection established");
        let _ = self.ctrl_tx.try_send(());
    }

    fn on_conn_closed(&mut self, _conn: &mut Connection) {
        info!("QUIC client connection closed");
        for (sid, s) in self.streams.drain() {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin);
        }
    }

    fn on_stream_created(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "QUIC stream created (server-initiated, ignored on client)");
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((0, _)) => break,
                Ok((n, fin)) => {
                    if let Some(s) = self.streams.get(&stream_id) {
                        let _ = s.reply_tx.try_send(QuicToTcp::Data {
                            data: buf[..n].to_vec(),
                        });
                    }
                    if fin {
                        if let Some(s) = self.streams.remove(&stream_id) {
                            let _ = s.reply_tx.try_send(QuicToTcp::Fin);
                        }
                        break;
                    }
                }
                Err(tquic::Error::Done) => break,
                Err(e) => {
                    warn!(stream_id, %e, "stream_read error");
                    if let Some(s) = self.streams.remove(&stream_id) {
                        let _ = s.reply_tx.try_send(QuicToTcp::Fin);
                    }
                    break;
                }
            }
        }
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "stream writable (pending writes handled in event loop)");
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "QUIC stream closed");
        if let Some(s) = self.streams.remove(&stream_id) {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin);
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
