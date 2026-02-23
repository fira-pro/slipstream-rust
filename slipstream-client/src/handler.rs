//! TQUIC TransportHandler for the client.

use std::{
    collections::HashMap,
    sync::mpsc,
};

use bytes::Bytes;
use tquic::{Connection, Shutdown, TransportHandler};
use tracing::{debug, info, warn};

pub enum QuicToTcp {
    Connected,
    Data    { stream_id: u64, data: Vec<u8> },
    Fin     { stream_id: u64 },
    Disconnected,
}

pub enum TcpToQuic {
    NewStream { reply_tx: mpsc::SyncSender<QuicToTcp> },
    Data      { stream_id: u64, data: Vec<u8> },
    Fin       { stream_id: u64 },
    Reset     { stream_id: u64 },
}

struct StreamState {
    reply_tx:    mpsc::SyncSender<QuicToTcp>,
    pending:     Vec<u8>,
    fin_pending: bool,
}

pub struct ClientHandler {
    ctrl_tx: mpsc::SyncSender<QuicToTcp>,
    streams: HashMap<u64, StreamState>,
}

impl ClientHandler {
    pub fn new(ctrl_tx: mpsc::SyncSender<QuicToTcp>) -> Self {
        Self { ctrl_tx, streams: HashMap::new() }
    }

    pub fn register_stream(&mut self, stream_id: u64, reply_tx: mpsc::SyncSender<QuicToTcp>) {
        self.streams.insert(stream_id, StreamState { reply_tx, pending: Vec::new(), fin_pending: false });
    }

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
            if !s.pending.is_empty() {
                let mut full = std::mem::take(&mut s.pending);
                full.extend_from_slice(&data);
                data = full;
            }
            match conn.stream_write(stream_id, Bytes::copy_from_slice(&data), fin) {
                Ok(n) if n < data.len() => { s.pending = data[n..].to_vec(); s.fin_pending = fin; }
                Ok(_) => { if fin { self.streams.remove(&stream_id); } }
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
        for (stream_id, s) in self.streams.drain() {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id });
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
            if s.pending.is_empty() { return; }
            let data = std::mem::take(&mut s.pending);
            let fin  = s.fin_pending;
            match conn.stream_write(stream_id, Bytes::copy_from_slice(&data), fin) {
                Ok(n) if n < data.len() => { s.pending = data[n..].to_vec(); }
                Ok(_) => { if fin { self.streams.remove(&stream_id); } }
                Err(e) => warn!(stream_id, %e, "stream_write on writable failed"),
            }
        }
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!(stream_id, "QUIC client stream closed");
        if let Some(s) = self.streams.remove(&stream_id) {
            let _ = s.reply_tx.try_send(QuicToTcp::Fin { stream_id });
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}
