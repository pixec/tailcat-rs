//! A DERP relay client.
//!
//! DERP is a TCP (normally TLS) connection to a relay that carries packets
//! between node keys. A client upgrades an HTTP request to the DERP
//! protocol, learns the relay's key, proves its own with a NaCl box, and
//! then exchanges length-prefixed frames. Tailcat uses one relay: the
//! region in the server's address. Everything a client sends before it has
//! found a direct path, and everything if it never does, goes through here.
//!
//! [`Session`] is the protocol over an already-open byte stream, sans-IO.
//! With the `std` feature, `DerpClient` dials, adds TLS, and reconnects on
//! its own. A dropped relay connection costs a few seconds of relayed
//! traffic, not the tunnel, since the same node key reattaches to the same
//! relay.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::DerpError;
use crate::key::{KEY_LEN, NodePrivate, NodePublic};
#[cfg(feature = "std")]
pub use crate::rt::{DerpClient, Options};

const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
const PROTOCOL_VERSION: u32 = 2;
pub const MAX_PACKET_SIZE: usize = 64 << 10;
const MAX_INFO_LEN: usize = 1 << 20;
const MAX_UPGRADE_LEN: usize = 16 << 10;
const FRAME_HEADER_LEN: usize = 5;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const FRAME_HEALTH: u8 = 0x14;
const FRAME_RESTARTING: u8 = 0x15;

/// One packet the relay delivered, and who sent it.
#[derive(Debug)]
pub struct Packet {
    pub src: NodePublic,
    pub data: Vec<u8>,
}

/// Something the relay told us.
#[derive(Debug)]
pub enum Event {
    Packet(Packet),
    /// A peer we sent to has disconnected from the relay.
    PeerGone(NodePublic),
    /// The relay reports a problem with this connection.
    Health(String),
}

fn frame(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    f.push(typ);
    let len = u32::try_from(body.len()).expect("frame body fits in u32");
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(body);
    f
}

/// The frame that relays `pkt` to `dst`, or `None` if `pkt` is too large.
#[must_use]
pub fn send_packet_frame(dst: &NodePublic, pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() > MAX_PACKET_SIZE {
        return None;
    }
    let mut body = Vec::with_capacity(KEY_LEN + pkt.len());
    body.extend_from_slice(dst.as_bytes());
    body.extend_from_slice(pkt);
    Some(frame(FRAME_SEND_PACKET, &body))
}

#[derive(Serialize)]
struct ClientInfo<'a> {
    version: u32,
    #[serde(rename = "CanAckPings")]
    is_ping_ack_capable: bool,
    #[serde(rename = "AppName")]
    app_name: &'a str,
}

#[derive(Deserialize)]
struct ServerInfo {}

enum State {
    Upgrade,
    ServerKey,
    ServerInfo(NodePublic),
    Connected,
}

/// One relay connection, from the HTTP upgrade on.
///
/// Feed it what the relay sends with [`receive`](Self::receive) and write
/// out whatever [`poll_transmit`](Self::poll_transmit) returns; the first
/// transmit is the upgrade request. Once
/// [`is_connected`](Self::is_connected), packets flow both ways.
pub struct Session<R> {
    key: NodePrivate,
    app_name: String,
    rng: R,
    state: State,
    rx: Vec<u8>,
    tx: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
}

impl<R: RngCore + CryptoRng> Session<R> {
    /// A session that upgrades a request for `host`, the value of the
    /// `Host` header, and announces `app_name` to the relay.
    pub fn new(key: NodePrivate, host: &str, app_name: &str, rng: R) -> Self {
        let mut tx = VecDeque::new();
        tx.push_back(
            format!(
                "GET /derp HTTP/1.1\r\nHost: {host}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
            )
            .into_bytes(),
        );
        Session {
            key,
            app_name: app_name.into(),
            rng,
            state: State::Upgrade,
            rx: Vec::new(),
            tx,
            events: VecDeque::new(),
        }
    }

    /// Whether the relay has accepted the HTTP upgrade.
    #[must_use]
    pub fn is_upgraded(&self) -> bool {
        !matches!(self.state, State::Upgrade)
    }

    /// Whether the handshake is done and packets can be sent.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Connected)
    }

    /// The next bytes to write to the relay.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Queues `pkt` for `dst`, returning `false` if it is too large or the
    /// session is not connected yet.
    pub fn send_packet(&mut self, dst: &NodePublic, pkt: &[u8]) -> bool {
        if !self.is_connected() {
            return false;
        }
        send_packet_frame(dst, pkt)
            .map(|f| self.tx.push_back(f))
            .is_some()
    }

    /// Processes bytes read from the relay.
    ///
    /// # Errors
    ///
    /// Fails if the relay refuses the upgrade, breaks the protocol, or is
    /// restarting. The session is unusable afterwards.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), DerpError> {
        self.rx.extend_from_slice(data);
        let mut pos = 0;
        let result = self.process(&mut pos);
        self.rx.drain(..pos);
        result
    }

    fn process(&mut self, pos: &mut usize) -> Result<(), DerpError> {
        if let State::Upgrade = self.state {
            let Some(end) = self.upgrade_end()? else {
                return Ok(());
            };
            *pos = end;
            self.state = State::ServerKey;
        }
        loop {
            let max = match self.state {
                State::Upgrade => unreachable!(),
                State::ServerKey => 1 << 10,
                State::ServerInfo(_) => MAX_INFO_LEN + 24,
                State::Connected => MAX_PACKET_SIZE + KEY_LEN,
            };
            let rest = &self.rx[*pos..];
            let Some(hdr) = rest.first_chunk::<FRAME_HEADER_LEN>() else {
                return Ok(());
            };
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
            if len > max {
                return Err(DerpError::FrameTooLarge { len, max });
            }
            let Some(body) = rest.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + len) else {
                return Ok(());
            };
            let (typ, body) = (hdr[0], body.to_vec());
            *pos += FRAME_HEADER_LEN + len;
            self.on_frame(typ, &body)?;
        }
    }

    fn upgrade_end(&self) -> Result<Option<usize>, DerpError> {
        let mut start = 0;
        while let Some(i) = self.rx[start..].iter().position(|&b| b == b'\n') {
            let line = &self.rx[start..=start + i];
            if start == 0 {
                if !line.starts_with(b"HTTP/1.1 101") {
                    return Err(DerpError::UpgradeRefused {
                        status: String::from_utf8_lossy(line).trim_end().into(),
                    });
                }
            } else if line == b"\r\n" || line == b"\n" {
                return Ok(Some(start + i + 1));
            }
            start += i + 1;
        }
        if self.rx.len() > MAX_UPGRADE_LEN {
            return Err(DerpError::UpgradeTooLarge);
        }
        Ok(None)
    }

    fn on_frame(&mut self, typ: u8, body: &[u8]) -> Result<(), DerpError> {
        match self.state {
            State::Upgrade => unreachable!(),
            State::ServerKey => {
                let Some(server_key) = body
                    .strip_prefix(MAGIC)
                    .and_then(<[u8]>::first_chunk::<KEY_LEN>)
                    .filter(|_| typ == FRAME_SERVER_KEY)
                else {
                    return Err(DerpError::InvalidGreeting);
                };
                let server_key = NodePublic::from_raw(*server_key);
                let info = serde_json::to_vec(&ClientInfo {
                    version: PROTOCOL_VERSION,
                    is_ping_ack_capable: true,
                    app_name: &self.app_name,
                })
                .expect("static struct serialises");
                let mut client_info = self.key.public().as_bytes().to_vec();
                client_info.extend(self.key.seal_to(&mut self.rng, &server_key, &info));
                self.tx.push_back(frame(FRAME_CLIENT_INFO, &client_info));
                self.state = State::ServerInfo(server_key);
            }
            State::ServerInfo(server_key) => {
                if typ != FRAME_SERVER_INFO {
                    return Err(DerpError::UnexpectedFrame { frame_type: typ });
                }
                let opened = self
                    .key
                    .open_from(&server_key, body)
                    .ok_or(DerpError::OpenServerInfo)?;
                serde_json::from_slice::<ServerInfo>(&opened)
                    .map_err(DerpError::InvalidServerInfo)?;
                self.state = State::Connected;
            }
            State::Connected => match typ {
                FRAME_RECV_PACKET => {
                    let Some((src, data)) = body.split_first_chunk::<KEY_LEN>() else {
                        return Err(DerpError::ShortRecvPacket);
                    };
                    self.events.push_back(Event::Packet(Packet {
                        src: NodePublic::from_raw(*src),
                        data: data.to_vec(),
                    }));
                }
                FRAME_PING => self.tx.push_back(frame(FRAME_PONG, body)),
                FRAME_PEER_GONE => {
                    if let Some(peer) = body.first_chunk::<KEY_LEN>() {
                        self.events
                            .push_back(Event::PeerGone(NodePublic::from_raw(*peer)));
                    }
                }
                FRAME_HEALTH => self
                    .events
                    .push_back(Event::Health(String::from_utf8_lossy(body).into())),
                FRAME_RESTARTING => return Err(DerpError::Restarting),
                _ => {}
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand::rngs::OsRng;

    use super::*;

    fn server_key_frame(server: &NodePrivate) -> Vec<u8> {
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(server.public().as_bytes());
        frame(FRAME_SERVER_KEY, &body)
    }

    #[test]
    fn handshake_and_packets() {
        let client = NodePrivate::generate();
        let server = NodePrivate::generate();
        let mut s = Session::new(client.clone(), "relay.example", "test", OsRng);
        let req = s.poll_transmit().unwrap();
        assert!(req.starts_with(b"GET /derp HTTP/1.1\r\nHost: relay.example\r\n"));

        let mut greeting = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n".to_vec();
        greeting.extend(server_key_frame(&server));
        let (a, b) = greeting.split_at(20);
        s.receive(a).unwrap();
        assert!(!s.is_upgraded());
        s.receive(b).unwrap();
        assert!(s.is_upgraded() && !s.is_connected());

        let info = s.poll_transmit().unwrap();
        assert_eq!(info[0], FRAME_CLIENT_INFO);
        let body = &info[FRAME_HEADER_LEN..];
        assert_eq!(&body[..KEY_LEN], client.public().as_bytes());
        let opened = server
            .open_from(&client.public(), &body[KEY_LEN..])
            .unwrap();
        assert!(opened.starts_with(b"{\"version\":2"));

        let sealed = server.seal_to(&mut OsRng, &client.public(), b"{}");
        s.receive(&frame(FRAME_SERVER_INFO, &sealed)).unwrap();
        assert!(s.is_connected());

        let peer = NodePrivate::generate().public();
        let mut recv = peer.as_bytes().to_vec();
        recv.extend_from_slice(b"hello");
        let mut wire = frame(FRAME_RECV_PACKET, &recv);
        wire.extend(frame(FRAME_PING, &[1; 8]));
        s.receive(&wire).unwrap();
        assert!(
            matches!(s.poll_event(), Some(Event::Packet(p)) if p.src == peer && p.data == b"hello")
        );
        assert_eq!(s.poll_transmit().unwrap(), frame(FRAME_PONG, &[1; 8]));

        assert!(s.send_packet(&peer, b"out"));
        let sent = s.poll_transmit().unwrap();
        assert_eq!(sent[0], FRAME_SEND_PACKET);
        assert!(!s.send_packet(&peer, &vec![0; MAX_PACKET_SIZE + 1]));

        assert!(matches!(
            s.receive(&frame(FRAME_RESTARTING, &[])),
            Err(DerpError::Restarting)
        ));
    }

    #[test]
    fn refused_upgrade_and_oversized_frames_fail() {
        let mut s = Session::new(NodePrivate::generate(), "h", "test", OsRng);
        assert!(matches!(
            s.receive(b"HTTP/1.1 404 Not Found\r\n"),
            Err(DerpError::UpgradeRefused { .. })
        ));

        let mut s = Session::new(NodePrivate::generate(), "h", "test", OsRng);
        let mut wire = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        wire.extend_from_slice(&[FRAME_SERVER_KEY, 0, 0, 0x10, 0]);
        assert!(matches!(
            s.receive(&wire),
            Err(DerpError::FrameTooLarge { .. })
        ));
    }
}
