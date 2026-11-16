//! Disco: Tailscale's path-discovery messages.
//!
//! A disco frame is the magic `TS💬`, the sender's disco public key, and a
//! NaCl box (sealed with the two parties' disco keys) around one message.
//! Pings and pongs probe candidate UDP paths; a call-me-maybe, sent over
//! DERP, tells the peer which endpoints to probe. Only the three message
//! types tailcat exchanges are decoded; anything else sealed correctly is
//! reported as [`Message::Other`] and ignored, as a newer peer's extension.

use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};

use rand_core::{CryptoRng, RngCore};

use crate::key::{DiscoPublic, DiscoShared, KEY_LEN, NodePublic};

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + KEY_LEN;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;
const V0: u8 = 0;
const ENDPOINT_LEN: usize = 18;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct TxId(pub [u8; 12]);

impl TxId {
    pub fn from_rng(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut b = [0u8; 12];
        rng.fill_bytes(&mut b);
        Self(b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping {
        tx_id: TxId,
        /// The sender's claimed node key. Not to be trusted alone, but it
        /// lets a receiver that knows the disco key pin it to one node.
        node_key: Option<NodePublic>,
    },
    Pong {
        tx_id: TxId,
        /// Where the ping being answered appeared to come from.
        src: SocketAddr,
    },
    CallMeMaybe {
        endpoints: Vec<SocketAddr>,
    },
    Other(u8),
}

fn put_endpoint(b: &mut Vec<u8>, ep: &SocketAddr) {
    let ip16 = match ep.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    b.extend_from_slice(&ip16.octets());
    b.extend_from_slice(&ep.port().to_be_bytes());
}

fn parse_endpoint(b: &[u8; ENDPOINT_LEN]) -> SocketAddr {
    let [ip @ .., hi, lo] = *b;
    let ip = IpAddr::V6(Ipv6Addr::from(ip)).to_canonical();
    SocketAddr::new(ip, u16::from_be_bytes([hi, lo]))
}

impl Message {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        match self {
            Message::Ping { tx_id, node_key } => {
                b.extend_from_slice(&[TYPE_PING, V0]);
                b.extend_from_slice(&tx_id.0);
                if let Some(k) = node_key {
                    b.extend_from_slice(k.as_bytes());
                }
            }
            Message::Pong { tx_id, src } => {
                b.extend_from_slice(&[TYPE_PONG, V0]);
                b.extend_from_slice(&tx_id.0);
                put_endpoint(&mut b, src);
            }
            Message::CallMeMaybe { endpoints } => {
                b.extend_from_slice(&[TYPE_CALL_ME_MAYBE, V0]);
                for ep in endpoints {
                    put_endpoint(&mut b, ep);
                }
            }
            Message::Other(t) => b.extend_from_slice(&[*t, V0]),
        }
        b
    }

    pub fn parse(p: &[u8]) -> Option<Message> {
        if p.len() < 2 {
            return None;
        }
        let (typ, ver, p) = (p[0], p[1], &p[2..]);
        match typ {
            TYPE_PING => {
                let (tx_id, rest) = p.split_first_chunk()?;
                let tx_id = TxId(*tx_id);
                let node_key = rest
                    .get(..KEY_LEN)
                    .and_then(NodePublic::from_slice)
                    .filter(|k| !k.is_zero());
                Some(Message::Ping { tx_id, node_key })
            }
            TYPE_PONG => {
                let (tx_id, rest) = p.split_first_chunk()?;
                Some(Message::Pong {
                    tx_id: TxId(*tx_id),
                    src: parse_endpoint(rest.first_chunk()?),
                })
            }
            TYPE_CALL_ME_MAYBE => {
                let (endpoints, rest) = p.as_chunks();
                if ver != V0 || endpoints.is_empty() || !rest.is_empty() {
                    return Some(Message::CallMeMaybe { endpoints: vec![] });
                }
                Some(Message::CallMeMaybe {
                    endpoints: endpoints.iter().map(parse_endpoint).collect(),
                })
            }
            other => Some(Message::Other(other)),
        }
    }
}

#[must_use]
pub fn is_disco(pkt: &[u8]) -> bool {
    pkt.len() >= HEADER_LEN + NONCE_LEN && &pkt[..MAGIC.len()] == MAGIC
}

/// The disco public key a frame claims to come from. Only meaningful if
/// the box later opens with that key.
#[must_use]
pub fn sender(pkt: &[u8]) -> Option<DiscoPublic> {
    if !is_disco(pkt) {
        return None;
    }
    DiscoPublic::from_slice(&pkt[MAGIC.len()..HEADER_LEN])
}

/// Frames and seals `msg` from `sender` for the peer `shared` was derived
/// with.
pub fn seal(
    rng: &mut (impl RngCore + CryptoRng),
    shared: &DiscoShared,
    sender: &DiscoPublic,
    msg: &Message,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(HEADER_LEN + NONCE_LEN + 64);
    pkt.extend_from_slice(MAGIC);
    pkt.extend_from_slice(sender.as_bytes());
    pkt.extend(shared.seal(rng, &msg.encode()));
    pkt
}

/// Opens a frame previously checked with [`is_disco`].
#[must_use]
pub fn open(shared: &DiscoShared, pkt: &[u8]) -> Option<Message> {
    let payload = shared.open(&pkt[HEADER_LEN..])?;
    Message::parse(&payload)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::key::NodePrivate;

    #[test]
    fn messages_round_trip() {
        let node = NodePrivate::generate().public();
        let msgs = vec![
            Message::Ping {
                tx_id: TxId::from_rng(&mut OsRng),
                node_key: Some(node),
            },
            Message::Ping {
                tx_id: TxId::from_rng(&mut OsRng),
                node_key: None,
            },
            Message::Pong {
                tx_id: TxId::from_rng(&mut OsRng),
                src: "203.0.113.9:4444".parse().unwrap(),
            },
            Message::Pong {
                tx_id: TxId::from_rng(&mut OsRng),
                src: "[2001:db8::9]:4444".parse().unwrap(),
            },
            Message::CallMeMaybe {
                endpoints: vec![
                    "192.0.2.1:1".parse().unwrap(),
                    "[2001:db8::2]:2".parse().unwrap(),
                ],
            },
        ];
        for m in msgs {
            assert_eq!(Message::parse(&m.encode()).unwrap(), m, "{m:?}");
        }
        assert_eq!(Message::parse(&[0x09, 0]), Some(Message::Other(9)));
        assert!(Message::parse(&[TYPE_PING, 0, 1, 2, 3]).is_none());
    }

    #[test]
    fn ping_wire_layout() {
        let node = NodePrivate::generate().public();
        let tx = TxId([7; 12]);
        let b = Message::Ping {
            tx_id: tx,
            node_key: Some(node),
        }
        .encode();
        assert_eq!(b.len(), 2 + 12 + 32);
        assert_eq!(&b[..2], &[1, 0]);
        assert_eq!(&b[2..14], &[7; 12]);
        assert_eq!(&b[14..], node.as_bytes());
    }

    #[test]
    fn sealed_frames_open_only_for_the_peer() {
        let a = NodePrivate::generate().disco();
        let b = NodePrivate::generate().disco();
        let c = NodePrivate::generate().disco();
        let msg = Message::CallMeMaybe {
            endpoints: vec!["10.0.0.1:41641".parse().unwrap()],
        };
        let pkt = seal(&mut OsRng, &a.shared(&b.public()), &a.public(), &msg);
        assert!(is_disco(&pkt));
        assert_eq!(sender(&pkt), Some(a.public()));
        assert_eq!(open(&b.shared(&a.public()), &pkt), Some(msg));
        assert_eq!(open(&c.shared(&a.public()), &pkt), None);
    }
}
