//! The seam between the transport and a WireGuard implementation.
//!
//! The transport never touches WireGuard's cryptography. It hands packets to
//! a [`Tunnel`] per client and asks a [`WireGuard`] for new tunnels and for
//! the static key inside a handshake initiation. With the `std` feature,
//! boringtun provides both; a `no_std` user plugs in their own.

use core::fmt::Debug;
use core::net::IpAddr;

use smoltcp::time::Instant;

use crate::key::NodePublic;

/// What a tunnel operation produced. Borrowed packets live in the buffer the
/// caller passed in.
#[derive(Debug)]
pub enum TunnelResult<'a, E> {
    Done,
    Err(E),
    /// A WireGuard message to send to the peer.
    WriteToNetwork(&'a [u8]),
    /// A decrypted IP packet from the peer.
    WriteToTunnel(&'a [u8]),
}

/// One WireGuard session with one peer.
pub trait Tunnel {
    type Error: Debug;

    /// Encrypts an IP packet for the peer.
    fn encapsulate<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnelResult<'a, Self::Error>;

    /// Processes a WireGuard message from the peer. After a
    /// [`TunnelResult::WriteToNetwork`], it is called again with an empty
    /// datagram until it returns something else, which flushes packets
    /// queued behind a handshake.
    fn decapsulate<'a>(
        &mut self,
        src: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnelResult<'a, Self::Error>;

    /// Runs handshake and keepalive timers. Called every
    /// [`TICK`](crate::transport::TICK). An expired session is
    /// [`TunnelResult::Done`], not an error.
    fn update_timers<'a>(
        &mut self,
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnelResult<'a, Self::Error>;
}

/// The server's WireGuard identity, which creates a tunnel per client.
pub trait WireGuard {
    type Tunnel: Tunnel;

    /// A tunnel to `peer`. The receiver index of every message the peer
    /// sends on it must carry `index` in its upper 24 bits.
    fn tunnel(&mut self, peer: NodePublic, index: u32) -> Self::Tunnel;

    /// The initiator's static key in a handshake initiation addressed to
    /// us, or `None` if it does not decrypt.
    fn initiator(&self, initiation: &[u8]) -> Option<NodePublic>;
}

pub(crate) enum Kind {
    Initiation,
    Receiver(u32),
}

/// Classifies a WireGuard message by its type and length.
pub(crate) fn classify(data: &[u8]) -> Option<Kind> {
    let typ = u32::from_le_bytes(*data.first_chunk()?);
    let at = match (typ, data.len()) {
        (1, 148) => return Some(Kind::Initiation),
        (2, 92) => 8,
        (3, 64) | (4, 32..) => 4,
        _ => return None,
    };
    Some(Kind::Receiver(u32::from_le_bytes(
        *data[at..].first_chunk()?,
    )))
}
