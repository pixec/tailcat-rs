use std::net::IpAddr;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use smoltcp::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::key::{NodePrivate, NodePublic, PresharedKey};
use crate::tunnel::{Tunnel, TunnelResult, WireGuard};

pub(crate) struct BoringTun {
    secret: StaticSecret,
    public: PublicKey,
    psk: Option<[u8; 32]>,
}

impl BoringTun {
    pub(crate) fn new(key: &NodePrivate, psk: Option<PresharedKey>) -> Self {
        BoringTun {
            secret: key.static_secret(),
            public: key.public().x25519(),
            psk: psk.map(|k| *k.as_bytes()),
        }
    }
}

impl WireGuard for BoringTun {
    type Tunnel = Tunn;

    fn tunnel(&mut self, peer: NodePublic, index: u32) -> Tunn {
        Tunn::new(
            self.secret.clone(),
            peer.x25519(),
            self.psk,
            None,
            index,
            None,
        )
    }

    fn initiator(&self, initiation: &[u8]) -> Option<NodePublic> {
        let Packet::HandshakeInit(init) = Tunn::parse_incoming_packet(initiation).ok()? else {
            return None;
        };
        let half = parse_handshake_anon(&self.secret, &self.public, &init).ok()?;
        Some(NodePublic::from_raw(half.peer_static_public))
    }
}

fn convert(r: TunnResult<'_>) -> TunnelResult<'_, WireGuardError> {
    match r {
        TunnResult::Done => TunnelResult::Done,
        TunnResult::Err(err) => TunnelResult::Err(err),
        TunnResult::WriteToNetwork(p) => TunnelResult::WriteToNetwork(p),
        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
            TunnelResult::WriteToTunnel(p)
        }
    }
}

impl Tunnel for Tunn {
    type Error = WireGuardError;

    fn encapsulate<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
        _: Instant,
    ) -> TunnelResult<'a, WireGuardError> {
        convert(Tunn::encapsulate(self, packet, dst))
    }

    fn decapsulate<'a>(
        &mut self,
        src: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
        _: Instant,
    ) -> TunnelResult<'a, WireGuardError> {
        convert(Tunn::decapsulate(self, src, datagram, dst))
    }

    fn update_timers<'a>(
        &mut self,
        dst: &'a mut [u8],
        _: Instant,
    ) -> TunnelResult<'a, WireGuardError> {
        match Tunn::update_timers(self, dst) {
            TunnResult::Err(WireGuardError::ConnectionExpired) => TunnelResult::Done,
            r => convert(r),
        }
    }
}
