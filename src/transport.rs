//! The transport under the tunnel: WireGuard over the relay and, once disco
//! has found one, over a direct UDP path.
//!
//! This is the small corner of magicsock that tailcat needs. Every client
//! that meows becomes a WireGuard peer whose packets can arrive from the
//! relay, tagged with its node key, or from any UDP address, in which case
//! the WireGuard receiver index (or, for a handshake initiation, the static
//! key inside it) says which tunnel they belong to.
//!
//! Path selection is deliberately simple. We learn our own endpoints from
//! STUN and the local interfaces and advertise them in a call-me-maybe
//! whenever a client registers or they change. Candidates for a client come
//! from its call-me-maybe and from wherever its disco pings arrive; we ping
//! them, and a pong promotes its address to the direct path, trusted for a
//! few seconds at a time and kept alive by a heartbeat. Without a recent
//! pong, sends fall back to the relay. The stock client runs the full
//! magicsock state machine on its side and needs nothing more from us than
//! prompt pongs and an honest call-me-maybe.
//!
//! [`Transport`] is sans-IO. The caller feeds it what arrives from the relay
//! and from UDP, the IP packets the stack wants sent, and a [`TICK`] timer,
//! always with the current time, then drains [`Transport::poll_transmit`]
//! and [`Transport::poll_received`].

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::{CryptoRng, RngCore};
use smoltcp::time::{Duration, Instant};

use crate::derpmap::DerpRegion;
use crate::disco::{self, Message, TxId};
use crate::key::{DiscoPrivate, DiscoPublic, DiscoShared, NodePrivate, NodePublic};
use crate::meow;
use crate::stun;
use crate::tunnel::{self, Kind, Tunnel, TunnelResult, WireGuard};

/// How often [`Transport::tick`] must be called.
pub const TICK: Duration = Duration::from_millis(250);
const TICKS_PER_HEARTBEAT: u64 = 12;
const TICKS_PER_STUN: u64 = 120;
/// How often a candidate is pinged while no direct path is trusted.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
/// How long a pong keeps a direct path trusted. Tailscale's figure.
const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// A peer with no tunnel traffic for this long stops being probed.
const SESSION_ACTIVE: Duration = Duration::from_secs(120);
/// Endpoints older than this are refreshed before being advertised to a new
/// client.
const ENDPOINTS_FRESH: Duration = Duration::from_secs(20);
const MAPPED_TTL: Duration = Duration::from_secs(90);
const CALL_ME_MAYBE_INTERVAL: Duration = Duration::from_secs(30);
/// Tailscale's placeholder address for "the relay" in disco pongs.
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const BUF: usize = 2048;

pub struct Config<W, R> {
    pub key: NodePrivate,
    pub region: DerpRegion,
    /// `None` admits every client.
    pub allowed_clients: Option<BTreeSet<NodePublic>>,
    pub wireguard: W,
    pub rng: R,
}

/// A packet for the caller to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transmit {
    /// Send over UDP. If that is impossible and `fallback` is set, relay
    /// the same packet to that node instead.
    Udp {
        dst: SocketAddr,
        data: Vec<u8>,
        fallback: Option<NodePublic>,
    },
    /// Send through the relay.
    Derp { dst: NodePublic, data: Vec<u8> },
}

/// A client as the transport sees it.
#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub key: NodePublic,
    pub addr: Ipv6Addr,
    /// The UDP address currently trusted for sending, if any.
    pub direct: Option<SocketAddr>,
    /// Last UDP address a disco pong authenticated. Kept after the sending
    /// path falls back to DERP, so a share can still spoof that public IP.
    pub last_udp: Option<SocketAddr>,
    pub idle: core::time::Duration,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Path {
    Derp,
    Udp(SocketAddr),
}

#[derive(Default)]
struct Candidate {
    is_from_call_me_maybe: bool,
    last_ping: Option<Instant>,
}

struct Direct {
    addr: SocketAddr,
    latency: Duration,
    trust_until: Instant,
    last_pong: Instant,
}

struct Peer<T> {
    key: NodePublic,
    shared: DiscoShared,
    tunn: T,
    addr: Ipv6Addr,
    direct: Option<Direct>,
    /// Last pong-verified UDP address, independent of whether it is still
    /// trusted for sending.
    last_udp: Option<SocketAddr>,
    candidates: BTreeMap<SocketAddr, Candidate>,
    sent_pings: BTreeMap<TxId, (SocketAddr, Instant)>,
    last_activity: Instant,
    last_call_me_maybe: Option<Instant>,
}

impl<T> Peer<T> {
    fn direct_path(&self, now: Instant) -> Option<SocketAddr> {
        self.direct
            .as_ref()
            .filter(|d| now < d.trust_until)
            .map(|d| d.addr)
    }
}

struct Outbox<R> {
    rng: R,
    public: NodePublic,
    disco_pub: DiscoPublic,
    transmits: VecDeque<Transmit>,
    received: VecDeque<Vec<u8>>,
}

impl<R: RngCore + CryptoRng> Outbox<R> {
    fn udp(&mut self, dst: SocketAddr, data: Vec<u8>, fallback: Option<NodePublic>) {
        self.transmits.push_back(Transmit::Udp {
            dst,
            data,
            fallback,
        });
    }

    fn derp(&mut self, dst: NodePublic, data: Vec<u8>) {
        self.transmits.push_back(Transmit::Derp { dst, data });
    }

    fn send_peer<T>(&mut self, peer: &Peer<T>, now: Instant, pkt: &[u8]) {
        match peer.direct_path(now) {
            Some(addr) => self.udp(addr, pkt.to_vec(), Some(peer.key)),
            None => self.derp(peer.key, pkt.to_vec()),
        }
    }

    fn send_disco<T>(&mut self, peer: &Peer<T>, path: Path, msg: &Message) {
        let pkt = disco::seal(&mut self.rng, &peer.shared, &self.disco_pub, msg);
        match path {
            Path::Udp(addr) => self.udp(addr, pkt, None),
            Path::Derp => self.derp(peer.key, pkt),
        }
    }

    fn ping<T>(&mut self, peer: &mut Peer<T>, addr: SocketAddr, now: Instant) {
        let tx_id = TxId::from_rng(&mut self.rng);
        peer.sent_pings.insert(tx_id, (addr, now));
        if let Some(c) = peer.candidates.get_mut(&addr) {
            c.last_ping = Some(now);
        }
        let node_key = Some(self.public);
        self.send_disco(peer, Path::Udp(addr), &Message::Ping { tx_id, node_key });
    }

    fn call_me_maybe<T>(&mut self, endpoints: &[SocketAddr], peer: &mut Peer<T>, now: Instant) {
        if endpoints.is_empty() {
            return;
        }
        peer.last_call_me_maybe = Some(now);
        self.send_disco(
            peer,
            Path::Derp,
            &Message::CallMeMaybe {
                endpoints: endpoints.to_vec(),
            },
        );
    }

    fn heartbeat<T>(&mut self, endpoints: &[SocketAddr], peer: &mut Peer<T>, now: Instant) {
        peer.sent_pings
            .retain(|_, (_, at)| now - *at < PING_TIMEOUT);
        if now - peer.last_activity > SESSION_ACTIVE {
            return;
        }
        if let Some(d) = &peer.direct {
            if now - d.last_pong > TRUST_UDP_ADDR + PING_TIMEOUT {
                tracing::info!(client = %peer.key.short(), addr = %d.addr, "direct path lost, using relay");
                peer.direct = None;
            } else {
                let addr = d.addr;
                self.ping(peer, addr, now);
                return;
            }
        }
        let due: Vec<SocketAddr> = peer
            .candidates
            .iter()
            .filter(|(_, c)| c.last_ping.is_none_or(|t| now - t >= DISCO_PING_INTERVAL))
            .map(|(a, _)| *a)
            .collect();
        for addr in due {
            self.ping(peer, addr, now);
        }
        if peer.candidates.is_empty()
            && peer
                .last_call_me_maybe
                .is_none_or(|t| now - t >= CALL_ME_MAYBE_INTERVAL)
        {
            self.call_me_maybe(endpoints, peer, now);
        }
    }

    fn decapsulate<T: Tunnel>(
        &mut self,
        peer: &mut Peer<T>,
        src_ip: Option<IpAddr>,
        data: &[u8],
        now: Instant,
    ) {
        let mut buf = [0u8; BUF];
        let mut datagram = data;
        loop {
            match peer.tunn.decapsulate(src_ip, datagram, &mut buf, now) {
                TunnelResult::WriteToNetwork(pkt) => {
                    self.send_peer(peer, now, pkt);
                    datagram = &[];
                }
                TunnelResult::WriteToTunnel(pkt) => {
                    // AllowedIPs: a client may only source packets from its own
                    // tunnel address, which is enforced here rather than by a
                    // filter that could be misordered.
                    match ipv6_src(pkt) {
                        Some(src) if src == peer.addr => {
                            peer.last_activity = now;
                            self.received.push_back(pkt.to_vec());
                        }
                        Some(src) => {
                            tracing::debug!(client = %peer.key.short(), %src, "dropping packet from disallowed source");
                        }
                        None => {}
                    }
                    return;
                }
                TunnelResult::Done => return,
                TunnelResult::Err(err) => {
                    tracing::trace!(client = %peer.key.short(), ?err, "decapsulate");
                    return;
                }
            }
        }
    }
}

fn ipv6_src(pkt: &[u8]) -> Option<Ipv6Addr> {
    let hdr = pkt.first_chunk::<40>()?;
    if hdr[0] >> 4 != 6 {
        return None;
    }
    Some(Ipv6Addr::from(*hdr[8..].first_chunk::<16>()?))
}

/// Every client's tunnel and path, and the server's own endpoints.
pub struct Transport<W: WireGuard, R> {
    disco_priv: DiscoPrivate,
    region: DerpRegion,
    wg: W,
    out: Outbox<R>,
    peers: BTreeMap<NodePublic, Peer<W::Tunnel>>,
    by_index: BTreeMap<u32, NodePublic>,
    by_addr: BTreeMap<Ipv6Addr, NodePublic>,
    by_disco: BTreeMap<DiscoPublic, NodePublic>,
    allowed: Option<BTreeSet<NodePublic>>,
    next_index: u32,
    stun_sent: BTreeMap<stun::TxId, (SocketAddr, Instant)>,
    mapped: BTreeMap<SocketAddr, (SocketAddr, Instant)>,
    local: Vec<SocketAddr>,
    endpoints: Vec<SocketAddr>,
    last_stun: Option<Instant>,
    is_stun_wanted: bool,
    ticks: u64,
}

impl<W: WireGuard, R: RngCore + CryptoRng> Transport<W, R> {
    pub fn new(cfg: Config<W, R>) -> Self {
        let disco_priv = cfg.key.disco();
        Transport {
            out: Outbox {
                rng: cfg.rng,
                public: cfg.key.public(),
                disco_pub: disco_priv.public(),
                transmits: VecDeque::new(),
                received: VecDeque::new(),
            },
            disco_priv,
            region: cfg.region,
            wg: cfg.wireguard,
            peers: BTreeMap::new(),
            by_index: BTreeMap::new(),
            by_addr: BTreeMap::new(),
            by_disco: BTreeMap::new(),
            allowed: cfg.allowed_clients,
            next_index: 1,
            stun_sent: BTreeMap::new(),
            mapped: BTreeMap::new(),
            local: Vec::new(),
            endpoints: Vec::new(),
            last_stun: None,
            is_stun_wanted: false,
            ticks: 0,
        }
    }

    /// The next packet to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.out.transmits.pop_front()
    }

    /// The next decrypted IPv6 packet for the stack.
    pub fn poll_received(&mut self) -> Option<Vec<u8>> {
        self.out.received.pop_front()
    }

    /// Handles a packet the relay delivered from `src`.
    pub fn handle_derp(&mut self, src: NodePublic, data: &[u8], now: Instant) {
        if disco::is_disco(data) {
            self.handle_disco(data, Path::Derp, Some(src), now);
        } else if meow::is_meow(data) {
            if let Some((_, disco_pub)) = meow::parse_ping(data) {
                self.on_meow(src, disco_pub, now);
            }
        } else if let Some(peer) = self.peers.get_mut(&src) {
            self.out.decapsulate(peer, None, data, now);
        }
    }

    /// Handles a datagram that arrived on one of our UDP sockets.
    pub fn handle_udp(&mut self, from: SocketAddr, data: &[u8], now: Instant) {
        if let Some((tx, mapped)) = stun::parse_response(data) {
            self.on_stun(tx, mapped, now);
            return;
        }
        if disco::is_disco(data) {
            self.handle_disco(data, Path::Udp(from), None, now);
            return;
        }
        let Some(key) = self.peer_for_wg(data) else {
            return;
        };
        if let Some(peer) = self.peers.get_mut(&key) {
            self.out.decapsulate(peer, Some(from.ip()), data, now);
        }
    }

    /// Which tunnel a WireGuard packet from an arbitrary UDP source belongs
    /// to. Every message but a handshake initiation names our session index,
    /// whose high bits are the peer's; an initiation is decrypted far enough
    /// to read the initiator's static key.
    fn peer_for_wg(&self, data: &[u8]) -> Option<NodePublic> {
        match tunnel::classify(data)? {
            Kind::Initiation => self.wg.initiator(data),
            Kind::Receiver(index) => self.by_index.get(&(index >> 8)).copied(),
        }
    }

    fn on_meow(&mut self, src: NodePublic, disco_pub: DiscoPublic, now: Instant) {
        if self.allowed.as_ref().is_some_and(|a| !a.contains(&src)) {
            tracing::info!(client = %src.short(), "ignoring meow: not an allowed client");
            return;
        }
        if !self.peers.contains_key(&src) {
            let index = self.next_index;
            self.next_index += 1;
            let addr = src.addr();
            self.peers.insert(
                src,
                Peer {
                    key: src,
                    shared: self.disco_priv.shared(&disco_pub),
                    tunn: self.wg.tunnel(src, index),
                    addr,
                    direct: None,
                    last_udp: None,
                    candidates: BTreeMap::new(),
                    sent_pings: BTreeMap::new(),
                    last_activity: now,
                    last_call_me_maybe: None,
                },
            );
            self.by_index.insert(index, src);
            self.by_addr.insert(addr, src);
            self.by_disco.insert(disco_pub, src);
            tracing::info!(client = %src.short(), %addr, "client registered");
        }
        // Sent last, and only here: a client reads the reply as permission to
        // dial, which is a lie unless its tunnel already exists.
        self.out.derp(src, meow::encode_meowed());
        if self.last_stun.is_none_or(|t| now - t > ENDPOINTS_FRESH) {
            self.is_stun_wanted = true;
        }
        let peer = self.peers.get_mut(&src).expect("just inserted");
        self.out.call_me_maybe(&self.endpoints, peer, now);
    }

    fn handle_disco(
        &mut self,
        data: &[u8],
        path: Path,
        derp_src: Option<NodePublic>,
        now: Instant,
    ) {
        let Some(sender) = disco::sender(data) else {
            return;
        };
        let Some(key) = self.by_disco.get(&sender).copied() else {
            return;
        };
        let peer = self.peers.get_mut(&key).expect("indexed peer exists");
        let Some(msg) = disco::open(&peer.shared, data) else {
            return;
        };
        match msg {
            Message::Ping { tx_id, .. } => {
                let src = match path {
                    Path::Udp(addr) => addr,
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    Path::Derp => {
                        SocketAddr::new(DERP_MAGIC_IP.into(), self.region.region_id as u16)
                    }
                };
                self.out
                    .send_disco(peer, path, &Message::Pong { tx_id, src });
                if let Path::Udp(addr) = path
                    && !peer.candidates.contains_key(&addr)
                {
                    peer.candidates.insert(addr, Candidate::default());
                    self.out.ping(peer, addr, now);
                }
            }
            Message::Pong { tx_id, .. } => {
                let Some((to, at)) = peer.sent_pings.remove(&tx_id) else {
                    return;
                };
                let Path::Udp(_) = path else {
                    return;
                };
                let latency = now - at;
                let better = match &peer.direct {
                    Some(d) if d.addr == to => false,
                    Some(d) => now > d.trust_until || latency < d.latency,
                    None => true,
                };
                match &mut peer.direct {
                    Some(d) if !better => {
                        if d.addr == to {
                            d.latency = latency;
                            d.last_pong = now;
                            d.trust_until = now + TRUST_UDP_ADDR;
                            peer.last_udp = Some(to);
                        }
                    }
                    slot => {
                        tracing::info!(client = %peer.key.short(), %to, %latency, "using direct path");
                        *slot = Some(Direct {
                            addr: to,
                            latency,
                            trust_until: now + TRUST_UDP_ADDR,
                            last_pong: now,
                        });
                        peer.last_udp = Some(to);
                    }
                }
            }
            Message::CallMeMaybe { endpoints } => {
                if path != Path::Derp || derp_src != Some(peer.key) {
                    return;
                }
                peer.candidates
                    .retain(|addr, c| !c.is_from_call_me_maybe || endpoints.contains(addr));
                for ep in endpoints {
                    if let IpAddr::V6(v6) = ep.ip()
                        && v6.is_unicast_link_local()
                    {
                        continue;
                    }
                    peer.candidates.entry(ep).or_default().is_from_call_me_maybe = true;
                }
                let addrs: Vec<SocketAddr> = peer.candidates.keys().copied().collect();
                tracing::debug!(client = %peer.key.short(), ?addrs, "call-me-maybe");
                for addr in addrs {
                    self.out.ping(peer, addr, now);
                }
            }
            Message::Other(_) => {}
        }
    }

    /// Encrypts an IPv6 packet from the stack for the client it is
    /// addressed to.
    pub fn send_ip(&mut self, pkt: &[u8], now: Instant) {
        let Some(dst) = pkt.get(24..).and_then(<[u8]>::first_chunk::<16>) else {
            return;
        };
        let Some(peer) = self
            .by_addr
            .get(&Ipv6Addr::from(*dst))
            .and_then(|key| self.peers.get_mut(key))
        else {
            return;
        };
        peer.last_activity = now;
        let mut buf = [0u8; BUF];
        match peer.tunn.encapsulate(pkt, &mut buf, now) {
            TunnelResult::WriteToNetwork(out) => self.out.send_peer(peer, now, out),
            TunnelResult::Err(err) => {
                tracing::debug!(client = %peer.key.short(), ?err, "encapsulate");
            }
            _ => {}
        }
    }

    /// Whether the next [`tick`](Self::tick) refreshes the advertised
    /// endpoints, so the caller should first report its interface addresses
    /// through [`set_local_endpoints`](Self::set_local_endpoints).
    #[must_use]
    pub fn wants_local_endpoints(&self) -> bool {
        self.ticks.is_multiple_of(TICKS_PER_STUN) || self.is_stun_wanted
    }

    /// Sets the endpoints of this host's interfaces, with the matching UDP
    /// socket's port. Loopback should be included only when nothing else
    /// is, as magicsock does.
    pub fn set_local_endpoints(&mut self, endpoints: Vec<SocketAddr>) {
        self.local = endpoints;
    }

    /// Runs WireGuard timers, disco heartbeats and STUN probes. Call every
    /// [`TICK`].
    pub fn tick(&mut self, now: Instant) {
        let n = self.ticks;
        self.ticks += 1;
        let mut buf = [0u8; BUF];
        for peer in self.peers.values_mut() {
            match peer.tunn.update_timers(&mut buf, now) {
                TunnelResult::WriteToNetwork(out) => self.out.send_peer(peer, now, out),
                TunnelResult::Err(err) => {
                    tracing::debug!(client = %peer.key.short(), ?err, "wireguard timers");
                }
                _ => {}
            }
        }
        if n.is_multiple_of(TICKS_PER_HEARTBEAT) {
            for peer in self.peers.values_mut() {
                self.out.heartbeat(&self.endpoints, peer, now);
            }
        }
        if n.is_multiple_of(TICKS_PER_STUN) || self.is_stun_wanted {
            self.is_stun_wanted = false;
            self.stun_probe(now);
            self.update_endpoints(now);
        }
    }

    fn stun_probe(&mut self, now: Instant) {
        self.stun_sent.retain(|_, (_, at)| now - *at < PING_TIMEOUT);
        for node in &self.region.nodes {
            let Some(port) = node.stun_port() else {
                continue;
            };
            for ip in node.ip_addrs() {
                let server = SocketAddr::new(ip, port);
                let tx = stun::TxId::from_rng(&mut self.out.rng);
                self.out.udp(server, stun::request(tx), None);
                self.stun_sent.insert(tx, (server, now));
            }
        }
        self.last_stun = Some(now);
    }

    fn on_stun(&mut self, tx: stun::TxId, mapped: SocketAddr, now: Instant) {
        let Some((server, _)) = self.stun_sent.remove(&tx) else {
            return;
        };
        self.mapped.insert(server, (mapped, now));
        self.update_endpoints(now);
    }

    /// Recomputes what we advertise: every interface address with the
    /// matching socket's port, plus whatever STUN has recently reported. A
    /// change is sent to every client, which is what lets a client behind a
    /// NAT find a path to us: magicsock never probes a peer it has no
    /// endpoints for.
    fn update_endpoints(&mut self, now: Instant) {
        self.mapped.retain(|_, (_, at)| now - *at < MAPPED_TTL);
        let mut eps = self.local.clone();
        eps.extend(self.mapped.values().map(|(a, _)| *a));
        eps.sort();
        eps.dedup();
        if eps == self.endpoints {
            return;
        }
        tracing::debug!(endpoints = ?eps, "endpoints changed");
        self.endpoints = eps;
        for peer in self.peers.values_mut() {
            peer.last_call_me_maybe = None;
            self.out.call_me_maybe(&self.endpoints, peer, now);
        }
    }

    /// The client whose tunnel address is `addr`.
    #[must_use]
    pub fn peer_for_addr(&self, addr: Ipv6Addr) -> Option<NodePublic> {
        self.by_addr.get(&addr).copied()
    }

    /// Admits `key`. Until any key is allowed every client is.
    pub fn add_allowed_client(&mut self, key: NodePublic) {
        self.allowed.get_or_insert_with(BTreeSet::new).insert(key);
    }

    /// The registered clients and the path each currently uses.
    #[must_use]
    pub fn peers(&self, now: Instant) -> Vec<PeerStatus> {
        self.peers
            .values()
            .map(|p| PeerStatus {
                key: p.key,
                addr: p.addr,
                direct: p.direct_path(now),
                last_udp: p.last_udp,
                idle: (now - p.last_activity).into(),
            })
            .collect()
    }
}
