//! The userspace TCP/UDP stack that terminates tunnel traffic.
//!
//! Decrypted IPv6 packets from peers are fed into a smoltcp interface; what
//! it wants to transmit comes back out to be encrypted. There is no TUN
//! device: the stack owns the server's tunnel address (and, when
//! forwarding is enabled, answers for any address) entirely in memory.
//!
//! Listeners are created on demand. Every inbound SYN is inspected before
//! the stack sees it: if the port policy admits it, a listening socket for
//! that exact address and port exists by the time the packet is processed,
//! so the connection completes and is reported as an accepted socket. A SYN
//! the policy refuses is dropped before the stack, so the client sees a
//! timeout rather than a refusal, as with the stock server's filter. UDP
//! datagrams likewise conjure a socket per destination and are demuxed per
//! source into flows that time out when idle.
//!
//! [`Netstack`] is sans-IO: the caller injects packets, calls
//! [`Netstack::poll`] with the current time, and drains
//! [`Netstack::poll_transmit`] and [`Netstack::poll_event`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::ops::RangeInclusive;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use crate::error::UdpSendError;

/// The tunnel MTU. WireGuard over IPv6 with room to spare, and what the
/// stock client assumes.
pub const MTU: usize = 1280;
const TCP_BUFFER: usize = 128 * 1024;
const UDP_PACKETS: usize = 128;
const UDP_BUFFER: usize = 256 * 1024;
/// A connection whose peer stops acknowledging is torn down after this,
/// so a client that vanished mid-transfer does not pin a socket forever.
const TCP_TIMEOUT: Duration = Duration::from_secs(90);

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// The NAT64 well-known prefix, `64:ff9b::/96`. Clients map IPv4
/// destinations into it, since the tunnel carries only IPv6.
const NAT64_PREFIX: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// Which ports on the server's own address admit new connections or flows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ports {
    All,
    Ranges(Vec<RangeInclusive<u16>>),
}

impl Ports {
    #[must_use]
    pub fn is_included(&self, port: u16) -> bool {
        match self {
            Ports::All => true,
            Ports::Ranges(ranges) => ranges.iter().any(|r| r.contains(&port)),
        }
    }

    pub fn list(ports: impl IntoIterator<Item = u16>) -> Self {
        Ports::Ranges(ports.into_iter().map(|p| p..=p).collect())
    }
}

/// What the stack admits from the tunnel.
#[derive(Clone, Debug)]
pub struct Policy {
    pub self_addr: Ipv6Addr,
    pub tcp_ports: Ports,
    /// `None` means no UDP is served at all.
    pub udp_ports: Option<Ports>,
    /// Also admit TCP aimed past us, which is what makes an exit node.
    pub is_tcp_forwarded: bool,
    pub is_udp_forwarded: bool,
    pub udp_idle_timeout: Duration,
}

/// Maps a NAT64-embedded IPv4 address back out; other addresses pass.
#[must_use]
pub fn unmap_nat64(ip: Ipv6Addr) -> IpAddr {
    let o = ip.octets();
    if o[..12] == NAT64_PREFIX {
        IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        IpAddr::V6(ip)
    }
}

/// A UDP flow: the local address and port, then the client's.
pub type FlowKey = (SocketAddrV6, SocketAddrV6);

/// Something the stack reports after a [`Netstack::poll`].
#[derive(Debug)]
pub enum Event {
    /// A client completed a TCP handshake. The socket is the caller's until
    /// it hands it back with [`Netstack::release_tcp`].
    TcpAccepted {
        handle: SocketHandle,
        local: SocketAddrV6,
        remote: SocketAddrV6,
    },
    /// A client started a UDP flow. Its datagrams follow.
    UdpFlow {
        key: FlowKey,
    },
    UdpDatagram {
        key: FlowKey,
        data: Vec<u8>,
    },
    /// A flow was idle for the policy's timeout and is gone.
    UdpFlowExpired {
        key: FlowKey,
    },
}

struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxToken(pkt), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

fn endpoint_v6(ep: IpEndpoint) -> SocketAddrV6 {
    match SocketAddr::from(ep) {
        SocketAddr::V6(a) => a,
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
    }
}

/// The stack, its sockets and the admission policy.
pub struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: Queues,
    policy: Policy,
    /// Sockets in `Listen` or `SynReceived` for each local endpoint. A SYN
    /// only creates a new listener when none of them is still listening.
    listeners: BTreeMap<(Ipv6Addr, u16), Vec<SocketHandle>>,
    /// Released sockets, removed once closed.
    closing: Vec<SocketHandle>,
    udp_sockets: BTreeMap<(Ipv6Addr, u16), SocketHandle>,
    flows: BTreeMap<FlowKey, Instant>,
    events: VecDeque<Event>,
    is_closed: bool,
}

impl Netstack {
    /// A stack owning `policy.self_addr`. `random_seed` seeds TCP initial
    /// sequence numbers and should be random.
    ///
    /// # Panics
    ///
    /// Never in practice: one address always fits the interface.
    #[must_use]
    pub fn new(policy: Policy, random_seed: u64, now: Instant) -> Self {
        let mut device = Queues {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(policy.self_addr), 128))
                .expect("one address fits");
        });
        iface.set_any_ip(policy.is_tcp_forwarded || policy.is_udp_forwarded);
        Netstack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            policy,
            listeners: BTreeMap::new(),
            closing: Vec::new(),
            udp_sockets: BTreeMap::new(),
            flows: BTreeMap::new(),
            events: VecDeque::new(),
            is_closed: false,
        }
    }

    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Queues one decrypted IPv6 packet from a peer, returning whether the
    /// policy admitted it.
    pub fn inject(&mut self, pkt: Vec<u8>) -> bool {
        if self.is_closed || !self.admit(&pkt) {
            return false;
        }
        self.device.rx.push_back(pkt);
        true
    }

    fn admit(&mut self, pkt: &[u8]) -> bool {
        let Some((hdr, payload)) = pkt.split_first_chunk::<40>() else {
            return false;
        };
        if hdr[0] >> 4 != 6 {
            return false;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&hdr[24..]);
        let dst = Ipv6Addr::from(dst);
        let to_self = dst == self.policy.self_addr;
        match hdr[6] {
            IPPROTO_TCP => {
                if payload.len() < 20 {
                    return false;
                }
                let port = u16::from_be_bytes([payload[2], payload[3]]);
                let admitted = if to_self {
                    self.policy.tcp_ports.is_included(port)
                } else {
                    self.policy.is_tcp_forwarded
                };
                if !admitted {
                    return false;
                }
                let flags = payload[13];
                if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
                    self.ensure_listener(dst, port);
                }
                true
            }
            IPPROTO_UDP => {
                if payload.len() < 8 {
                    return false;
                }
                let port = u16::from_be_bytes([payload[2], payload[3]]);
                let admitted = if to_self {
                    self.policy
                        .udp_ports
                        .as_ref()
                        .is_some_and(|p| p.is_included(port))
                } else {
                    self.policy.is_udp_forwarded
                };
                if !admitted {
                    return false;
                }
                self.ensure_udp_socket(dst, port);
                true
            }
            IPPROTO_ICMPV6 => to_self,
            _ => false,
        }
    }

    fn ensure_listener(&mut self, addr: Ipv6Addr, port: u16) {
        let handles = self.listeners.entry((addr, port)).or_default();
        if handles
            .iter()
            .any(|h| self.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen)
        {
            return;
        }
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        sock.set_nagle_enabled(false);
        sock.set_timeout(Some(TCP_TIMEOUT));
        sock.listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(addr)),
            port,
        })
        .expect("fresh socket listens");
        handles.push(self.sockets.add(sock));
    }

    fn ensure_udp_socket(&mut self, addr: Ipv6Addr, port: u16) {
        if self.udp_sockets.contains_key(&(addr, port)) {
            return;
        }
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_BUFFER],
            )
        };
        let mut sock = udp::Socket::new(buffer(), buffer());
        sock.bind(IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(addr)),
            port,
        })
        .expect("fresh socket binds");
        let h = self.sockets.add(sock);
        self.udp_sockets.insert((addr, port), h);
    }

    /// Processes injected packets and socket state, queueing transmits and
    /// events.
    pub fn poll(&mut self, now: Instant) {
        if self.is_closed {
            return;
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        let sockets = &mut self.sockets;
        let events = &mut self.events;
        self.listeners.retain(|_, handles| {
            handles.retain(|h| {
                let sock = sockets.get::<tcp::Socket>(*h);
                match sock.state() {
                    tcp::State::Listen | tcp::State::SynReceived => true,
                    tcp::State::Closed => {
                        sockets.remove(*h);
                        false
                    }
                    _ => {
                        if let (Some(local), Some(remote)) =
                            (sock.local_endpoint(), sock.remote_endpoint())
                        {
                            events.push_back(Event::TcpAccepted {
                                handle: *h,
                                local: endpoint_v6(local),
                                remote: endpoint_v6(remote),
                            });
                        } else {
                            sockets.remove(*h);
                        }
                        false
                    }
                }
            });
            !handles.is_empty()
        });

        self.closing.retain(|h| {
            if sockets.get::<tcp::Socket>(*h).state() == tcp::State::Closed {
                sockets.remove(*h);
                false
            } else {
                true
            }
        });

        for (&(addr, port), &h) in &self.udp_sockets {
            let sock = sockets.get_mut::<udp::Socket>(h);
            while let Ok((data, meta)) = sock.recv() {
                let key = (
                    SocketAddrV6::new(addr, port, 0, 0),
                    endpoint_v6(meta.endpoint),
                );
                if self.flows.insert(key, now).is_none() {
                    events.push_back(Event::UdpFlow { key });
                }
                events.push_back(Event::UdpDatagram {
                    key,
                    data: data.to_vec(),
                });
            }
        }

        let idle = self.policy.udp_idle_timeout;
        self.flows.retain(|&key, last| {
            let keep = now - *last < idle;
            if !keep {
                events.push_back(Event::UdpFlowExpired { key });
            }
            keep
        });
    }

    /// The next IPv6 packet the stack wants sent to a peer.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.device.tx.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// How long until [`poll`](Self::poll) has timer work to do, if ever.
    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        self.iface.poll_delay(now, &self.sockets)
    }

    /// An accepted TCP socket.
    ///
    /// # Panics
    ///
    /// Panics if `handle` is not a TCP socket of this stack.
    pub fn tcp_socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    /// Closes an accepted TCP socket gracefully and frees it once closed.
    pub fn release_tcp(&mut self, handle: SocketHandle) {
        if self.is_closed {
            return;
        }
        self.sockets.get_mut::<tcp::Socket>(handle).close();
        self.closing.push(handle);
    }

    /// Queues one datagram back to the client on a flow. Like any UDP send
    /// it may be dropped silently if the socket's buffer is full.
    ///
    /// # Errors
    ///
    /// Fails if the flow's local socket is gone or the client is
    /// unaddressable.
    pub fn send_udp(
        &mut self,
        key: &FlowKey,
        data: &[u8],
        now: Instant,
    ) -> Result<(), UdpSendError> {
        let (local, remote) = *key;
        let Some(&handle) = self.udp_sockets.get(&(*local.ip(), local.port())) else {
            return Err(UdpSendError::Closed);
        };
        let meta = udp::UdpMetadata {
            endpoint: IpEndpoint::from(SocketAddr::V6(remote)),
            local_address: Some(IpAddress::Ipv6(*local.ip())),
            meta: phy::PacketMeta::default(),
        };
        match self
            .sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(data, meta)
        {
            Ok(()) | Err(udp::SendError::BufferFull) => {}
            Err(udp::SendError::Unaddressable) => return Err(UdpSendError::Unaddressable),
        }
        if let Some(last) = self.flows.get_mut(key) {
            *last = now;
        }
        Ok(())
    }

    /// Forgets a flow, so the client's next datagram starts a new one.
    pub fn close_flow(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// Aborts every TCP connection and forgets every flow. The stack admits
    /// nothing afterwards.
    pub fn close(&mut self) {
        self.is_closed = true;
        for (_, sock) in self.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(sock) = sock {
                sock.abort();
            }
        }
        self.flows.clear();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
        UdpRepr,
    };

    use super::*;

    pub(crate) const SELF: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1);
    pub(crate) const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 2);

    pub(crate) fn policy(tcp_ports: Ports, udp_ports: Option<Ports>) -> Policy {
        Policy {
            self_addr: SELF,
            tcp_ports,
            udp_ports,
            is_tcp_forwarded: false,
            is_udp_forwarded: false,
            udp_idle_timeout: Duration::from_secs(60),
        }
    }

    fn ipv6(next_header: IpProtocol, payload_len: usize) -> (Vec<u8>, Ipv6Repr) {
        let ip = Ipv6Repr {
            src_addr: CLIENT,
            dst_addr: SELF,
            next_header,
            payload_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + payload_len];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf));
        (buf, ip)
    }

    pub(crate) fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = UdpRepr { src_port, dst_port };
        let (mut buf, ip) = ipv6(IpProtocol::Udp, udp.header_len() + payload.len());
        let mut pkt = Ipv6Packet::new_unchecked(&mut buf);
        udp.emit(
            &mut UdpPacket::new_unchecked(pkt.payload_mut()),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    pub(crate) fn syn(src_port: u16, dst_port: u16) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1220),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let (mut buf, ip) = ipv6(IpProtocol::Tcp, tcp.buffer_len());
        let mut pkt = Ipv6Packet::new_unchecked(&mut buf);
        tcp.emit(
            &mut TcpPacket::new_unchecked(pkt.payload_mut()),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    #[test]
    fn sans_io_udp_flow_round_trips_and_expires() {
        let start = Instant::from_secs(0);
        let mut ns = Netstack::new(policy(Ports::All, Some(Ports::All)), 1, start);
        assert!(ns.inject(udp(5000, 7777, b"ping")));
        ns.poll(start);
        let key = (
            SocketAddrV6::new(SELF, 7777, 0, 0),
            SocketAddrV6::new(CLIENT, 5000, 0, 0),
        );
        assert!(matches!(ns.poll_event(), Some(Event::UdpFlow { key: k }) if k == key));
        assert!(
            matches!(ns.poll_event(), Some(Event::UdpDatagram { key: k, data }) if k == key && data == b"ping")
        );

        ns.send_udp(&key, b"pong", start).unwrap();
        ns.poll(start);
        let pkt = ns.poll_transmit().unwrap();
        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.dst_addr(), CLIENT);
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (7777, 5000));
        assert_eq!(udp.payload(), b"pong");

        ns.poll(start + Duration::from_secs(61));
        assert!(matches!(ns.poll_event(), Some(Event::UdpFlowExpired { key: k }) if k == key));
    }

    #[test]
    fn tcp_outside_policy_is_not_admitted() {
        let start = Instant::from_secs(0);
        let mut ns = Netstack::new(policy(Ports::list([80]), None), 1, start);
        assert!(!ns.inject(syn(40000, 81)));
        assert!(!ns.inject(udp(5000, 53, b"nope")));
        assert!(ns.inject(syn(40001, 80)));
        ns.poll(start);
        let pkt = ns.poll_transmit().unwrap();
        let tcp = TcpPacket::new_checked(Ipv6Packet::new_checked(&pkt).unwrap().payload())
            .unwrap()
            .syn();
        assert!(tcp);
    }

    #[test]
    fn nat64_unmaps() {
        let mapped: Ipv6Addr = "64:ff9b::c000:201".parse().unwrap();
        assert_eq!(unmap_nat64(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(unmap_nat64(SELF), IpAddr::V6(SELF));
    }
}
