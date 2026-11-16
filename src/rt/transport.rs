use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::vec;
use std::vec::Vec;

use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::derp::{DerpClient, Options};
use super::netstack::Netstack;
use super::wireguard::BoringTun;
use crate::derp::Packet;
use crate::derpmap::DerpRegion;
use crate::key::{NodePrivate, NodePublic, PresharedKey};
use crate::transport::{self, PeerStatus, TICK, Transmit};

pub(crate) struct Config {
    pub key: NodePrivate,
    pub preshared_key: Option<PresharedKey>,
    pub region: DerpRegion,
    /// `None` admits every client.
    pub allowed_clients: Option<BTreeSet<NodePublic>>,
    pub derp: Options,
}

/// Sends go through plain non-blocking sockets rather than tokio's, so they
/// work from under the state lock and from the first tick, before the
/// reactor has observed the sockets as writable.
struct Io {
    udp4: Option<std::net::UdpSocket>,
    udp6: Option<std::net::UdpSocket>,
    derp: DerpClient,
}

impl Io {
    fn send_udp(&self, addr: SocketAddr, pkt: &[u8]) -> bool {
        let sock = match addr {
            SocketAddr::V4(_) => &self.udp4,
            SocketAddr::V6(_) => &self.udp6,
        };
        sock.as_ref().is_some_and(|s| s.send_to(pkt, addr).is_ok())
    }

    fn send(&self, transmit: &Transmit) {
        match transmit {
            Transmit::Udp {
                dst,
                data,
                fallback,
            } => {
                if !self.send_udp(*dst, data)
                    && let Some(key) = fallback
                {
                    self.derp.send(key, data);
                }
            }
            Transmit::Derp { dst, data } => {
                self.derp.send(dst, data);
            }
        }
    }

    fn port(sock: Option<&std::net::UdpSocket>) -> Option<u16> {
        sock.and_then(|s| s.local_addr().ok()).map(|a| a.port())
    }
}

struct State {
    core: transport::Transport<BoringTun, OsRng>,
    io: Io,
}

impl State {
    /// Sends what the core queued and returns the packets for the stack.
    fn flush(&mut self) -> Vec<Vec<u8>> {
        while let Some(t) = self.core.poll_transmit() {
            self.io.send(&t);
        }
        let mut received = Vec::new();
        while let Some(pkt) = self.core.poll_received() {
            received.push(pkt);
        }
        received
    }
}

/// The addresses of this host's interfaces, with the port of the socket
/// for each family. Loopback is advertised only when nothing else is,
/// matching what magicsock does.
fn local_endpoints(port4: Option<u16>, port6: Option<u16>) -> Vec<SocketAddr> {
    use nix::net::if_::InterfaceFlags;
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut regular = Vec::new();
    let mut loopback = Vec::new();
    for ifa in addrs {
        if !ifa.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        let Some(sa) = ifa.address else {
            continue;
        };
        let (ip, port) = if let Some(v4) = sa.as_sockaddr_in() {
            (IpAddr::V4(v4.ip()), port4)
        } else if let Some(v6) = sa.as_sockaddr_in6() {
            (IpAddr::V6(v6.ip()), port6)
        } else {
            continue;
        };
        let Some(port) = port else {
            continue;
        };
        let usable = match ip {
            IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_unicast_link_local() && !v6.is_unspecified(),
        };
        if !usable {
            continue;
        }
        let ep = SocketAddr::new(ip, port);
        if ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK) || ip.is_loopback() {
            loopback.push(ep);
        } else {
            regular.push(ep);
        }
    }
    if regular.is_empty() {
        loopback
    } else {
        regular
    }
}

/// Binds a UDP socket for receiving through tokio and a clone of it for
/// sending directly. A family that cannot be bound is simply not used.
fn bind_udp(addr: &str) -> std::io::Result<(Option<UdpSocket>, Option<std::net::UdpSocket>)> {
    let Ok(sock) = std::net::UdpSocket::bind(addr) else {
        return Ok((None, None));
    };
    sock.set_nonblocking(true)?;
    let sender = sock.try_clone()?;
    Ok((Some(UdpSocket::from_std(sock)?), Some(sender)))
}

/// The running transport. Dropping it stops every task.
pub(crate) struct Transport {
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

struct Handler {
    state: Arc<Mutex<State>>,
    netstack: Arc<Netstack>,
}

impl Handler {
    fn new(state: &Arc<Mutex<State>>, netstack: &Arc<Netstack>) -> Self {
        Handler {
            state: state.clone(),
            netstack: netstack.clone(),
        }
    }

    fn run(&self, f: impl FnOnce(&mut transport::Transport<BoringTun, OsRng>)) {
        let received = {
            let mut st = self.state.lock().unwrap();
            f(&mut st.core);
            st.flush()
        };
        for pkt in received {
            self.netstack.inject(pkt);
        }
    }
}

impl Transport {
    pub(crate) fn start(
        cfg: Config,
        netstack: &Arc<Netstack>,
        mut egress: mpsc::Receiver<Vec<u8>>,
    ) -> std::io::Result<Transport> {
        let (udp4, send4) = bind_udp("0.0.0.0:0")?;
        let (udp6, send6) = bind_udp("[::]:0")?;
        if udp4.is_none() && udp6.is_none() {
            return Err(std::io::Error::other("could not bind a UDP socket"));
        }
        let (derp, mut packets) =
            DerpClient::connect(cfg.region.clone(), cfg.key.clone(), cfg.derp);
        let state = Arc::new(Mutex::new(State {
            core: transport::Transport::new(transport::Config {
                wireguard: BoringTun::new(&cfg.key, cfg.preshared_key),
                key: cfg.key,
                region: cfg.region,
                allowed_clients: cfg.allowed_clients,
                rng: OsRng,
            }),
            io: Io {
                udp4: send4,
                udp6: send6,
                derp,
            },
        }));

        let mut tasks = Vec::new();
        {
            let handler = Handler::new(&state, netstack);
            tasks.push(tokio::spawn(async move {
                while let Some(Packet { src, data }) = packets.recv().await {
                    handler.run(|core| core.handle_derp(src, &data, super::now()));
                }
            }));
        }
        for sock in [udp4, udp6].into_iter().flatten() {
            let handler = Handler::new(&state, netstack);
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                        continue;
                    };
                    handler.run(|core| core.handle_udp(from, &buf[..n], super::now()));
                }
            }));
        }
        {
            let handler = Handler::new(&state, netstack);
            tasks.push(tokio::spawn(async move {
                while let Some(pkt) = egress.recv().await {
                    handler.run(|core| core.send_ip(&pkt, super::now()));
                }
            }));
        }
        {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(TICK.into());
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let mut st = state.lock().unwrap();
                    if st.core.wants_local_endpoints() {
                        let eps = local_endpoints(
                            Io::port(st.io.udp4.as_ref()),
                            Io::port(st.io.udp6.as_ref()),
                        );
                        st.core.set_local_endpoints(eps);
                    }
                    st.core.tick(super::now());
                    st.flush();
                }
            }));
        }
        Ok(Transport { state, tasks })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub(crate) fn peer_for_addr(&self, addr: Ipv6Addr) -> Option<NodePublic> {
        self.lock().core.peer_for_addr(addr)
    }

    pub(crate) fn add_allowed_client(&self, key: NodePublic) {
        self.lock().core.add_allowed_client(key);
    }

    pub(crate) fn peers(&self) -> Vec<PeerStatus> {
        self.lock().core.peers(super::now())
    }

    pub(crate) fn close(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.close();
    }
}
