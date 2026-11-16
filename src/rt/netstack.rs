use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;
use std::vec::Vec;

use smoltcp::iface::SocketHandle;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use super::Peer;
use crate::error::UdpSendError;
use crate::key::NodePublic;
use crate::netstack::{self, Event, FlowKey, Policy, unmap_nat64};

const FLOW_QUEUE: usize = 64;
const ACCEPT_QUEUE: usize = 256;
const EGRESS_QUEUE: usize = 512;

struct FlowTx {
    tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

struct Shared {
    stack: netstack::Netstack,
    flows: HashMap<FlowKey, FlowTx>,
}

/// The stack and the task that drives it.
pub(crate) struct Netstack {
    shared: Arc<Mutex<Shared>>,
    wake: Arc<Notify>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// The receiving ends a [`Netstack`] delivers into.
pub(crate) struct Outputs {
    /// IPv6 packets the stack wants sent to peers.
    pub egress: mpsc::Receiver<Vec<u8>>,
    pub tcp: mpsc::Receiver<TcpConn>,
    pub udp: mpsc::Receiver<UdpFlow>,
}

impl Netstack {
    pub(crate) fn start(policy: Policy) -> (Arc<Netstack>, Outputs) {
        let shared = Arc::new(Mutex::new(Shared {
            stack: netstack::Netstack::new(policy, rand::random(), super::now()),
            flows: HashMap::new(),
        }));
        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_QUEUE);
        let (tcp_tx, tcp_rx) = mpsc::channel(ACCEPT_QUEUE);
        let (udp_tx, udp_rx) = mpsc::channel(ACCEPT_QUEUE);
        let ns = Arc::new(Netstack {
            shared,
            wake: Arc::new(Notify::new()),
            task: Mutex::new(None),
        });
        let task = tokio::spawn(ns.clone().run(egress_tx, tcp_tx, udp_tx));
        *ns.task.lock().unwrap() = Some(task);
        (
            ns,
            Outputs {
                egress: egress_rx,
                tcp: tcp_rx,
                udp: udp_rx,
            },
        )
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap()
    }

    /// Feeds one decrypted IPv6 packet from a peer into the stack.
    pub(crate) fn inject(&self, pkt: Vec<u8>) {
        if self.lock().stack.inject(pkt) {
            self.wake.notify_one();
        }
    }

    pub(crate) fn close(&self) {
        let mut sh = self.lock();
        sh.stack.close();
        for flow in sh.flows.values() {
            flow.closed.store(true, Ordering::Relaxed);
        }
        sh.flows.clear();
        drop(sh);
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }

    async fn run(
        self: Arc<Self>,
        egress: mpsc::Sender<Vec<u8>>,
        tcp_tx: mpsc::Sender<TcpConn>,
        udp_tx: mpsc::Sender<UdpFlow>,
    ) {
        loop {
            let mut out = Vec::new();
            let mut accepted = Vec::new();
            let mut new_flows = Vec::new();
            let delay = {
                let mut guard = self.lock();
                let sh = &mut *guard;
                if sh.stack.is_closed() {
                    return;
                }
                let now = super::now();
                sh.stack.poll(now);
                while let Some(pkt) = sh.stack.poll_transmit() {
                    out.push(pkt);
                }
                while let Some(event) = sh.stack.poll_event() {
                    match event {
                        Event::TcpAccepted {
                            handle,
                            local,
                            remote,
                        } => accepted.push(TcpConn {
                            shared: self.shared.clone(),
                            wake: self.wake.clone(),
                            handle,
                            local,
                            remote,
                            peer_key: None,
                        }),
                        Event::UdpFlow { key } => {
                            let (tx, rx) = mpsc::channel(FLOW_QUEUE);
                            let closed = Arc::new(AtomicBool::new(false));
                            sh.flows.insert(
                                key,
                                FlowTx {
                                    tx,
                                    closed: closed.clone(),
                                },
                            );
                            new_flows.push(UdpFlow {
                                inner: Arc::new(FlowSender {
                                    shared: self.shared.clone(),
                                    wake: self.wake.clone(),
                                    key,
                                    closed,
                                }),
                                rx,
                                peer_key: None,
                            });
                        }
                        Event::UdpDatagram { key, data } => {
                            if let Some(flow) = sh.flows.get(&key) {
                                let _ = flow.tx.try_send(data);
                            }
                        }
                        Event::UdpFlowExpired { key } => {
                            if let Some(flow) = sh.flows.remove(&key) {
                                flow.closed.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
                sh.stack.poll_delay(now)
            };
            for pkt in out {
                if egress.send(pkt).await.is_err() {
                    return;
                }
            }
            for conn in accepted {
                if let Err(mpsc::error::SendError(conn)) = tcp_tx.send(conn).await {
                    conn.lock().stack.tcp_socket(conn.handle).abort();
                }
            }
            for flow in new_flows {
                let _ = udp_tx.send(flow).await;
            }
            let delay = delay.map_or(Duration::from_secs(1), Duration::from);
            tokio::select! {
                () = self.wake.notified() => {}
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
}

impl Drop for Netstack {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

/// A TCP connection a client opened through the tunnel.
///
/// Dropping it closes the connection gracefully; use
/// [`AsyncWriteExt::shutdown`](tokio::io::AsyncWriteExt::shutdown) for a
/// half-close that still reads.
pub struct TcpConn {
    shared: Arc<Mutex<Shared>>,
    wake: Arc<Notify>,
    handle: SocketHandle,
    local: SocketAddrV6,
    remote: SocketAddrV6,
    pub(crate) peer_key: Option<NodePublic>,
}

impl TcpConn {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap()
    }

    /// The address the client dialed. An IPv4 destination that arrived
    /// through NAT64 is reported as IPv4.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(unmap_nat64(*self.local.ip()), self.local.port())
    }

    /// The client's tunnel address and source port.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddrV6 {
        self.remote
    }

    /// The node key of the client, which is what its tunnel address was
    /// derived from.
    #[must_use]
    pub fn peer_key(&self) -> Option<NodePublic> {
        self.peer_key
    }

    /// Who opened this connection, for handlers and served processes.
    #[must_use]
    pub fn peer(&self) -> Peer {
        Peer {
            local: self.local_addr(),
            remote: self.remote.into(),
            key: self.peer_key,
        }
    }

    /// Whether the client dialed somewhere other than the server itself.
    ///
    /// # Panics
    ///
    /// Panics if the stack's lock is poisoned.
    #[must_use]
    pub fn is_forward(&self) -> bool {
        *self.local.ip() != self.lock().stack.policy().self_addr
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut sh = self.lock();
        let sock = sh.stack.tcp_socket(self.handle);
        if sock.can_recv() {
            let n = sock
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(e.to_string()))?;
            buf.advance(n);
            drop(sh);
            self.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !sock.may_recv() {
            return Poll::Ready(Ok(()));
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut sh = self.lock();
        let sock = sh.stack.tcp_socket(self.handle);
        if !sock.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if sock.can_send() {
            let n = sock
                .send_slice(data)
                .map_err(|e| io::Error::other(e.to_string()))?;
            drop(sh);
            self.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        sock.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.lock().stack.tcp_socket(self.handle).close();
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        self.lock().stack.release_tcp(self.handle);
        self.wake.notify_one();
    }
}

/// One client's UDP flow to one destination: every datagram from a given
/// source address and port to a given local address and port.
///
/// Datagram boundaries are preserved. A flow ends when it has been idle
/// for the configured timeout, after which [`recv`](Self::recv) returns
/// `None` and sends fail.
pub struct UdpFlow {
    inner: Arc<FlowSender>,
    rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) peer_key: Option<NodePublic>,
}

/// The sending side of a [`UdpFlow`], which closes the flow once dropped.
pub(crate) struct FlowSender {
    shared: Arc<Mutex<Shared>>,
    wake: Arc<Notify>,
    key: FlowKey,
    closed: Arc<AtomicBool>,
}

impl FlowSender {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap()
    }

    pub(crate) fn send(&self, data: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.lock()
            .stack
            .send_udp(&self.key, data, super::now())
            .map_err(|err| match err {
                UdpSendError::Closed => io::ErrorKind::NotConnected,
                UdpSendError::Unaddressable => io::ErrorKind::AddrNotAvailable,
            })?;
        self.wake.notify_one();
        Ok(())
    }
}

impl Drop for FlowSender {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        let mut sh = self.lock();
        sh.flows.remove(&self.key);
        sh.stack.close_flow(&self.key);
    }
}

impl UdpFlow {
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(unmap_nat64(*self.inner.key.0.ip()), self.inner.key.0.port())
    }

    #[must_use]
    pub fn remote_addr(&self) -> SocketAddrV6 {
        self.inner.key.1
    }

    #[must_use]
    pub fn peer_key(&self) -> Option<NodePublic> {
        self.peer_key
    }

    /// Who sent this flow, for handlers and served processes.
    #[must_use]
    pub fn peer(&self) -> Peer {
        Peer {
            local: self.local_addr(),
            remote: self.remote_addr().into(),
            key: self.peer_key,
        }
    }

    /// Whether the client sent somewhere other than the server itself.
    ///
    /// # Panics
    ///
    /// Panics if the stack's lock is poisoned.
    #[must_use]
    pub fn is_forward(&self) -> bool {
        *self.inner.key.0.ip() != self.inner.lock().stack.policy().self_addr
    }

    /// The next datagram, or `None` once the flow has ended.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Sends one datagram back to the client. Like any UDP send it may be
    /// dropped silently if the stack's buffer is full.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::NotConnected`] once the flow has ended.
    ///
    /// # Panics
    ///
    /// Panics if the stack's lock is poisoned.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.inner.send(data)
    }

    #[cfg(feature = "perf")]
    pub(crate) fn into_parts(self) -> (mpsc::Receiver<Vec<u8>>, Arc<FlowSender>) {
        (self.rx, self.inner)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};

    use smoltcp::wire::{IpProtocol, Ipv6Packet, TcpPacket, UdpPacket};
    use tokio::time::timeout;

    use super::*;
    use crate::netstack::Ports;
    use crate::netstack::tests::{CLIENT, SELF, policy, syn, udp};

    const WAIT: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn udp_flow_round_trips() {
        let (ns, mut out) = Netstack::start(policy(Ports::All, Some(Ports::All)));
        ns.inject(udp(5000, 7777, b"ping"));
        let mut flow = timeout(WAIT, out.udp.recv()).await.unwrap().unwrap();
        assert_eq!(flow.local_addr(), SocketAddr::new(IpAddr::V6(SELF), 7777));
        assert_eq!(flow.remote_addr(), SocketAddrV6::new(CLIENT, 5000, 0, 0));
        assert!(!flow.is_forward());
        assert_eq!(flow.recv().await.unwrap(), b"ping");

        flow.send(b"pong").unwrap();
        let pkt = timeout(WAIT, out.egress.recv()).await.unwrap().unwrap();
        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.dst_addr(), CLIENT);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (7777, 5000));
        assert_eq!(udp.payload(), b"pong");
        ns.close();
    }

    #[tokio::test]
    async fn udp_outside_policy_is_dropped() {
        let (ns, mut out) = Netstack::start(policy(Ports::All, Some(Ports::list([53]))));
        ns.inject(udp(5000, 54, b"nope"));
        assert!(
            timeout(Duration::from_millis(300), out.udp.recv())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(300), out.egress.recv())
                .await
                .is_err()
        );
        ns.close();
    }

    #[tokio::test]
    async fn tcp_policy_gates_syns() {
        let (ns, mut out) = Netstack::start(policy(Ports::list([80]), None));
        ns.inject(syn(40000, 81));
        assert!(
            timeout(Duration::from_millis(300), out.egress.recv())
                .await
                .is_err()
        );

        ns.inject(syn(40001, 80));
        let pkt = timeout(WAIT, out.egress.recv()).await.unwrap().unwrap();
        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.dst_addr(), CLIENT);
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        assert_eq!((tcp.src_port(), tcp.dst_port()), (80, 40001));
        ns.close();
    }
}
