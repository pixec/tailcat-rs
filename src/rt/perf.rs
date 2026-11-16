//! The server side of `tailcat perf`, an iperf-style throughput and latency
//! test over TCP and UDP on [`PORT`].

use std::boxed::Box;
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::netstack::FlowSender;
use super::{Peer, UdpFlow};

/// The TCP and UDP port the perf service listens on.
pub const PORT: u16 = 5201;
/// The size of the header at the start of each UDP test datagram, and so
/// the smallest UDP length.
pub const UDP_HEADER_LEN: usize = 32;
pub const DEFAULT_MAX_STREAMS: usize = 128;
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_mins(10);

const MAX_LENGTH: usize = 1 << 20;
const MAX_UDP_SIZE: usize = 65507;
const MIN_INTERVAL: Duration = Duration::from_millis(100);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_GRACE: Duration = Duration::from_secs(5);
const UDP_GRACE: Duration = Duration::from_secs(2);
const CTRL_BUF_SIZE: usize = 64 << 10;
const FIN_REPEAT: usize = 3;
const FLAG_OPEN: u8 = 1;
const FLAG_FIN: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// Which way test data flows, relative to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[serde(rename = "up")]
    Upload,
    #[serde(rename = "down")]
    Download,
    #[serde(rename = "both")]
    Bidirectional,
}

/// A test's parameters, chosen by the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub proto: Proto,
    #[serde(rename = "dir")]
    pub direction: Direction,
    /// How long each sender sends, unless `bytes` is set.
    #[serde(default, skip_serializing_if = "Duration::is_zero", with = "nanos")]
    pub duration: Duration,
    /// If non-zero, how many bytes each stream sends.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes: u64,
    #[serde(default)]
    pub streams: usize,
    /// The size of each TCP write or UDP datagram, header included.
    #[serde(default)]
    pub length: usize,
    /// If non-zero, each stream's target bits per second.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bitrate: u64,
    /// How often interval statistics are recorded, or zero for never.
    #[serde(default, skip_serializing_if = "Duration::is_zero", with = "nanos")]
    pub interval: Duration,
}

/// What one side sent or received.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Stats {
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: u64,
    /// From the first to the last byte, as this side saw it.
    #[serde(default, with = "nanos")]
    pub duration: Duration,
    /// Per-interval counts, kept by the side that recorded them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intervals: Vec<Interval>,
    /// UDP datagrams that arrived after a later one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reordered: u64,
    /// RFC 3550 smoothed inter-arrival jitter of UDP datagrams, averaged
    /// across streams.
    #[serde(default, skip_serializing_if = "Duration::is_zero", with = "nanos")]
    pub jitter: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: u64,
}

/// The outcome of a test. Directions the test did not exercise are `None`.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub params: Params,
    pub client_sent: Option<Stats>,
    pub server_received: Option<Stats>,
    pub server_sent: Option<Stats>,
    pub client_received: Option<Stats>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

mod nanos {
    use core::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let n = i64::deserialize(d)?;
        Ok(Duration::from_nanos(u64::try_from(n).unwrap_or(0)))
    }
}

fn go_duration(d: Duration) -> String {
    fn frac(v: u128, unit: u128, digits: usize, suffix: &str) -> String {
        let (int, rem) = (v / unit, v % unit);
        if rem == 0 {
            return std::format!("{int}{suffix}");
        }
        let rem = std::format!("{rem:0digits$}");
        std::format!("{int}.{}{suffix}", rem.trim_end_matches('0'))
    }
    let ns = d.as_nanos();
    match ns {
        0 => "0s".into(),
        1..1_000 => std::format!("{ns}ns"),
        1_000..1_000_000 => frac(ns, 1_000, 3, "\u{b5}s"),
        1_000_000..1_000_000_000 => frac(ns, 1_000_000, 6, "ms"),
        _ => {
            let (h, m) = (ns / 3_600_000_000_000, ns / 60_000_000_000 % 60);
            let hours = if h > 0 {
                std::format!("{h}h")
            } else {
                String::new()
            };
            let minutes = if h > 0 || m > 0 {
                std::format!("{m}m")
            } else {
                String::new()
            };
            hours + &minutes + &frac(ns % 60_000_000_000, 1_000_000_000, 9, "s")
        }
    }
}

impl Params {
    fn validate(&self, max_streams: usize, max_duration: Duration) -> Result<(), String> {
        if self.bytes == 0 && self.duration.is_zero() {
            return Err("a duration or byte count is required".into());
        }
        if self.bytes == 0 && self.duration > max_duration {
            return Err(std::format!(
                "duration {} exceeds the server's limit of {}",
                go_duration(self.duration),
                go_duration(max_duration)
            ));
        }
        if self.streams < 1 {
            return Err("at least one stream is required".into());
        }
        if self.streams > max_streams {
            return Err(std::format!(
                "{} streams exceeds the server's limit of {max_streams}",
                self.streams
            ));
        }
        if self.length < 1 {
            return Err("a positive length is required".into());
        }
        match self.proto {
            Proto::Tcp if self.length > MAX_LENGTH => {
                return Err(std::format!(
                    "TCP length {} exceeds {MAX_LENGTH}",
                    self.length
                ));
            }
            Proto::Udp if self.length < UDP_HEADER_LEN => {
                return Err(std::format!(
                    "UDP length {} is smaller than the {UDP_HEADER_LEN}-byte header",
                    self.length
                ));
            }
            Proto::Udp if self.length > MAX_UDP_SIZE => {
                return Err(std::format!(
                    "UDP length {} exceeds {MAX_UDP_SIZE}",
                    self.length
                ));
            }
            _ => {}
        }
        if !self.interval.is_zero() && self.interval < MIN_INTERVAL {
            return Err(std::format!(
                "interval {} is shorter than {}",
                go_duration(self.interval),
                go_duration(MIN_INTERVAL)
            ));
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Message {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    stream: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    t: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl Message {
    fn new(kind: &str) -> Message {
        Message {
            kind: kind.into(),
            ..Message::default()
        }
    }

    fn error(error: String) -> Message {
        Message {
            error,
            ..Message::new("error")
        }
    }

    fn stats(kind: &str, stats: &Stats) -> Message {
        Message {
            stats: Some(Stats {
                intervals: Vec::new(),
                ..stats.clone()
            }),
            ..Message::new(kind)
        }
    }
}

#[derive(Clone, Copy, Default)]
struct UdpHeader {
    id: [u8; 8],
    stream: u16,
    flags: u8,
    seq: u64,
    send_time: i64,
}

impl UdpHeader {
    fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.id);
        b[8..10].copy_from_slice(&self.stream.to_be_bytes());
        b[10] = self.flags;
        b[11..16].fill(0);
        b[16..24].copy_from_slice(&self.seq.to_be_bytes());
        b[24..32].copy_from_slice(&self.send_time.to_be_bytes());
    }

    fn parse(b: &[u8]) -> Option<UdpHeader> {
        let b = b.get(..UDP_HEADER_LEN)?;
        Some(UdpHeader {
            id: b[0..8].try_into().ok()?,
            stream: u16::from_be_bytes(b[8..10].try_into().ok()?),
            flags: b[10],
            seq: u64::from_be_bytes(b[16..24].try_into().ok()?),
            send_time: i64::from_be_bytes(b[24..32].try_into().ok()?),
        })
    }
}

fn unix_nanos() -> i64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
}

trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

trait DatagramSink: Send + Sync {
    fn send(&self, data: &[u8]) -> io::Result<()>;
}

impl DatagramSink for FlowSender {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        FlowSender::send(self, data)
    }
}

enum DataStream {
    Tcp(Box<dyn Stream>),
    Udp {
        rx: mpsc::Receiver<Vec<u8>>,
        tx: Arc<dyn DatagramSink>,
        first: Vec<u8>,
    },
}

struct Running {
    id: [u8; 8],
    streams: usize,
    attach: mpsc::UnboundedSender<(usize, DataStream)>,
}

type OnResult = dyn Fn(SocketAddr, &Report) + Send + Sync;

struct Inner {
    max_streams: usize,
    max_duration: Duration,
    on_result: Option<Box<OnResult>>,
    running: Mutex<Option<Running>>,
}

/// Accepts `tailcat perf` tests, one at a time.
///
/// Hand it the TCP connections and UDP flows a client opens to [`PORT`]
/// with [`serve_tcp`](Self::serve_tcp) and [`serve_udp`](Self::serve_udp).
#[derive(Clone)]
pub struct PerfHandler {
    inner: Arc<Inner>,
}

impl Default for PerfHandler {
    fn default() -> Self {
        PerfHandler {
            inner: Arc::new(Inner {
                max_streams: DEFAULT_MAX_STREAMS,
                max_duration: DEFAULT_MAX_DURATION,
                on_result: None,
                running: Mutex::new(None),
            }),
        }
    }
}

fn inner_mut(handler: &mut PerfHandler) -> &mut Inner {
    Arc::get_mut(&mut handler.inner).expect("PerfHandler configured after cloning")
}

struct Unregister<'a>(&'a Inner, [u8; 8]);

impl Drop for Unregister<'_> {
    fn drop(&mut self) {
        let mut running = self.0.running.lock().unwrap();
        if running.as_ref().is_some_and(|r| r.id == self.1) {
            *running = None;
        }
    }
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..=i]);
            r.consume(i + 1);
            return Ok(line);
        }
        let n = buf.len();
        line.extend_from_slice(buf);
        r.consume(n);
        if line.len() >= CTRL_BUF_SIZE {
            return Err(io::Error::other("control line too long"));
        }
    }
}

async fn read_message<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Message> {
    let line = read_line(r).await?;
    serde_json::from_slice(&line)
        .map_err(|e| io::Error::other(std::format!("bad control message: {e}")))
}

async fn send_message<W: AsyncWrite + Unpin>(w: &mut W, m: &Message) -> io::Result<()> {
    let mut b = serde_json::to_vec(m).map_err(io::Error::other)?;
    b.push(b'\n');
    w.write_all(&b).await?;
    w.flush().await
}

type CtrlWriter = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

async fn send_ctrl(w: &CtrlWriter, m: &Message) -> io::Result<()> {
    send_message(&mut *w.lock().await, m).await
}

impl PerfHandler {
    #[must_use]
    pub fn new() -> PerfHandler {
        PerfHandler::default()
    }

    /// Caps the parallel streams a client may ask for. Zero restores
    /// [`DEFAULT_MAX_STREAMS`].
    ///
    /// # Panics
    ///
    /// Panics if the handler has been cloned.
    #[must_use]
    pub fn max_streams(mut self, n: usize) -> PerfHandler {
        inner_mut(&mut self).max_streams = if n == 0 { DEFAULT_MAX_STREAMS } else { n };
        self
    }

    /// Caps a test's duration. A test that sends a byte count instead is
    /// cut off at this regardless. Zero restores [`DEFAULT_MAX_DURATION`].
    ///
    /// # Panics
    ///
    /// Panics if the handler has been cloned.
    #[must_use]
    pub fn max_duration(mut self, d: Duration) -> PerfHandler {
        inner_mut(&mut self).max_duration = if d.is_zero() { DEFAULT_MAX_DURATION } else { d };
        self
    }

    /// Calls `f` with the client's control address and the report of each
    /// completed test.
    ///
    /// # Panics
    ///
    /// Panics if the handler has been cloned.
    #[must_use]
    pub fn on_result(
        mut self,
        f: impl Fn(SocketAddr, &Report) + Send + Sync + 'static,
    ) -> PerfHandler {
        inner_mut(&mut self).on_result = Some(Box::new(f));
        self
    }

    /// Serves one TCP connection to [`PORT`]: either a control connection,
    /// in which case this returns when its test ends, or a data stream of the
    /// running test, which this hands over to it.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub async fn serve_tcp<S>(&self, stream: S, peer: Peer)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut br = BufReader::with_capacity(CTRL_BUF_SIZE, stream);
        let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut br)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                return tracing::debug!(remote = %peer.remote, "perf: reading first message: {e}");
            }
            Err(_) => {
                return tracing::debug!(remote = %peer.remote, "perf: reading first message: timed out");
            }
        };
        match first.kind.as_str() {
            "hello" => self.run_test(br, first, peer).await,
            "stream" => {
                let Some(id) = hex::decode(&first.id)
                    .ok()
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                else {
                    return;
                };
                if let Err(e) = self.attach(id, first.stream, DataStream::Tcp(Box::new(br))) {
                    tracing::debug!(remote = %peer.remote, "perf: data connection: {e}");
                }
            }
            _ => {}
        }
    }

    /// Serves one UDP flow to [`PORT`], a data stream of the running test.
    pub async fn serve_udp(&self, flow: UdpFlow) {
        let peer = flow.peer();
        let (rx, tx) = flow.into_parts();
        self.serve_datagrams(rx, tx, peer).await;
    }

    async fn serve_datagrams(
        &self,
        mut rx: mpsc::Receiver<Vec<u8>>,
        tx: Arc<dyn DatagramSink>,
        peer: Peer,
    ) {
        let Ok(Some(first)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, rx.recv()).await else {
            return;
        };
        let Some(h) = UdpHeader::parse(&first) else {
            return;
        };
        if let Err(e) = self.attach(h.id, h.stream.into(), DataStream::Udp { rx, tx, first }) {
            tracing::debug!(remote = %peer.remote, "perf: UDP flow: {e}");
        }
    }

    fn attach(&self, id: [u8; 8], index: i64, stream: DataStream) -> Result<(), String> {
        let running = self.inner.running.lock().unwrap();
        let Some(r) = running.as_ref().filter(|r| r.id == id) else {
            return Err("unknown test".into());
        };
        let i = usize::try_from(index)
            .ok()
            .filter(|&i| i < r.streams)
            .ok_or_else(|| std::format!("stream index {index} out of range"))?;
        let _ = r.attach.send((i, stream));
        Ok(())
    }

    async fn run_test<S>(&self, br: BufReader<S>, hello: Message, peer: Peer)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(br);
        let writer: CtrlWriter = Arc::new(tokio::sync::Mutex::new(Box::new(writer)));
        let reject = |e: String| async {
            let _ = send_ctrl(&writer, &Message::error(e)).await;
        };
        let params = match hello.params.map(serde_json::from_value::<Params>) {
            None => return reject("hello without params".into()).await,
            Some(Err(e)) => return reject(e.to_string()).await,
            Some(Ok(p)) => p,
        };
        let inner = &*self.inner;
        if let Err(e) = params.validate(inner.max_streams, inner.max_duration) {
            return reject(e).await;
        }
        let id: [u8; 8] = rand::random();
        let (attach, attached) = mpsc::unbounded_channel();
        let registered = {
            let mut running = inner.running.lock().unwrap();
            let free = running.is_none();
            if free {
                *running = Some(Running {
                    id,
                    streams: params.streams,
                    attach,
                });
            }
            free
        };
        if !registered {
            return reject("the server is busy with another test".into()).await;
        }
        let _unregister = Unregister(inner, id);
        let ok = Message {
            id: hex::encode(id),
            ..Message::new("ok")
        };
        if send_ctrl(&writer, &ok).await.is_err() {
            return;
        }
        let test = Test {
            params: params.clone(),
            id,
            sent: Counters::default(),
            received: Counters::default(),
        };
        let limit = inner.max_duration + HANDSHAKE_TIMEOUT + REPORT_TIMEOUT;
        let outcome =
            tokio::time::timeout(limit, test.run(BufReader::new(reader), writer, attached))
                .await
                .unwrap_or_else(|_| Err("test exceeded the server's time limit".into()));
        match outcome {
            Ok(report) => {
                if let Some(f) = &inner.on_result {
                    f(peer.remote, &report);
                }
            }
            Err(e) => tracing::info!(remote = %peer.remote, "perf: test failed: {e}"),
        }
    }
}

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    datagrams: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> Interval {
        Interval {
            bytes: self.bytes.load(Ordering::Relaxed),
            datagrams: self.datagrams.load(Ordering::Relaxed),
        }
    }
}

struct Test {
    params: Params,
    id: [u8; 8],
    sent: Counters,
    received: Counters,
}

#[derive(Default)]
struct Received {
    first: Option<Instant>,
    last: Option<Instant>,
    expect_seq: u64,
    reordered: u64,
    jitter: f64,
    last_transit: Option<i64>,
}

impl Received {
    fn count(&mut self, n: usize, now: Instant, c: &Counters) {
        self.first.get_or_insert(now);
        self.last = Some(now);
        c.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }

    #[allow(clippy::cast_precision_loss)]
    fn datagram(&mut self, pkt: &[u8], id: [u8; 8], now: Instant, c: &Counters) -> bool {
        let Some(h) = UdpHeader::parse(pkt).filter(|h| h.id == id) else {
            return false;
        };
        if h.flags & FLAG_FIN != 0 {
            return true;
        }
        if h.flags & FLAG_OPEN != 0 {
            return false;
        }
        self.count(pkt.len(), now, c);
        c.datagrams.fetch_add(1, Ordering::Relaxed);
        if h.seq < self.expect_seq {
            self.reordered += 1;
        } else {
            self.expect_seq = h.seq + 1;
        }
        let transit = unix_nanos().saturating_sub(h.send_time);
        if let Some(last) = self.last_transit {
            let d = (transit.saturating_sub(last)).unsigned_abs() as f64;
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.last_transit = Some(transit);
        false
    }
}

enum SendHalf {
    Tcp(tokio::io::WriteHalf<Box<dyn Stream>>),
    Udp(Arc<dyn DatagramSink>, u16),
}

enum RecvHalf {
    Tcp(tokio::io::ReadHalf<Box<dyn Stream>>),
    Udp {
        rx: mpsc::Receiver<Vec<u8>>,
        first: Vec<u8>,
        _flow: Arc<dyn DatagramSink>,
    },
}

struct Pacer {
    next: Option<Instant>,
    step: Duration,
}

impl Pacer {
    #[allow(clippy::cast_precision_loss)]
    fn new(bitrate: u64, length: usize) -> Option<Pacer> {
        (bitrate > 0).then(|| Pacer {
            next: None,
            step: Duration::from_secs_f64(length as f64 * 8.0 / bitrate as f64),
        })
    }

    async fn wait(&mut self) {
        let next = *self.next.get_or_insert_with(Instant::now);
        tokio::time::sleep_until(next).await;
        self.next = Some(next + self.step);
    }
}

struct PeerReports {
    sent: watch::Receiver<Option<Stats>>,
    received: watch::Receiver<Option<Stats>>,
}

async fn collect_streams(
    n: usize,
    attached: &mut mpsc::UnboundedReceiver<(usize, DataStream)>,
) -> Result<(Vec<SendHalf>, Vec<RecvHalf>), String> {
    let mut slots: Vec<Option<DataStream>> = (0..n).map(|_| None).collect();
    let collect = async {
        let mut got = 0;
        while got < n {
            let (i, s) = attached.recv().await?;
            if slots[i].is_none() {
                slots[i] = Some(s);
                got += 1;
            }
        }
        Some(())
    };
    if !matches!(
        tokio::time::timeout(HANDSHAKE_TIMEOUT, collect).await,
        Ok(Some(()))
    ) {
        return Err("timed out waiting for the client's streams to connect".into());
    }
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for (i, slot) in slots.into_iter().flatten().enumerate() {
        match slot {
            DataStream::Tcp(s) => {
                let (r, w) = tokio::io::split(s);
                senders.push(SendHalf::Tcp(w));
                receivers.push(RecvHalf::Tcp(r));
            }
            DataStream::Udp { rx, tx, first } => {
                receivers.push(RecvHalf::Udp {
                    rx,
                    first,
                    _flow: tx.clone(),
                });
                senders.push(SendHalf::Udp(tx, u16::try_from(i).unwrap_or(u16::MAX)));
            }
        }
    }
    Ok((senders, receivers))
}

impl Test {
    fn sends(&self) -> bool {
        self.params.direction != Direction::Upload
    }

    fn receives(&self) -> bool {
        self.params.direction != Direction::Download
    }

    async fn run(
        self,
        reader: impl tokio::io::AsyncBufRead + Send + Unpin + 'static,
        writer: CtrlWriter,
        attached: mpsc::UnboundedReceiver<(usize, DataStream)>,
    ) -> Result<Report, String> {
        let test = Arc::new(self);
        let (fail_tx, mut fail_rx) = mpsc::unbounded_channel::<String>();
        let (sent_tx, sent_rx) = watch::channel(None);
        let (received_tx, received_rx) = watch::channel(None);
        let mut tasks = JoinSet::new();
        {
            let (test, writer, fail_tx) = (test.clone(), writer.clone(), fail_tx.clone());
            tasks.spawn(async move {
                let mut reader = reader;
                loop {
                    let m = match read_message(&mut reader).await {
                        Ok(m) => m,
                        Err(e) => {
                            let reported = (!test.receives() || sent_tx.borrow().is_some())
                                && (!test.sends() || received_tx.borrow().is_some());
                            if !reported {
                                let _ = fail_tx.send(std::format!("control connection: {e}"));
                            }
                            return;
                        }
                    };
                    match m.kind.as_str() {
                        "ping" => {
                            let pong = Message {
                                t: m.t,
                                ..Message::new("pong")
                            };
                            let _ = send_ctrl(&writer, &pong).await;
                        }
                        "done" => {
                            sent_tx.send_replace(Some(m.stats.unwrap_or_default()));
                        }
                        "result" => {
                            received_tx.send_replace(Some(m.stats.unwrap_or_default()));
                        }
                        "error" => {
                            let _ = fail_tx.send(std::format!("peer: {}", m.error));
                            return;
                        }
                        _ => {}
                    }
                }
            });
        }
        let peer = PeerReports {
            sent: sent_rx,
            received: received_rx,
        };
        let body = test.clone().body(writer, attached, peer);
        tokio::select! {
            r = body => r,
            Some(e) = fail_rx.recv() => Err(e),
        }
    }

    async fn body(
        self: Arc<Self>,
        writer: CtrlWriter,
        mut attached: mpsc::UnboundedReceiver<(usize, DataStream)>,
        mut peer: PeerReports,
    ) -> Result<Report, String> {
        let (senders, receivers) = collect_streams(self.params.streams, &mut attached).await?;
        send_ctrl(&writer, &Message::new("ready"))
            .await
            .map_err(|e| e.to_string())?;

        let start = Instant::now();
        let intervals = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        let mut background = JoinSet::new();
        if !self.params.interval.is_zero() {
            background.spawn(self.clone().record_intervals(start, intervals.clone()));
        }
        let send = async {
            if !self.sends() {
                return Ok(None);
            }
            let stats = self.clone().run_senders(senders, start, &intervals).await?;
            send_ctrl(&writer, &Message::stats("done", &stats))
                .await
                .map_err(|e| std::format!("sending done: {e}"))?;
            Ok::<_, String>(Some(stats))
        };
        let recv = async {
            if !self.receives() {
                return Ok(None);
            }
            let stats = self
                .clone()
                .run_receivers(receivers, peer.sent.clone(), &intervals)
                .await?;
            send_ctrl(&writer, &Message::stats("result", &stats))
                .await
                .map_err(|e| std::format!("sending result: {e}"))?;
            Ok::<_, String>(Some(stats))
        };
        let (server_sent, server_received) = tokio::try_join!(send, recv)?;
        background.abort_all();

        let reports = async {
            if self.receives() {
                let _ = peer.sent.wait_for(Option::is_some).await;
            }
            if self.sends() {
                let _ = peer.received.wait_for(Option::is_some).await;
            }
        };
        let _ = tokio::time::timeout(REPORT_TIMEOUT, reports).await;
        if self.receives() && peer.sent.borrow().is_none() {
            return Err("timed out waiting for the peer's sender report".into());
        }
        if self.sends() && peer.received.borrow().is_none() {
            return Err("timed out waiting for the peer's receiver report".into());
        }
        let client_sent = peer.sent.borrow().clone();
        let client_received = peer.received.borrow().clone();
        Ok(Report {
            params: self.params.clone(),
            client_sent,
            server_received,
            server_sent,
            client_received,
        })
    }

    async fn record_intervals(
        self: Arc<Self>,
        start: Instant,
        intervals: Arc<Mutex<(Vec<Interval>, Vec<Interval>)>>,
    ) {
        let every = self.params.interval;
        let mut tick = tokio::time::interval_at(start + every, every);
        let (mut last_sent, mut last_recv) = (Interval::default(), Interval::default());
        let delta = |a: Interval, b: Interval| Interval {
            bytes: a.bytes - b.bytes,
            datagrams: a.datagrams - b.datagrams,
        };
        loop {
            tick.tick().await;
            let (sent, recv) = (self.sent.snapshot(), self.received.snapshot());
            let mut iv = intervals.lock().unwrap();
            if self.sends() {
                iv.0.push(delta(sent, last_sent));
            }
            if self.receives() {
                iv.1.push(delta(recv, last_recv));
            }
            (last_sent, last_recv) = (sent, recv);
        }
    }

    async fn run_senders(
        self: Arc<Self>,
        senders: Vec<SendHalf>,
        start: Instant,
        intervals: &Mutex<(Vec<Interval>, Vec<Interval>)>,
    ) -> Result<Stats, String> {
        let mut tasks = JoinSet::new();
        for (i, half) in senders.into_iter().enumerate() {
            let test = self.clone();
            tasks.spawn(async move { (i, test.send_stream(half, start).await) });
        }
        let mut ends = Vec::new();
        while let Some(r) = tasks.join_next().await {
            let (i, r) = r.map_err(|e| e.to_string())?;
            ends.push(r.map_err(|e| std::format!("stream {i}: write: {e}"))?);
        }
        let stats = Stats {
            bytes: self.sent.snapshot().bytes,
            datagrams: self.sent.snapshot().datagrams,
            duration: start.elapsed(),
            intervals: intervals.lock().unwrap().0.clone(),
            ..Stats::default()
        };
        for half in &mut ends {
            self.end_stream(half)
                .await
                .map_err(|e| std::format!("ending stream: {e}"))?;
        }
        Ok(stats)
    }

    async fn end_stream(&self, half: &mut SendHalf) -> io::Result<()> {
        match half {
            SendHalf::Tcp(w) => w.shutdown().await,
            SendHalf::Udp(tx, stream) => {
                let mut buf = [0; UDP_HEADER_LEN];
                UdpHeader {
                    id: self.id,
                    stream: *stream,
                    flags: FLAG_FIN,
                    send_time: unix_nanos(),
                    ..UdpHeader::default()
                }
                .put(&mut buf);
                for _ in 0..FIN_REPEAT {
                    tx.send(&buf)?;
                }
                Ok(())
            }
        }
    }

    async fn send_stream(&self, mut half: SendHalf, start: Instant) -> io::Result<SendHalf> {
        let p = &self.params;
        let mut buf: Vec<u8> = (0..=u8::MAX).cycle().take(p.length).collect();
        let mut pacer = Pacer::new(p.bitrate, p.length);
        let mut sent = 0u64;
        let mut seq = 0u64;
        loop {
            if p.bytes > 0 {
                if sent >= p.bytes {
                    return Ok(half);
                }
            } else if start.elapsed() >= p.duration {
                return Ok(half);
            }
            if let Some(pacer) = pacer.as_mut() {
                pacer.wait().await;
            }
            let mut n = buf.len();
            match &mut half {
                SendHalf::Tcp(w) => {
                    if p.bytes > 0 {
                        n = n.min(usize::try_from(p.bytes - sent).unwrap_or(usize::MAX));
                    }
                    w.write_all(&buf[..n]).await?;
                }
                SendHalf::Udp(tx, stream) => {
                    UdpHeader {
                        id: self.id,
                        stream: *stream,
                        seq,
                        send_time: unix_nanos(),
                        ..UdpHeader::default()
                    }
                    .put(&mut buf);
                    seq += 1;
                    tx.send(&buf)?;
                    self.sent.datagrams.fetch_add(1, Ordering::Relaxed);
                    if pacer.is_none() {
                        tokio::task::yield_now().await;
                    }
                }
            }
            sent += n as u64;
            self.sent.bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    async fn run_receivers(
        self: Arc<Self>,
        receivers: Vec<RecvHalf>,
        peer_sent: watch::Receiver<Option<Stats>>,
        intervals: &Mutex<(Vec<Interval>, Vec<Interval>)>,
    ) -> Result<Stats, String> {
        let mut tasks = JoinSet::new();
        for (i, half) in receivers.into_iter().enumerate() {
            let (test, peer_sent) = (self.clone(), peer_sent.clone());
            tasks.spawn(async move {
                test.recv_stream(half, peer_sent)
                    .await
                    .map_err(|e| std::format!("stream {i}: read: {e}"))
            });
        }
        let mut stats = Stats::default();
        let (mut first, mut last): (Option<Instant>, Option<Instant>) = (None, None);
        let mut jitter = 0.0;
        while let Some(r) = tasks.join_next().await {
            let st = r.map_err(|e| e.to_string())??;
            if let Some(f) = st.first {
                first = Some(first.map_or(f, |x| x.min(f)));
            }
            if let Some(l) = st.last {
                last = Some(last.map_or(l, |x| x.max(l)));
            }
            stats.reordered += st.reordered;
            jitter += st.jitter;
        }
        let total = self.received.snapshot();
        stats.bytes = total.bytes;
        stats.datagrams = total.datagrams;
        stats.intervals = intervals.lock().unwrap().1.clone();
        if let (Some(f), Some(l)) = (first, last) {
            stats.duration = l - f;
        }
        if self.params.proto == Proto::Udp {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let avg = (jitter / self.params.streams as f64) as u64;
            stats.jitter = Duration::from_nanos(avg);
        }
        Ok(stats)
    }

    async fn recv_stream(
        &self,
        half: RecvHalf,
        mut peer_sent: watch::Receiver<Option<Stats>>,
    ) -> io::Result<Received> {
        let grace = if self.params.proto == Proto::Udp {
            UDP_GRACE
        } else {
            TCP_GRACE
        };
        let peer_done = peer_sent.clone();
        let deadline = async move {
            if peer_sent.wait_for(Option::is_some).await.is_ok() {
                tokio::time::sleep(grace).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(deadline);
        let mut st = Received::default();
        match half {
            RecvHalf::Tcp(mut r) => {
                let mut buf = std::vec![0; self.params.length.max(64 << 10)];
                loop {
                    tokio::select! {
                        res = r.read(&mut buf) => match res {
                            Ok(0) => break,
                            Ok(n) => st.count(n, Instant::now(), &self.received),
                            Err(_) if peer_done.borrow().is_some() => break,
                            Err(e) => return Err(e),
                        },
                        () = &mut deadline => break,
                    }
                }
            }
            RecvHalf::Udp { mut rx, first, .. } => {
                if st.datagram(&first, self.id, Instant::now(), &self.received) {
                    return Ok(st);
                }
                loop {
                    tokio::select! {
                        pkt = rx.recv() => match pkt {
                            Some(pkt) if st.datagram(&pkt, self.id, Instant::now(), &self.received) => break,
                            Some(_) => {}
                            None => break,
                        },
                        () = &mut deadline => break,
                    }
                }
            }
        }
        Ok(st)
    }
}

#[cfg(test)]
mod tests;
