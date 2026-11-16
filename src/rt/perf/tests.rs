use std::net::{Ipv6Addr, SocketAddrV6};

use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

use super::*;

struct ChanSink(mpsc::UnboundedSender<Vec<u8>>);

impl DatagramSink for ChanSink {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        self.0
            .send(data.to_vec())
            .map_err(|_| io::ErrorKind::NotConnected.into())
    }
}

fn peer() -> Peer {
    Peer {
        local: SocketAddrV6::new(Ipv6Addr::LOCALHOST, PORT, 0, 0).into(),
        remote: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 40000, 0, 0).into(),
        key: None,
    }
}

fn params(proto: Proto, direction: Direction) -> Params {
    Params {
        proto,
        direction,
        duration: Duration::ZERO,
        bytes: 100_000,
        streams: 2,
        length: if proto == Proto::Tcp { 16 << 10 } else { 1232 },
        bitrate: 0,
        interval: Duration::ZERO,
    }
}

struct Ctrl {
    r: BufReader<ReadHalf<DuplexStream>>,
    w: WriteHalf<DuplexStream>,
    inbox: Vec<Message>,
}

impl Ctrl {
    async fn send(&mut self, m: &Message) {
        send_message(&mut self.w, m).await.unwrap();
    }

    async fn expect(&mut self, kind: &str) -> Message {
        if let Some(i) = self.inbox.iter().position(|m| m.kind == kind) {
            return self.inbox.remove(i);
        }
        loop {
            let m = tokio::time::timeout(Duration::from_secs(20), read_message(&mut self.r))
                .await
                .expect("control timed out")
                .unwrap();
            if m.kind == kind {
                return m;
            }
            assert_ne!(m.kind, "error", "server error: {}", m.error);
            self.inbox.push(m);
        }
    }
}

fn handler() -> (PerfHandler, mpsc::UnboundedReceiver<Report>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let h = PerfHandler::new().on_result(move |_, r| {
        let _ = tx.send(r.clone());
    });
    (h, rx)
}

async fn hello(h: &PerfHandler, p: &Params) -> (Ctrl, Message) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let h2 = h.clone();
    tokio::spawn(async move { h2.serve_tcp(server, peer()).await });
    let (reader, w) = tokio::io::split(client);
    let mut ctrl = Ctrl {
        r: BufReader::new(reader),
        w,
        inbox: Vec::new(),
    };
    let hello = Message {
        params: Some(serde_json::to_value(p).unwrap()),
        ..Message::new("hello")
    };
    ctrl.send(&hello).await;
    let reply = read_message(&mut ctrl.r).await.unwrap();
    (ctrl, reply)
}

async fn start(h: &PerfHandler, p: &Params) -> (Ctrl, String) {
    let (ctrl, reply) = hello(h, p).await;
    assert_eq!(reply.kind, "ok", "{}", reply.error);
    (ctrl, reply.id)
}

async fn tcp_round_trip(direction: Direction) {
    let (h, mut reports) = handler();
    let p = params(Proto::Tcp, direction);
    let (mut ctrl, id) = start(&h, &p).await;
    let mut streams = Vec::new();
    for i in 0..p.streams {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let h2 = h.clone();
        tokio::spawn(async move { h2.serve_tcp(server, peer()).await });
        let m = Message {
            id: id.clone(),
            stream: i64::try_from(i).unwrap(),
            ..Message::new("stream")
        };
        send_message(&mut client, &m).await.unwrap();
        streams.push(client);
    }
    ctrl.expect("ready").await;
    ctrl.send(&Message {
        t: 7,
        ..Message::new("ping")
    })
    .await;
    assert_eq!(ctrl.expect("pong").await.t, 7);

    let client_sends = direction != Direction::Download;
    let client_receives = direction != Direction::Upload;
    let mut tasks = JoinSet::new();
    for s in streams {
        let (mut r, mut w) = tokio::io::split(s);
        let bytes = p.bytes;
        tasks.spawn(async move {
            let writer = async {
                if client_sends {
                    w.write_all(&std::vec![7; usize::try_from(bytes).unwrap()])
                        .await
                        .unwrap();
                    w.shutdown().await.unwrap();
                }
            };
            let reader = async {
                let mut got = Vec::new();
                if client_receives {
                    r.read_to_end(&mut got).await.unwrap();
                }
                got.len() as u64
            };
            tokio::join!(writer, reader).1
        });
    }
    let mut received = 0;
    while let Some(n) = tasks.join_next().await {
        received += n.unwrap();
    }
    if client_sends {
        let stats = Stats {
            bytes: p.bytes * 2,
            ..Stats::default()
        };
        ctrl.send(&Message::stats("done", &stats)).await;
    }
    if client_receives {
        let done = ctrl.expect("done").await.stats.unwrap();
        assert_eq!(done.bytes, received);
        let stats = Stats {
            bytes: received,
            ..Stats::default()
        };
        ctrl.send(&Message::stats("result", &stats)).await;
    }
    if client_sends {
        assert_eq!(
            ctrl.expect("result").await.stats.unwrap().bytes,
            p.bytes * 2
        );
    }
    let report = tokio::time::timeout(Duration::from_secs(20), reports.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.params, p);
    if client_receives {
        assert_eq!(received, p.bytes * 2);
        assert_eq!(report.server_sent.unwrap().bytes, received);
        assert_eq!(report.client_received.unwrap().bytes, received);
    } else {
        assert!(report.server_sent.is_none() && report.client_received.is_none());
    }
    if client_sends {
        assert_eq!(report.server_received.unwrap().bytes, p.bytes * 2);
        assert_eq!(report.client_sent.unwrap().bytes, p.bytes * 2);
    } else {
        assert!(report.server_received.is_none() && report.client_sent.is_none());
    }
}

#[tokio::test]
async fn tcp_upload() {
    tcp_round_trip(Direction::Upload).await;
}

#[tokio::test]
async fn tcp_download() {
    tcp_round_trip(Direction::Download).await;
}

#[tokio::test]
async fn tcp_bidirectional() {
    tcp_round_trip(Direction::Bidirectional).await;
}

fn datagram(id: [u8; 8], stream: u16, flags: u8, seq: u64, len: usize) -> Vec<u8> {
    let mut b = std::vec![0; len];
    UdpHeader {
        id,
        stream,
        flags,
        seq,
        send_time: unix_nanos(),
    }
    .put(&mut b);
    b
}

#[tokio::test]
async fn udp_both_directions() {
    let (h, mut reports) = handler();
    let p = Params {
        streams: 1,
        bytes: 20 * 1232,
        ..params(Proto::Udp, Direction::Bidirectional)
    };
    let (mut ctrl, id_hex) = start(&h, &p).await;
    let id: [u8; 8] = hex::decode(&id_hex).unwrap().try_into().unwrap();
    let (to_server, server_rx) = mpsc::channel(1024);
    let (server_tx, mut from_server) = mpsc::unbounded_channel();
    let h2 = h.clone();
    tokio::spawn(async move {
        h2.serve_datagrams(server_rx, Arc::new(ChanSink(server_tx)), peer())
            .await;
    });
    to_server
        .send(datagram(id, 0, FLAG_OPEN, 0, UDP_HEADER_LEN))
        .await
        .unwrap();
    ctrl.expect("ready").await;

    for seq in [0, 1, 3, 2, 4] {
        to_server.send(datagram(id, 0, 0, seq, 1232)).await.unwrap();
    }
    to_server
        .send(datagram([9; 8], 0, 0, 99, 1232))
        .await
        .unwrap();
    for _ in 0..FIN_REPEAT {
        to_server
            .send(datagram(id, 0, FLAG_FIN, 0, UDP_HEADER_LEN))
            .await
            .unwrap();
    }
    let sent = Stats {
        bytes: 5 * 1232,
        datagrams: 5,
        ..Stats::default()
    };
    ctrl.send(&Message::stats("done", &sent)).await;

    let mut seqs = Vec::new();
    loop {
        let pkt = from_server.recv().await.unwrap();
        let hdr = UdpHeader::parse(&pkt).unwrap();
        assert_eq!(hdr.id, id);
        if hdr.flags & FLAG_FIN != 0 {
            break;
        }
        assert_eq!(pkt.len(), 1232);
        seqs.push(hdr.seq);
    }
    assert_eq!(seqs, (0..20).collect::<Vec<_>>());
    let done = ctrl.expect("done").await.stats.unwrap();
    assert_eq!((done.bytes, done.datagrams), (20 * 1232, 20));
    let result = Stats {
        bytes: 20 * 1232,
        datagrams: 20,
        ..Stats::default()
    };
    ctrl.send(&Message::stats("result", &result)).await;
    let got = ctrl.expect("result").await.stats.unwrap();
    assert_eq!((got.bytes, got.datagrams, got.reordered), (5 * 1232, 5, 1));

    let report = tokio::time::timeout(Duration::from_secs(20), reports.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.server_received.unwrap().datagrams, 5);
    assert_eq!(report.client_received.unwrap().datagrams, 20);
}

#[tokio::test]
async fn busy_and_limits() {
    let (h, _) = handler();
    let h = h.max_streams(4);
    let (_ctrl, _id) = start(&h, &params(Proto::Tcp, Direction::Upload)).await;
    let (_c, reply) = hello(&h, &params(Proto::Tcp, Direction::Upload)).await;
    assert_eq!(
        (reply.kind.as_str(), reply.error.as_str()),
        ("error", "the server is busy with another test")
    );

    let (h, _) = handler();
    let h = h.max_streams(4);
    let p = Params {
        streams: 5,
        ..params(Proto::Tcp, Direction::Upload)
    };
    let (_c, reply) = hello(&h, &p).await;
    assert_eq!(reply.error, "5 streams exceeds the server's limit of 4");

    let (_c, reply) = hello(
        &h,
        &Params {
            proto: Proto::Udp,
            ..p
        },
    )
    .await;
    assert_eq!(reply.kind, "error");
}

#[test]
fn validate() {
    let ok = params(Proto::Tcp, Direction::Upload);
    let max = DEFAULT_MAX_DURATION;
    assert_eq!(ok.validate(128, max), Ok(()));
    let cases = [
        (
            Params {
                bytes: 0,
                ..ok.clone()
            },
            "a duration or byte count is required",
        ),
        (
            Params {
                bytes: 0,
                duration: Duration::from_mins(20),
                ..ok.clone()
            },
            "duration 20m0s exceeds the server's limit of 10m0s",
        ),
        (
            Params {
                streams: 0,
                ..ok.clone()
            },
            "at least one stream is required",
        ),
        (
            Params {
                length: 0,
                ..ok.clone()
            },
            "a positive length is required",
        ),
        (
            Params {
                length: (1 << 20) + 1,
                ..ok.clone()
            },
            "TCP length 1048577 exceeds 1048576",
        ),
        (
            Params {
                proto: Proto::Udp,
                length: 8,
                ..ok.clone()
            },
            "UDP length 8 is smaller than the 32-byte header",
        ),
        (
            Params {
                proto: Proto::Udp,
                length: 70_000,
                ..ok.clone()
            },
            "UDP length 70000 exceeds 65507",
        ),
        (
            Params {
                interval: Duration::from_millis(50),
                ..ok.clone()
            },
            "interval 50ms is shorter than 100ms",
        ),
    ];
    for (p, want) in cases {
        assert_eq!(p.validate(128, max).unwrap_err(), want);
    }
}

#[test]
fn wire_format() {
    let p = Params {
        duration: Duration::from_secs(10),
        bytes: 0,
        interval: Duration::from_secs(1),
        ..params(Proto::Udp, Direction::Download)
    };
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(
        json,
        r#"{"proto":"udp","dir":"down","duration":10000000000,"streams":2,"length":1232,"interval":1000000000}"#
    );
    assert_eq!(serde_json::from_str::<Params>(&json).unwrap(), p);
    let m: Message =
        serde_json::from_str(r#"{"type":"stream","id":"0011223344556677","stream":3}"#).unwrap();
    assert_eq!((m.kind.as_str(), m.stream), ("stream", 3));
    let done = serde_json::to_string(&Message::stats(
        "done",
        &Stats {
            bytes: 5,
            ..Stats::default()
        },
    ))
    .unwrap();
    assert_eq!(done, r#"{"type":"done","stats":{"bytes":5,"duration":0}}"#);

    let h = UdpHeader {
        id: *b"abcdefgh",
        stream: 258,
        flags: FLAG_FIN,
        seq: 0x0102_0304_0506_0708,
        send_time: -2,
    };
    let mut b = [0xff; UDP_HEADER_LEN];
    h.put(&mut b);
    assert_eq!(&b[8..16], &[1, 2, FLAG_FIN, 0, 0, 0, 0, 0]);
    let back = UdpHeader::parse(&b).unwrap();
    assert_eq!(
        (back.id, back.stream, back.flags, back.seq, back.send_time),
        (h.id, h.stream, h.flags, h.seq, h.send_time)
    );
    assert!(UdpHeader::parse(&b[..31]).is_none());
}

#[test]
fn durations_format_like_go() {
    for (d, want) in [
        (Duration::ZERO, "0s"),
        (Duration::from_nanos(15), "15ns"),
        (Duration::from_micros(1500), "1.5ms"),
        (Duration::from_millis(100), "100ms"),
        (Duration::from_millis(1500), "1.5s"),
        (Duration::from_mins(10), "10m0s"),
        (Duration::from_secs(3723), "1h2m3s"),
    ] {
        assert_eq!(go_duration(d), want);
    }
}

#[test]
fn jitter_follows_rfc3550() {
    let c = Counters::default();
    let mut st = Received::default();
    let id = [1; 8];
    let now = Instant::now();
    assert!(!st.datagram(&datagram(id, 0, 0, 0, 64), id, now, &c));
    assert!(!st.datagram(&datagram(id, 0, FLAG_OPEN, 0, 64), id, now, &c));
    assert!(st.datagram(&datagram(id, 0, FLAG_FIN, 0, 64), id, now, &c));
    assert_eq!(c.snapshot().datagrams, 1);
    st.last_transit = Some(st.last_transit.unwrap() - 16_000_000);
    st.datagram(&datagram(id, 0, 0, 1, 64), id, now, &c);
    assert!(st.jitter > 900_000.0, "{}", st.jitter);
}
