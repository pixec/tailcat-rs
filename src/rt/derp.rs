use std::boxed::Box;
use std::format;
use std::string::{String, ToString};
use std::sync::Arc;
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::derp::{self, Event, MAX_PACKET_SIZE, Packet, Session};
use crate::derpmap::{DerpNode, DerpRegion};
use crate::error::{DerpError, Error, Result};
use crate::key::{NodePrivate, NodePublic};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The relay sends a keep-alive every minute; twice that with nothing at
/// all means the connection is dead even if the socket has not noticed.
const READ_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const SEND_QUEUE: usize = 256;
const READ_BUF: usize = MAX_PACKET_SIZE + 64;

const HTTPS_PORT: u16 = 443;
/// What `derper --dev` listens on without TLS.
const DEV_HTTP_PORT: u16 = 3340;

#[derive(Clone, Debug)]
pub struct Options {
    /// Speak plain HTTP to the relay, as `derper --dev` expects. Never for
    /// a real relay: the node key exchange is authenticated by the box, but
    /// the relay's identity is only TLS.
    pub is_plaintext_http: bool,
    /// Announced to the relay; some relays refuse app names they know to be
    /// abusive.
    pub app_name: String,
}

/// A handle to a relay connection that is maintained in the background.
pub struct DerpClient {
    frames: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

impl DerpClient {
    /// Starts connecting to `region` and keeps the connection up until the
    /// client is dropped or the event receiver is closed.
    #[must_use]
    pub fn connect(
        region: DerpRegion,
        key: NodePrivate,
        opts: Options,
    ) -> (DerpClient, mpsc::Receiver<Packet>) {
        let (frames_tx, frames_rx) = mpsc::channel(SEND_QUEUE);
        let (packets_tx, packets_rx) = mpsc::channel(SEND_QUEUE);
        let task = tokio::spawn(run(region, key, opts, packets_tx, frames_rx));
        (
            DerpClient {
                frames: frames_tx,
                task,
            },
            packets_rx,
        )
    }

    /// Queues `pkt` for `dst`. Delivery is best effort, as on any relay: a
    /// full queue or a disconnected relay drops the packet, and so does the
    /// relay if `dst` is not connected to it.
    #[allow(clippy::must_use_candidate)]
    pub fn send(&self, dst: &NodePublic, pkt: &[u8]) -> bool {
        derp::send_packet_frame(dst, pkt).is_some_and(|f| self.frames.try_send(f).is_ok())
    }
}

impl Drop for DerpClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Stream = Box<dyn Io + Send>;
type Reader = ReadHalf<Stream>;
type Writer = WriteHalf<Stream>;
type Conn = (Reader, Writer, Session<OsRng>);

trait Io: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> Io for T {}

async fn run(
    region: DerpRegion,
    key: NodePrivate,
    opts: Options,
    packets: mpsc::Sender<Packet>,
    mut frames: mpsc::Receiver<Vec<u8>>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_once(&region, &key, &opts).await {
            Ok((conn, node)) => {
                tracing::info!(region = region.region_id, node, "derp connected");
                backoff = Duration::from_secs(1);
                let err = session(conn, &mut frames, &packets).await;
                tracing::warn!(region = region.region_id, %err, "derp connection lost");
            }
            Err(err) => {
                tracing::warn!(region = region.region_id, %err, "derp connect failed");
            }
        }
        if packets.is_closed() {
            return;
        }
        // Anything queued while disconnected is stale by the time the relay
        // is back: WireGuard retransmits and disco re-probes on their own.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = &mut sleep => break,
                Some(_) = frames.recv() => {}
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn flush(writer: &mut Writer, session: &mut Session<OsRng>) -> std::io::Result<()> {
    while let Some(bytes) = session.poll_transmit() {
        writer.write_all(&bytes).await?;
    }
    Ok(())
}

async fn read(reader: &mut Reader, session: &Session<OsRng>, buf: &mut [u8]) -> Result<usize> {
    match reader.read(buf).await? {
        0 if !session.is_upgraded() => Err(DerpError::UpgradeClosed.into()),
        0 => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
        n => Ok(n),
    }
}

async fn deliver(session: &mut Session<OsRng>, packets: &mpsc::Sender<Packet>) -> Result<()> {
    while let Some(event) = session.poll_event() {
        match event {
            Event::Packet(packet) => packets.send(packet).await.map_err(|_| Error::Closed)?,
            Event::PeerGone(peer) => {
                tracing::debug!(peer = %peer.short(), "relay reports peer gone");
            }
            Event::Health(problem) => {
                tracing::warn!(%problem, "derp health");
            }
        }
    }
    Ok(())
}

async fn session(
    (mut reader, mut writer, mut session): Conn,
    frames: &mut mpsc::Receiver<Vec<u8>>,
    packets: &mpsc::Sender<Packet>,
) -> Error {
    if let Err(err) = deliver(&mut session, packets).await {
        return err;
    }
    let mut buf = vec![0u8; READ_BUF];
    loop {
        tokio::select! {
            frame = frames.recv() => {
                let Some(frame) = frame else { return Error::Closed };
                if let Err(err) = writer.write_all(&frame).await {
                    return err.into();
                }
            }
            read = tokio::time::timeout(READ_TIMEOUT, read(&mut reader, &session, &mut buf)) => {
                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(err)) => return err,
                    Err(_) => return DerpError::ReadTimeout.into(),
                };
                if let Err(err) = session.receive(&buf[..n]) {
                    return err.into();
                }
                if let Err(err) = deliver(&mut session, packets).await {
                    return err;
                }
                if let Err(err) = flush(&mut writer, &mut session).await {
                    return err.into();
                }
            }
        }
    }
}

async fn connect_once(
    region: &DerpRegion,
    key: &NodePrivate,
    opts: &Options,
) -> Result<(Conn, String)> {
    let mut last_err = DerpError::NoNodes {
        region_id: region.region_id,
    }
    .into();
    for node in region.nodes.iter().filter(|n| !n.is_stun_only) {
        match connect_node(node, key, opts).await {
            Ok(conn) => return Ok((conn, node.host_name.clone())),
            Err(err) => {
                tracing::debug!(node = node.host_name, %err, "derp node failed");
                last_err = err;
            }
        }
    }
    Err(last_err)
}

fn port_of(node: &DerpNode, opts: &Options) -> u16 {
    match u16::try_from(node.derp_port) {
        Ok(p) if p != 0 => p,
        _ if opts.is_plaintext_http => DEV_HTTP_PORT,
        _ => HTTPS_PORT,
    }
}

async fn dial(node: &DerpNode, port: u16) -> Result<TcpStream> {
    let mut targets: Vec<String> = node
        .ip_addrs()
        .into_iter()
        .map(|ip| std::net::SocketAddr::new(ip, port).to_string())
        .collect();
    if targets.is_empty() {
        targets.push(format!("{}:{port}", node.host_name));
    }
    let mut last_err = DerpError::NoAddress {
        host: node.host_name.clone(),
    };
    for target in targets {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&target)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(source)) => last_err = DerpError::Dial { target, source },
            Err(_) => last_err = DerpError::DialTimeout { target },
        }
    }
    Err(last_err.into())
}

fn tls_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    if insecure {
        return Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );
    }
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Accepts any certificate. Only for nodes flagged `InsecureForTests`,
/// which is how a test's self-signed relay gets used.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn connect_node(node: &DerpNode, key: &NodePrivate, opts: &Options) -> Result<Conn> {
    let port = port_of(node, opts);
    let tcp = dial(node, port).await?;
    let stream: Stream = if opts.is_plaintext_http {
        Box::new(tcp)
    } else {
        let name = ServerName::try_from(node.host_name.clone()).map_err(|source| {
            DerpError::InvalidHostName {
                host: node.host_name.clone(),
                source,
            }
        })?;
        let connector = tokio_rustls::TlsConnector::from(tls_config(node.is_insecure_for_tests));
        Box::new(
            connector
                .connect(name, tcp)
                .await
                .map_err(|source| DerpError::Tls {
                    host: node.host_name.clone(),
                    source,
                })?,
        )
    };
    let (mut rd, mut wr) = tokio::io::split(stream);

    let default_port = if opts.is_plaintext_http {
        DEV_HTTP_PORT
    } else {
        HTTPS_PORT
    };
    let host = if port == default_port {
        node.host_name.clone()
    } else {
        format!("{}:{port}", node.host_name)
    };
    let mut session = Session::new(key.clone(), &host, &opts.app_name, OsRng);
    let mut buf = vec![0u8; READ_BUF];
    while !session.is_connected() {
        flush(&mut wr, &mut session).await?;
        let n = read(&mut rd, &session, &mut buf).await?;
        session.receive(&buf[..n])?;
    }
    flush(&mut wr, &mut session).await?;
    Ok((rd, wr, session))
}
