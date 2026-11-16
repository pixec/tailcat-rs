#[cfg(feature = "std")]
use alloc::boxed::Box;
use alloc::string::String;

use crate::key::KEY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid tailcat address: {0}")]
    Addr(#[from] AddrError),

    #[error("derp map: {0}")]
    DerpMap(#[from] DerpMapError),

    #[error("derp: {0}")]
    Derp(#[from] DerpError),

    #[error("missing RegionID in DERP region")]
    MissingRegionId,

    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "std")]
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[cfg(feature = "ssh")]
    #[error(transparent)]
    AuthorizedKeys(#[from] AuthorizedKeysError),

    #[cfg(feature = "ssh")]
    #[error("SSH host key {}: {source}", path.display())]
    HostKey {
        path: std::path::PathBuf,
        #[source]
        source: russh::keys::Error,
    },

    #[cfg(feature = "ssh")]
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),

    #[error("server closed")]
    Closed,
}

/// Why OpenSSH `authorized_keys` text was rejected.
#[cfg(feature = "ssh")]
#[derive(Debug, thiserror::Error)]
pub enum AuthorizedKeysError {
    #[error("authorized keys entry {entry}, line {line}: no key found")]
    NoKey { entry: usize, line: usize },

    #[error("authorized keys entry {entry}, line {line}: options are not supported")]
    Options { entry: usize, line: usize },

    #[error("no SSH public keys found")]
    Empty,
}

/// Why a tailcat address failed to decode.
#[derive(Debug, thiserror::Error)]
pub enum AddrError {
    #[error("tailcat address doesn't start with \"tc\"")]
    MissingPrefix,

    #[error("base64 decode: {0}")]
    Base64(base64::DecodeError),

    #[error("CBOR unmarshal: {0}")]
    Cbor(String),

    #[error("{what} is not a map")]
    NotMap { what: &'static str },

    #[error("{what} is not an array")]
    NotArray { what: &'static str },

    #[error("{what} is not a byte string")]
    NotBytes { what: &'static str },

    #[error("{what} is not an integer")]
    NotInteger { what: &'static str },

    #[error("{what} is not a string")]
    NotString { what: &'static str },

    #[error("{what} is not a boolean")]
    NotBool { what: &'static str },

    #[error("{what} out of range")]
    OutOfRange { what: &'static str },

    #[error("invalid {what} length {len}, want {KEY_LEN}")]
    KeyLength { what: &'static str, len: usize },

    #[error("region {region} is null")]
    NullRegion { region: usize },

    #[error("region {region} node {node} is null")]
    NullNode { region: usize, node: usize },
}

/// Why a DERP map could not be fetched or a region resolved from it.
#[derive(Debug, thiserror::Error)]
pub enum DerpMapError {
    #[cfg(feature = "std")]
    #[error("fetching {url}: {status}")]
    Status {
        url: String,
        status: reqwest::StatusCode,
    },

    #[cfg(feature = "std")]
    #[error("DERP map from {url} exceeds {} bytes", crate::rt::FETCH_LIMIT)]
    TooLarge { url: String },

    #[cfg(feature = "std")]
    #[error("invalid DERP map JSON from {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: serde_json::Error,
    },

    #[cfg(feature = "std")]
    #[error("fetching DERPMap for region {region_id}: {source}")]
    Fetch {
        region_id: i64,
        #[source]
        source: Box<Error>,
    },

    #[error("failed to auto-detect any regions")]
    NoRegions,

    #[error(
        "tailcat address specified DERP RegionID {region_id} but no such region exists in {map}"
    )]
    NoSuchRegion { region_id: i64, map: String },

    #[error("no region resolved")]
    NoRegionResolved,
}

/// Why a DERP relay connection failed or ended.
#[derive(Debug, thiserror::Error)]
pub enum DerpError {
    #[cfg(feature = "std")]
    #[error("no frames for 120s")]
    ReadTimeout,

    #[error("short RecvPacket frame")]
    ShortRecvPacket,

    #[error("relay restarting")]
    Restarting,

    #[error("frame of {len} bytes exceeds limit of {max}")]
    FrameTooLarge { len: usize, max: usize },

    #[cfg(feature = "std")]
    #[error("region {region_id} has no DERP nodes")]
    NoNodes { region_id: i64 },

    #[cfg(feature = "std")]
    #[error("no address for {host}")]
    NoAddress { host: String },

    #[cfg(feature = "std")]
    #[error("dial {target}: {source}")]
    Dial {
        target: String,
        #[source]
        source: std::io::Error,
    },

    #[cfg(feature = "std")]
    #[error("dial {target}: timed out")]
    DialTimeout { target: String },

    #[cfg(feature = "std")]
    #[error("bad host name {host:?}: {source}")]
    InvalidHostName {
        host: String,
        #[source]
        source: rustls::pki_types::InvalidDnsNameError,
    },

    #[cfg(feature = "std")]
    #[error("tls to {host}: {source}")]
    Tls {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error("upgrade refused: {status}")]
    UpgradeRefused { status: String },

    #[error("upgrade response headers too large")]
    UpgradeTooLarge,

    #[error("connection closed in upgrade response")]
    UpgradeClosed,

    #[error("invalid server greeting")]
    InvalidGreeting,

    #[error("expected ServerInfo, got frame 0x{frame_type:02x}")]
    UnexpectedFrame { frame_type: u8 },

    #[error("failed to open ServerInfo box")]
    OpenServerInfo,

    #[error("invalid ServerInfo: {0}")]
    InvalidServerInfo(#[source] serde_json::Error),
}

/// Why a datagram could not be queued on a UDP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UdpSendError {
    #[error("flow closed")]
    Closed,

    #[error("destination unaddressable")]
    Unaddressable,
}

pub type Result<T> = core::result::Result<T, Error>;
