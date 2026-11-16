//! The `std` layer: tokio tasks, sockets, TLS, DERP map fetching and
//! boringtun around the sans-IO core.

mod derp;
mod derpmap;
#[cfg(feature = "exec")]
mod exec;
mod netstack;
mod peer;
#[cfg(feature = "perf")]
pub mod perf;
mod server;
#[cfg(feature = "sftp")]
mod sftp;
#[cfg(feature = "ssh")]
mod ssh;
mod transport;
mod wireguard;

use std::sync::OnceLock;
use std::time::Instant;

pub use derp::{DerpClient, Options};
pub(crate) use derpmap::FETCH_LIMIT;
pub use derpmap::{ExpandOptions, Mode, fetch_derp_map, pick_best_region};
#[cfg(feature = "exec")]
pub use exec::ExecHandler;
pub use netstack::{TcpConn, UdpFlow};
pub use peer::Peer;
#[cfg(feature = "perf")]
pub use perf::PerfHandler;
pub use server::{Config, DEFAULT_UDP_IDLE_TIMEOUT, Region, Server};
#[cfg(feature = "sftp")]
pub use sftp::{FileServeMode, FileService};
#[cfg(feature = "ssh")]
pub use ssh::{SshHandler, SshOptions, validate_ssh_authorized_keys};

fn now() -> smoltcp::time::Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let micros = EPOCH.get_or_init(Instant::now).elapsed().as_micros();
    smoltcp::time::Instant::from_micros(i64::try_from(micros).unwrap_or(i64::MAX))
}
