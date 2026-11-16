//! The Rust implementation of Tailcat's server component, enabling Tailcat
//! clients to securely access local services over WireGuard and DERP.
//!
//! This server speaks the tailcat wire protocols, so the stock `tailcat`
//! client connects to it unchanged. A server publishes a
//! compact [`Addr`] that encodes its WireGuard and path-discovery public
//! keys, a pre-shared key, and the DERP region it listens through. Clients
//! register over the relay with a "meow" handshake, after which both sides
//! carry WireGuard over DERP and, once disco has found a working UDP path,
//! directly.
//!
//! Traffic inside the tunnel terminates in a userspace TCP/UDP stack, so no
//! TUN device, routing table change, or privilege is needed. With the `std`
//! feature, connections addressed to the server surface through
//! `Server::accept_tcp` and `Server::accept_udp`; the caller decides what to
//! do with them.
//!
//! Tailscale's magicsock does far more than tailcat uses. Only the parts
//! tailcat depends on are here: the DERP client,
//! the meow and disco messages, STUN for learning our own endpoints, and a
//! small path selector. As with tailcat, a client that cannot reach the
//! server directly stays on the relay.
//!
//! Without the `std` feature the crate is `no_std` and needs only `alloc`.
//! The protocol core is then driven sans-IO: [`derp::Session`] for the relay
//! connection, [`transport::Transport`] for the tunnels and path selection,
//! and [`netstack::Netstack`] for the userspace stack, each fed bytes and the
//! current time by the caller. WireGuard itself plugs in through
//! [`tunnel::WireGuard`].

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod addr;
pub mod derp;
pub mod derpmap;
pub mod disco;
mod error;
pub mod key;
pub mod meow;
pub mod netstack;
#[cfg(feature = "std")]
mod rt;
pub mod stun;
pub mod transport;
pub mod tunnel;

pub use addr::{Addr, ConnInfo};
#[cfg(feature = "std")]
pub use derpmap::ExpandOptions;
pub use derpmap::{DerpMap, DerpNode, DerpRegion};
#[cfg(feature = "ssh")]
pub use error::AuthorizedKeysError;
pub use error::{AddrError, DerpError, DerpMapError, Error, Result, UdpSendError};
pub use key::{DiscoPublic, NodePrivate, NodePublic, PresharedKey};
pub use netstack::Ports;
#[cfg(feature = "exec")]
pub use rt::ExecHandler;
#[cfg(feature = "std")]
pub use rt::{Config, DEFAULT_UDP_IDLE_TIMEOUT, Peer, Region, Server, TcpConn, UdpFlow};
#[cfg(feature = "sftp")]
pub use rt::{FileServeMode, FileService};
#[cfg(feature = "perf")]
pub use rt::{PerfHandler, perf};
#[cfg(feature = "ssh")]
pub use rt::{SshHandler, SshOptions, validate_ssh_authorized_keys};
pub use transport::PeerStatus;

/// The URL of the JSON DERP map fetched when a server or address names a
/// region by ID only.
pub const DEFAULT_DERP_MAP_URL: &str = "https://tailcat.dev/derpmap.json";
