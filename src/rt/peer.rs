use std::net::SocketAddr;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::key::NodePublic;

/// The client side of an accepted connection or flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The server's own address the client connected to.
    pub local: SocketAddr,
    /// The client's tunnel address and port.
    pub remote: SocketAddr,
    /// The client's node key, which the tunnel has authenticated.
    pub key: Option<NodePublic>,
}

impl Peer {
    /// The variables describing this peer to a served process:
    /// `TAILCAT_REMOTE_ADDR`, `TAILCAT_LOCAL_ADDR` and, when known,
    /// `TAILCAT_PEER_KEY` in the `nodekey:...` form.
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = std::vec![
            ("TAILCAT_REMOTE_ADDR".into(), self.remote.to_string()),
            ("TAILCAT_LOCAL_ADDR".into(), self.local.to_string()),
        ];
        if let Some(key) = self.key {
            env.push(("TAILCAT_PEER_KEY".into(), key.to_string()));
        }
        env
    }
}
