use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::string::{String, ToString};
use std::time::{Duration, Instant};
use std::vec;
use std::vec::Vec;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use tokio::net::UdpSocket;

use crate::DEFAULT_DERP_MAP_URL;
use crate::addr::{Addr, ConnInfo};
use crate::derpmap::DerpMap;
use crate::error::{DerpMapError, Result};
use crate::stun;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const FETCH_LIMIT: usize = 8 << 20;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Whose behalf a DERP map is fetched on. Sent as a hint header, which lets
/// the map server tailor the regions it returns to a server that is about
/// to listen through one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    fn header(self) -> &'static str {
        match self {
            Mode::Client => "client",
            Mode::Server => "server",
        }
    }
}

/// Fetches and decodes the JSON DERP map at `url`.
///
/// # Errors
///
/// Fails on a network error, a non-success status, an oversized body, or
/// invalid JSON.
pub async fn fetch_derp_map(url: &str, mode: Mode) -> Result<DerpMap> {
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?;
    let mut resp = client
        .get(url)
        .header("Tailcat-Mode", mode.header())
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(DerpMapError::Status {
            url: url.into(),
            status: resp.status(),
        }
        .into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > FETCH_LIMIT {
            return Err(DerpMapError::TooLarge { url: url.into() }.into());
        }
        body.extend_from_slice(&chunk);
    }
    DerpMap::from_json(&body).map_err(|source| {
        DerpMapError::Json {
            url: url.into(),
            source,
        }
        .into()
    })
}

async fn recv_stun(sock: Option<&UdpSocket>) -> Option<stun::TxId> {
    let sock = sock?;
    let mut buf = [0u8; 1500];
    loop {
        let n = sock.recv(&mut buf).await.ok()?;
        if let Some((tx, _)) = stun::parse_response(&buf[..n]) {
            return Some(tx);
        }
    }
}

/// Probes every region's STUN servers and returns the region that answered
/// fastest, or `None` if nothing answered within a few seconds.
pub async fn pick_best_region(map: &DerpMap) -> Option<i64> {
    let v4 = UdpSocket::bind("0.0.0.0:0").await.ok();
    let v6 = UdpSocket::bind("[::]:0").await.ok();
    let mut sent: HashMap<stun::TxId, (i64, Instant)> = HashMap::new();
    for (id, region) in &map.regions {
        for node in &region.nodes {
            let Some(port) = node.stun_port() else {
                continue;
            };
            for ip in node.ip_addrs() {
                let sock = match ip {
                    IpAddr::V4(_) => v4.as_ref(),
                    IpAddr::V6(_) => v6.as_ref(),
                };
                let Some(sock) = sock else {
                    continue;
                };
                let tx = stun::TxId::from_rng(&mut OsRng);
                if sock
                    .send_to(&stun::request(tx), SocketAddr::new(ip, port))
                    .await
                    .is_ok()
                {
                    sent.insert(tx, (*id, Instant::now()));
                }
            }
        }
    }
    if sent.is_empty() {
        return None;
    }

    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let mut best: Option<(i64, Duration)> = None;
    let mut answered = 0;
    while answered < sent.len() {
        let tx = tokio::select! {
            Some(tx) = recv_stun(v4.as_ref()) => tx,
            Some(tx) = recv_stun(v6.as_ref()) => tx,
            () = tokio::time::sleep_until(deadline) => break,
        };
        let Some((id, at)) = sent.remove(&tx) else {
            continue;
        };
        answered += 1;
        let latency = at.elapsed();
        if best.is_none_or(|(_, b)| latency < b) {
            best = Some((id, latency));
        }
    }
    best.map(|(id, _)| id)
}

#[derive(Clone, Debug, Default)]
pub struct ExpandOptions {
    /// An alternate map URL, for a fleet running its own relays.
    pub derp_map_url: Option<String>,
    /// A DERP map to expand from instead of fetching one.
    pub derp_map: Option<DerpMap>,
    /// Whether the fetch is on behalf of a server; see [`Mode`].
    pub is_for_server: bool,
}

impl ConnInfo {
    /// Populates `region` from a DERP map when only `region_id` is set.
    ///
    /// A `region_id` of `-1` asks for the lowest-latency region, measured by
    /// STUN probes, with a random region as the fallback when nothing
    /// answers. Already-expanded info is left alone.
    ///
    /// # Errors
    ///
    /// Fails if the DERP map cannot be fetched or has no matching region.
    pub async fn expand(&mut self, opts: &ExpandOptions) -> Result<()> {
        self.number_regions();
        if !self.region.is_empty() || self.region_id == 0 {
            return Ok(());
        }

        let url = opts
            .derp_map_url
            .clone()
            .unwrap_or_else(|| DEFAULT_DERP_MAP_URL.to_string());
        let (mut map, source) = if let Some(m) = &opts.derp_map {
            (m.clone(), "provided DERP map".to_string())
        } else {
            let mode = if opts.is_for_server {
                Mode::Server
            } else {
                Mode::Client
            };
            let map = fetch_derp_map(&url, mode)
                .await
                .map_err(|err| DerpMapError::Fetch {
                    region_id: self.region_id,
                    source: std::boxed::Box::new(err),
                })?;
            (map, url)
        };

        if self.region_id == -1 {
            for r in map.regions.values_mut() {
                r.nodes.shuffle(&mut rand::thread_rng());
            }
            let id = if let Some(id) = pick_best_region(&map).await {
                id
            } else {
                let ids: Vec<i64> = map.regions.keys().copied().collect();
                *ids.choose(&mut rand::thread_rng())
                    .ok_or(DerpMapError::NoRegions)?
            };
            self.region_id = 0;
            self.region = vec![map.regions[&id].clone()];
            return Ok(());
        }

        self.expand_from(&map, &source)
    }
}

impl Addr {
    /// A self-contained equivalent with the relay's details embedded, so
    /// that using it later needs no DERP map fetch. An address that already
    /// embeds a region is returned unchanged; otherwise the region is looked
    /// up and trimmed to two nodes to keep the address short.
    ///
    /// # Errors
    ///
    /// Fails if the address is malformed or its region cannot be looked up.
    pub async fn resolve(&self, opts: &ExpandOptions) -> Result<Addr> {
        let mut ci = self.parse()?;
        if !ci.region.is_empty() {
            return Ok(self.clone());
        }
        ci.expand(opts).await?;
        for r in &mut ci.region {
            r.nodes.truncate(2);
        }
        ci.region_id = 0;
        Ok(ci.addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derpmap::DerpRegion;

    #[tokio::test]
    async fn expand_from_provided_map() {
        let mut map = DerpMap::default();
        map.regions.insert(
            7,
            DerpRegion {
                region_id: 7,
                region_code: "x".into(),
                ..Default::default()
            },
        );
        let opts = ExpandOptions {
            derp_map: Some(map),
            ..Default::default()
        };
        let mut ci = ConnInfo {
            region_id: 7,
            ..Default::default()
        };
        ci.expand(&opts).await.unwrap();
        assert_eq!(ci.region[0].region_code, "x");

        let mut missing = ConnInfo {
            region_id: 8,
            ..Default::default()
        };
        assert!(missing.expand(&opts).await.is_err());
    }
}
