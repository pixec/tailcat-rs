//! The DERP map: which relays exist, and how a server picks one.
//!
//! The JSON types mirror Tailscale's `tailcfg.DERPMap`, so the map served
//! at [`crate::DEFAULT_DERP_MAP_URL`], or one from a
//! self-hosted `derper`, decodes as is.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::addr::ConnInfo;
use crate::error::{DerpMapError, Result};
#[cfg(feature = "std")]
pub use crate::rt::{ExpandOptions, Mode, fetch_derp_map, pick_best_region};

pub const DEFAULT_STUN_PORT: u16 = 3478;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub host_name: String,
    /// The expected TLS certificate name when it differs from `host_name`.
    /// Carried through the wire format for compatibility; connections
    /// verify against `host_name`.
    pub cert_name: String,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    pub ipv6: String,
    /// The STUN port, `-1` to disable STUN for this node, `0` for the
    /// default.
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub is_stun_only: bool,
    /// The DERP port, `0` for the default.
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    #[serde(rename = "InsecureForTests")]
    pub is_insecure_for_tests: bool,
    #[serde(rename = "CanPort80")]
    pub is_port80_reachable: bool,
}

impl DerpNode {
    /// The literal addresses to dial, if the map gives any. `"none"` is how
    /// a map says a node has no address of that family.
    #[must_use]
    pub fn ip_addrs(&self) -> Vec<IpAddr> {
        [&self.ipv4, &self.ipv6]
            .into_iter()
            .filter(|s| !s.is_empty() && *s != "none")
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    #[must_use]
    pub fn stun_port(&self) -> Option<u16> {
        match self.stun_port {
            -1 => None,
            0 => Some(DEFAULT_STUN_PORT),
            p => u16::try_from(p).ok(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub region_code: String,
    pub region_name: String,
    #[serde(rename = "Avoid")]
    pub is_avoided: bool,
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpMap {
    pub regions: BTreeMap<i64, DerpRegion>,
}

impl DerpMap {
    /// Decodes a JSON DERP map.
    ///
    /// # Errors
    ///
    /// Fails if `json` is not a valid DERP map.
    pub fn from_json(json: &[u8]) -> core::result::Result<DerpMap, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

impl ConnInfo {
    pub(crate) fn number_regions(&mut self) {
        for r in &mut self.region {
            if r.region_id == 0 {
                r.region_id = 1;
            }
            for n in &mut r.nodes {
                if n.region_id == 0 {
                    n.region_id = r.region_id;
                }
            }
        }
    }

    /// Populates `region` from `map` when only a positive `region_id` is
    /// set. `source` names the map in errors. Already-expanded info is left
    /// alone.
    ///
    /// # Errors
    ///
    /// Fails if `map` has no matching region.
    pub fn expand_from(&mut self, map: &DerpMap, source: &str) -> Result<()> {
        self.number_regions();
        if !self.region.is_empty() || self.region_id == 0 {
            return Ok(());
        }
        let region =
            map.regions
                .get(&self.region_id)
                .ok_or_else(|| DerpMapError::NoSuchRegion {
                    region_id: self.region_id,
                    map: source.into(),
                })?;
        self.region.push(region.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn decodes_the_public_map_shape() {
        let json = r#"{"Regions":{"301":{"RegionID":301,"RegionCode":"nyc","RegionName":"New York City","Latitude":40.7,"Longitude":-74,"Nodes":[{"Name":"301a","RegionID":301,"HostName":"tc301a.ipn.dev","IPv4":"199.38.181.166","IPv6":"2607:f740:f::26b","CanPort80":true}]}}}"#;
        let map = DerpMap::from_json(json.as_bytes()).unwrap();
        let r = &map.regions[&301];
        assert_eq!(r.region_code, "nyc");
        let n = &r.nodes[0];
        assert_eq!(n.host_name, "tc301a.ipn.dev");
        assert!(n.is_port80_reachable);
        assert_eq!(n.stun_port(), Some(DEFAULT_STUN_PORT));
        assert_eq!(n.ip_addrs().len(), 2);
    }

    #[test]
    fn node_address_helpers() {
        let n = DerpNode {
            ipv4: "none".into(),
            ipv6: "2001:db8::1".into(),
            stun_port: -1,
            ..Default::default()
        };
        assert_eq!(n.ip_addrs(), vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(n.stun_port(), None);
    }

    #[test]
    fn expand_from_map() {
        let mut map = DerpMap::default();
        map.regions.insert(
            7,
            DerpRegion {
                region_id: 7,
                region_code: "x".into(),
                ..Default::default()
            },
        );
        let mut ci = ConnInfo {
            region_id: 7,
            ..Default::default()
        };
        ci.expand_from(&map, "test map").unwrap();
        assert_eq!(ci.region[0].region_code, "x");

        let mut missing = ConnInfo {
            region_id: 8,
            ..Default::default()
        };
        assert!(missing.expand_from(&map, "test map").is_err());
    }
}
