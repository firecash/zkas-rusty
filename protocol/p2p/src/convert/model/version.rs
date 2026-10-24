use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_core::{
    kaspad_env::{name, version},
    time::unix_now,
};
use kaspa_utils::networking::{NetAddress, PeerId};

/// Maximum allowed length for the user agent field in a version message `VersionMessage`.
pub const MAX_USER_AGENT_LEN: usize = 256;

pub struct Version {
    pub protocol_version: u32,
    pub network: String,
    pub services: u64,
    pub timestamp: u64,
    pub address: Option<NetAddress>,
    pub id: PeerId,
    pub user_agent: String,
    pub disable_relay_tx: bool,
    pub subnetwork_id: Option<SubnetworkId>,
}

/// Service bits advertised in `Version.services` (spec 06 H-4; ids per 16 A8.12). Every default
/// v11 node sets the same bits, so the mask carries no per-node information within a version.
pub mod services {
    /// Speaks `StemTransaction` (Dandelion++ stem phase).
    pub const NODE_DPP: u64 = 1 << 0;
    /// Speaks compact blocks (not implemented in this release; never set).
    pub const NODE_CMPCT: u64 = 1 << 1;
    /// Accepts `AddressesV2` (not implemented in this release; never set).
    pub const NODE_ADDRV2: u64 = 1 << 2;
    /// A submission relay (informational).
    pub const NODE_SUBMIT_RELAY: u64 = 1 << 3;
    /// Sends and forwards `ShieldedConflict` notices.
    pub const SHIELDED_CONFLICT: u64 = 1 << 7;
}

/// `unix_now()` rounded down to a whole second (spec 06 H-3). Millisecond timestamps let a peer
/// with two connections match them by clock skew; one second is still far finer than the
/// 2-minute-scale timestamp rules the offset feeds.
pub fn coarse_unix_now() -> u64 {
    unix_now() / 1000 * 1000
}

/// The user agent every node of one minor version sends: `/kaspad:<major>.<minor>/` (spec 06 H-5).
/// The patch level and comments are dropped because they split the network into small,
/// recognisable groups.
pub fn uniform_user_agent(name: &str, version: &str) -> String {
    let mut parts = version.split(['.', '-', '+']);
    let major = parts.next().unwrap_or("0");
    let minor = parts.next().unwrap_or("0");
    format!("/{}:{}.{}/", name, major, minor)
}

impl Version {
    pub fn new(
        address: Option<NetAddress>,
        id: PeerId,
        network: String,
        subnetwork_id: Option<SubnetworkId>,
        protocol_version: u32,
    ) -> Self {
        Self {
            protocol_version,
            network,
            services: 0,
            timestamp: coarse_unix_now(),
            address,
            id,
            user_agent: uniform_user_agent(name(), version()),
            disable_relay_tx: false,
            subnetwork_id,
        }
    }

    /// Appends `--uacomment` comments, `/kaspad:2.0(a; b)/`. Only reachable with
    /// `--allow-uacomment`: comments make a node unique on the network.
    pub fn add_user_agent_comments(&mut self, comments: &[String]) {
        if comments.is_empty() {
            return;
        }
        let base = self.user_agent.trim_end_matches('/').to_string();
        self.user_agent = format!("{}({})/", base, comments.join("; "));
        self.user_agent.truncate(self.user_agent.floor_char_boundary(MAX_USER_AGENT_LEN));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_is_name_major_minor_only() {
        assert_eq!(uniform_user_agent("kaspad", "2.0.1"), "/kaspad:2.0/");
        assert_eq!(uniform_user_agent("kaspad", "2.1.0-rc.3"), "/kaspad:2.1/");
        let mut v = Version::new(None, PeerId::default(), "zkas-devnet".into(), None, 11);
        assert_eq!(v.user_agent, uniform_user_agent(name(), version()));
        assert!(!v.user_agent.contains(version()) || version().matches('.').count() < 2);
        v.add_user_agent_comments(&["pool".to_string()]);
        assert!(v.user_agent.ends_with("(pool)/"));
    }

    #[test]
    fn timestamp_is_whole_seconds() {
        let v = Version::new(None, PeerId::default(), "zkas-devnet".into(), None, 11);
        assert_eq!(v.timestamp % 1000, 0);
        assert!(unix_now() - v.timestamp < 2000);
    }
}
