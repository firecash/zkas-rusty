pub mod bps;
pub mod constants;
pub mod genesis;
pub mod params;

use kaspa_utils::networking::{ContextualNetAddress, NetAddress};

#[cfg(feature = "devnet-prealloc")]
use crate::utxo::utxo_collection::UtxoCollection;
#[cfg(feature = "devnet-prealloc")]
use std::sync::Arc;

use std::ops::Deref;

use {
    constants::perf::{PERF_PARAMS, PerfParams},
    params::Params,
};

/// Various consensus configurations all bundled up under a single struct. Use `Config::new` for directly building from
/// a `Params` instance. For anything more complex it is recommended to use `ConfigBuilder`. NOTE: this struct can be
/// implicitly de-refed into `Params`
#[derive(Clone, Debug)]
pub struct Config {
    /// Consensus params
    pub params: Params,
    /// Performance params
    pub perf: PerfParams,

    //
    // Additional consensus configuration arguments which are not consensus sensitive
    //
    pub process_genesis: bool,

    /// Indicates whether this node is an archival node
    pub is_archival: bool,

    /// Whether to fetch the shielded note history below the pruning point from peers.
    ///
    /// `None` means "follow `is_archival`", which is the right default in both directions: an
    /// archival node claims to hold everything and would otherwise silently serve wallets a
    /// partial balance, while an ordinary node should not spend ~234 MB and a verification pass
    /// on history it does not intend to serve.
    ///
    /// Explicit `Some(true)` matters for a PRUNED wallet-serving node: the scan archive and the
    /// selected-chain index both survive pruning by design, so such a node can hold and serve
    /// complete note history without being archival. Without this flag it had no way to ask.
    pub shielded_history: Option<bool>,

    /// Enable various sanity checks which might be compute-intensive (mostly performed during pruning)
    pub enable_sanity_checks: bool,

    // TODO: move non-consensus parameters like utxoindex to a higher scoped Config
    /// Enable the UTXO index
    pub utxoindex: bool,

    /// Enable RPC commands which affect the state of the node
    pub unsafe_rpc: bool,

    /// Ban (for the address store's 24 hours) a peer whose error proves it broke the wire protocol
    /// itself, as opposed to disagreeing with us. Off by default; see
    /// `ProtocolError::is_auto_ban_eligible` for what qualifies and why consensus rejections never do.
    pub enable_banning: bool,

    /// N1 (spec 08 R1.4.4): ban (24 h) a peer that relays a shielded transaction whose proof or
    /// signatures fail, unless it advertises a newer protocol or release. ON by default, unlike
    /// `enable_banning`; `--no-ban-shielded` turns it off.
    pub ban_invalid_shielded_proofs: bool,

    /// Allow the node to accept blocks from RPC while not synced
    /// (required when initiating a new network from genesis)
    pub enable_unsynced_mining: bool,

    /// Allow mainnet mining. Until a stable Beta version we keep this option off by default
    pub enable_mainnet_mining: bool,

    pub user_agent_comments: Vec<String>,

    /// User agent admission rules.
    pub user_agent_rules: Vec<String>,

    /// If undefined, sets it to 0.0.0.0
    pub p2p_listen_address: ContextualNetAddress,

    pub externalip: Option<NetAddress>,

    pub block_template_cache_lifetime: Option<u64>,

    #[cfg(feature = "devnet-prealloc")]
    pub initial_utxo_set: Arc<UtxoCollection>,

    pub disable_upnp: bool,

    /// A scale factor to apply to memory allocation bounds
    pub ram_scale: f64,

    /// The number of days to keep data for
    pub retention_period_days: Option<f64>,
}

impl Config {
    /// Whether this node should obtain shielded note history below its pruning point.
    ///
    /// **Defaults to ON for every node**, archival or not.
    ///
    /// It used to default to `is_archival`, on the reasoning that "a non-archival node should not
    /// pay for history it will not serve". That reasoning priced the wrong thing. Measured on a
    /// fresh pruned sync 2026-08-22 at 968,613 chain blocks, the shielded scan archive is
    /// **499 MiB** (540 B mean per block) against a 1.5 GiB total database — a large SHARE of a
    /// pruned node, but a small absolute cost, and roughly a twentieth of what `--archival`'s
    /// block bodies ask for. Tying that decision to the archival one made history rare when it
    /// needs to be ubiquitous.
    ///
    /// (An earlier note here said 232 MB / 2.35%. That was measured on an ARCHIVAL node at
    /// 861,987 blocks; the archive has since roughly doubled with the chain, and the percentage
    /// was never the right comparison for a pruned node.)
    ///
    /// The failure that default produced is not hypothetical. Every node that fast-syncs with
    /// defaults holds no history below its own pruning point, so pre-pruning-point note data —
    /// which is USER FUNDS DATA, and is not recoverable from the network once lost — survives
    /// only on the handful of machines that happened to be running when those blocks were mined.
    /// Defaulting on is what makes the network, rather than two servers, the place history lives.
    ///
    /// Turn it off explicitly (`--shielded-history=off`) for a node that will never serve wallets.
    pub fn wants_shielded_history(&self) -> bool {
        self.shielded_history.unwrap_or(true)
    }

    pub fn new(params: Params) -> Self {
        Self::with_perf(params, PERF_PARAMS)
    }

    pub fn with_perf(params: Params, perf: PerfParams) -> Self {
        Self {
            params,
            perf,
            process_genesis: true,
            is_archival: false,
            shielded_history: None,
            enable_sanity_checks: false,
            utxoindex: false,
            unsafe_rpc: false,
            enable_banning: false,
            ban_invalid_shielded_proofs: true,
            enable_unsynced_mining: false,
            enable_mainnet_mining: false,
            user_agent_comments: Default::default(),
            user_agent_rules: Default::default(),
            externalip: None,
            p2p_listen_address: ContextualNetAddress::unspecified(),
            block_template_cache_lifetime: None,

            #[cfg(feature = "devnet-prealloc")]
            initial_utxo_set: Default::default(),
            disable_upnp: false,
            ram_scale: 1.0,
            retention_period_days: None,
        }
    }

    pub fn to_builder(&self) -> ConfigBuilder {
        ConfigBuilder { config: self.clone() }
    }
}

impl AsRef<Params> for Config {
    fn as_ref(&self) -> &Params {
        &self.params
    }
}

impl Deref for Config {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new(params: Params) -> Self {
        Self { config: Config::new(params) }
    }

    pub fn set_perf_params(mut self, perf: PerfParams) -> Self {
        self.config.perf = perf;
        self
    }

    pub fn adjust_perf_params_to_consensus_params(mut self) -> Self {
        self.config.perf.adjust_to_consensus_params(&self.config.params);
        self
    }

    pub fn edit_consensus_params<F>(mut self, edit_func: F) -> Self
    where
        F: Fn(&mut Params),
    {
        edit_func(&mut self.config.params);
        self
    }

    pub fn apply_args<F>(mut self, edit_func: F) -> Self
    where
        F: Fn(&mut Config),
    {
        edit_func(&mut self.config);
        self
    }

    pub fn skip_proof_of_work(mut self) -> Self {
        self.config.params.skip_proof_of_work = true;
        self
    }

    pub fn set_archival(mut self) -> Self {
        self.config.is_archival = true;
        self
    }

    pub fn enable_sanity_checks(mut self) -> Self {
        self.config.enable_sanity_checks = true;
        self
    }

    pub fn skip_adding_genesis(mut self) -> Self {
        self.config.process_genesis = false;
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}
