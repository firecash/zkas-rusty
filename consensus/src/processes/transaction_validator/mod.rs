pub mod errors;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
pub mod tx_validation_in_utxo_context;
use std::sync::Arc;

use kaspa_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use kaspa_consensus_core::{
    KType,
    config::params::{ForkActivation, ForkedParam},
    mass::MassCalculator,
};

/// Entries in the shielded verdict cache (N1, spec 08 R1.3.4; was 2,000).
pub const SHIELDED_VERIFY_CACHE_ENTRIES: usize = 65_536;

#[derive(Clone)]
pub struct TransactionValidator {
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    max_signature_script_len: ForkedParam<usize>,
    max_script_public_key_len: usize,
    coinbase_payload_script_public_key_max_len: u8,
    coinbase_maturity: u64,
    ghostdag_k: KType,
    sig_cache: Cache<SigCacheKey, bool>,
    /// Verdicts of Halo 2 bundle verification, keyed by transaction id.
    ///
    /// Verifying a shielded bundle is the most expensive per-byte operation in the system
    /// — and it was repeated for every transaction at mempool admission, on every block
    /// template build, and again at block validation, with nothing remembered in between.
    /// A miner rebuilding a template about once a second re-verified the entire mempool
    /// each time.
    ///
    /// Caching by txid is sound because the verdict is a pure function of bytes the txid
    /// already commits to: the payload carries the bundle, and the sighash context is
    /// version + subnetwork id + lock time + gas, every one of which is hashed into the
    /// id. Two transactions with the same id therefore verify identically, forever.
    ///
    /// Only successes are cached. Caching failures let a stream of distinct garbage txids
    /// evict the resident successes from this count-bounded, randomly evicting cache, so
    /// every template build re-verified the mempool. Re-offers of one bad txid are stopped by
    /// the relay flow's dedup and by the `InvalidShieldedProof` peer penalty instead.
    /// `u8` rather than `bool` only because the cache requires `MemSizeEstimator`, which is
    /// implemented for the integer primitives and not for `bool`. Always 1.
    shielded_verify_cache: kaspa_database::prelude::Cache<kaspa_consensus_core::tx::TransactionId, u8>,
    toccata_activation: ForkActivation,
    /// See `Params::security_fork_activation`. Defaults to never; set via
    /// [`TransactionValidator::with_security_fork_activation`].
    security_fork_activation: ForkActivation,
    mass_per_sig_op: u64,
    /// Per-network domain separator bound into the shielded-transaction sighash
    /// (the genesis hash). Prevents a shielded bundle valid on one network from
    /// being replayed on another (PLAN §3, replay protection).
    shielded_network_domain: [u8; 32],

    pub(crate) mass_calculator: MassCalculator,
}

impl TransactionValidator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: impl Into<ForkedParam<usize>>,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
        mass_calculator: MassCalculator,
        toccata_activation: ForkActivation,
        mass_per_sig_op: u64,
        shielded_network_domain: [u8; 32],
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len: max_signature_script_len.into(),
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            // Sized to the mempool's turnover at full load, not to one template (N1, spec 08
            // R1.3.4): ~26 txs/s x 600 s anchor maturity = ~15,600 txs; 2,000 entries covered 77 s
            // of full-load two-action traffic, so mempool-verified txs were re-verified at block
            // time. Only txids are stored (32 B key + 1 B), ~4-6 MB at capacity.
            shielded_verify_cache: kaspa_database::prelude::Cache::new(kaspa_database::prelude::CachePolicy::Count(
                SHIELDED_VERIFY_CACHE_ENTRIES,
            )),
            mass_calculator,
            toccata_activation,
            security_fork_activation: ForkActivation::never(),
            mass_per_sig_op,
            shielded_network_domain,
        }
    }

    pub fn with_security_fork_activation(mut self, activation: ForkActivation) -> Self {
        self.security_fork_activation = activation;
        self
    }

    pub fn new_for_tests(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: impl Into<ForkedParam<usize>>,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len: max_signature_script_len.into(),
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            // Sized to the mempool's turnover at full load, not to one template (N1, spec 08
            // R1.3.4): ~26 txs/s x 600 s anchor maturity = ~15,600 txs; 2,000 entries covered 77 s
            // of full-load two-action traffic, so mempool-verified txs were re-verified at block
            // time. Only txids are stored (32 B key + 1 B), ~4-6 MB at capacity.
            shielded_verify_cache: kaspa_database::prelude::Cache::new(kaspa_database::prelude::CachePolicy::Count(
                SHIELDED_VERIFY_CACHE_ENTRIES,
            )),
            mass_calculator: MassCalculator::new(0, 0, 0),
            toccata_activation: ForkActivation::never(),
            security_fork_activation: ForkActivation::never(),
            mass_per_sig_op: 0,
            shielded_network_domain: [0u8; 32],
        }
    }
}
