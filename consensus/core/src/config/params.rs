pub use super::{
    bps::{Bps, TenBps},
    constants::consensus::*,
    genesis::{DEVNET_GENESIS, GENESIS, GenesisBlock, SIMNET_GENESIS, TESTNET_GENESIS},
};
use crate::{
    BlockLevel, KType,
    constants::{BLOCK_VERSION, STORAGE_MASS_PARAMETER, TOCCATA_BLOCK_VERSION},
    mass::{BlockLaneLimits, BlockMassLimits, MassCofactors},
    network::{NetworkId, NetworkType},
};
use kaspa_addresses::Prefix;
use kaspa_math::Uint256;
use serde::{Deserialize, Serialize};
use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};

const MEMPOOL_BLOCK_MASS_ACTIVATION_DELAY_SECONDS: u64 = 24 * 60 * 60;
const PRIOR_MAX_SIGNATURE_SCRIPT_LEN: usize = 10_000;
// Increased for stark proofs. This value is effectively covered by the post-Toccata
// transient block mass limit: 1_000_000 transient mass / 4 grams-per-byte = 250_000
// bytes for the entire block, so a larger signature script cannot be accepted anyway.
// TODO(post-toccata): check whether this early signature-script length guard can be
// removed entirely, or whether it remains useful as cheap early protection.
const NEW_MAX_SIGNATURE_SCRIPT_LEN: usize = 250_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkActivation(u64);

impl ForkActivation {
    const NEVER: u64 = u64::MAX;
    const ALWAYS: u64 = 0;

    pub const fn new(daa_score: u64) -> Self {
        Self(daa_score)
    }

    pub const fn never() -> Self {
        Self(Self::NEVER)
    }

    pub const fn always() -> Self {
        Self(Self::ALWAYS)
    }

    /// Returns the actual DAA score triggering the activation. Should be used only
    /// for cases where the explicit value is required for computations (e.g., coinbase subsidy).
    /// Otherwise, **activation checks should always go through `self.is_active(..)`**
    pub fn daa_score(self) -> u64 {
        self.0
    }

    pub fn is_active(self, current_daa_score: u64) -> bool {
        current_daa_score >= self.0
    }

    pub fn delayed_by(self, daa_score_delta: u64) -> Self {
        match self.0 {
            Self::ALWAYS | Self::NEVER => self,
            daa_score => Self(daa_score.saturating_add(daa_score_delta)),
        }
    }

    pub fn early_by(self, daa_score_delta: u64) -> Self {
        match self.0 {
            Self::ALWAYS | Self::NEVER => self,
            daa_score => Self(daa_score.saturating_sub(daa_score_delta)),
        }
    }

    /// Checks if the fork was "recently" activated, i.e., in the time frame of the provided range.
    /// This function returns false for forks that were always active, since they were never activated.
    pub fn is_within_range_from_activation(self, current_daa_score: u64, range: u64) -> bool {
        self != Self::always() && self.is_active(current_daa_score) && current_daa_score < self.0 + range
    }

    /// Checks if the fork is expected to be activated "soon", i.e., in the time frame of the provided range.
    /// Returns the distance from activation if so, or `None` otherwise.
    pub fn is_within_range_before_activation(self, current_daa_score: u64, range: u64) -> Option<u64> {
        if !self.is_active(current_daa_score) && current_daa_score + range > self.0 { Some(self.0 - current_daa_score) } else { None }
    }
}

/// A consensus parameter which depends on forking activation
#[derive(Clone, Copy, Debug)]
pub struct ForkedParam<T: Copy> {
    pre: T,
    post: T,
    activation: ForkActivation,
}

impl<T: Copy> ForkedParam<T> {
    const fn new(pre: T, post: T, activation: ForkActivation) -> Self {
        Self { pre, post, activation }
    }

    pub const fn new_const(val: T) -> Self {
        Self { pre: val, post: val, activation: ForkActivation::never() }
    }

    pub fn activation(&self) -> ForkActivation {
        self.activation
    }

    pub fn get(&self, daa_score: u64) -> T {
        if self.activation.is_active(daa_score) { self.post } else { self.pre }
    }

    pub fn with_delayed_activation(&self, delay_daa_score: u64) -> Self {
        Self::new(self.pre, self.post, self.activation.delayed_by(delay_daa_score))
    }

    /// Returns the value before activation (=pre unless activation = always)
    pub fn before(&self) -> T {
        match self.activation.0 {
            ForkActivation::ALWAYS => self.post,
            _ => self.pre,
        }
    }

    /// Returns the permanent long-term value after activation (=post unless the activation is never scheduled)
    pub fn after(&self) -> T {
        match self.activation.0 {
            ForkActivation::NEVER => self.pre,
            _ => self.post,
        }
    }

    /// Returns the configured post-fork value regardless of whether activation is scheduled.
    pub fn raw_post(&self) -> T {
        self.post
    }

    /// Maps the ForkedParam<T> to a new ForkedParam<U> by applying a map function on both pre and post
    pub fn map<U: Copy, F: Fn(T) -> U>(&self, f: F) -> ForkedParam<U> {
        ForkedParam::new(f(self.pre), f(self.post), self.activation)
    }
}

impl<T: Copy> From<T> for ForkedParam<T> {
    fn from(value: T) -> Self {
        Self::new_const(value)
    }
}

impl<T: Copy + Ord> ForkedParam<T> {
    /// Returns the min of `pre` and `post` values. Useful for non-consensus initializations
    /// which require knowledge of the value bounds.
    ///
    /// Note that if activation is not scheduled (set to never) then pre is always returned,
    /// and if activation is set to always (since inception), post will be returned.
    pub fn lower_bound(&self) -> T {
        match self.activation.0 {
            ForkActivation::NEVER => self.pre,
            ForkActivation::ALWAYS => self.post,
            _ => self.pre.min(self.post),
        }
    }

    /// Returns the max of `pre` and `post` values. Useful for non-consensus initializations
    /// which require knowledge of the value bounds.
    ///
    /// Note that if activation is not scheduled (set to never) then pre is always returned,
    /// and if activation is set to always (since inception), post will be returned.
    pub fn upper_bound(&self) -> T {
        match self.activation.0 {
            ForkActivation::NEVER => self.pre,
            ForkActivation::ALWAYS => self.post,
            _ => self.pre.max(self.post),
        }
    }
}

/// Blockrate-related consensus params.
/// Grouped together under a single struct because they are logically related and
/// in order to easily support **future BPS acceleration hardforks** (by simply adding
/// a forked instance of blockrate params to the main [`Params`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockrateParams {
    pub target_time_per_block: u64, // (milliseconds)
    pub ghostdag_k: KType,
    pub past_median_time_sample_rate: u64,
    pub difficulty_sample_rate: u64,
    pub max_block_parents: u8,
    pub mergeset_size_limit: u64,
    pub merge_depth: u64,
    pub finality_depth: u64,
    pub pruning_depth: u64,
    pub coinbase_maturity: u64,
    /// Shielded-spend anchor maturity in blue-score units (PLAN §2.5): a mined
    /// shielded note is spendable once its minting block is this deep below the
    /// sink. Set to ~10 minutes of blocks (`600 * BPS`), independent of
    /// `finality_depth`, so spends do not have to wait the full finality window.
    pub shielded_anchor_depth: u64,
    /// Maximum shielded-spend anchor age in blue-score units (security audit
    /// F-04/F-05): a spend proving against an anchor older than this is dropped
    /// on every node class. Must satisfy
    /// `shielded_anchor_depth < max_shielded_anchor_age < pruning_depth - finality_depth`
    /// (compile-time asserted in [`BlockrateParams::new`]). The upper bound is
    /// what makes anchor finality a pure function of replicated data: any
    /// in-window anchor's source block is necessarily younger than every synced
    /// node's pruning point, so its ghostdag/reachability data exists on full,
    /// pruned AND IBD-seeded nodes alike — validation can fail closed on missing
    /// data without any risk of wedging the chain. Set to `pruning_depth / 4`
    /// (~7.5 hours of blocks on all four networks).
    pub max_shielded_anchor_age: u64,
}

impl BlockrateParams {
    pub const fn new<const BPS: u64>() -> Self {
        // F-04/F-05: bound the anchor validity window from above by a value
        // strictly below the pruning depth (with a finality-depth margin), so an
        // in-window anchor's source block always has ghostdag/reachability data
        // on every synced node (full, pruned or IBD-seeded). `new` is const and
        // evaluated for every network's params, so these asserts are compile-time
        // guarantees for all four networks.
        let max_shielded_anchor_age = Bps::<BPS>::pruning_depth() / 4;
        assert!(600 * BPS < max_shielded_anchor_age, "shielded_anchor_depth must be below max_shielded_anchor_age");
        assert!(
            max_shielded_anchor_age < Bps::<BPS>::pruning_depth() - Bps::<BPS>::finality_depth(),
            "max_shielded_anchor_age must be below pruning_depth - finality_depth"
        );
        Self {
            target_time_per_block: Bps::<BPS>::target_time_per_block(),
            ghostdag_k: Bps::<BPS>::ghostdag_k(),
            past_median_time_sample_rate: Bps::<BPS>::past_median_time_sample_rate(),
            difficulty_sample_rate: Bps::<BPS>::difficulty_adjustment_sample_rate(),
            max_block_parents: Bps::<BPS>::max_block_parents(),
            mergeset_size_limit: Bps::<BPS>::mergeset_size_limit(),
            merge_depth: Bps::<BPS>::merge_depth_bound(),
            finality_depth: Bps::<BPS>::finality_depth(),
            pruning_depth: Bps::<BPS>::pruning_depth(),
            coinbase_maturity: Bps::<BPS>::coinbase_maturity(),
            // ~10 minutes of blocks: shielded-spend maturity (PLAN §2.5).
            shielded_anchor_depth: 600 * BPS,
            // ~7.5 hours of blocks: shielded-spend maximum anchor age (F-04/F-05).
            max_shielded_anchor_age,
        }
    }

    pub const fn increase_max_block_parents(mut self, max_block_parents: u8) -> Self {
        if self.max_block_parents < max_block_parents {
            self.max_block_parents = max_block_parents;
        }
        self
    }

    /// Override the finality depth (and hence the shielded finalized-anchor window,
    /// PLAN §2.5). Used by non-mainnet networks that need spends to reference a
    /// finalized anchor within a short chain — a full 12-hour (432000-block)
    /// finality makes an in-session shielded spend infeasible. Leaves every other
    /// blockrate param untouched, mirroring the `finality_depth = N` test override.
    pub const fn with_finality_depth(mut self, finality_depth: u64) -> Self {
        self.finality_depth = finality_depth;
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideParams {
    /// Timestamp deviation tolerance (in seconds)
    pub timestamp_deviation_tolerance: Option<u64>,

    /// Size of the sampled block window that is used to calculate the past median time of each block
    pub past_median_time_window_size: Option<usize>,

    /// Size of the sampled block window that is used to calculate the required difficulty of each block
    pub difficulty_window_size: Option<usize>,

    /// The minimum size a difficulty window (full or sampled) must have to trigger a DAA calculation
    pub min_difficulty_window_size: Option<usize>,

    pub coinbase_payload_script_public_key_max_len: Option<u8>,
    pub max_coinbase_payload_len: Option<usize>,

    pub max_tx_inputs: Option<usize>,
    pub max_tx_outputs: Option<usize>,
    pub prior_max_signature_script_len: Option<usize>,
    pub new_max_signature_script_len: Option<usize>,
    pub max_script_public_key_len: Option<usize>,
    pub mass_per_tx_byte: Option<u64>,
    pub mass_per_script_pub_key_byte: Option<u64>,
    pub mass_per_sig_op: Option<u64>,
    pub prior_block_mass_limits: Option<BlockMassLimits>,
    pub new_transient_mass_limit: Option<u64>,
    pub block_lane_limits: Option<BlockLaneLimits>,

    /// The parameter for scaling inverse KAS value to mass units (KIP-0009)
    pub storage_mass_parameter: Option<u64>,

    /// DAA score after which the pre-deflationary period switches to the deflationary period
    pub deflationary_phase_daa_score: Option<u64>,

    pub pre_deflationary_phase_base_subsidy: Option<u64>,
    pub skip_proof_of_work: Option<bool>,
    pub max_block_level: Option<BlockLevel>,
    pub pruning_proof_m: Option<u64>,

    /// Blockrate-related params
    pub blockrate: Option<BlockrateParams>,

    /// Target time per block prior to the crescendo hardfork (in milliseconds)
    pub pre_crescendo_target_time_per_block: Option<u64>,

    /// Crescendo activation DAA score
    pub crescendo_activation: Option<ForkActivation>,

    pub toccata_activation: Option<ForkActivation>,

    /// Merged-mining (AuxPoW) activation DAA score. Before this score only native
    /// kHeavyHash PoW is accepted; at/after it a block may satisfy PoW via a valid
    /// AuxPoW proof (Option-2 dual acceptance).
    pub merged_mining_activation: Option<ForkActivation>,

    /// Whether the coinbase mints its reward into the shielded pool (private-by-default
    /// networks) rather than as a transparent output. Overridable so tests can exercise
    /// the shielded pipeline on a small-pruning simnet base (which is otherwise
    /// transparent-coinbase).
    pub shielded_coinbase: Option<bool>,
}

impl From<Params> for OverrideParams {
    fn from(p: Params) -> Self {
        Self {
            timestamp_deviation_tolerance: Some(p.timestamp_deviation_tolerance),
            pre_crescendo_target_time_per_block: Some(p.pre_crescendo_target_time_per_block),
            difficulty_window_size: Some(p.difficulty_window_size),
            past_median_time_window_size: Some(p.past_median_time_window_size),
            min_difficulty_window_size: Some(p.min_difficulty_window_size),
            coinbase_payload_script_public_key_max_len: Some(p.coinbase_payload_script_public_key_max_len),
            max_coinbase_payload_len: Some(p.max_coinbase_payload_len),
            max_tx_inputs: Some(p.max_tx_inputs),
            max_tx_outputs: Some(p.max_tx_outputs),
            prior_max_signature_script_len: Some(p.prior_max_signature_script_len),
            new_max_signature_script_len: Some(p.new_max_signature_script_len),
            max_script_public_key_len: Some(p.max_script_public_key_len),
            mass_per_tx_byte: Some(p.mass_per_tx_byte),
            mass_per_script_pub_key_byte: Some(p.mass_per_script_pub_key_byte),
            mass_per_sig_op: Some(p.mass_per_sig_op),
            prior_block_mass_limits: Some(p.prior_block_mass_limits),
            new_transient_mass_limit: Some(p.new_transient_mass_limit),
            block_lane_limits: Some(p.block_lane_limits),
            storage_mass_parameter: Some(p.storage_mass_parameter),
            deflationary_phase_daa_score: Some(p.deflationary_phase_daa_score),
            pre_deflationary_phase_base_subsidy: Some(p.pre_deflationary_phase_base_subsidy),
            skip_proof_of_work: Some(p.skip_proof_of_work),
            max_block_level: Some(p.max_block_level),
            pruning_proof_m: Some(p.pruning_proof_m),
            blockrate: Some(p.blockrate),
            crescendo_activation: Some(p.crescendo_activation),
            toccata_activation: Some(p.toccata_activation),
            merged_mining_activation: Some(p.merged_mining_activation),
            shielded_coinbase: Some(p.shielded_coinbase),
        }
    }
}

/// Consensus parameters. Contains settings and configurations which are consensus-sensitive.
/// Changing one of these on a network node would exclude and prevent it from reaching consensus
/// with the other unmodified nodes.
#[derive(Clone, Debug)]
pub struct Params {
    pub dns_seeders: &'static [&'static str],
    pub net: NetworkId,
    pub genesis: GenesisBlock,

    /// Timestamp deviation tolerance (in seconds)
    pub timestamp_deviation_tolerance: u64,

    /// Defines the highest allowed proof of work difficulty value for a block as a [`Uint256`]
    pub max_difficulty_target: Uint256,

    /// Highest allowed proof of work difficulty as a floating number
    pub max_difficulty_target_f64: f64,

    /// Size of the sampled block window that is used to calculate the past median time of each block
    pub past_median_time_window_size: usize,

    /// Size of the sampled block window that is used to calculate the required difficulty of each block
    pub difficulty_window_size: usize,

    /// The minimum size a difficulty window must have to trigger a DAA calculation
    pub min_difficulty_window_size: usize,

    pub coinbase_payload_script_public_key_max_len: u8,
    pub max_coinbase_payload_len: usize,

    /// zkas: when true, the coinbase creates **no transparent outputs**; the
    /// block reward (subsidy + fees per rewarded block) enters the mandatory
    /// shielded pool as coinbase notes, minted in the virtual processor (PLAN
    /// §2.7). The miner's shielded (Orchard) address is carried in the reward's
    /// `script_public_key` bytes. When false, classic transparent coinbase.
    pub shielded_coinbase: bool,

    pub max_tx_inputs: usize,
    pub max_tx_outputs: usize,
    pub prior_max_signature_script_len: usize,
    pub new_max_signature_script_len: usize,
    pub max_script_public_key_len: usize,

    pub mass_per_tx_byte: u64,
    pub mass_per_script_pub_key_byte: u64,
    pub mass_per_sig_op: u64,
    pub prior_block_mass_limits: BlockMassLimits,
    pub new_transient_mass_limit: u64,
    pub block_lane_limits: BlockLaneLimits,

    /// The parameter for scaling inverse KAS value to mass units (KIP-0009)
    pub storage_mass_parameter: u64,

    /// DAA score after which the pre-deflationary period switches to the deflationary period
    pub deflationary_phase_daa_score: u64,

    pub pre_deflationary_phase_base_subsidy: u64,
    pub skip_proof_of_work: bool,
    pub max_block_level: BlockLevel,
    pub pruning_proof_m: u64,

    /// Blockrate-related params
    pub blockrate: BlockrateParams,

    /// Target time per block prior to the crescendo hardfork (in milliseconds).
    /// Required permanently in order to calculate the subsidy month from the current DAA score
    pub pre_crescendo_target_time_per_block: u64,

    /// Crescendo activation DAA score
    pub crescendo_activation: ForkActivation,

    pub toccata_activation: ForkActivation,
    /// Activation of the reorg-safe shielded anchor resolution (multi-producer index).
    ///
    /// Before: an anchor resolves through the single-valued, last-write-wins `anchor_block`
    /// index, so a block that was briefly on the selected chain and then reorged out can
    /// overwrite the canonical producer's entry and make every node that witnessed that reorg
    /// drop spends the rest of the network keeps. After: an anchor is final if ANY block that
    /// produced it is a chain ancestor in the maturity window, which is derivable from
    /// canonical data alone and therefore identical on every node.
    ///
    /// This changes the validity of historical blocks, so it must be scheduled: nodes disagree
    /// across the boundary unless they upgrade. Set to `never()` until a height is chosen.
    pub shielded_anchor_multi_activation: ForkActivation,

    /// Dev-fee accrual activation DAA score.
    ///
    /// Before this score the dev fee is minted as its own coinbase note in **every**
    /// block. Measured on mainnet, that is exactly 1.00 note per chain block and
    /// **32.8% of all note creation** — the single largest contributor to permanent
    /// note-commitment-tree growth, and why a dev treasury accumulates one note per
    /// second (a payout of 47,159 such notes needed 9,006 spends).
    ///
    /// At/after this score the cut is carried in the per-block accrual
    /// (`ShieldedDevAccrued`) and paid as one note whenever the block's DAA score
    /// crosses a multiple of [`Self::dev_fee_payout_interval`]. Total emission is
    /// unchanged — the same value is paid, just batched — but it is *minted later*,
    /// so cumulative supply lags by at most one interval's worth of dev fee.
    ///
    /// Changes the coinbase of every block, so it must be scheduled: nodes disagree
    /// across the boundary unless they upgrade. `never()` until a height is chosen.
    /// Shielded coinbase note-seed activation DAA score (defect **F-02**).
    ///
    /// Before this score a coinbase note is derived from `coinbase_txid || output_index`
    /// alone. Two *sibling* blocks — same selected parent, same mergeset, same miner —
    /// build a byte-identical coinbase (the payload carries blue score, subsidy, the
    /// **parent's** shielded commitment and the miner script; all four match), so they
    /// share a txid, mint identical notes and therefore produce an **identical shielded
    /// tree root**. Measured on mainnet: canonical `da8dfb9d` and orphan `e6f50b47`
    /// share coinbase txid `6035c646…`. That collision is what made `anchor_block`
    /// order-dependent and wedged fresh nodes (§1).
    ///
    /// At/after this score the block's own hash is mixed into the seed, so no two blocks
    /// can produce the same root and the anchor index is injective by construction. No
    /// circularity: a block's coinbase commits its *parent's* shielded root, never its
    /// own notes.
    ///
    /// Changes note derivation, so **every** re-derivation site must gate on the same
    /// score — consensus, `shielded-wallet::effects`, walletd and shielded-pay. Scanning
    /// a pre-fork block must keep using the old seed forever, or a wallet silently
    /// mis-derives historical mining rewards.
    pub shielded_coinbase_seed_activation: ForkActivation,

    pub dev_fee_accrual_activation: ForkActivation,

    /// DAA-score interval between dev-fee payouts once accrual is active. A payout
    /// happens in the first block whose DAA score crosses a multiple of this value,
    /// judged against its selected parent's score — so the rule is per-block and
    /// deterministic even though a DAG block's score can jump by more than one.
    pub dev_fee_payout_interval: u64,

    /// Merged-mining (AuxPoW) activation DAA score. Before this score a block must
    /// clear the native kHeavyHash PoW; at/after it a block may instead carry a valid
    /// AuxPoW proof whose parent kHeavyHash clears our target (Option-2 dual acceptance).
    pub merged_mining_activation: ForkActivation,

    /// ZKas launch difficulty schedule — number of blocks (blue-score units) at the
    /// start of the chain during which difficulty is **pinned** to the genesis target
    /// (super-easy) so the chain can be bootstrap-mined on CPU. `0` (together with
    /// `difficulty_ramp_blocks == 0`) disables the schedule.
    pub low_difficulty_start_blocks: u64,

    /// ZKas launch difficulty schedule — number of blocks (blue-score units) after the
    /// low-difficulty start window over which the difficulty *ceiling* tightens geometrically from the
    /// genesis target toward real difficulty. After this ramp the ceiling is lifted and the
    /// pure DAA governs, so post-launch blocks are **not** easily mined. `0` disables the
    /// entire launch schedule (upstream KIP-0004 behaviour).
    pub difficulty_ramp_blocks: u64,

    /// ZKas dev fee: parts-per-1000 of each rewarded block's **subsidy** (not fees)
    /// diverted to [`Self::dev_fee_recipient`] as an extra coinbase note. `0` disables.
    /// Consensus-critical: it changes the coinbase every node reconstructs.
    pub dev_fee_permille: u64,

    /// ZKas dev fee recipient: raw 43-byte Orchard address the dev fee is minted to.
    /// `None` disables the dev fee regardless of `dev_fee_permille`. Only meaningful on a
    /// `shielded_coinbase` network (the recipient is a shielded address).
    pub dev_fee_recipient: Option<[u8; 43]>,
}

impl Params {
    /// Blue score at and below which difficulty is pinned to the (super-easy) genesis
    /// target during the low-difficulty start. See [`Self::difficulty_ramp_end_blue_score`].
    #[inline]
    #[must_use]
    pub fn low_difficulty_end_blue_score(&self) -> u64 {
        self.low_difficulty_start_blocks
    }

    /// Blue score at and above which the launch difficulty ceiling is fully lifted and the
    /// pure DAA governs difficulty. Returns `0` — meaning the launch schedule is disabled —
    /// when `difficulty_ramp_blocks == 0`.
    #[inline]
    #[must_use]
    pub fn difficulty_ramp_end_blue_score(&self) -> u64 {
        if self.difficulty_ramp_blocks == 0 { 0 } else { self.low_difficulty_start_blocks.saturating_add(self.difficulty_ramp_blocks) }
    }
    /// Returns the past median time sample rate
    #[inline]
    #[must_use]
    pub fn past_median_time_sample_rate(&self) -> u64 {
        self.blockrate.past_median_time_sample_rate
    }

    /// Returns the difficulty sample rate
    #[inline]
    #[must_use]
    pub fn difficulty_sample_rate(&self) -> u64 {
        self.blockrate.difficulty_sample_rate
    }

    /// Returns the target time per block (milliseconds)
    #[inline]
    #[must_use]
    pub fn target_time_per_block(&self) -> u64 {
        self.blockrate.target_time_per_block
    }

    /// Returns the expected number of blocks per second
    #[inline]
    #[must_use]
    pub fn bps(&self) -> u64 {
        1000 / self.blockrate.target_time_per_block
    }

    /// Returns the expected number of blocks per second throughout history (currently represented as [`ForkedParam`]).
    /// Required permanently in order to calculate the subsidy month from the current DAA score.
    #[inline]
    #[must_use]
    pub fn bps_history(&self) -> ForkedParam<u64> {
        ForkedParam::new(
            1000 / self.pre_crescendo_target_time_per_block,
            1000 / self.blockrate.target_time_per_block,
            self.crescendo_activation,
        )
    }

    /// Returns the forked per-dimension block mass limits.
    #[inline]
    #[must_use]
    pub fn block_mass_limits(&self) -> ForkedParam<BlockMassLimits> {
        let mut new_block_mass_limits = self.prior_block_mass_limits;
        new_block_mass_limits.transient = self.new_transient_mass_limit;
        ForkedParam::new(self.prior_block_mass_limits, new_block_mass_limits, self.toccata_activation)
    }

    /// Returns the forked cofactors for normalizing block mass dimensions.
    #[inline]
    #[must_use]
    pub fn block_mass_cofactors(&self) -> ForkedParam<MassCofactors> {
        self.block_mass_limits().map(|limits| limits.cofactors())
    }

    /// Returns the block mass limits used for mempool policy.
    ///
    /// Mempool policy lags the consensus transient mass relaxation, so transactions
    /// near activation are normalized by the stricter pre-activation limits.
    #[inline]
    #[must_use]
    pub fn mempool_block_mass_limits(&self) -> ForkedParam<BlockMassLimits> {
        let block_mass_limits = self.block_mass_limits();
        let prior_limits = block_mass_limits.before();
        let new_limits = block_mass_limits.after();
        assert_eq!(
            new_limits.compute, prior_limits.compute,
            "delaying mempool mass activation assumes the compute mass limit does not change"
        );
        assert_eq!(
            new_limits.storage, prior_limits.storage,
            "delaying mempool mass activation assumes the storage mass limit does not change"
        );
        assert!(
            new_limits.transient >= prior_limits.transient,
            "delaying mempool mass activation is only safe when the post-activation transient limit is not stricter"
        );

        block_mass_limits.with_delayed_activation(MEMPOOL_BLOCK_MASS_ACTIVATION_DELAY_SECONDS.saturating_mul(self.bps()))
    }

    /// Returns the mempool policy cofactors for normalizing block mass dimensions.
    #[inline]
    #[must_use]
    pub fn mempool_block_mass_cofactors(&self) -> ForkedParam<MassCofactors> {
        let cofactors = self.mempool_block_mass_limits().map(|limits| limits.cofactors());
        assert_eq!(
            cofactors.before().reference,
            cofactors.after().reference,
            "mempool mass normalization assumes the reference mass is stable across activation"
        );
        cofactors
    }

    /// Returns the forked maximum signature script length.
    #[inline]
    #[must_use]
    pub fn max_signature_script_len(&self) -> ForkedParam<usize> {
        ForkedParam::new(self.prior_max_signature_script_len, self.new_max_signature_script_len, self.toccata_activation)
    }

    pub fn ghostdag_k(&self) -> KType {
        self.blockrate.ghostdag_k
    }

    pub fn max_block_parents(&self) -> u8 {
        self.blockrate.max_block_parents
    }

    pub fn mergeset_size_limit(&self) -> u64 {
        self.blockrate.mergeset_size_limit
    }

    pub fn merge_depth(&self) -> u64 {
        self.blockrate.merge_depth
    }

    pub fn finality_depth(&self) -> u64 {
        self.blockrate.finality_depth
    }

    /// Shielded-spend anchor maturity in blue-score units (PLAN §2.5): how deep a
    /// mined shielded note must be before it can be spent (~10 min at 10 BPS).
    pub fn shielded_anchor_depth(&self) -> u64 {
        self.blockrate.shielded_anchor_depth
    }

    /// Maximum shielded-spend anchor age in blue-score units (audit F-04/F-05):
    /// beyond this an anchor is uniformly rejected on every node class
    /// (~7.5 h at any BPS). See [`BlockrateParams::max_shielded_anchor_age`].
    pub fn max_shielded_anchor_age(&self) -> u64 {
        self.blockrate.max_shielded_anchor_age
    }

    pub fn pruning_depth(&self) -> u64 {
        self.blockrate.pruning_depth
    }

    pub fn coinbase_maturity(&self) -> u64 {
        self.blockrate.coinbase_maturity
    }

    pub fn finality_duration_in_milliseconds(&self) -> u64 {
        self.blockrate.target_time_per_block * self.blockrate.finality_depth
    }

    pub fn difficulty_window_duration_in_block_units(&self) -> u64 {
        self.blockrate.difficulty_sample_rate * self.difficulty_window_size as u64
    }

    pub fn expected_difficulty_window_duration_in_milliseconds(&self) -> u64 {
        self.blockrate.target_time_per_block * self.blockrate.difficulty_sample_rate * self.difficulty_window_size as u64
    }

    /// Returns the depth at which the anticone of a chain block is final (i.e., is a permanently closed set).
    /// Based on the analysis at <https://github.com/kaspanet/docs/blob/main/Reference/prunality/Prunality.pdf>
    /// and on the decomposition of merge depth (rule R-I therein) from finality depth (φ)
    pub fn anticone_finalization_depth(&self) -> u64 {
        let anticone_finalization_depth = self.blockrate.finality_depth
            + self.blockrate.merge_depth
            + 4 * self.blockrate.mergeset_size_limit * self.blockrate.ghostdag_k as u64
            + 2 * self.blockrate.ghostdag_k as u64
            + 2;

        // In mainnet it's guaranteed that `self.pruning_depth` is greater
        // than `anticone_finalization_depth`, but for some tests we use
        // a smaller (unsafe) pruning depth, so we return the minimum of
        // the two to avoid a situation where a block can be pruned and
        // not finalized.
        min(self.blockrate.pruning_depth, anticone_finalization_depth)
    }

    pub fn block_version(&self) -> ForkedParam<u16> {
        ForkedParam::new(BLOCK_VERSION, TOCCATA_BLOCK_VERSION, self.toccata_activation)
    }

    pub fn network_name(&self) -> String {
        self.net.to_prefixed()
    }

    pub fn prefix(&self) -> Prefix {
        self.net.into()
    }

    pub fn default_p2p_port(&self) -> u16 {
        self.net.default_p2p_port()
    }

    pub fn default_listen_p2p_port(&self) -> u16 {
        self.net.default_listen_p2p_port()
    }

    pub fn default_rpc_port(&self) -> u16 {
        self.net.default_rpc_port()
    }

    pub fn override_params(self, overrides: OverrideParams) -> Self {
        Self {
            dns_seeders: self.dns_seeders,
            net: self.net,
            genesis: self.genesis.clone(),

            timestamp_deviation_tolerance: overrides.timestamp_deviation_tolerance.unwrap_or(self.timestamp_deviation_tolerance),

            max_difficulty_target: self.max_difficulty_target,
            max_difficulty_target_f64: self.max_difficulty_target_f64,

            difficulty_window_size: overrides.difficulty_window_size.unwrap_or(self.difficulty_window_size),
            past_median_time_window_size: overrides.past_median_time_window_size.unwrap_or(self.past_median_time_window_size),
            min_difficulty_window_size: overrides.min_difficulty_window_size.unwrap_or(self.min_difficulty_window_size),

            coinbase_payload_script_public_key_max_len: overrides
                .coinbase_payload_script_public_key_max_len
                .unwrap_or(self.coinbase_payload_script_public_key_max_len),

            max_coinbase_payload_len: overrides.max_coinbase_payload_len.unwrap_or(self.max_coinbase_payload_len),
            shielded_coinbase: overrides.shielded_coinbase.unwrap_or(self.shielded_coinbase),

            max_tx_inputs: overrides.max_tx_inputs.unwrap_or(self.max_tx_inputs),
            max_tx_outputs: overrides.max_tx_outputs.unwrap_or(self.max_tx_outputs),
            prior_max_signature_script_len: overrides.prior_max_signature_script_len.unwrap_or(self.prior_max_signature_script_len),
            new_max_signature_script_len: overrides.new_max_signature_script_len.unwrap_or(self.new_max_signature_script_len),
            max_script_public_key_len: overrides.max_script_public_key_len.unwrap_or(self.max_script_public_key_len),
            mass_per_tx_byte: overrides.mass_per_tx_byte.unwrap_or(self.mass_per_tx_byte),
            mass_per_script_pub_key_byte: overrides.mass_per_script_pub_key_byte.unwrap_or(self.mass_per_script_pub_key_byte),
            mass_per_sig_op: overrides.mass_per_sig_op.unwrap_or(self.mass_per_sig_op),
            prior_block_mass_limits: overrides.prior_block_mass_limits.unwrap_or(self.prior_block_mass_limits),
            new_transient_mass_limit: overrides.new_transient_mass_limit.unwrap_or(self.new_transient_mass_limit),
            block_lane_limits: overrides.block_lane_limits.unwrap_or(self.block_lane_limits),

            storage_mass_parameter: overrides.storage_mass_parameter.unwrap_or(self.storage_mass_parameter),

            deflationary_phase_daa_score: overrides.deflationary_phase_daa_score.unwrap_or(self.deflationary_phase_daa_score),

            pre_deflationary_phase_base_subsidy: overrides
                .pre_deflationary_phase_base_subsidy
                .unwrap_or(self.pre_deflationary_phase_base_subsidy),

            skip_proof_of_work: overrides.skip_proof_of_work.unwrap_or(self.skip_proof_of_work),

            max_block_level: overrides.max_block_level.unwrap_or(self.max_block_level),

            pruning_proof_m: overrides.pruning_proof_m.unwrap_or(self.pruning_proof_m),

            blockrate: overrides.blockrate.clone().unwrap_or(self.blockrate.clone()),

            pre_crescendo_target_time_per_block: overrides
                .pre_crescendo_target_time_per_block
                .unwrap_or(self.pre_crescendo_target_time_per_block),

            crescendo_activation: overrides.crescendo_activation.unwrap_or(self.crescendo_activation),
            toccata_activation: overrides.toccata_activation.unwrap_or(self.toccata_activation),
            shielded_anchor_multi_activation: self.shielded_anchor_multi_activation,
            shielded_coinbase_seed_activation: self.shielded_coinbase_seed_activation,
            dev_fee_accrual_activation: self.dev_fee_accrual_activation,
            dev_fee_payout_interval: self.dev_fee_payout_interval,
            merged_mining_activation: overrides.merged_mining_activation.unwrap_or(self.merged_mining_activation),

            // Consensus-critical launch schedule; not exposed as a CLI override.
            low_difficulty_start_blocks: self.low_difficulty_start_blocks,
            difficulty_ramp_blocks: self.difficulty_ramp_blocks,

            // Consensus-critical dev fee; not exposed as a CLI override.
            dev_fee_permille: self.dev_fee_permille,
            dev_fee_recipient: self.dev_fee_recipient,
        }
    }
}

impl Deref for Params {
    type Target = BlockrateParams;

    fn deref(&self) -> &Self::Target {
        &self.blockrate
    }
}

impl DerefMut for Params {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.blockrate
    }
}

impl From<NetworkType> for Params {
    fn from(value: NetworkType) -> Self {
        match value {
            NetworkType::Mainnet => MAINNET_PARAMS,
            NetworkType::Testnet => TESTNET_PARAMS,
            NetworkType::Devnet => DEVNET_PARAMS,
            NetworkType::Simnet => SIMNET_PARAMS,
        }
    }
}

impl From<NetworkId> for Params {
    fn from(value: NetworkId) -> Self {
        match value.network_type {
            NetworkType::Mainnet => MAINNET_PARAMS,
            NetworkType::Testnet => match value.suffix {
                Some(10) => TESTNET_PARAMS,
                Some(x) => panic!("Testnet suffix {} is not supported", x),
                None => panic!("Testnet suffix not provided"),
            },
            NetworkType::Devnet => DEVNET_PARAMS,
            NetworkType::Simnet => SIMNET_PARAMS,
        }
    }
}

/// ZKas dev-fund shielded recipient: the raw 43-byte Orchard address (version
/// `ShieldedOrchard`) that the per-block dev fee is minted to as a coinbase note.
/// Decoded from `zkas:py82h42m9qjff0knpcmllzq3c7qhurje5auh4tq2ceagf69wjpf23djwwmqr26zhsua8rrglrwdltsh`
/// (checksum-verified). Kept as raw bytes so consensus needs no address/bech32 dep.
pub const ZKAS_DEV_FEE_RECIPIENT: [u8; 43] = [
    0x0e, 0xab, 0xd5, 0x5b, 0x28, 0x24, 0x94, 0xbe, 0xd3, 0x0e, 0x37, 0xff, 0x88, 0x11, 0xc7, 0x81, 0x7e, 0x0e, 0x59, 0xa7, 0x79,
    0x7a, 0xac, 0x0a, 0xc6, 0x7a, 0x84, 0xe8, 0xae, 0x90, 0x52, 0xa8, 0xb6, 0x4e, 0x76, 0xc0, 0x35, 0x68, 0x57, 0x87, 0x3a, 0x71,
    0x8d,
];

/// ZKas dev fee: 50 permille (5%) of every block's subsidy is diverted to
/// [`ZKAS_DEV_FEE_RECIPIENT`].
pub const ZKAS_DEV_FEE_PERMILLE: u64 = 50;

pub const MAINNET_PARAMS: Params = Params {
    // ZKas is a distinct network with its own genesis; it MUST NOT advertise or
    // dial Kaspa's DNS seeders (doing so would waste connections on genesis-mismatch
    // rejects and leak our nodes into Kaspa's peer graph).
    //
    // `seed.zkas.info` is resolved with a plain A-record lookup (`to_socket_addrs`,
    // components/connectionmanager/src/lib.rs) and every address it returns is dialled on
    // the default p2p port, so it works as a static list of A records today and becomes a
    // crawling seeder the day one is put behind the same name - no node release needed.
    // Only consulted when no --connect peer is given (kaspad/src/daemon.rs).
    dns_seeders: &["seed.zkas.info"],
    net: NetworkId::new(NetworkType::Mainnet),
    genesis: GENESIS,
    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
    max_difficulty_target: MAX_DIFFICULTY_TARGET,
    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
    coinbase_payload_script_public_key_max_len: 150,
    max_coinbase_payload_len: 204,
    // ZKas is private-by-default: the mainnet coinbase creates no transparent
    // outputs — the reward enters the mandatory shielded pool as coinbase notes (PLAN §2.7).
    // The miner's Orchard address is carried in the reward's 43-byte script_public_key.
    shielded_coinbase: true,

    // Limit the cost of calculating compute/transient/storage masses
    max_tx_inputs: 1000,
    max_tx_outputs: 1000,
    // Transient mass enforces a limit of 125Kb, however script engine max scripts size is 10Kb so there's no point in surpassing that.
    prior_max_signature_script_len: PRIOR_MAX_SIGNATURE_SCRIPT_LEN,
    new_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    // Compute mass enforces a limit of ~45.5Kb, however script engine max scripts size is 10Kb so there's no point in surpassing that.
    // Note that storage mass will kick in and gradually penalize also for lower lengths (generalized KIP-0009, plurality will be high).
    max_script_public_key_len: 10_000,

    mass_per_tx_byte: 1,
    mass_per_script_pub_key_byte: 10,
    mass_per_sig_op: 1000,
    prior_block_mass_limits: BlockMassLimits::with_shared_limit(500_000),
    new_transient_mass_limit: 1_000_000,
    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },

    storage_mass_parameter: STORAGE_MASS_PARAMETER,

    // ZKas is a fresh 1-BPS-from-genesis chain (no 1→10 Crescendo history),
    // so emission uses the 1-BPS schedule from block 0. `deflationary_phase_daa_score
    // = 0` means the smooth halving decay (3-month half-life, see coinbase.rs) applies
    // immediately — no flat pre-deflationary plateau — matching the published emission
    // curve. The per-second emission (and total supply curve) is identical to the prior
    // 10-BPS design: the subsidy curve and the perpetual tail both scale by ÷BPS, so at
    // 1 BPS each block simply pays 10× more while blocks are produced 10× less often.
    // The pre-deflationary base subsidy is unused when this is 0, but is kept BPS-correct.
    deflationary_phase_daa_score: 0,
    pre_deflationary_phase_base_subsidy: Bps::<1>::pre_deflationary_phase_base_subsidy(),
    skip_proof_of_work: false,
    max_block_level: 225,
    pruning_proof_m: 1000,

    blockrate: BlockrateParams::new::<1>(),

    // 1 BPS from genesis: the "pre-Crescendo" block time equals the real one, and
    // Crescendo is active from block 0, so the BPS history is a constant 1 (the
    // subsidy table divides by 1 throughout — no legacy segment).
    pre_crescendo_target_time_per_block: Bps::<1>::target_time_per_block(),

    crescendo_activation: ForkActivation::always(),

    // RESET-BUNDLE VALUE: KIP-21 sequencing commitments (seq_commit) active from
    // genesis. This is required for the *trustless* KAS<->ZKAS bridge: canonical-R
    // proves a shielded state root R is committed by the chain's own PoW by having
    // the covenant read a block's seq_commit on-chain (OpChainblockSeqCommit). That
    // opcode only returns a value once seq_commit is being computed, and seq_commit
    // is gated on this activation (see utxo_validation.rs `seq_commit_accessor`).
    // The prior DAA-474_165_565 value (~2026-06-30 in *real* Kaspa DAA terms) is
    // effectively "never" for this young 1-BPS chain (~15 years out), which left the
    // bridge's trust root dormant. `always()` matches the neighboring crescendo /
    // merged_mining launch values and must ride the genesis re-cut. CONSENSUS-BREAKING.
    toccata_activation: ForkActivation::always(),
    // ZKAS-NU1 ACTIVATION — DAA 757,000.
    //
    // Chosen 2026-08-03 08:49 UTC at live DAA 671,210 from a measured 11-hour baseline of
    // 0.99339 DAA/s (85,829 DAA/day, slightly under the 1 BPS nominal), putting the crossing
    // at ~2026-08-04 08:48 UTC. DAA is hashrate-driven, so wall-clock moves if hashrate does
    // (~±1 h per ±5% sustained change). The DAA is the commitment; the time is an estimate.
    //
    // Both gates ride the SAME height on purpose — they were validated together in the
    // mainnet->mainnet rehearsal (2026-08-03), never separately.
    //
    // Non-upgraded nodes FAIL CLOSED here: they disqualify every chain block and log
    // `N disqualified vs 0 valid chain blocks`, character-identical to the known snapshot/IBD
    // wedge bug. This MUST be announced before the height is reached.
    shielded_anchor_multi_activation: ForkActivation::new(757_000),
    // Upgrade 2, deliberately NOT in this fork: F-02 needs the whole wallet fleet
    // shipped first. Leaving it `never()` is what makes NU1 a node-only upgrade.
    shielded_coinbase_seed_activation: ForkActivation::never(),
    dev_fee_accrual_activation: ForkActivation::new(757_000),
    // ~17 minutes at 1 BPS: short enough that the dev fund is never far behind,
    // long enough to cut per-block dev notes by three orders of magnitude.
    dev_fee_payout_interval: 1_000,
    // LAUNCH VALUE (decided 2026-07-22, reset bundle): merged mining active from
    // genesis. This is ZKas's production model — the chain merge-mines Kaspa from
    // block 0 (~20-25 KAS blocks/h in production), so aux-PoW acceptance is a launch
    // feature, not a future fork. Keeping it `always()` also exercises the aux path
    // from genesis and needs no activation DAA. (Earlier revisions carried a
    // "REVERT to day-14" note from when this was a demo value — that no longer
    // applies; since the July 2026 mainnet launch (fresh genesis), always() is the
    // intended, correct value. This is historical context, not a planned change.)
    merged_mining_activation: ForkActivation::always(),

    // ZKas launch difficulty: the low-difficulty bootstrap schedule is DISABLED on mainnet
    // (both 0), so the chain launches under pure upstream KIP-0004 DAA from genesis — the
    // genesis `bits` are the starting difficulty and the DAA governs from block 1. This is the
    // normal-launch path (identical to testnet/simnet). Rationale:
    //  - the chain is merge-mined with real Kaspa hashrate from block 0, so no CPU-mineable
    //    bootstrap ramp is needed; calibrate the genesis `bits` to the launch hashrate at re-cut.
    //  - removes the pinned super-easy window entirely: no blocks without economic finality and
    //    no cheap-block-flood launch surface (audit F-23).
    //  - `ramp_end == 0` also disables the post-ramp genesis-target difficulty floor, so difficulty
    //    can always ease back toward `MAX_DIFFICULTY_TARGET` if hashrate drops — no floor-induced
    //    soft-wedge (audit F-32). The DAA alone (bounded by MAX_DIFFICULTY_TARGET) governs, exactly
    //    as on upstream Kaspa.
    low_difficulty_start_blocks: 0,
    difficulty_ramp_blocks: 0,

    // ZKas dev fund: 5% of every block's subsidy is minted as a shielded coinbase note
    // to ZKAS_DEV_FEE_RECIPIENT. Mainnet is shielded_coinbase, so the note is diverted
    // into the shielded pool like any miner reward.
    dev_fee_permille: ZKAS_DEV_FEE_PERMILLE,
    dev_fee_recipient: Some(ZKAS_DEV_FEE_RECIPIENT),
};

pub const TESTNET_PARAMS: Params = Params {
    // testnet-10 mirrors MAINNET's ZKas feature set (shielded coinbase, Toccata, multi-
    // producer anchors, dev fee, 1 BPS emission) so a solo miner exercises real ZKas
    // consensus. Differs from mainnet only in: network id, TESTNET_GENESIS (easy PoW for
    // CPU solo mining), empty seeders (run standalone), and merged-mining-from-genesis.
    // No ZKas testnet seeders exist yet. These MUST NOT be Kaspa's testnet seeders
    // (inherited here until 2026-08-31): since 64beca1 the connection manager actually
    // dials every address a seeder returns, so a ZKas testnet node would spam Kaspa's
    // testnet with genesis-mismatch handshakes and leak itself into their peer graph.
    dns_seeders: &[],
    net: NetworkId::with_suffix(NetworkType::Testnet, 10),
    genesis: TESTNET_GENESIS,
    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
    max_difficulty_target: MAX_DIFFICULTY_TARGET,
    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
    coinbase_payload_script_public_key_max_len: 150,
    max_coinbase_payload_len: 204,
    shielded_coinbase: true,

    // Limit the cost of calculating compute/transient/storage masses
    max_tx_inputs: 1000,
    max_tx_outputs: 1000,
    // Transient mass enforces a limit of 125Kb, however script engine max scripts size is 10Kb so there's no point in surpassing that.
    prior_max_signature_script_len: PRIOR_MAX_SIGNATURE_SCRIPT_LEN,
    new_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    // Compute mass enforces a limit of ~45.5Kb, however script engine max scripts size is 10Kb so there's no point in surpassing that.
    // Note that storage mass will kick in and gradually penalize also for lower lengths (generalized KIP-0009, plurality will be high).
    max_script_public_key_len: 10_000,

    mass_per_tx_byte: 1,
    mass_per_script_pub_key_byte: 10,
    mass_per_sig_op: 1000,
    prior_block_mass_limits: BlockMassLimits::with_shared_limit(500_000),
    new_transient_mass_limit: 1_000_000,
    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },

    storage_mass_parameter: STORAGE_MASS_PARAMETER,
    // 1-BPS-from-genesis emission (same as mainnet): smooth halving applies from block 0,
    // no flat pre-deflationary plateau.
    deflationary_phase_daa_score: 0,
    pre_deflationary_phase_base_subsidy: Bps::<1>::pre_deflationary_phase_base_subsidy(),
    skip_proof_of_work: false,
    max_block_level: 250,
    pruning_proof_m: 1000,

    blockrate: BlockrateParams::new::<1>(),

    pre_crescendo_target_time_per_block: Bps::<1>::target_time_per_block(),

    // 18:30 UTC, March 6, 2025
    crescendo_activation: ForkActivation::always(),

    // ~16:00 UTC, May 18, 2026
    toccata_activation: ForkActivation::always(),
    shielded_anchor_multi_activation: ForkActivation::always(),
    shielded_coinbase_seed_activation: ForkActivation::never(),
    dev_fee_accrual_activation: ForkActivation::always(),
    // ~17 minutes at 1 BPS: short enough that the dev fund is never far behind,
    // long enough to cut per-block dev notes by three orders of magnitude.
    dev_fee_payout_interval: 1_000,
    // On testnet, merged mining is available from genesis for testing.
    merged_mining_activation: ForkActivation::always(),

    // Launch difficulty schedule disabled on testnet.
    low_difficulty_start_blocks: 0,
    difficulty_ramp_blocks: 0,

    // Dev fee mirrors mainnet so the coinbase (miner note + dev note) is identical to production.
    dev_fee_permille: ZKAS_DEV_FEE_PERMILLE,
    dev_fee_recipient: Some(ZKAS_DEV_FEE_RECIPIENT),
};

pub const SIMNET_PARAMS: Params = Params {
    dns_seeders: &[],
    net: NetworkId::new(NetworkType::Simnet),
    genesis: SIMNET_GENESIS,
    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
    max_difficulty_target: MAX_DIFFICULTY_TARGET,
    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,

    deflationary_phase_daa_score: TenBps::deflationary_phase_daa_score(),
    pre_deflationary_phase_base_subsidy: TenBps::pre_deflationary_phase_base_subsidy(),
    coinbase_payload_script_public_key_max_len: 150,
    max_coinbase_payload_len: 204,
    shielded_coinbase: false,

    max_tx_inputs: 1000,
    max_tx_outputs: 1000,
    prior_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    new_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    max_script_public_key_len: 10_000,

    mass_per_tx_byte: 1,
    mass_per_script_pub_key_byte: 10,
    mass_per_sig_op: 1000,
    // Transient mass is increased for stark proofs
    prior_block_mass_limits: BlockMassLimits::with_shared_limit(500_000),
    new_transient_mass_limit: 1_000_000,
    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },

    storage_mass_parameter: STORAGE_MASS_PARAMETER,

    skip_proof_of_work: true, // For simnet only, PoW can be simulated by default
    max_block_level: 250,
    pruning_proof_m: PRUNING_PROOF_M,

    // For simnet, we deviate from default 10BPS configuration and allow at least 64 parents in order to support mempool benchmarks out of the box
    blockrate: BlockrateParams::new::<10>().increase_max_block_parents(64),

    pre_crescendo_target_time_per_block: TenBps::target_time_per_block(),

    crescendo_activation: ForkActivation::always(),
    toccata_activation: ForkActivation::always(),
    // Scheduled separately once a height is agreed; see the field doc.
    shielded_anchor_multi_activation: ForkActivation::never(),
    shielded_coinbase_seed_activation: ForkActivation::never(),
    dev_fee_accrual_activation: ForkActivation::never(),
    // ~17 minutes at 1 BPS: short enough that the dev fund is never far behind,
    // long enough to cut per-block dev notes by three orders of magnitude.
    dev_fee_payout_interval: 1_000,
    merged_mining_activation: ForkActivation::always(),

    // Launch difficulty schedule disabled on simnet.
    low_difficulty_start_blocks: 0,
    difficulty_ramp_blocks: 0,

    // No dev fee on this network.
    dev_fee_permille: 0,
    dev_fee_recipient: None,
};

pub const DEVNET_PARAMS: Params = Params {
    dns_seeders: &[],
    net: NetworkId::new(NetworkType::Devnet),
    genesis: DEVNET_GENESIS,
    timestamp_deviation_tolerance: TIMESTAMP_DEVIATION_TOLERANCE,
    max_difficulty_target: MAX_DIFFICULTY_TARGET,
    max_difficulty_target_f64: MAX_DIFFICULTY_TARGET_AS_F64,
    past_median_time_window_size: MEDIAN_TIME_SAMPLED_WINDOW_SIZE as usize,
    difficulty_window_size: DIFFICULTY_SAMPLED_WINDOW_SIZE as usize,
    min_difficulty_window_size: MIN_DIFFICULTY_WINDOW_SIZE,
    coinbase_payload_script_public_key_max_len: 150,
    max_coinbase_payload_len: 204,
    // ZKas devnet is private-by-default like mainnet: the coinbase mints its
    // reward into the shielded pool, so there is a note to spend privately. A live
    // shielded payment over RPC (blocker #2) is provable here because the note
    // matures after `shielded_anchor_depth` (~10 min), not the full finality window.
    shielded_coinbase: true,

    max_tx_inputs: 1000,
    max_tx_outputs: 1000,
    prior_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    new_max_signature_script_len: NEW_MAX_SIGNATURE_SCRIPT_LEN,
    max_script_public_key_len: 10_000,

    mass_per_tx_byte: 1,
    mass_per_script_pub_key_byte: 10,
    mass_per_sig_op: 1000,

    // Transient mass is increased for stark proofs
    prior_block_mass_limits: BlockMassLimits::with_shared_limit(500_000),
    new_transient_mass_limit: 1_000_000,
    block_lane_limits: BlockLaneLimits { lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT, gas_per_lane: DEFAULT_GAS_PER_LANE_LIMIT },

    storage_mass_parameter: STORAGE_MASS_PARAMETER,

    deflationary_phase_daa_score: 0,
    pre_deflationary_phase_base_subsidy: TenBps::pre_deflationary_phase_base_subsidy(),
    skip_proof_of_work: false,
    max_block_level: 250,
    pruning_proof_m: 1000,

    // Full chain finality (like mainnet). Shielded-spend maturity is governed
    // separately by `shielded_anchor_depth` (~10 min), so a freshly-minted note is
    // spendable in minutes without weakening finality/pruning.
    blockrate: BlockrateParams::new::<10>(),

    pre_crescendo_target_time_per_block: TenBps::target_time_per_block(),

    crescendo_activation: ForkActivation::always(),
    toccata_activation: ForkActivation::never(),
    shielded_anchor_multi_activation: ForkActivation::new(200),
    // F-02 is held for upgrade 2 (it forces every wallet client to ship a gated
    // scanner). Devnet therefore models UPGRADE 1 exactly: multi-producer anchors +
    // dev-fee accrual, both at DAA 200, F-02 off. Its own rehearsal was run and
    // recorded separately (1aug.md §11.2, two-binary boundary test).
    shielded_coinbase_seed_activation: ForkActivation::never(),
    dev_fee_accrual_activation: ForkActivation::new(200),
    // ~17 minutes at 1 BPS: short enough that the dev fund is never far behind,
    // long enough to cut per-block dev notes by three orders of magnitude.
    dev_fee_payout_interval: 20,
    merged_mining_activation: ForkActivation::always(),

    // Pin difficulty to the (easy) genesis target for the first 50k blocks so the
    // short devnet demo chain stays CPU-mineable throughout (mirrors mainnet's launch
    // schedule); the ramp then tightens toward real difficulty exactly as on mainnet.
    // Launch window ends at blue score 250_000 (50k easy + 200k ramp), same as mainnet.
    low_difficulty_start_blocks: 50_000,
    difficulty_ramp_blocks: 200_000,

    // No dev fee on devnet.
    // Devnet carries the dev fee AND activates accrual early, so the fork can be
    // rehearsed end-to-end on a throwaway chain: blocks below DAA 200 mint a dev note
    // each (the pre-fork shape), blocks above it accrue and pay one note per 20 DAA.
    dev_fee_permille: ZKAS_DEV_FEE_PERMILLE,
    dev_fee_recipient: Some(ZKAS_DEV_FEE_RECIPIENT),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_params_deserializes_toccata_activation() {
        let override_params: OverrideParams = serde_json::from_str(r#"{"toccata_activation":42}"#).unwrap();

        assert_eq!(override_params.toccata_activation, Some(ForkActivation::new(42)));
    }

    #[test]
    fn override_params_rejects_unknown_top_level_fields() {
        let err = serde_json::from_str::<OverrideParams>(r#"{"unexpected":42}"#).unwrap_err();

        assert!(err.to_string().contains("unknown field `unexpected`"), "{err}");
    }

    #[test]
    fn override_params_rejects_unknown_nested_blockrate_fields() {
        let err = serde_json::from_str::<OverrideParams>(
            r#"{
                "blockrate": {
                    "target_time_per_block": 100,
                    "ghostdag_k": 124,
                    "past_median_time_sample_rate": 10,
                    "difficulty_sample_rate": 2,
                    "max_block_parents": 16,
                    "mergeset_size_limit": 248,
                    "merge_depth": 36000,
                    "finality_depth": 432000,
                    "pruning_depth": 1080000,
                    "coinbase_maturity": 200,
                    "unexpected": 1
                }
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field `unexpected`"), "{err}");
    }

    #[test]
    fn override_params_rejects_unknown_nested_mass_limit_fields() {
        let err = serde_json::from_str::<OverrideParams>(
            r#"{
                "prior_block_mass_limits": {
                    "storage": 500000,
                    "compute": 500000,
                    "transient": 500000,
                    "unexpected": 1
                }
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field `unexpected`"), "{err}");
    }
}
