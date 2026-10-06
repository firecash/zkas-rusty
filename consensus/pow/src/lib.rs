pub mod auxpow;
pub mod pegin;
// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;

use kaspa_consensus_core::{BlockLevel, hashing, header::Header};
use kaspa_hashes::PowHash;
use kaspa_math::Uint256;

use crate::matrix::Matrix;

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    pub(crate) target: Uint256,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE.
    pub(crate) hasher: PowHash,
    pub(crate) matrix: Matrix,
}

impl State {
    /// Build a verification state that runs the real kHeavyHash PoW.
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp);
        let matrix = Matrix::generate(pre_pow_hash);

        Self { target, matrix, hasher }
    }

    /// kHeavyHash builds its matrix cheaply, so there is no expensive context to
    /// skip (unlike the former FishHash light cache) — this simply mirrors upstream,
    /// which always builds the real state. `skip_proof_of_work` is honored by callers
    /// ignoring the returned `passed` flag, not by weakening the hash computed here.
    #[inline]
    pub fn new_skip_pow(header: &Header) -> Self {
        Self::new(header)
    }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE, then kHeavyHash.
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing.
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash = self.matrix.heavy_hash(hash);
        Uint256::from_le_bytes(hash.as_bytes())
    }

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel, skip_pow: bool) -> BlockLevel {
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level, skip_pow);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel, skip_pow: bool) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = if skip_pow { State::new_skip_pow(header) } else { State::new(header) };
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

/// Aux-aware variant of [`calc_block_level_check_pow`]: past the merged-mining
/// activation a block may earn its level via a valid AuxPoW witness (the level then
/// derives from the Kaspa parent's pow, exactly as header validation assigned it).
/// Every consumer that RE-derives a stored level (pruning-proof validation/apply)
/// must use this, or merged-mined blocks recompute to level 0 and valid proofs are
/// rejected ("level is 0 when it's expected to be at least N").
pub fn calc_block_level_check_pow_gated(
    header: &Header,
    max_block_level: BlockLevel,
    skip_pow: bool,
    merged_mining_active: impl Into<auxpow::AuxRule>,
) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }
    if skip_pow {
        let pow = State::new_skip_pow(header).check_pow(header.nonce).1;
        return (calc_level_from_pow(pow, max_block_level), true);
    }
    let (passed, pow) = auxpow::check_pow_gated(header, header.aux_pow.as_deref(), merged_mining_active);
    (calc_level_from_pow(pow, max_block_level), passed)
}

/// Aux-aware variant of [`calc_block_level`]; see [`calc_block_level_check_pow_gated`].
pub fn calc_block_level_gated(
    header: &Header,
    max_block_level: BlockLevel,
    skip_pow: bool,
    merged_mining_active: impl Into<auxpow::AuxRule>,
) -> BlockLevel {
    calc_block_level_check_pow_gated(header, max_block_level, skip_pow, merged_mining_active).0
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
