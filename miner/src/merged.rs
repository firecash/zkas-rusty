//! Merged-mining (AuxPoW) block production — the "dual-template" engine.
//!
//! Native mining ([`crate::solver`]) grinds the ZKas header's own nonce. Merged
//! mining instead proves the ZKas block's proof-of-work via a **parent** kHeavyHash
//! block (the Kaspa side of Option-2 dual acceptance): the parent's coinbase commits to
//! the ZKas block hash `H_fc`, and the parent's kHeavyHash clears ZKas's target.
//! The node accepts it through the exact [`kaspa_pow::auxpow`] verifier this mirrors.
//!
//! For a self-contained demo/test the "parent" is a synthetic Kaspa-shaped block we
//! build here — per the design, the parent need not be a *valid* Kaspa block, only
//! carry enough kHeavyHash work bound to `H_fc`. Real merged mining swaps this synthetic
//! parent for a live Kaspa `getBlockTemplate` (same struct, same grind); this module is
//! the reusable engine either way.

use std::sync::atomic::AtomicBool;

use kaspa_consensus_core::{
    auxpow::AuxPow, header::Header, merkle::calc_hash_merkle_root, subnets::SUBNETWORK_ID_COINBASE, tx::Transaction,
};
use kaspa_hashes::{Hash, ZERO_HASH};
use kaspa_pow::State;

use crate::solver;

/// Build an [`AuxPow`] proof for the ZKas block `fc_header` (whose hash is `H_fc`
/// and whose target comes from its `bits`). Constructs a single-transaction parent
/// whose coinbase embeds `MERGE_MINE_MAGIC || H_fc`, then grinds the parent's
/// kHeavyHash — against the *ZKas* target — until it clears it. Returns `None` if
/// `stop` fires before a solution (stale template).
///
/// Grinding reuses [`solver::mine_header`] by setting `parent.bits = fc_header.bits`,
/// so the search target is identical to what the consensus verifier compares against.
///
/// Returns the (possibly nonce-adjusted) ZKas header alongside the proof: to make
/// the demo unambiguous, the header's own `nonce` is set to a value whose **native**
/// kHeavyHash does *not* clear the target, so the block can only be accepted via the
/// aux path — never a lucky native nonce on an easy test target.
pub fn build_aux_pow(fc_header: &Header, threads: usize, stop: &AtomicBool) -> Option<(Header, AuxPow)> {
    // Choose a nonce whose native PoW fails (on a non-trivial target nonce 0 already
    // fails; this guarantees it even on an easy genesis target). Recompute H_fc for it.
    let mut fc = fc_header.clone();
    let native = State::new(&fc);
    let mut n = 0u64;
    while native.check_pow(n).0 {
        n = n.wrapping_add(1);
    }
    fc.nonce = n;
    fc.finalize();

    let h_fc = fc.hash;

    // Parent coinbase (leaf 0) carrying the ZKas commitment in the miner-writable slot.
    let coinbase = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, AuxPow::embed_commitment(&[], h_fc, &[]));
    // Single-tx parent: the coinbase is the whole tx tree, so the Merkle branch is empty.
    let hash_merkle_root = calc_hash_merkle_root(std::iter::once(&coinbase));

    let mut parent = Header::from_precomputed_hash(ZERO_HASH, vec![Hash::from_u64_word(0xF12E_CA54)]);
    parent.hash_merkle_root = hash_merkle_root;
    parent.bits = fc_header.bits; // grind against the ZKas target
    parent.timestamp = fc_header.timestamp;

    let nonce = solver::mine_header(&parent, threads, stop)?;
    parent.nonce = nonce;

    Some((fc, AuxPow { parent_header: parent, parent_coinbase: coinbase, coinbase_merkle_branch: vec![] }))
}

/// Security-fork form of [`build_aux_pow`]. The parent commits `ZKM1 || hex(bound_commitment(genesis,
/// nonce-free H_fc))` (the header hash with the nonce zeroed, the timestamp kept), the parent is mined,
/// and only then is the ZKas header's nonce set to the parent's hash. Order matters: the commitment
/// cannot depend on the nonce, and the nonce must name the parent, which is what makes one block have
/// exactly one witness.
pub fn build_aux_pow_bound(fc_header: &Header, genesis: Hash, threads: usize, stop: &AtomicBool) -> Option<(Header, AuxPow)> {
    let mut fc = fc_header.clone();
    let nonce_free = kaspa_consensus_core::hashing::header::hash_override_nonce_time(&fc, 0, fc.timestamp);
    let commitment = AuxPow::bound_commitment(genesis, nonce_free);
    let coinbase = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, AuxPow::embed_commitment_v1(&[], commitment, &[]));
    let hash_merkle_root = calc_hash_merkle_root(std::iter::once(&coinbase));

    let mut parent = Header::from_precomputed_hash(ZERO_HASH, vec![Hash::from_u64_word(0xF12E_CA54)]);
    parent.hash_merkle_root = hash_merkle_root;
    parent.bits = fc_header.bits;
    parent.timestamp = fc_header.timestamp;
    let nonce = solver::mine_header(&parent, threads, stop)?;
    parent.nonce = nonce;

    fc.nonce = AuxPow::nonce_binding(&parent);
    fc.finalize();
    Some((fc, AuxPow { parent_header: parent, parent_coinbase: coinbase, coinbase_merkle_branch: vec![] }))
}
