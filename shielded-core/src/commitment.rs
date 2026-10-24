//! Canonical shielded state root (PLAN §2.10).
//!
//! A single 32-byte digest binding the three pieces of shielded consensus state
//! that a fast-syncing or pruned node cannot otherwise verify without replaying
//! every block from genesis:
//!
//! - the **note-commitment tree root** (`anchor`) — commits to the full note
//!   history, so received notes and spend witnesses are trustworthy;
//! - the **nullifier-set accumulator root** (`nullifier_root`, a MuHash over all
//!   spent nullifiers) — commits to double-spend prevention across a checkpoint;
//! - the **turnstile cumulative totals** — commit to value conservation
//!   (shielded pool == cumulative coinbase − cumulative fees − cumulative burns, §2.6);
//! - the **burn accumulator root** ([`crate::burn`]) — commits to the sequence of
//!   bridge exit receipts, so a peg-out can be *proved* on the Kaspa side against a
//!   root the ZKas chain's own proof-of-work stands behind.
//!
//! This digest is what a block commits to (via the coinbase, itself bound by the
//! header's `hash_merkle_root` and thus by proof-of-work), forming a PoW-anchored
//! chain of shielded state roots.
//!
//! # Why the burn root belongs *here* and not in a side structure
//!
//! The peg-out's entire security rests on the Kaspa side being able to trust a ZKas state root.
//! Folding `burn_root` into the same digest the coinbase already commits to means a burn receipt
//! inherits, for free, every guarantee the shielded state root has: it is covered by the
//! coinbase, hence by `hash_merkle_root`, hence by proof-of-work, and (through merged mining)
//! witnessed in Kaspa's own history. A burn root carried anywhere else would need its own
//! anchoring story.

use blake2b_simd::Params;

/// Personalization for the shielded state root hash (blake2b personal is ≤16 bytes).
const STATE_ROOT_PERSONAL: &[u8; 16] = b"zkas_state_root0";

/// The canonical 32-byte shielded state root (see module docs). Deterministic in
/// its five inputs and independent of evaluation order — the accumulator inputs
/// (`anchor`, `nullifier_root`) are themselves order-independent set commitments,
/// and `burn_root` is a commitment to an ordered append-only sequence.
///
/// **Consensus-breaking.** Adding `burn_root` changes every state root, so this
/// must land at a fresh genesis (the planned reset), not on a live chain. A chain
/// with no burns passes `BurnAccumulator::new().root()` (all zeros).
pub fn shielded_state_root(
    anchor: &[u8; 32],
    nullifier_root: &[u8; 32],
    cumulative_coinbase: u128,
    cumulative_fees: u128,
    burn_root: &[u8; 32],
) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(STATE_ROOT_PERSONAL).to_state();
    h.update(anchor);
    h.update(nullifier_root);
    h.update(&cumulative_coinbase.to_le_bytes());
    h.update(&cumulative_fees.to_le_bytes());
    h.update(burn_root);
    let mut root = [0u8; 32];
    root.copy_from_slice(h.finalize().as_bytes());
    root
}

/// Personalization of the post-fork state root. A different personalization from
/// `zkas_state_root0`, so no v0 root can equal a v1 root.
const STATE_ROOT_V1_PERSONAL: &[u8; 16] = b"zkas_state_root1";

/// The miner-reward accrual slot as committed in [`shielded_state_root_v1`]: the payout script
/// (version and bytes) and the carried amount. An empty slot is `(0, &[], 0)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinerAccrualRef<'a> {
    pub script_version: u16,
    pub script: &'a [u8],
    pub amount: u64,
}

/// The shielded state root from the security fork on (`Params::security_fork_activation`):
/// the v0 root plus the values a syncing node previously had to take on trust (the dev-fee
/// accrual and the anchor window commitment, [`crate::anchor_window`]) and the miner-reward
/// accrual slot, which exists only from the fork. Selected by the DAA score of the block whose
/// state it describes.
pub fn shielded_state_root_v1(
    root_v0: &[u8; 32],
    dev_accrued: u64,
    anchor_window_commitment: &[u8; 32],
    miner_accrual: MinerAccrualRef<'_>,
) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(STATE_ROOT_V1_PERSONAL).to_state();
    h.update(root_v0);
    h.update(&dev_accrued.to_le_bytes());
    h.update(anchor_window_commitment);
    // Length-prefixed, so no (script, amount) pair can be re-split into another.
    h.update(&miner_accrual.script_version.to_le_bytes());
    h.update(&(miner_accrual.script.len() as u32).to_le_bytes());
    h.update(miner_accrual.script);
    h.update(&miner_accrual.amount.to_le_bytes());
    let mut root = [0u8; 32];
    root.copy_from_slice(h.finalize().as_bytes());
    root
}

/// NU-A (spec 08 R4.2.1): one closed note-commitment tree era. When a chain block is applied whose
/// selected parent's era holds at least the rollover threshold of leaves, the parent's tree is
/// frozen as this record and the block starts the next era on an empty tree. A spend of a note from
/// a frozen era names `freeze_block` as its anchor block and proves against `final_root`; such an
/// anchor is exempt from the maximum anchor age, because no newer root of that era will ever exist.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrozenEra {
    /// The era this record closes (0 for the first).
    pub era: u32,
    /// The era's final tree root (the freeze block's anchor).
    pub final_root: [u8; 32],
    /// The selected-chain block whose tree is the era's last state.
    pub freeze_block: [u8; 32],
    /// Blue score of `freeze_block` (the maturity reference for frozen-era spends).
    pub freeze_blue_score: u64,
    /// Number of leaves in the era.
    pub size: u64,
}

/// NU-A tree-era state carried per chain block and committed by [`shielded_state_root_v2`].
/// All zero / empty before NU-A, and until the first rollover apart from the burn counter.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NuaState {
    /// Total fee floor burned by applied shielded transactions since NU-A (spec 08 R2.4).
    pub cumulative_fee_burn: u128,
    /// The current tree era (0 until the first rollover).
    pub tree_era: u32,
    /// Every closed era, oldest first. Grows by one record per rollover (one per ~4.29 billion leaves).
    pub frozen: Vec<FrozenEra>,
}

impl NuaState {
    /// Leaves in every frozen era together (the current era's leaves are the tree frontier's size).
    pub fn frozen_leaves(&self) -> u64 {
        self.frozen.iter().fold(0u64, |acc, f| acc.saturating_add(f.size))
    }

    /// The frozen era a spend names, if `(anchor_block, anchor)` is exactly a freeze record.
    pub fn frozen_anchor(&self, anchor_block: &[u8; 32], anchor: &[u8; 32]) -> Option<&FrozenEra> {
        self.frozen.iter().find(|f| f.freeze_block == *anchor_block && f.final_root == *anchor)
    }

    /// [`frozen_eras_hash`] of this state's frozen list.
    pub fn frozen_hash(&self) -> [u8; 32] {
        frozen_eras_hash(&self.frozen)
    }
}

/// NU-A (spec 08 R4.2.3): whether the chain block about to be applied starts a new tree era, given
/// whether NU-A is active at ITS DAA score and how many leaves its selected parent's era holds. The
/// one rule consensus and every wallet use, so they cannot disagree about where an era ends: a wallet
/// replaying chain blocks in order knows each block's DAA score and its own era's leaf count.
pub fn starts_new_tree_era(nua_active_at_block: bool, parent_era_size: u64, rollover_threshold: u64) -> bool {
    nua_active_at_block && parent_era_size > 0 && parent_era_size >= rollover_threshold
}

/// Personalization of the frozen-era list hash.
const FROZEN_ERAS_PERSONAL: &[u8; 16] = b"zkas_frozen_eras";

/// `H(frozen)` of `zkas_state_root2`: BLAKE2b-256, personalization `zkas_frozen_eras`, over
/// `count u32 LE` followed by each record as `era u32 LE || final_root 32 || freeze_block 32 ||
/// freeze_blue_score u64 LE || size u64 LE`. The count prefix and the fixed record length make the
/// encoding injective. The empty list hashes the 4-byte zero count.
pub fn frozen_eras_hash(frozen: &[FrozenEra]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(FROZEN_ERAS_PERSONAL).to_state();
    h.update(&(frozen.len() as u32).to_le_bytes());
    for f in frozen {
        h.update(&f.era.to_le_bytes());
        h.update(&f.final_root);
        h.update(&f.freeze_block);
        h.update(&f.freeze_blue_score.to_le_bytes());
        h.update(&f.size.to_le_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Personalization of the NU-A state root. Distinct from v0 and v1, so no root of one version can
/// equal a root of another.
const STATE_ROOT_V2_PERSONAL: &[u8; 16] = b"zkas_state_root2";

/// The shielded state root from NU-A on (15 A8.13):
/// `BLAKE2b("zkas_state_root2", root_v1 || cumulative_fee_burn u128 LE || tree_era u32 LE || H(frozen))`.
/// Selected by the DAA score of the block whose state it describes, like v1.
pub fn shielded_state_root_v2(root_v1: &[u8; 32], nua: &NuaState) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(STATE_ROOT_V2_PERSONAL).to_state();
    h.update(root_v1);
    h.update(&nua.cumulative_fee_burn.to_le_bytes());
    h.update(&nua.tree_era.to_le_bytes());
    h.update(&nua.frozen_hash());
    let mut root = [0u8; 32];
    root.copy_from_slice(h.finalize().as_bytes());
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_binds_burn_era_and_every_frozen_field_and_differs_from_v1() {
        let v1 = [0x51; 32];
        let base = NuaState::default();
        let r = shielded_state_root_v2(&v1, &base);
        assert_ne!(r, v1, "v2 is a new digest, not v1");
        assert_ne!(r, shielded_state_root_v2(&[0x52; 32], &base), "the v1 root must matter");
        assert_ne!(r, shielded_state_root_v2(&v1, &NuaState { cumulative_fee_burn: 1, ..base.clone() }), "the burn must matter");
        assert_ne!(r, shielded_state_root_v2(&v1, &NuaState { tree_era: 1, ..base.clone() }), "the era must matter");
        let f = FrozenEra { era: 0, final_root: [1; 32], freeze_block: [2; 32], freeze_blue_score: 3, size: 4 };
        let one = NuaState { frozen: vec![f], ..base.clone() };
        let r1 = shielded_state_root_v2(&v1, &one);
        assert_ne!(r, r1, "a frozen record must matter");
        for g in [
            FrozenEra { era: 1, ..f },
            FrozenEra { final_root: [9; 32], ..f },
            FrozenEra { freeze_block: [9; 32], ..f },
            FrozenEra { freeze_blue_score: 9, ..f },
            FrozenEra { size: 9, ..f },
        ] {
            assert_ne!(r1, shielded_state_root_v2(&v1, &NuaState { frozen: vec![g], ..base.clone() }), "{g:?}");
        }
        // Order and multiplicity are committed.
        let g = FrozenEra { era: 1, final_root: [5; 32], freeze_block: [6; 32], freeze_blue_score: 7, size: 8 };
        assert_ne!(frozen_eras_hash(&[f, g]), frozen_eras_hash(&[g, f]));
        assert_ne!(frozen_eras_hash(&[f]), frozen_eras_hash(&[f, f]));
    }

    /// Wire pin: an independent implementation (Python `hashlib.blake2b(digest_size=32,
    /// person=...)`) must reproduce these, so a field-order or personalization drift fails here.
    #[test]
    fn v2_matches_independent_reference_vectors() {
        let empty = frozen_eras_hash(&[]);
        assert_eq!(hex(&empty), "b1fcb54b5a33cf8a273129cd83eb456b4fb27ee8d1f5da2c4cd2a68aee774c5e");
        let f = FrozenEra { era: 0, final_root: [0x11; 32], freeze_block: [0x22; 32], freeze_blue_score: 1_000, size: 4_293_918_720 };
        let nua = NuaState { cumulative_fee_burn: 2_400_000, tree_era: 1, frozen: vec![f] };
        assert_eq!(hex(&shielded_state_root_v2(&[0x33; 32], &nua)), "d20c7ab342bd37191f33f3844dc9de306f16e9abd6f2ffe82945fbaf2e8aebbb");
    }

    const A: [u8; 32] = [0x11; 32];
    const N: [u8; 32] = [0x22; 32];
    const B: [u8; 32] = [0x33; 32];
    const NO_BURNS: [u8; 32] = [0u8; 32];

    #[test]
    fn v1_binds_accrual_and_window_and_differs_from_v0() {
        let r0 = shielded_state_root(&A, &N, 7, 3, &B);
        let w = [0x44; 32];
        let none = MinerAccrualRef::default();
        let v1 = shielded_state_root_v1(&r0, 5, &w, none);
        assert_ne!(v1, r0);
        assert_ne!(v1, shielded_state_root_v1(&r0, 6, &w, none), "dev accrual must matter");
        assert_ne!(v1, shielded_state_root_v1(&r0, 5, &[0x45; 32], none), "anchor window must matter");
        assert_ne!(v1, shielded_state_root_v1(&[0x01; 32], 5, &w, none), "the v0 root must matter");

        // The miner slot: amount, script bytes and script version each matter, and the length prefix
        // stops a byte moving between script and amount.
        let slot = MinerAccrualRef { script_version: 0, script: &[7u8; 43], amount: 100 };
        let with_slot = shielded_state_root_v1(&r0, 5, &w, slot);
        assert_ne!(with_slot, v1, "a carried reward must matter");
        assert_ne!(with_slot, shielded_state_root_v1(&r0, 5, &w, MinerAccrualRef { amount: 101, ..slot }));
        assert_ne!(with_slot, shielded_state_root_v1(&r0, 5, &w, MinerAccrualRef { script: &[8u8; 43], ..slot }));
        assert_ne!(with_slot, shielded_state_root_v1(&r0, 5, &w, MinerAccrualRef { script_version: 1, ..slot }));
        assert_ne!(with_slot, shielded_state_root_v1(&r0, 5, &w, MinerAccrualRef { script: &[7u8; 42], ..slot }));
    }

    #[test]
    fn deterministic() {
        assert_eq!(shielded_state_root(&A, &N, 7, 3, &B), shielded_state_root(&A, &N, 7, 3, &B));
    }

    #[test]
    fn sensitive_to_every_field() {
        let base = shielded_state_root(&A, &N, 7, 3, &B);
        assert_ne!(base, shielded_state_root(&[0x12; 32], &N, 7, 3, &B), "anchor must matter");
        assert_ne!(base, shielded_state_root(&A, &[0x23; 32], 7, 3, &B), "nullifier root must matter");
        assert_ne!(base, shielded_state_root(&A, &N, 8, 3, &B), "cumulative coinbase must matter");
        assert_ne!(base, shielded_state_root(&A, &N, 7, 4, &B), "cumulative fees must matter");
        assert_ne!(base, shielded_state_root(&A, &N, 7, 3, &[0x34; 32]), "burn root must matter");
    }

    #[test]
    fn coinbase_and_fees_are_not_interchangeable() {
        // Guards against a swapped-argument / concatenation-ambiguity bug where
        // (coinbase=a, fees=b) would collide with (coinbase=b, fees=a).
        assert_ne!(shielded_state_root(&A, &N, 5, 9, &B), shielded_state_root(&A, &N, 9, 5, &B));
    }

    /// **Cross-implementation pin for the peg-out guest.**
    ///
    /// The Kaspa-side guest recomputes this exact digest inside the zkVM to check that a claimed
    /// state root really corresponds to the burn set it is proving against. Both sides assert this
    /// vector, computed independently by a third implementation (Python `hashlib.blake2b` with
    /// `person=b"zkas_state_root0"`), so a personalization or field-order drift fails a test rather
    /// than every peg-out.
    #[test]
    fn state_root_matches_the_shared_wire_contract() {
        use crate::burn::{BurnAccumulator, ExitReceipt};

        let acc = BurnAccumulator::from_receipts([
            ExitReceipt { v: 5_000_000, recipient: [0xA1; 32], n: [0x11; 32] },
            ExitReceipt { v: 250_000, recipient: [0xB2; 32], n: [0x22; 32] },
        ]);
        assert_eq!(hex(&acc.root()), "4a457e6dd8976c5b52b7d7337244ef6478c87e916bdec6465d730ecd5e7fe5d3",);

        let root = shielded_state_root(&A, &N, 1_000_000_000, 12_345, &acc.root());
        assert_eq!(hex(&root), "4c803ec34ec41afe760122a9e84802fa93d41e38bb84f5d369a9616a8f91dfc7");
    }

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A burn must move the committed state root. If it did not, a peg-out could never be proved
    /// against the chain's own commitment — the receipt would be invisible to the Kaspa side.
    #[test]
    fn recording_a_burn_moves_the_state_root() {
        use crate::burn::{BurnAccumulator, ExitReceipt};

        let empty = BurnAccumulator::new();
        let mut one = BurnAccumulator::new();
        one.push(ExitReceipt { v: 5_000_000, recipient: [0xA1; 32], n: [0x11; 32] });

        assert_eq!(empty.root(), NO_BURNS, "an empty accumulator is the no-burns sentinel");
        assert_ne!(
            shielded_state_root(&A, &N, 100, 3, &empty.root()),
            shielded_state_root(&A, &N, 100, 3, &one.root()),
            "appending a burn receipt must change the state root",
        );
    }
}
