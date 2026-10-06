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

#[cfg(test)]
mod tests {
    use super::*;

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
