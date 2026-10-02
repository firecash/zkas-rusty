//! The shielded state transition (PLAN §2.4).
//!
//! This is the heart of the project: the per-chain-block update of the two
//! pieces of order-sensitive global state — the nullifier set and the global
//! note-commitment tree — applied strictly in GHOSTDAG **accepted order**, with
//! the turnstile invariant enforced after every step.
//!
//! It composes the three primitives ([`crate::tree`], [`crate::nullifier`],
//! [`crate::turnstile`]) into one function, [`ShieldedState::apply_chain_block`],
//! which mirrors exactly the five steps the virtual processor performs per
//! accepted chain block:
//!
//! 1. resolve nullifier conflicts (drop conflicting transactions, first wins);
//! 2. insert surviving nullifiers;
//! 3. append this block's chain-block subtree to the global tree → new anchor;
//! 4. check the turnstile invariant;
//! 5. (the caller publishes the new anchor into the finalized ring buffer).
//!
//! Keeping the algorithm here — pure and independent of rocksdb and the kaspa
//! pipeline — is what makes the make-or-break determinism property unit-testable
//! (see the parallel-double-spend test below and task #9).

use orchard::note::ExtractedNoteCommitment;
use orchard::tree::Anchor;

use crate::bundle::ShieldedBundle;
use crate::nullifier::{MemNullifierSet, NullifierBytes, NullifierConflictResolver, NullifierSet};
use crate::tree::{ChainBlockSubtree, GlobalTree, NoteCommitmentTree, TreeFull};
use crate::turnstile::{SupplyLedger, TurnstileViolation};

/// A transaction's shielded effects, extracted from its Orchard bundle, ready to
/// be applied in the order the consensus layer accepts it.
#[derive(Clone, Debug)]
pub struct ShieldedTx {
    /// Nullifiers revealed by the transaction's actions (conflict keys).
    pub nullifiers: Vec<NullifierBytes>,
    /// Note commitments created by the transaction's actions (tree leaves).
    pub commitments: Vec<ExtractedNoteCommitment>,
    /// Public fee paid by the transaction: value leaving the shielded pool to the
    /// miner. (Orchard `value_balance` for a pure shielded payment.)
    pub fee: u64,
    /// The anchor the bundle's spends prove against. Must be a finalized anchor
    /// (PLAN §2.5); enforced by the consensus validation layer.
    pub anchor: [u8; 32],
    /// An optional bridge peg-out declared by this transaction ([`crate::burn`]).
    ///
    /// `fee` is the total the binding signature proved is leaving the pool. When a burn is
    /// present, that total is **split**: `burn.v` is destroyed and recorded as an exit receipt,
    /// and the remaining `fee - burn.v` is paid to the miner as an ordinary fee. A burn may
    /// therefore never exceed `fee` — otherwise it would move value the bundle never authorised.
    pub burn: Option<crate::burn::ExitReceipt>,
}

/// Error extracting a [`ShieldedTx`] from an on-wire [`ShieldedBundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleExtractError {
    /// A note commitment was not a canonical Pallas base-field encoding.
    NonCanonicalCommitment,
    /// A bundle declared a burn but spends nothing, so it has no nullifier to key the exit by.
    /// Without a unique exit key the peg-out could be replayed on Kaspa.
    BurnWithoutSpend,
    /// A non-coinbase bundle declared a negative value balance, i.e. it claims to
    /// mint value into the pool — only the coinbase may do that (PLAN §2.7).
    MintingValueBalance,
    /// A bundle declared a bridge peg-out burn while the bridge is deactivated
    /// ([`crate::burn::BRIDGE_ENABLED`] is `false`). Consensus rejects such a tx up front in
    /// `check_shielded_in_isolation`; this is the defense-in-depth guard at the extractor, so a
    /// burn can never become an applied effect even if it reached here.
    BridgeDisabled,
    /// A bundle declared a burn larger than the value it proved is leaving the pool.
    ///
    /// Enforced at this constructor so the bound is an invariant of [`ShieldedTx`] rather than an
    /// agreement between two crates: `check_shielded_in_isolation` compares against
    /// `bundle.value_balance` while the state transition compares against `tx.fee`, and those
    /// coincide only because `fee` is derived from `value_balance` right here. The state
    /// transition's own check is block-FATAL — it disqualifies the block that MERGES the
    /// transaction — so one future change to fee derivation would re-arm a one-transaction
    /// permanent selected-chain halt.
    BurnExceedsValueBalance,
}

impl ShieldedTx {
    /// Extract the consensus-relevant shielded effects from a parsed bundle.
    ///
    /// This is the bridge from the on-wire [`ShieldedBundle`] (carried in the tx
    /// payload) to the input of the state transition. It does **not** verify the
    /// proof or signatures (that is the validation layer's job, PLAN §3); it only
    /// decodes the fields the state transition consumes — nullifiers, note
    /// commitments, and the public fee.
    pub fn from_bundle(bundle: &ShieldedBundle) -> Result<Self, BundleExtractError> {
        let mut commitments = Vec::with_capacity(bundle.actions.len());
        for a in &bundle.actions {
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or(BundleExtractError::NonCanonicalCommitment)?;
            commitments.push(cmx);
        }
        let nullifiers = bundle.actions.iter().map(|a| a.nullifier).collect();
        // A normal shielded transaction's value balance is its (non-negative) fee.
        if bundle.value_balance < 0 {
            return Err(BundleExtractError::MintingValueBalance);
        }
        // A bridge peg-out, if the bundle declared one. The exit-nullifier is the bundle's FIRST
        // action nullifier — a real spent-note nullifier, which ZKas consensus already guarantees
        // can never appear twice on the selected chain. So the Kaspa-side replay key inherits this
        // chain's own double-spend prevention rather than needing a separate uniqueness argument.
        let burn = match bundle.burn {
            // Bridge deactivated: refuse to lift a peg-out declaration into an applied effect. The
            // isolation check already rejects such a tx before it reaches consensus; this keeps the
            // extractor honest as a second line of defense (see [`crate::burn::BRIDGE_ENABLED`]).
            Some(_) if !crate::burn::BRIDGE_ENABLED => return Err(BundleExtractError::BridgeDisabled),
            Some((v, recipient)) => {
                // The bound, established where the type is built and against the same quantity the
                // context-free isolation rule uses. See `BurnExceedsValueBalance`.
                if i128::from(v) > i128::from(bundle.value_balance) {
                    return Err(BundleExtractError::BurnExceedsValueBalance);
                }
                let n = *bundle.nullifiers().next().ok_or(BundleExtractError::BurnWithoutSpend)?;
                Some(crate::burn::ExitReceipt { v, recipient, n })
            }
            None => None,
        };
        Ok(ShieldedTx { nullifiers, commitments, fee: bundle.value_balance as u64, anchor: bundle.anchor, burn })
    }
}

/// A coinbase note minted into the pool — the one transparent seam (PLAN §2.7).
/// Its value is public and must already have been checked against the emission
/// schedule by the caller.
#[derive(Clone, Debug)]
pub struct CoinbaseMint {
    /// One coinbase note per rewarded mergeset block (PLAN §2.7). Kaspa pays each
    /// merged block's miner separately (subsidy + that block's fees), so a chain
    /// block's coinbase mints a *set* of notes rather than one.
    pub notes: Vec<CoinbaseNote>,
}

/// A single coinbase note minted into the pool: a **publicly stated value**
/// (the rewarded block's subsidy + fees) and its note commitment.
///
/// The value is public (verifiable against the emission schedule and the observed
/// fees) and the commitment binds it, so a miner cannot mint more than the value
/// consensus checked. Each note's value enters the turnstile as `cumulative_coinbase
/// += value`; because a shielded tx's fee is re-minted here (in the coinbase of the
/// block that merges it) after leaving the pool as `value_balance`, the pool nets to
/// the cumulative *subsidy* — all value stays shielded (PLAN §2.6, §2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseNote {
    /// The note's public value: the rewarded block's subsidy plus its fees.
    pub value: u64,
    /// The coinbase note commitment (added to the tree like any other leaf).
    pub commitment: ExtractedNoteCommitment,
}

impl CoinbaseMint {
    /// A coinbase mint of the given notes.
    pub fn new(notes: Vec<CoinbaseNote>) -> Self {
        Self { notes }
    }

    /// The total value minted by this coinbase across all its notes.
    pub fn total_value(&self) -> u128 {
        self.notes.iter().map(|n| n.value as u128).sum()
    }
}

/// Why a shielded state transition was rejected (an invalid state — the block /
/// virtual state must be rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedStateError {
    /// The turnstile supply invariant was violated.
    Turnstile(TurnstileViolation),
    /// The global note-commitment tree is full (2^32 leaves).
    TreeFull,
    /// A transaction declared a burn larger than the value its bundle authorised to leave the
    /// pool (`burn.v > fee`). Accepting it would move unauthorised value.
    BurnExceedsValueBalance {
        /// The declared burn amount.
        burn: u64,
        /// The total value the bundle proved is leaving the pool.
        value_balance: u64,
    },
}

impl From<TurnstileViolation> for ShieldedStateError {
    fn from(v: TurnstileViolation) -> Self {
        ShieldedStateError::Turnstile(v)
    }
}

impl From<TreeFull> for ShieldedStateError {
    fn from(_: TreeFull) -> Self {
        ShieldedStateError::TreeFull
    }
}

/// The outcome of applying one chain block's shielded transactions.
#[derive(Clone, Debug)]
pub struct BlockShieldedOutcome {
    /// Indices into the input `txs` that survived conflict resolution.
    pub accepted: Vec<usize>,
    /// Nullifiers inserted into the finalized set, in acceptance order.
    pub new_nullifiers: Vec<NullifierBytes>,
    /// The chain-block subtree of accepted commitments (coinbase first).
    pub subtree: ChainBlockSubtree,
    /// The anchor after appending this block's subtree to the global tree.
    pub anchor: Anchor,
    /// Bridge exit receipts recorded by accepted transactions, in acceptance order. These are
    /// appended to the burn accumulator, whose root the shielded state root commits to.
    pub burn_receipts: Vec<crate::burn::ExitReceipt>,
}

/// The mutable shielded consensus state, advanced in GHOSTDAG accepted order.
///
/// This in-memory form is the reference the rocksdb-backed stores mirror; the
/// virtual processor reconstructs it from the persisted frontier / nullifier set
/// / supply totals and applies blocks through it.
#[derive(Clone, Debug)]
pub struct ShieldedState {
    /// Spent-nullifier set (append-only).
    pub nullifiers: MemNullifierSet,
    /// Global note-commitment tree (append-only; only the frontier is retained).
    pub tree: GlobalTree,
    /// Turnstile supply ledger.
    pub supply: SupplyLedger,
    /// Bridge burn accumulator; its root is folded into the shielded state root.
    pub burns: crate::burn::BurnAccumulator,
}

impl ShieldedState {
    /// The genesis (empty) shielded state.
    pub fn new() -> Self {
        Self {
            nullifiers: MemNullifierSet::new(),
            tree: GlobalTree::new(),
            supply: SupplyLedger::new(),
            burns: crate::burn::BurnAccumulator::new(),
        }
    }

    /// The current anchor (root of the global note-commitment tree).
    pub fn anchor(&self) -> Anchor {
        self.tree.anchor()
    }

    /// Apply one accepted chain block's shielded effects (PLAN §2.4, steps 1–4).
    ///
    /// `coinbase` is the block's coinbase mint (if any); `txs` are the block's
    /// shielded transactions **in accepted order**. Conflicting transactions
    /// (those reusing an already-spent nullifier) are dropped — first occurrence
    /// in accepted order wins, exactly as for transparent UTXO double-spends.
    ///
    /// On success the state is advanced and a [`BlockShieldedOutcome`] is
    /// returned. On a turnstile violation or a full tree the state is left
    /// unchanged and an error is returned (the caller rejects the block).
    pub fn apply_chain_block(
        &mut self,
        coinbase: Option<&CoinbaseMint>,
        txs: &[ShieldedTx],
    ) -> Result<BlockShieldedOutcome, ShieldedStateError> {
        // Disjoint borrows of the three fields are permitted by direct field access.
        let outcome = apply_chain_block_to(&self.nullifiers, &mut self.tree, &mut self.supply, coinbase, txs, &mut self.burns)?;
        self.nullifiers.extend(outcome.new_nullifiers.iter().copied());
        Ok(outcome)
    }
}

/// Apply one accepted chain block against an arbitrary finalized nullifier set.
///
/// This is the store-agnostic core of the state transition. The finalized
/// nullifier set is read through the [`NullifierSet`] trait, so the live
/// consensus path can back it directly by rocksdb without ever loading the whole
/// (unbounded, append-only) set into memory. `tree` and `supply` are advanced
/// **only on success**; on rejection they are left untouched, and the caller is
/// responsible for inserting [`BlockShieldedOutcome::new_nullifiers`] into the
/// finalized set.
pub fn apply_chain_block_to<S: NullifierSet + ?Sized>(
    finalized: &S,
    tree: &mut GlobalTree,
    supply: &mut SupplyLedger,
    coinbase: Option<&CoinbaseMint>,
    txs: &[ShieldedTx],
    burns: &mut crate::burn::BurnAccumulator,
) -> Result<BlockShieldedOutcome, ShieldedStateError> {
    // ---- Phase 1: resolve conflicts & gather effects ----
    let mut resolver = NullifierConflictResolver::new(finalized);
    let mut subtree = ChainBlockSubtree::new();
    let mut accepted = Vec::new();
    let mut total_fees: u128 = 0;
    let mut total_mint: u128 = 0;

    // Coinbase is processed first: it has no nullifiers, mints its notes' public
    // values, and contributes their commitments as the first leaves of the
    // subtree (in the coinbase's own note order, which every node recomputes
    // identically). Each note's value = a rewarded block's subsidy + fees, so
    // minting them re-mints the fees that left the pool as `value_balance` when
    // those blocks were accepted — the pool nets to the cumulative subsidy.
    if let Some(cb) = coinbase {
        for note in &cb.notes {
            total_mint += note.value as u128;
            subtree.push(note.commitment);
        }
    }

    let mut total_burns: u128 = 0;
    let mut burn_receipts = Vec::new();

    for (i, tx) in txs.iter().enumerate() {
        // A burn may never exceed what the bundle proved is leaving the pool. Checked before
        // conflict resolution so an invalid declaration invalidates the block rather than being
        // silently skipped.
        if let Some(receipt) = &tx.burn {
            if receipt.v > tx.fee {
                return Err(ShieldedStateError::BurnExceedsValueBalance { burn: receipt.v, value_balance: tx.fee });
            }
        }

        match resolver.try_accept(tx.nullifiers.iter().copied()) {
            Ok(()) => {
                for &cmx in &tx.commitments {
                    subtree.push(cmx);
                }
                // Split the declared value_balance: the burn leaves the pool as a recorded exit,
                // the remainder is an ordinary miner fee.
                let burn_value = tx.burn.as_ref().map_or(0, |r| r.v);
                total_burns += burn_value as u128;
                total_fees += (tx.fee - burn_value) as u128;
                if let Some(receipt) = &tx.burn {
                    burn_receipts.push(*receipt);
                }
                accepted.push(i);
            }
            // Conflicting transaction: dropped (double-spend), records nothing — including no
            // burn receipt. A dropped peg-out must not become claimable on Kaspa.
            Err(_) => {}
        }
    }
    let new_nullifiers = resolver.into_accepted();

    // ---- Phase 2: commit effects to working copies, swap in on success ----
    let mut new_tree = tree.clone();
    let mut new_supply = supply.clone();

    if total_mint > 0 {
        new_supply.mint_coinbase(u64::try_from(total_mint).map_err(|_| TurnstileViolation::Overflow)?)?;
    }
    if total_fees > 0 {
        new_supply.collect_fees(u64::try_from(total_fees).map_err(|_| TurnstileViolation::Overflow)?)?;
    }
    if total_burns > 0 {
        new_supply.burn(u64::try_from(total_burns).map_err(|_| TurnstileViolation::Overflow)?)?;
    }

    // Step 3: append this block's subtree to the global tree, producing the anchor.
    new_tree.append_subtree(&subtree)?;
    let anchor = new_tree.anchor();

    // Step 4: the turnstile invariant must hold after the update.
    new_supply.check()?;

    // All checks passed: commit to the caller's tree/supply/burn accumulator. The accumulator is
    // appended last so a rejected block leaves it untouched.
    *tree = new_tree;
    *supply = new_supply;
    for receipt in &burn_receipts {
        burns.push(*receipt);
    }

    Ok(BlockShieldedOutcome { accepted, new_nullifiers, subtree, anchor, burn_receipts })
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmx(n: u32) -> ExtractedNoteCommitment {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        Option::from(ExtractedNoteCommitment::from_bytes(&b)).expect("canonical")
    }

    fn nf(n: u8) -> NullifierBytes {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    fn tx(nfs: &[u8], cmxs: &[u32], fee: u64) -> ShieldedTx {
        ShieldedTx {
            burn: None,
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee,
            anchor: [0u8; 32],
        }
    }

    /// While the bridge is deactivated, `from_bundle` refuses to lift a declared burn into an
    /// applied effect. If the master switch is ever flipped, the same declaration is extracted into
    /// an exit receipt keyed by the bundle's first spent nullifier (the pre-deactivation behavior).
    #[test]
    fn burn_declaration_is_rejected_while_bridge_disabled() {
        use crate::bundle::{BUNDLE_FLAG_BURN, ShieldedBundle};

        let mut bundle = ShieldedBundle::sample_for_test(2);
        bundle.value_balance = 30;
        bundle.flags |= BUNDLE_FLAG_BURN;
        bundle.burn = Some((20, [0xA1; 32]));

        if crate::burn::BRIDGE_ENABLED {
            let stx = ShieldedTx::from_bundle(&bundle).unwrap();
            let receipt = stx.burn.expect("burn must be extracted");
            assert_eq!(receipt.v, 20);
            assert_eq!(receipt.recipient, [0xA1; 32]);
            assert_eq!(receipt.n, bundle.actions[0].nullifier, "exit key is the first spent nullifier");
            assert_eq!(stx.fee, 30, "fee still carries the full declared value_balance");
        } else {
            assert!(
                matches!(ShieldedTx::from_bundle(&bundle), Err(BundleExtractError::BridgeDisabled)),
                "a peg-out burn must be refused while the bridge is off"
            );
        }
    }

    /// A burn with nothing spent has no unique exit key. While the bridge is off it is rejected as
    /// `BridgeDisabled` (the switch is checked first); with the bridge on it is rejected for the
    /// missing spend key.
    #[test]
    fn burn_without_a_spend_is_rejected() {
        use crate::bundle::{BUNDLE_FLAG_BURN, ShieldedBundle};

        let mut bundle = ShieldedBundle::sample_for_test(0);
        bundle.value_balance = 30;
        bundle.flags |= BUNDLE_FLAG_BURN;
        bundle.burn = Some((20, [0xA1; 32]));

        let expected =
            if crate::burn::BRIDGE_ENABLED { BundleExtractError::BurnWithoutSpend } else { BundleExtractError::BridgeDisabled };
        assert_eq!(ShieldedTx::from_bundle(&bundle).unwrap_err(), expected);
    }

    fn burn_tx(nfs: &[u8], cmxs: &[u32], value_balance: u64, burn_v: u64, tag: u8) -> ShieldedTx {
        ShieldedTx {
            burn: Some(crate::burn::ExitReceipt { v: burn_v, recipient: [tag; 32], n: [tag.wrapping_add(0x90); 32] }),
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee: value_balance,
            anchor: [0u8; 32],
        }
    }

    /// A burn splits the declared `value_balance`: part is destroyed and recorded as an exit
    /// receipt, the rest is an ordinary miner fee. Both leave the pool.
    #[test]
    fn burn_splits_value_balance_and_records_a_receipt() {
        let mut st = ShieldedState::new();
        let out = st
            .apply_chain_block(
                Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 100, commitment: cmx(10) }])),
                // value_balance 30, of which 20 is burned to the bridge and 10 is a fee.
                &[burn_tx(&[1], &[100], 30, 20, 0xAA)],
            )
            .expect("valid block");

        assert_eq!(out.burn_receipts.len(), 1);
        assert_eq!(out.burn_receipts[0].v, 20);
        assert_eq!(st.supply.cumulative_burns(), 20);
        assert_eq!(st.supply.cumulative_fees(), 10);
        // pool = 100 minted - 10 fee - 20 burned
        assert_eq!(st.supply.pool_value().unwrap(), 70);
        // The accumulator advanced, so the state root will change.
        assert_eq!(st.burns.len(), 1);
        assert_ne!(st.burns.root(), [0u8; 32]);
    }

    /// A burn larger than the value the bundle proved is leaving the pool must invalidate the
    /// block. Otherwise a peg-out could claim value the binding signature never authorised —
    /// i.e. mint on the Kaspa side out of thin air.
    #[test]
    fn burn_exceeding_value_balance_is_rejected() {
        let mut st = ShieldedState::new();
        let err = st
            .apply_chain_block(
                Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 100, commitment: cmx(10) }])),
                &[burn_tx(&[1], &[100], 10, 50, 0xBB)],
            )
            .expect_err("burn > value_balance must be rejected");

        assert_eq!(err, ShieldedStateError::BurnExceedsValueBalance { burn: 50, value_balance: 10 });
        // State untouched.
        assert_eq!(st.supply.cumulative_burns(), 0);
        assert_eq!(st.burns.len(), 0);
    }

    /// **A dropped double-spend must not record its burn.** If a conflicting transaction's exit
    /// receipt still entered the accumulator, the peg-out would become claimable on Kaspa even
    /// though the burn never happened — value created from nothing.
    #[test]
    fn dropped_double_spend_records_no_burn() {
        let mut st = ShieldedState::new();

        // First block spends nullifier 1 and burns 20.
        st.apply_chain_block(
            Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 100, commitment: cmx(10) }])),
            &[burn_tx(&[1], &[100], 30, 20, 0xAA)],
        )
        .expect("first spend accepted");
        assert_eq!(st.burns.len(), 1);
        let root_after_first = st.burns.root();

        // Second block re-spends the same nullifier and tries to burn again.
        let out = st
            .apply_chain_block(
                Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 100, commitment: cmx(11) }])),
                &[burn_tx(&[1], &[101], 30, 20, 0xCC)],
            )
            .expect("block is valid; the conflicting tx is merely dropped");

        assert!(out.accepted.is_empty(), "the double-spend must be dropped");
        assert!(out.burn_receipts.is_empty(), "a dropped tx must record no exit receipt");
        assert_eq!(st.burns.len(), 1, "accumulator must not have grown");
        assert_eq!(st.burns.root(), root_after_first, "burn root must be unchanged");
        assert_eq!(st.supply.cumulative_burns(), 20, "no second burn was charged");
    }

    /// Burns are subject to the same anti-inflation rule as fees: they cannot take more out of
    /// the pool than was ever issued.
    #[test]
    fn burn_cannot_drain_more_than_issuance() {
        let mut st = ShieldedState::new();
        let err = st
            .apply_chain_block(
                Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 10, commitment: cmx(10) }])),
                &[burn_tx(&[1], &[100], 50, 50, 0xDD)],
            )
            .expect_err("burning more than issuance must violate the turnstile");
        assert!(matches!(err, ShieldedStateError::Turnstile(_)));
        assert_eq!(st.burns.len(), 0, "a rejected block must leave the accumulator untouched");
    }

    /// THE make-or-break property (PLAN Phase 1 / task #9), at the algorithm
    /// level: two parallel chain blocks each spend the same shielded note. Once
    /// GHOSTDAG linearizes them, two independent nodes that apply that same
    /// accepted order must compute an identical anchor, exactly one spend
    /// survives, the nullifier is recorded once, and no value is created.
    #[test]
    fn parallel_double_spend_one_survives_identical_anchor_no_inflation() {
        // Note with nullifier nf(1) is spent by a tx in block X and by a tx in
        // block Y (produced in parallel). GHOSTDAG accepted order: [X, Y].
        // Each block also has a coinbase minting 50 and creating a coinbase note.
        let build = || {
            let mut st = ShieldedState::new();

            // Block X (accepted first): coinbase + tx spending nf(1), fee 5, new note cmx(100).
            let out_x = st
                .apply_chain_block(
                    Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 50, commitment: cmx(10) }])),
                    &[tx(&[1], &[100], 5)],
                )
                .unwrap();
            assert_eq!(out_x.accepted, vec![0], "X's spend is the first occurrence -> accepted");

            // Block Y (accepted second): coinbase + tx ALSO spending nf(1), new note cmx(200).
            let out_y = st
                .apply_chain_block(
                    Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 50, commitment: cmx(20) }])),
                    &[tx(&[1], &[200], 5)],
                )
                .unwrap();
            assert!(out_y.accepted.is_empty(), "Y's spend reuses nf(1) -> dropped as a double-spend");

            st
        };

        // Two independent "nodes" build from the same accepted order.
        let node_a = build();
        let node_b = build();

        // 1) Identical anchor across nodes.
        assert_eq!(node_a.anchor().to_bytes(), node_b.anchor().to_bytes());

        // 2) The double-spent nullifier is recorded exactly once.
        assert_eq!(node_a.nullifiers.len(), 1);
        assert!(node_a.nullifiers.contains(&nf(1)));

        // 3) No value created: pool = coinbase(100) - fees(5 from the single accepted tx).
        //    Block Y's tx was dropped, so its fee never applies.
        assert_eq!(node_a.supply.pool_value().unwrap(), 100 - 5);

        // 4) Tree holds: 2 coinbase notes + 1 accepted-tx note = 3 leaves.
        assert_eq!(node_a.tree.size(), 3);
    }

    /// Distinct spends in parallel blocks both survive, and the anchor is
    /// independent of which node assembled which block — it depends only on the
    /// accepted order, which GHOSTDAG fixes.
    #[test]
    fn distinct_parallel_spends_all_survive() {
        // fee 0: with no coinbase there is no pool to pay fees from (the turnstile
        // would correctly reject a fee here — covered by its own test).
        let mut st = ShieldedState::new();
        let a = st.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        assert_eq!(a.accepted, vec![0]);
        let b = st.apply_chain_block(None, &[tx(&[2], &[200], 0)]).unwrap();
        assert_eq!(b.accepted, vec![0]);
        assert_eq!(st.nullifiers.len(), 2);
        assert_eq!(st.tree.size(), 2);
    }

    /// THE fee-reminting property (PLAN §2.7 turnstile), across a chain of
    /// blocks: a shielded transaction's fee `value_balance` LEAVES the pool when
    /// its block is accepted, and is RE-MINTED into the coinbase note of a later
    /// block (whose value = that block's subsidy + the fees it merges). Over the
    /// full cycle the pool must net to the cumulative subsidy — fees create no
    /// net inflation and are not burned. This is the accounting the live
    /// `apply_chain_block_to` performs (mint_coinbase + collect_fees); here we
    /// drive it end-to-end and pin the invariant, plus a counterfactual proving
    /// the re-mint is load-bearing.
    #[test]
    fn fee_cycle_re_mints_and_pool_nets_to_cumulative_subsidy() {
        const SUBSIDY: u64 = 10_000;
        const FEE: u64 = 2_000;

        let mut st = ShieldedState::new();

        // Block 1: pure coinbase, one subsidy, no fees. pool = subsidy.
        st.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY, commitment: cmx(1) }])), &[]).unwrap();
        assert_eq!(st.supply.pool_value().unwrap(), SUBSIDY as u128);

        // Block 2: a shielded payment pays FEE (value leaves the pool), AND this
        // block's coinbase re-mints that fee: its note value = subsidy + FEE.
        // (In the live path Kaspa's coinbase manager sets this output value to
        // the merged block's subsidy + collected fees; build_coinbase_mint turns
        // it into the note value.)
        st.apply_chain_block(
            Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY + FEE, commitment: cmx(2) }])),
            &[tx(&[1], &[100], FEE)],
        )
        .unwrap();

        // Block 3: another plain subsidy, no fees.
        st.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY, commitment: cmx(3) }])), &[]).unwrap();

        // Turnstile: pool == cumulative subsidy. The FEE left the pool in block 2
        // and returned via block 2's coinbase re-mint; it neither inflated the
        // supply nor was burned.
        let cumulative_subsidy = (SUBSIDY as u128) * 3;
        assert_eq!(st.supply.pool_value().unwrap(), cumulative_subsidy, "pool must net to cumulative subsidy");

        // Counterfactual: if block 2 had NOT re-minted the fee (coinbase value =
        // bare subsidy), the same accepted txs would leave the pool short by
        // exactly FEE — proving the re-mint is what closes the loop, not that the
        // fee is silently ignored.
        let mut no_remint = ShieldedState::new();
        no_remint.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY, commitment: cmx(1) }])), &[]).unwrap();
        no_remint
            .apply_chain_block(
                Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY, commitment: cmx(2) }])),
                &[tx(&[1], &[100], FEE)],
            )
            .unwrap();
        no_remint.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: SUBSIDY, commitment: cmx(3) }])), &[]).unwrap();
        assert_eq!(
            no_remint.supply.pool_value().unwrap(),
            cumulative_subsidy - FEE as u128,
            "without the re-mint the pool is short by exactly the fee"
        );
    }

    /// A double-spend across blocks must not change the anchor relative to simply
    /// not including the conflicting transaction at all.
    #[test]
    fn dropped_double_spend_does_not_affect_anchor() {
        // With the conflicting tx present (but dropped):
        let mut with_conflict = ShieldedState::new();
        with_conflict.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        with_conflict.apply_chain_block(None, &[tx(&[1], &[200], 0)]).unwrap(); // dropped

        // Without the conflicting tx at all (second block empty):
        let mut without = ShieldedState::new();
        without.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        without.apply_chain_block(None, &[]).unwrap();

        assert_eq!(with_conflict.anchor().to_bytes(), without.anchor().to_bytes());
        assert_eq!(with_conflict.tree.size(), without.tree.size());
    }

    fn action(nf_seed: u8, cmx_n: u32) -> crate::bundle::ActionWire {
        use crate::bundle::sizes;
        let mut cmxb = [0u8; 32];
        cmxb[0..4].copy_from_slice(&cmx_n.to_le_bytes());
        crate::bundle::ActionWire {
            nullifier: nf(nf_seed),
            rk: [0; 32],
            cmx: cmxb,
            cv_net: [0; 32],
            ephemeral_key: [0; 32],
            enc_ciphertext: [0; sizes::ENC_CIPHERTEXT],
            out_ciphertext: [0; sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [0; sizes::SIG],
        }
    }

    #[test]
    fn extract_shielded_tx_from_bundle() {
        let bundle = ShieldedBundle {
            actions: vec![action(1, 100), action(2, 101)],
            burn: None,
            flags: 0b11,
            value_balance: 7,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
        };
        let stx = ShieldedTx::from_bundle(&bundle).unwrap();
        assert_eq!(stx.nullifiers, vec![nf(1), nf(2)]);
        assert_eq!(stx.commitments.len(), 2);
        assert_eq!(stx.fee, 7);
    }

    #[test]
    fn extract_rejects_minting_value_balance() {
        let bundle = ShieldedBundle {
            actions: vec![],
            flags: 0,
            value_balance: -1,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
            burn: None,
        };
        assert!(matches!(ShieldedTx::from_bundle(&bundle), Err(BundleExtractError::MintingValueBalance)));
    }

    #[test]
    fn extract_rejects_non_canonical_commitment() {
        let mut bad = action(1, 0);
        bad.cmx = [0xff; 32]; // not a canonical Pallas base-field element
        let bundle = ShieldedBundle {
            actions: vec![bad],
            flags: 0,
            value_balance: 0,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
            burn: None,
        };
        assert!(matches!(ShieldedTx::from_bundle(&bundle), Err(BundleExtractError::NonCanonicalCommitment)));
    }

    /// Spending more than has been minted is rejected (turnstile), and the state
    /// is left unchanged on rejection.
    #[test]
    fn turnstile_rejects_overspend_and_preserves_state() {
        let mut st = ShieldedState::new();
        st.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 10, commitment: cmx(1) }])), &[]).unwrap();
        let anchor_before = st.anchor().to_bytes();

        // A block whose fees (11) exceed the pool (10) -> PoolUnderflow -> rejected.
        let err = st.apply_chain_block(None, &[tx(&[5], &[2], 11)]).unwrap_err();
        assert_eq!(err, ShieldedStateError::Turnstile(TurnstileViolation::PoolUnderflow { coinbase: 10, fees: 11 }));

        // State unchanged: anchor, nullifiers and tree are as before the bad block.
        assert_eq!(st.anchor().to_bytes(), anchor_before);
        assert!(!st.nullifiers.contains(&nf(5)));
        assert_eq!(st.tree.size(), 1);
    }
}

/// End-to-end value loop with **real cryptography** (circuit feature): a coinbase
/// note enters the pool, a real wallet-built + proven bundle spends it, the
/// consensus verifier accepts it, and the §2.4 state transition applies it. This
/// exercises coinbase issuance → tree/anchor → real proof → verify → nullifier /
/// turnstile / tree in one flow — the make-or-break economic loop (PLAN §2.4/2.6/2.7).
#[cfg(all(test, feature = "circuit"))]
mod circuit_e2e {
    use super::*;
    use crate::coinbase::{CoinbaseNoteDesc, coinbase_note_commitment};
    use crate::verify::{sighash, verify_bundle};
    use crate::wallet::build::{ShieldedKeys, build_spend_bundle};
    use incrementalmerkletree::{Hashable, Level};
    use orchard::{
        circuit::ProvingKey,
        note::{Note, RandomSeed, Rho},
        tree::{MerkleHashOrchard, MerklePath},
        value::NoteValue,
    };

    fn canon(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = seed;
        b
    }

    #[test]
    fn coinbase_note_is_spent_end_to_end() {
        let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
        let keys = ShieldedKeys::from_seed([5u8; 32]).unwrap();
        let net = [0x77u8; 32];

        // --- Block 1: a coinbase note worth 10_000 enters the pool for the wallet. ---
        let value = 10_000u64;
        let rho = Option::<Rho>::from(Rho::from_bytes(&canon(1))).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(2), &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();

        // Consensus recomputes the coinbase note commitment from its public
        // description + value, and it must equal the wallet's own note commitment.
        let desc = CoinbaseNoteDesc { recipient: keys.address().to_raw_address_bytes(), rho: canon(1), rseed: canon(2) };
        let cmx = coinbase_note_commitment(&desc, value).unwrap();
        assert_eq!(
            cmx.to_bytes(),
            ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            "consensus recompute == wallet note commitment"
        );

        let mut st = ShieldedState::new();
        st.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value, commitment: cmx }])), &[]).unwrap();
        let anchor1 = st.anchor();

        // The coinbase note is leaf 0; its authentication path is the empty-subtree
        // roots, which must root to the manager's anchor (frontier root ==
        // authentication-path root — the linchpin that lets wallets prove membership).
        let auth_path: [MerkleHashOrchard; 32] =
            core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
        let merkle_path = MerklePath::from_parts(0, auth_path);
        assert_eq!(merkle_path.root(cmx).to_bytes(), anchor1.to_bytes(), "single-leaf frontier root == path root");

        // --- Block 2: the wallet spends the coinbase note (real proof). ---
        let recipient = ShieldedKeys::from_seed([6u8; 32]).unwrap().address();
        let output_value = 8_000u64;
        let ctx = b"e2e";
        let wire = build_spend_bundle(&pk, &keys, note, merkle_path, recipient, output_value, &net, ctx, rand::rng()).unwrap();

        // The consensus verifier accepts the real bundle, and it spends against the
        // coinbase anchor with the expected public fee.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("real spend bundle must verify");
        assert_eq!(wire.value_balance, (value - output_value) as i64, "fee = 2_000");
        assert_eq!(wire.anchor, anchor1.to_bytes(), "spends against the coinbase anchor");

        // The §2.4 transition applies it: nullifier inserted, fee collected, tree advanced.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        assert_eq!(stx.fee, 2_000);
        let out2 = st.apply_chain_block(None, &[stx.clone()]).unwrap();
        assert_eq!(out2.accepted, vec![0], "the real spend is accepted");

        // Turnstile: minted 10_000 (coinbase), collected 2_000 fee -> pool 8_000.
        // The 2_000 fee left the pool (to be re-minted in a later coinbase); the
        // 8_000 transferred note remains shielded, so the pool equals output_value.
        let fee = value - output_value;
        assert_eq!(st.supply.pool_value().unwrap(), (value - fee) as u128);
        assert_eq!(st.supply.pool_value().unwrap(), output_value as u128);

        // Double-spend guard: replaying the same real nullifier is dropped.
        let out3 = st.apply_chain_block(None, &[stx]).unwrap();
        assert!(out3.accepted.is_empty(), "reused nullifier -> dropped");
    }
}
