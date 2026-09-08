//! Consensus driver for the shielded state transition (PLAN §2.4), reorg-safe.
//!
//! Binds the per-chain-block shielded stores ([`crate::model::stores::shielded`])
//! to the store-agnostic state transition in `kaspa-shielded-core`. The virtual
//! processor advances the shielded state along the selected chain by applying a
//! run of accepted chain blocks ([`ShieldedStateManager::apply_chain`]) and, on
//! reorg, reverting the abandoned branch ([`ShieldedStateManager::revert_chain`]).
//!
//! Reorg safety (decision D10): the note-commitment tree frontier and the
//! turnstile totals are snapshotted per chain block, so extending a block loads
//! its selected parent's snapshot. The global nullifier set is append-only for
//! the selected chain; each block records the nullifiers it added so a reorg can
//! remove them. The unbounded nullifier set is never loaded into memory — the
//! finalized membership check goes straight to rocksdb, layered with nullifiers
//! accepted earlier in the same run.

use std::sync::Arc;

use kaspa_consensus_core::BlockHashSet;
use kaspa_consensus_core::tx::Transaction;
use kaspa_database::prelude::{CachePolicy, DB, StoreError, StoreResult};
use kaspa_hashes::Hash;
use kaspa_shielded_core::ExtractedNoteCommitment;
use kaspa_shielded_core::coinbase::{coinbase_note, derive_coinbase_note_desc};
use kaspa_shielded_core::nullifier::{MemNullifierSet, NullifierBytes, NullifierConflictResolver, NullifierSet};
use kaspa_shielded_core::state::CoinbaseNote;
use kaspa_shielded_core::state::{BlockShieldedOutcome, CoinbaseMint, ShieldedStateError, ShieldedTx, apply_chain_block_to};
use kaspa_shielded_core::tree::{FrontierState, GlobalTree, NoteCommitmentTree, TreeStateError};
use kaspa_shielded_core::turnstile::SupplyLedger;
use kaspa_shielded_core::wallet::CompactActionRecord;

use rocksdb::WriteBatch;

use kaspa_muhash::MuHash;

use crate::model::stores::shielded::DbAnchorGcQueueStore;
use crate::model::stores::shielded::{
    AnchorBlockStoreReader, AnchorProducersStoreReader, BurnReceipts, DbAnchorBlockStore, DbAnchorProducersStore,
    DbNullifierDiffStore, DbNullifierSetStore, DbShieldedAnchorSourceScoreStore, DbShieldedBurnStore, DbShieldedDevAccruedStore,
    DbShieldedNullifierMuHashStore,
    DbShieldedScanBlockStore, DbShieldedSupplyStore, DbShieldedTreeStore, NullifierDiffStoreReader, NullifierSetStore,
    NullifierSetStoreReader, ShieldedBurnStoreReader, ShieldedNullifierMuHashStoreReader, ShieldedScanBlockData,
    ShieldedScanBlockStoreReader, ShieldedSupplyStoreReader, ShieldedTreeStoreReader, SupplyTotals,
};

/// A computed (not-yet-persisted) shielded transition for one chain block.
///
/// Produced by [`ShieldedStateManager::compute`] in the validation phase and
/// persisted by [`ShieldedStateManager::persist`] in the commit phase.
pub struct ComputedBlockShielded {
    /// The global note-commitment tree frontier after this block.
    pub frontier_state: FrontierState,
    /// The turnstile cumulative totals after this block.
    pub supply_totals: SupplyTotals,
    /// The MuHash accumulator over the whole spent-nullifier set after this block
    /// (its selected parent's accumulator with this block's new nullifiers added).
    pub nullifier_muhash: MuHash,
    /// Conflict-resolution outcome: surviving txs, new nullifiers, new anchor.
    pub outcome: BlockShieldedOutcome,
    /// The bridge burn accumulator after this block (selected parent's snapshot plus any exit
    /// receipts this block recorded). Its root is committed by [`Self::state_root`].
    pub burns: BurnReceipts,
    /// Compact scan record of this block's applied effects (PLAN §2.9), attached by
    /// the virtual processor from the block-time applied set. `None` on the template
    /// path (nothing to persist) or a shielded-inactive block; `persist` writes it in
    /// the commit batch when present.
    pub scan_block: Option<ShieldedScanBlockData>,
}

impl ComputedBlockShielded {
    /// The anchor (global tree root) as of this block.
    pub fn anchor(&self) -> [u8; 32] {
        self.outcome.anchor.to_bytes()
    }

    /// The finalized 32-byte root of the nullifier-set accumulator after this block.
    pub fn nullifier_root(&self) -> [u8; 32] {
        let mut m = self.nullifier_muhash.clone();
        m.finalize().as_bytes().to_owned()
    }

    /// The canonical shielded state root after this block (PLAN §2.10): binds the
    /// note-commitment tree root, the nullifier-set accumulator, and the turnstile
    /// totals into one 32-byte commitment a block can attest to.
    pub fn state_root(&self) -> [u8; 32] {
        kaspa_shielded_core::commitment::shielded_state_root(
            &self.anchor(),
            &self.nullifier_root(),
            self.supply_totals.cumulative_coinbase,
            self.supply_totals.cumulative_fees,
            &self.burns.to_accumulator().root(),
        )
    }
}

/// Compact, verifiable summary of the shielded state at one chain block, used to
/// transfer that state to a fast-syncing node during pruning-point IBD (PLAN
/// §2.8/§2.9). The unbounded global nullifier *set* is streamed separately; this
/// metadata plus the streamed set fully determine the stores that
/// [`ShieldedStateManager::seed_pruning_point_shielded`] writes.
///
/// The declared `state_root` is recomputed on import and cross-checked against the
/// transferred parts. That is an internal-consistency check only — the true
/// consensus binding is the #24 coinbase commitment (`shielded_commitment =
/// state_root(selected_parent)`), which is enforced automatically when the pruning
/// point's first selected-chain child is validated: a peer that seeds wrong state
/// causes every real child of the pruning point to fail coinbase validation, so
/// the node makes no progress rather than adopting corrupt state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PruningPointShieldedMetadata {
    /// The global note-commitment tree frontier at the pruning point.
    pub frontier: FrontierState,
    /// Turnstile cumulative totals at the pruning point.
    pub supply: SupplyTotals,
    /// MuHash accumulator over the whole spent-nullifier set at the pruning point.
    pub nullifier_muhash: MuHash,
    /// Bridge burn accumulator at the pruning point. Transferred in full (not just its root)
    /// because a fast-synced node must be able to serve Merkle branches for past peg-outs; without
    /// it, receipts burned before the pruning point would become unprovable on Kaspa.
    #[serde(default)]
    pub burns: BurnReceipts,
    /// Declared shielded state root at the pruning point (anchor + nullifier-set
    /// accumulator + turnstile totals + burn root), recomputed and cross-checked on import.
    pub state_root: [u8; 32],
    /// `(anchor, source block)` for the selected-chain blocks in
    /// `[pruning_point - max_shielded_anchor_age, pruning_point)` — the anchors a spend mined
    /// just above the pruning point is still allowed to prove against.
    ///
    /// **Without these a fast-synced node cannot join the network at all.** Anchor finality is
    /// decided by `anchor_source_block(anchor)`, and an unknown anchor fails CLOSED
    /// (`is_shielded_anchor_final` → `false`, the F-04 anti-inflation choice). A syncee builds
    /// that index only for blocks it validates itself, i.e. from the pruning point forward, so
    /// every spend anchored below the pruning point is judged non-final and DROPPED. The real
    /// chain applied it, so the real coinbase re-mints its fee and the syncee's expected coinbase
    /// does not — `BadCoinbaseTransaction`, block disqualified, virtual frozen, permanently.
    ///
    /// Reproduced on a clean node 2026-07-31: pruning point at DAA 303,680, first disqualified
    /// block at DAA 303,686 — the 6th block after it, and the first whose mergeset carried an
    /// applied spend (coinbase 57.06905 + 3.0 ZKAS, i.e. subsidy plus fees).
    ///
    /// The window is bounded by consensus (`max_shielded_anchor_age`, 27,000 blocks at 1 BPS), so
    /// this is ~1.7 MB of `(32B, 32B)` pairs — anchors older than the window are provably
    /// unusable and are deliberately not sent. `#[serde(default)]` keeps the wire backward
    /// compatible with peers that predate the field.
    #[serde(default)]
    pub in_window_anchors: Vec<([u8; 32], Hash)>,

    /// Dev fee accrued but unpaid at the pruning point.
    ///
    /// A fast-syncing node must start with the exact value, or its very first coinbase
    /// check disagrees with the chain and it makes no progress (fail-closed, same shape
    /// as a wrong frontier). Zero before dev-fee accrual activates, so this is inert on
    /// every pre-fork sync.
    ///
    /// Wire compatibility: bincode is positional, so a peer that predates the field
    /// sends a shorter blob — [`Self::from_wire_bytes`] falls back to the legacy layout
    /// rather than failing. The other direction is already safe because
    /// `bincode::deserialize` allows trailing bytes, so an older peer simply ignores it.
    #[serde(default)]
    pub dev_accrued: u64,

    /// Blue score of each block named as a source in [`Self::in_window_anchors`].
    ///
    /// Without this a fast-synced node still cannot use those anchors, and
    /// [`Self::in_window_anchors`] alone does not fix the bug it was added for.
    /// `is_shielded_anchor_final` needs two things: WHICH block produced the root (the
    /// mapping, transferred above) and WHETHER that block is a matured chain ancestor. The
    /// second is read from `ghostdag_store.get_blue_score(source)` — and for a source below
    /// the pruning point, a fast-synced node has no ghostdag data at all, so the lookup fails
    /// and the anchor is judged non-final exactly as if it had never been transferred.
    ///
    /// `params.rs` asserts the opposite — that an in-window anchor's source "always has
    /// ghostdag/reachability data on every synced node (full, pruned or IBD-seeded)" because
    /// `max_shielded_anchor_age < pruning_depth - finality_depth`. That reasoning measures the
    /// anchor's age from the TIP. A node in IBD validates blocks sitting AT its pruning point,
    /// so their anchors reach BELOW it by construction. Measured on mainnet 2026-08-08:
    /// pruning point blue score 993,600; the first disqualified block 993,652 (+52); its
    /// anchor's source 990,606 — 2,994 BELOW the pruning point, at a perfectly legal age of
    /// 3,046 inside the `[600, 27000]` window. The node dropped the spend, omitted its
    /// 24,578,600 fee from the coinbase it expected, and disqualified the block; every later
    /// block inherited. That is the whole failure.
    ///
    /// Ancestry needs no transfer: the server builds this walking its OWN selected chain below
    /// the pruning point, and the pruning point is PoW-committed and on the syncee's chain too,
    /// so every source here is a selected-chain ancestor of every block above it.
    ///
    /// Not fail-open (audit F-04): an anchor whose source is absent from this set is still
    /// judged non-final. It only lets a node use anchors the serving peer explicitly attested,
    /// bounded to the window below the adopted pruning point.
    ///
    /// Wire compatibility: appended LAST, so a peer that predates it sends a shorter blob and
    /// [`Self::from_wire_bytes`] falls back — the same positional-bincode discipline
    /// `dev_accrued` needed. Empty means "peer cannot attest", which fails closed.
    #[serde(default)]
    pub in_window_anchor_source_scores: Vec<(Hash, u64)>,
}

/// The pre-accrual wire layout, kept only so [`PruningPointShieldedMetadata::from_wire_bytes`]
/// can still decode a blob from a peer that has not upgraded yet. Field order and types must
/// stay byte-identical to the current struct minus `dev_accrued`.
#[derive(serde::Deserialize)]
struct LegacyPruningPointShieldedMetadata {
    frontier: FrontierState,
    supply: SupplyTotals,
    nullifier_muhash: MuHash,
    #[serde(default)]
    burns: BurnReceipts,
    state_root: [u8; 32],
    #[serde(default)]
    in_window_anchors: Vec<([u8; 32], Hash)>,
}

impl From<LegacyPruningPointShieldedMetadata> for PruningPointShieldedMetadata {
    fn from(v: LegacyPruningPointShieldedMetadata) -> Self {
        Self {
            frontier: v.frontier,
            supply: v.supply,
            nullifier_muhash: v.nullifier_muhash,
            burns: v.burns,
            state_root: v.state_root,
            in_window_anchors: v.in_window_anchors,
            dev_accrued: 0,
            in_window_anchor_source_scores: Vec::new(),
        }
    }
}

/// The layout as of `dev_accrued` but before `in_window_anchor_source_scores`, so a peer that
/// carries the accrual but not the scores still decodes. Must stay byte-identical to the current
/// struct minus the trailing field — this is the third wire generation, and each one only works
/// because the new field went on the END.
#[derive(serde::Deserialize)]
struct PreAnchorScoresPruningPointShieldedMetadata {
    frontier: FrontierState,
    supply: SupplyTotals,
    nullifier_muhash: MuHash,
    #[serde(default)]
    burns: BurnReceipts,
    state_root: [u8; 32],
    #[serde(default)]
    in_window_anchors: Vec<([u8; 32], Hash)>,
    #[serde(default)]
    dev_accrued: u64,
}

impl From<PreAnchorScoresPruningPointShieldedMetadata> for PruningPointShieldedMetadata {
    fn from(v: PreAnchorScoresPruningPointShieldedMetadata) -> Self {
        Self {
            frontier: v.frontier,
            supply: v.supply,
            nullifier_muhash: v.nullifier_muhash,
            burns: v.burns,
            state_root: v.state_root,
            in_window_anchors: v.in_window_anchors,
            dev_accrued: v.dev_accrued,
            // Empty, not a guess: the peer never claimed any blue scores, so nothing is
            // attested and every in-window anchor keeps failing closed.
            in_window_anchor_source_scores: Vec::new(),
        }
    }
}

impl PruningPointShieldedMetadata {
    /// Encode for the wire (bincode). Paired with [`Self::from_wire_bytes`].
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("shielded pruning-point metadata is serializable")
    }

    /// Decode from the wire, tolerating a peer that predates `dev_accrued`.
    ///
    /// bincode is positional and not self-describing, so an older peer's blob is simply
    /// shorter and fails the primary decode; the legacy layout then reads it and defaults
    /// the accrual to zero — which is the correct value for any chain that has not yet
    /// activated accrual, i.e. exactly the chains an older peer can be serving.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Newest layout first, then each older one in turn. Order matters and must stay
        // newest-to-oldest: an older layout is a strict prefix of a newer one, and
        // `bincode::deserialize` ignores trailing bytes — so trying an old layout first would
        // succeed against a NEW blob and silently discard the fields it does not know.
        match bincode::deserialize::<Self>(bytes) {
            Ok(md) => Ok(md),
            Err(primary) => bincode::deserialize::<PreAnchorScoresPruningPointShieldedMetadata>(bytes)
                .map(Into::into)
                .or_else(|_| bincode::deserialize::<LegacyPruningPointShieldedMetadata>(bytes).map(Into::into))
                .map_err(|_: bincode::Error| format!("malformed shielded pruning-point metadata: {primary}")),
        }
    }

    /// The shielded state root implied by (frontier, supply, nullifier_muhash, burns).
    ///
    /// Returns the [`TreeStateError`] instead of panicking when the frontier bytes are
    /// malformed (non-canonical Pallas encoding, inconsistent ommers): this data is
    /// peer-controlled on the pruning-point IBD import path, so a panic here would be
    /// a remote DoS (audit finding F-17).
    pub fn recompute_state_root(
        frontier: &FrontierState,
        supply: &SupplyTotals,
        nullifier_muhash: &MuHash,
        burns: &BurnReceipts,
    ) -> Result<[u8; 32], TreeStateError> {
        let anchor = GlobalTree::from_state(frontier)?.anchor().to_bytes();
        let nullifier_root = nullifier_muhash.clone().finalize().as_bytes().to_owned();
        Ok(kaspa_shielded_core::commitment::shielded_state_root(
            &anchor,
            &nullifier_root,
            supply.cumulative_coinbase,
            supply.cumulative_fees,
            &burns.to_accumulator().root(),
        ))
    }

    /// The shielded state root of the **empty** state (empty tree, empty nullifier
    /// accumulator, zero supply, no burns) — what a chain block's coinbase commits
    /// when its selected parent has no shielded state. Used on the IBD import path
    /// to bind the peer's "this pruning point has no shielded state" claim (empty
    /// metadata) to the PoW-committed root (audit finding F-02). Computed over
    /// local constants only, so the expect below cannot fire on peer input.
    pub fn empty_state_root() -> [u8; 32] {
        Self::recompute_state_root(&FrontierState::default(), &SupplyTotals::default(), &MuHash::new(), &BurnReceipts::default())
            .expect("the default frontier is the canonical empty tree")
    }
}

/// Error advancing the shielded state.
#[derive(Debug)]
pub enum ShieldedManagerError {
    /// Invalid shielded state (turnstile / full tree) — the block must be rejected.
    State(ShieldedStateError),
    /// A shielded-coinbase reward output did not encode a valid coinbase note
    /// (recipient shorter than an Orchard address, or not a canonical address) —
    /// the block must be rejected.
    MalformedCoinbaseNote(&'static str),
    /// A storage error (fatal, as elsewhere in consensus).
    Store(StoreError),
}

impl From<ShieldedStateError> for ShieldedManagerError {
    fn from(e: ShieldedStateError) -> Self {
        Self::State(e)
    }
}
impl From<StoreError> for ShieldedManagerError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Build the shielded [`CoinbaseMint`] for a block from its coinbase transaction
/// (PLAN §2.7), on a `shielded_coinbase` network. Each coinbase output is a reward
/// for one mergeset block: its `value` is the public reward (subsidy + that
/// block's fees, already emission-checked by the coinbase verifier) and its
/// `script_public_key` script carries the recipient's 43-byte Orchard address.
///
/// The note's `(rho, rseed)` are **derived deterministically** from the coinbase
/// transaction id and the output index ([`derive_coinbase_note_desc`]), so every
/// node computes the identical note commitment and the recipient's wallet can
/// recompute the note to spend it. No transparent value is created — these outputs
/// are diverted into the shielded pool instead of the UTXO set.
///
/// `block_hash` selects the seed rule and is **not optional information** — it is the
/// F-02 fork gate made explicit in the signature, so no caller can silently inherit the
/// wrong one:
///
/// - `None`  → pre-fork seed `coinbase_txid || output_index`
/// - `Some(h)` → post-fork seed `h || coinbase_txid || output_index`
///
/// Sibling blocks build byte-identical coinbases (same parent, mergeset, miner, and the
/// payload commits the *parent's* shielded root), so the pre-fork seed makes them mint
/// identical notes and produce the same tree root — the collision behind the wedge.
/// Mixing the block hash in makes the root unique per block. There is no circularity:
/// a block's coinbase commits its parent's shielded state, never its own notes.
pub fn build_coinbase_mint(coinbase_tx: &Transaction, block_hash: Option<Hash>) -> Result<CoinbaseMint, ShieldedManagerError> {
    let outputs: Vec<(&[u8], u64)> =
        coinbase_tx.outputs.iter().map(|out| (out.script_public_key.script(), out.value)).collect();
    Ok(CoinbaseMint::new(coinbase_notes_from_outputs(coinbase_tx.id(), &outputs, block_hash)?))
}

/// The coinbase notes a block mints, derived from the **public output descriptions**
/// rather than from the coinbase transaction itself.
///
/// This is the same derivation [`build_coinbase_mint`] performs, factored out because the
/// scan archive keeps `(script_public_key bytes, value)` pairs and not the transaction — so
/// history replay would otherwise have to re-implement the seed rule in a second place. It
/// must not: a replay that derived even one commitment differently would fail against
/// honest data and reject a good peer. One function, both callers.
///
/// `block_hash` is the F-02 fork gate, decided by the caller against
/// `shielded_coinbase_seed_activation` — see [`build_coinbase_mint`] for what each value
/// means and why the choice cannot be defaulted.
pub fn coinbase_notes_from_outputs(
    coinbase_txid: Hash,
    outputs: &[(&[u8], u64)],
    block_hash: Option<Hash>,
) -> Result<Vec<CoinbaseNote>, ShieldedManagerError> {
    let mut notes = Vec::with_capacity(outputs.len());
    for (i, (script, value)) in outputs.iter().enumerate() {
        if script.len() < 43 {
            return Err(ShieldedManagerError::MalformedCoinbaseNote("coinbase reward script too short for an Orchard address"));
        }
        let recipient: [u8; 43] = script[..43].try_into().expect("checked length >= 43");
        // Per-note seed: [block hash ||] coinbase tx id || output index.
        let mut seed = Vec::with_capacity(32 + 32 + 4);
        if let Some(h) = block_hash {
            seed.extend_from_slice(&h.as_bytes());
        }
        seed.extend_from_slice(&coinbase_txid.as_bytes());
        seed.extend_from_slice(&(i as u32).to_le_bytes());
        let desc = derive_coinbase_note_desc(recipient, &seed);
        let note = coinbase_note(&desc, *value).map_err(|_| {
            ShieldedManagerError::MalformedCoinbaseNote("coinbase reward recipient is not a canonical Orchard address")
        })?;
        notes.push(note);
    }
    Ok(notes)
}

/// Why a history replay stopped — and the distinction the caller acts on.
///
/// [`ReplayError::Source`] means the replay could not read its own input; the range is
/// **unverified**, which is not the same as failed, and discarding history on it would delete
/// good data because a local disk read hiccuped. [`ReplayError::Data`] means the leaves
/// themselves are wrong, which is a real rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The iterator could not supply a block (missing record, index gap, read error).
    Source(String),
    /// A leaf was non-canonical or the tree refused it.
    Data(TreeStateError),
}

/// A finalized nullifier set layered over the persisted global set plus the
/// nullifiers accepted earlier in the current run (so cross-block double-spends
/// within one virtual update are caught).
struct LayeredNullifierSet<'a> {
    store: &'a DbNullifierSetStore,
    pending: &'a MemNullifierSet,
}

impl NullifierSet for LayeredNullifierSet<'_> {
    fn contains(&self, nf: &NullifierBytes) -> bool {
        // A store read failing is an unrecoverable consensus IO error, consistent
        // with how the rest of the pipeline treats store reads.
        self.pending.contains(nf) || self.store.contains(nf).expect("nullifier store read failed")
    }
}

// The external anchor-override mechanism was removed (2026-09): the multi-producer anchor
// resolution (`anchor_producer_blocks`, active on mainnet) makes the last-write-wins index
// order-independent, so no external pin is needed; and bulk-pinning a dump was measured to
// corrupt shielded state (the index is time-dependent). See GitHub issue #11.

/// Why one shielded transaction was kept or dropped.
///
/// The two flags are the two independent drop reasons, deliberately not collapsed: a spend
/// lost to a non-final anchor and a spend lost to a nullifier conflict look identical in the
/// resulting coinbase but indicate completely different faults.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PartitionOutcome {
    /// The spend's anchor resolved to a mature, canonical tree state.
    pub anchor_ok: bool,
    /// No nullifier of this spend was already claimed. Only evaluated when `anchor_ok`.
    pub conflict_ok: bool,
}

impl PartitionOutcome {
    pub fn kept(&self) -> bool {
        self.anchor_ok && self.conflict_ok
    }

    /// A short reason for a drop, or `None` when the spend was kept.
    pub fn drop_reason(&self) -> Option<&'static str> {
        match (self.anchor_ok, self.conflict_ok) {
            (true, true) => None,
            (false, _) => Some("anchor not final (unresolved, non-canonical source, or out of the maturity window)"),
            (true, false) => Some("nullifier already claimed (double spend, or a duplicate copy of an earlier-accepted tx)"),
        }
    }
}

/// Drives and persists the shielded state transition, reorg-safely.
#[derive(Clone)]
pub struct ShieldedStateManager {
    nullifiers: DbNullifierSetStore,
    nullifier_diffs: DbNullifierDiffStore,
    tree_store: DbShieldedTreeStore,
    supply_store: DbShieldedSupplyStore,
    dev_accrued_store: DbShieldedDevAccruedStore,
    nullifier_muhash: DbShieldedNullifierMuHashStore,
    anchor_block: DbAnchorBlockStore,
    /// Deferred age-based GC queue for the two anchor indexes; see [`Self::gc_aged_anchors`].
    anchor_gc: DbAnchorGcQueueStore,
    /// Every producer of each root — the reorg-safe replacement for `anchor_block`.
    anchor_producers: DbAnchorProducersStore,
    scan_block: DbShieldedScanBlockStore,
    burn_store: DbShieldedBurnStore,
    /// Peer-attested blue scores for in-window anchor sources below the pruning point.
    anchor_source_scores: DbShieldedAnchorSourceScoreStore,
}

impl ShieldedStateManager {
    /// Construct over the consensus database. Anchor-finality (canonical ancestry +
    /// the `[shielded_anchor_depth, max_shielded_anchor_age]` age window, audit
    /// F-04/F-05) is decided by the caller (virtual processor) using reachability
    /// and blue-score data; this manager only records the anchor→block index.
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            nullifiers: DbNullifierSetStore::new(Arc::clone(&db), cache_policy),
            nullifier_diffs: DbNullifierDiffStore::new(Arc::clone(&db), cache_policy),
            tree_store: DbShieldedTreeStore::new(Arc::clone(&db), cache_policy),
            supply_store: DbShieldedSupplyStore::new(Arc::clone(&db), cache_policy),
            dev_accrued_store: DbShieldedDevAccruedStore::new(Arc::clone(&db), cache_policy),
            nullifier_muhash: DbShieldedNullifierMuHashStore::new(Arc::clone(&db), cache_policy),
            anchor_block: DbAnchorBlockStore::new(Arc::clone(&db), cache_policy),
            anchor_gc: DbAnchorGcQueueStore::new(Arc::clone(&db), cache_policy),
            anchor_producers: DbAnchorProducersStore::new(Arc::clone(&db), cache_policy),
            scan_block: DbShieldedScanBlockStore::new(Arc::clone(&db), cache_policy),
            burn_store: DbShieldedBurnStore::new(Arc::clone(&db), cache_policy),
            anchor_source_scores: DbShieldedAnchorSourceScoreStore::new(db, cache_policy),
        }
    }

    /// Peer-attested blue score of an in-window anchor source, or `None` if nothing was
    /// attested. See [`DbShieldedAnchorSourceScoreStore`]; `None` must fail closed.
    pub fn attested_source_blue_score(&self, source: Hash) -> StoreResult<Option<u64>> {
        self.anchor_source_scores.get(source)
    }

    /// Read-only access to the compact scan archive (for `GetShieldedBlocks`).
    pub fn scan_block(&self, block: Hash) -> StoreResult<Option<ShieldedScanBlockData>> {
        self.scan_block.get(block)
    }

    /// Persist a scan record obtained from a peer's history backfill.
    ///
    /// Distinct from [`Self::persist`], which writes the record a node produced itself while
    /// validating. Backfilled records describe blocks BELOW this node's pruning point that it
    /// will never validate, so there is no local computation to compare them against
    /// block-by-block. Soundness comes from the caller's end-of-stream check: replaying every
    /// backfilled `cmx` into an empty tree must reproduce the frontier already held at the
    /// pruning point, which is PoW-anchored. Until that check passes the records are not
    /// advertised as complete.
    ///
    /// Never read by consensus — the archive only ever serves `GetShieldedBlocks` — so even a
    /// bogus record cannot influence validation.
    pub fn persist_backfilled_scan(&self, batch: &mut WriteBatch, block: Hash, data: ShieldedScanBlockData) -> StoreResult<()> {
        self.scan_block.set_batch(batch, block, data)
    }

    /// Drop a backfilled range after a failed verification.
    pub fn delete_backfilled_scan(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.scan_block.delete_batch(batch, block)
    }

    /// Persist a note-commitment tree frontier at `block` as a fast-sync / verification anchor.
    ///
    /// Distinct from [`Self::persist`], which writes the frontier a node computed while
    /// VALIDATING a block. This writes one reconstructed by replaying the compact scan archive,
    /// for blocks below the pruning point that this node never validated.
    ///
    /// # SAFETY — ordering is the whole argument
    ///
    /// A replayed frontier is only as trustworthy as the archive it was replayed from, and that
    /// archive arrived from a peer. Writing one before the replay has been checked end-to-end
    /// against a PoW-anchored frontier would leave a poisoned anchor behind on exactly the path
    /// that is supposed to reject bad history — and every later verification, local or served,
    /// would be measured against it. Callers MUST buffer checkpoints and write them only after a
    /// `Verified` verdict. `verify_shielded_history` is the only caller and does exactly that.
    ///
    /// Idempotent: re-verifying rewrites identical values, since the frontier is a pure function
    /// of the leaf prefix.
    ///
    /// # Interaction with the pruner
    ///
    /// [`Self::prune_block_snapshots`] deletes a block's frontier unless the pruner marks it a
    /// checkpoint, and it decides that from `daa_score % SHIELDED_FRONTIER_CHECKPOINT_INTERVAL`
    /// — a rule these index-spaced checkpoints do not satisfy, and one that reads a header a
    /// backfilled block does not have. That does not collide today: the pruner reaches blocks by
    /// walking REACHABILITY up from `ORIGIN`, and backfill writes only the selected-chain index
    /// and scan records, so a block whose history was backfilled is not in the reachability tree
    /// and the traversal never visits it.
    ///
    /// If that ever changes, the failure is benign — losing these frontiers returns the node to
    /// the old behaviour of being unable to anchor a peer's verification, and re-running
    /// `--verify-shielded-history` restores them. It is not a correctness risk: nothing in
    /// validation reads them.
    pub fn persist_replayed_frontier(&self, batch: &mut WriteBatch, block: Hash, frontier: FrontierState) -> StoreResult<()> {
        self.tree_store.set_batch(batch, block, frontier)
    }

    /// Replay a backfilled history range into an empty tree and return the resulting frontier.
    ///
    /// This is what makes history backfill trustless. `GlobalTree::append` is pure append-only,
    /// so the frontier is a deterministic function of the leaf sequence: replaying every `cmx`
    /// from genesis up to (and including) `blocks` must reproduce EXACTLY the frontier this node
    /// already holds at its pruning point — a value it did not learn from the backfilling peer,
    /// and which is PoW-anchored (the pruning point's selected child commits
    /// `shielded_state_root(pruning_point)` in its coinbase, bound by `hash_merkle_root`).
    ///
    /// A peer that fabricates, omits, reorders or truncates records cannot produce a matching
    /// frontier, so the check is cryptographic rather than reputational. `blocks` must be in
    /// ascending chain order (oldest first) — the same order the tree was originally built in.
    ///
    /// Leaves come from the coinbase mint first, then the accepted actions in consensus applied
    /// order, mirroring how `compute` built the tree at validation time.
    ///
    /// `coinbase_leaves` is supplied by the caller because the coinbase note seed is FORK
    /// DEPENDENT (see [`build_coinbase_mint`]): pre-fork it is `txid || index`, post-fork
    /// `block_hash || txid || index`. A replay that used the wrong rule for a block's height
    /// would derive different commitments and fail against honest data, so the activation
    /// decision stays with the caller that owns the params.
    pub fn replay_history_frontier(
        blocks: &[kaspa_consensus_core::api::ShieldedChainBlockData],
        coinbase_leaves: impl Fn(&kaspa_consensus_core::api::ShieldedChainBlockData) -> Vec<[u8; 32]>,
    ) -> Result<FrontierState, TreeStateError> {
        match Self::replay_frontier_streaming(blocks.iter().map(|b| Ok((coinbase_leaves(b), b.accepted_actions.clone())))) {
            Ok((frontier, _)) => Ok(frontier),
            Err(ReplayError::Data(e)) => Err(e),
            // Unreachable: an in-memory slice cannot fail to yield an item.
            Err(ReplayError::Source(_)) => Err(TreeStateError::Inconsistent),
        }
    }

    /// The replay itself, over a **stream** of `(coinbase leaves, accepted action blobs)` in
    /// ascending chain order. Returns the resulting frontier and the number of leaves appended.
    ///
    /// Streaming rather than slice-based because verifying a real chain means replaying the whole
    /// archive — ~1.98M actions and ~293 MB of records today — and materialising that to check it
    /// would cost more memory than the node uses for everything else. The tree keeps only its
    /// frontier, so this runs in constant space regardless of chain length.
    ///
    /// Each item is a `Result` so a caller reading from disk can abort on a missing or corrupt
    /// record instead of silently replaying a short range and reporting a mismatch that is
    /// really its own read error.
    pub fn replay_frontier_streaming(
        blocks: impl IntoIterator<Item = Result<(Vec<[u8; 32]>, Vec<Vec<u8>>), String>>,
    ) -> Result<(FrontierState, u64), ReplayError> {
        Self::replay_frontier_streaming_capturing::<()>(blocks.into_iter().map(|b| b.map(|(c, a)| (None, c, a))), |_, _| {})
    }

    /// [`Self::replay_frontier_streaming`] that also hands the caller the frontier as it stood
    /// after each block it labels — the raw material for tree-frontier checkpoints below the
    /// pruning point.
    ///
    /// # Why this exists
    ///
    /// Verifying backfilled history already computes every intermediate frontier and then throws
    /// them away. That is why a backfilled node can never anchor anyone else's verification:
    /// `verify_shielded_history` needs `frontier_at(base)`, and a node that learned its history
    /// from a peer holds frontiers only at (and above) its own pruning point. So history could be
    /// copied endlessly and still only ever be *checkable* against the handful of nodes that
    /// validated it themselves. Capturing the frontiers this pass already produces is what makes
    /// a backfilled node a first-class source.
    ///
    /// Each stream item may carry an opaque label; `on_checkpoint(label, frontier)` fires after
    /// that block's leaves are appended, for items whose label is `Some`. The caller chooses the
    /// spacing (by labelling only the blocks it wants) and — critically — chooses *when to
    /// persist*: a checkpoint captured here is only as good as the replay that produced it, so
    /// nothing may be written until the whole replay has been checked against a PoW-anchored
    /// frontier. See `verify_shielded_history`.
    pub fn replay_frontier_streaming_capturing<L>(
        blocks: impl IntoIterator<Item = Result<(Option<L>, Vec<[u8; 32]>, Vec<Vec<u8>>), String>>,
        mut on_checkpoint: impl FnMut(L, &FrontierState),
    ) -> Result<(FrontierState, u64), ReplayError> {
        let mut tree = GlobalTree::default();
        let mut leaves = 0u64;
        let append = |tree: &mut GlobalTree, cmx: &[u8; 32], leaves: &mut u64| -> Result<(), ReplayError> {
            let c = ExtractedNoteCommitment::from_bytes(cmx);
            if c.is_none().into() {
                return Err(ReplayError::Data(TreeStateError::NonCanonicalNode));
            }
            tree.append(c.unwrap()).map_err(|_| ReplayError::Data(TreeStateError::Inconsistent))?;
            *leaves += 1;
            Ok(())
        };
        for block in blocks {
            let (label, coinbase, accepted) = block.map_err(ReplayError::Source)?;
            // Coinbase mint first, then accepted actions in consensus applied order — the
            // order `compute` appended them in at validation time. Any other order yields a
            // different frontier from identical data.
            for cmx in &coinbase {
                append(&mut tree, cmx, &mut leaves)?;
            }
            for actions in &accepted {
                for rec in actions.chunks_exact(CompactActionRecord::SERIALIZED_LEN) {
                    let mut cmx = [0u8; 32];
                    cmx.copy_from_slice(&rec[32..64]);
                    append(&mut tree, &cmx, &mut leaves)?;
                }
            }
            // After this block's leaves, never between them: a frontier is only meaningful at a
            // block boundary, which is the only place `frontier_at` can ever be asked about.
            if let Some(label) = label {
                on_checkpoint(label, &tree.to_state());
            }
        }
        Ok((tree.to_state(), leaves))
    }

    /// Read-only access to the nullifier store (for validation / queries).
    pub fn nullifiers(&self) -> &DbNullifierSetStore {
        &self.nullifiers
    }

    /// DIAGNOSTIC: does the live global nullifier set still agree with the per-block muhash
    /// snapshot at `block`?
    ///
    /// These are two representations of the same set kept by different paths: `persist` inserts
    /// into the global store, while the snapshot is folded by `compute`. Only the snapshot is
    /// intrinsic to a block — the global store is mutated forward and backward by
    /// `apply_nullifiers_from_store` / `revert_nullifiers_from_store` as the virtual chain moves.
    /// If a reorg ever removes an entry the up-walk does not restore, the two silently diverge:
    /// the shielded state root still matches the chain (it reads the snapshot), while
    /// `partition_applied` — which consults the GLOBAL store — starts accepting spends whose
    /// nullifiers are already spent. That is exactly the observed failure, so measure it.
    pub fn global_set_matches_snapshot(&self, block: Hash) -> StoreResult<(bool, usize)> {
        let mut acc = MuHash::new();
        let mut count = 0usize;
        for nf in self.nullifiers.iter_all() {
            acc.add_element(&nf?);
            count += 1;
        }
        let snapshot = self.load_nullifier_muhash(block)?;
        Ok((acc.finalize() == snapshot.clone().finalize(), count))
    }

    /// The anchor (global tree root) as of a given chain block.
    pub fn anchor_at(&self, block: Hash) -> StoreResult<[u8; 32]> {
        Ok(self.load_tree(block)?.anchor().to_bytes())
    }

    /// The global note-commitment tree **frontier** as of a given chain block — the
    /// checkpoint a light wallet fast-syncs from (`WalletDb::from_frontier`): it scans
    /// only blocks after this block, yet still witnesses its notes against the live
    /// tip. Returns the empty-tree frontier for blocks with no shielded state.
    pub fn frontier_at(&self, block: Hash) -> StoreResult<FrontierState> {
        self.tree_store.get(block)
    }

    /// The chain block whose shielded tree root equals `anchor`, if any block ever
    /// produced it (PLAN §2.5). The caller decides finality by checking that this
    /// block is a selected-chain ancestor of the spending block (reorg-safety) and
    /// that its blue-score age lies in `[shielded_anchor_depth,
    /// max_shielded_anchor_age]` (maturity + fail-closed upper bound, audit
    /// F-04/F-05). `None` means the anchor is not a real tree root of any block.
    pub fn anchor_source_block(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>> {
        self.anchor_block.get(anchor)
    }

    /// Every block known to have produced `anchor`.
    ///
    /// Unlike [`Self::anchor_source_block`] this is not order-dependent: it keeps all producers
    /// rather than the last one written, so an orphan that briefly held the chain cannot destroy
    /// the canonical producer's mapping. See [`DbAnchorProducersStore`].
    pub fn anchor_producer_blocks(&self, anchor: &[u8; 32]) -> StoreResult<Vec<Hash>> {
        self.anchor_producers.get_producers(anchor)
    }

    /// The `(anchor, source block)` pairs whose source is in `blocks` — the in-window anchors a
    /// syncee needs so that spends anchored below the pruning point remain resolvable. One pass
    /// over the stored index; see [`DbAnchorBlockStore::iter_all`] for why this is not derived
    /// per block.
    pub fn anchors_for_blocks(&self, blocks: &BlockHashSet) -> StoreResult<Vec<([u8; 32], Hash)>> {
        // BOTH indexes, unioned. `anchor_block` is single-valued and last-write-wins, so a root
        // whose most recent writer is an orphan — or any block outside `blocks` — does not appear
        // there at all, and the syncee is left with NO mapping for it: `anchor is not a known tree
        // root`, spend dropped, coinbase short by that fee, block disqualified. Measured
        // 2026-08-08 on a fresh sync: anchor 9224320b resolved to nothing while the chain
        // accepted the spend. `anchor_producers` records every producer of every root, which is
        // precisely what the multi-producer upgrade added and what this export never read.
        //
        // Deduplicated because the same pair is normally in both.
        let mut seen: std::collections::HashSet<([u8; 32], Hash)> = std::collections::HashSet::new();
        let mut out = Vec::with_capacity(blocks.len());
        for entry in self.anchor_producers.iter_all().chain(self.anchor_block.iter_all()) {
            let (anchor, source) = entry?;
            if blocks.contains(&source) && seen.insert((anchor, source)) {
                out.push((anchor, source));
            }
        }
        Ok(out)
    }

    fn load_tree(&self, block: Hash) -> StoreResult<GlobalTree> {
        let state = self.tree_store.get(block)?;
        Ok(GlobalTree::from_state(&state).expect("persisted shielded frontier is corrupt"))
    }

    fn load_supply(&self, block: Hash) -> StoreResult<SupplyLedger> {
        let t = self.supply_store.get(block)?;
        Ok(SupplyLedger::from_totals(t.cumulative_coinbase, t.cumulative_fees))
    }

    fn load_burns(&self, block: Hash) -> StoreResult<kaspa_shielded_core::burn::BurnAccumulator> {
        Ok(self.burn_store.get(block)?.to_accumulator())
    }

    /// The turnstile cumulative totals as of a given chain block (zero totals for
    /// blocks with no shielded state). Used by the pool-delta consensus check.
    pub fn supply_totals_at(&self, block: Hash) -> StoreResult<SupplyTotals> {
        self.supply_store.get(block)
    }

    /// Delete a pruned block's per-block shielded snapshots.
    ///
    /// # What this may and may not drop
    ///
    /// The frontier / supply / MuHash / burn snapshots exist so the transition can be
    /// recomputed from a block's **selected parent**, and so a reorg can rebuild the
    /// chain from its fork point. Reorgs are bounded by `finality_depth`, and the
    /// pruner only ever reaches blocks below `pruning_depth` — which is deeper still
    /// (108,000 vs 43,200 at 1 BPS) — so a snapshot the pruner can see is one no
    /// reorg can ever need again.
    ///
    /// Deliberately NOT touched:
    /// - [`DbShieldedScanBlockStore`] — a wallet recovers its notes from the compact
    ///   archive, and a hole in that stream is the "restored my seed and my balance is
    ///   partial" failure. It is retained for the life of the chain.
    /// - the global nullifier set — membership must outlive every block that added to it.
    /// - the anchor index — bounded separately by anchor age, not by block pruning.
    ///
    /// `keep_checkpoint` marks blocks whose frontier survives as a fast-sync anchor for
    /// `GetShieldedTreeState`; pass `true` for pruning points and for the sparse
    /// checkpoints, `false` otherwise.
    pub fn prune_block_snapshots(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        keep_checkpoint: bool,
        blue_score: Option<u64>,
    ) -> StoreResult<()> {
        // Queue this block's anchor-index rows for age-based GC. The rows themselves must
        // NOT be deleted here: a block being pruned sits just below the pruning point,
        // which is still inside the window the shielded IBD export serves
        // (`anchors_for_blocks`) and inside `max_shielded_anchor_age` of blocks near the
        // pruning point — deleting now would break both. The root is read from the
        // frontier before it is (possibly) dropped below; once the block's header is
        // pruned its blue score is unrecoverable, which is exactly why it is snapshotted
        // into the queue key now.
        if let Some(blue) = blue_score {
            match self.tree_store.get(block) {
                Ok(state) => {
                    if let Ok(tree) = GlobalTree::from_state(&state) {
                        self.anchor_gc.enqueue_batch(batch, blue, tree.anchor().to_bytes(), block)?;
                    }
                }
                Err(kaspa_database::prelude::StoreError::KeyNotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        self.supply_store.delete_batch(batch, block)?;
        self.nullifier_muhash.delete_batch(batch, block)?;
        self.burn_store.delete_batch(batch, block)?;
        self.dev_accrued_store.delete_batch(batch, block)?;
        // Per-block nullifier diffs only exist to revert a reorg; below the pruning
        // point no reorg can reach them.
        self.nullifier_diffs.delete_batch(batch, block)?;
        if !keep_checkpoint {
            self.tree_store.delete_batch(batch, block)?;
        }
        Ok(())
    }

    /// Drain the anchor GC queue: delete anchor-index rows whose source block's blue
    /// score is more than `2 * max_age` below the pruning point's — provably outside
    /// the spend window (`max_shielded_anchor_age`, fail-closed on a missing entry
    /// anyway) and outside anything `anchors_for_blocks` can export. The 2x margin is
    /// deliberate slack over both. `anchor_block` is last-write-wins, so its row is
    /// only removed when it still points at the aged block — a younger producer of the
    /// same root keeps the mapping. Returns how many queue entries were processed.
    ///
    /// Without this the two anchor indexes grow one row per chain block for the life
    /// of the chain (~3.1M rows at 36 days old), and the IBD export pays a full-index
    /// scan per syncing peer. With it they stay bounded by the pruning window.
    pub fn gc_aged_anchors(&self, batch: &mut WriteBatch, pp_blue_score: u64, max_age: u64, cap: usize) -> StoreResult<usize> {
        let limit = pp_blue_score.saturating_sub(max_age.saturating_mul(2));
        if limit == 0 {
            return Ok(0);
        }
        let aged = self.anchor_gc.peek_upto(limit, cap);
        for &(blue, anchor, block) in &aged {
            if self.anchor_block.get(&anchor)? == Some(block) {
                self.anchor_block.delete_batch(batch, anchor)?;
            }
            self.anchor_producers.remove_producer_batch(batch, anchor, block)?;
            self.anchor_gc.delete_batch(batch, blue, anchor, block)?;
        }
        Ok(aged.len())
    }

    /// Dev fee accrued but unpaid as of a chain block. `0` for every block mined
    /// before dev-fee accrual activated, and for every payout block (the balance
    /// left as a note).
    pub fn dev_accrued_at(&self, block: Hash) -> StoreResult<u64> {
        self.dev_accrued_store.get(block)
    }

    /// Record the dev fee a block carries forward. Written in the block-commit batch
    /// so accrual and the coinbase that consumed it commit together.
    pub fn set_dev_accrued(&self, batch: &mut WriteBatch, block: Hash, accrued: u64) -> StoreResult<()> {
        self.dev_accrued_store.set_batch(batch, block, accrued)
    }

    /// Total value burned out of the pool (bridge peg-out) as of a chain block.
    ///
    /// The burn seam is deactivated (`BRIDGE_ENABLED == false`), so this is `0`
    /// everywhere on the live chain. It is summed from the persisted receipts
    /// rather than assumed zero, so a supply query stays correct the day the seam
    /// is enabled.
    pub fn burn_total_at(&self, block: Hash) -> StoreResult<u128> {
        Ok(self.burn_store.get(block)?.receipts.iter().map(|&(value, _, _)| value as u128).sum())
    }

    /// Decide, in accepted order, which candidate shielded txs a chain block will
    /// actually APPLY — mirroring exactly the drop rules of the state transition:
    /// a spending tx whose anchor fails the caller's finality predicate (PLAN §2.5)
    /// is dropped, then first-in-accepted-order nullifier conflict resolution runs
    /// against the finalized set (PLAN §2.4). Returns a keep-mask aligned with `txs`.
    ///
    /// This exists so the coinbase can be built/verified from the *applied* fees
    /// only: a dropped spend never left the pool, so re-minting its fee in the
    /// coinbase would create unbacked supply (the F-01 inflation vector). It must
    /// be called against the same persisted nullifier state `compute` will see —
    /// i.e. with the selected-parent chain committed — which is the invariant the
    /// virtual processor already maintains for `compute` itself.
    pub fn partition_applied<F: FnMut(&ShieldedTx) -> bool>(&self, txs: &[ShieldedTx], mut anchor_final: F) -> Vec<PartitionOutcome> {
        let pending = MemNullifierSet::new();
        let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
        let mut resolver = NullifierConflictResolver::new(&finalized);
        txs.iter()
            .map(|stx| {
                // Keep the two drop reasons apart. A composed expression cannot say whether a
                // spend fell to a non-final anchor or to a nullifier conflict, and those point at
                // completely different bugs.
                let anchor_ok = stx.nullifiers.is_empty() || anchor_final(stx);
                // Preserve the short-circuit: `try_accept` must NOT run when the anchor check
                // already failed, or a non-final spend would seed the pending conflict set and
                // wrongly knock out later copies. Diagnostics must not change consensus.
                let conflict_ok = anchor_ok && resolver.try_accept(stx.nullifiers.iter().copied()).is_ok();
                PartitionOutcome { anchor_ok, conflict_ok }
            })
            .collect()
    }

    fn load_nullifier_muhash(&self, block: Hash) -> StoreResult<MuHash> {
        self.nullifier_muhash.get(block)
    }

    /// The canonical shielded state root (PLAN §2.10) as of a given chain block:
    /// binds the note-commitment tree root, the nullifier-set accumulator, and the
    /// turnstile totals. Used to attest a block's parent shielded state in the
    /// coinbase (a PoW-anchored commitment chain for fast/pruned sync).
    pub fn state_root_at(&self, block: Hash) -> StoreResult<[u8; 32]> {
        let anchor = self.load_tree(block)?.anchor().to_bytes();
        let mut m = self.load_nullifier_muhash(block)?;
        let nullifier_root = m.finalize().as_bytes().to_owned();
        let t = self.supply_store.get(block)?;
        let burn_root = self.burn_store.get(block)?.to_accumulator().root();
        Ok(kaspa_shielded_core::commitment::shielded_state_root(
            &anchor,
            &nullifier_root,
            t.cumulative_coinbase,
            t.cumulative_fees,
            &burn_root,
        ))
    }

    /// Validate and compute one chain block's shielded transition against its
    /// selected parent's persisted state, **without** persisting (used in the
    /// validation phase, `verify_expected_utxo_state`). The finalized nullifier
    /// check reads the global set, which — because each chain block is committed
    /// before the next is validated — already reflects the selected-parent chain.
    pub fn compute(
        &self,
        selected_parent: Hash,
        coinbase: Option<&CoinbaseMint>,
        txs: &[ShieldedTx],
    ) -> Result<ComputedBlockShielded, ShieldedManagerError> {
        // Anchor finality (maturity + canonical ancestry, PLAN §2.5) is checked by
        // the caller (virtual processor) before `compute`, since it needs
        // reachability and the spending block's blue score. Here we only apply the
        // transition against the selected parent's persisted state.
        let mut tree = self.load_tree(selected_parent)?;
        let mut supply = self.load_supply(selected_parent)?;
        // Extend the selected parent's burn accumulator, so a reorg naturally rebuilds from the
        // new selected parent rather than replaying every burn from genesis.
        let mut burns = self.load_burns(selected_parent)?;
        let pending = MemNullifierSet::new();
        let outcome = {
            let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
            apply_chain_block_to(&finalized, &mut tree, &mut supply, coinbase, txs, &mut burns)?
        };
        // Advance the nullifier-set accumulator: the selected parent's snapshot
        // plus this block's newly spent nullifiers. MuHash is order-independent, so
        // this matches the set regardless of validation order and needs no separate
        // reorg handling (a reorg recomputes from the selected parent's snapshot).
        let mut nullifier_muhash = self.load_nullifier_muhash(selected_parent)?;
        for nf in &outcome.new_nullifiers {
            nullifier_muhash.add_element(nf);
        }
        Ok(ComputedBlockShielded {
            frontier_state: tree.to_state(),
            supply_totals: SupplyTotals {
                cumulative_coinbase: supply.cumulative_coinbase(),
                cumulative_fees: supply.cumulative_fees(),
            },
            nullifier_muhash,
            burns: BurnReceipts::from_accumulator(&burns),
            outcome,
            // Attached by the virtual processor from the block-time applied set
            // (it has the original bundle ciphertexts + coinbase); `compute` sees
            // only the distilled `ShieldedTx`, so it cannot build the scan record.
            scan_block: None,
        })
    }

    /// Persist a freshly validated block's shielded transition into `batch` and
    /// add its nullifiers to the global set (commit phase). Only non-trivial
    /// state is written, so a chain with no shielded activity incurs no shielded
    /// writes and no behavioural change.
    pub fn persist(&self, batch: &mut WriteBatch, block: Hash, computed: &ComputedBlockShielded) -> StoreResult<()> {
        if computed.frontier_state.size > 0 {
            self.tree_store.set_batch(batch, block, computed.frontier_state.clone())?;
            // Index this block's shielded tree root so spends can prove against it
            // (anchor-finality is decided at validation time via reachability + depth).
            // An anchor uniquely identifies (block, its history), so this is an
            // append-only map that needs no reorg reverting.
            self.anchor_block.set_batch(batch, computed.anchor(), block)?;
            // Record every producer, not just the last: see `DbAnchorProducersStore`.
            self.anchor_producers.add_producer_batch(batch, computed.anchor(), block)?;
        }
        if computed.supply_totals.cumulative_coinbase > 0 || computed.supply_totals.cumulative_fees > 0 {
            self.supply_store.set_batch(batch, block, computed.supply_totals)?;
        }
        // Only chains that have actually burned pay for this store; the empty accumulator is the
        // default a missing key reads back as.
        if !computed.burns.receipts.is_empty() {
            self.burn_store.set_batch(batch, block, computed.burns.clone())?;
        }
        if !computed.outcome.new_nullifiers.is_empty() {
            self.nullifier_diffs.set_batch(batch, block, computed.outcome.new_nullifiers.clone())?;
            for nf in &computed.outcome.new_nullifiers {
                self.nullifiers.insert_batch(batch, *nf)?;
            }
        }
        // Snapshot the nullifier accumulator for *every* block once it is non-empty
        // (not only blocks that add nullifiers), so `state_root_at(block)` is
        // readable at any block — mirroring the frontier/supply snapshots. The
        // accumulator is add-only along a chain, so once non-empty it stays so.
        if computed.nullifier_muhash.clone().finalize() != kaspa_muhash::EMPTY_MUHASH {
            self.nullifier_muhash.set_batch(batch, block, computed.nullifier_muhash.clone())?;
        }
        // Compact scan archive (PLAN §2.9): persist the block-time applied effects in
        // the same commit batch, so `GetShieldedBlocks` serves this exact record —
        // fixing the divergent-anchor drift (no RPC re-derivation) — and history stays
        // scannable after the body prunes. Written whenever the block had shielded
        // effects (coinbase notes or accepted actions).
        if let Some(scan) = &computed.scan_block {
            // Write the record for EVERY chain block, including one that minted nothing and
            // accepted nothing. It is tempting to skip those, but the archive is what makes a
            // pruned node able to serve a wallet scan: `shielded_chain_block_data` falls back to
            // the ghostdag/header stores when a record is absent, and pruning deletes both. A
            // skipped block therefore becomes a hole in the scan stream the moment it prunes —
            // the wallet's paging loop asks for it and gets an error, not an empty block.
            // An empty record is a few dozen bytes and on a shielded-coinbase network it is rare
            // anyway (every block mints its reward); paying it unconditionally buys "the whole
            // chain is always servable from the archive alone", which is the property the wallet
            // depends on. See [`Self::scan_block`] and `get_shielded_chain_range`.
            self.scan_block.set_batch(batch, block, scan.clone())?;
        }
        Ok(())
    }

    /// Re-add a chain block's nullifiers to the global set when it rejoins the
    /// selected chain on a reorg up-walk, reading its stored per-block diff. (The
    /// per-block frontier/supply snapshots are intrinsic and already persisted.)
    pub fn apply_nullifiers_from_store(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        for nf in self.nullifier_diffs.get(block)? {
            self.nullifiers.insert_batch(batch, nf)?;
        }
        Ok(())
    }

    /// Remove a chain block's nullifiers from the global set when it leaves the
    /// selected chain on a reorg down-walk, reading its stored per-block diff. The
    /// per-block snapshots are retained for a possible rejoin.
    pub fn revert_nullifiers_from_store(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        for nf in self.nullifier_diffs.get(block)? {
            self.nullifiers.delete_batch(batch, nf)?;
        }
        Ok(())
    }

    // ---------------------- Pruning-point IBD state transfer ----------------------

    /// Export the shielded metadata at `block` (a pruning point) for IBD transfer.
    /// Returns `None` when the block has no shielded state (empty pool — nothing to
    /// transfer). The caller streams the **PP-time** nullifier set separately, built
    /// from [`Self::nullifier_set_snapshot`] + [`Self::subtract_nullifier_diffs`]
    /// (F-03: the raw global set reflects the virtual tip, not the pruning point).
    pub fn export_pruning_point_shielded(&self, block: Hash) -> StoreResult<Option<PruningPointShieldedMetadata>> {
        let frontier = self.tree_store.get(block)?;
        if frontier.size == 0 {
            return Ok(None);
        }
        let supply = self.supply_store.get(block)?;
        let nullifier_muhash = self.nullifier_muhash.get(block)?;
        let burns = self.burn_store.get(block)?;
        let state_root = PruningPointShieldedMetadata::recompute_state_root(&frontier, &supply, &nullifier_muhash, &burns)
            .map_err(|e| StoreError::DataInconsistency(format!("stored shielded frontier at {block} is corrupt: {e:?}")))?;
        let dev_accrued = self.dev_accrued_store.get(block)?;
        Ok(Some(PruningPointShieldedMetadata {
            frontier,
            supply,
            nullifier_muhash,
            burns,
            state_root,
            // Both filled by the caller (`pruning_point_shielded_metadata`), which owns the
            // selected-chain walk and the ghostdag reads this layer has no business doing.
            in_window_anchors: Vec::new(),
            dev_accrued,
            in_window_anchor_source_scores: Vec::new(),
        }))
    }

    /// Snapshot of the current global spent-nullifier set (append-only; reflects the
    /// virtual selected tip, not any past block). First half of the F-03 PP-time
    /// export; the caller subtracts the post-pruning-point selected-chain diffs via
    /// [`Self::subtract_nullifier_diffs`].
    pub fn nullifier_set_snapshot(&self) -> StoreResult<Vec<[u8; 32]>> {
        self.nullifiers.iter_all().collect()
    }

    /// Subtract from `set` the nullifiers added by `post_blocks` (read from the
    /// per-block diff store). Recovers the PP-time nullifier set from the tip-time
    /// global set (audit finding F-03): the global set is append-only and tracks the
    /// virtual selected tip — typically a full pruning period ahead of the pruning
    /// point — so the set as of the pruning point is the current set minus the diffs
    /// of the selected-chain blocks in `(pp, tip]`. Both the exported `nullifier_count`
    /// and the streamed set must be this PP-time set, or the receiver's
    /// [`Self::verify_pruning_point_shielded`] fails against the PP MuHash snapshot.
    pub fn subtract_nullifier_diffs(
        &self,
        mut set: Vec<[u8; 32]>,
        post_blocks: impl IntoIterator<Item = Hash>,
    ) -> StoreResult<Vec<[u8; 32]>> {
        let mut post: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for block in post_blocks {
            post.extend(self.nullifier_diffs.get(block)?);
        }
        if !post.is_empty() {
            set.retain(|nf| !post.contains(nf));
        }
        Ok(set)
    }

    /// Verify imported pruning-point shielded metadata against the streamed
    /// nullifier set: the set must reproduce the metadata's MuHash accumulator, and
    /// the declared state root must match the value recomputed from (frontier,
    /// supply, muhash). Internal consistency only — see
    /// [`PruningPointShieldedMetadata`] for how the consensus binding is enforced.
    pub fn verify_pruning_point_shielded<'a, I>(md: &PruningPointShieldedMetadata, nullifiers: I) -> Result<usize, String>
    where
        I: IntoIterator<Item = &'a [u8; 32]>,
    {
        // 1. The streamed set must reproduce the committed accumulator (MuHash is a
        //    multiset hash, so transfer order does not matter).
        let mut acc = MuHash::new();
        let mut count = 0usize;
        for nf in nullifiers {
            acc.add_element(nf);
            count += 1;
        }
        if acc.finalize() != md.nullifier_muhash.clone().finalize() {
            return Err(format!("streamed nullifier set ({count}) does not reproduce the committed accumulator"));
        }
        // 2. The declared state root must be consistent with the transferred parts.
        //    The frontier is peer-controlled: propagate a rebuild failure as an Err
        //    rather than panicking (audit finding F-17).
        let recomputed = PruningPointShieldedMetadata::recompute_state_root(&md.frontier, &md.supply, &md.nullifier_muhash, &md.burns)
            .map_err(|e| format!("malformed shielded frontier in pruning-point metadata: {e:?}"))?;
        if recomputed != md.state_root {
            return Err("declared shielded state root is inconsistent with (frontier, supply, nullifier_muhash, burns)".to_string());
        }
        Ok(count)
    }

    /// Seed the shielded stores at the pruning point from verified imported state,
    /// so validation of the pruning point's descendants can proceed: they read
    /// `state_root_at(pruning_point)`, `frontier_at`, the global nullifier set, and
    /// the anchor→block index. Writes the same store shapes as [`Self::persist`]
    /// (no per-block nullifier diff — no reorg descends below a trusted pruning
    /// point). Call [`Self::verify_pruning_point_shielded`] first.
    pub fn seed_pruning_point_shielded<'a, I>(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        md: &PruningPointShieldedMetadata,
        nullifiers: I,
    ) -> StoreResult<()>
    where
        I: IntoIterator<Item = &'a [u8; 32]>,
    {
        // Per-block snapshots at the pruning point (mirrors `persist`).
        self.tree_store.set_batch(batch, block, md.frontier.clone())?;
        // Defense in depth (audit finding F-17): `verify_pruning_point_shielded` already rejects a
        // malformed frontier, but never panic on peer-supplied bytes here either — surface the
        // failure as a store data-inconsistency error instead.
        let anchor = GlobalTree::from_state(&md.frontier)
            .map_err(|e| StoreError::DataInconsistency(format!("malformed shielded frontier in pruning-point metadata: {e:?}")))?
            .anchor()
            .to_bytes();
        self.anchor_block.set_batch(batch, anchor, block)?;
        // Both indexes, always. `anchor_block` answers the pre-fork resolution path and
        // `anchor_producers` the post-`shielded_anchor_multi_activation` one, which reads
        // ONLY the producer set and treats a missing key as "anchor is not a known tree
        // root" (`DbAnchorProducersStore::get_producers` maps `KeyNotFound` to an empty
        // vec, with no fallback to `anchor_block`). Seeding just `anchor_block` therefore
        // left a fast-synced node blind after activation: every post-fork spend anchored
        // below the pruning point resolved to zero producers, was dropped while the
        // block's producer had kept it, and the resulting fee difference disqualified the
        // merging chain block — the same wedge this seeding exists to prevent, moved from
        // the old rule to the new one. `persist` writes both for self-validated blocks;
        // the import path must match it or the two disagree exactly across the window a
        // syncee cannot self-populate.
        self.anchor_producers.add_producer_batch(batch, anchor, block)?;
        // Seed the in-window historical anchors too. Without these the node drops every spend
        // anchored below the pruning point and disqualifies the block that merged it; see
        // [`PruningPointShieldedMetadata::in_window_anchors`].
        for (hist_anchor, source) in md.in_window_anchors.iter() {
            self.anchor_block.set_batch(batch, *hist_anchor, *source)?;
            self.anchor_producers.add_producer_batch(batch, *hist_anchor, *source)?;
        }
        // And the blue score of each of those sources. Without this the mappings above resolve
        // and then fail the maturity check, because a fast-synced node has no ghostdag data
        // below its pruning point — the mapping alone was never enough.
        for (source, blue_score) in md.in_window_anchor_source_scores.iter() {
            self.anchor_source_scores.set_batch(batch, *source, *blue_score)?;
        }
        if md.supply.cumulative_coinbase > 0 || md.supply.cumulative_fees > 0 {
            self.supply_store.set_batch(batch, block, md.supply)?;
        }
        if !md.burns.receipts.is_empty() {
            self.burn_store.set_batch(batch, block, md.burns.clone())?;
        }
        if md.nullifier_muhash.clone().finalize() != kaspa_muhash::EMPTY_MUHASH {
            self.nullifier_muhash.set_batch(batch, block, md.nullifier_muhash.clone())?;
        }
        // Dev-fee accrual carried at the pruning point. Zero is the store's default for a
        // missing key, so a pre-accrual chain (or a peer that predates the field) writes
        // nothing and behaves exactly as before.
        if md.dev_accrued > 0 {
            self.dev_accrued_store.set_batch(batch, block, md.dev_accrued)?;
        }
        // The whole append-only global membership set (unbounded, PLAN §2.9).
        for nf in nullifiers {
            self.nullifiers.insert_batch(batch, *nf)?;
        }
        Ok(())
    }

    /// F-02: bind an import to PoW-committed data. The pruning point's selected
    /// child commits `shielded_commitment = state_root(pruning_point)` in its
    /// coinbase payload (the #24 commitment, committed by the header's
    /// `hash_merkle_root` and hence by proof-of-work on the proof-verified header
    /// chain the syncee already holds). The imported metadata's declared state root
    /// must equal that commitment; without this check every import input is
    /// attacker-controlled and a malicious syncer can permanently fork the syncee.
    pub fn verify_import_binding(md: &PruningPointShieldedMetadata, committed_state_root: [u8; 32]) -> Result<(), String> {
        if md.state_root != committed_state_root {
            return Err(format!(
                "imported shielded state root does not match the PoW-committed coinbase binding \
                 (import is not anchored to the proof-verified header chain — refusing to seed)"
            ));
        }
        Ok(())
    }

    /// F-15: actually clear the shielded import state before a full re-seed —
    /// delete the whole global nullifier set and the per-block snapshots keyed at
    /// `pruning_point` into `batch` (the caller writes the stable-flag reset into
    /// the same batch, so the clear is atomic with the flag flip).
    ///
    /// SAFETY: this destroys live state. Call only on a path that immediately
    /// re-seeds the pruning point from scratch, and only when no locally
    /// UTXO-validated chain blocks above `pruning_point` exist (their nullifier
    /// contributions to the global set would be lost without revalidation). The
    /// IBD flow enforces both preconditions (see
    /// `protocol/flows/src/ibd/flow.rs::sync_new_shielded_state`).
    ///
    /// Note: the staged deletes become visible to store reads only once `batch` is
    /// written (`CachedDbAccess` removes the cache entry but RocksDB deletes land
    /// with the batch — the same semantics behind the F-01 two-batch reorg fix),
    /// so the caller MUST write the batch before any subsequent seed/validation.
    ///
    /// The per-block nullifier diffs and the anchor→block index are deliberately
    /// retained: diffs of chain blocks above the pruning point stay valid (the
    /// re-seeded set is their base state), and the anchor index is append-only by
    /// design with canonicality re-checked via reachability on every query.
    pub fn clear_for_pruning_reimport(&self, batch: &mut WriteBatch, pruning_point: Hash) -> StoreResult<()> {
        // The whole global membership set. `iter_all` is a pure RocksDB iterator
        // (no cache), and the deletions are only staged in `batch`, so iterating
        // while staging deletes is safe.
        for nf in self.nullifiers.iter_all() {
            self.nullifiers.delete_batch(batch, nf?)?;
        }
        // Per-block snapshots at the pruning point (absent keys are no-op deletes).
        self.tree_store.delete_batch(batch, pruning_point)?;
        self.supply_store.delete_batch(batch, pruning_point)?;
        self.nullifier_muhash.delete_batch(batch, pruning_point)?;
        self.burn_store.delete_batch(batch, pruning_point)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;
    use kaspa_shielded_core::ExtractedNoteCommitment;

    /// History replay derives coinbase leaves from the archive's `(script, value)` pairs, while
    /// validation derives them from the coinbase transaction. If those two ever disagree by a
    /// single byte, replay reproduces a different frontier from identical data — and the verifier
    /// would reject HONEST peers while a dishonest one is no easier to catch. So they are the same
    /// function, and this pins that they stay so, on both sides of the F-02 fork boundary.
    #[test]
    fn replay_and_validation_derive_identical_coinbase_leaves() {
        use kaspa_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
        use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput};
        use kaspa_shielded_core::wallet::scan::address_bytes_from_seed;

        let recipients = [address_bytes_from_seed([21u8; 32]).unwrap(), address_bytes_from_seed([22u8; 32]).unwrap()];
        let values = [5_000_000_000u64, 1_234_567u64];
        let outputs: Vec<TransactionOutput> = recipients
            .iter()
            .zip(values.iter())
            .map(|(r, v)| TransactionOutput::new(*v, ScriptPublicKey::new(0, ScriptVec::from_slice(&r[..]))))
            .collect();
        let tx = Transaction::new(0, vec![], outputs, 0, SUBNETWORK_ID_COINBASE, 0, vec![]);

        // The archive keeps only what the scan record keeps: the script bytes and the value.
        let record_outputs: Vec<(&[u8], u64)> =
            tx.outputs.iter().map(|o| (o.script_public_key.script(), o.value)).collect();

        for seed_block in [None, Some(Hash::from_bytes([0xab; 32]))] {
            let from_tx = build_coinbase_mint(&tx, seed_block).expect("validation builds the mint");
            let from_record = coinbase_notes_from_outputs(tx.id(), &record_outputs, seed_block).expect("replay derives leaves");
            assert_eq!(from_record.len(), from_tx.notes.len(), "same note count ({seed_block:?})");
            for (r, v) in from_record.iter().zip(from_tx.notes.iter()) {
                assert_eq!(r.value, v.value, "same public value ({seed_block:?})");
                assert_eq!(
                    r.commitment.to_bytes(),
                    v.commitment.to_bytes(),
                    "replay-derived coinbase commitment matches validation byte-for-byte ({seed_block:?})"
                );
            }
        }
    }

    /// The IBD metadata gained `dev_accrued` after the field order was already on the
    /// wire, so both directions of a mixed-version network are pinned here rather than
    /// argued from bincode's documentation: an upgraded node must read a legacy peer's
    /// shorter blob (falling back, accrual 0), and a legacy node must survive an upgraded
    /// peer's longer one (bincode allows trailing bytes). Get either wrong and IBD breaks
    /// during the upgrade window, which is exactly when nobody is watching for it.
    #[test]
    fn pruning_point_metadata_wire_is_compatible_across_the_accrual_field() {
        let md = PruningPointShieldedMetadata {
            frontier: FrontierState::default(),
            supply: SupplyTotals { cumulative_coinbase: 700, cumulative_fees: 25 },
            nullifier_muhash: MuHash::new(),
            burns: BurnReceipts::default(),
            state_root: [7u8; 32],
            in_window_anchors: vec![([3u8; 32], Hash::from_bytes([4u8; 32]))],
            dev_accrued: 123_456,
            in_window_anchor_source_scores: vec![(Hash::from_bytes([4u8; 32]), 990_606)],
        };

        // Round-trip through the current layout.
        let bytes = md.to_wire_bytes();
        let back = PruningPointShieldedMetadata::from_wire_bytes(&bytes).expect("current layout decodes");
        assert_eq!(back.dev_accrued, 123_456);
        assert_eq!(back.supply, md.supply);
        assert_eq!(back.in_window_anchors, md.in_window_anchors);
        assert_eq!(back.in_window_anchor_source_scores, md.in_window_anchor_source_scores);

        // A peer that has the accrual but not the anchor scores: our blob minus the trailing
        // vec. Decodes, with no attested scores — which fails closed rather than inventing one.
        let pre_scores = PruningPointShieldedMetadata {
            in_window_anchor_source_scores: Vec::new(),
            nullifier_muhash: md.nullifier_muhash.clone(),
            burns: md.burns.clone(),
            ..md.clone()
        };
        let pre_scores_bytes = pre_scores.to_wire_bytes();
        let truncated = &pre_scores_bytes[..pre_scores_bytes.len() - std::mem::size_of::<u64>()];
        let from_pre_scores = PruningPointShieldedMetadata::from_wire_bytes(truncated).expect("pre-scores layout decodes");
        assert!(from_pre_scores.in_window_anchor_source_scores.is_empty(), "no scores claimed means none attested");
        assert_eq!(from_pre_scores.dev_accrued, 123_456, "the accrual before it still survives");
        assert_eq!(from_pre_scores.in_window_anchors, md.in_window_anchors);

        // The oldest layout: also minus the accrual u64.
        let legacy_bytes = &truncated[..truncated.len() - std::mem::size_of::<u64>()];
        let from_legacy = PruningPointShieldedMetadata::from_wire_bytes(legacy_bytes).expect("legacy layout decodes");
        assert_eq!(from_legacy.dev_accrued, 0, "a peer without the field means no accrual, not a failure");
        assert_eq!(from_legacy.state_root, md.state_root, "everything before the new field survives");
        assert!(from_legacy.in_window_anchor_source_scores.is_empty());

        // And the other direction: an older reader sees our longer blob as its own layout
        // plus trailing bytes, which bincode ignores.
        let as_legacy: LegacyPruningPointShieldedMetadata =
            bincode::deserialize(&bytes).expect("older node tolerates the extra fields");
        assert_eq!(as_legacy.state_root, md.state_root);

        // The trap this ordering exists to avoid: a NEW blob must never be decoded by an OLD
        // layout in `from_wire_bytes`, because bincode ignores trailing bytes and would silently
        // drop the very fields the fix depends on — a node would then fail closed exactly as
        // before, with nothing in the log to say why.
        assert_eq!(
            PruningPointShieldedMetadata::from_wire_bytes(&bytes).unwrap().in_window_anchor_source_scores,
            md.in_window_anchor_source_scores,
            "newest layout must win when several can decode the same bytes"
        );
    }

    /// The fix, at the store level: a source with no local ghostdag data is judged from the
    /// blue score the pruning-point peer attested, and a source nobody attested still cannot be
    /// judged at all. `judge_anchor_source` turns the first into a usable anchor and the second
    /// into the same fail-closed rejection as before; this pins the data layer both rest on.
    #[test]
    fn attested_anchor_source_scores_are_seeded_and_absent_ones_stay_unjudgeable() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(db.clone(), CachePolicy::Empty);

        // Real shape of the mainnet failure: pruning point 993,600, spending block 993,652,
        // anchor source 990,606 — 2,994 BELOW the pruning point, age 3,046, legally in window.
        let source = Hash::from_bytes([9u8; 32]);
        let anchor = [11u8; 32];
        let md = PruningPointShieldedMetadata {
            frontier: FrontierState::default(),
            supply: SupplyTotals::default(),
            nullifier_muhash: MuHash::new(),
            burns: BurnReceipts::default(),
            state_root: [0u8; 32],
            in_window_anchors: vec![(anchor, source)],
            dev_accrued: 0,
            in_window_anchor_source_scores: vec![(source, 990_606)],
        };

        let mut batch = WriteBatch::default();
        mgr.seed_pruning_point_shielded(&mut batch, Hash::from_bytes([1u8; 32]), &md, std::iter::empty())
            .expect("seeding the pruning-point state succeeds");
        db.write(batch).unwrap();

        assert_eq!(
            mgr.attested_source_blue_score(source).unwrap(),
            Some(990_606),
            "the attested score must survive the import, or the anchor mapping is useless on its own"
        );
        assert_eq!(
            mgr.anchor_source_block(&anchor).unwrap(),
            Some(source),
            "the mapping itself still lands (this half already worked)"
        );
        assert_eq!(
            mgr.attested_source_blue_score(Hash::from_bytes([42u8; 32])).unwrap(),
            None,
            "an unattested source must read as None so finality still fails CLOSED (F-04)"
        );
    }

    /// Retention must drop the recomputation snapshots while leaving intact the two
    /// things a pruned node still has to serve: the compact scan archive (a hole in it
    /// is the "restored my seed and my balance is partial" bug) and the global nullifier
    /// set (membership outlives every block that added to it). The frontier survives only
    /// where the caller marks a checkpoint.
    #[test]
    fn pruning_snapshots_keeps_the_scan_archive_and_the_nullifier_set() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(db.clone(), CachePolicy::Empty);
        let pruned = Hash::from_bytes([1u8; 32]);
        let checkpoint = Hash::from_bytes([2u8; 32]);

        let mut batch = WriteBatch::default();
        for b in [pruned, checkpoint] {
            mgr.tree_store.set_batch(&mut batch, b, FrontierState { size: 1, leaf: Some(cmx(9).to_bytes()), ommers: vec![] }).unwrap();
            mgr.supply_store.set_batch(&mut batch, b, SupplyTotals { cumulative_coinbase: 10, cumulative_fees: 1 }).unwrap();
            mgr.dev_accrued_store.set_batch(&mut batch, b, 77).unwrap();
            mgr.scan_block
                .set_batch(
                    &mut batch,
                    b,
                    ShieldedScanBlockData {
                        blue_score: 1,
                        daa_score: 1,
                        timestamp: 0,
                        coinbase_txid: b,
                        coinbase_outputs: vec![(vec![9u8; 43], 42)],
                        coinbase_commitments: Vec::new(),
                        accepted: vec![],
                    },
                )
                .unwrap();
        }
        mgr.nullifiers.insert_batch(&mut batch, [5u8; 32]).unwrap();
        db.write(batch).unwrap();

        let mut batch = WriteBatch::default();
        mgr.prune_block_snapshots(&mut batch, pruned, false, Some(5)).unwrap();
        mgr.prune_block_snapshots(&mut batch, checkpoint, true, Some(6)).unwrap();
        db.write(batch).unwrap();

        // Recomputation snapshots are gone for both; zero/default is what a missing key reads as.
        assert_eq!(mgr.supply_totals_at(pruned).unwrap(), SupplyTotals::default());
        assert_eq!(mgr.dev_accrued_at(pruned).unwrap(), 0, "accrual snapshot is dropped with the rest");
        assert_eq!(mgr.frontier_at(pruned).unwrap().size, 0, "a non-checkpoint frontier is dropped");

        // The checkpoint keeps its frontier so fast-sync still has an anchor down here.
        assert_eq!(mgr.frontier_at(checkpoint).unwrap().size, 1, "a checkpoint frontier survives");

        // Never dropped: the wallet's scan archive and the global nullifier set.
        for b in [pruned, checkpoint] {
            assert!(mgr.scan_block(b).unwrap().is_some(), "the compact scan archive must survive pruning");
        }
        assert!(mgr.nullifiers.contains(&[5u8; 32]).unwrap(), "a spent nullifier must outlive its block");

        // Pruning ENQUEUED both blocks' anchor rows for age-based GC but deleted nothing:
        // a just-pruned block is still inside the window the IBD export serves.
        assert_eq!(mgr.anchor_gc.peek_upto(u64::MAX, 100).len(), 2, "both pruned blocks queue their anchor rows");
    }

    /// The anchor GC deletes only rows aged 2x `max_age` below the pruning point, and
    /// never breaks a last-write-wins mapping that a younger block still owns.
    #[test]
    fn anchor_gc_drops_only_aged_rows_and_respects_last_write_wins() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(db.clone(), CachePolicy::Empty);
        let (old_block, young_block) = (Hash::from_bytes([41u8; 32]), Hash::from_bytes([42u8; 32]));
        let root = [7u8; 32];

        let mut batch = WriteBatch::default();
        // Both blocks produced the same root (e.g. the younger carried no shielded txs);
        // the single-valued index points at the YOUNGER writer.
        mgr.anchor_block.set_batch(&mut batch, root, old_block).unwrap();
        mgr.anchor_block.set_batch(&mut batch, root, young_block).unwrap();
        mgr.anchor_producers.add_producer_batch(&mut batch, root, old_block).unwrap();
        mgr.anchor_producers.add_producer_batch(&mut batch, root, young_block).unwrap();
        mgr.anchor_gc.enqueue_batch(&mut batch, 100, root, old_block).unwrap();
        mgr.anchor_gc.enqueue_batch(&mut batch, 500, root, young_block).unwrap();
        db.write(batch).unwrap();

        // pp_blue 130, max_age 10: limit = 110 -> only the blue-100 entry qualifies.
        let mut batch = WriteBatch::default();
        let processed = mgr.gc_aged_anchors(&mut batch, 130, 10, 1000).unwrap();
        db.write(batch).unwrap();
        assert_eq!(processed, 1, "only the aged entry is drained");

        // The mapping survives - it points at the younger producer, not the aged one.
        assert_eq!(mgr.anchor_block.get(&root).unwrap(), Some(young_block), "last-write-wins mapping owned by a younger block survives");
        assert_eq!(mgr.anchor_producer_blocks(&root).unwrap(), vec![young_block], "only the aged producer row is removed");
        assert_eq!(mgr.anchor_gc.peek_upto(u64::MAX, 100).len(), 1, "the young queue entry stays");

        // Age the young entry out too: now the mapping itself goes.
        let mut batch = WriteBatch::default();
        let processed = mgr.gc_aged_anchors(&mut batch, 100_000, 10, 1000).unwrap();
        db.write(batch).unwrap();
        assert_eq!(processed, 1);
        assert_eq!(mgr.anchor_block.get(&root).unwrap(), None, "an anchor with no live producer is fully dropped");
        assert!(mgr.anchor_producer_blocks(&root).unwrap().is_empty());
        assert!(mgr.anchor_gc.peek_upto(u64::MAX, 100).is_empty(), "queue fully drained");
    }

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

    /// The empty-tree anchor (the finalized anchor of the genesis chain block).
    fn empty_anchor() -> [u8; 32] {
        kaspa_shielded_core::Anchor::empty_tree().to_bytes()
    }

    fn stx(nfs: &[u8], cmxs: &[u32], fee: u64) -> ShieldedTx {
        ShieldedTx {
            burn: None,
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee,
            anchor: empty_anchor(),
        }
    }

    fn coinbase(value: u64, c: u32) -> CoinbaseMint {
        CoinbaseMint::new(vec![CoinbaseNote { value, commitment: cmx(c) }])
    }

    fn h(n: u8) -> Hash {
        Hash::from_bytes([n; 32])
    }

    /// A fresh manager. Anchor-finality (maturity + canonical ancestry) is enforced
    /// by the virtual processor via reachability, not by `compute`, so these unit
    /// tests exercise the transition/turnstile/nullifier logic directly.
    fn manager(db: &Arc<DB>) -> ShieldedStateManager {
        ShieldedStateManager::new(Arc::clone(db), CachePolicy::Count(64))
    }

    /// Commit one block (compute → persist → write), mirroring the per-block
    /// flow the virtual processor uses (each block's batch is written before the
    /// next block is validated).
    fn commit_block(
        mgr: &ShieldedStateManager,
        db: &Arc<DB>,
        block: Hash,
        parent: Hash,
        coinbase: Option<CoinbaseMint>,
        txs: Vec<ShieldedTx>,
    ) -> ComputedBlockShielded {
        let computed = mgr.compute(parent, coinbase.as_ref(), &txs).unwrap();
        let mut batch = WriteBatch::default();
        mgr.persist(&mut batch, block, &computed).unwrap();
        db.write(batch).unwrap();
        computed
    }

    /// A chain of two blocks with a parallel double-spend resolves to one
    /// survivor, persists per-block, and a fresh manager sees the identical
    /// anchor at the tip and rejects later reuse across sessions.
    #[test]
    fn per_block_commit_persists_and_resolves_double_spend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (genesis, b1, b2) = (h(0), h(1), h(2));

        let c1 = commit_block(&mgr, &db, b1, genesis, Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        assert_eq!(c1.outcome.accepted, vec![0], "first spend of nf(1) wins");

        // b2 (parent b1) reuses nf(1); compute reads the persisted global set.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 20)), vec![stx(&[1], &[200], 5)]);
        assert!(c2.outcome.accepted.is_empty(), "second spend of nf(1) dropped");
        let tip_anchor = c2.anchor();

        // Fresh manager from the same DB: identical persisted anchor at the tip.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64));
        assert_eq!(mgr2.anchor_at(b2).unwrap(), tip_anchor);
        assert!(mgr2.nullifiers().contains(&nf(1)).unwrap());

        // A later block reusing nf(1) is still caught against the persisted set.
        let c3 = mgr2.compute(b2, None, &[stx(&[1], &[300], 0)]).unwrap();
        assert!(c3.outcome.accepted.is_empty(), "double-spend caught across sessions");
    }

    fn burn_stx(nfs: &[u8], cmxs: &[u32], value_balance: u64, burn_v: u64, tag: u8) -> ShieldedTx {
        ShieldedTx {
            burn: Some(kaspa_shielded_core::burn::ExitReceipt { v: burn_v, recipient: [tag; 32], n: [tag.wrapping_add(0x90); 32] }),
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee: value_balance,
            anchor: empty_anchor(),
        }
    }

    /// The DAA 371,851 mainnet wedge, reproduced at store level.
    ///
    /// Two sibling blocks with the same parent and the same contents mint identical notes and so
    /// carry an IDENTICAL shielded tree root. `anchor_block` keeps one value per root and is
    /// written last-write-wins, so whichever sibling a node validated last owns the mapping — and
    /// if that one later loses the chain race, `is_shielded_anchor_final` fails it on the
    /// chain-ancestor test and drops every spend against that root. A node that never witnessed
    /// the losing sibling keeps them. Identical canonical state, opposite verdicts.
    ///
    /// The producers index must retain BOTH, so the resolution stops depending on observation
    /// order and an existential test can find the canonical producer.
    #[test]
    fn sibling_blocks_share_a_root_and_both_are_retained_as_producers() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let parent = h(1);
        commit_block(&mgr, &db, parent, h(0), Some(coinbase(100, 0)), vec![]);

        // Two siblings over the same parent with identical contents.
        let (win, lose) = (h(2), h(3));
        let c_win = commit_block(&mgr, &db, win, parent, Some(coinbase(100, 0)), vec![]);
        let c_lose = commit_block(&mgr, &db, lose, parent, Some(coinbase(100, 0)), vec![]);

        assert_eq!(c_win.anchor(), c_lose.anchor(), "same parent + same contents ⇒ IDENTICAL tree root");

        // The single-valued index keeps only the last writer — the defect.
        assert_eq!(
            mgr.anchor_source_block(&c_win.anchor()).unwrap(),
            Some(lose),
            "anchor_block is last-write-wins: the canonical producer's mapping was destroyed"
        );

        // The producers index keeps both, so the canonical one is still reachable.
        let producers = mgr.anchor_producer_blocks(&c_win.anchor()).unwrap();
        assert_eq!(producers.len(), 2, "both producers retained: {producers:?}");
        assert!(producers.contains(&win) && producers.contains(&lose));
    }

    /// A fast-synced node must be able to answer the POST-fork resolution path, not just the
    /// pre-fork one.
    ///
    /// `resolve_shielded_anchor` reads `anchor_producers` once
    /// `shielded_anchor_multi_activation` is live, and `get_producers` maps a missing key to an
    /// EMPTY vec with no fallback to `anchor_block` — which reads as "anchor is not a known tree
    /// root". Seeding only `anchor_block` therefore moved the wedge rather than fixing it: after
    /// activation a syncee dropped every spend anchored below its pruning point while the block's
    /// producer had kept it, and the fee difference disqualified the merging chain block. The
    /// window is real — walletd anchors 630 blue units deep and `shielded-pay` 6,000, against a
    /// 27,000 legal maximum — so it spans blocks a syncee cannot populate from its own validation.
    #[test]
    fn seeding_a_pruning_point_populates_both_anchor_indexes() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let pp = h(9);
        let (hist_anchor, hist_source) = ([3u8; 32], h(5));
        let md = PruningPointShieldedMetadata {
            frontier: FrontierState::default(),
            supply: SupplyTotals::default(),
            nullifier_muhash: MuHash::new(),
            burns: BurnReceipts::default(),
            state_root: [0u8; 32],
            in_window_anchors: vec![(hist_anchor, hist_source)],
            dev_accrued: 0,
            in_window_anchor_source_scores: Vec::new(),
        };

        let mut batch = WriteBatch::default();
        mgr.seed_pruning_point_shielded(&mut batch, pp, &md, std::iter::empty()).unwrap();
        db.write(batch).unwrap();

        // Pre-fork path: unchanged.
        assert_eq!(mgr.anchor_source_block(&hist_anchor).unwrap(), Some(hist_source), "anchor_block seeded");

        // Post-fork path: the producer set must be non-empty, or the anchor reads as unknown and
        // every spend against it is dropped.
        let producers = mgr.anchor_producer_blocks(&hist_anchor).unwrap();
        assert_eq!(producers, vec![hist_source], "in-window anchor must be seeded into anchor_producers too");

        // The pruning point's own root as well.
        let pp_anchor = GlobalTree::from_state(&md.frontier).unwrap().anchor().to_bytes();
        assert_eq!(
            mgr.anchor_producer_blocks(&pp_anchor).unwrap(),
            vec![pp],
            "the pruning point's own anchor must resolve under the multi-producer rule"
        );
    }

    /// Re-applying a block after a reorg must not duplicate it: the producers list is a set, and
    /// unbounded growth on repeated reorgs would be its own problem.
    #[test]
    fn recording_a_producer_twice_is_idempotent() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let parent = h(1);
        commit_block(&mgr, &db, parent, h(0), Some(coinbase(100, 0)), vec![]);
        let c = commit_block(&mgr, &db, h(2), parent, Some(coinbase(100, 0)), vec![]);

        // Simulate a reorg re-apply of the very same block.
        let mut batch = WriteBatch::default();
        mgr.persist(&mut batch, h(2), &c).unwrap();
        db.write(batch).unwrap();

        assert_eq!(mgr.anchor_producer_blocks(&c.anchor()).unwrap(), vec![h(2)], "re-apply must not duplicate the producer");
    }

    /// A bridge burn must survive the round-trip through the stores: it moves the committed state
    /// root, a fresh manager over the same DB reproduces that root, and the accumulator carries
    /// forward to children so later peg-outs still prove against it.
    #[test]
    fn burn_persists_and_moves_the_committed_state_root() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, b2, b3) = (h(1), h(2), h(3));

        // b1: coinbase only — no burns yet, so the burn root is the zero sentinel.
        let c1 = commit_block(&mgr, &db, b1, h(0), Some(coinbase(100, 0)), vec![]);
        assert!(c1.burns.receipts.is_empty());
        assert_eq!(c1.state_root(), mgr.state_root_at(b1).unwrap());

        // b2: a transaction burning 20 of its 30 value_balance.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(100, 10)), vec![burn_stx(&[1], &[100], 30, 20, 0xAA)]);
        assert_eq!(c2.burns.receipts.len(), 1, "the burn must be recorded");
        assert_eq!(c2.burns.receipts[0].0, 20);
        assert_ne!(c2.state_root(), c1.state_root(), "a burn must move the committed state root");
        assert_eq!(c2.state_root(), mgr.state_root_at(b2).unwrap(), "persisted root must match compute-time root");

        // The committed root really is a function of the burn: recomputing it with an empty
        // accumulator gives a different value.
        let without_burns = kaspa_shielded_core::commitment::shielded_state_root(
            &c2.anchor(),
            &c2.nullifier_root(),
            c2.supply_totals.cumulative_coinbase,
            c2.supply_totals.cumulative_fees,
            &[0u8; 32],
        );
        assert_ne!(c2.state_root(), without_burns, "the burn root must be load-bearing in the commitment");

        // A fresh manager over the same DB reproduces it bit-for-bit.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64));
        assert_eq!(mgr2.state_root_at(b2).unwrap(), c2.state_root());

        // A child with no burns inherits the accumulator rather than resetting it.
        let c3 = commit_block(&mgr, &db, b3, b2, Some(coinbase(100, 0)), vec![]);
        assert_eq!(c3.burns.receipts.len(), 1, "accumulator must carry forward across a no-burn block");
        assert_eq!(mgr.state_root_at(b3).unwrap(), c3.state_root());
    }

    /// The shielded state root (PLAN §2.10) is persisted per block, reproduces
    /// exactly on a fresh manager, moves when a spend adds a nullifier, and its
    /// nullifier-accumulator component is empty until the first spend.
    #[test]
    fn state_root_commits_and_reproduces() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, b2, b3) = (h(1), h(2), h(3));

        // b1: coinbase only, no spend — nullifier accumulator is still empty.
        let c1 = commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 0)), vec![]);
        assert_eq!(c1.nullifier_root(), kaspa_muhash::EMPTY_MUHASH.as_bytes(), "no spend => empty accumulator");
        // compute-time root == the root recomputed from persisted stores.
        assert_eq!(c1.state_root(), mgr.state_root_at(b1).unwrap());

        // b2: coinbase + a spend — the accumulator (and thus the state root) moves.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        assert_ne!(c2.nullifier_root(), kaspa_muhash::EMPTY_MUHASH.as_bytes(), "spend populates accumulator");
        assert_ne!(c2.state_root(), c1.state_root(), "state root must advance");
        assert_eq!(c2.state_root(), mgr.state_root_at(b2).unwrap());

        // A fresh manager over the same DB reproduces both roots bit-for-bit.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64));
        assert_eq!(mgr2.state_root_at(b1).unwrap(), c1.state_root());
        assert_eq!(mgr2.state_root_at(b2).unwrap(), c2.state_root());

        // A no-spend child still carries the accumulator forward (readable at b3).
        let c3 = commit_block(&mgr, &db, b3, b2, Some(coinbase(50, 0)), vec![]);
        assert_eq!(c3.nullifier_root(), c2.nullifier_root(), "accumulator persists across a no-spend block");
        assert_eq!(mgr.state_root_at(b3).unwrap(), c3.state_root());
    }

    /// Pruning-point IBD transfer roundtrip (Tier-1 launch blocker): export the
    /// shielded state at a pruning point, verify + seed it into a fresh empty DB,
    /// and confirm the seeded node reproduces the state root, the anchor→block
    /// index, the frontier, the full nullifier membership, and still catches a
    /// double-spend of a pre-pruning nullifier while accepting a genuinely new one.
    #[test]
    fn pruning_point_shielded_export_seed_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, b2, pp) = (h(1), h(2), h(3));

        // A small chain with three spends so the nullifier set is non-trivial.
        commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 20)), vec![stx(&[2], &[200], 5)]);
        let cpp = commit_block(&mgr, &db, pp, b2, Some(coinbase(50, 30)), vec![stx(&[3], &[300], 5)]);
        let pp_root = cpp.state_root();
        let pp_anchor = cpp.anchor();

        // Export at the pruning point + collect the full nullifier set.
        let md = mgr.export_pruning_point_shielded(pp).unwrap().expect("pp has shielded state");
        assert_eq!(md.state_root, pp_root, "exported root == the committed root");
        let nullifiers: Vec<[u8; 32]> = mgr.nullifiers().iter_all().map(|r| r.unwrap()).collect();
        assert_eq!(nullifiers.len(), 3, "three spends => three nullifiers");

        // Verify passes; a tampered supply (inconsistent root) and a short set fail.
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md, nullifiers.iter()).unwrap(), 3);
        let mut bad = md.clone();
        bad.supply.cumulative_fees += 1;
        assert!(
            ShieldedStateManager::verify_pruning_point_shielded(&bad, nullifiers.iter()).is_err(),
            "inconsistent declared state root must be rejected"
        );
        assert!(
            ShieldedStateManager::verify_pruning_point_shielded(&md, nullifiers[..2].iter()).is_err(),
            "a short nullifier set must not reproduce the accumulator"
        );

        // Seed into a fresh, empty DB (the fast-syncing node).
        let (_lt2, db2) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let seeded = manager(&db2);
        let mut batch = WriteBatch::default();
        seeded.seed_pruning_point_shielded(&mut batch, pp, &md, nullifiers.iter()).unwrap();
        db2.write(batch).unwrap();

        // The seeded node reproduces the pruning point's shielded state exactly.
        assert_eq!(seeded.state_root_at(pp).unwrap(), pp_root, "seeded state root matches");
        assert_eq!(seeded.anchor_at(pp).unwrap(), pp_anchor);
        assert_eq!(seeded.frontier_at(pp).unwrap(), md.frontier);
        assert_eq!(seeded.anchor_source_block(&pp_anchor).unwrap(), Some(pp), "anchor→block index seeded");
        for spent in [1u8, 2, 3] {
            assert!(seeded.nullifiers().contains(&nf(spent)).unwrap(), "pre-pruning nullifier present");
        }

        // A descendant of the pruning point extends the tree and still catches a
        // re-spend of a pre-pruning nullifier against the seeded global set, while
        // accepting a genuinely new spend.
        let dbl = seeded.compute(pp, Some(&coinbase(50, 40)), &[stx(&[2], &[400], 5)]).unwrap();
        assert!(dbl.outcome.accepted.is_empty(), "re-spend of a pre-pruning nullifier dropped");
        let ok = seeded.compute(pp, Some(&coinbase(50, 41)), &[stx(&[9], &[401], 5)]).unwrap();
        assert_eq!(ok.outcome.accepted, vec![0], "a genuinely new spend is accepted on the seeded node");
    }

    /// F-03 regression: the IBD export must serve the **PP-time** nullifier set, not
    /// the tip-time global set. Build a chain with spends up to the "pruning point",
    /// then add MORE spends past it (as happens in the full pruning period between
    /// the PP and the virtual tip), and confirm that `nullifier_set_snapshot` +
    /// `subtract_nullifier_diffs` over the post-PP selected-chain blocks recovers a
    /// (set, count) pair that reproduces the PP MuHash — the receiver's
    /// `verify_pruning_point_shielded` check — while the raw tip-time set fails it.
    /// (Advancing a real pruning point is impractical in this harness, so the test
    /// exercises the diff-subtraction helper directly with explicit post-PP blocks.)
    #[test]
    fn pruning_point_export_serves_pp_time_nullifier_set() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, pp, a1, a2) = (h(1), h(2), h(3), h(4));

        // Up to and including the pruning point: two spends.
        commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        let cpp = commit_block(&mgr, &db, pp, b1, Some(coinbase(50, 20)), vec![stx(&[2], &[200], 5)]);
        let pp_root = cpp.state_root();

        // Past the pruning point: two MORE spends. The append-only global set now
        // reflects the tip (4 nullifiers), a superset of the PP-time set.
        commit_block(&mgr, &db, a1, pp, Some(coinbase(50, 30)), vec![stx(&[3], &[300], 5)]);
        commit_block(&mgr, &db, a2, a1, Some(coinbase(50, 40)), vec![stx(&[4], &[400], 5)]);
        assert_eq!(mgr.nullifiers().count(), 4, "tip-time global set is a superset of the PP-time set");

        // Export at the PP, then recover the PP-time set by subtracting the diffs of
        // the selected-chain blocks in (pp, tip].
        let md = mgr.export_pruning_point_shielded(pp).unwrap().expect("pp has shielded state");
        assert_eq!(md.state_root, pp_root, "exported root == the committed root");
        let pp_set = mgr.subtract_nullifier_diffs(mgr.nullifier_set_snapshot().unwrap(), [a1, a2]).unwrap();
        assert_eq!(pp_set.len(), 2, "post-PP nullifiers removed from the export");

        // The exported (set, count) reproduces the PP MuHash — the receiver's check.
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md, pp_set.iter()).unwrap(), 2);

        // The raw tip-time set must NOT verify against the PP snapshot — exactly the
        // pre-fix failure that deterministically broke honest IBD once the pool was used.
        let tip_set = mgr.nullifier_set_snapshot().unwrap();
        assert!(
            ShieldedStateManager::verify_pruning_point_shielded(&md, tip_set.iter()).is_err(),
            "the tip-time set must not reproduce the PP accumulator"
        );

        // The subtraction is a set operation: post-PP block order does not matter.
        let pp_set_rev = mgr.subtract_nullifier_diffs(mgr.nullifier_set_snapshot().unwrap(), [a2, a1]).unwrap();
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md, pp_set_rev.iter()).unwrap(), 2);

        // Blocks with no shielded spends contribute an empty diff (not an error),
        // and the PP itself is excluded by the caller's (pp, tip] window.
        let pp_set_extra = mgr.subtract_nullifier_diffs(mgr.nullifier_set_snapshot().unwrap(), [a1, a2, h(9)]).unwrap();
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md, pp_set_extra.iter()).unwrap(), 2);
    }

    /// Reverting a block removes the nullifiers it added, so the same nullifier
    /// can be spent again on the new branch (reorg correctness).
    #[test]
    fn revert_removes_block_nullifiers() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let b1 = h(1);

        commit_block(&mgr, &db, b1, h(0), Some(coinbase(10, 1)), vec![stx(&[1], &[100], 0)]);
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap());

        // Reorg abandons b1: remove its nullifiers from the global set.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, b1).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "reverted nullifier removed");

        // The new branch can now spend nf(1).
        let c = mgr.compute(h(0), Some(&coinbase(10, 2)), &[stx(&[1], &[101], 0)]).unwrap();
        assert_eq!(c.outcome.accepted, vec![0], "spend of reverted nullifier accepted on new branch");
    }

    /// A block that rejoins the selected chain has its nullifiers re-added from
    /// its persisted per-block diff (reorg up-walk).
    #[test]
    fn rejoin_re_adds_nullifiers_from_store() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let b1 = h(1);

        commit_block(&mgr, &db, b1, h(0), Some(coinbase(10, 1)), vec![stx(&[1], &[100], 0)]);
        // Reorg out, then back in.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, b1).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap());

        let mut ab = WriteBatch::default();
        mgr.apply_nullifiers_from_store(&mut ab, b1).unwrap();
        db.write(ab).unwrap();
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap(), "rejoined block's nullifiers restored");
    }

    /// Reorg with a shielded COINBASE: a coinbase mint on the abandoned branch
    /// must not leak into the competing branch's pool or anchor, and abandoning
    /// the branch must revert its nullifiers so the competing branch can re-spend
    /// the note. Because per-block frontier/supply snapshots are keyed by block
    /// hash, the competing branch loads its own selected-parent's state and never
    /// inherits the abandoned coinbase; only the global nullifier set is shared
    /// and is reverted via the per-block diff.
    #[test]
    fn reorg_isolates_and_reverts_shielded_coinbase() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (genesis, branch_a, branch_b) = (h(0), h(1), h(2));

        // Branch A (from genesis): coinbase mints 100, a tx spends nf(1), fee 5.
        let ca = commit_block(&mgr, &db, branch_a, genesis, Some(coinbase(100, 10)), vec![stx(&[1], &[100], 5)]);
        assert_eq!(ca.outcome.accepted, vec![0]);
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap());
        let pool_a = ca.supply_totals.cumulative_coinbase - ca.supply_totals.cumulative_fees;
        assert_eq!(pool_a, 100 - 5, "branch A pool = subsidy - fee");
        let anchor_a = ca.anchor();

        // Reorg abandons branch A: revert its nullifiers from the global set.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, branch_a).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "abandoned coinbase-block's nullifier reverted");

        // Branch B (also from genesis): a DIFFERENT coinbase mints 100, and a tx
        // re-spends the SAME nf(1) (now allowed) with fee 7. compute() loads the
        // genesis (empty) snapshot as its parent — branch A's coinbase mint of 100
        // is NOT present.
        let cb = commit_block(&mgr, &db, branch_b, genesis, Some(coinbase(100, 20)), vec![stx(&[1], &[200], 7)]);
        assert_eq!(cb.outcome.accepted, vec![0], "reverted note re-spendable on the competing branch");

        // Isolation: branch B's pool is its own subsidy - fee, NOT A's mint too
        // (would be 200 - 12 if A had leaked). The abandoned coinbase carried no
        // value across the reorg.
        let pool_b = cb.supply_totals.cumulative_coinbase - cb.supply_totals.cumulative_fees;
        assert_eq!(pool_b, 100 - 7, "branch B pool excludes the abandoned branch's coinbase");

        // Distinct branches, distinct anchors: A's coinbase note never entered B's tree.
        assert_ne!(cb.anchor(), anchor_a, "competing branch has an independent anchor");
    }

    /// Spending more than was ever minted is rejected (turnstile) at compute time.
    #[test]
    fn rejects_overspend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let res = mgr.compute(h(0), Some(&coinbase(10, 1)), &[stx(&[7], &[2], 11)]);
        assert!(matches!(res, Err(ShieldedManagerError::State(ShieldedStateError::Turnstile(_)))));
    }

    /// THE make-or-break property (PLAN Phase 1) at the consensus-manager layer:
    /// when a chain block **merges two parallel blocks** that each spend the same
    /// shielded note, both of those spends land in that one chain block's accepted
    /// set and are resolved in a **single** store-backed `compute` call (this is
    /// exactly what the virtual processor does — `ctx.shielded_txs` gathers the
    /// whole mergeset, then one `compute` runs). Exactly one spend must survive,
    /// the nullifier must be recorded once, no value may be created, and — the
    /// determinism requirement — two independent nodes must compute the identical
    /// anchor from the identical accepted order.
    #[test]
    fn parallel_mergeset_double_spend_resolved_in_one_compute() {
        // Two independent "nodes", each with its own DB/manager, apply the identical
        // accepted order: a coinbase (mints 100) then two conflicting spends of nf(1)
        // — the first from merged block X, the second from merged block Y — plus one
        // independent spend of nf(2). GHOSTDAG fixed the order [X's tx, Y's tx, other].
        let build_tip = || {
            let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
            let mgr = manager(&db);
            // First, a coinbase-only block matures a note into the pool for nf(1)/nf(2)
            // to have been "minted" against (turnstile needs the pool funded).
            let c0 = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(100, 10)), vec![]);
            assert_eq!(c0.outcome.accepted.len(), 0);
            // The merging chain block h(2): its accepted set carries BOTH conflicting
            // spends of nf(1) (from the two parallel merged blocks) and an independent
            // spend of nf(2), all resolved in this one compute call.
            let computed = mgr
                .compute(
                    h(1),
                    None,
                    &[
                        stx(&[1], &[100], 5), // X's spend of nf(1) — first in order, wins
                        stx(&[1], &[200], 5), // Y's spend of nf(1) — dropped (double-spend)
                        stx(&[2], &[300], 5), // independent spend — survives
                    ],
                )
                .unwrap();
            // Release all DB references before `_lt` drops (its Drop asserts the DB has
            // no strong refs left); only the owned `computed` result escapes.
            drop(mgr);
            drop(db);
            computed
        };

        let a = build_tip();
        let b = build_tip();

        // Exactly one of the conflicting spends survives; the independent one also does.
        assert_eq!(a.outcome.accepted, vec![0, 2], "first spend of nf(1) wins, Y's is dropped, nf(2) survives");
        // The double-spent nullifier is recorded exactly once (plus nf(2) once).
        assert_eq!(a.outcome.new_nullifiers.len(), 2);
        // No value created: pool = coinbase(100) − fees(5 for tx0 + 5 for tx2); Y's
        // dropped tx contributes no fee.
        assert_eq!(a.supply_totals.cumulative_coinbase - a.supply_totals.cumulative_fees, 100 - 10);
        // Determinism: two independent nodes compute the identical anchor.
        assert_eq!(a.anchor(), b.anchor(), "identical anchor across nodes from identical accepted order");
    }

    /// F-01 regression, the partition rules: `partition_applied` must drop exactly
    /// what the state transition drops — spends against non-final anchors, and
    /// nullifier conflicts both against the persisted set and within the batch
    /// (first in accepted order wins) — while pure-output txs are always kept.
    #[test]
    fn partition_applied_mirrors_transition_drop_rules() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);

        // Persist a block spending nf(1) so the finalized set contains it.
        commit_block(&mgr, &db, h(1), h(0), Some(coinbase(100, 10)), vec![stx(&[1], &[100], 5)]);

        let bad_anchor = [0xbb; 32];
        let mut immature = stx(&[4], &[400], 9);
        immature.anchor = bad_anchor;
        let candidates = vec![
            stx(&[2], &[200], 5), // fresh spend — kept
            stx(&[1], &[201], 5), // conflicts with the PERSISTED nf(1) — dropped
            stx(&[2], &[202], 7), // conflicts with the batch's first tx — dropped
            immature,             // spend against a non-final anchor — dropped
            stx(&[], &[203], 0),  // pure-output (no nullifiers): anchor rule exempt — kept
            stx(&[3], &[204], 2), // independent spend — kept
        ];
        let outcomes = mgr.partition_applied(&candidates, |stx| stx.anchor != bad_anchor);
        let keep: Vec<bool> = outcomes.iter().map(|o| o.kept()).collect();
        assert_eq!(keep, vec![true, false, false, false, true, true]);
        // The two drop reasons must stay distinguishable. A spend lost to a stale anchor and a
        // spend lost to a nullifier conflict produce an identical coinbase but mean completely
        // different things, and collapsing them is what made past divergences undiagnosable.
        assert!(outcomes[1].anchor_ok && !outcomes[1].conflict_ok, "index 1 lost to a nullifier conflict");
        assert!(!outcomes[3].anchor_ok, "index 3 lost to a non-final anchor");
        assert!(outcomes[3].drop_reason().unwrap().contains("anchor"));
        assert!(outcomes[2].drop_reason().unwrap().contains("nullifier"));
        assert!(outcomes[0].drop_reason().is_none(), "a kept spend has no drop reason");

        // The transition applied to the FULL set accepts exactly the kept indices —
        // the partition is a faithful precomputation of the transition's drops.
        let computed = mgr.compute(h(1), None, &candidates).unwrap();
        let kept_indices: Vec<usize> = keep.iter().enumerate().filter(|(_, k)| **k).map(|(i, _)| i).collect();
        // `compute` has no anchor predicate (the caller pre-filters), so exclude
        // the anchor-dropped tx from the comparison by feeding the pre-filtered set.
        let anchor_ok: Vec<ShieldedTx> = candidates.iter().filter(|s| s.anchor != bad_anchor).cloned().collect();
        let computed_filtered = mgr.compute(h(1), None, &anchor_ok).unwrap();
        assert_eq!(computed_filtered.outcome.accepted.len(), kept_indices.len());
        // And on the full set the nullifier-only drops agree (indices 1 and 2 dropped).
        assert_eq!(computed.outcome.accepted, vec![0, 3, 4, 5], "nullifier rules agree with the mask (anchor rule aside)");
    }

    /// F-01 regression, the accounting: when a spend is dropped, the coinbase must
    /// re-mint only the APPLIED fees — then the pool grows by exactly the subsidy.
    /// The counterfactual shows the pre-fix behavior (coinbase re-mints the dropped
    /// fee too) inflates the pool by exactly that fee — which the new pool-delta
    /// consensus check rejects.
    #[test]
    fn dropped_spend_fee_is_not_reminted() {
        const SUBSIDY: u64 = 100;
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);

        // Fund the pool.
        let c1 = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(SUBSIDY, 10)), vec![]);
        let pool_before = c1.supply_totals.cumulative_coinbase - c1.supply_totals.cumulative_fees;

        // Two conflicting spends of nf(1) arrive in one mergeset: fees 5 and 7.
        let candidates = vec![stx(&[1], &[100], 5), stx(&[1], &[200], 7)];
        let keep: Vec<bool> = mgr.partition_applied(&candidates, |_| true).iter().map(|o| o.kept()).collect();
        assert_eq!(keep, vec![true, false]);
        let applied: Vec<ShieldedTx> = candidates.iter().zip(&keep).filter(|(_, k)| **k).map(|(s, _)| s.clone()).collect();
        let applied_fees: u64 = applied.iter().map(|s| s.fee).sum();
        assert_eq!(applied_fees, 5);

        // COUNTERFACTUAL (the pre-fix coinbase), computed first — before h(2) is
        // committed, so nf(1) is not yet in the persisted set (`compute` does not
        // persist): re-minting the dropped fee too (subsidy + 5 + 7) inflates the
        // pool by the dropped 7 — silent unbacked supply. This is what
        // verify_expected_utxo_state's pool-delta check now turns into an
        // InvalidShieldedState rejection.
        let c_bad = mgr.compute(h(1), Some(&coinbase(SUBSIDY + 5 + 7, 21)), &applied).unwrap();
        let bad_pool = c_bad.supply_totals.cumulative_coinbase - c_bad.supply_totals.cumulative_fees;
        assert_eq!(bad_pool - pool_before, (SUBSIDY + 7) as u128, "the old behavior mints the dropped fee unbacked");

        // FIXED coinbase: subsidy + applied fees only. Pool grows by the subsidy.
        let c2 = commit_block(&mgr, &db, h(2), h(1), Some(coinbase(SUBSIDY + applied_fees, 20)), applied);
        let pool_after = c2.supply_totals.cumulative_coinbase - c2.supply_totals.cumulative_fees;
        assert_eq!(pool_after - pool_before, SUBSIDY as u128, "pool must grow by exactly the subsidy");
    }

    /// The anchor→block index records a block's tree root so a spend can later be
    /// resolved to its source block (finality/canonicality is then decided by the
    /// virtual processor via reachability + depth, tested at that layer).
    /// The backfill verifier must reproduce the exact frontier an honest range builds, and must
    /// reject any tampering. Without this the whole history-backfill path would be "trust the
    /// peer", which is precisely what it exists to avoid.
    #[test]
    /// The capturing replay must emit a frontier for every labelled block, and each captured
    /// frontier must equal what a replay TRUNCATED at that block produces. That equality is the
    /// entire reason a checkpoint is trustworthy once the full replay verifies: a checkpoint is a
    /// prefix of the same verified leaf sequence, not an independent claim.
    #[test]
    fn captured_checkpoints_equal_truncated_replays() {
        // Three blocks, each contributing distinct leaves; label every one.
        let blocks: Vec<(Vec<[u8; 32]>, Vec<Vec<u8>>)> = (0u32..3)
            .map(|b| (vec![cmx(b * 10 + 1).to_bytes(), cmx(b * 10 + 2).to_bytes()], Vec::new()))
            .collect();

        let mut captured: Vec<(usize, FrontierState)> = Vec::new();
        let (final_frontier, leaves) = ShieldedStateManager::replay_frontier_streaming_capturing(
            blocks.iter().enumerate().map(|(i, (c, a))| Ok((Some(i), c.clone(), a.clone()))),
            |i, f| captured.push((i, f.clone())),
        )
        .expect("replay of well-formed leaves must succeed");

        assert_eq!(leaves, 6, "two leaves per block over three blocks");
        assert_eq!(captured.len(), 3, "one checkpoint per labelled block");

        // Each captured frontier must match a replay of just the prefix up to that block.
        for (i, f) in &captured {
            let (prefix, _) =
                ShieldedStateManager::replay_frontier_streaming(blocks[..=*i].iter().map(|(c, a)| Ok((c.clone(), a.clone()))))
                    .expect("prefix replay must succeed");
            assert_eq!(&prefix, f, "checkpoint at block {i} must equal the truncated replay");
        }
        // And the last checkpoint is the final frontier.
        assert_eq!(captured.last().unwrap().1, final_frontier);
    }

    /// Unlabelled blocks must produce NO checkpoint, so the caller controls spacing entirely.
    #[test]
    fn unlabelled_blocks_capture_nothing() {
        let blocks: Vec<(Vec<[u8; 32]>, Vec<Vec<u8>>)> =
            (0u32..4).map(|b| (vec![cmx(b + 1).to_bytes()], Vec::new())).collect();
        let mut captured = 0usize;
        // Label only every 2nd block, mirroring how the verifier spaces checkpoints by index.
        ShieldedStateManager::replay_frontier_streaming_capturing(
            blocks.iter().enumerate().map(|(i, (c, a))| Ok(((i % 2 == 0).then_some(i), c.clone(), a.clone()))),
            |_, _| captured += 1,
        )
        .expect("replay must succeed");
        assert_eq!(captured, 2, "only labelled blocks may emit a checkpoint");
    }

    /// SAFETY PROPERTY: a replay that FAILS must not leave a usable checkpoint behind.
    ///
    /// The capturing replay hands frontiers to the caller as it goes, so it necessarily emits
    /// some before it discovers the data is bad. What must hold is that it still returns `Err`,
    /// which is what stops `verify_shielded_history` from reaching its persist branch. If this
    /// ever returned `Ok` on tampered data, poisoned anchors would be written on exactly the path
    /// that exists to reject bad history.
    #[test]
    fn a_failed_replay_reports_error_so_nothing_is_persisted() {
        let good = vec![cmx(1).to_bytes()];
        // A non-canonical Pallas encoding: all-0xff is not a valid base-field element.
        let bad = vec![[0xffu8; 32]];
        let mut captured = 0usize;
        let res = ShieldedStateManager::replay_frontier_streaming_capturing(
            vec![Ok((Some(0usize), good, Vec::new())), Ok((Some(1usize), bad, Vec::new()))].into_iter(),
            |_, _| captured += 1,
        );
        assert!(matches!(res, Err(ReplayError::Data(_))), "tampered leaves must fail the replay, got {res:?}");
        // It may have captured the first block's frontier — that is fine and unavoidable. The
        // guarantee is the Err above: the caller never reaches its write.
        assert!(captured <= 1, "must not capture past the failure point");
    }

    fn history_replay_reproduces_frontier_and_detects_tampering() {
        use kaspa_consensus_core::api::ShieldedChainBlockData;

        // Build a plausible history: three blocks, each contributing action leaves.
        let leaf = |n: u8| {
            let mut c = [0u8; 32];
            c[0] = n;
            // Keep it a canonical Pallas base encoding by clearing the high bits.
            c[31] = 0;
            c
        };
        let block = |leaves: &[u8]| {
            let mut action_bytes = Vec::new();
            for &n in leaves {
                let mut rec = [0u8; CompactActionRecord::SERIALIZED_LEN];
                rec[32..64].copy_from_slice(&leaf(n));
                action_bytes.extend_from_slice(&rec);
            }
            ShieldedChainBlockData {
                hash: h(1),
                blue_score: 0,
                daa_score: 0,
                coinbase_txid: h(0),
                coinbase_outputs: Vec::new(),
                coinbase_commitments: Vec::new(),
                accepted_actions: vec![action_bytes],
                accepted_txids: vec![h(2)],
                timestamp: 0,
            }
        };
        let no_coinbase = |_: &ShieldedChainBlockData| Vec::new();

        let honest = vec![block(&[1, 2]), block(&[3]), block(&[4, 5])];
        let expected = ShieldedStateManager::replay_history_frontier(&honest, no_coinbase).unwrap();
        assert_eq!(expected.size, 5, "five leaves appended across the range");

        // Same leaves, same order => same frontier. (Determinism is what makes the check sound.)
        let again = ShieldedStateManager::replay_history_frontier(&honest, no_coinbase).unwrap();
        assert_eq!(again, expected);

        // A peer that OMITS a record cannot match.
        let omitted = vec![honest[0].clone(), honest[2].clone()];
        assert_ne!(ShieldedStateManager::replay_history_frontier(&omitted, no_coinbase).unwrap(), expected, "omission must be caught");

        // A peer that REORDERS records cannot match (the tree is order-dependent).
        let reordered = vec![honest[1].clone(), honest[0].clone(), honest[2].clone()];
        assert_ne!(
            ShieldedStateManager::replay_history_frontier(&reordered, no_coinbase).unwrap(),
            expected,
            "reordering must be caught"
        );

        // A peer that FABRICATES a leaf cannot match.
        let mut tampered = honest.clone();
        tampered[1] = block(&[99]);
        assert_ne!(
            ShieldedStateManager::replay_history_frontier(&tampered, no_coinbase).unwrap(),
            expected,
            "fabrication must be caught"
        );

        // A peer that TRUNCATES the range cannot match.
        let truncated = vec![honest[0].clone(), honest[1].clone()];
        assert_ne!(
            ShieldedStateManager::replay_history_frontier(&truncated, no_coinbase).unwrap(),
            expected,
            "truncation must be caught"
        );
    }

    #[test]
    fn records_anchor_source_block() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        // Commit a coinbase-only block; its non-empty tree root is indexed to h(1).
        let computed = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(10, 1)), vec![]);
        let anchor = computed.anchor();
        assert_eq!(mgr.anchor_source_block(&anchor).unwrap(), Some(h(1)));
        // An anchor no block produced is unknown.
        assert_eq!(mgr.anchor_source_block(&[0xabu8; 32]).unwrap(), None);
    }

    /// F-02: the empty-state root (used to bind a peer's "no shielded state" claim
    /// to the PoW commitment) must equal the root recomputed from untouched stores,
    /// and `verify_import_binding` must accept exactly the committed root and
    /// reject anything else.
    #[test]
    fn empty_state_root_and_import_binding() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);

        // A block with no shielded state reads back the empty root from default stores.
        assert_eq!(mgr.state_root_at(h(0)).unwrap(), PruningPointShieldedMetadata::empty_state_root());

        // A real export binds to its own root; a single-bit difference is rejected.
        commit_block(&mgr, &db, h(1), h(0), Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        let md = mgr.export_pruning_point_shielded(h(1)).unwrap().expect("has shielded state");
        assert!(ShieldedStateManager::verify_import_binding(&md, md.state_root).is_ok());
        let mut wrong = md.state_root;
        wrong[0] ^= 1;
        assert!(ShieldedStateManager::verify_import_binding(&md, wrong).is_err(), "root mismatch must be rejected");
        // In particular the binding distinguishes non-empty state from the empty root
        // (the flow.rs:820 empty-metadata wedge).
        assert!(ShieldedStateManager::verify_import_binding(&md, PruningPointShieldedMetadata::empty_state_root()).is_err());
    }

    /// F-15 regression: `clear_for_pruning_reimport` must REALLY clear — the whole
    /// global nullifier set plus the per-block snapshots at the pruning point — so
    /// a re-seed starts from a clean slate and cannot union stale nullifiers into
    /// the new state (the pre-fix clear only flipped the stable flag, so nullifiers
    /// of abandoned-fork blocks survived and froze spends of unspent notes).
    #[test]
    fn clear_for_pruning_reimport_enables_clean_reseed() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, pp) = (h(1), h(2));

        // Original state at the pruning point: two spends.
        commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        commit_block(&mgr, &db, pp, b1, Some(coinbase(50, 20)), vec![stx(&[2], &[200], 5)]);
        assert!(mgr.export_pruning_point_shielded(pp).unwrap().is_some(), "pp has shielded state");
        assert_eq!(mgr.nullifiers().count(), 2);

        // Clear for a from-scratch re-import (what the IBD flow now does before seeding).
        let mut cb = WriteBatch::default();
        mgr.clear_for_pruning_reimport(&mut cb, pp).unwrap();
        db.write(cb).unwrap();

        // The global set is empty and the pruning point's snapshots are gone (the
        // root reads back as the empty-state root). The anchor→block index is
        // intentionally retained (append-only; canonicality is re-checked at query).
        assert_eq!(mgr.nullifiers().count(), 0, "the whole global nullifier set must be deleted");
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap() && !mgr.nullifiers().contains(&nf(2)).unwrap());
        assert_eq!(mgr.state_root_at(pp).unwrap(), PruningPointShieldedMetadata::empty_state_root(), "pp snapshots cleared");

        // Re-seed a DIFFERENT state at the same pruning point (e.g. the syncer's chain
        // disagreed with our abandoned fork): one spend, nf(3). The stale nf(1)/nf(2)
        // must NOT survive into the new state — the exact pre-fix union bug.
        let (_lt2, db2) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let donor = manager(&db2);
        commit_block(&donor, &db2, h(1), h(0), Some(coinbase(50, 10)), vec![]);
        let cpp = commit_block(&donor, &db2, pp, h(1), Some(coinbase(50, 20)), vec![stx(&[3], &[300], 5)]);
        let md_new = donor.export_pruning_point_shielded(pp).unwrap().expect("donor pp has shielded state");
        let new_set = donor.nullifier_set_snapshot().unwrap();
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md_new, new_set.iter()).unwrap(), 1);
        let mut sb = WriteBatch::default();
        mgr.seed_pruning_point_shielded(&mut sb, pp, &md_new, new_set.iter()).unwrap();
        db.write(sb).unwrap();

        assert_eq!(mgr.nullifiers().count(), 1, "no stale nullifiers survive the re-seed");
        assert!(mgr.nullifiers().contains(&nf(3)).unwrap());
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "stale nullifier of the abandoned state is gone");
        assert!(!mgr.nullifiers().contains(&nf(2)).unwrap(), "stale nullifier of the abandoned state is gone");
        assert_eq!(mgr.state_root_at(pp).unwrap(), cpp.state_root(), "re-seeded root matches the new state");
        // And a spend of nf(1) — unspent on the new chain — is accepted, not frozen.
        let ok = mgr.compute(pp, Some(&coinbase(50, 30)), &[stx(&[1], &[400], 5)]).unwrap();
        assert_eq!(ok.outcome.accepted, vec![0], "previously-frozen note is spendable again after the clean re-seed");
    }
}
