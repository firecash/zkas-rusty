//! Consensus stores for the shielded pool (PLAN §3), reorg-safe.
//!
//! Because the virtual processor re-applies chain blocks across reorgs (see
//! decision D10 in DEVLOG), the append-only shielded state is keyed **per chain
//! block**, exactly like the transparent UTXO state:
//!
//! - [`DbShieldedTreeStore`] — the global note-commitment tree **frontier
//!   snapshot at each chain block** (keyed by block hash). To extend a block we
//!   load its selected parent's frontier; to reorg we just load the frontier at
//!   the new tip. No reversal of appends is needed (§2.9).
//! - [`DbNullifierSetStore`] — the global, append-only spent-nullifier set
//!   (membership), plus [`DbNullifierDiffStore`] recording the nullifiers added
//!   by each chain block so a reorg can remove an abandoned branch's nullifiers.
//! - [`DbShieldedSupplyStore`] — the turnstile cumulative totals snapshot at each
//!   chain block (§2.6).
//! - [`DbAnchorBlockStore`] — maps each shielded tree root (anchor) to the block
//!   that produced it, so anchor-finality is decided reorg-consistently at
//!   validation time (canonical ancestor + age in `[shielded_anchor_depth,
//!   max_shielded_anchor_age]`, audit F-04/F-05), §2.5.
//!
//! The append/conflict/turnstile logic lives in `kaspa-shielded-core`; these are
//! the rocksdb-backed persistence the virtual processor drives.

use std::fmt;
use std::sync::Arc;

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_math::Uint3072;
use kaspa_muhash::MuHash;
use kaspa_shielded_core::burn::{BurnAccumulator, ExitReceipt};
use kaspa_shielded_core::tree::FrontierState;
use kaspa_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

/// A nullifier as a database key: its canonical 32-byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NullifierKey(pub [u8; 32]);

impl AsRef<[u8]> for NullifierKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ----------------------------- Nullifier set -----------------------------

pub trait NullifierSetStoreReader {
    /// Whether this nullifier has already been spent (is in the global set).
    fn contains(&self, nullifier: &[u8; 32]) -> StoreResult<bool>;
}

pub trait NullifierSetStore: NullifierSetStoreReader {
    /// Insert a freshly spent nullifier into the global set.
    fn insert_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()>;
    /// Remove a nullifier (used when reverting an abandoned branch's block).
    fn delete_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()>;
}

/// rocksdb + cache implementation of the global, append-only nullifier set. The
/// value is a single marker byte; presence of the key means "spent".
#[derive(Clone)]
pub struct DbNullifierSetStore {
    db: Arc<DB>,
    access: CachedDbAccess<NullifierKey, u8>,
}

impl DbNullifierSetStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifiers.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Iterate every spent nullifier in the global set. Used to export the
    /// shielded state at the pruning point for IBD state transfer (the global
    /// nullifier set is append-only and unprunable — PLAN §2.9 — so a fast-synced
    /// node must receive the full membership to reject future double-spends of
    /// notes that were already spent before the pruning point).
    pub fn iter_all(&self) -> impl Iterator<Item = StoreResult<[u8; 32]>> + '_ {
        self.access.iterator().map(|res| match res {
            Ok((key, _marker)) => {
                let mut nf = [0u8; 32];
                nf.copy_from_slice(&key);
                Ok(nf)
            }
            Err(e) => Err(StoreError::DataInconsistency(format!("nullifier-set iteration failed: {e}"))),
        })
    }

    /// Number of spent nullifiers in the global set (for export progress / sizing).
    pub fn count(&self) -> usize {
        self.access.iterator().count()
    }
}

impl NullifierSetStoreReader for DbNullifierSetStore {
    fn contains(&self, nullifier: &[u8; 32]) -> StoreResult<bool> {
        self.access.has(NullifierKey(*nullifier))
    }
}

impl NullifierSetStore for DbNullifierSetStore {
    fn insert_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), NullifierKey(nullifier), 1u8)
    }

    fn delete_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), NullifierKey(nullifier))
    }
}

// ------------------- Per-block nullifier additions (revert) ---------------

pub trait NullifierDiffStoreReader {
    /// The nullifiers added by a chain block (empty if none / unknown).
    fn get(&self, block: Hash) -> StoreResult<Vec<[u8; 32]>>;
}

/// Records, per chain block, the nullifiers it added to the global set, so a
/// reorg can remove an abandoned branch's nullifiers.
#[derive(Clone)]
pub struct DbNullifierDiffStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Vec<[u8; 32]>, BlockHasher>,
}

impl DbNullifierDiffStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifierDiffs.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, nullifiers: Vec<[u8; 32]>) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, nullifiers)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl NullifierDiffStoreReader for DbNullifierDiffStore {
    fn get(&self, block: Hash) -> StoreResult<Vec<[u8; 32]>> {
        match self.access.read(block) {
            Ok(v) => Ok(v),
            Err(StoreError::KeyNotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------- Global tree frontier --------------------------

/// Newtype wrapper so we can implement the foreign `MemSizeEstimator` trait for
/// the foreign `FrontierState` type (orphan rule). Serializes transparently.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoredFrontier(pub FrontierState);

impl MemSizeEstimator for StoredFrontier {}

pub trait ShieldedTreeStoreReader {
    /// The frontier snapshot at `block`, or the empty-tree frontier if absent
    /// (e.g. the parent of the first shielded block).
    fn get(&self, block: Hash) -> StoreResult<FrontierState>;
}

/// Per-chain-block frontier snapshots of the global note-commitment tree.
#[derive(Clone)]
pub struct DbShieldedTreeStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, StoredFrontier, BlockHasher>,
}

impl DbShieldedTreeStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedTreeFrontier.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, state: FrontierState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, StoredFrontier(state))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }

    /// The stored frontier, or `None` when this node holds no row for `block`. Unlike `get`, an
    /// absent row is not reported as the empty tree, so callers can tell "never stored" from
    /// "empty".
    pub fn get_present(&self, block: Hash) -> StoreResult<Option<FrontierState>> {
        match self.access.read(block) {
            Ok(s) => Ok(Some(s.0)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl ShieldedTreeStoreReader for DbShieldedTreeStore {
    fn get(&self, block: Hash) -> StoreResult<FrontierState> {
        match self.access.read(block) {
            Ok(s) => Ok(s.0),
            Err(StoreError::KeyNotFound(_)) => Ok(FrontierState::default()),
            Err(e) => Err(e),
        }
    }
}

// ----------------------------- Turnstile ----------------------------------

/// Persisted cumulative totals backing the turnstile invariant (PLAN §2.6),
/// snapshotted at each chain block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyTotals {
    pub cumulative_coinbase: u128,
    pub cumulative_fees: u128,
}

impl MemSizeEstimator for SupplyTotals {}

pub trait ShieldedSupplyStoreReader {
    fn get(&self, block: Hash) -> StoreResult<SupplyTotals>;
}

/// Per-chain-block snapshots of the turnstile cumulative totals.
#[derive(Clone)]
pub struct DbShieldedSupplyStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, SupplyTotals, BlockHasher>,
}

impl DbShieldedSupplyStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedSupply.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, totals: SupplyTotals) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, totals)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedSupplyStoreReader for DbShieldedSupplyStore {
    fn get(&self, block: Hash) -> StoreResult<SupplyTotals> {
        match self.access.read(block) {
            Ok(t) => Ok(t),
            Err(StoreError::KeyNotFound(_)) => Ok(SupplyTotals::default()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------------ Dev-fee accrual --------------------------------

/// Dev-fee value accrued but not yet paid out, as of a chain block.
///
/// Before the accrual fork the dev fee is minted as its own coinbase note in
/// **every** block — measured on mainnet as exactly 1.00 note per chain block,
/// 32.8% of all note creation, and the reason a treasury accumulates one note per
/// second. After activation the cut is carried here and paid as a single note once
/// per payout interval.
///
/// Kept in its own store, not as a new field on [`SupplyTotals`]: values are
/// bincode-encoded, bincode is not self-describing, and so widening an existing
/// value type makes every already-written row fail to decode. A separate prefix
/// sidesteps that entirely — an absent key reads as `0`, which is the correct
/// accrual for every block mined before activation.
///
/// It is deliberately **not** part of the shielded state root: that formula is
/// committed by every coinbase, and gating it would touch the most delicate code
/// in the node. It needs no commitment of its own, because the accrued value
/// determines the payout output, and the coinbase is compared byte-for-byte —
/// a node that disagrees about the accrual disagrees about the coinbase and
/// rejects the block.
#[derive(Clone)]
pub struct DbShieldedDevAccruedStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, u64, BlockHasher>,
}

impl DbShieldedDevAccruedStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedDevAccrued.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, accrued: u64) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, accrued)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }

    /// Accrual as of `block`; `0` for any block that never wrote one (every
    /// pre-activation block, and every block on a chain with no dev fee).
    pub fn get(&self, block: Hash) -> StoreResult<u64> {
        match self.access.read(block) {
            Ok(v) => Ok(v),
            Err(StoreError::KeyNotFound(_)) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Security fork: the miner accrual slot carried by each chain block (see
/// `kaspa_consensus_core::coinbase::MinerAccrual`). A missing key is the empty slot, which is the
/// value of every pre-fork block, so only non-empty slots are written.
#[derive(Clone)]
pub struct DbShieldedMinerAccrualStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, StoredMinerAccrual, BlockHasher>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredMinerAccrual(pub kaspa_consensus_core::coinbase::MinerAccrual);
impl MemSizeEstimator for StoredMinerAccrual {}

impl DbShieldedMinerAccrualStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedMinerAccrual.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, slot: kaspa_consensus_core::coinbase::MinerAccrual) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, StoredMinerAccrual(slot))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }

    pub fn get(&self, block: Hash) -> StoreResult<kaspa_consensus_core::coinbase::MinerAccrual> {
        match self.access.read(block) {
            Ok(v) => Ok(v.0),
            Err(StoreError::KeyNotFound(_)) => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }
}

/// Blue score of a block that produced an anchor in the window below the pruning point, as
/// attested by the peer that served the shielded IBD import.
///
/// Anchor finality asks two questions of a source block: is it a selected-chain ancestor of the
/// spending block, and is its age in `[shielded_anchor_depth, max_shielded_anchor_age]`. Both are
/// answered from ghostdag/reachability, which a fast-synced node does not have below its pruning
/// point — so it judged every such anchor non-final and disqualified the first block above the
/// pruning point that spent against one. Transferring the anchor→source mapping (`60abbfb`) was
/// necessary and not sufficient: the mapping resolved and the blue-score lookup still failed.
///
/// An absent key means "the peer did not attest this source", which keeps the old fail-closed
/// behaviour. Ancestry is not stored because it is implied: the server enumerates these by walking
/// its own selected chain below the pruning point, and the pruning point is PoW-committed, so
/// every source here is a selected-chain ancestor of every block above it.
#[derive(Clone)]
pub struct DbShieldedAnchorSourceScoreStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, u64, BlockHasher>,
}

impl DbShieldedAnchorSourceScoreStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedAnchorSourceScore.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, source: Hash, blue_score: u64) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), source, blue_score)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, source: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), source)
    }

    /// The attested blue score of `source`, or `None` when nothing was attested — which the
    /// caller must treat as "cannot judge", never as zero.
    pub fn get(&self, source: Hash) -> StoreResult<Option<u64>> {
        match self.access.read(source) {
            Ok(v) => Ok(Some(v)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// --------------------------- Anchor window (security fork) ---------------------------

/// Per-block anchor log and per-block log entry (see `kaspa_shielded_core::anchor_window`).
/// Both read an absent key as `None`, never as a default: a missing log at a post-fork block is a
/// store inconsistency the caller must surface, not an empty log. The entry row also keeps the log
/// state just BEFORE that entry: the per-block log row is pruned with the block, but an export needs
/// the state just below its lowest entry, and keeping it on that entry means a node needs nothing from
/// further below (a freshly fast-synced node holds exactly the entries it imported).
#[derive(Clone)]
pub struct DbAnchorWindowStore {
    db: Arc<DB>,
    windows: CachedDbAccess<Hash, StoredAnchorWindow, BlockHasher>,
    entries: CachedDbAccess<Hash, StoredWindowEntry, BlockHasher>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredAnchorWindow(pub kaspa_shielded_core::anchor_window::AnchorLog);
impl MemSizeEstimator for StoredAnchorWindow {}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredWindowEntry(pub kaspa_shielded_core::anchor_window::WindowEntry, pub kaspa_shielded_core::anchor_window::AnchorLog);
impl MemSizeEstimator for StoredWindowEntry {}

impl DbAnchorWindowStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            windows: CachedDbAccess::new(Arc::clone(&db), cache_policy, DatabaseStorePrefixes::ShieldedAnchorWindow.into()),
            entries: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedWindowEntry.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_window_batch(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        window: kaspa_shielded_core::anchor_window::AnchorLog,
    ) -> StoreResult<()> {
        self.windows.write(BatchDbWriter::new(batch), block, StoredAnchorWindow(window))
    }

    pub fn window(&self, block: Hash) -> StoreResult<Option<kaspa_shielded_core::anchor_window::AnchorLog>> {
        match self.windows.read(block) {
            Ok(v) => Ok(Some(v.0)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete_window_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.windows.delete(BatchDbWriter::new(batch), block)
    }

    pub fn set_entry_batch(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        entry: kaspa_shielded_core::anchor_window::WindowEntry,
        log_before: kaspa_shielded_core::anchor_window::AnchorLog,
    ) -> StoreResult<()> {
        self.entries.write(BatchDbWriter::new(batch), block, StoredWindowEntry(entry, log_before))
    }

    pub fn entry(&self, block: Hash) -> StoreResult<Option<kaspa_shielded_core::anchor_window::WindowEntry>> {
        Ok(self.entry_with_log(block)?.map(|(e, _)| e))
    }

    /// The entry and the log state right before it.
    pub fn entry_with_log(
        &self,
        block: Hash,
    ) -> StoreResult<Option<(kaspa_shielded_core::anchor_window::WindowEntry, kaspa_shielded_core::anchor_window::AnchorLog)>> {
        match self.entries.read(block) {
            Ok(v) => Ok(Some((v.0, v.1))),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete_entry_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.entries.delete(BatchDbWriter::new(batch), block)
    }
}

// --------------------------- Bridge burn accumulator ---------------------------

/// Persisted bridge burn accumulator at a chain block: the ordered exit receipts burned out of the
/// shielded pool ([`kaspa_shielded_core::burn`]).
///
/// The receipt *sequence* is stored rather than just the root, because the relayer must be able to
/// produce a Merkle branch for any receipt so the Kaspa-side peg-out guest can prove inclusion. A
/// receipt is 72 bytes and burns are rare relative to blocks, so the sequence is cheap.
///
/// Snapshotted per chain block for the same reason as the tree frontier and supply totals: a reorg
/// reloads the selected parent's accumulator instead of replaying from genesis.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnReceipts {
    /// Exit receipts in acceptance order: `(value, kaspa_recipient, exit_nullifier)`.
    pub receipts: Vec<(u64, [u8; 32], [u8; 32])>,
}

impl BurnReceipts {
    /// Rebuild the accumulator this snapshot represents.
    pub fn to_accumulator(&self) -> BurnAccumulator {
        BurnAccumulator::from_receipts(self.receipts.iter().map(|&(v, recipient, n)| ExitReceipt { v, recipient, n }))
    }

    /// Snapshot an accumulator for persistence.
    pub fn from_accumulator(acc: &BurnAccumulator) -> Self {
        Self { receipts: acc.receipts().iter().map(|r| (r.v, r.recipient, r.n)).collect() }
    }
}

impl MemSizeEstimator for BurnReceipts {}

pub trait ShieldedBurnStoreReader {
    fn get(&self, block: Hash) -> StoreResult<BurnReceipts>;
}

/// Per-chain-block snapshots of the bridge burn accumulator.
#[derive(Clone)]
pub struct DbShieldedBurnStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, BurnReceipts, BlockHasher>,
}

impl DbShieldedBurnStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedBurns.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, receipts: BurnReceipts) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, receipts)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedBurnStoreReader for DbShieldedBurnStore {
    fn get(&self, block: Hash) -> StoreResult<BurnReceipts> {
        match self.access.read(block) {
            Ok(r) => Ok(r),
            // A block with no snapshot has never burned: the empty accumulator.
            Err(StoreError::KeyNotFound(_)) => Ok(BurnReceipts::default()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------ Nullifier MuHash accumulator ------------------------

pub trait ShieldedNullifierMuHashStoreReader {
    /// The MuHash accumulator over all spent nullifiers as of the given chain
    /// block. A block with no shielded activity has never been written and
    /// inherits the empty accumulator, so `default` (empty) is returned.
    fn get(&self, block: Hash) -> StoreResult<MuHash>;
}

/// Per-chain-block snapshot of the [`MuHash`] accumulator over the global
/// spent-nullifier set (PLAN §2.2, §2.10).
///
/// Unlike [`DbNullifierDiffStore`] (which records per-block *diffs* so the flat
/// membership set can be reorged), this is an **absolute** snapshot of the
/// accumulator *value* as of each block — mirroring [`DbShieldedSupplyStore`] and
/// the frontier store. Because the accumulator only ever *adds* nullifiers along
/// a given chain (a reorg recomputes from the selected parent, never subtracts
/// from a snapshot), the stored value finalizes to a single field element and is
/// persisted as [`Uint3072`], exactly like the UTXO multiset. It lets the
/// shielded state root commit to double-spend prevention so a fast/pruned node
/// can trust the nullifier set at a checkpoint without replaying from genesis.
#[derive(Clone)]
pub struct DbShieldedNullifierMuHashStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Uint3072, BlockHasher>,
}

impl DbShieldedNullifierMuHashStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifierMuHash.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, muhash: MuHash) -> StoreResult<()> {
        // NOT an invariant that may be asserted. This value also arrives from an IBD peer, whose
        // `MuHash` is deserialized field-by-field (`#[derive(Deserialize)]` over numerator and
        // denominator) with no normalization check — the safe constructor `MuHash::deserialize` is
        // not on that path. A non-normalized denominator must surface as a store error, because
        // panicking here aborted the import AFTER the global nullifier set had already been cleared.
        let normalized = muhash
            .try_into()
            .map_err(|_| StoreError::DataInconsistency("nullifier muhash is not in normalized form".to_owned()))?;
        self.access.write(BatchDbWriter::new(batch), block, normalized)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedNullifierMuHashStoreReader for DbShieldedNullifierMuHashStore {
    fn get(&self, block: Hash) -> StoreResult<MuHash> {
        match self.access.read(block) {
            Ok(u) => Ok(u.into()),
            Err(StoreError::KeyNotFound(_)) => Ok(MuHash::new()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------- Finalized anchor ring -------------------------

/// An anchor (global tree root) as a database key: its 32-byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorKey(pub [u8; 32]);

impl AsRef<[u8]> for AnchorKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for AnchorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Key of the anchor GC queue: big-endian blue score first so the natural RocksDB
/// iteration order is oldest-first, then the anchor and its producing block so
/// sibling producers of one root age out independently.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorGcKey(pub [u8; 72]);

impl AnchorGcKey {
    pub fn new(blue_score: u64, anchor: [u8; 32], block: Hash) -> Self {
        let mut k = [0u8; 72];
        k[..8].copy_from_slice(&blue_score.to_be_bytes());
        k[8..40].copy_from_slice(&anchor);
        k[40..].copy_from_slice(&block.as_bytes());
        Self(k)
    }

    pub fn parts(&self) -> (u64, [u8; 32], Hash) {
        let blue = u64::from_be_bytes(self.0[..8].try_into().unwrap());
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&self.0[8..40]);
        let mut block = [0u8; 32];
        block.copy_from_slice(&self.0[40..]);
        (blue, anchor, Hash::from_bytes(block))
    }
}

impl AsRef<[u8]> for AnchorGcKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for AnchorGcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Deferred GC queue for the anchor indexes (see [`DatabaseStorePrefixes::ShieldedAnchorGcQueue`]).
#[derive(Clone)]
pub struct DbAnchorGcQueueStore {
    db: Arc<DB>,
    access: CachedDbAccess<AnchorGcKey, Hash>,
}

impl DbAnchorGcQueueStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedAnchorGcQueue.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn enqueue_batch(&self, batch: &mut WriteBatch, blue_score: u64, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), AnchorGcKey::new(blue_score, anchor, block), block)
    }

    /// Oldest-first entries whose blue score is `<= blue_limit`, capped at `cap`.
    /// Keys iterate in byte order and the blue score is the big-endian prefix, so this
    /// stops at the first too-young entry.
    pub fn peek_upto(&self, blue_limit: u64, cap: usize) -> Vec<(u64, [u8; 32], Hash)> {
        let mut out = Vec::new();
        for r in self.access.iterator() {
            let Ok((key, _)) = r else { break };
            if key.len() != 72 {
                continue;
            }
            let mut raw = [0u8; 72];
            raw.copy_from_slice(&key);
            let (blue, anchor, block) = AnchorGcKey(raw).parts();
            if blue > blue_limit || out.len() >= cap {
                break;
            }
            out.push((blue, anchor, block));
        }
        out
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, blue_score: u64, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), AnchorGcKey::new(blue_score, anchor, block))
    }
}

pub trait AnchorBlockStoreReader {
    /// The chain block whose shielded tree root equals `anchor`, if any block ever
    /// produced it. `None` means no block did (the anchor is not a real tree root).
    fn get(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>>;
}

/// **Every** block known to have produced a given shielded tree root.
///
/// # Why this exists
///
/// [`DbAnchorBlockStore`] stores one block per root and is written last-write-wins. Its doc
/// comment argues the index needs no reorg reverting because "an anchor from an abandoned
/// branch simply fails the ancestor check" — which is sound for a MULTI-valued index and
/// false for a single-valued one. A block that is briefly on the selected chain writes its
/// root, then gets reorged out, and its entry *overwrites* rather than accompanies the
/// canonical producer's. The canonical mapping is destroyed, so the ancestor check now fails
/// for everyone, and the merging block's coinbase drops a fee it should have kept.
///
/// It is the only shielded store written on reorg-apply and never reverted on reorg-revert
/// (contrast `revert_nullifiers_from_store`). Measured on mainnet: 360 roots produced by a
/// canonical block resolved to a non-canonical one, wedging every freshly synced node.
///
/// Keeping ALL producers restores the original intent. Orphan entries become inert instead of
/// destructive — they simply fail the ancestor check — and the store stays append-only, so no
/// revert logic is needed. It is also deterministic across nodes without any coordination:
/// every node necessarily has the canonical producer (it is a chain block it validated), and
/// extra orphan entries one node happened to witness cannot change an existential test that
/// only accepts chain ancestors.
pub trait AnchorProducersStoreReader {
    /// All blocks that produced `anchor`. Empty when no block did.
    fn get_producers(&self, anchor: &[u8; 32]) -> StoreResult<Vec<Hash>>;
}

#[derive(Clone)]
pub struct DbAnchorProducersStore {
    db: Arc<DB>,
    access: CachedDbAccess<AnchorKey, Vec<Hash>>,
}

impl DbAnchorProducersStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedAnchorProducers.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Record `block` as a producer of `anchor`, idempotently.
    ///
    /// Re-applying the same block after a reorg must not duplicate it, and the list stays
    /// tiny in practice (producers of one root are blocks sharing a mergeset).
    pub fn add_producer_batch(&self, batch: &mut WriteBatch, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        let mut producers = self.get_producers(&anchor)?;
        if producers.contains(&block) {
            return Ok(());
        }
        producers.push(block);
        self.access.write(BatchDbWriter::new(batch), AnchorKey(anchor), producers)
    }

    /// Remove one producer of `anchor`; drops the row entirely when it was the last.
    /// Only the age-based GC calls this.
    pub fn remove_producer_batch(&self, batch: &mut WriteBatch, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        let mut producers = self.get_producers(&anchor)?;
        let before = producers.len();
        producers.retain(|p| *p != block);
        if producers.len() == before {
            return Ok(());
        }
        if producers.is_empty() {
            self.access.delete(BatchDbWriter::new(batch), AnchorKey(anchor))
        } else {
            self.access.write(BatchDbWriter::new(batch), AnchorKey(anchor), producers)
        }
    }

    /// Every `(anchor, producer)` pair in the index, one row per producer.
    ///
    /// The pruning-point export needs this rather than `DbAnchorBlockStore::iter_all`: that index
    /// is single-valued and last-write-wins, so a root whose most recent writer happens to be an
    /// orphan (or any block outside the exported window) is invisible there, and the syncee ends
    /// up with no mapping for it at all — `anchor is not a known tree root`, spend dropped, block
    /// disqualified. Recording every producer is exactly what the multi-producer upgrade added;
    /// the export simply never read it.
    pub fn iter_all(&self) -> impl Iterator<Item = StoreResult<([u8; 32], Hash)>> + '_ {
        self.access.iterator().flat_map(|r| match r {
            Ok((key, producers)) => {
                let mut anchor = [0u8; 32];
                anchor.copy_from_slice(&key);
                producers.into_iter().map(move |p| Ok((anchor, p))).collect::<Vec<_>>()
            }
            Err(e) => vec![Err(StoreError::DataInconsistency(format!("anchor-producers iteration failed: {e}")))],
        })
    }
}

impl AnchorProducersStoreReader for DbAnchorProducersStore {
    fn get_producers(&self, anchor: &[u8; 32]) -> StoreResult<Vec<Hash>> {
        match self.access.read(AnchorKey(*anchor)) {
            Ok(v) => Ok(v),
            Err(StoreError::KeyNotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// Maps each shielded tree root (anchor) to the block that produced it (PLAN §2.5).
///
/// An anchor is a collision-resistant hash of the entire note sequence up to a
/// block, so it uniquely identifies `(block, its selected-chain history)`. This
/// index lets anchor-finality be decided reorg-consistently at validation time:
/// a spend's anchor is acceptable iff its source block is a selected-chain
/// ancestor of the spending block **and** its blue-score age lies in
/// `[shielded_anchor_depth, max_shielded_anchor_age]` (audit F-04/F-05).
/// Because that canonicality is re-checked via reachability on every query, the
/// index itself is append-only and needs no reorg reverting — an anchor from an
/// abandoned branch simply fails the ancestor check.
#[derive(Clone)]
pub struct DbAnchorBlockStore {
    db: Arc<DB>,
    access: CachedDbAccess<AnchorKey, Hash>,
}

impl DbAnchorBlockStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedAnchors.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), AnchorKey(anchor), block)
    }

    /// Remove an anchor mapping. Only the age-based GC calls this, for anchors provably
    /// outside every window a spend or the IBD export can name.
    pub fn delete_batch(&self, batch: &mut WriteBatch, anchor: [u8; 32]) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), AnchorKey(anchor))
    }

    /// Every `(anchor, source block)` pair this node has indexed.
    ///
    /// Used by the shielded IBD export to hand a syncee the anchors below the pruning point that
    /// spends may still legitimately prove against. The obvious alternative — walking the chain and
    /// calling `anchor_at(block)` per block — recomputes a `GlobalTree` root from each stored
    /// frontier, and at `max_shielded_anchor_age` (27,000 blocks at 1 BPS) that overran the 120s IBD
    /// timeout, so the whole import failed. The pairs are already stored here; read them instead of
    /// deriving them.
    pub fn iter_all(&self) -> impl Iterator<Item = StoreResult<([u8; 32], Hash)>> + '_ {
        self.access.iterator().map(|res| match res {
            Ok((key, block)) => {
                let mut anchor = [0u8; 32];
                anchor.copy_from_slice(&key);
                Ok((anchor, block))
            }
            Err(e) => Err(StoreError::DataInconsistency(format!("anchor-block index iteration failed: {e}"))),
        })
    }
}

impl AnchorBlockStoreReader for DbAnchorBlockStore {
    fn get(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>> {
        match self.access.read(AnchorKey(*anchor)) {
            Ok(block) => Ok(Some(block)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------- Compact scan archive (ZKas compact block) ----------------------

/// The exact shielded effects one accepted chain block applied, in **compact**
/// pruning-survivable form (PLAN §2.9). Recorded at validation time (from the
/// block-time applied set — `BlockShieldedOutcome.accepted`), so wallet sync
/// (`GetShieldedBlocks`) serves this persisted truth rather than re-deriving it
/// from block bodies that (a) drift once source blocks prune — the divergent-anchor
/// receive bug — and (b) may be pruned entirely.
///
/// It is self-contained (does not read any store that pruning may delete): the
/// header-derived fields are snapshotted here too, so a single store read serves a
/// block even after its body, ghostdag and acceptance data are gone.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShieldedScanBlockData {
    pub blue_score: u64,
    pub daa_score: u64,
    pub timestamp: u64,
    /// Coinbase tx id — the wallet derives this block's coinbase notes
    /// deterministically from `(coinbase_txid, output index, recipient)`.
    pub coinbase_txid: Hash,
    /// Each coinbase output's `(script_public_key script bytes, value)`. The script
    /// carries the recipient's 43-byte Orchard address; the value is public.
    pub coinbase_outputs: Vec<(Vec<u8>, u64)>,
    /// Consensus-computed note commitments, parallel to `coinbase_outputs`.
    ///
    /// **WARNING — `serde(default)` does NOT make this backward compatible.** Records are stored
    /// with bincode, which is non-self-describing: fields are read POSITIONALLY, so a record
    /// written before this field existed has no bytes for it and the reader consumes the NEXT
    /// field's bytes as this vector's length — yielding
    /// `bincode error: unexpected end of file`, not an empty vec. Proven by
    /// `serde_default_does_not_make_bincode_records_forward_compatible`.
    ///
    /// Consequence: a node upgraded to a binary carrying this field cannot read the scan records
    /// IT WROTE ITSELF beforehand, so `GetShieldedBlocks` fails and wallet history serving breaks
    /// on upgrade.
    ///
    /// Note the two legacy layouts are AMBIGUOUS at this position — pre-field records have
    /// `accepted: Vec<ShieldedScanTx>` here and post-field records have
    /// `commitments: Vec<[u8;32]>`; both start with a bincode length, so a decoder cannot tell
    /// them apart by inspection. The EOF-tolerance trick used by `UtxoEntry::deserialize`
    /// (`consensus/core/src/utxo/utxo_entry.rs`) only works for a field appended LAST.
    ///
    /// Viable migrations, in preference order:
    ///   1. Move this field to the END of the struct and give the type a manual `Deserialize`
    ///      with EOF tolerance (the `UtxoEntry` pattern). Handles pre-field records; requires
    ///      rewriting records already written WITH the field in its current position.
    ///   2. Prefix future records with an explicit version byte and decode by version.
    /// Do NOT assume serde papers over the layout change — it does not.
    #[serde(default)]
    pub coinbase_commitments: Vec<[u8; 32]>,
    /// Accepted shielded txs in consensus applied order, each with its actions in
    /// compact form (`CompactActionRecord::to_bytes()`, 148 bytes each, concatenated).
    pub accepted: Vec<ShieldedScanTx>,
}

/// One accepted shielded tx's compact effects within a [`ShieldedScanBlockData`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedScanTx {
    pub txid: Hash,
    /// Concatenated 148-byte compact action records (nullifier ‖ cmx ‖ epk ‖ enc[52]).
    pub action_bytes: Vec<u8>,
}

impl MemSizeEstimator for ShieldedScanBlockData {}

pub trait ShieldedScanBlockStoreReader {
    /// The compact scan record for a chain block, or `None` if it recorded no
    /// shielded effects (or was written by a pre-archive node).
    fn get(&self, block: Hash) -> StoreResult<Option<ShieldedScanBlockData>>;
}

/// Per-chain-block compact scan archive. Written in the block-commit `WriteBatch`
/// (so it is crash-consistent with the block), and intentionally NOT reorg-reverted:
/// like the anchor index it is keyed by chain-block hash, and an abandoned branch's
/// record is simply never served (its block is off the selected chain). Retained
/// across pruning by the pruning processor for scan-retention nodes.
#[derive(Clone)]
pub struct DbShieldedScanBlockStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, ShieldedScanBlockData, BlockHasher>,
}

impl DbShieldedScanBlockStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedScanBlock.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, data: ShieldedScanBlockData) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, data)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

/// `ShieldedScanBlockData` exactly as it was written BEFORE `coinbase_commitments`
/// existed. Kept so one binary can read a database containing both layouts.
///
/// This is not hypothetical tidiness. A node was upgraded across the field addition on
/// 2026-08-07, wrote ~20 minutes of new-layout records at the tip, and was then rolled
/// back — leaving a database neither binary could read end to end. Every wallet stalled
/// at the first new-layout block (99.7% of the chain) and retried it forever, because a
/// failed page fetch does not advance the sync cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyShieldedScanBlockData {
    blue_score: u64,
    daa_score: u64,
    timestamp: u64,
    coinbase_txid: Hash,
    coinbase_outputs: Vec<(Vec<u8>, u64)>,
    accepted: Vec<ShieldedScanTx>,
}

impl From<LegacyShieldedScanBlockData> for ShieldedScanBlockData {
    fn from(l: LegacyShieldedScanBlockData) -> Self {
        // A pre-field record genuinely carries no commitments. Empty is the truthful
        // value, and `GetShieldedBlocks` already serves `None` commitments per output
        // for such records — the wallet derives them itself, as it always did.
        Self {
            blue_score: l.blue_score,
            daa_score: l.daa_score,
            timestamp: l.timestamp,
            coinbase_txid: l.coinbase_txid,
            coinbase_outputs: l.coinbase_outputs,
            coinbase_commitments: Vec::new(),
            accepted: l.accepted,
        }
    }
}

impl ShieldedScanBlockStoreReader for DbShieldedScanBlockStore {
    fn get(&self, block: Hash) -> StoreResult<Option<ShieldedScanBlockData>> {
        match self.access.read(block) {
            Ok(d) => Ok(Some(d)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            // A decode failure here is the layout ambiguity, not a corrupt database:
            // bincode is positional, so a record written without `coinbase_commitments`
            // makes this reader consume the NEXT field's bytes as that vector's length
            // and run off the end. Retry the bytes as the pre-field layout before giving
            // up — the two are distinguished by which one decodes, since a wrong guess
            // overruns the buffer.
            Err(_) => {
                let db_key = kaspa_database::prelude::DbKey::new(
                    &[DatabaseStorePrefixes::ShieldedScanBlock.into()][..],
                    block,
                );
                match self.db.get_pinned(&db_key)? {
                    Some(slice) => match bincode::deserialize::<LegacyShieldedScanBlockData>(&slice) {
                        Ok(legacy) => Ok(Some(legacy.into())),
                        // Neither layout decodes: now it really is unreadable, and the
                        // caller must see that rather than a silently empty block, which
                        // would present a block's notes as absent.
                        Err(e) => Err(StoreError::DeserializationError(e)),
                    },
                    None => Ok(None),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    /// The repair for that incompatibility: one reader, both layouts.
    ///
    /// A node upgraded across the `coinbase_commitments` addition, wrote records at the
    /// tip, and was rolled back — leaving a database with both layouts in it. Neither
    /// binary could read it end to end, and every wallet froze at the first record of
    /// the other layout because a failed page fetch does not advance the sync cursor.
    ///
    /// Asserts the property the fix depends on: a record of EITHER layout decodes to the
    /// right values, and the pre-field layout is recognised by the current one FAILING
    /// first (it overruns the buffer), never by silently mis-decoding.
    #[test]
    fn both_record_layouts_decode_to_the_same_block() {
        let modern = ShieldedScanBlockData {
            blue_score: 7,
            daa_score: 8,
            timestamp: 9,
            coinbase_txid: Hash::from_bytes([3u8; 32]),
            coinbase_outputs: vec![(vec![1, 2, 3], 500)],
            coinbase_commitments: vec![[8u8; 32]],
            accepted: vec![ShieldedScanTx { txid: Hash::from_bytes([4u8; 32]), action_bytes: vec![9, 9] }],
        };
        let legacy = LegacyShieldedScanBlockData {
            blue_score: 7,
            daa_score: 8,
            timestamp: 9,
            coinbase_txid: Hash::from_bytes([3u8; 32]),
            coinbase_outputs: vec![(vec![1, 2, 3], 500)],
            accepted: vec![ShieldedScanTx { txid: Hash::from_bytes([4u8; 32]), action_bytes: vec![9, 9] }],
        };

        // A modern record still decodes as modern.
        let modern_bytes = bincode::serialize(&modern).unwrap();
        let back: ShieldedScanBlockData = bincode::deserialize(&modern_bytes).unwrap();
        assert_eq!(back.blue_score, 7);
        assert_eq!(back.coinbase_commitments.len(), 1);

        // A legacy record must FAIL as modern — that failure is exactly the signal the
        // store's fallback keys on. If this ever starts succeeding, the fallback becomes
        // unreachable and legacy records get silently mis-decoded instead.
        let legacy_bytes = bincode::serialize(&legacy).unwrap();
        assert!(
            bincode::deserialize::<ShieldedScanBlockData>(&legacy_bytes).is_err(),
            "a pre-field record decoded as the current layout — the store fallback would never fire"
        );

        // ...and decodes correctly as legacy, carrying no commitments.
        let recovered: ShieldedScanBlockData =
            bincode::deserialize::<LegacyShieldedScanBlockData>(&legacy_bytes).unwrap().into();
        assert_eq!(recovered.blue_score, 7);
        assert_eq!(recovered.daa_score, 8);
        assert_eq!(recovered.coinbase_txid, Hash::from_bytes([3u8; 32]));
        assert_eq!(recovered.coinbase_outputs, vec![(vec![1, 2, 3], 500)]);
        assert!(recovered.coinbase_commitments.is_empty());
        assert_eq!(recovered.accepted.len(), 1);
        assert_eq!(recovered.accepted[0].action_bytes, vec![9, 9]);
    }

    /// `#[serde(default)]` does NOT give bincode forward/backward compatibility.
    ///
    /// bincode is non-self-describing: fields are read POSITIONALLY with no names, so a record
    /// written before `coinbase_commitments` existed has no bytes for it and the reader consumes
    /// the NEXT field's bytes as its length. The doc comment on that field claims serde(default)
    /// "keeps pre-commitment archives readable" — this test exists because that is false, and the
    /// same wrong assumption was made once before about `in_window_anchors`.
    ///
    /// Consequence if ignored: a node upgraded to a binary carrying this field can no longer read
    /// the scan records IT ITSELF wrote earlier, so `GetShieldedBlocks` starts failing and wallet
    /// history serving breaks on upgrade.
    ///
    /// This test had no `#[test]` attribute — three were stacked on a later function, so it never
    /// ran once despite guarding an incident that was observed live.
    #[test]
    fn serde_default_does_not_make_bincode_records_forward_compatible() {
        // Exactly `ShieldedScanBlockData` as it was BEFORE `coinbase_commitments` was added.
        #[derive(Serialize)]
        struct LegacyScanBlockData {
            blue_score: u64,
            daa_score: u64,
            timestamp: u64,
            coinbase_txid: Hash,
            coinbase_outputs: Vec<(Vec<u8>, u64)>,
            accepted: Vec<ShieldedScanTx>,
        }

        let legacy = LegacyScanBlockData {
            blue_score: 7,
            daa_score: 9,
            timestamp: 11,
            coinbase_txid: Hash::from_bytes([1u8; 32]),
            coinbase_outputs: vec![(vec![0xAAu8; 43], 5_700_000_000)],
            accepted: vec![ShieldedScanTx { txid: Hash::from_bytes([2u8; 32]), action_bytes: vec![0xBB; 148] }],
        };
        let bytes = bincode::serialize(&legacy).unwrap();

        // Reading old bytes with the CURRENT struct must not silently succeed with wrong data.
        let decoded: Result<ShieldedScanBlockData, _> = bincode::deserialize(&bytes);
        match decoded {
            Err(_) => { /* expected: positional read runs off the end */ }
            Ok(v) => panic!(
                "serde(default) appeared to work for bincode — it does not. Decoded blue_score={}, \
                 commitments={}, accepted={}. If this ever passes, the field layout changed and the \
                 archive-compatibility story must be re-derived, not assumed.",
                v.blue_score,
                v.coinbase_commitments.len(),
                v.accepted.len()
            ),
        }
    }

    /// Also lost to the stacked-attribute bug above: a plain store round-trip.
    #[test]
    fn scan_block_store_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbShieldedScanBlockStore::new(db.clone(), CachePolicy::Count(16));
        let block = Hash::from_bytes([4u8; 32]);
        assert!(store.get(block).unwrap().is_none());
        let data = ShieldedScanBlockData {
            blue_score: 42,
            daa_score: 40,
            timestamp: 1234,
            coinbase_txid: Hash::from_bytes([7u8; 32]),
            coinbase_outputs: vec![(vec![9u8; 43], 60_00000000)],
            coinbase_commitments: vec![[8u8; 32]],
            accepted: vec![ShieldedScanTx { txid: Hash::from_bytes([5u8; 32]), action_bytes: vec![1u8; 148 * 2] }],
        };
        let mut b = WriteBatch::default();
        store.set_batch(&mut b, block, data.clone()).unwrap();
        db.write(b).unwrap();
        let got = store.get(block).unwrap().expect("present");
        assert_eq!(got.blue_score, 42);
        assert_eq!(got.coinbase_outputs, data.coinbase_outputs);
        assert_eq!(got.coinbase_commitments, data.coinbase_commitments);
        assert_eq!(got.accepted.len(), 1);
        assert_eq!(got.accepted[0].action_bytes.len(), 296);
    }

    #[test]
    fn anchor_block_index_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAnchorBlockStore::new(db.clone(), CachePolicy::Count(16));
        let anchor = [9u8; 32];
        let block = Hash::from_bytes([3u8; 32]);
        assert_eq!(store.get(&anchor).unwrap(), None);
        let mut b = WriteBatch::default();
        store.set_batch(&mut b, anchor, block).unwrap();
        db.write(b).unwrap();
        assert_eq!(store.get(&anchor).unwrap(), Some(block));
        assert_eq!(store.get(&[0u8; 32]).unwrap(), None);
    }

    #[test]
    fn nullifier_set_insert_delete_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbNullifierSetStore::new(db.clone(), CachePolicy::Count(16));
        let nf = [7u8; 32];
        assert!(!store.contains(&nf).unwrap());
        let mut b = WriteBatch::default();
        store.insert_batch(&mut b, nf).unwrap();
        db.write(b).unwrap();
        assert!(store.contains(&nf).unwrap());
        // Revert: deletion removes it again.
        let mut b2 = WriteBatch::default();
        store.delete_batch(&mut b2, nf).unwrap();
        db.write(b2).unwrap();
        assert!(!store.contains(&nf).unwrap());
    }

    #[test]
    fn frontier_store_is_block_keyed() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbShieldedTreeStore::new(db.clone(), CachePolicy::Count(16));
        let block_a = Hash::from_bytes([1; 32]);
        let block_b = Hash::from_bytes([2; 32]);
        // Absent block -> empty frontier.
        assert_eq!(store.get(block_a).unwrap(), FrontierState::default());
        let fs = FrontierState { size: 3, leaf: Some([9; 32]), ommers: vec![[8; 32]] };
        let mut b = WriteBatch::default();
        store.set_batch(&mut b, block_a, fs.clone()).unwrap();
        db.write(b).unwrap();
        assert_eq!(store.get(block_a).unwrap(), fs);
        // A different block is independent.
        assert_eq!(store.get(block_b).unwrap(), FrontierState::default());
    }
}
