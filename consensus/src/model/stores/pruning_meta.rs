use std::sync::Arc;

use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::StoreResult;
use kaspa_database::prelude::StoreResultExt;
use kaspa_database::prelude::{BatchDbWriter, CachedDbItem};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use rocksdb::WriteBatch;

use super::utxo_set::DbUtxoSetStore;

/// Used in order to group stores related to the pruning point utxoset under a single lock
pub struct PruningMetaStores {
    pub utxo_set: DbUtxoSetStore,
    utxoset_position_access: CachedDbItem<Hash>,
    utxoset_stable_flag_access: CachedDbItem<bool>,
    smt_stable_flag_access: CachedDbItem<bool>,
    shielded_stable_flag_access: CachedDbItem<bool>,
    body_missing_anticone_blocks: CachedDbItem<Vec<Hash>>,
    shielded_history_backfilled_access: CachedDbItem<bool>,
    shielded_history_verified_base_access: CachedDbItem<Hash>,
    shielded_history_own_base_access: CachedDbItem<Hash>,
}

impl PruningMetaStores {
    pub fn new(db: Arc<DB>, utxoset_cache_policy: CachePolicy) -> Self {
        Self {
            utxo_set: DbUtxoSetStore::new(db.clone(), utxoset_cache_policy, DatabaseStorePrefixes::PruningUtxoset.into()),
            utxoset_position_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::PruningUtxosetPosition.into()),
            utxoset_stable_flag_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::PruningUtxosetSyncFlag.into()),
            smt_stable_flag_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::SmtSyncFlag.into()),
            shielded_stable_flag_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::ShieldedSyncFlag.into()),
            body_missing_anticone_blocks: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::BodyMissingAnticone.into()),
            shielded_history_backfilled_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::ShieldedHistoryBackfilled.into()),
            shielded_history_verified_base_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::ShieldedHistoryVerifiedBase.into()),
            shielded_history_own_base_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::ShieldedHistoryOwnBase.into()),
        }
    }

    /// Record that chain-index entries below this node's own validated range were written
    /// from a peer's shielded-history backfill. Sticky: once any part of the index is
    /// peer-supplied, "the index reaches genesis" stops being evidence of anything until a
    /// replay has verified it (see [`Self::shielded_history_verified_base`]).
    pub fn set_shielded_history_backfilled(&mut self, batch: &mut WriteBatch) -> StoreResult<()> {
        self.shielded_history_backfilled_access.write(BatchDbWriter::new(batch), &true)
    }

    /// Default to false if missing: a node that never backfilled built its whole index itself.
    pub fn shielded_history_backfilled(&self) -> bool {
        self.shielded_history_backfilled_access.read().optional().unwrap().unwrap_or(false)
    }

    /// The base block a history replay reproduced the PoW-anchored frontier of. Only the
    /// `Verified` verdict writes this; a `Mismatch` purges the range and writes nothing.
    pub fn set_shielded_history_verified_base(&mut self, batch: &mut WriteBatch, base: Hash) -> StoreResult<()> {
        self.shielded_history_verified_base_access.write(BatchDbWriter::new(batch), &base)
    }

    pub fn shielded_history_verified_base(&self) -> Option<Hash> {
        self.shielded_history_verified_base_access.read().optional().unwrap()
    }

    /// Record the lowest block this node indexed itself, in the batch of the first backfill write
    /// below it.
    pub fn set_shielded_history_own_base(&mut self, batch: &mut WriteBatch, base: Hash) -> StoreResult<()> {
        self.shielded_history_own_base_access.write(BatchDbWriter::new(batch), &base)
    }

    /// The lowest block this node indexed itself, when part of its index is peer-supplied (`None` for
    /// a node that never backfilled). Nodes that backfilled before this was recorded verified against
    /// exactly that block, so the verified base stands in for it.
    pub fn shielded_history_own_base(&self) -> Option<Hash> {
        if !self.shielded_history_backfilled() {
            return None;
        }
        self.shielded_history_own_base_access.read().optional().unwrap().or_else(|| self.shielded_history_verified_base())
    }

    /// Forget a backfill (its records were purged): the index is this node's own again.
    pub fn clear_shielded_history_backfill(&mut self, batch: &mut WriteBatch) -> StoreResult<()> {
        self.shielded_history_backfilled_access.remove(BatchDbWriter::new(&mut *batch))?;
        self.shielded_history_own_base_access.remove(BatchDbWriter::new(&mut *batch))?;
        self.shielded_history_verified_base_access.remove(BatchDbWriter::new(batch))
    }

    /// Represents the exact point of the current pruning point utxoset. Used in order to safely
    /// progress the pruning point utxoset in batches and to allow recovery if the process crashes
    /// during the pruning point utxoset movement
    pub fn utxoset_position(&self) -> StoreResult<Hash> {
        self.utxoset_position_access.read()
    }

    pub fn set_utxoset_position(&mut self, batch: &mut WriteBatch, pruning_utxoset_position: Hash) -> StoreResult<()> {
        self.utxoset_position_access.write(BatchDbWriter::new(batch), &pruning_utxoset_position)
    }

    /// Flip the sync flag in the same batch as your other writes
    pub fn set_pruning_utxoset_stable_flag(&mut self, batch: &mut WriteBatch, stable: bool) -> StoreResult<()> {
        self.utxoset_stable_flag_access.write(BatchDbWriter::new(batch), &stable)
    }

    /// Read the flag; default to true if missing - this is important because a node upgrading should have this value true
    /// as all non staging consensuses had a stable utxoset previously
    pub fn pruning_utxoset_stable_flag(&self) -> bool {
        self.utxoset_stable_flag_access.read().optional().unwrap().unwrap_or(true)
    }

    /// Represents blocks in the anticone of the current pruning point which may lack a block body
    /// These blocks need to be kept track of as they require trusted validation,
    /// so that downloading of further blocks on top of them could resume
    pub fn set_body_missing_anticone(&mut self, batch: &mut WriteBatch, body_missing_anticone: Vec<Hash>) -> StoreResult<()> {
        self.body_missing_anticone_blocks.write(BatchDbWriter::new(batch), &body_missing_anticone)
    }

    /// Default to empty if missing - this is important because a node upgrading should have this value empty
    /// since all non staging consensuses had no missing body anticone previously
    pub fn get_body_missing_anticone(&self) -> Vec<Hash> {
        self.body_missing_anticone_blocks.read().optional().unwrap().unwrap_or(vec![])
    }

    // check if there are any body missing blocks remaining in the anticone of the current pruning point
    pub fn is_anticone_fully_synced(&self) -> bool {
        self.get_body_missing_anticone().is_empty()
    }

    pub fn set_pruning_smt_stable_flag(&mut self, batch: &mut WriteBatch, stable: bool) -> StoreResult<()> {
        self.smt_stable_flag_access.write(BatchDbWriter::new(batch), &stable)
    }

    /// Default to true if missing — upgrading nodes had no SMT state to sync.
    pub fn pruning_smt_stable_flag(&self) -> bool {
        self.smt_stable_flag_access.read().optional().unwrap().unwrap_or(true)
    }

    pub fn set_pruning_shielded_stable_flag(&mut self, batch: &mut WriteBatch, stable: bool) -> StoreResult<()> {
        self.shielded_stable_flag_access.write(BatchDbWriter::new(batch), &stable)
    }

    /// Default to true if missing — upgrading nodes had no shielded state to sync.
    pub fn pruning_shielded_stable_flag(&self) -> bool {
        self.shielded_stable_flag_access.read().optional().unwrap().unwrap_or(true)
    }

    pub fn is_in_transitional_ibd_state(&self) -> bool {
        !self.is_anticone_fully_synced()
            || !self.pruning_utxoset_stable_flag()
            || !self.pruning_smt_stable_flag()
            || !self.pruning_shielded_stable_flag()
    }
}
