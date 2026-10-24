//! The Dandelion++ stempool (spec 06 §3.3).
//!
//! Transactions in their stem phase: fully validated (proof included), held here and NOT in the
//! mempool. Nothing that answers other parties reads this pool: block templates, `getdata`
//! (`RequestTransactions`), RPC mempool queries and mempool metrics only see the mempool
//! (spec 06 D-8). A stem transaction leaves this pool when it is fluffed into the mempool, seen
//! in a block, evicted by a conflicting mempool transaction, or dropped at a limit.

use crate::mempool::model::utxo_set::shielded_nullifiers;
use kaspa_consensus_core::tx::{MutableTransaction, Transaction, TransactionId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// At most this many stem transactions (spec 06 §3.3.1).
pub const MAX_STEM_ENTRIES: usize = 1_000;
/// At most this many estimated bytes of stem transactions.
pub const MAX_STEM_BYTES: usize = 32 * 1024 * 1024;

pub struct StemEntry {
    pub mtx: MutableTransaction,
    pub own: bool,
    pub inserted_at: Instant,
    nullifiers: Vec<[u8; 32]>,
    bytes: usize,
}

/// Outcome of offering a transaction to the stem phase.
#[derive(Debug)]
pub enum StemAdmission {
    /// Validated and now in the stempool.
    Inserted,
    /// Already in the stempool, the mempool, or accepted: a loop (spec 06 D-3).
    Known { in_stempool: bool },
    /// Proof-valid, but spends a nullifier a resident mempool transaction already spends
    /// (spec 06 D-9 / 16 F12). Not inserted. Carries what a `ShieldedConflict` notice needs.
    MempoolConflict { nullifier: [u8; 32], resident: TransactionId, transaction: Arc<Transaction> },
    /// Proof-valid, but spends a nullifier another stem transaction spends; dropped (first wins).
    StemConflict,
    /// Valid, but the stempool is at a limit; the caller fluffs it instead of dropping it.
    Full(Box<MutableTransaction>),
}

#[derive(Default)]
pub struct Stempool {
    entries: HashMap<TransactionId, StemEntry>,
    nullifier_owner: HashMap<[u8; 32], TransactionId>,
    bytes: usize,
}

impl Stempool {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, id: &TransactionId) -> bool {
        self.entries.contains_key(id)
    }

    pub fn get(&self, id: &TransactionId) -> Option<&StemEntry> {
        self.entries.get(id)
    }

    pub fn is_full_for(&self, mtx: &MutableTransaction) -> bool {
        self.entries.len() >= MAX_STEM_ENTRIES || self.bytes + mtx.mempool_estimated_bytes() > MAX_STEM_BYTES
    }

    /// The stem entry already spending one of `tx`'s nullifiers, if any (other than `tx` itself).
    pub fn nullifier_conflict(&self, tx: &Transaction) -> Option<TransactionId> {
        let id = tx.id();
        shielded_nullifiers(tx).iter().find_map(|nf| self.nullifier_owner.get(nf).copied().filter(|owner| *owner != id))
    }

    pub fn insert(&mut self, mtx: MutableTransaction, own: bool) {
        let id = mtx.id();
        if self.entries.contains_key(&id) {
            return;
        }
        let nullifiers = shielded_nullifiers(&mtx.tx);
        for nf in &nullifiers {
            self.nullifier_owner.insert(*nf, id);
        }
        let bytes = mtx.mempool_estimated_bytes();
        self.bytes += bytes;
        self.entries.insert(id, StemEntry { mtx, own, inserted_at: Instant::now(), nullifiers, bytes });
    }

    pub fn remove(&mut self, id: &TransactionId) -> Option<StemEntry> {
        let entry = self.entries.remove(id)?;
        for nf in &entry.nullifiers {
            if self.nullifier_owner.get(nf) == Some(id) {
                self.nullifier_owner.remove(nf);
            }
        }
        self.bytes -= entry.bytes;
        Some(entry)
    }

    /// Removes every stem entry that `tx` makes obsolete: `tx` itself, and any other entry sharing
    /// one of its nullifiers. Used for transactions seen in a block (spec 06 D-6) and for a
    /// mempool transaction arriving with a nullifier a stem entry owns (spec 06 D-9).
    pub fn remove_superseded_by(&mut self, tx: &Transaction) -> Vec<TransactionId> {
        let mut removed = Vec::new();
        let id = tx.id();
        if self.remove(&id).is_some() {
            removed.push(id);
        }
        for nf in shielded_nullifiers(tx) {
            if let Some(owner) = self.nullifier_owner.get(&nf).copied()
                && self.remove(&owner).is_some()
            {
                removed.push(owner);
            }
        }
        removed
    }

    pub fn ids(&self) -> Vec<TransactionId> {
        self.entries.keys().copied().collect()
    }
}
