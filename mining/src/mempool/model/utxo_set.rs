use std::collections::{HashMap, HashSet};

use crate::{
    mempool::{
        errors::{RuleError, RuleResult},
        model::{map::OutpointIndex, tx::DoubleSpend},
    },
    model::TransactionIdSet,
};
use kaspa_consensus_core::{
    constants::UNACCEPTED_DAA_SCORE,
    tx::{MutableTransaction, Transaction, TransactionId, TransactionOutpoint, UtxoEntry},
    utxo::utxo_collection::UtxoCollection,
};
use kaspa_shielded_core::bundle::ShieldedBundle;

/// The nullifiers revealed by a shielded transaction (parsed from the Orchard
/// bundle in its payload). A shielded transaction spends notes by nullifier, not
/// by transparent outpoint, so this is the conflict key the mempool must track to
/// avoid admitting two transactions that spend the same note — the shielded
/// analogue of an outpoint double-spend. Returns empty for a non-shielded (or
/// unparsable) transaction. Parsing is wire-format only: no proof verification.
pub(crate) fn shielded_nullifiers(tx: &Transaction) -> Vec<[u8; 32]> {
    if !tx.is_shielded() {
        return Vec::new();
    }
    match ShieldedBundle::from_bytes(&tx.payload) {
        Ok(bundle) => bundle.actions.iter().map(|a| a.nullifier).collect(),
        // A malformed payload cannot be a valid shielded tx; consensus validation
        // will reject it. It reveals no trackable nullifiers here.
        Err(_) => Vec::new(),
    }
}

pub(crate) struct MempoolUtxoSet {
    pool_unspent_outputs: UtxoCollection,
    outpoint_owner_id: OutpointIndex,
    /// Owner transaction of each shielded nullifier currently in the mempool —
    /// the nullifier-keyed mirror of `outpoint_owner_id` (PLAN §2.4: nullifiers
    /// are the shielded conflict keys).
    nullifier_owner_id: HashMap<[u8; 32], TransactionId>,
}

impl MempoolUtxoSet {
    pub(crate) fn new() -> Self {
        Self {
            pool_unspent_outputs: UtxoCollection::default(),
            outpoint_owner_id: OutpointIndex::default(),
            nullifier_owner_id: HashMap::default(),
        }
    }

    pub(crate) fn add_transaction(&mut self, transaction: &MutableTransaction) {
        let transaction_id = transaction.id();
        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);

        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            outpoint.index = i as u32;

            // Delete the output this input spends, in case it was created by mempool.
            // If the outpoint doesn't exist in self.pool_unspent_outputs - this means
            // it was created in the DAG (a.k.a. in consensus).
            self.pool_unspent_outputs.remove(&outpoint);

            self.outpoint_owner_id.insert(input.previous_outpoint, transaction_id);
        }

        for (i, output) in transaction.tx.outputs.iter().enumerate() {
            let outpoint = TransactionOutpoint::new(transaction_id, i as u32);
            let entry = UtxoEntry::new(
                output.value,
                output.script_public_key.clone(),
                UNACCEPTED_DAA_SCORE,
                false,
                output.covenant.map(|x| x.covenant_id),
            );
            self.pool_unspent_outputs.insert(outpoint, entry);
        }

        // A shielded transaction reveals its spent notes as nullifiers (in its
        // payload bundle), not as transparent inputs, so record them separately.
        for nullifier in shielded_nullifiers(&transaction.tx) {
            self.nullifier_owner_id.insert(nullifier, transaction_id);
        }
    }

    pub(crate) fn remove_transaction(&mut self, transaction: &MutableTransaction, parent_ids_in_pool: &TransactionIdSet) {
        let transaction_id = transaction.id();
        // We cannot assume here that the transaction is fully populated.
        // Notably, this is not the case when revalidate_transaction fails and leads the execution path here.
        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            if let Some(ref entry) = transaction.entries[i] {
                // If the transaction creating the output spent by this input is in the mempool - restore it's UTXO
                if parent_ids_in_pool.contains(&input.previous_outpoint.transaction_id) {
                    self.pool_unspent_outputs.insert(input.previous_outpoint, entry.clone());
                }
            }
            self.outpoint_owner_id.remove(&input.previous_outpoint);
        }

        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);
        for i in 0..transaction.tx.outputs.len() {
            outpoint.index = i as u32;
            self.pool_unspent_outputs.remove(&outpoint);
        }

        // Release this transaction's shielded nullifiers so an equivalent spend
        // may re-enter the mempool (mirrors the outpoint owner cleanup above).
        for nullifier in shielded_nullifiers(&transaction.tx) {
            if self.nullifier_owner_id.get(&nullifier) == Some(&transaction_id) {
                self.nullifier_owner_id.remove(&nullifier);
            }
        }
    }

    pub(crate) fn get_outpoint_owner_id(&self, outpoint: &TransactionOutpoint) -> Option<&TransactionId> {
        self.outpoint_owner_id.get(outpoint)
    }

    /// The nullifier-keyed analogue of [`Self::get_outpoint_owner_id`]: the
    /// resident mempool transaction (if any) that spends the note identified by
    /// `nullifier`. Used to evict a losing shielded double-spend when the winning
    /// side confirms on-chain via a block this node never admitted locally (so the
    /// admission-time `check_nullifier_double_spends` never saw the conflict).
    pub(crate) fn get_nullifier_owner_id(&self, nullifier: &[u8; 32]) -> Option<&TransactionId> {
        self.nullifier_owner_id.get(nullifier)
    }

    /// Make sure no other transaction in the mempool is already spending an output which one of this transaction inputs spends
    pub(crate) fn check_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        match self.get_first_double_spend(transaction) {
            Some(double_spend) => Err(double_spend.into()),
            None => Ok(()),
        }
    }

    pub(crate) fn get_first_double_spend(&self, transaction: &MutableTransaction) -> Option<DoubleSpend> {
        let transaction_id = transaction.id();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint)
                && *existing_transaction_id != transaction_id
            {
                return Some(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
            }
        }
        None
    }

    /// The nullifier-keyed analogue of [`Self::check_double_spends`]: reject a
    /// shielded transaction that spends a note already spent by a different
    /// transaction in the mempool. Without this, two conflicting shielded
    /// transactions would both be admitted and a block template could include
    /// both — the state transition then drops the loser, but the coinbase would
    /// have been built expecting its fee, over-minting and failing the turnstile
    /// (an invalid block the miner builds against itself).
    pub(crate) fn check_nullifier_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        let transaction_id = transaction.id();
        for nullifier in shielded_nullifiers(&transaction.tx) {
            if let Some(existing) = self.nullifier_owner_id.get(&nullifier)
                && *existing != transaction_id
            {
                return Err(RuleError::RejectDoubleSpendNullifierInMempool(hex::encode(nullifier), *existing));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn nullifier_owner_count(&self) -> usize {
        self.nullifier_owner_id.len()
    }

    /// Returns the first double spend of every transaction in the mempool double spending on `transaction`
    pub(crate) fn get_double_spend_transaction_ids(&self, transaction: &MutableTransaction) -> Vec<DoubleSpend> {
        let transaction_id = transaction.id();
        let mut double_spends = vec![];
        let mut visited = HashSet::new();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint)
                && *existing_transaction_id != transaction_id
                && visited.insert(*existing_transaction_id)
            {
                double_spends.push(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
            }
        }
        double_spends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{subnets::SUBNETWORK_ID_NATIVE, tx::TX_VERSION_SHIELDED};
    use kaspa_shielded_core::bundle::{ActionWire, ShieldedBundle, sizes};

    /// A shielded transaction spending the notes identified by `nullifiers`.
    /// Only the payload's nullifiers matter here (mempool conflict keys); the
    /// rest of the bundle is zero-filled — no proof is needed to exercise the
    /// double-spend bookkeeping, which parses wire bytes only.
    fn shielded_tx(nullifiers: &[[u8; 32]]) -> MutableTransaction {
        let actions = nullifiers
            .iter()
            .map(|&nullifier| ActionWire {
                nullifier,
                rk: [0u8; sizes::FIELD],
                cmx: [0u8; sizes::FIELD],
                cv_net: [0u8; sizes::FIELD],
                ephemeral_key: [0u8; sizes::FIELD],
                enc_ciphertext: [0u8; sizes::ENC_CIPHERTEXT],
                out_ciphertext: [0u8; sizes::OUT_CIPHERTEXT],
                spend_auth_sig: [0u8; sizes::SIG],
            })
            .collect();
        let bundle = ShieldedBundle {
            actions,
            flags: 0b11,
            value_balance: 0,
            anchor: [0u8; sizes::FIELD],
            proof: vec![],
            binding_sig: [0u8; sizes::SIG],
            burn: None,
            anchor_block: None,
        };
        let tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, bundle.to_bytes());
        MutableTransaction::from_tx(tx)
    }

    fn nf(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = seed;
        b
    }

    /// A second shielded transaction spending a note already spent by one in the
    /// mempool is rejected — the shielded analogue of an outpoint double-spend.
    /// This is the mining-liveness bug the nullifier tracking closes: without it
    /// both would be admitted and a block template could carry a shielded
    /// double-spend, over-minting the coinbase and failing the turnstile.
    #[test]
    fn rejects_shielded_nullifier_double_spend() {
        let mut set = MempoolUtxoSet::new();

        let tx_a = shielded_tx(&[nf(1), nf(2)]);
        // Nothing conflicts with an empty pool.
        assert!(set.check_nullifier_double_spends(&tx_a).is_ok());
        set.add_transaction(&tx_a);
        assert_eq!(set.nullifier_owner_count(), 2);

        // A different tx reusing nf(1) is a shielded double-spend -> rejected.
        let tx_b = shielded_tx(&[nf(1)]);
        assert!(matches!(
            set.check_nullifier_double_spends(&tx_b),
            Err(RuleError::RejectDoubleSpendNullifierInMempool(_, owner)) if owner == tx_a.id()
        ));

        // A tx spending only fresh notes is fine.
        let tx_c = shielded_tx(&[nf(3), nf(4)]);
        assert!(set.check_nullifier_double_spends(&tx_c).is_ok());

        // Re-checking the very same tx already in the pool is not a self-conflict.
        assert!(set.check_nullifier_double_spends(&tx_a).is_ok());

        // Once tx_a leaves the pool, its notes are free to be spent again.
        set.remove_transaction(&tx_a, &TransactionIdSet::default());
        assert_eq!(set.nullifier_owner_count(), 0);
        assert!(set.check_nullifier_double_spends(&tx_b).is_ok());
    }

    /// The nullifier-keyed owner lookup that powers on-chain double-spend
    /// reconciliation (F-02): a resident shielded tx is discoverable by any of its
    /// nullifiers, and the mapping is dropped once the tx leaves the pool.
    #[test]
    fn nullifier_owner_lookup_tracks_residency() {
        let mut set = MempoolUtxoSet::new();
        let tx_a = shielded_tx(&[nf(1), nf(2)]);

        // Nothing owns a note before the tx is admitted.
        assert_eq!(set.get_nullifier_owner_id(&nf(1)), None);

        set.add_transaction(&tx_a);
        // Every one of the tx's notes resolves back to it.
        assert_eq!(set.get_nullifier_owner_id(&nf(1)), Some(&tx_a.id()));
        assert_eq!(set.get_nullifier_owner_id(&nf(2)), Some(&tx_a.id()));
        // A note the tx never spent has no owner.
        assert_eq!(set.get_nullifier_owner_id(&nf(9)), None);

        // After eviction the owner map no longer references the tx (regression
        // guard: a stale entry would let a permanently-spent note keep an owner).
        set.remove_transaction(&tx_a, &TransactionIdSet::default());
        assert_eq!(set.get_nullifier_owner_id(&nf(1)), None);
        assert_eq!(set.get_nullifier_owner_id(&nf(2)), None);
    }

    /// A transparent transaction has no nullifiers, so it never trips the shielded
    /// double-spend check regardless of mempool contents.
    #[test]
    fn transparent_tx_has_no_nullifier_conflicts() {
        let mut set = MempoolUtxoSet::new();
        set.add_transaction(&shielded_tx(&[nf(1)]));
        // A plain (version-0, no payload) transaction reveals no nullifiers.
        let transparent = MutableTransaction::from_tx(Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]));
        assert_eq!(shielded_nullifiers(&transparent.tx).len(), 0);
        assert!(set.check_nullifier_double_spends(&transparent).is_ok());
    }
}
