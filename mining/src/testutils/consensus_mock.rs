use super::coinbase_mock::CoinbaseManagerMock;
use kaspa_consensus_core::{
    api::{
        ConsensusApi,
        args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    },
    block::{BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector, VirtualStateApproxId},
    coinbase::MinerData,
    constants::BLOCK_VERSION,
    errors::{
        block::RuleError,
        coinbase::CoinbaseResult,
        tx::{TxResult, TxRuleError},
    },
    header::{CompressedParents, Header},
    mass::{ContextualMasses, NonContextualMasses, transaction_estimated_serialized_size},
    merkle::calc_hash_merkle_root,
    tx::{MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, UtxoEntry},
    utxo::utxo_collection::UtxoCollection,
};
use kaspa_core::time::unix_now;
use kaspa_hashes::{Hash, ZERO_HASH};
use kaspa_shielded_core::bundle::ShieldedBundle;

use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

pub(crate) struct ConsensusMock {
    transactions: RwLock<HashMap<TransactionId, Arc<Transaction>>>,
    statuses: RwLock<HashMap<TransactionId, TxResult<()>>>,
    utxos: RwLock<UtxoCollection>,
    dev_fee_spk: Option<ScriptPublicKey>,
    red_reward: bool,
}

impl ConsensusMock {
    pub(crate) fn new() -> Self {
        Self {
            transactions: RwLock::new(HashMap::default()),
            statuses: RwLock::new(HashMap::default()),
            utxos: RwLock::new(HashMap::default()),
            dev_fee_spk: None,
            red_reward: false,
        }
    }

    /// Configure the dev-fee coinbase script this mock reports (see
    /// `ConsensusApi::dev_fee_spk`), for `modify_block_template` tests.
    pub(crate) fn set_dev_fee_spk(&mut self, dev_fee_spk: ScriptPublicKey) {
        self.dev_fee_spk = Some(dev_fee_spk);
    }

    /// Make every built coinbase carry a red reward (a trailing output paying the template's miner),
    /// as a real coinbase does when the merged set has red blocks and no dev note is due.
    pub(crate) fn set_red_reward(&mut self) {
        self.red_reward = true;
    }

    pub(crate) fn set_status(&self, transaction_id: TransactionId, status: TxResult<()>) {
        self.statuses.write().insert(transaction_id, status);
    }

    pub(crate) fn add_transaction(&self, transaction: Transaction, block_daa_score: u64) {
        let transaction = MutableTransaction::from_tx(transaction);
        let mut transactions = self.transactions.write();
        let mut utxos = self.utxos.write();

        // Remove the spent UTXOs
        transaction.tx.inputs.iter().for_each(|x| {
            utxos.remove(&x.previous_outpoint);
        });
        // Create the new UTXOs
        transaction.tx.outputs.iter().enumerate().for_each(|(i, x)| {
            utxos.insert(
                TransactionOutpoint::new(transaction.id(), i as u32),
                UtxoEntry::new(
                    x.value,
                    x.script_public_key.clone(),
                    block_daa_score,
                    transaction.tx.is_coinbase(),
                    x.covenant.map(|y| y.covenant_id),
                ),
            );
        });
        // Register the transaction
        transactions.insert(transaction.id(), transaction.tx);
    }

    pub(crate) fn can_finance_transaction(&self, transaction: &MutableTransaction) -> bool {
        let utxos = self.utxos.read();
        for outpoint in transaction.missing_outpoints() {
            if !utxos.contains_key(&outpoint) {
                return false;
            }
        }
        true
    }
}

impl ConsensusApi for ConsensusMock {
    fn dev_fee_spk(&self) -> Option<ScriptPublicKey> {
        self.dev_fee_spk.clone()
    }

    fn build_block_template(
        &self,
        miner_data: MinerData,
        mut tx_selector: Box<dyn TemplateTransactionSelector>,
        _build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        let mut txs = tx_selector.select_transactions();
        let coinbase_manager = CoinbaseManagerMock::new();
        let mut coinbase = coinbase_manager.expected_coinbase_transaction(miner_data.clone());
        if self.red_reward {
            coinbase.tx.outputs.push(kaspa_consensus_core::tx::TransactionOutput::new(7 * kaspa_consensus_core::constants::SOMPI_PER_KASPA, miner_data.script_public_key.clone()));
            coinbase.has_red_reward = true;
        }
        txs.insert(0, coinbase.tx);
        let now = unix_now();
        let hash_merkle_root = self.calc_transaction_hash_merkle_root(&txs);
        let header = Header::new_finalized(
            BLOCK_VERSION,
            CompressedParents::default(),
            hash_merkle_root,
            ZERO_HASH,
            ZERO_HASH,
            now,
            123456789u32,
            0,
            0,
            0.into(),
            0,
            ZERO_HASH,
        );
        let mutable_block = MutableBlock::new(header, txs);

        Ok(BlockTemplate::new(mutable_block, miner_data, coinbase.has_red_reward, now, 0, ZERO_HASH, vec![]))
    }

    fn validate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction, _: &TransactionValidationArgs) -> TxResult<()> {
        // If a predefined status was registered to simulate an error, return it right away
        if let Some(status) = self.statuses.read().get(&mutable_tx.id())
            && status.is_err()
        {
            return status.clone();
        }
        let utxos = self.utxos.read();
        let mut has_missing_outpoints = false;
        for i in 0..mutable_tx.tx.inputs.len() {
            // Keep existing entries
            if mutable_tx.entries[i].is_some() {
                continue;
            }
            // Try add missing entries
            if let Some(entry) = utxos.get(&mutable_tx.tx.inputs[i].previous_outpoint) {
                mutable_tx.entries[i] = Some(entry.clone());
            } else {
                has_missing_outpoints = true;
            }
        }
        if has_missing_outpoints {
            return Err(TxRuleError::MissingTxOutpoints);
        }
        mutable_tx.tx.set_storage_mass(self.calculate_transaction_contextual_masses(mutable_tx).unwrap().storage_mass);

        // A shielded transaction has no transparent value: its fee is the bundle's
        // public value balance (value leaving the shielded pool), mirroring the
        // real consensus rule (tx_validation_in_utxo_context). This keeps the mock
        // faithful for the mempool/template integration path.
        if mutable_tx.tx.is_shielded() {
            if mutable_tx.calculated_fee.is_none() {
                let bundle = ShieldedBundle::from_bytes(&mutable_tx.tx.payload).map_err(|_| TxRuleError::MissingTxOutpoints)?;
                let fee = u64::try_from(bundle.value_balance).map_err(|_| TxRuleError::MissingTxOutpoints)?;
                mutable_tx.calculated_fee = Some(fee);
            }
            return Ok(());
        }

        // At this point we know all UTXO entries are populated, so we can safely calculate the fee
        let total_in: u64 = mutable_tx.entries.iter().map(|x| x.as_ref().unwrap().amount).sum();
        let total_out: u64 = mutable_tx.tx.outputs.iter().map(|x| x.value).sum();

        if mutable_tx.calculated_fee.is_none() {
            let calculated_fee = total_in - total_out;
            mutable_tx.calculated_fee = Some(calculated_fee);
        }
        Ok(())
    }

    fn validate_mempool_transactions_in_parallel(
        &self,
        transactions: &mut [MutableTransaction],
        _: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        transactions.iter_mut().map(|x| self.validate_mempool_transaction(x, &Default::default())).collect()
    }

    fn populate_mempool_transactions_in_parallel(&self, transactions: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        transactions.iter_mut().map(|x| self.validate_mempool_transaction(x, &Default::default())).collect()
    }

    fn calculate_transaction_non_contextual_masses(&self, transaction: &Transaction) -> TxResult<NonContextualMasses> {
        let mass = if transaction.is_coinbase() { 0 } else { transaction_estimated_serialized_size(transaction) };
        Ok(NonContextualMasses::new(mass, mass))
    }

    fn calculate_transaction_contextual_masses(&self, _transaction: &MutableTransaction) -> Option<ContextualMasses> {
        Some(ContextualMasses::new(0))
    }

    fn get_virtual_daa_score(&self) -> u64 {
        0
    }

    fn get_virtual_state_approx_id(&self) -> VirtualStateApproxId {
        VirtualStateApproxId::new(self.get_virtual_daa_score(), 0.into(), ZERO_HASH)
    }

    fn modify_coinbase_payload(&self, payload: Vec<u8>, miner_data: &MinerData) -> CoinbaseResult<Vec<u8>> {
        let coinbase_manager = CoinbaseManagerMock::new();
        Ok(coinbase_manager.modify_coinbase_payload(payload, miner_data))
    }

    fn calc_transaction_hash_merkle_root(&self, txs: &[Transaction]) -> Hash {
        calc_hash_merkle_root(txs.iter())
    }
}
