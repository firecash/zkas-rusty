//! Groups transaction validations that depend on the containing header and/or
//! its past headers (but do not depend on UTXO state or other transactions in
//! the containing block)

use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};
use crate::constants::LOCK_TIME_THRESHOLD;
use kaspa_consensus_core::{
    constants::{TX_VERSION, TX_VERSION_TOCCATA},
    tx::{TX_VERSION_SHIELDED, Transaction},
};

pub(crate) enum LockTimeType {
    Finalized,
    DaaScore,
    Time,
}

pub(crate) enum LockTimeArg {
    Finalized,
    DaaScore(u64),
    MedianTime(u64),
}

impl TransactionValidator {
    pub(crate) fn validate_tx_in_header_context_with_args(
        &self,
        tx: &Transaction,
        ctx_daa_score: u64,
        ctx_block_time: u64,
    ) -> TxResult<()> {
        self.validate_tx_in_header_context(
            tx,
            match Self::get_lock_time_type(tx) {
                LockTimeType::Finalized => LockTimeArg::Finalized,
                LockTimeType::DaaScore => LockTimeArg::DaaScore(ctx_daa_score),
                LockTimeType::Time => LockTimeArg::MedianTime(ctx_block_time),
            },
            ctx_daa_score,
        )
    }

    pub(crate) fn validate_tx_in_header_context(
        &self,
        tx: &Transaction,
        lock_time_arg: LockTimeArg,
        block_daa_score: u64,
    ) -> TxResult<()> {
        self.check_shielded_lock_time(tx, block_daa_score)?;
        self.check_tx_is_finalized(tx, lock_time_arg)?;
        self.check_transaction_version(tx, block_daa_score)?;
        self.check_shielded_format_in_header_context(tx, block_daa_score)?;
        self.check_transaction_signature_scripts_in_header_context(tx, block_daa_score)
    }

    /// The shielded payload must decode in the format of the carrying block's DAA score: before the
    /// security fork exactly as every node always parsed it (flag bit 3 carries no field), from it
    /// with the anchor-block field. See `ShieldedBundle::from_bytes_at`.
    ///
    /// NU-A (spec 08 R2.2): from the activation the decoded bundle's value balance must also reach
    /// the burned floor `600,000 * max(2, n)`. Like the format, the floor is a pure function of the
    /// transaction bytes and the carrying block's DAA score, so a block carrying an under-paying
    /// transaction is invalid (never a drop), and the mempool, which runs this at the virtual's DAA
    /// score, refuses it before any proof is verified.
    fn check_shielded_format_in_header_context(&self, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
        if !tx.is_shielded() {
            return Ok(());
        }
        let bundle =
            kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&tx.payload, self.security_fork_activation.is_active(block_daa_score))
                .map_err(|_| TxRuleError::InvalidShieldedTransaction("malformed Orchard bundle in payload"))?;
        if self.nu_a_activation.is_active(block_daa_score) {
            let n = bundle.actions.len();
            let floor = kaspa_consensus_core::config::params::shielded_fee_floor(n);
            // A negative value balance is refused in UTXO context as well; here it simply cannot
            // reach the floor.
            if bundle.value_balance < 0 || (bundle.value_balance as u64) < floor {
                return Err(TxRuleError::ShieldedFeeBelowFloor(bundle.value_balance.max(0) as u64, floor, n));
            }
        }
        Ok(())
    }

    /// SF-L (spec 01 §3.1 L-R1). From the activation, judged at the DAA score of the block that
    /// carries the transaction (the mempool passes the virtual's), a shielded transaction's
    /// `lock_time` means what it says:
    /// - (i) a time-type value (`>= LOCK_TIME_THRESHOLD`) is invalid: the past median time is a
    ///   second, miner-influenced clock computed lazily per block, and contracts convert wall time
    ///   to DAA at about 1 DAA/s;
    /// - (ii) a non-zero DAA-type value must be strictly below the carrying block's DAA score;
    /// - (iii) the input-sequence escape of [`Self::check_tx_is_finalized`] does not apply: a
    ///   shielded transaction has no inputs, so that loop is vacuous, which is exactly why every
    ///   value passed before the fork.
    ///
    /// Soundness at the carrying block: a block's DAA score is its selected parent's plus its
    /// DAA-window mergeset count, so a miner cannot give a block a score its past does not contain,
    /// and the chain block that later accepts the transaction has a strictly larger score. The rule
    /// only narrows the valid set, so it is a soft fork.
    fn check_shielded_lock_time(&self, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
        if !tx.is_shielded() || tx.lock_time == 0 || !self.shielded_locktime_activation.is_active(block_daa_score) {
            return Ok(());
        }
        if tx.lock_time >= LOCK_TIME_THRESHOLD {
            return Err(TxRuleError::ShieldedTimeLock(tx.lock_time));
        }
        if tx.lock_time >= block_daa_score {
            return Err(TxRuleError::ShieldedNotFinalized(tx.lock_time, block_daa_score));
        }
        Ok(())
    }

    pub(crate) fn get_lock_time_type(tx: &Transaction) -> LockTimeType {
        match tx.lock_time {
            // Lock time of zero means the transaction is finalized.
            0 => LockTimeType::Finalized,

            // The lock time field of a transaction is either a block DAA score at
            // which the transaction is finalized or a timestamp depending on if the
            // value is before the LOCK_TIME_THRESHOLD. When it is under the
            // threshold it is a DAA score
            t if t < LOCK_TIME_THRESHOLD => LockTimeType::DaaScore,

            // ..and when equal or above the threshold it represents time
            _t => LockTimeType::Time,
        }
    }

    fn check_tx_is_finalized(&self, tx: &Transaction, lock_time_arg: LockTimeArg) -> TxResult<()> {
        let block_time_or_daa_score = match lock_time_arg {
            LockTimeArg::Finalized => return Ok(()),
            LockTimeArg::DaaScore(ctx_daa_score) => ctx_daa_score,
            LockTimeArg::MedianTime(ctx_block_time) => ctx_block_time,
        };

        if tx.lock_time < block_time_or_daa_score {
            return Ok(());
        }

        // At this point, the transaction's lock time hasn't occurred yet, but
        // the transaction might still be finalized if the sequence number
        // for all transaction inputs is maxed out.
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.sequence != u64::MAX {
                return Err(TxRuleError::NotFinalized(i));
            }
        }

        Ok(())
    }

    // TODO(post-toccata): Remove the contextual check and only leave the isolated one after the HF
    fn check_transaction_version(&self, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
        // Shielded transactions use a dedicated version (PLAN §2.1, decision D7).
        if tx.version == TX_VERSION_SHIELDED {
            return Ok(());
        }
        if self.toccata_activation.is_active(block_daa_score) {
            if tx.version > TX_VERSION_TOCCATA {
                return Err(TxRuleError::UnknownTxVersion(tx.version));
            }
            return Ok(());
        }

        if tx.version != TX_VERSION {
            return Err(TxRuleError::UnknownTxVersion(tx.version));
        }

        Ok(())
    }

    // TODO(post-toccata): Remove this and restore the context-free check_transaction_signature_scripts.
    fn check_transaction_signature_scripts_in_header_context(&self, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
        let max_signature_script_len = self.max_signature_script_len.get(block_daa_score);
        if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > max_signature_script_len) {
            return Err(TxRuleError::TooBigSignatureScript(i, max_signature_script_len));
        }

        Ok(())
    }
}
