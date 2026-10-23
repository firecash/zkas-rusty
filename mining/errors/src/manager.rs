use crate::{block_template::BuilderError, mempool::RuleError};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum MiningManagerError {
    /// A consensus rule error
    #[error(transparent)]
    BlockTemplateBuilderError(#[from] BuilderError),

    /// A mempool rule error
    #[error(transparent)]
    MempoolError(#[from] RuleError),

    /// N1 (spec 08 R1.3.6): one peer's relayed batch contained a shielded transaction whose bundle
    /// fails verification (`proof_failure`: its proof or signatures; otherwise an encoding rule). The
    /// whole batch was discarded, nothing of it inserted.
    #[error("relayed batch rejected: shielded transaction {txid} fails verification: {reason}")]
    InvalidShieldedBatch { txid: kaspa_consensus_core::tx::TransactionId, reason: String, proof_failure: bool },
}

pub type MiningManagerResult<T> = std::result::Result<T, MiningManagerError>;
