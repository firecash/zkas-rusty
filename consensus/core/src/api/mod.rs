use futures_util::future::BoxFuture;
use kaspa_muhash::MuHash;
use std::sync::Arc;

use crate::{
    BlockHashSet, BlueWorkType, ChainPath,
    acceptance_data::{AcceptanceData, MergedBlockContext, MergesetBlockAcceptanceData},
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{Block, BlockTemplate, TemplateBuildMode, TemplateTransactionSelector, VirtualStateApproxId},
    blockstatus::BlockStatus,
    coinbase::MinerData,
    daa_score_timestamp::DaaScoreTimestamp,
    errors::{
        block::{BlockProcessResult, RuleError},
        coinbase::CoinbaseResult,
        consensus::ConsensusResult,
        pruning::PruningImportResult,
        tx::TxResult,
    },
    header::Header,
    mass::{ContextualMasses, NonContextualMasses},
    pruning::{PruningPointProof, PruningPointTrustedData, PruningPointsList, PruningProofMetadata},
    trusted::{ExternalGhostdagData, TrustedBlock},
    tx::{
        MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionIndexType, TransactionOutpoint,
        TransactionQueryResult, TransactionType, UtxoEntry,
    },
};
use kaspa_hashes::Hash;

pub use self::stats::{BlockCount, ConsensusStats};

pub mod args;
pub mod counters;
pub mod stats;

/// The shielded effects of one chain block, as applied by the §2.4 transition —
/// see [`ConsensusApi::get_shielded_chain_block_data`]. Plain types only, so
/// `kaspa-shielded-core` stays off this API boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShieldedChainBlockData {
    /// The chain block.
    pub hash: Hash,
    /// Its blue score — the depth unit of shielded anchor maturity.
    pub blue_score: u64,
    /// Its DAA score (progress reporting).
    pub daa_score: u64,
    /// The block's own coinbase transaction id (coinbase note ρ/ψ derivation
    /// seeds are `txid ‖ output_index`).
    pub coinbase_txid: Hash,
    /// The coinbase outputs in order: `(script_public_key bytes, value)`. A
    /// 43-byte script is a raw Orchard recipient minting a coinbase note.
    pub coinbase_outputs: Vec<(Vec<u8>, u64)>,
    /// Consensus-computed coinbase note commitments, parallel to
    /// `coinbase_outputs`. Empty when supplied by an older peer/archive; callers
    /// must then derive them from the public output description.
    #[serde(default)]
    pub coinbase_commitments: Vec<[u8; 32]>,
    /// Accepted shielded actions in consensus applied order, one entry per accepted
    /// tx (parallel to `accepted_txids`): each entry is that tx's actions in **compact**
    /// form — concatenated 148-byte `CompactActionRecord`s (nullifier ‖ cmx ‖ epk ‖
    /// enc[52]). Served from the persisted block-time scan archive (not re-derived), so
    /// it is the exact applied set and survives body pruning. A wallet chunks each entry
    /// by 148, trial-decrypts with `scan_compact`, and appends every `cmx` to its tree.
    pub accepted_actions: Vec<Vec<u8>>,
    /// Transaction id of each accepted tx, parallel to `accepted_actions` —
    /// lets a wallet date/link its history rows to real transactions.
    pub accepted_txids: Vec<Hash>,
    /// The chain block's header timestamp (ms since epoch) — the display time of
    /// everything this block applied.
    pub timestamp: u64,
}

/// The outcome of checking backfilled shielded history against the chain.
///
/// History arrives from a peer, and the scan archive it lands in is never read by validation —
/// so bad data cannot fork this node. What it *can* do is make wallets report a wrong balance
/// and a wrong history, silently and with no way for the user to tell. That is the failure this
/// verdict exists to prevent, which is why an unverified range is discarded rather than kept
/// with a warning: a wallet cannot act on a log line.
///
/// The check is cryptographic, not reputational. Appending to the note-commitment tree is
/// order-dependent and pure, so replaying every `cmx` from genesis reproduces this node's
/// frontier at `base` only if the peer supplied exactly the right leaves in exactly the right
/// order. That frontier is PoW-anchored (the pruning point's selected child commits the
/// shielded state root in its coinbase, bound by `hash_merkle_root`), and this node learned it
/// from the chain — never from the peer being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShieldedHistoryVerdict {
    /// The replayed range reproduced the anchored frontier exactly. History is trustworthy.
    Verified {
        /// Chain blocks replayed, genesis through `base`.
        blocks: u64,
        /// Note commitments appended during the replay.
        leaves: u64,
    },
    /// The replay did not reproduce the anchored frontier: records were omitted, reordered,
    /// fabricated or truncated.
    ///
    /// Deliberately says nothing about deletion. Verifying and discarding are separate
    /// operations because the right response depends on who asked: the p2p backfill purges the
    /// range it just accepted, while an operator running a check on their own archive wants an
    /// answer, not for a diagnostic to delete their history.
    Mismatch {
        /// Why the range failed, for the operator log.
        reason: String,
    },
    /// Verification could not run — a gap in the local index, a missing record, or no
    /// anchored frontier at `base`. NOT a pass: history is left in place but must be
    /// treated as unverified, because the check never happened.
    Unverifiable {
        /// What prevented the check.
        reason: String,
    },
}

pub type BlockValidationFuture = BoxFuture<'static, BlockProcessResult<BlockStatus>>;

/// A struct returned by consensus for block validation processing calls
pub struct BlockValidationFutures {
    /// A future triggered when block processing is completed (header and body processing)
    pub block_task: BlockValidationFuture,

    /// A future triggered when DAG state which included this block has been processed by the virtual processor
    /// (exceptions are header-only blocks and trusted blocks which have the future completed before virtual
    /// processing along with the `block_task`)
    pub virtual_state_task: BlockValidationFuture,
}

/// A proof is attached to the first lane and every `SMT_PROOF_INTERVAL`-th lane
/// during IBD SMT export. The importer verifies these against `lanes_root`.
///
/// The end-to-end correctness of the import is already guaranteed by the final
/// `computed_root == lanes_root` check in `streaming_import`. Inline proofs
/// only exist so the receiver can abort a misbehaving peer mid-stream before
/// downloading everything, so a sparse stride is enough — one every ~1M lanes
/// bounds wasted bandwidth and eliminates per-lane `prove_lane` cost on the
/// sender
pub const SMT_PROOF_INTERVAL: usize = 1 << 20;

/// A lane to import during IBD SMT sync.
#[derive(Clone, Debug)]
pub struct ImportLane {
    pub lane_key: Hash,
    pub lane_tip: Hash,
    pub blue_score: u64,
    pub proof: Option<kaspa_smt::proof::OwnedSmtProof>,
}

pub type ImportLaneBatchIterator<'a> = &'a mut (dyn Iterator<Item = Vec<ImportLane>> + Send);

/// SMT metadata for IBD sync, verified against the pruning point header.
///
/// Wire: `lanes_root || payload_and_ctx_digest || parent_seq_commit` (96 bytes).
/// `inactivity_shortcut_block` is derived by the receiver from chain headers; not transmitted.
#[derive(Clone, Copy, Debug)]
pub struct SmtExportMetadata {
    pub lanes_root: Hash,
    pub payload_and_ctx_digest: Hash,
    pub parent_seq_commit: Hash,
    pub active_lanes_count: u64,
}

/// Shielded-pool state export metadata for IBD sync (PLAN §2.8/§2.9). Transfers
/// the shielded state at the pruning point so a fast-syncing node can validate
/// the pruning point's descendants without replaying pre-pruning shielded history.
///
/// `data` is the opaque encoding of `(frontier, supply totals, nullifier MuHash,
/// state_root)` produced by the consensus layer; the unbounded global nullifier
/// set is streamed separately in [`ShieldedNullifierBatchIterator`] batches.
#[derive(Clone, Debug)]
pub struct ShieldedExportMetadata {
    pub data: Vec<u8>,
    pub nullifier_count: u64,
}

/// Upper bound on [`ShieldedExportMetadata::nullifier_count`] accepted on import
/// (audit finding F-08). The count is declared by an untrusted sync peer; the cap
/// bounds the memory/CPU the import can be made to spend (2^26 ≈ 67M entries ≈
/// 2 GiB of raw nullifiers) while still far exceeding any realistic near-term
/// shielded pool.
pub const MAX_SHIELDED_NULLIFIER_IMPORT_COUNT: u64 = 1 << 26;

/// Batches of spent nullifiers (each 32 bytes) streamed during pruning-point
/// shielded-state import, mirroring [`ImportLaneBatchIterator`].
pub type ShieldedNullifierBatchIterator<'a> = &'a mut (dyn Iterator<Item = Vec<[u8; 32]>> + Send);

#[derive(Clone, Debug)]
pub struct SeqCommitLaneEntry {
    pub tip: Hash,
    pub blue_score: u64,
}

/// Witness for verifying a single lane against the `seq_commit` of a canonical block.
///
/// Given the block's header (which carries `seq_commit` in `accepted_id_merkle_root`),
/// a client can reconstruct the lane's SMT leaf and verify the proof chain:
/// `smt_leaf → compute_root → lanes_root → activity_root → seq_state_root → seq_commit`.
///
/// `lane` is `None` when the lane is absent at this POV;
/// the SMT proof is then a non-inclusion proof.
///
/// `inactivity_shortcut` (KIP-21 activity_root level): the `accepted_id_merkle_root`
/// (= seq_commit) of the anchor block resolved per KIP-21. Folded into
/// `activity_root = H_activity_root(inactivity_shortcut, lanes_root)`.
#[derive(Clone, Debug)]
pub struct SeqCommitLaneProof {
    pub smt_proof: kaspa_smt::proof::OwnedSmtProof,
    pub lane: Option<SeqCommitLaneEntry>,
    pub payload_and_ctx_digest: Hash,
    pub parent_seq_commit: Hash,
    pub inactivity_shortcut: Hash,
    /// Canonical-`R` witness support (KIP-21): the mergeset context hash of this block —
    /// `H_mergeset_context(parent.timestamp, this.daa_score, this.blue_score)`. The guest folds
    /// its self-computed `payload_root` with this via `payload_and_context_digest`, so it needs the
    /// *raw* context hash, not the already-combined `payload_and_ctx_digest`.
    pub context_hash: Hash,
    /// Canonical-`R` witness support: the active-lanes SMT root at this block's POV. Combined with
    /// `inactivity_shortcut` via `activity_root_hash` this yields the `activity_root`.
    pub lanes_root: Hash,
    /// Canonical-`R` witness support: the full ordered list of `miner_payload_leaf`s of this
    /// block's mergeset (exactly as consensus feeds `miner_payload_root`). An external assembler
    /// locates the merge-mined ZKas block's own leaf by value and splices the rest as `other_leaves`
    /// — the fragile mergeset-ordering rule stays entirely node-side.
    pub miner_payload_leaves: Vec<Hash>,
}

/// Abstracts the consensus external API
#[allow(unused_variables)]
pub trait ConsensusApi: Send + Sync {
    fn build_block_template(
        &self,
        miner_data: MinerData,
        tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        unimplemented!()
    }

    fn validate_and_insert_block(&self, block: Block) -> BlockValidationFutures {
        unimplemented!()
    }

    fn validate_and_insert_trusted_block(&self, tb: TrustedBlock) -> BlockValidationFutures {
        unimplemented!()
    }

    /// Populates the mempool transaction with maximally found UTXO entry data and proceeds to full transaction
    /// validation if all are found. If validation is successful, also `transaction.calculated_fee` is expected to be populated.
    fn validate_mempool_transaction(&self, transaction: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        unimplemented!()
    }

    /// Populates the mempool transactions with maximally found UTXO entry data and proceeds to full transactions
    /// validation if all are found. If validation is successful, also `transaction.calculated_fee` is expected to be populated.
    fn validate_mempool_transactions_in_parallel(
        &self,
        transactions: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        unimplemented!()
    }

    /// Populates the mempool transaction with maximally found UTXO entry data.
    fn populate_mempool_transaction(&self, transaction: &mut MutableTransaction) -> TxResult<()> {
        unimplemented!()
    }

    /// Populates the mempool transactions with maximally found UTXO entry data.
    fn populate_mempool_transactions_in_parallel(&self, transactions: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        unimplemented!()
    }

    fn calculate_transaction_non_contextual_masses(&self, transaction: &Transaction) -> TxResult<NonContextualMasses> {
        unimplemented!()
    }

    fn calculate_transaction_contextual_masses(&self, transaction: &MutableTransaction) -> Option<ContextualMasses> {
        unimplemented!()
    }

    /// Returns an aggregation of consensus stats. Designed to be a fast call.
    fn get_stats(&self) -> ConsensusStats {
        unimplemented!()
    }

    fn get_virtual_daa_score(&self) -> u64 {
        unimplemented!()
    }

    fn get_virtual_bits(&self) -> u32 {
        unimplemented!()
    }

    fn get_virtual_past_median_time(&self) -> u64 {
        unimplemented!()
    }

    fn get_virtual_merge_depth_root(&self) -> Option<Hash> {
        unimplemented!()
    }

    /// Returns the `BlueWork` threshold at which blocks with lower or equal blue work are considered
    /// to be un-mergeable by current virtual state.
    /// (Note: in some rare cases when the node is unsynced the function might return zero as the threshold)
    fn get_virtual_merge_depth_blue_work_threshold(&self) -> BlueWorkType {
        unimplemented!()
    }

    fn get_sink(&self) -> Hash {
        unimplemented!()
    }

    fn get_sink_timestamp(&self) -> u64 {
        unimplemented!()
    }

    fn get_sink_blue_score(&self) -> u64 {
        unimplemented!()
    }

    fn get_sink_daa_score_timestamp(&self) -> DaaScoreTimestamp {
        unimplemented!()
    }

    fn get_merged_block_context(&self, hash: Hash) -> ConsensusResult<Option<MergedBlockContext>> {
        unimplemented!()
    }

    fn get_virtual_state_approx_id(&self) -> VirtualStateApproxId {
        unimplemented!()
    }

    /// retention period root refers to the earliest block from which the current node has full header & block data
    fn get_retention_period_root(&self) -> Hash {
        unimplemented!()
    }

    fn estimate_block_count(&self) -> BlockCount {
        unimplemented!()
    }

    /// Gets the virtual chain paths from `low` to the `sink` hash, or until `chain_path_added_limit` is reached
    ///
    /// Note:
    ///     1) `chain_path_added_limit` will populate removed fully, and then the added chain path, up to `chain_path_added_limit` amount of hashes.
    ///     1.1) use `None to impose no limit with optimized backward chain iteration, for better performance in cases where batching is not required.
    fn get_virtual_chain_from_block(&self, low: Hash, chain_path_added_limit: Option<usize>) -> ConsensusResult<ChainPath> {
        unimplemented!()
    }

    fn get_chain_block_samples(&self) -> Vec<DaaScoreTimestamp> {
        unimplemented!()
    }

    /// Returns the fully populated transaction with the given txid which was accepted at the provided accepting_block_daa_score.
    /// The argument `accepting_block_daa_score` is expected to be the DAA score of the accepting chain block of `txid`.
    /// Note: If the transaction vec is None, the function returns all accepted transactions.
    fn get_transactions_by_accepting_daa_score(
        &self,
        accepting_daa_score: u64,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_transactions_by_block_acceptance_data(
        &self,
        accepting_block: Hash,
        block_acceptance_data: MergesetBlockAcceptanceData,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_transactions_by_accepting_block(
        &self,
        accepting_block: Hash,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        unimplemented!()
    }

    fn get_virtual_parents(&self) -> BlockHashSet {
        unimplemented!()
    }

    fn get_virtual_parents_len(&self) -> usize {
        unimplemented!()
    }

    fn get_virtual_utxos(
        &self,
        from_outpoint: Option<TransactionOutpoint>,
        chunk_size: usize,
        skip_first: bool,
    ) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        unimplemented!()
    }

    fn get_tips(&self) -> Vec<Hash> {
        unimplemented!()
    }

    fn get_tips_len(&self) -> usize {
        unimplemented!()
    }

    fn modify_coinbase_payload(&self, payload: Vec<u8>, miner_data: &MinerData) -> CoinbaseResult<Vec<u8>> {
        unimplemented!()
    }

    /// The dev-fee coinbase output script for this network, when a dev fee is configured
    /// (the recipient's bytes as a version-0 script; `CoinbaseManager::expected_coinbase_transaction`
    /// appends the dev-fee note as the LAST coinbase output). `modify_block_template` uses it
    /// to exclude the dev-fee note from the red-reward reverse scan — otherwise, when the cached
    /// template's miner script equals the dev-fee recipient, the scan would repoint the fee
    /// (audit finding F-31). `None` when no dev fee is active.
    fn dev_fee_spk(&self) -> Option<ScriptPublicKey> {
        None
    }

    fn calc_transaction_hash_merkle_root(&self, txs: &[Transaction]) -> Hash {
        unimplemented!()
    }

    fn validate_pruning_proof(&self, proof: &PruningPointProof, proof_metadata: &PruningProofMetadata) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn apply_pruning_proof(
        &self,
        proof: PruningPointProof,
        trusted_set: &[TrustedBlock],
        header_only_chain_segment: &[Arc<Header>],
    ) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn import_pruning_points(&self, pruning_points: PruningPointsList) -> PruningImportResult<()> {
        unimplemented!()
    }

    fn append_imported_pruning_point_utxos(&self, utxoset_chunk: &[(TransactionOutpoint, UtxoEntry)], current_multiset: &mut MuHash) {
        unimplemented!()
    }

    fn import_pruning_point_utxo_set(&self, new_pruning_point: Hash, imported_utxo_multiset: MuHash) -> PruningImportResult<()> {
        unimplemented!()
    }

    /// Import SMT lane state at the pruning point. Builds the tree from lane
    /// preimages, verifies root matches `lanes_root`, and flushes to DB.
    ///
    /// The iterator yields lane chunks already sized by the wire-level chunker
    /// each element is up to `SMT_CHUNK_SIZE` lanes. The importer does not
    /// re-batch.
    ///
    /// `inactivity_shortcut_block` is resolved by the caller during metadata verification.
    fn import_pruning_point_smt(
        &self,
        _new_pruning_point: Hash,
        _metadata: SmtExportMetadata,
        _inactivity_shortcut_block: Hash,
        _lane_batches: ImportLaneBatchIterator<'_>,
    ) -> PruningImportResult<()> {
        unimplemented!()
    }

    /// Compute SMT metadata for the pruning point (for P2P streaming).
    fn get_pruning_point_smt_metadata(&self, _expected_pruning_point: Hash) -> ConsensusResult<SmtExportMetadata> {
        unimplemented!()
    }

    /// Compute the shielded-state export metadata at the pruning point (for P2P
    /// streaming). `Ok(None)` means the pruning point has no shielded state (empty
    /// pool — nothing to transfer). PLAN §2.8/§2.9.
    fn get_pruning_point_shielded_metadata(&self, _expected_pruning_point: Hash) -> ConsensusResult<Option<ShieldedExportMetadata>> {
        unimplemented!()
    }

    /// Open a streaming iterator over the whole spent-nullifier set at the pruning
    /// point (server side of shielded-state IBD sync).
    fn open_pruning_point_shielded_nullifier_stream(
        &self,
        _expected_pruning_point: Hash,
    ) -> ConsensusResult<Box<dyn Iterator<Item = ConsensusResult<[u8; 32]>> + Send + 'static>> {
        unimplemented!()
    }

    /// Import and seed the shielded state at the pruning point from transferred
    /// metadata + streamed nullifier batches (receiver side of shielded-state IBD
    /// sync). Verifies internal consistency before seeding; the consensus binding
    /// is the #24 coinbase commitment enforced when the pruning point's children
    /// are validated.
    ///
    /// `expected_state_root` (audit finding F-02): when `Some`, the imported
    /// metadata's declared state root must equal it before anything is seeded. The
    /// caller obtains it from the coinbase `shielded_commitment` of the pruning
    /// point's selected child — a PoW-committed value on the proof-verified header
    /// chain — so a malicious syncer can no longer seed arbitrary state. `None`
    /// skips the binding check (fallback only when the selected child cannot be
    /// determined; see the IBD flow).
    fn import_pruning_point_shielded(
        &self,
        _new_pruning_point: Hash,
        _metadata: ShieldedExportMetadata,
        _expected_state_root: Option<[u8; 32]>,
        _nullifier_batches: ShieldedNullifierBatchIterator<'_>,
    ) -> PruningImportResult<()> {
        unimplemented!()
    }

    /// The locally held shielded state root (PLAN §2.10) as of `block`, recomputed
    /// from the per-block snapshots (defaults to the empty-state root for blocks
    /// with no shielded state). Used on the IBD import path to decide whether the
    /// local state already matches the PoW-committed root (F-02/F-15).
    fn get_shielded_state_root(&self, _block: Hash) -> ConsensusResult<[u8; 32]> {
        unimplemented!()
    }

    /// The shielded state root of the empty state — what a chain block's coinbase
    /// commits when its selected parent has no shielded state. Used to bind a
    /// peer's "empty shielded state" claim to the PoW-committed root (F-02).
    fn empty_shielded_state_root(&self) -> [u8; 32] {
        unimplemented!()
    }

    /// Resolve the `inactivity_shortcut_block` (the block hash anchoring the
    /// `activity_root` shortcut) from the POV of `pov_block`. Uses headers +
    /// reachability only; safe to call at the IBD PP boundary before the SMT
    /// is imported. Callers resolve to the seq_commit Hash themselves (the
    /// block-to-seq_commit fold is just a header read + activation check).
    fn inactivity_shortcut_block_for_pov(&self, _pov_block: Hash) -> ConsensusResult<Hash> {
        unimplemented!()
    }

    /// The shielded note-commitment tree **frontier** as of `block`, as raw parts
    /// `(size, last_leaf, ommers)`. This is the fast-sync checkpoint a light wallet
    /// starts from: it reconstructs the frontier, then scans only blocks after
    /// `block`, yet still witnesses its notes against the live tip. Raw parts (rather
    /// than a `kaspa-shielded-core` type) keep that crate off this API boundary.
    fn get_shielded_tree_frontier(&self, _block: Hash) -> ConsensusResult<(u64, Option<[u8; 32]>, Vec<[u8; 32]>)> {
        unimplemented!()
    }

    /// The shielded turnstile totals as of `block`, as raw parts
    /// `(cumulative_coinbase, cumulative_fees, cumulative_burns)` in sompi — the
    /// public form of the PLAN §2.7 invariant `pool = minted - fees - burns`. Raw
    /// integers (rather than a `kaspa-shielded-core` type) keep that crate off this
    /// API boundary. A block with no shielded state reports zeroes.
    fn get_shielded_supply_totals(&self, _block: Hash) -> ConsensusResult<(u128, u128, u128)> {
        unimplemented!()
    }

    /// The shielded effects of one **chain block**, exactly as the §2.4 state
    /// transition applied them: the block's own coinbase mint (txid + outputs)
    /// and the accepted shielded transaction payloads in consensus accepted
    /// order, with anchor-non-final spends already dropped (the same retain rule
    /// the virtual processor ran at validation). This is the canonical stream a
    /// wallet must ingest to mirror the note-commitment tree: scanning raw DAG
    /// blocks (e.g. via `get_blocks`) counts non-chain coinbases that never mint
    /// and mis-orders leaves once the DAG is wider than a chain.
    fn get_shielded_chain_block_data(&self, _block: Hash) -> ConsensusResult<ShieldedChainBlockData> {
        unimplemented!()
    }

    /// The next `limit` selected-chain block hashes strictly after `low`, resolved
    /// through the retained chain index rather than a reachability walk.
    ///
    /// This is the enumeration half of a wallet scan, and it exists so that a **pruned**
    /// node can still serve one. `get_virtual_chain_from_block` answers the same question
    /// via `calculate_chain_path`, which walks reachability and therefore fails below the
    /// retention root — even though the shielded scan archive the wallet actually needs is
    /// retained forever. Reading the `index -> hash` map instead needs no reachability, no
    /// headers and no block bodies, so history stays scannable for the life of the chain.
    ///
    /// `Ok(None)` means `low` is not on the current selected chain — it was reorged out, or
    /// this node pruned its index before the retention change. Callers should treat that as
    /// "re-anchor" and fall back to the reachability path to obtain a precise error.
    fn get_shielded_chain_range(&self, _low: Hash, _limit: usize) -> ConsensusResult<Option<Vec<Hash>>> {
        unimplemented!()
    }

    /// The last selected-chain block strictly below `daa` that still has a retained shielded
    /// tree frontier — found by binary search over the chain index (DAA is non-decreasing
    /// along the chain), so a wallet can place a birthday anywhere in history with ONE call
    /// instead of walking thousands of metadata pages. `Ok(None)` = nothing below `daa` in
    /// the retained index (older than this node's history base), or no frontier within reach.
    fn get_shielded_frontier_block_below_daa(&self, _daa: u64) -> ConsensusResult<Option<Hash>> {
        unimplemented!()
    }

    /// Serve a shielded-history backfill request: this node's scan records for the chain blocks
    /// immediately BELOW `anchor` on its own selected chain, newest first, plus whether the walk
    /// reached genesis.
    ///
    /// Exists because a freshly synced node holds per-note history only from its pruning point
    /// forward — `PruningPointShieldedMetadata` carries aggregates (frontier, nullifier muhash,
    /// supply) that cannot yield notes — so wallets querying it see a silently partial balance.
    /// The requester verifies the result by replaying the `cmx` leaves into an empty tree and
    /// comparing against the PoW-anchored pruning-point frontier, so no trust in the server is
    /// required.
    /// Ingest one chunk of backfilled shielded history: chain-index entries plus scan records
    /// for blocks BELOW this node's own base.
    ///
    /// Restoring the records alone is NOT enough and was measured to fail: wallets reach history
    /// through `get_shielded_chain_range`, which resolves the start block via
    /// `selected_chain_store.get_by_hash()`. Without index entries a node holds the data and
    /// still answers `cannot find header`. The index is the enumerator.
    ///
    /// The first call rebases: `init_with_pruning_point` numbers a synced node from ITS pruning
    /// point as index 0, while the peer's indices are genesis-based, so local entries are shifted
    /// up to make room below. Returns how many index entries and scan records were written.
    ///
    /// The scan archive is never read by consensus, so bad data cannot affect validation; the
    /// caller still verifies the whole range by replaying its `cmx` leaves against the
    /// PoW-anchored pruning-point frontier before advertising history as complete.
    /// The oldest chain block this node can enumerate — the anchor a history backfill walks down
    /// from. On a headers-proof-synced node this is its pruning point.
    fn get_shielded_history_base(&self) -> Hash {
        unimplemented!()
    }

    /// How far back this node can actually serve shielded note history, and whether that
    /// reaches genesis.
    ///
    /// Returns `(daa_score_of_oldest_servable_block, complete)`.
    ///
    /// # Why a node must publish this
    ///
    /// IBD transfers a frontier and a nullifier MuHash — aggregates that cannot yield anyone's
    /// notes — so a node that has not backfilled holds per-note history only from its pruning
    /// point forward. Ask it for a wallet's balance and it answers with whatever it can see,
    /// which is a PARTIAL balance reported as final. There is no symptom: the number is
    /// plausible, the node says it is synced, and the user has no way to tell.
    ///
    /// That is not hypothetical on this chain. A wallet holding four tokens was observed reading
    /// 2,038,348 / 1,902,767 / 1,902,767 / 0.00 across successive queries, every one of them
    /// reported as synced. Publishing the floor is what lets a wallet say "this node cannot
    /// answer for my birthday" instead of inventing a number.
    ///
    /// `complete` means the node can enumerate down to genesis. It is derived, not stored: a
    /// backfill that fails verification is purged, so records that are present were verified.
    fn get_shielded_history_status(&self) -> ConsensusResult<(u64, bool)> {
        unimplemented!()
    }

    /// Ingest a backfilled chunk. `anchor` and `anchor_index` are the block the chunk was
    /// requested below and its index in the SERVER's genesis-based numbering — together they are
    /// what aligns the two index spaces, since the chunk itself never contains the anchor.
    fn backfill_shielded_history(
        &self,
        _anchor: Hash,
        _anchor_index: u64,
        _records: &[(u64, ShieldedChainBlockData)],
    ) -> ConsensusResult<(u64, u64)> {
        unimplemented!()
    }

    fn get_shielded_history_indexed_below(
        &self,
        _anchor: Hash,
        _max_blocks: usize,
    ) -> ConsensusResult<(Vec<(u64, ShieldedChainBlockData)>, bool, u64)> {
        unimplemented!()
    }

    /// Replay the scan archive from genesis up to and including `base`, and report whether it
    /// reproduces this node's own frontier at `base`. Read-only — see [`ShieldedHistoryVerdict`].
    ///
    /// `base` must be a block whose frontier this node did NOT learn from the data being checked:
    ///   - after a p2p backfill, the history base captured *before* it ran (the pruning point);
    ///   - for an operator check of a whole archive, the chain tip.
    fn verify_shielded_history(&self, _base: Hash) -> ConsensusResult<ShieldedHistoryVerdict> {
        unimplemented!()
    }

    /// Delete every scan record and chain-index entry below `base`, restoring the index numbering
    /// `init_with_pruning_point` produces. Returns the number of scan records discarded.
    ///
    /// The undo of a failed [`Self::verify_shielded_history`]. Separate from it on purpose: only
    /// the caller knows whether the range under test was just accepted from a peer (discard it) or
    /// is the node's own history being audited (never touch it).
    fn purge_shielded_history_below(&self, _base: Hash) -> ConsensusResult<u64> {
        unimplemented!()
    }

    /// Open a live canonical-lane stream for the pruning point. The returned
    /// iterator yields every canonical lane once, holds its own owned
    /// pruning-lock guard internally so data stays pinned for its full
    /// lifetime, and can be moved across `spawn_blocking` boundaries.
    ///
    /// Every [`SMT_PROOF_INTERVAL`]-th lane carries an inline SMT proof so the
    /// receiver can abort a misbehaving peer mid-stream. Correctness is still
    /// anchored by the final `lanes_root == computed_root` check in the
    /// importer.
    fn open_pruning_point_smt_lane_stream(
        &self,
        _expected_pruning_point: Hash,
    ) -> ConsensusResult<Box<dyn Iterator<Item = ConsensusResult<ImportLane>> + Send + 'static>> {
        unimplemented!()
    }

    fn is_chain_ancestor_of(&self, low: Hash, high: Hash) -> ConsensusResult<bool> {
        unimplemented!()
    }

    fn get_hashes_between(&self, low: Hash, high: Hash, max_blocks: usize) -> ConsensusResult<(Vec<Hash>, Hash)> {
        unimplemented!()
    }

    fn get_header(&self, hash: Hash) -> ConsensusResult<Arc<Header>> {
        unimplemented!()
    }

    fn get_headers_selected_tip(&self) -> Hash {
        unimplemented!()
    }

    /// Returns the antipast of block `hash` from the POV of `context`, i.e. `antipast(hash) ∩ past(context)`.
    /// Since this might be an expensive operation for deep blocks, we allow the caller to specify a limit
    /// `max_traversal_allowed` on the maximum amount of blocks to traverse for obtaining the answer
    fn get_antipast_from_pov(&self, hash: Hash, context: Hash, max_traversal_allowed: Option<u64>) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    /// Returns the anticone of block `hash` from the POV of `virtual`
    fn get_anticone(&self, hash: Hash) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn get_pruning_point_proof(&self) -> Arc<PruningPointProof> {
        unimplemented!()
    }

    fn create_virtual_selected_chain_block_locator(&self, low: Option<Hash>, high: Option<Hash>) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn create_block_locator_from_pruning_point(&self, high: Hash, limit: usize) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }

    fn pruning_point_headers(&self) -> Vec<Arc<Header>> {
        unimplemented!()
    }

    fn get_pruning_point_anticone_and_trusted_data(&self) -> ConsensusResult<Arc<PruningPointTrustedData>> {
        unimplemented!()
    }

    fn get_block(&self, hash: Hash) -> ConsensusResult<Block> {
        unimplemented!()
    }

    fn get_block_transactions(&self, hash: Hash, indices: Option<Vec<TransactionIndexType>>) -> ConsensusResult<Vec<Transaction>> {
        unimplemented!()
    }

    fn get_block_body(&self, hash: Hash) -> ConsensusResult<Arc<Vec<Transaction>>> {
        unimplemented!()
    }

    fn get_block_even_if_header_only(&self, hash: Hash) -> ConsensusResult<Block> {
        unimplemented!()
    }

    fn get_ghostdag_data(&self, hash: Hash) -> ConsensusResult<ExternalGhostdagData> {
        unimplemented!()
    }

    fn get_block_children(&self, hash: Hash) -> Option<Vec<Hash>> {
        unimplemented!()
    }

    fn get_block_parents(&self, hash: Hash) -> Option<Arc<Vec<Hash>>> {
        unimplemented!()
    }

    fn get_block_status(&self, hash: Hash) -> Option<BlockStatus> {
        unimplemented!()
    }

    fn get_block_acceptance_data(&self, hash: Hash) -> ConsensusResult<Arc<AcceptanceData>> {
        unimplemented!()
    }

    /// Returns acceptance data for a set of blocks belonging to the selected parent chain.
    ///
    /// See `self::get_virtual_chain`
    fn get_blocks_acceptance_data(
        &self,
        hashes: &[Hash],
        merged_blocks_limit: Option<usize>,
    ) -> ConsensusResult<Vec<Arc<AcceptanceData>>> {
        unimplemented!()
    }

    fn is_chain_block(&self, hash: Hash) -> ConsensusResult<bool> {
        unimplemented!()
    }

    /// Returns a self-contained witness for verifying the lane `lane_key` against
    /// the `seq_commit` carried in `block_hash`'s header. The block must be a
    /// chain (selected-parent) block at or after the current pruning point;
    /// non-canonical blocks are rejected with [`ConsensusError::BlockNotInSelectedChain`],
    /// too-deep blocks with [`ConsensusError::BlockTooDeep`], and genesis with
    /// [`ConsensusError::BlockIsGenesis`].
    fn get_seq_commit_lane_proof(&self, block_hash: Hash, lane_key: Hash) -> ConsensusResult<SeqCommitLaneProof> {
        unimplemented!()
    }

    fn get_pruning_point_utxos(
        &self,
        expected_pruning_point: Hash,
        from_outpoint: Option<TransactionOutpoint>,
        chunk_size: usize,
        skip_first: bool,
    ) -> ConsensusResult<Vec<(TransactionOutpoint, UtxoEntry)>> {
        unimplemented!()
    }

    fn get_missing_block_body_hashes(&self, high: Hash) -> ConsensusResult<Vec<Hash>> {
        unimplemented!()
    }
    fn get_body_missing_anticone(&self) -> Vec<Hash> {
        unimplemented!()
    }
    fn clear_body_missing_anticone_set(&self) {
        unimplemented!()
    }

    fn pruning_point(&self) -> Hash {
        unimplemented!()
    }

    fn estimate_network_hashes_per_second(&self, start_hash: Option<Hash>, window_size: usize) -> ConsensusResult<u64> {
        unimplemented!()
    }

    fn validate_pruning_points(&self, syncer_virtual_selected_parent: Hash) -> ConsensusResult<()> {
        unimplemented!()
    }

    fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        unimplemented!()
    }

    fn creation_timestamp(&self) -> u64 {
        unimplemented!()
    }

    fn finality_point(&self) -> Hash {
        unimplemented!()
    }

    fn clear_pruning_utxo_set(&self) {
        unimplemented!()
    }

    fn clear_pruning_smt_stores(&self) {
        unimplemented!()
    }

    fn set_pruning_smt_stable_flag(&self, _val: bool) {
        unimplemented!()
    }

    fn is_pruning_smt_stable(&self) -> bool {
        unimplemented!()
    }

    /// F-15: really clears the shielded import state — the whole global nullifier
    /// set, the per-block snapshots at the current pruning point, and the stable
    /// flag, in one atomic batch. Call ONLY immediately before a full re-seed (see
    /// `ShieldedStateManager::clear_for_pruning_reimport` in `kaspa-consensus` for
    /// the safety preconditions; the IBD flow enforces them).
    fn clear_pruning_shielded_stores(&self) {
        unimplemented!()
    }

    fn set_pruning_shielded_stable_flag(&self, _val: bool) {
        unimplemented!()
    }

    fn is_pruning_shielded_stable(&self) -> bool {
        unimplemented!()
    }

    fn set_pruning_utxoset_stable_flag(&self, val: bool) {
        unimplemented!()
    }

    fn is_pruning_utxoset_stable(&self) -> bool {
        unimplemented!()
    }

    fn is_pruning_point_anticone_fully_synced(&self) -> bool {
        unimplemented!()
    }

    fn is_consensus_in_transitional_ibd_state(&self) -> bool {
        unimplemented!()
    }

    fn intrusive_pruning_point_update(&self, new_pruning_point: Hash, syncer_sink: Hash) -> ConsensusResult<()> {
        unimplemented!()
    }

    /// Returns the n most recent pruning points (including the current pruning point)
    fn get_n_last_pruning_points(&self, n: usize) -> Vec<Hash> {
        unimplemented!()
    }
}

pub type DynConsensus = Arc<dyn ConsensusApi>;
