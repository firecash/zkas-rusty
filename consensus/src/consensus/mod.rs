pub mod cache_policy_builder;
pub mod ctl;
pub mod factory;
pub mod services;
pub mod storage;
pub mod test_consensus;

#[cfg(feature = "devnet-prealloc")]
mod utxo_set_override;

use crate::{
    config::Config,
    errors::{BlockProcessResult, RuleError},
    model::{
        services::reachability::ReachabilityService,
        stores::{
            DB,
            acceptance_data::AcceptanceDataStoreReader,
            block_transactions::BlockTransactionsStoreReader,
            ghostdag::{GhostdagData, GhostdagStoreReader},
            headers::{CompactHeaderData, HeaderStoreReader},
            headers_selected_tip::HeadersSelectedTipStoreReader,
            past_pruning_points::PastPruningPointsStoreReader,
            pruning::PruningStoreReader,
            relations::RelationsStoreReader,
            selected_chain::SelectedChainStore,
            statuses::StatusesStoreReader,
            tips::{TipsStore, TipsStoreReader},
            utxo_set::{UtxoSetStore, UtxoSetStoreReader},
            virtual_state::VirtualState,
        },
    },
    pipeline::{
        ProcessingCounters,
        body_processor::BlockBodyProcessor,
        deps_manager::{BlockProcessingMessage, BlockResultSender, BlockTask, VirtualStateProcessingMessage},
        header_processor::HeaderProcessor,
        pruning_processor::processor::{PruningProcessingMessage, PruningProcessor},
        virtual_processor::{VirtualStateProcessor, errors::PruningImportResult},
    },
    processes::{
        ghostdag::ordering::SortableBlock,
        window::{WindowManager, WindowType},
    },
};
use kaspa_consensus_core::{
    BlockHashSet, BlueWorkType, ChainPath, HashMapCustomHasher,
    acceptance_data::{AcceptanceData, MergedBlockContext, MergesetBlockAcceptanceData},
    api::{
        BlockValidationFutures, ConsensusApi, ConsensusStats, ImportLaneBatchIterator, SeqCommitLaneProof,
        args::{TransactionValidationArgs, TransactionValidationBatchArgs},
        stats::BlockCount,
    },
    block::{Block, BlockTemplate, TemplateBuildMode, TemplateTransactionSelector, VirtualStateApproxId},
    blockhash::BlockHashExtensions,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    daa_score_timestamp::DaaScoreTimestamp,
    errors::{
        coinbase::CoinbaseResult,
        consensus::{ConsensusError, ConsensusResult},
        difficulty::DifficultyError,
        pruning::PruningImportError,
        tx::{TxResult, TxRuleError},
    },
    header::Header,
    mass::{ContextualMasses, NonContextualMasses},
    merkle::calc_hash_merkle_root,
    mining_rules::MiningRules,
    muhash::MuHashExtensions,
    pruning::{PruningPointProof, PruningPointTrustedData, PruningPointsList, PruningProofMetadata},
    trusted::{ExternalGhostdagData, TrustedBlock},
    tx::{
        ComputeCommit, MutableTransaction, Transaction, TransactionId, TransactionIndexType, TransactionOutpoint,
        TransactionQueryResult, TransactionType, UtxoEntry,
    },
};
use kaspa_consensus_notify::root::ConsensusNotificationRoot;

use crossbeam_channel::{
    Receiver as CrossbeamReceiver, Sender as CrossbeamSender, bounded as bounded_crossbeam, unbounded as unbounded_crossbeam,
};
use itertools::Itertools;
use kaspa_consensusmanager::{SessionLock, SessionReadGuard};

use kaspa_core::info;
#[cfg(feature = "test-smt-pruning-diagnostics")]
use kaspa_database::prelude::StoreResult;
use kaspa_database::prelude::StoreResultExt;
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use kaspa_smt_store::processor::SmtReadBounds;
#[cfg(feature = "test-smt-pruning-diagnostics")]
use kaspa_smt_store::processor::StaleSmtEntriesCount;
use kaspa_txscript::caches::TxScriptCacheCounters;
use kaspa_utils::arc::ArcExtensions;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rocksdb::WriteBatch;

/// Chain-index spacing of the tree-frontier checkpoints reconstructed when backfilled shielded
/// history is verified (`verify_shielded_history`).
///
/// Deliberately keyed on CHAIN INDEX, not DAA score. The pruning processor spaces its own
/// checkpoints on `daa_score % 1000`, but a DAG block's DAA advances by its whole mergeset and
/// therefore steps over multiples — which is fine for "keep a usable anchor near here" and wrong
/// for "give me evenly sized verifiable segments". Index spacing makes every segment the same
/// number of blocks, which is what a range-verifying requester needs.
///
/// Cost: one `FrontierState` (~1 KB: size + leaf + <=32 ommers) per 1,000 blocks, so ~1 MB for a
/// 1M-block chain — against the ~232 MB the scan archive itself occupies.
const SHIELDED_REPLAY_CHECKPOINT_INTERVAL: u64 = 1_000;

use self::{services::ConsensusServices, storage::ConsensusStorage};
use kaspa_consensus_core::api::SeqCommitLaneEntry;
use std::{
    cmp,
    cmp::Reverse,
    collections::{BinaryHeap, HashSet, VecDeque},
    future::Future,
    iter::once,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;

use crate::model::stores::selected_chain::SelectedChainStoreReader;

pub struct Consensus {
    // DB
    db: Arc<DB>,

    // Channels
    block_sender: CrossbeamSender<BlockProcessingMessage>,

    // Processors
    pub(super) header_processor: Arc<HeaderProcessor>,
    pub(super) body_processor: Arc<BlockBodyProcessor>,
    pub(super) virtual_processor: Arc<VirtualStateProcessor>,
    pub(super) pruning_processor: Arc<PruningProcessor>,

    // Storage
    pub(super) storage: Arc<ConsensusStorage>,

    // Services and managers
    pub(super) services: Arc<ConsensusServices>,

    // Pruning lock
    pruning_lock: SessionLock,

    // Notification management
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    counters: Arc<ProcessingCounters>,

    // Config
    config: Arc<Config>,

    // Other
    creation_timestamp: u64,

    // Signals
    is_consensus_exiting: Arc<AtomicBool>,
}

impl Deref for Consensus {
    type Target = ConsensusStorage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

impl Consensus {
    /// Undo a shielded-history backfill: delete every scan record and index entry below `base`,
    /// and renumber the surviving chain so `base` is index 0 again.
    ///
    /// This restores exactly the state `init_with_pruning_point` left, which is what makes
    /// rejection safe to perform automatically. Two properties it must not violate:
    ///
    /// - **Records and index entries go together.** `get_shielded_chain_range` enumerates via the
    ///   index and then reads the record; an index entry whose record is gone makes the page
    ///   fetch fail, and a failed page fetch does not advance the wallet's cursor — every wallet
    ///   would retry the same block forever. Deleting one without the other trades bad history
    ///   for a wedged fleet.
    /// - **The renumbering is a single batch.** A crash midway would leave the index numbered
    ///   two different ways at once, and nothing would detect it afterwards.
    ///
    /// Returns the number of scan records discarded.
    fn purge_backfilled_shielded_history(&self, base: Hash) -> ConsensusResult<u64> {
        // No pruning-lock write here either: this is called from the IBD flow while it holds the
        // read side, and would deadlock for the same reason as the ingest. The caller's guard
        // pins the pruning point; `selected_chain_store.write()` serialises the mutation.
        let mut sc = self.storage.selected_chain_store.write();
        let Some(base_index) = sc.get_by_hash(base).optional().unwrap() else {
            return Ok(0);
        };
        if base_index == 0 {
            return Ok(0); // nothing below the base; the index is already as it started
        }
        let (tip, _) = sc.get_tip().map_err(|e| ConsensusError::GeneralOwned(format!("cannot read chain tip: {e}")))?;

        let mut batch = rocksdb::WriteBatch::default();
        let mut discarded = 0u64;
        // Drop the backfilled range: records and index entries, in lockstep.
        for index in 0..base_index {
            if let Ok(hash) = sc.get_by_index(index) {
                if self.virtual_processor.shielded_state_manager_ref().scan_block(hash).unwrap_or(None).is_some() {
                    self.virtual_processor
                        .shielded_state_manager_ref()
                        .delete_backfilled_scan(&mut batch, hash)
                        .map_err(|e| ConsensusError::GeneralOwned(format!("cannot delete scan record: {e}")))?;
                    discarded += 1;
                }
                sc.delete_entry(&mut batch, index, hash)
                    .map_err(|e| ConsensusError::GeneralOwned(format!("cannot delete index entry: {e}")))?;
            }
        }
        // Shift what remains back down. Ascending order, so a move never lands on an entry that
        // has not been vacated yet — the mirror of the highest-first rule the backfill shifts by.
        for index in base_index..=tip {
            if let Ok(hash) = sc.get_by_index(index) {
                sc.rebase_entry(&mut batch, index, hash, index - base_index)
                    .map_err(|e| ConsensusError::GeneralOwned(format!("cannot rebase index entry: {e}")))?;
            }
        }
        sc.set_highest_index(&mut batch, tip - base_index)
            .map_err(|e| ConsensusError::GeneralOwned(format!("cannot set highest index: {e}")))?;
        self.db.write(batch).map_err(|e| ConsensusError::GeneralOwned(format!("cannot commit history purge: {e}")))?;
        Ok(discarded)
    }

    pub fn new(
        db: Arc<DB>,
        config: Arc<Config>,
        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
        tx_script_cache_counters: Arc<TxScriptCacheCounters>,
        creation_timestamp: u64,
        mining_rules: Arc<MiningRules>,
    ) -> Self {
        let params = &config.params;
        let perf_params = &config.perf;
        let is_consensus_exiting: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        //
        // Storage layer
        //

        let storage = ConsensusStorage::new(db.clone(), config.clone());

        //
        // Services and managers
        //

        let services = ConsensusServices::new(
            db.clone(),
            storage.clone(),
            config.clone(),
            tx_script_cache_counters,
            is_consensus_exiting.clone(),
        );

        //
        // Processor channels
        //

        let (sender, receiver): (CrossbeamSender<BlockProcessingMessage>, CrossbeamReceiver<BlockProcessingMessage>) =
            unbounded_crossbeam();
        let (body_sender, body_receiver): (CrossbeamSender<BlockProcessingMessage>, CrossbeamReceiver<BlockProcessingMessage>) =
            unbounded_crossbeam();
        let (virtual_sender, virtual_receiver): (
            CrossbeamSender<VirtualStateProcessingMessage>,
            CrossbeamReceiver<VirtualStateProcessingMessage>,
        ) = unbounded_crossbeam();
        let (pruning_sender, pruning_receiver): (
            CrossbeamSender<PruningProcessingMessage>,
            CrossbeamReceiver<PruningProcessingMessage>,
        ) = bounded_crossbeam(2);

        //
        // Thread-pools
        //

        // Pool for header and body processors
        let block_processors_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(perf_params.block_processors_num_threads)
                .thread_name(|i| format!("block-pool-{i}"))
                .build()
                .unwrap(),
        );
        // We need a dedicated thread-pool for the virtual processor to avoid possible deadlocks probably caused by the
        // combined usage of `par_iter` (in virtual processor) and `rayon::spawn` (in header/body processors).
        // See for instance https://github.com/rayon-rs/rayon/issues/690
        let virtual_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(perf_params.virtual_processor_num_threads)
                .thread_name(|i| format!("virtual-pool-{i}"))
                .build()
                .unwrap(),
        );

        //
        // Pipeline processors
        //

        let header_processor = Arc::new(HeaderProcessor::new(
            receiver,
            body_sender,
            block_processors_pool.clone(),
            params,
            db.clone(),
            &storage,
            &services,
            pruning_lock.clone(),
            counters.clone(),
        ));

        let body_processor = Arc::new(BlockBodyProcessor::new(
            body_receiver,
            virtual_sender,
            block_processors_pool,
            params,
            db.clone(),
            &storage,
            &services,
            pruning_lock.clone(),
            notification_root.clone(),
            counters.clone(),
        ));

        let virtual_processor = Arc::new(VirtualStateProcessor::new(
            virtual_receiver,
            pruning_sender,
            pruning_receiver.clone(),
            virtual_pool,
            params,
            db.clone(),
            &storage,
            &services,
            pruning_lock.clone(),
            notification_root.clone(),
            counters.clone(),
            mining_rules,
        ));

        let pruning_processor = Arc::new(PruningProcessor::new(
            pruning_receiver,
            db.clone(),
            &storage,
            &services,
            pruning_lock.clone(),
            config.clone(),
            is_consensus_exiting.clone(),
        ));

        // Ensure the relations stores are initialized
        header_processor.init();
        // Ensure that some pruning point is registered
        virtual_processor.init();

        // Ensure that genesis was processed
        if config.process_genesis {
            header_processor.process_genesis();
            body_processor.process_genesis();
            virtual_processor.process_genesis();
        }

        let this = Self {
            db,
            block_sender: sender,
            header_processor,
            body_processor,
            virtual_processor,
            pruning_processor,
            storage,
            services,
            pruning_lock,
            notification_root,
            counters,
            config,
            creation_timestamp,
            is_consensus_exiting,
        };

        // Run database upgrades if any
        this.run_database_upgrades();

        this
    }

    /// A procedure for calling database upgrades which are self-contained (i.e., do not require knowing the DB version)
    fn run_database_upgrades(&self) {
        // Upgrade to initialize the new retention root field correctly
        self.retention_root_database_upgrade();
        self.consensus_transitional_flags_upgrade();
    }

    fn retention_root_database_upgrade(&self) {
        let mut pruning_point_store = self.pruning_point_store.write();
        if pruning_point_store.retention_period_root().optional().unwrap().is_none() {
            let mut batch = rocksdb::WriteBatch::default();
            if self.config.is_archival {
                // The retention checkpoint is what was previously known as history root
                let retention_checkpoint = pruning_point_store.retention_checkpoint().unwrap();
                pruning_point_store.set_retention_period_root(&mut batch, retention_checkpoint).unwrap();
            } else {
                // For non-archival nodes the retention root was the pruning point
                let pruning_point = pruning_point_store.pruning_point().unwrap();
                pruning_point_store.set_retention_period_root(&mut batch, pruning_point).unwrap();
            }
            self.db.write(batch).unwrap();
        }
    }

    fn consensus_transitional_flags_upgrade(&self) {
        // Write the defaults to the internal storage so they will remain in cache
        // *For a new staging consensus these flags will be updated again explicitly*
        let mut batch = rocksdb::WriteBatch::default();
        let mut pruning_meta_write = self.storage.pruning_meta_stores.write();
        if pruning_meta_write.is_anticone_fully_synced() {
            pruning_meta_write.set_body_missing_anticone(&mut batch, vec![]).unwrap();
        }
        if pruning_meta_write.pruning_utxoset_stable_flag() {
            pruning_meta_write.set_pruning_utxoset_stable_flag(&mut batch, true).unwrap();
        }
        if pruning_meta_write.pruning_smt_stable_flag() {
            pruning_meta_write.set_pruning_smt_stable_flag(&mut batch, true).unwrap();
        }
        self.db.write(batch).unwrap();
    }

    pub fn run_processors(&self) -> Vec<JoinHandle<()>> {
        // Spawn the asynchronous processors.
        let header_processor = self.header_processor.clone();
        let body_processor = self.body_processor.clone();
        let virtual_processor = self.virtual_processor.clone();
        let pruning_processor = self.pruning_processor.clone();

        vec![
            thread::Builder::new().name("header-processor".to_string()).spawn(move || header_processor.worker()).unwrap(),
            thread::Builder::new().name("body-processor".to_string()).spawn(move || body_processor.worker()).unwrap(),
            thread::Builder::new().name("virtual-processor".to_string()).spawn(move || virtual_processor.worker()).unwrap(),
            thread::Builder::new().name("pruning-processor".to_string()).spawn(move || pruning_processor.worker()).unwrap(),
        ]
    }

    /// Acquires a consensus session, blocking data-pruning from occurring until released
    pub fn acquire_session(&self) -> SessionReadGuard<'_> {
        self.pruning_lock.blocking_read()
    }

    fn validate_and_insert_block_impl(
        &self,
        task: BlockTask,
    ) -> (
        impl Future<Output = BlockProcessResult<BlockStatus>> + 'static,
        impl Future<Output = BlockProcessResult<BlockStatus>> + 'static,
    ) {
        let (btx, brx): (BlockResultSender, _) = oneshot::channel();
        let (vtx, vrx): (BlockResultSender, _) = oneshot::channel();
        self.block_sender.send(BlockProcessingMessage::Process(task, btx, vtx)).unwrap();
        self.counters.blocks_submitted.fetch_add(1, Ordering::Relaxed);
        (async { brx.await.unwrap() }, async { vrx.await.unwrap() })
    }

    pub fn body_tips(&self) -> BlockHashSet {
        self.body_tips_store.read().get().unwrap().read().clone()
    }

    pub fn block_status(&self, hash: Hash) -> BlockStatus {
        self.statuses_store.read().get(hash).unwrap()
    }

    pub fn session_lock(&self) -> SessionLock {
        self.pruning_lock.clone()
    }

    pub fn notification_root(&self) -> Arc<ConsensusNotificationRoot> {
        self.notification_root.clone()
    }

    pub fn processing_counters(&self) -> &Arc<ProcessingCounters> {
        &self.counters
    }

    pub fn signal_exit(&self) {
        self.is_consensus_exiting.store(true, Ordering::Relaxed);
        self.block_sender.send(BlockProcessingMessage::Exit).unwrap();
    }

    pub fn shutdown(&self, wait_handles: Vec<JoinHandle<()>>) {
        self.signal_exit();
        // Wait for async consensus processors to exit
        for handle in wait_handles {
            handle.join().unwrap();
        }
    }

    /// Validates that a valid block *header* exists for `hash`
    fn validate_block_exists(&self, hash: Hash) -> Result<(), ConsensusError> {
        if match self.statuses_store.read().get(hash).optional().unwrap() {
            Some(status) => status.is_valid(),
            None => false,
        } {
            Ok(())
        } else {
            Err(ConsensusError::HeaderNotFound(hash))
        }
    }

    fn estimate_network_hashes_per_second_impl(&self, ghostdag_data: &GhostdagData, window_size: usize) -> ConsensusResult<u64> {
        let window = match self.services.window_manager.block_window(ghostdag_data, WindowType::VaryingWindow(window_size)) {
            Ok(w) => w,
            Err(RuleError::InsufficientDaaWindowSize(s)) => return Err(DifficultyError::InsufficientWindowData(s).into()),
            Err(e) => panic!("unexpected error: {e}"),
        };
        Ok(self.services.window_manager.estimate_network_hashes_per_second(window)?)
    }

    fn pruning_point_compact_headers(&self) -> Vec<(Hash, CompactHeaderData)> {
        // PRUNE SAFETY: index is monotonic and past pruning point headers are expected permanently
        let (pruning_point, pruning_index) = self.pruning_point_store.read().pruning_point_and_index().unwrap();
        (0..pruning_index)
            .map(|index| self.past_pruning_points_store.get(index).unwrap())
            .chain(once(pruning_point))
            .map(|hash| (hash, self.headers_store.get_compact_header_data(hash).unwrap()))
            .collect_vec()
    }

    /// See: intrusive_pruning_point_update implementation below for details
    pub fn intrusive_pruning_point_store_writes(
        &self,
        new_pruning_point: Hash,
        syncer_sink: Hash,
        pruning_points_to_add: VecDeque<Hash>,
    ) -> ConsensusResult<()> {
        let mut batch = WriteBatch::default();
        let mut pruning_point_write = self.pruning_point_store.write();
        let old_pp_index = pruning_point_write.pruning_point_index().unwrap();
        let retention_period_root = pruning_point_write.retention_period_root().unwrap();

        let new_pp_index = old_pp_index + pruning_points_to_add.len() as u64;
        pruning_point_write.set_batch(&mut batch, new_pruning_point, new_pp_index).unwrap();
        for (i, &past_pp) in pruning_points_to_add.iter().rev().enumerate() {
            self.past_pruning_points_store.insert_batch(&mut batch, old_pp_index + i as u64 + 1, past_pp).unwrap();
        }

        // For archival nodes, keep the retention root in place
        if !self.config.is_archival {
            let adjusted_retention_period_root =
                self.pruning_processor.advance_retention_period_root(retention_period_root, new_pruning_point);
            pruning_point_write.set_retention_period_root(&mut batch, adjusted_retention_period_root).unwrap();
        }

        // Update virtual state based to the new pruning point
        // Updating of the utxoset is done separately as it requires downloading the new utxoset in its entirety.
        let virtual_parents = vec![new_pruning_point];
        let virtual_state = Arc::new(VirtualState {
            parents: virtual_parents.clone(),
            ghostdag_data: self.services.ghostdag_manager.ghostdag(&virtual_parents),
            ..VirtualState::default()
        });
        self.virtual_stores.write().state.set_batch(&mut batch, virtual_state).unwrap();
        // Remove old body tips and insert pruning point as the current tip
        self.body_tips_store.write().delete_all_tips(&mut batch).unwrap();
        self.body_tips_store.write().init_batch(&mut batch, &virtual_parents).unwrap();
        // Update selected_chain
        self.selected_chain_store.write().init_with_pruning_point(&mut batch, new_pruning_point).unwrap();
        // It is important to set these flags to false together with writing the batch, in case the node crashes suddenly before syncing starts
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        pruning_meta_write.set_pruning_utxoset_stable_flag(&mut batch, false).unwrap();
        pruning_meta_write.set_pruning_smt_stable_flag(&mut batch, false).unwrap();
        // The shielded flag MUST be lowered here too. Adopting a syncer's pruning point
        // invalidates the shielded state exactly as it invalidates the UTXO set and the SMT:
        // this node holds no frontier, nullifier set, supply totals or anchor index for the new
        // pruning point. Omitting it meant the flag kept its fail-open default of `true`
        // (`pruning_meta.rs`), so `IbdType::Sync` took the `else` branch at `ibd/flow.rs` and
        // *marked the missing state stable* instead of downloading it. The node then disqualified
        // every chain block above the pruning point — "N disqualified vs 0 valid chain blocks",
        // virtual frozen, headers still flowing — with no retry path, because it had recorded the
        // absent state as complete. Reported live 2026-07-31 by a node stuck at DAA 260,547
        // against a pruning point at 260,461.
        pruning_meta_write.set_pruning_shielded_stable_flag(&mut batch, false).unwrap();
        drop(pruning_meta_write);
        // Store the currently bodyless anticone from the POV of the syncer, for trusted body validation at a later stage.
        let mut anticone = self.services.dag_traversal_manager.anticone(new_pruning_point, [syncer_sink].into_iter(), None)?;
        // Add the pruning point itself which is also missing a body
        anticone.push(new_pruning_point);
        self.pruning_meta_stores.write().set_body_missing_anticone(&mut batch, anticone).unwrap();
        self.db.write(batch).unwrap();
        drop(pruning_point_write);
        Ok(())
    }

    /// Verify that the new pruning point can be safely imported
    /// and return all new pruning point on path to it that needs to be updated in consensus
    fn get_and_verify_path_to_new_pruning_point(&self, new_pruning_point: Hash, syncer_sink: Hash) -> ConsensusResult<VecDeque<Hash>> {
        // Let B.sp denote the selected parent of a block B, let f be the finality depth, and let p be the pruning depth.
        // The new pruning point P can be "finalized" into consensus if:
        // 1) P satisfies P.blue_score>Nf and selected_parent(P).blue_score<=NF
        // where N is some integer (i.e. it is a valid pruning point based on score)
        let Ok(candidate_ghostdag_data) = self.get_ghostdag_data(new_pruning_point) else {
            return Err(ConsensusError::General(
                "Catchup cannot be continued since the syncer pruning point could not be confirmed to be a valid pruning point",
            ));
        };
        let Ok(selected_parent_ghostdag_data) = self.get_ghostdag_data(candidate_ghostdag_data.selected_parent) else {
            return Err(ConsensusError::General(
                "Catchup cannot be continued since the syncer pruning point could not be confirmed to be a valid pruning point",
            ));
        };
        self.services
            .pruning_point_manager
            .is_pruning_sample(
                candidate_ghostdag_data.blue_score,
                selected_parent_ghostdag_data.blue_score,
                self.config.params.finality_depth(),
            )
            .then_some(())
            .ok_or(ConsensusError::General("the alleged pruning point is not a valid pruning point, aborting catchup attempt"))?;

        // 2) There are sufficient headers built on top of it, specifically,
        // a header is validated whose blue_score is greater than P.B+p:
        let syncer_pp_bscore = self.get_header(new_pruning_point).unwrap().blue_score;
        let syncer_virtual_bscore = self.get_header(syncer_sink).unwrap().blue_score;
        if syncer_virtual_bscore < syncer_pp_bscore + self.config.pruning_depth() {
            return Err(ConsensusError::General("declared pruning point is not of sufficient depth"));
        }
        // 3) The syncer pruning point is on the selected chain from that header.
        if !self.services.reachability_service.is_chain_ancestor_of(new_pruning_point, syncer_sink) {
            return Err(ConsensusError::General("new pruning point is not in the past of syncer sink"));
        }
        info!("Setting {new_pruning_point} as the pruning point");
        // 4) The pruning points declared on headers on that path must be consistent with those already known by the node:
        let pruning_point_read = self.pruning_point_store.read();
        let old_pruning_point = pruning_point_read.pruning_point().unwrap();

        // Note that the function below also updates the pruning samples,
        // and implicitly confirms any pruning point pointed at en route to virtual is a pruning sample.
        // it is emphasized that updating pruning samples for individual blocks is not harmful
        // even if the verification ultimately does not succeed.
        let mut pruning_points_to_add =
            self.services.pruning_point_manager.pruning_points_on_path_to_syncer_sink(old_pruning_point, syncer_sink).map_err(
                |e: PruningImportError| {
                    ConsensusError::GeneralOwned(format!("pruning points en route to syncer sink do not form a valid chain: {}", e))
                },
            )?;
        // next we filter the returned list so it contains only the pruning point that must be introduced to consensus

        // Remove the excess pruning points before the old pruning point
        while let Some(past_pp) = pruning_points_to_add.pop_back() {
            if past_pp == old_pruning_point {
                break;
            }
        }
        if pruning_points_to_add.is_empty() {
            return Err(ConsensusError::General("old pruning points is inconsistent with synced headers"));
        }
        // Remove the excess pruning points beyond the new pruning_point
        while let Some(&future_pp) = pruning_points_to_add.front() {
            if future_pp == new_pruning_point {
                break;
            }
            // Here we only pop_front after checking as we want the new pruning_point to stay in the list
            pruning_points_to_add.pop_front();
        }
        if pruning_points_to_add.is_empty() {
            return Err(ConsensusError::General("new pruning point is inconsistent with synced headers"));
        }
        Ok(pruning_points_to_add)
    }

    fn validate_transaction_for_non_contextual_masses(&self, transaction: &Transaction) -> TxResult<()> {
        if transaction.is_coinbase() {
            return Ok(());
        }

        if transaction.inputs.len() > self.config.params.max_tx_inputs {
            return Err(TxRuleError::TooManyInputs(transaction.inputs.len(), self.config.params.max_tx_inputs));
        }

        if transaction.outputs.len() > self.config.params.max_tx_outputs {
            return Err(TxRuleError::TooManyOutputs(transaction.outputs.len(), self.config.params.max_tx_outputs));
        }

        if ComputeCommit::version_expects_compute_budget_field(transaction.version) {
            for (i, input) in transaction.inputs.iter().enumerate() {
                if let Some(sig_op_count) = input.compute_commit.sig_op_count() {
                    return Err(TxRuleError::SigopCountInV1(i, sig_op_count));
                }
            }
        } else {
            for (i, input) in transaction.inputs.iter().enumerate() {
                if let Some(compute_budget) = input.compute_commit.compute_budget() {
                    return Err(TxRuleError::ComputeBudgetInV0(i, compute_budget));
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "test-smt-pruning-diagnostics")]
    #[doc(hidden)]
    /// Diagnostic invariant helper: count versioned SMT entries at or below a
    /// pruning cutoff. Used by integration tests to catch stale pruning data.
    pub fn count_stale_smt_entries(&self, cutoff_blue_score: u64) -> StoreResult<StaleSmtEntriesCount> {
        self.storage.smt_stores.count_entries_at_or_below(cutoff_blue_score)
    }

    #[cfg(feature = "test-smt-pruning-diagnostics")]
    #[doc(hidden)]
    /// Diagnostic invariant helper: return whether the pruning checkpoint has
    /// caught up with the retention-period root, which marks pruning complete.
    pub fn is_pruning_stable(&self) -> StoreResult<bool> {
        let pruning_point_read = self.pruning_point_store.read();
        Ok(pruning_point_read.retention_checkpoint()? == pruning_point_read.retention_period_root()?)
    }
}

impl ConsensusApi for Consensus {
    fn build_block_template(
        &self,
        miner_data: MinerData,
        tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        self.virtual_processor.build_block_template(miner_data, tx_selector, build_mode)
    }

    fn validate_and_insert_block(&self, block: Block) -> BlockValidationFutures {
        let (block_task, virtual_state_task) = self.validate_and_insert_block_impl(BlockTask::Ordinary { block });
        BlockValidationFutures { block_task: Box::pin(block_task), virtual_state_task: Box::pin(virtual_state_task) }
    }

    fn get_shielded_tree_frontier(&self, block: Hash) -> ConsensusResult<(u64, Option<[u8; 32]>, Vec<[u8; 32]>)> {
        let fs = self
            .virtual_processor
            .shielded_frontier_at(block)
            .map_err(|e| ConsensusError::GeneralOwned(format!("shielded frontier for {block}: {e}")))?;
        Ok((fs.size, fs.leaf, fs.ommers))
    }

    fn get_shielded_supply_totals(&self, block: Hash) -> ConsensusResult<(u128, u128, u128)> {
        let totals = self
            .virtual_processor
            .shielded_supply_totals_at(block)
            .map_err(|e| ConsensusError::GeneralOwned(format!("shielded supply for {block}: {e}")))?;
        let burns = self
            .virtual_processor
            .shielded_burn_total_at(block)
            .map_err(|e| ConsensusError::GeneralOwned(format!("shielded burns for {block}: {e}")))?;
        Ok((totals.cumulative_coinbase, totals.cumulative_fees, burns))
    }

    fn get_shielded_chain_block_data(&self, block: Hash) -> ConsensusResult<kaspa_consensus_core::api::ShieldedChainBlockData> {
        self.virtual_processor.shielded_chain_block_data(block).map_err(ConsensusError::GeneralOwned)
    }

    fn get_shielded_chain_range(&self, low: Hash, limit: usize) -> ConsensusResult<Option<Vec<Hash>>> {
        // Hold the pruning lock for the whole read so the index cannot be mutated between
        // resolving `low` and reading the range above it.
        let _guard = self.pruning_lock.blocking_read();
        let sc_read = self.storage.selected_chain_store.read();

        // `apply_changes` deletes the index entry of every block it removes from the selected
        // chain, so a hit here means `low` is on the chain *now*. A miss is a reorg (or a legacy
        // DB that pruned its index) — either way the caller must re-anchor.
        let Some(low_index) = sc_read.get_by_hash(low).optional().unwrap() else {
            return Ok(None);
        };
        let tip_index = sc_read.get_tip().unwrap().0;

        let high_index = tip_index.min(low_index.saturating_add(limit as u64));
        let mut hashes = Vec::with_capacity((high_index.saturating_sub(low_index)) as usize);
        for index in (low_index + 1)..=high_index {
            // A hole cannot occur while the pruning lock is held, but the index is also written
            // by reorgs; stop cleanly rather than panicking if one is observed.
            let Some(hash) = sc_read.get_by_index(index).optional().unwrap() else { break };
            hashes.push(hash);
        }
        Ok(Some(hashes))
    }

    fn get_shielded_frontier_block_below_daa(&self, daa: u64) -> ConsensusResult<Option<Hash>> {
        // Below the pruning point one chain block in ~1,000 keeps a frontier checkpoint, so a
        // bounded backward search from the located block always reaches one; above it every
        // block has one and the first probe hits.
        const FRONTIER_SEARCH: u64 = 2100;
        let _guard = self.pruning_lock.blocking_read();
        let sc = self.storage.selected_chain_store.read();
        // Index 0 is the history base (genesis on a complete-history node).
        let low = 0u64;
        let Some((tip, _)) = sc.get_tip().optional().unwrap() else { return Ok(None) };
        let daa_of = |index: u64| -> Option<(Hash, u64)> {
            let hash = sc.get_by_index(index).optional().unwrap()?;
            // Header when retained, else the archive record (headers are gone below the
            // pruning point; the archive keeps hash/blue/daa for every chain block).
            let daa = match self.headers_store.get_daa_score(hash) {
                Ok(d) => d,
                Err(_) => self.virtual_processor.shielded_chain_block_data(hash).ok()?.daa_score,
            };
            Some((hash, daa))
        };
        // First chain index whose DAA reaches `daa`.
        let (mut lo, mut hi) = (low, tip + 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match daa_of(mid) {
                Some((_, d)) if d >= daa => hi = mid,
                Some(_) => lo = mid + 1,
                None => return Ok(None),
            }
        }
        if lo == low {
            // Nothing strictly below `daa` in the index: the caller is older than this node's
            // history base and must anchor a full scan instead.
            return Ok(None);
        }
        // `lo - 1` is the last block strictly below; walk back to one with a retained frontier.
        let mut index = lo - 1;
        for _ in 0..FRONTIER_SEARCH {
            let Some(hash) = sc.get_by_index(index).optional().unwrap() else { return Ok(None) };
            if self.virtual_processor.shielded_frontier_at(hash).is_ok() {
                return Ok(Some(hash));
            }
            if index == low {
                return Ok(None);
            }
            index -= 1;
        }
        Ok(None)
    }

    fn get_shielded_history_base(&self) -> Hash {
        let _guard = self.pruning_lock.blocking_read();
        let sc = self.storage.selected_chain_store.read();
        sc.get_by_index(0).unwrap_or_else(|_| self.config.genesis.hash)
    }

    fn get_shielded_history_status(&self) -> ConsensusResult<(u64, bool)> {
        let _guard = self.pruning_lock.blocking_read();
        let sc = self.storage.selected_chain_store.read();
        // Index 0 is the oldest block this node can ENUMERATE, which is the real limit on what
        // it can serve: a wallet reaches history through `get_shielded_chain_range`, which
        // resolves its start block through this index. Holding records without index entries
        // still answers "cannot find header".
        let Ok(base) = sc.get_by_index(0) else {
            // No index at all: nothing below the pruning point is servable.
            return Ok((0, false));
        };
        // "The index reaches genesis" is only half of `complete`. A backfill writes the index
        // entries FIRST and verifies the replayed leaves against the PoW-anchored frontier
        // AFTERWARDS (minutes to an hour on a small box), and a Mismatch then purges the range.
        // For that whole window the index already reaches genesis while nothing has been
        // checked — observed live 2026-08-29: `history_complete: true` at 20% of the
        // verification replay. So a node whose index is even partly peer-supplied must also
        // hold a verified verdict; a node that built its whole index itself needs nothing more.
        let meta = self.pruning_meta_stores.read();
        let verified_or_own = !meta.shielded_history_backfilled() || meta.shielded_history_verified_base().is_some();
        drop(meta);
        let complete = base == self.config.genesis.hash && verified_or_own;
        // Read the DAA score from the SCAN RECORD, not the header. A backfilled block below the
        // pruning point has a scan record and no header — reading the header here would fail on
        // exactly the nodes this field exists to describe.
        let sm = self.virtual_processor.shielded_state_manager_ref();
        let daa = match sm.scan_block(base) {
            Ok(Some(d)) => d.daa_score,
            // Fall back to the header for a node whose base is its own pruning point.
            _ => self.headers_store.get_compact_header_data(base).map(|h| h.daa_score).unwrap_or(0),
        };
        Ok((daa, complete))
    }

    fn backfill_shielded_history(
        &self,
        anchor: Hash,
        anchor_index: u64,
        records: &[(u64, kaspa_consensus_core::api::ShieldedChainBlockData)],
    ) -> ConsensusResult<(u64, u64)> {
        use crate::model::stores::shielded::ShieldedScanBlockData;
        if records.is_empty() {
            return Ok((0, 0));
        }
        // NO pruning-lock acquisition here, deliberately.
        //
        // This runs inside the IBD flow, which holds an owned pruning-lock READ guard for its
        // whole duration (the `session` it passes in IS that guard). Asking for the WRITE side of
        // the same lock from underneath it can never be granted: the read guard is not released
        // until IBD finishes, and IBD does not finish until this returns. Deadlock, with every
        // thread idle and the connection healthy — which is exactly how it presented, and why the
        // 120s dequeue timeout never fired: the wait was on a lock, not on the peer.
        //
        // The caller's read guard is also what makes this safe: it already pins the pruning point
        // for the duration, so the index cannot move under us, and `selected_chain_store.write()`
        // below still serialises the mutation itself.
        let mut sc = self.storage.selected_chain_store.write();

        // Align the two numbering spaces from the ANCHOR, which both sides know by hash.
        //
        // Every earlier attempt tried to INFER this offset from the chunk's contents and could
        // not, because the server's walk is strictly BELOW the anchor: the one block whose index
        // both sides know is the one block the chunk never contains. Searching for it missed
        // every time, each chunk returned (0, 0) having written nothing, and the loop re-anchored
        // downward to genesis reporting success. Measured 2026-08-08: 34 minutes, 0 bytes.
        //
        // The anchor's index on the server now rides in the chunk, and its index here is a hash
        // lookup, so the offset is a subtraction rather than a guess. On the first chunk the
        // anchor is our pruning point at local index 0, giving shift = its genesis index; after
        // that the anchor is a block we wrote at its genesis index, giving shift = 0 and no
        // further rebase.
        let (local_tip, _) = sc.get_tip().unwrap();
        let Some(local_anchor_index) = sc.get_by_hash(anchor).optional().unwrap() else {
            return Err(ConsensusError::GeneralOwned(format!(
                "shielded history anchor {anchor} is not in this node's chain index; cannot place records below it"
            )));
        };
        let shift = anchor_index.saturating_sub(local_anchor_index);
        // At or above the anchor is our own validated range; ours is authoritative.
        let ours_from = anchor_index;

        let mut batch = rocksdb::WriteBatch::default();
        if shift > 0 {
            // Rebase highest-first so a shift never lands on an entry not yet moved.
            for i in (0..=local_tip).rev() {
                if let Ok(h) = sc.get_by_index(i) {
                    sc.rebase_entry(&mut batch, i, h, i + shift).unwrap();
                }
            }
            sc.set_highest_index(&mut batch, local_tip + shift).unwrap();
        }

        let (mut idx_written, mut rec_written) = (0u64, 0u64);
        for (index, r) in records.iter() {
            if *index > ours_from {
                continue; // above the anchor is our own validated range; ours is authoritative
            }
            // The anchor's own record is the exception, and dropping it was a real bug. Its INDEX
            // entry we already hold, so we must not rewrite it — but its scan RECORD we may not
            // hold at all, because adopting a block as a pruning point seeds the tree, supply and
            // anchor indexes and never writes a record. Its leaves are nonetheless part of the
            // frontier every replay is checked against, so omitting them makes an otherwise
            // perfect transfer fail by exactly one block. Measured 2026-08-08: 2,007,143 replayed
            // vs 2,007,184 anchored — a 41-leaf gap that discarded 404,928 good records.
            if *index < ours_from {
                sc.write_entry(&mut batch, *index, r.hash).unwrap();
                idx_written += 1;
            }
            if self.virtual_processor.shielded_state_manager_ref().scan_block(r.hash).unwrap_or(None).is_none() {
                let accepted = r
                    .accepted_actions
                    .iter()
                    .zip(r.accepted_txids.iter())
                    .map(|(action_bytes, txid)| crate::model::stores::shielded::ShieldedScanTx {
                        txid: *txid,
                        action_bytes: action_bytes.clone(),
                    })
                    .collect();
                let data = ShieldedScanBlockData {
                    blue_score: r.blue_score,
                    daa_score: r.daa_score,
                    timestamp: r.timestamp,
                    coinbase_txid: r.coinbase_txid,
                    coinbase_outputs: r.coinbase_outputs.clone(),
                    coinbase_commitments: r.coinbase_commitments.clone(),
                    accepted,
                };
                self.virtual_processor.shielded_state_manager_ref().persist_backfilled_scan(&mut batch, r.hash, data).unwrap();
                rec_written += 1;
            }
        }
        if idx_written > 0 {
            // Same batch as the entries, so the index can never reach genesis on peer data
            // without the flag that says so (see `get_shielded_history_status`). No lock-order
            // hazard with the pruning processor: it needs the pruning lock for WRITE, and IBD —
            // which this runs inside — holds it for read for its whole duration.
            self.pruning_meta_stores.write().set_shielded_history_backfilled(&mut batch).unwrap();
        }
        self.db.write(batch).unwrap();
        Ok((idx_written, rec_written))
    }

    fn verify_shielded_history(&self, base: Hash) -> ConsensusResult<kaspa_consensus_core::api::ShieldedHistoryVerdict> {
        use crate::model::stores::shielded::ShieldedScanBlockData;
        use crate::processes::shielded::{ReplayError, ShieldedStateManager, coinbase_notes_from_outputs};
        use kaspa_consensus_core::api::ShieldedHistoryVerdict;
        use rayon::prelude::*;

        let sm = self.virtual_processor.shielded_state_manager_ref();

        // The value being checked against, resolved FIRST. It is this node's own frontier at its
        // pre-backfill base — PoW-anchored, and never learned from the peer under test. Without
        // it there is nothing to compare to, and replaying a million blocks would be wasted work.
        let expected = match sm.frontier_at(base) {
            Ok(f) => f,
            Err(e) => return Ok(ShieldedHistoryVerdict::Unverifiable { reason: format!("no anchored frontier at {base}: {e}") }),
        };

        // No pruning-lock acquisition, for the same reason as the ingest: the p2p caller runs
        // inside the IBD flow, which already holds the read side for its whole duration, and
        // re-taking it here would queue behind any pending writer that the caller's own guard is
        // blocking. That guard is also what keeps the index stable across this walk. The startup
        // `--verify-shielded-history` path holds no guard, but it runs once before any service
        // starts, so nothing is moving the index there either.
        let sc = self.storage.selected_chain_store.read();
        let Some(base_index) = sc.get_by_hash(base).optional().unwrap() else {
            return Ok(ShieldedHistoryVerdict::Unverifiable { reason: format!("base {base} is not in the selected chain index") });
        };
        if base_index == 0 {
            return Ok(ShieldedHistoryVerdict::Unverifiable {
                reason: "no history was backfilled below the base; nothing to verify".to_owned(),
            });
        }

        let seed_activation = self.config.shielded_coinbase_seed_activation;
        // Replay genesis..=base. `base` is INCLUDED because `frontier_at(base)` is the tree after
        // that block's own leaves were appended; stopping one short would mismatch on honest data.
        //
        // Read in batches, derive in PARALLEL, yield in order. The replay is ~95% coinbase note
        // commitments: measured 404,928 records in ~30 minutes, 4.4 ms each over 3.46 notes per
        // record, i.e. ~1.28 ms per Sinsemilla commitment, against ~0.2 s total for all 2.24M tree
        // appends. Those derivations are independent, so they parallelise cleanly; the tree
        // appends stay strictly ordered because the frontier depends on leaf order. Batching keeps
        // memory bounded — the whole archive is ~255 MB and must never be materialised at once.
        //
        // (The other obvious win, batching the per-note `to_affine` inversions with Montgomery's
        // trick, is NOT reachable: orchard's `NoteCommitment` keeps its Pallas point `pub(crate)`
        // unless the `unstable-voting-circuits` feature is on, so the projective points cannot be
        // collected for a batch inversion from here.)
        const REPLAY_BATCH: usize = 4096;
        // Leave a core for everything else.
        //
        // The per-block coinbase derivations below are embarrassingly parallel and rayon will
        // otherwise take every core for the whole replay. That was acceptable while this only ran
        // on an operator's explicit `--verify-shielded-history`; shielded history now defaults ON,
        // so every node runs it once on its first sync.
        //
        // MEASURED, and narrower than it first looked. On a 2-core box, 2026-08-22, two fresh
        // syncs of the same chain:
        //
        //   uncapped (2 threads): replay 11.5 min, 4 inbound handshake timeouts
        //   capped   (1 thread):  replay 17.4 min, 4 inbound handshake timeouts, load avg 1.00
        //
        // The cap did NOT reduce handshake timeouts. In both runs half of them fell OUTSIDE the
        // replay window, and the same two peers recurred, so those timeouts are peer- or
        // path-side and were never caused by this code. An earlier version of this comment
        // claimed the replay starved the handshake path; that claim was wrong and is recorded
        // here so it does not get re-derived.
        //
        // The cap is kept on the narrow ground it can actually support: it holds the box at load
        // 1.00 instead of pinning every core for ~12 minutes, on a node that is simultaneously
        // relaying blocks and answering wallets. That is a plausible courtesy, NOT a measured
        // win — block-relay latency and RPC responsiveness under a saturated replay were not
        // measured. The cost is real and known: about +50% replay time, once, on first sync.
        // If someone measures no difference there either, delete this.
        let replay_threads = std::thread::available_parallelism().map(|n| n.get().saturating_sub(1).max(1)).unwrap_or(1);
        let replay_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(replay_threads)
            .thread_name(|i| format!("shielded-replay-{i}"))
            .build()
            .map_err(|e| ConsensusError::GeneralOwned(format!("cannot build shielded replay pool: {e}")))?;
        kaspa_core::info!(
            "shielded history: verifying with {replay_threads} thread(s), leaving a core for p2p"
        );
        let indices: Vec<u64> = (0..=base_index).collect();
        let total_blocks = indices.len() as u64;
        let started = std::time::Instant::now();
        // Atomics, not `Cell`: the replay now runs inside a dedicated rayon pool (see below) and
        // `ThreadPool::install` requires the closure to be `Send`, which a `Cell` is not.
        let done = std::sync::atomic::AtomicU64::new(0);
        // Milliseconds since `started`, so the "report at most every 15s" gate needs no `Instant`
        // in shared state.
        let last_report_ms = std::sync::atomic::AtomicU64::new(0);
        let stream = indices.chunks(REPLAY_BATCH).flat_map(|chunk| {
            // Progress, because this takes minutes and looks exactly like a hang otherwise: the
            // node logs "0 blocks processed" throughout while one pass re-derives ~1.4M coinbase
            // note commitments. Reported on a time interval rather than every batch so a fast
            // machine does not spam, and with an ETA so an operator can decide to wait.
            use std::sync::atomic::Ordering::Relaxed;
            let done_now = done.fetch_add(chunk.len() as u64, Relaxed) + chunk.len() as u64;
            let elapsed_ms = started.elapsed().as_millis() as u64;
            if elapsed_ms.saturating_sub(last_report_ms.load(Relaxed)) >= 15_000 {
                last_report_ms.store(elapsed_ms, Relaxed);
                let pct = done_now as f64 * 100.0 / total_blocks as f64;
                let elapsed = started.elapsed().as_secs_f64();
                let eta = if done_now > 0 { elapsed * (total_blocks - done_now) as f64 / done_now as f64 } else { 0.0 };
                kaspa_core::info!(
                    "shielded history: verifying {:.0}% ({}/{} blocks), about {:.0}s left",
                    pct,
                    done_now,
                    total_blocks,
                    eta
                );
            }
            // Reads stay sequential: RocksDB point lookups are a small fraction of the cost, and
            // keeping them on one thread avoids contending with the derivation workers.
            let raw: Vec<Result<Option<(u64, Hash, ShieldedScanBlockData)>, String>> = chunk
                .iter()
                .map(|&index| {
                    let hash = sc.get_by_index(index).map_err(|e| format!("chain index gap at {index}: {e}"))?;
                    // No record means the block contributed no leaves — a normal state, not a gap,
                    // so it must not abort the replay. Soundness is unaffected: if a block DID
                    // have leaves and the peer withheld its record, skipping it changes the leaf
                    // sequence and the frontier comparison fails, which is what we want.
                    match sm.scan_block(hash).map_err(|e| format!("scan record read failed for {hash}: {e}"))? {
                        Some(d) => Ok(Some((index, hash, d))),
                        None => Ok(None),
                    }
                })
                .collect();
            replay_pool.install(|| {
            raw.into_par_iter()
                .map(|entry| {
                    let Some((index, hash, d)) = entry? else { return Ok((None, Vec::new(), Vec::new())) };
                    // Label only the blocks that become checkpoints. The interval is in CHAIN
                    // INDEX, not DAA score: DAA advances by a block's whole mergeset, so spacing
                    // on it leaves uneven and occasionally huge gaps between anchors.
                    let label = (index % SHIELDED_REPLAY_CHECKPOINT_INTERVAL == 0).then_some(hash);
                    // Prefer the commitments consensus computed and stored. Deriving is the
                    // fallback for records written before that field existed; it uses the SAME
                    // function validation uses, gated on the same fork activation, so a replay
                    // cannot drift from the chain.
                    let coinbase = if !d.coinbase_commitments.is_empty() {
                        d.coinbase_commitments.clone()
                    } else {
                        let outputs: Vec<(&[u8], u64)> = d.coinbase_outputs.iter().map(|(s, v)| (s.as_slice(), *v)).collect();
                        let seed_block = seed_activation.is_active(d.daa_score).then_some(hash);
                        coinbase_notes_from_outputs(d.coinbase_txid, &outputs, seed_block)
                            .map_err(|e| format!("cannot derive coinbase commitments for {hash}: {e:?}"))?
                            .iter()
                            .map(|n| n.commitment.to_bytes())
                            .collect()
                    };
                    Ok((label, coinbase, d.accepted.iter().map(|t| t.action_bytes.clone()).collect()))
                })
                .collect::<Vec<_>>()
            })
        });

        // Capture the frontier at every checkpoint boundary as the replay passes it, but do NOT
        // write any of them yet — see `persist_replayed_frontier`'s safety note. ~1 KB each, one
        // per SHIELDED_REPLAY_CHECKPOINT_INTERVAL blocks, so a 1M-block chain buffers ~1 MB.
        let mut checkpoints: Vec<(Hash, kaspa_shielded_core::tree::FrontierState)> = Vec::new();

        // The replay itself stays SEQUENTIAL — the frontier depends on leaf order, so the tree
        // appends cannot be parallelised. Only the per-block coinbase derivations inside the
        // stream are parallel, and those already run on the bounded `replay_pool` built above.
        //
        // Note this cannot be wrapped in `pool.install(..)` as a whole: the stream carries the
        // progress counters as `Cell`s, which are `!Sync`, so the closure is not `Send`. That is
        // the right shape anyway — the pool belongs around the parallel part, not the serial one.
        let replayed = ShieldedStateManager::replay_frontier_streaming_capturing(stream, |hash, frontier| {
            checkpoints.push((hash, frontier.clone()));
        });

        match replayed {
            Ok((frontier, leaves)) if frontier == expected => {
                // Only now. The whole replay reproduced a frontier this node learned from
                // proof-of-work and never from the peer that supplied the records, so every
                // intermediate frontier on the way to it is equally proven — they are prefixes of
                // the same verified leaf sequence.
                //
                // This is what lets a backfilled node serve history that a THIRD node can verify
                // against it, instead of every verification in the network funnelling back to the
                // few nodes that validated the chain themselves.
                let written = checkpoints.len();
                let sm_w = self.virtual_processor.shielded_state_manager_ref();
                let mut batch = rocksdb::WriteBatch::default();
                for (hash, f) in checkpoints {
                    if let Err(e) = sm_w.persist_replayed_frontier(&mut batch, hash, f) {
                        // Not fatal: the history itself is verified and serving it is unaffected.
                        // Only the ability to ANCHOR someone else's verification is lost.
                        kaspa_core::warn!("shielded history: could not stage frontier checkpoint at {hash}: {e}");
                    }
                }
                // The verdict itself is persisted with the checkpoints: `history_complete` on
                // the wire requires it for any node whose index is partly peer-supplied.
                if let Err(e) = self.pruning_meta_stores.write().set_shielded_history_verified_base(&mut batch, base) {
                    kaspa_core::warn!("shielded history: could not stage the verified marker: {e}");
                }
                if let Err(e) = self.db.write(batch) {
                    kaspa_core::warn!("shielded history: verified, but frontier checkpoints were not written: {e}");
                } else if written > 0 {
                    kaspa_core::info!(
                        "shielded history: wrote {written} tree-frontier checkpoints below the pruning point;                          this node can now anchor another node's history verification"
                    );
                }
                Ok(ShieldedHistoryVerdict::Verified { blocks: base_index + 1, leaves })
            }
            Ok((frontier, leaves)) => Ok(ShieldedHistoryVerdict::Mismatch {
                reason: format!(
                    "replayed {} leaves over {} blocks giving a frontier of size {}, but this node's anchored \
                     frontier at {base} has size {}",
                    leaves,
                    base_index + 1,
                    frontier.size,
                    expected.size
                ),
            }),
            Err(ReplayError::Data(e)) => Ok(ShieldedHistoryVerdict::Mismatch { reason: format!("leaves are not replayable: {e:?}") }),
            // Our own read failed. NOT a mismatch: acting on this as though the data were bad
            // would discard real history because a local read hiccuped.
            Err(ReplayError::Source(reason)) => Ok(ShieldedHistoryVerdict::Unverifiable { reason }),
        }
    }

    fn purge_shielded_history_below(&self, base: Hash) -> ConsensusResult<u64> {
        self.purge_backfilled_shielded_history(base)
    }

    fn get_shielded_history_indexed_below(
        &self,
        anchor: Hash,
        max_blocks: usize,
    ) -> ConsensusResult<(Vec<(u64, kaspa_consensus_core::api::ShieldedChainBlockData)>, bool, u64)> {
        // Serve a history-backfill request: walk THIS node's selected chain downward from
        // `anchor` and return each block's scan record, plus the anchor's own index so the
        // requester can align its (re-based) numbering with ours.
        //
        // The walk must happen here rather than on the requester, because a syncing node cannot
        // enumerate this range itself: `init_with_pruning_point` re-bases its selected-chain
        // index so that its own pruning point is index 0, meaning index spaces do not align
        // between nodes, and its header segment stops far above genesis.
        //
        // Uses only the selected-chain index, which is deliberately retained below the retention
        // root, so this serves correctly from a pruned node with no reachability or block bodies.
        let _guard = self.pruning_lock.blocking_read();
        let sc_read = self.storage.selected_chain_store.read();
        let Some(anchor_index) = sc_read.get_by_hash(anchor).optional().unwrap() else {
            // Not on this node's selected chain (or reorged away): the requester must re-anchor.
            return Ok((Vec::new(), false, 0));
        };
        let mut out = Vec::with_capacity(max_blocks.min(anchor_index as usize) + 1);
        // The anchor block ITSELF first. The requester needs one block it can already locate to
        // learn how its own index maps onto this node's genesis-based numbering; without it the
        // very first chunk has no overlap, the shift is unknowable, and nothing can be written.
        // Costs one record per chunk and makes the walk self-anchoring.
        if let Ok(data) = self.virtual_processor.shielded_chain_block_data(anchor) {
            out.push((anchor_index, data));
        }
        let mut index = anchor_index;
        while out.len() <= max_blocks && index > 0 {
            index -= 1;
            let Some(hash) = sc_read.get_by_index(index).optional().unwrap() else { break };
            // A block with no shielded effects has no record; skip it rather than abort — the
            // requester reconstructs the tree from the `cmx` leaves it does receive.
            // Reuse the same serving path as `GetShieldedBlocks` so a backfilled record is
            // byte-identical to one served live. It already yields an empty record for a block
            // with no shielded effects, and the requester rebuilds the tree from the `cmx`
            // leaves it receives, so empty records are harmless and keep the walk contiguous.
            if let Ok(data) = self.virtual_processor.shielded_chain_block_data(hash) {
                out.push((index, data));
            }
        }
        Ok((out, index == 0, anchor_index))
    }

    fn validate_and_insert_trusted_block(&self, tb: TrustedBlock) -> BlockValidationFutures {
        let (block_task, virtual_state_task) = self.validate_and_insert_block_impl(BlockTask::Trusted { block: tb.block });
        BlockValidationFutures { block_task: Box::pin(block_task), virtual_state_task: Box::pin(virtual_state_task) }
    }

    fn validate_mempool_transaction(&self, transaction: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        self.virtual_processor.validate_mempool_transaction(transaction, args)?;
        Ok(())
    }

    fn validate_mempool_transactions_in_parallel(
        &self,
        transactions: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        self.virtual_processor.validate_mempool_transactions_in_parallel(transactions, args)
    }

    fn populate_mempool_transaction(&self, transaction: &mut MutableTransaction) -> TxResult<()> {
        self.virtual_processor.populate_mempool_transaction(transaction)?;
        Ok(())
    }

    fn populate_mempool_transactions_in_parallel(&self, transactions: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        self.virtual_processor.populate_mempool_transactions_in_parallel(transactions)
    }

    fn calculate_transaction_non_contextual_masses(&self, transaction: &Transaction) -> TxResult<NonContextualMasses> {
        self.validate_transaction_for_non_contextual_masses(transaction)?;
        Ok(self.services.mass_calculator.calc_non_contextual_masses(transaction))
    }

    fn calculate_transaction_contextual_masses(&self, transaction: &MutableTransaction) -> Option<ContextualMasses> {
        self.services.mass_calculator.calc_contextual_masses(&transaction.as_verifiable())
    }

    fn get_stats(&self) -> ConsensusStats {
        // This method is designed to return stats asap and not depend on locks which
        // might take time to acquire
        ConsensusStats {
            block_counts: self.estimate_block_count(),
            // This call acquires the tips store read lock which is expected to be fast. If this
            // turns out to be not fast enough then we should maintain an atomic integer holding this value
            num_tips: self.get_tips_len() as u64,
            virtual_stats: self.lkg_virtual_state.load().as_ref().into(),
        }
    }

    fn get_virtual_daa_score(&self) -> u64 {
        self.lkg_virtual_state.load().daa_score
    }

    fn get_virtual_bits(&self) -> u32 {
        self.lkg_virtual_state.load().bits
    }

    fn get_virtual_past_median_time(&self) -> u64 {
        self.lkg_virtual_state.load().past_median_time
    }

    fn get_virtual_merge_depth_root(&self) -> Option<Hash> {
        // TODO: consider saving the merge depth root as part of virtual state
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let virtual_state = self.lkg_virtual_state.load();
        let virtual_ghostdag_data = &virtual_state.ghostdag_data;
        let root = self.services.depth_manager.calc_merge_depth_root(virtual_ghostdag_data, pruning_point);
        if root.is_origin() { None } else { Some(root) }
    }

    fn get_virtual_merge_depth_blue_work_threshold(&self) -> BlueWorkType {
        // PRUNE SAFETY: merge depth root is never close to being pruned (in terms of block depth)
        self.get_virtual_merge_depth_root().map_or(BlueWorkType::ZERO, |root| self.ghostdag_store.get_blue_work(root).unwrap())
    }

    fn get_sink(&self) -> Hash {
        self.lkg_virtual_state.load().ghostdag_data.selected_parent
    }

    fn get_sink_timestamp(&self) -> u64 {
        self.headers_store.get_timestamp(self.get_sink()).unwrap()
    }

    fn get_sink_blue_score(&self) -> u64 {
        self.headers_store.get_blue_score(self.get_sink()).unwrap()
    }

    fn get_sink_daa_score_timestamp(&self) -> DaaScoreTimestamp {
        let sink = self.get_sink();
        let compact = self.headers_store.get_compact_header_data(sink).unwrap();
        DaaScoreTimestamp { daa_score: compact.daa_score, timestamp: compact.timestamp }
    }

    /// Returns the merge context of `hash`, if the block was already merged by a virtual chain block.
    ///
    /// Return semantics:
    /// - `Err` if `hash` is unknown or outside the retained context required for this query.
    /// - `Ok(None)` if `hash` is known and retained, but is not yet in `past(sink)`.
    /// - `Ok(Some(..))` with the merging chain block context otherwise.
    fn get_merged_block_context(&self, hash: Hash) -> ConsensusResult<Option<MergedBlockContext>> {
        let _guard = self.pruning_lock.blocking_read();

        // Verify the block exists and can be assumed to have relations and reachability data
        self.validate_block_exists(hash)?;

        // Verify that the block is in future(retention root), where Ghostdag data is complete
        if !self.services.reachability_service.is_dag_ancestor_of(self.get_retention_period_root(), hash) {
            return Err(ConsensusError::General("the queried hash does not have retention root in its past"));
        }

        let sink = self.get_sink();

        // Optimization: verify that the block is in past(sink), otherwise the search will fail anyway
        // (means the block was not merged yet by a virtual chain block)
        if !self.services.reachability_service.is_dag_ancestor_of(hash, sink) {
            return Ok(None);
        }

        let mut heap: BinaryHeap<Reverse<SortableBlock>> = BinaryHeap::new();
        let mut visited = BlockHashSet::new();

        for child in self.get_block_children(hash).unwrap() {
            if visited.insert(child) {
                let blue_work = self.ghostdag_store.get_blue_work(child).unwrap();
                heap.push(Reverse(SortableBlock::new(child, blue_work)));
            }
        }

        while let Some(Reverse(SortableBlock { hash: decedent, .. })) = heap.pop() {
            if self.services.reachability_service.is_chain_ancestor_of(decedent, sink) {
                let decedent_data = self.get_ghostdag_data(decedent).unwrap();

                return Ok(if decedent_data.mergeset_blues.contains(&hash) {
                    Some(MergedBlockContext { merging_chain_block_hash: decedent, is_blue: true })
                } else if decedent_data.mergeset_reds.contains(&hash) {
                    Some(MergedBlockContext { merging_chain_block_hash: decedent, is_blue: false })
                } else {
                    // Note: because we are doing a topological BFS up (from `hash` towards virtual), the first chain block
                    // found must also be our merging block, so hash will be either in blues or in reds, rendering this line
                    // unreachable.
                    kaspa_core::warn!("DAG topology inconsistency: {decedent} is expected to be a merging block of {hash}");
                    None
                });
            }

            for child in self.get_block_children(decedent).unwrap() {
                if visited.insert(child) {
                    let blue_work = self.ghostdag_store.get_blue_work(child).unwrap();
                    heap.push(Reverse(SortableBlock::new(child, blue_work)));
                }
            }
        }

        Ok(None)
    }

    fn get_virtual_state_approx_id(&self) -> VirtualStateApproxId {
        self.lkg_virtual_state.load().to_virtual_state_approx_id()
    }

    fn get_retention_period_root(&self) -> Hash {
        self.pruning_point_store.read().retention_period_root().unwrap()
    }

    /// Estimates the number of blocks and headers stored in the node database.
    ///
    /// This is an estimation based on the DAA score difference between the node's `retention root` and `virtual`'s DAA score,
    /// as such, it does not include non-daa blocks, and does not include headers stored as part of the pruning proof.
    fn estimate_block_count(&self) -> BlockCount {
        // PRUNE SAFETY: retention root is always a current or past pruning point which its header is kept permanently
        let retention_period_root_score = self.headers_store.get_daa_score(self.get_retention_period_root()).unwrap();
        let virtual_score = self.get_virtual_daa_score();
        // TODO(relaxed): change virtual's 0 daa initialization, and revert to normal subtraction
        let header_count = self
            .headers_store
            .get_daa_score(self.get_headers_selected_tip())
            .optional()
            .unwrap()
            .unwrap_or(virtual_score)
            .max(virtual_score)
            .saturating_sub(retention_period_root_score);
        let block_count = virtual_score.saturating_sub(retention_period_root_score);
        BlockCount { header_count, block_count }
    }

    fn get_virtual_chain_from_block(&self, low: Hash, chain_path_added_limit: Option<usize>) -> ConsensusResult<ChainPath> {
        // Calculate chain changes between the given `low` and the current sink hash (up to `limit` amount of block hashes).
        // Note:
        // 1) that we explicitly don't
        // do the calculation against the virtual itself so that we
        // won't later need to remove it from the result.
        // 2) supplying `None` as `chain_path_added_limit` will result in the full chain path, with optimized performance.
        let _guard = self.pruning_lock.blocking_read();

        // Verify that the block exists
        self.validate_block_exists(low)?;

        // Verify that retention root is on chain(block)
        self.services
            .reachability_service
            .is_chain_ancestor_of(self.get_retention_period_root(), low)
            .then_some(())
            .ok_or(ConsensusError::General("the queried hash does not have retention root on its chain"))?;

        Ok(self.services.dag_traversal_manager.calculate_chain_path(low, self.get_sink(), chain_path_added_limit))
    }

    /// Returns a Vec of header samples since genesis
    /// ordered by ascending daa_score, first entry is genesis
    fn get_chain_block_samples(&self) -> Vec<DaaScoreTimestamp> {
        // We need consistency between the past pruning points, selected chain and header store reads
        let _guard = self.pruning_lock.blocking_read();

        // Sorted from genesis to latest pruning_point_headers
        let pp_headers = self.pruning_point_compact_headers();
        let step_divisor: usize = 3; // The number of extra samples we'll get from blocks after last pp header
        let prealloc_len = pp_headers.len() + step_divisor + 1;

        let mut sample_headers;

        // Part 1: Add samples from pruning point headers.
        // Note: Kaspa prepended 16 hardcoded pre-genesis (daa 0..1312860, Nov-2021) samples here
        // because its mainnet used a checkpoint-style genesis. ZKas cuts a fresh genesis at
        // daa_score 0, so there is no pre-genesis history — seeding those Kaspa anchors would badly
        // skew daa-score→timestamp estimation. Samples come from pruning point headers and recent
        // chain blocks (Part 2) like every other network.
        sample_headers = Vec::<DaaScoreTimestamp>::with_capacity(prealloc_len);

        for header in pp_headers.iter() {
            sample_headers.push(DaaScoreTimestamp { daa_score: header.1.daa_score, timestamp: header.1.timestamp });
        }

        // Part 2: Add samples from recent chain blocks
        let sc_read = self.storage.selected_chain_store.read();
        let high_index = sc_read.get_tip().unwrap().0;
        // The last pruning point is always expected in the selected chain store. However if due to some reason
        // this is not the case, we prefer not crashing but rather avoid sampling (hence set low index to high index)
        let low_index = sc_read.get_by_hash(pp_headers.last().unwrap().0).optional().unwrap().unwrap_or(high_index);
        let step_size = cmp::max((high_index - low_index) / (step_divisor as u64), 1);

        // We chain `high_index` to make sure we sample sink, and dedup to avoid sampling it twice
        for index in (low_index + step_size..=high_index).step_by(step_size as usize).chain(once(high_index)).dedup() {
            let compact = self
                .storage
                .headers_store
                .get_compact_header_data(sc_read.get_by_index(index).expect("store lock is acquired"))
                .unwrap();
            sample_headers.push(DaaScoreTimestamp { daa_score: compact.daa_score, timestamp: compact.timestamp });
        }

        sample_headers
    }
    fn get_transactions_by_accepting_daa_score(
        &self,
        accepting_daa_score: u64,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        // We need consistency between the acceptance store and the block transaction store,
        let _guard = self.pruning_lock.blocking_read();
        let accepting_block = self
            .virtual_processor
            .find_accepting_chain_block_hash_at_daa_score(accepting_daa_score, self.get_retention_period_root())?;
        self.get_transactions_by_accepting_block(accepting_block, tx_ids, tx_type)
    }

    fn get_transactions_by_block_acceptance_data(
        &self,
        accepting_block: Hash,
        block_acceptance_data: MergesetBlockAcceptanceData,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        // Need consistency between the acceptance store and the block transaction store.
        let _guard = self.pruning_lock.blocking_read();

        match tx_type {
            TransactionType::Transaction => {
                if let Some(tx_ids) = tx_ids {
                    let mut tx_ids_filter = HashSet::with_capacity(tx_ids.len());
                    tx_ids_filter.extend(tx_ids);

                    Ok(TransactionQueryResult::Transaction(Arc::new(
                        self.get_block_transactions(
                            block_acceptance_data.block_hash,
                            Some(
                                block_acceptance_data
                                    .accepted_transactions
                                    .into_iter()
                                    .filter_map(|atx| {
                                        if tx_ids_filter.contains(&atx.transaction_id) { Some(atx.index_within_block) } else { None }
                                    })
                                    .collect(),
                            ),
                        )?,
                    )))
                } else {
                    Ok(TransactionQueryResult::Transaction(Arc::new(self.get_block_transactions(
                        block_acceptance_data.block_hash,
                        Some(block_acceptance_data.accepted_transactions.iter().map(|atx| atx.index_within_block).collect()),
                    )?)))
                }
            }
            TransactionType::SignableTransaction => Ok(TransactionQueryResult::SignableTransaction(Arc::new(
                self.virtual_processor.get_populated_transactions_by_block_acceptance_data(
                    tx_ids,
                    block_acceptance_data,
                    accepting_block,
                )?,
            ))),
        }
    }

    fn get_transactions_by_accepting_block(
        &self,
        accepting_block: Hash,
        tx_ids: Option<Vec<TransactionId>>,
        tx_type: TransactionType,
    ) -> ConsensusResult<TransactionQueryResult> {
        // need consistency between the acceptance store and the block transaction store,
        let _guard = self.pruning_lock.blocking_read();

        match tx_type {
            TransactionType::Transaction => {
                let accepting_block_mergeset_acceptance_data_iter = self
                    .acceptance_data_store
                    .get(accepting_block)
                    .map_err(|_| ConsensusError::MissingData(accepting_block))?
                    .unwrap_or_clone()
                    .into_iter();

                if let Some(tx_ids) = tx_ids {
                    let mut tx_ids_filter = HashSet::with_capacity(tx_ids.len());
                    tx_ids_filter.extend(tx_ids);

                    Ok(TransactionQueryResult::Transaction(Arc::new(
                        accepting_block_mergeset_acceptance_data_iter
                            .flat_map(|mbad| {
                                self.get_block_transactions(
                                    mbad.block_hash,
                                    Some(
                                        mbad.accepted_transactions
                                            .into_iter()
                                            .filter_map(|atx| {
                                                if tx_ids_filter.contains(&atx.transaction_id) {
                                                    Some(atx.index_within_block)
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect(),
                                    ),
                                )
                            })
                            .flatten()
                            .collect::<Vec<_>>(),
                    )))
                } else {
                    Ok(TransactionQueryResult::Transaction(Arc::new(
                        accepting_block_mergeset_acceptance_data_iter
                            .flat_map(|mbad| {
                                self.get_block_transactions(
                                    mbad.block_hash,
                                    Some(mbad.accepted_transactions.iter().map(|atx| atx.index_within_block).collect()),
                                )
                            })
                            .flatten()
                            .collect::<Vec<_>>(),
                    )))
                }
            }
            TransactionType::SignableTransaction => Ok(TransactionQueryResult::SignableTransaction(Arc::new(
                self.virtual_processor.get_populated_transactions_by_accepting_block(tx_ids, accepting_block)?,
            ))),
        }
    }

    fn get_virtual_parents(&self) -> BlockHashSet {
        self.lkg_virtual_state.load().parents.iter().copied().collect()
    }

    fn get_virtual_parents_len(&self) -> usize {
        self.lkg_virtual_state.load().parents.len()
    }

    fn get_virtual_utxos(
        &self,
        from_outpoint: Option<TransactionOutpoint>,
        chunk_size: usize,
        skip_first: bool,
    ) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        let virtual_stores = self.virtual_stores.read();
        let iter = virtual_stores.utxo_set.seek_iterator(from_outpoint, chunk_size, skip_first);
        iter.map(|item| item.unwrap()).collect()
    }

    fn get_tips(&self) -> Vec<Hash> {
        self.body_tips_store.read().get().unwrap().read().iter().copied().collect_vec()
    }

    fn get_tips_len(&self) -> usize {
        self.body_tips_store.read().get().unwrap().read().len()
    }

    fn get_pruning_point_utxos(
        &self,
        expected_pruning_point: Hash,
        from_outpoint: Option<TransactionOutpoint>,
        chunk_size: usize,
        skip_first: bool,
    ) -> ConsensusResult<Vec<(TransactionOutpoint, UtxoEntry)>> {
        if self.pruning_point_store.read().pruning_point().unwrap() != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }
        let pruning_meta_read = self.pruning_meta_stores.read();
        let iter = pruning_meta_read.utxo_set.seek_iterator(from_outpoint, chunk_size, skip_first);
        let utxos = iter.map(|item| item.unwrap()).collect();
        drop(pruning_meta_read);

        // We recheck the expected pruning point in case it was switched just before the utxo set read.
        // NOTE: we rely on order of operations by pruning processor. See extended comment therein.
        if self.pruning_point_store.read().pruning_point().unwrap() != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }

        Ok(utxos)
    }

    fn modify_coinbase_payload(&self, payload: Vec<u8>, miner_data: &MinerData) -> CoinbaseResult<Vec<u8>> {
        self.services.coinbase_manager.modify_coinbase_payload(payload, miner_data)
    }

    fn dev_fee_spk(&self) -> Option<kaspa_consensus_core::tx::ScriptPublicKey> {
        use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec};
        // Mirrors the dev-fee output construction in CoinbaseManager::expected_coinbase_transaction.
        self.config.params.dev_fee_recipient.map(|recipient| ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)))
    }

    fn calc_transaction_hash_merkle_root(&self, txs: &[Transaction]) -> Hash {
        calc_hash_merkle_root(txs.iter())
    }

    fn validate_pruning_proof(
        &self,
        proof: &PruningPointProof,
        proof_metadata: &PruningProofMetadata,
    ) -> Result<(), PruningImportError> {
        self.services.pruning_proof_manager.validate_pruning_point_proof(proof, proof_metadata)
    }

    fn apply_pruning_proof(
        &self,
        proof: PruningPointProof,
        trusted_set: &[TrustedBlock],
        header_only_chain_segment: &[Arc<Header>],
    ) -> PruningImportResult<()> {
        self.services.pruning_proof_manager.apply_proof(proof, trusted_set, header_only_chain_segment)
    }

    fn import_pruning_points(&self, pruning_points: PruningPointsList) -> PruningImportResult<()> {
        self.services.pruning_proof_manager.import_pruning_points(&pruning_points)
    }

    fn append_imported_pruning_point_utxos(&self, utxoset_chunk: &[(TransactionOutpoint, UtxoEntry)], current_multiset: &mut MuHash) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        pruning_meta_write.utxo_set.write_many(utxoset_chunk).unwrap();

        // Parallelize processing using the context of an existing thread pool.
        let inner_multiset = self.virtual_processor.install(|| {
            utxoset_chunk.par_iter().map(|(outpoint, entry)| MuHash::from_utxo(outpoint, entry)).reduce(MuHash::new, |mut a, b| {
                a.combine(&b);
                a
            })
        });

        current_multiset.combine(&inner_multiset);
    }

    fn import_pruning_point_utxo_set(&self, new_pruning_point: Hash, imported_utxo_multiset: MuHash) -> PruningImportResult<()> {
        self.virtual_processor.import_pruning_point_utxo_set(new_pruning_point, imported_utxo_multiset)
    }

    fn import_pruning_point_smt(
        &self,
        new_pruning_point: Hash,
        metadata: kaspa_consensus_core::api::SmtExportMetadata,
        inactivity_shortcut_block: Hash,
        lane_batches: ImportLaneBatchIterator<'_>,
    ) -> PruningImportResult<()> {
        use crate::model::stores::smt_metadata::SmtBlockMetadata;
        use kaspa_hashes::ZERO_HASH;
        use kaspa_smt_store::streaming_import::streaming_import;

        let kaspa_consensus_core::api::SmtExportMetadata { lanes_root, payload_and_ctx_digest, active_lanes_count, .. } = metadata;
        let expected_lane_count = active_lanes_count;

        // `inactivity_shortcut_block` was already resolved by the caller during metadata verification.
        let row = SmtBlockMetadata::new(payload_and_ctx_digest, inactivity_shortcut_block, active_lanes_count);

        let result = self.virtual_processor.install(|| {
            streaming_import(
                &self.db,
                &self.storage.smt_stores,
                ZERO_HASH,
                expected_lane_count,
                lanes_root,
                // Chunks arrive pre-sized (up to SMT_CHUNK_SIZE) from the wire-level chunker —
                // forwarded as-is, no re-batching.
                lane_batches,
                4096,
            )
            .map_err(|e| PruningImportError::SmtStoreError(format!("{e}")))
        })?;

        if result.root != lanes_root {
            return Err(PruningImportError::SmtRootMismatch { expected: lanes_root, computed: result.root });
        }

        let actual_count = result.lanes_imported;
        if actual_count != expected_lane_count {
            return Err(PruningImportError::SmtStoreError(format!(
                "active lanes count mismatch: expected {expected_lane_count}, got {actual_count}"
            )));
        }

        // The wire's metadata was already authenticated by the caller via `verify_smt_metadata`.
        let mut batch = rocksdb::WriteBatch::default();
        self.storage.smt_metadata_store.insert_batch(&mut batch, new_pruning_point, row).unwrap();
        self.db.write(batch).unwrap();

        info!("Imported SMT state for pruning point {}: {} lanes, root {}", new_pruning_point, actual_count, lanes_root);
        Ok(())
    }

    fn get_pruning_point_smt_metadata(
        &self,
        expected_pruning_point: Hash,
    ) -> ConsensusResult<kaspa_consensus_core::api::SmtExportMetadata> {
        self.virtual_processor.get_pruning_point_smt_metadata(expected_pruning_point)
    }

    fn inactivity_shortcut_block_for_pov(&self, pov_block: Hash) -> ConsensusResult<Hash> {
        self.virtual_processor.inactivity_shortcut_block_for_pov(pov_block)
    }

    fn open_pruning_point_smt_lane_stream(
        &self,
        expected_pruning_point: Hash,
    ) -> ConsensusResult<Box<dyn Iterator<Item = ConsensusResult<kaspa_consensus_core::api::ImportLane>> + Send + 'static>> {
        use kaspa_consensus_core::api::{ImportLane, SMT_PROOF_INTERVAL};

        let pp = self.pruning_point_store.read().pruning_point().unwrap();
        if pp != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }
        let max_score = self.storage.headers_store.get_blue_score(pp).unwrap();
        // KIP-21: IBD streams only the active-lanes window `[pp - finality_depth, pp]`.
        let min_score = max_score.saturating_sub(self.config.params.finality_depth());

        let smt_stores = self.storage.smt_stores.clone();
        let vp = self.virtual_processor.clone();

        let is_canonical = {
            let vp = vp.clone();
            move |bh| vp.is_smt_canonical(bh, pp)
        };
        // Clip the scan window to `[pp.blue_score - finality, pp.blue_score]`.
        // Entries above `pp.blue_score` belong to blocks in pp's future and
        // must not be part of the SMT state exported for this pruning point.
        let raw = smt_stores.lane_version.iter_all_canonical_owned(None, min_score, Some(max_score), is_canonical);

        let sl = self.session_lock().clone();
        let pps = self.pruning_point_store.clone();
        let smt_stores_proof = smt_stores.clone();
        let mut idx: u64 = 0;
        let mapped = raw.map(move |res| -> ConsensusResult<ImportLane> {
            let (lane_key, verified) = res.map_err(|e| ConsensusError::GeneralOwned(format!("SMT lane iter: {e}")))?;
            let proof = if (idx as usize).is_multiple_of(SMT_PROOF_INTERVAL) {
                let _g = sl.blocking_read();
                let upp = pps.read().pruning_point().unwrap();
                if upp != pp {
                    return Err(ConsensusError::UnexpectedPruningPoint);
                }
                let vp_proof = vp.clone();
                Some(
                    smt_stores_proof
                        .prove_lane(&lane_key, SmtReadBounds::new(max_score, min_score), move |bh| vp_proof.is_smt_canonical(bh, pp))
                        .map_err(|e| ConsensusError::GeneralOwned(format!("prove_lane: {e}")))?,
                )
            } else {
                None
            };
            idx += 1;
            Ok(ImportLane { lane_key, lane_tip: *verified.data(), blue_score: verified.blue_score(), proof })
        });

        // Chain a one-shot tail so a fully drained stream verifies that
        // pruning did not advance before the stream completed.
        let sl = self.session_lock().clone();
        let pps = self.pruning_point_store.clone();
        let final_check = std::iter::once_with(move || {
            let _g = sl.blocking_read();
            let upp = pps.read().pruning_point().unwrap();
            if upp != pp { Some(Err(ConsensusError::UnexpectedPruningPoint)) } else { None }
        })
        .flatten();

        Ok(Box::new(mapped.chain(final_check)))
    }

    fn validate_pruning_points(&self, syncer_virtual_selected_parent: Hash) -> ConsensusResult<()> {
        let hst = self.storage.headers_selected_tip_store.read().get().unwrap().hash;
        let (synced_pruning_point, synced_pp_index) = self.pruning_point_store.read().pruning_point_and_index().unwrap();
        if !self.services.pruning_point_manager.is_valid_pruning_point(synced_pruning_point, hst) {
            return Err(ConsensusError::General("pruning point does not coincide with the synced header selected tip"));
        }
        if !self.services.pruning_point_manager.is_valid_pruning_point(synced_pruning_point, syncer_virtual_selected_parent) {
            return Err(ConsensusError::General("pruning point does not coincide with the syncer's sink (virtual selected parent)"));
        }
        self.services
            .pruning_point_manager
            .are_pruning_points_in_valid_chain(synced_pruning_point, synced_pp_index, syncer_virtual_selected_parent)
            .map_err(|e| ConsensusError::GeneralOwned(format!("past pruning points do not form a valid chain: {}", e)))
    }

    fn is_chain_ancestor_of(&self, low: Hash, high: Hash) -> ConsensusResult<bool> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(low)?;
        self.validate_block_exists(high)?;
        Ok(self.services.reachability_service.is_chain_ancestor_of(low, high))
    }

    // max_blocks has to be greater than the merge set size limit
    fn get_hashes_between(&self, low: Hash, high: Hash, max_blocks: usize) -> ConsensusResult<(Vec<Hash>, Hash)> {
        let _guard = self.pruning_lock.blocking_read();
        assert!(max_blocks as u64 > self.config.mergeset_size_limit());
        self.validate_block_exists(low)?;
        self.validate_block_exists(high)?;

        self.services.sync_manager.antipast_hashes_between(low, high, Some(max_blocks)).map_err(ConsensusError::SyncManagerError)
    }

    fn get_header(&self, hash: Hash) -> ConsensusResult<Arc<Header>> {
        self.headers_store.get_header(hash).optional().unwrap().ok_or(ConsensusError::HeaderNotFound(hash))
    }

    fn get_headers_selected_tip(&self) -> Hash {
        self.headers_selected_tip_store.read().get().unwrap().hash
    }

    fn get_antipast_from_pov(&self, hash: Hash, context: Hash, max_traversal_allowed: Option<u64>) -> ConsensusResult<Vec<Hash>> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(hash)?;
        self.validate_block_exists(context)?;
        Ok(self.services.dag_traversal_manager.antipast(hash, std::iter::once(context), max_traversal_allowed)?)
    }

    fn get_anticone(&self, hash: Hash) -> ConsensusResult<Vec<Hash>> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(hash)?;
        let virtual_state = self.lkg_virtual_state.load();
        Ok(self.services.dag_traversal_manager.anticone(hash, virtual_state.parents.iter().copied(), None)?)
    }

    fn get_pruning_point_proof(&self) -> Arc<PruningPointProof> {
        // PRUNE SAFETY: proof is cached before the prune op begins and the
        // pruning point cannot move during the prune so the cache remains valid
        self.services.pruning_proof_manager.get_pruning_point_proof()
    }

    fn create_virtual_selected_chain_block_locator(&self, low: Option<Hash>, high: Option<Hash>) -> ConsensusResult<Vec<Hash>> {
        let _guard = self.pruning_lock.blocking_read();
        if let Some(low) = low {
            self.validate_block_exists(low)?;
        }

        if let Some(high) = high {
            self.validate_block_exists(high)?;
        }

        Ok(self.services.sync_manager.create_virtual_selected_chain_block_locator(low, high)?)
    }

    fn pruning_point_headers(&self) -> Vec<Arc<Header>> {
        // PRUNE SAFETY: index is monotonic and past pruning point headers are expected permanently
        let (pruning_point, pruning_index) = self.pruning_point_store.read().pruning_point_and_index().unwrap();
        (0..pruning_index)
            .map(|index| self.past_pruning_points_store.get(index).unwrap())
            .chain(once(pruning_point))
            .map(|hash| self.headers_store.get_header(hash).unwrap())
            .collect_vec()
    }

    fn get_pruning_point_anticone_and_trusted_data(&self) -> ConsensusResult<Arc<PruningPointTrustedData>> {
        // PRUNE SAFETY: anticone and trusted data are cached before the prune op begins and the
        // pruning point cannot move during the prune so the cache remains valid
        self.services.pruning_proof_manager.get_pruning_point_anticone_and_trusted_data()
    }

    fn get_block(&self, hash: Hash) -> ConsensusResult<Block> {
        if match self.statuses_store.read().get(hash).optional().unwrap() {
            Some(status) => !status.has_block_body(),
            None => true,
        } {
            return Err(ConsensusError::BlockNotFound(hash));
        }

        Ok(Block {
            header: self.headers_store.get_header(hash).optional().unwrap().ok_or(ConsensusError::BlockNotFound(hash))?,
            transactions: self.block_transactions_store.get(hash).optional().unwrap().ok_or(ConsensusError::BlockNotFound(hash))?,
        })
    }

    fn get_block_transactions(&self, hash: Hash, indices: Option<Vec<TransactionIndexType>>) -> ConsensusResult<Vec<Transaction>> {
        let transactions = self.block_transactions_store.get(hash).optional().unwrap().ok_or(ConsensusError::BlockNotFound(hash))?;
        let tx_len = transactions.len();

        if let Some(indices) = indices {
            if tx_len < indices.len() {
                return Err(ConsensusError::TransactionQueryTooLarge(indices.len(), hash, transactions.len()));
            }

            let res = transactions
                .unwrap_or_clone()
                .into_iter()
                .enumerate()
                .filter(|(index, _tx)| indices.contains(&(*index as TransactionIndexType)))
                .map(|(_, tx)| tx)
                .collect::<Vec<_>>();

            if res.len() != indices.len() {
                Err(ConsensusError::TransactionIndexOutOfBounds(*indices.iter().max().unwrap(), tx_len, hash))
            } else {
                Ok(res)
            }
        } else {
            Ok(transactions.unwrap_or_clone())
        }
    }

    fn get_block_body(&self, hash: Hash) -> ConsensusResult<Arc<Vec<Transaction>>> {
        if match self.statuses_store.read().get(hash).optional().unwrap() {
            Some(status) => !status.has_block_body(),
            None => true,
        } {
            return Err(ConsensusError::BlockNotFound(hash));
        }

        self.block_transactions_store.get(hash).optional().unwrap().ok_or(ConsensusError::BlockNotFound(hash))
    }

    fn get_block_even_if_header_only(&self, hash: Hash) -> ConsensusResult<Block> {
        let Some(status) = self.statuses_store.read().get(hash).optional().unwrap().filter(|&status| status.has_block_header()) else {
            return Err(ConsensusError::HeaderNotFound(hash));
        };
        Ok(Block {
            header: self.headers_store.get_header(hash).optional().unwrap().ok_or(ConsensusError::HeaderNotFound(hash))?,
            transactions: if status.is_header_only() {
                Default::default()
            } else {
                self.block_transactions_store.get(hash).optional().unwrap().unwrap_or_default()
            },
        })
    }

    fn get_ghostdag_data(&self, hash: Hash) -> ConsensusResult<ExternalGhostdagData> {
        match self.get_block_status(hash) {
            None => return Err(ConsensusError::HeaderNotFound(hash)),
            Some(BlockStatus::StatusInvalid) => return Err(ConsensusError::InvalidBlock(hash)),
            _ => {}
        };
        let ghostdag = self.ghostdag_store.get_data(hash).optional().unwrap().ok_or(ConsensusError::MissingData(hash))?;
        Ok((&*ghostdag).into())
    }

    fn get_block_children(&self, hash: Hash) -> Option<Vec<Hash>> {
        self.services
            .relations_service
            .get_children(hash)
            .optional()
            .unwrap()
            .map(|children| children.read().iter().copied().collect_vec())
    }

    fn get_block_parents(&self, hash: Hash) -> Option<Arc<Vec<Hash>>> {
        self.services.relations_service.get_parents(hash).optional().unwrap()
    }

    fn get_block_status(&self, hash: Hash) -> Option<BlockStatus> {
        self.statuses_store.read().get(hash).optional().unwrap()
    }

    fn get_block_acceptance_data(&self, hash: Hash) -> ConsensusResult<Arc<AcceptanceData>> {
        self.acceptance_data_store.get(hash).optional().unwrap().ok_or(ConsensusError::MissingData(hash))
    }

    fn get_blocks_acceptance_data(
        &self,
        hashes: &[Hash],
        merged_blocks_limit: Option<usize>,
    ) -> ConsensusResult<Vec<Arc<AcceptanceData>>> {
        // Note: merged_blocks_limit will limit after the sum of merged blocks is breached along the supplied hash's acceptance data
        // and not limit the acceptance data within a queried hash. i.e. It has mergeset_size_limit granularity, this is to guarantee full acceptance data coverage.
        if merged_blocks_limit.is_none() {
            return hashes
                .iter()
                .copied()
                .map(|hash| self.acceptance_data_store.get(hash).optional().unwrap().ok_or(ConsensusError::MissingData(hash)))
                .collect::<ConsensusResult<Vec<_>>>();
        }
        let merged_blocks_limit = merged_blocks_limit.unwrap(); // we handle `is_none`, so may unwrap.
        let mut num_of_merged_blocks = 0usize;

        hashes
            .iter()
            .copied()
            .map_while(|hash| {
                let entry = self.acceptance_data_store.get(hash).optional().unwrap().ok_or(ConsensusError::MissingData(hash));
                num_of_merged_blocks += entry.as_ref().map_or(0, |entry| entry.len());
                if num_of_merged_blocks > merged_blocks_limit { None } else { Some(entry) }
            })
            .collect::<ConsensusResult<Vec<_>>>()
    }

    fn is_chain_block(&self, hash: Hash) -> ConsensusResult<bool> {
        self.is_chain_ancestor_of(hash, self.get_sink())
    }

    fn get_seq_commit_lane_proof(&self, block_hash: Hash, lane_key: Hash) -> ConsensusResult<SeqCommitLaneProof> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(block_hash)?;

        // Genesis has no selected parent; reject before we try to dereference one.
        if block_hash == self.config.params.genesis.hash {
            return Err(ConsensusError::BlockIsGenesis(block_hash));
        }

        // Canonicality: must be a selected-parent-chain block (ancestor of or equal to sink).
        let sink = self.get_sink();
        if !self.services.reachability_service.is_chain_ancestor_of(block_hash, sink) {
            return Err(ConsensusError::BlockNotInSelectedChain(block_hash));
        }

        // Depth: block must be at or after the current pruning point. Blocks before
        // the pruning point may have had their SMT versions pruned.
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        if !self.services.reachability_service.is_chain_ancestor_of(pruning_point, block_hash) {
            return Err(ConsensusError::BlockTooDeep(block_hash));
        }

        let header = self.headers_store.get_header(block_hash).unwrap();

        // KIP-21 activity_root only exists post-Toccata. Drop the gate after all
        // nets activate.
        if !self.config.params.toccata_activation.is_active(header.daa_score) {
            return Err(ConsensusError::GeneralOwned(format!("toccata is not active at block {block_hash}")));
        }

        let selected_parent = header.post_toccata_chainblock_selected_parent();
        let parent_header = self.headers_store.get_header(selected_parent).unwrap();

        let finality_depth = self.config.params.finality_depth();
        let current_bounds = SmtReadBounds::for_pov(header.blue_score, finality_depth);
        let virtual_processor = self.virtual_processor.clone();
        let is_canonical = |bh| virtual_processor.is_smt_canonical(bh, block_hash);

        let smt_proof = self
            .storage
            .smt_stores
            .prove_lane(&lane_key, current_bounds, is_canonical)
            .map_err(|e| ConsensusError::GeneralOwned(format!("prove_lane: {e}")))?;

        let lane = self
            .storage
            .smt_stores
            .get_lane(lane_key, current_bounds, is_canonical)
            .map(|v| SeqCommitLaneEntry { tip: *v.data(), blue_score: v.blue_score() });

        let metadata =
            self.storage.smt_metadata_store.get(block_hash).map_err(|e| ConsensusError::GeneralOwned(format!("smt_metadata: {e}")))?;

        // Toccata is active (checked above), so the metadata carries a concrete
        // shortcut block. Its header must exist: block_hash was verified to be a
        // chain block between the pruning point and sink, so its shortcut block
        // lies on the chain segment [pp - F, sink] which is not pruned (and we
        // hold the pruning lock read guard). Fold to seq_commit via the virtual
        // processor.
        let inactivity_shortcut_block = metadata.inactivity_shortcut_block();
        let inactivity_shortcut = self.virtual_processor.inactivity_shortcut(inactivity_shortcut_block);

        let parent_seq_commit = parent_header.accepted_id_merkle_root;

        // Canonical-`R` witness support (KIP-21). Recompute the mergeset context hash exactly as
        // `recompute_seq_commit` does (all three inputs come from stored headers), read the
        // active-lanes SMT root, and re-derive the ordered mergeset miner-payload leaves from the
        // block's acceptance data via the *same* consensus helper the live seq_commit uses.
        let context_hash = {
            use kaspa_seq_commit::{hashing::mergeset_context_hash, types::MergesetContext};
            mergeset_context_hash(&MergesetContext {
                timestamp: parent_header.timestamp,
                daa_score: header.daa_score,
                blue_score: header.blue_score,
            })
        };
        let lanes_root = self.storage.smt_stores.get_lanes_root(current_bounds, is_canonical);
        let mergeset_acceptance_data =
            self.acceptance_data_store.get(block_hash).map_err(|e| ConsensusError::GeneralOwned(format!("acceptance_data: {e}")))?;
        let miner_payload_leaves = self.virtual_processor.mergeset_miner_payload_leaves(&mergeset_acceptance_data);

        // In debug builds, verify the proof is consistent with the stored lanes_root
        // and that metadata chains to the header's seq_commit.
        debug_assert!({
            use kaspa_hashes::SeqCommitActiveNode;
            use kaspa_seq_commit::{
                hashing::smt_leaf_hash,
                types::SmtLeafInput,
                verify::{SmtMetadata, verify_smt_metadata},
            };
            let leaf = lane.as_ref().map(|l| smt_leaf_hash(&SmtLeafInput { lane_tip: &l.tip, blue_score: l.blue_score }));
            let computed_root = smt_proof.as_proof().compute_root::<SeqCommitActiveNode>(&lane_key, leaf).unwrap();
            let payload_and_ctx_digest = metadata.payload_and_ctx_digest();
            let md = SmtMetadata {
                lanes_root: &lanes_root,
                payload_and_ctx_digest: &payload_and_ctx_digest,
                parent_seq_commit: &parent_seq_commit,
            };
            computed_root == lanes_root
                && verify_smt_metadata(&md, inactivity_shortcut, header.accepted_id_merkle_root, parent_seq_commit).is_ok()
        });

        Ok(SeqCommitLaneProof {
            smt_proof,
            lane,
            payload_and_ctx_digest: metadata.payload_and_ctx_digest(),
            parent_seq_commit,
            inactivity_shortcut,
            context_hash,
            lanes_root,
            miner_payload_leaves,
        })
    }

    fn get_missing_block_body_hashes(&self, high: Hash) -> ConsensusResult<Vec<Hash>> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(high)?;
        Ok(self.services.sync_manager.get_missing_block_body_hashes(high)?)
    }
    /// Returns the set of blocks in the anticone of the current pruning point
    /// which (may) lack a block body due to being in a transitional state
    /// If not in a transitional state this list is supposed to be empty
    fn get_body_missing_anticone(&self) -> Vec<Hash> {
        self.pruning_meta_stores.read().get_body_missing_anticone()
    }

    fn clear_body_missing_anticone_set(&self) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();
        pruning_meta_write.set_body_missing_anticone(&mut batch, vec![]).unwrap();
        self.db.write(batch).unwrap();
    }

    fn pruning_point(&self) -> Hash {
        self.pruning_point_store.read().pruning_point().unwrap()
    }

    fn create_block_locator_from_pruning_point(&self, high: Hash, limit: usize) -> ConsensusResult<Vec<Hash>> {
        let _guard = self.pruning_lock.blocking_read();
        self.validate_block_exists(high)?;
        // Keep the pruning point read guard throughout building the locator
        let pruning_point_read = self.pruning_point_store.read();
        let pruning_point = pruning_point_read.pruning_point().unwrap();
        Ok(self.services.sync_manager.create_block_locator_from_pruning_point(high, pruning_point, Some(limit))?)
    }

    fn estimate_network_hashes_per_second(&self, start_hash: Option<Hash>, window_size: usize) -> ConsensusResult<u64> {
        let _guard = self.pruning_lock.blocking_read();
        match start_hash {
            Some(hash) => {
                self.validate_block_exists(hash)?;
                let ghostdag_data = self.ghostdag_store.get_data(hash).unwrap();
                // The selected parent header is used within to check for sampling activation, so we verify its existence first
                if !self.headers_store.has(ghostdag_data.selected_parent).unwrap() {
                    return Err(ConsensusError::DifficultyError(DifficultyError::InsufficientWindowData(0)));
                }
                self.estimate_network_hashes_per_second_impl(&ghostdag_data, window_size)
            }
            None => {
                let virtual_state = self.lkg_virtual_state.load();
                self.estimate_network_hashes_per_second_impl(&virtual_state.ghostdag_data, window_size)
            }
        }
    }

    fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        self.virtual_processor.are_pruning_points_violating_finality(pp_list)
    }

    fn creation_timestamp(&self) -> u64 {
        self.creation_timestamp
    }

    fn finality_point(&self) -> Hash {
        self.virtual_processor.virtual_finality_point(&self.lkg_virtual_state.load().ghostdag_data, self.pruning_point())
    }

    /// The utxoset is an additive structure,
    /// to make room for the gradual aggregation of a new utxoset,
    /// first the old one must be cleared.
    /// Likewise, clearing the old utxoset is also a gradual process.
    /// The utxo stable flag guarantees that a full utxoset is never mistaken for
    /// an incomplete or partially deleted one.
    fn clear_pruning_utxo_set(&self) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();
        // Currently under the conditions in which this function is called, this flag should already be false.
        // We lower it down regardless as it is conceptually true to do so.
        pruning_meta_write.set_pruning_utxoset_stable_flag(&mut batch, false).unwrap();
        self.db.write(batch).unwrap();
        pruning_meta_write.utxo_set.clear().unwrap();
    }

    fn clear_pruning_smt_stores(&self) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();
        pruning_meta_write.set_pruning_smt_stable_flag(&mut batch, false).unwrap();
        self.db.write(batch).unwrap();
        self.storage.smt_stores.clear_all();
        self.storage.smt_metadata_store.delete_all().unwrap();
    }

    fn set_pruning_smt_stable_flag(&self, val: bool) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();
        pruning_meta_write.set_pruning_smt_stable_flag(&mut batch, val).unwrap();
        self.db.write(batch).unwrap();
    }

    fn is_pruning_smt_stable(&self) -> bool {
        self.pruning_meta_stores.read().pruning_smt_stable_flag()
    }

    // -------------------- Shielded-pool pruning-point state (IBD) --------------------

    fn get_pruning_point_shielded_metadata(
        &self,
        expected_pruning_point: Hash,
    ) -> ConsensusResult<Option<kaspa_consensus_core::api::ShieldedExportMetadata>> {
        let pp = self.pruning_point_store.read().pruning_point().unwrap();
        if pp != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }
        self.virtual_processor
            .export_pruning_point_shielded(pp)
            .map_err(|e| ConsensusError::GeneralOwned(format!("shielded metadata export failed: {e}")))
    }

    fn open_pruning_point_shielded_nullifier_stream(
        &self,
        expected_pruning_point: Hash,
    ) -> ConsensusResult<Box<dyn Iterator<Item = ConsensusResult<[u8; 32]>> + Send + 'static>> {
        let pp = self.pruning_point_store.read().pruning_point().unwrap();
        if pp != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }
        let all = self
            .virtual_processor
            .collect_pruning_point_nullifiers(pp)
            .map_err(|e| ConsensusError::GeneralOwned(format!("nullifier-set collection failed: {e}")))?;
        // Iterate the shared captured view by index — no second copy of the set.
        Ok(Box::new((0..all.len()).map(move |i| Ok(all[i]))))
    }

    fn import_pruning_point_shielded(
        &self,
        new_pruning_point: Hash,
        metadata: kaspa_consensus_core::api::ShieldedExportMetadata,
        expected_state_root: Option<[u8; 32]>,
        nullifier_batches: kaspa_consensus_core::api::ShieldedNullifierBatchIterator<'_>,
    ) -> PruningImportResult<()> {
        // F-08: `nullifier_count` is declared by an untrusted sync peer. Never
        // pre-allocate from it (a huge value aborts the process on allocation
        // failure), cap it to bound memory/CPU, and fail as soon as the stream
        // overruns the declared count instead of buffering unboundedly first.
        if metadata.nullifier_count > kaspa_consensus_core::api::MAX_SHIELDED_NULLIFIER_IMPORT_COUNT {
            return Err(PruningImportError::ShieldedStateError(format!(
                "declared nullifier count {} exceeds the sanity cap {}",
                metadata.nullifier_count,
                kaspa_consensus_core::api::MAX_SHIELDED_NULLIFIER_IMPORT_COUNT
            )));
        }
        let mut nullifiers: Vec<[u8; 32]> = Vec::new();
        for batch in nullifier_batches {
            nullifiers.extend(batch);
            if nullifiers.len() as u64 > metadata.nullifier_count {
                return Err(PruningImportError::ShieldedStateError(format!(
                    "streamed nullifiers exceed the declared count {}",
                    metadata.nullifier_count
                )));
            }
        }
        self.virtual_processor
            .seed_pruning_point_shielded(new_pruning_point, metadata, expected_state_root, nullifiers)
            .map_err(PruningImportError::ShieldedStateError)?;
        Ok(())
    }

    fn get_shielded_state_root(&self, block: Hash) -> ConsensusResult<[u8; 32]> {
        self.virtual_processor
            .shielded_state_root_at(block)
            .map_err(|e| ConsensusError::GeneralOwned(format!("shielded state root at {block}: {e}")))
    }

    fn empty_shielded_state_root(&self) -> [u8; 32] {
        crate::processes::shielded::PruningPointShieldedMetadata::empty_state_root()
    }

    /// F-15: really clear the shielded import state — the whole global nullifier
    /// set and the per-block snapshots at the current pruning point, together with
    /// the stable flag, in one atomic batch. Call ONLY immediately before a full
    /// re-seed, and only when no locally UTXO-validated chain blocks exist above
    /// the pruning point (their nullifier contributions would be lost without
    /// revalidation); the IBD flow enforces both preconditions.
    fn clear_pruning_shielded_stores(&self) {
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        self.virtual_processor.clear_shielded_state_for_pruning_reimport(&mut batch, pruning_point).unwrap();
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        pruning_meta_write.set_pruning_shielded_stable_flag(&mut batch, false).unwrap();
        self.db.write(batch).unwrap();
    }

    fn set_pruning_shielded_stable_flag(&self, val: bool) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();
        pruning_meta_write.set_pruning_shielded_stable_flag(&mut batch, val).unwrap();
        self.db.write(batch).unwrap();
    }

    fn is_pruning_shielded_stable(&self) -> bool {
        if !self.pruning_meta_stores.read().pruning_shielded_stable_flag() {
            return false;
        }
        // The flag alone is not trusted, because it is fail-open: a missing key reads back as
        // `true` (correct for upgrading nodes, which genuinely had no shielded state to fetch),
        // and any path that adopts a new pruning point without lowering it leaves a node
        // *claiming* a shielded state it does not have. That failure is silent and terminal —
        // every chain block above the pruning point is disqualified and nothing ever retries,
        // because the node believes it is already synced.
        //
        // So corroborate the claim against the data. On a shielded-coinbase network every chain
        // block mints coinbase notes, so a pruning point that is not genesis MUST have a
        // non-empty commitment-tree frontier. An empty one means the state was never seeded and
        // the flag is lying; report unstable so the IBD flow downloads it. Self-healing: an
        // already-wedged node repairs itself on restart instead of needing its database wiped.
        if !self.config.shielded_coinbase {
            return true;
        }
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        if pruning_point == self.config.genesis.hash {
            return true;
        }
        match self.virtual_processor.shielded_frontier_at(pruning_point) {
            // A seeded pruning point always has leaves; size 0 here is missing state, not an empty pool.
            Ok(fs) => fs.size > 0,
            // Unreadable frontier is likewise "not seeded" — fail toward re-downloading, never
            // toward silently validating against state we do not hold.
            Err(_) => false,
        }
    }

    /// The usual flow consists of the pruning point naturally updating during pruning, and hence maintains consistency by default
    /// During pruning catchup, we need to manually update the pruning point and
    /// make sure that consensus looks "as if" it has just moved to a new pruning point.
    fn intrusive_pruning_point_update(&self, new_pruning_point: Hash, syncer_sink: Hash) -> ConsensusResult<()> {
        let pruning_points_to_add = self.get_and_verify_path_to_new_pruning_point(new_pruning_point, syncer_sink)?;

        // If all has gone well, we can finally update pruning point and other stores.
        self.intrusive_pruning_point_store_writes(new_pruning_point, syncer_sink, pruning_points_to_add)
    }

    fn set_pruning_utxoset_stable_flag(&self, val: bool) {
        let mut pruning_meta_write = self.pruning_meta_stores.write();
        let mut batch = rocksdb::WriteBatch::default();

        pruning_meta_write.set_pruning_utxoset_stable_flag(&mut batch, val).unwrap();
        self.db.write(batch).unwrap();
    }

    fn is_pruning_utxoset_stable(&self) -> bool {
        let pruning_meta_read = self.pruning_meta_stores.read();
        pruning_meta_read.pruning_utxoset_stable_flag()
    }

    fn is_pruning_point_anticone_fully_synced(&self) -> bool {
        let pruning_meta_read = self.pruning_meta_stores.read();
        pruning_meta_read.is_anticone_fully_synced()
    }

    fn is_consensus_in_transitional_ibd_state(&self) -> bool {
        if self.pruning_meta_stores.read().is_in_transitional_ibd_state() {
            return true;
        }
        // Corroborate the shielded half against the data, for the same reason
        // `is_pruning_shielded_stable` does — but here it is what makes recovery *fire*.
        //
        // The relay flow re-triggers IBD as soon as this returns true ("if in a transitional ibd
        // state, do not wait, sync immediately"). The store-level answer depends on the shielded
        // stable flag, which is only lowered by two specific disqualification variants
        // (`BadCoinbaseTransaction` / `InvalidShieldedState`). A node that wedges through any other
        // path therefore never lowers the flag, never looks transitional, and so never re-enters
        // IBD — it is header-synced, so nothing else triggers one either. Observed live: a node
        // disqualifying every chain block for 75+ minutes straight (17:45 → 19:02) with a
        // successfully-completed IBD behind it and no recovery attempt.
        //
        // Asking whether the pruning point actually has shielded state makes recovery independent
        // of which error variant fired.
        !self.is_pruning_shielded_stable()
    }

    fn get_n_last_pruning_points(&self, n: usize) -> Vec<Hash> {
        let (_pruning_point, pruning_index) = self.pruning_point_store.read().pruning_point_and_index().unwrap();
        (0..=pruning_index).rev().take(n).map(|ind| self.past_pruning_points_store.get(ind).unwrap()).collect_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::test_consensus::TestConsensus;
    use kaspa_consensus_core::api::{ConsensusApi, ShieldedExportMetadata};
    use kaspa_consensus_core::config::params::MAINNET_PARAMS;

    /// A node whose chain index starts at genesis must report history COMPLETE; the whole point
    /// of the field is that a wallet can tell the difference, so getting the polarity wrong is
    /// worse than not publishing it at all.
    ///
    /// A fresh `TestConsensus` is exactly the genesis-rooted case: `init_with_pruning_point`
    /// has not rebased anything, so index 0 IS genesis — the same state a node reaches after a
    /// successful history backfill.
    #[test]
    fn history_status_reports_complete_when_the_index_starts_at_genesis() {
        let config = Config::new(MAINNET_PARAMS);
        let tc = TestConsensus::new(&config);
        let consensus = tc.consensus_clone();

        let (from_daa, complete) = consensus.get_shielded_history_status().expect("status must be readable");

        assert!(complete, "an index rooted at genesis must report complete history");
        assert_eq!(from_daa, 0, "genesis is DAA 0, so there is no floor below which this node cannot answer");
    }

    /// The index reaching genesis is NOT enough once any of it came from a peer: between the
    /// backfill writing the entries and the replay verifying them, `complete` must be false —
    /// that window was reported live as `history_complete: true` at 20% of the replay.
    #[test]
    fn history_status_is_incomplete_after_a_backfill_until_verified() {
        let config = Config::new(MAINNET_PARAMS);
        let tc = TestConsensus::new(&config);
        let consensus = tc.consensus_clone();

        let mut batch = rocksdb::WriteBatch::default();
        consensus.pruning_meta_stores.write().set_shielded_history_backfilled(&mut batch).unwrap();
        consensus.db.write(batch).unwrap();
        let (_, complete) = consensus.get_shielded_history_status().unwrap();
        assert!(!complete, "peer-supplied index entries without a verified verdict must not read as complete");

        let mut batch = rocksdb::WriteBatch::default();
        consensus.pruning_meta_stores.write().set_shielded_history_verified_base(&mut batch, config.genesis.hash).unwrap();
        consensus.db.write(batch).unwrap();
        let (_, complete) = consensus.get_shielded_history_status().unwrap();
        assert!(complete, "a verified replay restores complete");
    }

    /// F-08 regression: the peer-declared `nullifier_count` must never drive an
    /// allocation, an absurd count must be rejected up front by the sanity cap, and
    /// a stream overrunning the declared count must fail early — all as clean
    /// `PruningImportError`s, never a process abort (the pre-fix code did
    /// `Vec::with_capacity(count)` on the untrusted value and buffered unboundedly).
    #[test]
    fn import_pruning_point_shielded_rejects_peer_controlled_counts() {
        let config = Config::new(MAINNET_PARAMS);
        let tc = TestConsensus::new(&config);
        let consensus = tc.consensus_clone();
        let pp = config.genesis.hash;

        // 1. `u64::MAX` declared count: rejected by the sanity cap before any
        //    allocation or store access (pre-fix: allocation-failure abort).
        let metadata = ShieldedExportMetadata { data: vec![], nullifier_count: u64::MAX };
        let mut empty = std::iter::empty();
        match consensus.import_pruning_point_shielded(pp, metadata, None, &mut empty) {
            Err(PruningImportError::ShieldedStateError(msg)) => {
                assert!(msg.contains("exceeds the sanity cap"), "cap rejection, got: {msg}")
            }
            other => panic!("expected sanity-cap ShieldedStateError, got {other:?}"),
        }

        // 2. Stream longer than declared: fail early as soon as the buffered
        //    entries exceed the declared count (pre-fix: buffered everything first).
        let metadata = ShieldedExportMetadata { data: vec![], nullifier_count: 1 };
        let mut over = vec![vec![[7u8; 32]; 2]].into_iter();
        match consensus.import_pruning_point_shielded(pp, metadata, None, &mut over) {
            Err(PruningImportError::ShieldedStateError(msg)) => {
                assert!(msg.contains("exceed the declared count"), "early-overrun error, got: {msg}")
            }
            other => panic!("expected early-overrun ShieldedStateError, got {other:?}"),
        }

        // 3. The cap itself is not off-by-one hostile: a declared count within the
        //    cap passes the F-08 checks (it then fails later on malformed metadata —
        //    still a clean error, not an abort).
        let metadata = ShieldedExportMetadata { data: vec![], nullifier_count: 0 };
        let mut empty = std::iter::empty();
        match consensus.import_pruning_point_shielded(pp, metadata, None, &mut empty) {
            Err(PruningImportError::ShieldedStateError(msg)) => {
                assert!(!msg.contains("sanity cap") && !msg.contains("declared count"), "F-08 checks must pass, got: {msg}")
            }
            other => panic!("expected a downstream ShieldedStateError, got {other:?}"),
        }
    }
}
