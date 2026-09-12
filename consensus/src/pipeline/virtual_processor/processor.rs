use crate::{
    consensus::{
        services::{
            ConsensusServices, DbBlockDepthManager, DbDagTraversalManager, DbGhostdagManager, DbParentsManager, DbPruningPointManager,
            DbWindowManager,
        },
        storage::ConsensusStorage,
    },
    errors::RuleError,
    model::{
        services::{
            reachability::{MTReachabilityService, ReachabilityService},
            relations::MTRelationsService,
        },
        stores::{
            DB,
            acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore},
            block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore},
            block_window_cache::{BlockWindowCacheStore, BlockWindowCacheWriter},
            daa::DbDaaStore,
            depth::{DbDepthStore, DepthStoreReader},
            ghostdag::{DbGhostdagStore, GhostdagData, GhostdagStoreReader},
            headers::{DbHeadersStore, HeaderStoreReader},
            past_pruning_points::DbPastPruningPointsStore,
            pruning::{DbPruningStore, PruningStoreReader},
            pruning_meta::PruningMetaStores,
            pruning_samples::DbPruningSamplesStore,
            reachability::DbReachabilityStore,
            relations::{DbRelationsStore, RelationsStoreReader},
            selected_chain::{DbSelectedChainStore, SelectedChainStore, SelectedChainStoreReader},
            statuses::{DbStatusesStore, StatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            tips::{DbTipsStore, TipsStoreReader},
            utxo_diffs::{DbUtxoDiffsStore, UtxoDiffsStoreReader},
            utxo_multisets::{DbUtxoMultisetsStore, UtxoMultisetsStoreReader},
            virtual_state::{LkgVirtualState, VirtualState, VirtualStateStoreReader, VirtualStores},
        },
    },
    params::Params,
    pipeline::{
        ProcessingCounters,
        deps_manager::VirtualStateProcessingMessage,
        pruning_processor::processor::PruningProcessingMessage,
        virtual_processor::{fork_logger::ForkLogger, utxo_validation::UtxoProcessingContext},
    },
    processes::{
        coinbase::CoinbaseManager,
        ghostdag::ordering::SortableBlock,
        transaction_validator::{TransactionValidator, errors::TxResult, tx_validation_in_utxo_context::TxValidationFlags},
        window::WindowManager,
    },
};
use kaspa_consensus_core::{
    BlockHashSet, ChainPath,
    acceptance_data::AcceptanceData,
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockstatus::BlockStatus::{StatusDisqualifiedFromChain, StatusUTXOValid},
    coinbase::MinerData,
    config::{genesis::GenesisBlock, params::ForkActivation},
    header::Header,
    merkle::calc_hash_merkle_root,
    mining_rules::MiningRules,
    pruning::PruningPointsList,
    tx::{MutableTransaction, Transaction},
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
};
use kaspa_consensus_notify::{
    notification::{
        NewBlockTemplateNotification, Notification, SinkBlueScoreChangedNotification, UtxosChangedNotification,
        VirtualChainChangedNotification, VirtualDaaScoreChangedNotification,
    },
    root::ConsensusNotificationRoot,
};
use kaspa_consensusmanager::SessionLock;
use kaspa_core::{debug, info, time::unix_now, trace, warn};
use kaspa_database::prelude::{StoreError, StoreResultExt, StoreResultUnitExt};
use kaspa_hashes::{Hash, ZERO_HASH};
use kaspa_muhash::MuHash;
use kaspa_notify::{events::EventType, notifier::Notify};
use kaspa_smt_store::processor::SmtReadBounds;
use once_cell::unsync::Lazy;

use super::bounds::SeqCommitBounds;
use super::errors::{PruningImportError, PruningImportResult};
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use itertools::Itertools;
use kaspa_consensus_core::config::params::ForkedParam;
use kaspa_consensus_core::tx::ValidatedTransaction;
use kaspa_utils::binary_heap::BinaryHeapExtensions;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use rand::{Rng, seq::SliceRandom};
use rayon::{
    ThreadPool,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};
use rocksdb::WriteBatch;
use std::{
    cmp::min,
    collections::{BinaryHeap, HashMap, VecDeque},
    ops::Deref,
    sync::{Arc, atomic::Ordering},
};

/// The outcome of an anchor-finality decision, with the reasoning kept rather than
/// collapsed to a bool.
///
/// `is_final` is the only field validation reads; the rest exists so a divergence report
/// can state *why* a spend was kept or dropped without re-deriving it (a re-derivation can
/// drift from what validation actually did, which is how several wrong diagnoses happened).
#[derive(Default, Clone, Debug)]
pub(super) struct AnchorVerdict {
    pub is_final: bool,
    pub source: Option<Hash>,
    pub source_blue_score: Option<u64>,
    pub is_chain_ancestor: Option<bool>,
    pub age: Option<u64>,
    pub reject_reason: Option<&'static str>,
}

pub struct VirtualStateProcessor {
    // Channels
    receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
    pruning_sender: CrossbeamSender<PruningProcessingMessage>,
    pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // DB
    db: Arc<DB>,

    // Config
    pub(super) genesis: GenesisBlock,
    pub(super) max_block_parents: u8,
    pub(super) mergeset_size_limit: u64,
    pub(super) finality_depth: u64,
    /// Shielded-spend anchor maturity (PLAN §2.5): a shielded spend must prove its
    /// input note into the anchor as of the chain block this many blue-score units
    /// back from the sink. Decoupled from `finality_depth` (which governs chain
    /// finality/pruning) so a note becomes spendable in ~10 minutes rather than the
    /// full ~12-hour finality window.
    pub(super) shielded_anchor_depth: u64,
    /// Maximum shielded-spend anchor age in blue-score units (audit F-04/F-05):
    /// a spend whose anchor is older than this is dropped. Strictly below the
    /// pruning depth (param-invariant, compile-time asserted), so the source of
    /// any in-window anchor is never pruned on any synced node class — which is
    /// what allows `is_shielded_anchor_final` to fail CLOSED on pruned data.
    pub(super) max_shielded_anchor_age: u64,
    /// The Orchard empty-tree anchor, precomputed (always canonical/mature, PLAN §2.5).
    pub(super) empty_shielded_anchor: [u8; 32],
    pub(super) mempool_mass_cofactors: kaspa_consensus_core::config::params::ForkedParam<kaspa_consensus_core::mass::MassCofactors>,
    pub(super) block_version: ForkedParam<u16>,

    // Stores
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) ghostdag_store: Arc<DbGhostdagStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) daa_excluded_store: Arc<DbDaaStore>,
    pub(super) block_transactions_store: Arc<DbBlockTransactionsStore>,
    pub(super) pruning_point_store: Arc<RwLock<DbPruningStore>>,
    pub(super) past_pruning_points_store: Arc<DbPastPruningPointsStore>,
    pub(super) body_tips_store: Arc<RwLock<DbTipsStore>>,
    pub(super) depth_store: Arc<DbDepthStore>,
    pub(super) selected_chain_store: Arc<RwLock<DbSelectedChainStore>>,
    pub(super) pruning_samples_store: Arc<DbPruningSamplesStore>,

    // Utxo-related stores
    pub(super) utxo_diffs_store: Arc<DbUtxoDiffsStore>,
    pub(super) utxo_multisets_store: Arc<DbUtxoMultisetsStore>,
    pub(super) acceptance_data_store: Arc<DbAcceptanceDataStore>,
    pub(super) virtual_stores: Arc<RwLock<VirtualStores>>,
    pub(super) pruning_meta_stores: Arc<RwLock<PruningMetaStores>>,

    /// The "last known good" virtual state. To be used by any logic which does not want to wait
    /// for a possible virtual state write to complete but can rather settle with the last known state
    pub lkg_virtual_state: LkgVirtualState,

    // Managers and services
    pub(super) ghostdag_manager: DbGhostdagManager,
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) relations_service: MTRelationsService<DbRelationsStore>,
    pub(super) dag_traversal_manager: DbDagTraversalManager,
    pub(super) window_manager: DbWindowManager,
    pub(super) coinbase_manager: CoinbaseManager,
    pub(super) transaction_validator: TransactionValidator,
    pub(super) pruning_point_manager: DbPruningPointManager,
    pub(super) parents_manager: DbParentsManager,
    pub(super) depth_manager: DbBlockDepthManager,

    // block window caches
    pub(super) block_window_cache_for_difficulty: Arc<BlockWindowCacheStore>,
    pub(super) block_window_cache_for_past_median_time: Arc<BlockWindowCacheStore>,

    // Pruning lock
    pub(super) pruning_lock: SessionLock,

    // Notifier
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    pub(super) counters: Arc<ProcessingCounters>,

    // Toccata activation
    pub(crate) toccata_activation: ForkActivation,
    /// See `Params::shielded_anchor_multi_activation`.
    pub(crate) shielded_anchor_multi_activation: ForkActivation,
    /// See `Params::shielded_coinbase_seed_activation` (F-02).
    pub(crate) shielded_coinbase_seed_activation: ForkActivation,
    pub(crate) toccata_logger: ForkLogger,

    // SMT stores
    pub(super) smt_stores: Arc<kaspa_smt_store::processor::SmtStores>,
    pub(super) smt_metadata_store: Arc<crate::model::stores::smt_metadata::DbSmtMetadataStore>,

    // Shielded pool: reorg-safe driver over the shielded state stores (PLAN §2.4).
    // Advances the note-commitment tree / nullifier set / turnstile in GHOSTDAG
    // accepted order. Currently constructed and queryable; the accepted-order
    // commit hook is wired separately.
    pub(super) shielded_state_manager: crate::processes::shielded::ShieldedStateManager,

    /// F-03: the PP-time nullifier set last computed for shielded IBD export,
    /// shared between the metadata call (which reports its length as
    /// `nullifier_count`) and the streaming call so one request serves a single
    /// captured view. Keyed by pruning-point hash; the PP-time set is immutable per
    /// pruning point, so the cached value never goes stale.
    pub(super) pp_nullifier_export_cache: Mutex<Option<(Hash, Arc<Vec<[u8; 32]>>)>>,

    // zkas: when true, the coinbase reward enters the shielded pool as
    // coinbase notes (no transparent outputs) — see `build_coinbase_mint`.
    pub(super) shielded_coinbase: bool,

    // Mining Rule
    _mining_rules: Arc<MiningRules>,
}

impl VirtualStateProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
        pruning_sender: CrossbeamSender<PruningProcessingMessage>,
        pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,
        thread_pool: Arc<ThreadPool>,
        params: &Params,
        db: Arc<DB>,
        storage: &Arc<ConsensusStorage>,
        services: &Arc<ConsensusServices>,
        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
        mining_rules: Arc<MiningRules>,
    ) -> Self {
        // Mandatory-circuit guard (consensus safety): on a shielded-coinbase
        // network every block reward — and every payment — lives in the Orchard
        // pool, so a node that cannot verify Halo 2 proofs would reject every
        // shielded transaction and *fork away* from circuit-enabled peers. A
        // build without the `shielded-circuit` feature must therefore refuse to
        // run such a network rather than split consensus. (The feature is on by
        // default; this only fires for a deliberate `--no-default-features` build.)
        #[cfg(not(feature = "shielded-circuit"))]
        assert!(
            !params.shielded_coinbase,
            "this consensus build lacks the mandatory `shielded-circuit` feature and cannot verify \
             Orchard proofs; it must not run a shielded network (it would reject every shielded \
             transaction and fork). Rebuild with default features enabled."
        );

        // Reorg-safe driver over the shielded state stores. Anchor-finality
        // (maturity at `shielded_anchor_depth` + canonical ancestry, PLAN §2.5) is
        // decided here in the virtual processor via reachability, not by the manager.
        let shielded_state_manager = crate::processes::shielded::ShieldedStateManager::new(
            Arc::clone(&db),
            kaspa_database::prelude::CachePolicy::Count(10_000),
        );
        Self {
            receiver,
            pruning_sender,
            pruning_receiver,
            thread_pool,

            genesis: params.genesis.clone(),
            max_block_parents: params.max_block_parents(),
            mergeset_size_limit: params.mergeset_size_limit(),
            mempool_mass_cofactors: params.mempool_block_mass_cofactors(),
            block_version: params.block_version(),

            db,
            statuses_store: storage.statuses_store.clone(),
            headers_store: storage.headers_store.clone(),
            ghostdag_store: storage.ghostdag_store.clone(),
            daa_excluded_store: storage.daa_excluded_store.clone(),
            block_transactions_store: storage.block_transactions_store.clone(),
            pruning_point_store: storage.pruning_point_store.clone(),
            past_pruning_points_store: storage.past_pruning_points_store.clone(),
            body_tips_store: storage.body_tips_store.clone(),
            depth_store: storage.depth_store.clone(),
            selected_chain_store: storage.selected_chain_store.clone(),
            pruning_samples_store: storage.pruning_samples_store.clone(),
            utxo_diffs_store: storage.utxo_diffs_store.clone(),
            utxo_multisets_store: storage.utxo_multisets_store.clone(),
            acceptance_data_store: storage.acceptance_data_store.clone(),
            virtual_stores: storage.virtual_stores.clone(),
            pruning_meta_stores: storage.pruning_meta_stores.clone(),
            lkg_virtual_state: storage.lkg_virtual_state.clone(),

            block_window_cache_for_difficulty: storage.block_window_cache_for_difficulty.clone(),
            block_window_cache_for_past_median_time: storage.block_window_cache_for_past_median_time.clone(),

            ghostdag_manager: services.ghostdag_manager.clone(),
            reachability_service: services.reachability_service.clone(),
            relations_service: services.relations_service.clone(),
            dag_traversal_manager: services.dag_traversal_manager.clone(),
            window_manager: services.window_manager.clone(),
            coinbase_manager: services.coinbase_manager.clone(),
            transaction_validator: services.transaction_validator.clone(),
            pruning_point_manager: services.pruning_point_manager.clone(),
            parents_manager: services.parents_manager.clone(),
            depth_manager: services.depth_manager.clone(),

            pruning_lock,
            notification_root,
            counters,
            toccata_activation: params.toccata_activation,
            shielded_anchor_multi_activation: params.shielded_anchor_multi_activation,
            shielded_coinbase_seed_activation: params.shielded_coinbase_seed_activation,
            shielded_coinbase: params.shielded_coinbase,
            toccata_logger: ForkLogger::new("virtual state processing rules", true),
            smt_stores: storage.smt_stores.clone(),
            smt_metadata_store: storage.smt_metadata_store.clone(),
            shielded_state_manager,
            pp_nullifier_export_cache: Mutex::new(None),
            _mining_rules: mining_rules,
            finality_depth: params.finality_depth(),
            shielded_anchor_depth: params.shielded_anchor_depth(),
            max_shielded_anchor_age: params.max_shielded_anchor_age(),
            empty_shielded_anchor: kaspa_shielded_core::Anchor::empty_tree().to_bytes(),
        }
    }

    /// The shielded note-commitment tree anchor as of a given chain block
    /// (PLAN §2.4). Returns the empty-tree anchor for blocks with no shielded
    /// state. Used by RPC / wallet anchor queries.
    pub fn shielded_anchor_at(&self, block: kaspa_hashes::Hash) -> Result<[u8; 32], kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.anchor_at(block)
    }

    /// The shielded note-commitment tree **frontier** as of a given chain block — the
    /// fast-sync checkpoint a light wallet starts from (it then scans only later
    /// blocks). Exposed for the `GetShieldedTreeState` RPC.
    pub fn shielded_frontier_at(
        &self,
        block: kaspa_hashes::Hash,
    ) -> Result<kaspa_shielded_core::tree::FrontierState, kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.frontier_at(block)
    }

    /// The turnstile cumulative totals (PLAN §2.6) as of a given chain block.
    /// Exposed for supply queries and the pool-accounting tests.
    pub fn shielded_supply_totals_at(
        &self,
        block: kaspa_hashes::Hash,
    ) -> Result<crate::model::stores::shielded::SupplyTotals, kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.supply_totals_at(block)
    }

    /// Total value burned out of the shielded pool as of a chain block (dormant
    /// bridge seam: `0` on the live chain). Completes the turnstile identity
    /// `pool = coinbase - fees - burns` for supply queries.
    pub fn shielded_burn_total_at(&self, block: kaspa_hashes::Hash) -> Result<u128, kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.burn_total_at(block)
    }

    // ------------------ Pruning-point shielded-state IBD transfer ------------------

    /// Server side: export the shielded state metadata at a pruning point for IBD
    /// transfer. `Ok(None)` means the pruning point has no shielded state (empty
    /// pool — nothing to transfer). The nullifier set is streamed separately via
    /// [`Self::collect_pruning_point_nullifiers`].
    ///
    /// F-03: `nullifier_count` must count the **PP-time** nullifier set (the set the
    /// PP MuHash snapshot in `md` commits to), not the tip-time global set — see
    /// [`Self::pruning_point_nullifier_set`].
    pub fn export_pruning_point_shielded(
        &self,
        pp: kaspa_hashes::Hash,
    ) -> Result<Option<kaspa_consensus_core::api::ShieldedExportMetadata>, kaspa_database::prelude::StoreError> {
        let Some(mut md) = self.shielded_state_manager.export_pruning_point_shielded(pp)? else {
            return Ok(None);
        };
        // Attach the anchors a spend mined just above `pp` may still legitimately prove against.
        // The syncee builds its anchor→block index only for blocks it validates itself, so without
        // these it drops every such spend and disqualifies the block that merged it. See
        // [`PruningPointShieldedMetadata::in_window_anchors`]. Walk the selected chain back from
        // `pp` over exactly the consensus window; stop early if the chain index does not reach that
        // far (a node that itself fast-synced), since anything we cannot resolve we simply do not
        // claim — the receiver is no worse off than today.
        let window = self.max_shielded_anchor_age;
        let window_blocks: BlockHashSet = {
            let sc_read = self.selected_chain_store.read();
            match sc_read.get_by_hash(pp).optional()? {
                Some(pp_index) => {
                    let low_index = pp_index.saturating_sub(window);
                    (low_index..pp_index).filter_map(|i| sc_read.get_by_index(i).optional().ok().flatten()).collect()
                }
                None => BlockHashSet::default(),
            }
        };
        if !window_blocks.is_empty() {
            // Read the pairs out of the stored index rather than recomputing a tree root per
            // block: the derive-per-block version overran the 120s IBD timeout at 27,000 blocks
            // and made every shielded import fail. Observed live 2026-07-31.
            md.in_window_anchors = self.shielded_state_manager.anchors_for_blocks(&window_blocks)?;
            // Attach each source's blue score. The mapping alone leaves the syncee unable to
            // judge maturity — it has no ghostdag data below its pruning point — so it drops the
            // spend anyway and disqualifies the block. Only the blocks actually named as sources
            // are sent (deduplicated), not the whole window, so this adds 40 B per distinct
            // source rather than per window block.
            let mut scores: Vec<(Hash, u64)> = Vec::new();
            let mut seen = BlockHashSet::default();
            for (_, source) in md.in_window_anchors.iter() {
                if !seen.insert(*source) {
                    continue;
                }
                // Skip rather than fail on a source we cannot score: partial attestation still
                // helps, and claiming a score we do not have would be worse than claiming none.
                if let Ok(blue_score) = self.ghostdag_store.get_blue_score(*source) {
                    scores.push((*source, blue_score));
                }
            }
            md.in_window_anchor_source_scores = scores;
        }
        let nullifier_count = self.pruning_point_nullifier_set(pp)?.len() as u64;
        Ok(Some(kaspa_consensus_core::api::ShieldedExportMetadata { data: md.to_wire_bytes(), nullifier_count }))
    }

    /// Server side: the spent-nullifier set **as of the pruning point** (for shielded
    /// IBD streaming) — the same captured view the metadata call counted (F-03).
    pub fn collect_pruning_point_nullifiers(
        &self,
        pp: kaspa_hashes::Hash,
    ) -> Result<Arc<Vec<[u8; 32]>>, kaspa_database::prelude::StoreError> {
        self.pruning_point_nullifier_set(pp)
    }

    /// The spent-nullifier set as of pruning point `pp` (audit finding F-03): the
    /// current global set (which tracks the virtual selected tip, typically a full
    /// pruning period ahead of the PP) minus the nullifiers added by selected-chain
    /// blocks in `(pp, virtual selected tip]`, read from the per-block diff store.
    ///
    /// The computed set is cached per pruning point and shared by the metadata
    /// (count) and stream calls of one request, so both serve a single captured
    /// view. The PP-time set is immutable per pruning point, so the cache never
    /// goes stale; a different PP simply replaces it.
    ///
    /// Race note: the tip-time set is snapshotted BEFORE the tip is captured. A
    /// block committed while the snapshot streams has its commit ordered before the
    /// virtual-state update, so the tip captured afterward is at/after it and the
    /// subtraction window covers it — the result still lands on the exact PP-time
    /// set. A concurrent reorg walk can transiently desync the global set; that is
    /// tolerated by the serving flow, which aborts the transfer cleanly on drift
    /// instead of panicking.
    fn pruning_point_nullifier_set(&self, pp: kaspa_hashes::Hash) -> Result<Arc<Vec<[u8; 32]>>, kaspa_database::prelude::StoreError> {
        if let Some((cached_pp, set)) = self.pp_nullifier_export_cache.lock().as_ref() {
            if *cached_pp == pp {
                return Ok(Arc::clone(set));
            }
        }
        let snapshot = self.shielded_state_manager.nullifier_set_snapshot()?;
        let tip = self.lkg_virtual_state.load().ghostdag_data.selected_parent;
        // `forward_chain_iterator(pp, tip, true)` yields `[pp, tip]` along the
        // selected chain; `skip(1)` drops the PP itself, leaving exactly `(pp, tip]`.
        // The PP is finality-deep, so it is always a chain ancestor of the tip.
        let post_blocks = self.reachability_service.forward_chain_iterator(pp, tip, true).skip(1);
        let set = Arc::new(self.shielded_state_manager.subtract_nullifier_diffs(snapshot, post_blocks)?);
        *self.pp_nullifier_export_cache.lock() = Some((pp, Arc::clone(&set)));
        Ok(set)
    }

    /// Receiver side: verify + seed the shielded state at a pruning point from
    /// transferred metadata + the full streamed nullifier set. See
    /// [`crate::processes::shielded::PruningPointShieldedMetadata`] for how the
    /// consensus binding (the #24 coinbase commitment) is enforced afterward.
    ///
    /// `expected_state_root` (audit finding F-02): when `Some`, the metadata's
    /// declared state root must equal this PoW-committed value (the coinbase
    /// `shielded_commitment` of the pruning point's selected child) BEFORE anything
    /// is seeded — the import is otherwise entirely attacker-controlled.
    pub fn seed_pruning_point_shielded(
        &self,
        pp: kaspa_hashes::Hash,
        metadata: kaspa_consensus_core::api::ShieldedExportMetadata,
        expected_state_root: Option<[u8; 32]>,
        nullifiers: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        use crate::processes::shielded::{PruningPointShieldedMetadata, ShieldedStateManager};
        let md = PruningPointShieldedMetadata::from_wire_bytes(&metadata.data)?;
        // F-02: reject the import before seeding if it does not match the
        // PoW-committed shielded state root (peer can be dropped; another syncer
        // can be tried).
        if let Some(committed) = expected_state_root {
            ShieldedStateManager::verify_import_binding(&md, committed)?;
        }
        let n = ShieldedStateManager::verify_pruning_point_shielded(&md, nullifiers.iter())?;
        if n as u64 != metadata.nullifier_count {
            return Err(format!("nullifier count mismatch: metadata says {}, streamed {}", metadata.nullifier_count, n));
        }
        let mut batch = WriteBatch::default();
        self.shielded_state_manager
            .seed_pruning_point_shielded(&mut batch, pp, &md, nullifiers.iter())
            .map_err(|e| format!("seeding shielded stores failed: {e:?}"))?;
        self.db.write(batch).unwrap();
        info!("Imported shielded state for pruning point {}: {} nullifiers imported", pp, n);
        Ok(())
    }

    /// The locally held shielded state root (PLAN §2.10) as of `block`, recomputed
    /// from the per-block snapshots (the empty-state root for blocks with no
    /// shielded state). Used on the IBD import path to detect whether local state
    /// already matches the PoW-committed root (F-02/F-15).
    pub fn shielded_state_root_at(&self, block: kaspa_hashes::Hash) -> Result<[u8; 32], kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.state_root_at(block)
    }

    /// F-15: stage the real clear of the shielded import state (the whole global
    /// nullifier set + the per-block snapshots at `pruning_point`) into `batch`.
    /// See `ShieldedStateManager::clear_for_pruning_reimport` for the safety
    /// preconditions — the caller (IBD flow via `Consensus`) enforces them.
    pub fn clear_shielded_state_for_pruning_reimport(
        &self,
        batch: &mut WriteBatch,
        pruning_point: kaspa_hashes::Hash,
    ) -> Result<(), kaspa_database::prelude::StoreError> {
        self.shielded_state_manager.clear_for_pruning_reimport(batch, pruning_point)
    }

    /// The shielded effects one **chain block** applied (PLAN §2.4), for wallet sync
    /// (`GetShieldedBlocks` RPC): the block's own coinbase mint plus its accepted
    /// shielded actions in consensus applied order, in compact form.
    ///
    /// Served from the **persisted compact scan archive** written at validation time
    /// (`ShieldedStateManager::persist`), i.e. the exact block-time applied set — NOT
    /// re-derived from block bodies. This is deliberate and load-bearing:
    /// re-deriving the accepted set at RPC time (the previous implementation) called
    /// `is_shielded_anchor_final`, whose pruning short-circuit flips a *dropped* spend
    /// to *accepted* once its source block prunes → the wallet appended phantom leaves
    /// and its tree drifted from canonical (the divergent-anchor "sends don't credit"
    /// bug). Serving the persisted record removes that entire failure class, and keeps
    /// history scannable after the body itself is pruned.
    pub fn shielded_chain_block_data(
        &self,
        block: kaspa_hashes::Hash,
    ) -> Result<kaspa_consensus_core::api::ShieldedChainBlockData, String> {
        // The header is retained across pruning; the scan archive carries everything
        // else self-contained (blue score, coinbase, applied actions), so this serves
        // even a block whose body/ghostdag/acceptance data have been pruned.
        let Some(scan) = self.shielded_state_manager.scan_block(block).map_err(|e| format!("scan archive for {block}: {e}"))? else {
            // No shielded effects recorded (or a shielded-inactive block): return an
            // empty record, reading blue/daa/timestamp from the retained header.
            let blue_score = self.ghostdag_store.get_blue_score(block).unwrap_or(0);
            let daa_score = self.headers_store.get_daa_score(block).map_err(|e| format!("daa score for {block}: {e}"))?;
            let timestamp = self.headers_store.get_timestamp(block).map_err(|e| format!("timestamp for {block}: {e}"))?;
            return Ok(kaspa_consensus_core::api::ShieldedChainBlockData {
                hash: block,
                blue_score,
                daa_score,
                coinbase_txid: kaspa_hashes::Hash::default(),
                coinbase_outputs: Vec::new(),
                coinbase_commitments: Vec::new(),
                accepted_actions: Vec::new(),
                accepted_txids: Vec::new(),
                timestamp,
            });
        };
        let (accepted_actions, accepted_txids) = scan.accepted.into_iter().map(|t| (t.action_bytes, t.txid)).unzip();
        Ok(kaspa_consensus_core::api::ShieldedChainBlockData {
            hash: block,
            blue_score: scan.blue_score,
            daa_score: scan.daa_score,
            coinbase_txid: scan.coinbase_txid,
            coinbase_outputs: scan.coinbase_outputs,
            coinbase_commitments: scan.coinbase_commitments,
            accepted_actions,
            accepted_txids,
            timestamp: scan.timestamp,
        })
    }

    pub fn worker(self: &Arc<Self>) {
        'outer: while let Ok(msg) = self.receiver.recv() {
            if msg.is_exit_message() {
                break;
            }

            // Once a task arrived, collect all pending tasks from the channel.
            // This is done since virtual processing is not a per-block
            // operation, so it benefits from max available info

            let messages: Vec<VirtualStateProcessingMessage> = std::iter::once(msg).chain(self.receiver.try_iter()).collect();
            trace!("virtual processor received {} tasks", messages.len());

            self.resolve_virtual();

            let statuses_read = self.statuses_store.read();
            for msg in messages {
                match msg {
                    VirtualStateProcessingMessage::Exit => break 'outer,
                    VirtualStateProcessingMessage::Process(task, virtual_state_result_transmitter) => {
                        // We don't care if receivers were dropped
                        let _ = virtual_state_result_transmitter.send(Ok(statuses_read.get(task.block().hash()).unwrap()));
                    }
                };
            }
        }

        // Pass the exit signal on to the following processor
        self.pruning_sender.send(PruningProcessingMessage::Exit).unwrap();
    }

    fn resolve_virtual(self: &Arc<Self>) {
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let virtual_read = self.virtual_stores.upgradable_read();
        let prev_state = virtual_read.state.get().unwrap();
        let finality_point = self.virtual_finality_point(&prev_state.ghostdag_data, pruning_point);

        // PRUNE SAFETY: in order to avoid locking the prune lock throughout virtual resolving we make sure
        // to only process blocks in the future of the finality point (F) which are never pruned (since finality depth << pruning depth).
        // This is justified since:
        //      1. Tips which are not in the future of F definitely don't have F on their chain
        //         hence cannot become the next sink (due to finality violation).
        //      2. Such tips cannot be merged by virtual since they are violating the merge depth
        //         bound (merge depth <= finality depth).
        // (both claims are true by induction for any block in their past as well)
        let prune_guard = self.pruning_lock.blocking_read();
        let tips = self
            .body_tips_store
            .read()
            .get()
            .unwrap()
            .read()
            .iter()
            .copied()
            .filter(|&h| self.reachability_service.is_dag_ancestor_of(finality_point, h))
            .collect_vec();
        drop(prune_guard);
        let prev_sink = prev_state.ghostdag_data.selected_parent;
        let mut accumulated_diff = prev_state.utxo_diff.clone().to_reversed();

        let (new_sink, virtual_parent_candidates) =
            self.sink_search_algorithm(&virtual_read, &mut accumulated_diff, prev_sink, tips, finality_point, pruning_point);
        let (virtual_parents, virtual_ghostdag_data) = self.pick_virtual_parents(new_sink, virtual_parent_candidates, pruning_point);
        assert_eq!(virtual_ghostdag_data.selected_parent, new_sink);

        let sink_multiset = self.utxo_multisets_store.get(new_sink).unwrap();
        let chain_path = self.dag_traversal_manager.calculate_chain_path(prev_sink, new_sink, None);
        let sink_ghostdag_data = Lazy::new(|| self.ghostdag_store.get_data(new_sink).unwrap());
        // Cache the DAA and Median time windows of the sink for future use, as well as prepare for virtual's window calculations
        self.cache_sink_windows(new_sink, prev_sink, &sink_ghostdag_data);

        let new_virtual_state = self
            .calculate_and_commit_virtual_state(
                virtual_read,
                virtual_parents,
                virtual_ghostdag_data,
                sink_multiset,
                &mut accumulated_diff,
                &chain_path,
            )
            .expect("all possible rule errors are unexpected here");

        // Shielded (PLAN §2.5): nothing to publish here. Anchor-finality is decided
        // per spend at block-validation time (`is_shielded_anchor_final`) via the
        // reorg-safe anchor→block index + reachability + the
        // `[shielded_anchor_depth, max_shielded_anchor_age]` age window, so
        // there is no tip-level anchor window to maintain.

        let compact_sink_ghostdag_data = if let Some(sink_ghostdag_data) = Lazy::get(&sink_ghostdag_data) {
            // If we had to retrieve the full data, we convert it to compact
            sink_ghostdag_data.to_compact()
        } else {
            // Else we query the compact data directly.
            self.ghostdag_store.get_compact_data(new_sink).unwrap()
        };

        // Update the pruning processor about the virtual state change
        // Empty the channel before sending the new message. If pruning processor is busy, this step makes sure
        // the internal channel does not grow with no need (since we only care about the most recent message)
        let _consume = self.pruning_receiver.try_iter().count();
        self.pruning_sender.send(PruningProcessingMessage::Process { sink_ghostdag_data: compact_sink_ghostdag_data }).unwrap();

        // Emit notifications
        let accumulated_diff = Arc::new(accumulated_diff);
        let virtual_parents = Arc::new(new_virtual_state.parents.clone());
        self.notification_root
            .notify(Notification::NewBlockTemplate(NewBlockTemplateNotification {}))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::UtxosChanged(UtxosChangedNotification::new(accumulated_diff, virtual_parents)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::SinkBlueScoreChanged(SinkBlueScoreChangedNotification::new(compact_sink_ghostdag_data.blue_score)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification::new(new_virtual_state.daa_score)))
            .expect("expecting an open unbounded channel");
        if self.notification_root.has_subscription(EventType::VirtualChainChanged) {
            // check for subscriptions before the heavy lifting
            let added_chain_blocks_acceptance_data =
                chain_path.added.iter().copied().map(|added| self.acceptance_data_store.get(added).unwrap()).collect_vec();
            self.notification_root
                .notify(Notification::VirtualChainChanged(VirtualChainChangedNotification::new(
                    chain_path.added.into(),
                    chain_path.removed.into(),
                    Arc::new(added_chain_blocks_acceptance_data),
                )))
                .expect("expecting an open unbounded channel");
        }
    }

    pub(crate) fn virtual_finality_point(&self, virtual_ghostdag_data: &GhostdagData, pruning_point: Hash) -> Hash {
        let finality_point = self.depth_manager.calc_finality_point(virtual_ghostdag_data, pruning_point);
        if self.reachability_service.is_chain_ancestor_of(pruning_point, finality_point) {
            finality_point
        } else {
            // At the beginning of IBD when virtual finality point might be below the pruning point
            // or disagreeing with the pruning point chain, we take the pruning point itself as the finality point
            pruning_point
        }
    }

    /// Whether a shielded spend proving against `anchor` is acceptable in a block
    /// with selected parent `selected_parent` and blue score `block_blue_score`
    /// (PLAN §2.5). Reorg- and sync-mode-safe by construction: an anchor is final
    /// iff its source block (from the append-only anchor→block index) is
    ///
    ///  1. **canonical** — a selected-chain ancestor of `selected_parent` (an anchor
    ///     from an abandoned branch fails this, so a >`shielded_anchor_depth` reorg
    ///     cannot resurrect it — closing the shallow-anchor value-creation vector), and
    ///  2. **in-window** — the source's blue-score age relative to this block lies in
    ///     `[shielded_anchor_depth, max_shielded_anchor_age]` (~10 min to ~7.5 h).
    ///
    /// FAIL-CLOSED on missing data (security audit F-04/F-05). The parameter
    /// invariant `max_shielded_anchor_age < pruning_depth - finality_depth`
    /// (compile-time asserted in `BlockrateParams::new`) guarantees that the
    /// source block of any *in-window* anchor is younger than every synced
    /// node's pruning point, so its ghostdag and reachability data exists on
    /// full, pruned AND IBD-seeded nodes alike. Therefore:
    ///
    ///  - a pruned source (`get_blue_score` Err) can only belong to an anchor
    ///    that is out-of-window anyway — REJECT. The historical fail-open here
    ///    (`return true`, motivated by a panic-freeze when a `.unwrap()` hit a
    ///    pruned source) assumed "pruned == canonical". That is false: the
    ///    anchor→block index is written for every chain block while selected
    ///    and is NEVER reverted on reorg, so anchors of abandoned-then-pruned
    ///    branches kept resolving as final — notes that only ever existed on a
    ///    dead branch could be spent: inflation (F-04).
    ///  - a reachability `Err` likewise means out-of-window/abandoned, not
    ///    "pruned canonical" — REJECT.
    ///  - an IBD-seeded node (whose anchor index holds only the pruning point's
    ///    own anchor and later) now rejects out-of-window anchors exactly as a
    ///    full node does, instead of silently dropping old-but-canonical spends
    ///    full nodes accepted — removing the permanent full-vs-seeded split
    ///    (F-05). Wallets pick anchors near the maturity end of the window, far
    ///    below `max_shielded_anchor_age`, so honest spends are unaffected.
    ///
    /// Failing closed cannot wedge validation: no in-window anchor can ever hit
    /// either pruned-data path, on any node class.
    ///
    /// The empty-tree anchor is genesis (always canonical and mature); a spend can
    /// never actually prove a note into it, so its proof fails elsewhere.
    /// Validation calls [`Self::resolve_shielded_anchor`] directly so it can record the
    /// reasoning; this bool-only spelling is kept because the finality tests read far better
    /// against it.
    #[cfg(test)]
    pub(super) fn is_shielded_anchor_final(&self, anchor: &[u8; 32], selected_parent: Hash, block_blue_score: u64) -> bool {
        // Tests predate the activation; resolve with the pre-fork path (daa 0).
        self.resolve_shielded_anchor(anchor, selected_parent, block_blue_score, 0).is_final
    }

    /// [`is_shielded_anchor_final`] with its reasoning preserved instead of collapsed to a
    /// bool. The verdict is decided here and nowhere else, so a diagnostic built from an
    /// [`AnchorVerdict`] reports what validation actually did rather than a re-derivation
    /// that can drift from it.
    pub(super) fn resolve_shielded_anchor(
        &self,
        anchor: &[u8; 32],
        selected_parent: Hash,
        block_blue_score: u64,
        block_daa_score: u64,
    ) -> AnchorVerdict {
        if *anchor == self.empty_shielded_anchor {
            return AnchorVerdict { is_final: true, ..Default::default() };
        }
        // Post-activation: consider EVERY block that produced this root, not just the last one
        // written to the single-valued index. An orphan can no longer destroy the canonical
        // producer's mapping, so the verdict follows from canonical data alone and is identical
        // on every node regardless of which reorgs it happened to witness.
        if self.shielded_anchor_multi_activation.is_active(block_daa_score) {
            let producers = self.shielded_state_manager.anchor_producer_blocks(anchor).unwrap_or_default();
            if producers.is_empty() {
                return AnchorVerdict { reject_reason: Some("anchor is not a known tree root"), ..Default::default() };
            }
            let mut last = AnchorVerdict { reject_reason: Some("no producer is a matured chain ancestor"), ..Default::default() };
            for source in producers {
                let v = self.judge_anchor_source(source, selected_parent, block_blue_score);
                if v.is_final {
                    return v;
                }
                last = v; // keep the most informative rejection for diagnostics
            }
            return last;
        }
        let Some(source) = self.shielded_state_manager.anchor_source_block(anchor).unwrap() else {
            // not a real tree root of any block this node has indexed
            return AnchorVerdict { reject_reason: Some("anchor is not a known tree root"), ..Default::default() };
        };
        self.judge_anchor_source(source, selected_parent, block_blue_score)
    }

    /// Decide whether one candidate source block makes an anchor final: it must be a selected-chain
    /// ancestor of the spending block and lie inside the maturity window.
    fn judge_anchor_source(&self, source: Hash, selected_parent: Hash, block_blue_score: u64) -> AnchorVerdict {
        // No local ghostdag data for the source. Two very different situations share this
        // symptom, and telling them apart is the whole point of the fallback below:
        //
        //  - A genuinely ancient or abandoned source: older than any acceptable anchor, and
        //    failing CLOSED is right. (Fail-OPEN here was the F-04 inflation vector.)
        //  - A source inside the anchor window but below THIS node's pruning point. A
        //    fast-synced node has no ghostdag below its pruning point, so a perfectly legal
        //    anchor lands here too. `params.rs` asserts this cannot happen, reasoning from the
        //    tip; but a node in IBD validates blocks sitting AT its pruning point, whose anchors
        //    reach below it by construction. Measured on mainnet 2026-08-08: pruning point blue
        //    score 993,600, first disqualified block 993,652, its anchor's source 990,606 — age
        //    3,046, legal, and 2,994 below the pruning point. Failing closed there dropped the
        //    spend, shrank the expected coinbase by its 24,578,600 fee, and disqualified the
        //    block; everything after inherited.
        //
        // So consult the blue scores the pruning-point peer attested for exactly those in-window
        // sources. Still not fail-open: a source nobody attested is rejected as before.
        let (source_blue_score, attested) = match self.ghostdag_store.get_blue_score(source) {
            Ok(s) => (s, false),
            Err(_) => match self.shielded_state_manager.attested_source_blue_score(source) {
                Ok(Some(s)) => (s, true),
                _ => {
                    return AnchorVerdict {
                        source: Some(source),
                        reject_reason: Some("source ghostdag data pruned and no attested blue score"),
                        ..Default::default()
                    };
                }
            },
        };
        // Canonical: the source block is on this block's selected chain. Use the
        // pruning-aware `try_is_chain_ancestor_of` (not the panicking `is_chain_ancestor_of`)
        // so a source whose reachability data has been pruned since the blue-score read can
        // never crash the virtual processor here either. With the age window, an in-window
        // source's reachability is never pruned, so `Err` means out-of-window/abandoned —
        // fail closed (F-04); only an explicit `Ok(true)` is canonical.
        //
        // An ATTESTED source is the exception, and it needs no reachability lookup: it would
        // have none either, for the same reason it had no ghostdag. Ancestry is implied by how
        // the attestation is built — the serving node enumerates these by walking its OWN
        // selected chain below the pruning point, and this node adopted that same PoW-committed
        // pruning point, so a source on that chain is a selected-chain ancestor of every block
        // above it. Without this the blue-score fallback would resolve and then die one line
        // later on the identical missing-data problem.
        let is_chain_ancestor = attested
            || source == selected_parent
            || matches!(self.reachability_service.try_is_chain_ancestor_of(source, selected_parent), Ok(true));
        if !is_chain_ancestor {
            return AnchorVerdict {
                source: Some(source),
                source_blue_score: Some(source_blue_score),
                is_chain_ancestor: Some(false),
                age: Some(block_blue_score.saturating_sub(source_blue_score)),
                reject_reason: Some("source block is not on this block's selected chain"),
                ..Default::default()
            };
        }
        // In-window: at least `shielded_anchor_depth` deep (maturity, PLAN §2.5) and
        // at most `max_shielded_anchor_age` old (F-04/F-05 fail-closed bound).
        let age = block_blue_score.saturating_sub(source_blue_score);
        let verdict = age >= self.shielded_anchor_depth && age <= self.max_shielded_anchor_age;
        AnchorVerdict {
            is_final: verdict,
            source: Some(source),
            source_blue_score: Some(source_blue_score),
            is_chain_ancestor: Some(true),
            age: Some(age),
            reject_reason: (!verdict).then_some("age outside [shielded_anchor_depth, max_shielded_anchor_age]"),
        }
    }

    /// Access to the shielded state manager for offline/backfill paths that live outside the
    /// pipeline module (history backfill ingest). Not a validation entry point.
    pub(crate) fn shielded_state_manager_ref(&self) -> &crate::processes::shielded::ShieldedStateManager {
        &self.shielded_state_manager
    }

    /// The siblings of an anchor's source block, and whether each is known to carry the same
    /// shielded root.
    ///
    /// An anchor is a tree *root*, not a block identity. Sibling blocks can mint identical
    /// notes and so carry an identical root, and `anchor_block` keeps only the last one
    /// written — so which block a node resolves an anchor to depends on the order it validated
    /// them, orphans included. That is a consensus non-determinism.
    ///
    /// Crucially this reports siblings whose shielded state was NEVER persisted, rather than
    /// skipping them. A node persists shielded state only for chain candidates, so on the node
    /// that *rejects* a block the guilty orphan has no stored root and silently vanishes from
    /// any scan that requires one — which is precisely the case that needs reporting. An
    /// unpersisted sibling is recorded with `root_matches_anchor: None`, meaning "unknown from
    /// here, go ask a node that accepted the block".
    ///
    /// Siblings are the children of `source`'s selected parent, so this is a short bounded
    /// scan. Diagnostic path only — never consulted by validation.
    pub(super) fn source_sibling_blocks(
        &self,
        anchor: &[u8; 32],
        source: Hash,
        selected_parent: Hash,
    ) -> Vec<crate::processes::shielded_diag::SiblingBlock> {
        use crate::model::stores::relations::RelationsStoreReader;
        let mut out = Vec::new();
        let Ok(source_sp) = self.ghostdag_store.get_selected_parent(source) else { return out };
        let Ok(children) = self.relations_service.get_children(source_sp) else { return out };
        let indexed = self.shielded_state_manager.anchor_source_block(anchor).ok().flatten();
        for &sibling in children.read().iter() {
            if sibling == source {
                continue;
            }
            // `anchor_at` answers Ok(empty-tree root) for a block whose shielded state was never
            // stored, so it cannot distinguish "stored and different" from "never computed".
            // Treating the two alike is what made this scan report `ambiguity: none` on the very
            // node that needed the warning. `persist` writes only when the frontier is non-empty,
            // so a non-empty stored frontier is the honest test for "this node computed it".
            let persisted = self.shielded_state_manager.frontier_at(sibling).map(|f| f.size > 0).unwrap_or(false);
            let root_matches_anchor =
                if persisted { self.shielded_state_manager.anchor_at(sibling).ok().map(|a| &a == anchor) } else { None };
            let is_chain_ancestor = sibling == selected_parent
                || matches!(self.reachability_service.try_is_chain_ancestor_of(sibling, selected_parent), Ok(true));
            out.push(crate::processes::shielded_diag::SiblingBlock {
                block: sibling.to_string(),
                blue_score: self.ghostdag_store.get_blue_score(sibling).unwrap_or_default(),
                is_chain_ancestor,
                shielded_state_persisted: persisted,
                root_matches_anchor,
                indexed_as_source: indexed == Some(sibling),
            });
        }
        out
    }

    /// Calculates the UTXO state of `to` starting from the state of `from`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `from` from virtual.
    /// The function returns the top-most UTXO-valid block on `chain(to)` which is ideally
    /// `to` itself (with the exception of returning `from` if `to` is already known to be UTXO disqualified).
    /// When returning it is guaranteed that `diff` holds the diff of the returned block from virtual
    fn calculate_utxo_state_relatively(&self, stores: &VirtualStores, diff: &mut UtxoDiff, from: Hash, to: Hash) -> Hash {
        // Avoid reorging if disqualified status is already known
        if self.statuses_store.read().get(to).unwrap() == StatusDisqualifiedFromChain {
            return from;
        }

        let mut split_point: Option<Hash> = None;

        // Shielded (PLAN §2.4): a reorg's nullifier mutations are written in TWO batches, not one.
        //
        // Batch 1 (committed immediately after the down-walk, before the up-walk) holds the reverts
        // of the abandoned branch's nullifiers. It MUST land before the up-walk validates and
        // commits any new-branch block: `CachedDbAccess::delete` removes the key from the store
        // cache but only stages the RocksDB delete in the uncommitted batch, so `has()` misses the
        // cache and falls through to RocksDB where the key is still present. With a single
        // end-of-walk batch (the pre-F-01 design), abandoned-branch nullifiers therefore still read
        // as SPENT during the up-walk, and a new-branch block re-spending the same note would have
        // its spend wrongly dropped / the block disqualified via `commit_utxo_state` — a permanent
        // consensus divergence between nodes that reorged and nodes that never saw the abandoned
        // branch (audit finding F-01).
        //
        // Batch 2 (committed at the end of the walk, as before) holds the up-walk re-applies of the
        // rejoining branch's nullifiers. Inserts are cache-visible immediately, so within-walk
        // reads are unaffected; the batch still lands atomically at the end of the walk so a crash
        // mid-reorg can never leave the global nullifier set desynced from the selected chain
        // (there is no header commitment to detect such a split).
        //
        // Crash consistency: both batches are idempotent (deleting an absent key and re-inserting a
        // present key are no-ops in RocksDB) and the walk re-executes from the last committed
        // virtual state on restart, so a crash between batch 1 and batch 2 simply re-walks: reverts
        // are no-op deletes and re-applies re-run.
        let mut shielded_revert_batch = WriteBatch::default();

        // Walk down to the reorg split point
        for current in self.reachability_service.default_backward_chain_iterator(from) {
            if self.reachability_service.is_chain_ancestor_of(current, to) {
                split_point = Some(current);
                break;
            }

            let mergeset_diff = self.utxo_diffs_store.get(current).unwrap();
            // Apply the diff in reverse
            diff.with_diff_in_place(&mergeset_diff.as_reversed()).unwrap();

            // This chain block is leaving the selected chain, so remove the nullifiers it added
            // from the global set (its per-block frontier/supply snapshots are intrinsic and
            // retained for a rejoin). No-op for blocks with no shielded nullifiers.
            self.shielded_state_manager.revert_nullifiers_from_store(&mut shielded_revert_batch, current).unwrap();
        }

        // Commit the down-walk reverts NOW: RocksDB deletes staged in a batch are invisible to
        // store reads until the batch is written (see the F-01 comment above), and the up-walk
        // must observe the abandoned branch's nullifiers as unspent.
        self.db.write(shielded_revert_batch).unwrap();

        // NOTE: the up-walk no longer defers shielded writes into a batch — each re-apply is
        // committed inline (see below), because validation of new blocks in this same loop reads
        // the nullifier store directly and must observe them.

        let split_point = match split_point {
            Some(point) => point,
            None => {
                log::error!("Reorg split point not found for {from} -> {to}; declining reorg and staying on {from}");
                return from;
            }
        };
        debug!("VIRTUAL PROCESSOR, found split point: {split_point}");

        // A variable holding the most recent UTXO-valid block on `chain(to)` (note that it's maintained such
        // that 'diff' is always its UTXO diff from virtual)
        let mut diff_point = split_point;

        // Walk back up to the new virtual selected parent candidate
        let mut chain_block_counter = 0u64;
        let mut chain_disqualified_counter = 0u64;
        let mut lane_update_counter = 0u64;
        for (selected_parent, current) in self.reachability_service.forward_chain_iterator(split_point, to, true).tuple_windows() {
            if selected_parent != diff_point {
                // This indicates that the selected parent is disqualified, propagate up and continue
                let statuses_guard = self.statuses_store.upgradable_read();
                if statuses_guard.get(current).unwrap() != StatusDisqualifiedFromChain {
                    RwLockUpgradableReadGuard::upgrade(statuses_guard).set(current, StatusDisqualifiedFromChain).unwrap();
                    chain_disqualified_counter += 1;
                }
                continue;
            }

            match self.utxo_diffs_store.get(current) {
                Ok(mergeset_diff) => {
                    diff.with_diff_in_place(mergeset_diff.deref()).unwrap();
                    diff_point = current;

                    // This already-validated chain block is (re)joining the selected chain, so
                    // re-add the nullifiers it added from its stored per-block diff.
                    //
                    // Commit each re-apply IMMEDIATELY, for exactly the reason the down-walk
                    // commits its reverts immediately: RocksDB writes staged in a batch are
                    // invisible to store reads until written. This same loop also *validates new
                    // blocks* in the `KeyNotFound` arm below, and that path runs
                    // `partition_applied`, which resolves nullifier conflicts by reading the global
                    // store. With the re-applies still sitting unwritten in a batch, a freshly
                    // validated block sees their nullifiers as UNSPENT, accepts a spend that should
                    // have conflicted, and keeps its fee — so its expected coinbase carries a fee
                    // the chain never re-minted and the block is disqualified, permanently.
                    //
                    // Diagnosed live 2026-07-31: a fast-syncing node wedged at DAA 371,851 wanting
                    // out[0]=5724578600 where the chain had 5700000000 — one 24,578,600 sompi fee,
                    // from a spend whose 21 nullifiers were re-applied earlier in the same walk.
                    // The down-walk carries the same hazard and was already fixed this way; the
                    // up-walk was not.
                    let mut apply_batch = WriteBatch::default();
                    self.shielded_state_manager.apply_nullifiers_from_store(&mut apply_batch, current).unwrap();
                    self.db.write(apply_batch).unwrap();
                }
                Err(StoreError::KeyNotFound(_)) => {
                    if self.statuses_store.read().get(current).unwrap() == StatusDisqualifiedFromChain {
                        // Current block is already known to be disqualified
                        continue;
                    }

                    let header = self.headers_store.get_header(current).unwrap();
                    let mergeset_data = self.ghostdag_store.get_data(current).unwrap();
                    let pov_daa_score = header.daa_score;

                    let selected_parent_multiset_hash = self.utxo_multisets_store.get(selected_parent).unwrap();
                    let selected_parent_utxo_view = (&stores.utxo_set).compose(&*diff);

                    let mut ctx = UtxoProcessingContext::new(mergeset_data.into(), selected_parent_multiset_hash);

                    self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, pov_daa_score);
                    let res = self.verify_expected_utxo_state(&mut ctx, &selected_parent_utxo_view, &header);

                    match res {
                        Err(rule_error) => {
                            info!("Block {} is disqualified from virtual chain: {}", current, rule_error);
                            // F-09: a shielded-related disqualification of a CHAIN block means the
                            // local shielded state is likely inconsistent with the observed chain
                            // (e.g. a poisoned pruning-point IBD import). Once the shielded-stable
                            // flag was set, no failure path ever reset it, so this recurred forever
                            // with no operator signal and no recovery short of a DB wipe. Warn
                            // loudly and reset the flag so the next IBD re-validates the imported
                            // state against the PoW-committed coinbase binding (F-02): if the local
                            // state is actually fine (a one-off invalid block), the re-check
                            // short-circuits and re-sets the flag; if it is poisoned, the operator
                            // must resync.
                            if matches!(rule_error, RuleError::BadCoinbaseTransaction | RuleError::InvalidShieldedState(..)) {
                                warn!(
                                    "chain block {} failed shielded-related validation ({}): the local shielded state may be \
                                     inconsistent with the observed chain (possibly a poisoned shielded IBD import). Resetting the \
                                     shielded-stable flag so the next IBD re-checks the import; if this warning recurs after \
                                     re-import, a full resync of the node is required",
                                    current, rule_error
                                );
                                let mut pruning_meta_write = self.pruning_meta_stores.write();
                                let mut batch = WriteBatch::default();
                                pruning_meta_write.set_pruning_shielded_stable_flag(&mut batch, false).unwrap();
                                self.db.write(batch).unwrap();
                            }
                            self.statuses_store.write().set(current, StatusDisqualifiedFromChain).unwrap();
                            chain_disqualified_counter += 1;
                        }
                        Ok(smt_build) => {
                            debug!("VIRTUAL PROCESSOR, UTXO validated for {current}");

                            // Accumulate the diff
                            diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();
                            // Update the diff point
                            diff_point = current;
                            // Count lane updates from verified chain blocks
                            if let Some(ref build) = smt_build {
                                lane_update_counter += build.lane_update_count() as u64;
                            }
                            // Commit UTXO + SMT + shielded data for current chain block
                            let shielded_computed = ctx.shielded_computed.take();
                            let dev_accrued = ctx.dev_accrued;
                            self.commit_utxo_state(
                                current,
                                ctx.mergeset_diff,
                                ctx.multiset_hash,
                                ctx.mergeset_acceptance_data,
                                ctx.pruning_sample_from_pov.expect("verified"),
                                smt_build,
                                header.blue_score,
                                shielded_computed,
                                dev_accrued,
                            );
                            // Count the number of UTXO-processed chain blocks
                            chain_block_counter += 1;
                        }
                    }
                }
                Err(err) => panic!("unexpected error {err}"),
            }
        }
        // Report counters
        self.counters.chain_block_counts.fetch_add(chain_block_counter, Ordering::Relaxed);
        self.counters.lane_update_counts.fetch_add(lane_update_counter, Ordering::Relaxed);
        if chain_disqualified_counter > 0 {
            self.counters.chain_disqualified_counts.fetch_add(chain_disqualified_counter, Ordering::Relaxed);
        }

        // Commit the up-walk's nullifier re-applies atomically at the end of the walk (batch 2 of
        // the two-batch F-01 scheme; the down-walk reverts were already committed before the
        // up-walk). Empty (no shielded nullifiers touched) is a cheap no-op write.

        diff_point
    }

    fn commit_utxo_state(
        &self,
        current: Hash,
        mergeset_diff: UtxoDiff,
        multiset: MuHash,
        acceptance_data: AcceptanceData,
        pruning_sample_from_pov: Hash,
        smt_build: Option<kaspa_smt_store::processor::SmtBuild>,
        blue_score: u64,
        shielded_computed: Option<crate::processes::shielded::ComputedBlockShielded>,
        dev_accrued: u64,
    ) {
        let mut batch = WriteBatch::default();
        self.utxo_diffs_store.insert_batch(&mut batch, current, Arc::new(mergeset_diff)).unwrap();
        self.utxo_multisets_store.insert_batch(&mut batch, current, multiset).unwrap();
        self.acceptance_data_store.insert_batch(&mut batch, current, Arc::new(acceptance_data)).unwrap();
        // Note we call idempotent since this field can be populated during IBD with headers proof
        self.pruning_samples_store.insert_batch(&mut batch, current, pruning_sample_from_pov).idempotent().unwrap();
        // Flush SMT branch/lane/score-index changes (KIP-21) alongside UTXO data
        if let Some(build) = smt_build {
            let pd = build.payload_and_ctx_digest;
            let alc = build.active_lanes_count;
            let shortcut_block = build.inactivity_shortcut_block;
            build.flush(&self.smt_stores, &mut batch, blue_score, current).unwrap();
            use crate::model::stores::smt_metadata::SmtBlockMetadata;
            self.smt_metadata_store.insert_batch(&mut batch, current, SmtBlockMetadata::new(pd, shortcut_block, alc)).unwrap();
        }
        // Shielded state transition (PLAN §2.4): persist this block's frontier /
        // supply / nullifier-diff and add its nullifiers to the global set, in the
        // same atomic batch. Only non-trivial state is written, so blocks with no
        // shielded activity add nothing.
        if let Some(computed) = shielded_computed {
            self.shielded_state_manager.persist(&mut batch, current, &computed).unwrap();
        }
        // Dev-fee accrual rides the same atomic batch, so a crash can never leave a
        // block whose coinbase paid out but whose accrual still says it owes. Zero is
        // the store's default for a missing key, so pre-activation blocks write nothing.
        if dev_accrued > 0 {
            self.shielded_state_manager.set_dev_accrued(&mut batch, current, dev_accrued).unwrap();
        }
        let write_guard = self.statuses_store.set_batch(&mut batch, current, StatusUTXOValid).unwrap();
        self.db.write(batch).unwrap();
        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(write_guard);
    }

    fn calculate_and_commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        virtual_parents: Vec<Hash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        chain_path: &ChainPath,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let new_virtual_state = self.calculate_virtual_state(
            &virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            selected_parent_multiset,
            accumulated_diff,
        )?;
        self.commit_virtual_state(virtual_read, new_virtual_state.clone(), accumulated_diff, chain_path);
        Ok(new_virtual_state)
    }

    pub(super) fn calculate_virtual_state(
        &self,
        virtual_stores: &VirtualStores,
        virtual_parents: Vec<Hash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let selected_parent_utxo_view = (&virtual_stores.utxo_set).compose(&*accumulated_diff);
        let mut ctx = UtxoProcessingContext::new((&virtual_ghostdag_data).into(), selected_parent_multiset);

        // Calc virtual DAA score, difficulty bits and past median time
        let virtual_daa_window = self.window_manager.block_daa_window(&virtual_ghostdag_data)?;
        let virtual_bits = self.window_manager.calculate_difficulty_bits(&virtual_ghostdag_data, &virtual_daa_window);
        let virtual_past_median_time = self.window_manager.calc_past_median_time(&virtual_ghostdag_data)?.0;

        // Calc virtual UTXO state relative to selected parent
        self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, virtual_daa_window.daa_score);

        // Update the accumulated diff
        accumulated_diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();

        if self.toccata_activation.is_within_range_from_activation(virtual_daa_window.daa_score, 10_000) {
            self.toccata_logger.report_activation();
        }

        // Compute accepted_id_digests
        let accepted_id_digests = if self.toccata_activation.is_active(virtual_daa_window.daa_score) {
            let commit = self.compute_seq_commit(&ctx, &virtual_ghostdag_data, virtual_daa_window.daa_score);
            // Post-KIP21: single-element vec containing the seq_commit.
            // The virtual's SmtBuild is ephemeral - only chain blocks persist SMT state.
            vec![commit]
        } else {
            ctx.accepted_tx_ids.clone()
        };

        // Build the new virtual state
        let virtual_state = Arc::new(VirtualState::new(
            virtual_parents,
            virtual_daa_window.daa_score,
            virtual_bits,
            virtual_past_median_time,
            ctx.multiset_hash,
            ctx.mergeset_diff,
            accepted_id_digests,
            ctx.mergeset_rewards,
            virtual_daa_window.mergeset_non_daa,
            virtual_ghostdag_data,
        ));
        Ok(virtual_state)
    }

    /// KIP-21: Compute the sequencing commitment for the virtual block.
    fn compute_seq_commit(&self, ctx: &UtxoProcessingContext, virtual_ghostdag_data: &GhostdagData, daa_score: u64) -> Hash {
        use kaspa_seq_commit::hashing::mergeset_context_hash;
        use kaspa_seq_commit::types::MergesetContext;

        let selected_parent = ctx.selected_parent();
        let parent_header = self.headers_store.get_header(selected_parent).unwrap();
        let current_blue_score = virtual_ghostdag_data.blue_score;

        let inactivity_shortcut_block = self.compute_inactivity_shortcut_block(virtual_ghostdag_data);
        let context_hash =
            mergeset_context_hash(&MergesetContext { timestamp: parent_header.timestamp, daa_score, blue_score: current_blue_score });
        let inactivity_shortcut = self.inactivity_shortcut(inactivity_shortcut_block);

        let parent_seq_commit = parent_header.accepted_id_merkle_root;
        let data = self.collect_mergeset_seq_data(ctx);
        let lane_updates = self.resolve_lane_updates(
            &data,
            &context_hash,
            current_blue_score,
            parent_header.blue_score,
            selected_parent,
            parent_seq_commit,
        );
        let (parent_lanes_root, parent_active_lanes) = self.get_parent_lanes_root_and_count(selected_parent, parent_header.blue_score);
        let parent_state = crate::pipeline::virtual_processor::utxo_validation::ParentBlockSeqState {
            seq_commit: parent_seq_commit,
            blue_score: parent_header.blue_score,
            lanes_root: parent_lanes_root,
            active_lanes_count: parent_active_lanes,
        };

        let (commit, _build) = self.build_seq_commit(
            &parent_state,
            context_hash,
            current_blue_score,
            &lane_updates,
            data.miner_payload_leaves,
            selected_parent,
            inactivity_shortcut_block,
            inactivity_shortcut,
        );
        commit
    }

    /// Build the `accepted_id_digests` for the genesis block.
    ///
    /// Pre-KIP21: Vec of genesis tx ids.
    /// Post-KIP21: single-element vec with the genesis `seq_commit`.
    pub(super) fn compute_genesis_accepted_id_digests(&self, ghostdag_data: &GhostdagData) -> Vec<Hash> {
        let txs = self.genesis.build_genesis_transactions();
        if !self.toccata_activation.is_active(self.genesis.daa_score) {
            return txs.iter().map(|tx| tx.id()).collect();
        }

        use kaspa_consensus_core::BlueWorkType;
        use kaspa_hashes::SeqCommitActiveNode;
        use kaspa_seq_commit::hashing::{
            activity_digest_lane, activity_leaf, activity_root_hash, lane_key, lane_tip_next, mergeset_context_hash,
            miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit, seq_state_root, smt_leaf_hash,
        };
        use kaspa_seq_commit::types::{LaneTipInput, MergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState, SmtLeafInput};
        use kaspa_smt::SmtHasher;

        let blue_score = ghostdag_data.blue_score;
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp: self.genesis.timestamp,
            daa_score: self.genesis.daa_score,
            blue_score,
        });

        // Collect per-lane activity leaves from genesis transactions.
        let mut lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>> = std::collections::BTreeMap::new();
        for (idx, tx) in txs.iter().enumerate() {
            lane_activities.entry(*tx.subnetwork_id.as_bytes()).or_default().push(activity_leaf(&tx.id(), tx.version, idx as u32));
        }

        // Miner payload root for the single genesis block.
        let mpl = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &self.genesis.hash,
            blue_work_be_bytes: &BlueWorkType::ZERO.to_be_bytes(),
            payload: self.genesis.coinbase_payload,
        });
        let payload_root = miner_payload_root(std::iter::once(mpl));

        // Build SMT over an in-memory store - new lanes anchor at ZERO_HASH.
        let parent_seq_commit = ZERO_HASH;
        let leaf_updates = kaspa_smt::store::SortedLeafUpdates::from_unsorted(lane_activities.iter().map(|(lane_id, leaves)| {
            let lk = lane_key(lane_id);
            let ad = activity_digest_lane(leaves.iter().copied());
            let tip = lane_tip_next(&LaneTipInput {
                parent_ref: &parent_seq_commit,
                lane_key: &lk,
                activity_digest: &ad,
                context_hash: &context_hash,
            });
            kaspa_smt::store::LeafUpdate { key: lk, leaf_hash: smt_leaf_hash(&SmtLeafInput { lane_tip: &tip, blue_score }) }
        }));
        let empty_store = kaspa_smt::store::BTreeSmtStore::new();
        let (lanes_root, _) = kaspa_smt::tree::compute_root_update::<SeqCommitActiveNode, _>(
            &empty_store,
            SeqCommitActiveNode::empty_root(),
            leaf_updates,
        )
        .unwrap();

        // Genesis has no shortcut target, so Toccata commits ZERO_HASH at the activity-root level.
        let activity_root = activity_root_hash(&ZERO_HASH, &lanes_root);
        let pd = payload_and_context_digest(&context_hash, &payload_root);
        let state_root = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
        let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &state_root });
        vec![commit]
    }

    /// Read stored SMT metadata for the pruning point.
    ///
    /// The receiver derives `inactivity_shortcut_block` from chain headers, so it
    /// is not transmitted on the wire.
    pub fn get_pruning_point_smt_metadata(
        &self,
        expected_pruning_point: Hash,
    ) -> kaspa_consensus_core::errors::consensus::ConsensusResult<kaspa_consensus_core::api::SmtExportMetadata> {
        use kaspa_consensus_core::api::SmtExportMetadata;
        use kaspa_consensus_core::errors::consensus::ConsensusError;

        let pp = self.pruning_point_store.read().pruning_point().unwrap();
        if pp != expected_pruning_point {
            return Err(ConsensusError::UnexpectedPruningPoint);
        }
        // Genesis has no SMT metadata row and no parent to index.
        if pp == self.genesis.hash {
            return Err(ConsensusError::GeneralOwned("cannot export SMT metadata: pruning point is genesis".to_string()));
        }

        let meta = self
            .smt_metadata_store
            .get(pp)
            .map_err(|_| ConsensusError::GeneralOwned(format!("SMT metadata not found for pruning point {pp}")))?;

        let pp_header = self.headers_store.get_header(pp).unwrap();
        let parent = pp_header.direct_parents()[0];
        let parent_header = self.headers_store.get_header(parent).unwrap();
        let parent_seq_commit = parent_header.accepted_id_merkle_root;
        let lanes_root = self
            .smt_stores
            .get_lanes_root(SmtReadBounds::for_pov(pp_header.blue_score, self.finality_depth), |bh| self.is_smt_canonical(bh, pp));

        Ok(SmtExportMetadata {
            lanes_root,
            payload_and_ctx_digest: meta.payload_and_ctx_digest(),
            parent_seq_commit,
            active_lanes_count: meta.active_lanes_count(),
        })
    }

    /// Check if `block_hash` is canonical for SMT lookups.
    /// ZERO_HASH is treated as always canonical - it marks IBD-imported entries.
    ///
    /// After reachability pruning, blocks that were on the selected chain before
    /// a reorg may have their reachability data deleted - their SMT lane entries
    /// remain but they are no longer canonical. `Err(KeyNotFound)` from
    /// `try_is_chain_ancestor_of` means the block's reachability was pruned,
    /// so it is definitively outside `future(retention_root)` and non-canonical.
    pub fn is_smt_canonical(&self, block_hash: Hash, selected_parent: Hash) -> bool {
        block_hash == ZERO_HASH || matches!(self.reachability_service.try_is_chain_ancestor_of(block_hash, selected_parent), Ok(true))
    }

    /// KIP-21: block hash of the highest chain block at
    /// `bs <= ghostdag_data.blue_score - finality_depth - 1`. The committed
    /// `inactivity_shortcut` value is this block's seq_commit (see
    /// [`Self::inactivity_shortcut`]).
    ///
    /// Never returns `ZERO_HASH`. Before a real seqcommit-bearing shortcut block
    /// is reachable, the returned block can be genesis or another pre-Toccata
    /// ancestor and [`Self::inactivity_shortcut`] folds it to `ZERO_HASH`.
    pub(super) fn compute_inactivity_shortcut_block(&self, ghostdag_data: &GhostdagData) -> Hash {
        let selected_parent = ghostdag_data.selected_parent;

        if ghostdag_data.blue_score < self.finality_depth + 1 {
            return self.genesis.hash;
        }

        let target_bs = ghostdag_data.blue_score - self.finality_depth - 1;

        let bounds = SmtReadBounds::new(target_bs, 0);

        match self
            .smt_stores
            .get_lane(kaspa_seq_commit::hashing::COINBASE_LANE_KEY, bounds, |bh| self.is_smt_canonical(bh, selected_parent))
            .map(|l| l.block_hash())
        {
            // Live: the latest canonical coinbase touch already pins the highest
            // chain block at `bs <= target_bs` since every chain block touches the
            // coinbase lane. Return it directly.
            Some(v) if v != ZERO_HASH => return v,
            // Post-IBD boundary, "exact at pp": target_bs == pp.bs
            Some(_zero) => {}
            // Post-IBD boundary, "below pp": target_bs < pp.bs and no coinbase
            // entry exists at that depth in our SMT. Fall through to seed the
            // forward walk from the selected parent's recorded shortcut.
            None => {}
        };

        // Reaching this point implies `target_bs <= pp.bs`. The coinbase lane is touched by every
        // chain block, so for any `target_bs > pp.bs` we would have returned in the `Some(v) if
        // v != ZERO_HASH` arm above. That gives us `current.bs <= pp.bs + finality_depth + 1`:
        // we are in the narrow post-IBD window of at most `finality_depth + 1` blocks past pp.
        //
        // Inside that window, `selected_parent` is either pp itself, a post-IBD local
        // descendant of pp, or a pre-Toccata selected parent right after activation:
        //   - pp: inserted by `Consensus::import_pruning_point_smt` via `SmtBlockMetadata::new(...)`.
        //   - local descendant: committed by `commit_virtual_state` via `SmtBlockMetadata::new(...)`.
        //   - pre-Toccata sp: has no metadata row, so it is used directly and
        //     folded to ZERO_HASH by `inactivity_shortcut` until a later chain
        //     child is deep enough for the coinbase-lane fast path.
        let search_from = self
            .smt_metadata_store
            .get(selected_parent)
            .optional()
            .unwrap()
            .map(|md| md.inactivity_shortcut_block())
            .unwrap_or(selected_parent);

        let mut current = search_from;
        for chain_block in self.reachability_service.forward_chain_iterator(current, selected_parent, true).skip(1) {
            if self.headers_store.get_blue_score(chain_block).unwrap() > target_bs {
                break;
            }
            current = chain_block;
        }
        current
    }

    /// Derive the `inactivity_shortcut` value folded into `activity_root` from
    /// its block hash. Folds to `ZERO_HASH` for pre-Toccata blocks, whose
    /// headers do not encode a seqcommit. Otherwise returns the block's seqcommit.
    ///
    /// Panics on `ZERO_HASH` input — callers must pass a real block hash.
    pub fn inactivity_shortcut(&self, inactivity_shortcut_block: Hash) -> Hash {
        assert_ne!(inactivity_shortcut_block, ZERO_HASH, "inactivity_shortcut block must be a real block hash");
        let header = self.headers_store.get_header(inactivity_shortcut_block).unwrap();
        if !self.toccata_activation.is_active(header.daa_score) {
            return ZERO_HASH;
        }
        header.accepted_id_merkle_root
    }

    /// Resolve the `inactivity_shortcut_block` from the POV of an arbitrary chain
    /// block, using only headers + reachability (no SMT). Used by the IBD receiver
    /// at the PP boundary before the SMT is imported, and by `import_pruning_point_smt`
    /// to populate the pruning point metadata row.
    ///
    /// Algorithm: walks `pov_block`'s selected-chain ancestors backward by blue_score
    /// until `bs <= pov.bs - finality_depth - 1`. Folds to genesis on shallow chains,
    /// matching [`Self::compute_inactivity_shortcut_block`]'s shallow-chain rule.
    pub fn inactivity_shortcut_block_for_pov(
        &self,
        pov_block: Hash,
    ) -> kaspa_consensus_core::errors::consensus::ConsensusResult<Hash> {
        use kaspa_consensus_core::errors::consensus::ConsensusError;

        let pov_header = self
            .headers_store
            .get_header(pov_block)
            .map_err(|_| ConsensusError::GeneralOwned(format!("header not found for {pov_block}")))?;

        if pov_header.blue_score < self.finality_depth + 1 {
            return Ok(self.genesis.hash);
        }
        let target_bs = pov_header.blue_score - self.finality_depth - 1;
        self.reachability_service
            .default_backward_chain_iterator(pov_block)
            .find(|&h| {
                h == self.genesis.hash
                    || self.headers_store.get_blue_score(h).unwrap() <= target_bs
                    // Mirror `compute_inactivity_shortcut_block`: before a real
                    // seqcommit-bearing shortcut is reachable, a pre-Toccata
                    // ancestor is a valid shortcut block and folds to ZERO_HASH.
                    || !self.toccata_activation.is_active(self.headers_store.get_daa_score(h).unwrap())
            })
            .ok_or_else(|| {
                ConsensusError::GeneralOwned(format!(
                    "selected chain exhausted before shortcut anchor for {pov_block} (target_bs={target_bs})"
                ))
            })
    }

    /// Get the parent's lanes_root, active_lanes_count.
    /// lanes_root comes from the branch version store; the other two from metadata.
    /// When the parent has no stored metadata (e.g. pre-toccata or origin predecessor),
    /// returns `(empty_root, 0)`.
    pub(super) fn get_parent_lanes_root_and_count(&self, selected_parent: Hash, parent_blue_score: u64) -> (Hash, u64) {
        let active_lanes_count = self.smt_metadata_store.get(selected_parent).map(|meta| meta.active_lanes_count()).unwrap_or(0);
        let lanes_root = self.smt_stores.get_lanes_root(SmtReadBounds::for_pov(parent_blue_score, self.finality_depth), |bh| {
            self.is_smt_canonical(bh, selected_parent)
        });
        (lanes_root, active_lanes_count)
    }

    /// Expire lanes that fall out of the active window between parent and current blue score.
    /// Returns the number of lanes expired.
    pub(super) fn expire_stale_lanes(
        &self,
        proc: &mut kaspa_smt_store::processor::SmtProcessor,
        bounds: SeqCommitBounds,
        selected_parent: Hash,
    ) -> u64 {
        let read_bounds = bounds.selected_parent_read_bounds();
        let Some(expired_range) = bounds.newly_expired_range() else {
            return 0;
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut expired = 0u64;
        // Iterate score_index entries in [prev_min, curr_min) to find lanes that might expire
        for entry in self.smt_stores.score_index.get_leaf_updates(expired_range) {
            let entry = entry.unwrap();
            // Only process canonical entries
            if !self.is_smt_canonical(entry.block_hash(), selected_parent) {
                continue;
            }
            for lk in entry.data().iter().filter(|lk| seen.insert(**lk)) {
                // Check if this lane has a newer canonical version within [curr_min, parent].
                // target=parent filters anticone entries at (parent, current] at the seek level.
                let is_expired = self.smt_stores.get_lane(*lk, read_bounds, |bh| self.is_smt_canonical(bh, selected_parent)).is_none();

                if is_expired {
                    proc.expire_lane(*lk);
                    expired += 1;
                }
            }
        }
        expired
    }

    fn commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        new_virtual_state: Arc<VirtualState>,
        accumulated_diff: &UtxoDiff,
        chain_path: &ChainPath,
    ) {
        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        let mut selected_chain_write = self.selected_chain_store.write();

        // Apply the accumulated diff to the virtual UTXO set
        virtual_write.utxo_set.write_diff_batch(&mut batch, accumulated_diff).unwrap();

        // Update virtual state
        virtual_write.state.set_batch(&mut batch, new_virtual_state.clone()).unwrap();

        // Update the virtual selected chain
        selected_chain_write.apply_changes(&mut batch, chain_path).unwrap();

        // Flush the batch changes
        self.db.write(batch).unwrap();

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(virtual_write);
        drop(selected_chain_write);
    }

    /// Caches the DAA and Median time windows of the sink block (if needed). Following, virtual's window calculations will
    /// naturally hit the cache finding the sink's windows and building upon them.
    fn cache_sink_windows(&self, new_sink: Hash, prev_sink: Hash, sink_ghostdag_data: &impl Deref<Target = Arc<GhostdagData>>) {
        // We expect that the `new_sink` is cached (or some close-enough ancestor thereof) if it is equal to the `prev_sink`,
        // Hence we short-circuit the check of the keys in such cases, thereby reducing the access of the read-lock
        if new_sink != prev_sink {
            // this is only important for ibd performance, as we incur expensive cache misses otherwise.
            // this occurs because we cannot rely on header processing to pre-cache in this scenario.
            if !self.block_window_cache_for_difficulty.contains_key(&new_sink) {
                self.block_window_cache_for_difficulty
                    .insert(new_sink, self.window_manager.block_daa_window(sink_ghostdag_data.deref()).unwrap().window);
            };

            if !self.block_window_cache_for_past_median_time.contains_key(&new_sink) {
                self.block_window_cache_for_past_median_time
                    .insert(new_sink, self.window_manager.calc_past_median_time(sink_ghostdag_data.deref()).unwrap().1);
            };
        }
    }

    /// Returns the max number of tips to consider as virtual parents in a single virtual resolve operation.
    ///
    /// Guaranteed to be `>= self.max_block_parents`
    fn max_virtual_parent_candidates(&self, max_block_parents: usize) -> usize {
        // Limit to max_block_parents x 3 candidates. This way we avoid going over thousands of tips when the network isn't healthy.
        // There's no specific reason for a factor of 3, and its not a consensus rule, just an estimation for reducing the amount
        // of candidates considered.
        max_block_parents * 3
    }

    /// Searches for the next valid sink block (SINK = Virtual selected parent). The search is performed
    /// in the inclusive past of `tips`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `prev_sink` from virtual.
    /// The function returns with `diff` being the diff of the new sink from previous virtual.
    /// In addition to the found sink the function also returns a queue of additional virtual
    /// parent candidates ordered in descending blue work order.
    pub(super) fn sink_search_algorithm(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        prev_sink: Hash,
        tips: Vec<Hash>,
        finality_point: Hash,
        pruning_point: Hash,
    ) -> (Hash, VecDeque<Hash>) {
        // TODO (relaxed): additional tests

        let mut heap = tips
            .into_iter()
            .map(|block| SortableBlock { hash: block, blue_work: self.ghostdag_store.get_blue_work(block).unwrap() })
            .collect::<BinaryHeap<_>>();

        // The initial diff point is the previous sink
        let mut diff_point = prev_sink;

        // We maintain the following invariant: `heap` is an antichain.
        // It holds at step 0 since tips are an antichain, and remains through the loop
        // since we check that every pushed block is not in the past of current heap
        // (and it can't be in the future by induction)
        loop {
            let candidate = heap.pop().expect("valid sink must exist").hash;
            if self.reachability_service.is_chain_ancestor_of(finality_point, candidate) {
                diff_point = self.calculate_utxo_state_relatively(stores, diff, diff_point, candidate);
                if diff_point == candidate {
                    // This indicates that candidate has valid UTXO state and that `diff` represents its diff from virtual

                    // All blocks with lower blue work than filtering_root are:
                    // 1. not in its future (bcs blue work is monotonic),
                    // 2. will be removed eventually by the bounded merge check.
                    // Hence as an optimization we prefer removing such blocks in advance to allow valid tips to be considered.
                    let filtering_root = self.depth_store.merge_depth_root(candidate).unwrap();
                    let filtering_blue_work = self.ghostdag_store.get_blue_work(filtering_root).unwrap_or_default();
                    return (
                        candidate,
                        heap.into_sorted_iter().take_while(|s| s.blue_work >= filtering_blue_work).map(|s| s.hash).collect(),
                    );
                } else {
                    debug!("Block candidate {} has invalid UTXO state and is ignored from Virtual chain.", candidate)
                }
            } else if finality_point != pruning_point {
                // `finality_point == pruning_point` indicates we are at IBD start hence no warning required
                warn!("Finality Violation Detected. Block {} violates finality and is ignored from Virtual chain.", candidate);
            }
            // PRUNE SAFETY: see comment within [`resolve_virtual`]
            let prune_guard = self.pruning_lock.blocking_read();
            for parent in self.relations_service.get_parents(candidate).unwrap().iter().copied() {
                if self.reachability_service.is_dag_ancestor_of(finality_point, parent)
                    && !self.reachability_service.is_dag_ancestor_of_any(parent, &mut heap.iter().map(|sb| sb.hash))
                {
                    heap.push(SortableBlock { hash: parent, blue_work: self.ghostdag_store.get_blue_work(parent).unwrap() });
                }
            }
            drop(prune_guard);
        }
    }

    /// Picks the virtual parents according to virtual parent selection pruning constrains.
    /// Assumes:
    ///     1. `selected_parent` is a UTXO-valid block
    ///     2. `candidates` are an antichain ordered in descending blue work order
    ///     3. `candidates` do not contain `selected_parent` and `selected_parent.blue work > max(candidates.blue_work)`  
    pub(super) fn pick_virtual_parents(
        &self,
        selected_parent: Hash,
        mut candidates: VecDeque<Hash>,
        pruning_point: Hash,
    ) -> (Vec<Hash>, GhostdagData) {
        // TODO (relaxed): additional tests

        // Mergeset increasing might traverse DAG areas which are below the finality point and which theoretically
        // can borderline with pruned data, hence we acquire the prune lock to ensure data consistency. Note that
        // the final selected mergeset can never be pruned (this is the essence of the prunality proof), however
        // we might touch such data prior to validating the bounded merge rule. All in all, this function is short
        // enough so we avoid making further optimizations
        let _prune_guard = self.pruning_lock.blocking_read();
        let max_block_parents = self.max_block_parents as usize;
        let mergeset_size_limit = self.mergeset_size_limit;
        let max_candidates = self.max_virtual_parent_candidates(max_block_parents);

        // Prioritize half the blocks with highest blue work and pick the rest randomly to ensure diversity between nodes
        if candidates.len() > max_candidates {
            // make_contiguous should be a no op since the deque was just built
            let slice = candidates.make_contiguous();

            // Keep slice[..max_block_parents / 2] as is, choose max_candidates - max_block_parents / 2 in random
            // from the remainder of the slice while swapping them to slice[max_block_parents / 2..max_candidates].
            //
            // Inspired by rand::partial_shuffle (which lacks the guarantee on chosen elements location).
            for i in max_block_parents / 2..max_candidates {
                let j = rand::thread_rng().gen_range(i..slice.len()); // i < max_candidates < slice.len()
                slice.swap(i, j);
            }

            // Truncate the unchosen elements
            candidates.truncate(max_candidates);
        } else if candidates.len() > max_block_parents / 2 {
            // Fallback to a simpler algo in this case
            candidates.make_contiguous()[max_block_parents / 2..].shuffle(&mut rand::thread_rng());
        }

        let mut virtual_parents = Vec::with_capacity(min(max_block_parents, candidates.len() + 1));
        virtual_parents.push(selected_parent);
        let mut mergeset_size = 1; // Count the selected parent

        // Try adding parents as long as mergeset size and number of parents limits are not reached
        while let Some(candidate) = candidates.pop_front() {
            if mergeset_size >= mergeset_size_limit || virtual_parents.len() >= max_block_parents {
                break;
            }
            match self.mergeset_increase(&virtual_parents, candidate, mergeset_size_limit - mergeset_size) {
                MergesetIncreaseResult::Accepted { increase_size } => {
                    mergeset_size += increase_size;
                    virtual_parents.push(candidate);
                }
                MergesetIncreaseResult::Rejected { new_candidate } => {
                    // If we already have a candidate in the past of new candidate then skip.
                    if self.reachability_service.is_any_dag_ancestor(&mut candidates.iter().copied(), new_candidate) {
                        continue; // TODO (optimization): not sure this check is needed if candidates invariant as antichain is kept
                    }
                    // Remove all candidates which are in the future of the new candidate
                    candidates.retain(|&h| !self.reachability_service.is_dag_ancestor_of(new_candidate, h));
                    candidates.push_back(new_candidate);
                }
            }
        }
        assert!(mergeset_size <= mergeset_size_limit);
        assert!(virtual_parents.len() <= max_block_parents);
        self.remove_bounded_merge_breaking_parents(virtual_parents, pruning_point)
    }

    fn mergeset_increase(&self, selected_parents: &[Hash], candidate: Hash, budget: u64) -> MergesetIncreaseResult {
        /*
        Algo:
            Traverse past(candidate) \setminus past(selected_parents) and make
            sure the increase in mergeset size is within the available budget
        */

        let candidate_parents = self.relations_service.get_parents(candidate).unwrap();
        let mut queue: VecDeque<_> = candidate_parents.iter().copied().collect();
        let mut visited: BlockHashSet = queue.iter().copied().collect();
        let mut mergeset_increase = 1u64; // Starts with 1 to count for the candidate itself

        while let Some(current) = queue.pop_front() {
            if self.reachability_service.is_dag_ancestor_of_any(current, &mut selected_parents.iter().copied()) {
                continue;
            }
            mergeset_increase += 1;
            if mergeset_increase > budget {
                return MergesetIncreaseResult::Rejected { new_candidate: current };
            }

            let current_parents = self.relations_service.get_parents(current).unwrap();
            for &parent in current_parents.iter() {
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        MergesetIncreaseResult::Accepted { increase_size: mergeset_increase }
    }

    fn remove_bounded_merge_breaking_parents(
        &self,
        mut virtual_parents: Vec<Hash>,
        current_pruning_point: Hash,
    ) -> (Vec<Hash>, GhostdagData) {
        let mut ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        let merge_depth_root = self.depth_manager.calc_merge_depth_root(&ghostdag_data, current_pruning_point);
        let mut kosherizing_blues: Option<Vec<Hash>> = None;
        let mut bad_reds = Vec::new();

        //
        // Note that the code below optimizes for the usual case where there are no merge-bound-violating blocks.
        //

        // Find red blocks violating the merge bound and which are not kosherized by any blue
        for red in ghostdag_data.mergeset_reds.iter().copied() {
            if self.reachability_service.is_dag_ancestor_of(merge_depth_root, red) {
                continue;
            }
            // Lazy load the kosherizing blocks since this case is extremely rare
            if kosherizing_blues.is_none() {
                kosherizing_blues = Some(self.depth_manager.kosherizing_blues(&ghostdag_data, merge_depth_root).collect());
            }
            if !self.reachability_service.is_dag_ancestor_of_any(red, &mut kosherizing_blues.as_ref().unwrap().iter().copied()) {
                bad_reds.push(red);
            }
        }

        if !bad_reds.is_empty() {
            // Remove all parents which lead to merging a bad red
            virtual_parents.retain(|&h| !self.reachability_service.is_any_dag_ancestor(&mut bad_reds.iter().copied(), h));
            // Recompute ghostdag data since parents changed
            ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        }

        (virtual_parents, ghostdag_data)
    }

    fn validate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
        virtual_daa_score: u64,
        virtual_past_median_time: u64,
        args: &TransactionValidationArgs,
        selected_parent: Hash,
        virtual_blue_score: u64,
    ) -> TxResult<()> {
        self.transaction_validator.validate_tx_in_isolation(&mutable_tx.tx)?;
        self.transaction_validator.validate_tx_in_header_context_with_args(
            &mutable_tx.tx,
            virtual_daa_score,
            virtual_past_median_time,
        )?;
        self.validate_mempool_transaction_in_utxo_context(
            mutable_tx,
            virtual_utxo_view,
            virtual_daa_score,
            args,
            selected_parent,
            virtual_blue_score,
        )?;
        Ok(())
    }

    pub fn validate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;

        let sp = virtual_state.ghostdag_data.selected_parent;
        // The virtual's own blue score is the context a transaction admitted now would be
        // judged in — not the selected parent's, which is lower by the whole mergeset and
        // would age shielded anchors more strictly than the block that carries them.
        let virtual_blue_score = virtual_state.ghostdag_data.blue_score;
        // Run within the thread pool since par_iter might be internally applied to inputs
        self.thread_pool.install(|| {
            self.validate_mempool_transaction_impl(
                mutable_tx,
                virtual_utxo_view,
                virtual_daa_score,
                virtual_past_median_time,
                args,
                sp,
                virtual_blue_score,
            )
        })
    }

    pub fn validate_mempool_transactions_in_parallel(
        &self,
        mutable_txs: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;
        let virtual_sp = virtual_state.ghostdag_data.selected_parent;
        let virtual_blue_score = virtual_state.ghostdag_data.blue_score;
        self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| {
                    self.validate_mempool_transaction_impl(
                        mtx,
                        &virtual_utxo_view,
                        virtual_daa_score,
                        virtual_past_median_time,
                        args.get(&mtx.id()),
                        virtual_sp,
                        virtual_blue_score,
                    )
                })
                .collect::<Vec<TxResult<()>>>()
        })
    }

    fn populate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view)?;
        Ok(())
    }

    pub fn populate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.populate_mempool_transaction_impl(mutable_tx, virtual_utxo_view)
    }

    pub fn populate_mempool_transactions_in_parallel(&self, mutable_txs: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| self.populate_mempool_transaction_impl(mtx, &virtual_utxo_view))
                .collect::<Vec<TxResult<()>>>()
        })
    }

    fn validate_block_template_transactions_in_parallel<V: UtxoView + Sync>(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &V,
    ) -> Vec<TxResult<u64>> {
        self.thread_pool
            .install(|| txs.par_iter().map(|tx| self.validate_block_template_transaction(tx, virtual_state, &utxo_view)).collect())
    }

    fn validate_block_template_transaction(
        &self,
        tx: &Transaction,
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> TxResult<u64> {
        // No need to validate the transaction in isolation since we rely on the mining manager to submit transactions
        // which were previously validated through `validate_mempool_transaction_and_populate`, hence we only perform
        // in-context validations
        self.transaction_validator.validate_tx_in_header_context_with_args(
            tx,
            virtual_state.daa_score,
            virtual_state.past_median_time,
        )?;
        // Template transaction validation uses virtual's DAA score. This score is carried into the block as its
        // DAA score, and it must also serve as the POV DAA score because this is the only available POV at template time.
        //
        // For seqcommit, the template itself cannot be used as context: its hash is not available yet, and transactions
        // cannot meaningfully depend on the seqcommit context of the block that is still being built. We therefore use
        // the selected parent as the seqcommit context.
        let ValidatedTransaction { calculated_fee, .. } = self.validate_transaction_in_utxo_context(
            tx,
            utxo_view,
            virtual_state.daa_score,
            virtual_state.daa_score,
            TxValidationFlags::Full,
            virtual_state.ghostdag_data.selected_parent,
        )?;
        Ok(calculated_fee)
    }

    pub fn build_block_template(
        &self,
        miner_data: MinerData,
        mut tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        //
        // TODO (relaxed): additional tests
        //

        // We call for the initial tx batch before acquiring the virtual read lock,
        // optimizing for the common case where all txs are valid. Following selection calls
        // are called within the lock in order to preserve validness of already validated txs
        let mut txs = tx_selector.select_transactions();
        let mut calculated_fees = Vec::with_capacity(txs.len());
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;

        let mut invalid_transactions = HashMap::new();
        let results = self.validate_block_template_transactions_in_parallel(&txs, &virtual_state, &virtual_utxo_view);
        for (tx, res) in txs.iter().zip(results) {
            match res {
                Err(e) => {
                    invalid_transactions.insert(tx.id(), e);
                    tx_selector.reject_selection(tx.id());
                }
                Ok(fee) => {
                    calculated_fees.push(fee);
                }
            }
        }

        let mut has_rejections = !invalid_transactions.is_empty();
        if has_rejections {
            txs.retain(|tx| !invalid_transactions.contains_key(&tx.id()));
        }

        while has_rejections {
            has_rejections = false;
            let next_batch = tx_selector.select_transactions(); // Note that once next_batch is empty the loop will exit
            let next_batch_results =
                self.validate_block_template_transactions_in_parallel(&next_batch, &virtual_state, &virtual_utxo_view);
            for (tx, res) in next_batch.into_iter().zip(next_batch_results) {
                match res {
                    Err(e) => {
                        invalid_transactions.insert(tx.id(), e);
                        tx_selector.reject_selection(tx.id());
                        has_rejections = true;
                    }
                    Ok(fee) => {
                        txs.push(tx);
                        calculated_fees.push(fee);
                    }
                }
            }
        }

        // Check whether this was an overall successful selection episode. We pass this decision
        // to the selector implementation which has the broadest picture and can use mempool config
        // and context
        match (build_mode, tx_selector.is_successful()) {
            (TemplateBuildMode::Standard, false) => return Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)),
            (TemplateBuildMode::Standard, true) | (TemplateBuildMode::Infallible, _) => {}
        }

        // At this point we can safely drop the read lock
        drop(virtual_read);

        // Build the template
        self.build_block_template_from_virtual_state(virtual_state, miner_data, txs, calculated_fees)
    }

    pub(crate) fn validate_block_template_transactions(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> Result<(), RuleError> {
        // Search for invalid transactions
        let mut invalid_transactions = HashMap::new();
        for tx in txs.iter() {
            if let Err(e) = self.validate_block_template_transaction(tx, virtual_state, utxo_view) {
                invalid_transactions.insert(tx.id(), e);
            }
        }
        if !invalid_transactions.is_empty() { Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)) } else { Ok(()) }
    }

    pub(crate) fn build_block_template_from_virtual_state(
        &self,
        virtual_state: Arc<VirtualState>,
        miner_data: MinerData,
        mut txs: Vec<Transaction>,
        calculated_fees: Vec<u64>,
    ) -> Result<BlockTemplate, RuleError> {
        // [`calc_block_parents`] can use deep blocks below the pruning point for this calculation, so we
        // need to hold the pruning lock.
        let _prune_guard = self.pruning_lock.blocking_read();
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let header_pruning_point =
            self.pruning_point_manager.expected_header_pruning_point(virtual_state.ghostdag_data.to_compact()).pruning_point;
        // Commit to the selected parent's shielded state root (PLAN §2.10) so the template's
        // coinbase matches what `verify_coinbase_transaction` will expect for this block.
        let shielded_commitment = self.shielded_state_manager.state_root_at(virtual_state.ghostdag_data.selected_parent).unwrap();
        let parent_daa_score = self.headers_store.get_daa_score(virtual_state.ghostdag_data.selected_parent).unwrap();
        let dev_accrued_parent = self.shielded_state_manager.dev_accrued_at(virtual_state.ghostdag_data.selected_parent).unwrap();
        let coinbase = self
            .coinbase_manager
            .expected_coinbase_transaction(
                virtual_state.daa_score,
                miner_data.clone(),
                &virtual_state.ghostdag_data,
                &virtual_state.mergeset_rewards,
                &virtual_state.mergeset_non_daa,
                shielded_commitment,
                parent_daa_score,
                dev_accrued_parent,
            )
            .unwrap();
        txs.insert(0, coinbase.tx);
        let version = self.block_version.get(virtual_state.daa_score);
        assert_eq!(virtual_state.ghostdag_data.selected_parent, virtual_state.parents[0]);
        let parents_by_level = self.parents_manager.calc_block_parents(pruning_point, &virtual_state.parents);
        assert_eq!(virtual_state.ghostdag_data.selected_parent, parents_by_level.get(0).unwrap()[0]);
        let hash_merkle_root = calc_hash_merkle_root(txs.iter());

        let utxo_commitment = virtual_state.multiset.clone().finalize();
        // Past median time is the exclusive lower bound for valid block time, so we increase by 1 to get the valid min
        let min_block_time = virtual_state.past_median_time + 1;

        let accepted_id_merkle_root = if self.toccata_activation.is_active(virtual_state.daa_score) {
            // Post-KIP21: accepted_id_digests[0] = seq_commit
            virtual_state.accepted_id_digests[0]
        } else {
            self.calc_accepted_id_merkle_root(
                virtual_state.accepted_id_digests.iter().copied(),
                virtual_state.ghostdag_data.selected_parent,
            )
        };

        let header = Header::new_finalized(
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            u64::max(min_block_time, unix_now()),
            virtual_state.bits,
            0,
            virtual_state.daa_score,
            virtual_state.ghostdag_data.blue_work,
            virtual_state.ghostdag_data.blue_score,
            header_pruning_point,
        );
        let selected_parent_hash = virtual_state.ghostdag_data.selected_parent;
        let selected_parent_timestamp = self.headers_store.get_timestamp(selected_parent_hash).unwrap();
        let selected_parent_daa_score = self.headers_store.get_daa_score(selected_parent_hash).unwrap();
        Ok(BlockTemplate::new(
            MutableBlock::new(header, txs),
            miner_data,
            coinbase.has_red_reward,
            selected_parent_timestamp,
            selected_parent_daa_score,
            selected_parent_hash,
            calculated_fees,
        ))
    }

    /// Make sure pruning point-related stores are initialized
    pub fn init(self: &Arc<Self>) {
        let pruning_point_read = self.pruning_point_store.upgradable_read();
        if pruning_point_read.pruning_point().optional().unwrap().is_none() {
            let mut pruning_point_write = RwLockUpgradableReadGuard::upgrade(pruning_point_read);
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            let mut batch = WriteBatch::default();
            self.past_pruning_points_store.insert_batch(&mut batch, 0, self.genesis.hash).idempotent().unwrap();
            pruning_point_write.set_batch(&mut batch, self.genesis.hash, 0).unwrap();
            pruning_point_write.set_retention_checkpoint(&mut batch, self.genesis.hash).unwrap();
            pruning_point_write.set_retention_period_root(&mut batch, self.genesis.hash).unwrap();
            pruning_meta_write.set_utxoset_position(&mut batch, self.genesis.hash).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_point_write);
            drop(pruning_meta_write);
        }
    }

    /// Initializes UTXO state of genesis and points virtual at genesis.
    /// Note that pruning point-related stores are initialized by `init`
    pub fn process_genesis(self: &Arc<Self>) {
        // Write the UTXO state of genesis
        self.commit_utxo_state(
            self.genesis.hash,
            UtxoDiff::default(),
            MuHash::new(),
            AcceptanceData::default(),
            ZERO_HASH,
            None,
            0,
            None,
            0,
        );

        // Init the virtual selected chain store
        let mut batch = WriteBatch::default();
        let mut selected_chain_write = self.selected_chain_store.write();
        selected_chain_write.init_with_pruning_point(&mut batch, self.genesis.hash).unwrap();
        self.db.write(batch).unwrap();
        drop(selected_chain_write);

        // Init virtual state - pre-compute accepted_id_digests here so
        // VirtualState::from_genesis stays a plain data constructor.
        let ghostdag_data = self.ghostdag_manager.ghostdag(&[self.genesis.hash]);
        let accepted_id_digests = self.compute_genesis_accepted_id_digests(&ghostdag_data);
        self.commit_virtual_state(
            self.virtual_stores.upgradable_read(),
            Arc::new(VirtualState::from_genesis(&self.genesis, ghostdag_data, accepted_id_digests)),
            &Default::default(),
            &Default::default(),
        );
    }

    /// Finalizes the pruning point utxoset state and imports the pruning point utxoset *to* virtual utxoset
    pub fn import_pruning_point_utxo_set(
        &self,
        new_pruning_point: Hash,
        mut imported_utxo_multiset: MuHash,
    ) -> PruningImportResult<()> {
        info!("Importing the UTXO set of the pruning point {}", new_pruning_point);
        let new_pruning_point_header = self.headers_store.get_header(new_pruning_point).unwrap();
        let imported_utxo_multiset_hash = imported_utxo_multiset.finalize();
        if imported_utxo_multiset_hash != new_pruning_point_header.utxo_commitment {
            return Err(PruningImportError::ImportedMultisetHashMismatch(
                new_pruning_point_header.utxo_commitment,
                imported_utxo_multiset_hash,
            ));
        }

        {
            // Set the pruning point utxoset position to the new point we just verified
            let mut batch = WriteBatch::default();
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            pruning_meta_write.set_utxoset_position(&mut batch, new_pruning_point).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_meta_write);
        }

        {
            // Copy the pruning-point UTXO set into virtual's UTXO set
            let pruning_meta_read = self.pruning_meta_stores.read();
            let mut virtual_write = self.virtual_stores.write();

            virtual_write.utxo_set.clear().unwrap();
            for chunk in &pruning_meta_read.utxo_set.iterator().map(|iter_result| iter_result.unwrap()).chunks(1000) {
                virtual_write.utxo_set.write_from_iterator_without_cache(chunk).unwrap();
            }
        }

        let virtual_read = self.virtual_stores.upgradable_read();
        // Seqcommit validation uses the pruning point's selected parent as context. Post-Toccata chain
        // qualification enforces first parent = selected parent; for genesis imports, use genesis itself.
        let sp = new_pruning_point_header.direct_parents().first().copied().unwrap_or(new_pruning_point);
        // Validate transactions of the pruning point itself.
        // Mirrors the same contextual info used by validate_block_template_transaction and verify_expected_utxo_state.
        let new_pruning_point_transactions = self.block_transactions_store.get(new_pruning_point).unwrap();
        let validated_transactions = self.validate_transactions_in_parallel(
            &new_pruning_point_transactions,
            &virtual_read.utxo_set,
            new_pruning_point_header.daa_score,
            new_pruning_point_header.daa_score,
            TxValidationFlags::Full,
            sp,
        );
        if validated_transactions.len() < new_pruning_point_transactions.len() - 1 {
            // TODO: handle this failure together with pruning point body merkle validation, not as a
            // plain UTXO-set validation failure. No alternate UTXO set can satisfy this pruning point
            // commitment, so the node likely needs a DB reset.
            warn!(
                "Imported pruning point {} has transactions invalid under its imported UTXO set; node likely needs a DB reset",
                new_pruning_point
            );
            return Err(PruningImportError::NewPruningPointTxErrors);
        }

        {
            // Submit partial UTXO state for the pruning point.
            // Note we only have and need the multiset; acceptance data and utxo-diff are irrelevant.
            let mut batch = WriteBatch::default();
            self.utxo_multisets_store.set_batch(&mut batch, new_pruning_point, imported_utxo_multiset.clone()).unwrap();

            let statuses_write = self.statuses_store.set_batch(&mut batch, new_pruning_point, StatusUTXOValid).unwrap();
            self.db.write(batch).unwrap();
            drop(statuses_write);
        }

        // Calculate the virtual state, treating the pruning point as the only virtual parent
        let virtual_parents = vec![new_pruning_point];
        let virtual_ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);

        self.calculate_and_commit_virtual_state(
            virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            imported_utxo_multiset.clone(),
            &mut UtxoDiff::default(),
            &ChainPath::default(),
        )?;

        Ok(())
    }

    pub fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        // Ideally we would want to check if the last known pruning point has the finality point
        // in its chain, but in some cases it's impossible: let `lkp` be the last known pruning
        // point from the list, and `fup` be the first unknown pruning point (the one following `lkp`).
        // fup.blue_score - lkp.blue_score ≈ finality_depth (±k), so it's possible for `lkp` not to
        // have the finality point in its past. So we have no choice but to check if `lkp`
        // has `finality_point.finality_point` in its chain (in the worst case `fup` is one block
        // above the current finality point, and in this case `lkp` will be a few blocks above the
        // finality_point.finality_point), meaning this function can only detect finality violations
        // in depth of 2*finality_depth, and can give false negatives for smaller finality violations.
        let current_pp = self.pruning_point_store.read().pruning_point().unwrap();
        let vf = self.virtual_finality_point(&self.lkg_virtual_state.load().ghostdag_data, current_pp);
        let vff = self.depth_manager.calc_finality_point(&self.ghostdag_store.get_data(vf).unwrap(), current_pp);

        let last_known_pp = pp_list.iter().rev().find(|pp| match self.statuses_store.read().get(pp.hash).optional().unwrap() {
            Some(status) => status.is_valid(),
            None => false,
        });

        if let Some(last_known_pp) = last_known_pp {
            !self.reachability_service.is_chain_ancestor_of(vff, last_known_pp.hash)
        } else {
            // If no pruning point is known, there's definitely a finality violation
            // (normally at least genesis should be known).
            true
        }
    }

    /// Executes `op` within the thread pool associated with this processor.
    pub fn install<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        self.thread_pool.install(op)
    }
}

enum MergesetIncreaseResult {
    Accepted { increase_size: u64 },
    Rejected { new_candidate: Hash },
}
