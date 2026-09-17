use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    ibd::{HeadersChunkStream, TrustedEntryStream, negotiate::ChainNegotiationOutput},
};
use futures::future::{Either, join_all, select, try_join_all};
use itertools::Itertools;
use kaspa_consensus_core::{
    BlockHashSet,
    api::{BlockValidationFuture, ShieldedHistoryVerdict},
    block::Block,
    config::params::{ForkActivation, Params},
    header::Header,
    pruning::{PruningPointProof, PruningPointsList, PruningProofMetadata},
    trusted::TrustedBlock,
    tx::Transaction,
};
use kaspa_consensusmanager::{ConsensusProxy, StagingConsensus, spawn_blocking};
use kaspa_core::{debug, info, time::unix_now, warn};
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use kaspa_p2p_lib::{
    PeerKey,
    IncomingRoute, Router,
    common::ProtocolError,
    convert::{
        header::{HeaderFormat, Versioned},
        model::trusted::TrustedDataPackage,
    },
    dequeue_with_timeout, make_message, make_request,
    pb::{
        RequestAntipastMessage, RequestBlockBodiesMessage, RequestHeadersMessage, RequestIbdBlocksMessage,
        RequestPruningPointAndItsAnticoneMessage, RequestPruningPointProofMessage, RequestPruningPointUtxoSetMessage,
        kaspad_message::Payload,
    },
};
use kaspa_utils::channel::JobReceiver;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;

use super::{HeadersChunk, IBD_BATCH_SIZE, PruningPointUtxosetChunkStream, progress::ProgressReporter};
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

type BlockBody = Vec<Transaction>;

/// Flow for managing IBD - Initial Block Download
pub struct IbdFlow {
    pub(super) ctx: FlowContext,
    pub(super) router: Arc<Router>,
    pub(super) incoming_route: IncomingRoute,
    pub(super) body_only_ibd_permitted: bool,
    header_format: HeaderFormat,

    // Receives relay blocks from relay flow which are out of orphan resolution range and hence trigger IBD
    relay_receiver: JobReceiver<Block>,
}

#[async_trait::async_trait]
impl Flow for IbdFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

/// Set once shielded history has been obtained, so no further peer is ever asked.
static SHIELDED_HISTORY_BACKFILL_DONE: AtomicBool = AtomicBool::new(false);

/// Which peers have been asked for shielded history this process, by identity — NOT a count.
///
/// A single global attempt was too few and unlimited retries were far too many. A peer on a build
/// without `RequestShieldedHistory` closes the connection rather than ignoring it, so each ask
/// costs one dropped link: retrying per-IBD walked the entire peer set (459 attempts / 28 minutes
/// observed, node frozen at 0 UTXO-validated blocks), while one attempt per PROCESS spent itself
/// on whichever peer happened to be first — measured, an incapable one — and the node then never
/// tried again although a capable peer was available.
///
/// Keyed by peer identity because a counter is not enough: a failed ask ends the IBD, the node
/// reconnects to the SAME peer, and a counter happily spends the whole budget on it. Observed
/// 2026-08-08 on a node with exactly one peer, logging "3 of 8 peers asked" — three drops of the
/// one link, a miniature of the storm the guard exists to prevent.
static SHIELDED_HISTORY_ASKED_PEERS: Mutex<Option<HashSet<PeerKey>>> = Mutex::new(None);

/// Peer budget for the history backfill; see [`SHIELDED_HISTORY_ASKED_PEERS`].
const SHIELDED_HISTORY_MAX_PEERS: usize = 8;

pub enum IbdType {
    Sync {
        highest_known_syncer_chain_hash: Hash,
        is_utxo_stable: bool,
        is_smt_stable: bool,
        is_shielded_stable: bool,
        is_pp_anticone_synced: bool,
    },
    DownloadHeadersProof,
    PruningCatchUp {
        highest_known_syncer_chain_hash: Hash,
    },
}

struct QueueChunkOutput {
    jobs: Vec<BlockValidationFuture>,
    daa_score: u64,
    timestamp: u64,
}
// TODO: define a peer banning strategy

impl IbdFlow {
    pub fn new(
        ctx: FlowContext,
        router: Arc<Router>,
        incoming_route: IncomingRoute,
        relay_receiver: JobReceiver<Block>,
        body_only_ibd_permitted: bool,
        header_format: HeaderFormat,
    ) -> Self {
        Self { ctx, router, incoming_route, relay_receiver, body_only_ibd_permitted, header_format }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        // The backfill below runs inside `ibd()`, and a node enters IBD only when it is behind.
        // A node that was synced BEFORE its build learned to backfill (a miner's in-process node
        // upgraded in place, 2026-09-17: log full of accepted blocks, never a history line, wallet
        // refused forever) never IBDs again, so it never asked. Ask here too, once the node is
        // synced and the history is still incomplete; same peer budget, same one-ask-per-peer.
        self.backfill_if_synced_and_incomplete().await;
        while let Ok(relay_block) = self.relay_receiver.recv().await {
            if let Some(_guard) = self.ctx.try_set_ibd_running(self.router.key(), relay_block.header.daa_score) {
                info!("IBD started with peer {}", self.router);

                match self.ibd(relay_block).await {
                    Ok(_) => info!("IBD with peer {} completed successfully", self.router),
                    Err(e) => {
                        info!("IBD with peer {} completed with error: {}", self.router, e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Fetch the pre-pruning-point shielded history from this peer when the node is already
    /// synced but still serves partial history — the case `ibd()` never reaches. Runs on this
    /// flow's own route, so it cannot interleave with an IBD on another peer's route; it is
    /// skipped while any IBD is running, since IBD renumbers the same chain index.
    async fn backfill_if_synced_and_incomplete(&mut self) {
        if !self.ctx.config.wants_shielded_history() || SHIELDED_HISTORY_BACKFILL_DONE.load(Ordering::SeqCst) {
            return;
        }
        if self.ctx.is_ibd_running() {
            return;
        }
        let session = self.ctx.consensus().session().await;
        if !self.ctx.is_nearly_synced(&session).await {
            return; // the IBD path handles a node that still has to sync
        }
        match session.async_get_shielded_history_status().await {
            Ok((_, true)) => {
                SHIELDED_HISTORY_BACKFILL_DONE.store(true, Ordering::SeqCst);
                return;
            }
            Ok((_, false)) => {}
            Err(_) => return,
        }
        let should_ask = {
            let mut guard = SHIELDED_HISTORY_ASKED_PEERS.lock().unwrap();
            let asked = guard.get_or_insert_with(HashSet::new);
            asked.len() < SHIELDED_HISTORY_MAX_PEERS && asked.insert(self.router.key())
        };
        if !should_ask {
            return;
        }
        info!("shielded history: this node is synced but holds partial history; asking {} to backfill it", self.router);
        match self.backfill_shielded_history(&session).await {
            Ok(()) => SHIELDED_HISTORY_BACKFILL_DONE.store(true, Ordering::SeqCst),
            Err(e) => {
                let asked = SHIELDED_HISTORY_ASKED_PEERS.lock().unwrap().as_ref().map_or(0, |s| s.len());
                let floor = session.async_get_shielded_history_status().await.map(|(daa, _)| daa).unwrap_or(0);
                warn!(
                    "archival: shielded history backfill did not complete from {} ({e}); {} of {} peers asked; \
                     this node serves shielded history from DAA {floor} (incomplete) for now",
                    self.router, asked, SHIELDED_HISTORY_MAX_PEERS
                );
            }
        }
    }

    async fn ibd(&mut self, relay_block: Block) -> Result<(), ProtocolError> {
        let mut session = self.ctx.consensus().session().await;

        let negotiation_output = self.negotiate_missing_syncer_chain_segment(&session).await?;
        let ibd_type = self
            .determine_ibd_type(
                &session,
                &relay_block.header,
                negotiation_output.highest_known_syncer_chain_hash,
                negotiation_output.syncer_pruning_point,
            )
            .await?;
        match ibd_type {
            IbdType::Sync {
                highest_known_syncer_chain_hash,
                is_utxo_stable,
                is_smt_stable,
                is_shielded_stable,
                is_pp_anticone_synced,
            } => {
                let pruning_point = session.async_pruning_point().await;

                info!("syncing ahead from current pruning point");
                // Following IBD catchup a new pruning point is designated and finalized in consensus. Blocks from its anticone (including itself)
                // have undergone normal header verification, but contain no body yet. Processing of new blocks in the pruning point's future cannot proceed
                // since these blocks' parents are missing block data.
                // Hence we explicitly process bodies of the currently body missing anticone blocks as trusted blocks
                // Notice that this is degenerate following sync_with_headers_proof
                // but not necessarily so after sync_headers -
                // as it might sync following a previous pruning_catch_up that crashed before this stage concluded
                if !is_pp_anticone_synced {
                    self.sync_missing_trusted_bodies(&session).await?;
                }
                // SMT state and utxoset are gated independently so that a partial-progress state
                // (e.g. SMT fully synced but utxoset sync interrupted mid-stream) can resume
                // without re-downloading the SMT lanes. The invariant
                //     is_utxo_stable => is_smt_stable
                // is still maintained by set/clear ordering, so skipping SMT when it is already
                // stable is always safe.
                if !is_smt_stable {
                    info!(
                        "SMT state corresponding to the current pruning point {} is incomplete, attempting to download it from {}",
                        pruning_point, self.router
                    );
                    self.sync_new_smt_state(&session, pruning_point).await?;
                } else {
                    // TODO(post-toccata): In pre-Toccata nodes there are some edge cases where the SMT stable flag is wrongly set to false at this point.
                    // Therefore, the below line can be removed post-Toccata.
                    session.async_set_pruning_smt_stable().await;
                }

                if !is_shielded_stable {
                    info!(
                        "shielded state corresponding to the current pruning point {} is incomplete, attempting to download it from {}",
                        pruning_point, self.router
                    );
                    self.sync_new_shielded_state(&session, pruning_point).await?;
                } else {
                    session.async_set_pruning_shielded_stable().await;
                }

                if !is_utxo_stable
                // Utxo might not be available even if the pruning point block data is.
                // Utxo must be synced before all so the node could function
                {
                    info!(
                        "utxoset corresponding to the current pruning point is incomplete, attempting to download it from {}",
                        self.router
                    );
                    self.sync_new_utxo_set(&session, pruning_point).await?;
                }

                // Once utxo is valid, simply sync missing headers
                self.sync_headers(
                    &session,
                    negotiation_output.syncer_virtual_selected_parent,
                    highest_known_syncer_chain_hash,
                    &relay_block,
                )
                .await?;
            }
            IbdType::DownloadHeadersProof => {
                drop(session); // Avoid holding the previous consensus throughout the staging IBD
                let staging = self.ctx.consensus_manager.new_staging_consensus();
                match self.ibd_with_headers_proof(&staging, negotiation_output.syncer_virtual_selected_parent, &relay_block).await {
                    Ok(()) => {
                        spawn_blocking(|| staging.commit()).await.unwrap();
                        info!(
                            "Header download stage of IBD with headers proof completed successfully from {}. Committed staging consensus.",
                            self.router
                        );

                        // This will reobtain the freshly committed staging consensus
                        session = self.ctx.consensus().session().await;
                        // Next, sync a utxoset corresponding to the new pruning point from the syncer.
                        // Note that the new pruning point's anticone need not be downloaded separately as in other IBD types
                        // as it was just downloaded as part of the headers proof.
                        self.sync_new_smt_state(&session, negotiation_output.syncer_pruning_point).await?;
                        self.sync_new_shielded_state(&session, negotiation_output.syncer_pruning_point).await?;
                        self.sync_new_utxo_set(&session, negotiation_output.syncer_pruning_point).await?;
                    }
                    Err(e) => {
                        warn!("IBD with headers proof from {} was unsuccessful ({})", self.router, e);
                        staging.cancel();
                        return Err(e);
                    }
                }
            }
            IbdType::PruningCatchUp { highest_known_syncer_chain_hash } => {
                info!("catching up to new pruning point {} ", negotiation_output.syncer_pruning_point);
                match self.pruning_point_catchup(&session, &negotiation_output, &relay_block, highest_known_syncer_chain_hash).await {
                    Ok(()) => {
                        info!("header stage of pruning catchup from peer {} completed", self.router);
                        self.sync_missing_trusted_bodies(&session).await?;
                        self.sync_new_smt_state(&session, negotiation_output.syncer_pruning_point).await?;
                        self.sync_new_shielded_state(&session, negotiation_output.syncer_pruning_point).await?;
                        self.sync_new_utxo_set(&session, negotiation_output.syncer_pruning_point).await?;
                        // Note that pruning of old data will only occur once virtual has caught up sufficiently far
                    }

                    Err(e) => {
                        warn!("IBD catchup from peer {} was unsuccessful ({})", self.router, e);
                        return Err(e);
                    }
                }
            }
        }

        // An archival node must hold ALL note history, not just the range it validated itself.
        // Every IBD path leaves it holding scan records only from the pruning point forward
        // (`PruningPointShieldedMetadata` carries the frontier and a nullifier MuHash — aggregates
        // that cannot yield notes), so a wallet querying it would see a silently partial balance.
        //
        // This runs for ALL IBD types deliberately: a fresh node always takes
        // `DownloadHeadersProof`, which is precisely the case the backfill exists for. Placing it
        // inside the `Sync` arm — as it first was — meant it never fired for a new node.
        //
        // Failure is logged, not fatal: the node is fully valid and correctly validating without
        // it; it just cannot serve pre-pruning-point wallet history until a later IBD retries.
        //
        // Bounded across peers rather than one shot. A peer without `RequestShieldedHistory`
        // CLOSES THE CONNECTION instead of ignoring it, so an ask costs a dropped link — but
        // stopping after one ask meant an incapable first peer permanently denied this node its
        // history (observed: the first peer closed the connection and nothing retried). See
        // [`SHIELDED_HISTORY_ASKED_PEERS`].
        //
        // The eventual fix is a protocol-version gate so the request is never sent to a peer that
        // cannot serve it. That needs `PROTOCOL_VERSION` bumped to 11 plus a `v11` flow registry
        // AND an explicit `10 => v10::register(...)` arm in `handle_handshake` — without that arm
        // every pre-bump peer is rejected with `VersionMismatch` instead of merely lacking the
        // feature. It also only pays once v11 peers exist, so the peer budget is what makes the
        // feature work on today's mixed network.
        // A node that already holds verified history from genesis (restarted after a completed
        // backfill, or one that built its whole index itself) has nothing to fetch. Asking anyway
        // logged "a fresh node holds none" on every restart and spent one ask — a dropped link on
        // a peer without the feature — for an empty chunk.
        let already_complete = self.ctx.config.wants_shielded_history()
            && !SHIELDED_HISTORY_BACKFILL_DONE.load(Ordering::SeqCst)
            && matches!(session.async_get_shielded_history_status().await, Ok((_, true)));
        if already_complete {
            debug!("shielded history: already complete from genesis; not asking {} for a backfill", self.router);
            SHIELDED_HISTORY_BACKFILL_DONE.store(true, Ordering::SeqCst);
        }
        // Ask this peer only if it is one we have not already asked, and only while under the
        // peer budget. Both conditions are evaluated once, under the lock, so a concurrent IBD
        // cannot slip a second ask to the same peer through.
        let should_ask = self.ctx.config.wants_shielded_history()
            && !SHIELDED_HISTORY_BACKFILL_DONE.load(Ordering::SeqCst)
            && {
                let mut guard = SHIELDED_HISTORY_ASKED_PEERS.lock().unwrap();
                let asked = guard.get_or_insert_with(HashSet::new);
                asked.len() < SHIELDED_HISTORY_MAX_PEERS && asked.insert(self.router.key())
            };
        if should_ask {
            match self.backfill_shielded_history(&session).await {
                Ok(()) => {
                    SHIELDED_HISTORY_BACKFILL_DONE.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    let asked = SHIELDED_HISTORY_ASKED_PEERS.lock().unwrap().as_ref().map_or(0, |s| s.len());
                    // Name the floor the node is left with, so an operator reading this line
                    // knows what wallets will see rather than only that something failed.
                    let floor = session.async_get_shielded_history_status().await.map(|(daa, _)| daa).unwrap_or(0);
                    warn!(
                        "archival: shielded history backfill did not complete from {} ({e}); {} of {} \
                         peers asked. Peers on a build without shielded-history support close the \
                         connection on this request. Wallet history below the pruning point is \
                         unavailable until a peer that supports it is reached — this node serves \
                         shielded history from DAA {floor} (incomplete) for now.",
                        self.router, asked, SHIELDED_HISTORY_MAX_PEERS
                    );
                }
            }
        }

        // Sync missing bodies in the past of syncer sink (virtual selected parent)
        self.sync_missing_block_bodies(&session, negotiation_output.syncer_virtual_selected_parent).await?;

        // Relay block might be in the antipast of syncer sink, thus
        // check its past for missing bodies as well.
        self.sync_missing_block_bodies(&session, relay_block.hash()).await?;

        // Following IBD we revalidate orphans since many of them might have been processed during the IBD
        // or are now processable
        let (queued_hashes, virtual_processing_tasks) = self.ctx.revalidate_orphans(&session).await;
        let mut unorphaned_hashes = Vec::with_capacity(queued_hashes.len());
        let results = join_all(virtual_processing_tasks).await;
        for (hash, result) in queued_hashes.into_iter().zip(results) {
            match result {
                Ok(_) => unorphaned_hashes.push(hash),
                // We do not return the error and disconnect here since we don't know
                // that this peer was the origin of the orphan block
                Err(e) => warn!("Validation failed for orphan block {}: {}", hash, e),
            }
        }
        match unorphaned_hashes.len() {
            0 => {}
            n => info!("IBD post processing: unorphaned {} blocks ...{}", n, unorphaned_hashes.last().unwrap()),
        }

        Ok(())
    }

    async fn determine_ibd_type(
        &self,
        consensus: &ConsensusProxy,
        relay_header: &Header,
        highest_known_syncer_chain_hash: Option<Hash>,
        syncer_pruning_point: Hash,
    ) -> Result<IbdType, ProtocolError> {
        if let Some(highest_known_syncer_chain_hash) = highest_known_syncer_chain_hash {
            let pruning_point = consensus.async_pruning_point().await;
            let sink = consensus.async_get_sink().await;
            info!("current sink is:{}", sink);
            info!("current pruning point is:{}", pruning_point);
            if consensus.async_is_chain_ancestor_of(pruning_point, highest_known_syncer_chain_hash).await? {
                /// Categorizes the syncer's pruning point position relative to local
                enum SyncerSkew {
                    Lagging,
                    Aligned,
                    Leading,
                }

                let syncer_skew = if syncer_pruning_point == pruning_point {
                    SyncerSkew::Aligned
                } else if consensus.async_is_chain_ancestor_of(pruning_point, syncer_pruning_point).await.unwrap_or(false) {
                    SyncerSkew::Leading
                } else if consensus.async_get_n_last_pruning_points(4 /*syncer lag tolerance*/).await.contains(&syncer_pruning_point) {
                    SyncerSkew::Lagging
                } else {
                    return Err(ProtocolError::Other(
                        "The syncer purports to have data in the recent future but their pruning point could not be easily recognized",
                    ));
                };

                let is_utxo_stable = consensus.async_is_pruning_utxoset_stable().await;
                let is_pp_anticone_synced = consensus.async_is_pruning_point_anticone_fully_synced().await;
                // The SMT stable flag is only meaningful once Toccata is active at the current
                // pruning point. Before activation, `sync_new_smt_state` is a no-op and the flag
                // is never set, so we treat it as stable to preserve pre-activation IBD behavior.
                let pp_header = consensus.async_get_header(pruning_point).await.unwrap();
                let is_smt_stable = if self.ctx.config.toccata_activation.is_active(pp_header.daa_score) {
                    consensus.async_is_pruning_smt_stable().await
                } else {
                    true
                };
                // Shielded-pool state (ZKas). The flag defaults to true (no shielded state / upgrading
                // nodes), and the sender replies with empty metadata when the pruning point has no
                // shielded state, so reading it unconditionally is safe.
                let is_shielded_stable = consensus.async_is_pruning_shielded_stable().await;

                return match (syncer_skew, is_utxo_stable && is_smt_stable && is_shielded_stable && is_pp_anticone_synced) {
                    (SyncerSkew::Aligned, _) => Ok(IbdType::Sync {
                        highest_known_syncer_chain_hash,
                        is_utxo_stable,
                        is_smt_stable,
                        is_shielded_stable,
                        is_pp_anticone_synced,
                    }),
                    (SyncerSkew::Lagging, true) => Ok(IbdType::Sync {
                        highest_known_syncer_chain_hash,
                        is_utxo_stable,
                        is_smt_stable,
                        is_shielded_stable,
                        is_pp_anticone_synced,
                    }),
                    (SyncerSkew::Lagging, false) => Err(ProtocolError::Other(
                        "Local node is in a transitional state requiring external data to stabilize, but the syncer lags behind and is unable to provide said data",
                    )),
                    (SyncerSkew::Leading, true) => {
                        if consensus.async_get_block_status(syncer_pruning_point).await.is_some_and(|b| b.has_block_body()) {
                            // While a leading syncer skew often indicates the need for catchup, in this case
                            // the node is just missing a segment in the future of its current pruning point, that is available to the syncer
                            Ok(IbdType::Sync {
                                highest_known_syncer_chain_hash,
                                is_utxo_stable,
                                is_smt_stable,
                                is_shielded_stable,
                                is_pp_anticone_synced,
                            })
                        } else {
                            Ok(IbdType::PruningCatchUp { highest_known_syncer_chain_hash })
                        }
                    }
                    (SyncerSkew::Leading, false) => Ok(IbdType::PruningCatchUp { highest_known_syncer_chain_hash }),
                };
            }

            // If the pruning point is not in the chain of `highest_known_syncer_chain_hash`, it
            // means it's in its antichain (because if `highest_known_syncer_chain_hash` was in
            // the pruning point's past the pruning point itself would be
            // `highest_known_syncer_chain_hash`). So it means there's a finality conflict.
            //
            // TODO (relaxed): consider performing additional actions on finality conflicts in addition
            // to disconnecting from the peer (e.g., banning, rpc notification)
            return Err(ProtocolError::Other("peer is in a finality conflict with the local pruning point"));
        }

        let hst_header = consensus.async_get_header(consensus.async_get_headers_selected_tip().await).await.unwrap();
        let pruning_depth = self.ctx.config.pruning_depth();
        if relay_header.blue_score >= hst_header.blue_score + pruning_depth && relay_header.blue_work > hst_header.blue_work {
            let finality_duration_in_milliseconds = self.ctx.config.finality_duration_in_milliseconds();
            if unix_now() > consensus.async_creation_timestamp().await + finality_duration_in_milliseconds {
                let fp = consensus.async_finality_point().await;
                let fp_ts = consensus.async_get_header(fp).await?.timestamp;
                if unix_now() < fp_ts + finality_duration_in_milliseconds * 3 / 2 {
                    // We reject the headers proof if the node has a relatively up-to-date finality point and current
                    // consensus has matured for long enough (and not recently synced). This is mostly a spam-protector
                    // since subsequent checks identify these violations as well
                    // TODO (relaxed): consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)
                    return Err(ProtocolError::Other(
                        "peer has no known block but local consensus appears to be up to date, this is most likely a spam attempt",
                    ));
                }
            }

            // The relayed block has sufficient blue score and blue work over the current header selected tip
            Ok(IbdType::DownloadHeadersProof)
        } else {
            Err(ProtocolError::Other("peer has no known block but conditions for requesting headers proof are not met"))
        }
    }

    /// This function is triggered when the syncer's pruning point is higher
    /// than ours and we already processed its header before.
    /// so we only need to sync more headers and set it to our new pruning point before proceeding with IBD
    async fn pruning_point_catchup(
        &mut self,
        consensus: &ConsensusProxy,
        negotiation_output: &ChainNegotiationOutput,
        relay_block: &Block,
        highest_known_syncer_chain_hash: Hash,
    ) -> Result<(), ProtocolError> {
        // Before attempting to update to the syncer's pruning point, sync to the latest headers of the syncer,
        // to ensure that we will locally have sufficient headers on top of the syncer's pruning point
        let syncer_pp = negotiation_output.syncer_pruning_point;
        let syncer_sink = negotiation_output.syncer_virtual_selected_parent;
        self.sync_headers(consensus, syncer_sink, highest_known_syncer_chain_hash, relay_block).await?;

        // This function's main effect is to confirm the syncer's pruning point can be finalized into the consensus, and to update
        // all the relevant stores
        consensus.async_intrusive_pruning_point_update(syncer_pp, syncer_sink).await?;

        // A sanity check to confirm that following the intrusive addition of new pruning points,
        // the latest pruning point still correctly agrees with the DAG data,
        // and is the head of a pruning points "chain" leading all the way down to genesis
        // TODO (relaxed): once the catchup functionality has sufficiently matured, consider only doing this test if sanity checks are enabled
        info!("validating pruning points consistency");
        consensus.async_validate_pruning_points(syncer_sink).await.unwrap();
        info!("pruning points consistency validated");
        Ok(())
    }

    async fn ibd_with_headers_proof(
        &mut self,
        staging: &StagingConsensus,
        syncer_virtual_selected_parent: Hash,
        relay_block: &Block,
    ) -> Result<(), ProtocolError> {
        info!("Starting IBD with headers proof with peer {}", self.router);

        let staging_session = staging.session().await;

        let pruning_point = self.sync_and_validate_pruning_proof(&staging_session, relay_block).await?;
        self.sync_headers(&staging_session, syncer_virtual_selected_parent, pruning_point, relay_block).await?;
        staging_session.async_validate_pruning_points(syncer_virtual_selected_parent).await?;
        self.validate_staging_timestamps(&self.ctx.consensus().session().await, &staging_session).await?;
        Ok(())
    }

    async fn sync_and_validate_pruning_proof(&mut self, staging: &ConsensusProxy, relay_block: &Block) -> Result<Hash, ProtocolError> {
        // [Toccata] Guard IBD from outdated nodes. P2P flow registration does not protect
        // fresh IBD peers, and the relay block is usually the syncer sink, so reject an unexpected
        // block version before requesting the pruning proof. The pruning point itself is
        // checked below by `validate_pruning_point_freshness_for_toccata`.
        let expected_relay_block_version = self.ctx.config.block_version().get(relay_block.header.daa_score);
        if relay_block.header.version != expected_relay_block_version {
            return Err(ProtocolError::OtherOwned(format!(
                "peer relayed block {} header version mismatch: got {}, expected {} at DAA score {} (Toccata guard)",
                relay_block.hash(),
                relay_block.header.version,
                expected_relay_block_version,
                relay_block.header.daa_score
            )));
        }

        self.router.enqueue(make_message!(Payload::RequestPruningPointProof, RequestPruningPointProofMessage {})).await?;

        // Pruning proof generation and communication might take several minutes, so we allow a long 10 minute timeout
        let msg = dequeue_with_timeout!(self.incoming_route, Payload::PruningPointProof, Duration::from_secs(600))?;
        let proof: PruningPointProof = Versioned(self.header_format, msg).try_into()?;
        info!(
            "Received headers proof with overall {} headers ({} unique)",
            proof.iter().map(|l| l.len()).sum::<usize>(),
            proof.iter().flatten().unique_by(|h| h.hash).count()
        );

        let proof_metadata = PruningProofMetadata::new(relay_block.header.blue_work);

        // Get a new session for current consensus (non staging)
        let consensus = self.ctx.consensus().session().await;

        // The proof is validated in the context of current consensus
        let proof =
            consensus.clone().spawn_blocking(move |c| c.validate_pruning_proof(&proof, &proof_metadata).map(|()| proof)).await?;

        let proof_pruning_point_header = proof[0].last().expect("was just ensured by validation");
        let proof_pruning_point = proof_pruning_point_header.hash;

        if proof_pruning_point == self.ctx.config.genesis.hash {
            return Err(ProtocolError::Other("the proof pruning point is the genesis block"));
        }

        if proof_pruning_point == consensus.async_pruning_point().await {
            return Err(ProtocolError::Other("the proof pruning point is the same as the current pruning point"));
        }
        drop(consensus);

        // [Toccata] Reject IBD from outdated peers
        validate_pruning_point_freshness_for_toccata(
            self.ctx.config.as_ref(),
            proof_pruning_point_header.hash,
            proof_pruning_point_header.timestamp,
            proof_pruning_point_header.daa_score,
            unix_now(),
        )?;

        self.router
            .enqueue(make_message!(Payload::RequestPruningPointAndItsAnticone, RequestPruningPointAndItsAnticoneMessage {}))
            .await?;
        // First, all pruning points up to the last are sent
        let msg = dequeue_with_timeout!(self.incoming_route, Payload::PruningPoints)?;
        let pruning_points: PruningPointsList = Versioned(self.header_format, msg).try_into()?;

        if pruning_points.is_empty() || pruning_points.last().unwrap().hash != proof_pruning_point {
            return Err(ProtocolError::Other("the proof pruning point is not equal to the last pruning point in the list"));
        }

        if pruning_points.first().unwrap().hash != self.ctx.config.genesis.hash {
            return Err(ProtocolError::Other("the first pruning point in the list is expected to be genesis"));
        }

        // Check if past pruning points violate finality of current consensus
        if self.ctx.consensus().session().await.async_are_pruning_points_violating_finality(pruning_points.clone()).await {
            // TODO (relaxed): consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)
            return Err(ProtocolError::Other("pruning points are violating finality"));
        }

        {
            // Sanity check for consistency between past pruning points and the headers proof
            let pruning_points_set: BlockHashSet = pruning_points.iter().map(|h| h.hash).collect();
            for level in proof.iter() {
                if let Some(root) = level.first()
                    && root.hash != self.ctx.config.genesis.hash
                    && !pruning_points_set.contains(&root.pruning_point)
                {
                    return Err(ProtocolError::Other("proof and past pruning points are inconsistent with each other"));
                }
            }
        }

        // Trusted data is sent in two stages:
        // The first, TrustedDataPackage, contains meta data about daa_window
        // blocks headers, and ghostdag data, which are required to verify the pruning
        // point and its anticone.
        // The latter, the trusted data entries, each represent a block (with daa) from the anticone of the pruning point
        // (including the PP itself), alongside indexing denoting the respective metadata headers or ghostdag data
        let msg = dequeue_with_timeout!(self.incoming_route, Payload::TrustedData)?;
        let pkg: TrustedDataPackage = Versioned(self.header_format, msg).try_into()?;
        debug!("received trusted data with {} daa entries and {} ghostdag entries", pkg.daa_window.len(), pkg.ghostdag_window.len());

        let mut entry_stream = TrustedEntryStream::new(&self.router, &mut self.incoming_route, self.header_format);
        // The first entry of the trusted data is the pruning point itself.
        let Some(pruning_point_entry) = entry_stream.next().await? else {
            return Err(ProtocolError::Other("got `done` message before receiving the pruning point"));
        };

        if pruning_point_entry.block.is_header_only() {
            return Err(ProtocolError::Other("pruning point entry is header-only"));
        }

        if pruning_point_entry.block.hash() != proof_pruning_point {
            return Err(ProtocolError::Other("the proof pruning point is not equal to the expected trusted entry"));
        }

        // TODO(optimization): this buffering can be heavy on RAM for large chain segments, but is acceptable
        // since syncee memory usage is still low at this phase.
        let mut entries = vec![pruning_point_entry];
        let mut header_only_chain_segment = Vec::new();
        // Each selected-chain block contributes at least one blue score, so F blue-depth back is bounded
        // by F chain blocks (plus 2K for noise/robustness).
        let max_header_only_chain_segment_len =
            self.ctx.config.finality_depth().saturating_add(2 * self.ctx.config.ghostdag_k() as u64 + 1);
        while let Some(entry) = entry_stream.next().await? {
            match entry.block.is_header_only() {
                true => {
                    if header_only_chain_segment.is_empty() {
                        info!("Finished downloading {} blocks from the pruning point anticone", entries.len() - 1);
                        info!("Starting to download the pruning point chain segment");
                    }
                    header_only_chain_segment.push(entry.block.header.clone());
                    if header_only_chain_segment.len().is_multiple_of(1000) {
                        info!("Downloaded {} headers from the pruning point chain segment", header_only_chain_segment.len());

                        if header_only_chain_segment.len() as u64 > max_header_only_chain_segment_len {
                            return Err(ProtocolError::OtherOwned(format!(
                                "pruning point chain segment length {} exceeds maximum {}",
                                header_only_chain_segment.len(),
                                max_header_only_chain_segment_len
                            )));
                        }
                    }
                }
                // We expect all header-only entries to be sent after all non-header-only entries
                false if header_only_chain_segment.is_empty() => {
                    entries.push(entry);
                    if (entries.len() - 1).is_multiple_of(1000) {
                        info!("Downloaded {} blocks from the pruning point anticone", entries.len() - 1);
                    }
                }
                false => {
                    return Err(ProtocolError::Other("trusted body entries arrived after header-only trusted entries"));
                }
            }
        }

        if header_only_chain_segment.is_empty() {
            // No chain segment means the anticone was not logged yet.
            info!("Finished downloading {} blocks from the pruning point anticone", entries.len() - 1);
        } else {
            info!("Finished downloading {} headers from the pruning point chain segment", header_only_chain_segment.len());
        }

        // Create a topologically ordered vector of trusted blocks - the pruning point and its anticone,
        // and their daa windows headers
        let mut trusted_set = pkg.build_trusted_subdag(entries)?;

        if self.ctx.config.enable_sanity_checks {
            let con = self.ctx.consensus().unguarded_session_blocking();
            trusted_set = staging
                .clone()
                .spawn_blocking(move |c| {
                    let ref_proof = proof.clone();
                    c.apply_pruning_proof(proof, &trusted_set, &header_only_chain_segment)?;
                    c.import_pruning_points(pruning_points)?;

                    info!("Building the proof which was just applied (sanity test)");
                    let built_proof = c.get_pruning_point_proof();
                    let mut mismatch_detected = false;
                    for (i, (ref_level, built_level)) in ref_proof.iter().zip(built_proof.iter()).enumerate() {
                        if ref_level.iter().map(|h| h.hash).collect::<BlockHashSet>()
                            != built_level.iter().map(|h| h.hash).collect::<BlockHashSet>()
                        {
                            mismatch_detected = true;
                            warn!("Locally built proof for level {} does not match the applied one", i);
                        }
                    }
                    if mismatch_detected {
                        info!("Validating the locally built proof (sanity test fallback #2)");
                        // Note: the proof is validated in the context of *current* consensus
                        if let Err(err) = con.validate_pruning_proof(&built_proof, &proof_metadata) {
                            panic!("Locally built proof failed validation: {}", err);
                        }
                        info!("Locally built proof was validated successfully");
                    } else {
                        info!("Proof was locally built successfully");
                    }
                    Result::<_, ProtocolError>::Ok(trusted_set)
                })
                .await?;
        } else {
            trusted_set = staging
                .clone()
                .spawn_blocking(move |c| {
                    c.apply_pruning_proof(proof, &trusted_set, &header_only_chain_segment)?;
                    c.import_pruning_points(pruning_points)?;
                    Result::<_, ProtocolError>::Ok(trusted_set)
                })
                .await?;
        }

        // TODO (relaxed): add logs to staging commit process

        info!("Starting to process {} trusted blocks", trusted_set.len());
        let mut last_time = Instant::now();
        let mut last_index: usize = 0;
        for (i, tb) in trusted_set.into_iter().enumerate() {
            let now = Instant::now();
            let passed = now.duration_since(last_time);
            if passed > Duration::from_secs(1) {
                info!("Processed {} trusted blocks in the last {:.2}s (total {})", i - last_index, passed.as_secs_f64(), i);
                last_time = now;
                last_index = i;
            }
            // TODO (relaxed): queue and join in batches
            staging.validate_and_insert_trusted_block(tb).virtual_state_task.await?;
        }
        staging.async_clear_body_missing_anticone_set().await;
        info!("Done processing trusted blocks");
        Ok(proof_pruning_point)
    }

    async fn sync_headers(
        &mut self,
        consensus: &ConsensusProxy,
        syncer_virtual_selected_parent: Hash,
        highest_known_syncer_chain_hash: Hash,
        relay_block: &Block,
    ) -> Result<(), ProtocolError> {
        let highest_shared_header_score = consensus.async_get_header(highest_known_syncer_chain_hash).await?.daa_score;
        let mut progress_reporter = ProgressReporter::new(highest_shared_header_score, relay_block.header.daa_score, "block headers");

        self.router
            .enqueue(make_message!(
                Payload::RequestHeaders,
                RequestHeadersMessage {
                    low_hash: Some(highest_known_syncer_chain_hash.into()),
                    high_hash: Some(syncer_virtual_selected_parent.into())
                }
            ))
            .await?;
        let mut chunk_stream = HeadersChunkStream::new(&self.router, &mut self.incoming_route, self.header_format);

        if let Some(chunk) = chunk_stream.next().await? {
            let (mut prev_daa_score, mut prev_timestamp) = {
                let last_header = chunk.last().expect("chunk is never empty");
                (last_header.daa_score, last_header.timestamp)
            };
            let mut prev_jobs: Vec<BlockValidationFuture> =
                chunk.into_iter().map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task).collect();

            while let Some(chunk) = chunk_stream.next().await? {
                let (current_daa_score, current_timestamp) = {
                    let last_header = chunk.last().expect("chunk is never empty");
                    (last_header.daa_score, last_header.timestamp)
                };
                let current_jobs = chunk
                    .into_iter()
                    .map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task)
                    .collect();
                let prev_chunk_len = prev_jobs.len();
                // Join the previous chunk so that we always concurrently process a chunk and receive another
                try_join_all(prev_jobs).await?;
                // Log the progress
                progress_reporter.report(prev_chunk_len, prev_daa_score, prev_timestamp);
                prev_daa_score = current_daa_score;
                prev_timestamp = current_timestamp;
                prev_jobs = current_jobs;
            }

            let prev_chunk_len = prev_jobs.len();
            try_join_all(prev_jobs).await?;
            progress_reporter.report_completion(prev_chunk_len);
        }

        if consensus.async_get_block_status(syncer_virtual_selected_parent).await.is_none() {
            // If the syncer's claimed sink header has still not been received, the peer is misbehaving
            return Err(ProtocolError::OtherOwned(format!(
                "did not receive syncer's virtual selected parent {} from peer {} during header download",
                syncer_virtual_selected_parent, self.router
            )));
        }

        self.sync_missing_relay_past_headers(consensus, syncer_virtual_selected_parent, relay_block.hash()).await?;

        Ok(())
    }

    async fn sync_new_smt_state(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        use super::streams::SmtStream;
        use kaspa_p2p_lib::pb::RequestPruningPointSmtStateMessage;
        use kaspa_seq_commit::verify::{SmtMetadata, verify_smt_metadata};

        let pp_header = consensus.async_get_header(pruning_point).await.unwrap();
        if !self.ctx.config.toccata_activation.is_active(pp_header.daa_score) {
            consensus.async_set_pruning_smt_stable().await;
            return Ok(());
        }

        consensus.async_clear_pruning_smt_stores().await;

        info!("downloading the pruning point SMT state from {}", self.router);

        self.router
            .enqueue(make_message!(
                Payload::RequestPruningPointSmtState,
                RequestPruningPointSmtStateMessage { pruning_point_hash: Some(pruning_point.into()) }
            ))
            .await?;

        let mut stream = SmtStream::new(&self.router, &mut self.incoming_route);

        // Phase 0: receive and verify metadata. Single 96-byte wire.
        let md = stream.recv_metadata().await?;
        let parent_header = consensus.async_get_header(pp_header.direct_parents()[0]).await.unwrap();

        // Derive the shortcut block via consensus (uses reachability + headers only; safe at the PP
        // boundary before the SMT is imported). Then resolve to the seqcommit hash with the same
        // fold-to-zero rule used by `inactivity_shortcut(block)`.
        let shortcut_block = consensus
            .async_inactivity_shortcut_block_for_pov(pruning_point)
            .await
            .map_err(|e| ProtocolError::OtherOwned(format!("inactivity_shortcut_block resolution failed: {e}")))?;
        let shortcut_header = consensus
            .async_get_header(shortcut_block)
            .await
            .map_err(|_| ProtocolError::Other("inactivity_shortcut_block header not found"))?;
        let inactivity_shortcut = if !self.ctx.config.toccata_activation.is_active(shortcut_header.daa_score) {
            kaspa_hashes::ZERO_HASH
        } else {
            shortcut_header.accepted_id_merkle_root
        };

        verify_smt_metadata(
            &SmtMetadata {
                lanes_root: &md.lanes_root,
                payload_and_ctx_digest: &md.payload_and_ctx_digest,
                parent_seq_commit: &md.parent_seq_commit,
            },
            inactivity_shortcut,
            pp_header.accepted_id_merkle_root,
            parent_header.accepted_id_merkle_root,
        )
        .map_err(|e| ProtocolError::OtherOwned(format!("SMT metadata verification failed: {e}")))?;

        // Small queue of already-chunked batches: one in flight + one being processed
        // by the importer is enough headroom; each chunk holds up to SMT_CHUNK_SIZE lanes.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<kaspa_consensus_core::api::ImportLane>>(2);

        let consensus_for_import = consensus.clone();
        let builder_handle =
            tokio::task::spawn_blocking(move || consensus_for_import.import_pruning_point_smt(pruning_point, md, shortcut_block, rx));

        while let Some(chunk) = stream.next_chunk().await? {
            tx.send(chunk).await.map_err(|_| ProtocolError::Other("streaming SMT builder stopped unexpectedly"))?;
        }
        drop(tx);

        builder_handle.await.map_err(|e| ProtocolError::OtherOwned(format!("SMT builder task panicked: {e}")))??;
        consensus.async_set_pruning_smt_stable().await;

        info!("SMT state synced: {} lanes", stream.lane_count());
        Ok(())
    }

    /// Download and import the shielded-pool state at the pruning point (ZKas IBD,
    /// PLAN §2.8/§2.9): the metadata frame (frontier, supply totals, nullifier
    /// accumulator, state root) plus the whole spent-nullifier set, streamed in
    /// flow-controlled chunks and seeded into consensus so the pruning point's
    /// descendants can be validated. Mirrors `sync_new_smt_state`.
    ///
    /// Audit hardening (F-02/F-15): before ANY peer data is trusted, the import is
    /// bound to PoW-committed data — the coinbase `shielded_commitment` of the
    /// pruning point's selected child on the proof-verified header chain. If the
    /// locally held state root already equals that commitment the import is
    /// skipped entirely (a re-import would union the seeded PP-time nullifier set
    /// into the live global set); if it differs, the import proceeds only when no
    /// validated chain blocks sit above the pruning point, and the seeded state
    /// must match the commitment.
    /// Backfill the shielded scan archive below this node's base, so an archival node really
    /// holds ALL history rather than only what it validated itself.
    ///
    /// A headers-proof sync writes scan records only from the pruning point forward, and
    /// `PruningPointShieldedMetadata` carries aggregates (frontier, nullifier MuHash) that cannot
    /// yield notes. Without this an `--archival` node silently serves partial wallet history —
    /// a restored seed shows a too-low balance with no error.
    ///
    /// Server-driven: this node cannot enumerate the range itself (its index is re-based to 0 at
    /// its own pruning point, and its header segment stops far above genesis), so it names an
    /// anchor and the peer walks its own selected chain downward.
    ///
    /// Consensus-safe by construction: the scan archive is never read by validation, so even a
    /// dishonest peer cannot fork this node — the cost of bad data is bounded to wallet serving,
    /// which is why the range is verified before history is advertised as complete.
    async fn backfill_shielded_history(&mut self, consensus: &ConsensusProxy) -> Result<(), ProtocolError> {
        use kaspa_p2p_lib::pb::RequestShieldedHistoryMessage;

        const MAX_BLOCKS_PER_CHUNK: u32 = 4_000;
        let mut anchor = consensus.async_get_shielded_history_base().await;
        // The base BEFORE any backfill: this node's own pruning point, and the only block down
        // here whose shielded frontier came from the chain rather than from the peer. Captured
        // now because ingesting the first chunk renumbers the index and moves the base.
        let verify_base = anchor;
        let (mut total_idx, mut total_rec, mut rounds) = (0u64, 0u64, 0u32);
        // The floor wallets see while this runs. On a first sync this whole fetch plus its
        // verification runs BEFORE block bodies are synced, so the node reports NOT synced and
        // its block count does not move for the duration — without saying so here, that reads as
        // a stalled sync (reported 2026-09: "why is it so long").
        let floor = consensus.async_get_shielded_history_status().await.map(|(daa, _)| daa).unwrap_or(0);
        info!(
            "shielded history: fetching note history below {anchor} from {} — a fresh node holds \
             none, so wallets would otherwise see a partial balance. Block-body sync waits for this \
             and its verification, so a first sync reports NOT synced meanwhile; wallets connecting \
             now see shielded history only from DAA {floor}",
            self.router
        );
        let started = std::time::Instant::now();
        // The peer's GENESIS-based index of our base, learned from the first chunk: exactly the
        // number of chain blocks below it, i.e. the whole job. Each chunk's lowest index is what
        // is still left, which is what makes a percentage and an ETA possible here.
        let mut total_chain_blocks: Option<u64> = None;
        let mut reached_genesis = false;

        loop {
            self.router
                .enqueue(make_message!(
                    Payload::RequestShieldedHistory,
                    RequestShieldedHistoryMessage { anchor_hash: anchor.as_bytes().to_vec(), max_blocks: MAX_BLOCKS_PER_CHUNK }
                ))
                .await?;

            let chunk_started = std::time::Instant::now();
            let msg = dequeue_with_timeout!(self.incoming_route, Payload::ShieldedHistoryChunk)?;
            if msg.entries.is_empty() {
                info!("archival: peer has no further shielded history below {anchor}");
                break;
            }

            let mut records = Vec::with_capacity(msg.entries.len());
            for e in &msg.entries {
                let data: kaspa_consensus_core::api::ShieldedChainBlockData = bincode::deserialize(&e.data)
                    .map_err(|err| ProtocolError::OtherOwned(format!("malformed shielded history record: {err}")))?;
                // The peer's GENESIS-based chain index rides with each record. It cannot be
                // inferred locally: this node's own index is re-based to 0 at its pruning point,
                // so the two numbering spaces do not align.
                records.push((e.chain_index, data));
            }
            records.sort_by_key(|(i, _)| *i);
            let lowest = records.first().map(|(_, r)| r.hash).unwrap_or(anchor);
            // Chain blocks still below the lowest record of this chunk (its index counts from 0
            // at genesis), so this is what remains to fetch after the chunk lands.
            let remaining = records.first().map(|(i, _)| *i).unwrap_or(0);
            let total = *total_chain_blocks.get_or_insert(msg.anchor_index);

            let (idx, rec) = consensus.async_backfill_shielded_history(anchor, msg.anchor_index, records).await?;
            total_idx += idx;
            total_rec += rec;
            rounds += 1;

            // Progress, not silence. This moves ~460k records over ~116 round trips while the
            // node does nothing else; with only a start and an end line, a run that wrote NOTHING
            // for 34 minutes looked exactly like one that was working. Reporting what was
            // actually WRITTEN is what makes that failure visible at a glance — and a percentage
            // with an ETA is what tells an operator it is a long job rather than a stuck one.
            let done_blocks = total.saturating_sub(remaining);
            let progress = if total > 0 && done_blocks > 0 {
                let pct = done_blocks as f64 * 100.0 / total as f64;
                let eta = started.elapsed().as_secs_f64() * remaining as f64 / done_blocks as f64;
                format!(" — {pct:.0}% ({remaining} of {total} chain blocks left), about {eta:.0}s left")
            } else {
                String::new()
            };
            info!(
                "archival: shielded history chunk {rounds}: +{rec} records (+{idx} index) in {:?}, total {total_rec} (at {lowest}){progress}",
                chunk_started.elapsed()
            );

            if msg.done {
                info!("archival: reached genesis after {rounds} rounds");
                reached_genesis = true;
                break;
            }
            // A chunk that stored nothing means our state is not advancing. Continuing would walk
            // to genesis writing nothing and then report success — the exact 34-minute no-op this
            // path used to perform. Stop loudly instead.
            if idx == 0 && rec == 0 {
                return Err(ProtocolError::OtherOwned(format!(
                    "shielded history chunk below {anchor} (peer index {}) stored nothing; refusing to spin",
                    msg.anchor_index
                )));
            }
            // If the walk stops descending, stop — otherwise this loops forever on one block.
            if lowest == anchor {
                warn!("archival: shielded history stopped descending at {anchor} after {rounds} rounds; stopping");
                break;
            }
            anchor = lowest;
        }

        info!(
            "shielded history: received {total_rec} block records ({total_idx} index entries) in {:.1}s; verifying \
             against the chain's own committed state before serving any of it",
            started.elapsed().as_secs_f64()
        );
        if !reached_genesis {
            // The loop stopped short (peer ran out, or stopped descending). Say where that leaves
            // wallets, in the same terms the RPC reports (`history_from_daa_score`).
            let floor = consensus.async_get_shielded_history_status().await.map(|(daa, _)| daa).unwrap_or(0);
            warn!(
                "shielded history: fetch stopped short of genesis; this node serves shielded history from DAA {floor} \
                 (incomplete) until a later IBD retries"
            );
        }

        // Verify before this history is served to anyone.
        //
        // Nothing above this point checked the peer's work. The scan archive is never read by
        // validation, so a dishonest peer cannot fork this node — but it can make every wallet
        // querying it report a wrong balance and a wrong history, with no symptom the user could
        // notice. Replaying the range reproduces this node's own PoW-anchored frontier only if
        // the peer supplied exactly the right leaves in exactly the right order, so omission,
        // reordering, fabrication and truncation are all caught by one comparison.
        //
        // Cost is dominated by re-reading the archive, not by the tree: appending is ~0.1 us/leaf
        // (~2.2M leaves today), while the replay also does one store read per chain block (~1.07M).
        // Unconditional anyway — it runs once per process, after a backfill that took far longer,
        // and the alternative is serving wallets history nobody ever checked.
        if total_rec > 0 {
            match consensus.async_verify_shielded_history(verify_base).await {
                Ok(ShieldedHistoryVerdict::Verified { blocks, leaves }) => {
                    // Say what this proves, not just that it passed: the replayed leaves reproduce
                    // a frontier this node learned from PoW, never from the peer that sent them.
                    info!(
                        "shielded history: VERIFIED — {leaves} note commitments over {blocks} blocks replay exactly \
                         to this node's proof-of-work-committed state. History is complete from genesis and safe \
                         to serve to wallets."
                    );
                }
                Ok(ShieldedHistoryVerdict::Mismatch { reason }) => {
                    // Discard what this peer gave us. Safe, not drastic: the node returns to the
                    // history it can prove, which is exactly where it started.
                    let discarded = match consensus.async_purge_shielded_history_below(verify_base).await {
                        Ok(n) => n,
                        Err(e) => {
                            // Could not undo. Say so loudly and precisely — the archive is now
                            // holding unverified records and no log line further up says that.
                            warn!(
                                "archival: shielded history from {} FAILED verification ({reason}) AND could not be \
                                 discarded ({e}); the archive holds UNVERIFIED records below {verify_base}. Re-verify \
                                 with --verify-shielded-history.",
                                self.router
                            );
                            return Err(ProtocolError::OtherOwned(format!("shielded history failed verification: {reason}")));
                        }
                    };
                    warn!(
                        "archival: shielded history from {} FAILED verification ({reason}); discarded {discarded} scan records",
                        self.router
                    );
                    return Err(ProtocolError::OtherOwned(format!("shielded history failed verification: {reason}")));
                }
                Ok(ShieldedHistoryVerdict::Unverifiable { reason }) => {
                    warn!("archival: shielded history could NOT be verified ({reason}); it is retained but unproven");
                }
                Err(e) => warn!("archival: shielded history verification did not run ({e}); history is retained but unproven"),
            }
        }
        // One closing line in the terms wallets and the RPC use, whatever path led here: the
        // Unverifiable/Err arms above leave the index reaching genesis but `history_complete`
        // false, and that is exactly the state a wallet's node check will report back.
        match consensus.async_get_shielded_history_status().await {
            Ok((_, true)) => info!("shielded history: backfill finished — complete from genesis; wallets may connect to this node"),
            Ok((floor, false)) => warn!(
                "shielded history: backfill finished but history is NOT complete (serving from DAA {floor}); wallets born \
                 before that see a partial balance"
            ),
            Err(_) => {}
        }
        Ok(())
    }

    async fn sync_new_shielded_state(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        use super::streams::ShieldedStream;
        use kaspa_p2p_lib::pb::RequestPruningPointShieldedStateMessage;

        // F-02: determine the PoW-committed shielded state root for this pruning point.
        let binding = self.shielded_pp_commitment(consensus, pruning_point).await?;

        if let Some(&(child, committed)) = binding.as_ref() {
            // F-15: if the locally held state root at the pruning point already equals the
            // PoW-committed root, the local state IS the committed state (the root binds the
            // frontier, supply totals, burns and the nullifier-set accumulator) — skip the
            // import entirely. This covers the fully-synced PruningCatchUp node (whose global
            // nullifier set reflects its old tip; the pre-fix unconditional re-import UNIONED
            // the seeded PP-time set into it, freezing spends of unspent notes), a crash
            // between seed and stable-flag write, and the default-true flag on a network with
            // no shielded activity.
            let local_root = consensus
                .async_get_shielded_state_root(pruning_point)
                .await
                .map_err(|e| ProtocolError::OtherOwned(format!("local shielded state root at pruning point {pruning_point}: {e}")))?;
            if local_root == committed {
                info!(
                    "local shielded state at pruning point {} already matches the PoW-committed root; skipping re-import",
                    pruning_point
                );
                consensus.async_set_pruning_shielded_stable().await;
                return Ok(());
            }

            // F-15 SAFETY: the re-import below clears the global nullifier set. If the pruning
            // point's selected child was already UTXO-validated locally, validated chain blocks
            // above the pruning point have contributed nullifiers to that set which a clear
            // would destroy without revalidation. An honest node in that situation matches the
            // committed root (handled above), so reaching here means the local state is corrupt
            // AND has validated descendants — no in-place re-import can repair that, and
            // clearing would trade a detectable wedge for silent state loss.
            if consensus
                .async_get_block_status(child)
                .await
                .is_some_and(|s| s == kaspa_consensus_core::blockstatus::BlockStatus::StatusUTXOValid)
            {
                return Err(ProtocolError::OtherOwned(format!(
                    "local shielded state at pruning point {pruning_point} does not match the PoW-committed root, but chain \
                     blocks above it are already validated; refusing to clear live shielded state — a full resync is required"
                )));
            }
        } else {
            // The pruning point has no selected child in the local DAG yet (or its coinbase
            // carries no commitment). This fallback exists only while the chain tip is within
            // one block of the pruning point; the import then proceeds unverified, as before.
            warn!(
                "could not determine a PoW coinbase binding for pruning point {}; proceeding with an UNVERIFIED shielded import",
                pruning_point
            );
        }

        // F-15: the real clear (global nullifier set + pruning-point snapshots + stable flag,
        // atomically) — only here, immediately before the re-seed, and only after the
        // no-validated-descendants check above.
        consensus.async_clear_pruning_shielded_stores().await;

        info!("downloading the pruning point shielded state from {}", self.router);

        self.router
            .enqueue(make_message!(
                Payload::RequestPruningPointShieldedState,
                RequestPruningPointShieldedStateMessage { pruning_point_hash: Some(pruning_point.into()) }
            ))
            .await?;

        let mut stream = ShieldedStream::new(&self.router, &mut self.incoming_route);

        // Metadata frame. Empty `data` => the pruning point has no shielded state.
        let md = stream.recv_metadata().await?;
        if md.data.is_empty() {
            // F-02: the "empty" claim must also match the PoW commitment — a peer that claims
            // empty while the selected child commits a non-empty root is misbehaving.
            if let Some(&(_, committed)) = binding.as_ref() {
                let empty_root = consensus.async_empty_shielded_state_root().await;
                if committed != empty_root {
                    return Err(ProtocolError::OtherOwned(format!(
                        "peer claims pruning point {pruning_point} has no shielded state, but its selected child commits a \
                         non-empty shielded state root"
                    )));
                }
            }
            consensus.async_set_pruning_shielded_stable().await;
            info!("pruning point {} has no shielded state to import", pruning_point);
            return Ok(());
        }

        // F-02: the seeded state must match the PoW-committed root (checked inside consensus
        // before anything is seeded; on mismatch the import fails and this peer can be dropped).
        let expected_state_root = binding.map(|(_, committed)| committed);

        // One chunk in flight + one being processed by the importer is enough headroom.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(2);

        let consensus_for_import = consensus.clone();
        let builder_handle = tokio::task::spawn_blocking(move || {
            consensus_for_import.import_pruning_point_shielded(pruning_point, md, expected_state_root, rx)
        });

        while let Some(chunk) = stream.next_chunk().await? {
            tx.send(chunk).await.map_err(|_| ProtocolError::Other("streaming shielded importer stopped unexpectedly"))?;
        }
        drop(tx);

        builder_handle.await.map_err(|e| ProtocolError::OtherOwned(format!("shielded importer task panicked: {e}")))??;
        consensus.async_set_pruning_shielded_stable().await;

        info!("shielded state synced: {} nullifiers", stream.count());
        Ok(())
    }

    /// F-02: determine the pruning point's selected child `c` on the local header
    /// DAG (the ghostdag selected chain, which the headers-proof / header sync
    /// already PoW-verified) and return `(c, shielded_commitment)` extracted from
    /// `c`'s coinbase payload (the #24 commitment: `c` commits
    /// `shielded_state_root(pruning_point)`, and the commitment is PoW-anchored via
    /// the header's `hash_merkle_root`). Returns `Ok(None)` when `c` cannot be
    /// determined locally (the pruning point has no selected chain child yet — tip
    /// within one block of the pruning point) or its coinbase carries no
    /// commitment slot; the caller then falls back to the legacy unverified
    /// import. Any actual misbehaviour (wrong block, merkle-root mismatch, no
    /// coinbase) is a `ProtocolError`.
    async fn shielded_pp_commitment(
        &mut self,
        consensus: &ConsensusProxy,
        pruning_point: Hash,
    ) -> Result<Option<(Hash, [u8; 32])>, ProtocolError> {
        let Some(children) = consensus.async_get_block_children(pruning_point).await else { return Ok(None) };
        let hst = consensus.async_get_headers_selected_tip().await;
        let mut selected_child = None;
        for child in children {
            let Ok(gd) = consensus.async_get_ghostdag_data(child).await else { continue };
            if gd.selected_parent != pruning_point {
                continue;
            }
            // On a fork right at the pruning point several children can share it as selected
            // parent; the selected child is the one on the header-DAG selected chain — the
            // proof-verified chain the import must bind to.
            if consensus.async_is_chain_ancestor_of(child, hst).await.unwrap_or(false) {
                selected_child = Some(child);
                break;
            }
        }
        let Some(child) = selected_child else { return Ok(None) };

        // Obtain `c`'s body: the local block store first (trusted-set bodies may already be
        // synced depending on the IBD path), else request it by hash from the sync peer.
        let block = if consensus.async_get_block_status(child).await.is_some_and(|s| s.has_block_body()) {
            consensus.async_get_block(child).await.map_err(|e| ProtocolError::OtherOwned(format!("local block {child}: {e}")))?
        } else {
            self.router
                .enqueue(make_message!(Payload::RequestIbdBlocks, RequestIbdBlocksMessage { hashes: vec![child.into()] }))
                .await?;
            let msg = dequeue_with_timeout!(self.incoming_route, Payload::IbdBlock)?;
            let block: Block = Versioned(self.header_format, msg).try_into()?;
            block
        };

        // Verify the block against the locally stored header before trusting its coinbase.
        if block.hash() != child {
            return Err(ProtocolError::OtherOwned(format!("expected block {} but got {}", child, block.hash())));
        }
        if block.is_header_only() {
            return Err(ProtocolError::OtherOwned(format!("sent header of {} where expected block with body", block.hash())));
        }
        let local_header = consensus.async_get_header(child).await?;
        if block.header.hash_merkle_root != local_header.hash_merkle_root {
            return Err(ProtocolError::OtherOwned(format!(
                "block {} hash_merkle_root does not match the locally stored header",
                child
            )));
        }
        let coinbase = block
            .transactions
            .first()
            .ok_or_else(|| ProtocolError::OtherOwned(format!("block {} has no coinbase transaction", child)))?;
        Ok(kaspa_consensus_core::zkas_state_binding::extract_state_root(&coinbase.payload).map(|root| (child, root)))
    }

    async fn sync_new_utxo_set(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        // A better solution could be to create a copy of the old utxo state for some sort of fallback rather than delete it.
        consensus.async_clear_pruning_utxo_set().await; // this deletes the old pruning utxoset and also sets the pruning utxo as invalidated
        self.sync_pruning_point_utxoset(consensus, pruning_point).await?;
        // Only if the function has reached here, will the utxo be considered "final"
        consensus.async_set_pruning_utxoset_stable().await;
        // Once a new utxoset is stored, the utxoindex needs to be resynced as well. This happens through the reset handler mechanism.
        let consensus_manager = self.ctx.consensus_manager.clone();
        spawn_blocking(move || consensus_manager.invoke_consensus_reset_handlers()).await.unwrap();
        self.ctx.on_pruning_point_utxoset_override();
        Ok(())
    }

    async fn sync_missing_relay_past_headers(
        &mut self,
        consensus: &ConsensusProxy,
        syncer_virtual_selected_parent: Hash,
        relay_block_hash: Hash,
    ) -> Result<(), ProtocolError> {
        // Finished downloading syncer selected tip blocks,
        // check if we already have the triggering relay block
        if consensus.async_get_block_status(relay_block_hash).await.is_some() {
            return Ok(());
        }

        // Send a special header request for the sink antipast. This is expected to
        // be a relatively small set since virtual and relay blocks should be close topologically.
        // See server-side handling of `RequestAnticone` for further details.
        self.router
            .enqueue(make_message!(
                Payload::RequestAntipast,
                RequestAntipastMessage {
                    block_hash: Some(syncer_virtual_selected_parent.into()),
                    context_hash: Some(relay_block_hash.into())
                }
            ))
            .await?;

        let msg = dequeue_with_timeout!(self.incoming_route, Payload::BlockHeaders)?;
        let chunk: HeadersChunk = Versioned(self.header_format, msg).try_into()?;
        let jobs: Vec<BlockValidationFuture> =
            chunk.into_iter().map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task).collect();
        try_join_all(jobs).await?;
        dequeue_with_timeout!(self.incoming_route, Payload::DoneHeaders)?;

        if consensus.async_get_block_status(relay_block_hash).await.is_none() {
            // If the relay block has still not been received, the peer is misbehaving
            Err(ProtocolError::OtherOwned(format!(
                "did not receive relay block {} from peer {} during header download",
                relay_block_hash, self.router
            )))
        } else {
            Ok(())
        }
    }

    async fn validate_staging_timestamps(
        &self,
        consensus: &ConsensusProxy,
        staging_consensus: &ConsensusProxy,
    ) -> Result<(), ProtocolError> {
        // The purpose of this check is to prevent the potential abuse explained here:
        // https://github.com/kaspanet/research/issues/3#issuecomment-895243792
        let staging_hst = staging_consensus.async_get_header(staging_consensus.async_get_headers_selected_tip().await).await.unwrap();
        let current_hst = consensus.async_get_header(consensus.async_get_headers_selected_tip().await).await.unwrap();
        // If staging is behind current or within 10 minutes ahead of it, then something is wrong and we reject the IBD
        if staging_hst.timestamp < current_hst.timestamp || staging_hst.timestamp - current_hst.timestamp < 600_000 {
            Err(ProtocolError::OtherOwned(format!(
                "The difference between the timestamp of the current selected tip ({}) and the 
staging selected tip ({}) is too small or negative. Aborting IBD...",
                current_hst.timestamp, staging_hst.timestamp
            )))
        } else {
            Ok(())
        }
    }

    async fn sync_pruning_point_utxoset(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        info!("downloading the pruning point utxoset, this can take a little while.");
        self.router
            .enqueue(make_message!(
                Payload::RequestPruningPointUtxoSet,
                RequestPruningPointUtxoSetMessage { pruning_point_hash: Some(pruning_point.into()) }
            ))
            .await?;
        let mut chunk_stream = PruningPointUtxosetChunkStream::new(&self.router, &mut self.incoming_route);
        let mut multiset = MuHash::new();
        while let Some(chunk) = chunk_stream.next().await? {
            multiset = consensus
                .clone()
                .spawn_blocking(move |c| {
                    c.append_imported_pruning_point_utxos(&chunk, &mut multiset);
                    multiset
                })
                .await;
        }
        consensus.clone().spawn_blocking(move |c| c.import_pruning_point_utxo_set(pruning_point, multiset)).await?;
        Ok(())
    }
    async fn sync_missing_trusted_bodies(&mut self, consensus: &ConsensusProxy) -> Result<(), ProtocolError> {
        info!("downloading pruning point anticone missing block data");
        let diesembodied_hashes = consensus.async_get_body_missing_anticone().await;
        if self.body_only_ibd_permitted {
            self.sync_missing_trusted_bodies_no_headers(consensus, diesembodied_hashes).await?
        } else {
            self.sync_missing_trusted_bodies_full_blocks(consensus, diesembodied_hashes).await?;
        }
        consensus.async_clear_body_missing_anticone_set().await;
        Ok(())
    }
    async fn sync_missing_trusted_bodies_no_headers(
        &mut self,
        consensus: &ConsensusProxy,
        diesembodied_hashes: Vec<Hash>,
    ) -> Result<(), ProtocolError> {
        let iter = diesembodied_hashes.chunks(IBD_BATCH_SIZE);
        for chunk in iter {
            self.router
                .enqueue(make_message!(
                    Payload::RequestBlockBodies,
                    RequestBlockBodiesMessage { hashes: chunk.iter().map(|h| h.into()).collect() }
                ))
                .await?;
            let mut jobs = Vec::with_capacity(chunk.len());

            for &hash in chunk.iter() {
                let msg = dequeue_with_timeout!(self.incoming_route, Payload::BlockBody)?;
                let blk_body: BlockBody = msg.try_into()?;
                // TODO (relaxed): make header queries in a batch.
                let blk_header = consensus.async_get_header(hash).await.map_err(|err| {
                    // Conceptually this indicates local inconsistency, since we received the expected hashes via a local
                    // get_missing_block_body_hashes call. However for now we fail gracefully and only disconnect from this peer.
                    ProtocolError::OtherOwned(format!("syncee inconsistency: missing block header for {}, err: {}", hash, err))
                })?;
                if blk_body.is_empty() {
                    return Err(ProtocolError::OtherOwned(format!("sent empty block body for block {}", hash)));
                }
                let block = Block { header: blk_header, transactions: blk_body.into() };
                // TODO (relaxed): sending ghostdag data may be redundant, especially when the headers were already verified.
                // Consider sending empty ghostdag data, simplifying a great deal. The result should be the same -
                // a trusted task is sent, however the header is already verified, and hence only the block body will be verified.
                jobs.push(
                    consensus
                        .validate_and_insert_trusted_block(TrustedBlock::new(block, consensus.async_get_ghostdag_data(hash).await?))
                        .virtual_state_task,
                );
            }
            try_join_all(jobs).await?; // TODO (relaxed): be more efficient with batching as done with block bodies in general
        }
        Ok(())
    }
    async fn sync_missing_trusted_bodies_full_blocks(
        &mut self,
        consensus: &ConsensusProxy,
        diesembodied_hashes: Vec<Hash>,
    ) -> Result<(), ProtocolError> {
        let iter = diesembodied_hashes.chunks(IBD_BATCH_SIZE);
        for chunk in iter {
            self.router
                .enqueue(make_message!(
                    Payload::RequestIbdBlocks,
                    RequestIbdBlocksMessage { hashes: chunk.iter().map(|h| h.into()).collect() }
                ))
                .await?;
            let mut jobs = Vec::with_capacity(chunk.len());

            for &hash in chunk.iter() {
                // TODO: change to BodyOnly requests when incorporated
                let msg = dequeue_with_timeout!(self.incoming_route, Payload::IbdBlock)?;
                let block: Block = Versioned(self.header_format, msg).try_into()?;
                if block.hash() != hash {
                    return Err(ProtocolError::OtherOwned(format!("expected block {} but got {}", hash, block.hash())));
                }
                if block.is_header_only() {
                    return Err(ProtocolError::OtherOwned(format!("sent header of {} where expected block with body", block.hash())));
                }
                // TODO (relaxed): sending ghostdag data may be redundant, especially when the headers were already verified.
                // Consider sending empty ghostdag data, simplifying a great deal. The result should be the same -
                // a trusted task is sent, however the header is already verified, and hence only the block body will be verified.
                jobs.push(
                    consensus
                        .validate_and_insert_trusted_block(TrustedBlock::new(block, consensus.async_get_ghostdag_data(hash).await?))
                        .virtual_state_task,
                );
            }
            try_join_all(jobs).await?; // TODO (relaxed): be more efficient with batching as done with block bodies in general
        }
        Ok(())
    }
    async fn sync_missing_block_bodies(&mut self, consensus: &ConsensusProxy, high: Hash) -> Result<(), ProtocolError> {
        // TODO (relaxed): query consensus in batches
        let sleep_task = sleep(Duration::from_secs(2));
        let hashes_task = consensus.async_get_missing_block_body_hashes(high);
        tokio::pin!(sleep_task);
        tokio::pin!(hashes_task);
        let hashes = match select(sleep_task, hashes_task).await {
            Either::Left((_, hashes_task)) => {
                // We select between the tasks in order to inform the user if this operation is taking too long. On full IBD
                // this operation requires traversing the full DAG which indeed might take several seconds or even minutes.
                info!(
                    "IBD: searching for missing block bodies to request from peer {}. This operation might take several seconds.",
                    self.router
                );
                // Now re-await the original task
                hashes_task.await
            }
            Either::Right((hashes_result, _)) => hashes_result,
        }?;
        if hashes.is_empty() {
            return Ok(());
        }

        let low_header = consensus.async_get_header(*hashes.first().expect("hashes was non empty")).await?;
        let high_header = consensus.async_get_header(*hashes.last().expect("hashes was non empty")).await?;
        let mut progress_reporter = ProgressReporter::new(low_header.daa_score, high_header.daa_score, "blocks");

        let mut iter = hashes.chunks(IBD_BATCH_SIZE);
        let QueueChunkOutput { jobs: mut prev_jobs, daa_score: mut prev_daa_score, timestamp: mut prev_timestamp } =
            self.queue_block_processing_chunk(consensus, iter.next().expect("hashes was non empty")).await?;

        for chunk in iter {
            let QueueChunkOutput { jobs: current_jobs, daa_score: current_daa_score, timestamp: current_timestamp } =
                self.queue_block_processing_chunk(consensus, chunk).await?;
            let prev_chunk_len = prev_jobs.len();
            // Join the previous chunk so that we always concurrently process a chunk and receive another
            try_join_all(prev_jobs).await?;
            // Log the progress
            progress_reporter.report(prev_chunk_len, prev_daa_score, prev_timestamp);
            prev_daa_score = current_daa_score;
            prev_timestamp = current_timestamp;
            prev_jobs = current_jobs;
        }

        let prev_chunk_len = prev_jobs.len();
        try_join_all(prev_jobs).await?;
        progress_reporter.report_completion(prev_chunk_len);

        Ok(())
    }

    async fn queue_block_processing_chunk(
        &mut self,
        consensus: &ConsensusProxy,
        chunk: &[Hash],
    ) -> Result<QueueChunkOutput, ProtocolError> {
        if self.body_only_ibd_permitted {
            self.queue_block_processing_chunk_body_only(consensus, chunk).await
        } else {
            self.queue_block_processing_chunk_full_block(consensus, chunk).await
        }
    }

    async fn queue_block_processing_chunk_full_block(
        &mut self,
        consensus: &ConsensusProxy,
        chunk: &[Hash],
    ) -> Result<QueueChunkOutput, ProtocolError> {
        let mut jobs = Vec::with_capacity(chunk.len());
        let mut current_daa_score = 0;
        let mut current_timestamp = 0;
        self.router
            .enqueue(make_message!(
                Payload::RequestIbdBlocks,
                RequestIbdBlocksMessage { hashes: chunk.iter().map(|h| h.into()).collect() }
            ))
            .await?;
        for &expected_hash in chunk {
            let msg = dequeue_with_timeout!(self.incoming_route, Payload::IbdBlock)?;
            let block: Block = Versioned(self.header_format, msg).try_into()?;
            if block.hash() != expected_hash {
                return Err(ProtocolError::OtherOwned(format!("expected block {} but got {}", expected_hash, block.hash())));
            }
            if block.is_header_only() {
                return Err(ProtocolError::OtherOwned(format!("sent header of {} where expected block with body", block.hash())));
            }
            current_daa_score = block.header.daa_score;
            current_timestamp = block.header.timestamp;
            jobs.push(consensus.validate_and_insert_block(block).virtual_state_task);
        }
        Ok(QueueChunkOutput { jobs, daa_score: current_daa_score, timestamp: current_timestamp })
    }

    async fn queue_block_processing_chunk_body_only(
        &mut self,
        consensus: &ConsensusProxy,
        chunk: &[Hash],
    ) -> Result<QueueChunkOutput, ProtocolError> {
        let mut jobs = Vec::with_capacity(chunk.len());
        let mut current_daa_score = 0;
        let mut current_timestamp = 0;
        self.router
            .enqueue(make_request!(
                Payload::RequestBlockBodies,
                RequestBlockBodiesMessage { hashes: chunk.iter().map(|h| h.into()).collect() },
                self.incoming_route.id()
            ))
            .await?;
        for &expected_hash in chunk {
            let msg = dequeue_with_timeout!(self.incoming_route, Payload::BlockBody)?;
            // TODO (relaxed): make header queries in a batch.
            let blk_header = consensus.async_get_header(expected_hash).await.map_err(|err| {
                // Conceptually this indicates local inconsistency, since we received the expected hashes via a local
                // get_missing_block_body_hashes call. However for now we fail gracefully and only disconnect from this peer.
                ProtocolError::OtherOwned(format!("syncee inconsistency: missing block header for {}, err: {}", expected_hash, err))
            })?;
            let blk_body: BlockBody = msg.try_into()?;
            if blk_body.is_empty() {
                return Err(ProtocolError::OtherOwned(format!("sent empty block body for block {}", expected_hash)));
            }
            let block = Block { header: blk_header, transactions: blk_body.into() };
            current_daa_score = block.header.daa_score;
            current_timestamp = block.header.timestamp;
            jobs.push(consensus.validate_and_insert_block(block).virtual_state_task);
        }
        Ok(QueueChunkOutput { jobs, daa_score: current_daa_score, timestamp: current_timestamp })
    }
}

/// [Toccata] Fresh nodes cannot easily identify outdated peers after activation, so we guard
/// against syncers advertising pruning points that are clearly stale.
///
/// TODO(post-toccata): remove or adjust this stale pruning-point guard once Toccata is cleaned up.
fn validate_pruning_point_freshness_for_toccata(
    params: &Params,
    pp_hash: Hash,
    pp_timestamp: u64,
    pp_daa_score: u64,
    now: u64,
) -> Result<(), ProtocolError> {
    // No activation is expected.
    if params.toccata_activation == ForkActivation::never() {
        return Ok(());
    }

    // If the pruning point is post-activation, its header is validated as part of the pruning proof.
    if params.toccata_activation.is_active(pp_daa_score) {
        return Ok(());
    }

    // Otherwise, protect fresh nodes from outdated syncers with stale pre-activation pruning points.

    let activation_daa_score = params.toccata_activation.daa_score();

    // Reject if:
    // 1. the syncer's pruning point is still pre-activation;
    // 2. based on its timestamp and DAA score, activation should have happened long enough ago
    //    for the syncer to already expose a post-activation pruning point.
    const ONE_DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
    let millis_per_block = params.target_time_per_block();

    let pp_to_activation_blocks = activation_daa_score.saturating_sub(pp_daa_score);
    let pp_to_activation_millis = pp_to_activation_blocks.saturating_mul(millis_per_block);
    let estimated_activation_time = pp_timestamp.saturating_add(pp_to_activation_millis);

    let pruning_period_millis = params.pruning_depth().saturating_add(params.finality_depth()).saturating_mul(millis_per_block);
    // The oldest activation estimate for which a pre-activation pruning point is still tolerated.
    let stale_activation_time_cutoff = now.saturating_sub(pruning_period_millis).saturating_sub(ONE_DAY_MILLIS);

    // If activation should have happened before this cutoff, the syncer should already
    // expose a post-activation pruning point.
    if estimated_activation_time < stale_activation_time_cutoff {
        return Err(ProtocolError::OtherOwned(format!(
            "syncer pruning point {} is stale: DAA score {} is below Toccata activation DAA score {}, but based on its timestamp {} a post-activation pruning point is expected by now",
            pp_hash, pp_daa_score, activation_daa_score, pp_timestamp
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::config::params::MAINNET_PARAMS;

    fn params_with_toccata_activation(activation_daa_score: u64) -> Params {
        let mut params = MAINNET_PARAMS.clone();
        params.toccata_activation = ForkActivation::new(activation_daa_score);
        params
    }

    fn params_without_toccata_activation() -> Params {
        let mut params = MAINNET_PARAMS.clone();
        params.toccata_activation = ForkActivation::never();
        params
    }

    fn pruning_period_millis(params: &Params) -> u64 {
        params.pruning_depth().saturating_add(params.finality_depth()).saturating_mul(params.target_time_per_block())
    }

    #[test]
    fn test_toccata_pruning_point_staleness_guard() {
        const ONE_DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
        let activation_daa_score = 10_000_000;
        let params = params_with_toccata_activation(activation_daa_score);
        let blocks_per_day = ONE_DAY_MILLIS / params.target_time_per_block();
        let pp_hash = Hash::from_u64_word(1);
        let pp_daa_score = activation_daa_score - 10;
        let pp_timestamp = 1_000_000_000_000;
        let pp_to_activation_millis = 10 * params.target_time_per_block();
        let estimated_activation_time = pp_timestamp + pp_to_activation_millis;
        let stale_after = estimated_activation_time + pruning_period_millis(&params) + ONE_DAY_MILLIS;

        // No activation is configured:
        // PP(pre-activation by score) ---- estimated activation ---- pruning period + margin ---- now
        assert!(
            validate_pruning_point_freshness_for_toccata(
                &params_without_toccata_activation(),
                pp_hash,
                pp_timestamp,
                pp_daa_score,
                stale_after + 1
            )
            .is_ok()
        );

        // Normal pre-activation IBD: activation is still ten days away.
        // PP/now -------- 10d -------- activation
        let pp_ten_days_before_activation = activation_daa_score - 10 * blocks_per_day;
        assert!(
            validate_pruning_point_freshness_for_toccata(&params, pp_hash, pp_timestamp, pp_ten_days_before_activation, pp_timestamp)
                .is_ok()
        );

        // The syncer's pruning point is already post-activation, so the staleness guard is done:
        // PP(post-activation by score) ----------------------------------------------- now
        assert!(
            validate_pruning_point_freshness_for_toccata(&params, pp_hash, pp_timestamp, activation_daa_score, stale_after + 1)
                .is_ok()
        );

        // Last tolerated instant for a pre-activation pruning point:
        // PP ---- estimated activation ---- pruning period + margin == now
        assert!(validate_pruning_point_freshness_for_toccata(&params, pp_hash, pp_timestamp, pp_daa_score, stale_after).is_ok());

        // One millisecond later, the same pre-activation pruning point is stale:
        // PP ---- estimated activation ---- pruning period + margin < now
        assert!(validate_pruning_point_freshness_for_toccata(&params, pp_hash, pp_timestamp, pp_daa_score, stale_after + 1).is_err());

        // Stale IBD: the syncer's pruning point is three days before activation, and now is
        // six days after that pruning point. Activation should have happened long enough ago
        // for the syncer to already expose a post-activation pruning point.
        // PP -------- 3d -------- activation -------- 3d -------- now
        let pp_three_days_before_activation = activation_daa_score - 3 * blocks_per_day;
        let now_six_days_after_pp = pp_timestamp + 6 * ONE_DAY_MILLIS;
        assert!(
            validate_pruning_point_freshness_for_toccata(
                &params,
                pp_hash,
                pp_timestamp,
                pp_three_days_before_activation,
                now_six_days_after_pp
            )
            .is_err()
        );

        // Normal IBD: two days after activation, a pruning point just before activation is
        // still expected because pruning points trail the live chain by the pruning period.
        // PP - activation -------- 2d -------- now
        let pp_just_before_activation = activation_daa_score - 1;
        let pp_just_before_activation_timestamp = pp_timestamp + 3 * ONE_DAY_MILLIS - params.target_time_per_block();
        let now_two_days_after_activation = pp_timestamp + 5 * ONE_DAY_MILLIS;
        assert!(
            validate_pruning_point_freshness_for_toccata(
                &params,
                pp_hash,
                pp_just_before_activation_timestamp,
                pp_just_before_activation,
                now_two_days_after_activation
            )
            .is_ok()
        );
    }
}
