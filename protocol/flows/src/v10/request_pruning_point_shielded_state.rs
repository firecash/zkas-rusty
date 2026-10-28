use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    ibd::{EXPORT_NEXT_WINDOW_TIMEOUT, EXPORT_READ_AHEAD_CHUNKS, SHIELDED_CHUNK_SIZE, SMT_FLOW_CONTROL_WINDOW},
};
use kaspa_consensus_core::{api::ShieldedExportMetadata, errors::consensus::ConsensusError};

/// Minimum wall-clock spacing between pruning-point shielded-state exports served to ONE peer.
///
/// `export_pruning_point_shielded` is not cached, and it is expensive: a `BlockHashSet` of up to
/// `max_shielded_anchor_age` (27,000 at 1 BPS) chain-index lookups, then an end-to-end iteration of
/// BOTH anchor indexes, then a ghostdag blue-score read per distinct source, then bincode over the
/// result. The code's own comment records an earlier version overrunning the 120 s IBD timeout at
/// 27,000 blocks, so this is a known-costly path — and its request loop had no rate limit at all, in
/// deliberate contrast to the history flow beside it, which documents exactly why it needs one. An
/// honest syncer makes this request once, so the spacing costs it nothing.
const SHIELDED_STATE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Longest the server spends SENDING one flow-control window (`SMT_FLOW_CONTROL_WINDOW` chunks,
/// about 1.3 MB), export slot held. A window takes an honest peer well under a second; a peer
/// that reads slower than ~11 KB/s is holding a node-wide slot on purpose, and is dropped.
const EXPORT_WINDOW_SEND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);
use kaspa_core::{debug, info};
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    dequeue_with_timeout, make_message,
    pb::{ShieldedMetadataMessage, ShieldedNullifierChunkMessage, UnexpectedPruningPointMessage, kaspad_message::Payload},
};
use std::sync::Arc;

/// One export request: a full stream (`ranged == false`, every protocol version) or one key range.
struct ExportRequest {
    pp: Hash,
    from: Option<[u8; 32]>,
    before: Option<[u8; 32]>,
    with_metadata: bool,
    ranged: bool,
}

/// Server side of pruning-point shielded-state IBD transfer (PLAN §2.8/§2.9):
/// sends the shielded metadata at the pruning point followed by the whole
/// spent-nullifier set in flow-controlled chunks. Mirrors
/// `RequestPruningPointSmtStateFlow`.
pub struct RequestPruningPointShieldedStateFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for RequestPruningPointShieldedStateFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestPruningPointShieldedStateFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        let mut last_served: Option<std::time::Instant> = None;
        loop {
            // A full request (every version), or (N1, spec 08 R3.3/R3.4.1) one key range of the set.
            let msg = match self.incoming_route.recv().await {
                Some(msg) => msg,
                None => return Err(ProtocolError::ConnectionClosed),
            };
            let request = match msg.payload {
                Some(Payload::RequestPruningPointShieldedState(m)) => {
                    let pp: Hash = m.try_into()?;
                    ExportRequest { pp, from: None, before: None, with_metadata: true, ranged: false }
                }
                Some(Payload::RequestPruningPointShieldedChunkFrom(m)) => {
                    let (pp, from, before, with_metadata): kaspa_p2p_lib::convert::messages::ShieldedRangeRequest = m.try_into()?;
                    if let (Some(f), Some(b)) = (from, before)
                        && f >= b
                    {
                        return Err(ProtocolError::Other("shielded range request with from >= before"));
                    }
                    ExportRequest { pp, from, before, with_metadata, ranged: true }
                }
                other => {
                    return Err(ProtocolError::UnexpectedMessage(
                        "Payload::RequestPruningPointShieldedState | Payload::RequestPruningPointShieldedChunkFrom",
                        other.as_ref().map(|v| v.into()),
                    ));
                }
            };
            // Space out repeat exports from one peer. A full export is requested once by an honest
            // syncer; a range-split import asks one peer for its ranges one after the other, which
            // this spacing paces (16 ranges = 30 s of spacing at most per source).
            if let Some(last) = last_served {
                let elapsed = last.elapsed();
                if elapsed < SHIELDED_STATE_MIN_INTERVAL {
                    tokio::time::sleep(SHIELDED_STATE_MIN_INTERVAL - elapsed).await;
                }
            }
            last_served = Some(std::time::Instant::now());
            // One export per peer address at a time: a host with several connections must not take
            // several of the node-wide slots below.
            let ip = self.router.net_address().ip();
            let Some(_ip_claim) = self.ctx.claim_shielded_export_ip(ip) else {
                return Err(ProtocolError::Other("a shielded export to this peer address is already running"));
            };
            self.handle_request(request).await?
        }
    }

    /// One of the node-wide export slots (`MAX_CONCURRENT_SHIELDED_EXPORTS`, spec 08 R3.3). A
    /// requester that has to wait past its timeout tries another source, which is the "busy"
    /// answer an older requester also understands.
    async fn acquire_export_slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ProtocolError> {
        self.ctx.shielded_export_permits().acquire_owned().await.map_err(|_| ProtocolError::Other("shielded export gate closed"))
    }

    async fn handle_request(&mut self, req: ExportRequest) -> Result<(), ProtocolError> {
        let ExportRequest { pp: expected_pp, from, before, with_metadata, ranged } = req;
        // Held while this export reads and sends; released while it waits for the peer.
        let mut slot = Some(self.acquire_export_slot().await?);
        let mut window_started = std::time::Instant::now();
        let consensus = self.ctx.consensus();
        let mut nullifier_count: Option<u64> = None;
        if with_metadata {
            let session = consensus.session().await;
            let metadata = match session.async_get_pruning_point_shielded_metadata(expected_pp).await {
                Err(ConsensusError::UnexpectedPruningPoint) => return self.send_unexpected_pruning_point().await,
                res => res,
            }?;
            drop(session);

            // No shielded state at the pruning point: signal it with empty metadata.
            let Some(ShieldedExportMetadata { data, nullifier_count: count }) = metadata else {
                self.router
                    .enqueue(make_message!(Payload::ShieldedMetadata, ShieldedMetadataMessage { data: vec![], nullifier_count: 0 }))
                    .await?;
                debug!("Finished sending shielded state for pruning point {}: no shielded state", expected_pp);
                return Ok(());
            };
            // `nullifier_count` is the size of the WHOLE set, also for a range request.
            self.router
                .enqueue(make_message!(Payload::ShieldedMetadata, ShieldedMetadataMessage { data, nullifier_count: count }))
                .await?;
            if count == 0 && !ranged {
                debug!("Finished sending shielded state for pruning point {}: 0 nullifiers", expected_pp);
                return Ok(());
            }
            nullifier_count = Some(count);
        }

        // Read-ahead is bounded to what the send loop needs: this channel is invisible to the
        // router's byte budget (see `EXPORT_READ_AHEAD_CHUNKS`).
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(EXPORT_READ_AHEAD_CHUNKS);

        // N1 (spec 08 R3.3): the set is streamed from a database snapshot in ascending order and
        // never materialised; an unbounded stream is checked against the committed accumulator
        // before its last chunk is handed over (a torn view errors here instead of completing).
        let session_for_reader = consensus.unguarded_session();
        let reader_handle = tokio::task::spawn_blocking(move || -> Result<u64, ConsensusError> {
            session_for_reader.stream_pruning_point_shielded_nullifiers(expected_pp, from, before, SHIELDED_CHUNK_SIZE, &mut |chunk| {
                tx.blocking_send(chunk).is_ok()
            })
        });

        let mut sent: u64 = 0;
        let mut chunks_sent: usize = 0;

        // Fetch one chunk ahead. A full stream skips the flow-control wait exactly when no chunk
        // follows (its requester asks for the next window only while it still expects nullifiers);
        // a ranged stream always waits after a full window, because its requester cannot know the
        // range's size and always asks.
        let mut next = rx.recv().await;
        while let Some(batch) = next {
            let nullifiers: Vec<Vec<u8>> = batch.into_iter().map(|nf| nf.to_vec()).collect();
            let chunk_len = nullifiers.len() as u64;
            // Paced: waits while this peer's backlog drains. Bounded per window, so a peer that
            // reads a trickle cannot hold the slot.
            let budget = EXPORT_WINDOW_SEND_DEADLINE.saturating_sub(window_started.elapsed());
            match tokio::time::timeout(
                budget,
                self.router.enqueue_paced(make_message!(Payload::ShieldedNullifierChunk, ShieldedNullifierChunkMessage { nullifiers })),
            )
            .await
            {
                Ok(sent_ok) => sent_ok?,
                Err(_) => return Err(ProtocolError::Timeout(EXPORT_WINDOW_SEND_DEADLINE)),
            }

            sent += chunk_len;
            chunks_sent += 1;

            next = rx.recv().await;
            if (next.is_some() || ranged) && chunks_sent.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
                // Bounded: see `EXPORT_NEXT_WINDOW_TIMEOUT`. The slot is free while the peer imports.
                drop(slot.take());
                dequeue_with_timeout!(self.incoming_route, Payload::RequestNextPruningPointShieldedChunk, EXPORT_NEXT_WINDOW_TIMEOUT)?;
                slot = Some(self.acquire_export_slot().await?);
                window_started = std::time::Instant::now();
            }
        }

        let reader_count = match reader_handle.await {
            Ok(Ok(count)) => count,
            Ok(Err(ConsensusError::UnexpectedPruningPoint)) => return self.send_unexpected_pruning_point().await,
            Ok(Err(e)) => return Err(ProtocolError::OtherOwned(format!("shielded nullifier stream error: {e}"))),
            Err(e) => return Err(ProtocolError::OtherOwned(format!("shielded nullifier reader task panicked: {e}"))),
        };

        // F-03: the metadata (count) and the stream are produced by two separate consensus calls; a
        // concurrent virtual update (e.g. a reorg walk) can transiently desync them. Abort the
        // transfer cleanly -- the peer detects the torn stream and retries -- rather than panicking.
        let drifted = sent != reader_count
            || nullifier_count.is_some_and(|n| sent > n || (!ranged && from.is_none() && before.is_none() && sent != n));
        if drifted {
            return Err(ProtocolError::OtherOwned(format!(
                "shielded nullifier stream for pruning point {expected_pp} drifted during transfer: \
                 sent {sent}, reader streamed {reader_count}, metadata declared {nullifier_count:?}; aborting"
            )));
        }
        if ranged {
            // The end of the range: one empty chunk.
            self.router
                .enqueue(make_message!(Payload::ShieldedNullifierChunk, ShieldedNullifierChunkMessage { nullifiers: vec![] }))
                .await?;
        }

        info!(
            "Finished sending shielded state for pruning point {}: {} nullifiers in {} chunks{}",
            expected_pp,
            sent,
            chunks_sent,
            if ranged { " (one range)" } else { "" }
        );
        Ok(())
    }

    async fn send_unexpected_pruning_point(&mut self) -> Result<(), ProtocolError> {
        self.router.enqueue(make_message!(Payload::UnexpectedPruningPoint, UnexpectedPruningPointMessage {})).await?;
        Ok(())
    }
}
