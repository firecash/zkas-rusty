use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    ibd::{SHIELDED_CHUNK_SIZE, SMT_FLOW_CONTROL_WINDOW},
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
use kaspa_core::{debug, info};
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    dequeue, dequeue_with_timeout, make_message,
    pb::{ShieldedMetadataMessage, ShieldedNullifierChunkMessage, UnexpectedPruningPointMessage, kaspad_message::Payload},
};
use std::sync::Arc;

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
            let expected_pp = dequeue!(self.incoming_route, Payload::RequestPruningPointShieldedState)?.try_into()?;
            // Space out repeat exports from one peer. An honest syncer asks once, so this costs it
            // nothing; the loop previously had no bound whatsoever.
            if let Some(last) = last_served {
                let elapsed = last.elapsed();
                if elapsed < SHIELDED_STATE_MIN_INTERVAL {
                    tokio::time::sleep(SHIELDED_STATE_MIN_INTERVAL - elapsed).await;
                }
            }
            last_served = Some(std::time::Instant::now());
            self.handle_request(expected_pp).await?
        }
    }

    async fn handle_request(&mut self, expected_pp: Hash) -> Result<(), ProtocolError> {
        let consensus = self.ctx.consensus();
        let session = consensus.session().await;

        let metadata = match session.async_get_pruning_point_shielded_metadata(expected_pp).await {
            Err(ConsensusError::UnexpectedPruningPoint) => return self.send_unexpected_pruning_point().await,
            res => res,
        }?;
        drop(session);

        // No shielded state at the pruning point: signal it with empty metadata.
        let Some(ShieldedExportMetadata { data, nullifier_count }) = metadata else {
            self.router
                .enqueue(make_message!(Payload::ShieldedMetadata, ShieldedMetadataMessage { data: vec![], nullifier_count: 0 }))
                .await?;
            debug!("Finished sending shielded state for pruning point {}: no shielded state", expected_pp);
            return Ok(());
        };

        self.router.enqueue(make_message!(Payload::ShieldedMetadata, ShieldedMetadataMessage { data, nullifier_count })).await?;

        if nullifier_count == 0 {
            debug!("Finished sending shielded state for pruning point {}: 0 nullifiers", expected_pp);
            return Ok(());
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(256);

        let session_for_reader = consensus.unguarded_session();
        let stream = match session_for_reader.open_pruning_point_shielded_nullifier_stream(expected_pp) {
            Err(ConsensusError::UnexpectedPruningPoint) => return self.send_unexpected_pruning_point().await,
            res => res,
        }?;
        drop(session_for_reader);
        let reader_handle = tokio::task::spawn_blocking(move || -> Result<u64, ConsensusError> {
            let mut count: u64 = 0;
            let mut batch: Vec<[u8; 32]> = Vec::with_capacity(SHIELDED_CHUNK_SIZE);
            for item in stream {
                batch.push(item?);
                if batch.len() == SHIELDED_CHUNK_SIZE {
                    count += batch.len() as u64;
                    if tx.blocking_send(std::mem::take(&mut batch)).is_err() {
                        return Err(ConsensusError::General("receiver went away"));
                    }
                    batch.reserve(SHIELDED_CHUNK_SIZE);
                }
            }
            if !batch.is_empty() {
                count += batch.len() as u64;
                if tx.blocking_send(batch).is_err() {
                    return Err(ConsensusError::General("receiver went away"));
                }
            }
            Ok(count)
        });

        let mut sent: u64 = 0;
        let mut chunks_sent: usize = 0;

        while let Some(batch) = rx.recv().await {
            let nullifiers: Vec<Vec<u8>> = batch.into_iter().map(|nf| nf.to_vec()).collect();
            let chunk_len = nullifiers.len() as u64;
            self.router.enqueue(make_message!(Payload::ShieldedNullifierChunk, ShieldedNullifierChunkMessage { nullifiers })).await?;

            sent += chunk_len;
            chunks_sent += 1;

            // Flow-control round-trip; skip on the last window so the peer never has
            // to send a trailing RequestNext just to unblock us.
            if sent < nullifier_count && chunks_sent.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
                // Bounded: a requester that never asks for the next window would otherwise hold this
                // flow, and the blocking reader thread parked on the full channel, for the life of the
                // connection.
                // Generous: a small syncing node may take minutes between windows while it imports.
                dequeue_with_timeout!(
                    self.incoming_route,
                    Payload::RequestNextPruningPointShieldedChunk,
                    std::time::Duration::from_secs(600)
                )?;
            }
        }

        let reader_count = match reader_handle.await {
            Ok(Ok(count)) => count,
            Ok(Err(ConsensusError::UnexpectedPruningPoint)) => return self.send_unexpected_pruning_point().await,
            Ok(Err(e)) => return Err(ProtocolError::OtherOwned(format!("shielded nullifier stream error: {e}"))),
            Err(e) => return Err(ProtocolError::OtherOwned(format!("shielded nullifier reader task panicked: {e}"))),
        };

        // F-03: the metadata (count) and the stream are produced by two separate
        // consensus calls; a concurrent virtual update (e.g. a reorg walk) can
        // transiently desync them. Abort the transfer cleanly — the peer detects the
        // torn stream and retries — rather than panicking the whole node.
        if sent != reader_count || sent != nullifier_count {
            return Err(ProtocolError::OtherOwned(format!(
                "shielded nullifier stream for pruning point {expected_pp} drifted during transfer: \
                 sent {sent}, reader streamed {reader_count}, metadata declared {nullifier_count}; aborting"
            )));
        }

        info!("Finished sending shielded state for pruning point {}: {} nullifiers in {} chunks", expected_pp, sent, chunks_sent);
        Ok(())
    }

    async fn send_unexpected_pruning_point(&mut self) -> Result<(), ProtocolError> {
        self.router.enqueue(make_message!(Payload::UnexpectedPruningPoint, UnexpectedPruningPointMessage {})).await?;
        Ok(())
    }
}
