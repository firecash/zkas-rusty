use crate::{flow_context::FlowContext, flow_trait::Flow};
use kaspa_core::debug;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    dequeue, make_message,
    pb::{ShieldedHistoryChunkMessage, ShieldedHistoryEntry, kaspad_message::Payload},
};
use std::sync::Arc;

/// How many chain blocks to put in one history chunk. Records average ~540 B, so this is a
/// few MB per message — large enough that a 340k-block chain takes hundreds of round trips
/// rather than hundreds of thousands, small enough to stay well inside the message size cap.
const HISTORY_CHUNK_BLOCKS: usize = 4_000;

/// Minimum wall-clock spacing between history chunks served to ONE peer.
///
/// Serving is not free: each chunk is a `HISTORY_CHUNK_BLOCKS`-deep walk of the selected-chain
/// index plus one scan-archive point lookup per block — a few MB of RocksDB reads — and the
/// request loop has no other bound, so a peer could previously issue them back to back for as
/// long as it liked. That was survivable while history serving was rare (it defaulted to
/// `--archival` only). It stops being survivable now that every node defaults to holding and
/// serving history, which is exactly the change that makes this path worth attacking.
///
/// A whole-chain backfill is ~116 round trips, so at this spacing an honest requester pays about
/// 12 s of added latency on a transfer that already takes minutes — while a peer trying to pin a
/// server's disk gets throttled to one walk per interval per connection.
const HISTORY_CHUNK_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// How many chunks one peer may request before it must wait out a full interval regardless.
///
/// The spacing above bounds the sustained rate; this bounds the burst, so a peer cannot open with
/// an unbounded run of free walks before the throttle engages.
const HISTORY_BURST_CHUNKS: u32 = 8;

/// Server side of shielded-history backfill.
///
/// A node that synced from a headers proof writes scan records only for blocks it validated
/// itself, i.e. from its pruning point forward. `PruningPointShieldedMetadata` carries the
/// frontier and a nullifier MuHash — aggregates that cannot yield notes — so the per-note
/// history below the pruning point is simply absent, and a wallet querying such a node sees a
/// silently partial balance. This flow serves that missing range to a requesting peer.
///
/// The walk happens here, not on the requester: a syncing node cannot enumerate the range
/// itself, because `init_with_pruning_point` numbers its selected-chain index from ITS OWN
/// pruning point as 0 (so index spaces do not align between nodes) and its header segment stops
/// far above genesis. The requester names an anchor block; this side walks its own selected
/// chain downward from there.
///
/// Serving needs only the selected-chain index and the scan archive, both of which survive
/// pruning, so a pruned node can serve full history it can no longer otherwise reach.
pub struct RequestShieldedHistoryFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    /// When this peer last had a chunk served, for [`HISTORY_CHUNK_MIN_INTERVAL`].
    last_served: Option<std::time::Instant>,
    /// Chunks served to this peer so far, for the [`HISTORY_BURST_CHUNKS`] allowance.
    served_count: u32,
}

#[async_trait::async_trait]
impl Flow for RequestShieldedHistoryFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestShieldedHistoryFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route, last_served: None, served_count: 0 }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let msg = dequeue!(self.incoming_route, Payload::RequestShieldedHistory)?;
            if msg.anchor_hash.len() != 32 {
                return Err(ProtocolError::Other("shielded history request has a malformed anchor hash"));
            }
            let mut ab = [0u8; 32];
            ab.copy_from_slice(&msg.anchor_hash);
            let anchor = kaspa_hashes::Hash::from_bytes(ab);
            let max_blocks = (msg.max_blocks as usize).clamp(1, HISTORY_CHUNK_BLOCKS);
            // Throttle before doing the work, not after: the cost this guards is the walk itself,
            // so sleeping afterwards would still let a peer queue the reads back to back.
            if self.served_count >= HISTORY_BURST_CHUNKS {
                if let Some(last) = self.last_served {
                    let since = last.elapsed();
                    if since < HISTORY_CHUNK_MIN_INTERVAL {
                        tokio::time::sleep(HISTORY_CHUNK_MIN_INTERVAL - since).await;
                    }
                }
            }
            self.last_served = Some(std::time::Instant::now());
            self.served_count = self.served_count.saturating_add(1);
            if self.served_count == HISTORY_BURST_CHUNKS {
                debug!("peer {} is now rate-limited on shielded history after {HISTORY_BURST_CHUNKS} chunks", self.router);
            }
            self.handle_request(anchor, max_blocks).await?;
        }
    }

    async fn handle_request(&mut self, anchor: kaspa_hashes::Hash, max_blocks: usize) -> Result<(), ProtocolError> {
        let session = self.ctx.consensus().session().await;
        let (records, done, anchor_index) = session.async_get_shielded_history_indexed_below(anchor, max_blocks).await?;
        drop(session);

        let entries: Vec<ShieldedHistoryEntry> = records
            .iter()
            .map(|(index, r)| {
                // `bincode` of the API record: the requester rebuilds `ShieldedScanBlockData`
                // from it and verifies the whole range by replaying the `cmx` leaves.
                bincode::serialize(r)
                    .map(|data| ShieldedHistoryEntry { block_hash: r.hash.as_bytes().to_vec(), data, chain_index: *index })
                    .map_err(|e| ProtocolError::OtherOwned(format!("serializing shielded history record: {e}")))
            })
            .collect::<Result<_, _>>()?;

        debug!("serving {} shielded history records below {} (done={})", entries.len(), anchor, done);
        self.router
            .enqueue_paced(make_message!(Payload::ShieldedHistoryChunk, ShieldedHistoryChunkMessage { entries, done, anchor_index }))
            .await?;
        Ok(())
    }
}
