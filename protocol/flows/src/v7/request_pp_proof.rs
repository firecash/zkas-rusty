use std::{sync::Arc, time::Instant};

use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::{DEFAULT_TIMEOUT, ProtocolError},
    convert::header::HeaderFormat,
    dequeue_with_timeout, make_message, make_response,
    pb::{PruningPointProofMessage, kaspad_message::Payload},
    pp_proof_chunks::{ProofChunker, requests_next_after},
};
use log::{debug, info};

use crate::{flow_context::FlowContext, flow_trait::Flow};

/// Longest a chunked proof serve may take, from the request to the final chunk. Bounds how long a
/// serve keeps its `Arc` of the proof alive: after the pruning point moves, consensus caches a new
/// proof and a running serve still holds the old one.
const CHUNKED_SERVE_MAX_DURATION: std::time::Duration = std::time::Duration::from_secs(30 * 60);

pub struct RequestPruningPointProofFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    header_format: HeaderFormat,
}

#[async_trait::async_trait]
impl Flow for RequestPruningPointProofFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestPruningPointProofFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute, header_format: HeaderFormat) -> Self {
        Self { ctx, router, incoming_route, header_format }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let Some(msg) = self.incoming_route.recv().await else {
                return Err(ProtocolError::ConnectionClosed);
            };
            match msg.payload {
                Some(Payload::RequestPruningPointProof(request)) => self.serve_whole(request.dedup_headers, msg.request_id).await?,
                Some(Payload::RequestPruningPointProofChunks(_)) => self.serve_chunks().await?,
                // A window ask is only valid inside a chunked serve, which consumes its own.
                other => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::RequestPruningPointProof | Payload::RequestPruningPointProofChunks),
                        other.as_ref().map(|v| v.into()),
                    ));
                }
            }
        }
    }

    /// The legacy form: the whole proof as one `PruningPointProofMessage`, deduplicated when the
    /// requester asks for it (N1, spec 13 L1; an older requester never sets the field and gets the
    /// full form, as before).
    async fn serve_whole(&mut self, dedup_headers: bool, request_id: u32) -> Result<(), ProtocolError> {
        debug!("Got pruning point proof request");
        // Nothing of ours may still be queued for this peer before a proof is built for it.
        self.router.pace_outgoing().await?;
        // `ctx` is cloned so the permit does not borrow `self` across the sends below.
        let ctx = self.ctx.clone();
        let Some(_permit) = ctx.proof_serve_gate.admit().await else {
            return Err(ProtocolError::Other("this node has served its share of pruning point proofs for now; ask another peer"));
        };
        let proof = ctx.consensus().unguarded_session().async_get_pruning_point_proof().await;
        let message = if dedup_headers {
            kaspa_p2p_lib::convert::pruning::dedup_pruning_point_proof(self.header_format, &proof)
        } else {
            PruningPointProofMessage {
                headers: proof.iter().map(|headers| (self.header_format, headers).into()).collect(),
                ..Default::default()
            }
        };
        let wire_bytes = prost::Message::encoded_len(&message);
        let slots: usize = proof.iter().map(|l| l.len()).sum();
        info!(
            "Serving pruning point proof to {}: {} header slots, {} wire bytes ({})",
            self.router,
            slots,
            wire_bytes,
            if dedup_headers { "deduplicated" } else { "full" }
        );
        self.router.enqueue(make_response!(Payload::PruningPointProof, message, request_id)).await?;
        drop(proof);
        // Hold the build slot until the transport has taken the message off the route, so at
        // most one converted proof exists outside the send buffers at any time.
        self.router.pace_outgoing().await?;
        debug!("Sent pruning point proof");
        Ok(())
    }

    /// The chunked form (`kaspa_p2p_lib::pp_proof_chunks`). The serve takes one slot of the same
    /// global budget as the legacy form, but holds the build slot only while the proof is fetched:
    /// what a chunked serve keeps in memory is one converted chunk plus the paced backlog (32 MiB),
    /// not a whole converted proof, so a slow reader no longer blocks every other serve.
    async fn serve_chunks(&mut self) -> Result<(), ProtocolError> {
        debug!("Got chunked pruning point proof request from {}", self.router);
        let started = Instant::now();
        self.router.pace_outgoing().await?;
        let proof = {
            let ctx = self.ctx.clone();
            let Some(_permit) = ctx.proof_serve_gate.admit().await else {
                return Err(ProtocolError::Other("this node has served its share of pruning point proofs for now; ask another peer"));
            };
            ctx.consensus().unguarded_session().async_get_pruning_point_proof().await
        };
        let mut sent = 0usize;
        for chunk in ProofChunker::new(proof, self.header_format) {
            if started.elapsed() > CHUNKED_SERVE_MAX_DURATION {
                return Err(ProtocolError::Timeout(CHUNKED_SERVE_MAX_DURATION));
            }
            let done = chunk.done;
            self.router.enqueue_paced(make_message!(Payload::PruningPointProofChunk, chunk)).await?;
            sent += 1;
            if requests_next_after(sent, done) {
                // The requester asks as soon as it has the window's last chunk, before converting it.
                dequeue_with_timeout!(self.incoming_route, Payload::RequestNextPruningPointProofChunk, DEFAULT_TIMEOUT)?;
            }
        }
        debug!("Sent pruning point proof to {} in {} chunks, {:.1}s", self.router, sent, started.elapsed().as_secs_f64());
        Ok(())
    }
}
