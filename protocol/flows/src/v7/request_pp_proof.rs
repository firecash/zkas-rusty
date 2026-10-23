use std::sync::Arc;

use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    convert::header::HeaderFormat,
    dequeue_with_request_id, make_response,
    pb::{PruningPointProofMessage, kaspad_message::Payload},
};
use log::{debug, info};

use crate::{flow_context::FlowContext, flow_trait::Flow};

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
            let (request, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestPruningPointProof)?;
            debug!("Got pruning point proof request");
            // Nothing of ours may still be queued for this peer before a proof is built for it.
            self.router.pace_outgoing().await?;
            // `ctx` is cloned so the permit does not borrow `self` across the sends below.
            let ctx = self.ctx.clone();
            let Some(_permit) = ctx.proof_serve_gate.admit().await else {
                return Err(ProtocolError::Other("this node has served its share of pruning point proofs for now; ask another peer"));
            };
            let proof = ctx.consensus().unguarded_session().async_get_pruning_point_proof().await;
            // N1 (spec 13 L1): the deduplicated form when the requester asks for it (an older
            // requester never sets the field and gets the full form, as before).
            let message = if request.dedup_headers {
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
                if request.dedup_headers { "deduplicated" } else { "full" }
            );
            self.router.enqueue(make_response!(Payload::PruningPointProof, message, request_id)).await?;
            drop(proof);
            // Hold the build slot until the transport has taken the message off the route, so at
            // most one converted proof exists outside the send buffers at any time.
            self.router.pace_outgoing().await?;
            debug!("Sent pruning point proof");
        }
    }
}
