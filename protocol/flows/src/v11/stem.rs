use crate::{flow_context::FlowContext, flow_trait::Flow};
use kaspa_consensus_core::tx::Transaction;
use kaspa_p2p_lib::{IncomingRoute, Router, common::ProtocolError, dequeue, pb::kaspad_message::Payload};
use std::sync::Arc;

/// Receives `StemTransaction` (spec 06 D-3): validate, then forward along the stem or fluff.
pub struct HandleStemTransactionsFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for HandleStemTransactionsFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        loop {
            let msg = dequeue!(self.incoming_route, Payload::StemTransaction)?;
            let tx: Transaction = msg.transaction.ok_or(ProtocolError::Other("stem transaction message without a transaction"))?.try_into()?;
            self.ctx.handle_stem_transaction(&self.router, tx).await?;
        }
    }
}

impl HandleStemTransactionsFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}

/// Receives `ShieldedConflict` (spec 12 S4.1, 06 D-9): verify, then forward once.
pub struct HandleShieldedConflictFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for HandleShieldedConflictFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        loop {
            let msg = dequeue!(self.incoming_route, Payload::ShieldedConflict)?;
            self.ctx.handle_conflict_notice(&self.router, msg).await?;
        }
    }
}

impl HandleShieldedConflictFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}
