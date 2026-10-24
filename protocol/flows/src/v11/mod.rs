//! Protocol v11 flows: the v10 flows plus the Dandelion++ stem flow, `ShieldedConflict` notices
//! and pinned-key authentication (spec 06 H-1, §3.3, T-8). Payloads >= 80 are only ever sent to a
//! peer registered here, so a v10 peer never receives one.

pub mod auth;
pub mod stem;

use crate::{flow_context::FlowContext, flow_trait::Flow, v10};
use kaspa_p2p_lib::{KaspadMessagePayloadType, Router};
use std::sync::Arc;

pub fn register(ctx: FlowContext, router: Arc<Router>, protocol_version: u32) -> Vec<Box<dyn Flow>> {
    let mut flows = v10::register(ctx.clone(), router.clone(), protocol_version);
    flows.push(Box::new(stem::HandleStemTransactionsFlow::new(
        ctx.clone(),
        router.clone(),
        router.subscribe(vec![KaspadMessagePayloadType::StemTransaction]),
    )));
    flows.push(Box::new(stem::HandleShieldedConflictFlow::new(
        ctx.clone(),
        router.clone(),
        router.subscribe(vec![KaspadMessagePayloadType::ShieldedConflict]),
    )));
    flows.push(Box::new(auth::AuthFlow::new(
        ctx,
        router.clone(),
        router.subscribe(vec![KaspadMessagePayloadType::AuthRequest, KaspadMessagePayloadType::AuthResponse]),
    )));
    flows
}
