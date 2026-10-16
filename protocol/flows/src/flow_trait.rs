use crate::flow_context::FlowContext;
use kaspa_core::warn;
use kaspa_p2p_lib::{Router, common::ProtocolError};
use kaspa_utils::any::type_name_short;
use std::sync::Arc;

#[async_trait::async_trait]
pub trait Flow
where
    Self: 'static + Send + Sync,
{
    fn name(&self) -> &'static str {
        type_name_short::<Self>()
    }

    fn router(&self) -> Option<Arc<Router>>;

    async fn start(&mut self) -> Result<(), ProtocolError>;

    /// Runs the flow on its own task. On error the peer is sent a reject and disconnected, and the
    /// error is offered to `--enablebanning` (`FlowContext::ban_if_protocol_violation`), which
    /// acts only on the narrow class of errors no honest peer can produce. This is the one place
    /// every flow error passes, which is why the ban decision is made here rather than per flow.
    fn launch(mut self: Box<Self>, ctx: FlowContext) {
        tokio::spawn(async move {
            let res = self.start().await;
            if let Err(err) = res
                && let Some(router) = self.router()
            {
                router.try_sending_reject_message(&err).await;
                if router.close().await || !err.is_connection_closed_error() {
                    warn!("{} flow error: {}, disconnecting from peer {}.", self.name(), err, router);
                }
                ctx.ban_if_protocol_violation(&router, &err);
            }
        });
    }
}
