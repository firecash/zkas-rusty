use std::sync::Arc;

use super::{
    handler::RequestHandler,
    handler_trait::Handler,
    interface::{Interface, KaspadMethod, KaspadRoutingPolicy},
    method::Method,
};
use crate::{
    connection::{Connection, IncomingRoute},
    connection_handler::ServerContext,
    error::GrpcServerError,
};
use kaspa_grpc_core::protowire::{kaspad_request::Payload, *};
use kaspa_grpc_core::{ops::KaspadPayloadOps, protowire::NotifyFinalityConflictResponseMessage};
use kaspa_notify::{
    scope::{FinalityConflictResolvedScope, Scope},
    subscriber::SubscriptionManager,
    subscription::Command,
};
use kaspa_rpc_core::{SubmitBlockRejectReason, SubmitBlockResponse, api::safe_mode::check_subscription_allowed};
use kaspa_rpc_macros::build_grpc_server_interface;

pub struct Factory {}

impl Factory {
    pub fn new_handler(
        rpc_op: KaspadPayloadOps,
        incoming_route: IncomingRoute,
        server_context: ServerContext,
        interface: &Interface,
        connection: Connection,
    ) -> Box<dyn Handler> {
        Box::new(RequestHandler::new(rpc_op, incoming_route, server_context, interface, connection))
    }

    pub fn new_interface(server_ctx: ServerContext, network_bps: u64) -> Interface {
        // The array as last argument in the macro call below must exactly match the full set of
        // KaspadPayloadOps variants.
        let mut interface = build_grpc_server_interface!(
            server_ctx.clone(),
            ServerContext,
            Connection,
            KaspadRequest,
            KaspadResponse,
            KaspadPayloadOps,
            [
                SubmitBlock,
                GetBlockTemplate,
                GetCurrentNetwork,
                GetBlock,
                GetBlocks,
                GetInfo,
                Shutdown,
                GetPeerAddresses,
                GetSink,
                GetShieldedTreeState,
                GetShieldedBlocks,
                GetShieldedSupply,
                GetShieldedCoinbaseRewards,
                GetShieldedTagColumn,
                GetMempoolEntry,
                GetMempoolEntries,
                GetConnectedPeerInfo,
                AddPeer,
                SubmitTransaction,
                SubmitTransactionReplacement,
                GetSubnetwork,
                GetVirtualChainFromBlock,
                GetBlockCount,
                GetBlockDagInfo,
                ResolveFinalityConflict,
                GetHeaders,
                GetUtxosByAddresses,
                GetBalanceByAddress,
                GetBalancesByAddresses,
                GetSinkBlueScore,
                Ban,
                Unban,
                EstimateNetworkHashesPerSecond,
                GetMempoolEntriesByAddresses,
                GetCoinSupply,
                Ping,
                GetMetrics,
                GetConnections,
                GetSystemInfo,
                GetServerInfo,
                GetSyncStatus,
                GetDaaScoreTimestampEstimate,
                GetFeeEstimate,
                GetFeeEstimateExperimental,
                GetCurrentBlockColor,
                GetBlockRewardInfo,
                GetUtxoReturnAddress,
                GetVirtualChainFromBlockV2,
                GetSeqCommitLaneProof,
                NotifyBlockAdded,
                NotifyNewBlockTemplate,
                NotifyFinalityConflict,
                NotifyUtxosChanged,
                NotifySinkBlueScoreChanged,
                NotifyPruningPointUtxoSetOverride,
                NotifyVirtualDaaScoreChanged,
                NotifyVirtualChainChanged,
                StopNotifyingUtxosChanged,
                StopNotifyingPruningPointUtxoSetOverride,
            ]
        );

        // Manually reimplementing the NotifyFinalityConflictRequest method so subscription
        // gets mirrored to FinalityConflictResolved notifications as well.
        let method: KaspadMethod = Method::new(|server_ctx: ServerContext, connection: Connection, request: KaspadRequest| {
            Box::pin(async move {
                let mut response: KaspadResponse = match request.payload {
                    Some(Payload::NotifyFinalityConflictRequest(ref request)) => {
                        match kaspa_rpc_core::NotifyFinalityConflictRequest::try_from(request) {
                            Ok(request) => {
                                let listener_id = connection.get_or_register_listener_id()?;
                                let command = request.command;
                                let result = server_ctx
                                    .notifier
                                    .clone()
                                    .execute_subscribe_command(listener_id, request.into(), command)
                                    .await
                                    .and(
                                        server_ctx
                                            .notifier
                                            .clone()
                                            .execute_subscribe_command(
                                                listener_id,
                                                FinalityConflictResolvedScope::default().into(),
                                                command,
                                            )
                                            .await,
                                    );
                                NotifyFinalityConflictResponseMessage::from(result).into()
                            }
                            Err(err) => NotifyFinalityConflictResponseMessage::from(err).into(),
                        }
                    }
                    _ => {
                        return Err(GrpcServerError::InvalidRequestPayload);
                    }
                };
                response.id = request.id;
                Ok(response)
            })
        });
        interface.replace_method(KaspadPayloadOps::NotifyFinalityConflict, method);

        // Manually reimplementing the NotifyUtxosChangedRequest method so `--unsaferpc` gates it.
        // Subscriptions go to this server's own notifier, never through `RpcCoreService::start_notify`
        // where the rule used to live alone, so a blanket UtxosChanged was refused to nobody remote.
        // Unsubscribing (`Stop` here, or the separate `StopNotifyingUtxosChanged` op) stays allowed.
        let method: KaspadMethod = Method::new(|server_ctx: ServerContext, connection: Connection, request: KaspadRequest| {
            Box::pin(async move {
                let mut response: KaspadResponse = match request.payload {
                    Some(Payload::NotifyUtxosChangedRequest(ref request)) => {
                        match kaspa_rpc_core::NotifyUtxosChangedRequest::try_from(request) {
                            Ok(request) => {
                                let command = request.command;
                                let scope: Scope = request.into();
                                let allowed = match command {
                                    Command::Start => check_subscription_allowed(server_ctx.unsafe_rpc, &scope),
                                    Command::Stop => Ok(()),
                                };
                                match allowed {
                                    Ok(()) => {
                                        let listener_id = connection.get_or_register_listener_id()?;
                                        let result =
                                            server_ctx.notifier.clone().execute_subscribe_command(listener_id, scope, command).await;
                                        NotifyUtxosChangedResponseMessage::from(result).into()
                                    }
                                    Err(err) => NotifyUtxosChangedResponseMessage::from(err).into(),
                                }
                            }
                            Err(err) => NotifyUtxosChangedResponseMessage::from(err).into(),
                        }
                    }
                    _ => {
                        return Err(GrpcServerError::InvalidRequestPayload);
                    }
                };
                response.id = request.id;
                Ok(response)
            })
        });
        interface.replace_method(KaspadPayloadOps::NotifyUtxosChanged, method);

        // Methods with special properties
        let network_bps = network_bps as usize;
        // ZKas: a large merge-mining fleet (100+ ASICs behind one pool gRPC connection) bursts
        // block submissions far above `network_bps`. Upstream sizes this route at
        // (tasks=bps, queue=10.max(bps*2)) — on a 1-bps chain that is 1 worker / 10-slot queue,
        // which overflows under fleet bursts and returns `RouteIsFull`, silently dropping valid
        // target-clearing blocks. Widen the SubmitBlock route so concurrent submissions are
        // validated in parallel and queued rather than dropped. Block validation is CPU-bound and
        // idempotent, so extra workers/queue depth are safe; other routes are unchanged.
        let submit_block_tasks = network_bps.max(8);
        let submit_block_queue = 256.max(network_bps * 4);
        interface.set_method_properties(
            KaspadPayloadOps::SubmitBlock,
            submit_block_tasks,
            submit_block_queue,
            KaspadRoutingPolicy::DropIfFull(Arc::new(Box::new(|_: &KaspadRequest| {
                Ok(Ok(SubmitBlockResponse::reject(SubmitBlockRejectReason::RouteIsFull, "the node's block-processing route is full"))
                    .into())
            }))),
        );

        interface
    }
}
