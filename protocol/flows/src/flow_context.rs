use crate::ban_policy::{AutoBanBudget, auto_ban_may_target, is_fork_reject_reason};
use crate::serve_policy::ProofServeGate;
use crate::flowcontext::{
    orphans::{OrphanBlocksPool, OrphanOutput},
    process_queue::ProcessQueue,
    transactions::TransactionsSpread,
};
use crate::user_agent_rule::{UserAgentRuleRejectReason, UserAgentRuleSet};
use crate::{v7, v8, v10};
use async_trait::async_trait;
use futures::future::join_all;
use kaspa_addressmanager::AddressManager;
use kaspa_connectionmanager::ConnectionManager;
use kaspa_consensus_core::api::{BlockValidationFuture, BlockValidationFutures};
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::config::{Config, params::ForkActivation};
use kaspa_consensus_core::errors::block::RuleError;
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use kaspa_consensus_notify::{
    notification::{Notification, PruningPointUtxoSetOverrideNotification},
    root::ConsensusNotificationRoot,
};
use kaspa_consensusmanager::{BlockProcessingBatch, ConsensusInstance, ConsensusManager, ConsensusProxy, ConsensusSessionOwned};
use kaspa_core::{
    debug, info,
    kaspad_env::{name, version},
    task::tick::TickService,
};
use kaspa_core::{time::unix_now, warn};
use kaspa_hashes::Hash;
use kaspa_mining::mempool::tx::{Orphan, Priority};
use kaspa_mining::{manager::MiningManagerProxy, mempool::tx::RbfPolicy};
use kaspa_notify::notifier::Notify;
use kaspa_p2p_lib::{
    ConnectionInitializer, Hub, KaspadHandshake, PeerKey, PeerProperties, Router,
    common::ProtocolError,
    convert::model::version::Version,
    make_message,
    pb::{InvRelayBlockMessage, kaspad_message::Payload},
};
use kaspa_p2p_mining::rule_engine::MiningRuleEngine;
use kaspa_utils::iter::IterExtensions;
use kaspa_utils::networking::PeerId;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::time::Instant;
use std::{collections::hash_map::Entry, fmt::Display};
use std::{
    iter::once,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{
    RwLock as AsyncRwLock,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_stream::{StreamExt, wrappers::UnboundedReceiverStream};
use uuid::Uuid;

/// The P2P protocol version.
const PROTOCOL_VERSION: u32 = 10;

/// Whether a peer that relayed an invalid shielded proof is exempt from the ban (N1, spec 08
/// R1.4.4): it advertises a protocol version above ours, or a newer release of this node software.
pub(crate) fn shielded_proof_ban_exempt(peer_protocol_version: u32, user_agent: &str) -> bool {
    peer_protocol_version > PROTOCOL_VERSION
        || crate::user_agent_rule::advertises_newer_release(user_agent, kaspa_core::kaspad_env::name(), kaspa_core::kaspad_env::version())
}

/// Concurrent pruning-point nullifier exports one node serves (spec 08 R3.3). Each one walks the
/// whole set from a database snapshot; a third requester waits (and past its timeout, tries another
/// peer) instead of adding a third full read.
pub const MAX_CONCURRENT_SHIELDED_EXPORTS: usize = 2;

/// See `check_orphan_resolution_range`
const BASELINE_ORPHAN_RESOLUTION_RANGE: u32 = 5;

/// Orphans are kept as full blocks so we cannot hold too much of them in memory
const MAX_ORPHANS_UPPER_BOUND: usize = 1024;

/// The min time to wait before allowing another parallel request
const REQUEST_SCOPE_WAIT_TIME: Duration = Duration::from_secs(1);

/// Represents a block event to be logged
#[derive(Debug, PartialEq)]
pub enum BlockLogEvent {
    /// Accepted block via *relay*
    Relay(Hash, u64),
    /// Accepted block via *submit block*
    Submit(Hash, u64),
    /// Orphaned block with x missing roots
    Orphaned(Hash, usize),
    /// Unorphaned x blocks with hash being a representative
    Unorphaned(Hash, usize),
}

pub struct BlockEventLogger {
    bps: usize,
    countdown_activation: CountdownActivation,
    sender: UnboundedSender<BlockLogEvent>,
    receiver: Mutex<Option<UnboundedReceiver<BlockLogEvent>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CountdownActivation {
    name: &'static str,
    activation: ForkActivation,
}

impl CountdownActivation {
    fn toccata(toccata_activation: ForkActivation) -> Self {
        Self { name: "Toccata", activation: toccata_activation }
    }
}

impl BlockEventLogger {
    fn new(bps: usize, countdown_activation: CountdownActivation) -> Self {
        let (sender, receiver) = unbounded_channel();
        Self { bps, countdown_activation, sender, receiver: Mutex::new(Some(receiver)) }
    }

    pub fn log(&self, event: BlockLogEvent) {
        self.sender.send(event).unwrap();
    }

    /// Start the logger listener. Must be called from an async tokio context
    fn start(&self) {
        let chunk_limit = self.bps * 10; // We prefer that the 1 sec timeout forces the log, but nonetheless still want a reasonable bound on each chunk
        let receiver = self.receiver.lock().take().expect("expected to be called once");
        let countdown_activation = self.countdown_activation;
        tokio::spawn(async move {
            let chunk_stream = UnboundedReceiverStream::new(receiver).chunks_timeout(chunk_limit, Duration::from_secs(1));
            tokio::pin!(chunk_stream);
            while let Some(chunk) = chunk_stream.next().await {
                #[derive(Default)]
                struct LogSummary {
                    // Representatives
                    relay_rep: Option<(Hash, u64)>,
                    submit_rep: Option<(Hash, u64)>,
                    orphan_rep: Option<Hash>,
                    unorphan_rep: Option<Hash>,
                    // Counts
                    relay_count: usize,
                    submit_count: usize,
                    orphan_count: usize,
                    unorphan_count: usize,
                    orphan_roots_count: usize,
                }

                struct LogHash {
                    op: Option<Hash>,
                }

                impl From<Option<Hash>> for LogHash {
                    fn from(op: Option<Hash>) -> Self {
                        Self { op }
                    }
                }

                impl Display for LogHash {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        if let Some(hash) = self.op { hash.fmt(f) } else { Ok(()) }
                    }
                }

                fn activation_countdown_suffix(countdown: CountdownActivation, daa_score: Option<u64>) -> String {
                    daa_score
                        .and_then(|daa_score| countdown.activation.is_within_range_before_activation(daa_score, 36_000))
                        .map(|dist| format!(" \t [{} countdown: -{}]", countdown.name, dist))
                        .unwrap_or_default()
                }

                impl LogSummary {
                    fn relay(&self) -> LogHash {
                        self.relay_rep.map(|(hash, _)| hash).into()
                    }

                    fn submit(&self) -> LogHash {
                        self.submit_rep.map(|(hash, _)| hash).into()
                    }

                    fn relay_rep_daa_score(&self) -> Option<u64> {
                        self.relay_rep.map(|(_, daa_score)| daa_score)
                    }

                    fn submit_rep_daa_score(&self) -> Option<u64> {
                        self.submit_rep.map(|(_, daa_score)| daa_score)
                    }

                    fn orphan(&self) -> LogHash {
                        self.orphan_rep.into()
                    }

                    fn unorphan(&self) -> LogHash {
                        self.unorphan_rep.into()
                    }
                }

                let summary = chunk.into_iter().fold(LogSummary::default(), |mut summary, ev| {
                    match ev {
                        BlockLogEvent::Relay(hash, daa_score) => {
                            summary.relay_count += 1;
                            summary.relay_rep = Some((hash, daa_score));
                        }
                        BlockLogEvent::Submit(hash, daa_score) => {
                            summary.submit_count += 1;
                            summary.submit_rep = Some((hash, daa_score));
                        }
                        BlockLogEvent::Orphaned(hash, roots_count) => {
                            summary.orphan_roots_count += roots_count;
                            summary.orphan_count += 1;
                            summary.orphan_rep = Some(hash)
                        }
                        BlockLogEvent::Unorphaned(hash, count) => {
                            summary.unorphan_count += count;
                            summary.unorphan_rep = Some(hash)
                        }
                    }
                    summary
                });

                match (summary.submit_count, summary.relay_count) {
                    (0, 0) => {}
                    (1, 0) => info!(
                        "Accepted block {} via submit block{}",
                        summary.submit(),
                        activation_countdown_suffix(countdown_activation, summary.submit_rep_daa_score())
                    ),
                    (n, 0) => info!(
                        "Accepted {} blocks ...{} via submit block{}",
                        n,
                        summary.submit(),
                        activation_countdown_suffix(countdown_activation, summary.submit_rep_daa_score())
                    ),
                    (0, 1) => info!(
                        "Accepted block {} via relay{}",
                        summary.relay(),
                        activation_countdown_suffix(countdown_activation, summary.relay_rep_daa_score())
                    ),
                    (0, m) => info!(
                        "Accepted {} blocks ...{} via relay{}",
                        m,
                        summary.relay(),
                        activation_countdown_suffix(countdown_activation, summary.relay_rep_daa_score())
                    ),
                    (n, m) => {
                        info!(
                            "Accepted {} blocks ...{}, {} via relay and {} via submit block{}",
                            n + m,
                            summary.submit(),
                            m,
                            n,
                            activation_countdown_suffix(countdown_activation, summary.submit_rep_daa_score())
                        )
                    }
                }

                match (summary.orphan_count, summary.orphan_roots_count) {
                    (0, 0) => {}
                    (n, m) => info!("Orphaned {} block(s) ...{} and queued {} missing roots", n, summary.orphan(), m),
                }

                match summary.unorphan_count {
                    0 => {}
                    1 => info!("Unorphaned block {}", summary.unorphan()),
                    n => info!("Unorphaned {} block(s) ...{}", n, summary.unorphan()),
                }
            }
        });
    }
}

pub struct FlowContextInner {
    pub node_id: PeerId,
    pub consensus_manager: Arc<ConsensusManager>,
    pub config: Arc<Config>,
    hub: Hub,
    orphans_pool: AsyncRwLock<OrphanBlocksPool>,
    shared_block_requests: Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>,
    transactions_spread: AsyncRwLock<TransactionsSpread>,
    shared_transaction_requests: Arc<Mutex<HashMap<TransactionId, RequestScopeMetadata>>>,
    is_ibd_running: Arc<AtomicBool>,
    ibd_metadata: Arc<RwLock<Option<IbdMetadata>>>,
    pub address_manager: Arc<Mutex<AddressManager>>,
    connection_manager: RwLock<Option<Arc<ConnectionManager>>>,
    mining_manager: MiningManagerProxy,
    pub(crate) tick_service: Arc<TickService>,
    notification_root: Arc<ConsensusNotificationRoot>,
    user_agent_rules: UserAgentRuleSet,

    // Special sampling logger used only for high-bps networks where logs must be throttled
    block_event_logger: Option<BlockEventLogger>,

    /// Per-peer tally of blocks that peer was the FIRST to relay to us.
    ///
    /// The p2p layer otherwise forgets where a block came from the moment it is
    /// handed to consensus, so without this the question "which peers keep us
    /// supplied?" has no answer at all. Keyed by `PeerKey` and pruned when a
    /// peer is no longer connected, so it cannot grow without bound.
    relay_credit: Mutex<HashMap<PeerKey, u64>>,

    /// Rate limit on `--enablebanning`, see `ban_if_protocol_violation`.
    auto_ban_budget: Mutex<AutoBanBudget>,

    /// Global limit on pruning-point proof serves, see `serve_policy`.
    pub(crate) proof_serve_gate: ProofServeGate,

    /// At most this many pruning-point nullifier exports at once (N1, spec 08 R3.3).
    shielded_export_permits: Arc<tokio::sync::Semaphore>,

    /// IBD flows of peers that serve ranged nullifier streams and are idle, by peer: a range-split
    /// import hands them one range at a time (N1, spec 08 R3.4.1).
    shielded_range_helpers: Mutex<HashMap<PeerKey, tokio::sync::mpsc::Sender<crate::ibd::ShieldedRangeJob>>>,

    /// Failed integrity checks of range-split imports, per pruning point (N1, spec 08 R3.4.4/R3.5).
    shielded_import_suspects: Mutex<crate::ibd::ShieldedImportSuspects>,

    /// Node-wide shielded proof-verification budget for relayed transactions (N1, spec 08 R1.4).
    verify_budget_params: crate::verify_budget::BudgetParams,
    verify_budget_global: Mutex<crate::verify_budget::TokenBucket>,

    bps: usize,

    // Orphan parameters
    orphan_resolution_range: u32,
    max_orphans: usize,

    // Mining rule engine
    mining_rule_engine: Arc<MiningRuleEngine>,
}

#[derive(Clone)]
pub struct FlowContext {
    inner: Arc<FlowContextInner>,
}

pub struct IbdRunningGuard {
    indicator: Arc<AtomicBool>,
}

impl Drop for IbdRunningGuard {
    fn drop(&mut self) {
        let result = self.indicator.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_ok())
    }
}

#[derive(Debug, Clone, Copy)]
struct IbdMetadata {
    /// The peer from which current IBD is syncing from
    peer: PeerKey,
    /// The DAA score of the relay block which triggered the current IBD
    daa_score: u64,
}

pub struct RequestScopeMetadata {
    pub timestamp: Instant,
    pub obtained: bool,
}

pub struct RequestScope<T: PartialEq + Eq + std::hash::Hash> {
    set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>,
    pub req: T,
}

impl<T: PartialEq + Eq + std::hash::Hash> RequestScope<T> {
    pub fn new(set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>, req: T) -> Self {
        Self { set, req }
    }

    /// Scope holders should use this function to report that the request has
    /// successfully been obtained from the peer and is now being processed
    pub fn report_obtained(&self) {
        if let Some(e) = self.set.lock().get_mut(&self.req) {
            e.obtained = true;
        }
    }
}

impl<T: PartialEq + Eq + std::hash::Hash> Drop for RequestScope<T> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.req);
    }
}

impl Deref for FlowContext {
    type Target = FlowContextInner;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl FlowContext {
    pub fn new(
        consensus_manager: Arc<ConsensusManager>,
        address_manager: Arc<Mutex<AddressManager>>,
        config: Arc<Config>,
        mining_manager: MiningManagerProxy,
        tick_service: Arc<TickService>,
        notification_root: Arc<ConsensusNotificationRoot>,
        hub: Hub,
        mining_rule_engine: Arc<MiningRuleEngine>,
    ) -> Self {
        let bps = config.bps() as usize;
        let orphan_resolution_range = BASELINE_ORPHAN_RESOLUTION_RANGE + (bps as f64).log2().ceil() as u32;
        let user_agent_rules = UserAgentRuleSet::parse_lossy(&config.user_agent_rules);

        // The maximum amount of orphans allowed in the orphans pool. This number is an approximation
        // of how many orphans there can possibly be on average bounded by an upper bound.
        let max_orphans = (2u64.pow(orphan_resolution_range) as usize * config.ghostdag_k() as usize).min(MAX_ORPHANS_UPPER_BOUND);
        Self {
            inner: Arc::new(FlowContextInner {
                node_id: Uuid::new_v4().into(),
                consensus_manager,
                orphans_pool: AsyncRwLock::new(OrphanBlocksPool::new(max_orphans)),
                shared_block_requests: Arc::new(Mutex::new(HashMap::new())),
                transactions_spread: AsyncRwLock::new(TransactionsSpread::new(hub.clone())),
                shared_transaction_requests: Arc::new(Mutex::new(HashMap::new())),
                is_ibd_running: Default::default(),
                ibd_metadata: Default::default(),
                hub,
                address_manager,
                connection_manager: Default::default(),
                mining_manager,
                tick_service,
                notification_root,
                user_agent_rules,
                block_event_logger: Some(BlockEventLogger::new(bps, CountdownActivation::toccata(config.toccata_activation))),
                relay_credit: Default::default(),
                auto_ban_budget: Default::default(),
                proof_serve_gate: Default::default(),
                shielded_export_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHIELDED_EXPORTS)),
                shielded_range_helpers: Default::default(),
                shielded_import_suspects: Default::default(),
                verify_budget_params: crate::verify_budget::BudgetParams::for_cores(crate::verify_budget::default_verify_cores()),
                verify_budget_global: Mutex::new(
                    crate::verify_budget::BudgetParams::for_cores(crate::verify_budget::default_verify_cores())
                        .global_bucket(std::time::Instant::now()),
                ),
                bps,
                orphan_resolution_range,
                max_orphans,
                config,
                mining_rule_engine,
            }),
        }
    }

    /// Offer this peer's idle IBD flow as a ranged-stream source (N1, spec 08 R3.4.1).
    pub fn register_shielded_range_helper(&self, key: PeerKey, jobs: tokio::sync::mpsc::Sender<crate::ibd::ShieldedRangeJob>) {
        self.inner.shielded_range_helpers.lock().insert(key, jobs);
    }

    pub fn unregister_shielded_range_helper(&self, key: &PeerKey) {
        self.inner.shielded_range_helpers.lock().remove(key);
    }

    /// The registered range helpers other than `me`.
    pub fn shielded_range_helpers_except(&self, me: &PeerKey) -> Vec<(PeerKey, tokio::sync::mpsc::Sender<crate::ibd::ShieldedRangeJob>)> {
        self.inner.shielded_range_helpers.lock().iter().filter(|(k, _)| *k != me).map(|(k, s)| (*k, s.clone())).collect()
    }

    /// The suspect record of range-split imports (N1, spec 08 R3.4.4/R3.5).
    pub fn shielded_import_suspects(&self) -> parking_lot::MutexGuard<'_, crate::ibd::ShieldedImportSuspects> {
        self.inner.shielded_import_suspects.lock()
    }

    /// The node-wide verification budget parameters (N1, spec 08 R1.4).
    pub fn verify_budget_params(&self) -> crate::verify_budget::BudgetParams {
        self.inner.verify_budget_params
    }

    /// Charge `vu` verify units to `peer` and the node-wide budget (N1, spec 08 R1.4).
    pub fn charge_verify_budget(
        &self,
        peer: &mut crate::verify_budget::PeerBudget,
        vu: f64,
        now: std::time::Instant,
    ) -> crate::verify_budget::Admission {
        crate::verify_budget::charge(peer, &mut self.inner.verify_budget_global.lock(), vu, now)
    }

    /// The gate on concurrent pruning-point nullifier exports (N1, spec 08 R3.3).
    pub fn shielded_export_permits(&self) -> Arc<tokio::sync::Semaphore> {
        self.inner.shielded_export_permits.clone()
    }

    pub fn block_invs_channel_size(&self) -> usize {
        self.bps * Router::incoming_flow_baseline_channel_size()
    }

    pub fn orphan_resolution_range(&self) -> u32 {
        self.orphan_resolution_range
    }

    pub fn max_orphans(&self) -> usize {
        self.max_orphans
    }

    pub fn start_async_services(&self) {
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.start();
        }
    }

    pub fn set_connection_manager(&self, connection_manager: Arc<ConnectionManager>) {
        self.connection_manager.write().replace(connection_manager);
    }

    pub fn drop_connection_manager(&self) {
        self.connection_manager.write().take();
    }

    pub fn connection_manager(&self) -> Option<Arc<ConnectionManager>> {
        self.connection_manager.read().clone()
    }

    /// `--enablebanning`: ban the peer behind `router` if `err` proves it broke the wire protocol
    /// itself. Called for every failed connection: by the handshake, and by `Flow::launch` for
    /// every flow error.
    ///
    /// Off by default, and narrow when on. `ProtocolError::is_auto_ban_eligible` admits only errors
    /// no honest peer of any version can produce; consensus rejections never qualify, because
    /// after a rule change they are what honest peers on the other side send, and banning them
    /// would turn a transient partition into a permanent one. `auto_ban_may_target` refuses
    /// addresses a port forwarder hides many peers behind. An IP with an `--addpeer`/`--connect`
    /// request is never auto-banned: the operator chose that peer by name, and an automatic rule
    /// should not overrule a person (`ConnectionManager::ban` enforces this as well). And
    /// `AutoBanBudget` bounds how many rows a stream of fresh addresses can make us persist.
    ///
    /// The ban runs on its own task. An outbound connection is initialized while the connection
    /// manager holds its request lock (`handle_connection_requests` awaits the connect under it),
    /// and both the permanent-request check and `ConnectionManager::ban` take that lock, so
    /// awaiting them here would deadlock the connection loop.
    pub(crate) fn ban_if_protocol_violation(&self, router: &Router, err: &ProtocolError) {
        // N1 (spec 08 R1.4.4): relaying an invalid shielded proof is its own ban class, ON by
        // default (`--no-ban-shielded` turns it off) and independent of `--enablebanning`. A proof
        // fails for every honest peer of the SAME rules, which verify before relaying; the one
        // honest way to send one is to run newer rules (a circuit upgrade makes an upgraded peer's
        // proofs invalid here), so a peer advertising a newer protocol or release is only
        // disconnected. `spawn_auto_ban` keeps the other exemptions (non-routable addresses,
        // operator-chosen peers, the ban budget).
        if let ProtocolError::InvalidShieldedProof(reason) = err {
            if !self.config.ban_invalid_shielded_proofs {
                return;
            }
            let props = router.properties();
            if shielded_proof_ban_exempt(props.advertised_protocol_version, &props.user_agent) {
                info!("P2P, not banning peer {} for an invalid shielded proof ({}): it advertises newer rules", router, reason);
                return;
            }
            self.spawn_auto_ban(router, format!("invalid shielded proof: {reason}"), false);
            return;
        }
        if !self.config.enable_banning {
            return;
        }
        // A peer that rejected what WE sent closes the connection with its reason, and every flow
        // then ends here with `ConnectionClosed`; the router hands the reason to the first of them.
        // Only one reason counts: see `is_fork_reject_reason`.
        if let Some(reason) = router.take_peer_reject_reason() {
            if is_fork_reject_reason(&reason) {
                self.spawn_auto_ban(router, format!("it rejects our blocks as \"{reason}\", i.e. it follows the pre-fork rules"), true);
            }
            return;
        }
        if !err.is_auto_ban_eligible() {
            return;
        }
        self.spawn_auto_ban(router, err.to_string(), false);
    }

    /// The shared tail of `ban_if_protocol_violation`: exemptions, budget, then the ban.
    ///
    /// `fork_reject` adds two conditions the reason alone cannot carry. The security fork must be
    /// active at this node's own virtual DAA score: before it, a peer calling our PoW invalid means
    /// something else entirely. And this node must be nearly synced: a node that was fed a chain
    /// nobody mined is rejected by every honest peer for exactly this reason, and must never answer
    /// that by banning them.
    fn spawn_auto_ban(&self, router: &Router, reason: String, fork_reject: bool) {
        let ip = router.net_address().ip();
        if !auto_ban_may_target(ip) {
            debug!("P2P, not auto-banning peer {} ({}): its address is not publicly routable", router, reason);
            return;
        }
        let Some(connection_manager) = self.connection_manager() else {
            return;
        };
        if fork_reject {
            let user_agent = &router.properties().user_agent;
            if crate::user_agent_rule::advertises_newer_release(user_agent, kaspa_core::kaspad_env::name(), kaspa_core::kaspad_env::version()) {
                info!(
                    "P2P, not auto-banning peer {} ({}): it runs a newer release ({}), so this node may be the one behind",
                    router, reason, user_agent
                );
                return;
            }
        }
        let ctx = self.clone();
        let peer = router.to_string();
        tokio::spawn(async move {
            if fork_reject {
                let session = ctx.consensus().unguarded_session();
                if !ctx.config.security_fork_activation.is_active(session.get_virtual_daa_score()) {
                    debug!("P2P, not auto-banning peer {} ({}): the security fork is not active here yet", peer, reason);
                    return;
                }
                if !ctx.is_nearly_synced(&session).await {
                    info!("P2P, not auto-banning peer {} ({}): this node is not synced, so it cannot tell whose chain is wrong", peer, reason);
                    return;
                }
            }
            // Both spellings: a permanent request names the IPv4 address, but the same peer dialing
            // in on a dual-stack listener arrives as `::ffff:a.b.c.d`.
            if connection_manager.ip_has_permanent_connection(ip).await
                || connection_manager.ip_has_permanent_connection(ip.to_canonical()).await
            {
                // A pre-fork --addpeer redials every few seconds; its reject is already logged.
                if fork_reject {
                    debug!("P2P, not auto-banning peer {} ({}): it is an --addpeer/--connect peer", peer, reason);
                } else {
                    info!("P2P, not auto-banning peer {} ({}): it is an --addpeer/--connect peer", peer, reason);
                }
                return;
            }
            let granted = ctx.auto_ban_budget.lock().try_take(Instant::now());
            if !granted {
                warn!("P2P, not auto-banning peer {} ({}): this hour's automatic ban budget is spent", peer, reason);
                return;
            }
            warn!("P2P, banning peer {} for 24 hours: {}", peer, reason);
            connection_manager.ban(ip).await;
        });
    }

    pub fn consensus(&self) -> ConsensusInstance {
        self.consensus_manager.consensus()
    }

    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    pub fn mining_manager(&self) -> &MiningManagerProxy {
        &self.mining_manager
    }

    pub fn try_set_ibd_running(&self, peer: PeerKey, relay_daa_score: u64) -> Option<IbdRunningGuard> {
        if self.is_ibd_running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            self.ibd_metadata.write().replace(IbdMetadata { peer, daa_score: relay_daa_score });
            Some(IbdRunningGuard { indicator: self.is_ibd_running.clone() })
        } else {
            None
        }
    }

    pub fn is_ibd_running(&self) -> bool {
        self.is_ibd_running.load(Ordering::SeqCst)
    }

    /// If IBD is running, returns the IBD peer we are syncing from
    /// Credit a peer for being the first to hand us a block body.
    ///
    /// Called from the relay flow once consensus has accepted the block, so a
    /// peer only earns credit for blocks that turned out to be valid.
    pub fn credit_relay(&self, peer: PeerKey) {
        *self.relay_credit.lock().entry(peer).or_default() += 1;
    }

    /// Blocks a peer was the first to relay to us since this node started.
    pub fn relay_credit(&self, peer: &PeerKey) -> u64 {
        self.relay_credit.lock().get(peer).copied().unwrap_or(0)
    }

    /// Drop tallies for peers that are no longer connected, so a node churning
    /// through peers over weeks does not accumulate a map of dead keys.
    pub fn prune_relay_credit(&self, connected: &[PeerKey]) {
        let mut credit = self.relay_credit.lock();
        if credit.len() <= connected.len() {
            return;
        }
        let live: std::collections::HashSet<PeerKey> = connected.iter().copied().collect();
        credit.retain(|k, _| live.contains(k));
    }

    pub fn ibd_peer_key(&self) -> Option<PeerKey> {
        if self.is_ibd_running() { self.ibd_metadata.read().map(|md| md.peer) } else { None }
    }

    /// If IBD is running, returns the DAA score of the relay block which triggered it
    pub fn ibd_relay_daa_score(&self) -> Option<u64> {
        if self.is_ibd_running() { self.ibd_metadata.read().map(|md| md.daa_score) } else { None }
    }

    fn try_adding_request_impl(req: Hash, map: &Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>) -> Option<RequestScope<Hash>> {
        match map.lock().entry(req) {
            Entry::Occupied(mut e) => {
                if e.get().obtained {
                    None
                } else {
                    let now = Instant::now();
                    if now > e.get().timestamp + REQUEST_SCOPE_WAIT_TIME {
                        e.get_mut().timestamp = now;
                        Some(RequestScope::new(map.clone(), req))
                    } else {
                        None
                    }
                }
            }
            Entry::Vacant(e) => {
                e.insert(RequestScopeMetadata { timestamp: Instant::now(), obtained: false });
                Some(RequestScope::new(map.clone(), req))
            }
        }
    }

    pub fn try_adding_block_request(&self, req: Hash) -> Option<RequestScope<Hash>> {
        Self::try_adding_request_impl(req, &self.shared_block_requests)
    }

    pub fn try_adding_transaction_request(&self, req: TransactionId) -> Option<RequestScope<TransactionId>> {
        Self::try_adding_request_impl(req, &self.shared_transaction_requests)
    }

    pub async fn add_orphan(&self, consensus: &ConsensusProxy, orphan_block: Block) -> Option<OrphanOutput> {
        self.orphans_pool.write().await.add_orphan(consensus, orphan_block).await
    }

    pub async fn is_known_orphan(&self, hash: Hash) -> bool {
        self.orphans_pool.read().await.is_known_orphan(hash)
    }

    pub async fn get_orphan_roots_if_known(&self, consensus: &ConsensusProxy, orphan: Hash) -> OrphanOutput {
        self.orphans_pool.read().await.get_orphan_roots_if_known(consensus, orphan).await
    }

    pub async fn unorphan_blocks(&self, consensus: &ConsensusProxy, root: Hash) -> Vec<(Block, BlockValidationFuture)> {
        let (blocks, block_tasks, virtual_state_tasks) = self.orphans_pool.write().await.unorphan_blocks(consensus, root).await;
        let mut unorphaned_blocks = Vec::with_capacity(blocks.len());
        let results = join_all(block_tasks).await;
        for ((block, result), virtual_state_task) in blocks.into_iter().zip(results).zip(virtual_state_tasks) {
            match result {
                Ok(_) => {
                    unorphaned_blocks.push((block, virtual_state_task));
                }
                Err(e) => warn!("Validation failed for orphan block {}: {}", block.hash(), e),
            }
        }

        // Log or send to event logger
        if !unorphaned_blocks.is_empty() {
            if let Some(logger) = self.block_event_logger.as_ref() {
                logger.log(BlockLogEvent::Unorphaned(unorphaned_blocks[0].0.hash(), unorphaned_blocks.len()));
            } else {
                match unorphaned_blocks.len() {
                    1 => info!("Unorphaned block {}", unorphaned_blocks[0].0.hash()),
                    n => info!("Unorphaned {} blocks: {}", n, unorphaned_blocks.iter().map(|b| b.0.hash()).reusable_format(", ")),
                }
            }
        }
        unorphaned_blocks
    }

    pub async fn revalidate_orphans(&self, consensus: &ConsensusProxy) -> (Vec<Hash>, Vec<BlockValidationFuture>) {
        self.orphans_pool.write().await.revalidate_orphans(consensus).await
    }

    /// Adds the rpc-submitted block to the DAG and propagates it to peers.
    pub async fn submit_rpc_block(&self, consensus: &ConsensusProxy, block: Block) -> Result<(), ProtocolError> {
        if block.transactions.is_empty() {
            return Err(RuleError::NoTransactions)?;
        }
        let hash = block.hash();
        let BlockValidationFutures { block_task, virtual_state_task } = consensus.validate_and_insert_block(block.clone());
        if let Err(err) = block_task.await {
            warn!("Validation failed for block {}: {}", hash, err);
            return Err(err)?;
        }
        // Broadcast as soon as the block has been validated and inserted into the DAG
        self.hub.broadcast(make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(hash.into()) }), None).await;

        let daa_score = block.header.daa_score;
        self.on_new_block(consensus, Default::default(), block, virtual_state_task).await;
        self.log_block_event(BlockLogEvent::Submit(hash, daa_score));

        Ok(())
    }

    pub fn log_block_event(&self, event: BlockLogEvent) {
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.log(event)
        } else {
            match event {
                BlockLogEvent::Relay(hash, _) => info!("Accepted block {} via relay", hash),
                BlockLogEvent::Submit(hash, _) => info!("Accepted block {} via submit block", hash),
                BlockLogEvent::Orphaned(orphan, roots_count) => {
                    info!("Received a block with {} missing ancestors, adding to orphan pool: {}", roots_count, orphan)
                }
                _ => {}
            }
        }
    }

    /// Updates the mempool after a new block arrival, relays newly unorphaned transactions
    /// and possibly rebroadcast manually added transactions when not in IBD.
    ///
    /// _GO-KASPAD: OnNewBlock + broadcastTransactionsAfterBlockAdded_
    pub async fn on_new_block(
        &self,
        consensus: &ConsensusProxy,
        ancestor_batch: BlockProcessingBatch,
        block: Block,
        virtual_state_task: BlockValidationFuture,
    ) {
        let hash = block.hash();
        let mut blocks = self.unorphan_blocks(consensus, hash).await;

        // Broadcast unorphaned blocks
        let msgs = blocks
            .iter()
            .map(|(b, _)| make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(b.hash().into()) }))
            .collect();
        self.hub.broadcast_many(msgs, None).await;

        // Process blocks in topological order
        blocks.sort_by(|a, b| a.0.header.blue_work.partial_cmp(&b.0.header.blue_work).unwrap());
        // Use a ProcessQueue so we get rid of duplicates
        let mut transactions_to_broadcast = ProcessQueue::new();
        for (block, virtual_state_task) in ancestor_batch.zip().chain(once((block, virtual_state_task))).chain(blocks) {
            // We only care about waiting for virtual to process the block at this point, before proceeding with post-processing
            // actions such as updating the mempool. We know this will not err since `block_task` already completed w/o error
            let _ = virtual_state_task.await;
            if let Ok(txs) = self
                .mining_manager()
                .clone()
                .handle_new_block_transactions(consensus, block.header.daa_score, block.transactions.clone())
                .await
            {
                transactions_to_broadcast.enqueue_chunk(txs.into_iter().map(|x| x.id()));
            }
        }

        // Transaction relay is disabled if the node is out of sync
        if !self.is_nearly_synced(consensus).await {
            return;
        }

        // TODO: Throttle these transactions as well if needed
        self.broadcast_transactions(transactions_to_broadcast, false).await;

        if self.should_run_mempool_scanning_task().await {
            // Spawn a task executing the removal of expired low priority transactions and, if time has come too,
            // the revalidation of high priority transactions.
            //
            // The TransactionSpread member ensures at most one instance of this task is running at any
            // given time.
            let mining_manager = self.mining_manager().clone();
            let consensus_clone = consensus.clone();
            let context = self.clone();
            debug!("<> Starting mempool scanning task #{}...", self.mempool_scanning_job_count().await);
            tokio::spawn(async move {
                mining_manager.clone().expire_low_priority_transactions(&consensus_clone).await;
                if context.should_rebroadcast().await {
                    let (tx, mut rx) = unbounded_channel();
                    tokio::spawn(async move {
                        mining_manager.revalidate_high_priority_transactions(&consensus_clone, tx).await;
                    });
                    while let Some(transactions) = rx.recv().await {
                        let _ = context
                            .broadcast_transactions(
                                transactions,
                                true, // We throttle high priority even when the network is not flooded since they will be rebroadcast if not accepted within reasonable time.
                            )
                            .await;
                    }
                }
                context.mempool_scanning_is_done().await;
                debug!("<> Mempool scanning task is done");
            });
        }
    }

    pub async fn is_nearly_synced(&self, session: &ConsensusSessionOwned) -> bool {
        let sink_daa_score_and_timestamp = session.async_get_sink_daa_score_timestamp().await;
        self.mining_rule_engine.is_nearly_synced(sink_daa_score_and_timestamp)
    }

    pub async fn should_mine(&self, session: &ConsensusSessionOwned) -> bool {
        let sink_daa_score_and_timestamp = session.async_get_sink_daa_score_timestamp().await;
        self.mining_rule_engine.should_mine(sink_daa_score_and_timestamp)
    }

    /// Notifies that the UTXO set was reset due to pruning point change via IBD.
    pub fn on_pruning_point_utxoset_override(&self) {
        // Notifications from the flow context might be ignored if the inner channel is already closing
        // due to global shutdown, hence we ignore the possible error
        let _ = self.notification_root.notify(Notification::PruningPointUtxoSetOverride(PruningPointUtxoSetOverrideNotification {}));
    }

    /// Notifies that a transaction has been added to the mempool.
    pub async fn on_transaction_added_to_mempool(&self) {
        // TODO: call a handler function or a predefined registered service
    }

    /// Adds the rpc-submitted transaction to the mempool and propagates it to peers.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
        orphan: Orphan,
    ) -> Result<(), ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, orphan, RbfPolicy::Forbidden)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        Ok(())
    }

    /// Replaces the rpc-submitted transaction into the mempool and propagates it to peers.
    ///
    /// Returns the removed mempool transaction on successful replace by fee.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction_replacement(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
    ) -> Result<Arc<Transaction>, ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, Orphan::Forbidden, RbfPolicy::Mandatory)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        // The combination of args above of Orphan::Forbidden and RbfPolicy::Mandatory should always result
        // in a removed transaction returned, however we prefer failing gracefully in case of future internal mempool changes
        transaction_insertion.removed.ok_or(ProtocolError::Other(
            "Replacement transaction was actually accepted but the *replaced* transaction was not returned from the mempool",
        ))
    }

    /// Returns true if the time has come for running the task cleaning mempool transactions.
    async fn should_run_mempool_scanning_task(&self) -> bool {
        self.transactions_spread.write().await.should_run_mempool_scanning_task()
    }

    /// Returns true if the time has come for a rebroadcast of the mempool high priority transactions.
    async fn should_rebroadcast(&self) -> bool {
        self.transactions_spread.read().await.should_rebroadcast()
    }

    async fn mempool_scanning_job_count(&self) -> u64 {
        self.transactions_spread.read().await.mempool_scanning_job_count()
    }

    async fn mempool_scanning_is_done(&self) {
        self.transactions_spread.write().await.mempool_scanning_is_done()
    }

    /// Add the given transactions IDs to a set of IDs to broadcast. The IDs will be broadcasted to all peers
    /// within transaction Inv messages.
    ///
    /// The broadcast itself may happen only during a subsequent call to this function since it is done at most
    /// after a predefined interval or when the queue length is larger than the Inv message capacity.
    pub async fn broadcast_transactions<I: IntoIterator<Item = TransactionId>>(&self, transaction_ids: I, should_throttle: bool) {
        self.transactions_spread.write().await.broadcast_transactions(transaction_ids, should_throttle).await
    }
}

#[async_trait]
impl ConnectionInitializer for FlowContext {
    async fn initialize_connection(&self, router: Arc<Router>) -> Result<(), ProtocolError> {
        let res = self.initialize_connection_inner(router.clone()).await;
        if let Err(err) = &res {
            // A malformed version message is the handshake's share of `--enablebanning`; the flows
            // report their own errors from `Flow::launch`.
            self.ban_if_protocol_violation(&router, err);
        }
        res
    }
}

impl FlowContext {
    async fn initialize_connection_inner(&self, router: Arc<Router>) -> Result<(), ProtocolError> {
        // An operator's ban was only ever a kick. `ConnectionManager::ban` terminates the peer's
        // current connections and persists the IP, and `is_banned` was written to read that back --
        // but nothing called it, on any path. The banned peer reconnected on its next dial and the
        // ban meant one dropped connection and nothing more. Consult it here, where every
        // connection passes exactly once, inbound and outbound alike, before any handshake work is
        // spent on its behalf.
        //
        // By default every ban in this store is operator-issued. `--enablebanning` (off by default)
        // adds automatic ones, but only for errors no honest peer of any version can produce --
        // never for a consensus rejection, which after a fork is what most honest peers send; see
        // `ban_if_protocol_violation`. Either way a ban expires with the store's 24-hour window.
        //
        // A stored ban refuses an `--addpeer`/`--connect` address too. Neither ban path creates
        // one for such an address (`ConnectionManager::ban` and the Ban RPC both refuse an IP with
        // a permanent request), so it only happens when the ban predates the request, and
        // `Unban` clears it. `ConnectionManager::is_banned`, which exempts permanent requests,
        // cannot be called here: an outbound permanent connection runs this initializer while the
        // connection manager holds the request lock that function takes.
        if self.address_manager.lock().is_banned(router.net_address().ip().into()) {
            return Err(ProtocolError::PeerBanned(router.to_string()));
        }

        // Build the handshake object and subscribe to handshake messages
        let mut handshake = KaspadHandshake::new(&router);

        // We start the router receive loop only after we registered to handshake routes
        router.start();

        let network_name = self.config.network_name();

        let local_address = self.address_manager.lock().best_local_address();

        // Networks with a scheduled Toccata activation advertise the current protocol version.
        // Other networks still support v10 locally, but advertise v9 so future Toccata-activated peers reject them.
        let advertise_toccata_p2p = self.config.toccata_activation != ForkActivation::never();
        let advertised_protocol_version = if advertise_toccata_p2p { PROTOCOL_VERSION } else { 9 };

        // Build the local version message
        // Subnets are not currently supported
        let mut self_version_message =
            Version::new(local_address, self.node_id, network_name.clone(), None, advertised_protocol_version);
        self_version_message.add_user_agent(name(), version(), &self.config.user_agent_comments);
        // Serves `RequestPruningPointProofChunks` (every node of this version does). Old peers
        // ignore `services`, and they are still asked for the proof in the legacy single message.
        self_version_message.services |= kaspa_p2p_lib::pp_proof_chunks::SERVICE_PRUNING_PROOF_CHUNKS;
        self_version_message.services |= kaspa_p2p_lib::common::SERVICE_NF_SORTED_STREAM;
        // TODO: disable_relay_tx from config/cmd

        // Perform the handshake
        let peer_version_message = handshake.handshake(self_version_message.into()).await?;
        // Get time_offset as accurate as possible by computing right after the handshake.
        //
        // `timestamp` is the peer's raw protobuf int64, unchecked at this point, and release builds
        // run with `overflow-checks = true`: a plain `-` let any TCP client of the p2p port send
        // `i64::MIN` and overflow here, and the panic hook turned that into `process::exit(1)` before
        // the network name, version or anything else about the peer had been looked at. The offset
        // is informational (peer info), so saturate rather than refuse.
        let time_offset = (unix_now() as i64).saturating_sub(peer_version_message.timestamp);

        let peer_version: Version = peer_version_message.try_into()?;
        router.set_identity(peer_version.id);
        // Avoid duplicate connections
        if self.hub.has_peer(router.key()) {
            return Err(ProtocolError::PeerAlreadyExists(router.key()));
        }
        // And loopback connections...
        if self.node_id == router.identity() {
            return Err(ProtocolError::LoopbackConnection(router.key()));
        }

        if peer_version.network != network_name {
            return Err(ProtocolError::WrongNetwork(network_name, peer_version.network));
        }

        if let Some(reason) = self.user_agent_rules.reject_reason(&peer_version.user_agent) {
            match reason {
                UserAgentRuleRejectReason::AllowanceExcluded => {
                    info!(
                        "Rejecting peer {} because user agent is outside configured allowance rules: {}",
                        router, peer_version.user_agent
                    );
                }
                UserAgentRuleRejectReason::Rejection(rule) => {
                    info!(
                        "Rejecting peer {} because user agent matched rejection rule `{}`: {}",
                        router,
                        rule.source(),
                        peer_version.user_agent
                    );
                }
            }
            return Err(ProtocolError::OtherOwned(format!("peer user agent rejected: {}", peer_version.user_agent)));
        }

        debug!("protocol versions - self: {}, peer: {}", PROTOCOL_VERSION, peer_version.protocol_version);

        let peer_protocol_version = peer_version.protocol_version;

        // One day before activation, upgraded nodes start disconnecting outdated peers from the P2P network.
        const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
        let daa_threshold = ONE_DAY_SECONDS * self.config.bps();
        let virtual_daa_score = self.consensus().unguarded_session().get_virtual_daa_score();
        let connect_only_new_versions = self.config.toccata_activation.is_active(virtual_daa_score.saturating_add(daa_threshold));

        // Until the one-day pre-activation threshold is reached, older protocol versions remain accepted.
        // Once it is reached, peers must advertise protocol 10.
        //
        // Note: post-activation fresh nodes with virtual DAA score near genesis are not covered here and
        // are guarded later during IBD by `validate_pruning_point_freshness_for_toccata`.
        let (flows, applied_protocol_version) = if connect_only_new_versions {
            // Register all flows according to version
            match peer_protocol_version {
                v if v >= PROTOCOL_VERSION => (v10::register(self.clone(), router.clone(), PROTOCOL_VERSION), PROTOCOL_VERSION),
                v => return Err(ProtocolError::VersionMismatch(PROTOCOL_VERSION, v)),
            }
        } else {
            // Register all flows according to version
            match peer_protocol_version {
                v if v >= PROTOCOL_VERSION => (v10::register(self.clone(), router.clone(), PROTOCOL_VERSION), PROTOCOL_VERSION),
                9 => (v8::register(self.clone(), router.clone(), 9), 9),
                8 => (v8::register(self.clone(), router.clone(), 8), 8),
                7 => (v7::register(self.clone(), router.clone()), 7),
                v => return Err(ProtocolError::VersionMismatch(PROTOCOL_VERSION, v)),
            }
        };

        // Build and register the peer properties
        let peer_properties = Arc::new(PeerProperties {
            user_agent: peer_version.user_agent,
            services: peer_version.services,
            advertised_protocol_version: peer_version.protocol_version,
            protocol_version: applied_protocol_version,
            disable_relay_tx: peer_version.disable_relay_tx,
            subnetwork_id: peer_version.subnetwork_id,
            time_offset,
        });
        router.set_properties(peer_properties);

        // Send and receive the ready signal
        handshake.exchange_ready_messages().await?;

        info!("Registering p2p flows for peer {} for protocol version {}", router, applied_protocol_version);

        // Launch all flows. Note we launch only after the ready signal was exchanged
        for flow in flows {
            flow.launch(self.clone());
        }

        if router.is_outbound() || peer_version.address.is_some() {
            let mut address_manager = self.address_manager.lock();

            if router.is_outbound() {
                address_manager.add_address(router.net_address().into());
            }

            if let Some(peer_ip_address) = peer_version.address {
                address_manager.add_address(peer_ip_address);
            }
        }

        // Note: we deliberately do not hold the handshake in memory so at this point receivers for handshake subscriptions
        // are dropped, hence effectively unsubscribing from these messages. This means that if the peer re-sends them
        // it is considered a protocol error and the connection will disconnect

        Ok(())
    }
}

#[cfg(test)]
mod n1_tests {
    use super::*;

    /// N1 (spec 08 R1.4.4): an invalid shielded proof bans by default, except from a peer that
    /// advertises newer rules (newer protocol version or newer release of this software); and the
    /// class stays out of `--enablebanning`'s narrow gate.
    #[test]
    fn invalid_shielded_proof_ban_class_and_version_exemption() {
        let name = kaspa_core::kaspad_env::name();
        let ours = kaspa_core::kaspad_env::version();
        let same = format!("/{name}:{ours}/");
        assert!(!shielded_proof_ban_exempt(PROTOCOL_VERSION, &same), "same version, same release: banned");
        assert!(!shielded_proof_ban_exempt(PROTOCOL_VERSION - 1, &same), "older protocol: banned");
        assert!(shielded_proof_ban_exempt(PROTOCOL_VERSION + 1, &same), "newer protocol: exempt");
        assert!(shielded_proof_ban_exempt(PROTOCOL_VERSION, &format!("/{name}:999.0.0/")), "newer release: exempt");
        assert!(!shielded_proof_ban_exempt(PROTOCOL_VERSION, "/someone-else:999.0.0/"), "another software's version is not ours");
        assert!(!ProtocolError::InvalidShieldedProof("x".into()).is_auto_ban_eligible());
        assert!(Config::new(kaspa_consensus_core::config::params::MAINNET_PARAMS).ban_invalid_shielded_proofs, "on by default");
    }
}
