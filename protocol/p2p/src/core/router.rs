use crate::core::hub::HubEvent;
use crate::pb::RejectMessage;
use crate::pb::{KaspadMessage, kaspad_message::Payload as KaspadMessagePayload};
use crate::{KaspadMessagePayloadType, common::{DEFAULT_TIMEOUT, ProtocolError}};
use crate::{Peer, make_message};
use kaspa_core::{debug, error, info, trace, warn};
use kaspa_utils::networking::PeerId;
use parking_lot::{Mutex, RwLock};
use seqlock::SeqLock;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{collections::HashMap, sync::Arc};
use tokio::select;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel as mpsc_channel};
use tokio::sync::oneshot::{Sender as OneshotSender, channel as oneshot_channel};
use tonic::Streaming;

use super::peer::{PeerKey, PeerProperties};

pub struct IncomingRoute {
    rx: MpscReceiver<KaspadMessage>,
    id: u32,
}

// BLANK_ROUTE_ID is the value that is used in the p2p when no request or response IDs
// are needed. To support backward compatibility, this is set to the default gRPC value
// for uint32.
pub const BLANK_ROUTE_ID: u32 = 0;
static ROUTE_ID: AtomicU32 = AtomicU32::new(BLANK_ROUTE_ID + 1);

impl IncomingRoute {
    pub fn new(rx: MpscReceiver<KaspadMessage>) -> Self {
        let id = ROUTE_ID.fetch_add(1, Ordering::SeqCst);
        Self { rx, id }
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Deref for IncomingRoute {
    type Target = MpscReceiver<KaspadMessage>;

    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}

impl DerefMut for IncomingRoute {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rx
    }
}

#[derive(Clone)]
pub struct SharedIncomingRoute(Arc<tokio::sync::Mutex<IncomingRoute>>);

impl SharedIncomingRoute {
    pub fn new(incoming_route: IncomingRoute) -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(incoming_route)))
    }

    pub async fn recv(&mut self) -> Option<KaspadMessage> {
        self.0.lock().await.recv().await
    }
}

/// The policy for handling the case where route capacity is reached for a specific route type
pub enum IncomingRouteOverflowPolicy {
    /// Drop the incoming message
    Drop,

    /// Disconnect from this peer
    Disconnect,
}

impl From<KaspadMessagePayloadType> for IncomingRouteOverflowPolicy {
    fn from(msg_type: KaspadMessagePayloadType) -> Self {
        match msg_type {
            // Inv messages are unique in the sense that no harm is done if some of them are dropped
            KaspadMessagePayloadType::InvTransactions | KaspadMessagePayloadType::InvRelayBlock => IncomingRouteOverflowPolicy::Drop,
            _ => IncomingRouteOverflowPolicy::Disconnect,
        }
    }
}

/// How many encoded bytes a peer may leave queued and unread before the flows that SERVE its
/// requests stop producing more for it (see [`Router::enqueue_paced`]).
///
/// The outgoing queue was bounded only in MESSAGES (`(1 << 17) + 256`), and every serving flow
/// produced its response in full regardless of whether the peer read it. A peer that sends
/// requests and never reads the replies could therefore park 131,328 full messages per connection
/// in this node's memory -- one ~3 KB `RequestIbdBlocks` names 99 blocks, one `RequestTransactions`
/// may name 131,072 ids that are all the same large mempool transaction, and a blind stream of
/// `RequestNextHeaders` or `RequestPruningPointProof` needs no reading at all.
///
/// Pacing only delays: a serving flow waits for the backlog to drain under this mark, so an honest
/// peer, which keeps reading, sees at most added latency. 32 MiB is above the bandwidth-delay
/// product of any realistic link (1 Gbit/s x 250 ms = ~30 MiB), so a reading peer is not slowed.
/// With it, what one connection can make this node hold is this mark plus one message per serving
/// flow, instead of 131,328 messages.
pub const OUTGOING_PACING_BYTES: usize = 32 * 1024 * 1024;

/// How long a paced flow tolerates a backlog that is not shrinking at all. Progress -- any byte
/// taken by the transport -- resets it, so a slow honest link is never cut by it; only a peer that
/// stops reading entirely is.
const OUTGOING_PACING_STALL: Duration = DEFAULT_TIMEOUT;

/// How often a paced flow re-checks the backlog while it waits. Wake-ups also come from the
/// transport when the backlog crosses [`OUTGOING_PACING_BYTES`]; the poll exists only to observe
/// partial progress for the stall clock.
const OUTGOING_PACING_POLL: Duration = Duration::from_secs(1);

/// The bytes queued for one peer and not yet taken by the transport.
#[derive(Debug, Default)]
pub(crate) struct OutgoingBacklog {
    bytes: AtomicUsize,
    drained: Notify,
}

impl OutgoingBacklog {
    fn charge(&self, len: usize) {
        self.bytes.fetch_add(len, Ordering::SeqCst);
    }

    /// Called by the transport side for every message it takes off the queue, with the length
    /// `enqueue` charged for it.
    fn release(&self, len: usize) {
        let before = self.bytes.fetch_sub(len, Ordering::SeqCst);
        if before > OUTGOING_PACING_BYTES && before - len <= OUTGOING_PACING_BYTES {
            self.drained.notify_waiters();
        }
    }

    fn bytes(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }

    /// Waits until at most [`OUTGOING_PACING_BYTES`] are queued. Fails if the backlog does not
    /// shrink at all for `stall`, or once `closed()` reports the connection gone.
    async fn wait_until_drained(&self, stall: Duration, closed: impl Fn() -> bool) -> Result<(), PaceError> {
        let mut low_water = self.bytes();
        let mut stalled_since = Instant::now();
        loop {
            // Register for the wake-up BEFORE checking, so a drain between the check and the wait
            // is not missed (`notify_waiters` reaches every `Notified` that already exists).
            let drained = self.drained.notified();
            let queued = self.bytes();
            if queued <= OUTGOING_PACING_BYTES {
                return Ok(());
            }
            if closed() {
                return Err(PaceError::Closed);
            }
            if queued < low_water {
                low_water = queued;
                stalled_since = Instant::now();
            } else if stalled_since.elapsed() >= stall {
                return Err(PaceError::Stalled(queued));
            }
            let _ = tokio::time::timeout(OUTGOING_PACING_POLL, drained).await;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PaceError {
    Closed,
    Stalled(usize),
}

/// The sending half of a peer's outgoing pipe. Each message travels with the encoded length it was
/// charged at, so the transport side releases exactly that.
#[derive(Debug)]
pub(crate) struct OutgoingRoute {
    sender: MpscSender<(KaspadMessage, usize)>,
    backlog: Arc<OutgoingBacklog>,
}

impl OutgoingRoute {
    /// Charges `msg`'s encoded length and queues it, or releases the charge again if the queue is
    /// full or closed, so a refused message leaves nothing behind in the backlog.
    fn try_send(&self, msg: KaspadMessage) -> Result<(), TrySendError<(KaspadMessage, usize)>> {
        use prost::Message as _;
        let len = msg.encoded_len();
        // Charge before sending, so the transport's release can never run ahead of the charge.
        self.backlog.charge(len);
        self.sender.try_send((msg, len)).inspect_err(|_| self.backlog.release(len))
    }
}

/// Builds a peer's outgoing pipe: the route the router enqueues into, and the stream the transport
/// sends from. Taking a message off the stream releases its bytes from the backlog.
pub(crate) fn outgoing_pipe(capacity: usize) -> (OutgoingRoute, impl tokio_stream::Stream<Item = KaspadMessage> + Send + 'static) {
    use tokio_stream::StreamExt as _;
    let (sender, receiver) = mpsc_channel(capacity);
    let backlog = Arc::new(OutgoingBacklog::default());
    let release = backlog.clone();
    let stream = tokio_stream::wrappers::ReceiverStream::new(receiver).map(move |(msg, len): (KaspadMessage, usize)| {
        release.release(len);
        msg
    });
    (OutgoingRoute { sender, backlog }, stream)
}

#[derive(Debug, Default)]
struct RouterMutableState {
    /// Used on router init to signal the router receive loop to start listening
    start_signal: Option<OneshotSender<()>>,

    /// Used on router close to signal the router receive loop to exit
    shutdown_signal: Option<OneshotSender<()>>,

    /// Properties of the peer
    properties: Arc<PeerProperties>,

    /// Duration of the last ping to this peer
    last_ping_duration: u64,
}

impl RouterMutableState {
    fn new(start_signal: Option<OneshotSender<()>>, shutdown_signal: Option<OneshotSender<()>>) -> Self {
        Self { start_signal, shutdown_signal, ..Default::default() }
    }
}

/// A router object for managing the communication to a network peer. It is named a router because it's responsible
/// for internally routing messages to P2P flows based on registration and message types
#[derive(Debug)]
pub struct Router {
    /// Internal identity of this peer
    identity: SeqLock<PeerId>,

    /// The socket address of this peer
    net_address: SocketAddr,

    /// Indicates whether this connection is an outbound connection
    is_outbound: bool,

    /// Time of creation of this object and the connection it holds
    connection_started: Instant,

    /// Routing map for mapping messages to subscribed flows
    routing_map_by_type: RwLock<HashMap<KaspadMessagePayloadType, MpscSender<KaspadMessage>>>,

    routing_map_by_id: RwLock<HashMap<u32, MpscSender<KaspadMessage>>>,

    /// The outgoing route for sending messages to this peer
    outgoing_route: OutgoingRoute,

    /// A channel sender for internal event management. Used to send information from each router to a central hub object
    hub_sender: MpscSender<HubEvent>,

    /// Used for managing router mutable state
    mutable_state: Mutex<RouterMutableState>,
}

impl Display for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.net_address)
    }
}

impl From<&Router> for PeerKey {
    fn from(value: &Router) -> Self {
        Self::new(value.identity.read(), value.net_address.ip().into())
    }
}

impl From<&Router> for Peer {
    fn from(router: &Router) -> Self {
        Self::new(
            router.identity(),
            router.net_address,
            router.is_outbound,
            router.connection_started,
            router.properties(),
            router.last_ping_duration(),
        )
    }
}

fn message_summary(msg: &KaspadMessage) -> impl Debug {
    // TODO (low priority): display a concise summary of the message. Printing full messages
    // overflows the logs and is hardly useful, hence we currently only return the type
    msg.payload.as_ref().map(std::convert::Into::<KaspadMessagePayloadType>::into)
}

impl Router {
    pub(crate) async fn new(
        net_address: SocketAddr,
        is_outbound: bool,
        hub_sender: MpscSender<HubEvent>,
        mut incoming_stream: Streaming<KaspadMessage>,
        outgoing_route: OutgoingRoute,
    ) -> Arc<Self> {
        let (start_sender, start_receiver) = oneshot_channel();
        let (shutdown_sender, mut shutdown_receiver) = oneshot_channel();

        let router = Arc::new(Router {
            identity: Default::default(),
            net_address,
            is_outbound,
            connection_started: Instant::now(),
            routing_map_by_type: RwLock::new(HashMap::new()),
            routing_map_by_id: RwLock::new(HashMap::new()),
            outgoing_route,
            hub_sender,
            mutable_state: Mutex::new(RouterMutableState::new(Some(start_sender), Some(shutdown_sender))),
        });

        let router_clone = router.clone();
        // Start the router receive loop
        tokio::spawn(async move {
            // Wait for a start signal before entering the receive loop
            let _ = start_receiver.await;
            loop {
                select! {
                    biased; // We use biased polling so that the shutdown signal is always checked first

                    _ = &mut shutdown_receiver => {
                        debug!("P2P, Router receive loop - shutdown signal received, exiting router receive loop, router-id: {}", router.identity());
                        break;
                    }

                    res = incoming_stream.message() => match res {
                        Ok(Some(msg)) => {
                            trace!("P2P msg: {:?}, router-id: {}, peer: {}", message_summary(&msg), router.identity(), router);
                            match router.route_to_flow(msg) {
                                Ok(()) => {},
                                Err(e) => {
                                    match e {
                                        ProtocolError::IgnorableReject(reason) => debug!("P2P, got reject message: {} from peer: {}", reason, router),
                                        ProtocolError::Rejected(reason) => warn!("P2P, got reject message: {} from peer: {}", reason, router),
                                        e => warn!("P2P, route error: {} for peer: {}", e, router),
                                    }
                                    break;
                                },
                            }
                        }
                        Ok(None) => {
                            info!("P2P, incoming stream ended from peer {}", router);
                            break;
                        }
                        Err(status) => {
                            if let Some(err) = match_for_io_error(&status) {
                                info!("P2P, network error: {} from peer {}", err, router);
                            } else {
                                info!("P2P, network error: {} from peer {}", status, router);
                            }
                            break;
                        }
                    }
                }
            }
            router.close().await;
            debug!("P2P, Router receive loop - exited, router-id: {}, router refs: {}", router.identity(), Arc::strong_count(&router));
        });

        router_clone
    }

    /// Internal identity of this peer
    pub fn identity(&self) -> PeerId {
        self.identity.read()
    }

    pub fn set_identity(&self, identity: PeerId) {
        *self.identity.lock_write() = identity;
    }

    /// The socket address of this peer
    pub fn net_address(&self) -> SocketAddr {
        self.net_address
    }

    pub fn key(&self) -> PeerKey {
        self.into()
    }

    /// Indicates whether this connection is an outbound connection
    pub fn is_outbound(&self) -> bool {
        self.is_outbound
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.mutable_state.lock().shutdown_signal.is_none()
    }

    pub fn connection_started(&self) -> Instant {
        self.connection_started
    }

    pub fn time_connected(&self) -> u64 {
        Instant::now().duration_since(self.connection_started).as_millis() as u64
    }

    pub fn properties(&self) -> Arc<PeerProperties> {
        self.mutable_state.lock().properties.clone()
    }

    pub fn set_properties(&self, properties: Arc<PeerProperties>) {
        self.mutable_state.lock().properties = properties;
    }

    /// Sets the duration of the last ping
    pub fn set_last_ping_duration(&self, last_ping_duration: u64) {
        self.mutable_state.lock().last_ping_duration = last_ping_duration;
    }

    pub fn last_ping_duration(&self) -> u64 {
        self.mutable_state.lock().last_ping_duration
    }

    pub fn incoming_flow_baseline_channel_size() -> usize {
        256
    }

    /// Send a signal to start this router's receive loop
    pub fn start(&self) {
        // Acquire state mutex and send the start signal
        let op = self.mutable_state.lock().start_signal.take();
        if let Some(signal) = op {
            let _ = signal.send(());
        } else {
            debug!("P2P, Router start was called more than once, router-id: {}", self.identity())
        }
    }

    /// Subscribe to specific message types.
    ///
    /// This should be used by `ConnectionInitializer` instances to register application-specific flows
    pub fn subscribe(&self, msg_types: Vec<KaspadMessagePayloadType>) -> IncomingRoute {
        self.subscribe_with_capacity(msg_types, Self::incoming_flow_baseline_channel_size())
    }

    /// Subscribe to specific message types with a specific channel capacity.
    ///
    /// This should be used by `ConnectionInitializer` instances to register application-specific flows.
    pub fn subscribe_with_capacity(&self, msg_types: Vec<KaspadMessagePayloadType>, capacity: usize) -> IncomingRoute {
        let (sender, receiver) = mpsc_channel(capacity);
        let incoming_route = IncomingRoute::new(receiver);
        let mut map_by_type = self.routing_map_by_type.write();
        for msg_type in msg_types {
            match map_by_type.insert(msg_type, sender.clone()) {
                Some(_) => {
                    // Overrides an existing route -- panic
                    error!(
                        "P2P, Router::subscribe overrides an existing message type: {:?}, router-id: {}",
                        msg_type,
                        self.identity()
                    );
                    panic!("P2P, Tried to subscribe to an existing route");
                }
                None => {
                    trace!("P2P, Router::subscribe - msg_type: {:?} route is registered, router-id:{:?}", msg_type, self.identity());
                }
            }
        }
        let mut map_by_id = self.routing_map_by_id.write();
        match map_by_id.insert(incoming_route.id, sender.clone()) {
            Some(_) => {
                // Overrides an existing route -- panic
                error!(
                    "P2P, Router::subscribe overrides an existing route id: {:?}, router-id: {}",
                    incoming_route.id,
                    self.identity()
                );
                panic!("P2P, Tried to subscribe to an existing route");
            }
            None => {
                trace!(
                    "P2P, Router::subscribe - route id: {:?} route is registered, router-id:{:?}",
                    incoming_route.id,
                    self.identity()
                );
            }
        }
        incoming_route
    }

    /// Routes a message coming from the network to the corresponding registered flow
    pub fn route_to_flow(&self, msg: KaspadMessage) -> Result<(), ProtocolError> {
        if msg.payload.is_none() {
            debug!("P2P, Route to flow got empty payload, peer: {}", self);
            return Err(ProtocolError::Other("received kaspad p2p message with empty payload"));
        }
        let msg_type: KaspadMessagePayloadType = msg.payload.as_ref().expect("payload was just verified").into();
        // Handle the special case of a reject message ending the connection
        if msg_type == KaspadMessagePayloadType::Reject {
            let Some(KaspadMessagePayload::Reject(reject)) = msg.payload else { unreachable!() };
            return Err(ProtocolError::from_reject_message(reject.reason));
        }

        let op = if msg.response_id != BLANK_ROUTE_ID {
            self.routing_map_by_id.read().get(&msg.response_id).cloned()
        } else {
            self.routing_map_by_type.read().get(&msg_type).cloned()
        };

        if let Some(sender) = op {
            match sender.try_send(msg) {
                Ok(_) => Ok(()),
                Err(TrySendError::Closed(_)) => Err(ProtocolError::ConnectionClosed),
                Err(TrySendError::Full(_)) => {
                    let overflow_policy: IncomingRouteOverflowPolicy = msg_type.into();
                    match overflow_policy {
                        IncomingRouteOverflowPolicy::Drop => Ok(()),
                        IncomingRouteOverflowPolicy::Disconnect => {
                            Err(ProtocolError::IncomingRouteCapacityReached(msg_type, self.to_string()))
                        }
                    }
                }
            }
        } else {
            Err(ProtocolError::NoRouteForMessageType(msg_type))
        }
    }

    /// Enqueues a locally-originated message to be sent to the network peer
    pub async fn enqueue(&self, msg: KaspadMessage) -> Result<(), ProtocolError> {
        assert!(msg.payload.is_some(), "Kaspad P2P message should always have a value");
        match self.outgoing_route.try_send(msg) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ProtocolError::ConnectionClosed),
            Err(TrySendError::Full(_)) => Err(ProtocolError::OutgoingRouteCapacityReached(self.to_string())),
        }
    }

    /// Enqueues a message produced in answer to this peer's REQUEST, after waiting for the peer to
    /// have read its outgoing backlog down to [`OUTGOING_PACING_BYTES`].
    ///
    /// Every flow that serves a peer's requests must send through this (or call
    /// [`Self::pace_outgoing`] before producing a response), because it is the peer that decides
    /// how much those flows produce. Unsolicited traffic -- broadcasts, invs, our own requests --
    /// keeps using [`Self::enqueue`], which never waits: a broadcast loop must not stall on one
    /// slow peer.
    ///
    /// Never call this while holding a consensus session: the wait is as long as the peer chooses
    /// to be slow, and a held session blocks staging commits for that long.
    pub async fn enqueue_paced(&self, msg: KaspadMessage) -> Result<(), ProtocolError> {
        self.pace_outgoing().await?;
        self.enqueue(msg).await
    }

    /// Waits until this peer's unread outgoing backlog is at most [`OUTGOING_PACING_BYTES`].
    ///
    /// Fails only if the backlog makes no progress at all for [`OUTGOING_PACING_STALL`], or the
    /// connection closes; a peer that reads, however slowly, is waited for.
    pub async fn pace_outgoing(&self) -> Result<(), ProtocolError> {
        match self.outgoing_route.backlog.wait_until_drained(OUTGOING_PACING_STALL, || self.is_closed()).await {
            Ok(()) => Ok(()),
            Err(PaceError::Closed) => Err(ProtocolError::ConnectionClosed),
            Err(PaceError::Stalled(queued)) => Err(ProtocolError::OtherOwned(format!(
                "peer {self} read none of its {queued} queued outgoing bytes in {}s",
                OUTGOING_PACING_STALL.as_secs()
            ))),
        }
    }

    /// Based on the type of the protocol error, tries sending a reject message before shutting down the connection
    pub async fn try_sending_reject_message(&self, err: &ProtocolError) {
        if err.can_send_outgoing_message() {
            // Send an explicit reject message for easier tracing of logical bugs causing protocol errors.
            // No need to handle errors since we are closing anyway
            let _ = self.enqueue(make_message!(KaspadMessagePayload::Reject, RejectMessage { reason: err.to_reject_message() })).await;
        }
    }

    /// Closes the router, signals exit, and cleans up all resources so that underlying connections will be aborted correctly.
    /// Returns true of this is the first call to close
    pub async fn close(self: &Arc<Router>) -> bool {
        // Acquire state mutex and send the shutdown signal
        // NOTE: Using a block to drop the lock asap
        {
            let mut state = self.mutable_state.lock();

            // Make sure start signal was fired, just in case `self.start()` was never called
            if let Some(signal) = state.start_signal.take() {
                let _ = signal.send(());
            }

            if let Some(signal) = state.shutdown_signal.take() {
                let _ = signal.send(());
                // Release any flow waiting in `pace_outgoing`: nothing will drain the queue now.
                self.outgoing_route.backlog.drained.notify_waiters();
            } else {
                // This means the router was already closed
                trace!("P2P, Router close was called more than once, router-id: {}", self.identity());
                return false;
            }
        }

        // Drop all flow senders
        self.routing_map_by_type.write().clear();
        self.routing_map_by_id.write().clear();

        // Send a close notification to the central Hub
        self.hub_sender.send(HubEvent::PeerClosing(self.clone())).await.expect("hub receiver should never drop before senders");

        true
    }
}

fn match_for_io_error(err_status: &tonic::Status) -> Option<&std::io::Error> {
    let mut err: &(dyn std::error::Error + 'static) = err_status;

    loop {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return Some(io_err);
        }

        // h2::Error do not expose std::io::Error with `source()`
        // https://github.com/hyperium/h2/pull/462
        if let Some(h2_err) = err.downcast_ref::<h2::Error>()
            && let Some(io_err) = h2_err.get_io()
        {
            return Some(io_err);
        }

        err = err.source()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;

    /// Queues one message charged at `len` bytes, the way `Router::enqueue` does.
    fn queue(route: &OutgoingRoute, len: usize) {
        route.backlog.charge(len);
        route.sender.try_send((KaspadMessage::default(), len)).unwrap();
    }

    #[tokio::test]
    async fn the_transport_releases_what_enqueue_charged() {
        let (route, stream) = outgoing_pipe(8);
        let mut stream = Box::pin(stream);
        queue(&route, 100);
        queue(&route, 50);
        assert_eq!(route.backlog.bytes(), 150);
        stream.next().await.unwrap();
        assert_eq!(route.backlog.bytes(), 50);
        stream.next().await.unwrap();
        assert_eq!(route.backlog.bytes(), 0);
    }

    fn ping(nonce: u64) -> KaspadMessage {
        make_message!(KaspadMessagePayload::Ping, crate::pb::PingMessage { nonce })
    }

    /// The path `Router::enqueue` sends through: a refused message (queue full, or the transport
    /// gone) releases its charge, so the backlog that paces serving flows never counts bytes that
    /// were not queued. A leaked charge would never be released and would stall every paced flow.
    #[tokio::test]
    async fn a_refused_enqueue_releases_its_charge() {
        use prost::Message as _;
        let (route, stream) = outgoing_pipe(1);
        let queued = ping(1);
        let len = queued.encoded_len();
        assert!(len > 0);
        route.try_send(queued).unwrap();
        assert_eq!(route.backlog.bytes(), len, "a queued message is charged");

        assert!(matches!(route.try_send(ping(2)), Err(TrySendError::Full(_))));
        assert_eq!(route.backlog.bytes(), len, "a message refused on a full queue is not charged");

        drop(stream);
        assert!(matches!(route.try_send(ping(3)), Err(TrySendError::Closed(_))));
        assert_eq!(route.backlog.bytes(), len, "a message refused on a closed queue is not charged");
    }

    #[tokio::test]
    async fn pacing_does_not_wait_under_the_mark() {
        let (route, _stream) = outgoing_pipe(8);
        queue(&route, OUTGOING_PACING_BYTES);
        assert_eq!(route.backlog.wait_until_drained(Duration::ZERO, || false).await, Ok(()));
    }

    #[tokio::test]
    async fn pacing_waits_for_a_peer_that_reads() {
        let (route, stream) = outgoing_pipe(8);
        let mut stream = Box::pin(stream);
        queue(&route, OUTGOING_PACING_BYTES + 1);
        let reader = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.next().await.unwrap();
        });
        assert_eq!(route.backlog.wait_until_drained(Duration::from_secs(30), || false).await, Ok(()));
        reader.await.unwrap();
        assert_eq!(route.backlog.bytes(), 0);
    }

    #[tokio::test]
    async fn pacing_gives_up_on_a_peer_that_reads_nothing() {
        let (route, _stream) = outgoing_pipe(8);
        queue(&route, OUTGOING_PACING_BYTES + 1);
        assert_eq!(
            route.backlog.wait_until_drained(Duration::ZERO, || false).await,
            Err(PaceError::Stalled(OUTGOING_PACING_BYTES + 1))
        );
    }

    #[tokio::test]
    async fn pacing_stops_waiting_once_the_connection_closes() {
        let (route, _stream) = outgoing_pipe(8);
        queue(&route, OUTGOING_PACING_BYTES + 1);
        assert_eq!(route.backlog.wait_until_drained(Duration::from_secs(30), || true).await, Err(PaceError::Closed));
    }
}
