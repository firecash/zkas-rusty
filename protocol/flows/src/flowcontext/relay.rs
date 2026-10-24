//! Transaction-origin privacy on the relay path (spec 06 §3.2–§3.3): per-connection node ids,
//! Dandelion++ (stem, fluff, embargo, re-stem), the per-peer inv trickle, the self-template
//! embargo, and `ShieldedConflict` notices for stemmed double spends (16 F12).

use super::dandelion::{Candidate, Dandelion, DandelionParams, Route, embargo_delay};
use super::trickle::{TRICKLE_TICK, Trickle};
use crate::flow_context::{FlowContext, FlowContextInner};
use crate::flowcontext::transactions::MAX_INV_PER_TX_INV_MSG;
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use kaspa_consensusmanager::ConsensusProxy;
use kaspa_core::{debug, info, time::unix_now, warn};
use kaspa_mining::errors::MiningManagerError;
use kaspa_mining::mempool::errors::RuleError;
use kaspa_mining::mempool::tx::{Orphan, Priority, RbfPolicy};
use kaspa_mining::stempool::StemAdmission;
use kaspa_consensus_core::errors::tx::TxRuleError;
use kaspa_p2p_lib::convert::model::version::services;
use kaspa_p2p_lib::{
    PeerKey, Router,
    common::ProtocolError,
    make_message,
    pb::{InvTransactionsMessage, ShieldedConflictMessage, StemTransactionMessage, kaspad_message::Payload},
};
use kaspa_utils::networking::PeerId;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Own per-connection ids are remembered this long for loopback detection (spec 06 H-2).
pub const OWN_ID_LIFETIME: Duration = Duration::from_secs(600);
pub const OWN_ID_CAP: usize = 4096;
/// `ShieldedConflict` notices accepted per peer per minute (spec 12 S4.1).
pub const CONFLICT_NOTICES_PER_MINUTE: u32 = 10;
/// Nullifiers remembered so each conflict is forwarded once.
pub const CONFLICT_SEEN_CAP: usize = 10_000;
/// Inbound cap per publicly routable IP and per /24 (spec 06 H-2).
pub const MAX_INBOUND_PER_IP: usize = 2;
pub const MAX_INBOUND_PER_PREFIX: usize = 4;

#[derive(Default)]
pub struct OwnConnectionIds {
    order: VecDeque<(PeerId, Instant)>,
    set: HashSet<PeerId>,
}

impl OwnConnectionIds {
    fn expire(&mut self, now: Instant) {
        while let Some((id, at)) = self.order.front().copied() {
            if now.saturating_duration_since(at) < OWN_ID_LIFETIME && self.order.len() <= OWN_ID_CAP {
                break;
            }
            self.order.pop_front();
            self.set.remove(&id);
        }
    }

    pub fn issue(&mut self, now: Instant) -> PeerId {
        let id: PeerId = Uuid::new_v4().into();
        self.order.push_back((id, now));
        self.set.insert(id);
        self.expire(now);
        id
    }

    pub fn contains(&mut self, id: &PeerId, now: Instant) -> bool {
        self.expire(now);
        self.set.contains(id)
    }
}

#[derive(Default)]
struct SeenNullifiers {
    order: VecDeque<[u8; 32]>,
    set: HashSet<[u8; 32]>,
}

impl SeenNullifiers {
    fn insert(&mut self, nf: [u8; 32]) -> bool {
        if !self.set.insert(nf) {
            return false;
        }
        self.order.push_back(nf);
        if self.order.len() > CONFLICT_SEEN_CAP
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }

    fn contains(&self, nf: &[u8; 32]) -> bool {
        self.set.contains(nf)
    }
}

/// A conflict this node verified (for logging and a future `SubscribeShieldedConflicts`).
#[derive(Clone, Debug)]
pub struct ConflictNotice {
    pub nullifier: [u8; 32],
    pub resident: TransactionId,
    pub conflicting: TransactionId,
}

pub struct RelayPrivacy {
    pub(crate) dandelion_enabled: bool,
    pub(crate) dandelion: Mutex<Dandelion>,
    pub(crate) trickle: Mutex<Trickle>,
    pub(crate) own_ids: Mutex<OwnConnectionIds>,
    conflicts_seen: Mutex<SeenNullifiers>,
    conflict_budget: Mutex<HashMap<PeerKey, (Instant, u32)>>,
    pub conflict_notices: tokio::sync::broadcast::Sender<ConflictNotice>,
    auth_keypair: Option<secp256k1::Keypair>,
    pins: HashMap<std::net::SocketAddr, [u8; 32]>,
}

impl RelayPrivacy {
    pub fn new(config: &kaspa_consensus_core::config::P2pPrivacyConfig, params: DandelionParams) -> Self {
        use std::net::ToSocketAddrs;
        let auth_keypair = config.auth_secret_key.and_then(|k| secp256k1::Keypair::from_seckey_slice(&**secp256k1::SECP256K1, &k).ok());
        let mut pins = HashMap::new();
        for (target, key) in &config.peer_pins {
            match target.to_socket_addrs() {
                Ok(addrs) => {
                    for a in addrs {
                        pins.insert(a, *key);
                    }
                }
                Err(err) => warn!("P2P, cannot resolve pinned peer {target}: {err}"),
            }
        }
        Self {
            auth_keypair,
            pins,
            dandelion_enabled: config.dandelion,
            dandelion: Mutex::new(Dandelion::new(params)),
            trickle: Default::default(),
            own_ids: Default::default(),
            conflicts_seen: Default::default(),
            conflict_budget: Default::default(),
            conflict_notices: tokio::sync::broadcast::channel(256).0,
        }
    }
}

/// Wall-clock microseconds for the spy-node log (compile-time feature `spy-log`, devnet only).
#[cfg(feature = "spy-log")]
pub fn spy_now_us() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros()
}

fn is_misbehaviour(err: &MiningManagerError) -> bool {
    matches!(
        err,
        MiningManagerError::MempoolError(RuleError::RejectInvalid(_))
            | MiningManagerError::MempoolError(RuleError::RejectTxRule(TxRuleError::InvalidShieldedProof(_)))
    )
}

impl FlowContext {
    /// A fresh `Version.id` for one connection (spec 06 H-2).
    pub fn issue_connection_id(&self) -> PeerId {
        self.relay_privacy.own_ids.lock().issue(Instant::now())
    }

    /// Whether `id` is one this node issued recently: the connection loops back to us.
    pub fn is_own_connection_id(&self, id: PeerId) -> bool {
        self.relay_privacy.own_ids.lock().contains(&id, Instant::now())
    }

    /// The pinned BIP 340 key of the peer at `addr`, if the operator pinned one (T-8).
    pub fn pinned_key_for(&self, addr: std::net::SocketAddr) -> Option<[u8; 32]> {
        self.relay_privacy.pins.get(&addr).copied()
    }

    /// This node's long-term authentication key (`--p2p-auth-key`), if any.
    pub fn auth_keypair(&self) -> Option<secp256k1::Keypair> {
        self.relay_privacy.auth_keypair
    }

    /// `Version.services` of this node (spec 06 H-4).
    pub fn local_services(&self) -> u64 {
        let mut s = services::SHIELDED_CONFLICT;
        if self.relay_privacy.dandelion_enabled {
            s |= services::NODE_DPP;
        }
        s
    }

    fn stem_candidates(&self) -> Vec<Candidate> {
        self.hub()
            .active_peers()
            .into_iter()
            .map(|p| {
                let props = p.properties();
                Candidate {
                    key: p.key(),
                    addr: p.net_address(),
                    outbound: p.is_outbound(),
                    dpp: props.protocol_version >= 11 && props.services & services::NODE_DPP != 0,
                    connected_for: Duration::from_millis(p.time_connected()),
                }
            })
            .collect()
    }

    async fn send_stem(&self, peer: PeerKey, tx: &Transaction) -> bool {
        let msg = make_message!(Payload::StemTransaction, StemTransactionMessage { transaction: Some(tx.into()) });
        matches!(self.hub().send(peer, msg).await, Ok(true))
    }

    /// Queues ids for the per-peer trickle (D-7). `throttle` limits a flood to 8 random peers.
    pub(crate) fn trickle_transactions(&self, ids: Vec<TransactionId>, throttle: bool) {
        if ids.is_empty() {
            return;
        }
        let targets: Option<HashSet<PeerKey>> = throttle.then(|| {
            use rand::seq::IteratorRandom;
            self.hub().active_peers().into_iter().map(|p| p.key()).choose_multiple(&mut rand::thread_rng(), 8).into_iter().collect()
        });
        self.relay_privacy.trickle.lock().enqueue(&ids, targets.as_ref());
    }

    fn template_embargo_until(submitted_at: Instant) -> u64 {
        let delay = embargo_delay(&mut rand::thread_rng());
        let submitted_ms = unix_now().saturating_sub(submitted_at.elapsed().as_millis() as u64);
        submitted_ms + delay.as_millis() as u64
    }

    /// An own transaction (RPC `submitTransaction`, walletd, a submission relay): stem it to the
    /// own stem peer, never announce it (spec 06 D-2, fallback leg of 16 F6; see 21-p2p-v11-impl.md
    /// for why the default onion-relay leg is not in the node).
    pub async fn submit_own_transaction(&self, consensus: &ConsensusProxy, transaction: Transaction, orphan: Orphan) -> Result<(), ProtocolError> {
        let id = transaction.id();
        let now = Instant::now();
        if !self.relay_privacy.dandelion_enabled {
            return self.submit_own_without_stem(consensus, transaction, orphan, now).await;
        }
        match self.mining_manager().clone().validate_stem_transaction(consensus, transaction.clone(), true, false).await {
            Ok(StemAdmission::Inserted) => {
                let route = {
                    let mut d = self.relay_privacy.dandelion.lock();
                    d.track_stem(id, true, now, embargo_delay(&mut rand::thread_rng()));
                    d.route_own(now, &self.stem_candidates(), &mut rand::thread_rng())
                };
                match route {
                    Route::Stem(peer) if self.send_stem(peer, &transaction).await => {
                        debug!("Dandelion++: own tx {id} stemmed to {peer}");
                    }
                    _ => {
                        debug!("Dandelion++: no stem peer for own tx {id}, fluffing");
                        self.fluff_stem(consensus, id).await;
                    }
                }
                Ok(())
            }
            Ok(StemAdmission::Known { .. }) => Err(MiningManagerError::MempoolError(RuleError::RejectDuplicate(id)).into()),
            Ok(StemAdmission::MempoolConflict { nullifier, resident, .. }) => {
                Err(MiningManagerError::MempoolError(RuleError::RejectDoubleSpendNullifierInMempool(hex::encode(nullifier), resident)).into())
            }
            Ok(StemAdmission::StemConflict) => Err(ProtocolError::Other("the transaction spends a note another stem-phase transaction spends")),
            Ok(StemAdmission::Full(_)) => self.submit_own_without_stem(consensus, transaction, orphan, now).await,
            Err(MiningManagerError::MempoolError(RuleError::RejectMissingOutpoint)) if orphan == Orphan::Allowed => {
                self.submit_own_without_stem(consensus, transaction, orphan, now).await
            }
            Err(err) => Err(err.into()),
        }
    }

    /// `--no-dandelion`, no stem capacity, or an orphan: straight to the mempool with the
    /// self-template embargo (D-10), announced through the trickle.
    async fn submit_own_without_stem(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
        orphan: Orphan,
        submitted_at: Instant,
    ) -> Result<(), ProtocolError> {
        let id = transaction.id();
        self.mining_manager().set_template_embargo(id, Self::template_embargo_until(submitted_at));
        let insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, orphan, RbfPolicy::Forbidden)
            .await?;
        self.trickle_transactions(insertion.accepted.iter().map(|x| x.id()).collect(), false);
        Ok(())
    }

    /// Moves a stem transaction into the mempool and announces it (D-6).
    pub async fn fluff_stem(&self, consensus: &ConsensusProxy, id: TransactionId) {
        let meta = self.relay_privacy.dandelion.lock().stems.remove(&id);
        let own = meta.is_some_and(|m| m.own);
        let embargo = meta.filter(|m| m.own).map(|m| Self::template_embargo_until(m.submitted_at));
        match self.mining_manager().clone().fluff_stem_transaction(consensus, id, embargo).await {
            Ok(accepted) => {
                self.trickle_transactions(accepted.iter().map(|x| x.id()).collect(), false);
                if own {
                    self.relay_privacy.dandelion.lock().track_own_fluffed(id, Instant::now());
                }
            }
            Err(err) => debug!("Dandelion++: stem tx {id} failed revalidation at fluff and is dropped: {err}"),
        }
    }

    /// A relayed `StemTransaction` from `router` (D-3, D-9, D-12).
    pub async fn handle_stem_transaction(&self, router: &Router, transaction: Transaction) -> Result<(), ProtocolError> {
        let consensus = self.consensus().unguarded_session();
        if !self.is_nearly_synced(&consensus).await {
            return Ok(());
        }
        let from = router.key();
        let id = transaction.id();
        #[cfg(feature = "spy-log")]
        info!(target: "txsrc", "TXSRC stem {} {} {} {}", id, router.net_address(), router.identity(), spy_now_us());
        self.relay_privacy.trickle.lock().note_known(&from, &[id]);
        let admitted = self.relay_privacy.dandelion_enabled && self.relay_privacy.dandelion.lock().admit_stem_from(from, Instant::now());
        if !admitted {
            // Over the rate limit (or D++ off here): fluff rather than drop, so the limit state
            // is not observable (D-12).
            return self.fluff_relayed(&consensus, from, transaction).await;
        }
        match self.mining_manager().clone().validate_stem_transaction(&consensus, transaction.clone(), false, false).await {
            Err(err) if is_misbehaviour(&err) => {
                Err(ProtocolError::MisbehavingPeer(format!("stem transaction {id} failed validation: {err}")))
            }
            Err(MiningManagerError::MempoolError(RuleError::RejectMissingOutpoint)) => self.fluff_relayed(&consensus, from, transaction).await,
            Err(err) => {
                debug!("Dandelion++: stem tx {id} from {router} rejected: {err}");
                Ok(())
            }
            Ok(StemAdmission::Known { in_stempool: true }) => {
                // A loop: the transaction came back along the stem. Fluff it (D-3).
                self.fluff_stem(&consensus, id).await;
                Ok(())
            }
            Ok(StemAdmission::Known { in_stempool: false }) | Ok(StemAdmission::StemConflict) => Ok(()),
            Ok(StemAdmission::MempoolConflict { nullifier, resident, transaction }) => {
                self.emit_conflict(nullifier, resident, transaction, Some(from)).await;
                Ok(())
            }
            Ok(StemAdmission::Full(_)) => self.fluff_relayed(&consensus, from, transaction).await,
            Ok(StemAdmission::Inserted) => {
                let now = Instant::now();
                let route = {
                    let mut d = self.relay_privacy.dandelion.lock();
                    d.track_stem(id, false, now, embargo_delay(&mut rand::thread_rng()));
                    d.route_relayed(from, now, &self.stem_candidates(), &mut rand::thread_rng())
                };
                match route {
                    Route::Stem(peer) if self.send_stem(peer, &transaction).await => {}
                    _ => self.fluff_stem(&consensus, id).await,
                }
                Ok(())
            }
        }
    }

    async fn fluff_relayed(&self, consensus: &ConsensusProxy, from: PeerKey, transaction: Transaction) -> Result<(), ProtocolError> {
        let id = transaction.id();
        match self.mining_manager().clone().insert_fluffed(consensus, transaction, Priority::Low, None).await {
            Ok(accepted) => {
                self.trickle_transactions(accepted.iter().map(|x| x.id()).collect(), false);
                Ok(())
            }
            Err(err) if is_misbehaviour(&err) => {
                Err(ProtocolError::MisbehavingPeer(format!("stem transaction {id} from {from} failed validation: {err}")))
            }
            Err(_) => Ok(()),
        }
    }

    /// `from` announced `ids` by inv. They are public now: never announce them back to `from`,
    /// end the self-template embargo of own ones (D-10), fluff stem copies (D-4). Returns the
    /// ids that still need a `RequestTransactions`.
    pub async fn on_transactions_announced(&self, consensus: &ConsensusProxy, from: PeerKey, ids: Vec<TransactionId>) -> Vec<TransactionId> {
        self.relay_privacy.trickle.lock().note_known(&from, &ids);
        {
            let mut d = self.relay_privacy.dandelion.lock();
            for id in &ids {
                d.note_announced(id);
            }
        }
        self.mining_manager().clone().release_template_embargoes_for(ids.clone()).await;
        let mut rest = Vec::with_capacity(ids.len());
        for id in ids {
            if self.mining_manager().stem_contains(&id) {
                self.fluff_stem(consensus, id).await;
            } else {
                rest.push(id);
            }
        }
        rest
    }

    /// Sends a verified `ShieldedConflict` notice to every v11 peer that wants them, once per
    /// nullifier (spec 06 D-9, 12 S4.1).
    pub(crate) async fn emit_conflict(&self, nullifier: [u8; 32], resident: TransactionId, tx: Arc<Transaction>, except: Option<PeerKey>) {
        if !self.relay_privacy.conflicts_seen.lock().insert(nullifier) {
            return;
        }
        info!(
            "Shielded conflict: tx {} spends nullifier {} that mempool tx {} already spends; notifying peers",
            tx.id(),
            hex::encode(nullifier),
            resident
        );
        let _ = self.relay_privacy.conflict_notices.send(ConflictNotice { nullifier, resident, conflicting: tx.id() });
        let msg = make_message!(
            Payload::ShieldedConflict,
            ShieldedConflictMessage { nullifier: nullifier.to_vec(), txid_a: Some(resident.into()), tx_b: Some((&*tx).into()) }
        );
        for p in self.hub().active_peers() {
            let props = p.properties();
            if props.protocol_version >= 11 && props.services & services::SHIELDED_CONFLICT != 0 && Some(p.key()) != except {
                let _ = self.hub().send(p.key(), msg.clone()).await;
            }
        }
    }

    /// A received `ShieldedConflict`: verify `tx_b` and that it conflicts with what we hold, then
    /// forward once (spec 12 S4.1 receiver duty).
    pub async fn handle_conflict_notice(&self, router: &Router, msg: ShieldedConflictMessage) -> Result<(), ProtocolError> {
        let from = router.key();
        {
            let mut budget = self.relay_privacy.conflict_budget.lock();
            let now = Instant::now();
            let e = budget.entry(from).or_insert((now, 0));
            if now.saturating_duration_since(e.0) >= Duration::from_secs(60) {
                *e = (now, 0);
            }
            if e.1 >= CONFLICT_NOTICES_PER_MINUTE {
                return Ok(());
            }
            e.1 += 1;
        }
        let nullifier: [u8; 32] = msg.nullifier.as_slice().try_into().map_err(|_| ProtocolError::Other("conflict notice nullifier is not 32 bytes"))?;
        if self.relay_privacy.conflicts_seen.lock().contains(&nullifier) {
            return Ok(());
        }
        let tx_b: Transaction = msg.tx_b.ok_or(ProtocolError::Other("conflict notice without a transaction"))?.try_into()?;
        let consensus = self.consensus().unguarded_session();
        match self.mining_manager().clone().validate_stem_transaction(&consensus, tx_b, false, true).await {
            Ok(StemAdmission::MempoolConflict { nullifier: nf, resident, transaction }) if nf == nullifier => {
                self.emit_conflict(nf, resident, transaction, Some(from)).await;
                Ok(())
            }
            Err(err) if is_misbehaviour(&err) => Err(ProtocolError::MisbehavingPeer(format!("conflict notice carried an invalid transaction: {err}"))),
            _ => Ok(()),
        }
    }

    /// The relay timer: inv trickle (D-7), embargo expiry (D-4), re-stems (D-11).
    pub(crate) fn spawn_relay_timer(&self) {
        let weak: Weak<FlowContextInner> = Arc::downgrade(&self.inner_arc());
        tokio::spawn(async move {
            let mut tick: u64 = 0;
            let mut interval = tokio::time::interval(TRICKLE_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                let ctx = FlowContext::from_inner(inner);
                tick += 1;
                let now = Instant::now();
                if tick % 20 == 1 {
                    let peers: Vec<_> = ctx.hub().active_peers().into_iter().map(|p| (p.key(), p.is_outbound(), p.net_address().ip())).collect();
                    ctx.relay_privacy.trickle.lock().sync_peers(&peers, now, &mut rand::thread_rng());
                }
                let due = ctx.relay_privacy.trickle.lock().due(now, &mut rand::thread_rng());
                for (peer, ids) in due {
                    for chunk in ids.chunks(MAX_INV_PER_TX_INV_MSG) {
                        let msg = make_message!(Payload::InvTransactions, InvTransactionsMessage { ids: chunk.iter().map(|x| (*x).into()).collect() });
                        let _ = ctx.hub().send(peer, msg).await;
                    }
                }
                if !ctx.relay_privacy.dandelion_enabled {
                    continue;
                }
                if tick % 4 == 0 {
                    let due = ctx.relay_privacy.dandelion.lock().due_embargoes(now);
                    if !due.is_empty() {
                        let consensus = ctx.consensus().unguarded_session();
                        for id in due {
                            if ctx.mining_manager().stem_contains(&id) {
                                debug!("Dandelion++: embargo expired for {id}, fluffing");
                                ctx.fluff_stem(&consensus, id).await;
                            } else {
                                ctx.relay_privacy.dandelion.lock().stems.remove(&id);
                            }
                        }
                    }
                }
                if tick % 40 == 0 {
                    ctx.run_restems(now).await;
                }
            }
        });
    }

    async fn run_restems(&self, now: Instant) {
        use kaspa_mining::model::tx_query::TransactionQuery;
        // Own transactions that left the mempool (mined, or dropped by revalidation) are done.
        let tracked: Vec<TransactionId> = self.relay_privacy.dandelion.lock().own_fluffed.keys().copied().collect();
        for id in tracked {
            if !self.mining_manager().clone().has_transaction(id, TransactionQuery::TransactionsOnly).await {
                self.relay_privacy.dandelion.lock().own_fluffed.remove(&id);
            }
        }
        let (restem, give_up) = self.relay_privacy.dandelion.lock().due_restems(now);
        let peer = self.relay_privacy.dandelion.lock().own_stem_peer();
        for id in restem {
            let tx = self.mining_manager().clone().get_transaction(id, TransactionQuery::TransactionsOnly).await;
            if let (Some(mtx), Some(peer)) = (tx, peer) {
                debug!("Dandelion++: own tx {id} not announced back after 30 s, re-stemming to {peer}");
                self.send_stem(peer, &mtx.tx).await;
            }
        }
        if !give_up.is_empty() {
            warn!("Dandelion++: {} own transaction(s) were never announced back after 3 re-stems; announcing to all peers", give_up.len());
            self.trickle_transactions(give_up, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_ids_detect_loopback_and_expire() {
        let mut ids = OwnConnectionIds::default();
        let t0 = Instant::now();
        let a = ids.issue(t0);
        let b = ids.issue(t0);
        assert_ne!(a, b, "a fresh id per connection");
        assert!(ids.contains(&a, t0 + Duration::from_secs(10)));
        assert!(!ids.contains(&a, t0 + OWN_ID_LIFETIME + Duration::from_secs(1)));
        let other: PeerId = Uuid::new_v4().into();
        assert!(!ids.contains(&other, t0));
    }

    #[test]
    fn own_ids_are_capped() {
        let mut ids = OwnConnectionIds::default();
        let t0 = Instant::now();
        let first = ids.issue(t0);
        for _ in 0..OWN_ID_CAP {
            ids.issue(t0);
        }
        assert!(!ids.contains(&first, t0));
        assert!(ids.set.len() <= OWN_ID_CAP);
    }

    #[test]
    fn each_conflict_is_forwarded_once() {
        let mut s = SeenNullifiers::default();
        assert!(s.insert([1; 32]));
        assert!(!s.insert([1; 32]));
        assert!(s.insert([2; 32]));
    }
}
