//! Dandelion++ routing state (spec 06 §3.3): relay epochs, stem peers, one-to-one forwarding,
//! the origin's own stem peer, and per-transaction stem metadata (embargo timers, re-stems).
//!
//! Everything here is synchronous and clock-injected so the rules are unit-testable; the flow
//! context drives it from the stem flow, the RPC submit path and a timer task.

use kaspa_consensus_core::tx::TransactionId;
use kaspa_p2p_lib::PeerKey;
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Probability that a node is a diffuser for one relay epoch (D-1; Monero `FLUFF_PROBABILITY 20`).
pub const FLUFF_PROBABILITY: f64 = 0.20;
/// Relay epoch length 600 s + U(0, 30 s) (D-1).
pub const EPOCH_BASE: Duration = Duration::from_secs(600);
pub const EPOCH_JITTER: Duration = Duration::from_secs(30);
/// Outbound stem peers per epoch (D-1).
pub const STEM_PEERS: usize = 2;
/// A peer must have been connected this long to be a stem peer (D-1; sybil churn).
pub const STEM_PEER_MIN_AGE: Duration = Duration::from_secs(3600);
/// The origin's own stem peer is kept 24 h + U(0, 1 h) (D-2, 16 F6 fallback leg).
pub const OWN_STEM_BASE: Duration = Duration::from_secs(24 * 3600);
pub const OWN_STEM_JITTER: Duration = Duration::from_secs(3600);
/// Embargo: 2 s + Exp(mean 1 s) (D-4).
pub const EMBARGO_BASE: Duration = Duration::from_secs(2);
pub const EMBARGO_EXP_MEAN: Duration = Duration::from_secs(1);
/// An own transaction neither in a block nor announced back this long after fluff is re-stemmed
/// (D-11), at most `MAX_RESTEMS` times, then trickled to everyone.
pub const RESTEM_AFTER: Duration = Duration::from_secs(30);
pub const MAX_RESTEMS: u8 = 3;
/// Per-inbound-peer stem admission: 10 tx/s, burst 50; excess is fluffed, not dropped (D-12).
pub const STEM_RATE_PER_SEC: f64 = 10.0;
pub const STEM_BURST: f64 = 50.0;

/// Tunables; the defaults are the spec values. A devnet shortens the peer-age rule.
#[derive(Clone, Debug)]
pub struct DandelionParams {
    pub fluff_probability: f64,
    pub epoch_base: Duration,
    pub epoch_jitter: Duration,
    pub stem_peers: usize,
    pub min_peer_age: Duration,
    pub own_stem_base: Duration,
    pub own_stem_jitter: Duration,
}

impl Default for DandelionParams {
    fn default() -> Self {
        Self {
            fluff_probability: FLUFF_PROBABILITY,
            epoch_base: EPOCH_BASE,
            epoch_jitter: EPOCH_JITTER,
            stem_peers: STEM_PEERS,
            min_peer_age: STEM_PEER_MIN_AGE,
            own_stem_base: OWN_STEM_BASE,
            own_stem_jitter: OWN_STEM_JITTER,
        }
    }
}

/// A connected peer as the router sees it.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub key: PeerKey,
    pub addr: SocketAddr,
    pub outbound: bool,
    /// Negotiated v11 and advertises `NODE_DPP`.
    pub dpp: bool,
    pub connected_for: Duration,
}

/// The /16 (IPv4) or /32 (IPv6) a stem peer is in; two stem peers must differ (D-1).
pub fn prefix_group(ip: IpAddr) -> [u8; 4] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [4, o[0], o[1], 0]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [o[0], o[1], o[2], o[3]]
        }
    }
}

/// Where a transaction goes next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Stem(PeerKey),
    Fluff,
}

struct Epoch {
    ends_at: Instant,
    is_diffuser: bool,
    stem_peers: Vec<PeerKey>,
    /// One-to-one forwarding: each inbound edge maps to one stem peer for the whole epoch.
    map: HashMap<PeerKey, usize>,
}

struct OwnStem {
    peer: PeerKey,
    ends_at: Instant,
}

/// Per stem transaction (in this node's stempool).
#[derive(Clone, Copy, Debug)]
pub struct StemMeta {
    pub own: bool,
    pub embargo_at: Instant,
    /// When an own transaction was submitted; the self-template embargo counts from here.
    pub submitted_at: Instant,
}

/// An own transaction after fluff, watched for D-11.
#[derive(Clone, Copy, Debug)]
pub struct OwnFluffed {
    pub fluffed_at: Instant,
    pub restems: u8,
    pub announced_back: bool,
}

struct TokenBucket {
    tokens: f64,
    at: Instant,
}

pub struct Dandelion {
    params: DandelionParams,
    epoch: Option<Epoch>,
    epoch_id: u64,
    own_stem: Option<OwnStem>,
    pub(crate) stems: HashMap<TransactionId, StemMeta>,
    pub(crate) own_fluffed: HashMap<TransactionId, OwnFluffed>,
    buckets: HashMap<PeerKey, TokenBucket>,
}

fn exp_sample<R: Rng>(rng: &mut R, mean: Duration) -> Duration {
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    mean.mul_f64(-u.ln())
}

fn uniform<R: Rng>(rng: &mut R, max: Duration) -> Duration {
    if max.is_zero() { Duration::ZERO } else { max.mul_f64(rng.gen_range(0.0..1.0)) }
}

pub fn embargo_delay<R: Rng>(rng: &mut R) -> Duration {
    EMBARGO_BASE + exp_sample(rng, EMBARGO_EXP_MEAN)
}

impl Dandelion {
    pub fn new(params: DandelionParams) -> Self {
        Self {
            params,
            epoch: None,
            epoch_id: 0,
            own_stem: None,
            stems: HashMap::new(),
            own_fluffed: HashMap::new(),
            buckets: HashMap::new(),
        }
    }

    pub fn params(&self) -> &DandelionParams {
        &self.params
    }

    fn eligible<'a>(&self, candidates: &'a [Candidate]) -> impl Iterator<Item = &'a Candidate> {
        let min_age = self.params.min_peer_age;
        candidates.iter().filter(move |c| c.outbound && c.dpp && c.connected_for >= min_age)
    }

    /// Draws up to `stem_peers` distinct eligible peers in distinct prefix groups.
    fn draw_stem_peers<R: Rng>(&self, candidates: &[Candidate], rng: &mut R) -> Vec<PeerKey> {
        let mut pool: Vec<&Candidate> = self.eligible(candidates).collect();
        let mut chosen: Vec<&Candidate> = Vec::new();
        while chosen.len() < self.params.stem_peers && !pool.is_empty() {
            let i = rng.gen_range(0..pool.len());
            let c = pool.swap_remove(i);
            if chosen.iter().all(|x| prefix_group(x.addr.ip()) != prefix_group(c.addr.ip())) {
                chosen.push(c);
            }
        }
        chosen.into_iter().map(|c| c.key).collect()
    }

    /// Starts a new epoch if none is running or the current one ended, or if one of its stem
    /// peers is gone (D-5: re-pick within the epoch). Returns whether a new epoch started.
    pub fn refresh_epoch<R: Rng>(&mut self, now: Instant, candidates: &[Candidate], rng: &mut R) -> bool {
        let live = |k: &PeerKey| self.eligible(candidates).any(|c| c.key == *k);
        let expired = self.epoch.as_ref().is_none_or(|e| now >= e.ends_at);
        if !expired {
            let e = self.epoch.as_ref().unwrap();
            let lost = e.stem_peers.iter().any(|k| !live(k));
            let short = e.stem_peers.len() < self.params.stem_peers && self.eligible(candidates).count() > e.stem_peers.len();
            if lost || short {
                let peers = self.draw_stem_peers(candidates, rng);
                let e = self.epoch.as_mut().unwrap();
                e.stem_peers = peers;
                e.map.clear();
            }
            return false;
        }
        let ends_at = now + self.params.epoch_base + uniform(rng, self.params.epoch_jitter);
        let is_diffuser = rng.gen_bool(self.params.fluff_probability.clamp(0.0, 1.0));
        let stem_peers = self.draw_stem_peers(candidates, rng);
        self.epoch = Some(Epoch { ends_at, is_diffuser, stem_peers, map: HashMap::new() });
        self.epoch_id += 1;
        true
    }

    pub fn is_diffuser(&self) -> Option<bool> {
        self.epoch.as_ref().map(|e| e.is_diffuser)
    }

    pub fn stem_peers(&self) -> Vec<PeerKey> {
        self.epoch.as_ref().map(|e| e.stem_peers.clone()).unwrap_or_default()
    }

    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    /// Routing for a relayed stem transaction that arrived from `from` (D-3, D-5).
    pub fn route_relayed<R: Rng>(&mut self, from: PeerKey, now: Instant, candidates: &[Candidate], rng: &mut R) -> Route {
        self.refresh_epoch(now, candidates, rng);
        let e = self.epoch.as_mut().expect("refresh_epoch sets an epoch");
        if e.is_diffuser || e.stem_peers.is_empty() {
            return Route::Fluff;
        }
        let n = e.stem_peers.len();
        let idx = *e.map.entry(from).or_insert_with(|| rng.gen_range(0..n));
        let target = e.stem_peers[idx % n];
        if target != from {
            return Route::Stem(target);
        }
        // Never hand a stem straight back; use the other stem peer if there is one.
        match e.stem_peers.iter().find(|k| **k != from) {
            Some(k) => Route::Stem(*k),
            None => Route::Fluff,
        }
    }

    /// Routing for an own transaction: the 24-hour own stem peer (D-2 fallback leg). A new one
    /// is drawn only on expiry or when the current one is gone or no longer eligible.
    pub fn route_own<R: Rng>(&mut self, now: Instant, candidates: &[Candidate], rng: &mut R) -> Route {
        let still_good = self.own_stem.as_ref().is_some_and(|o| now < o.ends_at && self.eligible(candidates).any(|c| c.key == o.peer));
        if !still_good {
            let pool: Vec<&Candidate> = self.eligible(candidates).collect();
            if pool.is_empty() {
                self.own_stem = None;
                return Route::Fluff;
            }
            let pick = pool[rng.gen_range(0..pool.len())].key;
            let ends_at = now + self.params.own_stem_base + uniform(rng, self.params.own_stem_jitter);
            self.own_stem = Some(OwnStem { peer: pick, ends_at });
        }
        Route::Stem(self.own_stem.as_ref().unwrap().peer)
    }

    /// The current own stem peer, without drawing one (D-11 re-stems go to the same peer).
    pub fn own_stem_peer(&self) -> Option<PeerKey> {
        self.own_stem.as_ref().map(|o| o.peer)
    }

    /// D-12 rate limit: whether `peer` may put another transaction into our stem phase now.
    pub fn admit_stem_from(&mut self, peer: PeerKey, now: Instant) -> bool {
        let b = self.buckets.entry(peer).or_insert(TokenBucket { tokens: STEM_BURST, at: now });
        let refill = now.saturating_duration_since(b.at).as_secs_f64() * STEM_RATE_PER_SEC;
        b.tokens = (b.tokens + refill).min(STEM_BURST);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn forget_peer(&mut self, peer: &PeerKey) {
        self.buckets.remove(peer);
        if let Some(e) = self.epoch.as_mut() {
            e.map.remove(peer);
        }
    }

    pub fn track_stem(&mut self, id: TransactionId, own: bool, now: Instant, embargo: Duration) {
        self.stems.insert(id, StemMeta { own, embargo_at: now + embargo, submitted_at: now });
    }

    /// Stem transactions whose embargo ran out (D-4).
    pub fn due_embargoes(&self, now: Instant) -> Vec<TransactionId> {
        self.stems.iter().filter(|(_, m)| m.embargo_at <= now).map(|(id, _)| *id).collect()
    }

    pub fn track_own_fluffed(&mut self, id: TransactionId, now: Instant) {
        self.own_fluffed.insert(id, OwnFluffed { fluffed_at: now, restems: 0, announced_back: false });
    }

    /// A peer announced `id`: an own transaction is out, and a stem transaction is public.
    pub fn note_announced(&mut self, id: &TransactionId) {
        if let Some(o) = self.own_fluffed.get_mut(id) {
            o.announced_back = true;
        }
    }

    /// Own transactions due for a re-stem (D-11), and those that used up their re-stems.
    pub fn due_restems(&mut self, now: Instant) -> (Vec<TransactionId>, Vec<TransactionId>) {
        let mut restem = Vec::new();
        let mut give_up = Vec::new();
        for (id, o) in self.own_fluffed.iter_mut() {
            if o.announced_back || now.saturating_duration_since(o.fluffed_at) < RESTEM_AFTER {
                continue;
            }
            if o.restems < MAX_RESTEMS {
                o.restems += 1;
                o.fluffed_at = now;
                restem.push(*id);
            } else {
                give_up.push(*id);
            }
        }
        for id in &give_up {
            self.own_fluffed.remove(id);
        }
        (restem, give_up)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_utils::networking::PeerId;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::net::Ipv4Addr;

    fn key(i: u8) -> PeerKey {
        PeerKey::new(PeerId::from(uuid::Uuid::from_bytes([i; 16])), IpAddr::V4(Ipv4Addr::new(10, i, 0, 1)).into())
    }

    fn cand(i: u8, outbound: bool, dpp: bool, age_s: u64) -> Candidate {
        Candidate {
            key: key(i),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, i, 0, 1)), 16111),
            outbound,
            dpp,
            connected_for: Duration::from_secs(age_s),
        }
    }

    fn net() -> Vec<Candidate> {
        (1..=8).map(|i| cand(i, true, true, 7200)).chain((20..30).map(|i| cand(i, false, true, 7200))).collect()
    }

    #[test]
    fn diffuser_fraction_is_q() {
        let mut rng = StdRng::seed_from_u64(1);
        let now = Instant::now();
        let mut diffusers = 0;
        for _ in 0..20_000 {
            let mut d = Dandelion::new(Default::default());
            d.refresh_epoch(now, &net(), &mut rng);
            diffusers += d.is_diffuser().unwrap() as u32;
        }
        let q = diffusers as f64 / 20_000.0;
        assert!((q - 0.2).abs() < 0.015, "q = {q}");
    }

    #[test]
    fn stem_peers_are_two_eligible_outbound_peers_in_distinct_groups() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut cands = net();
        cands.push(cand(40, true, false, 7200)); // no NODE_DPP
        cands.push(cand(41, true, true, 60)); // too young
        for _ in 0..200 {
            let mut d = Dandelion::new(Default::default());
            d.refresh_epoch(Instant::now(), &cands, &mut rng);
            let peers = d.stem_peers();
            assert_eq!(peers.len(), 2);
            assert_ne!(peers[0], peers[1]);
            for p in &peers {
                let c = cands.iter().find(|c| c.key == *p).unwrap();
                assert!(c.outbound && c.dpp && c.connected_for >= STEM_PEER_MIN_AGE);
            }
        }
    }

    #[test]
    fn same_prefix_peers_are_never_both_stem_peers() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut cands = vec![cand(1, true, true, 7200), cand(1, true, true, 7200)];
        cands[1].key = key(99);
        cands[1].addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 7, 7)), 1);
        let mut d = Dandelion::new(Default::default());
        d.refresh_epoch(Instant::now(), &cands, &mut rng);
        assert_eq!(d.stem_peers().len(), 1);
    }

    #[test]
    fn forwarding_is_one_to_one_within_an_epoch_and_redrawn_after() {
        let mut rng = StdRng::seed_from_u64(4);
        let now = Instant::now();
        let cands = net();
        let mut d = Dandelion::new(DandelionParams { fluff_probability: 0.0, ..Default::default() });
        let from = key(25);
        let first = d.route_relayed(from, now, &cands, &mut rng);
        for k in 1..50 {
            assert_eq!(d.route_relayed(from, now + Duration::from_secs(k), &cands, &mut rng), first);
        }
        let epoch = d.epoch_id();
        d.route_relayed(from, now + EPOCH_BASE + EPOCH_JITTER + Duration::from_secs(1), &cands, &mut rng);
        assert_eq!(d.epoch_id(), epoch + 1);
    }

    #[test]
    fn a_diffuser_fluffs_and_no_stem_peer_means_fluff() {
        let mut rng = StdRng::seed_from_u64(5);
        let mut d = Dandelion::new(DandelionParams { fluff_probability: 1.0, ..Default::default() });
        assert_eq!(d.route_relayed(key(25), Instant::now(), &net(), &mut rng), Route::Fluff);
        let mut d = Dandelion::new(DandelionParams { fluff_probability: 0.0, ..Default::default() });
        let v10_only: Vec<Candidate> = (1..=8).map(|i| cand(i, true, false, 7200)).collect();
        assert_eq!(d.route_relayed(key(25), Instant::now(), &v10_only, &mut rng), Route::Fluff);
        assert_eq!(d.route_own(Instant::now(), &v10_only, &mut rng), Route::Fluff);
    }

    #[test]
    fn a_stem_never_goes_back_to_its_sender() {
        let mut rng = StdRng::seed_from_u64(6);
        let cands = net();
        for _ in 0..200 {
            let mut d = Dandelion::new(DandelionParams { fluff_probability: 0.0, ..Default::default() });
            d.refresh_epoch(Instant::now(), &cands, &mut rng);
            let sp = d.stem_peers();
            assert_eq!(d.route_relayed(sp[0], Instant::now(), &cands, &mut rng), Route::Stem(sp[1]));
        }
    }

    #[test]
    fn the_own_stem_peer_is_kept_across_epochs_for_a_day() {
        let mut rng = StdRng::seed_from_u64(7);
        let cands = net();
        let now = Instant::now();
        let mut d = Dandelion::new(Default::default());
        let Route::Stem(first) = d.route_own(now, &cands, &mut rng) else { panic!() };
        for h in 1..24 {
            let t = now + Duration::from_secs(h * 3600);
            d.refresh_epoch(t, &cands, &mut rng);
            assert_eq!(d.route_own(t, &cands, &mut rng), Route::Stem(first), "hour {h}");
        }
        // After 25 h it is re-drawn (it may land on the same peer by chance; check the expiry moved).
        let t = now + Duration::from_secs(25 * 3600 + 1);
        d.route_own(t, &cands, &mut rng);
        assert!(d.own_stem.as_ref().unwrap().ends_at > t + Duration::from_secs(23 * 3600));
        // A lost own stem peer is replaced at once.
        let lost: Vec<Candidate> = cands.iter().copied().filter(|c| c.key != d.own_stem_peer().unwrap()).collect();
        let Route::Stem(next) = d.route_own(t, &lost, &mut rng) else { panic!() };
        assert!(lost.iter().any(|c| c.key == next));
    }

    #[test]
    fn embargo_is_two_seconds_plus_exp_one() {
        let mut rng = StdRng::seed_from_u64(8);
        let n = 20_000;
        let mut sum = 0.0;
        for _ in 0..n {
            let e = embargo_delay(&mut rng);
            assert!(e >= EMBARGO_BASE);
            sum += e.as_secs_f64();
        }
        let mean = sum / n as f64;
        assert!((mean - 3.0).abs() < 0.05, "mean {mean}");
    }

    #[test]
    fn rate_limit_bursts_fifty_then_ten_per_second() {
        let mut d = Dandelion::new(Default::default());
        let now = Instant::now();
        let p = key(1);
        assert_eq!((0..60).filter(|_| d.admit_stem_from(p, now)).count(), 50);
        assert_eq!((0..20).filter(|_| d.admit_stem_from(p, now + Duration::from_secs(1))).count(), 10);
    }

    #[test]
    fn restems_three_times_then_gives_up_unless_announced_back() {
        let mut d = Dandelion::new(Default::default());
        let now = Instant::now();
        let id = TransactionId::from_bytes([1; 32]);
        let other = TransactionId::from_bytes([2; 32]);
        d.track_own_fluffed(id, now);
        d.track_own_fluffed(other, now);
        d.note_announced(&other);
        let mut t = now;
        for _ in 0..MAX_RESTEMS {
            t += RESTEM_AFTER;
            assert_eq!(d.due_restems(t), (vec![id], vec![]));
        }
        t += RESTEM_AFTER;
        assert_eq!(d.due_restems(t), (vec![], vec![id]));
        assert!(d.own_fluffed.get(&id).is_none());
        assert!(d.own_fluffed.contains_key(&other), "announced back: watched no more, but kept until it leaves the mempool");
    }
}
