//! Proof-verification budgets for relayed shielded transactions (N1; spec 08 R1.4).
//!
//! A relayed shielded transaction costs its receiver a Halo 2 verification before anything can be
//! known about it beyond its declared fee. Measured on the 142 build box (spec 01 §3b), one bundle
//! costs `v(n) ≈ 16.0 + 0.63·n` core-ms single-threaded, so a peer pushing garbage-proof 2-action
//! bundles at 100 Mbps buys 23-34 core-seconds of verification per second. Fee-first admission
//! (R1.1) stops only an under-paying sender; the declared fee is bound only by the proof itself.
//!
//! Budgets bound what any one peer, and all peers together, can make this node verify:
//! - work is counted in **verify units** (VU), reference core-milliseconds: `VU(n) = 16 + ⌈0.63·n⌉`
//!   for an `n`-action bundle, charged when the bytes arrive, before verification;
//! - a **global** token bucket with rate `g = 500·C` VU/s (C = verify cores, default
//!   `max(1, ncpu/2)`) and burst `4g`: honest full-load relay is <= 26 two-action bundles/s
//!   ≈ 450 VU/s unbatched, so one core's budget carries it with margin and half the box stays free
//!   for block processing;
//! - a **per-peer** bucket: outbound rate `g/4` burst `g`; inbound rate `g/16` burst `g/4`; a NEW
//!   inbound peer gets burst `g/64` until it has been connected [`TRUST_RAMP`] (trust ramp);
//! - when a bucket is empty the peer's shielded transactions wait at most [`MAX_BUDGET_WAIT`] and are
//!   then dropped silently (not misbehaviour: an honest peer can be faster than our budget).
//!
//! Blocks are never budgeted: consensus must progress; batched block verification bounds them.

use std::time::{Duration, Instant};

/// Reference VU per verify core per second.
pub const VU_PER_CORE_PER_SEC: f64 = 500.0;
/// How long an inbound peer is "new" (smaller burst).
pub const TRUST_RAMP: Duration = Duration::from_secs(10 * 60);
/// Longest a peer's batch waits for budget before its excess shielded transactions are dropped.
pub const MAX_BUDGET_WAIT: Duration = Duration::from_secs(2);

/// Verify units of one `n`-action bundle: `16 + ⌈0.63·n⌉` (spec 08 R1.4.1).
pub fn verify_units(n_actions: usize) -> f64 {
    16.0 + (0.63 * n_actions as f64).ceil()
}

/// Default verify cores: `max(1, available_parallelism / 2)`.
pub fn default_verify_cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get() / 2).unwrap_or(1).max(1)
}

/// A token bucket over a monotone clock.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self { rate, burst, tokens: burst, last: now }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        self.last = now;
    }

    /// Change the burst (trust ramp). Tokens above the new burst are cut.
    pub fn set_burst(&mut self, burst: f64, now: Instant) {
        self.refill(now);
        self.burst = burst;
        self.tokens = self.tokens.min(burst);
    }

    pub fn burst(&self) -> f64 {
        self.burst
    }

    /// Take `n` tokens if available.
    pub fn try_take(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Return `n` tokens (an admission the other bucket refused).
    pub fn refund(&mut self, n: f64) {
        self.tokens = (self.tokens + n).min(self.burst);
    }

    /// How long until `n` tokens are available; `None` if `n` exceeds the burst (never).
    pub fn time_until(&mut self, n: f64, now: Instant) -> Option<Duration> {
        self.refill(now);
        if n > self.burst {
            return None;
        }
        if self.tokens >= n {
            return Some(Duration::ZERO);
        }
        Some(Duration::from_secs_f64((n - self.tokens) / self.rate))
    }
}

/// The node-wide verification budget.
#[derive(Clone, Copy, Debug)]
pub struct BudgetParams {
    /// `g`, VU per second.
    pub global_rate: f64,
}

impl BudgetParams {
    pub fn for_cores(cores: usize) -> Self {
        Self { global_rate: VU_PER_CORE_PER_SEC * cores.max(1) as f64 }
    }

    pub fn global_bucket(&self, now: Instant) -> TokenBucket {
        TokenBucket::new(self.global_rate, 4.0 * self.global_rate, now)
    }

    /// The per-peer bucket and its full (post-ramp) burst.
    pub fn peer_bucket(&self, outbound: bool, now: Instant) -> (TokenBucket, f64) {
        let g = self.global_rate;
        if outbound {
            (TokenBucket::new(g / 4.0, g, now), g)
        } else {
            // A new inbound peer starts on the ramp burst; `PeerBudget::admit` raises it.
            (TokenBucket::new(g / 16.0, g / 64.0, now), g / 4.0)
        }
    }
}

/// One peer's budget state, with the trust ramp.
#[derive(Clone, Debug)]
pub struct PeerBudget {
    bucket: TokenBucket,
    full_burst: f64,
    connected_at: Instant,
    ramped: bool,
}

impl PeerBudget {
    pub fn new(params: &BudgetParams, outbound: bool, connected_at: Instant) -> Self {
        let (bucket, full_burst) = params.peer_bucket(outbound, connected_at);
        Self { bucket, full_burst, connected_at, ramped: outbound }
    }

    fn ramp(&mut self, now: Instant) {
        if !self.ramped && now.saturating_duration_since(self.connected_at) >= TRUST_RAMP {
            self.bucket.set_burst(self.full_burst, now);
            self.ramped = true;
        }
    }

    pub fn burst(&mut self, now: Instant) -> f64 {
        self.ramp(now);
        self.bucket.burst()
    }
}

/// Outcome of charging one transaction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Admission {
    /// Charged; verify it.
    Admitted,
    /// Not enough budget now; retry after this long.
    Wait(Duration),
    /// Cannot be admitted within [`MAX_BUDGET_WAIT`] (or ever): drop it, silently.
    Drop,
}

/// Charge `vu` to the peer and the global bucket together (both or neither).
pub fn charge(peer: &mut PeerBudget, global: &mut TokenBucket, vu: f64, now: Instant) -> Admission {
    peer.ramp(now);
    if peer.bucket.try_take(vu, now) {
        if global.try_take(vu, now) {
            return Admission::Admitted;
        }
        peer.bucket.refund(vu);
    }
    let wait = match (peer.bucket.time_until(vu, now), global.time_until(vu, now)) {
        (Some(a), Some(b)) => a.max(b),
        _ => return Admission::Drop,
    };
    if wait > MAX_BUDGET_WAIT { Admission::Drop } else { Admission::Wait(wait) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_units_follow_the_measured_fit() {
        assert_eq!(verify_units(1), 17.0);
        assert_eq!(verify_units(2), 18.0);
        assert_eq!(verify_units(38), 16.0 + 24.0);
    }

    /// Simulate `secs` seconds of a peer offering `per_sec` bundles of `n` actions each second,
    /// waiting when told to (time advances), and return the VU admitted.
    fn offer(peer: &mut PeerBudget, global: &mut TokenBucket, t0: Instant, secs: u64, per_sec: usize, n: usize) -> f64 {
        let vu = verify_units(n);
        let mut admitted = 0.0;
        for s in 0..secs {
            let now = t0 + Duration::from_secs(s);
            for _ in 0..per_sec {
                if charge(peer, global, vu, now) == Admission::Admitted {
                    admitted += vu;
                }
            }
        }
        admitted
    }

    /// Adversarial (spec 08 T3 shape, single node, no network): one inbound peer floods garbage-sized
    /// 2-action bundles at ~1,360 bundles/s (100 Mbps / 9,181 B). It is held to its own bucket:
    /// burst + rate x time, a small fraction of the flood, and of the global budget.
    #[test]
    fn a_flooding_inbound_peer_is_held_to_its_bucket() {
        let params = BudgetParams::for_cores(2); // g = 1,000 VU/s
        let t0 = Instant::now();
        let mut global = params.global_bucket(t0);
        let mut peer = PeerBudget::new(&params, false, t0);
        let secs = 60;
        let admitted = offer(&mut peer, &mut global, t0, secs, 1_360, 2);
        let bound = params.global_rate / 64.0 + params.global_rate / 16.0 * secs as f64;
        assert!(admitted <= bound + 1.0, "admitted {admitted} VU > bound {bound}");
        let offered = 1_360.0 * secs as f64 * verify_units(2);
        assert!(admitted / offered < 0.01, "a flooder gets < 1% of what it offers ({admitted} of {offered})");
    }

    /// Adversarial: 64 sybil inbound peers flood at once. The global bucket caps the node's total
    /// verification at its rate (plus one burst), whatever the number of peers.
    #[test]
    fn sybils_together_are_held_to_the_global_budget() {
        let params = BudgetParams::for_cores(2);
        let t0 = Instant::now();
        let mut global = params.global_bucket(t0);
        let mut sybils: Vec<PeerBudget> = (0..64).map(|_| PeerBudget::new(&params, false, t0)).collect();
        let secs = 30u64;
        let mut admitted = 0.0;
        for s in 0..secs {
            let now = t0 + Duration::from_secs(s);
            for p in sybils.iter_mut() {
                for _ in 0..50 {
                    if charge(p, &mut global, verify_units(2), now) == Admission::Admitted {
                        admitted += verify_units(2);
                    }
                }
            }
        }
        let bound = 4.0 * params.global_rate + params.global_rate * secs as f64;
        assert!(admitted <= bound + 1.0, "{admitted} > {bound}");
    }

    /// The honest side of the same flood: an outbound peer relaying full-load honest traffic
    /// (26 two-action bundles/s ≈ 468 VU/s, spec 08 R1.4.2) keeps getting admitted while 63 inbound
    /// sybils flood, because sybils are capped per peer and the global rate leaves room.
    #[test]
    fn honest_full_load_relay_survives_a_sybil_flood() {
        let params = BudgetParams::for_cores(4); // g = 2,000 VU/s
        let t0 = Instant::now();
        let mut global = params.global_bucket(t0);
        let mut honest = PeerBudget::new(&params, true, t0);
        let mut sybils: Vec<PeerBudget> = (0..63).map(|_| PeerBudget::new(&params, false, t0)).collect();
        let (mut ok, mut offered) = (0usize, 0usize);
        for s in 0..120u64 {
            let now = t0 + Duration::from_secs(s);
            // Honest bundles are interleaved with the flood within each second.
            for k in 0..26 {
                for p in sybils.iter_mut().skip(k % 3).step_by(3) {
                    for _ in 0..4 {
                        let _ = charge(p, &mut global, verify_units(2), now);
                    }
                }
                offered += 1;
                if charge(&mut honest, &mut global, verify_units(2), now) == Admission::Admitted {
                    ok += 1;
                }
            }
        }
        // Report, and require that most honest traffic still gets through: the sybils' combined
        // rate (63 x g/16 ≈ 3.9 g) exceeds g, so the global bucket is contended and admission is
        // first-come within a second; the bound below is what this ordering guarantees.
        let share = ok as f64 / offered as f64;
        assert!(share > 0.2, "honest admission share {share}");
    }

    #[test]
    fn the_trust_ramp_raises_an_inbound_burst_after_ten_minutes() {
        let params = BudgetParams::for_cores(2);
        let t0 = Instant::now();
        let mut p = PeerBudget::new(&params, false, t0);
        assert_eq!(p.burst(t0), params.global_rate / 64.0);
        assert_eq!(p.burst(t0 + TRUST_RAMP - Duration::from_secs(1)), params.global_rate / 64.0);
        assert_eq!(p.burst(t0 + TRUST_RAMP), params.global_rate / 4.0);
        let mut o = PeerBudget::new(&params, true, t0);
        assert_eq!(o.burst(t0), params.global_rate, "outbound peers start trusted");
    }

    #[test]
    fn charging_is_all_or_nothing_across_the_two_buckets() {
        let params = BudgetParams::for_cores(1);
        let t0 = Instant::now();
        let mut global = TokenBucket::new(1.0, 10.0, t0);
        assert!(global.try_take(10.0, t0)); // empty the global bucket
        let mut peer = PeerBudget::new(&params, true, t0);
        let before = peer.bucket.clone();
        assert!(matches!(charge(&mut peer, &mut global, 5.0, t0), Admission::Drop | Admission::Wait(_)));
        assert_eq!(peer.bucket.tokens, before.tokens, "the peer's tokens were refunded");
    }
}
