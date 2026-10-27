//! The public-data statistics that say whether Stage W worked (spec 02 §7.2-7.3).
//!
//! - M2 [`dispersion_index`]: the within-hour dispersion index D_h of per-minute counts of user
//!   bundles. A Poisson stream with a rate constant within the hour gives D_h ≈ 1; bursts and
//!   cadences push it up (4.87 on the 48-h crawl of 2026-10-18..20, spec 02 §1.3 S4). Target ≤ 1.20.
//! - M3 [`matching_set_sizes`]: S_tx(Δ), how many transactions within ±Δ share every envelope
//!   feature with a target.
//! - M4 [`classifier_auc`]: a cross-validated classifier separating two client families (or a
//!   family from the background) on public features; its AUC is the per-client fingerprint
//!   statistic. Target ≤ 0.55 with the upper 95% bound ≤ 0.60. The production monitor of spec
//!   02 §7.2 uses gradient boosting; this crate carries a dependency-free naive Bayes over
//!   quantile bins so every client's CI can run the same check on simulated or canary data.
//! - M1 [`non_conformance`]: the share of bundles violating the envelope.
//!
//! Inputs are plain numbers (times in ms, feature vectors), so the same code runs over the
//! node's `GetShieldedBlocks` stream, an explorer crawl, or a devnet harness.

use crate::uniform::{UNIFORM_ACTIONS, UNIFORM_FEE_V1, UNIFORM_FLAGS_V1, UNIFORM_LOCK_TIME, UNIFORM_PAYLOAD_LEN_V1};
use serde::{Deserialize, Serialize};

const HOUR_MS: u64 = 3_600_000;
const MINUTE_MS: u64 = 60_000;

/// D_h of one complete UTC hour.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct HourDispersion {
    pub hour_start_ms: u64,
    /// Mean of the 60 per-minute counts.
    pub mean_per_minute: f64,
    /// Sample variance / mean of the per-minute counts.
    pub dispersion: f64,
}

/// The M2 statistic over an observation window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DispersionReport {
    /// Mean D_h over the qualifying hours.
    pub mean: f64,
    /// Complete hours in the window whose mean count was at least 0.5 per minute.
    pub hours: usize,
    /// Complete hours skipped for a mean below 0.5 per minute.
    pub sparse_hours: usize,
    pub per_hour: Vec<HourDispersion>,
}

/// M2: within-hour dispersion index of per-minute event counts (spec 02 §7.3).
///
/// Only hours lying entirely inside `[observed_from_ms, observed_to_ms)` count: a partial hour
/// has empty minutes that are an artefact of the window, not of the traffic, and including one
/// biased a Poisson simulation to 1.17 (spec 02 §7.3 M2). Hours with a mean below 0.5 per
/// minute are skipped. Returns `None` when no hour qualifies.
pub fn dispersion_index(event_ms: &[u64], observed_from_ms: u64, observed_to_ms: u64) -> Option<DispersionReport> {
    let first = observed_from_ms.div_ceil(HOUR_MS) * HOUR_MS;
    let mut per_hour = Vec::new();
    let mut sparse_hours = 0usize;
    let mut sorted: Vec<u64> = event_ms.iter().copied().filter(|&t| t >= first && t < observed_to_ms).collect();
    sorted.sort_unstable();
    let mut idx = 0usize;
    let mut h = first;
    while h + HOUR_MS <= observed_to_ms {
        let mut counts = [0u32; 60];
        while idx < sorted.len() && sorted[idx] < h + HOUR_MS {
            counts[((sorted[idx] - h) / MINUTE_MS) as usize] += 1;
            idx += 1;
        }
        let mean = counts.iter().map(|&c| c as f64).sum::<f64>() / 60.0;
        if mean >= 0.5 {
            let var = counts.iter().map(|&c| (c as f64 - mean).powi(2)).sum::<f64>() / 59.0;
            per_hour.push(HourDispersion { hour_start_ms: h, mean_per_minute: mean, dispersion: var / mean });
        } else {
            sparse_hours += 1;
        }
        h += HOUR_MS;
    }
    if per_hour.is_empty() {
        return None;
    }
    let mean = per_hour.iter().map(|x| x.dispersion).sum::<f64>() / per_hour.len() as f64;
    Some(DispersionReport { mean, hours: per_hour.len(), sparse_hours, per_hour })
}

/// The public envelope of one included user bundle, as the monitor sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub actions: usize,
    pub fee: i64,
    pub flags: u8,
    pub lock_time: u64,
    pub payload_len: usize,
    /// Anchor lag in epochs: `K(s) - epoch(anchor)` at the including block (0 or 1 for Stage W).
    pub anchor_lag: u64,
}

impl Envelope {
    /// Whether this envelope is the V1 uniform one (M1 counts the rest).
    pub fn is_uniform_v1(&self) -> bool {
        self.actions == UNIFORM_ACTIONS
            && self.fee == UNIFORM_FEE_V1 as i64
            && self.flags == UNIFORM_FLAGS_V1
            && self.lock_time == UNIFORM_LOCK_TIME
            && self.payload_len == UNIFORM_PAYLOAD_LEN_V1
            && self.anchor_lag <= 1
    }
}

/// M1: the share of envelopes violating the V1 uniform envelope. `None` for no input.
pub fn non_conformance(envelopes: &[Envelope]) -> Option<f64> {
    if envelopes.is_empty() {
        return None;
    }
    Some(envelopes.iter().filter(|e| !e.is_uniform_v1()).count() as f64 / envelopes.len() as f64)
}

/// M3: for each event, the number of events (itself included) within ±`delta_ms` whose class
/// key is equal. `events` are `(time_ms, class_key)`; the key is whatever the observer can see
/// (action count, fee, flags, lock_time, anchor lag), hashed or packed by the caller.
pub fn matching_set_sizes(events: &[(u64, u64)], delta_ms: u64) -> Vec<usize> {
    use std::collections::HashMap;
    let mut by_class: HashMap<u64, Vec<u64>> = HashMap::new();
    for &(t, k) in events {
        by_class.entry(k).or_default().push(t);
    }
    for v in by_class.values_mut() {
        v.sort_unstable();
    }
    events
        .iter()
        .map(|&(t, k)| {
            let v = &by_class[&k];
            let lo = v.partition_point(|&x| x < t.saturating_sub(delta_ms));
            let hi = v.partition_point(|&x| x <= t.saturating_add(delta_ms));
            hi - lo
        })
        .collect()
}

/// Median of a slice (upper median for even lengths); `None` when empty.
pub fn median(xs: &[usize]) -> Option<usize> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// Area under the ROC curve of `pos` scored above `neg`: the Mann-Whitney U statistic over
/// `n_pos x n_neg`, ties counting one half. 0.5 = no separation.
pub fn auc(pos: &[f64], neg: &[f64]) -> Option<f64> {
    if pos.is_empty() || neg.is_empty() {
        return None;
    }
    let mut all: Vec<(f64, bool)> = pos.iter().map(|&s| (s, true)).chain(neg.iter().map(|&s| (s, false))).collect();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
    // Average ranks over ties.
    let mut rank_sum_pos = 0.0;
    let mut i = 0usize;
    while i < all.len() {
        let mut j = i;
        while j + 1 < all.len() && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        let avg = (i + j) as f64 / 2.0 + 1.0;
        rank_sum_pos += all[i..=j].iter().filter(|x| x.1).count() as f64 * avg;
        i = j + 1;
    }
    let (np, nn) = (pos.len() as f64, neg.len() as f64);
    Some((rank_sum_pos - np * (np + 1.0) / 2.0) / (np * nn))
}

/// Hanley-McNeil standard error of an AUC (spec 02 §7.2: 0.0152 at 0.5 with 720 vs 720).
pub fn hanley_mcneil_se(a: f64, n_pos: usize, n_neg: usize) -> f64 {
    let (n1, n2) = (n_pos as f64, n_neg as f64);
    let q1 = a / (2.0 - a);
    let q2 = 2.0 * a * a / (1.0 + a);
    ((a * (1.0 - a) + (n1 - 1.0) * (q1 - a * a) + (n2 - 1.0) * (q2 - a * a)) / (n1 * n2)).sqrt()
}

/// The M4 verdict on one pair: AUC, its SE, and whether it passes (AUC ≤ 0.55 and the upper
/// 95% bound ≤ 0.60).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct AucVerdict {
    pub auc: f64,
    pub se: f64,
    pub upper95: f64,
    pub pass: bool,
}

/// Turn an AUC into the M4 verdict. A classifier may learn the inverted rule, so the separation
/// is `max(auc, 1 - auc)`.
pub fn auc_verdict(a: f64, n_pos: usize, n_neg: usize) -> AucVerdict {
    let a = a.max(1.0 - a);
    let se = hanley_mcneil_se(a, n_pos, n_neg);
    let upper95 = a + 1.96 * se;
    AucVerdict { auc: a, se, upper95, pass: a <= 0.55 && upper95 <= 0.60 }
}

/// Bins per feature in [`classifier_auc`].
const NB_BINS: usize = 10;

fn bin_edges(values: &mut [f64]) -> Vec<f64> {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
    let mut edges = Vec::with_capacity(NB_BINS);
    for q in 1..NB_BINS {
        let x = values[(q * values.len() / NB_BINS).min(values.len() - 1)];
        if edges.last().is_none_or(|&l| x > l) {
            edges.push(x);
        }
    }
    edges
}

fn bin_of(edges: &[f64], x: f64) -> usize {
    edges.partition_point(|&e| e <= x)
}

/// M4: out-of-fold AUC of a naive Bayes classifier over quantile-binned features, `folds`-fold
/// stratified cross-validation with a deterministic split from `seed`.
///
/// Each row of `a` and `b` is one transaction's public feature vector (the same length for
/// every row). The classifier is deliberately simple and assumption-light: it finds any
/// single-feature distribution difference (an action count, a fee, an anchor lag, an hour of
/// day, a gap length) and adds them up, which is exactly what a client fingerprint is.
pub fn classifier_auc(a: &[Vec<f64>], b: &[Vec<f64>], folds: usize, seed: u64) -> Option<f64> {
    let folds = folds.max(2);
    if a.len() < folds || b.len() < folds {
        return None;
    }
    let dims = a[0].len();
    if a.iter().chain(b.iter()).any(|r| r.len() != dims) {
        return None;
    }
    // Deterministic stratified fold assignment.
    let fold_of = |n: usize, salt: u64| -> Vec<usize> {
        let mut order: Vec<(u64, usize)> = (0..n)
            .map(|i| {
                let mut z = (i as u64).wrapping_add(seed).wrapping_add(salt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                (z ^ (z >> 27), i)
            })
            .collect();
        order.sort_unstable();
        let mut f = vec![0usize; n];
        for (rank, (_, i)) in order.into_iter().enumerate() {
            f[i] = rank % folds;
        }
        f
    };
    let fa = fold_of(a.len(), 1);
    let fb = fold_of(b.len(), 2);
    let mut score_a = vec![0.0; a.len()];
    let mut score_b = vec![0.0; b.len()];
    for k in 0..folds {
        let train_a: Vec<&Vec<f64>> = a.iter().zip(&fa).filter(|(_, f)| **f != k).map(|(r, _)| r).collect();
        let train_b: Vec<&Vec<f64>> = b.iter().zip(&fb).filter(|(_, f)| **f != k).map(|(r, _)| r).collect();
        let mut model: Vec<(Vec<f64>, Vec<f64>, Vec<f64>)> = Vec::with_capacity(dims);
        for d in 0..dims {
            let mut pooled: Vec<f64> = train_a.iter().chain(train_b.iter()).map(|r| r[d]).collect();
            let edges = bin_edges(&mut pooled);
            let bins = edges.len() + 1;
            let mut ca = vec![1.0; bins];
            let mut cb = vec![1.0; bins];
            for r in &train_a {
                ca[bin_of(&edges, r[d])] += 1.0;
            }
            for r in &train_b {
                cb[bin_of(&edges, r[d])] += 1.0;
            }
            let (ta, tb) = (ca.iter().sum::<f64>(), cb.iter().sum::<f64>());
            let la: Vec<f64> = ca.iter().map(|c| (c / ta).ln()).collect();
            let lb: Vec<f64> = cb.iter().map(|c| (c / tb).ln()).collect();
            model.push((edges, la, lb));
        }
        let score = |r: &Vec<f64>| -> f64 {
            model.iter().enumerate().map(|(d, (e, la, lb))| {
                let bi = bin_of(e, r[d]);
                la[bi] - lb[bi]
            }).sum()
        };
        for (i, r) in a.iter().enumerate() {
            if fa[i] == k {
                score_a[i] = score(r);
            }
        }
        for (i, r) in b.iter().enumerate() {
            if fb[i] == k {
                score_b[i] = score(r);
            }
        }
    }
    auc(&score_a, &score_b)
}

/// The public feature vector of spec 02 §7.2 for one included transaction, in a fixed order.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct TxFeatures {
    pub envelope: Envelope,
    /// UTC milliseconds of the including block.
    pub time_ms: u64,
    /// Seconds to the previous and the next user bundle.
    pub gap_prev_s: f64,
    pub gap_next_s: f64,
    /// User bundles within ±30 s and ±300 s.
    pub within_30s: usize,
    pub within_300s: usize,
    /// Other user bundles in the same block.
    pub same_block: usize,
    /// Seen in the public mempool before inclusion (1) or not (0), and the log dwell.
    pub seen_in_mempool: bool,
    pub log_dwell_s: f64,
}

impl TxFeatures {
    /// The vector the classifier consumes.
    pub fn to_vec(&self) -> Vec<f64> {
        let hour = ((self.time_ms / 1_000) % 86_400) as f64 / 86_400.0 * core::f64::consts::TAU;
        vec![
            self.envelope.actions as f64,
            self.envelope.fee as f64,
            self.envelope.flags as f64,
            self.envelope.lock_time as f64,
            self.envelope.payload_len as f64,
            self.envelope.anchor_lag as f64,
            hour.sin(),
            hour.cos(),
            (1.0 + self.gap_prev_s).ln(),
            (1.0 + self.gap_next_s).ln(),
            self.within_30s as f64,
            self.within_300s as f64,
            self.same_block as f64,
            if self.seen_in_mempool { 1.0 } else { 0.0 },
            self.log_dwell_s,
        ]
    }
}

/// Fill the timing features of a time-sorted stream of `(time_ms, block_id, envelope)`.
pub fn stream_features(stream: &[(u64, u64, Envelope)]) -> Vec<TxFeatures> {
    let times: Vec<u64> = stream.iter().map(|x| x.0).collect();
    let mut per_block: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for x in stream {
        *per_block.entry(x.1).or_default() += 1;
    }
    let count_within = |t: u64, d: u64| {
        let lo = times.partition_point(|&x| x < t.saturating_sub(d));
        let hi = times.partition_point(|&x| x <= t.saturating_add(d));
        hi - lo - 1
    };
    stream
        .iter()
        .enumerate()
        .map(|(i, &(t, blk, env))| {
            let prev = if i > 0 { (t - times[i - 1]) as f64 / 1_000.0 } else { 0.0 };
            let next = if i + 1 < times.len() { (times[i + 1] - t) as f64 / 1_000.0 } else { 0.0 };
            let same_block = per_block[&blk] - 1;
            TxFeatures {
                envelope: env,
                time_ms: t,
                gap_prev_s: prev,
                gap_next_s: next,
                within_30s: count_within(t, 30_000),
                within_300s: count_within(t, 300_000),
                same_block,
                seen_in_mempool: true,
                log_dwell_s: 0.0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::tests::rng;
    use crate::schedule::{HoldMode, exp_ms, hold_ms, poisson_next, uniform_ms};

    fn poisson_stream(rate_per_s: f64, from: u64, to: u64, seed: u64) -> Vec<u64> {
        let mut r = rng(seed);
        let mut t = from;
        let mut out = Vec::new();
        loop {
            t = poisson_next(t, rate_per_s, &mut r);
            if t >= to {
                return out;
            }
            out.push(t);
        }
    }

    #[test]
    fn m2_poisson_is_about_one_and_partial_hours_are_dropped() {
        // 200 h at today's Stage W rate (922 tx/h). Start mid-hour: the partial first hour must
        // not count.
        let from = 1_800_000;
        let to = from + 200 * HOUR_MS;
        let ev = poisson_stream(922.0 / 3_600.0, from, to, 7);
        let r = dispersion_index(&ev, from, to).unwrap();
        assert_eq!(r.hours, 199, "the partial first and last hours are dropped");
        assert!((r.mean - 1.0).abs() < 0.06, "Poisson D_h {}", r.mean);
        assert!(r.mean <= 1.20, "passes the M2 threshold");
    }

    #[test]
    fn m2_bursts_and_cadences_fail() {
        // The chunked-payment burst of spec 02 §2.2a: groups of 5 at the same instant.
        let from = 0;
        let to = 48 * HOUR_MS;
        let starts = poisson_stream(30.0 / 3_600.0, from, to, 8);
        let mut ev = Vec::new();
        for s in starts {
            for k in 0..11u64 {
                // 11-tx clusters, groups of 5 every 8.5 s.
                ev.push(s + (k / 5) * 8_500);
            }
        }
        let r = dispersion_index(&ev, from, to).unwrap();
        assert!(r.mean > 3.0, "burst D_h {}", r.mean);
        // The 62-s cadence: under-dispersed per minute, D_h near 0 for that sender alone, but
        // mixed with a burst source it still fails the Poisson test as a whole.
        let cadence: Vec<u64> = (0..2_800u64).map(|i| i * 62_000).collect();
        let r = dispersion_index(&cadence, 0, 2_800 * 62_000).unwrap();
        assert!(r.mean < 0.5, "a fixed timer is far from Poisson too: {}", r.mean);
    }

    #[test]
    fn auc_and_hanley_mcneil() {
        assert_eq!(auc(&[1.0, 2.0], &[0.0, 0.5]), Some(1.0));
        assert_eq!(auc(&[0.0], &[1.0]), Some(0.0));
        assert_eq!(auc(&[1.0, 1.0], &[1.0, 1.0]), Some(0.5), "ties count one half");
        assert_eq!(auc(&[], &[1.0]), None);
        let se = hanley_mcneil_se(0.5, 720, 720);
        assert!((se - 0.0152).abs() < 0.0002, "spec 02 §7.2: 0.0152, got {se}");
        assert!(auc_verdict(0.5, 720, 720).pass);
        assert!(!auc_verdict(0.58, 720, 720).pass);
        assert!(!auc_verdict(0.40, 720, 720).pass, "an inverted rule is still a fingerprint");
    }

    /// Simulate one client family's canary transactions inside a Poisson background, and return
    /// the features of the canaries.
    fn family(stage_w: bool, kind: u8, seed: u64) -> Vec<Vec<f64>> {
        let mut r = rng(seed);
        let hours = 720u64;
        let to = hours * HOUR_MS;
        let bg = poisson_stream(922.0 / 3_600.0, 0, to, seed ^ 0xABCD);
        // Canaries: Poisson 1/h confirm times, then each family's hold and its shape.
        let confirms = poisson_stream(1.0 / 3_600.0, 0, to, seed ^ 0x1234);
        let mut stream: Vec<(u64, u64, Envelope, bool)> = bg
            .iter()
            .map(|&t| {
                let env = Envelope { actions: 4, fee: UNIFORM_FEE_V1 as i64, flags: 0x0b, lock_time: 0, payload_len: 15_493, anchor_lag: u64::from(uniform_ms(100, &mut r) < 8) };
                (t, t / 1_000, env, false)
            })
            .collect();
        for c in confirms {
            let (t, env) = if stage_w {
                let t = c + hold_ms(HoldMode::Standard, &mut r) + 1_000 + exp_ms(1_500.0, &mut r);
                let lag = u64::from(uniform_ms(100, &mut r) < 8);
                (t, Envelope { actions: 4, fee: UNIFORM_FEE_V1 as i64, flags: 0x0b, lock_time: 0, payload_len: 15_493, anchor_lag: lag })
            } else {
                // Today: n = max(spends, outputs), fee = f(n), no hold. Family 0 is a phone that
                // spends 1-3 notes; family 1 is a payout engine paying 3-20 payees.
                let n = if kind == 0 { 2 + (uniform_ms(1, &mut r) as usize) } else { 4 + uniform_ms(16, &mut r) as usize };
                let fee = crate::payment::chunk_fee(crate::DEFAULT_FEE_SOMPI, n) as i64;
                (c + 1_000, Envelope { actions: n, fee, flags: 0x0b, lock_time: 0, payload_len: kaspa_shielded_core::bundle::expected_wire_len(n) + 32, anchor_lag: 0 })
            };
            stream.push((t, t / 1_000, env, true));
        }
        stream.sort_by_key(|x| x.0);
        let plain: Vec<(u64, u64, Envelope)> = stream.iter().map(|x| (x.0, x.1, x.2)).collect();
        let feats = stream_features(&plain);
        stream.iter().zip(feats).filter(|(x, _)| x.3).map(|(_, f)| f.to_vec()).collect()
    }

    #[test]
    fn m4_stage_w_families_are_indistinguishable() {
        let a = family(true, 0, 11);
        let b = family(true, 1, 22);
        assert!(a.len() > 600 && b.len() > 600, "about 720 canaries each: {} {}", a.len(), b.len());
        let v = auc_verdict(classifier_auc(&a, &b, 5, 0).unwrap(), a.len(), b.len());
        assert!(v.pass, "Stage W families must pass M4: {v:?}");
    }

    #[test]
    fn m4_has_power_against_todays_shapes() {
        // The same statistic must FAIL today's two families, or passing it would mean nothing.
        let a = family(false, 0, 33);
        let b = family(false, 1, 44);
        let v = auc_verdict(classifier_auc(&a, &b, 5, 0).unwrap(), a.len(), b.len());
        assert!(!v.pass && v.auc > 0.95, "today's shapes are trivially separable: {v:?}");
        // And a Stage W family against today's phone family.
        let w = family(true, 0, 55);
        let v = auc_verdict(classifier_auc(&w, &a, 5, 0).unwrap(), w.len(), a.len());
        assert!(!v.pass, "{v:?}");
    }

    #[test]
    fn m1_and_m3() {
        let u = Envelope { actions: 4, fee: UNIFORM_FEE_V1 as i64, flags: 0x0b, lock_time: 0, payload_len: 15_493, anchor_lag: 1 };
        let mut bad = u;
        bad.actions = 2;
        assert_eq!(non_conformance(&[u, u, u, bad]), Some(0.25));
        let mut lt = u;
        lt.lock_time = 1;
        assert!(!lt.is_uniform_v1());
        // S_tx: 3 of class 1 within 5 min of each other, one class-2 alone.
        let ev = [(0u64, 1u64), (60_000, 1), (120_000, 1), (100_000, 2), (10 * 60_000, 1)];
        let s = matching_set_sizes(&ev, 5 * 60_000);
        assert_eq!(s, vec![3, 3, 3, 1, 1]);
        assert_eq!(median(&s), Some(3));
    }
}
