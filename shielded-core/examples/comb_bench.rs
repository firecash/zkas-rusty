//! What the comb actually costs against what the daemon actually runs.
//!
//! Three things are timed on the same points, in the same process, so nothing here can
//! be confounded by a different build profile or a different machine:
//!
//! 1. `orchard`'s own `batch_epk` + `batch_ka_agree_dec` — the CPU path a wallet scan
//!    takes today when no device is installed. This is the number that matters; the
//!    rest is only useful if it beats this.
//! 2. `Table::batch` + `Table::mul_decomposed_batch` — the same work one layer down, to
//!    confirm (1) is exactly this and nothing else is hiding in it.
//! 3. `PageCombs` — the comb, at the width `width_for_cohort` picks and across a sweep.
//!
//! Costs are reported as `build/W + per-pair`, because the table is built once per page
//! and read by every viewing key in the cohort; a number that leaves the build out is
//! not a number a daemon ever pays.
//!
//! Deliberately single-threaded. Both paths parallelise the same way (per-page batches
//! spread over cores), so the ratio is what transfers, and a threaded measurement on a
//! box running a live daemon measures the daemon's load as much as the code.
//!
//! Usage: `comb_bench [N] [reps]`.

use kaspa_shielded_core::comb::{self, PageCombs};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::glv::{Decomposed, Table};
use pasta_curves::group::GroupEncoding;
use pasta_curves::group::ff::FromUniformBytes;
use pasta_curves::group::{Curve, Group};
use pasta_curves::pallas;
use std::time::Instant;

struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 31)
    }
    fn scalar(&mut self) -> pallas::Scalar {
        let mut b = [0u8; 64];
        for c in b.chunks_exact_mut(8) {
            c.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        pallas::Scalar::from_uniform_bytes(&b)
    }
}

/// Best of `reps`, in nanoseconds — the minimum, because on a box with a live daemon
/// the mean measures the neighbours.
fn best<F: FnMut() -> u128>(reps: usize, mut f: F) -> f64 {
    (0..reps).map(|_| f()).min().unwrap() as f64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    comb::assert_endomorphism();
    println!("endomorphism: phi(x,y) = (ZETA^1 * x, y) == lambda*P   [asserted]");

    let mut rng = Lcg(0x5eed_1234);
    let g = pallas::Point::generator();
    let pts: Vec<pallas::Point> = (0..n).map(|_| g * rng.scalar()).collect();
    let epks: Vec<Option<pallas::Point>> = pts.iter().copied().map(Some).collect();
    let keys: Vec<pallas::Scalar> = (0..8).map(|_| rng.scalar()).collect();

    println!("N = {n} ephemeral keys, best of {reps}\n");

    // ---------------------------------------------------------------- orchard
    // The production CPU path, called exactly as `scan_compact_cpu` reaches it.
    {
        use orchard::keys::{FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
        use orchard::note_encryption::OrchardDomain;
        use zcash_note_encryption::{BatchDomain, EphemeralKeyBytes};

        let epk_bytes: Vec<EphemeralKeyBytes> =
            pts.iter().map(|p| EphemeralKeyBytes(p.to_affine().to_bytes())).collect();
        let ivks: Vec<PreparedIncomingViewingKey> = (0..8)
            .map(|i| {
                let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([i as u8 + 1; 32])).expect("valid spending key");
                let fvk = FullViewingKey::from(&sk);
                let ivk: IncomingViewingKey = fvk.to_ivk(Scope::External);
                PreparedIncomingViewingKey::new(&ivk)
            })
            .collect();

        let t_prep = best(reps, || {
            let s = Instant::now();
            std::hint::black_box(<OrchardDomain as BatchDomain>::batch_epk(epk_bytes.iter().cloned()));
            s.elapsed().as_nanos()
        });
        let prepared = <OrchardDomain as BatchDomain>::batch_epk(epk_bytes.iter().cloned());
        let refs: Vec<Option<&_>> = prepared.iter().map(|(p, _)| p.as_ref()).collect();
        let t_agree = best(reps, || {
            let s = Instant::now();
            for ivk in &ivks {
                std::hint::black_box(<OrchardDomain as BatchDomain>::batch_ka_agree_dec(ivk, refs.iter().copied()));
            }
            s.elapsed().as_nanos()
        });
        println!(
            "orchard batch_epk + batch_ka_agree_dec  : prepare {:6.2} us/epk   agree {:7.3} us/pair",
            t_prep / n as f64 / 1000.0,
            t_agree / (8.0 * n as f64) / 1000.0
        );
    }

    // ------------------------------------------------------------ glv::Table
    let (tbl_build, tbl_pair) = {
        let t_build = best(reps, || {
            let s = Instant::now();
            std::hint::black_box(Table::<pallas::Point>::batch(&pts));
            s.elapsed().as_nanos()
        });
        let tables = Table::<pallas::Point>::batch(&pts);
        let refs: Vec<&Table<pallas::Point>> = tables.iter().collect();
        let decs: Vec<Decomposed<pallas::Point>> = keys.iter().map(Decomposed::new).collect();
        let t_pair = best(reps, || {
            let s = Instant::now();
            for d in &decs {
                std::hint::black_box(Table::mul_decomposed_batch(&refs, d));
            }
            s.elapsed().as_nanos()
        });
        let (b, p) = (t_build / n as f64, t_pair / (8.0 * n as f64));
        println!(
            "glv::Table batch + mul_decomposed_batch : build   {:6.2} us/epk   pair  {:7.3} us/pair",
            b / 1000.0,
            p / 1000.0
        );
        (b, p)
    };

    // ------------------------------------------------------------------ comb
    println!("\n{:>3} {:>4} {:>5} {:>9} {:>13} {:>11} {:>7}", "w", "pos", "ent", "KiB/epk", "build us/epk", "pair us", "exact");
    let mut rows: Vec<(usize, f64, f64)> = Vec::new();
    for w in 2..=9usize {
        let kib = comb::bytes_per_epk(w) as f64 / 1024.0;
        if kib * n as f64 > 2048.0 * 1024.0 {
            continue;
        }
        let budget = comb::DEFAULT_TABLE_BUDGET_BYTES.max(comb::bytes_per_epk(w) * n);
        let t_build = best(reps.min(3), || {
            let s = Instant::now();
            let c = PageCombs::build_at_width(&epks, w, budget).expect("build");
            std::hint::black_box(c.bytes());
            s.elapsed().as_nanos()
        });
        let combs = PageCombs::build_at_width(&epks, w, budget).expect("build");
        let t_pair = best(reps, || {
            let s = Instant::now();
            for k in &keys {
                std::hint::black_box(combs.agree(k).expect("safe"));
            }
            s.elapsed().as_nanos()
        });
        // Every lane checked against the curve's own multiplication, at every width, in
        // the same run that reports the speed. A fast wrong answer is worth nothing.
        let got = combs.agree(&keys[0]).expect("safe");
        let exact = pts.iter().enumerate().all(|(l, p)| got[l] == Some((*p * keys[0]).to_affine()));
        let (b, p) = (t_build / n as f64, t_pair / (8.0 * n as f64));
        println!(
            "{:>3} {:>4} {:>5} {:>9.1} {:>13.2} {:>11.3} {:>7}",
            w,
            comb::positions_for(w),
            comb::entries_for(w),
            kib,
            b / 1000.0,
            p / 1000.0,
            if exact { "yes" } else { "NO" }
        );
        assert!(exact, "comb disagreed with epk * ivk at w={w}");
        rows.push((w, b, p));
    }

    // --------------------------------------------------- amortised comparison
    println!("\ntotal us/pair = build/W + pair    (W = viewing keys riding one page)");
    println!("{:>6} {:>12} {:>12} {:>8} {:>10}", "W", "glv::Table", "comb(best)", "width", "speedup");
    for wk in [1usize, 2, 3, 4, 9, 16, 32, 64, 128, 512, 2000] {
        let base = tbl_build / wk as f64 + tbl_pair;
        let mut bt = f64::MAX;
        let mut bw = 0usize;
        for (w, b, p) in &rows {
            let t = b / wk as f64 + p;
            if t < bt {
                bt = t;
                bw = *w;
            }
        }
        let picked = comb::width_for_cohort(wk);
        let picked_cost = picked.and_then(|w| rows.iter().find(|r| r.0 == w).map(|(_, b, p)| b / wk as f64 + p));
        println!(
            "{:>6} {:>10.2}us {:>10.2}us {:>8} {:>9.2}x   [width_for_cohort -> {:?}{}]",
            wk,
            base / 1000.0,
            bt / 1000.0,
            bw,
            base / bt,
            picked,
            picked_cost.map(|c| format!(", {:.2}us, {:.2}x", c / 1000.0, base / c)).unwrap_or_default()
        );
    }
}
