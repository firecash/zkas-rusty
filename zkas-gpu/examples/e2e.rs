//! END-TO-END us/action for a cohort of wallets scanning one page.
//!
//! The only number that has ever predicted this daemon's behaviour is wall time for a
//! whole page-lap divided by the actions in it. us/mult flatters a device that is
//! latency-bound; per-batch tables measured with ONE caller have twice sent this
//! project's live blocks/s down. So: W long-lived threads, their own viewing keys, the
//! same shared page, exactly as `sync_chunk` drives them -- and the figure reported is
//! the time to serve one round of W wallets, over the actions in that round.
//!
//! The three paths, chosen by argv so each runs in its own process (the hooks are
//! `OnceLock`s, so one process cannot hold two):
//!
//!   cpu     no device: orchard's batch API across rayon.
//!   agree   today's production path: the key agreement on the device, then the
//!           Jacobian-to-affine, KDF, ChaCha20 and lead-byte test on the host.
//!   filter  the whole per-action filter on the device; the host sees only verdicts.
//!
//! usage: e2e <cpu|agree|filter> [actions] [wallets] [rounds]

use group::{Curve, Group, GroupEncoding};
use kaspa_shielded_core::wallet::{self, CompactActionRecord};
use pasta_curves::pallas;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map(|s| s.as_str()).unwrap_or("cpu").to_string();
    let n: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(13000);
    let w: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(9);
    let rounds: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(6);

    if mode != "cpu" {
        if std::env::var("ZKAS_GPU_LIB").is_err() {
            std::env::set_var("ZKAS_GPU_LIB", "/root/zkas/rk-gpu2/gpu/libzkas_gpu2.so");
        }
        let gpu = std::sync::Arc::new(zkas_gpu::Gpu::load().expect("a GPU, for this mode"));
        if mode == "filter" {
            assert!(gpu.has_filter(), "this library has no filter ABI, or it failed its self-test");
            let g = gpu.clone();
            wallet::install_gpu_filter(Box::new(move |ivk, xy, rows, ct0| g.batch_filter(ivk, xy, rows, ct0)));
        }
        let g = gpu.clone();
        wallet::install_gpu_agree(Box::new(move |ivk, epks| g.batch_agree_points(ivk, epks)));
        std::mem::forget(gpu); // the hooks outlive main
    }

    // A page nobody owns. Ownership is not what is being timed: ~255 of every 256
    // actions are rejected on one byte whoever scans them, so a page of misses is the
    // honest steady state and a page of hits would only measure orchard.
    let mut rng = rand::rng();
    let page: Vec<CompactActionRecord> = (0..n)
        .map(|_| CompactActionRecord {
            nullifier: [0u8; 32],
            cmx: [0u8; 32],
            ephemeral_key: pallas::Point::random(&mut rng).to_affine().to_bytes(),
            enc_ciphertext: [7u8; 52],
        })
        .collect();

    // The cohort's shared decode, paid once per page exactly as `DecodedPage` pays it.
    let t = std::time::Instant::now();
    let epks: Vec<Option<pallas::Point>> = page.iter().map(|r| wallet::decompress_epk(&r.ephemeral_key)).collect();
    let dec_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = std::time::Instant::now();
    let prep = wallet::prepare_epks(&epks);
    let prep_ms = t.elapsed().as_secs_f64() * 1e3;

    let keys: Vec<_> = (0..w)
        .map(|i| {
            let ivk = wallet::ivk_from_seed([i as u8 + 1; 32]).unwrap();
            let sc = wallet::ivk_agreement_scalar(&ivk).unwrap();
            (ivk.prepare(), sc)
        })
        .collect();

    // Long-lived threads, started once. Creating them per round measures thread
    // creation and start-up skew, and it makes the submit queue look worse than it is
    // because half the cohort has not been spawned when the first launch goes out.
    let barrier = std::sync::Barrier::new(w + 1);
    let mut per_round: Vec<f64> = Vec::new();
    std::thread::scope(|s| {
        for (prepared, sc) in &keys {
            let (page, epks, prep, barrier, mode) = (&page, &epks, &prep, &barrier, &mode);
            s.spawn(move || {
                let scan = || match mode.as_str() {
                    "filter" => wallet::scan_compact_auto_prepared(prepared, Some(sc), page, Some(prep), Some(epks)),
                    "agree" => wallet::scan_compact_auto_cached(prepared, Some(sc), page, Some(epks)),
                    _ => wallet::scan_compact_auto_cached(prepared, None, page, Some(epks)),
                };
                scan(); // warm-up, outside every timed region
                for _ in 0..rounds {
                    barrier.wait();
                    scan();
                    barrier.wait();
                }
            });
        }
        for _ in 0..rounds {
            barrier.wait();
            let t = std::time::Instant::now();
            barrier.wait();
            per_round.push(t.elapsed().as_secs_f64() * 1e3);
        }
    });

    per_round.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let lo = per_round[0];
    let med = per_round[per_round.len() / 2];
    let hi = *per_round.last().unwrap();
    let actions = (n * w) as f64;
    println!(
        "{mode:<7} n={n} W={w} rounds={rounds}   page-lap min {lo:8.2} ms  med {med:8.2}  max {hi:8.2}  (spread {:4.1}%)",
        100.0 * (hi - lo) / lo
    );
    println!(
        "{:<7} END-TO-END {:.3} us/action (min) / {:.3} (med)   [shared per page: decompress {dec_ms:.1} ms, pack {prep_ms:.1} ms]",
        "", lo * 1e3 / actions, med * 1e3 / actions
    );
}
