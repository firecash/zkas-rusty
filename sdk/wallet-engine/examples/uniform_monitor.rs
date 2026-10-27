//! Spec 02 §7.3 M2/M3 over a block crawl.
//!
//! Input: JSON lines, one per chain block, each with `ts` (block time, ms) and `tx`, a list
//! of `[txid, action_count]` for the block's accepted user bundles (the format of the
//! 2026-10-20 48-h crawl, `consensus-2026-10-20/data/shielded-48h.jsonl`). Reads stdin.
//!
//! Output: D_h over all user bundles, over n = 38 and over n != 38, and S_tx(±5 min / ±30 min)
//! keyed on the action count (on today's chain the fee is a pure function of n, so n is the
//! whole envelope class). Usage:
//!
//!     zcat shielded-48h.jsonl.gz | cargo run --release --example uniform_monitor
use std::io::BufRead;
use zkas_wallet_engine::monitor::{dispersion_index, matching_set_sizes, median};

fn main() {
    let mut events: Vec<(u64, u64)> = Vec::new();
    let (mut first, mut last) = (u64::MAX, 0u64);
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let Some(ts) = v.get("ts").and_then(|t| t.as_u64()) else { continue };
        first = first.min(ts);
        last = last.max(ts);
        for tx in v.get("tx").and_then(|t| t.as_array()).into_iter().flatten() {
            if let Some(n) = tx.get(1).and_then(|n| n.as_u64()) {
                events.push((ts, n));
            }
        }
    }
    if events.is_empty() {
        eprintln!("no transactions read");
        std::process::exit(1);
    }
    let all: Vec<u64> = events.iter().map(|e| e.0).collect();
    let n38: Vec<u64> = events.iter().filter(|e| e.1 == 38).map(|e| e.0).collect();
    let rest: Vec<u64> = events.iter().filter(|e| e.1 != 38).map(|e| e.0).collect();
    println!("window {:.2} h, {} user bundles", (last - first) as f64 / 3.6e6, events.len());
    for (name, ev) in [("all", &all), ("n=38", &n38), ("n!=38", &rest)] {
        match dispersion_index(ev, first, last + 1) {
            Some(r) => println!(
                "M2 D_h {name:6}: {:.2} over {} complete hours ({} sparse hours skipped)",
                r.mean, r.hours, r.sparse_hours
            ),
            None => println!("M2 D_h {name:6}: no qualifying hour"),
        }
    }
    for (label, d) in [("±5 min", 5 * 60_000u64), ("±30 min", 30 * 60_000)] {
        let s = matching_set_sizes(&events, d);
        let unique = s.iter().filter(|&&x| x == 1).count() as f64 / s.len() as f64;
        let gm = (s.iter().map(|&x| (x as f64).ln()).sum::<f64>() / s.len() as f64).exp();
        println!("M3 S_tx {label}: median {}, geometric mean {gm:.1}, unique {:.1}%", median(&s).unwrap(), unique * 100.0);
    }
}
