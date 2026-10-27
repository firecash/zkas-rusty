//! Rate rules for the pruning-point nullifier import (N1; spec 08 R3.4 as revised by 16 F8).
//!
//! The withdrawn rule dropped every source below an absolute 1 MiB/s. Honest Tor and residential
//! links and busy public nodes sit below that, so with every source below the floor the import
//! cycled through peers forever: the halt R3 exists to remove. The rules here never trade the best
//! source for nothing:
//!
//! - **relative floor** (R3.4.2): after a 30-s warm-up, measured over 60-s windows, a source slower
//!   than half the fastest source seen in this import is dropped, but only when an eligible
//!   replacement is connected;
//! - **absolute floor** (R3.4.3): below [`MIN_IMPORT_RATE_ABS`] a source is dropped if any other
//!   eligible source exists;
//! - **the last source is never dropped for rate.** Zero progress is still bounded by the per-chunk
//!   timeout of the stream itself.
//!
//! Dropping means: this peer stops serving this import (the connection's IBD attempt ends); the
//! staged prefix is kept, and the next source resumes after its last nullifier.

use std::time::{Duration, Instant};

/// Absolute floor, 64 KiB/s (2,048 nullifiers/s): a full 2^26 set in ≤ 9.1 h even if every source is
/// hostile (spec 08 R3.4.3).
pub const MIN_IMPORT_RATE_ABS: f64 = 64.0 * 1024.0;
/// No verdict during the first 30 s of a source (connection warm-up).
pub const RATE_WARMUP: Duration = Duration::from_secs(30);
/// Rates are measured over 60-s windows.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// What to do with the current source after a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateVerdict {
    Keep,
    /// Slower than half the best source while a replacement exists.
    DropRelative,
    /// Below the absolute floor while another source exists.
    DropAbsolute,
}

/// Measures one source's delivery rate in fixed windows.
#[derive(Clone, Debug)]
pub struct ImportRateMeter {
    started: Instant,
    window_start: Option<Instant>,
    window_bytes: u64,
    /// Rate of the last completed window, bytes/s.
    last_rate: Option<f64>,
}

impl ImportRateMeter {
    pub fn new(now: Instant) -> Self {
        Self { started: now, window_start: None, window_bytes: 0, last_rate: None }
    }

    /// Record `bytes` received at `now`. Returns the rate of a window that just completed, if any.
    pub fn record(&mut self, bytes: u64, now: Instant) -> Option<f64> {
        if now.saturating_duration_since(self.started) < RATE_WARMUP {
            return None;
        }
        let ws = *self.window_start.get_or_insert(now);
        self.window_bytes += bytes;
        let elapsed = now.saturating_duration_since(ws);
        if elapsed >= RATE_WINDOW {
            let rate = self.window_bytes as f64 / elapsed.as_secs_f64();
            self.last_rate = Some(rate);
            self.window_start = Some(now);
            self.window_bytes = 0;
            return Some(rate);
        }
        None
    }

    pub fn last_rate(&self) -> Option<f64> {
        self.last_rate
    }
}

/// The verdict for a source whose last completed window ran at `rate`, given the fastest rate any
/// source achieved in this import (`best`, including this one) and whether an eligible replacement
/// (connected, advertising the sorted-stream service bit, not suspect) exists.
pub fn rate_verdict(rate: f64, best: f64, replacement_available: bool) -> RateVerdict {
    if !replacement_available {
        // The last remaining source is never dropped for rate (16 F8).
        return RateVerdict::Keep;
    }
    if rate < MIN_IMPORT_RATE_ABS {
        return RateVerdict::DropAbsolute;
    }
    if rate < best / 2.0 {
        return RateVerdict::DropRelative;
    }
    RateVerdict::Keep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_source_is_never_dropped_for_rate() {
        for rate in [0.0, 1.0, 1_000.0, MIN_IMPORT_RATE_ABS - 1.0, 1e9] {
            assert_eq!(rate_verdict(rate, 1e9, false), RateVerdict::Keep, "rate {rate}");
        }
    }

    #[test]
    fn slow_sources_are_dropped_only_for_a_replacement() {
        // Below the absolute floor.
        assert_eq!(rate_verdict(10_000.0, 10_000.0, true), RateVerdict::DropAbsolute);
        // Above the floor but under half the best.
        assert_eq!(rate_verdict(200_000.0, 1_000_000.0, true), RateVerdict::DropRelative);
        // Honest slow link (Tor ~1 MB/s) that is the best seen: kept.
        assert_eq!(rate_verdict(1_000_000.0, 1_000_000.0, true), RateVerdict::Keep);
        // Within 2x of the best: kept (the withdrawn 1 MiB/s absolute floor would have dropped it).
        assert_eq!(rate_verdict(600_000.0, 1_000_000.0, true), RateVerdict::Keep);
    }

    #[test]
    fn rates_are_measured_after_warmup_in_whole_windows() {
        let t0 = Instant::now();
        let mut m = ImportRateMeter::new(t0);
        // Warm-up traffic does not count.
        assert_eq!(m.record(10_000_000, t0 + Duration::from_secs(10)), None);
        // First window opens at 30 s.
        assert_eq!(m.record(0, t0 + RATE_WARMUP), None);
        assert_eq!(m.record(3_000_000, t0 + RATE_WARMUP + Duration::from_secs(30)), None);
        let r = m.record(3_000_000, t0 + RATE_WARMUP + RATE_WINDOW).expect("window closes");
        assert!((r - 100_000.0).abs() < 1.0, "6 MB / 60 s = 100 kB/s, got {r}");
        assert_eq!(m.last_rate(), Some(r));
    }

    /// The slow-loris case of spec 08 T8: one 4,096-nullifier chunk (128 KiB) every 119 s is
    /// ~1.1 KiB/s; with any other source connected it is dropped at the first completed window,
    /// i.e. within warm-up + one window = 90 s of its first byte, instead of 22.6 days per peer.
    #[test]
    fn a_slow_loris_source_is_dropped_within_ninety_seconds() {
        let t0 = Instant::now();
        let mut m = ImportRateMeter::new(t0);
        let chunk = 4096u64 * 32;
        let mut t = t0;
        let mut dropped_at = None;
        for _ in 0..10 {
            t += Duration::from_secs(20); // even a faster drip than 1 chunk / 119 s
            if let Some(rate) = m.record(chunk / 6, t) {
                if rate_verdict(rate, 4.0 * 1024.0 * 1024.0, true) != RateVerdict::Keep {
                    dropped_at = Some(t);
                    break;
                }
            }
        }
        let at = dropped_at.expect("dropped");
        assert!(at.duration_since(t0) <= RATE_WARMUP + RATE_WINDOW + Duration::from_secs(20), "{:?}", at.duration_since(t0));
    }
}
