//! Limits on serving the pruning-point proof, the one response a peer can ask for that is hundreds
//! of megabytes.
//!
//! The proof is cached by consensus, but every serve converts it to a protobuf message of its own
//! (~221 MB encoded on mainnet, measured 2026-10-16, more in memory), and once the transport has
//! taken it off the outgoing route it sits whole in the HTTP/2 send buffer until the peer reads it.
//! Byte pacing bounds what one connection queues, not how many connections ask: a few peers that
//! request the proof and never read it held several gigabytes. So serves are global: one is built
//! at a time, and only a few start per window. An honest node needs the proof once, at the start of
//! an IBD from a fresh or far-behind state, and any of its peers can serve it; a refused request
//! costs it a reconnect to another peer, while an unbounded one could cost this node its memory.

use parking_lot::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Length of one proof-serve budget window.
pub(crate) const PROOF_SERVE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Proof serves that may start per window. Each can leave one encoded proof in a send buffer until
/// that peer reads it or the connection dies (the ping flow drops a peer that reads nothing), so
/// this bounds that memory at roughly this many proofs.
pub(crate) const MAX_PROOF_SERVES_PER_WINDOW: usize = 3;

#[derive(Debug)]
pub(crate) struct ProofServeGate {
    /// One proof is converted and handed to a transport at a time.
    building: Semaphore,
    budget: Mutex<FixedWindow>,
}

impl Default for ProofServeGate {
    fn default() -> Self {
        Self { building: Semaphore::new(1), budget: Default::default() }
    }
}

impl ProofServeGate {
    /// Waits for the single build slot, then takes one serve from the window's budget. `None` when
    /// the budget is spent: the caller refuses the request instead of serving it.
    pub(crate) async fn admit(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.building.acquire().await.ok()?;
        self.budget.lock().try_take(Instant::now()).then_some(permit)
    }
}

/// A fixed-window count, the same shape as the auto-ban budget.
#[derive(Debug, Default)]
struct FixedWindow {
    window_start: Option<Instant>,
    used: usize,
}

impl FixedWindow {
    fn try_take(&mut self, now: Instant) -> bool {
        let in_window = self.window_start.is_some_and(|start| now.saturating_duration_since(start) < PROOF_SERVE_WINDOW);
        if !in_window {
            self.window_start = Some(now);
            self.used = 0;
        }
        if self.used >= MAX_PROOF_SERVES_PER_WINDOW {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_admits_a_fixed_number_and_then_refills() {
        let mut w = FixedWindow::default();
        let t0 = Instant::now();
        for _ in 0..MAX_PROOF_SERVES_PER_WINDOW {
            assert!(w.try_take(t0));
        }
        assert!(!w.try_take(t0), "the budget is spent within the window");
        assert!(!w.try_take(t0 + PROOF_SERVE_WINDOW - Duration::from_secs(1)));
        assert!(w.try_take(t0 + PROOF_SERVE_WINDOW), "a new window refills it");
    }

    #[tokio::test]
    async fn one_build_at_a_time_and_a_refusal_frees_the_slot() {
        let gate = ProofServeGate::default();
        let first = gate.admit().await.expect("first serve admitted");
        assert!(gate.building.try_acquire().is_err(), "a second build waits while the first holds the slot");
        drop(first);
        for _ in 1..MAX_PROOF_SERVES_PER_WINDOW {
            assert!(gate.admit().await.is_some());
        }
        assert!(gate.admit().await.is_none(), "past the budget the request is refused");
        assert!(gate.building.try_acquire().is_ok(), "a refused request does not keep the build slot");
    }
}
