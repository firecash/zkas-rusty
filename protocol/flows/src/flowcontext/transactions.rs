//! Scheduling of the mempool scanning task. Transaction announcement itself moved to the
//! per-peer trickle (`trickle.rs`, spec 06 D-7); the 500 ms global gate is gone.

use kaspa_p2p_lib::Hub;
use std::time::{Duration, Instant};

/// Interval between mempool scanning tasks (in seconds)
const SCANNING_TASK_INTERVAL: u64 = 10;
const REBROADCAST_FREQUENCY: u64 = 3;
pub(crate) const MAX_INV_PER_TX_INV_MSG: usize = 131_072;

pub struct TransactionsSpread {
    last_scanning_time: Instant,
    scanning_task_running: bool,
    scanning_job_count: u64,
}

impl TransactionsSpread {
    pub fn new(_hub: Hub) -> Self {
        Self { last_scanning_time: Instant::now(), scanning_task_running: false, scanning_job_count: 0 }
    }

    /// Returns true if the time has come for running the task of scanning mempool transactions
    /// and if so, mark the task as running.
    pub fn should_run_mempool_scanning_task(&mut self) -> bool {
        let now = Instant::now();
        if self.scanning_task_running || now < self.last_scanning_time + Duration::from_secs(SCANNING_TASK_INTERVAL) {
            return false;
        }
        let delta = now.checked_duration_since(self.last_scanning_time).expect("verified above");
        // Keep the launching times aligned to exact intervals. Note that `delta=10.1` seconds will result in
        // adding 10 seconds to last scan time, while `delta=11` will result in adding 20 (assuming scanning
        // interval is 10 seconds).
        self.last_scanning_time += Duration::from_secs(delta.as_secs().div_ceil(SCANNING_TASK_INTERVAL) * SCANNING_TASK_INTERVAL);

        self.scanning_job_count += 1;
        self.scanning_task_running = true;
        true
    }

    /// Returns true if the time for a rebroadcast of the mempool high priority transactions has come.
    pub fn should_rebroadcast(&self) -> bool {
        self.scanning_job_count.is_multiple_of(REBROADCAST_FREQUENCY)
    }

    pub fn mempool_scanning_job_count(&self) -> u64 {
        self.scanning_job_count
    }

    pub fn mempool_scanning_is_done(&mut self) {
        assert!(self.scanning_task_running, "no stop without a matching start");
        self.scanning_task_running = false;
    }
}
