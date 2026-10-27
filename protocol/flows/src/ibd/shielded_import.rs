//! Range-split, resumable download of the pruning-point nullifier set (N1; spec 08 R3.3-R3.5 as
//! revised by 16 F8).
//!
//! The IBD peer (the "coordinator") first asks for the metadata only, binds it to the PoW-committed
//! root (`begin_pruning_point_shielded_import`, which also reopens a staging an interrupted attempt
//! or a killed process left), then streams the missing key ranges from up to four sources at once:
//! itself plus up to three other connected peers whose IBD flows are idle and that advertise
//! `SERVICE_NF_SORTED_STREAM` ("helpers"). Sources pull ranges from one queue, so a fast source
//! takes more ranges than a slow one and the tail is at most one range per slow source.
//!
//! Rate rules (16 F8): after a 30-s warm-up, per 60-s window, a source slower than half the fastest
//! active source, or below 64 KiB/s, is dropped while another source is still active; its range goes
//! back to the queue and resumes after its last staged nullifier. The last active source is never
//! dropped for rate (zero progress is still bounded by the per-chunk timeout). A dropped helper's
//! link is closed (its stream was abandoned mid-range). A dropped COORDINATOR ends this attempt once
//! the helpers' runs end: everything staged is kept, and the next IBD attempt, with another peer,
//! resumes the rest.
//!
//! Integrity (R3.4.4/R3.5): MuHash can only be checked over the whole set, at the end. When that
//! fails, every source of the attempt is recorded as suspect for this pruning point and the staging
//! is discarded. The next attempt uses no suspect helper; after two failed attempts the import is
//! single-source, as one unbounded stream that the SERVER also checks against the committed
//! accumulator. Suspects are never refused outright: a torn view on an honest server (a reorg walk
//! racing a ranged export) also fails the check, and refusing it could stall an honest sync.

use super::flow::IbdFlow;
use super::streams::ShieldedRangeStream;
use super::import_rate::{ImportRateMeter, RateVerdict, rate_verdict};
use futures::stream::{FuturesUnordered, StreamExt};
use kaspa_consensus_core::api::{ShieldedImportRange, ShieldedStreamScope};
use kaspa_consensus_core::errors::pruning::PruningImportError;
use kaspa_consensusmanager::ConsensusProxy;
use kaspa_core::{info, warn};
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{IncomingRoute, PeerKey, Router, common::ProtocolError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Most sources of one range-split import, the coordinator included (spec 08 R3.4.1: k <= 4).
pub const MAX_SHIELDED_IMPORT_SOURCES: usize = 4;

/// Chunks buffered between a source and the staging (4,096 nullifiers = 128 KiB each, so 4 MiB).
/// The staging folds and writes each chunk; a short buffer let any stall of that work throttle the
/// peer's stream (measured on a loaded box: 223 s of streaming for 239 MB, against 70 s when the
/// importer only buffered), so the network and the staging now overlap.
pub const STAGING_CHANNEL_CHUNKS: usize = 32;

/// Failed integrity checks after which an import is single-source (spec 08 R3.4.4).
pub const SINGLE_SOURCE_AFTER_FAILURES: u32 = 2;

/// One range handed to a helper's idle IBD flow.
pub struct ShieldedRangeJob {
    pub pruning_point: Hash,
    pub from: Option<[u8; 32]>,
    pub before: Option<[u8; 32]>,
    /// Where the helper forwards each chunk. Dropped by the coordinator to abandon the range.
    pub chunks: tokio::sync::mpsc::Sender<Vec<[u8; 32]>>,
    /// `Ok(true)`: the range's end marker arrived. `Ok(false)`: abandoned by the coordinator.
    pub done: tokio::sync::oneshot::Sender<Result<bool, ProtocolError>>,
}

/// Range-split imports whose final integrity check failed, for one pruning point.
#[derive(Default)]
pub struct ShieldedImportSuspects {
    pruning_point: Option<Hash>,
    failures: u32,
    peers: HashSet<PeerKey>,
}

impl ShieldedImportSuspects {
    /// `(failed attempts, suspect peers)` for `pp`; a new pruning point clears the record.
    pub fn for_pruning_point(&mut self, pp: Hash) -> (u32, HashSet<PeerKey>) {
        if self.pruning_point != Some(pp) {
            *self = Self { pruning_point: Some(pp), ..Default::default() };
        }
        (self.failures, self.peers.clone())
    }

    /// Record a failed attempt that used `sources`.
    pub fn record_failure(&mut self, pp: Hash, sources: impl IntoIterator<Item = PeerKey>) {
        self.for_pruning_point(pp);
        self.failures += 1;
        self.peers.extend(sources);
    }
}

/// Helper side: serve one range job on this peer's IBD route. A range that does not end cleanly
/// (error, or abandoned by the coordinator) leaves unread messages of the stream on the route, so
/// the connection is closed: the next IBD with this peer must not read them.
pub(super) async fn serve_range_job(router: &Arc<Router>, route: &mut IncomingRoute, job: ShieldedRangeJob) {
    let ShieldedRangeJob { pruning_point, from, before, chunks, done } = job;
    let result: Result<bool, ProtocolError> = async {
        let mut stream = ShieldedRangeStream::request(router, route, pruning_point, from, before, false).await?;
        while let Some(chunk) = stream.next_chunk().await? {
            if chunks.send(chunk).await.is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    .await;
    let clean = matches!(result, Ok(true));
    let _ = done.send(result);
    if !clean {
        router.close().await;
    }
}

/// Who serves a range.
#[derive(Clone)]
enum Source {
    Coordinator,
    Helper(PeerKey, tokio::sync::mpsc::Sender<ShieldedRangeJob>),
}

impl Source {
    fn key(&self, coordinator: PeerKey) -> PeerKey {
        match self {
            Source::Coordinator => coordinator,
            Source::Helper(k, _) => *k,
        }
    }
}

/// How one range run ended.
enum RunEnd {
    /// The end marker arrived; the range is complete.
    Complete,
    /// The coordinator dropped this source for rate; the range goes back to the queue.
    DroppedForRate,
}

/// Why one range run failed.
enum RunError {
    /// The source failed to deliver (timeout, disconnect, protocol error): requeue the range.
    Source(ProtocolError),
    /// The helper could not take the job (busy or gone): requeue, do not count it as a fault.
    Unavailable,
    /// The staging refused a chunk (out of order, out of range, over the count): the staging is
    /// discarded and the attempt ends; the source misbehaved.
    Refused(PruningImportError),
}

/// Shared rate bookkeeping of one import.
#[derive(Default)]
struct RateBoard {
    /// Last completed-window rate per active source, bytes/s.
    active: HashMap<PeerKey, Option<f64>>,
    best: f64,
}

impl RateBoard {
    /// The rate rules for `who` after a completed window at `rate`. Any source is dropped only while
    /// another source is active (the last active source is never dropped for rate, 16 F8).
    fn verdict(&mut self, who: PeerKey, rate: f64) -> RateVerdict {
        self.active.insert(who, Some(rate));
        self.best = self.best.max(rate);
        let others = self.active.len() > 1;
        rate_verdict(rate, self.best, others)
    }
}

impl IbdFlow {
    /// Download the pruning point's nullifier set from a peer that serves ranged streams (N1).
    /// Called after the PoW binding has been determined; `child` is the pruning point's selected
    /// child, `committed` the root it commits.
    pub(super) async fn sync_shielded_state_ranged(
        &mut self,
        consensus: &ConsensusProxy,
        pruning_point: Hash,
        child: Hash,
        committed: [u8; 32],
    ) -> Result<(), ProtocolError> {
        // 1. Metadata only: a probe of a one-key range carries the metadata frame.
        let mut probe_to = [0u8; 32];
        probe_to[31] = 1;
        let md = {
            let mut probe =
                ShieldedRangeStream::request(&self.router, &mut self.incoming_route, pruning_point, None, Some(probe_to), true).await?;
            let md = probe.recv_metadata().await?;
            if !md.data.is_empty() {
                // Read (and drop) the probe range itself, through its end marker.
                while probe.next_chunk().await?.is_some() {}
            }
            md
        };
        super::flow::refuse_if_validated_above(consensus, child, pruning_point).await?;
        if md.data.is_empty() {
            return self.accept_empty_shielded_state(consensus, pruning_point, committed).await;
        }
        let expected_state_root = Some(committed);

        // 2. Bind and open (or reopen) the staging.
        let (failures, suspects) = self.ctx.shielded_import_suspects().for_pruning_point(pruning_point);
        let single_source = failures >= SINGLE_SOURCE_AFTER_FAILURES;
        let mut ranges = consensus.async_begin_pruning_point_shielded_import(pruning_point, md.clone(), expected_state_root).await?;
        if single_source && ranges.iter().any(|r| r.received > 0 || r.complete) {
            consensus.async_discard_shielded_import_staging().await;
            ranges = consensus.async_begin_pruning_point_shielded_import(pruning_point, md.clone(), expected_state_root).await?;
        }
        let staged_before: u64 = ranges.iter().map(|r| r.received).sum();
        info!(
            "downloading the pruning point shielded state ({} nullifiers{}) from {}{}",
            md.nullifier_count,
            if staged_before > 0 { format!(", {staged_before} already staged") } else { String::new() },
            self.router,
            if single_source { " as one verified stream (earlier range-split attempts failed the integrity check)" } else { "" }
        );

        // 3. Stream.
        let started = Instant::now();
        let sources_used = if single_source {
            self.stream_single_source(consensus, pruning_point).await?;
            vec![self.router.key()]
        } else {
            self.stream_ranges(consensus, pruning_point, ranges, &suspects).await?
        };

        // 4. Finish: the fold must reproduce the committed accumulator.
        match consensus.async_finish_pruning_point_shielded_import(pruning_point, md.clone(), expected_state_root).await {
            Ok(()) => {}
            Err(e) => {
                // Missing nullifiers after every range ended, or a fold mismatch: some source lied or
                // served a torn view. Nothing staged can be trusted.
                consensus.async_discard_shielded_import_staging().await;
                self.ctx.shielded_import_suspects().record_failure(pruning_point, sources_used.iter().copied());
                warn!(
                    "shielded import from {} source(s) failed its integrity check ({e}); they are suspect for this pruning point",
                    sources_used.len()
                );
                return Err(e.into());
            }
        }
        consensus.async_set_pruning_shielded_stable().await;
        let secs = started.elapsed().as_secs_f64();
        info!(
            "shielded state synced: {} nullifiers from {} source(s) in {:.1} s ({:.0} nullifiers/s)",
            md.nullifier_count,
            sources_used.len(),
            secs,
            (md.nullifier_count - staged_before) as f64 / secs.max(0.001)
        );
        Ok(())
    }

    /// The pruning point has no shielded state: the claim must match the PoW commitment.
    async fn accept_empty_shielded_state(&mut self, consensus: &ConsensusProxy, pruning_point: Hash, committed: [u8; 32]) -> Result<(), ProtocolError> {
        let empty_root = consensus.async_empty_shielded_state_root().await;
        if committed != empty_root {
            return Err(ProtocolError::OtherOwned(format!(
                "peer claims pruning point {pruning_point} has no shielded state, but its selected child commits a non-empty \
                 shielded state root"
            )));
        }
        consensus.async_discard_shielded_import_staging().await;
        consensus.async_clear_pruning_shielded_stores().await;
        consensus.async_set_pruning_shielded_stable().await;
        info!("pruning point {} has no shielded state to import", pruning_point);
        Ok(())
    }

    /// One unbounded ranged stream from the coordinator (the server checks it against the committed
    /// accumulator before releasing its last chunk), staged as a full stream.
    async fn stream_single_source(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(STAGING_CHANNEL_CHUNKS);
        let c = consensus.clone();
        let stager = tokio::task::spawn_blocking(move || c.stage_pruning_point_shielded_nullifiers(pruning_point, ShieldedStreamScope::Full, rx));
        let streamed: Result<(), ProtocolError> = async {
            let mut stream = ShieldedRangeStream::request(&self.router, &mut self.incoming_route, pruning_point, None, None, false).await?;
            while let Some(chunk) = stream.next_chunk().await? {
                tx.send(chunk).await.map_err(|_| ProtocolError::Other("shielded staging stopped unexpectedly"))?;
            }
            Ok(())
        }
        .await;
        drop(tx);
        let staged = stager.await.map_err(|e| ProtocolError::OtherOwned(format!("shielded staging task panicked: {e}")))?;
        staged?;
        streamed
    }

    /// Stream the incomplete ranges from the coordinator and up to three helpers. Returns the
    /// sources that delivered data.
    async fn stream_ranges(
        &mut self,
        consensus: &ConsensusProxy,
        pruning_point: Hash,
        ranges: Vec<ShieldedImportRange>,
        suspects: &HashSet<PeerKey>,
    ) -> Result<Vec<PeerKey>, ProtocolError> {
        let me = self.router.key();
        let mut queue: VecDeque<ShieldedImportRange> = ranges.into_iter().filter(|r| !r.complete).collect();
        let helpers: Vec<Source> = self
            .ctx
            .shielded_range_helpers_except(&me)
            .into_iter()
            .filter(|(k, _)| !suspects.contains(k))
            .take(MAX_SHIELDED_IMPORT_SOURCES - 1)
            .map(|(k, s)| Source::Helper(k, s))
            .collect();
        if !helpers.is_empty() {
            info!("shielded import: {} ranges over {} sources (this peer + {} helper(s))", queue.len(), helpers.len() + 1, helpers.len());
        }
        let mut idle: Vec<Source> = helpers;
        idle.push(Source::Coordinator);
        let board = Arc::new(parking_lot::Mutex::new(RateBoard::default()));
        let mut used: HashSet<PeerKey> = HashSet::new();
        let router = self.router.clone();
        let route = &mut self.incoming_route;
        // The coordinator's own route is lent to at most one run at a time.
        let mut route_slot: Option<&mut IncomingRoute> = Some(route);
        let mut running = FuturesUnordered::new();
        let mut failure: Option<ProtocolError> = None;

        loop {
            // Hand out ranges to idle sources (the coordinator last, so helpers start first).
            while failure.is_none() && !queue.is_empty() {
                let Some(src) = idle.pop() else { break };
                let r = queue.pop_front().unwrap();
                let key = src.key(me);
                board.lock().active.insert(key, None);
                let fut: futures::future::BoxFuture<'_, (Source, ShieldedImportRange, Result<RunEnd, RunError>, Option<&mut IncomingRoute>)> =
                    match &src {
                        Source::Coordinator => {
                            let lent = route_slot.take().expect("the coordinator runs one range at a time");
                            let (c, b, rt) = (consensus.clone(), board.clone(), router.clone());
                            Box::pin(async move {
                                let res = run_coordinator_range(&rt, lent, &c, pruning_point, r, &b, me).await;
                                (src, r, res.0, Some(res.1))
                            })
                        }
                        Source::Helper(k, sender) => {
                            let (c, b, k, sender) = (consensus.clone(), board.clone(), *k, sender.clone());
                            Box::pin(async move {
                                let res = run_helper_range(sender, &c, pruning_point, r, &b, k).await;
                                (src, r, res, None)
                            })
                        }
                    };
                running.push(fut);
            }
            let Some((src, r, res, lent_back)) = running.next().await else { break };
            if let Some(rt) = lent_back {
                route_slot = Some(rt);
            }
            let key = src.key(me);
            board.lock().active.remove(&key);
            match res {
                Ok(RunEnd::Complete) => {
                    used.insert(key);
                    consensus.async_complete_pruning_point_shielded_range(pruning_point, r.range).await?;
                    idle.push(src);
                }
                Ok(RunEnd::DroppedForRate) => {
                    used.insert(key);
                    queue.push_back(refresh_range(consensus, pruning_point, r).await?);
                    // A dropped source is not given another range in this import. The coordinator's
                    // own stream is now abandoned, so this attempt ends once the helpers' runs do;
                    // what they staged is kept and the next attempt (another peer) resumes the rest.
                    if let Source::Coordinator = src {
                        route_slot = None;
                        if failure.is_none() {
                            failure = Some(ProtocolError::Other("this peer is too slow a nullifier source; the staged import resumes elsewhere"));
                        }
                    }
                }
                Err(RunError::Unavailable) => {
                    queue.push_back(r);
                }
                Err(RunError::Source(e)) => {
                    used.insert(key);
                    match src {
                        Source::Coordinator => {
                            // The IBD peer itself failed: end this attempt (what arrived stays staged
                            // and the next attempt resumes it). Let the helpers' runs end first.
                            failure = Some(e);
                        }
                        Source::Helper(k, _) => {
                            warn!("shielded import: helper {} failed its range ({e}); the range is re-queued", k);
                            queue.push_back(refresh_range(consensus, pruning_point, r).await?);
                        }
                    }
                }
                Err(RunError::Refused(e)) => {
                    // The staging refused this source's data and is gone; every other run fails now.
                    self.ctx.shielded_import_suspects().record_failure(pruning_point, [key]);
                    if failure.is_none() {
                        failure = Some(e.into());
                    }
                    queue.clear();
                }
            }
            if failure.is_some() {
                // Drain: the other runs end by themselves (helpers notice the dropped channels).
                queue.clear();
            }
            if queue.is_empty() && running.is_empty() {
                break;
            }
            if !queue.is_empty() && idle.is_empty() && running.is_empty() {
                // Every source was dropped or failed: the coordinator takes over (it is never dropped).
                if route_slot.is_some() {
                    idle.push(Source::Coordinator);
                } else {
                    break;
                }
            }
        }
        drop(running);
        if let Some(e) = failure {
            return Err(e);
        }
        if !queue.is_empty() {
            return Err(ProtocolError::Other("shielded import: no source left for the remaining ranges"));
        }
        let mut used: Vec<PeerKey> = used.into_iter().collect();
        if used.is_empty() {
            used.push(me);
        }
        Ok(used)
    }
}

/// The current resume point of range `r` (after a run that staged part of it).
async fn refresh_range(consensus: &ConsensusProxy, pruning_point: Hash, r: ShieldedImportRange) -> Result<ShieldedImportRange, ProtocolError> {
    let ranges = consensus.async_get_pruning_point_shielded_import_ranges(pruning_point).await;
    Ok(ranges.and_then(|rs| rs.into_iter().find(|x| x.range == r.range)).unwrap_or(r))
}

/// The staging side of one range run: a blocking task fed through a channel, plus the rate meter.
struct RangeStager {
    tx: Option<tokio::sync::mpsc::Sender<Vec<[u8; 32]>>>,
    task: tokio::task::JoinHandle<Result<u64, PruningImportError>>,
    meter: ImportRateMeter,
    who: PeerKey,
}

impl RangeStager {
    fn start(consensus: &ConsensusProxy, pruning_point: Hash, r: ShieldedImportRange, who: PeerKey) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(STAGING_CHANNEL_CHUNKS);
        let c = consensus.clone();
        let task =
            tokio::task::spawn_blocking(move || c.stage_pruning_point_shielded_nullifiers(pruning_point, ShieldedStreamScope::Range(r.range), rx));
        Self { tx: Some(tx), task, meter: ImportRateMeter::new(Instant::now()), who }
    }

    /// Hand one chunk to the staging and apply the rate rules. `Some(end)` stops the run: the
    /// staging stopped (its verdict comes from [`Self::finish`]) or the source was dropped for rate.
    async fn push(&mut self, chunk: Vec<[u8; 32]>, board: &parking_lot::Mutex<RateBoard>) -> Option<RunEnd> {
        let window = self.meter.record(chunk.len() as u64 * 32, Instant::now());
        if self.tx.as_ref().expect("open").send(chunk).await.is_err() {
            return Some(RunEnd::Complete);
        }
        let rate = window?;
        let verdict = board.lock().verdict(self.who, rate);
        if verdict == RateVerdict::Keep {
            return None;
        }
        let best = board.lock().best;
        warn!("shielded import: source {} delivers {:.0} B/s (best {:.0} B/s, {:?}); its range goes to another source", self.who, rate, best, verdict);
        Some(RunEnd::DroppedForRate)
    }

    /// Close the channel and read the staging's verdict.
    async fn finish(mut self) -> Result<u64, RunError> {
        drop(self.tx.take());
        match self.task.await {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(RunError::Refused(e)),
            Err(e) => Err(RunError::Source(ProtocolError::OtherOwned(format!("shielded staging task panicked: {e}")))),
        }
    }
}

async fn run_coordinator_range<'r>(
    router: &Arc<Router>,
    route: &'r mut IncomingRoute,
    consensus: &ConsensusProxy,
    pruning_point: Hash,
    r: ShieldedImportRange,
    board: &parking_lot::Mutex<RateBoard>,
    me: PeerKey,
) -> (Result<RunEnd, RunError>, &'r mut IncomingRoute) {
    let res = async {
        let mut stream = ShieldedRangeStream::request(router, &mut *route, pruning_point, r.from, r.before, false)
            .await
            .map_err(RunError::Source)?;
        let mut stager = RangeStager::start(consensus, pruning_point, r, me);
        let mut end = RunEnd::Complete;
        let streamed: Result<(), ProtocolError> = async {
            while let Some(chunk) = stream.next_chunk().await? {
                if let Some(e) = stager.push(chunk, board).await {
                    end = e;
                    break;
                }
            }
            Ok(())
        }
        .await;
        stager.finish().await?;
        streamed.map_err(RunError::Source)?;
        if let RunEnd::DroppedForRate = end {
            // Its stream is abandoned mid-range, so this route can no longer be read in order.
            return Ok(RunEnd::DroppedForRate);
        }
        if !stream.is_done() {
            return Err(RunError::Source(ProtocolError::Other("shielded range stream abandoned before its end")));
        }
        Ok(RunEnd::Complete)
    }
    .await;
    (res, route)
}

async fn run_helper_range(
    sender: tokio::sync::mpsc::Sender<ShieldedRangeJob>,
    consensus: &ConsensusProxy,
    pruning_point: Hash,
    r: ShieldedImportRange,
    board: &parking_lot::Mutex<RateBoard>,
    who: PeerKey,
) -> Result<RunEnd, RunError> {
    let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<Vec<[u8; 32]>>(STAGING_CHANNEL_CHUNKS);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let job = ShieldedRangeJob { pruning_point, from: r.from, before: r.before, chunks: chunk_tx, done: done_tx };
    if sender.try_send(job).is_err() {
        return Err(RunError::Unavailable);
    }
    let mut stager = RangeStager::start(consensus, pruning_point, r, who);
    let mut end = RunEnd::Complete;
    while let Some(chunk) = chunk_rx.recv().await {
        if let Some(e) = stager.push(chunk, board).await {
            end = e;
            break;
        }
    }
    // Drop our side first, so an abandoned helper stops at its next send and closes its link.
    drop(chunk_rx);
    let done = done_rx.await.unwrap_or(Ok(false));
    stager.finish().await?;
    match end {
        RunEnd::DroppedForRate => Ok(RunEnd::DroppedForRate),
        RunEnd::Complete => match done {
            Ok(true) => Ok(RunEnd::Complete),
            Ok(false) => Err(RunError::Source(ProtocolError::Other("shielded range abandoned"))),
            Err(e) => Err(RunError::Source(e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> PeerKey {
        PeerKey::new(kaspa_utils::networking::PeerId::new(uuid::Uuid::from_u128(i as u128)), std::net::IpAddr::from([127, 0, 0, i]).into())
    }

    #[test]
    fn suspects_reset_with_the_pruning_point_and_accumulate_within_it() {
        let mut s = ShieldedImportSuspects::default();
        let (a, b) = (key(1), key(2));
        let (pp1, pp2): (Hash, Hash) = (1.into(), 2.into());
        assert_eq!(s.for_pruning_point(pp1).0, 0);
        s.record_failure(pp1, [a]);
        s.record_failure(pp1, [b]);
        let (f, peers) = s.for_pruning_point(pp1);
        assert_eq!(f, SINGLE_SOURCE_AFTER_FAILURES, "two failures => single-source");
        assert!(peers.contains(&a) && peers.contains(&b));
        let (f, peers) = s.for_pruning_point(pp2);
        assert_eq!(f, 0, "a new pruning point starts clean");
        assert!(peers.is_empty());
    }

    #[test]
    fn a_slow_source_is_dropped_only_while_another_source_is_active() {
        let k = key;
        let mut b = RateBoard::default();
        // Alone: a source at 1 B/s is kept (the last active source is never dropped for rate).
        assert_eq!(b.verdict(k(1), 1.0), RateVerdict::Keep);
        // A second, fast source appears: the slow one is now dropped.
        assert_eq!(b.verdict(k(2), 4.0e6), RateVerdict::Keep);
        assert_eq!(b.verdict(k(1), 1.0), RateVerdict::DropAbsolute);
        assert_eq!(b.verdict(k(1), 1.5e6), RateVerdict::DropRelative, "below half the best");
        assert_eq!(b.verdict(k(1), 2.5e6), RateVerdict::Keep);
        // When the other source leaves, the slow one is the last and is kept.
        b.active.remove(&k(2));
        assert_eq!(b.verdict(k(1), 1.0), RateVerdict::Keep, "the last active source is never dropped");
    }
}
