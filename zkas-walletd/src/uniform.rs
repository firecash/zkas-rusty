//! Stage W of uniform transactions in walletd (spec 02 §3.1; 15 A1/A5/A6).
//!
//! Every transaction built here has the one uniform shape (4 actions, fee exactly
//! `UNIFORM_FEE_V1`, flags 0x0b, lock_time 0, anchor at the newest matured epoch opener) and is
//! released at a time drawn by `zkas_wallet_engine::schedule`, never by a timer:
//!
//! - `POST /api/wallet/uniform/send`: an interactive payment. Built right after the call
//!   (the confirm), held `U[0, W]` by hold mode, split into ≤ 8 siblings released independently
//!   over `max(W, 4k²/λ̂)` when it needs more than 4 notes, re-proved at release if the anchor
//!   epoch rolled meanwhile. More than 8 siblings: 409 `needs_consolidation`.
//! - `POST /api/wallet/uniform/send_many`: payouts and withdrawals, one payee per transaction,
//!   each released at an i.i.d. uniform time inside the caller's window (default 300 s, the desk
//!   window of W10). Replaces the batch-then-sleep loop shape.
//! - `POST /api/wallet/uniform/consolidate`: one 4 -> 1 merge.
//! - `GET /api/wallet/uniform/scheduled`: what this wallet has scheduled and released.
//! - `GET /api/uniform/anchor`: the anchor a uniform spend would use now, and the network rate
//!   estimate, so a non-custodial client holding a signed payment can tell when to re-prepare.
//! - the background merger (W9), when the operator enables it: Poisson-timed 4 -> 1 merges for
//!   custodial wallets above 8 notes, never within 600 s of the wallet's own payments, and
//!   urgent merges (Exp(30 s) gaps) for a payment that needed consolidation first.
//!
//! **Defaults (memory dont-change-privacy-defaults).** Nothing here changes what an existing
//! endpoint does unless the operator turns it on: [`UniformPolicy`] is all-off by default. With
//! `enabled`, the legacy `/send`, `/send_many` and `/consolidate` route here (and block until
//! every transaction is released, so their response shape is unchanged). `internal_change` and
//! `merge` are separate switches because each changes something an owner must decide.

use super::*;
use kaspa_shielded_core::wallet::build::{SendShape, build_wallet_payment_multi_shaped};
use zkas_wallet_engine::schedule::{
    self, DESK_RELEASE_WINDOW_MS, HoldMode, URGENT_MERGE_MEAN_MS, merge_allowed_at, merge_rate_per_s, poisson_next,
    sibling_release_times,
};
use zkas_wallet_engine::uniform::{
    AnchorRule, MAX_SIBLINGS, MERGE_TRIGGER_NOTES, UNIFORM_FEE_V1, UniformPlanError, check_uniform_payload, plan_merge,
    plan_uniform_payment, plan_urgent_merges,
};

static ANCHOR_RULE: std::sync::RwLock<AnchorRule> = std::sync::RwLock::new(AnchorRule::MAINNET);

/// Set the anchor-epoch rule for this daemon's network (from `serve`).
pub(crate) fn set_anchor_rule(r: AnchorRule) {
    *ANCHOR_RULE.write().unwrap_or_else(|e| e.into_inner()) = r;
}

pub(crate) fn anchor_rule() -> AnchorRule {
    *ANCHOR_RULE.read().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------

/// The operator's Stage W switches. All off by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniformPolicy {
    /// `uniform_v1`: route the legacy send endpoints through Stage W (uniform shape, scheduled
    /// release). Off by default: it changes the fee of a 1-note payment (+117,800 sompi), the
    /// latency of every send (mean +60 s at the standard hold) and splits large payments.
    pub enabled: bool,
    /// Change to the internal address (B1). Off by default: wallets that do not run the spec 11
    /// R4 trigger scan (any client older than this release, the deployed phone signer's verifier)
    /// would not see it.
    pub internal_change: bool,
    /// Default hold of interactive sends.
    pub hold: HoldMode,
    /// W9 background merges (Poisson, trigger 8 notes). Off by default: it spends custodial
    /// wallets' fees on their behalf; replaces the legacy 500-note / 60-s merger when on.
    pub merge: bool,
}

impl UniformPolicy {
    pub const OFF: UniformPolicy = UniformPolicy { enabled: false, internal_change: false, hold: HoldMode::Standard, merge: false };

    fn shape(&self) -> SendShape {
        if self.internal_change { SendShape::UNIFORM_INTERNAL } else { SendShape::UNIFORM }
    }
}

impl Default for UniformPolicy {
    fn default() -> Self {
        Self::OFF
    }
}

static POLICY: std::sync::RwLock<UniformPolicy> = std::sync::RwLock::new(UniformPolicy::OFF);

/// Set the process-wide Stage W policy (from the CLI). Kept out of [`Config`] so the embedders
/// that build `Config` by struct literal (walletd-mobile) keep compiling.
pub fn set_uniform_policy(p: UniformPolicy) {
    *POLICY.write().unwrap_or_else(|e| e.into_inner()) = p;
}

/// The current Stage W policy.
pub fn uniform_policy() -> UniformPolicy {
    *POLICY.read().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------------------------
// λ̂ from the blocks walletd already decodes
// ---------------------------------------------------------------------------------------------

static RECENT_BLOCKS: std::sync::Mutex<std::collections::BTreeMap<u64, (u64, usize)>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

const LAMBDA_SPAN_MS: u64 = 3_600_000;

/// Longest release window a caller may ask for (`release_window_s`): one day.
const MAX_RELEASE_WINDOW_S: u64 = 86_400;

/// Record a decoded chain block's accepted user transactions for λ̂ (W8). Keyed by blue score, so
/// the same block decoded for many wallets counts once.
pub(crate) fn note_block_txs(blue: u64, timestamp_ms: u64, txs: usize) {
    if timestamp_ms == 0 {
        return;
    }
    let mut m = RECENT_BLOCKS.lock().unwrap_or_else(|e| e.into_inner());
    m.insert(blue, (timestamp_ms, txs));
    // Blue-score order is time order, so the newest block is the last key and stale entries sit
    // at the front: pop them, O(log n + stale) per call. A full max + retain over every entry
    // here ran on every decoded block, under this mutex, and serialised mass-rescan decoding.
    let newest = m.values().next_back().map_or(0, |v| v.0).max(timestamp_ms);
    while let Some((&first, &(ts, _))) = m.iter().next() {
        if ts.saturating_add(LAMBDA_SPAN_MS) >= newest && m.len() <= 20_000 {
            break;
        }
        m.remove(&first);
    }
}

/// λ̂, transactions per second over the last hour of decoded chain (floored).
fn lambda_now() -> f64 {
    let m = RECENT_BLOCKS.lock().unwrap_or_else(|e| e.into_inner());
    let (lo, hi) = m.values().fold((u64::MAX, 0u64), |(l, h), v| (l.min(v.0), h.max(v.0)));
    if hi <= lo {
        return schedule::LAMBDA_FLOOR_PER_S;
    }
    schedule::lambda_hat(m.values().map(|v| v.1).sum(), hi - lo)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn os_u64() -> u64 {
    use rand::RngCore;
    rand::rngs::OsRng.next_u64()
}

// ---------------------------------------------------------------------------------------------
// Anchor
// ---------------------------------------------------------------------------------------------

/// The anchor a uniform spend uses: the newest matured epoch opener (01 E-R2 W4').
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnchorChoice {
    pub blue: u64,
    pub leaves: u64,
    pub block: [u8; 32],
}

pub(crate) enum PickErr {
    Wait(u64),
    Fail((StatusCode, Json<serde_json::Value>)),
}

fn chain_blue(e: &WalletEntry) -> Vec<u64> {
    e.boundaries.iter().map(|b| b.0).collect()
}

pub(crate) fn pick_anchor(e: &WalletEntry) -> Result<AnchorChoice, PickErr> {
    let p = anchor_rule().pick(&chain_blue(e), e.sink_blue);
    let Some((i, blue)) = p.ready() else {
        return Err(match p.wait_blue {
            Some(w) => PickErr::Wait(w),
            None => PickErr::Fail(err(StatusCode::CONFLICT, "no matured epoch opener in this wallet's view yet; retry after a few minutes of sync")),
        });
    };
    let leaves = e.boundaries[i].1;
    match e.anchor_block_at_blue(Some(blue)).map_err(PickErr::Fail)? {
        Some(block) => Ok(AnchorChoice { blue, leaves, block }),
        None => Err(PickErr::Fail(err(
            StatusCode::CONFLICT,
            "uniform transactions name their anchor block, which this network only accepts after its security fork",
        ))),
    }
}

/// [`pick_anchor`], waiting out a near-boundary or chain-jump hold (≤ ~2 min in total).
pub(crate) async fn pick_anchor_waiting(w: &Wallet) -> Result<AnchorChoice, (StatusCode, Json<serde_json::Value>)> {
    for _ in 0..6 {
        let r = { pick_anchor(&*w.lock().await) };
        match r {
            Ok(c) => return Ok(c),
            Err(PickErr::Fail(e)) => return Err(e),
            // One blue score is ~1.06 s at 0.945 blue/s.
            Err(PickErr::Wait(b)) => tokio::time::sleep(std::time::Duration::from_millis((b.min(25) * 1_100).max(500))).await,
        }
    }
    Err(err(StatusCode::SERVICE_UNAVAILABLE, "the anchor epoch is changing; retry in a minute"))
}

/// Witnesses for `positions` at `leaves`, shared tree first, own tree as the fallback.
fn witness_inputs(
    state: &AppState,
    e: &WalletEntry,
    positions: &[u64],
    leaves: u64,
) -> Result<Vec<(kaspa_shielded_core::Note, kaspa_shielded_core::MerklePath)>, (StatusCode, Json<serde_json::Value>)> {
    let paths = tokio::task::block_in_place(|| state.batch_witness_paths(&e.db, positions, leaves));
    let mut out = Vec::with_capacity(positions.len());
    for (k, &p) in positions.iter().enumerate() {
        let note = e
            .db
            .notes()
            .iter()
            .find(|n| n.position == p)
            .ok_or_else(|| err(StatusCode::CONFLICT, "a note this transaction holds was spent elsewhere"))?;
        let path = match paths.get(k).cloned().flatten() {
            Some(path) => path,
            None => tokio::task::block_in_place(|| e.db.witness_path_at(p, leaves))
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?,
        };
        out.push((note.note.clone(), path));
    }
    Ok(out)
}

/// The candidate notes of a uniform plan: matured, unreserved, non-zero (a zero-value change
/// note pays nothing and must not count against the 4-spend limit or the merge trigger).
/// A note worth no more than its share of a 4 -> 1 merge's fee is never merged, nor counted
/// toward the merge trigger (see `dust_floor_sompi`).
fn merge_dust_floor() -> u64 {
    UNIFORM_FEE_V1 / zkas_wallet_engine::uniform::MERGE_INPUTS as u64
}

#[cfg(test)]
pub(crate) fn merge_dust_floor_for_test() -> u64 {
    merge_dust_floor()
}

fn uniform_candidates<'a>(e: &'a WalletEntry, leaves: u64) -> Result<Vec<&'a OwnedNote>, (StatusCode, Json<serde_json::Value>)> {
    let (mut c, _stranded) = spend_candidates(e, leaves)?;
    c.retain(|n| n.value() > 0);
    Ok(c)
}

/// Hold `positions` against every other spend path until `for_how_long` has passed.
fn reserve(e: &mut WalletEntry, positions: &[u64], for_how_long: std::time::Duration) {
    let now = std::time::Instant::now();
    e.reserved.retain(|_, until| *until > now);
    for p in positions {
        e.reserved.insert(*p, now + for_how_long);
    }
}

pub(crate) fn reserve_pub(e: &mut WalletEntry, positions: &[u64], for_how_long: std::time::Duration) {
    reserve(e, positions, for_how_long)
}

pub(crate) fn witness_inputs_pub(
    state: &AppState,
    e: &WalletEntry,
    positions: &[u64],
    leaves: u64,
) -> Result<Vec<(kaspa_shielded_core::Note, kaspa_shielded_core::MerklePath)>, (StatusCode, Json<serde_json::Value>)> {
    witness_inputs(state, e, positions, leaves)
}

pub(crate) fn unreserve(e: &mut WalletEntry, positions: &[u64]) {
    for p in positions {
        e.reserved.remove(p);
    }
}

// ---------------------------------------------------------------------------------------------
// Building and releasing
// ---------------------------------------------------------------------------------------------

type Payees = Vec<([u8; 43], u64, [u8; 512])>;

/// Build one uniform transaction payload and check its envelope before it can leave.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_uniform_tx<R: rand10::rand_core::RngCore + rand10::rand_core::CryptoRng>(
    seed: [u8; 32],
    inputs: Vec<(kaspa_shielded_core::Note, kaspa_shielded_core::MerklePath)>,
    payees: &Payees,
    net: &[u8; 32],
    ctx: &[u8],
    recoverable: bool,
    anchor_block: [u8; 32],
    shape: SendShape,
    rng: &mut R,
) -> Result<Vec<u8>, String> {
    let payload =
        build_wallet_payment_multi_shaped(seed, inputs, payees, UNIFORM_FEE_V1, net, ctx, recoverable, Some(anchor_block), shape, rng)
            .map_err(|e| format!("failed to build uniform transaction: {e:?}"))?;
    check_uniform_payload(&payload).map_err(|v| format!("built transaction is not uniform: {v}"))?;
    Ok(payload)
}

/// One scheduled transaction.
struct Job {
    release_at_ms: u64,
    positions: Vec<u64>,
    payees: Payees,
    anchor_blue: u64,
    payload: Vec<u8>,
}

/// What `/uniform/scheduled` reports about one transaction.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct JobView {
    pub id: String,
    pub kind: &'static str,
    pub release_at_ms: u64,
    pub amount_sompi: u64,
    pub fee_sompi: u64,
    /// scheduled | released | outcome_unknown | failed. `outcome_unknown`: the connection to the
    /// node failed while it received the transaction (`txid` is set); its coins stay parked and
    /// come back on their own if it never lands. Never read it as "not paid".
    pub status: &'static str,
    pub txid: Option<String>,
    pub reproved: u32,
    pub error: Option<String>,
}

static JOBS: std::sync::Mutex<std::collections::BTreeMap<String, Vec<JobView>>> = std::sync::Mutex::new(std::collections::BTreeMap::new());
/// Release times of each wallet's payments (past and scheduled), for the W9 merge exclusion.
static PAYMENT_TIMES: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u64>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
/// Wallets with an urgent consolidation pending (W8 consolidate-first): token -> amount to cover.
static URGENT: std::sync::Mutex<std::collections::BTreeMap<String, u64>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

fn note_payment_times(token: &str, times: &[u64]) {
    let mut m = PAYMENT_TIMES.lock().unwrap_or_else(|e| e.into_inner());
    let v = m.entry(token.to_string()).or_default();
    let cutoff = now_ms().saturating_sub(schedule::PAYMENT_MERGE_EXCLUSION_MS);
    v.retain(|t| *t >= cutoff);
    v.extend_from_slice(times);
}

fn payment_times(token: &str) -> Vec<u64> {
    PAYMENT_TIMES.lock().unwrap_or_else(|e| e.into_inner()).get(token).cloned().unwrap_or_default()
}

fn update_view(token: &str, id: &str, f: impl FnOnce(&mut JobView)) {
    let mut m = JOBS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = m.get_mut(token).and_then(|v| v.iter_mut().find(|j| j.id == id)) {
        f(v);
    }
}

fn random_id() -> String {
    let mut b = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// Everything a release task needs.
struct Release {
    state: Arc<AppState>,
    w: Wallet,
    token: String,
    seed: [u8; 32],
    recoverable: bool,
    shape: SendShape,
}

/// A released transaction: accepted by the node, or broadcast with its answer lost
/// ([`Submitted::presumed`]) — which may have paid, so it is never reported as a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Released {
    Sent(String),
    Unknown(String),
}

impl Released {
    fn txid(&self) -> &str {
        match self {
            Released::Sent(t) | Released::Unknown(t) => t,
        }
    }
}

/// Release one job at its time: re-prove if the anchor epoch rolled (W5), submit, park the notes.
/// `Err` only when nothing went out (a refusal, or a failure before the broadcast).
async fn release_one(r: &Release, id: &str, mut job: Job) -> Result<Released, String> {
    let wait = job.release_at_ms.saturating_sub(now_ms());
    if wait > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
    }
    let net: [u8; 32] = r.state.genesis.as_bytes();
    let ctx = payment_tx_context();
    for attempt in 0..3u32 {
        let roll = {
            let e = r.w.lock().await;
            anchor_rule().needs_reanchor(job.anchor_blue, &chain_blue(&e), e.sink_blue)
        };
        if !roll {
            break;
        }
        // Re-prove at the new opener: same notes, same outputs, new witnesses and proof.
        let choice = pick_anchor_waiting(&r.w).await.map_err(|(_, b)| b.0.to_string())?;
        let inputs = {
            let e = r.w.lock().await;
            witness_inputs(&r.state, &e, &job.positions, choice.leaves).map_err(|(_, b)| b.0.to_string())?
        };
        let (seed, payees, shape, recoverable, net2, ctx2) = (r.seed, job.payees.clone(), r.shape, r.recoverable, net, ctx.clone());
        let payload = tokio::task::spawn_blocking(move || {
            let _proving = ProvingGuard::new();
            build_uniform_tx(seed, inputs, &payees, &net2, &ctx2, recoverable, choice.block, shape, &mut rand10::rng())
        })
        .await
        .map_err(|e| format!("proof task failed: {e}"))??;
        job.payload = payload;
        job.anchor_blue = choice.blue;
        update_view(&r.token, id, |v| v.reproved = attempt + 1);
        log::info!("uniform: re-proved scheduled tx {id} at anchor epoch {} (W5)", anchor_rule().epoch_of(choice.blue));
    }
    let tx: Transaction = payment_tx(job.payload);
    let client = r.state.request_client().await.ok_or("the wallet service cannot reach its node to broadcast")?;
    let pay: u64 = job.payees.iter().map(|p| p.1).sum();
    match submit_guarded(&r.state, &client, &tx).await {
        Ok(Submitted { id: accepted, presumed }) => {
            let mut e = r.w.lock().await;
            let now_daa = e.scanned as u64;
            for p in &job.positions {
                e.db.mark_spent(*p, accepted.as_bytes(), now_daa);
            }
            unreserve(&mut e, &job.positions);
            e.db.note_pending_outflow(accepted.as_bytes(), pay.saturating_add(UNIFORM_FEE_V1));
            e.forget_stale_outflow_previews();
            // Saved promptly: a restart must not forget the parked coins.
            e.force_checkpoint = true;
            if presumed {
                // Its coins stay parked (returned by the reclaim if it never lands): releasing them
                // as for a refusal would let the next payment spend coins that may already be gone.
                // Nor is it a failure: a caller told "failed" pays again while this one may land.
                log::warn!("uniform: OUTCOME UNKNOWN for scheduled tx {id} ({accepted}): the connection to the node failed while sending it");
                return Ok(Released::Unknown(accepted.to_string()));
            }
            Ok(Released::Sent(accepted.to_string()))
        }
        Err(err) => {
            let mut e = r.w.lock().await;
            unreserve(&mut e, &job.positions);
            Err(format!("node rejected the transaction: {err}"))
        }
    }
}

/// Run a schedule in release order; returns `(job index, txid or error)` for each.
async fn run_schedule(r: Release, ids: Vec<String>, jobs: Vec<Job>) -> Vec<(usize, Result<Released, String>)> {
    let mut order: Vec<(usize, Job)> = jobs.into_iter().enumerate().collect();
    order.sort_by_key(|(_, j)| j.release_at_ms);
    let mut out = Vec::with_capacity(order.len());
    // Each job sleeps to its own time; running them in one task in release order keeps the
    // daemon to one waiting task per payment.
    for (i, job) in order {
        let res = release_one(&r, &ids[i], job).await;
        match &res {
            Ok(Released::Sent(txid)) => update_view(&r.token, &ids[i], |v| {
                v.status = "released";
                v.txid = Some(txid.clone());
            }),
            Ok(Released::Unknown(txid)) => update_view(&r.token, &ids[i], |v| {
                v.status = "outcome_unknown";
                v.txid = Some(txid.clone());
                v.error = Some("the connection to the node failed while sending it; it may still land".into());
            }),
            Err(e) => {
                log::warn!("uniform: scheduled tx {} failed: {e}", ids[i]);
                update_view(&r.token, &ids[i], |v| {
                    v.status = "failed";
                    v.error = Some(e.clone());
                })
            }
        }
        out.push((i, res));
    }
    out
}

/// Planned transactions before building: notes, payees (with their request index), release time.
struct Planned {
    positions: Vec<u64>,
    payees: Payees,
    payee_index: Vec<usize>,
    release_at_ms: u64,
    kind: &'static str,
}

/// Build every planned transaction at `choice`, register views, and spawn (or await) the
/// releases. Notes are reserved before this is called.
async fn build_and_schedule(
    rel: Release,
    choice: AnchorChoice,
    planned: Vec<Planned>,
    wait: bool,
) -> Result<(Vec<JobView>, Option<Vec<(usize, Result<Released, String>)>>), (StatusCode, Json<serde_json::Value>)> {
    let net: [u8; 32] = rel.state.genesis.as_bytes();
    let ctx = payment_tx_context();
    let mut jobs = Vec::with_capacity(planned.len());
    let mut views = Vec::with_capacity(planned.len());
    for p in planned {
        let inputs = {
            let e = rel.w.lock().await;
            witness_inputs(&rel.state, &e, &p.positions, choice.leaves)?
        };
        let (seed, payees, shape, recoverable, net2, ctx2) = (rel.seed, p.payees.clone(), rel.shape, rel.recoverable, net, ctx.clone());
        let built = tokio::task::spawn_blocking(move || {
            let _proving = ProvingGuard::new();
            build_uniform_tx(seed, inputs, &payees, &net2, &ctx2, recoverable, choice.block, shape, &mut rand10::rng())
        })
        .await;
        let payload = match built {
            Ok(Ok(p)) => p,
            failed => {
                // Nothing was scheduled: free every note this plan held.
                let msg = match failed {
                    Ok(Err(e)) => e,
                    Err(e) => format!("proof task failed: {e}"),
                    Ok(Ok(_)) => unreachable!(),
                };
                let mut e2 = rel.w.lock().await;
                let all: Vec<u64> = jobs.iter().flat_map(|j: &Job| j.positions.clone()).chain(p.positions.iter().copied()).collect();
                unreserve(&mut e2, &all);
                return Err(err(StatusCode::INTERNAL_SERVER_ERROR, msg));
            }
        };
        let amount: u64 = p.payees.iter().map(|x| x.1).sum();
        views.push(JobView {
            id: random_id(),
            kind: p.kind,
            release_at_ms: p.release_at_ms,
            amount_sompi: amount,
            fee_sompi: UNIFORM_FEE_V1,
            status: "scheduled",
            txid: None,
            reproved: 0,
            error: None,
        });
        jobs.push(Job { release_at_ms: p.release_at_ms, positions: p.positions, payees: p.payees, anchor_blue: choice.blue, payload });
    }
    {
        let mut m = JOBS.lock().unwrap_or_else(|e| e.into_inner());
        let v = m.entry(rel.token.clone()).or_default();
        v.retain(|j| j.status == "scheduled" || j.release_at_ms + 86_400_000 > now_ms());
        v.extend(views.iter().cloned());
    }
    if views.iter().any(|v| v.kind != "merge") {
        note_payment_times(&rel.token, &views.iter().map(|v| v.release_at_ms).collect::<Vec<_>>());
    }
    let ids: Vec<String> = views.iter().map(|v| v.id.clone()).collect();
    let token = rel.token.clone();
    let handle = tokio::spawn(run_schedule(rel, ids, jobs));
    if wait {
        let res = handle.await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("release task failed: {e}")))?;
        // Report what happened, not the schedule as it stood before the releases.
        let ids: HashSet<&str> = views.iter().map(|v| v.id.as_str()).collect();
        let now_views: Vec<JobView> = JOBS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&token)
            .map(|v| v.iter().filter(|j| ids.contains(j.id.as_str())).cloned().collect())
            .unwrap_or(views);
        Ok((now_views, Some(res)))
    } else {
        Ok((views, None))
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct USendReq {
    pub to: String,
    pub amount_sompi: Option<JsonU64>,
    pub amount_fc: Option<f64>,
    pub memo: Option<String>,
    /// immediate | standard | private (W11). Default: the operator's policy (standard).
    pub hold: Option<String>,
    /// Block until every transaction is released and return the txids.
    pub wait: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct USendResp {
    pub transactions: Vec<JobView>,
    pub siblings: usize,
    pub fee_sompi_each: u64,
    pub total_fee_sompi: u64,
    pub txids: Vec<String>,
}

fn parse_hold(h: Option<&str>) -> Result<HoldMode, (StatusCode, Json<serde_json::Value>)> {
    match h {
        None => Ok(uniform_policy().hold),
        Some(s) => HoldMode::parse(s).ok_or_else(|| err(StatusCode::BAD_REQUEST, "hold must be immediate, standard or private")),
    }
}

fn needs_consolidation(token: &str, siblings: usize, amount: u64) -> (StatusCode, Json<serde_json::Value>) {
    let merging = uniform_policy().merge;
    if merging {
        URGENT.lock().unwrap_or_else(|e| e.into_inner()).insert(token.to_string(), amount);
    }
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": UniformPlanError::NeedsConsolidation { siblings }.to_string(),
            "needs_consolidation": true,
            "siblings": siblings,
            "max_siblings": MAX_SIBLINGS,
            "merging": merging,
        })),
    )
}

/// The common front of every custodial uniform spend: wallet, seed, gate, anchor.
async fn custodial_front(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(String, Wallet, [u8; 32], bool), (StatusCode, Json<serde_json::Value>)> {
    require_custodial(state)?;
    let token = token_from(headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    ensure_canonical_checkpoint(state, &w).await?;
    let (seed, recoverable) = {
        let e = w.lock().await;
        if e.reorged_strikes > 0 {
            return Err(err(StatusCode::CONFLICT, "wallet checkpoint is being repaired after a reorg; retry shortly"));
        }
        (e.key.seed()?, e.recoverable_history && !private_sends(&state.wallet_dir, &token))
    };
    Ok((token, w, seed, recoverable))
}

/// Plan one payee's payment over `candidates` (not yet used), returning sibling note positions
/// and amounts.
fn plan_one(candidates: &[&OwnedNote], used: &HashSet<u64>, amount: u64) -> Result<Vec<(Vec<u64>, u64)>, UniformPlanError> {
    let free: Vec<&OwnedNote> = candidates.iter().copied().filter(|n| !used.contains(&n.position)).collect();
    let plan = plan_uniform_payment(free.iter().map(|n| n.value()).collect(), amount)?;
    // The plan sorted VALUES; map back to notes through the same order.
    let mut order: Vec<&OwnedNote> = free.clone();
    let target = zkas_wallet_engine::uniform::uniform_single_note_target(amount);
    order.sort_unstable_by_key(|n| spend_order_key(n.value(), target));
    debug_assert!(order.iter().map(|n| n.value()).eq(plan.sorted_note_values.iter().copied()));
    Ok(plan.siblings.iter().map(|s| (s.notes.iter().map(|&i| order[i].position).collect(), s.amount)).collect())
}

/// What the legacy `/send` and `/send_many` bring to a uniform spend that the uniform endpoints do
/// not: the caller's request id (as the record key, see `sent_request_key`) and its fee ceiling.
#[derive(Default)]
pub(crate) struct LegacyTerms {
    pub request_key: Option<String>,
    pub max_total_fee: Option<u64>,
}

impl LegacyTerms {
    /// Under the wallet's send gate: a retry racing its original waits for it, then finds it here.
    fn refuse_if_sent(&self, what: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        if let Some(done) = self.request_key.as_deref().and_then(sent_request) {
            log::info!("uniform {what}: request already broadcast as {}; returning it instead of paying again", done.txid);
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": format!("this {what} was already sent (transaction {})", done.txid), "already_sent": done })),
            ));
        }
        Ok(())
    }

    /// Refused before anything is reserved or proved, as the legacy paths refuse it.
    fn check_fee(&self, txs: usize, what: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        let planned_fee = UNIFORM_FEE_V1.saturating_mul(txs as u64);
        match self.max_total_fee {
            Some(cap) if planned_fee > cap => Err(err(
                StatusCode::CONFLICT,
                format!(
                    "this {what} needs {txs} uniform transactions and would pay {planned_fee} sompi in fees, over the {cap} sompi \
                     ceiling; consolidate first or raise max_total_fee"
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Remember what went out (accepted or possibly accepted), so a retry is answered, never paid
    /// again. Nothing is recorded when nothing went out: a retry then pays, as it must.
    fn record(&self, txids: &[String], sent: u64) {
        if let (Some(k), Some(first)) = (self.request_key.as_ref(), txids.first()) {
            let fee = UNIFORM_FEE_V1.saturating_mul(txids.len() as u64);
            record_sent_request(
                k.clone(),
                &SendResp {
                    txid: first.clone(),
                    amount_sompi: sent,
                    fee_sompi: fee,
                    amount_sompi_exact: sent.to_string(),
                    fee_sompi_exact: fee.to_string(),
                    txids: txids.to_vec(),
                    tx_count: txids.len(),
                },
            );
        }
    }
}

/// The outcome of a waited-for schedule, in release order: every transaction that went out or may
/// have (`txids`, with `sent` their amounts), the first whose answer was lost, the first refusal.
struct Settled {
    txids: Vec<String>,
    sent: u64,
    unknown: Option<String>,
    refused: Option<String>,
}

fn settle(views: &[JobView], results: &[(usize, Result<Released, String>)]) -> Settled {
    let mut out = Settled { txids: Vec::new(), sent: 0, unknown: None, refused: None };
    for (i, res) in results {
        match res {
            Ok(rel) => {
                out.txids.push(rel.txid().to_string());
                out.sent = out.sent.saturating_add(views.get(*i).map_or(0, |v| v.amount_sompi));
                if let (Released::Unknown(t), None) = (rel, &out.unknown) {
                    out.unknown = Some(t.clone());
                }
            }
            Err(e) => {
                if out.refused.is_none() {
                    out.refused = Some(e.clone());
                }
            }
        }
    }
    out
}

pub(crate) async fn send_core(
    state: Arc<AppState>,
    headers: HeaderMap,
    to: String,
    amount: u64,
    memo: [u8; 512],
    hold: HoldMode,
    wait: bool,
    terms: LegacyTerms,
) -> Result<USendResp, (StatusCode, Json<serde_json::Value>)> {
    if amount == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "amount must be positive"));
    }
    let to_addr = Address::try_from(to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr).ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let (token, w, seed, recoverable) = custodial_front(&state, &headers).await?;
    let gate = state.send_gate(&token).await;
    let _spending = gate.lock().await;
    terms.refuse_if_sent("payment")?;
    await_consolidation_clear().await;
    build_send_cache_off_lock(&state, &token, &w).await;
    let choice = pick_anchor_waiting(&w).await?;
    let confirmed = now_ms();
    let planned = {
        let mut e = w.lock().await;
        let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
        let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
        tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded(shared_covers, shared_base));
        let cands = uniform_candidates(&e, choice.leaves)?;
        let siblings = match plan_one(&cands, &HashSet::new(), amount) {
            Ok(s) => s,
            Err(UniformPlanError::NeedsConsolidation { siblings }) => return Err(needs_consolidation(&token, siblings, amount)),
            Err(e) => return Err(err(StatusCode::CONFLICT, format!("{e} (funds must be ~10 min old to spend)"))),
        };
        terms.check_fee(siblings.len(), "payment")?;
        let times = sibling_release_times(siblings.len(), confirmed, lambda_now(), hold, &mut os_u64);
        let last = *times.last().unwrap_or(&confirmed);
        let positions: Vec<u64> = siblings.iter().flat_map(|s| s.0.clone()).collect();
        // Held until released, plus room for re-proves and a slow node.
        reserve(&mut e, &positions, std::time::Duration::from_millis(last - confirmed + 3_600_000));
        siblings
            .into_iter()
            .zip(times)
            .enumerate()
            .map(|(k, ((pos, amt), t))| Planned {
                positions: pos,
                // The memo rides on the first sibling only (today's rule).
                payees: vec![(recipient, amt, if k == 0 { memo } else { [0u8; 512] })],
                payee_index: vec![0],
                release_at_ms: t,
                kind: "payment",
            })
            .collect::<Vec<_>>()
    };
    let k = planned.len();
    let rel = Release { state: state.clone(), w: w.clone(), token: token.clone(), seed, recoverable, shape: uniform_policy().shape() };
    let (views, results) = build_and_schedule(rel, choice, planned, wait).await?;
    let txids = match results {
        Some(r) => {
            let o = settle(&views, &r);
            terms.record(&o.txids, o.sent);
            // A lost answer first: whatever else happened, the caller must not pay this again.
            if let Some(t) = &o.unknown {
                let mut body = submit_outcome_unknown_body(t, "payment");
                body["txids"] = serde_json::json!(o.txids);
                body["sent_sompi"] = serde_json::json!(o.sent);
                return Err((StatusCode::GATEWAY_TIMEOUT, Json(body)));
            }
            if let Some(e) = &o.refused {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("payment partially sent: {}/{k} txs accepted: {e}", o.txids.len()),
                        "txids": o.txids,
                        "sent_sompi": o.sent,
                        "sent_sompi_exact": o.sent.to_string(),
                    })),
                ));
            }
            o.txids
        }
        None => Vec::new(),
    };
    Ok(USendResp { transactions: views, siblings: k, fee_sompi_each: UNIFORM_FEE_V1, total_fee_sompi: UNIFORM_FEE_V1 * k as u64, txids })
}

fn parse_amount(s: Option<&JsonU64>, fc: Option<f64>) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
    match (s, fc) {
        (Some(s), _) => s.parse("amount_sompi"),
        (None, Some(fc)) => Ok((fc * SOMPI_PER_ZKAS as f64).round() as u64),
        (None, None) => Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    }
}

/// `POST /api/wallet/uniform/send`.
pub(crate) async fn send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<USendReq>,
) -> Result<Json<USendResp>, (StatusCode, Json<serde_json::Value>)> {
    let amount = parse_amount(req.amount_sompi.as_ref(), req.amount_fc)?;
    let memo = memo_bytes(req.memo.as_deref())?;
    let hold = parse_hold(req.hold.as_deref())?;
    send_core(state, headers, req.to, amount, memo, hold, req.wait.unwrap_or(false), LegacyTerms::default()).await.map(Json)
}

/// The legacy `/api/wallet/send` under `uniform_v1`: same request, same response, Stage W inside.
/// A legacy caller cannot ask for a fee or a fee ceiling below F; a `fee` above F is ignored
/// (the fee is exact), a `max_total_fee` below the plan's total is refused.
pub(crate) async fn legacy_send(state: Arc<AppState>, headers: HeaderMap, req: SendReq) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    let memo = memo_bytes(req.memo.as_deref())?;
    // The same record key as `wallet_send`, so the request id keeps its meaning whichever mode the
    // daemon runs in (and across a switch between them).
    let token = token_from(&headers, state.allow_default_token)?;
    let request_key = req.request_id.as_deref().and_then(|id| sent_request_key(&format!("custodial:{token}"), id, &send_fingerprint(&req)));
    let terms = LegacyTerms { request_key, max_total_fee: req.max_total_fee };
    let r = send_core(state, headers, req.to, amount, memo, uniform_policy().hold, true, terms).await?;
    Ok(Json(SendResp {
        txid: r.txids.first().cloned().unwrap_or_default(),
        amount_sompi: amount,
        fee_sompi: r.total_fee_sompi,
        amount_sompi_exact: amount.to_string(),
        fee_sompi_exact: r.total_fee_sompi.to_string(),
        tx_count: r.txids.len(),
        txids: r.txids,
    }))
}

#[derive(Deserialize)]
pub(crate) struct USendManyReq {
    pub payees: Vec<Payee>,
    /// Release window: every transaction goes out at an i.i.d. uniform time in
    /// `[now, now + release_window_s]` (W10). Default 300 s (desk withdrawals); a pool passes its
    /// payout cycle.
    pub release_window_s: Option<u64>,
    pub wait: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct USendManyResp {
    pub transactions: Vec<JobView>,
    pub payee_txids: Vec<PayeeTxid>,
    pub total_fee_sompi: u64,
}

pub(crate) async fn send_many_core(
    state: Arc<AppState>,
    headers: HeaderMap,
    payees: Vec<Payee>,
    window_ms: u64,
    wait: bool,
    terms: LegacyTerms,
) -> Result<(USendManyResp, ManyOutcome), (StatusCode, Json<serde_json::Value>)> {
    if payees.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "payees must not be empty"));
    }
    let mut resolved: Payees = Vec::with_capacity(payees.len());
    for (i, p) in payees.iter().enumerate() {
        let amount = parse_amount(p.amount_sompi.as_ref(), p.amount_fc)?;
        if amount == 0 {
            return Err(err(StatusCode::BAD_REQUEST, format!("payee {i}: amount must be positive")));
        }
        let addr = Address::try_from(p.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("payee {i}: invalid address: {e}")))?;
        let r = orchard_recipient_bytes(&addr).ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("payee {i}: not a shielded Orchard address")))?;
        resolved.push((r, amount, memo_bytes(p.memo.as_deref())?));
    }
    let (token, w, seed, recoverable) = custodial_front(&state, &headers).await?;
    let gate = state.send_gate(&token).await;
    let _spending = gate.lock().await;
    terms.refuse_if_sent("payout")?;
    await_consolidation_clear().await;
    build_send_cache_off_lock(&state, &token, &w).await;
    let choice = pick_anchor_waiting(&w).await?;
    let start = now_ms();
    let planned = {
        let mut e = w.lock().await;
        let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
        let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
        tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded(shared_covers, shared_base));
        let cands = uniform_candidates(&e, choice.leaves)?;
        let mut used: HashSet<u64> = HashSet::new();
        let mut planned = Vec::new();
        for (i, (r, amount, memo)) in resolved.iter().enumerate() {
            // One payee per transaction (W10); a payee that needs more than 4 notes gets siblings.
            let sibs = match plan_one(&cands, &used, *amount) {
                Ok(s) => s,
                Err(UniformPlanError::NeedsConsolidation { siblings }) => return Err(needs_consolidation(&token, siblings, *amount)),
                Err(e) => return Err(err(StatusCode::CONFLICT, format!("payee {i}: {e} (funds must be ~10 min old to spend)"))),
            };
            for (k, (pos, amt)) in sibs.into_iter().enumerate() {
                used.extend(pos.iter().copied());
                planned.push(Planned {
                    positions: pos,
                    payees: vec![(*r, amt, if k == 0 { *memo } else { [0u8; 512] })],
                    payee_index: vec![i],
                    release_at_ms: 0,
                    kind: "payout",
                });
            }
        }
        terms.check_fee(planned.len(), "payout")?;
        // i.i.d. uniform times over the window, assigned in a random order: no tick gates a send.
        let times = schedule::release_times(planned.len(), start, start.saturating_add(window_ms), &mut os_u64);
        let mut slots: Vec<(u64, usize)> = (0..planned.len()).map(|i| (os_u64(), i)).collect();
        slots.sort_unstable();
        for (t, (_, i)) in times.into_iter().zip(slots) {
            planned[i].release_at_ms = t;
        }
        let positions: Vec<u64> = used.into_iter().collect();
        reserve(&mut e, &positions, std::time::Duration::from_millis(window_ms.saturating_add(3_600_000)));
        planned
    };
    let payee_of: Vec<usize> = planned.iter().map(|p| p.payee_index[0]).collect();
    let rel = Release { state: state.clone(), w: w.clone(), token, seed, recoverable, shape: uniform_policy().shape() };
    let (views, results) = build_and_schedule(rel, choice, planned, wait).await?;
    // A payee is paid once EVERY transaction carrying its payment went out. One whose answer was
    // lost counts as out: reported unpaid, its payee would be paid again while it may still land.
    let mut paid: Vec<Option<String>> = vec![None; resolved.len()];
    let mut failed = vec![false; resolved.len()];
    let mut sent_to = vec![0u64; resolved.len()];
    let mut outcome = ManyOutcome::default();
    if let Some(r) = &results {
        for (ji, res) in r {
            match res {
                Ok(rel) => {
                    let t = rel.txid().to_string();
                    if paid[payee_of[*ji]].is_none() {
                        paid[payee_of[*ji]] = Some(t.clone());
                    }
                    sent_to[payee_of[*ji]] = sent_to[payee_of[*ji]].saturating_add(views.get(*ji).map_or(0, |v| v.amount_sompi));
                }
                Err(_) => failed[payee_of[*ji]] = true,
            }
        }
        for (i, f) in failed.iter().enumerate() {
            if *f {
                paid[i] = None;
            }
        }
        let o = settle(&views, r);
        terms.record(&o.txids, o.sent);
        outcome = ManyOutcome { paid: paid.clone(), sent_to, txids: o.txids, unknown: o.unknown, refused: o.refused.is_some() };
    }
    let payee_txids = resolved
        .iter()
        .enumerate()
        .map(|(i, (r, a, _))| PayeeTxid {
            address: String::from(&Address::new(state.prefix, Version::ShieldedOrchard, r)),
            amount_sompi: *a,
            amount_sompi_exact: a.to_string(),
            txid: paid[i].clone(),
        })
        .collect();
    let total_fee = UNIFORM_FEE_V1 * views.len() as u64;
    Ok((USendManyResp { transactions: views, payee_txids, total_fee_sompi: total_fee }, outcome))
}

/// What a waited-for payout did, per payee and overall (see [`send_many_core`]).
#[derive(Default)]
pub(crate) struct ManyOutcome {
    /// The payee's first transaction, when every one carrying its payment went out.
    paid: Vec<Option<String>>,
    /// What went out to each payee, including the part of one paid only in part.
    sent_to: Vec<u64>,
    /// Every transaction that went out or may have, in release order.
    txids: Vec<String>,
    /// The first transaction whose answer was lost.
    unknown: Option<String>,
    /// Some transaction was refused (nothing of it went out).
    refused: bool,
}

/// `POST /api/wallet/uniform/send_many`.
pub(crate) async fn send_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<USendManyReq>,
) -> Result<Json<USendManyResp>, (StatusCode, Json<serde_json::Value>)> {
    // Clamped: a caller-chosen window feeds `start + window_ms` and the reservation length, and
    // release builds trap on overflow. A day is far beyond any payout schedule.
    let window = req.release_window_s.map(|s| s.min(MAX_RELEASE_WINDOW_S).saturating_mul(1_000)).unwrap_or(DESK_RELEASE_WINDOW_MS);
    send_many_core(state, headers, req.payees, window, req.wait.unwrap_or(false), LegacyTerms::default()).await.map(|(r, _)| Json(r))
}

/// The legacy `/api/wallet/send_many` under `uniform_v1` (the OTC desk's call): one payee per
/// transaction, released over the desk window, and the call returns once all are out.
pub(crate) async fn legacy_send_many(
    state: Arc<AppState>,
    headers: HeaderMap,
    req: SendManyReq,
) -> Result<Json<SendManyResp>, (StatusCode, Json<serde_json::Value>)> {
    // The same record key as `wallet_send_many` (see `legacy_send`).
    let token = token_from(&headers, state.allow_default_token)?;
    let request_key =
        req.request_id.as_deref().and_then(|id| sent_request_key(&format!("custodial-many:{token}"), id, &send_many_fingerprint(&req.payees)));
    let max_total_fee = req.max_total_fee.as_ref().map(|c| c.parse("max_total_fee")).transpose()?;
    let (r, o) = send_many_core(state, headers, req.payees, DESK_RELEASE_WINDOW_MS, true, LegacyTerms { request_key, max_total_fee }).await?;
    let paid_sompi: u64 = r.payee_txids.iter().filter(|p| p.txid.is_some()).map(|p| p.amount_sompi).sum();
    let txids = o.txids;
    if let Some(t) = &o.unknown {
        let mut body = submit_outcome_unknown_body(t, "payout");
        body["txids"] = serde_json::json!(txids);
        body["paid_sompi"] = serde_json::json!(paid_sompi);
        body["payee_txids"] = serde_json::json!(r.payee_txids);
        body["payee_sent_sompi"] = serde_json::json!(o.sent_to);
        return Err((StatusCode::GATEWAY_TIMEOUT, Json(body)));
    }
    if o.refused || o.paid.iter().any(|p| p.is_none()) {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "payout partially sent",
                "txids": txids,
                "paid_sompi": paid_sompi,
                "payee_txids": r.payee_txids,
                // A payee split over several transactions can be paid in part: its txid is null
                // but this says what it did receive.
                "payee_sent_sompi": o.sent_to,
            })),
        ));
    }
    Ok(Json(SendManyResp {
        tx_count: r.transactions.len(),
        payees: r.payee_txids.len(),
        paid_sompi,
        fee_sompi: r.total_fee_sompi,
        paid_sompi_exact: paid_sompi.to_string(),
        fee_sompi_exact: r.total_fee_sompi.to_string(),
        payee_txids: r.payee_txids,
        txids,
    }))
}

#[derive(Serialize)]
pub(crate) struct UMergeResp {
    pub txid: String,
    pub consolidated: usize,
    pub value_sompi: u64,
    pub notes_remaining: usize,
}

/// One uniform 4 -> 1 merge, released now (its time is the Poisson event that triggered it).
/// `urgent_amount`: pick the groups an urgent consolidation needs instead of the smallest notes.
async fn merge_once(state: &Arc<AppState>, w: &Wallet, token: &str, urgent_amount: Option<u64>, manual: bool) -> Result<UMergeResp, (StatusCode, Json<serde_json::Value>)> {
    let _merging = ConsolidateGuard::new();
    ensure_canonical_checkpoint(state, w).await?;
    let (seed, recoverable) = {
        let e = w.lock().await;
        if e.reorged_strikes > 0 {
            return Err(err(StatusCode::CONFLICT, "wallet checkpoint is being repaired after a reorg; retry shortly"));
        }
        (e.key.seed()?, e.recoverable_history)
    };
    let choice = pick_anchor_waiting(w).await?;
    let (positions, sum, own) = {
        let mut e = w.lock().await;
        let mut cands = uniform_candidates(&e, choice.leaves)?;
        // Dust is never merged: `plan_merge` pays a dusty group's fee out of a real note, so a
        // stranger's tiny notes cost the wallet more to merge than they cost to send.
        cands.retain(|n| n.value() > merge_dust_floor());
        let values: Vec<u64> = cands.iter().map(|n| n.value()).collect();
        let pick = match urgent_amount {
            Some(a) => plan_urgent_merges(&values, a).into_iter().next(),
            None => plan_merge(&values).or_else(|| {
                // A manual merge is allowed at or under the trigger: the smallest up to 4.
                if !manual || values.len() < 2 {
                    return None;
                }
                let mut idx: Vec<usize> = (0..values.len()).collect();
                idx.sort_by_key(|&i| values[i]);
                idx.truncate(4);
                (idx.iter().map(|&i| values[i] as u128).sum::<u128>() > UNIFORM_FEE_V1 as u128).then_some(idx)
            }),
        }
        .ok_or_else(|| err(StatusCode::CONFLICT, "nothing to merge"))?;
        let positions: Vec<u64> = pick.iter().map(|&i| cands[i].position).collect();
        let sum: u64 = pick.iter().map(|&i| values[i]).sum();
        let own = if uniform_policy().internal_change { e.db.internal_address_bytes() } else { e.db.my_address_bytes() };
        reserve(&mut e, &positions, std::time::Duration::from_secs(3_600));
        (positions, sum, own)
    };
    let consolidated = positions.len();
    let value = sum - UNIFORM_FEE_V1;
    let planned = vec![Planned { positions, payees: vec![(own, value, [0u8; 512])], payee_index: vec![0], release_at_ms: now_ms(), kind: "merge" }];
    let rel = Release { state: state.clone(), w: w.clone(), token: token.to_string(), seed, recoverable, shape: uniform_policy().shape() };
    let (_, results) = build_and_schedule(rel, choice, planned, true).await?;
    let txid = match results.and_then(|mut r| r.pop()).map(|x| x.1) {
        Some(Ok(Released::Sent(t))) => t,
        Some(Ok(Released::Unknown(t))) => return Err((StatusCode::GATEWAY_TIMEOUT, Json(submit_outcome_unknown_body(&t, "consolidation")))),
        Some(Err(e)) => return Err(err(StatusCode::BAD_GATEWAY, e)),
        None => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "merge did not run")),
    };
    let notes_remaining = w.lock().await.db.notes().iter().filter(|n| n.value() > 0).count();
    Ok(UMergeResp { txid, consolidated, value_sompi: value, notes_remaining })
}

/// `POST /api/wallet/uniform/consolidate`: one uniform merge.
pub(crate) async fn consolidate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UMergeResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    merge_once(&state, &w, &token, None, true).await.map(Json)
}

/// The legacy `/api/wallet/consolidate` under `uniform_v1`.
pub(crate) async fn legacy_consolidate(state: &Arc<AppState>, headers: &HeaderMap) -> Result<ConsolidateResp, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(state)?;
    let token = token_from(headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let r = merge_once(state, &w, &token, None, true).await?;
    Ok(ConsolidateResp { txid: r.txid, consolidated: r.consolidated, value_sompi: r.value_sompi, notes_remaining: r.notes_remaining })
}

/// `GET /api/wallet/uniform/scheduled`.
pub(crate) async fn scheduled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let v = JOBS.lock().unwrap_or_else(|e| e.into_inner()).get(&token).cloned().unwrap_or_default();
    Ok(Json(serde_json::json!({ "transactions": v })))
}

/// The uniform-anchor facts a non-custodial client needs to hold and re-prepare (W5, W11).
#[derive(Serialize)]
pub(crate) struct UniformAnchorInfo {
    pub anchor_blue: u64,
    pub anchor_epoch: u64,
    /// The first blue score at which consensus (01 E-R1) would no longer accept this anchor.
    pub valid_until_blue: u64,
    pub sink_blue: u64,
    pub lambda_per_s: f64,
    pub epoch: u64,
    pub depth: u64,
    pub fee_sompi: u64,
}

pub(crate) fn anchor_info_of(e: &WalletEntry, choice: &AnchorChoice) -> UniformAnchorInfo {
    let r = anchor_rule();
    UniformAnchorInfo {
        anchor_blue: choice.blue,
        anchor_epoch: r.epoch_of(choice.blue),
        valid_until_blue: r.valid_until(choice.blue),
        sink_blue: e.sink_blue,
        lambda_per_s: lambda_now(),
        epoch: r.epoch,
        depth: r.depth,
        fee_sompi: UNIFORM_FEE_V1,
    }
}

/// `GET /api/uniform/anchor` (token-scoped: the anchor is the wallet's own view of the chain).
pub(crate) async fn anchor_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UniformAnchorInfo>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let choice = pick_anchor_waiting(&w).await?;
    let e = w.lock().await;
    Ok(Json(anchor_info_of(&e, &choice)))
}

// ---------------------------------------------------------------------------------------------
// W9 background merger
// ---------------------------------------------------------------------------------------------

/// Poisson-timed background merges for custodial wallets above [`MERGE_TRIGGER_NOTES`] (W9),
/// plus urgent merges at Exp(30 s) gaps for payments that needed consolidation first (W8).
/// Replaces the legacy merger (500 notes, 38 at a time, 60-s cooldown: the cadence the chain
/// shows today) when the operator enables `merge`.
pub(crate) async fn merge_loop(state: Arc<AppState>) {
    log::info!(
        "uniform merger: ON — custodial wallets above {MERGE_TRIGGER_NOTES} notes merge 4 -> 1 at Poisson times \
         (rate (notes - 8) / 18 h, at least one per 2 h), never within 10 min of their own payments"
    );
    let mut next: HashMap<String, u64> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if proving_now() {
            continue;
        }
        let wallets: Vec<(String, Wallet)> = state.wallets.lock().await.iter().map(|(t, w)| (t.clone(), w.clone())).collect();
        for (token, w) in wallets {
            let notes = {
                let Ok(e) = w.try_lock() else { continue };
                if e.key.seed().is_err() || !e.caught_up {
                    continue;
                }
                e.db.notes().iter().filter(|n| n.value() > merge_dust_floor()).count()
            };
            let now = now_ms();
            let urgent = URGENT.lock().unwrap_or_else(|e| e.into_inner()).get(&token).copied();
            if notes <= MERGE_TRIGGER_NOTES && urgent.is_none() {
                next.remove(&token);
                continue;
            }
            let rate = if urgent.is_some() { 1_000.0 / URGENT_MERGE_MEAN_MS as f64 } else { merge_rate_per_s(notes) };
            let due = *next.entry(token.clone()).or_insert_with(|| poisson_next(now, rate, &mut os_u64));
            if now < due {
                continue;
            }
            next.insert(token.clone(), poisson_next(now, rate, &mut os_u64));
            if urgent.is_none() && !merge_allowed_at(now, &payment_times(&token)) {
                continue;
            }
            match merge_once(&state, &w, &token, urgent, false).await {
                Ok(r) => log::info!("uniform merger: merged {} notes into one, {} left — tx {}", r.consolidated, r.notes_remaining, r.txid),
                Err((code, body)) => {
                    if urgent.is_some() && code == StatusCode::CONFLICT {
                        // Nothing more to merge for this payment: urgent mode ends.
                        URGENT.lock().unwrap_or_else(|e| e.into_inner()).remove(&token);
                    }
                    log::debug!("uniform merger: skipped a wallet ({code}): {}", body.0);
                }
            }
            if proving_now() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(amount: u64) -> JobView {
        JobView {
            id: "j".into(),
            kind: "payment",
            release_at_ms: 0,
            amount_sompi: amount,
            fee_sompi: UNIFORM_FEE_V1,
            status: "scheduled",
            txid: None,
            reproved: 0,
            error: None,
        }
    }

    /// A lost answer is "may have paid", never "failed": the legacy answer used to list only the
    /// accepted siblings and call the rest a refusal, so the caller paid again.
    #[test]
    fn a_lost_answer_counts_as_sent_and_a_refusal_does_not() {
        let views = vec![view(100), view(200), view(400)];
        let r = vec![(0, Ok(Released::Sent("a".into()))), (1, Ok(Released::Unknown("b".into()))), (2, Err("refused".into()))];
        let o = settle(&views, &r);
        assert_eq!(o.txids, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(o.sent, 300);
        assert_eq!(o.unknown.as_deref(), Some("b"));
        assert_eq!(o.refused.as_deref(), Some("refused"));
        let none = settle(&views, &[(0, Err("x".into()))]);
        assert!(none.txids.is_empty() && none.sent == 0 && none.unknown.is_none());
    }

    /// Under `--uniform-v1` the legacy `/send` ignored `request_id`: a retry paid again.
    #[test]
    fn uniform_legacy_terms_remember_what_went_out_and_refuse_it_again() {
        let key = sent_request_key(&"ef".repeat(96), "uniform-rid", "fp").unwrap();
        let terms = LegacyTerms { request_key: Some(key.clone()), max_total_fee: Some(2 * UNIFORM_FEE_V1) };
        assert!(terms.refuse_if_sent("payment").is_ok());
        // Nothing went out: no record, so a retry pays (as it must).
        terms.record(&[], 0);
        assert!(sent_request(&key).is_none());
        terms.record(&["t1".into(), "t2".into()], 700);
        let done = sent_request(&key).unwrap();
        assert_eq!((done.txid.as_str(), done.amount_sompi, done.tx_count, done.fee_sompi), ("t1", 700, 2, 2 * UNIFORM_FEE_V1));
        let (code, body) = terms.refuse_if_sent("payment").unwrap_err();
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(body.0["already_sent"]["txid"], "t1");
        // Without a request id nothing is remembered or refused.
        assert!(LegacyTerms::default().refuse_if_sent("payment").is_ok());
        // The fee ceiling is checked against the plan, before anything is reserved.
        assert!(terms.check_fee(2, "payment").is_ok());
        assert_eq!(terms.check_fee(3, "payment").unwrap_err().0, StatusCode::CONFLICT);
    }

    #[test]
    fn policy_is_off_by_default() {
        assert_eq!(UniformPolicy::default(), UniformPolicy::OFF);
        assert!(!UniformPolicy::OFF.enabled && !UniformPolicy::OFF.internal_change && !UniformPolicy::OFF.merge);
        assert_eq!(UniformPolicy::OFF.shape(), SendShape::UNIFORM);
    }

    #[test]
    fn lambda_counts_each_block_once() {
        RECENT_BLOCKS.lock().unwrap().clear();
        for i in 0..3_600u64 {
            note_block_txs(1_000 + i, 1_000_000 + i * 1_000, 1);
            // The same block decoded again for another wallet.
            note_block_txs(1_000 + i, 1_000_000 + i * 1_000, 1);
        }
        let l = lambda_now();
        assert!((l - 1.0).abs() < 0.01, "{l}");
        RECENT_BLOCKS.lock().unwrap().clear();
        assert_eq!(lambda_now(), schedule::LAMBDA_FLOOR_PER_S);
    }

    /// T1 for walletd: its uniform build entry point, given the inputs of the "pay-1-note"
    /// golden vector and the same pinned RNG, produces exactly the golden bytes.
    #[test]
    fn t1_walletd_builds_the_golden_pay_1_note_vector() {
        use kaspa_shielded_core::coinbase::coinbase_note_commitment;
        use kaspa_shielded_core::state::{CoinbaseMint, CoinbaseNote, ShieldedState};
        use rand_chacha::ChaCha20Rng;
        use rand_chacha::rand_core::SeedableRng;
        use sha2::Digest;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sdk/wallet-engine/tests/vectors/uniform-v1.json");
        let golden: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let unhex = |s: &str| -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() };
        let net: [u8; 32] = unhex(golden["network_domain"].as_str().unwrap()).try_into().unwrap();
        let ctx = unhex(golden["tx_context"].as_str().unwrap());
        let block: [u8; 32] = unhex(golden["anchor_block"].as_str().unwrap()).try_into().unwrap();
        let v = golden["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "pay-1-note").unwrap();
        // The fixture of shielded-core's uniform_tests: one 5-ZKAS coinbase note to seed [71; 32].
        let miner = [71u8; 32];
        let addr = address_bytes_from_seed(miner).unwrap();
        let note = (derive_coinbase_note_desc(addr, b"u||0"), 5 * SOMPI_PER_ZKAS);
        let mut state = ShieldedState::new();
        state
            .apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: note.1, commitment: coinbase_note_commitment(&note.0, note.1).unwrap() }])), &[])
            .unwrap();
        let mut db = WalletDb::from_seed(miner).unwrap();
        db.ingest_block(&[note], &[]);
        let inputs: Vec<_> = db.notes().iter().map(|o| (o.note.clone(), db.witness_path(o.position).unwrap())).collect();
        let to = address_bytes_from_seed([2u8; 32]).unwrap();
        let payload = build_uniform_tx(
            miner,
            inputs,
            &vec![(to, 2 * SOMPI_PER_ZKAS, [0u8; 512])],
            &net,
            &ctx,
            true,
            block,
            SendShape::UNIFORM,
            &mut ChaCha20Rng::from_seed([1u8; 32]),
        )
        .unwrap();
        let sha: String = sha2::Sha256::digest(&payload).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sha, v["sha256"].as_str().unwrap(), "walletd's uniform build drifted from the golden vector");
        assert_eq!(hex(&payload), v["payload_hex"].as_str().unwrap());
    }
}
