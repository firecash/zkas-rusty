//! `zkas-api` — the ZKas explorer backend.
//!
//! Translates a running ZKas node's gRPC interface into the small REST +
//! shielded-pool API the explorer frontend (a fork of kaspa-explorer-ng) consumes,
//! and follows the chain tip to maintain a live "recent blocks" feed and a running
//! shielded-pool aggregate (notes minted, nullifiers spent, value shielded).
//!
//! It intentionally does NOT stand up the full kaspa-rest-server + Postgres stack:
//! on a shielded-by-default chain most transparent address/UTXO data is empty, so
//! the meaningful surface is blocks/DAG/coinbase plus the ZKas-specific
//! `/info/shielded` endpoint — all servable straight from the node.

mod geo;
mod merged;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use kaspa_consensus::processes::coinbase::CoinbaseManager;
use kaspa_consensus_core::{config::params::Params, network::NetworkType, tx::TX_VERSION_SHIELDED};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcBlock, RpcHash, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::ShieldedBundle;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

/// Orchard (shielded) recipient script length in a coinbase output.
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Coinbase-payload offset where the 32-byte shielded state-root commitment sits
/// (after blue_score(8) + subsidy(8)); see consensus `processes/coinbase.rs`.
const COMMITMENT_OFFSET: usize = 16;
const SOMPI_PER_ZKAS: u64 = 100_000_000;
/// Blocks per second. The chain relaunched at 1 BPS (v0.2.0); the halving and
/// countdown math below is in blocks, so it must track this.
const BPS: u64 = 1;
// No halving-interval constant lives here on purpose. The emission schedule is a
// decayed monthly table floored by a perpetual tail, evaluated by consensus in
// `CoinbaseManager::calc_block_subsidy`; a local "blocks per halving" figure was a
// second, wrong source of truth for it. See `next_emission_step`.
/// Keep enough history for a real trailing-hour pulse while limiting the public
/// live-feed response separately.
const RECENT_CAP: usize = 6_000;
const RECENT_PUBLIC_CAP: usize = 200;
const WORK_HISTORY_CAP: usize = 100_000;
/// How many transactions the id→location index retains. The live feed ring only
/// covers RECENT_CAP blocks (~3 min at 1 BPS), which made EVERY transaction older
/// than a few minutes report "not found" — the explorer had no tx index at all.
/// This index is what makes a transaction permanently linkable (wallet history,
/// shared links). ~1M entries ≈ tens of MB, and it is persisted so restarts keep it.
const TX_INDEX_CAP: usize = 1_000_000;

#[derive(Parser, Debug)]
#[command(name = "zkas-api", about = "ZKas explorer backend (gRPC → REST)")]
struct Cli {
    /// kaspad (ZKas) gRPC endpoint.
    #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
    rpc_server: String,
    /// Address to serve the HTTP API on.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8500")]
    listen: String,
    /// Append-only transaction index (txid → block). Persisted so a restart keeps
    /// every transaction linkable instead of losing everything but the last ~3 min.
    #[arg(long, default_value = "/root/zkas/txindex.tsv")]
    tx_index: String,
    /// This node's own public address, used only to place it on the network map.
    /// The node's gRPC cannot report its own external address, so it has to be
    /// supplied; without it the explorer's node is still counted, just unplaced.
    #[arg(long)]
    self_ip: Option<String>,
}

/// Where a transaction lives, so it can be served long after it left the live ring.
#[derive(Clone)]
struct TxLoc {
    block_hash: String,
    blue_score: u64,
    block_time: u64,
}

/// One block as the frontend's live feed expects it.
#[derive(Clone, serde::Serialize)]
struct BlockSummary {
    block_hash: String,
    difficulty: f64,
    #[serde(rename = "daaScore")]
    daa_score: String,
    #[serde(rename = "blueScore")]
    blue_score: String,
    timestamp: String,
    #[serde(rename = "txCount")]
    tx_count: u64,
    txs: Vec<TxSummary>,
}

#[derive(Clone, serde::Serialize)]
struct TxSummary {
    #[serde(rename = "txId")]
    tx_id: String,
    /// `[amount, label]` pairs; on a shielded chain the label is "shielded".
    outputs: Vec<[String; 2]>,
}

#[derive(Clone, Serialize)]
struct WorkPoint {
    timestamp: u64,
    difficulty: f64,
}

/// Running shielded-pool aggregate, advanced as the follower ingests blocks.
#[derive(Default, Clone)]
struct ShieldedAgg {
    note_count: u64,
    nullifier_count: u64,
    emission_per_block_fc: f64,
    state_root: String,
    blue_score: u64,
}

struct AppState {
    client: GrpcClient,
    recent: RwLock<VecDeque<BlockSummary>>,
    work_history: RwLock<VecDeque<WorkPoint>>,
    shielded: RwLock<ShieldedAgg>,
    network_name: String,
    /// txid → where it landed. Survives the live ring so a transaction stays
    /// linkable forever (see TX_INDEX_CAP).
    tx_index: RwLock<(std::collections::HashMap<String, TxLoc>, VecDeque<String>)>,
    tx_index_path: String,
    /// This node's own public address, for placing it on the network map.
    self_ip: Option<std::net::IpAddr>,
    /// Cached merged-mining scan: peer id -> what answered on its Kaspa port.
    /// Refreshed on a timer by `scan_merged`; see `merged` for why it is cached.
    merged: RwLock<MergedScan>,
    /// Circulating supply, derived from the consensus emission schedule rather than
    /// by summing coinbases. See `SupplyCache` and `info_coinsupply`.
    supply: RwLock<SupplyCache>,
}

/// Running total of issued ZKas, memoised by DAA score.
///
/// Supply must NOT be accumulated by adding up the coinbase outputs a follower happens
/// to see. On a BlockDAG every block carries a coinbase paying its whole mergeset, but
/// only the accepted chain block's coinbase actually mints — so summing every block
/// counts unaccepted coinbases, and counts each merged block's reward twice (once in
/// the merging block's coinbase, once in its own). Measured live 2026-07-30: the
/// explorer reported 27,814,508 ZKAS against 21,964,860 actually issued, and was still
/// diverging at 161.79 ZKAS per block against a 60 ZKAS subsidy.
///
/// `calc_block_subsidy` is the same function consensus uses to build coinbases, so this
/// total is exact by construction and cannot drift. The cache advances by the new blocks
/// only, keeping the cost proportional to chain growth rather than chain length.
#[derive(Default)]
struct SupplyCache {
    /// Highest DAA score included in `total_sompi`.
    daa_score: u64,
    total_sompi: u128,
}

/// Result of the most recent merged-mining sweep.
#[derive(Default)]
struct MergedScan {
    /// Unix seconds of the last completed sweep; 0 until one finishes.
    scanned_at: u64,
    /// Short peer id -> every Kaspa node found at that peer's address.
    found: std::collections::HashMap<String, Vec<merged::Found>>,
    /// Short peer ids checked in the last sweep (so "not found" is distinguishable
    /// from "never checked").
    checked: std::collections::HashSet<String>,
    /// Short peer ids that answered a TCP knock on at least one swept port. A peer
    /// that was checked but is NOT here is unreachable — firewalled / inbound-only —
    /// which is not the same as "runs no Kaspa".
    reachable: std::collections::HashSet<String>,
}

/// Read the persisted index back at startup: one `txid\tblock_hash\tblue\ttime` row
/// per transaction. A malformed row is skipped rather than failing the boot.
fn load_tx_index(path: &str) -> (std::collections::HashMap<String, TxLoc>, VecDeque<String>) {
    let mut map = std::collections::HashMap::new();
    let mut order = VecDeque::new();
    let Ok(text) = std::fs::read_to_string(path) else { return (map, order) };
    for line in text.lines() {
        let mut f = line.split('\t');
        let (Some(id), Some(bh), Some(bs), Some(bt)) = (f.next(), f.next(), f.next(), f.next()) else { continue };
        let (Ok(blue_score), Ok(block_time)) = (bs.parse::<u64>(), bt.parse::<u64>()) else { continue };
        if map.insert(id.to_string(), TxLoc { block_hash: bh.to_string(), blue_score, block_time }).is_none() {
            order.push_back(id.to_string());
        }
    }
    while order.len() > TX_INDEX_CAP {
        if let Some(old) = order.pop_front() {
            map.remove(&old);
        }
    }
    log::info!("tx index: loaded {} transactions from {path}", map.len());
    (map, order)
}

/// Record every transaction in `block`, in memory and appended to the index file.
async fn index_block(state: &AppState, block: &RpcBlock) {
    use std::io::Write;
    let block_hash = block.header.hash.to_string();
    let blue_score = block.verbose_data.as_ref().map(|v| v.blue_score).unwrap_or(block.header.blue_score);
    let block_time = block.header.timestamp;

    let mut rows = String::new();
    {
        let mut guard = state.tx_index.write().await;
        let (map, order) = &mut *guard;
        for tx in &block.transactions {
            let Some(id) = tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()) else { continue };
            if map.contains_key(&id) {
                continue;
            }
            rows.push_str(&format!("{id}\t{block_hash}\t{blue_score}\t{block_time}\n"));
            map.insert(id.clone(), TxLoc { block_hash: block_hash.clone(), blue_score, block_time });
            order.push_back(id);
            if order.len() > TX_INDEX_CAP {
                if let Some(old) = order.pop_front() {
                    map.remove(&old);
                }
            }
        }
    }
    if rows.is_empty() {
        return;
    }
    // Append outside the lock; a failed write only costs us the index across a
    // restart, never correctness of what we serve now.
    let path = state.tx_index_path.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(rows.as_bytes()))
    })
    .await
    .unwrap_or_else(|e| Err(std::io::Error::other(e)))
    {
        log::warn!("tx index append failed: {e}");
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn fatal(msg: String) -> ! {
    log::error!("{msg}");
    std::process::exit(1);
}

async fn connect(address: &str) -> GrpcClient {
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{address}"),
        None,
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .unwrap_or_else(|e| fatal(format!("failed to connect to {address}: {e}")))
}

/// Read the u64 subsidy (sompi) a coinbase paid, from bytes 8..16 of its payload.
fn coinbase_subsidy_sompi(block: &RpcBlock) -> Option<u64> {
    let cb = block.transactions.first()?;
    if cb.payload.len() < 16 {
        return None;
    }
    Some(u64::from_le_bytes(cb.payload[8..16].try_into().ok()?))
}

/// Read the 32-byte shielded state-root commitment from a coinbase payload.
fn coinbase_state_root(block: &RpcBlock) -> Option<String> {
    let cb = block.transactions.first()?;
    let end = COMMITMENT_OFFSET + 32;
    if cb.payload.len() < end {
        return None;
    }
    Some(cb.payload[COMMITMENT_OFFSET..end].iter().map(|b| format!("{b:02x}")).collect())
}

/// Turn an `RpcBlock` into the summary the live feed serves, and fold its shielded
/// effects into `agg`.
fn ingest(block: &RpcBlock, agg: &mut ShieldedAgg) -> BlockSummary {
    let vd = block.verbose_data.as_ref();
    let blue_score = vd.map(|v| v.blue_score).unwrap_or(block.header.blue_score);
    let difficulty = vd.map(|v| v.difficulty).unwrap_or(0.0);

    let mut txs = Vec::new();
    for (i, tx) in block.transactions.iter().enumerate() {
        let tx_id = tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default();
        let mut outputs = Vec::new();

        if i == 0 {
            // Coinbase: each Orchard-scripted output mints a shielded note.
            for out in &tx.outputs {
                let is_shielded = out.script_public_key.script().len() == ORCHARD_SCRIPT_LEN;
                if is_shielded {
                    agg.note_count += 1;
                    // NB: deliberately NOT accumulating value here. A block's coinbase pays
                    // its whole mergeset, and `ingest` runs on every block the follower sees
                    // — accepted or not — so adding these outputs counts unaccepted coinbases
                    // and double-counts every merged reward. Circulating supply comes from
                    // the consensus emission schedule instead; see `SupplyCache`.
                }
                outputs.push([out.value.to_string(), if is_shielded { "shielded".into() } else { "transparent".into() }]);
            }
        } else if tx.version == TX_VERSION_SHIELDED {
            // Shielded transfer: each Orchard action is a spend (nullifier) + an
            // output note (cmx).
            if let Ok(bundle) = ShieldedBundle::from_bytes(&tx.payload) {
                let n = bundle.actions.len() as u64;
                agg.nullifier_count += n;
                agg.note_count += n;
                outputs.push([n.to_string(), "shielded".into()]);
            }
        } else {
            for out in &tx.outputs {
                outputs.push([out.value.to_string(), "transparent".into()]);
            }
        }
        txs.push(TxSummary { tx_id, outputs });
    }

    if let Some(sub) = coinbase_subsidy_sompi(block) {
        agg.emission_per_block_fc = sub as f64 / SOMPI_PER_ZKAS as f64;
    }
    if let Some(root) = coinbase_state_root(block) {
        agg.state_root = root;
    }
    agg.blue_score = agg.blue_score.max(blue_score);

    BlockSummary {
        block_hash: block.header.hash.to_string(),
        difficulty,
        daa_score: block.header.daa_score.to_string(),
        blue_score: blue_score.to_string(),
        timestamp: block.header.timestamp.to_string(),
        tx_count: block.transactions.len() as u64,
        txs,
    }
}

/// Follow the chain tip: pre-seed from near the sink, then poll for new blocks,
/// updating the recent-block ring and the shielded aggregate.
async fn follow(state: Arc<AppState>) {
    let (sink, _pruning_point) = match state.client.get_block_dag_info().await {
        Ok(dag) => (dag.sink, dag.pruning_point_hash),
        Err(e) => {
            log::warn!("get_block_dag_info failed at startup: {e}");
            return;
        }
    };

    // Pre-fill the recent feed by walking selected parents back from the sink.
    // These blocks don't mutate the aggregate (a throwaway scratch soaks the fold);
    // the aggregate is seeded from chain totals below and advanced only forward.
    let mut backfill: Vec<RpcBlock> = Vec::new();
    let mut cursor = sink;
    for _ in 0..RECENT_CAP {
        match state.client.get_block(cursor, true).await {
            Ok(b) => {
                let parent = b.verbose_data.as_ref().map(|v| v.selected_parent_hash);
                backfill.push(b);
                match parent {
                    Some(p) if p != RpcHash::default() => cursor = p,
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }
    backfill.reverse(); // oldest → newest

    // Recover compact timestamp/difficulty samples for the last 24 hours. Keep
    // only WorkPoint values so the scan cannot retain hundreds of megabytes of
    // full RPC blocks.
    let mut work_backfill: Vec<WorkPoint> = Vec::new();
    let mut work_cursor = backfill.first().and_then(|b| b.verbose_data.as_ref().map(|v| v.selected_parent_hash));
    let cutoff_ms = now_secs().saturating_sub(24 * 60 * 60) * 1_000;
    while work_backfill.len() + backfill.len() < WORK_HISTORY_CAP {
        let Some(cursor) = work_cursor else { break };
        if cursor == RpcHash::default() {
            break;
        }
        let Ok(block) = state.client.get_block(cursor, false).await else {
            break;
        };
        work_cursor = block.verbose_data.as_ref().map(|v| v.selected_parent_hash);
        let difficulty = block.verbose_data.as_ref().map(|v| v.difficulty).unwrap_or(0.0);
        let old_enough = block.header.timestamp <= cutoff_ms;
        work_backfill.push(WorkPoint { timestamp: block.header.timestamp, difficulty });
        if old_enough {
            break;
        }
    }
    work_backfill.reverse();

    // Seed cumulative counters from chain totals so history is right without
    // replaying every block: on a shielded chain every block mints one coinbase
    // note, so noteCount ≈ blueScore and value-shielded ≈ blueScore × subsidy.
    // (No shielded spends on mainnet yet ⇒ nullifierCount starts at 0 and is
    // advanced exactly by the forward follower.)
    {
        let mut agg = state.shielded.write().await;
        if let Some(sink_block) = backfill.last() {
            if let Some(sub) = coinbase_subsidy_sompi(sink_block) {
                agg.emission_per_block_fc = sub as f64 / SOMPI_PER_ZKAS as f64;
                if let Ok(dag) = state.client.get_block_dag_info().await {
                    agg.blue_score = dag.virtual_daa_score;
                    agg.note_count = dag.virtual_daa_score;
                }
            }
            if let Some(root) = coinbase_state_root(sink_block) {
                agg.state_root = root;
            }
        }
        let mut scratch = ShieldedAgg::default();
        let mut recent = state.recent.write().await;
        for b in &backfill {
            let summary = ingest(b, &mut scratch);
            {
                let mut work = state.work_history.write().await;
                work.push_back(WorkPoint { timestamp: b.header.timestamp, difficulty: summary.difficulty });
                while work.len() > WORK_HISTORY_CAP {
                    work.pop_front();
                }
            }
            recent.push_front(summary);
            if recent.len() > RECENT_CAP {
                recent.pop_back();
            }
        }
        for point in &work_backfill {
            let mut work = state.work_history.write().await;
            work.push_back(point.clone());
            while work.len() > WORK_HISTORY_CAP {
                work.pop_front();
            }
        }
    }
    // Index the seeded blocks too, so a just-restarted API can still serve the
    // transactions that are on screen right now.
    for b in &backfill {
        index_block(&state, b).await;
    }
    log::info!("seeded {} recent blocks; following tip...", backfill.len());

    // Poll forward from the last block we have. `get_blocks` pages over a DAG
    // overlap heavily (each page re-covers the previous cursor's anticone), so
    // every block is deduplicated before it touches the ring or the aggregate —
    // without this the ring filled with duplicates (96 unique of 200 observed
    // live), inflating the explorer's block-rate stat to 9–26 "bps" and
    // double-counting the shielded aggregate.
    let mut seen: std::collections::HashSet<RpcHash> = backfill.iter().filter_map(|b| Some(b.header.hash)).collect();
    let mut seen_order: VecDeque<RpcHash> = backfill.iter().map(|b| b.header.hash).collect();
    const SEEN_CAP: usize = 8 * RECENT_CAP;
    let mut low = sink;
    // Count consecutive polls where the cursor could not move forward. A healthy
    // tip-follow sits at 0–1 (waiting for the next block); a sustained non-zero
    // value means the cursor is pinned behind a live tip — the freeze we self-heal.
    let mut stalled_polls: u32 = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let resp = match state.client.get_blocks(Some(low), true, true).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("get_blocks failed: {e}");
                continue;
            }
        };
        for (hash, block) in resp.block_hashes.iter().zip(resp.blocks.iter()) {
            if *hash == low || !seen.insert(*hash) {
                continue; // page anchor or an already-ingested block
            }
            seen_order.push_back(*hash);
            if seen_order.len() > SEEN_CAP {
                if let Some(old) = seen_order.pop_front() {
                    seen.remove(&old);
                }
            }
            let mut agg = state.shielded.write().await;
            let summary = ingest(block, &mut agg);
            drop(agg);
            {
                let mut work = state.work_history.write().await;
                work.push_back(WorkPoint { timestamp: block.header.timestamp, difficulty: summary.difficulty });
                while work.len() > WORK_HISTORY_CAP {
                    work.pop_front();
                }
            }
            {
                let mut recent = state.recent.write().await;
                recent.push_front(summary);
                if recent.len() > RECENT_CAP {
                    recent.pop_back();
                }
            }
            // Permanently index this block's transactions — this is what keeps a tx
            // findable after it falls out of the live ring.
            index_block(&state, block).await;
        }
        // Advance the cursor whenever the page moved forward — NOT only when we
        // ingested something new. `get_blocks` pages overlap heavily, so a page can
        // be entirely already-`seen` (nothing to ingest) yet still sit between us and
        // the tip; gating the cursor on "did we ingest?" pinned `low` there forever
        // while the real tip raced ahead (observed: indexer stuck ~19k blocks back).
        // `seen` still dedups ingestion, so walking through seen regions is safe.
        match resp.block_hashes.last().copied() {
            Some(last) if last != low => {
                low = last;
                stalled_polls = 0;
            }
            _ => {
                // Cursor could not advance. If we're genuinely at the tip this is
                // normal (wait for the next block); if we're pinned behind a live
                // sink, re-anchor to it so a single wedged cursor can't freeze the
                // whole feed. A few polls of grace first to avoid needless jumps.
                stalled_polls = stalled_polls.saturating_add(1);
                if stalled_polls >= 5 {
                    if let Ok(dag) = state.client.get_block_dag_info().await {
                        if dag.sink != low {
                            log::warn!("follow cursor pinned; re-anchoring to sink {}", dag.sink);
                            low = dag.sink;
                        }
                    }
                    stalled_polls = 0;
                }
            }
        }
    }
}

// ---- REST handlers ----

/// Public network overview: how many nodes this node can see. `nodes` counts the
/// node itself plus its unique connected peer addresses; peer IPs are masked to
/// /24 (privacy-first chain — the count is the story, not who runs them).
async fn info_network(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match s.client.get_connected_peer_info().await {
        Ok(resp) => {
            let peers = resp.peer_info;
            let mut ips: Vec<String> = peers
                .iter()
                .map(|p| {
                    let ip = p.address.ip.to_string();
                    match ip.rsplit_once('.') {
                        Some((net, _)) => format!("{net}.x"),
                        None => "ipv6".to_string(),
                    }
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            ips.sort();
            let versions: Vec<String> =
                peers.iter().map(|p| p.user_agent.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            Json(json!({
                "nodes": ips.len() + 1, // unique peers + this node
                "connectedPeers": peers.len(),
                "peerNets": ips,
                "userAgents": versions,
            }))
            .into_response()
        }
        Err(e) => err(e.to_string()),
    }
}

/// One node as the map page renders it. No address ever leaves this struct —
/// only the country an address is *allocated to* and a masked network label.
#[derive(serde::Serialize)]
struct MapNode {
    id: String,
    country: Option<String>,
    #[serde(rename = "countryName")]
    country_name: Option<String>,
    lat: Option<f32>,
    lon: Option<f32>,
    net: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: String,
    #[serde(rename = "protocolVersion")]
    protocol_version: u32,
    #[serde(rename = "pingMs")]
    ping_ms: Option<u64>,
    outbound: Option<bool>,
    /// How long the connection has been up, in seconds. The node reports elapsed
    /// time since the connection started — NOT a wall-clock timestamp — so this
    /// stays a duration rather than being turned into a date.
    #[serde(rename = "connectedForSec")]
    connected_for_sec: Option<u64>,
    /// Blocks this peer was the first to hand us, since the node started.
    /// Gossip is a race, so this is "who supplies us first", not "who mined it".
    #[serde(rename = "blocksRelayed")]
    blocks_relayed: u64,
    ibd: bool,
    #[serde(rename = "self")]
    is_self: bool,
}

/// Spread nodes that share a country centroid into a small deterministic spiral
/// around it, so a country holding several nodes renders as a cluster of
/// distinct dots instead of one dot hiding the rest. The offset depends only on
/// the node's identity and its index within the country, so dots stay put
/// between polls.
fn scatter(lat: f32, lon: f32, seed: u64, index: usize) -> (f32, f32) {
    if index == 0 {
        return (lat, lon);
    }
    // Golden-angle placement keeps successive nodes well separated.
    let angle = (seed % 360) as f32 * std::f32::consts::PI / 180.0 + index as f32 * 2.399_963;
    let radius = 1.1 + (index as f32).sqrt() * 1.2; // degrees
    let out_lat = (lat + radius * angle.sin()).clamp(-84.0, 84.0);
    // Widen the longitude offset as latitude rises so the cluster stays roughly
    // circular on the globe rather than collapsing near the poles.
    let lon_scale = (1.0 / out_lat.to_radians().cos().max(0.35)).min(2.5);
    let out_lon = (lon + radius * angle.cos() * lon_scale + 180.0).rem_euclid(360.0) - 180.0;
    (out_lat, out_lon)
}

/// Stable, non-reversible row key for a peer. A node id is public p2p data, but
/// the UI only needs something stable to key rows and dots on.
fn short_id(node_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    node_id.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// Mask an address to the granularity `/info/network` has always published:
/// /24 for IPv4, /48 for IPv6 — enough to tell rows apart, not enough to locate.
/// The truncated form is shown as-is (no `.x` placeholder), which reads cleanly
/// as "the network this peer is on" rather than as a broken address.
fn masked_net(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// `/info/nodes` — the network map.
///
/// Reports every peer this explorer's node is currently connected to, resolved
/// to a **country** (never an address) through the embedded RIR allocation
/// tables, plus the aggregates the map page renders: country distribution,
/// client versions, and the protocol/direction split.
///
/// This is one vantage point — the peers of a single node — not a crawl of the
/// whole network, and the page says so.
async fn info_nodes(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let peers = match s.client.get_connected_peer_info().await {
        Ok(resp) => resp.peer_info,
        Err(e) => return err(e.to_string()),
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // code → (display name, centroid, count so far)
    let mut per_country: std::collections::HashMap<String, (String, (f32, f32), usize)> = Default::default();
    let mut agents: std::collections::HashMap<String, usize> = Default::default();
    let mut nodes: Vec<MapNode> = Vec::with_capacity(peers.len() + 1);
    let (mut ipv4, mut ipv6, mut inbound, mut outbound) = (0usize, 0usize, 0usize, 0usize);

    // Place a node: resolve its country, claim the next slot in that country's
    // cluster, and record it. Returns nothing — everything lands in `nodes`.
    let mut place = |ip: Option<std::net::IpAddr>,
                     id: String,
                     user_agent: String,
                     protocol_version: u32,
                     ping_ms: Option<u64>,
                     outbound: Option<bool>,
                     connected_for_sec: Option<u64>,
                     blocks_relayed: u64,
                     ibd: bool,
                     is_self: bool| {
        let country = ip.and_then(geo::lookup);
        let placed = country.map(|c| {
            let slot = per_country.entry(c.code.clone()).or_insert_with(|| (c.name.clone(), (c.lat, c.lon), 0));
            slot.2 += 1;
            let seed = u64::from_str_radix(&id, 16).unwrap_or_else(|_| id.len() as u64);
            (c, scatter(c.lat, c.lon, seed, slot.2 - 1))
        });
        nodes.push(MapNode {
            id,
            country: placed.map(|(c, _)| c.code.clone()),
            country_name: placed.map(|(c, _)| c.name.clone()),
            lat: placed.map(|(_, p)| p.0),
            lon: placed.map(|(_, p)| p.1),
            net: ip.map(masked_net),
            user_agent,
            protocol_version,
            ping_ms,
            outbound,
            connected_for_sec,
            blocks_relayed,
            ibd,
            is_self,
        });
    };

    // The explorer's own node leads the list.
    let self_agent = format!("/zkas-explorer:{}/", env!("CARGO_PKG_VERSION"));
    place(s.self_ip, "explorer".to_string(), self_agent.clone(), 0, None, None, None, 0, false, true);
    *agents.entry(self_agent).or_default() += 1;
    match s.self_ip {
        Some(std::net::IpAddr::V4(_)) => ipv4 += 1,
        Some(std::net::IpAddr::V6(_)) => ipv6 += 1,
        None => {}
    }

    for p in &peers {
        let ip = p.address.ip.to_string().parse::<std::net::IpAddr>().ok();
        match ip {
            Some(std::net::IpAddr::V4(_)) => ipv4 += 1,
            Some(std::net::IpAddr::V6(_)) => ipv6 += 1,
            None => {}
        }
        if p.is_outbound {
            outbound += 1
        } else {
            inbound += 1
        }
        *agents.entry(p.user_agent.clone()).or_default() += 1;
        // The node reports `time_connected` as milliseconds ELAPSED since the
        // connection was established, not as a timestamp.
        let connected_for = (p.time_connected > 0).then_some(p.time_connected / 1_000);
        place(
            ip,
            short_id(&p.id.to_string()),
            p.user_agent.clone(),
            p.advertised_protocol_version,
            Some(p.last_ping_duration),
            Some(p.is_outbound),
            connected_for,
            p.blocks_relayed,
            p.is_ibd_peer,
            false,
        );
    }

    let located = nodes.iter().filter(|n| n.country.is_some()).count();
    let total = nodes.len().max(1);
    let mut countries: Vec<Value> = per_country
        .iter()
        .map(|(code, (name, centroid, count))| {
            json!({
                "code": code,
                "name": name,
                "count": count,
                "share": *count as f64 / total as f64,
                "lat": centroid.0,
                "lon": centroid.1,
            })
        })
        .collect();
    countries.sort_by(|a, b| {
        let (ca, cb) = (a["count"].as_u64().unwrap_or(0), b["count"].as_u64().unwrap_or(0));
        cb.cmp(&ca).then_with(|| a["code"].as_str().unwrap_or("").cmp(b["code"].as_str().unwrap_or("")))
    });

    let mut user_agents: Vec<Value> = agents.into_iter().map(|(agent, count)| json!({ "agent": agent, "count": count })).collect();
    user_agents.sort_by(|a, b| {
        let (ca, cb) = (a["count"].as_u64().unwrap_or(0), b["count"].as_u64().unwrap_or(0));
        cb.cmp(&ca).then_with(|| a["agent"].as_str().unwrap_or("").cmp(b["agent"].as_str().unwrap_or("")))
    });

    Json(json!({
        "updatedAt": now,
        "totals": {
            "nodes": nodes.len(),
            "peers": peers.len(),
            "countries": per_country.len(),
            "located": located,
            "inbound": inbound,
            "outbound": outbound,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "blocksRelayed": peers.iter().map(|p| p.blocks_relayed).sum::<u64>(),
        },
        "nodes": nodes,
        "countries": countries,
        "userAgents": user_agents,
    }))
    .into_response()
}

/// Node-level relay telemetry: what this node has actually ingested and what it
/// has published itself.
///
/// This is deliberately NODE-wide, not per peer. The p2p layer does not record
/// which peer a given block arrived from — `BlockLogEvent` distinguishes only
/// *relay* from *submit block* — and nothing in `GetConnectedPeerInfo` counts
/// blocks. So "block X came from IP Y" is not a fact this node possesses, and we
/// do not publish peer addresses in any case (see `geo`: country level only).
///
/// What IS true and useful is this node's own throughput. Note the counter
/// names: `blocks_submitted` in consensus means "handed to the processing
/// pipeline" from ANY source (see `Consensus::validate_and_insert_block`), not
/// "mined here" — so it is published as `blocksIngested` and the frontend must
/// not call it mining. Counters reset when the node restarts.
async fn info_relay(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let m = match s.client.get_metrics(false, true, false, true, false, false).await {
        Ok(m) => m,
        Err(e) => return err(e.to_string()),
    };
    let c = m.consensus_metrics;
    let n = m.connection_metrics;
    Json(json!({
        "updatedAt": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "blocksIngested": c.as_ref().map(|c| c.node_blocks_submitted_count),
        "headersProcessed": c.as_ref().map(|c| c.node_headers_processed_count),
        "bodiesProcessed": c.as_ref().map(|c| c.node_bodies_processed_count),
        "chainBlocksProcessed": c.as_ref().map(|c| c.node_chain_blocks_processed_count),
        "transactionsProcessed": c.as_ref().map(|c| c.node_transactions_processed_count),
        "databaseBlocks": c.as_ref().map(|c| c.node_database_blocks_count),
        "mempoolSize": c.as_ref().map(|c| c.network_mempool_size),
        "tipHashes": c.as_ref().map(|c| c.network_tip_hashes_count),
        "virtualDaaScore": c.as_ref().map(|c| c.network_virtual_daa_score),
        "difficulty": c.as_ref().map(|c| c.network_difficulty),
        "activePeers": n.as_ref().map(|n| n.active_peers),
    }))
    .into_response()
}

/// Sweep every connected peer for a co-located Kaspa node.
///
/// See `merged` for why this identifies merged miners. Runs on a long timer: the
/// answer changes only when an operator reconfigures, and probing peers is a
/// courtesy-bounded activity — one connect per peer per sweep, nothing more.
async fn scan_merged(state: Arc<AppState>) {
    const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
    // Let the node settle its peer set before the first sweep.
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    loop {
        let peers = match state.client.get_connected_peer_info().await {
            Ok(r) => r.peer_info,
            Err(e) => {
                log::warn!("merged scan: peer list unavailable: {e}");
                tokio::time::sleep(SWEEP_INTERVAL).await;
                continue;
            }
        };

        let mut found = std::collections::HashMap::new();
        let mut checked = std::collections::HashSet::new();
        let mut reachable = std::collections::HashSet::new();
        for p in &peers {
            let Ok(ip) = p.address.ip.to_string().parse::<std::net::IpAddr>() else { continue };
            let id = short_id(&p.id.to_string());
            checked.insert(id.clone());
            let sweep = merged::probe_kaspa_all(ip, p.address.port).await;
            if sweep.reachable {
                reachable.insert(id.clone());
            }
            if !sweep.found.is_empty() {
                for h in &sweep.found {
                    log::info!("merged scan: peer {id} also runs {} at {}", h.network, h.address);
                }
                found.insert(id, sweep.found);
            }
        }
        log::info!(
            "merged scan: {}/{} peers run Kaspa; {} unreachable (firewalled/inbound)",
            found.len(),
            checked.len(),
            checked.len().saturating_sub(reachable.len())
        );
        {
            let mut m = state.merged.write().await;
            m.scanned_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            m.found = found;
            m.checked = checked;
            m.reachable = reachable;
        }
        tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

/// Which peers demonstrably run BOTH chains — the merged-mining view.
///
/// `kaspa` is present only when that peer's own address answered a Kaspa p2p
/// handshake. `checked=false` means the sweep has not reached it yet, which is not
/// the same as a negative result and must not be rendered as one.
/// Attribution written by the off-node ZKMM pipeline (see `zkmm_indexer` +
/// `zkmm_join.sh`): keyed by full peer IP, the Kaspa payout address(es) that peer's
/// merge-mined blocks committed to, with block counts. Re-read each request (tiny
/// file); absent/stale is fine — the fields just come back null.
fn load_attribution() -> serde_json::Value {
    std::fs::read_to_string("/root/firecash/attribution.json").ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

async fn info_merged(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let peers = match s.client.get_connected_peer_info().await {
        Ok(r) => r.peer_info,
        Err(e) => return err(e.to_string()),
    };
    let scan = s.merged.read().await;
    let attr = load_attribution();
    let attr_nodes = attr.get("nodes").cloned().unwrap_or(Value::Null);

    let rows: Vec<Value> = peers
        .iter()
        .map(|p| {
            let id = short_id(&p.id.to_string());
            let ip_str = p.address.ip.to_string();
            let ip = ip_str.parse::<std::net::IpAddr>().ok();
            let country = ip.and_then(geo::lookup);
            // Inferred merge-mining attribution for THIS peer, by full IP.
            let mm = attr_nodes.get(&ip_str).cloned();
            json!({
                "id": id,
                "country": country.map(|c| c.code.clone()),
                "countryName": country.map(|c| c.name.clone()),
                "net": ip.map(masked_net),
                // The port the peer listens on for ZKas. A non-default value here
                // next to a Kaspa node on 16111 is the merged-mining signature.
                "zkasPort": p.address.port,
                "userAgent": p.user_agent.clone(),
                "blocksRelayed": p.blocks_relayed,
                "checked": scan.checked.contains(&id),
                // Reachable = at least one swept port accepted a connection. False on
                // a checked peer means firewalled / inbound-only: unprobeable.
                "reachable": scan.reachable.contains(&id),
                "kaspa": scan.found.get(&id),
                "kaspaAddress": scan.found.get(&id).and_then(|v| v.first()).map(|f| f.address.clone()),
                // Inferred from ZKMM-tag ↔ first-relayer join (see /map-merged-mining
                // note). `null` until this peer's merge-mined blocks are observed.
                "mergeMined": mm,
            })
        })
        .collect();

    let merged_count = rows.iter().filter(|r| !r["kaspa"].is_null()).count();
    Json(json!({
        "scannedAt": scan.scanned_at,
        "peers": peers.len(),
        "merged": merged_count,
        "checked": scan.checked.len(),
        "ports": merged::KASPA_PORTS,
        "attribution": attr.get("updatedAt"),
        "attributionMatched": attr.get("matched"),
        "nodes": rows,
    }))
    .into_response()
}

async fn info_blockdag(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match s.client.get_block_dag_info().await {
        Ok(d) => Json(json!({
            "networkName": s.network_name,
            "blockCount": d.block_count.to_string(),
            "headerCount": d.header_count.to_string(),
            "tipHashes": d.tip_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "difficulty": d.difficulty,
            "pastMedianTime": d.past_median_time.to_string(),
            "virtualParentHashes": d.virtual_parent_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "pruningPointHash": [d.pruning_point_hash.to_string()],
            "virtualDaaScore": d.virtual_daa_score.to_string(),
            "sink": d.sink.to_string(),
        }))
        .into_response(),
        Err(e) => err(e.to_string()),
    }
}

/// The consensus emission schedule, built once from the mainnet params. This is the
/// exact object consensus uses to decide each block's subsidy.
fn coinbase_manager() -> CoinbaseManager {
    let p = Params::from(NetworkType::Mainnet);
    CoinbaseManager::new(
        p.coinbase_payload_script_public_key_max_len,
        p.max_coinbase_payload_len,
        p.deflationary_phase_daa_score,
        p.pre_deflationary_phase_base_subsidy,
        p.bps_history(),
        p.toccata_activation,
        p.dev_fee_permille,
        p.dev_fee_recipient,
        p.dev_fee_accrual_activation,
        p.dev_fee_payout_interval,
        // Same gating as consensus (`services.rs`); only the subsidy schedule is read here.
        if p.shielded_coinbase { p.security_fork_activation } else { kaspa_consensus_core::config::params::ForkActivation::never() },
        p.miner_accrual_payout_interval,
    )
}

/// Total ZKas issued through `daa_score`, summed from the consensus subsidy schedule.
///
/// Memoised: only blocks added since the last call are summed, so a running explorer
/// pays for chain growth, not chain length.
async fn circulating_sompi(s: &AppState, daa_score: u64) -> u128 {
    let mut cache = s.supply.write().await;
    if daa_score <= cache.daa_score {
        return cache.total_sompi;
    }
    let cbm = coinbase_manager();
    let mut total = cache.total_sompi;
    for daa in (cache.daa_score + 1)..=daa_score {
        total += cbm.calc_block_subsidy(daa) as u128;
    }
    cache.daa_score = daa_score;
    cache.total_sompi = total;
    total
}

async fn info_coinsupply(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // On a shielded chain the node's UTXO-based coin supply is 0 (no transparent
    // outputs), so the explorer has to derive it. Derive it from the EMISSION SCHEDULE,
    // never by summing the coinbases a follower saw: on a DAG that counts unaccepted
    // coinbases and double-counts every merged reward (see `SupplyCache`).
    let daa = match s.client.get_block_dag_info().await {
        Ok(d) => d.virtual_daa_score,
        Err(e) => return err(e.to_string()),
    };
    let circulating = circulating_sompi(&s, daa).await;
    // ZKas emission has a PERPETUAL TAIL (the subsidy floors at 3 FC/s and never
    // reaches zero — see the consensus `tail_subsidy`), so there is no terminal
    // supply. Reporting a finite `maxSupply` here was simply false. `null` is the
    // honest answer; consumers that need a cap have to model the tail themselves.
    Json(json!({
        "circulatingSupply": circulating.to_string(),
        "maxSupply": serde_json::Value::Null,
        "emissionModel": "perpetual-tail",
    }))
    .into_response()
}

async fn info_blockreward(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let agg = s.shielded.read().await;
    Json(json!({ "blockreward": agg.emission_per_block_fc })).into_response()
}

/// How far ahead to look for the next emission step before reporting that there
/// isn't one. Two years covers the tail step-down at real month 24; beyond that
/// the schedule is flat forever and a countdown would be a fiction.
const EMISSION_SEARCH_HORIZON_BLOCKS: u64 = 2 * 365 * 86_400 * BPS;

/// The next DAA score at which the block subsidy actually goes DOWN, or `None` if
/// it does not change again within the horizon.
///
/// `calc_block_subsidy` is monotonically non-increasing in DAA score, so the first
/// decrease can be found by bisection instead of walking tens of millions of scores.
/// Asking consensus is the point: the schedule is a decaying table read at a scaled
/// month index and then floored by a two-step perpetual tail, and any reimplementation
/// here would be a second source of truth that drifts from the chain.
fn next_emission_step(cbm: &CoinbaseManager, daa_score: u64) -> Option<(u64, u64)> {
    let current = cbm.calc_block_subsidy(daa_score);
    let horizon = daa_score.saturating_add(EMISSION_SEARCH_HORIZON_BLOCKS);
    if cbm.calc_block_subsidy(horizon) >= current {
        return None;
    }
    let (mut lo, mut hi) = (daa_score, horizon); // subsidy(lo) == current > subsidy(hi)
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if cbm.calc_block_subsidy(mid) < current {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Some((hi, cbm.calc_block_subsidy(hi)))
}

/// When the block reward next steps down, and by how much.
///
/// Named "halving" for the endpoint's original callers, but ZKas does not halve in
/// one visible event: the curve decays through the monthly table four times faster
/// than Kaspa's, so a step lands every ~7.6 days and takes twelve steps to halve.
/// The previous implementation counted 90-day intervals of BLUE score from zero and
/// reported the current reward divided by two — wrong counter, wrong period, wrong
/// amount, and it ignored the perpetual tail floor entirely, so it promised a
/// reduction on a schedule where reductions had stopped.
async fn info_halving(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Consensus keys emission off DAA score, not blue score. They differ by the red
    // blocks the DAG merged — thousands apart on a live chain — so using blue score
    // silently reports the wrong point on the curve.
    let daa_score = match s.client.get_block_dag_info().await {
        Ok(d) => d.virtual_daa_score,
        Err(e) => return err(e.to_string()),
    };
    let cbm = coinbase_manager();
    let current_sompi = cbm.calc_block_subsidy(daa_score);
    let current = current_sompi as f64 / SOMPI_PER_ZKAS as f64;

    let Some((next_daa, next_sompi)) = next_emission_step(&cbm, daa_score) else {
        // The curve has decayed into the perpetual tail: the reward is pinned at the
        // floor and does not fall again. Saying "in ~N days" here would be inventing
        // an event. Nulls, so a client shows nothing rather than a stale countdown.
        return Json(json!({
            "nextHalvingTimestamp": Value::Null,
            "nextHalvingDate": "no further reductions scheduled",
            "nextHalvingAmount": current,
            "currentAmount": current,
            "reductionPending": false,
            "atTailFloor": true,
        }))
        .into_response();
    };

    let blocks_left = next_daa.saturating_sub(daa_score);
    let secs_left = blocks_left / BPS;
    let next = next_sompi as f64 / SOMPI_PER_ZKAS as f64;
    let cut_pct = if current_sompi > 0 { (1.0 - next_sompi as f64 / current_sompi as f64) * 100.0 } else { 0.0 };

    // Hours matter here. A step lands every ~7.6 days, so "in ~0 days" is the normal
    // reading for most of the final day and reads as broken.
    let when = if secs_left >= 172_800 {
        format!("in ~{} days", secs_left / 86_400)
    } else if secs_left >= 7_200 {
        format!("in ~{} hours", secs_left / 3_600)
    } else if secs_left >= 120 {
        format!("in ~{} minutes", secs_left / 60)
    } else {
        "in under a minute".to_string()
    };

    Json(json!({
        // Original keys, with values that are now true.
        "nextHalvingTimestamp": now_secs() + secs_left,
        "nextHalvingDate": when,
        "nextHalvingAmount": next,
        // What the reduction actually is, so a client need not guess.
        "currentAmount": current,
        "reductionPercent": (cut_pct * 100.0).round() / 100.0,
        "reductionPending": true,
        "atTailFloor": false,
        "nextReductionDaaScore": next_daa,
        "blocksRemaining": blocks_left,
        "daaScore": daa_score,
    }))
    .into_response()
}

async fn info_shielded(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // `turnstileIn` is the value minted into the shielded pool, which on this chain is
    // exactly the issued supply — so it comes from the emission schedule for the same
    // reason `circulatingSupply` does, and the two can never disagree.
    let turnstile_in = match s.client.get_block_dag_info().await {
        Ok(d) => circulating_sompi(&s, d.virtual_daa_score).await,
        Err(_) => 0,
    };
    let agg = s.shielded.read().await;
    Json(json!({
        "anchor": if agg.state_root.is_empty() { Value::Null } else { json!(agg.state_root) },
        "nullifierCount": agg.nullifier_count,
        "noteCount": agg.note_count,
        "turnstileIn": turnstile_in.to_string(),
        "turnstileOut": "0",
        "emissionPerBlock": agg.emission_per_block_fc,
        "blueScore": agg.blue_score.to_string(),
    }))
    .into_response()
}

async fn info_feeestimate() -> impl IntoResponse {
    // ZKas shielded txs carry a flat public fee; expose a nominal estimate.
    Json(json!({
        "priorityBucket": { "feerate": 1.0, "estimateSeconds": 1.0 },
        "normalBuckets": [{ "feerate": 1.0, "estimateSeconds": 1.0 }],
        "lowBuckets": [{ "feerate": 1.0, "estimateSeconds": 2.0 }],
    }))
}

async fn info_marketdata() -> impl IntoResponse {
    // No market for a young chain.
    StatusCode::NO_CONTENT
}

async fn transactions_count(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Approximate: one coinbase per block; regular ≈ ingested shielded spends.
    let (blue_score, nullifiers) = {
        let agg = s.shielded.read().await;
        (agg.blue_score, agg.nullifier_count)
    };
    Json(json!({
        "timestamp": now_secs() * 1000,
        "dateTime": "",
        "coinbase": blue_score,
        "regular": nullifiers,
    }))
}

async fn blocks_recent(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let recent = s.recent.read().await;
    Json(recent.iter().take(RECENT_PUBLIC_CAP).cloned().collect::<Vec<_>>())
}

#[derive(Debug, Deserialize)]
struct PulseQuery {
    /// Work-chart window: 15m, 1h, 12h, or 24h. Defaults to 15m.
    window: Option<String>,
}

async fn info_pulse(State(s): State<Arc<AppState>>, Query(query): Query<PulseQuery>) -> impl IntoResponse {
    const FIFTEEN_MIN_MS: u64 = 15 * 60 * 1_000;
    const HOUR_MS: u64 = 60 * 60 * 1_000;
    const BIN_MS: u64 = 15_000;
    const BINS: usize = (FIFTEEN_MIN_MS / BIN_MS) as usize;

    let now_ms = now_secs() * 1_000;
    let recent = s.recent.read().await;
    let mut blocks_15m = 0_u64;
    let mut transactions_15m = 0_u64;
    let mut transactions_1h = 0_u64;
    let mut block_bins = vec![0_u64; BINS];
    let mut transaction_bins = vec![0_u64; BINS];
    let mut difficulty_bins = vec![0.0_f64; BINS];
    let mut difficulty_counts = vec![0_u64; BINS];
    let mut daa_15m = Vec::new();
    let mut daa_1h = Vec::new();

    for block in recent.iter() {
        let Ok(ts) = block.timestamp.parse::<u64>() else { continue };
        if ts > now_ms {
            continue;
        }
        let age = now_ms - ts;
        let daa = block.daa_score.parse::<u64>().unwrap_or(0);
        if age < HOUR_MS {
            transactions_1h = transactions_1h.saturating_add(block.tx_count);
            daa_1h.push(daa);
        }
        if age < FIFTEEN_MIN_MS {
            blocks_15m += 1;
            transactions_15m = transactions_15m.saturating_add(block.tx_count);
            let bin = BINS - 1 - (age / BIN_MS) as usize;
            block_bins[bin] += 1;
            transaction_bins[bin] = transaction_bins[bin].saturating_add(block.tx_count);
            if block.difficulty.is_finite() && block.difficulty > 0.0 {
                difficulty_bins[bin] += block.difficulty;
                difficulty_counts[bin] += 1;
            }
            daa_15m.push(daa);
        }
    }
    // Selected-parent backfill contains only blue-chain blocks, but consecutive
    // DAA scores account for the full DAG (including parallel/red blocks).
    let dag_blocks_15m = daa_15m.iter().max().zip(daa_15m.iter().min()).map(|(max, min)| max.saturating_sub(*min)).unwrap_or(0);
    let dag_blocks_1h = daa_1h.iter().max().zip(daa_1h.iter().min()).map(|(max, min)| max.saturating_sub(*min)).unwrap_or(0);
    // Coinbase is one transaction per DAG block. Add non-coinbase transactions
    // observed in the window without double-counting the selected-chain coinbases.
    let non_coinbase_1h = transactions_1h.saturating_sub(daa_1h.len() as u64);
    transactions_1h = dag_blocks_1h.saturating_add(non_coinbase_1h);
    blocks_15m = dag_blocks_15m;
    for i in 0..BINS {
        if difficulty_counts[i] > 0 {
            difficulty_bins[i] /= difficulty_counts[i] as f64;
        }
    }
    // Network work estimate follows the consensus difficulty convention:
    // hashrate = difficulty × 2 hashes/sec.
    let hashrate_bins: Vec<f64> = difficulty_bins.iter().map(|d| d * 2.0).collect();

    let work_window_seconds = match query.window.as_deref() {
        Some("1h") => 3_600_u64,
        Some("12h") => 43_200_u64,
        Some("24h") => 86_400_u64,
        Some("7d") => 604_800_u64,
        Some("30d") => 2_592_000_u64,
        _ => 900_u64,
    };
    let work_bins = (work_window_seconds / 15).clamp(60, 240) as usize;
    let work_bin_seconds = (work_window_seconds / work_bins as u64).max(15);
    let work_now_ms = now_ms;
    let work = s.work_history.read().await;
    let mut work_sum = vec![0.0_f64; work_bins];
    let mut work_count = vec![0_u64; work_bins];
    for point in work.iter() {
        if point.timestamp > work_now_ms {
            continue;
        }
        let age = work_now_ms - point.timestamp;
        if age >= work_window_seconds * 1_000 {
            continue;
        }
        let bin = work_bins - 1 - ((age / (work_bin_seconds * 1_000)) as usize).min(work_bins - 1);
        if point.difficulty > 0.0 && point.difficulty.is_finite() {
            work_sum[bin] += point.difficulty;
            work_count[bin] += 1;
        }
    }
    for i in 0..work_bins {
        if work_count[i] > 0 {
            work_sum[i] /= work_count[i] as f64;
        }
    }
    let fallback_difficulty = work_sum
        .iter()
        .rev()
        .copied()
        .find(|d| *d > 0.0)
        .or_else(|| recent.iter().find(|b| b.difficulty > 0.0).map(|b| b.difficulty))
        .unwrap_or(0.0);
    for value in &mut work_sum {
        if *value <= 0.0 {
            *value = fallback_difficulty;
        }
    }
    let work_hashrate: Vec<f64> = work_sum.iter().map(|d| d * 2.0).collect();

    Json(json!({
        "windowSeconds": 900,
        "blocks15m": blocks_15m,
        "bps15m": dag_blocks_15m as f64 / 900.0,
        "averageBlockTime15m": if blocks_15m > 0 { 900.0 / blocks_15m as f64 } else { 0.0 },
        "transactions15m": transactions_15m,
        "transactions1h": transactions_1h,
        "binSeconds": 15,
        "blockBins": block_bins,
        "transactionBins": transaction_bins,
        "difficultyBins": difficulty_bins,
        "hashrateBins": hashrate_bins,
        "workWindowSeconds": work_window_seconds,
        "workBinSeconds": work_bin_seconds,
        "workDifficultyBins": work_sum,
        "workHashrateBins": work_hashrate,
        "timestamp": now_ms,
    }))
}

async fn block_by_id(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    let hash = match id.parse::<RpcHash>() {
        Ok(h) => h,
        Err(_) => return err("invalid block hash".into()),
    };
    match s.client.get_block(hash, true).await {
        Ok(b) => {
            let vd = b.verbose_data.as_ref();
            Json(json!({
                "block_hash": b.header.hash.to_string(),
                "header": {
                    "hash": b.header.hash.to_string(),
                    "version": b.header.version,
                    "timestamp": b.header.timestamp,
                    "daaScore": b.header.daa_score.to_string(),
                    "blueScore": b.header.blue_score.to_string(),
                    "blueWork": b.header.blue_work.to_string(),
                    "bits": b.header.bits,
                    "nonce": b.header.nonce.to_string(),
                    "pruningPoint": b.header.pruning_point.to_string(),
                    "hashMerkleRoot": b.header.hash_merkle_root.to_string(),
                    "acceptedIdMerkleRoot": b.header.accepted_id_merkle_root.to_string(),
                    "utxoCommitment": b.header.utxo_commitment.to_string(),
                    // Kaspa shape: parents are grouped per level as { parentHashes: [...] }.
                    "parents": b.header.parents_by_level.iter()
                        .map(|level| json!({ "parentHashes": level.iter().map(|h| h.to_string()).collect::<Vec<_>>() }))
                        .collect::<Vec<_>>(),
                },
                "verboseData": {
                    "difficulty": vd.map(|v| v.difficulty).unwrap_or(0.0),
                    "selectedParentHash": vd.map(|v| v.selected_parent_hash.to_string()).unwrap_or_default(),
                    "transactionIds": vd.map(|v| v.transaction_ids.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "isChainBlock": vd.map(|v| v.is_chain_block).unwrap_or(false),
                    "childrenHashes": vd.map(|v| v.children_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "mergeSetBluesHashes": vd.map(|v| v.merge_set_blues_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "mergeSetRedsHashes": vd.map(|v| v.merge_set_reds_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                },
                "transactions": b.transactions.iter().map(tx_json).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Err(e) => err(e.to_string()),
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(serde::Deserialize)]
struct TxSearchReq {
    #[serde(rename = "transactionIds", default)]
    transaction_ids: Vec<String>,
}

/// Batch acceptance lookup (`POST /transactions/search`): the block-details page asks
/// which of a block's txids are accepted. Everything in the recent ring is accepted
/// chain data, so answer from the ring with each tx's accepting blue score.
async fn transactions_search(State(s): State<Arc<AppState>>, Json(req): Json<TxSearchReq>) -> impl IntoResponse {
    let recent = s.recent.read().await;
    let mut found = Vec::new();
    for b in recent.iter() {
        for t in &b.txs {
            if req.transaction_ids.iter().any(|id| *id == t.tx_id) {
                found.push(json!({
                    "transaction_id": t.tx_id,
                    "is_accepted": true,
                    "accepting_block_hash": b.block_hash,
                    "accepting_block_blue_score": b.blue_score.parse::<u64>().unwrap_or(0),
                    "block_time": b.timestamp.parse::<u64>().unwrap_or(0),
                }));
            }
        }
    }
    Json(found)
}

/// The full transaction-detail shape the explorer's tx page consumes. We locate the
/// tx by scanning the recent-block ring for its id (the explorer only links txs it
/// has just shown), then fetch that block from the node for the full transaction.
async fn transaction_by_id(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    // Find which block carries this tx: the live ring first (hot), then the
    // persistent index (which is what lets a tx older than the ring still resolve —
    // without it every tx older than ~3 min reported "not found").
    let block_hash = {
        let recent = s.recent.read().await;
        recent.iter().find(|b| b.txs.iter().any(|t| t.tx_id == id)).map(|b| b.block_hash.clone())
    };
    let block_hash = match block_hash {
        Some(h) => Some(h),
        None => s.tx_index.read().await.0.get(&id).map(|loc| loc.block_hash.clone()),
    };
    let Some(block_hash) = block_hash else {
        // Not in a mined block yet — surface it straight from the node mempool so a
        // just-broadcast tx appears immediately as pending (0-conf) rather than
        // "not found". Confirmations stay 0 (accepting_block_blue_score = 0) until it
        // is mined and enters the recent-block window on a later request.
        if let Ok(txid) = id.parse::<RpcHash>() {
            if let Ok(entry) = s.client.get_mempool_entry(txid, false, false).await {
                let tx = &entry.transaction;
                let now_ms =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                let outputs = detail_outputs(tx, &id, "");
                return Json(json!({
                    "subnetwork_id": tx.subnetwork_id.to_string(),
                    "transaction_id": id,
                    "hash": tx.verbose_data.as_ref().map(|v| v.hash.to_string()).unwrap_or_else(|| id.clone()),
                    "mass": tx.verbose_data.as_ref().map(|v| v.compute_mass).unwrap_or(0).to_string(),
                    "payload": hexs(&tx.payload),
                    "block_hash": Vec::<String>::new(),
                    "block_time": now_ms,
                    "is_accepted": false,
                    "confirmations": 0u64,
                    "accepting_block_blue_score": 0u64,
                    "inputs": Value::Null,
                    "outputs": if outputs.is_empty() { Value::Null } else { json!(outputs) },
                }))
                .into_response();
            }
        }
        return err(format!("transaction {id} not found in the recent window"));
    };
    let hash = match block_hash.parse::<RpcHash>() {
        Ok(h) => h,
        Err(_) => return err("bad block hash".into()),
    };
    let block = match s.client.get_block(hash, true).await {
        Ok(b) => b,
        Err(e) => return err(e.to_string()),
    };
    let Some((i, tx)) = block
        .transactions
        .iter()
        .enumerate()
        .find(|(_, t)| t.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default() == id)
    else {
        return err(format!("transaction {id} not in block"));
    };

    let is_coinbase = i == 0;
    let block_hash_s = block.header.hash.to_string();
    let block_time = block.header.timestamp;
    let blue_score = block.verbose_data.as_ref().map(|v| v.blue_score).unwrap_or(block.header.blue_score);
    // Compute confirmations HERE, against the chain tip's blue score. Doing this in
    // the frontend meant subtracting a blue score from virtualDaaScore — different
    // counters (DAA counts red blocks), which reported a constant ~4.5k on every tx.
    // One authoritative number, in the same units, removes that whole bug class.
    let confirmations = {
        let recent = s.recent.read().await;
        let tip_blue = recent.iter().filter_map(|b| b.blue_score.parse::<u64>().ok()).max().unwrap_or(0);
        tip_blue.saturating_sub(blue_score)
    };

    // Transparent/shielded outputs → address rows. A 43-byte Orchard script is a
    // shielded note; render its zkas: address.
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            let script = o.script_public_key.script();
            let shielded = script.len() == ORCHARD_SCRIPT_LEN;
            let address = if shielded {
                String::from(&kaspa_addresses::Address::new(
                    kaspa_addresses::Prefix::Mainnet,
                    kaspa_addresses::Version::ShieldedOrchard,
                    script,
                ))
            } else {
                String::new()
            };
            json!({
                "transaction_id": id,
                "index": idx,
                "amount": o.value,
                "script_public_key": hexs(script),
                "script_public_key_address": address,
                "script_public_key_type": if shielded { "shielded" } else { "pubkey" },
                "accepting_block_hash": block_hash_s,
            })
        })
        .collect();

    Json(json!({
        "subnetwork_id": tx.subnetwork_id.to_string(),
        "transaction_id": id,
        "hash": tx.verbose_data.as_ref().map(|v| v.hash.to_string()).unwrap_or_else(|| id.clone()),
        "mass": tx.verbose_data.as_ref().map(|v| v.compute_mass).unwrap_or(0).to_string(),
        "payload": hexs(&tx.payload),
        "block_hash": [block_hash_s.clone()],
        "block_time": block_time,
        "is_accepted": true,
        "confirmations": confirmations,
        "accepting_block_hash": block_hash_s,
        "accepting_block_blue_score": blue_score,
        "accepting_block_time": block_time,
        // Coinbase and shielded spends expose no transparent inputs; null renders the
        // "Coinbase" / shielded source in the UI instead of a transparent address list.
        "inputs": Value::Null,
        "outputs": if is_coinbase || !outputs.is_empty() { json!(outputs) } else { Value::Null },
    }))
    .into_response()
}

/// Emit a transaction in the Kaspa-node JSON shape the explorer's block-details page
/// consumes (`verboseData.transactionId`, `inputs[].previousOutpoint`, and
/// `outputs[].verboseData.scriptPublicKeyAddress`). Shielded (43-byte) output scripts
/// render their zkas: address.
fn tx_json(tx: &kaspa_rpc_core::RpcTransaction) -> Value {
    let outputs = tx
        .outputs
        .iter()
        .map(|o| {
            let script = o.script_public_key.script();
            let shielded = script.len() == ORCHARD_SCRIPT_LEN;
            let address = if shielded {
                String::from(&kaspa_addresses::Address::new(
                    kaspa_addresses::Prefix::Mainnet,
                    kaspa_addresses::Version::ShieldedOrchard,
                    script,
                ))
            } else {
                String::new()
            };
            json!({
                "amount": o.value,
                "scriptPublicKey": { "version": o.script_public_key.version(), "scriptPublicKey": hexs(script) },
                "verboseData": {
                    "scriptPublicKeyType": if shielded { "shielded" } else { "pubkey" },
                    "scriptPublicKeyAddress": address,
                },
            })
        })
        .collect::<Vec<_>>();

    let inputs = tx
        .inputs
        .iter()
        .map(|i| {
            json!({
                "previousOutpoint": {
                    "transactionId": i.previous_outpoint.transaction_id.to_string(),
                    "index": i.previous_outpoint.index,
                },
                "signatureScript": hexs(&i.signature_script),
                "sequence": i.sequence,
                "sigOpCount": i.sig_op_count,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "version": tx.version,
        "shielded": tx.version == TX_VERSION_SHIELDED,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": tx.lock_time,
        "subnetworkId": tx.subnetwork_id.to_string(),
        "payload": hexs(&tx.payload),
        "verboseData": {
            "transactionId": tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default(),
            "hash": tx.verbose_data.as_ref().map(|v| v.hash.to_string()).unwrap_or_default(),
            "mass": tx.verbose_data.as_ref().map(|v| v.compute_mass).unwrap_or(0),
        },
    })
}

/// Render a tx's outputs in the transaction-detail shape the explorer's tx page
/// consumes, resolving shielded (43-byte Orchard) scripts to their zkas:
/// address. Shared by the mined-block and mempool paths.
fn detail_outputs(tx: &kaspa_rpc_core::RpcTransaction, id: &str, accepting_block_hash: &str) -> Vec<Value> {
    tx.outputs
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            let script = o.script_public_key.script();
            let shielded = script.len() == ORCHARD_SCRIPT_LEN;
            let address = if shielded {
                String::from(&kaspa_addresses::Address::new(
                    kaspa_addresses::Prefix::Mainnet,
                    kaspa_addresses::Version::ShieldedOrchard,
                    script,
                ))
            } else {
                String::new()
            };
            json!({
                "transaction_id": id,
                "index": idx,
                "amount": o.value,
                "script_public_key": hexs(script),
                "script_public_key_address": address,
                "script_public_key_type": if shielded { "shielded" } else { "pubkey" },
                "accepting_block_hash": accepting_block_hash,
            })
        })
        .collect()
}

/// Shielded chains expose no meaningful transparent address data; answer these so
/// the frontend degrades gracefully instead of erroring.
async fn address_empty() -> impl IntoResponse {
    Json(json!({ "balance": 0 }))
}
async fn empty_array() -> impl IntoResponse {
    Json(json!([]))
}

fn err(msg: String) -> axum::response::Response {
    (StatusCode::BAD_GATEWAY, Json(json!({ "error": msg }))).into_response()
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let cli = Cli::parse();

    let client = connect(&cli.rpc_server).await;
    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let network_name = dag.network.to_string();
    log::info!("connected to ZKas node on {} (network {network_name})", cli.rpc_server);

    let state = Arc::new(AppState {
        client,
        recent: RwLock::new(VecDeque::with_capacity(RECENT_CAP)),
        work_history: RwLock::new(VecDeque::with_capacity(WORK_HISTORY_CAP)),
        shielded: RwLock::new(ShieldedAgg::default()),
        network_name,
        tx_index: RwLock::new(load_tx_index(&cli.tx_index)),
        tx_index_path: cli.tx_index.clone(),
        self_ip: cli.self_ip.as_deref().and_then(|s| match s.parse() {
            Ok(ip) => Some(ip),
            Err(e) => {
                log::warn!("ignoring --self-ip {s}: {e}");
                None
            }
        }),
        merged: RwLock::new(MergedScan::default()),
        supply: RwLock::new(SupplyCache::default()),
    });

    tokio::spawn(follow(state.clone()));
    tokio::spawn(scan_merged(state.clone()));

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new()
        .route("/info/blockdag", get(info_blockdag))
        .route("/info/pulse", get(info_pulse))
        .route("/info/network", get(info_network))
        .route("/info/nodes", get(info_nodes))
        .route("/info/relay", get(info_relay))
        .route("/info/merged-mining", get(info_merged))
        .route("/info/coinsupply", get(info_coinsupply))
        .route("/info/blockreward", get(info_blockreward))
        .route("/info/halving", get(info_halving))
        .route("/info/shielded", get(info_shielded))
        .route("/info/fee-estimate", get(info_feeestimate))
        .route("/info/market-data", get(info_marketdata))
        .route("/transactions/count", get(transactions_count))
        .route("/transactions/count/", get(transactions_count))
        .route("/transactions/:id", get(transaction_by_id))
        .route("/transactions/search", axum::routing::post(transactions_search))
        .route("/addresses/:address/full-transactions-page", get(empty_array))
        .route("/blocks/recent", get(blocks_recent))
        .route("/blocks/:id", get(block_by_id))
        .route("/addresses/:address/balance", get(address_empty))
        .route("/addresses/:address/utxos", get(empty_array))
        .route("/addresses/:address/transactions-count", get(address_empty))
        .route("/addresses/names", get(empty_array))
        .route("/addresses/top", get(empty_array))
        .route("/addresses/distribution", get(empty_array))
        .route("/health", get(|| async { "ok" }))
        .layer(cors)
        .with_state(state);

    let listener =
        tokio::net::TcpListener::bind(&cli.listen).await.unwrap_or_else(|e| fatal(format!("failed to bind {}: {e}", cli.listen)));
    log::info!("ZKas explorer API listening on http://{}", cli.listen);
    axum::serve(listener, app).await.unwrap_or_else(|e| fatal(format!("server error: {e}")));
}

#[cfg(test)]
mod emission_tests {
    use super::*;

    /// The schedule the chain actually runs, pinned so a UI countdown cannot drift
    /// from it again. ZKas traverses Kaspa's monthly subsidy table four times faster
    /// (a halving every 3 months rather than 12), which puts a step every
    /// `2629800 * 3 / 12` = 657,450 seconds — ~7.61 days at 1 BPS — each cutting the
    /// reward by ~5.6%, NOT halving it.
    #[test]
    fn steps_land_every_seven_and_a_half_days_and_are_not_halvings() {
        let cbm = coinbase_manager();
        let daa = 1_276_152; // a real mainnet score
        let (next_daa, next_sompi) = next_emission_step(&cbm, daa).expect("curve is still decaying here");

        assert_eq!(next_daa % 657_450, 0, "steps fall on table-index boundaries");
        assert!(next_daa > daa && next_daa - daa <= 657_450, "the next step is within one interval");

        let current = cbm.calc_block_subsidy(daa);
        assert!(next_sompi < current, "a step reduces the reward");
        // One twelfth of a halving: 2^(-1/12) ≈ 0.9439.
        let ratio = next_sompi as f64 / current as f64;
        assert!((0.94..0.95).contains(&ratio), "a step cuts ~5.6%, got {:.4}", 1.0 - ratio);
        assert!(next_sompi > current / 2, "a step is emphatically not a halving");
    }

    /// Consecutive steps are exactly one interval apart, so "every ~7.6 days" is a
    /// claim the schedule actually supports.
    #[test]
    fn consecutive_steps_are_one_interval_apart() {
        let cbm = coinbase_manager();
        let (first, _) = next_emission_step(&cbm, 1_276_152).unwrap();
        let (second, _) = next_emission_step(&cbm, first).unwrap();
        assert_eq!(second - first, 657_450);
    }

    /// Once the decaying curve sinks to the perpetual tail the reward stops falling.
    /// A countdown must go quiet rather than promise a reduction that never arrives —
    /// the failure the old 90-day interval produced forever.
    #[test]
    fn no_step_is_reported_once_emission_reaches_the_tail_floor() {
        let cbm = coinbase_manager();
        // Far past the month-24 tail step-down, where the floor is flat forever.
        let deep = 40 * 365 * 86_400;
        assert!(next_emission_step(&cbm, deep).is_none());
        assert_eq!(cbm.calc_block_subsidy(deep), cbm.calc_block_subsidy(deep + 5 * 365 * 86_400));
    }

    /// Bisection is only valid because the schedule never rises.
    #[test]
    fn emission_never_increases() {
        let cbm = coinbase_manager();
        let mut previous = u64::MAX;
        for month in 0..60u64 {
            let subsidy = cbm.calc_block_subsidy(month * 657_450);
            assert!(subsidy <= previous, "emission rose at index {month}");
            previous = subsidy;
        }
    }
}
