//! `ZKas-walletd` — a shielded wallet daemon for the ZKas network.
//!
//! It is the engine behind the ZKas web wallet. It drives the *same* shielded
//! primitives the CLI `shielded-pay` uses (`kaspa-shielded-core`): key generation,
//! chain scan with the wallet's viewing key, real Orchard (Halo 2) shielded spends,
//! and message sign/verify. Proofs are generated natively here (no in-browser Halo 2
//! needed) and submitted to a ZKas node over gRPC.
//!
//! ## Custody model
//!
//! The shipped product model is **non-custodial / watch-only**. The device keeps its
//! seed and registers only its 96-byte full viewing key (`/api/wallet/watch`); the
//! daemon scans the chain for it and builds Halo2 spend *proofs* (`/api/wallet/prepare`),
//! but never holds spend authority — the device signs each payment itself and hands
//! the signatures back via `/api/wallet/submit`. A daemon compromise then leaks
//! *visibility* into these wallets, never their coins.
//!
//! Custodial seed wallets (`create` / `import` / `send` / `send_many` / `reveal` /
//! `consolidate` / `sign`) remain supported for self-hosted and payment-gateway use,
//! where the operator IS the owner. On a hosted multi-tenant deployment they can be
//! switched off entirely with `--no-custodial`, which makes every seed-requiring
//! endpoint return 403.
//!
//! ## Two deployment modes
//!
//! - **Self-hosted:** the user runs this on their own machine (or on their node via
//!   `--serve-public`: built-in TLS + a bearer-token pairing QR). Point the web UI's
//!   daemon URL at `http://127.0.0.1:8501`.
//! - **Hosted (non-custodial):** one instance serves many browsers behind a reverse
//!   proxy, connected to a public ZKas node so users need no node of their own. Each
//!   browser owns a random **wallet token** (an `X-Wallet-Token` header); the daemon
//!   keeps one wallet per token, each holding only a viewing key. Do not expose this
//!   daemon directly; put a TLS proxy in front, keep the bind on loopback, and run
//!   with `--no-custodial` (see OPERATIONS.md).
//!
//! ## Sync model
//!
//! Each wallet keeps a live [`WalletDb`] in memory and advances it **incrementally**:
//! an initial one-time replay from genesis (needed to build the note-commitment tree
//! correctly), then cheap catch-up of only new blocks. The background loop processes
//! wallets in bounded chunks so status stays responsive while a big initial scan runs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

pub mod selfhost;
pub use selfhost::{SelfHostConfig, run_selfhost};

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{Next, from_fn, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcHash, RpcShieldedChainBlock, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::coinbase::CoinbaseNoteDesc;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::{FrontierState, GlobalTree, NoteCommitmentTree};
use kaspa_shielded_core::wallet::CompactActionRecord;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::{
    PreparedPayment, build_wallet_payment, build_wallet_payment_multi, finalize_payment, prepare_payment, proving_key,
};
use kaspa_shielded_core::walletdb::{BlockMeta, HistoryKind, OwnedNote, Preview, WalletDb};
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zkas_sdk::{
    ClaimedIntent as SdkClaimedIntent, Network as SdkNetwork, PreparedPayment as SdkPreparedPayment, PreparedPaymentEnvelope,
    SpendAuthRequest as SdkSpendAuthRequest,
};
use zkas_wallet_engine::{
    DEFAULT_FEE_SOMPI, chunk_fee, max_payees_per_tx, max_spends_per_tx, min_relay_fee_for_actions, plan_payment,
    select_spend_count as engine_select_spend_count,
};

/// 1 FC = 10^8 sompi.
const SOMPI_PER_ZKAS: u64 = 100_000_000;
/// Shielded output script length (raw Orchard address carried in a reward script).
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Anchor maturity depth (blocks) — must match consensus `shielded_anchor_depth`
/// (600 * BPS = 600 at 1 BPS, ~10 min). A note is spendable once this deep.
const DEFAULT_ANCHOR_DEPTH: u64 = 600;
/// Max `GetShieldedBlocks` pages a wallet advances per sync chunk. Kept small so
/// the per-wallet lock is released frequently (status stays responsive); speed
/// comes from looping back immediately instead of pausing between chunks.
// Small so each `sync_chunk` — which holds the wallet's mutex the whole time — is short
// (one page ≈ 200 blocks ≈ tens of ms). The status handler locks the same mutex; a large
// chunk held the lock for seconds and hung status behind the sync loop. The loop drops
// the lock and re-acquires per chunk, so status interleaves.
// 4 pages/chunk: the shared decode (see `DecodedPage`) makes per-wallet ingest
// cheaper, so a wallet can absorb more blocks per pass — fewer passes to clear a
// mass rescan — while the lock is still dropped between chunks for status calls.
// NB: kept small on purpose. Enlarging the page/chunk (tried 1000/2) lengthens the
// synchronous decode burst under the wallet lock and starves the axum HTTP handlers
// during a scan — it took wallet.zkas.info's /health/status to timeouts on 2026-07-15.
const PAGES_PER_CHUNK: usize = 4;
/// Chain blocks requested per `GetShieldedBlocks` page (node max 2000, see
/// `MAX_LIMIT` in `rpc/service/src/service.rs:774`). Raised 200→1000 for fewer
/// round-trips and bigger ingest bursts between the node's pruning-lock stalls.
///
/// I briefly took this to the node's 2000 cap on the theory that a bigger page means
/// a bigger trial-decryption batch. It measured worse end to end (892 blocks/s
/// against 2,219), so it is back at 1000. Page size is not free: it is also the unit
/// of work held under the wallet lock, and eight wallets each holding a doubled page
/// cost more than the batching saved.
const SHIELDED_PAGE: u64 = 1000;
/// Blocks requested per page once a wallet is CAUGHT UP and holding a healthy
/// preview roll: the roll already covers the ~200-block unsettled window (its
/// entries are hash-verified, so they don't need re-sending), and a caught-up
/// wallet only needs the ~1 newly settled block + the new tip blocks per second.
/// Pulling the full 1000-block page anyway was ~60 KB of node egress and decode
/// per wallet per second, and past 64 active cursors it thrashed the page cache
/// — the dominant per-wallet cost at hosted scale. 16 covers a 16 s stall; a
/// page that comes back FULL means more blocks than that arrived, so the next
/// iteration of the chunk loop drops back to SHIELDED_PAGE and catches up in
/// one go (see sync_chunk).
const CAUGHT_UP_PAGE: u64 = 16;
/// Blue-score margin the sync holds back from the sink before ingesting a chain
/// block. The wallet's tree is append-only (no rollback), so it must not ingest a
/// block that a routine near-tip reorg could still replace. Blue score advances
/// roughly with the DAG block rate, so on a wide DAG a small margin is only
/// seconds of depth — 20 was observed thrashing live (dozens of reorg evictions
/// per hour). 200 ≈ 2–3 minutes of settling; balances simply lag the tip by
/// that much. A reorg deeper than this margin triggers a rescan.
const SYNC_TIP_MARGIN: u64 = 200;

/// How often a sync pass republishes its progress snapshot WHILE the pass is running.
///
/// The snapshot used to be written once, at the end of a pass. Between those writes the
/// wallet's own mutex is held, so `/status` fell back to the cached snapshot — and for a
/// wallet on its FIRST pass there is no cached snapshot at all, so status answered
/// "loading" for the entire pass. A first pass is minutes for any wallet with history,
/// and every wallet on the box is on its first pass after a daemon restart. The app
/// showed "Opening your wallet · Found 0 ZKAS so far" that whole time, with a progress
/// bar that never moved, because the daemon was not telling it anything.
///
/// Two seconds is well under the poll interval, so progress moves visibly, and far above
/// the per-page cost, so the snapshot work stays in the noise.
const SNAPSHOT_PUBLISH_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// Longest a single wallet may hold a sync pass before it must yield.
///
/// A pass resumes exactly where it stopped, so yielding costs nothing but a lap.
const PASS_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// Lock-free gap the shared chain tree leaves between the pages of one pass, longer
/// than the 20 ms `try_lock` poll of `chain_tree_paths` so a waiting spend is sure to
/// find the tree free once per page (see `sync_one_wallet`).
const CHAIN_TREE_PAGE_GAP: std::time::Duration = std::time::Duration::from_millis(25);

/// Longest the scheduler waits for the slowest wallet before starting the next lap.
///
/// The lap used to `join_next()` every task with no deadline, so ONE wallet that could
/// not finish a pass froze every other wallet on the daemon — including the shared chain
/// tree, which is a member of the same lap. Observed live: a wallet with 273,731 notes
/// never completed a pass (`updated_unix` stayed 0) and ~900 wallets sat at a fixed
/// `scanned` while the chain moved on, each showing "Catching up 99.8%" that could never
/// finish. Raising sync concurrency does nothing for this: parallelism inside a lap is
/// irrelevant when the lap itself cannot end.
///
/// Stragglers are not killed — they keep their permit and finish in their own time, and
/// [`AppState::in_pass`] keeps the next lap from stacking a second pass on the same
/// wallet. One pathological wallet now slows itself down instead of everyone.
const LAP_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// A wallet still at least this many blocks behind the tip keeps taking chunks within
/// ONE pass instead of stopping after `PAGES_PER_CHUNK` pages and waiting for the lap's
/// stragglers. Measured 2026-09-15 on the hosted daemon: the box sat 90% idle while a
/// restoring wallet crawled at ~140 blocks/s — exactly 4,000 blocks per 30 s lap — because
/// every lap ran to `LAP_BUDGET` on a few note-heavy wallets and the fast ones idled.
/// The lock is still dropped between chunks, so status keeps interleaving.
const CATCHUP_BURST_MIN_BEHIND: u64 = 20_000;
/// The burst's per-pass time budget: comfortably under `LAP_BUDGET`, so a bursting wallet
/// is never one of the stragglers a lap detaches.
const CATCHUP_BURST_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a lap waits for a free sync slot before moving on to the next wallet.
///
/// Short on purpose: a full budget means other wallets are mid-pass, and waiting on them
/// is the stall this whole mechanism exists to avoid. The skipped wallet is swept next lap.
const PERMIT_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Above this note count, computing a status snapshot is no longer cheap (it walks every
/// note), so mid-pass publishing is skipped and the end-of-pass snapshot stands. Progress
/// reporting must never become the reason a heavy wallet cannot finish.
const SNAPSHOT_NOTE_CEILING: usize = 20_000;

/// Marks a token as having a sync pass in flight, and unmarks it however the pass ends —
/// normally, by early return, or by panic. See [`AppState::in_pass`].
struct InPassGuard {
    state: Arc<AppState>,
    token: String,
}

impl InPassGuard {
    /// `None` when a pass for this token is already running.
    fn claim(state: &Arc<AppState>, token: &str) -> Option<Self> {
        let fresh = state.in_pass.lock().unwrap_or_else(|e| e.into_inner()).insert(token.to_string());
        fresh.then(|| Self { state: state.clone(), token: token.to_string() })
    }
}

impl Drop for InPassGuard {
    fn drop(&mut self) {
        // `unwrap_or_else(into_inner)`: a poisoned lock here means some other task panicked
        // while holding it. The set is a plain collection of tokens with no invariant a
        // panic could have broken, and refusing to release claims would strand wallets.
        self.state.in_pass.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.token);
    }
}
/// How many consecutive sync passes must see the cursor off the selected chain
/// before the wallet is evicted and rescanned. The virtual chain flips
/// transiently near the tip; a single `reorged` response is usually stale within
/// a pass or two, and a rescan costs the whole scan history.
const REORG_STRIKES: u32 = 3;
/// Node error substrings that are *positive* evidence the wallet's cursor block is
/// no longer retrievable, so its checkpoint must be retired and the wallet rescanned
/// from the current pruning-point frontier:
/// - `cannot find full block` — the node never knew the hash (`ConsensusError::BlockNotFound`).
/// - `cannot find header` — the block was **pruned away** (its header is gone;
///   `ConsensusError::HeaderNotFound`). A wallet that falls behind the pruning point —
///   e.g. the daemon was starved for a while and the chain pruned past its cursor —
///   lands here. Before this it stalled **forever**, stuck at whatever % it froze at,
///   because only the first string was matched.
/// - `required chain data is missing` — pruned/corrupt chain store (`SyncManagerError`).
///
/// Discarding a checkpoint is destructive (forces a rescan), so it must be driven by
/// one of these *positive* signals — never by the mere fact that an RPC returned `Err`.
/// A timeout or an overloaded node also returns `Err`, and treating that as "cursor
/// unknown" is what nuked eleven wallets in one 20ms burst on 2026-07-12 and a live
/// user's wallet seconds after a send on 2026-07-13 (the send's Halo 2 proof is exactly
/// the CPU spike that makes the probe RPC time out).
///
/// A marker is evidence only from a node that has REACHED the cursor (see
/// [`node_reaches`]): a node still syncing answers `cannot find header` for every block
/// it has not received yet, and a walletd repointed at one used to retire a synced
/// checkpoint on that alone (desktop "Chain source" switch, 2026-09).
const CURSOR_GONE_MARKERS: [&str; 4] = [
    "cannot find full block",
    "cannot find header",
    "required chain data is missing",
    // The node refuses to base a chain walk on this cursor: it is below the retention
    // period root, or on a stale branch whose chain no longer reaches it. The block may
    // still *exist* (a `get_block` probe succeeds!), but the walk can never proceed from
    // it — deterministic, not transient. Observed live 2026-07-16: a wallet frozen at 74%
    // for hours, its page fetch failing with this while `get_block` kept succeeding.
    "does not have retention root",
];

/// True if a node error string is positive evidence the cursor block is gone (see
/// [`CURSOR_GONE_MARKERS`]).
fn cursor_gone(err: &str) -> bool {
    CURSOR_GONE_MARKERS.iter().any(|m| err.contains(m))
}
/// Extra blue-score slack under the consensus anchor-maturity depth when picking
/// the anchor a spend roots at, so it stays matured while the tx awaits merging.
const ANCHOR_SLACK: u64 = 30;

/// Compatibility seam while payment preparation moves into the engine. Inputs
/// have already been validated by the HTTP boundary; an arithmetic failure is
/// represented as no selectable notes and becomes the existing conflict error.
fn select_spend_count(values: &[u64], amount: u64, base_fee: u64, max_per: usize) -> (usize, u64) {
    engine_select_spend_count(values, amount, base_fee, max_per).unwrap_or((0, chunk_fee(base_fee, 1)))
}

/// Runtime configuration for the wallet daemon — the library entry point's input.
/// The CLI binary builds this from flags; the desktop app builds it directly.
///
/// Policy note: the CLI refuses non-loopback binds without `--allow-remote`; that
/// check lives in the binary, so an embedding caller owns its own bind policy.
pub struct Config {
    /// ZKas node gRPC endpoint (host:port).
    pub rpc_server: String,
    /// Address:port to serve the wallet REST API on.
    pub listen: SocketAddr,
    /// Directory holding one wallet file per token.
    pub wallet_dir: String,
    /// Network: mainnet | testnet | devnet | simnet.
    pub network: String,
    /// Browser origins allowed via CORS; empty = same-origin only.
    pub allow_origin: Vec<String>,
    /// Permit the tokenless "default" wallet (trusted single-user localhost only).
    pub allow_default_token: bool,
    /// Secret encrypting wallet seed files at rest; None = plaintext (0600) + warning.
    pub wallet_secret: Option<String>,
    /// TLS identity to serve HTTPS with. `None` = plaintext HTTP (loopback / proxied /
    /// VPN only). Set by self-hosting mode ([`run_selfhost`]) so a phone can connect to a
    /// raw public IP without a reverse proxy.
    pub tls: Option<selfhost::TlsIdentity>,
    /// When set, every request (except `/health`) must carry `Authorization: Bearer
    /// <token>`. The transport gate for a publicly-bound daemon; the phone gets the token
    /// from the pairing QR. `None` = no bearer gate (loopback-only deployments).
    pub require_bearer: Option<String>,
    /// Permit custodial (seed-holding) wallets and endpoints: `create`, `import`,
    /// `send`, `send_many`, `reveal`, `consolidate`, `sign`. `true` preserves the
    /// historical behaviour; `false` (the CLI's `--no-custodial`) makes each of
    /// those return 403, so a hosted multi-tenant daemon can serve ONLY the
    /// watch-only `watch` + `prepare` + `submit` model — it then holds no seeds at
    /// all, and a daemon compromise cannot move anyone's coins by construction.
    pub allow_custodial: bool,
    /// Cap on concurrent payment preparations (the Halo2 proving inside
    /// `/api/wallet/prepare`). Each proof saturates every core it is given
    /// (~2.4 core-seconds per input note), so unbounded concurrency is a CPU
    /// denial-of-service on a hosted daemon. Excess callers queue briefly on the
    /// semaphore and then get a retry-friendly 503 rather than piling up work.
    /// The CLI defaults this to [`default_max_concurrent_proves`].
    pub max_concurrent_proves: usize,
    /// Keep custodial wallets below this many notes by merging their oldest notes in
    /// the background. `None` = off; the CLI defaults it to
    /// [`AUTO_CONSOLIDATE_DEFAULT`] and takes `--no-auto-consolidate` to clear it.
    ///
    /// Why it exists: Halo2 proving costs a flat ~0.8 core-seconds **per note spent**
    /// and already saturates every core, so moving value out of a wallet made of many
    /// tiny notes has a hard time floor of `0.8s x notes`. A mining treasury that takes
    /// one coinbase note per block reaches tens of thousands of notes and a payout then
    /// needs thousands of spends — hours of proving, in front of a waiting operator.
    /// Merging notes does not reduce that total work, it *relocates* it: each merge
    /// makes one note worth ~38x more, so the eventual payout spends ~38x fewer notes.
    /// Run continuously the cost is paid a few seconds at a time in the background,
    /// off the interactive path, and the note count never runs away in the first place.
    pub auto_consolidate: Option<usize>,
    /// Build and advance the daemon-wide SHARED chain tree. True on a server, where
    /// many wallets borrow one keyless copy of the public commitment stream. FALSE on
    /// a single-wallet on-device engine: there is nobody to share it with, the wallet's
    /// own frontier-seeded tree already witnesses its notes, and building the shared
    /// copy from genesis is a multi-minute grind that only delays the first send.
    pub build_shared_tree: bool,
    /// Runtime resource policy. Defaults are hardware-derived and suitable for a
    /// single-user daemon; hosted operators can override every bound from the CLI.
    pub resources: ResourceLimits,
    /// Stop the daemon after this long with no wallet API request. `None` = run
    /// forever, which stays the default for hosted and loopback deployments.
    ///
    /// This exists for the daemon a person exposes on a network to pair a phone.
    /// That service holds viewing keys for every wallet it serves, and it is left
    /// running long after the payment that needed it — an open door on a laptop
    /// that then travels to a café. An idle bound turns "until I remember" into a
    /// property of the deployment. `/health` deliberately does not count as use:
    /// an uptime monitor polling it would otherwise hold the door open forever.
    pub idle_timeout: Option<std::time::Duration>,
    /// SOCKS5 proxy (host:port) for the node gRPC connection (Tor on-device). None = direct.
    pub node_socks_proxy: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ResourceLimits {
    /// Refuse a full scan whose span exceeds this many blocks and surface a clear
    /// error instead. Unset = never refuse (servers). A phone sets it: when fast-sync
    /// is impossible (pruned node, birthday older than its checkpoint) the fallback
    /// is a scan of the ENTIRE chain, which on a phone never finishes and read as
    /// "syncing from 0" forever — an honest error beats a hopeless progress bar.
    pub max_full_scan_blocks: Option<u64>,
    pub sync_wallets: usize,
    pub sync_wallet_memory_mb: u64,
    pub load_wallets: usize,
    pub warm_wallets: usize,
    pub page_decode_threads: usize,
    pub page_cache_entries: usize,
    pub page_cache_ttl_secs: u64,
    pub active_sync_secs: u64,
    pub idle_evict_secs: u64,
    pub max_resident_wallets: usize,
    pub subtree_free_floor_mb: u64,
    /// Full pages to fetch CONCURRENTLY ahead of the ingest cursor during a
    /// deep (restore/catch-up) scan. 1 keeps the single cross-wallet prefetch
    /// the hosted daemon relies on; a fetch-bound client (a phone hitting a
    /// remote node) raises it so the loop stops fetching pages one-at-a-time
    /// with the cores idle between round-trips. See `deep_prefetch`.
    pub prefetch_depth: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1);
        // A loaded checkpoint currently occupies roughly 100–190 MiB depending on
        // chain height and note count. Derive the resident cap from live memory rather
        // than baking a hosted-machine size into the binary.
        let max_resident_wallets = mem_available_mb().map(|mb| (mb / 192).clamp(4, 256) as usize).unwrap_or(32);
        Self {
            max_full_scan_blocks: None,
            sync_wallets: cores.saturating_sub(1).clamp(1, 8),
            sync_wallet_memory_mb: 512,
            load_wallets: cores.saturating_sub(2).clamp(1, 4),
            warm_wallets: 1,
            page_decode_threads: cores.saturating_sub(2).clamp(1, 8),
            page_cache_entries: 64,
            page_cache_ttl_secs: 10,
            active_sync_secs: 90,
            idle_evict_secs: 30 * 60,
            max_resident_wallets,
            subtree_free_floor_mb: 1_200,
            prefetch_depth: 1,
        }
    }
}

/// Default for [`Config::max_concurrent_proves`]: two concurrent preparations —
/// one proof uses every core, so a second slot only absorbs the overlap between a
/// finishing proof and a waiting caller — but never more slots than cores.
pub fn default_max_concurrent_proves() -> usize {
    std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1).min(2).max(1)
}

/// 403 for seed-requiring endpoints when the daemon runs with custodial wallets
/// disabled ([`Config::allow_custodial`] = false). The message names the
/// non-custodial path so an old client tells its user where to go.
fn require_custodial(state: &AppState) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.allow_custodial {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "custodial wallets are disabled on this daemon (--no-custodial): it holds no seeds and cannot \
             create, import, reveal, spend, consolidate, or sign for any wallet. Register a viewing key with \
             /api/wallet/watch and spend via /api/wallet/prepare + /api/wallet/submit, signing on your own device.",
        ))
    }
}

/// Map the `--network` string to the consensus [`NetworkType`] the compile-time
/// params are keyed by.
fn state_prefix_network(network: &str) -> kaspa_consensus_core::network::NetworkType {
    use kaspa_consensus_core::network::NetworkType;
    match network.to_ascii_lowercase().as_str() {
        "testnet" => NetworkType::Testnet,
        "devnet" => NetworkType::Devnet,
        "simnet" => NetworkType::Simnet,
        _ => NetworkType::Mainnet,
    }
}

fn prefix_from(network: &str) -> Prefix {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Prefix::Mainnet,
        "testnet" => Prefix::Testnet,
        "devnet" => Prefix::Devnet,
        "simnet" => Prefix::Simnet,
        _ => Prefix::Mainnet,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A wallet token identifies one browser's wallet. Sanitise it hard: it becomes a
/// filename, so allow only url-safe token chars and a sane length.
/// Build the shared chain tree, resuming its persisted checkpoint when there is one.
///
/// Deliberately falls back to a genesis start rather than failing: this entry is an
/// optimization, and a daemon that cannot load it must still serve wallets from their
/// own trees exactly as before.
fn chain_tree_from_genesis(genesis: RpcHash) -> WalletEntry {
    let mut db = WalletDb::from_seed(CHAIN_TREE_SEED).expect("fixed chain-tree seed is a valid spending key");
    db.set_leaves_only(true);
    WalletEntry::from_parts(WalletKey::Seed(CHAIN_TREE_SEED), false, db, genesis, genesis, 0, VecDeque::new(), 0)
}

fn build_chain_tree(dir: &str, genesis: RpcHash) -> Wallet {
    let key = WalletKey::Seed(CHAIN_TREE_SEED);
    let entry = match load_checkpoint(dir, CHAIN_TREE_TOKEN, key, &genesis, None) {
        Some((mut db, low, scanned, boundaries, sink_blue, _blind_below)) => {
            // The flag is not persisted (it describes what this copy is FOR, not the
            // stream it holds), so re-arm it on every load or the tree would start
            // trial-decrypting against a key that matches nothing.
            db.set_leaves_only(true);
            log::info!("shared chain tree resumed from checkpoint: {} leaves, scanned {scanned} blocks", db.size());
            WalletEntry::from_parts(key, false, db, genesis, low, scanned, boundaries, sink_blue)
        }
        None => {
            log::info!("shared chain tree starting from genesis — one keyless pass builds the stream every wallet shares");
            chain_tree_from_genesis(genesis)
        }
    };
    Arc::new(Mutex::new(entry))
}

/// Token of the daemon-wide **shared chain tree** — one keyless copy of the public
/// commitment stream that every wallet witnesses against.
///
/// ~80% of a wallet scan is building a structure that depends on no viewing key
/// (measured: 151 µs/leaf of tree against 103 µs/action of trial decryption), plus a
/// second full Sinsemilla fold to build the subtree cache. Each of those is a pure
/// function of the chain, so N resident wallets were computing N byte-identical copies
/// of it — and storing N copies too (the live pool wallet's checkpoint is 133 MB, of
/// which ~65 MB is leaf stream; its first load took 128 s).
///
/// The chain tree is that work, done once. It is an ordinary [`WalletEntry`] holding a
/// key that matches nothing (`set_leaves_only`), driven by the ordinary sync loop — so
/// its leaf stream cannot drift from a real wallet's, because it is produced by the
/// same code path over the same pages. See `WalletDb::set_leaves_only`.
///
/// The `.` is deliberate: [`sanitize_token`] accepts only alphanumerics, `-` and `_`,
/// so **no HTTP request can ever name this token**. That is a property of the parser,
/// not a blocklist someone can forget to update.
const CHAIN_TREE_TOKEN: &str = "__chain.tree__";

/// Seed for the chain tree's throwaway key. Its only requirement is that it is not a
/// key anybody uses: the entry never decrypts (`leaves_only`), never holds a note, and
/// never spends. Fixed so a restart reloads the same checkpoint.
const CHAIN_TREE_SEED: [u8; 32] = *b"zkas-shared-chain-tree-v1-notele";

fn sanitize_token(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > 128 {
        return None;
    }
    if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { Some(t.to_string()) } else { None }
}

/// Pull the wallet token from the request. A token is required by default (401 when
/// absent), so an unauthenticated caller can't reach any wallet. When
/// `allow_default` is set the daemon falls back to the "default" wallet for the
/// trusted single-user localhost case.
fn token_from(headers: &HeaderMap, allow_default: bool) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    match headers.get("x-wallet-token").and_then(|v| v.to_str().ok()) {
        Some(raw) => sanitize_token(raw).ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid X-Wallet-Token")),
        None if allow_default => Ok("default".to_string()),
        None => Err(err(StatusCode::UNAUTHORIZED, "missing X-Wallet-Token")),
    }
}

// ---------------------------------------------------------------------------
// Persistence: one 0600 JSON file per wallet token.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    network: String,
    seed_hex: String,
    encrypted: bool,
    /// Wallet "birthday": the block height the display scan starts from. 0 = scan
    /// from genesis (a wallet that may hold historical funds). A freshly created
    /// wallet is born at the current tip, so it needs no historical scan.
    #[serde(default)]
    birthday: u64,
    /// Non-custodial wallets store their 96-byte FULL VIEWING KEY here and leave
    /// `seed_hex` empty: the daemon can scan and build proofs, but holds no spend
    /// authority. Absent in v1 files, which are all seed wallets.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fvk_hex: String,
    /// Transaction history, **opt-in**: when on, ingest records readable history
    /// rows in the scan checkpoint AND each send's details are encrypted to the
    /// wallet's own OVK (Zcash-standard), so history recovers recipient/amount/
    /// memo even after a seed restore. Trade-offs the user accepts by enabling:
    /// anyone holding this wallet's file/token reads the record, and someone the
    /// user hands the FULL VIEWING KEY to (message-sign verification!) also sees
    /// outgoing recipients. Default off — nothing readable is stored until the
    /// user activates it.
    #[serde(default)]
    recoverable_history: bool,
}

/// What key material the daemon holds for a wallet.
///
/// `Fvk` is the non-custodial (mobile) case: the device generated the seed, kept it,
/// and registered only its viewing key. Every spend path is refused for such a wallet
/// — signatures must come from the device (`/prepare` + `/submit`).
#[derive(Clone, Copy)]
enum WalletKey {
    Seed([u8; 32]),
    Fvk([u8; 96]),
}

impl WalletKey {
    fn is_watch_only(&self) -> bool {
        matches!(self, WalletKey::Fvk(_))
    }

    /// The seed, or a 403 telling the caller where spend authority actually lives.
    fn seed(&self) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
        match self {
            WalletKey::Seed(s) => Ok(*s),
            WalletKey::Fvk(_) => Err(err(
                StatusCode::FORBIDDEN,
                "this wallet is watch-only: the daemon holds no seed and cannot spend or sign for it. \
                 Use /api/wallet/prepare + /api/wallet/submit and sign on the device that holds the seed.",
            )),
        }
    }

    fn empty_db(&self) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_seed(*s),
            WalletKey::Fvk(f) => WalletDb::from_fvk(f),
        }
    }

    fn db_from_checkpoint(&self, bytes: &[u8]) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_checkpoint(*s, bytes),
            WalletKey::Fvk(f) => WalletDb::from_checkpoint_fvk(f, bytes),
        }
    }

    /// As [`Self::db_from_checkpoint`], but with the tip tree the node reported for the
    /// checkpoint's own cursor block — so an old (v3) checkpoint restores without
    /// replaying its leaf stream. Falls back to the replay if the frontier doesn't match.
    fn db_from_checkpoint_with_tip(&self, bytes: &[u8], tip: &kaspa_shielded_core::tree::FrontierState) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_checkpoint_with_tip(*s, bytes, tip),
            WalletKey::Fvk(f) => WalletDb::from_checkpoint_fvk_with_tip(f, bytes, tip),
        }
    }

    /// A wallet view fast-synced onto a pruning-point frontier.
    fn db_from_frontier(&self, fs: &kaspa_shielded_core::tree::FrontierState) -> Option<WalletDb> {
        let mut db = self.empty_db()?;
        db.apply_frontier(fs)?;
        Some(db)
    }

    /// The 96-byte Orchard full viewing key this wallet watches with — the identity
    /// two registrations of the same wallet share, whatever form (seed or FVK) the
    /// key material arrived in. Everything in a scan checkpoint is derivable from
    /// this key plus the public chain, which is what makes checkpoint adoption
    /// (see [`adopt_twin_checkpoint`]) sound.
    fn fvk_bytes(&self) -> Option<[u8; 96]> {
        self.empty_db().map(|db| db.fvk().to_bytes())
    }
}

fn wallet_path(dir: &str, token: &str) -> String {
    format!("{dir}/{token}.json")
}

/// Encrypt a 32-byte seed under `secret` → `salt(16) || nonce(24) || ciphertext`.
/// Key = Argon2 over `(secret, salt)`; the key is never written to the file.
fn encrypt_seed(seed: &[u8; 32], secret: &str) -> Result<Vec<u8>, String> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut key = [0u8; 32];
    argon2::Argon2::default().hash_password_into(secret.as_bytes(), &salt, &mut key).map_err(|e| format!("argon2: {e}"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), seed.as_slice()).map_err(|e| format!("encrypt: {e}"))?;
    let mut blob = Vec::with_capacity(16 + 24 + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Inverse of [`encrypt_seed`]: recover the 32-byte seed from `blob` using `secret`.
fn decrypt_seed(blob: &[u8], secret: &str) -> Result<[u8; 32], String> {
    if blob.len() < 16 + 24 + 16 {
        return Err("ciphertext too short".into());
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce, ct) = rest.split_at(24);
    let mut key = [0u8; 32];
    argon2::Argon2::default().hash_password_into(secret.as_bytes(), salt, &mut key).map_err(|e| format!("argon2: {e}"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| "decrypt failed (wrong --wallet-secret?)".to_string())?;
    <[u8; 32]>::try_from(pt.as_slice()).map_err(|_| "decrypted seed is not 32 bytes".to_string())
}

/// The scan birthday recorded in a wallet's file, without touching key material.
/// `None` when the file is absent or unreadable; `Some(0)` when no birthday is known.
fn wallet_birthday_on_disk(dir: &str, token: &str) -> Option<u64> {
    let bytes = std::fs::read(wallet_path(dir, token)).ok()?;
    let wf: WalletFile = serde_json::from_slice(&bytes).ok()?;
    Some(wf.birthday)
}

/// Load a wallet's (key, birthday) from disk, decrypting the seed with `secret`
/// when the file is encrypted. A file carrying an `fvk_hex` is a watch-only
/// (non-custodial) wallet: there is no seed on this machine to decrypt.
fn load_wallet_meta(dir: &str, token: &str, secret: Option<&str>) -> Option<(WalletKey, u64, bool)> {
    let bytes = std::fs::read(wallet_path(dir, token)).ok()?;
    let wf: WalletFile = serde_json::from_slice(&bytes).ok()?;
    if !wf.fvk_hex.is_empty() {
        let fvk = unhex(&wf.fvk_hex).and_then(|b| <[u8; 96]>::try_from(b.as_slice()).ok())?;
        return Some((WalletKey::Fvk(fvk), wf.birthday, wf.recoverable_history));
    }
    let seed = if wf.encrypted {
        let blob = unhex(&wf.seed_hex)?;
        let secret = secret.or_else(|| {
            log::error!("wallet '{token}' is encrypted but no --wallet-secret / ZKAS_WALLET_SECRET is set");
            None
        })?;
        decrypt_seed(&blob, secret).map_err(|e| log::error!("cannot decrypt wallet '{token}': {e}")).ok()?
    } else {
        unhex(&wf.seed_hex).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?
    };
    Some((WalletKey::Seed(seed), wf.birthday, wf.recoverable_history))
}

/// How a wallet file on disk is protected — what an embedding shell (the desktop
/// app) must know before it can decide between "ask for a new passphrase",
/// "ask to unlock", and "offer to encrypt what is already here".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultState {
    /// No wallet yet: the next step is creating one under a fresh passphrase.
    Missing,
    /// A wallet exists with its seed in CLEARTEXT (a daemon run without a
    /// secret, or a wallet from before passphrases). Anyone who reads the file
    /// holds the funds — it should be encrypted in place.
    Plaintext,
    /// Seed encrypted at rest; a passphrase is required to load it.
    Encrypted,
    /// Watch-only: no seed on this machine, so there is nothing to encrypt.
    WatchOnly,
}

/// Inspect a wallet file's protection ([`VaultState`]) without decrypting it.
pub fn vault_state(dir: &str, token: &str) -> VaultState {
    let Ok(bytes) = std::fs::read(wallet_path(dir, token)) else { return VaultState::Missing };
    let Ok(wf) = serde_json::from_slice::<WalletFile>(&bytes) else { return VaultState::Missing };
    if !wf.fvk_hex.is_empty() {
        VaultState::WatchOnly
    } else if wf.encrypted {
        VaultState::Encrypted
    } else {
        VaultState::Plaintext
    }
}

/// Check a passphrase against an encrypted wallet **without** starting a daemon
/// or loading the wallet — the unlock screen's verification step. `true` for a
/// wallet that needs no passphrase (plaintext or watch-only), so a caller can
/// treat "unlocked" uniformly.
pub fn verify_wallet_secret(dir: &str, token: &str, secret: &str) -> bool {
    match vault_state(dir, token) {
        VaultState::Missing => false,
        VaultState::Plaintext | VaultState::WatchOnly => true,
        VaultState::Encrypted => load_wallet_meta(dir, token, Some(secret)).is_some(),
    }
}

/// Encrypt an existing cleartext wallet in place under `secret`, so a wallet
/// created before passphrases (or by a secretless daemon) gains protection
/// without the user re-importing a seed. Writes via the same 0600 path as
/// creation. No-op for an already-encrypted or watch-only wallet.
///
/// The rewrite is atomic in the sense that matters: the new file is only
/// written after the seed has been successfully re-encrypted, so a failure
/// leaves the original readable wallet intact rather than a corpse the user
/// cannot open.
pub fn encrypt_wallet_in_place(dir: &str, token: &str, secret: &str) -> Result<(), String> {
    match vault_state(dir, token) {
        VaultState::Missing => return Err("no wallet to encrypt".into()),
        VaultState::Encrypted | VaultState::WatchOnly => return Ok(()),
        VaultState::Plaintext => {}
    }
    let bytes = std::fs::read(wallet_path(dir, token)).map_err(|e| format!("read wallet: {e}"))?;
    let mut wf: WalletFile = serde_json::from_slice(&bytes).map_err(|e| format!("parse wallet: {e}"))?;
    let seed = unhex(&wf.seed_hex)
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| "wallet seed is not 32 bytes".to_string())?;
    let blob = encrypt_seed(&seed, secret)?;
    wf.seed_hex = hex(&blob);
    wf.encrypted = true;
    write_wallet_file(dir, token, &wf).map_err(|e| format!("write wallet: {e}"))
}

/// A portable, self-contained wallet backup: the seed encrypted under a
/// passphrase of the user's choosing, plus the little bit of metadata a restore
/// needs. Safe to keep on a USB stick, in cloud storage, or in a password
/// manager — without the passphrase it is 32 bytes of noise.
///
/// Deliberately NOT a copy of the on-disk wallet file: the backup carries its
/// own salt/nonce and its own passphrase, so exporting cannot leak anything
/// about the device passphrase, and a user can hand a backup to a restore on
/// another machine without reusing the daily unlock secret.
#[derive(Serialize, Deserialize)]
pub struct WalletBackup {
    /// Fixed marker so a restore can reject an unrelated JSON file with a clear
    /// message instead of a decryption error.
    pub magic: String,
    pub version: u32,
    pub network: String,
    /// Wallet birthday, so a restore syncs from there instead of genesis.
    pub birthday: u64,
    /// `salt(16) || nonce(24) || ciphertext` — see [`encrypt_seed`].
    pub encrypted_seed_hex: String,
    pub created_unix: u64,
}

const BACKUP_MAGIC: &str = "zkas-wallet-backup";
const BACKUP_VERSION: u32 = 1;

/// Produce an encrypted backup of `token`'s seed under `backup_secret`.
///
/// `wallet_secret` is the device passphrase, needed only to read the seed that
/// is being backed up (`None` for a legacy cleartext wallet). Watch-only
/// wallets have no seed and are refused — backing one up would produce a file
/// that cannot restore spending ability, which is worse than no backup because
/// the user would believe they were covered.
pub fn export_backup(dir: &str, token: &str, wallet_secret: Option<&str>, backup_secret: &str) -> Result<String, String> {
    if backup_secret.chars().count() < 8 {
        return Err("backup passphrase must be at least 8 characters".into());
    }
    let bytes = std::fs::read(wallet_path(dir, token)).map_err(|_| "no wallet on this device".to_string())?;
    let wf: WalletFile = serde_json::from_slice(&bytes).map_err(|e| format!("parse wallet: {e}"))?;
    if !wf.fvk_hex.is_empty() {
        return Err("this is a watch-only wallet — it holds no seed to back up".into());
    }
    let (key, birthday, _) = load_wallet_meta(dir, token, wallet_secret).ok_or("cannot read the wallet seed (wrong passphrase?)")?;
    let seed = match key {
        WalletKey::Seed(s) => s,
        WalletKey::Fvk(_) => return Err("this is a watch-only wallet — it holds no seed to back up".into()),
    };
    let blob = encrypt_seed(&seed, backup_secret)?;
    let backup = WalletBackup {
        magic: BACKUP_MAGIC.into(),
        version: BACKUP_VERSION,
        network: wf.network,
        birthday,
        encrypted_seed_hex: hex(&blob),
        created_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    serde_json::to_string_pretty(&backup).map_err(|e| format!("serialize backup: {e}"))
}

/// Restore a wallet from an [`export_backup`] file: decrypt with
/// `backup_secret`, then write it as `token`'s wallet encrypted under
/// `wallet_secret` (the device passphrase from here on).
///
/// Refuses to clobber an existing wallet — restoring over a live wallet whose
/// seed the user has not backed up would destroy funds. Any stale scan
/// checkpoint is dropped so the restored wallet rescans from its birthday
/// rather than resuming a different wallet's stream.
pub fn import_backup(dir: &str, token: &str, json: &str, backup_secret: &str, wallet_secret: &str) -> Result<(), String> {
    if wallet_secret.chars().count() < 8 {
        return Err("passphrase must be at least 8 characters".into());
    }
    let backup: WalletBackup = serde_json::from_str(json).map_err(|_| "not a ZKas wallet backup file".to_string())?;
    if backup.magic != BACKUP_MAGIC {
        return Err("not a ZKas wallet backup file".into());
    }
    if backup.version > BACKUP_VERSION {
        return Err(format!("this backup was written by a newer wallet (format v{}) — update the app", backup.version));
    }
    if wallet_exists(dir, token) {
        return Err("a wallet already exists on this device; remove it before restoring".into());
    }
    let blob = unhex(&backup.encrypted_seed_hex).ok_or("backup is corrupt (bad seed field)")?;
    let seed = decrypt_seed(&blob, backup_secret).map_err(|_| "wrong backup passphrase".to_string())?;
    save_seed(dir, token, &backup.network, &seed, backup.birthday, Some(wallet_secret)).map_err(|e| format!("write wallet: {e}"))?;
    let _ = std::fs::remove_file(scan_path(dir, token));
    // A previous key's quarantined copies must not be restored under this one.
    retire_quarantine_copies(dir, token);
    Ok(())
}

fn wallet_exists(dir: &str, token: &str) -> bool {
    std::path::Path::new(&wallet_path(dir, token)).exists()
}

fn save_seed(dir: &str, token: &str, network: &str, seed: &[u8; 32], birthday: u64, secret: Option<&str>) -> std::io::Result<()> {
    let (seed_hex, encrypted) = match secret {
        Some(s) => {
            let blob = encrypt_seed(seed, s).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            (hex(&blob), true)
        }
        None => (hex(seed), false),
    };
    let wf = WalletFile {
        version: 1,
        network: network.to_string(),
        seed_hex,
        encrypted,
        birthday,
        fvk_hex: String::new(),
        // History is opt-in: nothing readable is recorded until the user
        // explicitly enables it (accepting that anyone holding the wallet
        // file / server token could read the record).
        recoverable_history: false,
    };
    write_wallet_file(dir, token, &wf)
}

/// Persist a **watch-only** wallet: only the full viewing key is written — there is
/// no seed to protect, so `--wallet-secret` encryption is moot. A compromise of this
/// file leaks the ability to *see* the wallet, never to spend it.
fn save_fvk(dir: &str, token: &str, network: &str, fvk: &[u8; 96], birthday: u64, recoverable_history: bool) -> std::io::Result<()> {
    let wf = WalletFile {
        version: 2,
        network: network.to_string(),
        seed_hex: String::new(),
        encrypted: false,
        birthday,
        fvk_hex: hex(fvk),
        // Opt-in by default (same as the seed path); a view-key import asks for it on.
        recoverable_history,
    };
    write_wallet_file(dir, token, &wf)
}

fn write_wallet_file(dir: &str, token: &str, wf: &WalletFile) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = wallet_path(dir, token);
    std::fs::write(&path, serde_json::to_vec_pretty(wf).expect("serializes"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Reset a wallet file's `birthday` to 0 in place, preserving every other field
/// (seed/fvk, encryption, network, history flag) and its 0600 perms. A rescan uses
/// this so the reload FULL-SCANS from genesis instead of fast-syncing from a stored
/// birthday: a birthday set later than the wallet's actual notes makes fast-sync skip
/// the older blocks into the frontier and the balance comes back ZERO (the 2026-07-27
/// "rescan wiped my balance" reports). The node is archival, so a full scan loses
/// nothing, and the rebuilt checkpoint keeps future restarts fast.
/// Point the wallet's stored birthday at `birthday` so the reload scans from there.
///
/// `0` means genesis, which is what a recovery with no idea when the wallet was made
/// has to do. But a full replay of this chain is millions of leaves, and most people
/// know roughly WHEN they made the wallet even though nobody knows a block height —
/// so the caller can supply one and skip the years before it. Scanning a little too
/// far back costs seconds; starting too late costs notes, which is why the client
/// applies a margin rather than trusting the date exactly.
fn set_wallet_birthday(dir: &str, token: &str, birthday: u64) -> std::io::Result<()> {
    let path = wallet_path(dir, token);
    let bytes = std::fs::read(&path)?;
    let mut v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    v["birthday"] = serde_json::json!(birthday);
    std::fs::write(&path, serde_json::to_vec_pretty(&v).expect("serializes"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan checkpoint: persist the scanned commitment stream + owned notes + cursor
// so a restart resumes instead of rescanning the chain from the wallet birthday.
// ---------------------------------------------------------------------------

/// Sidecar file holding a token's scan checkpoint (next to its `.json` seed file).
fn scan_path(dir: &str, token: &str) -> String {
    format!("{dir}/{token}.scan")
}

const SCAN_MAGIC: &[u8; 4] = b"FCWS";
/// v3: WalletDb v3 (spent-nullifier drop rule) — v2 trees may hold
/// double-applied bundles (phantom notes + shifted positions), so they rescan.
/// v2: chain-ordered sync (cursor = last ingested *chain* block), guarded by the
/// network genesis hash, with the matured-anchor ring + sink blue score appended.
/// Bumping from v1 deliberately invalidates every v1 checkpoint: those were built
/// from DAG-ordered `get_blocks` ingestion, which double-counts non-chain
/// coinbases and mis-orders leaves on a wide DAG (the live balance-mismatch bug).
const SCAN_VERSION: u8 = 4;
/// v3 checkpoints (no `blind_below` trailer) still load — the field defaults to 0.
const SCAN_VERSION_PREV: u8 = 3;
/// magic(4) + version(1) + genesis(32) + low(32) + scanned(8).
const SCAN_HEADER_LEN: usize = 77;
/// Rewrite the checkpoint after this many newly-scanned blocks (and once a wallet
/// first reaches the tip). Bounds work lost on a crash without writing the growing
/// blob on every tiny sync pass; a restart re-scans at most this many cheap blocks.
// Persist scan progress this often. Kept modest so a daemon restart during a long
// initial scan doesn't throw away all progress and re-trigger a full rescan of the
// whole wallet cohort (a "thundering herd" that pins every core). At ~32B/leaf the
// checkpoint blob stays small, so frequent writes are cheap.
//
// Near the tip only. A wallet bursting through a deep catch-up advances several
// thousand blocks per pass while retaining every leaf since its birthday, so there
// this rule would rewrite a growing many-MB blob every pass; those wallets save on
// `CHECKPOINT_INTERVAL` alone (see `sync_one_wallet`).
const CHECKPOINT_EVERY: usize = 1000;
/// Also checkpoint whenever this much wall time has passed with ANY progress. The
/// block-count rule alone let a slow scanner — a phone against a public node — run
/// for many minutes before its first save, and a process kill in that window (Android
/// force-stop, no shutdown) threw all of it away.
const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Minimum block lead a twin must have over THIS wallet's own checkpoint before it is
/// worth cloning instead of scanning the gap. Below this, the argon2 + decrypt cost of
/// adoption outweighs just scanning the few blocks; well above it (a second device that
/// entered the same seed and is many hours behind) the clone is the whole point.
const TWIN_ADOPT_LEAD: u64 = 5_000;

/// Max leaves the background loop advances a wallet's spend-witnesses per step before
/// yielding, so a large catch-up never runs as one core-pinning burst.
#[allow(dead_code)]
const WITNESS_ADVANCE_CAP: u64 = 4000;

/// Total per-pass budget for eager witness catch-up, in (leaf × witness) hash units.
/// `advance_witnesses_capped(cap)` costs `cap × (owned-note count)` Sinsemilla hashes —
/// so a fixed leaf cap makes a many-note wallet's step blow up: a pool/miner wallet with
/// thousands of notes was observed taking **7–15 s per step**, which pins the sync loop
/// and freezes every other wallet's scan. Deriving the per-pass leaf cap as
/// `BUDGET / note_count` (floored at [`WITNESS_MIN_STEP`]) bounds the step to roughly this
/// many hashes regardless of wallet size, keeping the loop responsive. Witnesses that
/// don't finish catching up here are rebuilt on demand at spend time anyway.
const WITNESS_ADVANCE_BUDGET: u64 = 400_000;
/// Floor on the per-pass leaf cap, so even a huge wallet still makes some progress.
const WITNESS_MIN_STEP: u64 = 32;

/// Leaves the background compaction rolls the fast-sync base forward per step. Each step
/// costs O(step) Sinsemilla work (it rebuilds the frontier at the new base), so it is
/// bounded like the witness step; a full-scan wallet's base climbs to its own notes over a
/// couple of minutes of throttled passes, after which every spend replays only the few
/// thousand leaves above the notes instead of the whole chain. See
/// [`WalletDb::advance_base_capped`].
const BASE_ADVANCE_STEP: u64 = 8192;

/// Leaves per step for the ONE-TIME cold warm (base roll + witness build) of a freshly
/// loaded / full-scan wallet. Larger than the steady step so the ~30–90 s one-time build
/// converges in a handful of passes instead of crawling for minutes while the user keeps
/// hitting a COLD send. Each step is one `block_in_place`, so it holds the wallet lock for
/// ~a few seconds at a time (status calls for that one wallet wait briefly); it runs at
/// most once per wallet load, then `witnesses_warm` latches and only the cheap incremental
/// step runs.
const COLD_WARM_STEP: u64 = 16384;

/// Per-step WORK budget (≈ leaves × witnesses) for the cold warm. Dividing the leaf step
/// by the note count keeps a 32-note wallet's step as cheap as a 1-note wallet's, so no
/// single wallet monopolises a warm slot and starves the interactive few-note wallets.
const COLD_WARM_BUDGET: u64 = 32768;

/// Wall-clock the cold warm may spend per sync tick, running back-to-back steps.
///
/// One step is ~5.7 s of work, but the sync loop only reached this branch about once
/// every 47 s — a ~12 % duty cycle, so a wallet needing ~4.4 min of CPU took the better
/// part of an hour, and every restart lost ground. The total work is unchanged; this
/// just stops it being spread so thin that it never finishes. The wallet lock is held
/// for a step at a time, so that wallet's own status calls wait briefly during its
/// one-time warm — worth it to have sends stop costing 20 s per note.
/// Kept short deliberately. The warm holds the wallet lock and a sync slot for its whole
/// tick, so a long tick starves every other wallet's ordinary sync — a 1-note wallet was
/// observed stuck at "syncing 97%" while the note-heavy backlog warmed. Short ticks cost
/// slightly more overhead but interleave, so warming stays a background task instead of
/// monopolising the box.
const COLD_WARM_TICK: std::time::Duration = std::time::Duration::from_secs(4);

/// Above this many notes a wallet keeps only a *bounded* witness set rather than one per
/// note — witnessing them all costs leaves × notes and would hog the shared loop for
/// minutes. These are pool/treasury/miner wallets.
///
/// This used to disable witnessing for such a wallet **entirely**, on the reasoning that
/// they rarely spend and the few notes a send selects could rebuild on demand. That was
/// wrong in a way that only shows up at scale: the rebuild is a base→matured Sinsemilla
/// replay whose length is the gap between the wallet's oldest unspent note and the matured
/// tip, and `advance_base_capped` cannot roll the base past that oldest note — so the gap
/// grows with the chain, forever. On the live miner wallet it reached ~117 K leaves ≈ 20 s
/// *per selected note*, making a 6-note send take two minutes and getting worse daily.
/// Bounding the witness *set* keeps the cost `leaves × budget` (a constant) instead of
/// `leaves × notes`, so these wallets stay warm like any other.
const EAGER_WARM_MAX_NOTES: u64 = 32;

/// Witness slots kept for a note-heavy wallet. MUST cover a full standard transaction's
/// spends (`max_spends_per_tx()`, currently **38**) with slack, so the value-descending
/// selection a single-tx send makes lands entirely on warm notes and the send is an O(1)
/// lookup instead of paying a base→matured Sinsemilla rebuild for every note past the
/// budget. This was `12`, sized when `max_spends_per_tx()` was 6; the spend cap was later
/// lifted 6→38 (the block-fit "6× lift" in `sdk/wallet-engine`) without raising this, so a
/// 38-note send warm-covered only 12 notes and rebuilt the other 26 cold — ~22 s each,
/// i.e. minutes per send on a note-heavy wallet. Kept a small constant so the one-time warm
/// catch-up (and the ~`budget` hashes/leaf steady cost) stays bounded no matter how many
/// thousands of notes the wallet holds. Keep this ≥ `max_spends_per_tx()`.
const SPENDABLE_WITNESS_BUDGET: usize = 48;

/// Longest witness climb a note-heavy (never-eager-warmed) wallet may do inline at
/// send time. Each climbed leaf costs one Sinsemilla append per live witness (up to
/// 256, ~15 ms/leaf worst case), so 512 leaves ≈ ≤8 s — and at 1 BPS it comfortably
/// covers the gap since the wallet's last spend. Anything longer is skipped: the few
/// selected notes rebuild on demand instead, which is witness-count-free.
const SPEND_CLIMB_INLINE_MAX: u64 = 512;

/// Leaf span (matured − base) at which retaining complete subtree roots starts to pay.
/// The cache costs ~4 bytes per leaf of span and one O(chain) build; it removes a replay
/// that costs ~0.26 ms per leaf on this hardware. At 20 000 leaves the replay it deletes
/// is already ~5 s per send, which is the point where a send stops feeling instant.
const SUBTREE_CACHE_MIN_SPAN: u64 = 20_000;

/// Longest a single subtree-cache slice may hold the wallet lock.
///
/// This is a LATENCY bound, not a throughput knob: the sweep is resumable, so slicing
/// changes only how often the lock is handed back, never how much work is done. 250 ms
/// is well under the point a user notices a stalled request, and long enough that the
/// per-slice bookkeeping stays negligible against ~1024 Sinsemilla combines per check.
/// Leaves of scanning between scan-cost reports.
///
/// Keyed on LEAVES, not actions: on this chain almost every leaf is a coinbase note
/// (~1.98 leaves per block = one reward note plus the dev-fee note), and coinbase
/// notes are recovered by an address comparison, never trial-decrypted. An
/// action-keyed trigger would essentially never fire.
const SCAN_COST_REPORT_LEAVES: u64 = 20_000;


/// Free memory the daemon refuses to build a subtree cache below.
///
/// The cache itself is small (~4 B/leaf of span) but building it forces that wallet's
/// decoded leaf stream to materialise, and the pair measured ~11 MB per 200 K-leaf
/// wallet on the hosted daemon (32 B/leaf stored + 32 B/leaf decoded). Across hundreds
/// of wallets that is gigabytes, on a box that also runs a node.
///
/// This replaced a fixed daemon-wide leaf budget, which had two faults a live sweep
/// exposed: the number was a guess unrelated to the box's actual memory, and it was a
/// **lifetime** counter, so once spent, every wallet loaded afterwards was permanently
/// stuck on the replay path (observed: 31 wallets skipped, one of them then taking
/// 16.1 s to witness 3 notes where a cached wallet took 32 ms). Gating on live free
/// memory is self-regulating — builds stop as memory tightens and resume when it frees
/// — and it reconsiders a skipped wallet on a later pass instead of writing it off.

/// How long a `MemAvailable` reading is reused. The gate is consulted per wallet per
/// sync pass; re-reading `/proc/meminfo` every time would be pointless syscall traffic,
/// and memory does not move fast enough for a stale-by-seconds figure to matter.
const MEM_AVAILABLE_TTL: std::time::Duration = std::time::Duration::from_secs(15);

/// Cached `MemAvailable`, in MB, with the instant it was read.
static MEM_AVAILABLE_MB: std::sync::Mutex<Option<(u64, std::time::Instant)>> = std::sync::Mutex::new(None);

/// Free memory in MB as the kernel reports it (`MemAvailable`), cached for
/// [`MEM_AVAILABLE_TTL`]. `None` on any platform or kernel that doesn't publish it —
/// callers then skip the memory gate rather than refuse to work.
fn mem_available_mb() -> Option<u64> {
    let mut slot = MEM_AVAILABLE_MB.lock().ok()?;
    if let Some((mb, at)) = *slot {
        if at.elapsed() < MEM_AVAILABLE_TTL {
            return Some(mb);
        }
    }
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())?;
    let mb = kb / 1024;
    *slot = Some((mb, std::time::Instant::now()));
    Some(mb)
}

/// The free-memory floor a subtree-cache build of `leaves` leaves must clear.
///
/// The configured floor (`--subtree-free-floor-mb`, 1,200 MB by default) is sized for
/// the hosted daemon, where a build competes with hundreds of resident wallets. Applied
/// unchanged to a SINGLE-wallet daemon (desktop, phone: `single_wallet`, i.e. no shared
/// tree) it refused the background build on any laptop with less than 1.2 GB free — and
/// the identical fold then ran anyway at send time, on the user's critical path, where
/// no floor applies. So on a single-wallet daemon the floor is sized to the job instead:
/// ~32 B/leaf for its snapshot of the decoded stream, ~4 B/leaf for the cache, plus
/// headroom for the parallel fold's per-window scratch — never more than configured,
/// never under 256 MB. The hosted daemon (shared tree) keeps its configured floor.
fn subtree_build_floor_mb(configured_mb: u64, leaves: u64, single_wallet: bool) -> u64 {
    if !single_wallet {
        return configured_mb;
    }
    let job = leaves.saturating_mul(40) / (1024 * 1024) + 128;
    job.max(256).min(configured_mb)
}

/// Re-log a deferred-for-memory build this often, so a build that never starts is
/// visible in the log as such rather than silent after its first warning.
const SUBTREE_LOW_MEM_RELOG: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Payment proofs currently being computed anywhere in this daemon.
///
/// Halo 2 proving is the one thing a user is actually waiting on, and it saturates
/// every core it is given. Any other CPU-bound background work — the witness warm-up
/// (which is why it was disabled for note-heavy wallets), a subtree-cache build —
/// competes with it directly and stretches a send. On a 4-core box the cache sweep
/// across hundreds of wallets pushed a 38-spend proof from ~40 s to ~92 s at load 9.
/// So background builds check this and stand down while a payment is proving.
static PROVING_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Unix-seconds of the last shared-chain-tree reset-to-genesis, so a node that
/// keeps a cursor off its selected chain (pruned/non-archival, or unstable and
/// constantly reorging) cannot drive a genesis rebuild every ~1s lap forever —
/// the livelock an operator reported 2026-08-24 (`resetting it to genesis and
/// rebuilding` on a tight loop). 0 = never reset.
static CHAIN_TREE_LAST_RESET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Minimum seconds between shared-chain-tree genesis resets. A genuine reorg is
/// handled by the first reset; anything re-striking within this window is a node
/// that cannot serve the shielded history, so back off instead of spinning.
const CHAIN_TREE_RESET_MIN_INTERVAL: u64 = 120;

/// Marks a payment proof as in flight for as long as it is held — including on an
/// early return or a panic, which a bare increment/decrement pair would leak.
struct ProvingGuard;

impl ProvingGuard {
    fn new() -> Self {
        PROVING_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for ProvingGuard {
    fn drop(&mut self) {
        PROVING_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Whether a payment is being proved right now, i.e. background CPU work should wait.
fn proving_now() -> bool {
    PROVING_IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) > 0
}

// A global "some wallet is still backfilling" timestamp used to live here, and
// subtree-cache builds stood down while it was set. The intent was sound — on
// 2026-07-28 back-to-back cache builds held every `SYNC_CONCURRENCY` slot and
// starved a pool wallet's visible rescan — but the mechanism inverted the
// priority it was meant to protect. The flag is GLOBAL and re-stamped on every
// visit to any wallet more than 5,000 blocks behind, so a standing backlog of
// never-scanned wallets keeps it set forever. Its own doc claimed there was "no
// way for one permanently-behind wallet to suppress every other wallet's cache
// forever"; on the public daemon 108 such wallets did exactly that, and the
// result was 0 cache builds, 0 deferrals, and every resident wallet condemned to
// the O(leaves x budget) witness climb the cache exists to replace.
//
// The real constraint was never "is anything else behind" but "how many O(chain)
// sweeps may run at once", which is what a semaphore expresses. Cache builds now
// take the warm gate (`--warm-wallets`) and hold it across the sweep: bounded
// like before, but it cannot starve, because a permit is always eventually free.
// Payments still preempt — see `proving_now`.

/// Threads to give each proof when several are proven at once.
///
/// A single Halo2 proof's parallel efficiency is sublinear — measured on 4 cores at
/// 38 spends: 91.7 s at 1 thread, 50.1 s at 2 (91.5 % efficient), 37.6 s at 3 (81 %),
/// 29.7 s at 4 (77 %). Total CPU work is flat at ~92 core-seconds either way, so the
/// cores given to one proof past the second are partly wasted. Handing each proof a
/// small pool and running several at once recovers that waste: measured 2x38 spends,
/// 63.9 s sequentially (each on all 4 cores) vs 52.9 s concurrently (2x2 threads) —
/// **1.21x**, free, and the gap widens on boxes with more cores.
///
/// Two, not one: at one thread a proof is 100 % efficient but a chunked payment would
/// need as many concurrent proofs as cores, and each in-flight proof costs memory.
const PROOF_THREADS_EACH: usize = 2;

/// Free memory assumed needed per concurrent proof beyond the first. A 38-spend Halo2
/// proof holds its whole witness and extended-domain polynomials in RAM, so running
/// several at once multiplies that. Deliberately generous: the throughput this buys is
/// ~1.2x, nowhere near worth an OOM on a box that also runs a node.
const PROOF_MEM_PER_EXTRA_MB: u64 = 2_000;

/// How many chunk proofs to run at once — bounded by BOTH cores and free memory.
/// A single-core or memory-squeezed box degrades to the old strictly-sequential path.
fn proof_concurrency() -> usize {
    let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1);
    let by_cores = (cores / PROOF_THREADS_EACH).max(1);
    // Unknown memory (non-Linux, no /proc) keeps the core-derived answer.
    match mem_available_mb() {
        Some(free) => by_cores.min(1 + (free / PROOF_MEM_PER_EXTRA_MB) as usize),
        None => by_cores,
    }
}

/// Background consolidations currently between note selection and broadcast.
///
/// A consolidation spends the wallet's own notes, so it races a user payment over the
/// same notes: whichever broadcasts second is rejected by the node for reusing a
/// nullifier (no funds are at risk — it simply fails). The two directions are closed
/// separately. A consolidation never *starts* during a payment because the payment
/// holds a [`ProvingGuard`] across its whole select→submit span and the loop checks
/// [`proving_now`]. This counter closes the other direction: a payment that arrives
/// mid-consolidation waits for it to finish before selecting notes.
static CONSOLIDATING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Marks a consolidation in flight for as long as it is held (panic-safe, as [`ProvingGuard`]).
struct ConsolidateGuard;

impl ConsolidateGuard {
    fn new() -> Self {
        CONSOLIDATING.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for ConsolidateGuard {
    fn drop(&mut self) {
        CONSOLIDATING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Block until no consolidation is mid-flight, so a payment cannot select notes a
/// background merge is already proving over. Bounded: a consolidation is one
/// transaction (~35 s at the 38-note cap), so this waits seconds, never minutes, and
/// gives up rather than hanging a request if something is stuck.
async fn await_consolidation_clear() {
    let deadline = std::time::Instant::now() + CONSOLIDATE_WAIT_MAX;
    let mut logged = false;
    while CONSOLIDATING.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        if std::time::Instant::now() >= deadline {
            log::warn!("payment proceeding while a consolidation is still in flight after {CONSOLIDATE_WAIT_MAX:?}");
            return;
        }
        if !logged {
            log::info!("payment waiting for an in-flight background consolidation to finish...");
            logged = true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Longest a payment waits behind a background consolidation before going ahead anyway.
const CONSOLIDATE_WAIT_MAX: std::time::Duration = std::time::Duration::from_secs(120);

/// Note ceiling background consolidation keeps custodial wallets under, unless
/// `--auto-consolidate N` overrides it or `--no-auto-consolidate` turns it off.
///
/// On by default because the failure it prevents is severe and silent: proving costs a
/// flat ~2.4 core-seconds per note spent, so a wallet that accrues notes without bound
/// (one coinbase note per block) eventually cannot be spent from in reasonable time —
/// measured live, a 47 000-note treasury needed 237 transactions and ~2 hours to make a
/// single payment. By the time an operator notices, the cure costs as much as the
/// disease. Merging early, continuously, in the background is the only cheap moment.
///
/// The ceiling is what makes "on by default" safe on a shared daemon: an ordinary
/// wallet holds a handful of notes and is **never touched**, so it never pays a fee.
/// Only wallets far past any normal usage — miners and treasuries, exactly the ones
/// that suffer — are merged, at ~0.05 % of the merged value in fees.
pub const AUTO_CONSOLIDATE_DEFAULT: usize = 500;

/// Gap between two background consolidation transactions.
///
/// A full 38-note merge is ~30 core-seconds of proving, so this sets the duty cycle:
/// at 60 s, background merging can never take more than about a third of the box, and
/// it yields entirely while any payment is proving. Tightening this is how you would
/// re-create the CPU starvation that once stretched a 38-spend proof from 40 s to 92 s.
const CONSOLIDATE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Poll interval when every wallet is already under its note ceiling.
const CONSOLIDATE_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(120);

/// Minimum wall-clock gap between two background witness pre-advance steps for the SAME
/// wallet. The sync loop spins as fast as every 10 ms while any wallet is behind, so
/// without this a caught-up wallet would fire a `WITNESS_ADVANCE_BUDGET` step ~100×/s and
/// pin every core. One step per second caps the steady witness work to ~`BUDGET` hashes/s
/// per wallet: a cold miner wallet (≈491 K leaves) warms in ~2–3 min at low CPU, then the
/// step drops to ~1 leaf/block and idles. See [`WalletEntry::last_witness_advance`].
const WITNESS_ADVANCE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1000);

/// How long `/prepare` waits for a borrowing wallet's mirror tree to line up with the
/// shared tree before giving up. The two advance from the same block stream, so a
/// mismatch is a mid-flight artifact that clears within a sync pass; waiting a moment
/// is what the old "retry in a moment" error was asking the USER to do by hand.
/// Deliberately longer than [`PASS_BUDGET`], because the thing being waited FOR can only
/// happen once a pass ends.
///
/// A borrowing wallet's mirror is invalidated by every appended leaf and becomes valid
/// again only by adopting the shared tree's frontier at EXACTLY its own leaf count — an
/// alignment that exists between passes, not during them. This wait was 4s while a pass
/// could run to PASS_BUDGET (20s), so a payment started during a pass could not succeed
/// no matter how healthy the wallet was: it gave up before the only moment that would
/// have satisfied it. Tying the two together means the window is always reachable, and
/// anything that outlasts it is a real fault rather than a race with the sync loop.
const CHECKPOINT_ADOPT_WAIT: std::time::Duration = std::time::Duration::from_secs(PASS_BUDGET.as_secs() + 8);

/// A wallet is synced by the background loop only while it has been touched by a
/// request within this window; after that it is parked until the next request. Keeps a
/// public daemon's CPU proportional to *active* wallets, not total tokens ever seen.

/// How many active wallets the sync loop advances **concurrently**. The per-wallet
/// scan is CPU-bound (Sinsemilla appends + trial decryption) with no await inside, so
/// a single sequential loop pins exactly one core while the other cores sit idle — a
/// wallet then advances at (one core's rate ÷ number of active wallets), which crawls
/// once several wallets are active (observed: a wallet "stuck at 74%" on the live
/// daemon while one tokio worker ran at 99% and the rest were idle). Running a bounded
/// number in parallel uses the idle cores, multiplying throughput ~N×. Bounded (not
/// unbounded) so it never consumes every core — HTTP handlers, the node, and the
/// mempool loop must still get scheduled. Kept at cores-2 (min 2) to leave headroom.
/// Adaptive wallet catch-up fan-out. Each active wallet owns a large commitment
/// tree, so memory pressure must reduce concurrency before the host starts swapping.
/// On the 4-core hosted VPS this normally resolves to two jobs, leaving headroom for
/// the node, HTTP handlers, and the shared page decoder.
fn sync_concurrency(resources: &ResourceLimits) -> usize {
    let configured = resources.sync_wallets.max(1);
    let per_wallet_mb = resources.sync_wallet_memory_mb.max(64);
    let memory_cap = mem_available_mb().map(|mb| (mb / per_wallet_mb).max(1) as usize).unwrap_or(configured);
    configured.min(memory_cap)
}

/// How many wallets may be in their one-time COLD WARM at once.
///
/// Warming is the only sync work that runs flat out for whole seconds at a time
/// (`COLD_WARM_TICK`), so without a cap of its own every [`SYNC_CONCURRENCY`] slot can be
/// occupied by one, pinning a core each. On the live 4-core host that left one core for
/// the HTTP handlers, the node RPC and Halo 2 proving combined — so one user's first send
/// visibly slowed everyone else's sync. Ordinary incremental sync is unaffected by this
/// cap; only the heavy catch-up queues behind it.

/// Real sleep between wallets in the sync loop, to guarantee CPU headroom for the HTTP
/// handlers even while scans run. Caps sync throughput; keeps the daemon responsive.
/// Hard ceiling on any single node RPC made from the shared sync loop. The loop drives
/// every wallet sequentially, so an un-timed-out await there is a whole-daemon stall, not
/// a one-wallet stall (see `sync_chunk`). Generous enough that a merely busy node is never
/// mistaken for a dead one.
const SYNC_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// How often the sync loop re-checks the chain + mempool once every active wallet is
/// caught up. This is the floor on how fast an incoming payment can appear, so it is a
/// UX number, not a throughput one.
const IDLE_SYNC_POLL: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the dedicated mempool loop looks for unmined payments. This is the floor on
/// "the receiver's screen changed" — keep it fast; the work behind it is trivial.
const MEMPOOL_POLL: std::time::Duration = std::time::Duration::from_millis(700);
/// The mempool loop's cadence while no active wallet is at the tip yet (see there).
const MEMPOOL_POLL_BEHIND: std::time::Duration = std::time::Duration::from_secs(5);
// 150→50 ms: with the bounded-parallel loop another scan task overlaps this sleep, so
// its only job is guaranteeing the HTTP runtime a scheduling gap — 50 ms is plenty.
const SYNC_WALLET_THROTTLE_MS: u64 = 50;

/// Idle wallets are evicted from RAM after this long without a request. The on-disk
/// checkpoint IS the wallet; memory is only a cache of it, and reloading on the next
/// touch costs a file read (witness state included since v5). On a hosted daemon with
/// hundreds of one-visitor browsers, the resident set otherwise grows with every token
/// ever seen — forever.
/// Hard cap on resident wallets regardless of idleness; the least-recently-touched go
/// first. A generous browser cohort fits well under this; it exists for the day the
/// hosted wallet count stops fitting.
/// The eviction sweep itself runs at most this often (cheap map walk; the victim
/// checkpoint flushes are the real work, and victims are rare).
const EVICT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Persist a wallet's scan checkpoint atomically (write-tmp + rename). `genesis`
/// is the network genesis hash (a chain relaunch invalidates the checkpoint);
/// `low` is the last ingested chain block, from which sync resumes. The
/// matured-anchor ring and sink blue score ride along so a restarted wallet can
/// select a matured spend anchor without a replay.
fn save_checkpoint(
    dir: &str,
    token: &str,
    genesis: &RpcHash,
    low: &RpcHash,
    scanned: u64,
    db: &WalletDb,
    boundaries: &VecDeque<(u64, u64)>,
    sink_blue: u64,
    blind_below: u64,
) -> std::io::Result<()> {
    let buf = checkpoint_bytes(genesis, low, scanned, db, boundaries, sink_blue, blind_below);
    write_checkpoint_bytes(dir, token, &buf)
}

/// The serialised checkpoint file for [`save_checkpoint`], built from the wallet
/// state alone. Split from the write so the sync loop can serialise under the wallet
/// lock and hand the bytes to a blocking thread: the blob copies every retained leaf
/// (32 B each — tens to hundreds of MB mid-restore), and writing it inline held the
/// lock AND a runtime worker for the whole `fs::write`.
fn checkpoint_bytes(
    genesis: &RpcHash,
    low: &RpcHash,
    scanned: u64,
    db: &WalletDb,
    boundaries: &VecDeque<(u64, u64)>,
    sink_blue: u64,
    blind_below: u64,
) -> Vec<u8> {
    let db_blob = db.to_checkpoint();
    let mut buf = Vec::with_capacity(SCAN_HEADER_LEN + 8 + db_blob.len() + 4 + boundaries.len() * 16 + 8);
    buf.extend_from_slice(SCAN_MAGIC);
    buf.push(SCAN_VERSION);
    buf.extend_from_slice(&genesis.as_bytes());
    buf.extend_from_slice(&low.as_bytes());
    buf.extend_from_slice(&scanned.to_le_bytes());
    buf.extend_from_slice(&(db_blob.len() as u64).to_le_bytes());
    buf.extend_from_slice(&db_blob);
    buf.extend_from_slice(&(boundaries.len() as u32).to_le_bytes());
    for (blue, leaves) in boundaries {
        buf.extend_from_slice(&blue.to_le_bytes());
        buf.extend_from_slice(&leaves.to_le_bytes());
    }
    buf.extend_from_slice(&sink_blue.to_le_bytes());
    buf.extend_from_slice(&blind_below.to_le_bytes());
    buf
}

/// Write a serialised checkpoint (from [`checkpoint_bytes`]) atomically: tmp + rename.
///
/// The tmp name is unique per write. The sync loop now writes OFF the wallet lock,
/// so it can overlap a write from the lock-holding paths (`/api/checkpoint` on app
/// pause, the eviction sweep, the twin-clone flush); two writers on one shared
/// `.tmp` would truncate each other and rename a torn blob into place.
fn write_checkpoint_bytes(dir: &str, token: &str, buf: &[u8]) -> std::io::Result<()> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = scan_path(dir, token);
    let tmp = format!("{path}.{}.tmp", SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    // A unique name is never reused, so a failed write must clean up after itself or a
    // full disk grows a fresh partial `.tmp` on every retry.
    std::fs::write(&tmp, buf).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The cursor block a wallet's checkpoint resumes from, read from the header alone.
/// Needed before the body is parsed, because the node must be asked for the tree state
/// *at that block* so the restore can skip the leaf replay.
fn checkpoint_cursor(dir: &str, token: &str, current_genesis: &RpcHash) -> Option<RpcHash> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || !matches!(buf[4], SCAN_VERSION | SCAN_VERSION_PREV) {
        return None;
    }
    if RpcHash::from_bytes(buf[5..37].try_into().ok()?) != *current_genesis {
        return None;
    }
    Some(RpcHash::from_bytes(buf[37..69].try_into().ok()?))
}

/// `(cursor, cursor DAA score)` from the fixed header of the checkpoint file at `path`
/// (a live `.scan` or a quarantined `.scan.stale-*` / `.scan.bak` copy), or `None` unless
/// it is a checkpoint for `current_genesis`. Reads only the header — the body can be
/// hundreds of megabytes and this runs on error paths and at every load.
fn checkpoint_header(path: &str, current_genesis: &RpcHash) -> Option<(RpcHash, u64)> {
    use std::io::Read as _;
    let mut buf = [0u8; SCAN_HEADER_LEN];
    std::fs::File::open(path).ok()?.read_exact(&mut buf).ok()?;
    if &buf[0..4] != SCAN_MAGIC || !matches!(buf[4], SCAN_VERSION | SCAN_VERSION_PREV) {
        return None;
    }
    if RpcHash::from_bytes(buf[5..37].try_into().ok()?) != *current_genesis {
        return None;
    }
    let cursor = RpcHash::from_bytes(buf[37..69].try_into().ok()?);
    let scanned = u64::from_le_bytes(buf[69..77].try_into().ok()?);
    Some((cursor, scanned))
}

/// Positive evidence that the node's chain has REACHED a wallet cursor at DAA
/// `cursor_daa`: the node reports itself synced AND its virtual DAA score is at or past
/// the cursor. Only then is an absent-header answer for that cursor proof the cursor is
/// gone (pruned / off the selected chain). A node that is merely behind — in IBD, still
/// backfilling, or a public node re-syncing from genesis — answers `cannot find header`
/// for any block it has not received yet, and a walletd repointed at one (desktop
/// "Chain source" switch, 2026-09) used to retire a fully synced checkpoint on it.
/// `Err` carries the reason for the log line; a node that cannot answer in time is
/// `Err` too, never evidence.
async fn node_reaches(client: &GrpcClient, cursor_daa: u64, timeout: std::time::Duration) -> Result<(), String> {
    let synced = match tokio::time::timeout(timeout, client.get_sync_status()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("get_sync_status failed: {e}")),
        Err(_) => return Err("get_sync_status timed out".into()),
    };
    let tip = match tokio::time::timeout(timeout, client.get_block_dag_info()).await {
        Ok(Ok(d)) => d.virtual_daa_score,
        Ok(Err(e)) => return Err(format!("get_block_dag_info failed: {e}")),
        Err(_) => return Err("get_block_dag_info timed out".into()),
    };
    if !synced {
        return Err(format!("node reports NOT synced (tip DAA {tip}, cursor DAA {cursor_daa})"));
    }
    if tip < cursor_daa {
        return Err(format!("node tip DAA {tip} is below the cursor DAA {cursor_daa}"));
    }
    Ok(())
}

/// Take `token`'s `.scan.stale-<ts>` quarantine copies out of `restore_quarantined`'s
/// reach by renaming them `.rescanned` (kept for forensics, never auto-restored). Called
/// by `/rescan`, whose whole point is to rebuild rather than resume.
fn retire_quarantine_copies(dir: &str, token: &str) {
    let prefix = format!("{token}.scan.stale-");
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for name in rd.flatten().filter_map(|e| e.file_name().into_string().ok()) {
        if name.strip_prefix(&prefix).is_some_and(|stamp| stamp.parse::<u64>().is_ok()) {
            let _ = std::fs::rename(format!("{dir}/{name}"), format!("{dir}/{name}.rescanned"));
        }
    }
}

/// Load a wallet's scan checkpoint if present and still valid for
/// `current_genesis` (the network genesis hash). Returns the reconstructed
/// `(db, low_cursor, scanned, boundaries, sink_blue)`, or `None` on any absence /
/// corruption / version or genesis mismatch — the caller then rescans, so a stale
/// checkpoint can never yield a wrong tree.
#[allow(clippy::type_complexity)]
fn load_checkpoint(
    dir: &str,
    token: &str,
    key: WalletKey,
    current_genesis: &RpcHash,
    tip: Option<&kaspa_shielded_core::tree::FrontierState>,
) -> Option<(WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64, u64)> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    let (saved_genesis, rest) = parse_scan_bytes(&buf, key, tip)?;
    if saved_genesis != *current_genesis {
        return None; // chain relaunched → rescan
    }
    Some(rest)
}

/// Parse one scan-file blob into `(genesis, (db, low, scanned, boundaries,
/// sink_blue, blind_below))`. Factored out of [`load_checkpoint`] so the offline
/// admin tooling (`--diagnose`, `--graft`) can read snapshots at arbitrary paths
/// with exactly the daemon's own parser.
#[allow(clippy::type_complexity)]
fn parse_scan_bytes(
    buf: &[u8],
    key: WalletKey,
    tip: Option<&kaspa_shielded_core::tree::FrontierState>,
) -> Option<(RpcHash, (WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64, u64))> {
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || !matches!(buf[4], SCAN_VERSION | SCAN_VERSION_PREV) {
        return None;
    }
    let saved_genesis = RpcHash::from_bytes(buf[5..37].try_into().ok()?);
    let low = RpcHash::from_bytes(buf[37..69].try_into().ok()?);
    let scanned = u64::from_le_bytes(buf[69..77].try_into().ok()?) as usize;
    let mut pos = SCAN_HEADER_LEN;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        let s = buf.get(*pos..end)?;
        *pos = end;
        Some(s)
    };
    let db_len = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?) as usize;
    let blob = take(&mut pos, db_len)?;
    let mut db = match tip {
        Some(fs) => key.db_from_checkpoint_with_tip(blob, fs)?,
        None => key.db_from_checkpoint(blob)?,
    };
    // A syntactically valid checkpoint is not necessarily a canonical one. Older
    // walletd versions could ingest ordinary-accepted shielded bundles whose state
    // transition was actually dropped, leaving a plausible but divergent tree.
    // Bind every restored checkpoint to the node's frontier at its exact cursor.
    if let Some(fs) = tip {
        // A checkpoint written while borrowing the shared tree records no tip frontier,
        // so the restored mirror tree is empty and its anchor would fail the check
        // below — throwing away a perfectly good checkpoint and forcing a full rescan.
        //
        // Adopt the NODE's frontier at this exact cursor instead. That is what the
        // wallet's tree should be, and `adopt_tip_frontier` accepts it only if it
        // describes the same leaf count, so the size binding is still enforced. What is
        // NOT re-derived is the root — for a wallet that never hashed, the root was
        // never its own claim to make. Its protection is elsewhere and fails closed: a
        // wallet whose stream diverged produces witnesses that fail `subtree_paths`'
        // root check, so it declines to spend rather than spending wrongly.
        if !db.tree_is_valid() {
            db.adopt_tip_frontier(fs);
        }
        let expected = GlobalTree::from_state(fs).ok()?.anchor().to_bytes();
        if db.size() != fs.size || db.anchor() != expected {
            log::warn!(
                "rejecting divergent wallet checkpoint at cursor {low}: wallet size/root {}/{}, node size/root {}/{}",
                db.size(),
                hex(&db.anchor()),
                fs.size,
                hex(&expected),
            );
            return None;
        }
    }
    let ring_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    let mut boundaries = VecDeque::with_capacity(ring_len.min(MATURED_RING));
    for _ in 0..ring_len {
        let blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        let leaves = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        boundaries.push_back((blue, leaves));
    }
    let sink_blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    // v4 trailer: the frontier size this view was anchored on while the wallet may
    // hold OLDER notes it cannot see (0 = complete view). v3 files predate it.
    let blind_below = if buf[4] == SCAN_VERSION { u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?) } else { 0 };
    if pos != buf.len() {
        return None;
    }
    Some((saved_genesis, (db, low, scanned, boundaries, sink_blue, blind_below)))
}

// ---------------------------------------------------------------------------
// Twin-checkpoint adoption: "enter the seed on a second device → synced at once".
//
// A scan checkpoint is a pure function of (full viewing key, public chain): the
// notes, positions, witnesses and cursor in it are exactly what ANY scan with
// that key would produce. So when a seed/FVK is registered under a fresh token
// and some other token on this daemon has already scanned the same key, cloning
// that token's checkpoint hands the new registration a fully synced wallet —
// and hands it nothing the presented key couldn't derive by scanning, so the
// fast path is security-neutral. Spend authority is not involved at all.
// ---------------------------------------------------------------------------

/// The `blind_below` trailer of a checkpoint file, read without the wallet key
/// (the full body needs one; the trailer is plain). `0` = the view is complete.
fn checkpoint_blind_below(path: &str) -> Option<u64> {
    let buf = std::fs::read(path).ok()?;
    if buf.len() < SCAN_HEADER_LEN + 8 || &buf[0..4] != SCAN_MAGIC {
        return None;
    }
    match buf[4] {
        SCAN_VERSION => Some(u64::from_le_bytes(buf[buf.len() - 8..].try_into().ok()?)),
        SCAN_VERSION_PREV => Some(0), // v3 predates fast-sync blindness — always a full view
        _ => None,
    }
}

/// Find another token in `dir` holding the SAME full viewing key with a resumable
/// checkpoint for `genesis`, and clone that checkpoint for `token`. Returns the
/// donor token and the birthday to persist (the earlier of the donor's and the
/// requested one, so a later cold rescan can never skip notes either wallet knew
/// about). `candidates` comes from the in-RAM viewing-key index; every donor is
/// re-verified against its wallet file here, so a stale index entry (a token that
/// re-imported a different seed since) is harmless.
fn adopt_twin_checkpoint(
    dir: &str,
    token: &str,
    fvk: &[u8; 96],
    birthday: u64,
    want_history: bool,
    genesis: &RpcHash,
    secret: Option<&str>,
    candidates: &[String],
) -> Option<(String, u64)> {
    let mut best: Option<(String, u64, std::time::SystemTime)> = None;
    for donor in candidates {
        if donor == token {
            continue;
        }
        if checkpoint_cursor(dir, donor, genesis).is_none() {
            continue;
        }
        let Some((key, donor_birthday, donor_history)) = load_wallet_meta(dir, donor, secret) else { continue };
        if key.fvk_bytes() != Some(*fvk) {
            continue;
        }
        // History rows live INSIDE the checkpoint and are only recorded while the flag
        // is on. A wallet that keeps history must not clone a twin that does not: the
        // clone carries the twin's notes but none of the rows, and the user's History
        // tab goes empty from one load to the next (reported 2026-09-19, right after
        // birthday-0 registrations started adopting twins instead of scanning).
        if want_history && !donor_history {
            continue;
        }
        // Only adopt a view at least as complete as this registration asked for: a
        // donor fast-synced from a LATER birthday is blind to older notes
        // (`blind_below` > 0) that a birthday-0 / earlier-birthday restore explicitly
        // wants recovered — scanning honestly beats inheriting someone else's blind
        // spot and silently under-reporting the balance.
        // `birthday == 0` means the client has NO opinion (a re-pair, a second device, a
        // service switch that lost its local copy), not "scan from genesis": the donor's
        // birthday is a fact the same user asserted for the same key, so it is adopted
        // along with the view. Seen live 2026-09-16: seven registrations of one key at
        // birthday 0, each refusing its own synced twin and rescanning from genesis. A
        // deliberate everything-from-genesis scan is `/rescan`, not a registration.
        let blind = checkpoint_blind_below(&scan_path(dir, donor)).unwrap_or(u64::MAX);
        if blind != 0 && birthday != 0 && birthday < donor_birthday {
            continue;
        }
        // Freshest donor wins: least catch-up left for the clone.
        let mtime = std::fs::metadata(scan_path(dir, donor)).and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(_, _, m)| mtime > *m) {
            best = Some((donor.clone(), donor_birthday, mtime));
        }
    }
    let (donor, donor_birthday, _) = best?;
    // save_checkpoint writes are atomic (tmp + rename), so a plain copy always sees
    // a consistent file. At worst it lags the donor's RAM state by CHECKPOINT_EVERY
    // blocks; the clone re-scans that tail in seconds.
    std::fs::copy(scan_path(dir, &donor), scan_path(dir, token)).ok()?;
    Some((donor, if birthday == 0 { donor_birthday } else { donor_birthday.min(birthday) }))
}

/// One pass over every wallet file in `dir` → viewing key → tokens map. Argon2 per
/// encrypted seed file, so this belongs on a blocking thread (startup does ~50 ms ×
/// wallet count there once; registrations keep the map current after that).
fn build_fvk_index(dir: &str, secret: Option<&str>) -> HashMap<[u8; 96], HashSet<String>> {
    let mut map: HashMap<[u8; 96], HashSet<String>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return map };
    for name in entries.flatten().filter_map(|e| e.file_name().into_string().ok()) {
        let Some(token) = name.strip_suffix(".json") else { continue };
        let Some((key, ..)) = load_wallet_meta(dir, token, secret) else { continue };
        if let Some(f) = key.fvk_bytes() {
            map.entry(f).or_default().insert(token.to_string());
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Offline admin tooling (`--diagnose` / `--graft`). Run with the daemon STOPPED:
// both operate on the same scan files the sync loop rewrites.

/// Report every wallet in `dir`: note count, compaction base, and — the reason
/// this exists — **stranded** notes (below the base with no witness; the
/// note@564934 incident). One line per wallet.
pub fn diagnose_wallets(dir: &str, secret: Option<&str>) -> String {
    let mut out = String::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return format!("cannot read wallet dir {dir}\n");
    };
    let mut tokens: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".scan").map(str::to_owned))
        .collect();
    tokens.sort();
    for token in tokens {
        let Some((key, ..)) = load_wallet_meta(dir, &token, secret) else {
            out.push_str(&format!("{token}: wallet file missing/undecryptable (need --wallet-secret?)\n"));
            continue;
        };
        let Ok(buf) = std::fs::read(scan_path(dir, &token)) else {
            out.push_str(&format!("{token}: scan file unreadable\n"));
            continue;
        };
        let Some((_, (db, _, scanned, ..))) = parse_scan_bytes(&buf, key, None) else {
            out.push_str(&format!("{token}: scan checkpoint does not parse\n"));
            continue;
        };
        let stranded = db.stranded_notes();
        let stranded_value: u64 = stranded.iter().map(|n| n.value()).sum();
        out.push_str(&format!(
            "{token}: notes={} balance={} scanned={} base={} size={} stranded={} stranded_value={}{}\n",
            db.notes().len(),
            fmt_fc(db.balance()),
            scanned,
            db.base_size(),
            db.size(),
            stranded.len(),
            fmt_fc(stranded_value as u128),
            if stranded.is_empty() {
                String::new()
            } else {
                format!(" positions={:?}", stranded.iter().map(|n| n.position).collect::<Vec<_>>())
            },
        ));
    }
    out
}

/// Repair a stranded wallet (see [`WalletDb::graft_history`]) by re-inserting the
/// leaf prefix from `older_scan` — an older snapshot of the SAME wallet (its
/// `.scan.bak`, a `wallets-PRESERVE` copy, …). Verifies the streams agree before
/// touching anything, then rewrites the wallet's scan checkpoint in place.
pub fn graft_wallet(dir: &str, token: &str, older_scan: &str, secret: Option<&str>) -> Result<String, String> {
    let (key, ..) = load_wallet_meta(dir, token, secret).ok_or("wallet file missing/undecryptable (need --wallet-secret?)")?;
    let buf = std::fs::read(scan_path(dir, token)).map_err(|e| format!("read current scan: {e}"))?;
    let (genesis, (mut db, low, scanned, boundaries, sink_blue, blind_below)) =
        parse_scan_bytes(&buf, key, None).ok_or("current scan checkpoint does not parse")?;
    let old_buf = std::fs::read(older_scan).map_err(|e| format!("read older snapshot: {e}"))?;
    let (old_genesis, (old_db, ..)) = parse_scan_bytes(&old_buf, key, None).ok_or("older snapshot does not parse")?;
    if old_genesis != genesis {
        return Err("older snapshot is from a different chain (genesis mismatch)".into());
    }
    let before = db.stranded_notes().len();
    let restored = db.graft_history(&old_db).map_err(|e| e.to_string())?;
    let after = db.stranded_notes().len();
    save_checkpoint(dir, token, &genesis, &low, scanned as u64, &db, &boundaries, sink_blue, blind_below)
        .map_err(|e| format!("write repaired checkpoint: {e}"))?;
    Ok(format!("grafted {restored} leaves back (base now {}); stranded notes {before} -> {after}", db.base_size()))
}

// ---------------------------------------------------------------------------
// Shared sync page cache
//
// During a mass rescan every wallet walks the same chain-block stream from the
// same start (the pruning point), so without sharing, N wallets cost N full
// chain fetches (~170 x 169K blocks observed live). Caching each
// `GetShieldedBlocks` page by its start cursor for a few seconds means one
// fetch serves the whole cohort — fetch cost becomes O(chain), leaving only
// per-wallet trial decryption. The short TTL keeps near-tip pages fresh (the
// same cursor returns more blocks as the chain grows).
// ---------------------------------------------------------------------------

/// One chain block, fetched once and **decoded once** for the whole wallet cohort.
/// The two costs that are identical for every wallet — parsing each accepted
/// bundle, and computing each coinbase note's Sinsemilla leaf commitment — are paid
/// here, so a wallet's per-block work drops to the parts that actually depend on its
/// key (a coinbase recipient byte-compare, and trial-decryption of the rare real
/// payment bundles). `coinbase` holds only the notes that commit successfully, in
/// coinbase order — exactly what `WalletDb::ingest_block_precomputed` expects.
struct DecodedBlock {
    hash: RpcHash,
    blue_score: u64,
    daa_score: u64,
    coinbase: Vec<(kaspa_shielded_core::coinbase::CoinbaseNoteDesc, u64, kaspa_shielded_core::ExtractedNoteCommitment)>,
    /// Accepted txs' actions in compact form (parallel to `txids`), from the
    /// node's compact scan archive (`accepted_actions`).
    compact: Vec<Vec<CompactActionRecord>>,
    /// Txid per accepted tx (parallel to `compact`), from the v2 RPC fields.
    /// Empty when the node predates them — history simply isn't recorded then.
    txids: Vec<[u8; 32]>,
    coinbase_txid: [u8; 32],
    /// Header timestamp ms (0 from a pre-v2 node).
    timestamp: u64,
}

/// A decoded `GetShieldedBlocks` page: the response envelope plus the per-block
/// decode shared across wallets.
struct DecodedPage {
    reorged: bool,
    sink_blue_score: u64,
    blocks: Vec<DecodedBlock>,
}

/// Whether to trust a node-supplied coinbase commitment verbatim instead of
/// re-deriving it. Off by default (safety); operators syncing against their own
/// trusted node can set ZKAS_WALLETD_TRUST_NODE_CMX=1 to skip the Sinsemilla
/// re-derivation on a full historical backfill.
fn trust_node_cmx() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("ZKAS_WALLETD_TRUST_NODE_CMX").as_deref() == Ok("1"))
}

/// Choose the authoritative coinbase note commitment for a coinbase output.
///
/// The commitment is fully determined by PoW-committed block data (the recipient
/// script, coinbase txid, output index and value that feed desc/value), so the
/// locally-derived value is authoritative. A node-supplied commitment is only a
/// CPU hint. In the default (secure) mode we derive locally and, if the node also
/// supplied one, verify they match: a valid-but-wrong supplied leaf would silently
/// fork the wallet note-commitment tree and break every future spend. In
/// trust_node mode we take the supplied value as-is (fast path, opt-in).
fn select_coinbase_cmx(
    supplied: Option<kaspa_shielded_core::ExtractedNoteCommitment>,
    desc: &kaspa_shielded_core::coinbase::CoinbaseNoteDesc,
    value: u64,
    trust_node: bool,
) -> Option<kaspa_shielded_core::ExtractedNoteCommitment> {
    if trust_node {
        return supplied.or_else(|| kaspa_shielded_core::coinbase::coinbase_note_commitment(desc, value).ok());
    }
    match kaspa_shielded_core::coinbase::coinbase_note_commitment(desc, value).ok() {
        Some(derived) => {
            if let Some(sup) = supplied {
                if sup.to_bytes() != derived.to_bytes() {
                    log::warn!(
                        "coinbase commitment mismatch: node-supplied value != local derivation; using derived (node may be faulty or malicious)"
                    );
                }
            }
            Some(derived)
        }
        // A well-formed coinbase output always derives; fall back rather than drop.
        None => supplied,
    }
}

/// Shared page decoding gets a bounded pool so it cannot consume every host core
/// and starve HTTP or kaspad while several wallets ingest concurrently. Two threads
/// are used on a 4-core box; larger wallet hosts expand to `cores - 2`, capped at
/// eight. This pool is shared by every wallet and never multiplies per scan.
fn decode_block(b: &kaspa_rpc_core::RpcShieldedChainBlock) -> DecodedBlock {
    let mut coinbase = Vec::new();
    for (i, out) in b.coinbase_outputs.iter().enumerate() {
        if out.script_public_key.len() >= ORCHARD_SCRIPT_LEN {
            let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
            recipient.copy_from_slice(&out.script_public_key[..ORCHARD_SCRIPT_LEN]);
            let mut note_seed = Vec::with_capacity(36);
            note_seed.extend_from_slice(&b.coinbase_txid.as_bytes());
            note_seed.extend_from_slice(&(i as u32).to_le_bytes());
            let desc = derive_coinbase_note_desc(recipient, &note_seed);
            // Only keep a note that commits — exactly `WalletDb::ingest_block`'s skip
            // rule, so the shared leaf stream matches the recompute path leaf-for-leaf.
            let supplied = out.commitment.and_then(|bytes| {
                Option::<kaspa_shielded_core::ExtractedNoteCommitment>::from(
                    kaspa_shielded_core::ExtractedNoteCommitment::from_bytes(&bytes),
                )
            });
            // Never trust a coinbase leaf we cannot reproduce: derive it from the
            // PoW-committed block fields and reject a valid-but-wrong node value
            // (which would silently fork the wallet tree). See select_coinbase_cmx.
            let cmx = select_coinbase_cmx(supplied, &desc, out.value, trust_node_cmx());
            if let Some(cmx) = cmx {
                coinbase.push((desc, out.value, cmx));
            }
        }
    }
    // Chunk each accepted tx's compact bytes into 148-byte records; keep the txid
    // pairing aligned (a malformed length drops its txid with it).
    let mut compact = Vec::with_capacity(b.accepted_actions.len());
    let mut txids = Vec::with_capacity(b.accepted_actions.len());
    for (i, bytes) in b.accepted_actions.iter().enumerate() {
        if let Some(records) = decode_compact_actions(bytes) {
            compact.push(records);
            txids.push(b.accepted_txids.get(i).map(|h| h.as_bytes()).unwrap_or([0u8; 32]));
        }
    }
    DecodedBlock {
        hash: b.hash,
        blue_score: b.blue_score,
        daa_score: b.daa_score,
        coinbase,
        compact,
        txids,
        coinbase_txid: b.coinbase_txid.as_bytes(),
        timestamp: b.timestamp,
    }
}

/// Chunk a node's concatenated compact-action bytes into [`CompactActionRecord`]s.
/// `None` if the length is not a whole number of 148-byte records.
/// The full shielded bundle of `txid`, which chain block `chain` ACCEPTED. The tx body lives
/// in `chain` itself or in one of its mergeset blocks, so fetch those with transactions and
/// match on the id. `None` when the node no longer holds the block bodies (pruned) or the
/// tx carries no shielded bundle.
async fn fetch_bundle_for_tx(client: &GrpcClient, chain: RpcHash, txid: &[u8; 32]) -> Option<ShieldedBundle> {
    let first = tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block(chain, true)).await.ok()?.ok()?;
    let mut candidates = vec![chain];
    if let Some(v) = &first.verbose_data {
        candidates.extend(v.merge_set_blues_hashes.iter().copied());
        candidates.extend(v.merge_set_reds_hashes.iter().copied());
    }
    let find = |b: &kaspa_rpc_core::RpcBlock| -> Option<ShieldedBundle> {
        b.transactions
            .iter()
            .find(|t| t.verbose_data.as_ref().is_some_and(|v| v.transaction_id.as_bytes() == *txid))
            .and_then(|t| ShieldedBundle::from_bytes(&t.payload).ok())
    };
    if let Some(b) = find(&first) {
        return Some(b);
    }
    for h in candidates.into_iter().skip(1) {
        let Ok(Ok(blk)) = tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block(h, true)).await else { continue };
        if let Some(b) = find(&blk) {
            return Some(b);
        }
    }
    None
}

fn decode_compact_actions(bytes: &[u8]) -> Option<Vec<CompactActionRecord>> {
    if bytes.len() % CompactActionRecord::SERIALIZED_LEN != 0 {
        return None;
    }
    bytes.chunks_exact(CompactActionRecord::SERIALIZED_LEN).map(CompactActionRecord::from_bytes).collect()
}

struct PageCache {
    map: HashMap<(RpcHash, u64), (std::time::Instant, Arc<DecodedPage>)>,
    order: VecDeque<(RpcHash, u64)>,
    /// Pages being fetched right now, so simultaneous askers wait for one answer
    /// instead of each fetching and decoding the same page. See `fetch_shielded_page`.
    in_flight: HashMap<(RpcHash, u64), Arc<tokio::sync::Semaphore>>,
    pool: Arc<rayon::ThreadPool>,
    ttl: std::time::Duration,
    cap: usize,
}

impl PageCache {
    fn new(resources: &ResourceLimits) -> Self {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(resources.page_decode_threads.max(1))
            .thread_name(|i| format!("wallet-page-decode-{i}"))
            .build()
            .expect("build wallet page decode pool");
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            in_flight: HashMap::new(),
            pool: Arc::new(pool),
            ttl: std::time::Duration::from_secs(resources.page_cache_ttl_secs.max(1)),
            cap: resources.page_cache_entries.max(1),
        }
    }
}

/// Fetch one `GetShieldedBlocks` page through the shared cache, decoding it once.
/// During a mass rescan every active wallet walks the same stream, so the single
/// fetch+decode here serves the whole cohort for `PAGE_CACHE_TTL`. The cache key
/// includes the page limit: a 16-block tip page and a 1000-block catch-up page
/// from the same cursor are different answers.
/// Concurrent read-ahead for a deep (restore/catch-up) scan.
///
/// The per-page prefetch in `sync_chunk` only ever warms ONE page ahead, because a
/// full page reveals exactly one future cursor (its last block hash). On a
/// fetch-bound client - a phone hitting a remote node, where a page is round-trip
/// latency and not CPU - that leaves the loop fetching pages strictly one at a time
/// with the cores idle in between. This discovers the next `depth` page boundaries
/// with cheap `metadata_only` scouts (header-only, no archive read; the node returns
/// up to 2000 hashes per call = two page boundaries) and fires the full-page fetches
/// CONCURRENTLY into the shared page cache, so the ingest loop finds them warm.
///
/// Fire-and-forget and cache-only: it never advances a cursor or touches the tree, so
/// a failed or reorged scout can only waste a fetch, never a note. `depth` includes
/// the page at `start` itself.
async fn deep_prefetch(state: std::sync::Arc<AppState>, client: GrpcClient, start: RpcHash, depth: usize) {
    let page = SHIELDED_PAGE as usize;
    let warm = |cur: RpcHash| {
        let st = state.clone();
        let cl = client.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                SYNC_RPC_TIMEOUT,
                fetch_shielded_page(&cl, &st.page_cache, cur, SHIELDED_PAGE),
            )
            .await;
        });
    };
    // Page 1: the very next page the loop will ask for (deduped against the loop's
    // own fetch and the per-page prefetch by the in-flight gate).
    warm(start);
    let mut warmed = 1usize;
    let mut anchor = start; // exclusive cursor of the page we scout past
    while warmed < depth {
        let meta = match tokio::time::timeout(
            SYNC_RPC_TIMEOUT,
            client.get_shielded_block_metadata(anchor, 2 * SHIELDED_PAGE),
        )
        .await
        {
            Ok(Ok(m)) if !m.reorged => m,
            // Scout failed / reorged / node busy: stop. The loop's own fetch still
            // covers `start`; the next chunk retries the read-ahead.
            _ => break,
        };
        // The 1000th and 2000th block after `anchor` are the exclusive cursors of the
        // next two full pages.
        for boundary in [page - 1, 2 * page - 1] {
            if warmed >= depth {
                break;
            }
            match meta.blocks.get(boundary) {
                Some(b) => {
                    warm(b.hash);
                    warmed += 1;
                }
                // Short page: reached the tip, nothing further to warm.
                None => return,
            }
        }
        if (meta.blocks.len() as u64) < 2 * SHIELDED_PAGE {
            break; // reached the tip
        }
        anchor = meta.blocks[2 * page - 1].hash;
    }
}

async fn fetch_shielded_page(
    client: &GrpcClient,
    cache: &Mutex<PageCache>,
    low: RpcHash,
    limit: u64,
) -> Result<Arc<DecodedPage>, kaspa_rpc_core::RpcError> {
    let key = (low, limit);
    {
        let c = cache.lock().await;
        if let Some((at, resp)) = c.map.get(&key) {
            if at.elapsed() < c.ttl {
                return Ok(resp.clone());
            }
        }
    }
    // Miss. Everyone who misses the SAME page queues behind one fetch rather than
    // each running their own.
    //
    // The cache only ever helped askers who arrived after a fetch had finished. The
    // ones that matter arrive together: the sync loop advances several wallets at once
    // (`--sync-wallets 8`) and, once they are caught up, they all want the same tip
    // page in the same pass. Each was doing its own `get_shielded_blocks` AND its own
    // parallel decode of the identical bytes — and the decode is the expensive half
    // (~1 ms/block of Sinsemilla), burning cores on the box that is also proving
    // somebody's payment.
    let gate = {
        let mut c = cache.lock().await;
        // This call is wrapped in a timeout by the sync loop, so a caller can be
        // dropped between taking the slot and clearing it — Drop cannot clear it,
        // since releasing needs the cache lock and Drop cannot await. Abandoned slots
        // are therefore collected here: a strong count of one means the map is the
        // only holder, so nobody is fetching or waiting on it. Cheap, and it keeps a
        // map keyed by page from growing on every cancelled fetch.
        c.in_flight.retain(|k, gate| *k == key || Arc::strong_count(gate) > 1);
        c.in_flight.entry(key).or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1))).clone()
    };
    let _lead = gate.acquire().await;
    // The leader may have filled the cache while we waited, which is the whole point.
    {
        let c = cache.lock().await;
        if let Some((at, resp)) = c.map.get(&key) {
            if at.elapsed() < c.ttl {
                return Ok(resp.clone());
            }
        }
    }

    let pool = { cache.lock().await.pool.clone() };
    // Not held across the fetch/decode below: `_lead` is what serialises duplicates,
    // and taking the cache lock here would serialise every page instead of this one.
    let raw = match client.get_shielded_blocks(low, limit).await {
        Ok(raw) => raw,
        Err(e) => {
            // Release the slot on the way out or the next asker inherits a gate whose
            // leader is gone and waits for an answer nobody is producing.
            cache.lock().await.in_flight.remove(&key);
            return Err(e);
        }
    };
    // Decode the page ACROSS CORES. The per-block coinbase Sinsemilla commitment is the
    // dominant scan cost (~1 ms/block — it, not decryption, set the measured ~900 blk/s
    // single-thread ceiling), and each block decodes independently. `block_in_place`
    // moves this task off the async worker pool so the rayon fan-out doesn't stall other
    // tokio tasks; the decode is done once here and shared by every wallet via the cache.
    let blocks = tokio::task::block_in_place(|| {
        pool.install(|| {
            use rayon::prelude::*;
            raw.blocks.par_iter().map(decode_block).collect::<Vec<_>>()
        })
    });
    let decoded = Arc::new(DecodedPage { reorged: raw.reorged, sink_blue_score: raw.sink_blue_score, blocks });
    let mut c = cache.lock().await;
    // Re-inserting a key must not leave a second copy in the eviction queue. A page
    // refetched after its TTL used to be pushed again while `map` still held one
    // entry, so `order` counted it twice: the queue hit `cap` early, and popping the
    // stale first copy deleted the freshly inserted page from `map` — evicting a hot
    // entry and leaving the cache holding fewer pages than it was configured for.
    if c.map.insert(key, (std::time::Instant::now(), decoded.clone())).is_some() {
        if let Some(pos) = c.order.iter().position(|k| *k == key) {
            c.order.remove(pos);
        }
    }
    c.order.push_back(key);
    // Expired pages go NOW, not when `cap` pushes them out. The TTL used to be read
    // only on lookup, so a dead page stayed resident until `cap` newer ones had been
    // inserted — and on a single-wallet daemon every page is read exactly once, so a
    // long restore held `cap` decoded pages (~0.45 MB each) it would never touch again.
    // `order` is insertion-ordered (a re-insert moves to the back), so the sweep stops
    // at the first live entry and costs only what it evicts.
    while let Some(old) = c.order.front().copied() {
        if c.map.get(&old).is_some_and(|(at, _)| at.elapsed() < c.ttl) {
            break;
        }
        c.order.pop_front();
        c.map.remove(&old);
    }
    if c.order.len() > c.cap {
        if let Some(old) = c.order.pop_front() {
            c.map.remove(&old);
        }
    }
    c.in_flight.remove(&key);
    Ok(decoded)
}

// ---------------------------------------------------------------------------
// In-memory wallet + incremental sync
// ---------------------------------------------------------------------------

struct WalletEntry {
    /// Spend authority (seed) — or, for a non-custodial wallet, viewing key only.
    key: WalletKey,
    /// From the wallet file: build sends with the wallet's own OVK so history can
    /// recover recipient/amount/memo (see `WalletFile::recoverable_history`).
    recoverable_history: bool,
    db: WalletDb,
    /// The network genesis hash — guards the persisted checkpoint against a chain
    /// relaunch (and is also the shielded sighash network domain).
    genesis: RpcHash,
    /// Sync cursor: the last ingested **chain** block; `GetShieldedBlocks`
    /// resumes strictly after it.
    low: RpcHash,
    caught_up: bool,
    /// DAA score of the last ingested chain block (progress display).
    scanned: usize,
    chain_len: u64,
    updated_unix: u64,
    error: Option<String>,
    /// `scanned` at the last persisted checkpoint — the sync loop rewrites the
    /// checkpoint once enough new blocks accrue past this.
    saved_scanned: usize,
    /// When the checkpoint was last written (or the entry created) — the time-based
    /// checkpoint rule in `sync_one_wallet` is measured from here.
    last_checkpoint_at: std::time::Instant,
    /// How many history rows have been examined for send-detail recovery (see
    /// `recover_sent_details`). Rows below this index are not re-examined in this
    /// process — a failed fetch (block body pruned, node without the locator) is retried
    /// only on the next load, never every pass.
    history_examined: usize,
    /// `(blue_score, absolute leaf count)` after each ingested chain block,
    /// oldest→newest, capped at [`MATURED_RING`]. `send` picks the newest entry
    /// at least `anchor_depth + slack` blue units below the sink to root a spend
    /// at a matured, canonical chain-block anchor without a rescan. Persisted in
    /// the v2 checkpoint, so it survives restarts.
    boundaries: VecDeque<(u64, u64)>,
    /// The sink's blue score from the latest sync response — the reference the
    /// matured cutoff is measured against.
    sink_blue: u64,
    /// Consecutive sync passes that saw the cursor off the selected chain
    /// (deeper reorg than [`SYNC_TIP_MARGIN`]). Transient virtual flips clear on
    /// retry; at [`REORG_STRIKES`] the sync loop discards the checkpoint and
    /// reloads this wallet from scratch (the append-only tree cannot roll back).
    reorged_strikes: u32,
    /// Balance effect of the blocks between the settled cutoff and the tip — value
    /// arriving and owned value being spent, seen by trial-decryption without touching
    /// the append-only tree. This is what makes a payment visible ~1 second after it is
    /// mined instead of ~3 minutes later when SYNC_TIP_MARGIN clears.
    preview: Preview,
    /// Balance effect of shielded txs sitting in the node's **mempool** — not mined yet,
    /// not in any block. Trial-decrypting these is what makes an incoming payment visible
    /// within a second of being broadcast instead of only after it is mined AND the sync
    /// loop next runs. Costs nothing on-chain: it never touches the tree, and if the tx is
    /// dropped the figure simply disappears (the same contract as any 0-conf balance).
    mempool: Preview,
    /// Nullifiers of the bundles already counted in `preview` (the unsettled blocks).
    /// A tx that has just been mined can still linger in the mempool for a moment, and
    /// counting it from both places would briefly double the pending amount — so mempool
    /// bundles whose nullifiers appear here are skipped.
    unsettled_nulls: HashSet<kaspa_shielded_core::nullifier::NullifierBytes>,
    /// The unsettled-margin preview as ONE ENTRY PER BLOCK, newest last, covering
    /// exactly the window above the settled cutoff. `sync_chunk` used to rebuild
    /// the whole ~200-block preview from scratch every pass (~1s per wallet): the
    /// window rolls by one block per second, so ~199/200 of that trial-decryption
    /// was redoing the previous second's result — the daemon's #1 steady-state
    /// CPU. The roll is matched against the fresh window by hash and reused
    /// verbatim; only genuinely new tail blocks are previewed. Any mismatch
    /// (reorg inside the margin) drops the roll and rebuilds the window once —
    /// the same self-correction the full recompute gave.
    preview_roll: VecDeque<PreviewRollEntry>,
    /// The LAST page of the previous `sync_chunk` call was a caught-up (16-block) page
    /// that came back FULL, so the next fetch must be a full page. Inside a chunk the
    /// local flag carries that over between iterations; this carries it across calls,
    /// which matters for the shared chain tree (ONE page per call — without it a tree
    /// that fell a few hundred blocks behind crawled at CAUGHT_UP_PAGE per page).
    need_full_page: bool,
    /// Mempool previews by bundle key (first action's nullifier): the same
    /// pending bundles sit in the mempool for many 700 ms ticks and were
    /// re-trial-decrypted on every one. Cleared whenever a block is ingested
    /// (wallet state may have changed); between blocks it is exact.
    mempool_cache: HashMap<kaspa_shielded_core::nullifier::NullifierBytes, Preview>,
    /// When the background witness pre-advance last ran for this wallet. The sync loop
    /// spins as fast as every 10 ms while any wallet is behind, so without this throttle
    /// a caught-up note-heavy wallet fires a full `WITNESS_ADVANCE_BUDGET` step ~100×/s
    /// and pins every core (observed live: walletd at 214 % CPU that never relents). We
    /// take at most one witness step per [`WITNESS_ADVANCE_INTERVAL`], which caps the
    /// steady witness work to ~`BUDGET` hashes/s per wallet — a cold miner wallet warms
    /// over a couple of minutes at low CPU, then idles (matured grows ~1 leaf/block).
    last_witness_advance: Option<std::time::Instant>,
    /// Set once this wallet's witnesses have first been warmed all the way to the matured
    /// anchor (base compacted to its notes + every note witnessed). Until then the
    /// caught-up tail does the one-time heavy build in large steps so it converges in a
    /// few passes instead of crawling; after it, only the cheap ~1-leaf/block incremental
    /// advance runs.
    witnesses_warm: bool,
    /// `witnesses_warm` was latched because the **subtree cache** serves this wallet's
    /// spends, not because the live-witness set actually reached the anchor. Kept
    /// separate so the latch can be released — and the ordinary climb resumed — if the
    /// cache is ever rejected or invalidated, without mistaking a genuinely warm wallet
    /// for one that only looked warm.
    warm_via_subtree_cache: bool,
    /// The wallet can witness a spend WITHOUT an O(chain) climb right now (its own
    /// subtree cache is ready, or a shared tree covers it). Mirrors `cache_serves` in
    /// the sync loop; surfaced to `/api/status` so the app can say "preparing" honestly.
    spend_fast_ready: bool,
    /// The `--warm-wallets` slot this wallet is holding **for the duration of its
    /// subtree-cache build**, not just for one slice.
    ///
    /// Acquiring per pass and dropping at the end of it turned the build into
    /// round-robin starvation: with ~46 resident wallets sharing 4 permits, a 247 s
    /// build advanced one 2 s slice per turn and needed hours. Live, 17 builds started
    /// and **zero finished** in 11 minutes, so users kept paying that same 247 s inline
    /// on their first send. Holding the permit makes it a queue instead — a wallet that
    /// starts a build finishes it, then hands the slot on.
    build_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// Set by `sync_chunk` when this wallet wants a subtree cache and holds a slot for
    /// one; cleared by `sync_one_wallet` when it takes the snapshot. The build runs off
    /// the wallet lock, so the decision and the work are deliberately separated.
    wants_cache_build: bool,
    /// A detached subtree-cache build is already folding for this wallet. Without it,
    /// every sync pass during the ~247 s fold would queue another identical build.
    build_in_flight: bool,
    /// Last logged completion percentage of a sliced subtree-cache build, so progress is
    /// reported once per 10% instead of on every 250 ms slice.
    subtree_build_pct_logged: u64,
    /// Wall time spent WAITING for pages, and the wall time spent ingesting them.
    /// Kept next to the scan-cost counters so the log can no longer report a slice of
    /// the work as though it were the work.
    page_fetch_ns: u128,
    page_ingest_ns: u128,
    page_count: u64,
    /// Leaf count at the last scan-cost report, so it is emitted per unit of WORK
    /// rather than per tick (a tick can be a whole chunk or almost nothing).
    scan_cost_reported: u64,
    /// Whether this wallet has already taken its decision on the subtree cache (built
    /// it, or been turned away by the daemon-wide budget). Stops an O(chain) build —
    /// or a budget probe — from being re-attempted on every sync tick.
    /// When the "deferred, memory is tight" warning was last logged for this wallet, so
    /// the gate reports the squeeze every [`SUBTREE_LOW_MEM_RELOG`] instead of every
    /// sync pass — and not just once, which left a never-starting build silent.
    subtree_low_mem_logged: Option<std::time::Instant>,
    /// Request an immediate checkpoint write on the next `sync_one_wallet` pass, regardless
    /// of the block-count threshold — set the moment the witnesses first warm, so the
    /// expensive-to-rebuild witness state is persisted at once (a restart seconds later
    /// must not throw it away and re-do the ~30–90 s warm).
    force_checkpoint: bool,
    /// Tree size of the frontier this view was anchored on when the wallet may hold
    /// notes MINTED BELOW it — notes this view can never discover, because the node
    /// has pruned their blocks (0 = complete view). Set on a full-scan rebuild of a
    /// wallet whose birthday predates the pruning point, persisted in the v4
    /// checkpoint, and surfaced as `missing_history` in status — the 2026-07-19
    /// incident was a wallet silently "losing" 23K ZKAS to exactly this after a
    /// rescan, with nothing anywhere admitting the view was partial.
    blind_below: u64,
    /// DAA score of the block the blind view was anchored on (the node's pruning point at
    /// the time), so status can NAME the floor — "history available from block N" — rather
    /// than only flag it. Not persisted: 0 after a restart, and status then omits it.
    blind_from_daa: u64,
}

/// One block's contribution to the rolling unsettled preview (see
/// [`WalletEntry::preview_roll`]). Hash-verified against the fresh window before
/// reuse, so a reorg inside the margin can never resurrect a stale block.
struct PreviewRollEntry {
    hash: RpcHash,
    blue_score: u64,
    preview: Preview,
    nulls: Vec<kaspa_shielded_core::nullifier::NullifierBytes>,
}

/// How many chain-block→leaf boundaries [`WalletEntry`] keeps. Anchor maturity is
/// measured in *blue score*, which advances at least one per chain block, so
/// `depth + slack` entries always reach the cutoff, with room to spare.
const MATURED_RING: usize = (DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK) as usize + 64;

/// How close (in DAA/blue score) the wallet's latest ingested block must be to the
/// node tip to report `synced: true`. On a live ~1-block/s chain the strict
/// `caught_up` flag rarely latches, so we treat "within this many blocks of the tip"
/// as synced (~32 s at 1 BPS).
const SYNC_MARGIN: u64 = 32;

/// How long (chain DAA ≈ seconds at 1 BPS) a submitted spend may stay unobserved
/// on-chain before the wallet concludes the transaction was lost and returns its
/// notes to the spendable set. Long enough to ride out mempool latency, ingest
/// maturity lag (~3 min) and a node restart with room to spare; short enough that
/// a user whose send evaporated gets their balance back within the hour instead
/// of never.
const PENDING_SPEND_EXPIRY_DAA: u64 = 3_600;

impl WalletEntry {
    /// Rebuild an entry from a wallet view + cursor (a fresh frontier start or a
    /// persisted checkpoint): the background sync resumes strictly after `low`.
    /// `saved_scanned == scanned` so the next checkpoint write waits for
    /// genuinely new blocks.
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        key: WalletKey,
        recoverable_history: bool,
        db: WalletDb,
        genesis: RpcHash,
        low: RpcHash,
        scanned: usize,
        boundaries: VecDeque<(u64, u64)>,
        sink_blue: u64,
    ) -> Self {
        let mut db = db;
        // History is opt-in per wallet: the same flag that makes sends
        // OVK-recoverable also authorizes recording rows at all. Applying it here
        // (the one place every entry is built) also purges rows persisted while
        // the flag was on if the user has since turned it off.
        db.set_history_enabled(recoverable_history);
        Self {
            key,
            recoverable_history,
            db,
            genesis,
            low,
            caught_up: false,
            scanned,
            chain_len: 0,
            updated_unix: 0,
            error: None,
            saved_scanned: scanned,
            last_checkpoint_at: std::time::Instant::now(),
            history_examined: 0,
            boundaries,
            sink_blue,
            reorged_strikes: 0,
            preview: Preview::default(),
            mempool: Preview::default(),
            unsettled_nulls: HashSet::new(),
            preview_roll: VecDeque::new(),
            need_full_page: false,
            mempool_cache: HashMap::new(),
            last_witness_advance: None,
            witnesses_warm: false,
            warm_via_subtree_cache: false,
            spend_fast_ready: false,
            build_permit: None,
            wants_cache_build: false,
            build_in_flight: false,
            subtree_build_pct_logged: 0,
            page_fetch_ns: 0,
            page_ingest_ns: 0,
            page_count: 0,
            scan_cost_reported: 0,
            subtree_low_mem_logged: None,
            force_checkpoint: false,
            blind_below: 0,
            blind_from_daa: 0,
        }
    }

    /// Recover recipient / paid amount / memo / fee for this wallet's own sends whose history
    /// rows were written from compact scan records (no `out_ciphertext` there). For each
    /// such row not yet examined: find its chain block — by DAA in the page just ingested,
    /// else through the node's DAA locator for rows recorded before this daemon could do
    /// this — fetch that block and its mergeset with transactions, locate the txid, and let
    /// the wallet decrypt the outputs with its outgoing viewing key. A view-key wallet thus
    /// sees where its money went, just like the spending wallet does. Bounded per pass;
    /// a row whose block body is gone (pruned) or whose node lacks the locator stays as it
    /// was and is retried on the next load only.
    async fn recover_sent_details(&mut self, client: &GrpcClient, page: &[DecodedBlock]) {
        const MAX_PER_PASS: usize = 8;
        let from = self.history_examined.min(self.db.history().len());
        let pending = self.db.unrecovered_sends(from);
        self.history_examined = self.db.history().len();
        if pending.is_empty() {
            return;
        }
        let mut done = 0usize;
        for (txid, daa) in pending.into_iter().take(MAX_PER_PASS) {
            // The chain block that accepted the tx: same DAA as the row (rows are dated by
            // the accepting chain block's metadata).
            let chain = match page.iter().find(|b| b.daa_score == daa) {
                Some(b) => Some(b.hash),
                None => {
                    // Backfill: rows from before this daemon could recover details. Ask the
                    // node for the chain block at this DAA (locator: last block strictly
                    // below daa+1). A node without the locator answers its finality point,
                    // whose DAA will not match — skipped.
                    let req = kaspa_rpc_core::GetShieldedTreeStateRequest { block_hash: None, below_daa_score: Some(daa + 1) };
                    match tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_shielded_tree_state_call(None, req)).await {
                        Ok(Ok(ts)) if ts.daa_score == daa => Some(ts.block_hash),
                        _ => None,
                    }
                }
            };
            let Some(chain) = chain else { continue };
            let Some(bundle) = fetch_bundle_for_tx(client, chain, &txid).await else { continue };
            let recovered = self.db.recover_sent_from_bundle(&txid, &bundle);
            done += 1;
            log::info!(
                "history: own send {} at daa {daa} — {}",
                hex(&txid[..8]),
                if recovered { "recipient/amount/memo/fee recovered from the full transaction" } else { "fee recovered; no recipient (sent without this wallet's OVK)" }
            );
        }
        if done > 0 {
            // Persist what was recovered on the next checkpoint rather than waiting 1000 blocks.
            self.force_checkpoint = true;
        }
    }

    /// Call right after parking a just-submitted spend (`mark_spent` +
    /// `note_pending_outflow`). A preview computed BEFORE the park saw the input
    /// still in `notes` and classified this transaction as `outgoing = amount + fee`;
    /// now that the input has left the balance and the change is carried by
    /// `pending_change`, that figure would be subtracted a second time — and a roll
    /// entry keeps it for the whole ~200-block unsettled window. Drop the cached
    /// mempool previews (re-derived on the next tick) together with the mempool
    /// outgoing figure, and zero the outgoing part of any roll entry whose block
    /// already spends a parked note (mined inside the submit→park gap); the block's
    /// incoming part is untouched.
    fn forget_stale_outflow_previews(&mut self) {
        self.mempool_cache.clear();
        self.mempool.outgoing = 0;
        let parked: HashSet<kaspa_shielded_core::nullifier::NullifierBytes> =
            self.db.pending_spends().iter().map(|p| p.note.nullifier()).collect();
        let mut touched = false;
        for e in self.preview_roll.iter_mut() {
            if e.preview.outgoing > 0 && e.nulls.iter().any(|n| parked.contains(n)) {
                e.preview.outgoing = 0;
                touched = true;
            }
        }
        if touched {
            let mut preview = Preview::default();
            for e in &self.preview_roll {
                preview.add(e.preview);
            }
            self.preview = preview;
        }
    }

    /// Trial-decrypt the shielded bundles currently in the node's mempool and record what
    /// they would do to this wallet. Purely a display figure: no tree mutation, no leaf,
    /// no position — so it carries none of the reorg hazard that keeps `sync_chunk` from
    /// ingesting unsettled blocks. This is what makes an incoming payment appear about a
    /// second after the sender hits Confirm, rather than only after it has been mined.
    fn scan_mempool(&mut self, bundles: &[ShieldedBundle]) {
        // Skip anything already counted from the unsettled blocks: a just-mined tx can
        // still linger in the mempool, and counting it twice would double the pending sum.
        let fresh: Vec<&ShieldedBundle> =
            bundles.iter().filter(|b| !b.actions.iter().any(|a| self.unsettled_nulls.contains(&a.nullifier))).collect();
        // Trial-decrypt each bundle ONCE per key (first action's nullifier — unique
        // per bundle). Pending bundles linger for many 700 ms ticks and were
        // re-decrypted on every single one; between blocks the wallet state the
        // preview depends on cannot change, so the cached figure is exact. The
        // cache is cleared on every chain-block ingest (see sync_chunk) and
        // retained only for bundles still present, so it stays small and current.
        let mut total = Preview::default();
        let mut present: HashSet<kaspa_shielded_core::nullifier::NullifierBytes> = HashSet::with_capacity(fresh.len());
        for b in fresh {
            let Some(key) = b.actions.first().map(|a| a.nullifier) else { continue };
            present.insert(key);
            if let Some(p) = self.mempool_cache.get(&key) {
                total.add(*p);
            } else {
                let p = self.db.preview_block(&[], &[b]);
                self.mempool_cache.insert(key, p);
                total.add(p);
            }
        }
        self.mempool_cache.retain(|k, _| present.contains(k));
        self.mempool = total;
    }

    /// Advance this wallet by up to `PAGES_PER_CHUNK` pages (the shared chain tree:
    /// one page, see below) of new **chain**
    /// blocks, ingesting exactly the shielded effects consensus applied per block
    /// (own coinbase mint + accepted post-retain bundles, consensus order), and
    /// only once a block is `SYNC_TIP_MARGIN` blue units below the sink (the
    /// append-only tree must not ingest anything a routine reorg could replace).
    async fn sync_chunk(
        &mut self,
        client: &GrpcClient,
        cache: &Mutex<PageCache>,
        warm_gate: &std::sync::Arc<tokio::sync::Semaphore>,
        // Published to mid-pass so a long scan reports progress instead of silence; see
        // [`SNAPSHOT_PUBLISH_EVERY`]. Arc so the page prefetch below can hold the
        // shared page cache across an await without borrowing from this frame.
        state: &std::sync::Arc<AppState>,
        token: &str,
        // Whether this wallet was caught up BEFORE this pass reset the flag. Mid-pass
        // progress is only published for a wallet that is genuinely scanning; see below.
        was_caught_up: bool,
        subtree_free_floor_mb: u64,
        // Leaves the daemon-wide shared tree can already witness against, or 0 when it
        // cannot be consulted. A wallet covered by it needs no subtree cache of its own.
        shared_tree_covers: u64,
        // The shared tree's base (oldest witnessable position). The tree serves only
        // `[base, covers)`; a wallet whose oldest note is below `base` is NOT covered.
        shared_tree_base: u64,
    ) {
        // Local to the pass on purpose: a fresh pass should publish promptly rather
        // than inherit a timer from the last one.
        let mut last_publish = std::time::Instant::now();
        let pass_started = std::time::Instant::now();
        // Stop building this wallet's own mirror tree while the shared tree is at or
        // ahead of us. That tree is ~80% of a scan (measured: 319 s of Sinsemilla
        // against 79 s of trial decryption) and it is PUBLIC — the shared copy builds
        // bit-identical nodes. The wallet keeps COUNTING leaves, so note positions are
        // unaffected; only the hashing goes away.
        //
        // This must run on EVERY pass, before any ingest. It first lived in the
        // caught-up tail below, which meant it only ever ran for wallets that had
        // already finished syncing — so an initial scan, the one case the whole change
        // exists for, never borrowed anything and hashed the entire chain itself.
        // Measured after that deploy: tree still 83–99% of scan cost, i.e. no effect.
        //
        // Requires the shared tree to be AHEAD of us, since that is what makes a
        // frontier available to adopt afterwards; a wallet that overtakes it simply
        // keeps hashing until it is passed again.
        // Borrow while the shared tree covers us — but NEVER drop the flag while this
        // wallet's own mirror is still invalid.
        //
        // Turning borrowing off does not rebuild the mirror; every leaf appended while
        // borrowing was skipped, and `tree_valid` is set true again by exactly one thing:
        // `adopt_tip_frontier`, which refuses unless the shared tree is at EXACTLY this
        // wallet's leaf count. So clearing the flag on an invalid mirror strands the
        // wallet: `ensure_canonical_checkpoint` forgives a wallet that IS borrowing and
        // refuses one that merely WAS, and a wallet behind the shared tree can never hit
        // the exact size that would make it valid again.
        //
        // That is not hypothetical. When the shared tree stalled, `shared_tree_covers`
        // stopped growing while wallets kept advancing, so healthy wallets flipped to
        // non-borrowing with invalid mirrors and every send they attempted answered
        // "wallet is still catching up with the shared chain state" — permanently, with
        // the card still offering Send.
        //
        // A wallet that has borrowed genuinely depends on the shared tree, so it keeps
        // saying so until it can honestly stop. Spending stays safe by the same argument
        // as any borrower: every witness handed to a payment is verified to root before
        // it is used, so a tree that had diverged declines rather than lying.
        // Base-aware, same as `shared_serves`: the shared tree only witnesses `[base, size)`,
        // so a wallet whose oldest note is below the shared base is NOT covered and must keep
        // maintaining its own tree — borrowing would strand those old notes at spend time.
        let oldest_note = self.db.notes().iter().map(|n| n.position).min().unwrap_or(u64::MAX);
        let covered =
            !self.db.is_leaves_only() && shared_tree_covers >= self.db.size() && shared_tree_base <= oldest_note;
        self.db.set_borrow_tree(covered || !self.db.tree_is_valid());

        // Set when a small caught-up page comes back FULL: more blocks than it
        // carried arrived, so the next iteration must take a full page to catch
        // up in one go (otherwise a stalled wallet would crawl at CAUGHT_UP_PAGE
        // blocks per pass).
        // Concurrent read-ahead for the deep-sync regime. `preview_roll` empty means
        // this wallet is not caught up, so `page_limit` below is a full SHIELDED_PAGE
        // and the loop is fetch-bound; warm `prefetch_depth` pages at once so the
        // cores are not idle between round-trips. Fire-and-forget and cache-only.
        if state.resources.prefetch_depth > 1 && self.preview_roll.is_empty() {
            let depth = state.resources.prefetch_depth;
            tokio::spawn(deep_prefetch(state.clone(), client.clone(), self.low, depth));
        }
        let mut need_full_page = self.need_full_page;
        // The shared chain tree takes ONE page per call: every borrowing wallet's spend
        // witnesses through it (`chain_tree_paths` spins on its `try_lock` while holding
        // the sending wallet's own lock), and this method runs entirely under the tree's
        // lock, so a whole chunk here was a whole chunk of fetch+ingest a spend could
        // wait — code-recorded ~8 s at ~2 s/page under heavy ingest, and past 20 s the
        // spend falls to an O(chain) replay. `sync_one_wallet` re-calls per page with
        // the lock released between pages, for the same page count per pass.
        let pages = if token == CHAIN_TREE_TOKEN { 1 } else { PAGES_PER_CHUNK };
        for _ in 0..pages {
            // HARD TIMEOUT. There is ONE sync loop for every wallet, and it advances them
            // sequentially — so an await here that never returns does not stall one wallet,
            // it stalls ALL of them, forever. That was a live outage: a hung page fetch
            // froze the loop, so no wallet's cursor advanced, `sink_blue` went stale, the
            // maturity cutoff never moved, and every wallet's whole balance showed as
            // "maturing" and unspendable — indistinguishable from a broken wallet, and only
            // a daemon restart cleared it. A timed-out page is treated exactly like any
            // other transient node failure: keep the checkpoint, record it, move on.
            // Page size adapts to the wallet's state: caught-up with a healthy
            // preview roll → only the newest few blocks (the roll already covers
            // the unsettled window, hash-verified); anything else → a full page.
            let page_limit = if !need_full_page && !self.preview_roll.is_empty() { CAUGHT_UP_PAGE } else { SHIELDED_PAGE };
            // Time the FETCH separately from the ingest below.
            //
            // The `scan cost so far` counters measure trial decryption and the tree, and
            // nothing else — so for months they described a slice of the work and were
            // read as if they described the work. Tracked against wall clock, decryption
            // turned out to be ~2% of a wallet's sync time (9,514 -> 10,722 ms of decrypt
            // across 67 s of syncing). Everything spent making it faster moved ~2% of the
            // total, which is why a 1.8x on decrypt did not show up as a faster wallet.
            //
            // A page is ~536 ms at the observed 1,865 blocks/s, of which ~10 ms is
            // decryption. This says where the other ~526 ms goes.
            let t_fetch = std::time::Instant::now();
            let fetched = tokio::time::timeout(SYNC_RPC_TIMEOUT, fetch_shielded_page(client, cache, self.low, page_limit)).await;
            self.page_fetch_ns += t_fetch.elapsed().as_nanos();
            self.page_count += 1;
            let resp = match fetched {
                Ok(Ok(r)) => r,
                Err(_elapsed) => {
                    log::warn!("wallet sync page timed out after {SYNC_RPC_TIMEOUT:?} (checkpoint kept); will retry next pass");
                    self.error = Some("node is slow to answer; retrying".into());
                    return;
                }
                Ok(Err(e)) => {
                    // Distinguish "cursor unusable" (pruned / stale-branch / relaunched —
                    // needs a rescan) from a transient node failure.
                    //
                    // FIRST, read the page error itself: if the node *answered* with one of
                    // the definitive cursor-gone verdicts (see [`CURSOR_GONE_MARKERS`]),
                    // that IS the evidence — no probe needed. Probing `get_block` here was
                    // the trap that froze wallets for hours: a cursor below the retention
                    // root still *exists* (probe succeeds → "transient") while every page
                    // fetch is deterministically refused. The node answering at all also
                    // proves it is alive.
                    //
                    // Otherwise (timeout, transport, node busy), the error says nothing
                    // about the cursor: probe it, and only a definitive verdict on a live
                    // node counts. Either way, take a single strike and require
                    // REORG_STRIKES *consecutive* passes to agree — a merely-slow node must
                    // never be able to delete a wallet's scan history (2026-07-12 outage).
                    // Probes are timed out too — they run on the same shared loop.
                    let gone = if cursor_gone(&e.to_string()) {
                        true
                    } else {
                        let probe_gone = match tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block(self.low, false)).await {
                            Ok(Err(probe)) => cursor_gone(&probe.to_string()),
                            Ok(Ok(_)) => false,
                            Err(_) => false, // timed out: says nothing about the cursor
                        };
                        let node_alive =
                            matches!(tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block_dag_info()).await, Ok(Ok(_)));
                        probe_gone && node_alive
                    };
                    if gone {
                        // A verdict is only evidence from a node whose chain has REACHED
                        // the cursor. "cannot find header" is also what a node answers for
                        // a block it simply has not received yet (IBD, backfill, a public
                        // node re-syncing from genesis) — and such a node still "serves
                        // genesis", so nothing downstream caught it: a walletd repointed at
                        // one retired a fully synced checkpoint within three passes.
                        match node_reaches(client, self.scanned as u64, SYNC_RPC_TIMEOUT).await {
                            Ok(()) => {
                                self.reorged_strikes += 1;
                                self.error = Some("wallet cursor no longer usable on the node; rescanning".into());
                                log::info!("wallet cursor unusable (strike {}/{REORG_STRIKES}): {e}", self.reorged_strikes);
                            }
                            Err(why) => {
                                log::debug!(
                                    "wallet cursor {} reported unusable ({e}) but the node has not reached it ({why}); checkpoint kept, no strike",
                                    self.low
                                );
                                self.error = Some(format!("node is behind the wallet cursor ({why}); waiting"));
                            }
                        }
                    } else {
                        log::debug!("wallet sync page failed (transient, checkpoint kept): {e}");
                        self.error = Some(format!("get_shielded_blocks failed: {e}"));
                    }
                    return;
                }
            };
            if resp.reorged {
                // Usually a transient virtual flip near the tip: retry a few
                // passes before paying for a full rescan.
                self.reorged_strikes += 1;
                self.error = Some("chain reorged below the wallet cursor; retrying".into());
                return;
            }
            self.reorged_strikes = 0;
            self.sink_blue = resp.sink_blue_score;
            // PREFETCH the next page while this one is being ingested below. The next
            // cursor is this page's LAST block hash - known right now, before any
            // ingest - and the result lands in the shared page cache, so this loop's
            // next iteration (and every other wallet walking the same stream) hits it
            // warm instead of paying the fetch serially. The wall-clock profile that
            // motivates this: a page is ~136 ms of fetch against ~38 ms of ingest, so
            // the fetch is the loop's critical path and overlapping it is worth more
            // than any decrypt-side work (see the `scan cost so far` comment above).
            //
            // Restore-shaped pages only (`page_limit == SHIELDED_PAGE` and the page
            // came back full): a caught-up wallet's next page does not exist yet, and
            // caching a premature partial tip page would pin it for PAGE_CACHE_TTL.
            // The in-flight gate inside `fetch_shielded_page` dedupes this against
            // other wallets' prefetches of the same cursor, so a cohort spawns one
            // fetch, not one per wallet. Deliberately NOT the node-max 2000-block
            // page: that was tried and measured slower end to end (892 vs 2,219
            // blocks/s) because the page is also the unit of work held under the
            // wallet lock - overlap attacks the fetch without touching that trade.
            if page_limit == SHIELDED_PAGE && resp.blocks.len() as u64 == page_limit {
                if let Some(next_cursor) = resp.blocks.last().map(|b| b.hash) {
                    let st = state.clone();
                    let cl = client.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            SYNC_RPC_TIMEOUT,
                            fetch_shielded_page(&cl, &st.page_cache, next_cursor, SHIELDED_PAGE),
                        )
                        .await;
                    });
                }
            }
            let settled = resp.sink_blue_score.saturating_sub(SYNC_TIP_MARGIN);
            // This section is synchronous trial-decryption/tree work. Mark it as
            // blocking so Tokio starts replacement workers for HTTP and RPC tasks
            // while up to three wallets continue ingesting in parallel.
            let t_ingest = std::time::Instant::now();
            let (advanced, at_margin) = tokio::task::block_in_place(|| {
                let mut advanced = false;
                let mut at_margin = false;
                // Decide the WHOLE page's trial decryption in one batch before ingesting
                // any of it. The ingest below walks block by block and transaction by
                // transaction, which is a handful of actions per call — too small to
                // spread across cores, and far below the ~100-point batch a GPU needs to
                // beat the CPU at all. Since the tree work was shared away, decryption is
                // ~99% of a scan (measured: 113.7 us/action against 0.1 us/leaf), so the
                // batch size WAS the bottleneck for both.
                //
                // Purely a memo: anything it does not cover is decrypted the old way, so
                // this can cost time but never a note.
                {
                    let page_actions: Vec<kaspa_shielded_core::wallet::CompactActionRecord> =
                        resp.blocks.iter().flat_map(|b| b.compact.iter().flatten().copied()).collect();
                    if !page_actions.is_empty() {
                        tokio::task::block_in_place(|| self.db.predecrypt_page(&page_actions));
                    }
                }
                for (i, b) in resp.blocks.iter().enumerate() {
                    if b.blue_score > settled {
                        // Everything from here to the tip is inside the reorg margin and must
                        // not be appended to the tree. Preview it instead, so a payment shows
                        // up as pending the moment it is mined rather than ~3 minutes later
                        // when the margin clears.
                        //
                        // The window ROLLS by ~one block per second, so keep it as a
                        // per-block roll and reuse it: entries that hash-match the fresh
                        // window are kept verbatim (their trial-decryption is NOT redone),
                        // matured-out entries are dropped, and only genuinely new tail
                        // blocks are previewed. A hash MISMATCH anywhere (a reorg inside
                        // the margin) drops the roll and rebuilds the page's portion —
                        // the same self-correction the full recompute gave.
                        //
                        // CRITICAL: a caught-up page (16 blocks) covers only the START of
                        // the ~200-block unsettled window — the roll's unmatched TAIL is
                        // the rest of that window and must be KEPT, not treated as a
                        // mismatch. Clearing on leftovers rebuilt the entire window every
                        // pass — and with preview_block_compact being O(notes x actions),
                        // one note-heavy wallet (a miner's, registered 4x) pinned every
                        // sync slot at 400% CPU and froze all progress (2026-08-05).
                        let window = &resp.blocks[i..];
                        let mut roll = std::mem::take(&mut self.preview_roll);
                        while roll.front().is_some_and(|e| e.blue_score <= settled) {
                            roll.pop_front();
                        }
                        let mut kept: VecDeque<PreviewRollEntry> = VecDeque::with_capacity(window.len() + roll.len());
                        let mut reusable = true;
                        for u in window {
                            if !reusable {
                                break;
                            }
                            match roll.pop_front() {
                                Some(e) if e.hash == u.hash && e.blue_score == u.blue_score => kept.push_back(e),
                                _ => reusable = false,
                            }
                        }
                        if !reusable {
                            // Reorg inside the margin: neither matched entries nor the tail
                            // are trustworthy — rebuild the page's portion from scratch.
                            kept.clear();
                        }
                        for u in &window[kept.len()..] {
                            let cb: Vec<(CoinbaseNoteDesc, u64)> = u.coinbase.iter().map(|(d, v, _)| (d.clone(), *v)).collect();
                            let preview = self.db.preview_block_compact(&cb, &u.compact);
                            // Remember what these blocks spend, so the same tx still sitting
                            // in the mempool is not counted a second time (see `mempool`).
                            let nulls: Vec<_> = u.compact.iter().flat_map(|records| records.iter().map(|a| a.nullifier)).collect();
                            kept.push_back(PreviewRollEntry { hash: u.hash, blue_score: u.blue_score, preview, nulls });
                        }
                        if reusable {
                            // The rest of the unsettled window, past the end of this page:
                            // hash-verified when computed, still unsettled (the maturity
                            // drop above ran first), still valid.
                            kept.append(&mut roll);
                        }
                        let mut preview = Preview::default();
                        let mut nulls: HashSet<_> = HashSet::new();
                        for e in &kept {
                            preview.add(e.preview);
                            nulls.extend(e.nulls.iter().copied());
                        }
                        self.preview = preview;
                        self.unsettled_nulls = nulls;
                        self.preview_roll = kept;
                        at_margin = true;
                        break;
                    }
                    // Ingest with the coinbase commitments the shared cache already
                    // computed for this block — the Sinsemilla work is not repeated per
                    // wallet.
                    // History dating needs the v2 RPC fields; a pre-v2 node serves
                    // timestamp 0 and no txids — sync still works, history is skipped.
                    let meta = (b.timestamp > 0 && b.txids.len() == b.compact.len()).then(|| BlockMeta {
                        coinbase_txid: b.coinbase_txid,
                        txids: b.txids.clone(),
                        timestamp_ms: b.timestamp,
                        daa_score: b.daa_score,
                    });
                    self.db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.compact, meta.as_ref());
                    self.low = b.hash;
                    self.scanned = b.daa_score as usize;
                    self.boundaries.push_back((b.blue_score, self.db.size()));
                    if self.boundaries.len() > MATURED_RING {
                        self.boundaries.pop_front();
                    }
                    advanced = true;
                }
                // The page memo must not survive the page.
                self.db.end_page();
                if !at_margin {
                    // No unsettled blocks in this page — nothing is pending from the margin.
                    self.preview = Preview::default();
                    self.unsettled_nulls.clear();
                    self.preview_roll.clear();
                }
                if advanced {
                    // Chain ingest may have changed this wallet's note/nullifier
                    // state — cached mempool previews are only valid between blocks.
                    self.mempool_cache.clear();
                }
                (advanced, at_margin)
            });
            self.page_ingest_ns += t_ingest.elapsed().as_nanos();
            // Own sends ingested from compact records have no recipient/memo/fee yet — fetch
            // the full transaction for each new Sent row and recover them with the OVK. Rare
            // per wallet (one fetch per own send), bounded, best-effort; async, so it lives
            // outside the blocking ingest section above.
            if advanced && self.recoverable_history && !self.db.is_leaves_only() {
                self.recover_sent_details(client, &resp.blocks).await;
            }
            // Publish what this pass has reached so far. Without this the only progress
            // report is the one after the pass ENDS, which for an initial scan means the
            // user watches "opening" for minutes while the daemon is in fact working
            // through their history at full speed.
            // `!was_caught_up` is load-bearing, not an optimisation. `sync_one_wallet`
            // clears `caught_up` at the start of every pass, and `synced` is computed from
            // it — so publishing mid-pass for a wallet that WAS caught up reports
            // `synced: false` for the duration of the pass. The fallback test
            // (`scanned + SYNC_MARGIN >= tip`) cannot rescue it either: a caught-up wallet
            // rests ~SYNC_TIP_MARGIN (200) blocks behind by design and SYNC_MARGIN is 32.
            //
            // The client holds a "synced" dip for 6s; a pass may now run to PASS_BUDGET
            // (20s). So this would have flapped every steady-state wallet back to
            // "Catching up" once per pass — replacing the bug this publishing exists to
            // fix with a noisier one. A wallet already at the tip has nothing to report
            // mid-pass anyway: its end-of-pass snapshot is the whole story.
            if !was_caught_up && last_publish.elapsed() >= SNAPSHOT_PUBLISH_EVERY && self.db.notes().len() <= SNAPSHOT_NOTE_CEILING {
                let snap = snap_from_entry(state.address_of(&self.db), self, self.chain_len);
                state.snapshots.lock().await.insert(token.to_string(), snap);
                last_publish = std::time::Instant::now();
            }
            // A FULL small page means more blocks arrived than CAUGHT_UP_PAGE
            // carried: this wallet is not at the tip after all — take a full
            // page next iteration instead of declaring victory.
            let small_page_full = page_limit == CAUGHT_UP_PAGE && resp.blocks.len() == CAUGHT_UP_PAGE as usize;
            if small_page_full {
                need_full_page = true;
            }
            // Only the last page's verdict outlives the call (see the field).
            self.need_full_page = small_page_full;
            if !advanced || (at_margin && !small_page_full) {
                self.caught_up = true;
                break;
            }
            // Out of pass budget: stop cleanly and let the lap move on. The cursor has
            // already advanced, so the next pass resumes from here with nothing repeated.
            if pass_started.elapsed() >= PASS_BUDGET {
                break;
            }
            // Just yield between pages — do NOT sleep here: this runs while the wallet's
            // mutex is held, and sleeping would block any status call for this wallet for
            // the sleep's duration. The CPU throttle is the between-wallet sleep in
            // `sync_loop`, which runs with the lock released.
            tokio::task::yield_now().await;
        }
        // Keep this wallet's spend-witnesses tracking the matured anchor so pressing Send is
        // a witness *lookup* (~ms), never a Sinsemilla replay of the chain (measured cold:
        // 30–36 s, 90 % of a send). Two regimes, only near the tip (`caught_up`):
        //
        //   COLD (`!witnesses_warm`): the one-time heavy build for a full-scan / freshly
        //   loaded wallet — roll the base up to the wallet's notes (dropping the leaves
        //   below, `advance_base_capped`), then witness every note up to the matured anchor
        //   (`advance_witnesses_capped`). Done in LARGE steps so it converges in a handful
        //   of passes instead of crawling for minutes (the earlier throttled version let the
        //   user keep sending mid-warm — every send stayed COLD). Each big step is a single
        //   `block_in_place`, so it can't spin the loop; and it latches `witnesses_warm`
        //   when done, so this heavy path runs at most once per wallet load. The instant it
        //   warms it asks for a checkpoint (`force_checkpoint`) so the expensive witness
        //   state is persisted (v5) and a restart never has to redo it.
        //
        //   WARM: cheap throttled maintenance — the base only needs a nudge if a note
        //   arrived below it (rare), and witnesses advance ~1 leaf/block as the anchor moves.
        //
        // The base compaction no longer wipes warm witnesses (they are self-contained and
        // valid above the base — see `advance_base_capped`), so the two no longer fight.
        // Any note not yet reached still rebuilds on demand in `witness_path_at`, so
        // correctness never depends on this pre-advance.
        // A wallet that has fallen behind the tip again will not reach the build block
        // below, so it would sit on its slot without using it. Hand it back now; it
        // re-queues when it catches up.
        if !self.caught_up && self.build_permit.is_some() {
            self.build_permit = None;
        }
        if self.caught_up {
            if let Some(matured) = self.matured_leaves() {
                // How many witnesses this wallet maintains. Every step below costs
                // `leaves × budget`, so pinning the budget to a constant for a note-heavy
                // wallet is what keeps its catch-up bounded — see EAGER_WARM_MAX_NOTES.
                let note_count = self.db.notes().len() as u64;
                let budget = if note_count > EAGER_WARM_MAX_NOTES { SPENDABLE_WITNESS_BUDGET } else { note_count.max(1) as usize };
                self.db.set_witness_budget(budget);
                // Note-heavy wallets are served at spend time by the batch builder
                // (`witness_paths_at`, one O(chain) pass for all selected notes), which does
                // NOT read the legacy live-witness set. So the per-note ~30 s O(chain)
                // `install_witness` adopts below are pure waste — and worse, they run on a
                // blocking thread and steal CPU from the actual Halo 2 proof of a concurrent
                // send. Skip them: mark warm (bypasses the adopt loop) and keep a minimal
                // live set. The base still rolls up on the cheap steady path below.
                if note_count > EAGER_WARM_MAX_NOTES {
                    self.db.set_witness_budget(1);
                    self.witnesses_warm = true;
                }
                // Retain the tree's COMPLETE subtree roots once. Every authentication
                // sibling of every note is then either one of those (a lookup), the empty
                // root, or the single subtree straddling the anchor — so a spend witnesses
                // in O(depth) instead of replaying the chain. Measured at 200 K leaves:
                // 29.4 s per send -> 0.36 s, and ~4 ms/note thereafter.
                //
                // One O(chain) pass, on a BLOCKING thread (never the async runtime — see
                // the 2026-07-12 freeze), then `append_leaf` keeps it current for the same
                // one-hash-per-leaf the tip mirror already costs. Only built once the
                // replay it replaces is actually slow, so ordinary wallets pay no memory.
                let span = matured.saturating_sub(self.db.base_size());
                // Stand down while any payment is proving: the build is one-time and can
                // wait a tick, a user's send cannot. Deliberately does NOT mark the wallet
                // charged, so it is retried once the daemon is idle again.
                //
                // It deliberately does NOT stand down for `backfilling_now()` any more.
                // That flag is GLOBAL and sticky: any single wallet more than
                // BACKFILL_BEHIND_BLOCKS behind stamps it for every other wallet. With a
                // backlog of never-scanned wallets it is permanently set, so the build
                // that makes a wallet fast was starved forever by the wallets that are
                // slow — a self-sustaining inversion. Observed on the public daemon:
                // 0 cache builds, 0 deferrals, and every resident wallet stuck on the
                // O(leaves x budget) climb instead. Backfill is background work nobody
                // waits on; a proof is not. Yield to the proof, not to the backlog.
                //
                // The build is bounded instead by the warm gate (`--warm-wallets`),
                // acquired below and held across it, so a burst of cold wallets can no
                // longer put one O(chain) sweep per sync slot on the box at once.
                // `subtree_cache_failed` is checked too: a wallet the cache cannot serve
                // must not sit on a build slot re-attempting a build that will be
                // rejected again.
                // The subtree cache exists to make THIS wallet's spends O(depth). If the
                // shared tree already covers `matured`, it answers those spends and this
                // wallet's own cache would be a second copy of the same public structure,
                // built at the same cost: ~324 s of Sinsemilla over ~2.07 M leaves,
                // measured, PER WALLET. That is 45% of a wallet's whole cold cost, spent
                // reproducing something the daemon already has.
                //
                // The shared tree itself is exempt — it is the copy everyone else is
                // relying on, so it must build. `shared_tree_covers` is 0 for it anyway
                // (its own lock is held by this very sync pass), but say so explicitly
                // rather than depend on that.
                // The shared tree serves only positions at or above its own base. A wallet
                // whose OLDEST note is below that base (an old miner wallet, once the shared
                // tree's base was raised by the 2026-08 compaction bug) is not covered — the
                // tree declines those positions and the spend climbs O(chain). Gate on the
                // oldest note so such a wallet builds its own cache instead of relying on a
                // shared tree that cannot reach its history.
                let oldest_note = self.db.notes().iter().map(|n| n.position).min().unwrap_or(u64::MAX);
                let shared_serves = !self.db.is_leaves_only()
                    && shared_tree_covers >= matured
                    && matured > 0
                    && shared_tree_base <= oldest_note;
                let needs_cache = span >= SUBTREE_CACHE_MIN_SPAN
                    && !self.db.subtree_cache_ready(matured)
                    && !self.db.subtree_cache_failed()
                    && !shared_serves;
                // Take a build slot and KEEP it across passes until the build finishes —
                // see `build_permit`. Releasing the moment a wallet no longer needs one
                // hands the slot straight to whoever is queued.
                // The build itself no longer runs under this lock — see `SubtreeBuildJob`.
                // Record the intent and let `sync_one_wallet` snapshot and fold it after
                // the guard is released.
                //
                // Slicing it to keep the lock available was the previous answer, and it
                // did not work: one 2 s slice per sync lap is a ~10 % duty cycle, so on
                // the live daemon builds crawled and NONE completed, while users kept
                // paying the whole 247 s inline on their first send. Off the lock there is
                // no reason to slice at all.
                if needs_cache && !self.build_in_flight {
                    if self.build_permit.is_none() {
                        self.build_permit = warm_gate.clone().try_acquire_owned().ok();
                    }
                    // A payment in flight still wins: the box has finite cores and the
                    // user is watching that one.
                    if self.build_permit.is_some() && !proving_now() {
                        // Only refuse when the kernel says memory is genuinely tight. A
                        // wallet skipped here is retried on a later pass, so a transient
                        // squeeze costs this wallet one slow send, not its whole session.
                        // Sized to the job on a single-wallet daemon — see
                        // `subtree_build_floor_mb`: a flat 1.2 GB floor kept laptops from
                        // ever pre-building, and then charged the same fold to the send.
                        let floor = subtree_build_floor_mb(subtree_free_floor_mb, span, !state.build_shared_tree);
                        match mem_available_mb() {
                            Some(free) if free < floor => {
                                // Once per wallet per SUBTREE_LOW_MEM_RELOG, not once per sync pass.
                                if self.subtree_low_mem_logged.is_none_or(|at| at.elapsed() >= SUBTREE_LOW_MEM_RELOG) {
                                    self.subtree_low_mem_logged = Some(std::time::Instant::now());
                                    log::warn!(
                                        "subtree cache deferred ({span} leaves): only {free} MB free, floor is {floor} MB; this wallet keeps the replay path for now (a send will build it off-lock instead)"
                                    );
                                }
                            }
                            _ => {
                                self.subtree_low_mem_logged = None;
                                self.wants_cache_build = true;
                            }
                        }
                    }
                } else if self.build_permit.is_some() {
                    self.build_permit = None;
                }
                // Once the complete-subtree cache covers the matured anchor, EVERY spend
                // path reaches `witness_paths_at`, which serves from `subtree_paths` in
                // O(depth) and returns before it ever looks at the live-witness set. The
                // warm below then builds a structure nothing reads: phase 2 is a
                // leaf-by-leaf climb costing `leaves × budget`, phase 3 one O(chain)
                // replay per adopted note.
                //
                // This is the same argument the note-heavy branch above already makes —
                // it was just tied to the wrong condition. Being served by the batch
                // builder is not a property of holding many notes; it is a property of
                // the cache being ready, which is equally true of a 4-note wallet.
                // Live cost of getting that wrong: 48 resident wallets each burning
                // 4–7 s ticks with ~1 M leaves still to climb, `adopted 0` on every one
                // of them, walletd pinned at 470% CPU — for witnesses no send consumes.
                //
                // Declaring the wallet warm here is not a claim that its witness set
                // reached the anchor; it is a claim that it does not need to. If the
                // cache is later rejected or invalidated the latch is released below and
                // the ordinary climb resumes, so the failure mode is the old behaviour.
                // `matured > base_size` is `subtree_paths`' own precondition: below it the
                // cache declines and the wallet would silently be left with neither a
                // cache nor a witness set.
                // Served by EITHER this wallet's own cache or the shared tree. Checking
                // only the former was a bug of exactly the kind this whole file keeps
                // producing: a borrowing wallet never builds a cache of its own, so the
                // condition was permanently false and the wallet dropped into the
                // leaf-by-leaf witness climb — the very work the shared tree exists to
                // make unnecessary — and sat in "Almost ready" indefinitely.
                //
                // The question was never "do I have a cache", it is "can somebody
                // witness for me".
                let cache_serves = (self.db.subtree_cache_ready(matured) || shared_serves) && matured > self.db.base_size();
                // Surface the true "can I pay without climbing?" answer to status.
                self.spend_fast_ready = cache_serves;
                // A wallet whose cache is still building must not ALSO run the warm. Both
                // are one-time heavy work aiming at the same outcome — a fast spend — and
                // the cache is the one that achieves it, in a fraction of the work. Left
                // unguarded this tick spends 250 ms building the cache and then 4 s
                // climbing witnesses the cache is about to make redundant, which is the
                // treadmill this whole change removes, reintroduced at 94% strength.
                //
                // `!subtree_cache_failed()` matters: a rejected cache never becomes ready,
                // so without it `needs_cache` would stay true forever and suppress the warm
                // permanently, leaving the wallet with no fast path at all.
                let cache_pending = needs_cache && !self.db.subtree_cache_failed();
                if cache_serves {
                    if !self.witnesses_warm {
                        self.force_checkpoint = true;
                        log::info!(
                            "wallet spend-ready from the subtree cache (notes={note_count}, matured={matured}) — skipping a {}-leaf witness climb it would never read",
                            matured.saturating_sub(self.db.witnessed_upto())
                        );
                    }
                    self.witnesses_warm = true;
                    self.warm_via_subtree_cache = true;
                } else if cache_pending {
                    // Cache still building: hold the warm off rather than race it. The
                    // latch is reused only to skip the phases — this is "deferred", not a
                    // claim the witness set reached the anchor, and nothing reads it as one.
                    self.witnesses_warm = true;
                    self.warm_via_subtree_cache = true;
                } else if self.warm_via_subtree_cache {
                    // Neither serving nor pending — the cache was rejected by its root gate
                    // or invalidated by a rebuild, and will not come back. Resume actually
                    // maintaining witnesses; the climb is slow but it is the only path left.
                    self.warm_via_subtree_cache = false;
                    self.witnesses_warm = false;
                    // Only worth a warning when there is actually a climb to resume.
                    //
                    // This fired for every empty or freshly fast-synced wallet, where
                    // `matured == base_size` and there are no notes: a warning about
                    // resuming work that amounts to nothing. It ran tens of thousands of
                    // times and buried the lines that mattered — a wallet stuck
                    // re-quarantining its checkpoint every 60 s, and a payment spending
                    // 392 s on a witness climb, both of which had to be found by
                    // filtering this message out. A log nobody can read is not a log.
                    let climb = matured.saturating_sub(self.db.witnessed_upto());
                    let idle = self.db.notes().is_empty() || climb == 0;
                    if idle {
                        log::debug!(
                            "subtree cache not serving at matured={matured}, but nothing to climb (notes={}, climb={climb})",
                            self.db.notes().len()
                        );
                    } else {
                        log::warn!(
                            "subtree cache unavailable at matured={matured} (failed={}); resuming a {climb}-leaf witness climb for this wallet",
                            self.db.subtree_cache_failed()
                        );
                    }
                }
                // Take a warm permit, or leave the heavy catch-up to another tick. This is
                // `try_acquire`, not `acquire`: a wallet that can't warm right now should
                // fall through and keep doing its cheap incremental sync rather than block
                // a sync slot waiting. Ordinary sync never touches this gate.
                // The warm climb takes its own short-lived permit. It is throttled work,
                // not a build that must run to completion, so it must not sit on a slot a
                // queued cache build could use.
                let warm_permit = if self.witnesses_warm { None } else { warm_gate.try_acquire().ok() };
                if !self.witnesses_warm && warm_permit.is_some() {
                    // Roll the base up to our notes first (cheap: cost is leaves, not
                    // leaves×budget), then warm the witnesses to the matured anchor.
                    // Bound each step by WORK (≈ leaves×budget ≤ COLD_WARM_BUDGET) so every
                    // wallet's step costs the same regardless of its size.
                    let wstep = (COLD_WARM_BUDGET / budget as u64).clamp(WITNESS_MIN_STEP, COLD_WARM_STEP);
                    // Run every phase of the warm back-to-back inside one tick, instead of
                    // one step per sync pass.
                    //
                    // Spreading it out was the real cost. The three phases are sequential —
                    // roll the base, sweep the witnesses to `matured`, then adopt the notes
                    // the sweep passed — and adoption is the ONLY phase that makes a spend
                    // fast. On the live miner wallet the sweep had ~46 K leaves to climb
                    // while opening zero witnesses (every eligible note sits below it), which
                    // is ~8 s of actual work; at one 2 730-leaf step per pass that became a
                    // 30-minute prologue, and adoption never ran at all. Meanwhile every
                    // send paid 6 × 22 s of rebuilds. Same total work, run to completion.
                    let deadline = std::time::Instant::now() + COLD_WARM_TICK;
                    let t_tick = std::time::Instant::now();
                    let mut adopted = 0usize;
                    loop {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                        // Phase 1: roll the base up to our notes (cost is leaves, not
                        // leaves×budget), which shortens every later replay.
                        // Freeze base compaction while an off-lock cache build is in flight.
                        // The build snapshots (base, leaves) and `install_subtree_cache`
                        // rejects it if the base moved since — so a wallet whose base kept
                        // advancing (consolidation spends its oldest note, the cap rises,
                        // the base rolls up) rebuilt forever, never installing (117 "the
                        // stream moved" failures live). The base is a memory optimisation;
                        // it can wait the ~minutes a build takes, then resume.
                        if !self.build_in_flight
                            && tokio::task::block_in_place(|| self.db.advance_base_capped(matured, COLD_WARM_STEP))
                        {
                            continue;
                        }
                        // A wallet holding ZERO notes has nothing to witness: phases 2-3
                        // would sweep the whole tree (~1.5M leaves at 4.4 s/tick, observed
                        // live after a rescan) for exactly zero benefit. Mark warm once the
                        // base is rolled; notes arriving later always land ABOVE the matured
                        // anchor and get witnessed by the steady incremental advance as it
                        // passes them, and a rescan that finds notes comes back through here
                        // with note_count > 0 anyway.
                        if note_count == 0 {
                            self.witnesses_warm = true;
                            break;
                        }
                        // Phase 2: sweep the witness set forward to the matured anchor.
                        if tokio::task::block_in_place(|| self.db.advance_witnesses_capped(matured, wstep)) {
                            continue;
                        }
                        // Phase 3: the sweep only opens a witness for a note it PASSES, so
                        // notes below it — a note-heavy wallet's entire holding — get none
                        // and would replay on every spend forever. Adopt them: one O(chain)
                        // replay each, paid here rather than on the send path, kept for good.
                        let Some(pos) = self.db.next_note_needing_witness() else {
                            self.witnesses_warm = true;
                            break;
                        };
                        let t = std::time::Instant::now();
                        let ok = tokio::task::block_in_place(|| self.db.install_witness(pos, matured));
                        adopted += 1;
                        log::info!(
                            "adopted witness for note@{pos} in {:.1?} (ok={ok}, {}/{} slots warm) — this note no longer replays at spend time",
                            t.elapsed(),
                            self.db.live_witness_count(),
                            budget,
                        );
                        if !ok {
                            break;
                        }
                    }
                    // Persist only when this tick achieved something worth a checkpoint.
                    //
                    // A checkpoint serialises the whole leaf stream — 15–29 MB on these
                    // wallets — so forcing one every tick (as this did) meant tens of MB of
                    // write amplification per wallet per few seconds, on top of the warm's
                    // own CPU. Adoption is expensive to redo (a full replay each) so it is
                    // always persisted; raw sweep progress is cheap by comparison and rides
                    // the ordinary `CHECKPOINT_EVERY` cadence instead.
                    if adopted > 0 || self.witnesses_warm {
                        self.force_checkpoint = true;
                    }
                    if self.witnesses_warm {
                        log::info!(
                            "witnesses warmed for wallet (notes={}, witness_budget={}, warm={}, adopted {} this tick, base_size={}, witnessed_upto={} == matured {})",
                            note_count,
                            budget,
                            self.db.live_witness_count(),
                            adopted,
                            self.db.base_size(),
                            self.db.witnessed_upto(),
                            matured,
                        );
                    } else {
                        log::info!(
                            "warming wallet: {:.1?} this tick (notes={}, warm={}/{}, adopted {}, witnessed_upto={} of matured {}, {} leaves to go)",
                            t_tick.elapsed(),
                            note_count,
                            self.db.live_witness_count(),
                            budget,
                            adopted,
                            self.db.witnessed_upto(),
                            matured,
                            matured.saturating_sub(self.db.witnessed_upto()),
                        );
                    }
                } else {
                    let due = self.last_witness_advance.map(|t| t.elapsed() >= WITNESS_ADVANCE_INTERVAL).unwrap_or(true);
                    if due {
                        // Bound the step by WORK, not leaves. `WITNESS_ADVANCE_CAP` is a
                        // LEAF cap sized when only ≤32-note wallets reached this path; with
                        // a 12-witness budget it costs 4 000 × 12 ≈ 48 000 Sinsemilla
                        // appends ≈ 8 s — once per second, per wallet, holding the wallet
                        // lock. Every note-heavy wallet that loses the race for a warm
                        // permit lands here, so that alone saturated the box and starved
                        // ordinary sync (a 1-note wallet stuck at "syncing 97%").
                        let steady_cap = (COLD_WARM_BUDGET / budget as u64).clamp(WITNESS_MIN_STEP, WITNESS_ADVANCE_CAP);
                        tokio::task::block_in_place(|| {
                            if !self.build_in_flight {
                                self.db.advance_base_capped(matured, BASE_ADVANCE_STEP);
                            }
                            // Only a WARM wallet belongs on the incremental step: it is a
                            // few appends per new leaf (one leaf per block at 1 BPS). A
                            // wallet still waiting for a warm permit must NOT do its
                            // catch-up here — that is the warm's job, under the gate that
                            // bounds how many run at once.
                            // `warm_via_subtree_cache` wallets are excluded: the sweep
                            // still costs one `lag_tree` append per leaf even with an
                            // empty witness set, so leaving them on it would just move
                            // the same wasted Sinsemilla work from the warm tick to the
                            // steady tick. Their paths come from the cache, which
                            // `append_leaf` keeps current for one hash per leaf.
                            if self.witnesses_warm
                                && !self.warm_via_subtree_cache
                                && self.db.advance_witnesses_capped(matured, steady_cap)
                            {
                                self.witnesses_warm = false;
                            }
                        });
                        self.last_witness_advance = Some(std::time::Instant::now());
                    }
                }
            }
        }
        self.error = None;
        self.updated_unix = now_unix();
    }

    /// The newest chain-block boundary at least `anchor_depth + slack` blue units below
    /// the sink: the matured, canonical anchor a spend roots at.
    fn matured_leaves(&self) -> Option<u64> {
        let cutoff_blue = self.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        self.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, leaves)| leaves)
    }

    /// Send-time witness top-up, **bounded for every wallet**.
    ///
    /// This is a latency optimization, never a correctness requirement: the send path
    /// calls `witness_paths_at` first (subtree cache, O(depth)) and falls back to a
    /// per-note rebuild for anything it declines. Climbing only pre-warms
    /// `live_witness_path`, a third route neither of those needs.
    ///
    /// It used to exempt wallets with <= 32 notes from the cap entirely and climb
    /// *unbounded*, on the theory that a small wallet is always nearly warm. It isn't:
    /// a wallet whose witnesses were last advanced long ago is arbitrarily far behind
    /// no matter how few notes it holds. Live, a 2-note wallet spent **397.8 s**
    /// climbing 891,565 leaves inside a send — and the batch builder then witnessed the
    /// selected note in **2.9 ms**. The user watched "building your zero-knowledge
    /// proof" for six minutes before the proof even started. The exemption made the
    /// smallest wallets pay the largest bill.
    ///
    /// So: skip outright when the subtree cache can serve the anchor, and otherwise cap
    /// the inline climb the same way for everyone. A skipped climb costs nothing but a
    /// slower first witness build; an uncapped one costs the user the whole payment.
    fn advance_spend_witnesses_bounded(&mut self, shared_tree_covers: u64, shared_tree_base: u64) {
        let Some(matured) = self.matured_leaves() else { return };
        let note_count = self.db.notes().len() as u64;
        // `subtree_paths`' preconditions: if it can serve, the climb is pure waste.
        //
        // The SHARED tree counts too, and forgetting it was expensive. Sync deliberately
        // stops a wallet building its own cache once the shared tree covers it — that is
        // the ~324 s per wallet the shared tree exists to save — so a borrowing wallet
        // has no cache of its own BY DESIGN. Asking only about its own cache therefore
        // concluded "no cache, build one" for precisely the wallets that need none, and
        // the spend then took its witnesses from the shared tree anyway
        // (`batch_witness_paths`), discarding everything the climb had built.
        //
        // Measured on the hosted daemon, one payment: 392.0 s climbing 2,770,988 leaves
        // with `witnessed_upto` ending where it began (2 → 2), then 102.6 s to
        // batch-witness the 13 notes actually being spent, and only then did the proof
        // start. Eight minutes before any cryptography, six and a half of them on work
        // nothing read. The user's app gave up first.
        //
        // Mirrors `shared_serves` in the sync path so the two cannot drift apart again:
        // a leaves-only wallet is not a borrower, the shared tree must reach the anchor,
        // AND its base must reach down to this wallet's oldest note (else those old
        // positions decline and the spend climbs O(chain) — the consolidation killer).
        let oldest_note = self.db.notes().iter().map(|n| n.position).min().unwrap_or(u64::MAX);
        let shared_serves = !self.db.is_leaves_only()
            && shared_tree_covers >= matured
            && matured > 0
            && shared_tree_base <= oldest_note;
        if (self.db.subtree_cache_ready(matured) || shared_serves) && matured > self.db.base_size() {
            return;
        }
        let climb = matured.saturating_sub(self.db.witnessed_upto());
        if climb <= SPEND_CLIMB_INLINE_MAX {
            self.db.advance_witnesses(matured);
            return;
        }
        // The subtree cache used to be built HERE — inline, under the wallet lock, in
        // `block_in_place`, on ONE core — so that the batch builder would not do the same
        // O(chain) walk and throw it away. That reasoning still holds; the placement did
        // not. On a self-hosted daemon (no shared tree) the first send folded the whole
        // stream on one thread for an hour, `/api/wallet/balance` and the sync loop
        // waited on this mutex the whole time, nothing was logged, and the app gave up
        // at 300 s. The build now runs BEFORE the send takes the lock
        // (`build_send_cache_off_lock`): the same detached job the sync pass uses, on
        // every core, with progress in `/api/status`. By the time this runs the cache is
        // ready (and returned above), or the build was rejected / did not install and
        // this one send takes the batch replay once. Never fold O(chain) under the lock.
        let span = matured.saturating_sub(self.db.base_size());
        log::info!(
            "send: skipping inline witness climb of {climb} leaves (notes={note_count}, span={span}, cache_failed={}, build_in_flight={}); selected notes come from the batch builder, or rebuild on demand",
            self.db.subtree_cache_failed(),
            self.build_in_flight,
        );
    }

    /// Would a send from this wallet have to build its subtree cache first? The gates
    /// of [`Self::advance_spend_witnesses_bounded`] up to its (former) build branch,
    /// asked without doing anything: no cache and no shared tree at the anchor, a climb
    /// beyond the inline cap, a span worth caching, and no earlier rejection.
    /// `build_send_cache_off_lock` polls this with the lock released between polls.
    fn send_needs_cache_build(&self, shared_tree_covers: u64, shared_tree_base: u64) -> bool {
        let Some(matured) = self.matured_leaves() else { return false };
        let oldest_note = self.db.notes().iter().map(|n| n.position).min().unwrap_or(u64::MAX);
        let shared_serves = !self.db.is_leaves_only()
            && shared_tree_covers >= matured
            && matured > 0
            && shared_tree_base <= oldest_note;
        if (self.db.subtree_cache_ready(matured) || shared_serves) && matured > self.db.base_size() {
            return false;
        }
        if matured.saturating_sub(self.db.witnessed_upto()) <= SPEND_CLIMB_INLINE_MAX {
            return false;
        }
        matured.saturating_sub(self.db.base_size()) >= SUBTREE_CACHE_MIN_SPAN && !self.db.subtree_cache_failed()
    }
}

/// Ingest one chain block's shielded effects — the node already assembled them
/// (`GetShieldedBlocks`) exactly as the consensus §2.4 transition applied them:
/// the block's own coinbase notes first, then each accepted (post-retain)
/// shielded bundle's actions in consensus order.
fn ingest_shielded_chain_block(db: &mut WalletDb, blk: &RpcShieldedChainBlock) {
    let mut coinbase_notes = Vec::new();
    for (i, out) in blk.coinbase_outputs.iter().enumerate() {
        if out.script_public_key.len() >= ORCHARD_SCRIPT_LEN {
            let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
            recipient.copy_from_slice(&out.script_public_key[..ORCHARD_SCRIPT_LEN]);
            let mut note_seed = Vec::with_capacity(36);
            note_seed.extend_from_slice(&blk.coinbase_txid.as_bytes());
            note_seed.extend_from_slice(&(i as u32).to_le_bytes());
            coinbase_notes.push((derive_coinbase_note_desc(recipient, &note_seed), out.value));
        }
    }
    let compact: Vec<Vec<CompactActionRecord>> = blk.accepted_actions.iter().filter_map(|b| decode_compact_actions(b)).collect();
    db.ingest_block_compact_with_meta(&coinbase_notes, &compact, None);
}

/// One-off replay of the settled **matured** chain prefix into a fresh wallet
/// view (send fallback + non-custodial `/prepare`): anchors the tree as far back as
/// the node can serve — genesis on an archival node, the pruning-point frontier
/// otherwise — then ingests chain blocks up to `sink_blue − (anchor_depth + slack)` — so
/// every recovered note is matured and `witness_path` roots at a matured,
/// canonical chain-block anchor. `db` must be freshly constructed (seed or FVK).
async fn replay_matured(client: &GrpcClient, genesis: RpcHash, mut db: WalletDb) -> Result<WalletDb, String> {
    // Probe genesis first, exactly like `full_scan_entry`. Anchoring at the pruning
    // point unconditionally was this function's version of the 2026-07-28 amputation
    // bug: `--archival` pins the RETENTION ROOT (what block serving is gated on), not
    // `pruning_point_hash`, which advances on every node — and the shielded stores are
    // never pruned at all. So an archival node serves genesis, and starting at the
    // pruning point discards real history for nothing. Measured live 2026-07-31: the
    // pruning point sat at tree position 589,776 of 792,715, i.e. 74% of every note
    // ever minted was below the anchor. Here that is worse than a wrong balance —
    // both callers are SPEND paths, so an unseen note is a note the plan cannot select
    // and the user gets "insufficient funds" while holding the coins.
    let (start, ts) = match client.get_shielded_tree_state(Some(genesis)).await {
        Ok(ts) if ts.block_hash == genesis => {
            log::info!("matured replay anchored at GENESIS — this node serves the complete shielded history");
            (genesis, ts)
        }
        _ => {
            let dag = client.get_block_dag_info().await.map_err(|e| format!("get_block_dag_info failed: {e}"))?;
            let start = dag.pruning_point_hash;
            let ts = client
                .get_shielded_tree_state(Some(start))
                .await
                .map_err(|e| format!("get_shielded_tree_state({start}) failed: {e}"))?;
            if ts.block_hash != start {
                return Err("node does not support explicit tree-state checkpoints (update the node)".into());
            }
            log::warn!(
                "matured replay anchored at the PRUNING POINT (daa {}, tree position {}) — this node cannot serve \
                 genesis, so notes minted below that point are invisible to this spend and it may report \
                 insufficient funds against a wallet that in fact holds enough",
                ts.daa_score,
                ts.size
            );
            (start, ts)
        }
    };
    let fs = FrontierState {
        size: ts.size,
        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
        ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
    };
    db.apply_frontier(&fs).ok_or("inconsistent scan-anchor frontier")?;

    let mut low = start;
    loop {
        let resp = client.get_shielded_blocks(low, SHIELDED_PAGE).await.map_err(|e| format!("get_shielded_blocks failed: {e}"))?;
        if resp.reorged {
            return Err("chain reorged during the matured replay; retry".into());
        }
        let cutoff = resp.sink_blue_score.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        let mut advanced = false;
        for b in &resp.blocks {
            if b.blue_score > cutoff {
                return Ok(db);
            }
            ingest_shielded_chain_block(&mut db, b);
            low = b.hash;
            advanced = true;
        }
        if !advanced {
            return Ok(db);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

type Wallet = Arc<Mutex<WalletEntry>>;

/// Progress of one detached subtree-cache build, readable WITHOUT the wallet lock.
///
/// The build runs on a blocking thread and whoever is waiting for it (a first send, the
/// sync loop) may be holding the wallet mutex, so the figures `/api/status` and the
/// logs report must live elsewhere. `done` is bumped by the fold itself
/// (`SubtreeBuildJob::run_with_progress`), every ~1 K leaves.
#[derive(Clone)]
struct BuildProgress {
    done: Arc<std::sync::atomic::AtomicU64>,
    total: u64,
    started: std::time::Instant,
}

impl BuildProgress {
    /// `(done, total, percent, seconds remaining)` — the ETA extrapolates the observed
    /// rate and is `None` until there is one (first second, nothing folded yet).
    fn snapshot(&self) -> (u64, u64, f64, Option<u64>) {
        let done = self.done.load(std::sync::atomic::Ordering::Relaxed).min(self.total);
        let pct = if self.total == 0 { 100.0 } else { done as f64 * 100.0 / self.total as f64 };
        let secs = self.started.elapsed().as_secs_f64();
        let eta = if done > 0 && secs >= 1.0 { Some(((self.total - done) as f64 * secs / done as f64).round() as u64) } else { None };
        (done, self.total, pct, eta)
    }

    /// The same figures as one phrase for a log line or an error message, e.g.
    /// `43.2% (1,203,200/2,780,000 leaves, 4m 10s elapsed, ETA ~5m 30s)`.
    fn describe(&self) -> String {
        let (done, total, pct, eta) = self.snapshot();
        let el = self.started.elapsed().as_secs();
        let eta = match eta {
            Some(s) => format!("~{}m {}s", s / 60, s % 60),
            None => "n/a".to_string(),
        };
        format!("{pct:.1}% ({done}/{total} leaves, {}m {}s elapsed, ETA {eta})", el / 60, el % 60)
    }
}

/// How often a running subtree-cache build logs where it is. An hour-long fold that
/// printed nothing between "started" and "complete" is what made the daemon look hung.
const BUILD_PROGRESS_LOG_SECS: u64 = 20;

/// Longest a send waits for the wallet's off-lock subtree-cache build before taking the
/// one-off batch replay instead. Generous on purpose: the wait is the build, and the
/// build is what makes every later send O(depth). The client's own transport ceiling
/// (the app aborts at 300 s) does not end it — the build is detached and installs
/// regardless, so a retry after the app gives up finds the cache ready.
const SEND_CACHE_BUILD_WAIT_MAX: std::time::Duration = std::time::Duration::from_secs(2 * 3600);

/// Run a detached subtree-cache fold on a blocking thread, logging where it is every
/// [`BUILD_PROGRESS_LOG_SECS`] and publishing the same figures in `state.cache_builds`
/// for `/api/status` — both readable without the wallet lock. Every off-lock build
/// (sync pass, warm sweep, first send, operator warm) goes through here. The progress
/// entry is removed when the fold returns; installing the result is the caller's job.
async fn run_subtree_build(
    state: &AppState,
    token: &str,
    who: &str,
    job: kaspa_shielded_core::walletdb::SubtreeBuildJob,
) -> Option<kaspa_shielded_core::walletdb::BuiltSubtreeCache> {
    let progress = BuildProgress {
        done: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        total: job.leaves() as u64,
        started: std::time::Instant::now(),
    };
    if let Ok(mut m) = state.cache_builds.lock() {
        m.insert(token.to_string(), progress.clone());
    }
    let counter = progress.done.clone();
    let mut fold = tokio::task::spawn_blocking(move || job.run_with_progress(&counter));
    let built = loop {
        tokio::select! {
            r = &mut fold => break r.ok().flatten(),
            _ = tokio::time::sleep(std::time::Duration::from_secs(BUILD_PROGRESS_LOG_SECS)) => {
                let (done, _, _, _) = progress.snapshot();
                let secs = progress.started.elapsed().as_secs_f64().max(1.0);
                log::info!(
                    "subtree cache build for {who}: {} — {:.0} leaves/s across {} threads",
                    progress.describe(),
                    done as f64 / secs,
                    rayon::current_num_threads(),
                );
            }
        }
    };
    if let Ok(mut m) = state.cache_builds.lock() {
        m.remove(token);
    }
    built
}

/// Start a detached subtree-cache build for `w` from a job snapshotted under its lock
/// (with `build_in_flight` already set by the caller): fold off the lock, then re-lock,
/// install, and persist. DETACHED on purpose — the sync loop joins its wallet tasks per
/// lap, and a client that gives up on a send must not take the build down with it.
/// `origin` names the path that asked, for the log.
fn spawn_subtree_build(state: &Arc<AppState>, token: &str, w: &Wallet, job: kaspa_shielded_core::walletdb::SubtreeBuildJob, origin: &'static str) {
    let state = state.clone();
    let w2 = w.clone();
    let who = token.to_string();
    tokio::spawn(async move {
        let leaves = job.leaves();
        log::info!("subtree cache build started for {who} ({leaves} leaves, off the wallet lock, asked by {origin})");
        let t = std::time::Instant::now();
        let built = run_subtree_build(&state, &who, &who, job).await;
        let mut e = w2.lock().await;
        e.build_in_flight = false;
        // Hand the slot back either way, so a queued wallet starts immediately.
        e.build_permit = None;
        let installed = built.is_some_and(|b| e.db.install_subtree_cache(b));
        if installed {
            // Persist at once: this was expensive and a restart must not repeat it.
            e.force_checkpoint = true;
            log::info!(
                "subtree cache complete for {who} in {:.1?} ({leaves} leaves, built OFF the wallet lock, asked by {origin}) — spends now witness in O(depth)",
                t.elapsed()
            );
        } else {
            log::warn!(
                "subtree cache build for {who} did not install after {:.1?} ({leaves} leaves, asked by {origin}) — the stream moved under it; keeping the replay path and retrying",
                t.elapsed()
            );
        }
    });
}

/// The one-time subtree-cache build a first send needs, run OFF the wallet lock and
/// awaited with the lock released.
///
/// `advance_spend_witnesses_bounded` used to fold it inline, under the lock, inside
/// `block_in_place`: on a self-hosted daemon (no shared tree) that pinned ONE core for
/// the whole O(chain) sweep — over an hour on a laptop — while `/api/wallet/balance`,
/// history and the sync loop waited on the mutex, nothing was logged, and the app gave
/// up at its 300 s ceiling (the build finished anyway, which is why the retry was fast).
/// Now it is the same detached job the sync pass runs — snapshot under the lock, fold on
/// every core with progress in `/api/status`, install under the lock — and this waits
/// for it by polling `build_in_flight` once a second, holding nothing. If another path
/// is already building, wait for that instead of folding twice. Returns once the wallet
/// has its cache, was shown not to need one, or its build ended without installing (the
/// caller then takes the batch replay once, exactly as before).
async fn build_send_cache_off_lock(state: &Arc<AppState>, token: &str, w: &Wallet) {
    let started = std::time::Instant::now();
    let mut armed = false;
    loop {
        let job = {
            let mut e = w.lock().await;
            let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
            let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
            if !e.send_needs_cache_build(shared_covers, shared_base) {
                return;
            }
            if e.build_in_flight {
                None
            } else if armed {
                // Our build came back without installing; one batch replay, then the
                // sync pass retries the build.
                return;
            } else {
                e.wants_cache_build = false;
                e.build_in_flight = true;
                Some(e.db.subtree_build_job())
            }
        };
        if let Some(job) = job {
            armed = true;
            spawn_subtree_build(state, token, w, job, "send");
        }
        if started.elapsed() >= SEND_CACHE_BUILD_WAIT_MAX {
            log::warn!("send: {token} waited {:.0?} for its subtree cache build; proceeding with the batch replay", started.elapsed());
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// The two node channels, swapped together so a reconnect can never leave the
/// request path talking to one connection and the sync loop to another.
#[derive(Clone)]
struct NodeClients {
    request: GrpcClient,
    sync: GrpcClient,
}

struct AppState {
    /// gRPC connection for the REQUEST path — wallet loads, the tip ticker, prepare /
    /// submit. Kept separate from `sync_client` so the background sync loop's continuous
    /// block-fetch traffic can't make a user's wallet load (which needs a couple of node
    /// RPCs) queue for seconds. Sharing one connection for both was the root cause of the
    /// "wallet won't connect": loads timed out behind the sync loop, so wallets never
    /// cached and every poll re-ran a slow, timing-out load.
    /// Node connectivity is deliberately OPTIONAL.
    ///
    /// The wallet API must stay up while its node is starting, restarting or simply
    /// unreachable. When `serve` blocked on the first connection instead, an
    /// unreachable node meant the HTTP listener was never bound at all, so the
    /// embedding app reported "wallet engine didn't start" and hid the user's cached
    /// wallet state — a node problem presenting as a wallet problem.
    ///
    /// A connector task fills this slot and retries forever; the tip monitor clears it
    /// after repeated failures so a fresh pair of channels is established.
    clients: std::sync::Arc<tokio::sync::RwLock<Option<NodeClients>>>,
    /// Why the node is unreachable, for status to report instead of guessing.
    node_error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    wallet_dir: String,
    prefix: Prefix,
    network: String,
    wallets: Mutex<HashMap<String, Wallet>>,
    /// The shared public commitment stream — see [`CHAIN_TREE_TOKEN`]. The SAME `Arc`
    /// is also in `wallets` under that token, so the ordinary sync loop advances it and
    /// the ordinary checkpoint path persists it; this handle just saves readers a map
    /// lookup on the spend path.
    chain_tree: Wallet,
    /// How far the shared tree reaches, PUBLISHED so readers never take its lock.
    ///
    /// This started as `chain_tree.try_lock()`, which was wrong in a way that silently
    /// disabled the whole optimisation: the chain tree is pinned always-active, so its
    /// own sync pass holds that lock across an entire chunk. `try_lock` therefore failed
    /// almost every time, every wallet read "the shared tree covers 0 leaves", and every
    /// wallet went on building its own tree. Measured after deploying: tree still 83–99%
    /// of scan cost, i.e. no change at all.
    ///
    /// An atomic cannot fail to be read, which is the property that was actually needed.
    chain_tree_size: std::sync::atomic::AtomicU64,
    /// The shared tree's BASE — the oldest position it can witness. Published alongside
    /// `chain_tree_size` for the same lock-free reason.
    ///
    /// `chain_tree_size` alone says the shared tree reaches the tip, but NOT how far down
    /// it reaches. The tree only serves positions in `[base, size)`; a wallet whose oldest
    /// note is below `base` is not covered and must keep its own cache. Ignoring this made
    /// old-note consolidations pay a full O(chain) climb even with the shared tree "ready"
    /// — the shared tree's base was raised to ~2.06M by the 2026-08 compaction bug and can
    /// never come back down on a pruned node, so every note below it was silently uncovered.
    chain_tree_base: std::sync::atomic::AtomicU64,
    /// The shared tree's tip frontier, republished after each of its own passes.
    ///
    /// A short-lived lock held only long enough to clone ~32 ommers, never across
    /// ingest — so a wallet adopting a frontier cannot queue behind a page scan.
    chain_tree_frontier: Mutex<Option<kaspa_shielded_core::tree::FrontierState>>,
    /// When true, a missing `X-Wallet-Token` maps to the "default" wallet (trusted
    /// single-user localhost). Off by default → a token is required on every request.
    allow_default_token: bool,
    /// Secret for encrypting seed files at rest. `None` → seeds stored in plaintext.
    wallet_secret: Option<String>,
    /// The network genesis hash: the shielded sighash **network domain** (what
    /// consensus signs against — `params.genesis.hash`, NOT the moving pruning
    /// point) and the guard persisted checkpoints are keyed by.
    genesis: RpcHash,
    /// Shared `GetShieldedBlocks` page cache for the sync loop (see [`PageCache`]).
    page_cache: Mutex<PageCache>,
    /// Last time each wallet token was touched by a request. The sync loop only keeps
    /// a wallet synced while it is being actively viewed; idle wallets (the bulk of a
    /// public daemon's tokens are one-time visitors) stop consuming CPU. Without this,
    /// 272 loaded wallets all full-scanning at once pinned every core and starved even
    /// `/health` — a live outage. A returning user's first poll re-touches and resumes
    /// it from its checkpoint.
    last_touch: Mutex<HashMap<String, std::time::Instant>>,
    /// Caps how many wallets load (rebuild their Merkle tree from the checkpoint /
    /// pruning point — tens of thousands of Sinsemilla hashes, synchronous on the async
    /// worker) at once. Without it, a daemon restart makes every reconnecting browser
    /// trigger a load simultaneously; hundreds of concurrent tree rebuilds pin every
    /// runtime worker and starve even `/health` (a live outage). With a small cap, most
    /// workers stay free for HTTP and loads queue briefly instead of melting the box.
    load_gate: tokio::sync::Semaphore,
    /// Payment preparation is deliberately serialized: witness reconstruction and Halo2
    /// proving are CPU-heavy synchronous work, and overlapping copies exhaust every
    /// runtime worker and take the whole wallet API offline.
    ///
    /// This bounds *total* proving CPU, so it is shared by every tenant — which means a
    /// caller must QUEUE on it, not fail on it. It used to be `try_acquire`, so on the
    /// hosted daemon one user's send made every other user's send fail outright with
    /// "a shielded payment is already being prepared", and a chunked payment (several
    /// sequential prepares) held that window open for minutes. Racing retries of the
    /// *same* wallet — the browser-retry storm this was really written for — are caught
    /// by `preparing` below, which is the check that should be a fast rejection.
    prepare_gate: tokio::sync::Semaphore,
    /// One permit for CONSOLIDATION — a payment a wallet makes to itself to merge its
    /// own notes.
    ///
    /// Two wallets consolidating would otherwise trade the prover between them, each
    /// taking the slot the moment the other released it, and a payment arriving in that
    /// gap would find it busy every time it looked.
    consolidate_gate: tokio::sync::Semaphore,
    /// Wallets (by FVK) with a preparation already in flight. A second concurrent
    /// prepare for the SAME wallet is a duplicate — a retry, a double-clicked button —
    /// and is rejected immediately rather than queued: it would select the same notes.
    /// Wallets with a preparation in flight → when it started, and whether it is the
    /// wallet paying itself (background note merging) rather than a payment the user is
    /// waiting on. Both are needed to explain a refusal instead of merely issuing one.
    preparing: std::sync::Mutex<HashMap<String, (std::time::Instant, bool)>>,
    /// Subtree-cache builds in flight, by token — see [`BuildProgress`]. Kept OUTSIDE
    /// the wallet mutex so `/api/status` and the 429 text can report a build's
    /// percentage while whoever is waiting on that build holds the wallet lock.
    cache_builds: std::sync::Mutex<HashMap<String, BuildProgress>>,
    /// Permits for the one-time cold warm; configured by
    /// [`ResourceLimits::warm_wallets`].
    warm_gate: std::sync::Arc<tokio::sync::Semaphore>,
    /// Last known virtual DAA score, refreshed by the sync loop and successful status
    /// calls, so status can answer instantly when the node RPC is momentarily contended.
    node_tip: Mutex<(u64, std::time::Instant)>,
    /// In-flight **non-custodial** payments: a `/api/wallet/prepare` builds the proof
    /// from a viewing key and parks the awaiting-signature bundle here, keyed by a
    /// random session id; `/api/wallet/submit` pops it, applies the device's spend-auth
    /// signatures, and broadcasts. Held in memory only — a restart drops pending
    /// sessions (the device just re-prepares). The seed is never involved.
    prepared: Mutex<HashMap<String, PreparedSession>>,
    /// Last-known-good status per loaded wallet, read by `status` when the wallet mutex
    /// is momentarily held by the sync loop (see [`StatusSnap`]). Refreshed by the sync
    /// loop each pass and by any `status` call that acquires the wallet lock.
    snapshots: Mutex<HashMap<String, StatusSnap>>,
    /// token -> receive address, derived from the wallet FILE and independent of whether
    /// the wallet is loaded, its mutex is free, or a snapshot exists.
    ///
    /// The address was previously reachable only through a loaded wallet's `WalletDb`, so
    /// every path that answered for a known-but-not-yet-loaded wallet returned
    /// `has_wallet: true` with `address: None`. Clients read a nameless wallet as a LOST
    /// REGISTRATION -- the SPA's `missingKnownWallet` test is `(!has_wallet || !address)` --
    /// and after three failed silent re-registrations it asked the user to retype their
    /// 64-character recovery seed for a wallet that was simply still opening. The window
    /// is normally milliseconds, which is why this survived; a daemon restart makes it
    /// minutes for every one of ~900 wallets at once, and then it is everybody's bug.
    ///
    /// A wallet file always carries enough to derive the address (seed or FVK), so a name
    /// is available the instant the file is found. Cached because it costs a file read and
    /// a key expansion, and status is polled once a second per open wallet.
    addr_index: Mutex<HashMap<String, String>>,
    /// Tokens whose sync pass from an earlier lap is still running. A lap skips these
    /// rather than queueing a second pass behind the first one's wallet mutex, which
    /// would consume a concurrency permit to wait on a wallet already being swept.
    ///
    /// A std mutex, deliberately: the entry must be removable from `Drop`, which cannot
    /// await. Held only for a set insert/remove, never across a suspension point.
    in_pass: std::sync::Mutex<HashSet<String>>,
    /// Full viewing key → tokens registered with it, for twin-checkpoint adoption
    /// (see [`adopt_twin_checkpoint`]). Built in the background at startup, kept
    /// current by registrations; entries are re-verified against the wallet files
    /// before use, so staleness only ever costs the fast path, never correctness.
    fvk_index: Mutex<HashMap<[u8; 96], HashSet<String>>>,
    /// Note-count ceiling for background consolidation; see [`Config::auto_consolidate`].
    auto_consolidate: Option<usize>,
    /// See [`Config::build_shared_tree`].
    build_shared_tree: bool,
    /// Whether custodial (seed-holding) endpoints are enabled; see
    /// [`Config::allow_custodial`] and [`require_custodial`].
    allow_custodial: bool,
    resources: ResourceLimits,
}

/// Build a status snapshot from a locked wallet entry. Shared by the sync loop and the
/// `status` handler so the spendable/maturing split is computed identically to what
/// `/prepare` will actually draw on (same anchor-depth cutoff).
fn snap_from_entry(address: String, e: &WalletEntry, daa_score: u64) -> StatusSnap {
    let tip = e.chain_len.max(daa_score);
    let total = e.db.balance();
    let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
    let matured_leaves = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc);
    let spendable: u128 = match matured_leaves {
        Some(matured) => e.db.notes().iter().filter(|n| n.position < matured).map(|n| n.value() as u128).sum(),
        None => 0,
    };
    // "I have a balance but cannot spend any of it" is the single worst state this
    // wallet can be in, and from the outside it is indistinguishable from a hang.
    // When it happens, say exactly why: the anchor cutoff, whether the boundary ring
    // even reaches back that far, and where the notes sit relative to it.
    // NB: debug, not info — `snap_from_entry` runs on every status call AND every mempool
    // tick (sub-second, per wallet), so an info! here floods the log. Turn it on with
    // RUST_LOG=zkas_walletd=debug when actually investigating a stuck balance.
    if total > 0 && spendable == 0 {
        log::debug!(
            "spendable=0 with balance {total}: sink_blue={} cutoff_blue={cutoff_blue} boundaries={} (oldest_blue={:?} newest_blue={:?}) matured_leaves={:?} note_positions={:?}",
            e.sink_blue,
            e.boundaries.len(),
            e.boundaries.front().map(|b| b.0),
            e.boundaries.back().map(|b| b.0),
            matured_leaves,
            e.db.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
        );
    }
    StatusSnap {
        address,
        watch_only: e.key.is_watch_only(),
        // `tip > 0` guard: when the pass's dag-info call times out, `chain_len` is 0 and
        // `scanned + margin >= 0` is trivially true — the UI then flashed "synced" on a
        // wallet that was mid-scan (observed live 2026-07-16). No tip info ⇒ not synced.
        // `blind_below == 0` guard: a view rebuilt against a node that could not serve the
        // wallet's history (see `WalletEntry::blind_below`) is caught up to the tip but
        // its balance is NOT final - notes minted below the blind point are invisible.
        // Reporting that as `synced` is the exact lie the 2026-07-30 four-token incident
        // told; `missing_history` already said why, but nothing consumed it before
        // presenting the balance as the whole truth.
        synced: tip > 0 && e.blind_below == 0 && (e.caught_up || (e.scanned as u64) + SYNC_MARGIN >= tip),
        scanned: e.scanned,
        chain_len: tip,
        balance_sompi: total,
        spendable_sompi: spendable,
        maturing_sompi: total.saturating_sub(spendable),
        // 0-conf = what the unsettled blocks do + what the mempool would do once mined.
        // The two are de-duplicated by nullifier in `scan_mempool`, so a tx crossing from
        // mempool into a block is counted exactly once throughout.
        pending_in: e.preview.incoming + e.mempool.incoming,
        pending_out: e.preview.outgoing + e.mempool.outgoing,
        // Change owed back by this wallet's own in-flight sends. `mark_spent` takes the
        // WHOLE input note out of `balance` at submit, so without this a one-note
        // wallet reads 0 until the change note is seen on-chain (the "balance goes to
        // 0 for ~3 s after a send" report). Not spendable, not in balance/maturing.
        pending_change: e.db.pending_change(),
        note_count: e.db.notes().len(),
        updated_unix: e.updated_unix,
        error: e.error.clone(),
        // Synced, but still doing the ONE-TIME witness warm-up (building/persisting the
        // spend paths) — sends work but the first one is slow until this finishes. Lets the
        // UI show "Preparing wallet for fast sends…" instead of a confusing "syncing 100%".
        // Note-heavy wallets skip the eager warm, so they are never reported as warming.
        warming: e.caught_up && !e.spend_fast_ready,
        missing_history: e.blind_below > 0,
        history_from_daa: (e.blind_below > 0 && e.blind_from_daa > 0).then_some(e.blind_from_daa),
        // Whether a spend would be ACCEPTED right now, which is not the same question as
        // `synced` and must not be inferred from it. `ensure_canonical_checkpoint` also
        // requires a valid mirror tree: a wallet borrowing the shared chain tree has no
        // meaningful anchor until it adopts that tree's frontier, and /prepare answers
        // "wallet is still catching up with the shared chain state".
        //
        // Reporting only `synced` meant a client could truthfully say "Ready - 1.27 ZKAS"
        // from one flag while Send refused on a different one, seconds apart, in the same
        // wallet. Users read that as the app contradicting itself, correctly, because it
        // was. The readiness a UI shows has to be the readiness the spend path enforces,
        // so it is published here rather than guessed there.
        // Deliberately NOT `tree_is_valid()`. A borrowing wallet clears that flag on
        // every appended leaf, so on a live chain it is false almost always — gating on
        // it would report a healthy wallet as permanently unable to spend. The mirror
        // tree is instead brought into line by `ensure_canonical_checkpoint`, which
        // waits for the shared tree rather than refusing. What remains, and what this
        // reports, is whether the scan is far enough along for a spend to be sound.
        //
        // Gated on reaching the ANCHOR, not the tip. A payment does not prove against the
        // chain head: it proves against a root `DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK`
        // blocks deep, and the spend tree is built only from blocks at or below that
        // cutoff. So a view that reaches the anchor already holds every note the payment
        // spends and every witness it needs; the blocks above the anchor contribute
        // nothing a proof consumes.
        //
        // Requiring `caught_up` conflated the two and cost real money-movement: a wallet
        // that hovers a few hundred blocks behind was refused although its proof would
        // verify — observed on a wallet holding 4.15M ZKAS, all of it matured, all of it
        // unspendable purely because a sync counter had not reached the tip.
        //
        // The allowance is DEFAULT_ANCHOR_DEPTH while the proof needs DEPTH + SLACK, so
        // ANCHOR_SLACK stays exactly what it is named: the cushion. It also absorbs the
        // small DAA-vs-blue-score divergence between `scanned` and the cutoff's units.
        //
        // What is genuinely given up is nullifier freshness: a note spent from another
        // device inside the lag window is unknown here, and such a spend is REJECTED by
        // consensus rather than mis-settled. Note that this risk is not created by
        // relaxing the gate — a wallet never ingests the last SYNC_TIP_MARGIN blocks at
        // all, so the blind window exists even when the app says "Ready". This widens it
        // from 200 blocks to 200 + lag; it does not open it. The UI is given
        // `blocks_behind` so it can say so instead of silently deciding for the user.
        //
        // The tree test is part of the predicate, not an afterthought: `/prepare` refuses
        // a wallet whose mirror tree is invalid unless it is BORROWING the shared tree
        // (which has no mirror of its own to check). Leaving it out here is how the app
        // came to show "Ready" and then answer a tap with "wallet is still catching up
        // with the shared chain state" — two flags, one wallet, seconds apart, and the
        // user correctly reading it as the app contradicting itself.
        //
        // Whatever the spend path enforces, this must state. If the two ever diverge
        // again, the card is lying rather than the daemon being strict.
        spend_ready: tip > 0
            && (e.caught_up || (e.scanned as u64) + DEFAULT_ANCHOR_DEPTH >= tip)
            && (e.db.tree_is_valid() || e.db.is_borrowing()),
        blocks_behind: tip.saturating_sub(e.scanned as u64),
        caught_up: e.caught_up,
    }
}

/// Project a cached snapshot onto a `StatusResp` (the wire shape the SPA reads).
fn fill_status_from_snap(resp: &mut StatusResp, s: &StatusSnap) {
    resp.has_wallet = true;
    resp.address = Some(s.address.clone());
    resp.watch_only = s.watch_only;
    resp.synced = s.synced;
    resp.spend_ready = s.spend_ready;
    resp.blocks_behind = s.blocks_behind;
    resp.scanned_blocks = s.scanned;
    resp.chain_len = s.chain_len;
    resp.balance_sompi = s.balance_sompi.to_string();
    resp.balance_fc = fmt_fc(s.balance_sompi);
    resp.spendable_sompi = s.spendable_sompi.to_string();
    resp.spendable_fc = fmt_fc(s.spendable_sompi);
    resp.maturing_sompi = s.maturing_sompi.to_string();
    resp.maturing_fc = fmt_fc(s.maturing_sompi);
    resp.pending_in_sompi = s.pending_in.to_string();
    resp.pending_in_fc = fmt_fc(s.pending_in);
    resp.pending_out_sompi = s.pending_out.to_string();
    resp.pending_out_fc = fmt_fc(s.pending_out);
    resp.pending_change_sompi = s.pending_change.to_string();
    resp.pending_change_fc = fmt_fc(s.pending_change);
    resp.note_count = s.note_count;
    resp.updated_unix = s.updated_unix;
    resp.error = s.error.clone();
    resp.warming = s.warming;
    resp.missing_history = s.missing_history;
    resp.history_from_daa = s.history_from_daa;
}

/// Last-known-good status for a loaded wallet, kept OUTSIDE the wallet mutex so the
/// `status` handler can answer from it the moment the sync loop is holding the wallet
/// lock (which, during a scan, is most of the time). Without this, a `try_lock` miss
/// on the request path returned an all-zero default — balance and scan progress
/// flickered to 0 on every poll that raced a scan pass, which read as "the wallet
/// stopped updating". The sync loop refreshes this after each pass; `status` also
/// refreshes it whenever it does get the lock.
#[derive(Clone, Default)]
struct StatusSnap {
    address: String,
    watch_only: bool,
    synced: bool,
    scanned: usize,
    chain_len: u64,
    balance_sompi: u128,
    spendable_sompi: u128,
    maturing_sompi: u128,
    pending_in: u128,
    pending_out: u128,
    pending_change: u128,
    note_count: usize,
    updated_unix: u64,
    error: Option<String>,
    warming: bool,
    missing_history: bool,
    history_from_daa: Option<u64>,
    /// May a spend be STARTED right now - the same condition `/prepare` enforces,
    /// not merely "the scan is caught up". See where it is computed.
    spend_ready: bool,
    /// How far this wallet's view trails the chain tip, in blocks.
    ///
    /// Published because a lagging wallet may now legitimately pay (see `spend_ready`)
    /// and the UI has to be able to say what it is trading away: arrivals inside this
    /// window are not counted yet, and a spend made from ANOTHER device inside it is
    /// unknown here.
    blocks_behind: u64,
    /// The sync loop's own verdict (`WalletEntry::caught_up`) as of this snapshot — not
    /// `synced`, which also folds in tip knowledge and the blind-history guard. Read by
    /// `mempool_loop` to tell a wallet that is idling at the tip (its lock is free, a
    /// preview can land) from one mid-scan (its lock is held for whole chunks).
    caught_up: bool,
}

/// A non-custodial payment proven and awaiting on-device spend-auth signatures.
struct PreparedSession {
    payment: PreparedPayment,
    amount: u64,
    fee: u64,
    created: std::time::Instant,
    /// Wallet this payment was prepared against, when the caller presented a token.
    /// `/submit` needs it to park the spent notes — without it the notes stay in the
    /// unspent set until the block carrying them clears the reorg holdback (~3 min),
    /// and a second send in that window re-selects the same note value-descending,
    /// producing a transaction consensus DROPS as a double-spend. The UI reports that
    /// send as successful, the payer's balance falls, and the payee never receives it.
    /// (The custodial `/send` path has always done this; the non-custodial one, which
    /// is what every shipped wallet actually uses, did not.)
    token: Option<String>,
    /// Absolute leaf positions of the notes this payment spends, to park on acceptance.
    positions: Vec<u64>,
}

/// How long a prepared (unsigned) non-custodial payment lives before it is swept.
const PREPARED_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a prepare waits for the shared proving slot before giving up. Generous:
/// a cold witness rebuild plus proof can run tens of seconds, and waiting behind one
/// is a far better outcome for the user than being told to retry — which is what
/// produced the retry storms in the first place.
const PREPARE_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// How long a consolidation WAITS for a prover/consolidate slot before giving up.
///
/// Consolidation used to fail the instant a slot was busy ("another wallet is
/// consolidating") — sensible when a merge took tens of seconds and was rare, but with
/// per-wallet subtree caches a merge is ~seconds, so a slot frees almost immediately and
/// the right thing is to WAIT a little, not reject. Kept well under `PREPARE_QUEUE_WAIT`
/// so a user-facing PAYMENT still has priority for the prover.
const CONSOLIDATE_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Releases this wallet's in-flight prepare marker on every exit path, including the
/// `?` early returns and a panic in the proving task.
struct PreparingGuard {
    state: Arc<AppState>,
    key: String,
}

impl Drop for PreparingGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.state.preparing.lock() {
            set.remove(&self.key);
        }
    }
}

impl AppState {
    /// The request-path channel, or `None` while the node is unreachable.
    ///
    /// Every caller already tolerates an RPC failure, so "no node yet" travels the
    /// same path a failed call does: the wallet keeps serving what it knows and
    /// reports the node as disconnected, rather than the whole service vanishing.
    async fn request_client(&self) -> Option<GrpcClient> {
        self.clients.read().await.as_ref().map(|c| c.request.clone())
    }

    /// The sync-loop channel, or `None` while the node is unreachable.
    async fn sync_client(&self) -> Option<GrpcClient> {
        self.clients.read().await.as_ref().map(|c| c.sync.clone())
    }

    /// Why the node is unreachable, if it is.
    fn node_error(&self) -> Option<String> {
        self.node_error.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Merkle paths for `positions` at `matured`, served from the **shared chain tree**
    /// instead of the calling wallet's own copy of the stream.
    ///
    /// Returns `None` — meaning "use your own tree" — unless the shared tree can answer
    /// for *every* requested position. A partial answer would send the caller down its
    /// own O(chain) path anyway, and paying both is worse than paying one.
    ///
    /// **Never blocks.** `try_lock`: the chain tree is being advanced by the sync loop
    /// most of the time, and a send must not queue behind a page ingest. A miss here
    /// costs the old behaviour, not a stall. This is also what keeps the lock order
    /// safe — a wallet may reach for the chain tree, the chain tree never reaches for a
    /// wallet, and neither ever waits.
    ///
    /// Correctness does not rest on the two streams agreeing: every path
    /// `witness_paths_at` returns is verified to root at `matured` before it is handed
    /// out (`subtree_paths`), so a chain tree that had somehow diverged would return
    /// `None` and decline, never a wrong witness.
    fn chain_tree_paths(&self, positions: &[u64], matured: u64) -> Option<Vec<Option<kaspa_shielded_core::MerklePath>>> {
        // Wait BRIEFLY for the tree, don't bail on the first miss.
        //
        // A bare `try_lock().ok()?` returned `None` the instant the sync loop held the
        // tree for its (sub-second) tip-follow chunk — and `None` here sends the spend
        // down `witness_paths_at`, an O(chain) replay that is 500–700 s for an old note.
        // Trading a wait for the tree against a ~10-minute climb is not close. This
        // runs under `block_in_place` (see `batch_witness_paths`), so a blocking sleep is
        // correct here; the deadline caps it so a genuinely wedged tree still falls back.
        //
        // Why 20 s, not 2 s: measured live, the chain tree's own catch-up chunk holds this
        // lock ~8 s during a heavy `GetShieldedBlocks` ingest (1978 ms/page × 4 pages), and
        // the pinned shared tree runs those chunks back-to-back with only a per-page sleep
        // between them. A 2 s deadline expired inside a single ingest chunk, so ~1/3 of
        // sends fell to the climb even with the subtree cache READY and able to answer in
        // µs the instant the lock is free (observed: 12 climbs of 675–1520 s in 40 min).
        // 20 s spans an ingest chunk plus its inter-page window, so the reader wins the
        // lock and serves from the cache; only a tree wedged for longer than that — the
        // case the fallback exists for — still declines.
        let e = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                if let Ok(g) = self.chain_tree.try_lock() {
                    break g;
                }
                if std::time::Instant::now() >= deadline {
                    // DIAGNOSTIC: the shared tree can witness any old note (it never
                    // compacts), so any decline here is why a consolidation fell to the
                    // O(chain) climb. Record which branch, once, with the numbers.
                    log::warn!(
                        "chain_tree_paths DECLINE=lock_timeout for {} position(s) (min={:?})",
                        positions.len(),
                        positions.iter().min()
                    );
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        if !e.db.is_leaves_only() || e.db.size() < matured {
            log::warn!(
                "chain_tree_paths DECLINE=size (leaves_only={}, shared_size={}, matured={}) for {} position(s) min={:?}",
                e.db.is_leaves_only(),
                e.db.size(),
                matured,
                positions.len(),
                positions.iter().min()
            );
            return None;
        }
        let paths = e.db.witness_paths_at(positions, matured);
        let served = paths.iter().filter(|p| p.is_some()).count();
        if served < positions.len() {
            let mut unserved: Vec<u64> =
                positions.iter().zip(paths.iter()).filter(|(_, p)| p.is_none()).map(|(pos, _)| *pos).collect();
            unserved.sort_unstable();
            log::warn!(
                "chain_tree_paths DECLINE=unserved {}/{} (shared base_size={}, upto={}, cache_ready={}, matured={}); first unserved positions={:?}",
                positions.len() - served,
                positions.len(),
                e.db.base_size(),
                e.db.subtree_build_upto(),
                e.db.subtree_cache_ready(matured),
                matured,
                &unserved[..unserved.len().min(6)]
            );
        }
        paths.iter().all(|p| p.is_some()).then_some(paths)
    }

    /// Batch Merkle paths for a spend: from the shared chain tree when it can serve
    /// them, otherwise from the wallet's own stream.
    ///
    /// **The differential.** When the shared tree answers AND the wallet's own subtree
    /// cache is ready, both answers cost O(depth), so we take both and compare. That
    /// makes every send on an already-warm wallet a live cross-check of the shared
    /// stream against an independently built one, on production data, through real
    /// reorgs — the evidence needed before wallets are allowed to stop keeping their own
    /// tree at all.
    ///
    /// It is deliberately gated on `subtree_cache_ready`: the wallet's fallback answer
    /// is an O(chain) replay, and paying that to check the thing that exists to avoid it
    /// would defeat the entire change. Cheap to verify, or not verified.
    ///
    /// On disagreement we log loudly and return the wallet's OWN paths. A wallet's own
    /// tree is the incumbent; the shared one has to earn the trust.
    fn batch_witness_paths(&self, db: &WalletDb, positions: &[u64], matured: u64) -> Vec<Option<kaspa_shielded_core::MerklePath>> {
        // Serve from the shared chain tree when it can answer for every position.
        //
        // This was pulled off the spend path on 2026-08-07 while payments were failing
        // with `InvalidExternalSignature`, on nothing more than timing. The cause turned
        // out to be a shipped APK carrying a signer built for a different chain's
        // genesis — the signature was over the wrong domain, and the daemon was innocent
        // throughout. Removing it did not fix the failures, which is what proved it.
        //
        // It has since logged ZERO disagreements against wallets' own trees, on
        // production data, through reorgs. That is the evidence it was asked for.
        //
        // Correctness does not rest on the two agreeing: `subtree_paths` verifies every
        // path it returns roots at `matured` before handing it over, so a diverged tree
        // declines rather than lying. The differential below is a second line, kept
        // because it costs one comparison when both answers are already cheap.
        if let Some(shared) = self.chain_tree_paths(positions, matured) {
            if db.subtree_cache_ready(matured) {
                let own = db.witness_paths_at(positions, matured);
                for (i, (a, b)) in shared.iter().zip(own.iter()).enumerate() {
                    let (Some(a), Some(b)) = (a, b) else { continue };
                    if a.position() != b.position() || a.auth_path() != b.auth_path() {
                        log::error!(
                            "SHARED TREE DISAGREES with the wallet's own tree at position {} (matured={matured}, \
                             note {i} of {}) — using the wallet's own path; the shared stream must not be trusted",
                            positions.get(i).copied().unwrap_or_default(),
                            positions.len()
                        );
                        return own;
                    }
                }
            }
            return shared;
        }
        db.witness_paths_at(positions, matured)
    }

    /// The wallet's receive address, taken from its view (works for seed and
    /// watch-only wallets alike — both know the address).
    fn address_of(&self, db: &WalletDb) -> String {
        String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &db.my_address_bytes()))
    }

    /// This wallet's receive address, read from its FILE -- no scan, no loaded state, no
    /// wallet mutex. Answers for a wallet that is merely known to exist.
    ///
    /// The point is that "which wallet is this" and "what is in it" are different
    /// questions with very different costs, and only the second one needs the wallet to
    /// be open. Conflating them is what let a still-loading wallet look like a forgotten
    /// one (see [`AppState::addr_index`]).
    ///
    /// Returns `None` only when the file is absent or unreadable -- including an encrypted
    /// seed with no passphrase available, where the daemon genuinely cannot name the
    /// wallet. Nothing is cached in that case, so a later unlock is picked up.
    async fn address_from_disk(&self, token: &str) -> Option<String> {
        if let Some(addr) = self.addr_index.lock().await.get(token) {
            return Some(addr.clone());
        }
        // Deliberately outside the index lock: a cold read touches the disk and expands a
        // key, and holding the map across that would serialise every status poll behind
        // the slowest wallet on the box. A duplicate derivation under a race is harmless
        // -- it is a pure function of the file.
        let (key, _, _) = load_wallet_meta(&self.wallet_dir, token, self.wallet_secret.as_deref())?;
        let addr = self.address_of(&key.empty_db()?);
        self.addr_index.lock().await.insert(token.to_string(), addr.clone());
        Some(addr)
    }

    fn address_for_seed(&self, seed: &[u8; 32]) -> Option<String> {
        let raw = address_bytes_from_seed(*seed)?;
        Some(String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &raw)))
    }

    /// Build a **fast-sync** wallet entry from the node's pruning-point frontier
    /// (`GetShieldedTreeState`): the wallet's note-commitment tree starts at that
    /// finalized checkpoint and it scans only later blocks. Since the node prunes
    /// pre-checkpoint blocks anyway, this is both the *correct* start (right absolute
    /// leaf positions once pruning is active) and the *fast* one — sync is O(blocks
    /// since the pruning point), not O(chain). Returns `None` if the node lacks the
    /// RPC or a frontier yet, so the caller falls back to a full pruning-point scan.
    ///
    /// **Completeness gate:** a fast-synced wallet is blind to notes minted before
    /// the checkpoint, so this path is only sound for a wallet *born at or after*
    /// it. `birthday` is the wallet's birth DAA score; when it precedes the
    /// checkpoint (and in particular `birthday == 0`, "may hold funds from any
    /// height"), this returns `None` and the caller must full-scan. Skipping this
    /// gate was a live bug: imported wallets silently showed less than their real
    /// balance ("fully synced but missing coins") because their older notes were
    /// behind the fast-sync base.
    async fn fast_sync_entry(&self, key: WalletKey, recoverable: bool, guard: RpcHash, birthday: u64) -> Option<WalletEntry> {
        // Page budgets for the metadata walks (2,000 blocks per page, ~0.3 s each). Headers
        // above the pruning point: generous — the finality window is a few dozen pages.
        // From genesis through the archive (only a node with the archive fallbacks but no
        // locator ever gets here): a short budget, because the request blocks meanwhile.
        const WALK_PAGES_HEADERS: u32 = 4000;
        const WALK_PAGES_ARCHIVE: u32 = 100;
        // Bound the checkpoint RPC: on a healthy chain it returns immediately, but the
        // node's finality-point walk can be pathologically slow on a degenerate DAG
        // (e.g. difficulty collapsed to the floor). Time it out and fall back to a full
        // scan rather than hanging the wallet.
        let cp = match tokio::time::timeout(std::time::Duration::from_secs(5), self.request_client().await?.get_shielded_tree_state(None)).await {
            Ok(Ok(cp)) => cp,
            _ => return None,
        };
        // A birthday OLDER than the finality checkpoint used to mean "full scan
        // required" — and a full scan anchors at GENESIS, i.e. every block the chain
        // ever had. Any wallet older than the ~12 h finality window hit it, and on a
        // phone that is hours to days ("syncing from 0"). But an ARCHIVAL node retains
        // the per-block tree frontier for every selected-chain block back to genesis,
        // so the same metadata-only walk that finds a birthday AFTER the checkpoint
        // can find one BEFORE it — starting from genesis: thousands of 2000-block
        // metadata pages instead of millions of blocks of tree work. A pruned node
        // cannot serve that walk (pages fail below its pruning point) and falls
        // through to the full scan exactly as before.
        let older_than_checkpoint = birthday < cp.daa_score;
        // The walk reads block HEADERS (metadata only, never the scan archive), and a
        // node — even an archival one that went archival after it had already pruned —
        // holds headers only back to its pruning point. Walking from genesis therefore
        // failed on the first page ("cannot find header"). Start from the pruning point
        // instead: every birthday between it and the finality checkpoint (~1.5 days)
        // fast-syncs; an older one falls through to the full scan below.
        let walked = if older_than_checkpoint {
            // Headers survive only back to the pruning point, so try from there first — a
            // birthday below it fails on the first page, cheaply. Then from genesis: the
            // archive chain index enumerates from genesis on a complete-history node, and a
            // node with the archive-record metadata fallback can place the birthday below
            // the pruning point too (an older node errors on the first page → full scan).
            // ONE call first: the node binary-searches its chain index for the last block
            // strictly below the birthday and serves the nearest retained frontier at-or-before
            // it. A node without the locator answers with the finality point instead, which
            // `frontier_below_daa` rejects, and the walks below take over.
            let mut w = self.frontier_below_daa(birthday).await;
            if w.is_none() {
                let pp = self.request_client().await?.get_block_dag_info().await.ok().map(|i| i.pruning_point_hash);
                if let Some(pp) = pp {
                    w = self.birthday_start(pp, birthday, WALK_PAGES_HEADERS).await;
                }
            }
            if w.is_none() {
                // Bounded: a page costs ~0.3 s and the import/open request blocks for the
                // whole walk, so past this budget a full scan (which runs in the background
                // and survives restarts) is the better experience than a hung "Opening".
                w = self.birthday_start(guard, birthday, WALK_PAGES_ARCHIVE).await;
            }
            w
        } else {
            self.birthday_start(cp.block_hash, birthday, WALK_PAGES_HEADERS).await
        };
        if older_than_checkpoint && walked.is_none() {
            log::info!(
                "wallet birthday {birthday} precedes fast-sync checkpoint (daa {}) and this node cannot walk the chain back to it; full scan required",
                cp.daa_score
            );
            return None;
        }
        // Default start = the finality checkpoint. But when the wallet's birthday is
        // meaningfully later than the checkpoint, don't replay the whole finality window
        // (tens of thousands of blocks of sequential Sinsemilla tree-building — the "super
        // slow even though I set a birthday" report). The node retains a per-block tree
        // frontier for every selected-chain block, so walk the chain to the birthday block
        // (metadata only, no tree work) and start the tree from *that* block's frontier.
        // Sound because a birthday asserts the wallet holds no notes before it. Any failure
        // (RPC hiccup, tip reached early) falls back to the checkpoint start.
        let (start_hash, start_daa, start_size, start_leaf, start_ommers) = match walked {
            Some(s) => s,
            None => (cp.block_hash, cp.daa_score, cp.size, cp.leaf, cp.ommers),
        };
        if older_than_checkpoint {
            log::info!(
                "fast-sync from birthday block daa {start_daa} via the archival frontier walk (finality checkpoint daa {}) — no genesis scan",
                cp.daa_score
            );
        }
        if start_daa > cp.daa_score {
            log::info!(
                "fast-sync from birthday block daa {start_daa} (checkpoint daa {}) — skipped {} blocks of replay",
                cp.daa_score,
                start_daa - cp.daa_score
            );
        }
        let fs = FrontierState {
            size: start_size,
            leaf: (start_size > 0).then(|| start_leaf.as_bytes()),
            ommers: start_ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = key.db_from_frontier(&fs)?;
        // low = the start chain block; sync resumes strictly after it.
        // Progress is proxied by its DAA score so status reads "near tip".
        Some(WalletEntry::from_parts(key, recoverable, db, guard, start_hash, start_daa as usize, VecDeque::new(), 0))
    }

    /// Walk the selected chain forward from the finality checkpoint `from` until the
    /// first block whose DAA score reaches `birthday`, and return that block's retained
    /// shielded tree frontier `(hash, daa, size, leaf, ommers)`. Metadata-only: it reads
    /// only each block's hash + daa from `GetShieldedBlocks` (no tree work), so skipping
    /// a large finality window is cheap. Returns `None` on any RPC error, a reorg during
    /// the walk, or if the tip is reached before `birthday` — the caller then starts from
    /// the checkpoint as before.
    /// The tree frontier to start scanning from for `base` (the last chain block strictly
    /// below the birthday). A retained block answers with its own frontier. Below the pruning
    /// point only checkpointed blocks keep one, and the node answers a bare request with the
    /// nearest checkpoint AT OR AFTER the block — which could sit past the birthday and skip
    /// its notes — so that answer is accepted only if it is `base` itself. Otherwise ask again
    /// from two walk pages earlier: the node searches at most 2,100 blocks forward from there,
    /// so its answer is at or before `base`. The wallet scans a few thousand extra blocks
    /// instead of the whole chain.
    async fn frontier_at_or_before(&self, base: RpcHash, two_back: Option<RpcHash>) -> Option<(RpcHash, u64, u64, RpcHash, Vec<RpcHash>)> {
        if let Ok(ts) = self.request_client().await?.get_shielded_tree_state(Some(base)).await {
            if ts.block_hash == base {
                return Some((ts.block_hash, ts.daa_score, ts.size, ts.leaf, ts.ommers));
            }
        }
        let earlier = two_back?;
        let ts = self.request_client().await?.get_shielded_tree_state(Some(earlier)).await.ok()?;
        log::info!("birthday below the node's retained headers: starting from frontier checkpoint at daa {} (block {})", ts.daa_score, ts.block_hash);
        Some((ts.block_hash, ts.daa_score, ts.size, ts.leaf, ts.ommers))
    }

    /// Place `birthday` with the node's DAA locator: one `GetShieldedTreeState` call carrying
    /// `below_daa_score` returns the nearest retained frontier at-or-before the last chain
    /// block strictly below the birthday (the node binary-searches its chain index). A node
    /// that predates the field ignores it and answers with its finality point — which, in the
    /// only branch that calls this, lies at-or-past the birthday — so the `< birthday` check
    /// tells the two apart and never lets an overshooting frontier skip the birthday's notes.
    async fn frontier_below_daa(&self, birthday: u64) -> Option<(RpcHash, u64, u64, RpcHash, Vec<RpcHash>)> {
        let req = kaspa_rpc_core::GetShieldedTreeStateRequest { block_hash: None, below_daa_score: Some(birthday) };
        let ts = tokio::time::timeout(std::time::Duration::from_secs(30), self.request_client().await?.get_shielded_tree_state_call(None, req))
            .await
            .ok()?
            .ok()?;
        if ts.daa_score >= birthday {
            return None;
        }
        log::info!("node placed birthday {birthday} at frontier daa {} (block {}) in one call", ts.daa_score, ts.block_hash);
        Some((ts.block_hash, ts.daa_score, ts.size, ts.leaf, ts.ommers))
    }

    async fn birthday_start(&self, from: RpcHash, birthday: u64, max_pages: u32) -> Option<(RpcHash, u64, u64, RpcHash, Vec<RpcHash>)> {
        const WALK_PAGE: u64 = 2000; // RPC MAX_LIMIT — few round-trips across the window
        let mut cursor = from;
        // The last selected-chain block seen with daa < birthday. The tree starts from
        // ITS frontier so that scanning resumes at (and trial-decrypts) the birthday block
        // itself — a note received *in* the birthday block must not be skipped.
        let mut base_below: Option<RpcHash> = None;
        // First block of the previous page and of the one before it. Below the pruning point
        // the node serves the nearest frontier checkpoint AT OR AFTER the block it is asked
        // for, so to get one at-or-before `base` we ask from two full pages back (≥3,999
        // blocks earlier; the node searches at most 2,100 forward). See frontier_at_or_before.
        let mut one_back: Option<RpcHash> = None;
        let mut two_back: Option<RpcHash> = None;
        // Bound the walk: `max_pages` × a 2000-block page.
        for pages in 0..max_pages {
            let page = match self.request_client().await?.get_shielded_block_metadata(cursor, WALK_PAGE).await {
                Ok(p) => p,
                Err(e) => {
                    log::info!("birthday walk stopped after {pages} page(s) at cursor {cursor}: rpc error: {e}");
                    return None;
                }
            };
            if page.reorged {
                log::info!("birthday walk stopped after {pages} page(s) at cursor {cursor}: node reports the cursor reorged off the selected chain");
                return None;
            }
            let Some(last) = page.blocks.last() else {
                log::info!("birthday walk stopped after {pages} page(s) at cursor {cursor}: node returned an empty page");
                return None;
            };
            if last.daa_score >= birthday {
                // Birthday reached within this page. Advance `base_below` to the last block
                // still strictly below it, then start the tree from that block's frontier.
                for b in &page.blocks {
                    if b.daa_score >= birthday {
                        break;
                    }
                    base_below = Some(b.hash);
                }
                // No block below birthday anywhere (birthday <= first block past the
                // checkpoint) → nothing to skip; let the caller start from the checkpoint.
                let base = base_below?;
                return self.frontier_at_or_before(base, two_back).await;
            }
            base_below = Some(last.hash);
            two_back = one_back;
            one_back = page.blocks.first().map(|b| b.hash);
            cursor = last.hash;
            // Short page → we walked all the way to the tip without reaching the birthday,
            // which is exactly what a wallet born *now* looks like (its birthday is the
            // current tip). Start it at the tip: it cannot hold a note older than itself.
            // Falling back to the checkpoint here was a bug with a very visible symptom —
            // a freshly created wallet opened at "syncing 87%" and ground through ~44K
            // blocks of history it could not possibly appear in.
            if (page.blocks.len() as u64) < WALK_PAGE {
                let base = base_below?;
                return self.frontier_at_or_before(base, two_back).await;
            }
        }
        None
    }

    /// Full-history wallet entry: the tree is anchored as far back as the node can
    /// serve — **genesis** on an archival node, the pruning-point frontier
    /// otherwise — and every later chain block is scanned. Used when the wallet may
    /// hold funds older than the fast-sync checkpoint (birthday 0 / early birthday).
    ///
    /// Anchoring at the pruning point unconditionally was the 2026-07-28 "20K ZKAS
    /// vanished after I rescanned" bug. `--archival` stops a node DELETING blocks;
    /// it does not hold `pruning_point_hash` at genesis, so on a two-day-old chain
    /// the pruning point had already advanced to DAA 43,248 and a rescan silently
    /// dropped every note minted below it — 18,354 ZKAS in that report. An archival
    /// node serves the genesis tree state (an empty frontier) and the full block
    /// stream from genesis, so the correct anchor is genesis whenever it is offered.
    async fn full_scan_entry(&self, key: WalletKey, recoverable: bool, guard: RpcHash, birthday: u64) -> Option<WalletEntry> {
        // Prefer genesis. A node that has pruned answers for a block it no longer
        // holds with an error or a different hash; both fall through to the
        // pruning point, which is the most history that node can honestly offer.
        let genesis_ts = match self.request_client().await?.get_shielded_tree_state(Some(guard)).await {
            Ok(ts) if ts.block_hash == guard => Some(ts),
            _ => None,
        };
        let (start, ts) = match genesis_ts {
            Some(ts) => {
                log::info!("full scan anchored at GENESIS — this node serves the complete shielded history");
                (guard, ts)
            }
            None => {
                let start = self.request_client().await?.get_block_dag_info().await.ok()?.pruning_point_hash;
                let ts = self.request_client().await?.get_shielded_tree_state(Some(start)).await.ok()?;
                if ts.block_hash != start {
                    log::error!("node ignored the explicit tree-state checkpoint (update the node)");
                    return None;
                }
                log::warn!(
                    "full scan anchored at the PRUNING POINT (daa {}, tree position {}) — this node cannot serve \
                     genesis, so notes minted below that point are invisible to this wallet",
                    ts.daa_score,
                    ts.size
                );
                (start, ts)
            }
        };
        // Refuse only a scan that cannot succeed: the node holds PARTIAL history (it is
        // pruned and never backfilled), so notes below its history floor are invisible no
        // matter how long the scan runs. A complete-history node's genesis scan is slow on
        // a phone but finishes, and with checkpoints surviving restarts it is the honest
        // path for a wallet older than the node's fast-sync window — never refuse that.
        if let Some(max) = self.resources.max_full_scan_blocks {
            let tip = self.node_tip.lock().await.0;
            let span = tip.saturating_sub(ts.daa_score);
            if span > max && !ts.history_complete {
                let msg = format!(
                    "This node holds only partial shielded history (from block {}), so a wallet born at block {birthday} cannot be synced from it — its older notes are not on this node. Wait for your node to finish filling in shielded history (its log says \"shielded history: VERIFIED\"), or connect to a node with complete history.",
                    ts.history_from_daa_score
                );
                log::error!("{msg}");
                let db = key.empty_db()?;
                let mut e = WalletEntry::from_parts(key, recoverable, db, guard, start, ts.daa_score as usize, VecDeque::new(), 0);
                e.error = Some(msg);
                return Some(e);
            }
        }
        let fs = FrontierState {
            size: ts.size,
            leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
            ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = key.db_from_frontier(&fs)?;
        let mut e = WalletEntry::from_parts(key, recoverable, db, guard, start, ts.daa_score as usize, VecDeque::new(), 0);
        // The wallet claims history from before the pruning point (birthday below the
        // frontier's DAA, or 0 = "any height"), but the node cannot serve those blocks:
        // any note minted below this frontier is INVISIBLE to this view. Record it so
        // status can say so — a partial balance shown as the whole truth is how the
        // 2026-07-19 "23K ZKAS missing" report happened.
        if ts.size > 0 && birthday < ts.daa_score {
            e.blind_below = ts.size;
            e.blind_from_daa = ts.daa_score;
            // Say WHY in the node's own terms: a node whose history is not complete is
            // either still filling it in from peers (retry later, and the view can be
            // rebuilt) or was started with --shielded-history=off; a complete node that
            // still could not serve genesis is an older build.
            let why = if ts.history_complete {
                "the node reports complete history but did not serve genesis (older node build?)".to_string()
            } else {
                format!(
                    "the node's shielded history starts at daa {} and is NOT complete — it is still filling it in from \
                     peers (its log shows \"shielded history: … % … left\") or runs with --shielded-history=off",
                    ts.history_from_daa_score
                )
            };
            log::warn!(
                "wallet rebuilt BLIND below tree position {} (birthday {birthday} predates pruning-point daa {}): \
                 notes minted before the pruning point cannot be recovered through this node; {why}",
                ts.size,
                ts.daa_score
            );
        }
        Some(e)
    }

    /// Mark a token active so the sync loop keeps it current (idle wallets are parked).
    async fn touch(&self, token: &str) {
        self.last_touch.lock().await.insert(token.to_string(), std::time::Instant::now());
    }

    /// The wallet if it is already loaded in memory — never loads. For the request path,
    /// which must not block on a load.
    async fn cached_wallet(&self, token: &str) -> Option<Wallet> {
        self.wallets.lock().await.get(token).cloned()
    }

    /// Ensure a known-but-unloaded wallet gets loaded, in the background, exactly once.
    /// The request path calls this and returns "loading…" immediately; when the load
    /// finishes the wallet is in the map and the next poll answers from it.
    fn spawn_load(self: &Arc<Self>, token: &str) {
        let state = self.clone();
        let token = token.to_string();
        tokio::spawn(async move {
            // `get_wallet` dedupes via the load gate + cache re-check, so racing spawns
            // for the same token collapse to one real load.
            //
            // A failure is LOGGED. `get_wallet` returns `None` through `?` on a dozen
            // different paths (unreadable file, undecryptable seed, node RPC unavailable
            // while verifying the checkpoint cursor), and this used to discard that with
            // `let _ =`. The wallet then stayed uncached, every poll answered "loading",
            // and the log said nothing at all — leaving "it just says Opening forever"
            // with no thread to pull. One line here is the difference between a diagnosis
            // and a guess.
            if state.get_wallet(&token).await.is_none() {
                log::warn!("wallet {token}: load did not complete; it stays 'opening' until a later request succeeds");
            }
        });
    }

    /// Fetch a loaded wallet for a token, loading it from disk on first use.
    /// Record that `token` is registered with `key`'s viewing key, so later
    /// registrations of the same wallet on other devices can adopt its checkpoint.
    async fn index_fvk(&self, token: &str, key: &WalletKey) {
        if let Some(f) = key.fvk_bytes() {
            self.fvk_index.lock().await.entry(f).or_default().insert(token.to_string());
        }
    }

    /// Try the twin-adoption fast path for a registration of `fvk` under `token`:
    /// clone the freshest same-key checkpoint another token already scanned. Runs
    /// the donor verification (argon2 decrypts included) off the async workers.
    async fn adopt_twin(&self, token: &str, fvk: &[u8; 96], birthday: u64, want_history: bool) -> Option<(String, u64)> {
        // The index is built in the background at daemon startup. A second device
        // commonly registers while that scan is still running; do not silently miss
        // the reuse path just because the asynchronous warm-up has not finished.
        // Build a one-shot fallback index off the async runtime and merge it back.
        let mut candidates: Vec<String> =
            self.fvk_index.lock().await.get(fvk).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        if candidates.is_empty() {
            let (dir, secret) = (self.wallet_dir.clone(), self.wallet_secret.clone());
            if let Ok(Ok(map)) = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || build_fvk_index(&dir, secret.as_deref())),
            )
            .await
            {
                if let Some(found) = map.get(fvk) {
                    candidates = found.iter().filter(|t| t.as_str() != token).cloned().collect();
                    let mut index = self.fvk_index.lock().await;
                    index.entry(*fvk).or_default().extend(found.iter().cloned());
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }
        // Flush RAM-resident candidates to disk first: the sync loop only rewrites a
        // live wallet's checkpoint every CHECKPOINT_EVERY blocks, so the file the
        // clone copies could otherwise lag the donor's actual state by ~17 minutes
        // of chain — the whole point here is that the second device starts where
        // the first one IS, not where it was at the last periodic save.
        {
            let map = self.wallets.lock().await;
            let resident: Vec<(String, Wallet)> =
                candidates.iter().filter_map(|t| map.get(t).map(|w| (t.clone(), w.clone()))).collect();
            drop(map);
            for (t, w) in resident {
                let mut e = w.lock().await;
                if e.error.is_none()
                    && save_checkpoint(
                        &self.wallet_dir,
                        &t,
                        &e.genesis,
                        &e.low,
                        e.scanned as u64,
                        &e.db,
                        &e.boundaries,
                        e.sink_blue,
                        e.blind_below,
                    )
                    .is_ok()
                {
                    e.saved_scanned = e.scanned;
            e.last_checkpoint_at = std::time::Instant::now();
                    e.force_checkpoint = false;
                }
            }
        }
        let (dir, genesis, secret) = (self.wallet_dir.clone(), self.genesis, self.wallet_secret.clone());
        let (token, fvk) = (token.to_string(), *fvk);
        tokio::task::spawn_blocking(move || {
            adopt_twin_checkpoint(&dir, &token, &fvk, birthday, want_history, &genesis, secret.as_deref(), &candidates)
        })
        .await
        .ok()?
    }

    /// Highest `scanned` block height across same-viewing-key twins of `token`, if any.
    ///
    /// A read-only peek used to decide whether an already-checkpointed wallet should
    /// jump to a sibling that is further along (see the load path). Twins share the
    /// viewing key, so `load_checkpoint` parses their file with THIS wallet's key and
    /// hands back the donor's `scanned` (field .2) without mutating anything. Resident
    /// wallets are read from memory (freshest); the rest are peeked from disk. Never
    /// takes a lock across the node and never writes.
    async fn best_twin_scanned(&self, token: &str, fvk: &[u8; 96]) -> Option<u64> {
        let candidates: Vec<String> = {
            let idx = self.fvk_index.lock().await;
            idx.get(fvk)?.iter().filter(|t| t.as_str() != token).cloned().collect()
        };
        if candidates.is_empty() {
            return None;
        }
        // Prefer the live figure for a resident twin — its on-disk checkpoint can lag its
        // actual progress by up to CHECKPOINT_EVERY blocks.
        let mut best = 0u64;
        {
            let map = self.wallets.lock().await;
            for t in &candidates {
                if let Some(w) = map.get(t) {
                    if let Ok(e) = w.try_lock() {
                        best = best.max(e.scanned as u64);
                    }
                }
            }
        }
        let (dir, genesis) = (self.wallet_dir.clone(), self.genesis);
        let (fvk, candidates) = (*fvk, candidates);
        let disk = tokio::task::spawn_blocking(move || {
            let mut m = 0u64;
            for t in &candidates {
                if let Some(r) = load_checkpoint(&dir, t, WalletKey::Fvk(fvk), &genesis, None) {
                    m = m.max(r.2 as u64);
                }
            }
            m
        })
        .await
        .unwrap_or(0);
        Some(best.max(disk)).filter(|&v| v > 0)
    }

    /// The node's tree frontier at the cursor of the checkpoint file currently on disk for
    /// `token` — what `load_checkpoint` binds a restored tree to. `Ok(None)` when there is
    /// no usable checkpoint file; `Err` when the node could not answer (timeout / RPC
    /// error), which callers treat as "try again later", never as permission to trust the
    /// file unverified.
    async fn frontier_at_checkpoint_cursor(
        &self,
        token: &str,
        genesis: &RpcHash,
    ) -> Result<Option<kaspa_shielded_core::tree::FrontierState>, String> {
        let Some(cursor) = checkpoint_cursor(&self.wallet_dir, token, genesis) else { return Ok(None) };
        let c = self.request_client().await.ok_or_else(|| "no node connection".to_string())?;
        let ts = tokio::time::timeout(std::time::Duration::from_secs(8), c.get_shielded_tree_state(Some(cursor)))
            .await
            .map_err(|_| format!("cursor verification timed out ({cursor})"))?
            .map_err(|e| e.to_string())?;
        // The node answers with the nearest checkpointed block when it holds no frontier
        // for the cursor itself (see `get_wallet`). That frontier is returned AS IS: the
        // adopted copy then fails `load_checkpoint`'s size binding and the caller discards
        // it and scans clean. Returning `Err` here instead left the donor's copy in place
        // as this token's own `.scan`, and the next load quarantined it, adopted the same
        // donor again, and so on — a fresh `.scan.stale-*` copy per load, never a scan.
        Ok(Some(kaspa_shielded_core::tree::FrontierState {
            size: ts.size,
            leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
            ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
        }))
    }

    /// Bring back the furthest-scanned `.scan.stale-<ts>` copy of `token`'s checkpoint when
    /// the node NOW serves its cursor and it is meaningfully ahead of what this token resumes
    /// from. A restored copy is renamed `.restored` so it is used at most once.
    ///
    /// Quarantine copies were write-only: after a false quarantine (a node that had not
    /// reached the cursor — gated in `get_wallet` since) the rebuild's partial `.scan` was
    /// all any later load resumed from, so a user who reverted to the original node kept
    /// scanning from genesis with the synced checkpoint sitting next to it. Nothing is
    /// trusted: the node must serve the frontier at exactly that cursor, the copy goes
    /// through `parse_scan_bytes`' size/root binding, and its notes must derive their
    /// nullifiers under THIS key (a blob carries no key material, and the token may have
    /// held another key when it was quarantined) — all BEFORE it replaces the live file.
    /// A deliberate `/rescan` retires these copies first (`retire_quarantine_copies`), so
    /// it is never undone here. `.divergent-*` copies failed a real size/root check and
    /// `.bak` is also what `/rescan` writes; neither is a candidate.
    #[allow(clippy::type_complexity)]
    async fn restore_quarantined(
        &self,
        token: &str,
        key: WalletKey,
        genesis: &RpcHash,
        mine_scanned: u64,
    ) -> Option<(WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64, u64)> {
        let prefix = format!("{token}.scan.stale-");
        let (_, path, cursor, scanned) = std::fs::read_dir(&self.wallet_dir)
            .ok()?
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let stamp = name.strip_prefix(&prefix)?.parse::<u64>().ok()?;
                let path = format!("{}/{name}", self.wallet_dir);
                let (cursor, scanned) = checkpoint_header(&path, genesis)?;
                Some((stamp, path, cursor, scanned))
            })
            // The FURTHEST-scanned copy, not the newest: a false quarantine repeats on every
            // reload while the node stays behind, each time taking the partial rebuild (seen
            // live: five copies at 6 h intervals, shrinking) — the original synced checkpoint
            // is the OLDEST of them. Stamp only breaks ties.
            .max_by_key(|(stamp, _, _, scanned)| (*scanned, *stamp))?;
        if scanned <= mine_scanned + TWIN_ADOPT_LEAD {
            return None;
        }
        let c = self.request_client().await?;
        let ts = match tokio::time::timeout(std::time::Duration::from_secs(8), c.get_shielded_tree_state(Some(cursor))).await {
            Ok(Ok(ts)) => ts,
            Ok(Err(e)) => {
                log::info!("wallet {token}: quarantined checkpoint {path} (DAA {scanned}) is not resumable on this node ({e})");
                return None;
            }
            Err(_) => return None,
        };
        if ts.block_hash != cursor {
            log::info!("wallet {token}: node cannot serve the frontier at quarantined cursor {cursor} (served {}); not restoring", ts.block_hash);
            return None;
        }
        let fs = kaspa_shielded_core::tree::FrontierState {
            size: ts.size,
            leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
            ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
        };
        let buf = std::fs::read(&path).ok()?;
        let (saved_genesis, rest) = parse_scan_bytes(&buf, key, Some(&fs))?;
        if saved_genesis != *genesis {
            return None;
        }
        // `None` = the copy holds no notes at all (a synced but still-empty wallet): nothing
        // to bind, and nothing another key could smuggle in — restore it. Only a copy whose
        // notes do NOT derive under this key is refused.
        if rest.0.notes_bound_to_key(8) == Some(false) {
            log::warn!("wallet {token}: quarantined checkpoint {path} holds notes not derived under this wallet's key; not restoring");
            return None;
        }
        // Keep the partial rebuild it replaces (its pending-spend bookkeeping, if any).
        let live = scan_path(&self.wallet_dir, token);
        // Copy first, swap last: a failed copy must not leave the token with no `.scan`.
        let tmp = format!("{live}.tmp");
        std::fs::copy(&path, &tmp).ok()?;
        let _ = std::fs::rename(&live, format!("{live}.replaced-{}", now_unix()));
        std::fs::rename(&tmp, &live).ok()?;
        // Consumed: a copy is restored at most once. If the sync loop then finds this cursor
        // unusable on a node that has reached it (retired to `.bak`), the next reload must
        // not bring the same copy back and start that cycle over; a later false quarantine
        // takes a fresh copy of the live file anyway, so nothing is lost by retiring this one.
        let _ = std::fs::rename(&path, format!("{path}.restored"));
        log::warn!(
            "wallet {token}: restored quarantined checkpoint {path} (cursor {cursor}, DAA {scanned}) — the node serves its cursor again; the rebuild had reached DAA {mine_scanned}"
        );
        Some(rest)
    }

    async fn get_wallet(self: &Arc<Self>, token: &str) -> Option<Wallet> {
        // Mark the wallet active so the sync loop keeps it current; idle wallets are
        // parked (see `sync_loop`).
        self.last_touch.lock().await.insert(token.to_string(), std::time::Instant::now());
        {
            let map = self.wallets.lock().await;
            if let Some(w) = map.get(token) {
                return Some(w.clone());
            }
        }
        // Cache miss → an expensive load. Gate concurrent loads so a reconnect storm
        // can't pin every worker with tree rebuilds. Re-check the cache after acquiring
        // the permit: while we waited, another task may have loaded this same wallet.
        let _permit = self.load_gate.acquire().await.ok()?;
        {
            let map = self.wallets.lock().await;
            if let Some(w) = map.get(token) {
                return Some(w.clone());
            }
        }
        let (key, birthday, recoverable_history) = load_wallet_meta(&self.wallet_dir, token, self.wallet_secret.as_deref())?;
        let genesis = self.genesis;
        // Resume from a persisted checkpoint when one is present and version/genesis
        // valid; otherwise fast-sync (birthday-gated: a fast-synced wallet is blind
        // to notes older than its base) or the pruning-point full scan.
        // Ask the node for the tree at this checkpoint's cursor. It is the same tree the
        // wallet would rebuild from its own leaf stream, so having it turns a ~60s
        // Sinsemilla replay into a frontier copy. Best-effort: if the node can't answer
        // (pruned cursor, RPC hiccup), we simply restore the old way.
        let mut abandoned_checkpoint = false;
        let tip = match checkpoint_header(&scan_path(&self.wallet_dir, token), &genesis) {
            Some((cursor, cursor_daa)) => {
                // Bounded, like fast_sync_entry: this runs FIRST for a returning wallet and
                // holds the single load permit. Un-timed-out, a half-open node connection
                // (e.g. Orbot up but the node unreachable) hangs the load forever with no
                // error -- the wallet sits on "opening" and blocks every other load.
                let c = self.request_client().await?;
                let verified = match tokio::time::timeout(std::time::Duration::from_secs(8), c.get_shielded_tree_state(Some(cursor))).await
                {
                    Ok(r) => r,
                    Err(_) => {
                        log::warn!("checkpoint cursor verification timed out ({cursor}); keeping checkpoint and retrying");
                        return None;
                    }
                };
                match verified {
                    // The node serves the NEAREST checkpointed block at-or-after a cursor
                    // it holds no frontier for (below its pruning point, or still
                    // backfilling). Binding this wallet's tree to another block's frontier
                    // can only fail the size/root check below and mislabel a good
                    // checkpoint "divergent" — so a foreign answer is "not resumable on
                    // this node yet", never a verdict on the checkpoint.
                    //
                    // Three cases, told apart by what the node says about itself:
                    // - not synced / tip below the cursor: it may still receive it — retry;
                    // - synced, and it claims history at the cursor (complete, or its floor
                    //   is at/below the cursor) yet cannot serve that exact block: the
                    //   cursor is not on its chain — the same verdict as an absent header;
                    // - synced, but its history floor is ABOVE the cursor (a pruned node,
                    //   or an archival one still filling): resuming here would silently
                    //   drop every note between the cursor and the floor, so the wallet is
                    //   parked with that message and the checkpoint stays on disk.
                    Ok(ts) if ts.block_hash != cursor => {
                        if let Err(why) = node_reaches(&c, cursor_daa, std::time::Duration::from_secs(8)).await {
                            log::warn!(
                                "node cannot serve the frontier at the checkpoint cursor {cursor} (served {} instead) and has not reached it ({why}); keeping checkpoint and retrying",
                                ts.block_hash
                            );
                            return None;
                        }
                        if ts.history_complete || ts.history_from_daa_score <= cursor_daa {
                            let scan = scan_path(&self.wallet_dir, token);
                            let quarantine = format!("{scan}.stale-{}", now_unix());
                            if std::fs::copy(&scan, &quarantine).is_ok() {
                                let _ = std::fs::remove_file(&scan);
                                log::warn!(
                                    "checkpoint cursor {cursor} (DAA {cursor_daa}) is not on the chain of a synced node that holds history there (served {} instead); quarantined as {quarantine} and rebuilding",
                                    ts.block_hash
                                );
                                abandoned_checkpoint = true;
                                None
                            } else {
                                log::warn!("cannot quarantine stale checkpoint (foreign block served); keeping checkpoint and retrying");
                                return None;
                            }
                        } else {
                            let msg = format!(
                                "This node holds shielded history only from block {}, but this wallet was last synced at block {cursor_daa}. Resuming here would lose the notes in between, so the wallet is paused with its progress kept. Wait for the node to finish filling in shielded history (its log says \"shielded history: VERIFIED\"), or connect to a node with complete history.",
                                ts.history_from_daa_score
                            );
                            // Not loaded, only logged: a resident placeholder entry would be
                            // advanced by the sync loop like any other wallet (`sync_chunk`
                            // clears `error` on its first served page) and its checkpoint
                            // write would then replace the kept `.scan` with an empty
                            // wallet at a later cursor. The wallet stays "opening" until
                            // the node's floor passes the cursor or walletd is repointed.
                            log::warn!("wallet {token}: {msg}");
                            return None;
                        }
                    }
                    Ok(ts) => Some(kaspa_shielded_core::tree::FrontierState {
                        size: ts.size,
                        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
                        ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
                    }),
                    // Never load an unverified checkpoint. A transient node failure is
                    // retried on the next request; treating it as permission to trust the
                    // local file is how stale twin state previously propagated.
                    Err(e) => {
                        let detail = e.to_string();
                        // A cursor whose header is absent from the selected chain cannot
                        // become valid by retrying: it is a checkpoint from a discarded
                        // chain (or an old/pruned store). Keep an immutable forensic copy,
                        // retire only the active cursor, and rebuild honestly from the
                        // wallet birthday. Other errors may be transient RPC/node
                        // failures, so preserve the checkpoint and retry as before.
                        //
                        // "Absent" is only a verdict from a node that has REACHED the cursor
                        // (synced, tip DAA at or past it). A node still syncing answers the
                        // same text for every block it has not received yet, and the warm
                        // sweep loads every wallet on disk at startup — so a walletd
                        // restarted against a behind node quarantined every synced
                        // checkpoint with no user action (desktop "Chain source" switch).
                        let absent = detail.to_ascii_lowercase().contains("cannot find header")
                            || detail.to_ascii_lowercase().contains("header not found");
                        let permanent = absent
                            && match node_reaches(&c, cursor_daa, std::time::Duration::from_secs(8)).await {
                                Ok(()) => true,
                                Err(why) => {
                                    log::warn!(
                                        "checkpoint cursor {cursor} is absent on the node ({detail}) but the node has not reached it ({why}); keeping checkpoint and retrying"
                                    );
                                    return None;
                                }
                            };
                        if permanent {
                            let scan = scan_path(&self.wallet_dir, token);
                            let quarantine = format!("{scan}.stale-{}", now_unix());
                            if std::fs::copy(&scan, &quarantine).is_ok() {
                                let _ = std::fs::remove_file(&scan);
                                log::warn!(
                                    "checkpoint cursor {cursor} (DAA {cursor_daa}) is not on the selected chain of a synced node that has passed it ({detail}); quarantined as {quarantine} and rebuilding"
                                );
                                abandoned_checkpoint = true;
                                None
                            } else {
                                log::warn!("cannot quarantine stale checkpoint ({detail}); keeping checkpoint and retrying");
                                return None;
                            }
                        } else {
                            log::warn!(
                                "cannot verify checkpoint cursor against selected chain ({detail}); keeping checkpoint and retrying"
                            );
                            return None;
                        }
                    }
                }
            }
            None => None,
        };
        let restored =
            (!abandoned_checkpoint).then(|| load_checkpoint(&self.wallet_dir, token, key, &genesis, tip.as_ref())).flatten();
        // Preserve a rejected checkpoint for forensic recovery/grafting. Never let
        // the subsequent clean scan overwrite the only copy of older owned notes.
        if restored.is_none() && tip.is_some() && checkpoint_cursor(&self.wallet_dir, token, &genesis).is_some() {
            let scan = scan_path(&self.wallet_dir, token);
            let quarantine = format!("{scan}.divergent-{}", now_unix());
            if std::fs::copy(&scan, &quarantine).is_ok() {
                log::warn!("preserved rejected checkpoint as {quarantine}");
            }
        }
        // A quarantined copy of this token's own checkpoint that the node serves again
        // beats both the partial rebuild and a twin (same key, further along, verified).
        let restored = {
            let mine = restored.as_ref().map(|r| r.2 as u64).unwrap_or(0);
            match self.restore_quarantined(token, key, &genesis, mine).await {
                Some(r) => Some(r),
                None => restored,
            }
        };
        // No usable checkpoint — but this wallet may have a TWIN: another token
        // registered against the same viewing key that has already scanned the chain.
        //
        // `adopt_twin` was only ever reached from import / watch-only registration, so a
        // token registered BEFORE its twin finished scanning, or whose own checkpoint was
        // later quarantined as stale or divergent, fell through to a full rescan and never
        // reconsidered it. Measured on the public daemon: **51 of 159** checkpoint-less
        // wallets had a checkpointed twin sitting on the same disk, each facing a ~330 s
        // scan (78 % of it Sinsemilla tree work its sibling had already done) to reproduce
        // state that was already there.
        //
        // Nothing is taken on trust: `adopt_twin_checkpoint` matches the donor's FVK and
        // refuses a donor whose `blind_below` hides notes this birthday wants, and the
        // adopted file then goes through the SAME `load_checkpoint` verification as any
        // other — including the cursor-on-selected-chain test above. If any of that
        // declines, this falls through to the honest scan exactly as before.
        // Adopt a twin even when THIS token already has a (partial) checkpoint, as long
        // as a sibling on the same viewing key has scanned meaningfully further. The old
        // gate was `restored.is_none()`, so two devices that entered the same seed at the
        // same time BOTH ran a full genesis scan: whoever registered first had no
        // checkpoint to donate yet, and once the slower device wrote its own partial
        // checkpoint it never reconsidered the twin — it ground out the whole ~40-minute
        // decrypt-bound scan while its sibling sat synced on the same disk. Now the slower
        // device jumps to the faster one. Nothing is trusted: the adopted file goes
        // through the same `load_checkpoint` verification (cursor-on-selected-chain
        // included), so a divergent donor still declines to the honest scan.
        let mine_scanned = restored.as_ref().map(|r| r.2 as u64).unwrap_or(0);
        let prefer_twin = match (restored.is_some(), key.fvk_bytes()) {
            (true, Some(fvk)) => {
                // Only worth the argon2/decrypt of adoption if a twin is >TWIN_ADOPT_LEAD
                // blocks ahead — a small lead is cheaper to just scan than to clone.
                self.best_twin_scanned(token, &fvk)
                    .await
                    .is_some_and(|twin_scanned| twin_scanned > mine_scanned + TWIN_ADOPT_LEAD)
            }
            _ => false,
        };
        let restored = match restored {
            Some(r) if !prefer_twin => Some(r),
            _ => match key.fvk_bytes() {
                Some(fvk) => match self.adopt_twin(token, &fvk, birthday, recoverable_history).await {
                    Some((donor, keep_birthday)) => {
                        // The copied file carries the DONOR's cursor. Verify it against the
                        // node's frontier at THAT block — not `tip`, fetched above for this
                        // wallet's own, different cursor. Comparing the donor's tree against
                        // the wrong block's frontier made every adopted twin look "divergent"
                        // (its size can never match another block's) and sent BOTH wallets back
                        // to a birthday rescan on every load — the daily mass-rescan source, and
                        // the 20,087-iteration loop described below.
                        let twin_tip = match self.frontier_at_checkpoint_cursor(token, &genesis).await {
                            Ok(t) => t,
                            Err(e) => {
                                log::warn!("wallet {token}: cannot verify the adopted twin checkpoint ({e}); retrying later");
                                return None;
                            }
                        };
                        match load_checkpoint(&self.wallet_dir, token, key, &genesis, twin_tip.as_ref()) {
                            Some(restored) => {
                                log::info!(
                                    "wallet {token}: adopted checkpoint from twin token {donor} (birthday {keep_birthday}) instead of rescanning from {birthday}"
                                );
                                Some(restored)
                            }
                            None => {
                                // The donor's checkpoint is no better than the one just
                                // rejected — twins share a viewing key, so they share a
                                // cursor, and a cursor that has left the selected chain has
                                // left it for BOTH of them.
                                //
                                // `adopt_twin_checkpoint` cannot see that: it runs on a
                                // blocking thread and the test needs the node. So it copies
                                // the donor's file into place and only then is the copy
                                // rejected — leaving a known-bad checkpoint as THIS wallet's
                                // own. The next load rejects it, adopts the twin again, and
                                // so on: measured on the public daemon, one wallet did this
                                // 20,087 times over 30 hours and never once completed a scan.
                                // A wallet that cannot finish a scan cannot see the notes
                                // being paid to it, so money arrived on-chain and never
                                // appeared in the app.
                                //
                                // Discard the copy. Scanning from scratch is slow; looping
                                // forever is permanent.
                                let scan = scan_path(&self.wallet_dir, token);
                                if std::fs::remove_file(&scan).is_ok() {
                                    log::warn!(
                                        "wallet {token}: twin {donor}'s checkpoint was rejected too (same cursor); discarded it and scanning clean"
                                    );
                                }
                                None
                            }
                        }
                    }
                    None => None,
                },
                None => None,
            },
        };
        // A wallet that keeps history but whose checkpoint has notes and NO rows was
        // scanned with recording off — a twin clone from a history-off device, or a
        // checkpoint older than the flag. Every note receipt/mint records a row while
        // recording is on, so this state cannot arise otherwise. Rebuild from the
        // birthday now instead of showing an empty History tab forever; the file is
        // kept as .bak like any other retirement.
        let restored = match restored {
            Some((db, ..)) if recoverable_history && db.history().is_empty() && !db.notes().is_empty() => {
                let scan = scan_path(&self.wallet_dir, token);
                let _ = std::fs::rename(&scan, format!("{scan}.bak"));
                retire_quarantine_copies(&self.wallet_dir, token);
                log::info!(
                    "wallet {token}: keeps history but its checkpoint has {} notes and no history rows (scanned with recording off); rebuilding from birthday {birthday}",
                    db.notes().len()
                );
                None
            }
            other => other,
        };
        let entry = match restored {
            Some((db, low, scanned, boundaries, sink_blue, blind_below)) => {
                let mut e = WalletEntry::from_parts(key, recoverable_history, db, genesis, low, scanned, boundaries, sink_blue);
                e.blind_below = blind_below;
                e
            }
            None => match self.fast_sync_entry(key, recoverable_history, genesis, birthday).await {
                Some(e) => e,
                None => self.full_scan_entry(key, recoverable_history, genesis, birthday).await?,
            },
        };
        // Decode the leaf stream to curve points NOW, on a blocking thread, while we still
        // own the entry exclusively. `warm_leaves` was written for exactly this and then
        // never called, so the cost landed on the first *spend* instead — a big chunk of the
        // ~29s a send took. Doing it here costs the user nothing: the wallet is already
        // usable (balance, notes, receive) and this finishes long before anyone hits Send.
        let entry = tokio::task::spawn_blocking(move || {
            let t = std::time::Instant::now();
            entry.db.warm_leaves();
            log::info!("wallet leaf-stream decoded in {:.1?} (kept off the spend path)", t.elapsed());
            entry
        })
        .await
        .ok()?;
        let w = Arc::new(Mutex::new(entry));
        self.wallets.lock().await.insert(token.to_string(), w.clone());
        // NB: do NOT eagerly decode the leaf stream here. It is tempting — only a spend
        // needs curve points, so "warm them in the background" sounds free. It is not:
        // decoding is ~60s of curve arithmetic per wallet, and firing it for every wallet
        // that loads (a restart touches all of them) buries every tokio worker on a
        // 4-core box and starves the HTTP handler — the daemon stops answering entirely
        // (observed live: a 331-deep accept backlog, every wallet reading "node offline").
        // The decode stays lazy: it happens inside the spend path, which already runs on
        // a blocking thread, and is paid once by the one wallet that actually spends.
        Some(w)
    }
}

// ---------------------------------------------------------------------------
// Background sync: advance every loaded wallet a bounded chunk each pass.
// ---------------------------------------------------------------------------

/// Watch the node's **mempool** and tell every active wallet what is heading its way,
/// *before* any of it is mined. This is the whole "instant payment" path.
///
/// It is deliberately its OWN loop, not a step inside `sync_loop`. The sync loop walks
/// wallets one at a time and does real block work (page fetches, tree ingest, a throttle
/// between each), so a wallet's turn can come many seconds after the pass began — putting
/// the mempool check in there made an incoming payment take ~28s to show for no reason
/// other than queueing. Here the only per-wallet cost is trial decryption of a handful of
/// mempool bundles: microseconds, no RPC, no tree. So a payment appears within about a
/// second of the sender hitting Confirm, no matter how many wallets are mid-scan.
async fn mempool_loop(state: Arc<AppState>) {
    let mut last_seen = 0usize;
    loop {
        let active: HashSet<String> = {
            let now = std::time::Instant::now();
            state
                .last_touch
                .lock()
                .await
                .iter()
                .filter(|(_, t)| now.duration_since(**t) < std::time::Duration::from_secs(state.resources.active_sync_secs))
                .map(|(k, _)| k.clone())
                .collect()
        };
        // Only worth a fetch for a wallet that is idling at the tip. A wallet mid-scan
        // holds its lock for whole chunks (or a 20 s burst), so the `try_lock` below
        // skips it nearly every tick and the mempool — every entry, transaction bodies
        // included — was fetched and thrown away ~1.4 times a second for the length of
        // a restore, kept "active" by nothing more than the app's 1 s status poll. A
        // wallet with no snapshot yet has not finished a pass and counts as behind.
        let ready = {
            let snaps = state.snapshots.lock().await;
            active.iter().filter(|t| snaps.get(*t).is_some_and(|s| s.caught_up)).count()
        };
        if ready > 0 {
            // One decode of the mempool, shared by every wallet.
            let bundles: Vec<ShieldedBundle> =
                match tokio::time::timeout(SYNC_RPC_TIMEOUT, async {
                    match state.request_client().await {
                        Some(c) => c.get_mempool_entries(false, false).await,
                        None => Err(kaspa_rpc_core::RpcError::General("node unavailable".into())),
                    }
                })
                .await
                {
                    Ok(Ok(entries)) => entries
                        .iter()
                        .filter(|e| e.transaction.version == TX_VERSION_SHIELDED)
                        .filter_map(|e| ShieldedBundle::from_bytes(&e.transaction.payload).ok())
                        .collect(),
                    _ => Vec::new(), // node hiccup: no preview this tick, never a stall
                };
            // Log only on change — this loop runs sub-second. Without this line there is no
            // way to tell "the mempool preview is working and the tx simply isn't there yet"
            // apart from "the mempool preview is silently broken", which is exactly the hole
            // that let an incoming payment take minutes to show.
            if bundles.len() != last_seen {
                log::info!("mempool: {} shielded bundle(s) pending", bundles.len());
                last_seen = bundles.len();
            }
            let wallets: Vec<(String, Wallet)> = {
                state.wallets.lock().await.iter().filter(|(k, _)| active.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect()
            };
            for (token, w) in wallets {
                // try_lock, never lock: if the sync loop is mid-chunk on this wallet, skip it
                // and catch it next tick. Blocking here would re-couple us to the very queue
                // this loop exists to escape.
                let Ok(mut e) = w.try_lock() else { continue };
                e.scan_mempool(&bundles);
                let snap = snap_from_entry(state.address_of(&e.db), &e, e.chain_len);
                drop(e);
                state.snapshots.lock().await.insert(token, snap);
            }
        }
        // Sub-second whenever ANY active wallet is at the tip — a restore on one tenant
        // must not slow every other receiver's preview (the guarantee in the doc above).
        // With nothing ready there is nothing to fetch for, so only the snapshot check
        // above runs: ease off until a wallet arrives.
        tokio::time::sleep(if ready > 0 { MEMPOOL_POLL } else { MEMPOOL_POLL_BEHIND }).await;
    }
}

/// Keep custodial wallets under their note ceiling by merging their oldest notes,
/// one transaction at a time, whenever nothing else is proving.
///
/// This exists because Halo2 proving costs a flat ~2.4 core-seconds of CPU work **per
/// note spent** — total CPU is 91.7 s at 1 thread and 93.4 s at 4 for 38 spends, so the
/// work is fixed and only the cores dividing it change. The time to move value out of a
/// wallet is therefore set by how many notes it is made of, and nothing else.
/// A mining treasury that receives one coinbase note per block reaches tens of thousands
/// of notes, and a payout then needs thousands of spends: a measured 237-transaction,
/// ~2-hour payment on the live pool.
///
/// Merging does not make that total work smaller — it moves it. Each merge turns
/// [`max_spends_per_tx`] notes into one worth ~38x more, so a later payment spends ~38x
/// fewer notes; run continuously the cost is paid ~30 s at a time in the background and
/// the note count never runs away. `heal: true` (oldest-first) is deliberate: it also
/// lets the fast-sync base roll forward past the spent notes, shortening every later
/// witness rebuild.
async fn consolidate_loop(state: Arc<AppState>) {
    let Some(ceiling) = state.auto_consolidate else { return };
    log::info!(
        "auto-consolidate: ON — custodial wallets are kept under {ceiling} notes \
         (one merge of up to {} notes per {}s, only while nothing is proving)",
        max_spends_per_tx(),
        CONSOLIDATE_COOLDOWN.as_secs()
    );
    let mut last_quiet = (usize::MAX, 0usize, 0usize, 0usize);
    loop {
        // Never take cores from a payment somebody is waiting on.
        if proving_now() {
            tokio::time::sleep(CONSOLIDATE_COOLDOWN).await;
            continue;
        }
        let wallets: Vec<Wallet> = state.wallets.lock().await.values().cloned().collect();
        let loaded = wallets.len();
        let mut merged_any = false;
        // Why nothing happened is as important as when something does. Without this
        // an operator cannot distinguish "no wallet needs merging" from "merging is
        // silently never eligible", and the docs tell them to watch for merge lines
        // that would never appear.
        let (mut over_ceiling, mut skip_watch_only, mut skip_behind, mut skip_busy) = (0usize, 0usize, 0usize, 0usize);
        for w in wallets {
            if proving_now() {
                break;
            }
            // Cheap pre-check: try_lock so a wallet mid-scan is simply skipped this
            // pass rather than queueing the loop behind it.
            let (over, notes) = {
                let Ok(e) = w.try_lock() else {
                    skip_busy += 1;
                    continue;
                };
                let notes = e.db.notes().len();
                if notes <= ceiling {
                    continue;
                }
                over_ceiling += 1;
                // Watch-only wallets hold no seed here and cannot be merged by the
                // daemon at all; a wallet still catching up has no stable anchor.
                if e.key.seed().is_err() {
                    skip_watch_only += 1;
                    (false, notes)
                } else if !e.caught_up {
                    skip_behind += 1;
                    (false, notes)
                } else {
                    (true, notes)
                }
            };
            if !over {
                continue;
            }
            match consolidate_once(&state, &w, DEFAULT_FEE_SOMPI, true).await {
                Ok(r) => {
                    merged_any = true;
                    log::info!(
                        "auto-consolidate: merged {} notes into one ({} sompi), {} notes left (was {notes}, ceiling {ceiling}) — tx {}",
                        r.consolidated,
                        r.value_sompi,
                        r.notes_remaining,
                        r.txid
                    );
                }
                Err((code, body)) => {
                    // Expected and harmless when a wallet is briefly un-mergeable
                    // (still syncing the maturity window, fewer than 2 matured notes).
                    let reason = body.0.get("error").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    if code == StatusCode::CONFLICT {
                        log::debug!("auto-consolidate: skipping a wallet this pass: {reason}");
                    } else {
                        log::warn!("auto-consolidate: merge failed ({code}): {reason}");
                    }
                }
            }
            tokio::time::sleep(CONSOLIDATE_COOLDOWN).await;
        }
        if !merged_any {
            // Report a quiet pass only when the picture changes, so a healthy daemon
            // stays quiet but a stuck one says exactly which gate is holding it.
            let picture = (over_ceiling, skip_watch_only, skip_behind, skip_busy);
            if over_ceiling > 0 && picture != last_quiet {
                log::info!(
                    "auto-consolidate: nothing merged this pass — {over_ceiling} of {loaded} loaded wallet(s) are over the {ceiling}-note ceiling                      but none were eligible ({skip_watch_only} watch-only, {skip_behind} not caught up to the tip, {skip_busy} locked by sync)"
                );
                last_quiet = picture;
            }
            tokio::time::sleep(CONSOLIDATE_IDLE_POLL).await;
        } else {
            last_quiet = (usize::MAX, 0, 0, 0);
        }
    }
}

/// What advancing one wallet a chunk told the loop it must do afterwards.
enum SyncOutcome {
    /// Cursor is gone (pruned/unknown) for `REORG_STRIKES` passes: its checkpoint was
    /// retired to `.bak`; the loop must evict it so the next request reloads it clean.
    Retired(String),
    /// Still catching up (or taking reorg strikes): the loop should spin its fast path.
    Behind,
    /// Caught up to the tip.
    Idle,
}

/// Advance a single wallet by one chunk and do its post-chunk bookkeeping (witness
/// catch-up, reorg-strike handling, checkpoint, status snapshot). Factored out of
/// [`sync_loop`] so several wallets can run **concurrently** (see [`SYNC_CONCURRENCY`]);
/// the logic is identical to the old sequential body.
async fn sync_one_wallet(state: Arc<AppState>, token: String, w: Wallet, chain_len: u64) -> SyncOutcome {
    let mut e = w.lock().await;
    e.chain_len = chain_len;
    // Advance one chunk from `low` (also the cheap tip catch-up once already synced).
    let was_caught_up = e.caught_up;
    e.caught_up = false;
    // Published, not peeked. A `try_lock` here read 0 nearly always (the shared tree
    // holds its own lock across each page it ingests) and so disabled borrowing entirely.
    // The shared tree itself must not borrow from itself, hence the token check.
    let shared_tree_covers =
        if token == CHAIN_TREE_TOKEN { 0 } else { state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed) };
    let shared_tree_base =
        if token == CHAIN_TREE_TOKEN { u64::MAX } else { state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed) };
    // No node means no block stream to advance along. Report the wallet as still
    // behind rather than idle: "caught up" would be a claim about the chain that this
    // daemon currently cannot see, and the UI would show a partial balance as final.
    let Some(sync_client) = state.sync_client().await else { return SyncOutcome::Behind };
    // One chunk per pass for a wallet near the tip; a wallet far behind bursts through
    // more chunks while the pass budget lasts (see `CATCHUP_BURST_MIN_BEHIND`). The shared
    // chain tree keeps its single chunk's worth of pages per pass, but takes them ONE
    // per `sync_chunk` call with its lock released in between: a spend on any borrowing
    // wallet witnesses through this tree (`chain_tree_paths`), so it can now take the
    // tree after at most one page instead of a whole chunk. That reader polls `try_lock`
    // every 20 ms and cannot queue, so the gap between pages is held open for one of
    // its polls (see below) — a bare yield would close it in microseconds. Every other
    // wallet reads the tree's published reach between passes, never its lock.
    let pass_started = std::time::Instant::now();
    let mut was_caught_up = was_caught_up;
    let mut chain_tree_pages = 0usize;
    loop {
        e.sync_chunk(&sync_client, &state.page_cache, &state.warm_gate, &state, &token, was_caught_up, state.resources.subtree_free_floor_mb, shared_tree_covers, shared_tree_base)
            .await;
        let behind_by = chain_len.saturating_sub(e.scanned as u64);
        if token == CHAIN_TREE_TOKEN {
            chain_tree_pages += 1;
            if chain_tree_pages >= PAGES_PER_CHUNK || e.caught_up || e.error.is_some() || pass_started.elapsed() >= PASS_BUDGET {
                break;
            }
        } else if e.caught_up
            || e.error.is_some()
            || behind_by < CATCHUP_BURST_MIN_BEHIND
            || pass_started.elapsed() >= CATCHUP_BURST_BUDGET
        {
            break;
        }
        // Let queued status/history calls on this wallet through before the next chunk.
        drop(e);
        if token == CHAIN_TREE_TOKEN {
            // Lock released: this sleep blocks nothing, it only guarantees a spinning
            // `chain_tree_paths` (20 ms poll) one look at the free tree per page.
            tokio::time::sleep(CHAIN_TREE_PAGE_GAP).await;
        } else {
            tokio::task::yield_now().await;
        }
        e = w.lock().await;
        e.chain_len = chain_len;
        // A bursting wallet is by definition not at the tip. The chain tree re-loops per
        // PAGE even when it was: keep its verdict, or any lap longer than CAUGHT_UP_PAGE
        // blocks (a 30 s lap at 1 BPS) ends the pass "just caught up" — which is a full
        // checkpoint write of the whole shared stream (475 MB live) per such lap.
        if token != CHAIN_TREE_TOKEN {
            was_caught_up = false;
        }
    }
    // A borrowing wallet's mirror tree is stale by construction; make it current again
    // by taking the shared tree's frontier. `adopt_tip_frontier` REFUSES unless the
    // frontier describes exactly this wallet's leaf count — the frontier at N leaves is
    // a pure function of leaves 0..N, so an equal size proves it is this wallet's own
    // and an unequal one proves it is not. That single check is the whole safety
    // argument, and it lives in the wallet, not here.
    //
    // Re-peeked after the chunk rather than reused from before it: both trees moved.
    if !e.db.tree_is_valid() {
        let fs = state.chain_tree_frontier.lock().await.clone();
        if let Some(fs) = fs {
            if e.db.adopt_tip_frontier(&fs) {
                log::debug!("wallet adopted the shared tree's frontier at {} leaves", fs.size);
            }
        }
    }

    // The shared tree republishes its reach after its own pass, so every other wallet
    // sees it without ever touching its lock.
    if token == CHAIN_TREE_TOKEN {
        state.chain_tree_size.store(e.db.size(), std::sync::atomic::Ordering::Relaxed);
        state.chain_tree_base.store(e.db.base_size(), std::sync::atomic::Ordering::Relaxed);
        let fs = e.db.tip_frontier_state();
        *state.chain_tree_frontier.lock().await = fs;
    }
    // Report where scan CPU actually goes, once per SCAN_COST_REPORT_ACTIONS of work.
    //
    // A scan has two heavy halves — trial decryption (one Pallas scalar mul per action
    // per ivk) and tree append (one Sinsemilla combine per leaf) — and they need
    // opposite remedies: decryption is per (wallet, action) and parallelises across
    // wallets or hardware, while tree work is per leaf and is IDENTICAL for every
    // wallet, so it wants sharing, not more cores. Until now nothing measured the
    // ratio, which makes any optimization decision a guess.
    {
        let c = e.db.scan_cost();
        if c.leaves >= e.scan_cost_reported + SCAN_COST_REPORT_LEAVES {
            e.scan_cost_reported = c.leaves;
            let total = c.total_ns().max(1);
            log::info!(
                "scan cost so far: decrypt {} ms ({}%) over {} actions = {:.1} us/action | tree {} ms ({}%) over {} leaves = {:.1} us/leaf",
                c.decrypt_ns / 1_000_000,
                c.decrypt_ns * 100 / total,
                c.actions,
                c.decrypt_ns as f64 / 1000.0 / c.actions.max(1) as f64,
                c.tree_ns / 1_000_000,
                c.tree_ns * 100 / total,
                c.leaves,
                c.tree_ns as f64 / 1000.0 / c.leaves.max(1) as f64,
            );
            // The percentages above are shares of decrypt+tree, NOT of the sync. Report
            // the page pipeline next to them so the two can never again be confused: a
            // 1.8x on decryption moved ~2% of a wallet's sync time, and the counters as
            // they stood gave no way to see that.
            if e.page_count > 0 {
                let fetch_ms = (e.page_fetch_ns / 1_000_000) as u64;
                let ingest_ms = (e.page_ingest_ns / 1_000_000) as u64;
                log::info!(
                    "page pipeline: fetch {} ms ({:.0} ms/page) | ingest {} ms ({:.0} ms/page) | {} pages -> fetch is {}% of the two",
                    fetch_ms,
                    fetch_ms as f64 / e.page_count as f64,
                    ingest_ms,
                    ingest_ms as f64 / e.page_count as f64,
                    e.page_count,
                    fetch_ms * 100 / (fetch_ms + ingest_ms).max(1),
                );
            }
        }
    }
    // NB: the eager witness pre-advance and base compaction live in `sync_chunk`'s
    // `caught_up` tail, THROTTLED to one bounded step per `WITNESS_ADVANCE_INTERVAL` per
    // wallet (an unthrottled advance on the 10 ms sync spin pinned every core, observed
    // live 2026-07-16). Together with the v5 checkpoint persisting the resulting witnesses,
    // a spend becomes a lookup instead of an O(chain) Sinsemilla replay; `witness_path_at`
    // still rebuilds on demand for any note whose witness isn't held (correctness never
    // depends on the pre-advance).
    if e.reorged_strikes >= REORG_STRIKES {
        // Cursor off the selected chain (or pruned away) for enough passes: retire the
        // checkpoint to .bak and let the caller evict + reload it from a fresh anchor.
        //
        // But a reload is only LOSSLESS if the node can still serve genesis. The `/rescan`
        // handler already refuses this exact operation against a node that cannot (it returns
        // 409 rather than quietly amputating), and that guard exists because a user lost
        // 18,354 ZKAS to it on 2026-07-28. This path reached the same destructive reload with
        // no such check: refused when a user asks for it, performed silently when a pruning
        // jump triggers it. The trigger is routine — the pruning point advances a whole
        // `finality_depth` at a time (measured live: 567,082 → 610,666), taking every cursor
        // below it with one step — so this fires on ordinary operation, not on some edge case.
        //
        // Park the wallet instead and keep the checkpoint. A stale cursor shows a stale
        // balance until the operator repoints at an archival node; a pruning-point rebuild
        // silently hides every note minted below it, and both `/prepare` paths are SPEND
        // paths, so those notes become "insufficient funds" while the user holds the coins.
        let serves_genesis = matches!(
            match state.request_client().await {
                Some(c) => c.get_shielded_tree_state(Some(e.genesis)).await,
                None => Err(kaspa_rpc_core::RpcError::General("node unavailable".into())),
            },
            Ok(ts) if ts.block_hash == e.genesis
        );
        if !serves_genesis {
            // Log once, on the pass that crosses the threshold: this branch is re-entered
            // every ~1s lap for as long as the wallet stays parked.
            if e.reorged_strikes == REORG_STRIKES {
                log::error!(
                    "wallet '{token}': cursor is unusable ({}) but this node CANNOT SERVE GENESIS, \
                     so rebuilding would drop every note minted below its pruning point — \
                     REFUSING to retire the checkpoint. The wallet is parked and its balance is \
                     stale until you point walletd at an archival node and restart.",
                    e.error.as_deref().unwrap_or("no error recorded")
                );
            }
            e.error = Some(
                "cursor unusable and this node cannot serve genesis; checkpoint preserved — \
                 repoint at an archival node (rebuilding here would lose notes)"
                    .into(),
            );
            return SyncOutcome::Behind;
        }
        // Belt and braces for the strike gate in `sync_chunk`: retire only on a node that
        // has reached the cursor. The strikes may predate a repoint (the entry is long
        // lived), so re-check here, at the moment the file is actually renamed.
        if let Err(why) = node_reaches(&sync_client, e.scanned as u64, SYNC_RPC_TIMEOUT).await {
            // Once per episode: `sync_chunk` records the same message on every later
            // pass the node stays behind, so this fires only on the pass that parks it.
            if !e.error.as_deref().is_some_and(|m| m.starts_with("node is behind the wallet cursor")) {
                log::warn!(
                    "wallet '{token}': cursor reported unusable for {} passes but the node has not reached it ({why}); \
                     keeping the checkpoint until it does",
                    e.reorged_strikes
                );
            }
            e.error = Some(format!("node is behind the wallet cursor ({why}); waiting"));
            return SyncOutcome::Behind;
        }
        let scan = scan_path(&state.wallet_dir, &token);
        log::warn!(
            "wallet '{token}': cursor off the selected chain for {} consecutive passes ({}) \
             — retiring checkpoint to .bak and rescanning",
            e.reorged_strikes,
            e.error.as_deref().unwrap_or("no error recorded")
        );
        // Never clobber an existing backup. The rename used to be unconditional, so a second
        // retirement overwrote the good pre-amputation checkpoint with the already-damaged one
        // and destroyed the only copy — exactly when a recovering operator is retrying.
        let bak = format!("{scan}.bak");
        if std::fs::metadata(&bak).is_ok() {
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default();
            let _ = std::fs::rename(&bak, format!("{bak}.{stamp}"));
        }
        let _ = std::fs::rename(&scan, &bak);
        return SyncOutcome::Retired(token);
    }
    if e.reorged_strikes > 0 {
        // Striking but not yet retired: don't checkpoint a suspect cursor. Come back next pass.
        return SyncOutcome::Behind;
    }
    // A submitted spend the chain has still not shown after an hour of chain time
    // is lost — a node that crashed with it in the mempool, an eviction, or a
    // consensus-dropped shielded spend. Hand the notes back (live report
    // 2026-07-18: "ZKAS disappeared without a trace" was exactly this). Only
    // judged when caught up, so "unobserved" means the chain really doesn't have
    // it, not that we haven't looked yet.
    if e.caught_up {
        let now_daa = e.scanned as u64;
        for (txid, value) in e.db.reclaim_expired(now_daa, PENDING_SPEND_EXPIRY_DAA) {
            e.force_checkpoint = true; // persist the returned note promptly
            log::warn!(
                "wallet '{token}': submitted spend {} ({value} sompi) never appeared on-chain within ~{PENDING_SPEND_EXPIRY_DAA}s of chain time — note returned to the spendable balance",
                RpcHash::from_bytes(txid)
            );
        }
    }
    let behind = !e.caught_up;
    // Persist a checkpoint once enough new blocks accrue, or the first time this wallet
    // reaches the tip, so a restart resumes here instead of rescanning from birthday.
    let advanced = e.scanned.saturating_sub(e.saved_scanned);
    let just_caught_up = e.caught_up && !was_caught_up;
    // `force_checkpoint` is set the instant the witnesses first warm, so the expensive
    // witness state (v5) is persisted immediately — a restart seconds later must not throw
    // it away and re-do the ~30–90 s warm.
    let force = e.force_checkpoint;
    let overdue = advanced > 0 && e.last_checkpoint_at.elapsed() >= CHECKPOINT_INTERVAL;
    // A wallet far enough behind to burst (see `CATCHUP_BURST_MIN_BEHIND`) ingests
    // several thousand blocks per pass, so the block rule alone would rewrite the
    // checkpoint on EVERY pass — and a restoring wallet retains every leaf since its
    // birthday until it is caught up (base compaction runs only then), so each write
    // is the whole growing stream, ~150 MB by the end of a full-chain restore. Bursting
    // wallets checkpoint on the time rule only; the block rule keeps its near-tip role.
    let bursting = chain_len.saturating_sub(e.scanned as u64) >= CATCHUP_BURST_MIN_BEHIND;
    let due_by_blocks = advanced >= CHECKPOINT_EVERY && !bursting;
    // Serialised under the lock (the bytes must describe one consistent state), but
    // WRITTEN off it, on a blocking thread, below: `fs::write` of a many-MB blob on the
    // async worker stalled every other task and every status/history call on this
    // wallet for the duration. The flag is consumed here so a force that arrives while
    // the write is in flight is not lost; a failed write hands it back.
    let pending_checkpoint = if e.error.is_none() && (due_by_blocks || (just_caught_up && advanced > 0) || force || overdue) {
        e.force_checkpoint = false;
        Some((
            checkpoint_bytes(&e.genesis, &e.low, e.scanned as u64, &e.db, &e.boundaries, e.sink_blue, e.blind_below),
            e.scanned,
        ))
    } else {
        None
    };
    // Snapshot the subtree-cache build inputs while we still hold the lock; the fold
    // itself runs without it (see `SubtreeBuildJob`).
    let build_job = if e.wants_cache_build && !e.build_in_flight {
        e.wants_cache_build = false;
        e.build_in_flight = true;
        Some(e.db.subtree_build_job())
    } else {
        None
    };
    // Refresh the out-of-band status snapshot while we still hold the lock.
    let snap = snap_from_entry(state.address_of(&e.db), &e, chain_len);
    drop(e);
    state.snapshots.lock().await.insert(token.clone(), snap);
    if let Some((buf, scanned)) = pending_checkpoint {
        let dir = state.wallet_dir.clone();
        let who = token.clone();
        let written = tokio::task::spawn_blocking(move || write_checkpoint_bytes(&dir, &who, &buf)).await;
        let mut e = w.lock().await;
        match written {
            Ok(Ok(())) => {
                e.saved_scanned = scanned;
                e.last_checkpoint_at = std::time::Instant::now();
            }
            Ok(Err(err)) => {
                eprintln!("checkpoint write failed for {token}: {err}");
                e.force_checkpoint |= force;
            }
            Err(err) => {
                eprintln!("checkpoint write task failed for {token}: {err}");
                e.force_checkpoint |= force;
            }
        }
    }
    if let Some(job) = build_job {
        // DETACHED on purpose. `sync_loop` joins every wallet task before starting the
        // next lap, so awaiting a ~247 s fold here would stall every other wallet for
        // that long — the opposite of the point. Progress is logged and published by
        // `run_subtree_build` as it goes.
        spawn_subtree_build(&state, &token, &w, job, "sync");
    }
    // A real sleep (not just yield_now) after each wallet, so HTTP handlers get a cycle
    // even while scans run. With bounded concurrency each in-flight scan still yields here.
    tokio::time::sleep(std::time::Duration::from_millis(SYNC_WALLET_THROTTLE_MS)).await;
    if behind { SyncOutcome::Behind } else { SyncOutcome::Idle }
}

/// Evict wallets past [`ResourceLimits::idle_evict_secs`] (plus LRU overflow past
/// [`ResourceLimits::max_resident_wallets`]). Memory is a cache of the on-disk checkpoint — a hosted
/// daemon serving hundreds of browsers must not hold every wallet it has ever loaded.
/// A dirty victim is flushed to disk first, so the reload on its next request costs a
/// file read, not a rescan. Safe by construction:
///  - a wallet in active use is touched on every request, so it can never be a victim;
///  - a mid-flight `/prepare` + `/submit` pair spans minutes, not the 30-minute idle bar,
///    and even a cap-evicted submit simply reloads from the checkpoint (the prepared
///    session lives in `state.prepared`, not in the wallet);
///  - removal is by Arc identity: a wallet retired/reloaded between our map read and
///    removal is left alone.
async fn evict_idle_wallets(state: &Arc<AppState>) {
    let now = std::time::Instant::now();
    let touches: HashMap<String, std::time::Instant> = state.last_touch.lock().await.clone();
    // The chain tree is never a victim. It has no `last_touch` (nothing can address it),
    // so both the idle rule and the LRU-overflow rule would evict it immediately — and
    // evicting it throws away the one structure every other wallet is about to use,
    // guaranteeing it is rebuilt from scratch. Filtering it out here is why it needs no
    // special case in either rule below.
    let resident: Vec<(String, Wallet)> = {
        state
            .wallets
            .lock()
            .await
            .iter()
            .filter(|(k, _)| k.as_str() != CHAIN_TREE_TOKEN)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let mut victims: Vec<String> = resident
        .iter()
        .filter(|(t, _)| {
            touches
                .get(t)
                .map(|at| now.duration_since(*at) >= std::time::Duration::from_secs(state.resources.idle_evict_secs))
                .unwrap_or(false)
        })
        .map(|(t, _)| t.clone())
        .collect();
    if resident.len() > state.resources.max_resident_wallets {
        // The count cap is a cache-pressure policy, not permission to throw away a
        // wallet a user is watching while it is catching up. During a redirect/restart
        // cohort many browsers reconnect together; evicting their recently touched
        // entries every sweep made large wallets restart forever at 0–70%. Restrict
        // LRU overflow victims to wallets outside the active-sync window. If every
        // resident wallet is genuinely active the cap is temporarily soft; the
        // operator's MemoryHigh/MemoryMax remains the final host safety boundary.
        let active_window = std::time::Duration::from_secs(state.resources.active_sync_secs);
        let mut by_touch: Vec<(String, std::time::Instant)> = resident
            .iter()
            .filter_map(|(t, _)| {
                let at = touches.get(t).copied().unwrap_or(now);
                (now.duration_since(at) >= active_window).then(|| (t.clone(), at))
            })
            .collect();
        by_touch.sort_by_key(|(_, at)| *at);
        for (t, _) in by_touch.into_iter().take(resident.len() - state.resources.max_resident_wallets) {
            if !victims.contains(&t) {
                victims.push(t);
            }
        }
    }
    for token in victims {
        let Some(w) = state.wallets.lock().await.get(&token).cloned() else { continue };
        {
            let mut e = w.lock().await;
            // Flush a dirty victim so eviction is free of rescan cost. A wallet in an
            // error state is evicted as-is — its checkpoint already lagged and the
            // reload path re-derives whatever it can.
            if e.error.is_none() && e.saved_scanned != e.scanned {
                if save_checkpoint(
                    &state.wallet_dir,
                    &token,
                    &e.genesis,
                    &e.low,
                    e.scanned as u64,
                    &e.db,
                    &e.boundaries,
                    e.sink_blue,
                    e.blind_below,
                )
                .is_ok()
                {
                    e.saved_scanned = e.scanned;
            e.last_checkpoint_at = std::time::Instant::now();
                    e.force_checkpoint = false;
                }
            }
        }
        // Remove only if the map still holds THIS instance (a retire/reload racing the
        // sweep must not be eaten).
        let mut map = state.wallets.lock().await;
        if map.get(&token).map(|cur| Arc::ptr_eq(cur, &w)).unwrap_or(false) {
            map.remove(&token);
            log::info!("evicted idle wallet '{token}' (checkpoint on disk; it reloads on its next request)");
        }
    }
}

/// Memory policing must not share the sync loop. A cohort of large checkpoints can
/// keep that loop inside CPU-heavy scan/witness work for minutes — exactly when the
/// resident cap is most important. Run the sweep independently so its cadence remains
/// bounded under scan load.
async fn eviction_loop(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(EVICT_SWEEP_INTERVAL).await;
        evict_idle_wallets(&state).await;
        prune_token_bookkeeping(&state).await;
    }
}

/// Forget the per-token bookkeeping of wallets that are no longer resident.
///
/// `last_touch` and `snapshots` are keyed by a token the CLIENT supplies, and
/// nothing was removing them. `touch` runs on every `/api/status` before anything
/// checks whether that wallet exists, so a caller sending fresh random tokens grew
/// `last_touch` without bound — a public daemon's memory, driven by a header. And a
/// snapshot carries an address and balances, so keeping one for every wallet that
/// ever loaded retains viewing-key-derived data about wallets long since evicted.
///
/// Neither map is a cache of anything expensive: `last_touch` only decides whether a
/// token is inside the active-sync window, and a snapshot is rebuilt from the wallet
/// the first time it is polled again. Dropping what is out of scope costs nothing.
/// Keep a `last_touch` entry? Yes while it is inside the active-sync window, and yes
/// for a resident wallet whatever its age — a parked wallet still in memory must not
/// have its activity record dropped out from under the sync loop's active-set check.
fn keep_touch(age: std::time::Duration, window: std::time::Duration, resident: bool) -> bool {
    age < window || resident
}

async fn prune_token_bookkeeping(state: &Arc<AppState>) {
    let resident: HashSet<String> = state.wallets.lock().await.keys().cloned().collect();
    // Anything past the active window can never make a token active again, so it has
    // no bearing on any decision. Keep the window itself as the retention rule rather
    // than inventing a second one that could drift from it.
    let window = std::time::Duration::from_secs(state.resources.active_sync_secs);
    let now = std::time::Instant::now();
    state
        .last_touch
        .lock()
        .await
        .retain(|token, at| keep_touch(now.duration_since(*at), window, resident.contains(token)));
    state.snapshots.lock().await.retain(|token, _| resident.contains(token));
}

async fn sync_loop(state: Arc<AppState>) {
    // Shared across every lap for the lifetime of the daemon; see where it is used.
    let sync_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(sync_concurrency(&state.resources)));
    loop {
        // Snapshot token names, not Wallet Arcs. Holding an Arc for every resident
        // wallet across the whole cohort kept evicted multi-hundred-MiB checkpoints
        // alive until the slowest scan finished, making the resident cap appear to
        // run while RSS stayed pinned. Resolve one Arc only when its bounded worker
        // slot is ready; an entry evicted in the meantime is simply skipped.
        let wallet_tokens: Vec<String> = { state.wallets.lock().await.keys().cloned().collect() };
        let mut any_behind = false;
        let mut reorged_tokens: Vec<String> = Vec::new();
        // Only sync wallets touched within this window. The rest are parked (kept in
        // memory at their last checkpoint) until a request re-touches them — so a
        // public daemon with hundreds of one-time-visitor tokens doesn't try to
        // full-scan all of them at once and pin every core.
        let active: HashSet<String> = {
            let now = std::time::Instant::now();
            let mut a: HashSet<String> = state
                .last_touch
                .lock()
                .await
                .iter()
                .filter(|(_, t)| now.duration_since(**t) < std::time::Duration::from_secs(state.resources.active_sync_secs))
                .map(|(k, _)| k.clone())
                .collect();
            // The chain tree is never "touched" by a request — nothing can address its
            // token — so the activity filter would park it forever. It is always active:
            // it is the one entry whose work every other wallet depends on, and it can
            // serve nobody it has not already reached.
            a.insert(CHAIN_TREE_TOKEN.to_string());
            a
        };
        if !wallet_tokens.is_empty() {
            // Timed out for the same reason as the page fetch: this runs once per pass on
            // the shared loop, so a hang here freezes every wallet.
            // A timed-out dag-info must NOT be reported as "the chain is 0 blocks long".
            // This value is stamped into EVERY wallet swept this pass, and `synced`
            // compares `scanned + margin >= chain_len` — so a zero here makes every
            // wallet claim to be synced, and one still halfway through its scan then
            // presents a PARTIAL balance as final. Observed live 2026-07-30: one wallet
            // under four tokens reporting 2,038,348 / 1,902,767 / 1,902,767 / 0.00 ZKAS,
            // all four "synced". Fall back to the last tip actually observed.
            let chain_len = match tokio::time::timeout(SYNC_RPC_TIMEOUT, async {
                match state.sync_client().await {
                    Some(c) => c.get_block_dag_info().await,
                    None => Err(kaspa_rpc_core::RpcError::General("node unavailable".into())),
                }
            })
            .await
            {
                Ok(Ok(d)) => d.virtual_daa_score,
                _ => state.node_tip.lock().await.0,
            };
            if chain_len > 0 {
                *state.node_tip.lock().await = (chain_len, std::time::Instant::now());
            }
            // Advance the active wallets with BOUNDED CONCURRENCY across the idle cores.
            // A single sequential loop pinned exactly one core (the per-wallet scan and
            // witness step are CPU-bound), so one wallet's heavy step — e.g. a 7–15 s
            // witness advance on a many-note wallet — froze every other wallet's scan.
            // Running up to `SYNC_CONCURRENCY` at once uses the otherwise-idle cores while
            // still leaving headroom for the HTTP handlers, the node RPC, and the mempool
            // loop. Per-wallet correctness is unchanged (each holds only its own lock).
            // Sweep the FURTHEST-BEHIND wallets first, so the shared page cache can
            // actually hit.
            //
            // `fetch_shielded_page` is keyed `(low_hash, limit)` and its whole premise is
            // that "during a mass rescan every active wallet walks the same stream". That
            // is only true if their cursors coincide. Iterating a HashMap's arbitrary
            // order kept the backlog spread across the entire chain, so every wallet
            // fetched and decoded every page for itself and the cache hit ~0. Measured
            // 2026-08-07: kaspad burning **562 % CPU** serving 8 independent historical
            // page streams while merely tip-following at 10 blocks/10 s — the node, not
            // walletd, had become the bottleneck.
            //
            // Ordering by cursor puts the laggards in the same slots at the same time.
            // They converge toward each other's cursors and, once two wallets land on the
            // same page, they advance in lockstep from then on (same page ⇒ same next
            // cursor) and share every subsequent fetch and decode. Purely a scheduling
            // order: every wallet still scans its own full range, so no wallet can miss a
            // block because of it.
            let mut wallet_tokens = wallet_tokens;
            {
                let snaps = state.snapshots.lock().await;
                wallet_tokens.sort_by_key(|t| snaps.get(t).map(|s| s.scanned).unwrap_or(usize::MAX));
            }
            // ONE budget for all laps, not a fresh one per lap.
            //
            // When a lap exceeds LAP_BUDGET its stragglers are detached and keep running.
            // A per-lap semaphore meant those stragglers held permits from a semaphore
            // nobody consults again, while the next lap started with full capacity — so
            // the real number of concurrent passes was `sync_wallets + however many
            // wallets are currently stuck`, with nothing bounding the second term. Each
            // pass carries a memory budget, so that grows into the failure the limit
            // exists to prevent.
            //
            // Sharing the semaphore bounds it. Acquisition is a TRY with a short timeout
            // rather than an await, because blocking the lap on a permit held by a stuck
            // wallet would restore exactly the head-of-line stall LAP_BUDGET removes: a
            // wallet that cannot get a permit this lap is simply swept in the next one.
            let sem = sync_sem.clone();
            let mut set = tokio::task::JoinSet::new();
            for token in wallet_tokens {
                if !active.contains(&token) {
                    continue; // parked: nobody is looking at this wallet right now
                }
                // Still being swept by an earlier lap that outran its budget — leave it be.
                if token == CHAIN_TREE_TOKEN && !state.build_shared_tree {
                    continue; // on-device: no shared tree to build; the wallet serves itself
                }
                let Some(guard) = InPassGuard::claim(&state, &token) else { continue };
                let Ok(Ok(permit)) =
                    tokio::time::timeout(PERMIT_WAIT, sem.clone().acquire_owned()).await
                else {
                    // Every slot is busy. Skip this wallet for now — `guard` drops here and
                    // frees the claim, so the next lap picks it up.
                    continue;
                };
                let Some(w) = state.wallets.lock().await.get(&token).cloned() else {
                    continue; // `guard` drops here and releases the claim
                };
                let st = state.clone();
                set.spawn(async move {
                    let _permit = permit; // held for the wallet's whole chunk, bounding concurrency
                    // Released on EVERY exit including a panic. Removing the token at the
                    // end of the task body instead would have leaked the claim whenever a
                    // wallet task panicked, and a leaked claim is permanent: every later
                    // lap skips that token, so the wallet silently stops syncing until the
                    // daemon restarts.
                    let _guard = guard;
                    sync_one_wallet(st, token, w, chain_len).await
                });
            }
            // Wait for the lap, but not forever: one wallet that cannot finish must not
            // hold every other wallet's next pass hostage (see [`LAP_BUDGET`]).
            let lap_deadline = tokio::time::Instant::now() + LAP_BUDGET;
            loop {
                match tokio::time::timeout_at(lap_deadline, set.join_next()).await {
                    Ok(Some(res)) => match res {
                        Ok(SyncOutcome::Retired(t)) => reorged_tokens.push(t),
                        Ok(SyncOutcome::Behind) => any_behind = true,
                        Ok(SyncOutcome::Idle) => {}
                        Err(join_err) => log::warn!("wallet sync task failed: {join_err}"),
                    },
                    // Lap complete.
                    Ok(None) => break,
                    Err(_) => {
                        // Let the stragglers run on. They hold their permits, so
                        // concurrency stays bounded, `in_pass` stops the next lap from
                        // doubling up on them, and every OTHER wallet gets swept now
                        // instead of waiting on the slowest one.
                        let stragglers = set.len();
                        set.detach_all();
                        any_behind = true;
                        log::info!(
                            "sync lap exceeded {}s with {stragglers} wallet(s) still working; continuing without them",
                            LAP_BUDGET.as_secs()
                        );
                        break;
                    }
                }
            }
        }
        if !reorged_tokens.is_empty() {
            // The chain tree cannot be handled by "remove it and let the next request
            // reload it" — nothing can request it. Dropping it would leave `wallets`
            // without it forever, so it would stop advancing, go stale, and silently
            // decline every wallet from then until a restart. Reset it in place instead
            // (same `Arc`, so `state.chain_tree` follows) and let it rescan; its
            // checkpoint has already been retired to .bak by the retire path.
            if reorged_tokens.iter().any(|t| t == CHAIN_TREE_TOKEN) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let last = CHAIN_TREE_LAST_RESET.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= CHAIN_TREE_RESET_MIN_INTERVAL {
                    // First reset (or the first after the back-off window): a real reorg
                    // is absorbed here and the tree rebuilds cleanly.
                    log::warn!("shared chain tree hit a reorg it could not follow — resetting it to genesis and rebuilding");
                    CHAIN_TREE_LAST_RESET.store(now, std::sync::atomic::Ordering::Relaxed);
                    *state.chain_tree.lock().await = chain_tree_from_genesis(state.genesis);
                } else if last != 0 {
                    // Re-striking within the window: this is not a passing reorg, it is a
                    // node that cannot serve the shielded history from genesis (pruned /
                    // non-archival, or unsynced and constantly reselecting its chain). Do
                    // NOT rebuild every lap — that is the 1 Hz genesis-reset livelock. Leave
                    // the tree as it is (parked, serving stale roots) until the window
                    // elapses, and say why, once.
                    if now.saturating_sub(last) <= 2 {
                        log::error!(
                            "shared chain tree cannot follow this node's chain and a genesis rebuild keeps failing                              — the node cannot serve the shielded history from genesis. Point walletd at an ARCHIVAL,                              fully-synced node (or run the node with --shielded-history=on / --archival). Backing off                              for {CHAIN_TREE_RESET_MIN_INTERVAL}s instead of rescanning every pass."
                        );
                    }
                }
            }
            let mut map = state.wallets.lock().await;
            let mut snaps = state.snapshots.lock().await;
            for t in reorged_tokens {
                snaps.remove(&t);
                if t == CHAIN_TREE_TOKEN {
                    continue; // reset above; keep it resident so the sync loop keeps driving it
                }
                map.remove(&t);
            }
        }
        // While catching up a big initial scan, loop back immediately (only a
        // tiny yield so status calls can grab the lock); idle slowly once synced.
        if any_behind {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        } else {
            // A caught-up wallet used to idle here for 12 SECONDS, which is most of the
            // delay before a payment appears: the tx is mined in ~1s, but nothing looks at
            // it until this sleep ends. It is a cheap pass when nothing has changed (one
            // dag-info call, one mempool call, a short page), so poll at ~1s instead —
            // payments are supposed to feel instant.
            tokio::time::sleep(IDLE_SYNC_POLL).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(serde_json::json!({ "error": msg.into() })))
}

fn fmt_fc(sompi: u128) -> String {
    let whole = sompi / SOMPI_PER_ZKAS as u128;
    let frac = sompi % SOMPI_PER_ZKAS as u128;
    format!("{whole}.{frac:08}")
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "zkas-walletd" }))
}

#[derive(Serialize)]
struct NoteInfo {
    position: u64,
    value: u64,
}

#[derive(Serialize)]
struct StatusResp {
    has_wallet: bool,
    address: Option<String>,
    /// The scan birthday (DAA score) this daemon keeps for the wallet; 0 = unknown.
    /// Lets a client that lost its own copy (a re-pair, a second device, a service
    /// switch) re-register elsewhere with the real birthday instead of 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    birthday: Option<u64>,
    network: String,
    node_connected: bool,
    daa_score: u64,
    synced: bool,
    /// Synced, but still doing the one-time witness warm-up. The SPA shows a "preparing for
    /// fast sends" notice; sends still work (the first is just slower). Absent/false on
    /// older daemons and on note-heavy wallets (which skip the eager warm).
    #[serde(default)]
    warming: bool,
    /// While this wallet's subtree cache is being built (the one-time O(chain) fold a
    /// first send otherwise waits on): leaves folded, leaves in total, percent, and the
    /// seconds remaining at the observed rate. Read from `AppState::cache_builds`, so
    /// they are live even while the wallet lock is held. Absent when nothing is
    /// building (and on older daemons), so clients that do not know them keep parsing.
    #[serde(skip_serializing_if = "Option::is_none")]
    warming_done_leaves: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warming_total_leaves: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warming_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warming_eta_secs: Option<u64>,
    scanned_blocks: usize,
    chain_len: u64,
    balance_sompi: String,
    balance_fc: String,
    /// Spendable-now balance: the subset of `balance_*` held in notes matured past
    /// the shielded anchor depth (~10 min). A send can only draw on this; the rest
    /// is `maturing_*`. Exposed so the wallet shows "spendable vs maturing" instead
    /// of offering the full balance and then failing a send with "have 0".
    spendable_sompi: String,
    spendable_fc: String,
    /// balance − spendable: value in notes too new to spend yet (still maturing).
    maturing_sompi: String,
    maturing_fc: String,
    /// 0-conf: value seen arriving/leaving in blocks too near the tip to ingest. Lets a
    /// payment show up ~1s after it is mined instead of ~3min later. Older daemons omit
    /// these; a missing value means "none pending".
    pending_in_sompi: String,
    pending_in_fc: String,
    pending_out_sompi: String,
    pending_out_fc: String,
    /// Change coming back from this wallet's own in-flight send(s): the part of the
    /// parked input note(s) that is neither the amount paid nor the fee. Already out
    /// of `balance_*` (the whole input note leaves at submit) and NOT spendable until
    /// the send is mined and settles. Lets the headline read `balance + pending_change`
    /// instead of dipping to 0 between submit and the first 0-conf preview. Older
    /// daemons omit these; a missing value means "none".
    #[serde(default)]
    pending_change_sompi: String,
    #[serde(default)]
    pending_change_fc: String,
    note_count: usize,
    updated_unix: u64,
    error: Option<String>,
    /// True when the daemon holds only this wallet's viewing key: it can show the
    /// balance but cannot spend. Sends must go through /prepare + /submit with the
    /// signature produced on the device that holds the seed.
    watch_only: bool,
    /// True when this wallet's view was rebuilt from a pruning-point frontier while
    /// its birthday claims older history: notes minted before that point exist on
    /// chain but CANNOT be discovered through this node (their blocks are pruned).
    /// The balance shown is a lower bound, and the UI must say so. False on older
    /// daemons (field absent) and on wallets with a complete view.
    #[serde(default)]
    missing_history: bool,
    /// With `missing_history`: the DAA score this wallet's view starts at (the serving
    /// node's pruning point when the view was built), so the UI can say "history
    /// available from block N". Absent on older daemons and after a daemon restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history_from_daa: Option<u64>,
    /// Whether a spend would be accepted right now. Older clients that only read
    /// `synced` keep working; clients that read this stop contradicting the daemon.
    #[serde(default)]
    spend_ready: bool,
    /// The wallet exists and is being opened: its balance and scan progress are not
    /// known YET. Distinct from `synced: false`, which means "open, and behind the
    /// chain" -- here the daemon has nothing to report rather than something small.
    ///
    /// Published because the client cannot otherwise tell "still opening" from "the
    /// daemon forgot this wallet", and it guessed wrong in the direction that asks a
    /// user to retype their recovery seed. A zero balance under `loading` must be
    /// rendered as "opening", never as a balance.
    #[serde(default)]
    loading: bool,
    /// Blocks between this wallet's view and the chain tip. Non-zero is NORMAL: a wallet
    /// deliberately never ingests the last `SYNC_TIP_MARGIN` blocks. Meaningful to show
    /// only alongside `spend_ready` — it is the caveat attached to paying while behind.
    #[serde(default)]
    blocks_behind: u64,
}

async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<StatusResp> {
    let token = token_from(&headers, state.allow_default_token).ok();
    // Do NOT call the node here. The gRPC client is shared with the background sync loop,
    // whose block fetches make a fresh get_block_dag_info queue for seconds — which made
    // every status call take ~4s. The sync loop already refreshes `node_tip` every pass,
    // and a dedicated ticker keeps it current even with no wallets loaded, so status reads
    // the cached tip instantly. `node_connected` follows whether the tip is fresh.
    let (node_connected, daa_score) = {
        let (tip, at) = *state.node_tip.lock().await;
        (at.elapsed() < std::time::Duration::from_secs(30), tip)
    };

    let mut resp = StatusResp {
        has_wallet: false,
        address: None,
        birthday: None,
        network: state.network.clone(),
        node_connected,
        daa_score,
        synced: false,
        warming: false,
        warming_done_leaves: None,
        warming_total_leaves: None,
        warming_pct: None,
        warming_eta_secs: None,
        spend_ready: false,
        loading: false,
        blocks_behind: 0,
        scanned_blocks: 0,
        chain_len: daa_score,
        balance_sompi: "0".into(),
        balance_fc: "0.00000000".into(),
        spendable_sompi: "0".into(),
        spendable_fc: "0.00000000".into(),
        maturing_sompi: "0".into(),
        maturing_fc: "0.00000000".into(),
        pending_in_sompi: "0".into(),
        pending_in_fc: "0.00000000".into(),
        pending_out_sompi: "0".into(),
        pending_out_fc: "0.00000000".into(),
        pending_change_sompi: "0".into(),
        pending_change_fc: "0.00000000".into(),
        note_count: 0,
        updated_unix: 0,
        error: None,
        missing_history: false,
        history_from_daa: None,
        watch_only: false,
    };

    if let Some(token) = token {
        // NEVER load on the request path. A wallet load makes node RPCs and rebuilds a
        // Merkle tree — seconds of work. Doing it here (even with a timeout) livelocked
        // the daemon: the timeout cancelled the half-done load, so the wallet never
        // cached, so every poll re-ran and re-cancelled it. Instead: if the wallet is
        // already loaded, answer from it (fast); otherwise kick off a background load
        // and report "syncing" until it lands. Subsequent polls are instant.
        state.touch(&token).await;
        if let Some(w) = state.cached_wallet(&token).await {
            if let Ok(e) = w.try_lock() {
                // Got the lock → compute a fresh snapshot, cache it out-of-band for the
                // polls that will race the next scan pass, and answer from it.
                let snap = snap_from_entry(state.address_of(&e.db), &e, daa_score);
                drop(e);
                state.snapshots.lock().await.insert(token.clone(), snap.clone());
                fill_status_from_snap(&mut resp, &snap);
            } else if let Some(snap) = state.snapshots.lock().await.get(&token).cloned() {
                // Lock held by the sync loop this instant — answer from the last-known-good
                // snapshot (real balance + progress) instead of a zero default. This is the
                // fix for the balance/scan-progress flickering to 0 mid-scan.
                fill_status_from_snap(&mut resp, &snap);
                // Deliberately NOT an error. `error` is rendered by every client as a
                // red failure box, and this condition — the sync loop happening to hold
                // the wallet lock at this instant — is the most ordinary thing the
                // daemon does. It flickered on and off with the lock, so a healthy
                // wallet showed a red "updating…" strobing under its balance.
                //
                // The snapshot above already carries the real balance and progress, and
                // the client's own status model decides what to call the state. There is
                // nothing here a user needs told.
            } else {
                // Loaded but not yet snapshotted — the wallet's own mutex is held by its
                // first sync pass and no cached snapshot exists yet. Common after a
                // restart, because snapshots live in memory and all of them are gone.
                //
                // Report presence AND identity: the balance is genuinely unknown here,
                // but which wallet this is never was.
                resp.has_wallet = true;
                resp.loading = true;
                resp.address = state.address_from_disk(&token).await;
            }
        } else if wallet_exists(&state.wallet_dir, &token) {
            // Known wallet, not yet in memory — load it in the background. Same again:
            // a load in flight is a state, not a fault.
            state.spawn_load(&token);
            resp.has_wallet = true;
            resp.loading = true;
            resp.address = state.address_from_disk(&token).await;
        }
        if resp.has_wallet {
            resp.birthday = wallet_birthday_on_disk(&state.wallet_dir, &token);
        }
        // A subtree-cache build in flight for this wallet: report where it is. This is
        // the figure the app shows as "Preparing … N%" while a first send waits, and
        // it needs no wallet lock — the build's own counter lives in `cache_builds`.
        let progress = state.cache_builds.lock().ok().and_then(|m| m.get(&token).cloned());
        if let Some(p) = progress {
            let (done, total, pct, eta) = p.snapshot();
            resp.warming = true;
            resp.warming_done_leaves = Some(done);
            resp.warming_total_leaves = Some(total);
            resp.warming_pct = Some((pct * 10.0).round() / 10.0);
            resp.warming_eta_secs = eta;
        }
    }
    // Name the node fault when there is one and the wallet itself has nothing to
    // report. Without this the app shows a wallet that is simply not progressing and
    // no reason for it, which reads as the wallet being broken rather than its node
    // being unreachable — the same confusion in a different place.
    if !resp.node_connected && resp.error.is_none() {
        resp.error = Some(match state.node_error() {
            Some(detail) => format!("cannot reach the ZKas node: {detail}"),
            None => "cannot reach the ZKas node".to_string(),
        });
    }
    Json(resp)
}

#[derive(Serialize)]
struct CreateResp {
    address: String,
    seed_hex: String,
    network: String,
    warning: String,
}

async fn wallet_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CreateResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    if wallet_exists(&state.wallet_dir, &token) {
        return Err(err(StatusCode::CONFLICT, "a wallet already exists for this token; import replaces it"));
    }
    use rand::RngCore;
    let mut seed = [0u8; 32];
    let address = loop {
        rand::rngs::OsRng.fill_bytes(&mut seed);
        if let Some(addr) = state.address_for_seed(&seed) {
            break addr;
        }
    };
    // A brand-new wallet holds no historical funds: birth it at the current tip so
    // it is instantly ready to receive — no full-history scan needed.
    let tip = match state.request_client().await {
        Some(c) => c.get_block_dag_info().await.map(|d| d.virtual_daa_score).unwrap_or(0),
        None => 0,
    };
    load_new_wallet(&state, &token, seed, tip, false).await?;
    Ok(Json(CreateResp {
        address,
        seed_hex: hex(&seed),
        network: state.network.clone(),
        warning: "Write this seed down and keep it offline. Anyone with it controls these funds. Shown once.".into(),
    }))
}

#[derive(Deserialize)]
struct ImportReq {
    seed_hex: String,
    /// Optional wallet birthday (block height). Start the display scan here instead
    /// of genesis to sync fast; omit / 0 to scan the whole chain for old funds.
    #[serde(default)]
    birthday: u64,
}

async fn wallet_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ImportReq>,
) -> Result<Json<CreateResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let bytes = unhex(&req.seed_hex).ok_or_else(|| err(StatusCode::BAD_REQUEST, "seed_hex is not valid hex"))?;
    if bytes.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "seed must be exactly 32 bytes (64 hex chars)"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let address =
        state.address_for_seed(&seed).ok_or_else(|| err(StatusCode::BAD_REQUEST, "seed is not a valid Orchard spending key"))?;
    load_new_wallet(&state, &token, seed, req.birthday, true).await?;
    Ok(Json(CreateResp {
        address,
        seed_hex: req.seed_hex,
        network: state.network.clone(),
        warning: "Wallet imported. Keep your seed offline.".into(),
    }))
}

/// Persist a new seed for a token and (re)load it into memory, replacing any prior.
/// `birthday` is the block height the display scan starts from (0 = from genesis).
/// `adopt_twin`: for an IMPORTED seed, allow cloning a same-key checkpoint another
/// token already scanned (a freshly created seed cannot have a twin).
async fn load_new_wallet(
    state: &Arc<AppState>,
    token: &str,
    seed: [u8; 32],
    birthday: u64,
    adopt_twin: bool,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let key = WalletKey::Seed(seed);
    save_seed(&state.wallet_dir, token, &state.network, &seed, birthday, state.wallet_secret.as_deref())
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Drop any prior scan checkpoint: a (re)imported seed must rescan from its own
    // birthday, not resume a different wallet's stream. That includes quarantined copies,
    // which `restore_quarantined` would otherwise bring back on the next load.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, token));
    retire_quarantine_copies(&state.wallet_dir, token);
    // Same-wallet-on-another-device fast path (see wallet_watch): a re-imported seed
    // whose viewing key some other token already scanned resumes from that
    // checkpoint instead of rescanning history the daemon already walked.
    if adopt_twin {
        if let Some(fvk) = key.fvk_bytes() {
            // A freshly written seed wallet starts with history OFF (save_seed), so any twin qualifies.
            if let Some((donor, keep_birthday)) = state.adopt_twin(token, &fvk, birthday, false).await {
                if keep_birthday != birthday {
                    save_seed(&state.wallet_dir, token, &state.network, &seed, keep_birthday, state.wallet_secret.as_deref())
                        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
                }
                state.wallets.lock().await.remove(token);
                if state.get_wallet(token).await.is_some() {
                    state.index_fvk(token, &key).await;
                    log::info!(
                        "imported wallet for token {token}: adopted checkpoint from twin token {donor} (birthday {keep_birthday})"
                    );
                    return Ok(());
                }
                // The clone failed to load — fall back to the honest scan from the
                // REQUESTED birthday (restore it if the adoption lowered it).
                let _ = std::fs::remove_file(scan_path(&state.wallet_dir, token));
                if keep_birthday != birthday {
                    save_seed(&state.wallet_dir, token, &state.network, &seed, birthday, state.wallet_secret.as_deref())
                        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
                }
            }
        }
    }
    // Fast-sync from the node's frontier when the wallet is born after the
    // checkpoint (complete by construction); otherwise the pruning-point full scan.
    // History starts OFF (opt-in) — must match what `save_seed` just wrote, or
    // the in-memory entry records rows the user never consented to.
    let entry = match state.fast_sync_entry(key, false, state.genesis, birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(key, false, state.genesis, birthday)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.to_string(), Arc::new(Mutex::new(entry)));
    state.index_fvk(token, &key).await;
    Ok(())
}

#[derive(Serialize)]
struct AddressResp {
    address: String,
    /// Diversifier index this address was derived at (0 = the wallet's default address).
    index: u32,
}

/// `?index=N` selects the wallet's N-th diversified address. All of them pay into the same
/// wallet and are found by its one scan (trial decryption is keyed on the incoming viewing
/// key, not the diversifier); each received history row names the diversified address that
/// was paid. This is how a custodial service gives every customer a distinct deposit
/// address and attributes deposits by address instead of by memo. Omitted = 0, the address
/// this endpoint always returned.
#[derive(Deserialize, Default)]
struct AddressQuery {
    index: Option<u32>,
}

async fn wallet_address(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AddressQuery>,
) -> Result<Json<AddressResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let index = query.index.unwrap_or(0);
    let address = if index == 0 {
        state.address_of(&e.db)
    } else {
        String::from(&Address::new(state.prefix, Version::ShieldedOrchard, &e.db.address_bytes_at(index)))
    };
    Ok(Json(AddressResp { address, index }))
}

#[derive(Serialize)]
struct RevealResp {
    address: String,
    seed_hex: String,
    network: String,
}

/// Return the wallet's recovery seed. On the hosted daemon the server already
/// holds the seed (hot-wallet model), so this discloses nothing new to the host;
/// it lets the owning browser (identified by its wallet token) back up or export
/// the phrase at any time — not just once at creation.
async fn wallet_reveal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RevealResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let address = state.address_of(&e.db);
    let seed = e.key.seed()?;
    Ok(Json(RevealResp { address, seed_hex: hex(&seed), network: state.network.clone() }))
}

#[derive(Deserialize)]
struct WatchReq {
    /// 96-byte full viewing key (hex), derived on the device from a seed the daemon
    /// never sees.
    fvk_hex: String,
    /// Birth DAA score. A wallet generated on-device right now is born at the tip and
    /// needs no historical scan; 0 means "may hold funds from any height" → full scan.
    #[serde(default)]
    birthday: u64,
    /// Record chain history (own sends' recipient/amount/memo via the OVK) from the
    /// first scan. Unset keeps the wallet's existing setting (a fresh wallet: OFF,
    /// opt-in). A view-key import sets this: the caller imported a full viewing key
    /// precisely to SEE the wallet, and the key already lets this daemon decrypt
    /// everything, so recording rows adds no disclosure.
    #[serde(default)]
    recoverable_history: Option<bool>,
}

/// Register a **watch-only** wallet for this token: the daemon syncs it, shows its
/// balance and builds spend *proofs* for it, but never holds spend authority. This is
/// the non-custodial (mobile) registration path — the device keeps the seed, sends only
/// the viewing key, and signs every spend itself via `/prepare` + `/submit`.
///
/// A daemon compromise then leaks *visibility* into these wallets, never their coins.
async fn wallet_watch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WatchReq>,
) -> Result<Json<AddressResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let fvk = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;
    let key = WalletKey::Fvk(fvk);
    let db = key.empty_db().ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?;
    let address = state.address_of(&db);

    // If this EXACT key is already registered under this token and has a resumable
    // checkpoint, a reconnect must NOT discard it and fast-sync from the client-supplied
    // birthday. A browser reconnecting after a daemon restart re-registers with
    // birthday ≈ tip; trusting that would skip the blocks where the wallet actually
    // received funds and show a ZERO balance for coins it still holds (live incident
    // 2026-07-16: a restart→re-register set birthday to the tip and the wallet's real note
    // sat in the skipped window). Resume the existing checkpoint instead, and never let the
    // persisted birthday move forward (min with the old value) so a later cold load can't
    // skip those notes either. Only a genuinely new/changed key, or a missing checkpoint,
    // takes the rescan-from-birthday path below.
    let existing = load_wallet_meta(&state.wallet_dir, &token, state.wallet_secret.as_deref());
    let same_key = matches!(&existing, Some((WalletKey::Fvk(f), _, _)) if *f == fvk);
    // An explicit request wins; otherwise keep what the wallet already had (OFF for a
    // brand-new wallet — history stays opt-in unless the caller asks for it).
    let existing_history = existing.as_ref().map(|(_, _, h)| *h).unwrap_or(false);
    let history = req.recoverable_history.unwrap_or(existing_history);
    // No live checkpoint but a quarantined copy of this key's own scan that the node
    // serves again (the app re-registers right after a chain-source switch is reverted):
    // bring it back NOW, before the fast-sync path below installs a resident entry that
    // would scan from the birthday until the next reload found the copy.
    let has_checkpoint = checkpoint_cursor(&state.wallet_dir, &token, &state.genesis).is_some()
        || (same_key && state.restore_quarantined(&token, key, &state.genesis, 0).await.is_some());
    // A re-registration of the SAME key carrying birthday 0 is a client with no opinion
    // (the app sends 0 whenever it has no birthday stored — after a service switch,
    // re-pair or repair), not a request to widen the view. Taking `min` with it persisted
    // 0, so the next quarantine or retirement rebuilt from genesis (seven of one user's
    // eight registrations on the hosted daemon carried 0). An explicit genesis rescan
    // remains available through `/rescan`, which sets the birthday deliberately.
    let stored_birthday = existing.as_ref().map(|(_, b, _)| *b).unwrap_or(0);
    let req_birthday = if same_key && req.birthday == 0 && stored_birthday != 0 { stored_birthday } else { req.birthday };
    if same_key && has_checkpoint {
        let keep_birthday = stored_birthday.min(req_birthday);
        save_fvk(&state.wallet_dir, &token, &state.network, &fvk, keep_birthday, history)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
        // Evict any stale in-RAM entry so the next load resumes from the preserved checkpoint.
        state.wallets.lock().await.remove(&token);
        state
            .get_wallet(&token)
            .await
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to resume wallet from checkpoint"))?;
        log::info!("re-registered watch-only wallet for token {token}: resumed from checkpoint (birthday kept {keep_birthday})");
        return Ok(Json(AddressResp { address, index: 0 }));
    }

    // A new or changed key must not resume a DIFFERENT key's checkpoint stream — nor
    // have one restored from a quarantined copy on the next load. The same key
    // re-registering while its own checkpoint sits in quarantine keeps those copies:
    // that is the case `restore_quarantined` exists for.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
    if !same_key {
        retire_quarantine_copies(&state.wallet_dir, &token);
    }
    // Same-wallet-on-another-device fast path: if any other token here has already
    // scanned this exact viewing key, clone its checkpoint — the second device is
    // synced immediately instead of rescanning history the daemon already walked.
    if let Some((donor, keep_birthday)) = state.adopt_twin(&token, &fvk, req_birthday, history).await {
        save_fvk(&state.wallet_dir, &token, &state.network, &fvk, keep_birthday, history)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
        state.wallets.lock().await.remove(&token);
        if state.get_wallet(&token).await.is_some() {
            state.index_fvk(&token, &key).await;
            log::info!(
                "registered watch-only wallet for token {token}: adopted checkpoint from twin token {donor} (birthday {keep_birthday})"
            );
            return Ok(Json(AddressResp { address, index: 0 }));
        }
        // The clone failed to load (corrupt donor file, node hiccup) — scan honestly.
        let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
    }
    save_fvk(&state.wallet_dir, &token, &state.network, &fvk, req_birthday, history)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Matches what `save_fvk` just wrote: opt-in unless the caller asked for history.
    let entry = match state.fast_sync_entry(key, history, state.genesis, req_birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(key, history, state.genesis, req_birthday)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.clone(), Arc::new(Mutex::new(entry)));
    state.index_fvk(&token, &WalletKey::Fvk(fvk)).await;
    log::info!("registered watch-only wallet for token {token} (birthday {req_birthday}, requested {})", req.birthday);
    Ok(Json(AddressResp { address, index: 0 }))
}

#[derive(Serialize)]
struct BalanceResp {
    balance_sompi: String,
    balance_fc: String,
    synced: bool,
    missing_history: bool,
    scanned_blocks: usize,
    chain_len: u64,
    /// Every owned note, **only when asked for** (`?notes=1`).
    ///
    /// This used to be unconditional, and it is the most frequently polled
    /// endpoint in the product. On a miner/pool wallet that is ~273 K entries —
    /// about **11 MB per poll** — serialised while holding the wallet lock, so
    /// the cost lands on both the client and every other request for that
    /// wallet. Nothing consumed it: the web wallet declares the field in its
    /// API type and never reads it, the SDK does not reference it, and the
    /// mobile bundle uses `note_count` from `/api/status` instead. A balance
    /// call should answer "how much do I have", and `note_count` already
    /// carries the only part of this a UI actually shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<Vec<NoteInfo>>,
    /// How many owned notes there are — the part callers actually used the
    /// `notes` array for. Always present, and O(1).
    note_count: usize,
    updated_unix: u64,
    error: Option<String>,
}

/// `?notes=1` restores the full per-note array for a caller that genuinely
/// needs it (consolidation planning, support tooling).
#[derive(Deserialize, Default)]
struct BalanceQuery {
    notes: Option<String>,
}

async fn wallet_balance(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BalanceQuery>,
    headers: HeaderMap,
) -> Result<Json<BalanceResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let want_notes = matches!(query.notes.as_deref(), Some("1" | "true" | "yes"));
    let note_count = e.db.notes().len();
    let notes = want_notes.then(|| e.db.notes().iter().map(|n| NoteInfo { position: n.position, value: n.value() }).collect());
    Ok(Json(BalanceResp {
        balance_sompi: e.db.balance().to_string(),
        balance_fc: fmt_fc(e.db.balance()),
        // Same `tip > 0` guard `status` carries: an unknown tip is NOT evidence of being
        // synced. Without it, `scanned + margin >= 0` is trivially true and a wallet that
        // has not yet been swept (or was swept on a pass whose dag-info timed out) reports
        // a partial balance as final — the shape every "my coins vanished" report takes.
        synced: e.chain_len > 0 && e.blind_below == 0 && (e.caught_up || (e.scanned as u64) + SYNC_MARGIN >= e.chain_len),
        // Why `synced` can be false on a caught-up wallet: the serving node could not
        // provide the wallet's history from its birthday, so this balance is partial.
        missing_history: e.blind_below > 0,
        scanned_blocks: e.scanned,
        chain_len: e.chain_len,
        notes,
        note_count,
        updated_unix: e.updated_unix,
        error: e.error.clone(),
    }))
}

#[derive(Deserialize)]
struct SendReq {
    to: String,
    amount_sompi: Option<u64>,
    amount_fc: Option<f64>,
    fee: Option<u64>,
    /// Optional memo (max 512 bytes UTF-8) carried inside the recipient's
    /// encrypted note — readable only by them (and, with recoverable history,
    /// by this wallet's own OVK).
    memo: Option<String>,
}

#[derive(Serialize)]
struct SendResp {
    /// First transaction id (kept for callers that expect a single txid).
    txid: String,
    amount_sompi: u64,
    /// Total fees paid across all transactions.
    fee_sompi: u64,
    /// Exact decimal forms for clients whose number type cannot represent u64.
    amount_sompi_exact: String,
    fee_sompi_exact: String,
    /// Every transaction id: a large send is split across several
    /// standard-size transactions (at most [`max_spends_per_tx`] spends each).
    txids: Vec<String>,
    tx_count: usize,
}

/// Greedy chunk planning over **value-descending** candidate notes: each
/// transaction spends at most `max_per` notes and pays `min(remaining,
/// chunk_sum − fee)` to the recipient, until `amount` is covered. The fee is
/// **byte-proportional per chunk** (`chunk_fee`): the node's minimum relay fee
/// grows with the number of spends, so a flat fee that clears a 1-spend tx is
/// rejected for a 5-spend one. Returns the per-chunk `(note_count, pay, fee)`
/// plan, or `None` if the notes run out (insufficient funds once per-tx fees
/// are accounted).
fn plan_chunks(values: &[u64], amount: u64, base_fee: u64, max_per: usize) -> Option<Vec<(usize, u64, u64)>> {
    let plan = plan_payment(values.to_vec(), amount, base_fee, max_per).ok()?;
    Some(plan.chunks.into_iter().map(|chunk| (chunk.note_range.len(), chunk.amount, chunk.fee)).collect())
}

/// The wallet's chain-derived transaction history, newest first.
///
/// Rows are recorded by the sync loop as blocks are ingested (received amounts via
/// IVK trial decryption, spends via our nullifiers, recipients/memos of our own
/// sends via the OVK when `recoverableHistory` is on) and persisted in the scan
/// checkpoint, so they survive restarts — and, for OVK sends, a seed restore.
#[derive(Deserialize, Default)]
struct HistoryQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn wallet_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let history_page = query.limit.unwrap_or(500).clamp(1, 5_000);
    let offset = query.offset.unwrap_or(0);
    let rows: Vec<serde_json::Value> =
        e.db.history()
            .iter()
            .rev()
            .skip(offset)
            .take(history_page)
            .map(|h| {
                serde_json::json!({
                    "kind": match h.kind {
                        HistoryKind::Coinbase => "coinbase",
                        HistoryKind::Received => "received",
                        HistoryKind::Sent => "sent",
                    },
                    "txid": hex(&h.txid),
                    "daaScore": h.daa_score,
                    "timestamp": h.timestamp_ms,
                    "amountSompi": h.amount,
                    "amountSompiExact": h.amount.to_string(),
                    "amountZkas": h.amount as f64 / SOMPI_PER_ZKAS as f64,
                    "amountKind": if h.amount_is_net_outflow { "netOutflow" } else { "paid" },
                    "feeSompi": h.fee,
                    "feeSompiExact": h.fee.to_string(),
                    "feeKnown": h.fee_known,
                    "recipient": h.recipient.map(|r| String::from(&Address::new(state.prefix, Version::ShieldedOrchard, &r))),
                    "memo": (!h.memo.is_empty()).then(|| String::from_utf8_lossy(&h.memo).into_owned()),
                })
            })
            .collect();
    // Spends submitted from this daemon but not yet observed on-chain — surfaced
    // so "where did my money go" is answerable while a send is in flight (the
    // notes come back automatically if the tx is lost; see `reclaim_expired`).
    let pending: Vec<serde_json::Value> =
        e.db.pending_spends()
            .iter()
            .map(|p| {
                serde_json::json!({
                    "txid": hex(&p.txid),
                    "amountSompi": p.note.value(),
                    "amountZkas": p.note.value() as f64 / SOMPI_PER_ZKAS as f64,
                    "submittedDaa": p.submitted_daa,
                })
            })
            .collect();
    Ok(Json(serde_json::json!({
        "recoverableHistory": e.recoverable_history,
        "total": e.db.history().len(),
        "offset": offset,
        "limit": history_page,
        "rows": rows,
        "pendingOutgoing": pending,
    })))
}

#[derive(Deserialize)]
struct SettingsReq {
    /// Toggle OVK-recoverable send history for this wallet (see `WalletFile`).
    recoverable_history: Option<bool>,
}

async fn wallet_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let bytes = std::fs::read(wallet_path(&state.wallet_dir, &token)).map_err(|_| err(StatusCode::NOT_FOUND, "no such wallet"))?;
    let mut wf: WalletFile =
        serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt wallet file"))?;
    if let Some(v) = req.recoverable_history {
        wf.recoverable_history = v;
    }
    write_wallet_file(&state.wallet_dir, &token, &wf)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Keep a loaded entry in step so the next send honours the change immediately.
    // The same flag gates history-row recording: turning it OFF also purges the
    // rows already recorded (withdrawing consent removes the readable record).
    if let Some(w) = state.cached_wallet(&token).await {
        let mut e = w.lock().await;
        e.recoverable_history = wf.recoverable_history;
        e.db.set_history_enabled(wf.recoverable_history);
        e.force_checkpoint = true; // persist the purge/enable promptly
    }
    Ok(Json(serde_json::json!({ "recoverableHistory": wf.recoverable_history })))
}

/// Retire this wallet's scan checkpoint and reload it from its birthday — a full
/// re-derivation of the wallet from the chain itself. Two jobs: BACKFILL history
/// rows after the user enables history (rows are only recorded while blocks are
/// scanned), and RECOVER anything the incremental view ever lost (e.g. notes
/// deleted by the pre-v7 submit-and-forget spend bug — the "my ZKAS vanished"
/// report). Bounded work: birthday fast-sync + a scan of blocks since birthday.
#[derive(Deserialize, Default)]
struct RescanReq {
    /// Accept losing notes the node can no longer serve. Without it, a rescan that
    /// would forget anything is refused with the exact damage it would do.
    #[serde(default)]
    force: bool,
    /// DAA height to scan from. Omitted (or 0) means genesis — correct, and slow: a
    /// full replay of this chain is millions of leaves. A caller that knows when the
    /// wallet was created can start there instead.
    #[serde(default)]
    birthday: Option<u64>,
}

async fn wallet_rescan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RescanReq>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    if !wallet_exists(&state.wallet_dir, &token) {
        return Err(err(StatusCode::NOT_FOUND, "no such wallet"));
    }
    // A rescan rebuilds the wallet from whatever the node can serve, so it is only
    // lossless if the node can serve GENESIS. The previous version of this guard
    // assumed `--archival` guaranteed that; it does not — archival stops deletion
    // but the pruning point still advances, and on 2026-07-28 a user rescanned
    // against an archival node whose pruning point had reached DAA 43,248 and lost
    // 18,354 ZKAS of notes minted below it. So: probe the node for genesis, and if
    // it cannot answer, refuse rather than quietly amputate the wallet.
    let force = body.as_ref().map(|b| b.force).unwrap_or(false);
    if !force {
        let serves_genesis = matches!(
            match state.request_client().await {
                Some(c) => c.get_shielded_tree_state(Some(state.genesis)).await,
                None => Err(kaspa_rpc_core::RpcError::General("node unavailable".into())),
            },
            Ok(ts) if ts.block_hash == state.genesis
        );
        if !serves_genesis {
            let node = state.request_client().await;
            let pp = match &node {
                Some(c) => c.get_block_dag_info().await.ok().map(|d| d.pruning_point_hash),
                None => None,
            };
            let below = match (&node, pp) {
                (Some(c), Some(pp)) => c.get_shielded_tree_state(Some(pp)).await.ok().map(|ts| (ts.daa_score, ts.size)),
                _ => None,
            };
            let detail = match below {
                Some((daa, size)) => format!(
                    "this node cannot serve the chain from genesis — its history starts at the pruning point \
                     (DAA {daa}, tree position {size}). Rescanning against it would permanently drop every note \
                     your wallet holds from below that point"
                ),
                None => "this node cannot serve the chain from genesis, so a rescan would drop older notes".to_string(),
            };
            return Err(err(
                StatusCode::CONFLICT,
                format!(
                    "rescan refused: {detail}. Point the wallet at an archival node and try again, or pass force=true to rescan anyway and accept the loss."
                ),
            ));
        }
    }
    // A rescan is the "find my funds" action, so it must not trust the birthday the
    // wallet already has — fast-syncing from one set later than the wallet's real
    // notes skips those blocks and the balance comes back ZERO.
    //
    // The CALLER may supply one, and that is a different matter: it is a deliberate
    // statement about when this wallet started existing, made by someone who knows.
    // Genesis remains the default and the only safe assumption in the absence of
    // that knowledge, but it replays millions of leaves, so a user who remembers
    // roughly when they made the wallet should not have to wait for years of chain
    // they were never part of.
    let from = body.as_ref().and_then(|b| b.birthday).unwrap_or(0);
    match set_wallet_birthday(&state.wallet_dir, &token, from) {
        Ok(()) if from == 0 => log::info!("wallet '{token}': rescan from genesis (no birthday given)"),
        Ok(()) => log::info!("wallet '{token}': rescan from DAA {from} — the caller supplied a birthday"),
        Err(e) => log::warn!("wallet '{token}': could not set birthday for rescan ({e}); reload uses stored birthday"),
    }
    // Poison any in-flight sync pass first: checkpoint writes are gated on
    // `error.is_none()`, so this stops a concurrent pass from re-persisting the
    // old cursor after we retire it below.
    if let Some(w) = state.cached_wallet(&token).await {
        w.lock().await.error = Some("rescanning from birthday".into());
    }
    state.wallets.lock().await.remove(&token);
    let scan = scan_path(&state.wallet_dir, &token);
    let _ = std::fs::rename(&scan, format!("{scan}.bak"));
    // A deliberate rescan must not be undone by `restore_quarantined` on the next load.
    retire_quarantine_copies(&state.wallet_dir, &token);
    log::info!("wallet '{token}': rescan requested — checkpoint retired, will reload from birthday");
    // Return NOW. Reloading a wallet means a fast-sync anchor fetch and a scan
    // from birthday; doing that inline would hold the request open for minutes and
    // starve the HTTP path (the 2026-07-12 "wallet won't connect" outage). The
    // next status/balance poll — or the background sync loop — reloads it lazily.
    Ok(Json(serde_json::json!({ "rescanning": true })))
}

/// Pack an optional UTF-8 memo into the fixed 512-byte Orchard memo field.
fn memo_bytes(m: Option<&str>) -> Result<[u8; 512], (StatusCode, Json<serde_json::Value>)> {
    let mut out = [0u8; 512];
    if let Some(m) = m {
        let b = m.as_bytes();
        if b.len() > 512 {
            return Err(err(StatusCode::BAD_REQUEST, "memo too long (max 512 bytes)"));
        }
        out[..b.len()].copy_from_slice(b);
    }
    Ok(out)
}

/// Matured spend candidates for a wallet, EXCLUDING stranded notes — notes whose
/// leaves were compacted away with no surviving witness (the note@564934
/// incident: pending-spend → base compaction → reclaim left a note below the
/// base). A stranded note can never produce a witness path from local state, so
/// including it fails the entire payment with "matured note has no witness path"
/// even though every other note is spendable. Selection skips them; their value
/// is returned so error messages can be honest about funds that exist on-chain
/// but need a state graft (`--graft`) to spend. Unsorted — callers order.
fn matured_candidates(db: &WalletDb, matured: u64) -> (Vec<&OwnedNote>, u64) {
    let stranded = db.stranded_notes();
    let stranded_value: u64 = stranded.iter().map(|n| n.value()).sum();
    if stranded_value > 0 {
        log::warn!(
            "spend selection: skipping {} stranded note(s) worth {} sompi (below base {}, no witness) — recoverable only by grafting older wallet state",
            stranded.len(),
            stranded_value,
            db.base_size(),
        );
    }
    let skip: HashSet<u64> = stranded.iter().map(|n| n.position).collect();
    let candidates = db.notes().iter().filter(|n| n.position < matured && !skip.contains(&n.position)).collect();
    (candidates, stranded_value)
}

/// One line of honesty appended to "insufficient funds" errors when part of the
/// wallet's balance is stranded (see [`matured_candidates`]).
fn stranded_hint(stranded_value: u64) -> String {
    if stranded_value == 0 {
        String::new()
    } else {
        format!(
            "; note: {} ZKAS of this wallet is temporarily unspendable (stranded by an old state bug — contact support to recover it)",
            fmt_fc(stranded_value as u128)
        )
    }
}

/// Prove that a loaded wallet's commitment tree is exactly the node's canonical
/// tree at the wallet cursor. Height/freshness alone cannot establish this: a
/// legacy checkpoint may be near-tip yet contain bundles consensus dropped.
async fn ensure_canonical_checkpoint(state: &Arc<AppState>, w: &Wallet) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // A borrowing wallet's mirror tree is stale until it adopts the shared tree's
    // frontier, and `anchor()` is meaningless until then. Comparing a stale anchor
    // against the node would report a divergence that does not exist and retire a
    // perfectly good checkpoint — turning an optimisation into data loss. So: make it
    // valid first, and if that is not possible, say "retry" rather than "diverged".
    //
    // One attempt is not enough, and this was a live bug. A borrowing wallet clears
    // `tree_valid` on EVERY appended leaf, so on a 1-block/s chain it is invalid nearly
    // all the time, and `adopt_tip_frontier` refuses unless the shared tree's frontier
    // is at EXACTLY this wallet's leaf count. The two advance from the same block
    // stream, so they are equal between passes and unequal mid-flight — meaning a
    // perfectly healthy, fully synced wallet failed here whenever the user happened to
    // press the button while the sizes differed by a few leaves. `synced` additionally
    // tolerates a 200-block margin, so the UI could legitimately read "Ready" at that
    // instant. The result was a wallet that said Ready and then answered "still
    // catching up" on the very next tap, which is what users reported.
    //
    // The gap closes on its own within a sync pass, so wait for it instead of telling
    // the user to retry something the daemon can simply do itself.
    // Ask FIRST whether this wallet needs the wait at all.
    //
    // A borrowing wallet has no mirror tree of its own: its anchor IS the shared tree's,
    // and the block below forgives it explicitly. But that forgiveness sat AFTER the wait
    // loop, so the common healthy case burned the entire adoption budget and was then
    // told it never needed to. With that budget at 28s, every send from a borrowing
    // wallet paid ~28 seconds of pure waiting before any work began — invisible in the
    // log, because the first line is only written once the wait is over. Measured against
    // it: the daemon's own prepare→submit span was ~4s while users timed the whole
    // payment at ~45s, three times running.
    //
    // Waiting for a borrowing wallet's mirror to become valid is waiting for something
    // the spend path does not require.
    if w.lock().await.db.is_borrowing() {
        return Ok(());
    }
    {
        let deadline = std::time::Instant::now() + CHECKPOINT_ADOPT_WAIT;
        loop {
            if w.lock().await.db.tree_is_valid() {
                break;
            }
            let fs = state.chain_tree.lock().await.db.tip_frontier_state();
            if let Some(fs) = fs {
                // Refused only on a size mismatch, which is transient by construction.
                if w.lock().await.db.adopt_tip_frontier(&fs) {
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
    }
    let (cursor, wallet_size, wallet_anchor) = {
        let e = w.lock().await;
        if !e.db.tree_is_valid() {
            // A BORROWING wallet has no tree of its own to check.
            //
            // `borrow_tree` invalidates its mirror on the very next leaf, and validity
            // returns only by adopting the shared frontier at EXACTLY this wallet's
            // size — an alignment that exists between sync passes and not during them.
            // So on a one-block-per-second chain this is the resting state, not a
            // fault, and refusing here made a four-second race decide whether a fully
            // synced wallet was allowed to pay. Users saw "Ready", tapped Send, and
            // were told the wallet was still catching up.
            //
            // Worse, the anchor being demanded is the shared tree's frontier: for a
            // borrower this check compares the SHARED tree to the node, once per
            // payment, per wallet. That is a property of the shared tree, and it
            // belongs in one background place rather than on everybody's spend path.
            //
            // Skipping costs nothing the spend relies on. Every witness path handed to
            // a payment is verified to root at `matured` by `subtree_paths` before it
            // is used, so a tree that had diverged declines rather than lying, and a
            // cursor that has left the selected chain is caught by the sync loop's own
            // reorg strikes. What is genuinely being given up is divergence detection
            // for a wallet's PERSISTED checkpoint — which only has meaning for a wallet
            // that maintains its own tree, and those still get the full check below.
            if e.db.is_borrowing() {
                log::debug!(
                    "checkpoint canonicality skipped for a borrowing wallet (size {}): its anchor is the shared tree's",
                    e.db.size()
                );
                return Ok(());
            }
            // Logged because this is the one refusal a user meets mid-payment, and it
            // left no trace at all — a report of "it said Ready then refused" was not
            // findable in the log, which is why it survived so long.
            log::warn!(
                "prepare refused: wallet tree is not valid and it is not borrowing (size {}, low {}) — the status card should not have offered this send",
                e.db.size(),
                e.low
            );
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "wallet is still catching up with the shared chain state; retry in a moment",
            ));
        }
        (e.low, e.db.size(), e.db.anchor())
    };
    let node = state
        .request_client()
        .await
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node right now; retry shortly"))?;
    let ts = tokio::time::timeout(SYNC_RPC_TIMEOUT, node.get_shielded_tree_state(Some(cursor)))
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "node timed out while validating the wallet checkpoint; retry"))?
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("cannot validate wallet checkpoint: {e}")))?;
    let fs = FrontierState {
        size: ts.size,
        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
        ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
    };
    let node_anchor = GlobalTree::from_state(&fs)
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "node returned an invalid shielded frontier"))?
        .anchor()
        .to_bytes();
    if wallet_size != fs.size || wallet_anchor != node_anchor {
        let mut e = w.lock().await;
        e.reorged_strikes = REORG_STRIKES;
        e.error = Some("wallet checkpoint diverged from canonical shielded state; repairing from chain".into());
        log::error!(
            "wallet checkpoint divergence at {cursor}: wallet size/root {}/{}, node size/root {}/{}; marked for repair",
            wallet_size,
            hex(&wallet_anchor),
            fs.size,
            hex(&node_anchor),
        );
        return Err(err(
            StatusCode::CONFLICT,
            "wallet checkpoint was created by an older broken sync path and differs from canonical chain state; automatic repair started—wait for sync before sending",
        ));
    }
    Ok(())
}

async fn wallet_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    ensure_canonical_checkpoint(&state, &w).await?;
    // Don't select notes a background merge is already proving over, and — for as long
    // as this send runs — keep background CPU work (merges, cache builds) off the box.
    await_consolidation_clear().await;
    let _proving = ProvingGuard::new();
    let (seed, recoverable) = {
        let e = w.lock().await;
        // A send roots at the MATURED anchor (>= DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK blue
        // below the sink), which by construction already trails the live tip. Whether the
        // wallet's scan cursor has closed the entire gap to the tip is irrelevant to that
        // anchor's validity, so gate on (a) a matured anchor being available and (b) no
        // in-progress reorg repair — NOT on scanned-vs-tip. The old tip-proximity test
        // (scanned + 264 < node_tip) spuriously 409'd note-heavy / busy payout wallets:
        // they legitimately trail the tip by more than that while a slow spend is in
        // flight, yet every note they would spend is already matured and spendable.
        // `ensure_canonical_checkpoint` above still rejects a genuinely divergent tree.
        if e.reorged_strikes > 0 {
            return Err(err(StatusCode::CONFLICT, "wallet checkpoint is being repaired after a reorg; retry shortly"));
        }
        if e.matured_leaves().is_none() {
            return Err(err(
                StatusCode::CONFLICT,
                format!("wallet has not established a matured anchor yet (scanned DAA {}); wait for initial sync", e.scanned),
            ));
        }
        (e.key.seed()?, e.recoverable_history)
    };
    let memo = memo_bytes(req.memo.as_deref())?;

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    // Floor fee: plan_chunks raises each chunk's fee to the node's
    // byte-proportional minimum for however many notes that chunk spends.
    let fee = req.fee.unwrap_or(DEFAULT_FEE_SOMPI);

let client = state.request_client().await.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node right now; retry shortly"))?;
    let client = &client;
    // The shielded sighash network domain: the GENESIS hash — what consensus
    // verifies signatures against (`params.genesis.hash`). The moving pruning
    // point only coincides with it on a young, unpruned chain.
    let net: [u8; 32] = state.genesis.as_bytes();

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;

    if amount == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "amount must be positive"));
    }
    let max_per_tx = max_spends_per_tx();
    let insufficient = |have: u64, stranded: u64| {
        err(
            StatusCode::CONFLICT,
            format!(
                "insufficient matured funds: have {have}, need {need}+ (amount {amount} + a {fee} fee per tx; funds must be ~10 min old to spend){}",
                stranded_hint(stranded)
            ),
        )
    };

    // Gather ALL matured candidates and plan the transactions. A standard tx fits
    // at most `max_per_tx` spends (transient-mass cap), so a large send is split
    // into several transactions, each paying part of the amount. Everything —
    // candidates, plan, witnesses — is materialized before any proving starts, so
    // an over-cap or underfunded request fails in milliseconds, not after a
    // multi-minute (or, live, 106-minute) proof.
    //
    // Fast path: reuse the wallet state the sync loop already maintains, rooting
    // each spend at the newest chain-block boundary at least `anchor_depth +
    // slack` blue units below the sink — a matured, canonical chain-block root
    // consensus accepts (`is_shielded_anchor_final`; maturity is measured in blue
    // score). The entry lock is held only for selection + witness building.
    let mut planned: Option<(Vec<(Vec<_>, u64, Vec<u64>, u64)>, u64, bool, u64)> = None;
    // A first send may need the wallet's subtree cache built: do that OFF the lock, on
    // every core, before taking it — see `build_send_cache_off_lock`.
    build_send_cache_off_lock(&state, &token, &w).await;
    {
        let mut e = w.lock().await;
        // Top up the live witnesses to the current matured anchor (a no-op unless a
        // block landed since the last sync tick), so witnessing below is a lookup.
        // block_in_place: this is CPU-bound Sinsemilla; run inline on the async
        // runtime it can capture the tokio I/O driver and freeze ALL of HTTP.
        let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
        let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
        tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded(shared_covers, shared_base));
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
            let (mut candidates, stranded_value) = matured_candidates(&e.db, matured);
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
            let have: u64 = values.iter().sum();
            match plan_chunks(&values, amount, fee, max_per_tx) {
                Some(plan) => {
                    // All notes the plan will spend are candidates[0..total]; witness them
                    // in ONE base→matured pass (O(chain + N·depth)) rather than a per-note
                    // O(chain) rebuild each, then distribute into chunks. A note the batch
                    // declines falls back to the exact per-note rebuild — never wrong.
                    let total: usize = plan.iter().map(|(n, _, _)| *n).sum();
                    let all_positions: Vec<u64> = candidates[..total].iter().map(|n| n.position).collect();
                    let batch_paths = tokio::task::block_in_place(|| state.batch_witness_paths(&e.db, &all_positions, matured));
                    let mut chunks = Vec::with_capacity(plan.len());
                    let mut idx = 0usize;
                    for (n_notes, pay, cfee) in plan {
                        let mut inputs = Vec::with_capacity(n_notes);
                        let mut positions = Vec::with_capacity(n_notes);
                        for (j, note) in candidates[idx..idx + n_notes].iter().enumerate() {
                            let path = match batch_paths[idx + j].clone() {
                                Some(p) => p,
                                // block_in_place: a cold note's on-demand rebuild is an
                                // O(chain) Sinsemilla replay — must not pin a runtime worker.
                                None => tokio::task::block_in_place(|| e.db.witness_path_at(note.position, matured))
                                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?,
                            };
                            inputs.push((note.note.clone(), path));
                            positions.push(note.position);
                        }
                        idx += n_notes;
                        chunks.push((inputs, pay, positions, cfee));
                    }
                    planned = Some((chunks, have, e.caught_up, stranded_value));
                }
                None => planned = Some((Vec::new(), have, e.caught_up, stranded_value)),
            }
        }
    }

    let chunks = match planned {
        // A complete plan at the wallet's own anchor — the fast, no-rescan path.
        Some((chunks, _, _, _)) if !chunks.is_empty() => chunks,
        // Planning failed but the wallet is caught up to the tip, so a full replay
        // would see the exact same matured notes: authoritative insufficient.
        Some((_, have, true, stranded)) => return Err(insufficient(have, stranded)),
        // Ring not filled yet (cold start) or wallet behind the tip: one-off matured
        // replay — correct, just slow, and transient until the sync loop catches up.
        _ => {
            log::warn!("send: fast path unavailable/insufficient; falling back to a matured chain replay (slow, one-off)");
            let fresh = WalletDb::from_seed(seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad seed"))?;
            let db = replay_matured(client, state.genesis, fresh).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let mut candidates = db.notes().to_vec();
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
            let have: u64 = values.iter().sum();
            let plan = plan_chunks(&values, amount, fee, max_per_tx).ok_or_else(|| insufficient(have, 0))?;
            // The replayed `db` roots witnesses at its tip; batch all selected notes in
            // one pass, per-note fallback for any the batch declines.
            let matured_tip = db.size();
            let total: usize = plan.iter().map(|(n, _, _)| *n).sum();
            let all_positions: Vec<u64> = candidates[..total].iter().map(|n| n.position).collect();
            let batch_paths = db.witness_paths_at(&all_positions, matured_tip);
            let mut chunks = Vec::with_capacity(plan.len());
            let mut idx = 0usize;
            for (n_notes, pay, cfee) in plan {
                let mut inputs = Vec::with_capacity(n_notes);
                let mut positions = Vec::with_capacity(n_notes);
                for (j, note) in candidates[idx..idx + n_notes].iter().enumerate() {
                    let path = match batch_paths[idx + j].clone() {
                        Some(p) => p,
                        None => db
                            .witness_path(note.position)
                            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?,
                    };
                    inputs.push((note.note.clone(), path));
                    positions.push(note.position);
                }
                idx += n_notes;
                chunks.push((inputs, pay, positions, cfee));
            }
            chunks
        }
    };

    // Prove + submit each chunk sequentially. Proving runs on a blocking thread so
    // the daemon (status/balance endpoints, other wallets) stays responsive; each
    // accepted chunk's notes are marked spent immediately so a concurrent or
    // follow-up send cannot re-select them before the scan loop observes the tx.
    let ctx = payment_tx_context();
    let tx_count = chunks.len();
    let mut txids: Vec<String> = Vec::with_capacity(tx_count);
    let mut sent = 0u64;
    let mut total_fee = 0u64;
    // Prove in groups rather than one at a time: see `PROOF_THREADS_EACH`. A group of
    // one keeps the global rayon pool (all cores), so an ordinary single-chunk send is
    // byte-for-byte the old path and never pays for this.
    let degree = proof_concurrency();
    if degree > 1 && tx_count > 1 {
        log::info!("send: proving {tx_count} txs {} at a time ({PROOF_THREADS_EACH} threads each)", degree.min(tx_count));
    }
    let mut pending = chunks;
    let mut ci = 0usize;
    while !pending.is_empty() {
        let take = degree.min(pending.len());
        let rest = pending.split_off(take);
        let group = std::mem::replace(&mut pending, rest);
        // One proof in the group means one proof on the box: give it every core.
        let threads_each = if group.len() > 1 { Some(PROOF_THREADS_EACH) } else { None };

        let mut proving = Vec::with_capacity(group.len());
        for (k, (inputs, pay, positions, cfee)) in group.into_iter().enumerate() {
            let idx = ci + k;
            log::info!(
                "send: building Orchard proof for tx {}/{tx_count} ({} spends, {pay} sompi + {cfee} fee)...",
                idx + 1,
                inputs.len()
            );
            let ctx2 = ctx.clone();
            // The memo rides on the first chunk only — one memo per logical payment.
            let chunk_memo = if idx == 0 { memo } else { [0u8; 512] };
            proving.push(tokio::task::spawn_blocking(move || {
                let _proving = ProvingGuard::new();
                let started = std::time::Instant::now();
                let build = || build_wallet_payment(seed, inputs, recipient, pay, cfee, &net, &ctx2, recoverable, chunk_memo);
                // A scoped pool bounds THIS proof's threads; halo2's rayon work nests
                // inside `install`, so the group shares the box instead of fighting for it.
                let built = match threads_each.map(|n| rayon::ThreadPoolBuilder::new().num_threads(n).build()) {
                    Some(Ok(pool)) => pool.install(build),
                    // No pool wanted, or the OS refused the threads: use the global pool.
                    _ => build(),
                };
                (idx, pay, positions, cfee, built, started.elapsed())
            }));
        }

        // Await the whole group, then submit strictly in order so a partial failure
        // reports exactly which prefix of the payment went through.
        let mut done = Vec::with_capacity(proving.len());
        for h in proving {
            done.push(h.await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?);
        }
        done.sort_by_key(|(idx, ..)| *idx);
        ci += done.len();

        for (idx, pay, positions, cfee, built, took) in done {
            let payload = built.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build payment: {e:?}")))?;
            log::info!("send: tx {}/{tx_count} proven in {:.0?}", idx + 1, took);

            let tx: Transaction = payment_tx(payload);
            match client.submit_transaction(RpcTransaction::from(&tx), false).await {
                Ok(accepted) => {
                    txids.push(accepted.to_string());
                    sent += pay;
                    total_fee += cfee;
                    let mut e = w.lock().await;
                    // The wallet's scan cursor is its chain clock — available whether or
                    // not the node serves block metadata, unlike WalletDb's own.
                    let now_daa = e.scanned as u64;
                    for p in positions {
                        e.db.mark_spent(p, accepted.as_bytes(), now_daa);
                    }
                    // Publish the change owed back (parked − pay − fee) so the balance
                    // does not read as if the whole input note were gone, and drop the
                    // cached mempool previews: one computed BEFORE the park classified
                    // this tx as `outgoing`, which would now double-subtract.
                    e.db.note_pending_outflow(accepted.as_bytes(), pay.saturating_add(cfee));
                    e.forget_stale_outflow_previews();
                }
                Err(e) if txids.is_empty() => return Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the payment: {e}"))),
                Err(e) => {
                    // Partial success: report what actually went through.
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({
                            "error": format!("payment partially sent: {}/{tx_count} txs accepted, then the node rejected: {e}", txids.len()),
                            "txids": txids,
                            "sent_sompi": sent,
                        })),
                    ));
                }
            }
        }
    }

    Ok(Json(SendResp {
        txid: txids[0].clone(),
        amount_sompi: amount,
        fee_sompi: total_fee,
        amount_sompi_exact: amount.to_string(),
        fee_sompi_exact: total_fee.to_string(),
        txids,
        tx_count,
    }))
}

/// One recipient of a batched payout.
#[derive(Deserialize)]
struct Payee {
    /// Recipient `zkas:` shielded address.
    to: String,
    /// Exact integer amount. Decimal strings preserve the full u64 range for
    /// JavaScript clients; numeric JSON remains accepted for compatibility.
    amount_sompi: Option<JsonU64>,
    amount_fc: Option<f64>,
    /// Optional memo, carried inside THIS payee's encrypted note only.
    memo: Option<String>,
}

#[derive(Deserialize)]
struct SendManyReq {
    payees: Vec<Payee>,
    /// Fee floor per transaction; raised to the node's byte-proportional minimum.
    fee: Option<JsonU64>,
}

#[derive(Serialize)]
struct SendManyResp {
    txids: Vec<String>,
    tx_count: usize,
    payees: usize,
    paid_sompi: u64,
    fee_sompi: u64,
    paid_sompi_exact: String,
    fee_sompi_exact: String,
}

/// Pay **many recipients in as few transactions as possible**.
///
/// The single-recipient [`wallet_send`] is the wrong shape for a payout run: a pool
/// crediting N miners pays N separate bundles, and each one carries its own Halo 2
/// proof, its own witness set and its own relay fee — serially. That is the 45-minute
/// payout. An Orchard bundle carries `max(spends, outputs)` actions, so one bundle can
/// hold `max_payees_per_tx()` recipients plus change; batching collapses the run to
/// `ceil(N / max_payees_per_tx())` proofs.
///
/// Selection happens ONCE, under a single lock, across all batches, so two batches can
/// never select the same note. Witnesses for every selected note are built in one pass.
/// Each batch is then proven and submitted in turn, marking its notes spent on
/// acceptance exactly as `wallet_send` does.
async fn wallet_send_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendManyReq>,
) -> Result<Json<SendManyResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    ensure_canonical_checkpoint(&state, &w).await?;
    // Same span guard as `wallet_send`: no merge selects the notes this batch is
    // about to spend, and no background CPU work runs while the batch is proving.
    await_consolidation_clear().await;
    let _proving = ProvingGuard::new();

    let (seed, recoverable) = {
        let e = w.lock().await;
        if e.reorged_strikes > 0 {
            return Err(err(StatusCode::CONFLICT, "wallet checkpoint is being repaired after a reorg; retry shortly"));
        }
        if e.matured_leaves().is_none() {
            return Err(err(
                StatusCode::CONFLICT,
                format!("wallet has not established a matured anchor yet (scanned DAA {}); wait for initial sync", e.scanned),
            ));
        }
        (e.key.seed()?, e.recoverable_history)
    };

    if req.payees.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "payees must not be empty"));
    }
    // Resolve every payee up front: one bad address fails the batch before any proving.
    let mut resolved: Vec<([u8; 43], u64, [u8; 512])> = Vec::with_capacity(req.payees.len());
    let mut requested: u64 = 0;
    for (i, p) in req.payees.iter().enumerate() {
        let amount = match (p.amount_sompi.as_ref(), p.amount_fc) {
            (Some(s), _) => s.parse("amount_sompi").map_err(|_| {
                err(StatusCode::BAD_REQUEST, format!("payee {i}: amount_sompi must be an unsigned 64-bit decimal integer"))
            })?,
            (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
            (None, None) => return Err(err(StatusCode::BAD_REQUEST, format!("payee {i}: specify amount_sompi or amount_fc"))),
        };
        if amount == 0 {
            return Err(err(StatusCode::BAD_REQUEST, format!("payee {i}: amount must be positive")));
        }
        let addr = Address::try_from(p.to.as_str())
            .map_err(|e| err(StatusCode::BAD_REQUEST, format!("payee {i}: invalid recipient address: {e}")))?;
        let recipient = orchard_recipient_bytes(&addr)
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("payee {i}: not a shielded Orchard address")))?;
        requested = requested.checked_add(amount).ok_or_else(|| err(StatusCode::BAD_REQUEST, "payee amounts overflow"))?;
        resolved.push((recipient, amount, memo_bytes(p.memo.as_deref())?));
    }

    let base_fee = match req.fee.as_ref() {
        Some(fee) => fee.parse("fee")?,
        None => DEFAULT_FEE_SOMPI,
    };
    let per_tx = max_payees_per_tx();
    let groups: Vec<Vec<([u8; 43], u64, [u8; 512])>> = resolved.chunks(per_tx).map(|c| c.to_vec()).collect();
    let net: [u8; 32] = state.genesis.as_bytes();
let client = state.request_client().await.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node right now; retry shortly"))?;
    let client = &client;

    // Select notes and build witnesses for EVERY group under one lock, so no note is
    // selected twice and all witnesses share one matured anchor.
    struct Batch {
        payees: Vec<([u8; 43], u64, [u8; 512])>,
        inputs: Vec<(kaspa_shielded_core::Note, kaspa_shielded_core::MerklePath)>,
        positions: Vec<u64>,
        fee: u64,
    }
    let mut batches: Vec<Batch> = Vec::with_capacity(groups.len());
    // As in `wallet_send`: any one-time subtree-cache build happens off the lock first.
    build_send_cache_off_lock(&state, &token, &w).await;
    {
        let mut e = w.lock().await;
        let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
        let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
        tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded(shared_covers, shared_base));
        let matured = e.matured_leaves().ok_or_else(|| err(StatusCode::CONFLICT, "wallet has no matured anchor yet"))?;
        let (mut candidates, stranded) = matured_candidates(&e.db, matured);
        candidates.sort_by(|a, b| b.value().cmp(&a.value()));
        let have: u64 = candidates.iter().map(|n| n.value()).sum();

        // Walk the groups, consuming value-descending notes as each is covered. The
        // per-tx fee is priced on the bundle's ACTION count — `max(spends, payees+1)` —
        // because that, not the spend count alone, is what the node charges mass for.
        let mut taken = 0usize;
        let mut plan: Vec<(usize, usize, u64)> = Vec::with_capacity(groups.len()); // (start, n_notes, fee)
        for g in &groups {
            let pay: u64 = g.iter().map(|(_, a, _)| *a).sum();
            let start = taken;
            let mut sum = 0u64;
            let mut fee = base_fee.max(min_relay_fee_for_actions(g.len() + 1));
            loop {
                let n = taken - start;
                if sum >= pay.saturating_add(fee) && n > 0 {
                    break;
                }
                if taken >= candidates.len() {
                    return Err(err(
                        StatusCode::CONFLICT,
                        format!(
                            "insufficient matured funds: have {have}, need {}+ across {} payees (funds must be ~10 min old to spend){}",
                            requested.saturating_add(fee),
                            resolved.len(),
                            stranded_hint(stranded)
                        ),
                    ));
                }
                if n >= max_spends_per_tx() {
                    return Err(err(
                        StatusCode::CONFLICT,
                        format!(
                            "a batch of {} payees needs more than {} note spends to cover {pay} sompi; split the payout or consolidate first",
                            g.len(),
                            max_spends_per_tx()
                        ),
                    ));
                }
                sum += candidates[taken].value();
                taken += 1;
                // Re-price: the fee floor grows with the action count.
                fee = base_fee.max(min_relay_fee_for_actions((taken - start).max(g.len() + 1)));
            }
            plan.push((start, taken - start, fee));
        }

        // One witness pass for every note across every batch.
        let all_positions: Vec<u64> = candidates[..taken].iter().map(|n| n.position).collect();
        let paths = tokio::task::block_in_place(|| state.batch_witness_paths(&e.db, &all_positions, matured));
        for (gi, (start, n_notes, fee)) in plan.into_iter().enumerate() {
            let mut inputs = Vec::with_capacity(n_notes);
            let mut positions = Vec::with_capacity(n_notes);
            for k in 0..n_notes {
                let note = &candidates[start + k];
                let path = match paths[start + k].clone() {
                    Some(p) => p,
                    None => tokio::task::block_in_place(|| e.db.witness_path_at(note.position, matured))
                        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?,
                };
                inputs.push((note.note.clone(), path));
                positions.push(note.position);
            }
            batches.push(Batch { payees: groups[gi].clone(), inputs, positions, fee });
        }
    }

    let ctx = payment_tx_context();
    let tx_count = batches.len();
    let mut txids: Vec<String> = Vec::with_capacity(tx_count);
    let mut paid = 0u64;
    let mut total_fee = 0u64;
    for (bi, b) in batches.into_iter().enumerate() {
        let group_pay: u64 = b.payees.iter().map(|(_, a, _)| *a).sum();
        log::info!(
            "send_many: building Orchard proof for tx {}/{tx_count} ({} payees, {} spends, {group_pay} sompi + {} fee)...",
            bi + 1,
            b.payees.len(),
            b.inputs.len(),
            b.fee
        );
        let started = std::time::Instant::now();
        let ctx2 = ctx.clone();
        let (payees, inputs, fee) = (b.payees, b.inputs, b.fee);
        let payload = tokio::task::spawn_blocking(move || {
            let _proving = ProvingGuard::new();
            build_wallet_payment_multi(seed, inputs, &payees, fee, &net, &ctx2, recoverable)
        })
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build payment: {e:?}")))?;
        log::info!("send_many: tx {}/{tx_count} proven in {:.0?}", bi + 1, started.elapsed());

        let tx: Transaction = payment_tx(payload);
        match client.submit_transaction(RpcTransaction::from(&tx), false).await {
            Ok(accepted) => {
                txids.push(accepted.to_string());
                paid += group_pay;
                total_fee += fee;
                let mut e = w.lock().await;
                let now_daa = e.scanned as u64;
                for p in b.positions {
                    e.db.mark_spent(p, accepted.as_bytes(), now_daa);
                }
                // Same as /send: surface the change and re-derive stale mempool previews.
                e.db.note_pending_outflow(accepted.as_bytes(), group_pay.saturating_add(fee));
                e.forget_stale_outflow_previews();
            }
            Err(e) if txids.is_empty() => return Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the payout: {e}"))),
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("payout partially sent: {}/{tx_count} txs accepted, then the node rejected: {e}", txids.len()),
                        "txids": txids,
                        "paid_sompi": paid,
                    })),
                ));
            }
        }
    }

    Ok(Json(SendManyResp {
        tx_count: txids.len(),
        payees: resolved.len(),
        paid_sompi: paid,
        fee_sompi: total_fee,
        paid_sompi_exact: paid.to_string(),
        fee_sompi_exact: total_fee.to_string(),
        txids,
    }))
}

#[derive(Deserialize, Default)]
struct ConsolidateReq {
    fee: Option<u64>,
    /// Select the OLDEST (lowest-position) matured notes instead of the smallest by
    /// value. Merging the oldest notes lets `advance_base_capped` roll the fast-sync
    /// base past them, which shortens EVERY future on-demand witness rebuild — the
    /// right strategy for healing a note-heavy miner/pool treasury, whose coinbase
    /// notes are near-equal value (so smallest-value selection is ~arbitrary and does
    /// not systematically unpin the base). Loop this endpoint with `heal:true` to walk
    /// the base up. Default false = smallest-value dust cleanup.
    heal: Option<bool>,
}

#[derive(Serialize)]
struct ConsolidateResp {
    txid: String,
    /// How many notes were merged into one.
    consolidated: usize,
    /// Value of the resulting note (inputs minus fee).
    value_sompi: u64,
    /// Unspent notes the wallet still tracks after this merge.
    notes_remaining: usize,
}

/// Merge the wallet's **smallest matured notes** into a single note paid back to
/// its own address. Mining wallets accumulate one ~60 FC coinbase note per block;
/// since a standard transaction spends at most [`max_spends_per_tx`] notes
/// (transient-mass cap), a fragmented wallet needs many chunked transactions per
/// large send. Calling this periodically (each call folds up to 6 notes → 1, the
/// result spendable after ~10 min maturity) keeps big payouts down to a single tx.
async fn wallet_consolidate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<ConsolidateReq>>,
) -> Result<Json<ConsolidateResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let (base_fee, heal) = match body {
        Some(Json(b)) => (b.fee.unwrap_or(DEFAULT_FEE_SOMPI), b.heal.unwrap_or(false)),
        None => (DEFAULT_FEE_SOMPI, false),
    };
    consolidate_once(&state, &w, base_fee, heal).await.map(Json)
}

/// One consolidation transaction: select, prove, submit, mark spent.
///
/// Shared by the `/api/wallet/consolidate` handler and the background
/// [`consolidate_loop`], so the manual and automatic paths cannot drift — in
/// particular they share the anchor-maturity check, the pending-spend-aware
/// candidate selection, and the byte-proportional fee floor.
async fn consolidate_once(
    state: &AppState,
    w: &Wallet,
    base_fee: u64,
    heal: bool,
) -> Result<ConsolidateResp, (StatusCode, Json<serde_json::Value>)> {
    // Held until this returns: a payment arriving mid-merge waits rather than
    // selecting the same notes (see `CONSOLIDATING`).
    let _merging = ConsolidateGuard::new();
    let (seed, recoverable) = {
        let e = w.lock().await;
        (e.key.seed()?, e.recoverable_history)
    };
    let own_recipient =
        address_bytes_from_seed(seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "seed is not a valid spending key"))?;

    let net: [u8; 32] = state.genesis.as_bytes();

    // Select up to a tx-full of the smallest matured notes under the entry lock.
    let (inputs, positions, sum, fee) = {
        let e = w.lock().await;
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) else {
            return Err(err(StatusCode::CONFLICT, "wallet is still syncing the maturity window; try again shortly"));
        };
        let (mut candidates, _stranded) = matured_candidates(&e.db, matured);
        if heal {
            // Oldest first: spending the lowest-position notes lets the fast-sync base
            // roll forward past them (`advance_base_capped`), shortening every later
            // rebuild. This is what actually heals a note-heavy treasury.
            candidates.sort_by_key(|n| n.position);
        } else {
            // Smallest value first: ordinary dust cleanup.
            candidates.sort_by_key(|n| n.value());
        }
        candidates.truncate(max_spends_per_tx());
        let sum: u64 = candidates.iter().map(|n| n.value()).sum();
        if candidates.len() < 2 {
            return Err(err(StatusCode::CONFLICT, "nothing to consolidate: fewer than 2 matured notes"));
        }
        // A full consolidation tx is the biggest standard tx there is — its fee
        // must clear the node's byte-proportional minimum for that size.
        let fee = chunk_fee(base_fee, candidates.len());
        if sum <= fee {
            return Err(err(StatusCode::CONFLICT, format!("smallest notes sum to {sum}, not more than the {fee} fee")));
        }
        let mut inputs = Vec::with_capacity(candidates.len());
        let mut positions = Vec::with_capacity(candidates.len());
        // One base→matured pass for every note being merged (O(chain + N·depth)); this is
        // what makes healing a fragmented treasury feasible — a full 38-note consolidation
        // costs one pass, not 38 × ~26 s. Declined notes fall back to the exact rebuild.
        let cons_positions: Vec<u64> = candidates.iter().map(|n| n.position).collect();
        let cons_paths = tokio::task::block_in_place(|| state.batch_witness_paths(&e.db, &cons_positions, matured));
        for (i, n) in candidates.iter().enumerate() {
            let path = match cons_paths[i].clone() {
                Some(p) => p,
                // block_in_place: an on-demand rebuild is an O(chain) Sinsemilla replay —
                // must not pin a runtime worker (it can hold the tokio I/O driver).
                None => tokio::task::block_in_place(|| e.db.witness_path_at(n.position, matured))
                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?,
            };
            inputs.push((n.note.clone(), path));
            positions.push(n.position);
        }
        (inputs, positions, sum, fee)
    };

    let consolidated = inputs.len();
    let value = sum - fee;
    let ctx = payment_tx_context();
    log::info!("consolidate: merging {consolidated} notes ({sum} sompi) into one...");
    let payload = tokio::task::spawn_blocking(move || {
        let _proving = ProvingGuard::new();
        build_wallet_payment(seed, inputs, own_recipient, value, fee, &net, &ctx, recoverable, [0u8; 512])
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build consolidation: {e:?}")))?;

    let tx: Transaction = payment_tx(payload);
    let node = state
        .request_client()
        .await
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node to broadcast; nothing was sent"))?;
    match node.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            let mut e = w.lock().await;
            let now_daa = e.scanned as u64;
            for p in positions {
                e.db.mark_spent(p, accepted.as_bytes(), now_daa);
            }
            // Everything but the fee comes back to us: show it as pending change rather
            // than letting the balance drop by the whole merged sum until it is mined.
            e.db.note_pending_outflow(accepted.as_bytes(), fee);
            e.forget_stale_outflow_previews();
            let notes_remaining = e.db.notes().len();
            Ok(ConsolidateResp { txid: accepted.to_string(), consolidated, value_sompi: value, notes_remaining })
        }
        Err(e) => Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the consolidation: {e}"))),
    }
}

// ===========================================================================
// Non-custodial payment: prepare (viewing key only) + submit (device sigs).
//
// This is the mobile / hardened path. The device holds the seed and never sends
// it: it posts only its 96-byte FULL VIEWING KEY to `/prepare`. The daemon scans
// watch-only, builds the Halo 2 proof, signs the throwaway padding dummies, and
// returns the payment sighash plus one spend randomizer (`alpha`) per real spend.
// The device signs each with `ask.randomize(alpha)` (e.g. via ZKas-signer) and
// posts the signatures to `/submit`, which applies them and broadcasts. A server
// compromise can see balances but CANNOT move funds — it never holds spend authority.
// The crypto split is proven in shielded-core (`non_custodial_payment_api_roundtrip`).
// ===========================================================================

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonU64 {
    Number(u64),
    Decimal(String),
}

impl JsonU64 {
    fn parse(&self, field: &'static str) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::Decimal(value) => {
                value.parse().map_err(|_| err(StatusCode::BAD_REQUEST, format!("{field} must be an unsigned 64-bit decimal integer")))
            }
        }
    }
}

#[derive(Deserialize)]
struct PrepareReq {
    /// 96-byte full viewing key (hex). Grants viewing capability, not spend.
    fvk_hex: String,
    /// Recipient `zkas:` shielded address.
    to: String,
    amount_sompi: Option<JsonU64>,
    amount_fc: Option<f64>,
    fee: Option<JsonU64>,
    /// Optional memo (max 512 bytes UTF-8), as in `SendReq`.
    memo: Option<String>,
    /// Opt in to a partial payment when the amount needs more notes than one standard
    /// transaction can spend. The response's `remaining_sompi` is what is still owed;
    /// the caller repeats prepare/submit until it reaches 0.
    allow_partial: Option<bool>,
}

#[derive(Serialize)]
struct SpendAuthReq {
    /// Action index in the bundle this randomizer authorizes.
    index: usize,
    /// 32-byte spend randomizer (hex); the device signs `ask.randomize(alpha)`.
    alpha: String,
}

#[derive(Serialize)]
struct PrepareResp {
    /// Opaque id to submit the signatures against.
    session: String,
    /// 32-byte payment sighash (hex) the device signs.
    sighash: String,
    /// Public fee / value balance of the payment.
    value_balance: i64,
    amount_sompi: u64,
    fee_sompi: u64,
    amount_sompi_exact: String,
    fee_sompi_exact: String,
    /// Sompi of the originally requested amount this payment does NOT cover, because it
    /// needed more notes than one standard transaction can spend. 0 for a complete
    /// payment. Only ever non-zero when the caller passed `allow_partial`.
    remaining_sompi: u64,
    remaining_sompi_exact: String,
    /// One randomizer per real spend the device must sign.
    spend_auth: Vec<SpendAuthReq>,
    /// The unsigned bundle (hex). The device MUST recompute the sighash from this
    /// itself rather than trust `sighash` above, and MUST verify the bundle against
    /// `disclosure` before signing — otherwise it is blind-signing whatever this
    /// daemon says, and a compromised daemon could have it authorize a payment to
    /// the attacker (`kaspa_shielded_core::wallet::build::check_prepared_payment`).
    bundle_hex: String,
    /// Per-action plaintext of the payment, so the device can check what it signs.
    disclosure: Vec<ActionDisclosureJson>,
    /// Stable SDK envelope. Legacy fields above remain during the compatibility
    /// window; new clients should deserialize and verify this object.
    #[serde(rename = "preparedPayment")]
    prepared_payment: PreparedPaymentEnvelope,
    /// True when the spend was planned from the daemon's live, synced wallet view
    /// (the fast path — request token matched this FVK's registered wallet).
    /// False means it fell back to a watch-only matured chain REPLAY — minutes on
    /// a long chain — so the client can warn the user about the wait instead of
    /// looking hung (and fix the token↔FVK mismatch that usually causes it).
    fast_path: bool,
}

/// [`kaspa_shielded_core::wallet::build::ActionDisclosure`] over the wire.
#[derive(Serialize)]
struct ActionDisclosureJson {
    spend_value: u64,
    out_value: u64,
    out_recipient: String,
    out_rseed: String,
    rcv: String,
}

async fn wallet_prepare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PrepareReq>,
) -> Result<Json<PrepareResp>, (StatusCode, Json<serde_json::Value>)> {
    use rand::RngCore;

    // Watch-only: authenticated by possession of the FVK, not a token/seed.
    let fvk_bytes = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;

    // Is this wallet paying ITSELF? Decided from the viewing key and the recipient,
    // both cheap to derive, so it is known before anything is reserved.
    let self_payment = Address::try_from(req.to.as_str())
        .ok()
        .and_then(|to| orchard_recipient_bytes(&to))
        .zip(WalletDb::from_fvk(&fvk_bytes))
        .is_some_and(|(recipient, db)| db.my_address_bytes() == recipient);

    // One preparation per wallet: a second would select the same notes as the one in
    // flight. Rejecting is right; the old wording was not. It said "wait for it to
    // finish before retrying", which reads as an accusation of impatience — while the
    // truth is that the first attempt is STILL RUNNING and cannot be stopped. Cancelling
    // in the app only drops the HTTP request; the work behind it is a witness climb and
    // a Halo2 proof inside `block_in_place`, which no dropped connection interrupts. One
    // measured on this daemon took 392 s for a 273,676-note wallet. So say what is
    // happening, how long it has been going, and that waiting is the only option.
    let _preparing = {
        let mut set = state.preparing.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare tracker poisoned"))?;
        if let Some((since, was_self)) = set.get(&req.fvk_hex) {
            let secs = since.elapsed().as_secs();
            let elapsed = if secs >= 60 { format!("{}m {}s", secs / 60, secs % 60) } else { format!("{secs}s") };
            // If what it is waiting on is the one-time subtree-cache build, say how far
            // along that is — the app shows this text, and a bare "still being
            // prepared" for an hour is what the "no meaningful logging" report was.
            let building = token_from(&headers, state.allow_default_token)
                .ok()
                .and_then(|t| state.cache_builds.lock().ok().and_then(|m| m.get(&t).cloned()))
                .map(|p| format!(" It is building this wallet's spend index first: {}.", p.describe()))
                .unwrap_or_default();
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                if *was_self {
                    format!(
                        "this wallet is merging its own notes in the background ({elapsed} so far).{building} It finishes on its own; your payment can be sent straight after."
                    )
                } else {
                    format!(
                        "the previous payment from this wallet is still being prepared ({elapsed} so far).{building} Closing or cancelling the screen does not stop it — the proof runs to completion on the server. Wait for it rather than starting another."
                    )
                },
            ));
        }
        set.insert(req.fvk_hex.clone(), (std::time::Instant::now(), self_payment));
        PreparingGuard { state: state.clone(), key: req.fvk_hex.clone() }
    };

    let requested = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s.parse("amount_sompi")?,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    // A standard transaction spends at most `max_spends_per_tx()` notes, so a wallet
    // whose balance is spread over many small notes (a miner's per-block coinbase, say)
    // cannot pay a large amount in one transaction. `allow_partial` lets the caller ask
    // for "as much of this as one transaction can carry", then repeat for the remainder
    // — which is what the custodial `/send` path has always done internally via
    // `plan_chunks`. It is OPT-IN precisely because already-shipped wallets do not loop:
    // silently sending them a partial payment while reporting success would be the same
    // class of bug as the missing `mark_spent`. Callers that don't ask still get the
    // explicit "send in smaller chunks" error.
    let allow_partial = req.allow_partial.unwrap_or(false);
    let mut amount = requested;
    // The caller's fee (or the flat default) is a FLOOR: the actual fee is raised
    // to the node's byte-proportional minimum once the input count is known
    // (`select_spend_count`), so multi-note payments are never relay-rejected.
    let base_fee = match req.fee {
        Some(fee) => fee.parse("fee")?,
        None => DEFAULT_FEE_SOMPI,
    };
    let mut fee = chunk_fee(base_fee, 1);

let client = state.request_client().await.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node right now; retry shortly"))?;
    let client = &client;
    let net: [u8; 32] = state.genesis.as_bytes();

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let mut need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;

    let max_per_tx = max_spends_per_tx();

    // Fast path: if the caller also presents the wallet token this key is registered
    // under (the app always does), the sync loop is already holding a live, matured
    // view of exactly this wallet — reuse it and spend straight from it. Without this
    // every send re-walked the chain watch-only first (measured: 3m24s on a 174K-block
    // chain), which on a phone reads as a hung app; the proof itself is ~7s.
    let mut inputs = Vec::new();
    let mut selected = 0u64;
    let mut have_total: Option<u64> = None;
    // Set when the spend is planned from the live tracked-wallet view rather than
    // the watch-only chain replay — reported to the caller as `fast_path`.
    let mut fast_path = false;
    // Notes this payment will spend, so `/submit` can park them once the node accepts.
    // Only the tracked-wallet path below can fill these: the FVK-only slow path has no
    // wallet to record against.
    let mut spent_positions: Vec<u64> = Vec::new();
    let mut session_token: Option<String> = None;
    if let Ok(token) = token_from(&headers, state.allow_default_token) {
        if let Some(w) = state.get_wallet(&token).await {
            ensure_canonical_checkpoint(&state, &w).await?;
            // A first send may need this wallet's subtree cache built: do it OFF the
            // lock, on every core, before taking the lock below — the hour-long,
            // single-core, silent inline build was the "sent a tx, walletd pinned a core
            // for an hour" report. Only for the wallet this request is actually about.
            if w.lock().await.db.fvk().to_bytes() == fvk_bytes {
                build_send_cache_off_lock(&state, &token, &w).await;
            }
            let mut e = w.lock().await;
            if e.db.fvk().to_bytes() == fvk_bytes {
                // Gate on a matured anchor being available + no in-progress reorg repair,
                // not on scanned-vs-tip — see the note in `wallet_send`. A note-heavy or
                // busy wallet legitimately trails the live tip while every note it would
                // spend is already matured and spendable.
                if e.reorged_strikes > 0 {
                    return Err(err(StatusCode::CONFLICT, "wallet checkpoint is being repaired after a reorg; retry shortly"));
                }
                if e.matured_leaves().is_none() {
                    return Err(err(
                        StatusCode::CONFLICT,
                        format!("wallet has not established a matured anchor yet (scanned DAA {}); wait for initial sync", e.scanned),
                    ));
                }
                let matured_leaves = e.matured_leaves().unwrap_or(0);
                let warm_before = e.db.witnessed_upto();
                let climb = matured_leaves.saturating_sub(warm_before);
                let t_w = std::time::Instant::now();
                // Bounded + block_in_place: the uncapped inline climb here is what froze
                // the whole daemon for ~50 min on 2026-07-17 (3,304-note wallet).
                // The shared tree's reach decides whether this wallet must climb at all.
                let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
                let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
                tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded(shared_covers, shared_base));
                log::info!(
                    "prepare: witness advance took {:.1?} (notes={}, base_size={}, witnessed_upto {}→{} of matured {}, climbed {} leaves; {} at send time)",
                    t_w.elapsed(),
                    e.db.notes().len(),
                    e.db.base_size(),
                    warm_before,
                    e.db.witnessed_upto(),
                    matured_leaves,
                    climb,
                    if climb == 0 { "WARM — background pre-advance kept up" } else { "COLD — witnesses were behind" },
                );
                let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
                if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
                    let (mut candidates, _stranded) = matured_candidates(&e.db, matured);
                    candidates.sort_by(|a, b| b.value().cmp(&a.value()));
                    have_total = Some(candidates.iter().map(|n| n.value()).sum());
                    fast_path = true;
                    let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
                    let (mut take, mut dyn_fee) = select_spend_count(&values, amount, base_fee, max_per_tx);
                    // Size a SELF-payment's round to the fee the caller held back.
                    //
                    // Identical to the slow path below, and it belongs here far more: the
                    // slow path serves untracked FVK-only callers, while every wallet the
                    // hosted daemon actually tracks — which is every wallet that presses
                    // Consolidate in the app — arrives HERE. Landing the fix on one branch
                    // meant shipping it to nobody, and the same "insufficient matured funds"
                    // reports kept coming in against a daemon that supposedly fixed them.
                    //
                    // Fee scales with note count, so merging fewer notes both fits the
                    // caller's reserve and stays under the signing ceiling older builds
                    // enforce. A caller that reserves properly is untouched.
                    if self_payment {
                        let budget = have_total.unwrap_or(0).saturating_sub(amount);
                        while take > 2 && dyn_fee > budget {
                            take -= 1;
                            dyn_fee = chunk_fee(base_fee, take);
                        }
                    }
                    let take = take;
                    fee = dyn_fee;
                    need = amount.saturating_add(fee);
                    // Build every selected note's witness in ONE base→matured pass
                    // (O(chain + N·depth)) instead of N independent O(chain) replays —
                    // the difference between ~one pass and N × ~26 s on a note-heavy
                    // wallet. Any note the batch declines (warm-miss edge / out of window)
                    // falls back to the exact per-note rebuild, so this is never wrong.
                    let selected_notes: Vec<_> = candidates.iter().take(take).cloned().collect();
                    let positions: Vec<u64> = selected_notes.iter().map(|n| n.position).collect();
                    let t_b = std::time::Instant::now();
                    let paths = tokio::task::block_in_place(|| state.batch_witness_paths(&e.db, &positions, matured));
                    let batched = paths.iter().filter(|p| p.is_some()).count();
                    log::info!(
                        "prepare: batch-witnessed {}/{} notes in {:.1?} (rest rebuild individually)",
                        batched,
                        positions.len(),
                        t_b.elapsed(),
                    );
                    for (i, n) in selected_notes.iter().enumerate() {
                        let path = match paths[i].clone() {
                            Some(p) => p,
                            None => {
                                let t_p = std::time::Instant::now();
                                let p = tokio::task::block_in_place(|| e.db.witness_path_at(n.position, matured))
                                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                                log::info!("prepare: fallback witness_path_at(note@{}) took {:.1?}", n.position, t_p.elapsed());
                                p
                            }
                        };
                        inputs.push((n.note.clone(), path));
                        spent_positions.push(n.position);
                        selected += n.value();
                    }
                    session_token = Some(token.clone());
                }
            }
        }
    }

    // Slow path (no token, unsynced wallet, or a key we don't track): recover the note
    // set from the FVK alone over the settled matured chain prefix, so every witness
    // still roots at a matured canonical anchor.
    if have_total.is_none() {
        let db =
            WalletDb::from_fvk(&fvk_bytes).ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?;
        log::info!("non-custodial prepare: watch-only matured chain replay...");
        let db = replay_matured(client, state.genesis, db).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let mut candidates = db.notes().to_vec();
        candidates.sort_by(|a, b| b.value().cmp(&a.value()));
        have_total = Some(candidates.iter().map(|n| n.value()).sum());
        let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
        let (mut take, mut dyn_fee) = select_spend_count(&values, amount, base_fee, max_per_tx);
        // A SELF-payment tells us its fee budget by what it held back.
        //
        // Consolidation asks to move `spendable - reserve` to its own address, so the gap
        // between what the wallet holds and what it asked for IS the fee the caller
        // budgeted. Older wallet builds reserve a flat 0.1 ZKAS while the byte-priced
        // relay minimum for a full 38-note merge is 0.246 — so they ask for more than they
        // can pay for, and every consolidation fails with "insufficient matured funds".
        // Worse, those builds also refuse to SIGN a fee above their reserve, so simply
        // clamping the amount here would trade one refusal for another.
        //
        // Merging fewer notes fixes both at once: fee scales with note count, so a round
        // sized to the caller's budget both fits their balance and passes their signing
        // ceiling. They consolidate in smaller steps without updating anything. A caller
        // that reserves properly still gets a full-size round, so nothing is slowed down
        // to accommodate old builds.
        //
        // Only for self-payments: silently shrinking a payment to somebody else would be
        // a different and much worse bug.
        if self_payment {
            let budget = have_total.unwrap_or(0).saturating_sub(amount);
            while take > 2 && dyn_fee > budget {
                take -= 1;
                dyn_fee = chunk_fee(base_fee, take);
            }
        }
        fee = dyn_fee;
        need = amount.saturating_add(fee);
        for n in candidates.iter().take(take) {
            let path = db
                .witness_path(n.position)
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
            inputs.push((n.note.clone(), path));
            selected += n.value();
        }
    }
    if selected < need {
        let have: u64 = have_total.unwrap_or(0);
        // Log every near-miss, with the numbers that decide it.
        //
        // This refusal reaches the user and wrote NOTHING, so a report of "insufficient
        // funds on a wallet that has funds" could not be traced afterwards — the numbers in
        // the message were the only evidence, and they arrive truncated in a chat. Three
        // separate diagnoses were attempted from arithmetic alone before this line existed.
        //
        // `fee_budget` is the gap the caller reserved for the fee, which is what the
        // self-payment sizing below spends; printing it next to the fee actually chosen
        // makes an under-reserved client obvious at a glance.
        log::warn!(
            "prepare shortfall: have {have}, need {need} (amount {amount} + fee {fee}), selected {selected} from {} candidate note(s), \
             fee_budget {}, self_payment {self_payment}, allow_partial {allow_partial}, token {}",
            inputs.len(),
            have.saturating_sub(amount),
            if session_token.is_some() { "yes" } else { "no" },
        );
        // The notes exist, they just don't fit one transaction. Pay what this
        // transaction can carry and report the rest, if the caller opted in.
        let capacity = selected.saturating_sub(fee);
        // Chunking is only safe on the tracked-wallet path. The FVK-only slow path has
        // no wallet to record the spend against, so `/submit` cannot park the notes —
        // the caller's next chunk would re-select the very same notes value-descending
        // and build a transaction consensus drops as a double-spend, silently. Without a
        // token we refuse to chunk and return the explicit error instead.
        // `self_payment` joins `have >= need` here: a consolidation that asked for slightly
        // more of its own money than the fee leaves available is not short of funds, it is
        // off by a fee. Pay what the selected notes can carry and report the remainder.
        if allow_partial && session_token.is_some() && (have >= need || self_payment) && capacity > 0 {
            // Change is then exactly zero: the chunk pays out every selected note less
            // the fee. `need` is not reassigned — past this point only `amount`/`fee`
            // matter, `prepare_payment` derives the change from the inputs themselves.
            amount = capacity;
            log::info!(
                "prepare: partial chunk — paying {amount} of {requested} sompi with {} note(s); {} sompi remain",
                inputs.len(),
                requested - amount,
            );
        } else {
            return Err(if have >= need {
                err(
                    StatusCode::CONFLICT,
                    format!(
                        "amount needs more than {max_per_tx} input notes (standard tx size cap): max sendable in one tx is {capacity} sompi; send in smaller chunks",
                    ),
                )
            } else {
                // Name the actual cause. "Insufficient matured funds" sent one user hunting
                // for coins that were never missing: what had happened was that their
                // consolidation SUCCEEDED, the merged note was still inside the ~10 minute
                // maturity window, and the dust left behind was worth less than the cheapest
                // possible fee. The old wording described the maturity rule while implying a
                // shortfall, which is the least useful combination available.
                // `chunk_fee(0, n)` is the relay minimum for n spends: the policy floor is 0,
                // so the byte-priced minimum wins. Two spends is the smallest a merge can be.
                let floor = chunk_fee(0, 2);
                if have < floor {
                    err(
                        StatusCode::CONFLICT,
                        format!(
                            "spendable balance {} ZKAS is below the {} ZKAS minimum network fee for a transaction, so there is nothing that can be sent or merged right now.                              If a payment or consolidation just went through, its output becomes spendable about 10 minutes after it is mined.",
                            fmt_fc(have as u128),
                            fmt_fc(floor as u128),
                        ),
                    )
                } else {
                    err(
                        StatusCode::CONFLICT,
                        format!(
                            "insufficient matured funds: spendable {} ZKAS, need {} ZKAS (amount plus a {} ZKAS fee). Funds become spendable about 10 minutes after they are mined.",
                            fmt_fc(have as u128),
                            fmt_fc(need as u128),
                            fmt_fc(fee as u128),
                        ),
                    )
                }
            });
        }
    }

    let ctx = payment_tx_context();
    log::info!("non-custodial prepare: building Orchard payment proof (Halo 2) for {} spends...", inputs.len());
    let fvk = WalletDb::from_fvk(&fvk_bytes)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?
        .fvk()
        .clone();
    // The per-wallet recoverable-history flag lives in the wallet file; prepare is
    // keyed by FVK, so resolve it via the (optional) token — default on.
    let recoverable = token_from(&headers, state.allow_default_token)
        .ok()
        .and_then(|t| load_wallet_meta(&state.wallet_dir, &t, state.wallet_secret.as_deref()))
        .map(|(_, _, r)| r)
        .unwrap_or(true);
    let memo = memo_bytes(req.memo.as_deref())?;
    let _consolidate_permit = if self_payment {
        // WAIT for a consolidation slot rather than reject on the first busy instant. A
        // merge is now ~seconds, so the slot frees quickly; blocking here means the user's
        // request simply completes a moment later instead of bouncing with "try again".
        Some(
            tokio::time::timeout(CONSOLIDATE_QUEUE_WAIT, state.consolidate_gate.acquire())
                .await
                .map_err(|_| {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Still merging other wallets — your consolidation is queued and didn't get a turn this time. It's safe to try again in a minute.",
                    )
                })?
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "consolidate gate closed"))?,
        )
    } else {
        None
    };

    // Then take the proving slot shared with every other wallet — taken HERE, once the
    // inputs are selected and witnessed, not at the top of the handler. The slot exists
    // to bound concurrent PROVING; held from the start it also covered every cold-wallet
    // step of one tenant's send (an inline wallet load, the checkpoint adopt wait, the
    // subtree-cache build wait, the shared-tree lock spin and the FVK-only chain replay),
    // and on the hosted daemon's single slot that starved every other tenant's warm send
    // for minutes. The per-FVK `_preparing` guard above still rejects a second prepare
    // on the SAME wallet from the first instant.
    //
    // A PAYMENT queues: somebody is watching it, and another tenant's send is not this
    // caller's error. CONSOLIDATION does not queue — it starts only if the prover is
    // free this instant, and otherwise tells the caller to come back.
    //
    // The difference matters most where it is easiest to miss. The hosted daemon runs
    // `--max-concurrent-proves 1`, so "at most one consolidation at a time" would be an
    // empty promise there: that one consolidation IS the only slot, and a round
    // deliberately spends the maximum notes a transaction allows (~38, tens of seconds
    // of proving) while every payment waits. Yielding rather than queueing is the rule
    // the daemon's own background merger already follows — "never take cores from a
    // payment somebody is waiting on" — applied to the merge a user asks for, and to the
    // background maintenance the wallet app now performs on its own.
    let _prepare_permit = if self_payment {
        // WAIT for the prover instead of yielding immediately. Payments still get priority
        // — their queue window (PREPARE_QUEUE_WAIT) is longer, and on the same fair
        // semaphore — but a consolidation now waits its short turn rather than bouncing.
        tokio::time::timeout(CONSOLIDATE_QUEUE_WAIT, state.prepare_gate.acquire())
            .await
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The prover is busy with payments right now — your consolidation is queued and didn't get a turn this time. Try again in a minute.",
                )
            })?
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare gate closed"))?
    } else {
        tokio::time::timeout(PREPARE_QUEUE_WAIT, state.prepare_gate.acquire())
            .await
            .map_err(|_| {
                err(StatusCode::SERVICE_UNAVAILABLE, "The daemon is still preparing other payments — please try again in a moment.")
            })?
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare gate closed"))?
    };

    let t_proof = std::time::Instant::now();
    let payment = tokio::task::spawn_blocking(move || {
        let _proving = ProvingGuard::new();
        prepare_payment(&fvk, inputs, recipient, amount, fee, &net, &ctx, recoverable, memo)
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to prepare payment: {e:?}")))?;
    log::info!("prepare: Halo2 proof took {:.1?}", t_proof.elapsed());

    let spend_auth: Vec<SpendAuthReq> =
        payment.spend_auth_requests.iter().map(|(i, alpha)| SpendAuthReq { index: *i, alpha: hex(alpha) }).collect();
    let sighash_hex = hex(&payment.sighash);
    let value_balance = payment.value_balance;

    // Hand the device everything it needs to check this payment for itself: the
    // unsigned bundle and the plaintext of every action. Anything we lie about here
    // fails the device's commitment checks, so it can refuse to sign.
    let bundle_hex = hex(&payment.effects.to_bytes());
    let disclosure: Vec<ActionDisclosureJson> = payment
        .disclosure
        .iter()
        .map(|d| ActionDisclosureJson {
            spend_value: d.spend_value,
            out_value: d.out_value,
            out_recipient: hex(&d.out_recipient),
            out_rseed: hex(&d.out_rseed),
            rcv: hex(&d.rcv),
        })
        .collect();

    let sdk_network = match state.network.as_str() {
        "testnet" => SdkNetwork::Testnet,
        "devnet" => SdkNetwork::Devnet,
        "simnet" => SdkNetwork::Simnet,
        _ => SdkNetwork::Mainnet,
    };
    let prepared_payment = PreparedPaymentEnvelope::from_typed(
        &SdkPreparedPayment {
            version: SdkPreparedPayment::VERSION,
            network_domain: net,
            tx_context: payment_tx_context(),
            bundle: payment.effects.clone(),
            disclosure: payment.disclosure.clone(),
            spend_auth: payment
                .spend_auth_requests
                .iter()
                .map(|(action_index, alpha)| SdkSpendAuthRequest { action_index: *action_index, alpha: *alpha })
                .collect(),
            // What this payment IS, embedded so a detached signer can display and
            // verify it from the envelope alone. The device cross-checks these
            // against the user's approval and the bundle — lying here only makes
            // the device refuse to sign.
            claimed: SdkClaimedIntent { recipient, amount, fee },
        },
        &sdk_network,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build prepared envelope: {e}")))?;

    // Park the awaiting-signature payment under a random, unguessable session id.
    let mut sid = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut sid);
    let session = hex(&sid);
    {
        let now = std::time::Instant::now();
        let mut map = state.prepared.lock().await;
        map.retain(|_, s| now.duration_since(s.created) < PREPARED_TTL); // bound memory
        map.insert(
            session.clone(),
            PreparedSession { payment, amount, fee, created: now, token: session_token, positions: spent_positions },
        );
    }

    Ok(Json(PrepareResp {
        session,
        sighash: sighash_hex,
        value_balance,
        amount_sompi: amount,
        fee_sompi: fee,
        remaining_sompi: requested - amount,
        remaining_sompi_exact: (requested - amount).to_string(),
        amount_sompi_exact: amount.to_string(),
        fee_sompi_exact: fee.to_string(),
        spend_auth,
        bundle_hex,
        disclosure,
        prepared_payment,
        fast_path,
    }))
}

#[derive(Deserialize)]
struct SubmitSig {
    /// Action index this signature authorizes (echoed from `spend_auth`).
    index: usize,
    /// 64-byte RedPallas spend-auth signature (hex).
    sig: String,
}

#[derive(Deserialize)]
struct SubmitReq {
    /// The `session` returned by `/prepare`.
    session: String,
    /// The device's spend-auth signatures, one per `spend_auth` request.
    sigs: Vec<SubmitSig>,
}

async fn wallet_submit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    // Pop the session (single-use); also sweep any expired ones.
    let session = {
        let now = std::time::Instant::now();
        let mut map = state.prepared.lock().await;
        map.retain(|_, s| now.duration_since(s.created) < PREPARED_TTL);
        map.remove(&req.session)
    };
    let PreparedSession { payment, amount, fee, token, positions, .. } =
        session.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such prepared session (expired or already submitted)"))?;

    let mut device_sigs: Vec<(usize, [u8; SIG_LEN])> = Vec::with_capacity(req.sigs.len());
    for s in &req.sigs {
        let sig = unhex(&s.sig)
            .and_then(|b| <[u8; SIG_LEN]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "each sig must be 64 bytes of hex"))?;
        device_sigs.push((s.index, sig));
    }

    // Log both failure modes below. A send that fails is the single most alarming
    // thing a user experiences, and until now neither of them left ANY trace in the
    // daemon log — the reason went out in the HTTP body and nowhere else, so an
    // operator asked "why did my send fail?" had nothing to read. Reported live
    // 2026-08-07 as "bad signature" after a two-minute wait, undiagnosable after the
    // fact. The user-facing text is plain English; the detail goes to the log.
    let n_sigs = device_sigs.len();
    let sig_indices: Vec<usize> = device_sigs.iter().map(|(i, _)| *i).collect();
    let bundle = finalize_payment(payment, device_sigs).map_err(|e| {
        // Log WHICH wallet and which action indices. `InvalidExternalSignature` means
        // the device's signature did not verify against the bundle's randomized key —
        // that is about the signing key, the randomizer, or the sighash, never the
        // Merkle witness. Knowing the token separates "this one wallet's device key
        // does not match the wallet the token addresses" from a general fault: seen
        // live 2026-08-07, one wallet failed 3/3 while another succeeded in between.
        log::error!(
            "submit REJECTED for session {} (wallet token {}): finalize_payment failed with {n_sigs} device \
             signature(s) for action index/es {sig_indices:?}: {e:?}",
            req.session,
            token.as_deref().unwrap_or("<none>"),
        );
        err(
            StatusCode::BAD_REQUEST,
            "This payment could not be completed: the signatures from your device did not match the \
             prepared transaction. Nothing was sent and no coins moved. Please try the payment again.",
        )
    })?;
    let tx: Transaction = payment_tx(bundle.to_bytes());
    let node = state
        .request_client()
        .await
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the wallet service cannot reach its node to broadcast; nothing was sent"))?;
    match node.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            // The node has the transaction: park the notes it spends so they leave the
            // unspent set NOW rather than ~3 minutes from now when the block carrying
            // them clears the reorg holdback. Parking (not deleting) is what makes this
            // safe — `reclaim_expired` returns the notes if the transaction never lands.
            // Skipping this is what let a second send inside that window re-select the
            // same notes and build a transaction consensus drops as a double-spend.
            if let Some(token) = token {
                if let Some(w) = state.get_wallet(&token).await {
                    let mut e = w.lock().await;
                    let now_daa = e.scanned as u64;
                    for p in &positions {
                        e.db.mark_spent(*p, accepted.as_bytes(), now_daa);
                    }
                    // The parked notes are worth more than amount + fee: the rest is
                    // CHANGE, and until the block carrying it is previewed nothing else
                    // in the status carries it — a one-note wallet read "0" for the
                    // 1-3 s in between. Record the outflow now (the only moment the
                    // daemon holds amount, fee and the parked notes together) and drop
                    // cached mempool previews so one taken before the park (classified
                    // as `outgoing = amount + fee`) is re-derived on the next tick
                    // instead of stacking on top of the already-reduced balance.
                    e.db.note_pending_outflow(accepted.as_bytes(), amount.saturating_add(fee));
                    e.forget_stale_outflow_previews();
                    log::info!("submit: parked {} spent note(s) for tx {}", positions.len(), accepted);
                }
            }
            let txid = accepted.to_string();
            Ok(Json(SendResp {
                txid: txid.clone(),
                amount_sompi: amount,
                fee_sompi: fee,
                amount_sompi_exact: amount.to_string(),
                fee_sompi_exact: fee.to_string(),
                txids: vec![txid],
                tx_count: 1,
            }))
        }
        Err(e) => {
            log::error!("submit REJECTED by the node for session {}: {e}", req.session);
            Err(err(StatusCode::BAD_GATEWAY, format!("The node would not accept this payment: {e}. No coins moved.")))
        }
    }
}

#[derive(Deserialize)]
struct SignReq {
    message: String,
}

#[derive(Serialize)]
struct SignResp {
    address: String,
    message: String,
    signature: String,
    note: String,
}

async fn wallet_sign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SignReq>,
) -> Result<Json<SignResp>, (StatusCode, Json<serde_json::Value>)> {
    require_custodial(&state)?;
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let seed = { w.lock().await.key.seed()? };
    let tag = state.prefix.to_string();
    let signed = sign_message(seed, tag.as_bytes(), req.message.as_bytes(), rand10::rng())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "seed is not a valid spending key"))?;
    let address = String::from(&Address::new(state.prefix, Version::ShieldedOrchard, &signed.address));
    let mut blob = Vec::with_capacity(FVK_LEN + SIG_LEN);
    blob.extend_from_slice(&signed.fvk);
    blob.extend_from_slice(&signed.sig);
    Ok(Json(SignResp {
        address,
        message: req.message,
        signature: hex(&blob),
        note:
            "This signature discloses the wallet's viewing key (proves ownership + enables note detection, but NOT spend authority)."
                .into(),
    }))
}

#[derive(Deserialize)]
struct VerifyReq {
    address: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
    reason: Option<String>,
}

async fn verify(Json(req): Json<VerifyReq>) -> Result<Json<VerifyResp>, (StatusCode, Json<serde_json::Value>)> {
    let addr = Address::try_from(req.address.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid address: {e}")))?;
    let tag = addr.prefix.to_string();
    let raw =
        orchard_recipient_bytes(&addr).ok_or_else(|| err(StatusCode::BAD_REQUEST, "address is not a shielded Orchard address"))?;
    let blob = unhex(&req.signature).ok_or_else(|| err(StatusCode::BAD_REQUEST, "signature is not valid hex"))?;
    if blob.len() != FVK_LEN + SIG_LEN {
        return Err(err(StatusCode::BAD_REQUEST, format!("signature must be {} bytes (fvk||sig)", FVK_LEN + SIG_LEN)));
    }
    let fvk: [u8; FVK_LEN] = blob[..FVK_LEN].try_into().expect("checked");
    let s: [u8; SIG_LEN] = blob[FVK_LEN..].try_into().expect("checked");
    match verify_message(&raw, tag.as_bytes(), req.message.as_bytes(), &fvk, &s) {
        Ok(()) => Ok(Json(VerifyResp { valid: true, reason: None })),
        Err(e) => Ok(Json(VerifyResp { valid: false, reason: Some(format!("{e:?}")) })),
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// Default wallet directory (`~/.zkas/wallets` — the pre-rebrand path is kept
/// so existing wallet files keep working).
pub fn default_wallet_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.zkas/wallets")
}

/// Length-then-value compare that doesn't early-exit on the first differing byte, so a
/// bearer token can't be recovered by timing. Token length is fixed and not secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Transport auth for a publicly-bound daemon: every request except `/health` must carry
/// `Authorization: Bearer <token>` matching the paired token. Without this, anyone who
/// can reach the port could read/drain wallets.
/// Monotonic "last used" marker for the idle bound.
///
/// Monotonic on purpose: a wall clock that steps backwards (NTP, a laptop waking
/// from sleep) would make the daemon look freshly used and postpone the shutdown
/// indefinitely, which is exactly the state the bound exists to prevent.
struct IdleClock {
    start: std::time::Instant,
    last_used_millis: std::sync::atomic::AtomicU64,
}

impl IdleClock {
    fn new() -> Self {
        Self { start: std::time::Instant::now(), last_used_millis: std::sync::atomic::AtomicU64::new(0) }
    }

    fn touch(&self) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        self.last_used_millis.store(elapsed, std::sync::atomic::Ordering::Relaxed);
    }

    fn idle_for(&self) -> std::time::Duration {
        let last = self.last_used_millis.load(std::sync::atomic::Ordering::Relaxed);
        self.start.elapsed().saturating_sub(std::time::Duration::from_millis(last))
    }
}

async fn bearer_guard(State(expected): State<std::sync::Arc<String>>, req: Request, next: Next) -> Response {
    // A CORS preflight is the browser asking whether a request would be permitted.
    // It is generated by the browser itself and CANNOT carry credentials, so
    // demanding a bearer from it rejects every authenticated call before the real
    // request is ever sent — the caller only ever sees an opaque network failure.
    // The CORS layer still validates the requested origin, method and headers, and
    // the real request that follows remains fully gated.
    if req.method() == Method::OPTIONS || req.uri().path() == "/health" {
        return next.run(req).await;
    }
    let presented = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|s| s.strip_prefix("Bearer "));
    match presented {
        Some(tok) if ct_eq(tok.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response(),
    }
}

/// Longest a single `warm_chain_tree` call drives the shared tree before returning, so a
/// wedged node cannot hang the request forever. The work resumes where it left off, so an
/// operator can simply call again if `caught_up` came back false.
const WARM_ENDPOINT_BUDGET_SECS: u64 = 90;

/// Operator tool: drive the **shared chain tree** to the node tip right now.
///
/// The background sync advances the shared tree one chunk per lap and, after a restart,
/// it can trail the matured tip for a long time — and while it does, every consolidation
/// of an old note pays a full O(chain) climb (500–700 s) because `chain_tree_paths`
/// declines until `size >= matured`. This endpoint runs the very same `sync_one_wallet`
/// pass the background loop runs, just back-to-back until the tree reaches the tip, so an
/// operator can close that window by hand instead of waiting it out.
///
/// It holds the tree's in-pass claim for the duration so the background lap does not
/// double-sync it, and yields the tree's lock between chunks so concurrent sends can still
/// borrow. Auth is the ordinary token gate — the work is idempotent and is exactly what
/// the daemon already does, so any authorized caller may trigger it.
async fn warm_chain_tree(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _token = token_from(&headers, state.allow_default_token)?;
    let ct = state
        .wallets
        .lock()
        .await
        .get(CHAIN_TREE_TOKEN)
        .cloned()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "shared chain tree is not loaded yet"))?;

    // No in-pass claim: this drives the very same `sync_one_wallet` the background lap
    // runs, and both fully serialize on the tree's own mutex (each call holds it for one
    // whole chunk), so running them concurrently just means they take turns advancing the
    // same tree — correct, and never a conflict the operator has to retry around.

    // Fresh tip so we know the target and don't stop short of it.
    let chain_len = match state.sync_client().await {
        Some(c) => match c.get_block_dag_info().await {
            Ok(d) => d.virtual_daa_score,
            Err(_) => state.node_tip.lock().await.0,
        },
        None => state.node_tip.lock().await.0,
    };
    if chain_len == 0 {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "node tip unknown; is the node up and synced?"));
    }

    let started = std::time::Instant::now();
    let leaves_before = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
    let deadline = started + std::time::Duration::from_secs(WARM_ENDPOINT_BUDGET_SECS);
    let mut chunks: u32 = 0;
    let mut caught_up = false;
    loop {
        match sync_one_wallet(state.clone(), CHAIN_TREE_TOKEN.to_string(), ct.clone(), chain_len).await {
            SyncOutcome::Idle => {
                caught_up = true;
                break;
            }
            // A reorg the tree could not follow: leave it for the sync loop's reorg path.
            SyncOutcome::Retired(_) => break,
            SyncOutcome::Behind => {}
        }
        chunks += 1;
        if std::time::Instant::now() >= deadline {
            break;
        }
    }
    let leaves_after = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);

    // Ensure the shared tree's subtree CACHE — the actual O(depth) index — is built.
    //
    // Catching up leaves is not enough on its own: `chain_tree_paths` calls
    // `witness_paths_at`, which is an O(chain) replay until this cache exists, so an
    // old-note consolidation stays at ~500 s even with the tree at the tip. The background
    // builder is supposed to build it, but it is gated behind `!proving_now()` (lib.rs
    // ~2607), and constant consolidation proving keeps that false — a self-sustaining
    // stall, since the climbs that need the cache ARE the proofs that block it. An operator
    // calling this means to pay for it now, so force the build unconditionally.
    //
    // Detached and OFF the tree's lock (snapshot -> fold -> install): the fold is a ~minutes
    // O(chain) sweep, so holding the HTTP request (or the lock) for it would be wrong. The
    // call returns at once with the state; re-call to see it flip to "ready". `build_in_flight`
    // stops a second call from starting a duplicate fold.
    let (cache_ready, cache_state) = {
        let mut e = ct.lock().await;
        let matured = e.matured_leaves().unwrap_or(leaves_after);
        if e.db.subtree_cache_ready(matured) {
            (true, "ready")
        } else if e.build_in_flight {
            (false, "building")
        } else {
            e.build_in_flight = true;
            let job = e.db.subtree_build_job();
            drop(e);
            let ct2 = ct.clone();
            let state2 = state.clone();
            tokio::spawn(async move {
                let leaves = job.leaves();
                let t = std::time::Instant::now();
                log::info!("admin warm_chain_tree: shared tree subtree-cache build started ({leaves} leaves, off-lock)");
                let built = run_subtree_build(&state2, CHAIN_TREE_TOKEN, "the shared chain tree", job).await;
                let mut e = ct2.lock().await;
                e.build_in_flight = false;
                if built.is_some_and(|b| e.db.install_subtree_cache(b)) {
                    e.force_checkpoint = true;
                    log::info!(
                        "admin warm_chain_tree: shared tree subtree-cache COMPLETE in {:.1?} ({leaves} leaves) — consolidations now witness O(depth)",
                        t.elapsed()
                    );
                } else {
                    log::warn!("admin warm_chain_tree: shared tree subtree-cache did not install (stream moved under it); call again to retry");
                }
            });
            (false, "started")
        }
    };

    log::info!(
        "admin warm_chain_tree: {leaves_before} -> {leaves_after} leaves (+{}) in {chunks} chunk(s), {:.1?}, caught_up={caught_up}, cache={cache_state}, tip_daa={chain_len}",
        leaves_after.saturating_sub(leaves_before),
        started.elapsed(),
    );
    Ok(Json(serde_json::json!({
        "leaves_before": leaves_before,
        "leaves_after": leaves_after,
        "leaves_gained": leaves_after.saturating_sub(leaves_before),
        "caught_up": caught_up,
        "subtree_cache_ready": cache_ready,
        "subtree_cache_state": cache_state,
        "chunks": chunks,
        "chain_tip_daa": chain_len,
        "seconds": started.elapsed().as_secs_f64(),
    })))
}

/// Operator tool: build one wallet's own **subtree cache** right now.
///
/// Complements [`warm_chain_tree`]: even when the shared tree cannot serve a wallet (it is
/// borrowing, or a position falls outside what the shared stream can path), a wallet with
/// its own cache witnesses old notes in O(depth) instead of an O(chain) replay. This is
/// the targeted fix for a known note-heavy wallet whose consolidations are slow. The build
/// is the one-time O(chain) pass, and its result is persisted (`force_checkpoint`) so a
/// later restart does not repeat it.
async fn warm_wallet(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state
        .get_wallet(&token)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "wallet is not loaded; open it first, then retry"))?;
    let started = std::time::Instant::now();
    let (ready, matured, notes) = {
        let mut e = w.lock().await;
        let matured = e.matured_leaves().unwrap_or(0);
        let notes = e.db.notes().len();
        tokio::task::block_in_place(|| e.db.build_subtree_cache());
        let ready = e.db.subtree_cache_ready(matured);
        if ready {
            // Expensive and public: persist it so a restart reloads it warm.
            e.force_checkpoint = true;
        }
        (ready, matured, notes)
    };
    log::info!(
        "admin warm_wallet {token}: subtree cache ready={ready} (notes={notes}, matured={matured}) in {:.1?}",
        started.elapsed(),
    );
    Ok(Json(serde_json::json!({
        "subtree_cache_ready": ready,
        "notes": notes,
        "matured_leaves": matured,
        "seconds": started.elapsed().as_secs_f64(),
    })))
}

/// Make this wallet fast to interact with, without making the caller wait for anything.
///
/// Token-scoped and idempotent: loading the wallet (the call itself does that) marks it
/// active, so the sync loop keeps it current; if its complete-subtree cache is missing we
/// arm the same off-lock build the sync pass would eventually request, but NOW — so by the
/// time the user reaches the send button the O(depth) witness path is (or is becoming)
/// ready. Returns the readiness picture so a client can even show "optimizing…" honestly.
async fn wallet_warm(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet for this token"))?;
    let mut e = w.lock().await;
    let matured = e.matured_leaves().unwrap_or(0);
    let notes = e.db.notes().len();
    let ready = e.db.subtree_cache_ready(matured);
    let span = e.db.size().saturating_sub(e.db.base_size());
    let mut armed = false;
    if !ready && !e.db.subtree_cache_failed() && !e.build_in_flight && notes > 0 && span >= SUBTREE_CACHE_MIN_SPAN {
        // Same memory floor the sync pass applies: warming must never squeeze a scan out.
        match mem_available_mb() {
            Some(free) if free < subtree_build_floor_mb(state.resources.subtree_free_floor_mb, span, !state.build_shared_tree) => {}
            _ => {
                e.wants_cache_build = true;
                armed = true;
            }
        }
    }
    let building = e.build_in_flight || e.wants_cache_build;
    let witnesses_warm = e.witnesses_warm;
    drop(e);
    Ok(Json(serde_json::json!({
        "notes": notes,
        "subtree_cache_ready": ready,
        "witnesses_warm": witnesses_warm,
        "building": building,
        "armed": armed,
    })))
}

/// How often the warm sweep looks for something to do. Cheap when idle-gated out.
const WARM_SWEEP_TICK_SECS: u64 = 30;
/// Rest after a full pass over every wallet before rescanning for new wallets and
/// previously failed installs.
const WARM_SWEEP_REST: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
/// Give up on a wallet whose build keeps failing to install (the stream moved under it
/// every time) after this many attempts in one pass; the next pass tries again.
const WARM_SWEEP_MAX_ATTEMPTS: u32 = 3;

/// Wallet tokens eligible for the warm sweep: every `<token>.scan` in the wallet dir,
/// excluding the shared chain tree and any quarantine/backup artifacts
/// (`*.scan.divergent-*`, `*.scan.stale-*`, `*.scan.bak` — none of which end in `.scan`
/// after the strip, or carry a dot inside the token and are skipped).
fn sweep_candidates(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| {
                let name = e.ok()?.file_name().into_string().ok()?;
                let token = name.strip_suffix(".scan")?;
                if token == CHAIN_TREE_TOKEN || token.contains('.') || token.is_empty() {
                    return None;
                }
                Some(token.to_string())
            })
            .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// Background auto-warm: while the daemon is otherwise idle, bring every known wallet's
/// complete-subtree cache to ready — ONE wallet at a time — so a user's first interaction
/// finds the O(depth) witness path already in place instead of paying the one-time
/// O(chain) build inline (the "first transaction takes longer" reports).
///
/// Why this exists when the sync pass already arms builds: the sync pass only ever sees
/// ACTIVE wallets (touched in the last few minutes). A wallet nobody has opened since the
/// last restart never gets a cache until its owner shows up — and then pays the build at
/// exactly the moment they are watching. The sweep does that work up front, in idle time,
/// and the result is persisted (v8 checkpoint section) and rolls forward on append, so it
/// is paid once per wallet, ever — not once per restart.
///
/// Careful by construction:
///  - runs only when nothing is proving, no consolidation is in flight, memory is above
///    the same floor the sync pass honors, and fewer than half the residency slots are in
///    use (loading a parked wallet must never evict someone's live session);
///  - loads through `get_wallet`, so the ordinary sync/checkpoint/eviction machinery owns
///    the wallet afterwards — the sweep adds no second persistence path;
///  - one build at a time, inline-awaited: the sweep can never pile up background folds.
async fn warm_sweep_loop(state: Arc<AppState>) {
    let mut done: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut attempts: HashMap<String, u32> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(WARM_SWEEP_TICK_SECS)).await;
        if proving_now() || CONSOLIDATING.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            continue;
        }
        if let Some(free) = mem_available_mb() {
            // The wallet is not chosen yet, so size the floor to nothing: on a
            // single-wallet daemon that is the 256 MB minimum, on the hosted one the
            // configured floor.
            if free < subtree_build_floor_mb(state.resources.subtree_free_floor_mb, 0, !state.build_shared_tree) {
                continue;
            }
        }
        if state.wallets.lock().await.len() >= state.resources.max_resident_wallets / 2 {
            continue;
        }
        let Some(token) = sweep_candidates(&state.wallet_dir).into_iter().find(|t| !done.contains(t)) else {
            log::info!("warm sweep: pass complete ({} wallets checked); resting", done.len());
            done.clear();
            attempts.clear();
            tokio::time::sleep(WARM_SWEEP_REST).await;
            continue;
        };
        let Some(w) = state.get_wallet(&token).await else {
            done.insert(token);
            continue;
        };
        let job = {
            let mut e = w.lock().await;
            let matured = e.matured_leaves().unwrap_or(0);
            let span = e.db.size().saturating_sub(e.db.base_size());
            if e.db.notes().is_empty()
                || e.db.subtree_cache_ready(matured)
                || e.db.subtree_cache_failed()
                || span < SUBTREE_CACHE_MIN_SPAN
            {
                done.insert(token.clone());
                None
            } else if !e.caught_up {
                // Still syncing: the stream WILL move under a build (observed 3/3 failed
                // installs on a wallet catching up ~40 leaves/s). Touching it above already
                // made it active, so the sync loop is bringing it to the tip right now —
                // build on a later tick, once the stream is still.
                None
            } else if e.build_in_flight {
                // The sync loop is already building it; check back next tick.
                None
            } else {
                e.build_in_flight = true;
                Some(e.db.subtree_build_job())
            }
        };
        let Some(job) = job else { continue };
        let leaves = job.leaves();
        let t = std::time::Instant::now();
        log::info!("warm sweep: building subtree cache for {token} ({leaves} leaves)");
        let built = run_subtree_build(&state, &token, &token, job).await;
        let mut e = w.lock().await;
        e.build_in_flight = false;
        let installed = built.is_some_and(|b| e.db.install_subtree_cache(b));
        if installed {
            // Expensive and durable: persist so a restart reloads it warm.
            e.force_checkpoint = true;
        }
        drop(e);
        if installed {
            log::info!("warm sweep: {token} spend-ready in {:.1?} ({leaves} leaves, persisted)", t.elapsed());
            done.insert(token);
        } else {
            let n = attempts.entry(token.clone()).or_insert(0);
            *n += 1;
            log::warn!("warm sweep: {token} cache did not install (attempt {n}) — the stream moved under it; will retry");
            if *n >= WARM_SWEEP_MAX_ATTEMPTS {
                done.insert(token);
            }
        }
    }
}

#[cfg(test)]
mod warm_sweep_tests {
    use super::sweep_candidates;

    #[test]
    fn sweep_skips_chain_tree_and_quarantine_artifacts() {
        let dir = std::env::temp_dir().join(format!("sweep-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for f in [
            "aabb.scan",
            "ccdd.scan",
            "__chain.tree__.scan",
            "aabb.scan.divergent-1788080871",
            "ccdd.scan.stale-1788080871",
            "aabb.scan.bak",
            "eeff.wallet",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let got = sweep_candidates(dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(got, vec!["aabb".to_string(), "ccdd".to_string()]);
    }
}

/// Run the daemon until `shutdown` resolves (hold the sender forever to run
/// forever). Returns once the HTTP server has stopped and the background loops are
/// aborted, so an embedding process (the desktop app) can call `serve` again with a
/// new config — e.g. after the user switches nodes.
pub async fn serve(cfg: Config, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
    let listen = cfg.listen;
    // Route node gRPC through Tor/SOCKS when the embedder asked for it, and CLEAR it
    // when they did not -- set on every start so toggling Tor off takes effect (a stale
    // proxy with no Orbot leaves the node unreachable and the wallet stuck "opening").
    // Must happen before the first connect below.
    kaspa_grpc_client::set_node_socks_proxy(cfg.node_socks_proxy.clone());
    let wallet_dir = cfg.wallet_dir;
    let _ = std::fs::create_dir_all(&wallet_dir);

    // Two node connections: one for the request path, one for the background sync loop,
    // so heavy sync traffic can't stall user wallet loads. Retry until the node is up —
    // but stay interruptible, so an embedder can cancel while the node is unreachable.
    async fn connect_node(rpc_server: &str, label: &str) -> GrpcClient {
        loop {
            match GrpcClient::connect_with_args(
                NotificationMode::Direct,
                format!("grpc://{rpc_server}"),
                None,
                true,
                None,
                false,
                Some(500_000),
                Default::default(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    log::warn!("node {rpc_server} ({label}) not reachable yet ({e}); retrying in 3s...");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
    }
    // NOT awaited here. Blocking startup on the node is what turned an unreachable
    // node into "the wallet engine didn't start": the HTTP listener was never bound,
    // so the app could not even show the cached wallet state it already had, and a
    // node problem was indistinguishable from a broken wallet. The connector runs in
    // the background and publishes the channels when they exist; every RPC path
    // already copes with not having them.
    let node_clients: std::sync::Arc<tokio::sync::RwLock<Option<NodeClients>>> = Default::default();
    let node_error: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let connector_task = {
        let rpc_server = cfg.rpc_server.clone();
        let slot = node_clients.clone();
        let err_slot = node_error.clone();
        tokio::spawn(async move {
            loop {
                if slot.read().await.is_some() {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
                let request = connect_node(&rpc_server, "request").await;
                let sync = connect_node(&rpc_server, "sync").await;
                log::info!("connected to node at {rpc_server} (2 connections: request + sync)");
                *err_slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
                *slot.write().await = Some(NodeClients { request, sync });
            }
        })
    };

    let wallet_secret = cfg.wallet_secret;
    // Pulled out before `cfg` is partially moved into AppState below.
    let tls = cfg.tls;
    let require_bearer = cfg.require_bearer;
    let idle_timeout = cfg.idle_timeout;
    if wallet_secret.is_none() {
        log::warn!("no wallet secret set: seed files are stored in PLAINTEXT (0600 on unix)");
    }
    if cfg.allow_default_token {
        log::warn!("allow_default_token: tokenless requests map to the 'default' wallet; use only on a trusted single-user localhost");
    }
    if !cfg.allow_custodial {
        log::info!("custodial endpoints disabled (--no-custodial): create/import/send/send_many/reveal/consolidate/sign return 403");
    }

    // The network genesis hash — the shielded sighash domain consensus verifies
    // against, and the checkpoint guard. Taken from the compile-time network
    // params (identical to what consensus signs against); resolving it over RPC
    // (`get_blocks(None)`) fails on any pruned node, whose genesis chain data is
    // gone.
    let genesis = RpcHash::from_bytes(
        kaspa_consensus_core::config::params::Params::from(state_prefix_network(&cfg.network)).genesis.hash.as_bytes(),
    );
    log::info!("network genesis (shielded sighash domain): {genesis}");

    let resources = cfg.resources.clone();
    log::info!("wallet resource limits: {:?}", resources);
    let chain_tree = build_chain_tree(&wallet_dir, genesis);
    let state = Arc::new(AppState {
        clients: node_clients.clone(),
        node_error: node_error.clone(),
        chain_tree: chain_tree.clone(),
        chain_tree_size: std::sync::atomic::AtomicU64::new(0),
        chain_tree_base: std::sync::atomic::AtomicU64::new(0),
        chain_tree_frontier: Mutex::new(None),
        wallet_dir,
        prefix: prefix_from(&cfg.network),
        network: cfg.network,
        wallets: Mutex::new(HashMap::new()),
        allow_default_token: cfg.allow_default_token,
        wallet_secret,
        genesis,
        page_cache: Mutex::new(PageCache::new(&resources)),
        last_touch: Mutex::new(HashMap::new()),
        load_gate: tokio::sync::Semaphore::new(resources.load_wallets.max(1)),
        // Concurrent preparations are capped by config (`--max-concurrent-proves`):
        // proving is CPU-heavy, and unbounded overlap is a CPU DoS on a hosted daemon.
        prepare_gate: tokio::sync::Semaphore::new(cfg.max_concurrent_proves.max(1)),
        // Scaled to the prover, with headroom reserved for payments.
        //
        // This was hardcoded to 1, and the reasoning for that was sound WHEN IT WAS
        // WRITTEN: the hosted daemon ran `--max-concurrent-proves 1`, so a second
        // concurrent consolidation was impossible anyway and the constant only said so
        // out loud. That daemon now runs 6, and the constant did not follow — so one
        // tenant's merge held the only consolidation slot for the ~7.5 minutes its
        // witness build takes, while five prove slots sat idle and every other user's
        // Consolidate button answered "another wallet is consolidating right now".
        //
        // Half the prover, minimum one. Consolidation still YIELDS to payments — it takes
        // its slot with `try_acquire` and gives up rather than queueing — and capping it
        // at half means a burst of merges can never starve the payments somebody is
        // actually waiting on.
        consolidate_gate: tokio::sync::Semaphore::new((cfg.max_concurrent_proves / 2).max(1)),
        preparing: std::sync::Mutex::new(HashMap::new()),
        cache_builds: std::sync::Mutex::new(HashMap::new()),
        warm_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(resources.warm_wallets.max(1))),
        node_tip: Mutex::new((0, std::time::Instant::now())),
        prepared: Mutex::new(HashMap::new()),
        snapshots: Mutex::new(HashMap::new()),
        addr_index: Mutex::new(HashMap::new()),
        in_pass: std::sync::Mutex::new(HashSet::new()),
        fvk_index: Mutex::new(HashMap::new()),
        auto_consolidate: cfg.auto_consolidate,
        build_shared_tree: cfg.build_shared_tree,
        allow_custodial: cfg.allow_custodial,
        resources,
    });

    // Register the chain tree as an ordinary resident wallet so the ordinary sync loop
    // advances it and the ordinary checkpoint path persists it. Same `Arc` as
    // `state.chain_tree`, so both views are one object. It is never returned by
    // `get_wallet` (no request can name its token) and never evicted.
    state.wallets.lock().await.insert(CHAIN_TREE_TOKEN.to_string(), chain_tree);
    // Publish its reach immediately. A checkpoint-resumed tree already covers most of
    // the chain, and without this every wallet would build its own tree for one whole
    // pass before the first republish — the slow path, for no reason.
    {
        let c = state.chain_tree.lock().await;
        state.chain_tree_size.store(c.db.size(), std::sync::atomic::Ordering::Relaxed);
        state.chain_tree_base.store(c.db.base_size(), std::sync::atomic::Ordering::Relaxed);
        let fs = c.db.tip_frontier_state();
        drop(c);
        *state.chain_tree_frontier.lock().await = fs;
    }

    // GPU acceleration for trial decryption, on by default when a device is present.
    // `install_gpu_agree` is a no-op on hosts without one, and every scan then takes the
    // CPU path — same results, only slower. A device that ever misbehaves poisons itself
    // and the daemon carries on, so this can make the wallet faster but never wrong.
    match std::env::var("ZKAS_GPU").as_deref() {
        Ok("off") | Ok("0") => log::info!("GPU disabled by ZKAS_GPU=off; trial decryption stays on the CPU"),
        _ => {
            if let Some(gpu) = zkas_gpu::Gpu::load() {
                let devices = gpu.devices();
                kaspa_shielded_core::wallet::install_gpu_agree(Box::new(move |ivk, epks| gpu.batch_agree_points(ivk, epks)));
                log::info!("GPU trial decryption enabled ({devices} device(s))");
            } else {
                log::info!("no GPU found; trial decryption stays on the CPU");
            }
        }
    }

    // Index every existing wallet's viewing key in the background (argon2 per
    // encrypted seed file — a blocking thread, not the startup path), then MERGE
    // into the live index so registrations that landed while it built survive.
    // Until it finishes, adoption just misses and a restore scans as before.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let (dir, secret) = (state.wallet_dir.clone(), state.wallet_secret.clone());
            let started = std::time::Instant::now();
            if let Ok(map) = tokio::task::spawn_blocking(move || build_fvk_index(&dir, secret.as_deref())).await {
                let mut idx = state.fvk_index.lock().await;
                let wallets = map.values().map(|s| s.len()).sum::<usize>();
                for (k, tokens) in map {
                    idx.entry(k).or_default().extend(tokens);
                }
                log::info!(
                    "viewing-key index ready: {} keys / {wallets} wallets in {:.1?} (twin-checkpoint adoption armed)",
                    idx.len(),
                    started.elapsed()
                );
            }
        });
    }

    let sync_task = tokio::spawn(sync_loop(state.clone()));
    let eviction_task = tokio::spawn(eviction_loop(state.clone()));
    // Unmined payments — the instant-payment path. Separate from sync_loop on purpose
    // (see mempool_loop): it must never queue behind block scanning.
    let mempool_task = tokio::spawn(mempool_loop(state.clone()));
    // No-op unless --auto-consolidate is set; returns immediately when it is not.
    let consolidate_task = tokio::spawn(consolidate_loop(state.clone()));
    let warm_sweep_task = tokio::spawn(warm_sweep_loop(state.clone()));

    // Keep the cached node tip fresh independently of loaded wallets, so `status` can
    // report node connectivity + chain height without ever calling the node on the
    // request path (which was contended by the sync loop and made status take ~4s).
    let tip_task = {
        let state = state.clone();
        tokio::spawn(async move {
            let mut failures = 0u32;
            loop {
                match state.request_client().await {
                    None => {
                        // No channel yet; the connector is working on it.
                    }
                    Some(c) => match c.get_block_dag_info().await {
                        Ok(d) => {
                            failures = 0;
                            *state.node_error.lock().unwrap_or_else(|p| p.into_inner()) = None;
                            *state.node_tip.lock().await = (d.virtual_daa_score, std::time::Instant::now());
                        }
                        Err(e) => {
                            failures += 1;
                            *state.node_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
                            // A channel can stay "open" onto a node that has gone away, so
                            // reconnecting has to be driven by failures rather than by the
                            // transport noticing. Three strikes keeps a blip from cycling it.
                            if failures >= 3 {
                                log::warn!("node connection failed {failures} health probes ({e}); reconnecting");
                                *state.clients.write().await = None;
                                failures = 0;
                            }
                        }
                    },
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        })
    };

    // Build the (deterministic, process-wide) Orchard proving key now, off the
    // async runtime, so the first send doesn't eat the multi-minute keygen.
    std::thread::spawn(|| {
        let started = std::time::Instant::now();
        let _ = proving_key();
        log::info!("Orchard proving key ready in {:.0?} (max {} spends per standard tx)", started.elapsed(), max_spends_per_tx());
    });

    // Lock CORS to an explicit browser-origin allowlist. With no allowed origin given
    // the list is empty, so cross-origin browser reads are refused (same-origin only):
    // a random page a user visits can no longer read /reveal or call /send.
    let origins: Vec<HeaderValue> = cfg
        .allow_origin
        .iter()
        .filter_map(|o| match o.parse::<HeaderValue>() {
            Ok(hv) => Some(hv),
            Err(_) => {
                log::error!("ignoring invalid allow_origin {o:?}");
                None
            }
        })
        .collect();
    log::info!("CORS allowed origins: {:?}", cfg.allow_origin);
    let cors = tower_http::cors::CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        // `authorization` belongs here or an exposed daemon is unreachable by
        // construction: it REQUIRES a bearer token, while a browser refuses to send
        // a header the preflight did not permit. Omitting it made every LAN/WAN
        // deployment fail as an unexplained network error, no matter how correct the
        // address and token were.
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, HeaderName::from_static("x-wallet-token")])
        // A deliberately exposed daemon (bearer configured, bound off loopback) is
        // reached from installed apps whose page origin is a synthetic scheme —
        // Capacitor serves the Android bundle from `https://localhost`. Chromium
        // cannot resolve such an origin to an IP address space, treats it as public,
        // and therefore sends a Private Network Access preflight before any request
        // to a LAN address. An unanswered PNA preflight fails with no status at all.
        // The loopback default stays off, so a public web page still cannot reach a
        // wallet daemon on the user's own machine.
        .allow_private_network(require_bearer.is_some())
        // Let the browser cache the preflight. tower-http sets no Access-Control-Max-Age
        // by default, and the WebView then falls back to its own ~5 s cache — so the
        // Android app (origin `https://localhost`, `X-Wallet-Token` on every call, hence
        // never a "simple" request) re-ran an OPTIONS round trip through nginx and the
        // tunnel every few seconds of its 1 s status poll, and paid one on the first
        // call after any pause. The policy never changes at runtime, so a day is safe.
        .max_age(std::time::Duration::from_secs(86_400))
        .allow_origin(origins);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/status", get(status))
        .route("/api/checkpoint", post(checkpoint))
        .route("/api/wallet/create", post(wallet_create))
        .route("/api/wallet/import", post(wallet_import))
        .route("/api/wallet/watch", post(wallet_watch))
        .route("/api/wallet/address", get(wallet_address))
        .route("/api/wallet/reveal", get(wallet_reveal))
        .route("/api/wallet/balance", get(wallet_balance))
        .route("/api/wallet/history", get(wallet_history))
        .route("/api/wallet/settings", post(wallet_settings))
        .route("/api/wallet/rescan", post(wallet_rescan))
        .route("/api/wallet/send", post(wallet_send))
        .route("/api/wallet/send_many", post(wallet_send_many))
        .route("/api/wallet/consolidate", post(wallet_consolidate))
        .route("/api/wallet/prepare", post(wallet_prepare))
        .route("/api/wallet/submit", post(wallet_submit))
        .route("/api/wallet/sign", post(wallet_sign))
        .route("/api/verify", post(verify))
        // Operator tools: force the shared tree / a wallet to the tip on demand, so a
        // restart's catch-up window can be closed by hand instead of waited out.
        .route("/api/admin/warm_chain_tree", post(warm_chain_tree))
        .route("/api/admin/warm_wallet", post(warm_wallet))
        // Public, token-scoped warm: the app calls it when a wallet is opened so the
        // send path is already fast by the time the user reaches it.
        .route("/api/wallet/warm", post(wallet_warm))
        .with_state(state.clone());

    // Transport auth: gate every route behind the bearer token when one is configured
    // (self-hosting / public bind). Loopback deployments pass `None` and skip it.
    let app = match require_bearer {
        Some(token) => app.layer(from_fn_with_state(std::sync::Arc::new(token), bearer_guard)),
        None => app,
    };

    // CORS goes on LAST so it is the OUTERMOST layer, and therefore also decorates
    // the responses the auth layer short-circuits. With the order reversed, a wrong
    // or missing bearer produced a 401 carrying no `Access-Control-Allow-Origin`, so
    // the browser withheld the response from the page and the caller could only
    // report an opaque transport failure — indistinguishable from a wrong address, a
    // closed port or a firewall. An error the caller can read is the difference
    // between a five-second fix and an unfalsifiable one.
    let app = app.layer(cors);

    // Idle shutdown. The marker sits INSIDE the CORS layer so a preflight — which the
    // browser sends on its own, without the user doing anything — does not count as
    // use, and outside auth so a rejected caller still proves somebody is talking to
    // this daemon.
    let (app, idle_clock) = match idle_timeout {
        Some(limit) => {
            let clock = std::sync::Arc::new(IdleClock::new());
            let marker = clock.clone();
            (
                app.layer(from_fn(move |req: Request, next: Next| {
                    let marker = marker.clone();
                    async move {
                        // A monitor polling /health must not hold the door open.
                        if req.uri().path() != "/health" {
                            marker.touch();
                        }
                        next.run(req).await
                    }
                })),
                Some((clock, limit)),
            )
        }
        None => (app, None),
    };

    // One shutdown signal for the server, fed by either the caller's or the idle
    // bound. Without merging them the embedding process (the desktop shell) could
    // no longer stop the daemon once an idle timer was armed.
    let shutdown = match idle_clock {
        None => shutdown,
        Some((clock, limit)) => {
            let (idle_tx, idle_rx) = tokio::sync::oneshot::channel::<()>();
            log::info!("idle shutdown armed: stopping after {limit:?} with no wallet API request");
            tokio::spawn(async move {
                let tick = std::time::Duration::from_secs(15).min(limit);
                loop {
                    tokio::select! {
                        _ = &mut shutdown => return, // caller stopped us first
                        _ = tokio::time::sleep(tick) => {
                            if clock.idle_for() >= limit {
                                log::info!("no wallet API request for {limit:?}; shutting down");
                                let _ = idle_tx.send(());
                                return;
                            }
                        }
                    }
                }
            });
            idle_rx
        }
    };

    let result = match tls {
        // HTTPS directly — no reverse proxy. The client pins the cert fingerprint from the
        // pairing QR, so the self-signed cert is trusted for exactly this node.
        Some(id) => {
            log::info!("zkas-walletd listening on https://{listen} (self-signed, fingerprint {})", id.fingerprint);
            let tls_cfg = axum_server::tls_rustls::RustlsConfig::from_pem(id.cert_pem, id.key_pem)
                .await
                .map_err(|e| format!("load TLS identity: {e}"))?;
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                let _ = shutdown.await;
                h.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
            });
            axum_server::bind_rustls(listen, tls_cfg)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .map_err(|e| format!("server error: {e}"))
        }
        None => {
            log::info!("zkas-walletd listening on http://{listen}");
            let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("failed to bind {listen}: {e}"))?;
            // Bound the drain. `with_graceful_shutdown` waits for every in-flight
            // connection to close, and a browser/proxy keep-alive connection may simply
            // never close — so this waited forever. Observed 2026-08-07 on the first
            // SIGTERM: the listener was released (API down, 000) while the process stayed
            // alive still syncing, and the checkpoint flush below never ran. Worse, the
            // freed port lets a restart bind while the old process is still writing the
            // same wallet files.
            //
            // The TLS branch above was already bounded (`graceful_shutdown(Some(2s))`);
            // this one was not. After the deadline we stop waiting and go flush, which is
            // the part that actually protects the user's scan progress.
            const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
            let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
            let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = shutdown.await;
                let _ = drain_tx.send(());
                let _ = deadline_tx.send(());
            });
            tokio::select! {
                r = axum::serve(listener, app).with_graceful_shutdown(async move { let _ = drain_rx.await; }) => {
                    r.map_err(|e| format!("server error: {e}"))
                }
                _ = async move {
                    let _ = deadline_rx.await;
                    tokio::time::sleep(DRAIN_GRACE).await;
                } => {
                    log::warn!("connections did not drain within {DRAIN_GRACE:?}; proceeding to flush checkpoints anyway");
                    Ok(())
                }
            }
        }
    };
    // The loops hold node connections and wallet state; kill them so a re-`serve`
    // starts clean instead of double-scanning the same wallet files.
    //
    // EVERY endless loop belongs here. `serve` is re-callable by design — the desktop
    // shell calls it again whenever the user switches nodes — and the two that were
    // missing leaked on every such switch. The connector kept two gRPC channels open
    // and went on reconnecting to the node the user had just left, and the merger held
    // an `Arc<AppState>`, so the previous daemon's wallets, trees and caches were never
    // reclaimed: switch nodes five times and five full wallet states stay resident,
    // each still talking to a node nobody asked about.
    sync_task.abort();
    eviction_task.abort();
    mempool_task.abort();
    tip_task.abort();
    connector_task.abort();
    consolidate_task.abort();
    warm_sweep_task.abort();
    flush_checkpoints_on_exit(&state).await;
    result
}

/// Flush the scan checkpoint of the wallet under `only` (or of every resident wallet
/// when `only` is None) to disk now. Returns (wallets saved, wallets considered,
/// blocks of progress preserved). Skips wallets in error and wallets whose on-disk
/// checkpoint already matches memory, so calling it often is cheap.
async fn flush_checkpoints(state: &Arc<AppState>, only: Option<&str>) -> (usize, usize, usize) {
    let resident: Vec<(String, Wallet)> = {
        state
            .wallets
            .lock()
            .await
            .iter()
            .filter(|(k, _)| only.map_or(true, |t| t == k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let total = resident.len();
    let (mut saved, mut blocks) = (0usize, 0usize);
    for (token, w) in resident {
        let mut e = w.lock().await;
        if e.error.is_some() || e.saved_scanned == e.scanned {
            continue;
        }
        let advanced = e.scanned.saturating_sub(e.saved_scanned);
        if save_checkpoint(
            &state.wallet_dir,
            &token,
            &e.genesis,
            &e.low,
            e.scanned as u64,
            &e.db,
            &e.boundaries,
            e.sink_blue,
            e.blind_below,
        )
        .is_ok()
        {
            e.saved_scanned = e.scanned;
            e.last_checkpoint_at = std::time::Instant::now();
            saved += 1;
            blocks += advanced;
        }
    }
    (saved, total, blocks)
}

/// `POST /api/checkpoint` — write the caller's wallet checkpoint NOW.
///
/// The sync loop checkpoints every `CHECKPOINT_EVERY` blocks and on graceful shutdown.
/// A phone gives neither guarantee: Android freezes or kills the app process the moment
/// the screen goes dark, with no shutdown at all, so everything scanned since the last
/// periodic save was redone on the next open — seen by users as the sync "going back to
/// 0". The app calls this as it goes to the background, so the checkpoint is as fresh as
/// that moment. Token-scoped: a hosted daemon flushes only the caller's wallet.
async fn checkpoint(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<serde_json::Value> {
    let only = token_from(&headers, state.allow_default_token).ok();
    let (saved, total, blocks) = flush_checkpoints(&state, only.as_deref()).await;
    if blocks > 0 {
        log::info!("checkpoint on request: saved {saved}/{total} wallet(s), preserving {blocks} block(s) of scan progress");
    }
    Json(serde_json::json!({ "saved": saved, "resident": total, "blocks": blocks }))
}

/// Persist every resident wallet's scan progress on the way out.
async fn flush_checkpoints_on_exit(state: &Arc<AppState>) {
    let started = std::time::Instant::now();
    let (saved, total, blocks) = flush_checkpoints(state, None).await;
    log::info!(
        "shutdown: flushed {saved}/{total} wallet checkpoint(s) in {:.1?}, preserving {blocks} block(s) of scan progress that a restart would otherwise redo",
        started.elapsed()
    );
}

#[cfg(test)]
mod token_bookkeeping_tests {
    use super::keep_touch;
    use std::time::Duration;

    /// `touch` records a token on every /api/status, BEFORE anything establishes that
    /// the wallet exists, and the token comes straight from a client header. Nothing
    /// removed those entries, so a caller sending fresh random tokens grew the map
    /// without bound — a public daemon's memory driven by a request header.
    #[test]
    fn a_stranger_token_is_forgotten_once_it_leaves_the_window() {
        let window = Duration::from_secs(120);
        assert!(keep_touch(Duration::from_secs(1), window, false), "recent tokens still decide the active set");
        assert!(!keep_touch(Duration::from_secs(600), window, false), "a stale token nobody owns is dropped");
    }

    /// A resident wallet is kept whatever its age: it is parked, not gone, and the
    /// sync loop reads this map to decide what is active. Dropping it would strand a
    /// wallet that is still in memory.
    #[test]
    fn a_resident_wallet_is_kept_however_long_it_has_been_quiet() {
        assert!(keep_touch(Duration::from_secs(86_400), Duration::from_secs(120), true));
    }
}

#[cfg(test)]
mod idle_bound_tests {
    use super::*;
    use std::time::Duration;

    /// The marker must measure time since the LAST use, not since start-up.
    #[test]
    fn idle_is_measured_from_the_most_recent_request() {
        let clock = IdleClock::new();
        std::thread::sleep(Duration::from_millis(40));
        assert!(clock.idle_for() >= Duration::from_millis(35), "un-touched clock counts from start");
        clock.touch();
        assert!(clock.idle_for() < Duration::from_millis(20), "a request resets the bound");
    }

    /// A daemon that has never been called is idle, not exempt. The opposite reading
    /// would leave an exposed service open forever precisely when nobody is using it.
    #[test]
    fn a_daemon_nobody_has_called_is_idle() {
        let clock = IdleClock::new();
        std::thread::sleep(Duration::from_millis(30));
        assert!(clock.idle_for() >= Duration::from_millis(25));
    }

    /// `--idle-timeout 0` means "never", matching what someone typing 0 to switch the
    /// feature off expects — not "shut down at once".
    #[test]
    fn zero_minutes_disables_the_bound() {
        let resolve = |m: Option<u64>| m.filter(|m| *m > 0).map(|m| Duration::from_secs(m * 60));
        assert_eq!(resolve(None), None);
        assert_eq!(resolve(Some(0)), None);
        assert_eq!(resolve(Some(30)), Some(Duration::from_secs(1800)));
    }
}

#[cfg(test)]
mod sdk_api_tests {
    use super::*;

    #[test]
    fn prepare_accepts_exact_decimal_u64_values() {
        let request: PrepareReq = serde_json::from_value(serde_json::json!({
            "fvk_hex": "00",
            "to": "zkas:test",
            "amount_sompi": "18446744073709551615",
            "fee": "3000000"
        }))
        .unwrap();
        assert_eq!(request.amount_sompi.unwrap().parse("amount_sompi").unwrap(), u64::MAX);
        assert_eq!(request.fee.unwrap().parse("fee").unwrap(), 3_000_000);
    }

    #[test]
    fn prepare_keeps_legacy_numeric_values_compatible() {
        let request: PrepareReq = serde_json::from_value(serde_json::json!({
            "fvk_hex": "00",
            "to": "zkas:test",
            "amount_sompi": 100,
            "fee": 3
        }))
        .unwrap();
        assert_eq!(request.amount_sompi.unwrap().parse("amount_sompi").unwrap(), 100);
        assert_eq!(request.fee.unwrap().parse("fee").unwrap(), 3);
    }

    #[test]
    fn send_many_accepts_exact_decimal_u64_values() {
        let request: SendManyReq = serde_json::from_value(serde_json::json!({
            "payees": [{
                "to": "zkas:test",
                "amount_sompi": "18446744073709551615"
            }],
            "fee": "3000000"
        }))
        .unwrap();
        assert_eq!(request.payees[0].amount_sompi.as_ref().unwrap().parse("amount_sompi").unwrap(), u64::MAX);
        assert_eq!(request.fee.as_ref().unwrap().parse("fee").unwrap(), 3_000_000);
    }

    #[test]
    fn send_many_keeps_legacy_numeric_values_compatible() {
        let request: SendManyReq = serde_json::from_value(serde_json::json!({
            "payees": [{ "to": "zkas:test", "amount_sompi": 100 }],
            "fee": 3
        }))
        .unwrap();
        assert_eq!(request.payees[0].amount_sompi.as_ref().unwrap().parse("amount_sompi").unwrap(), 100);
        assert_eq!(request.fee.as_ref().unwrap().parse("fee").unwrap(), 3);
    }

    /// A backup must restore the SAME wallet on another device, and must refuse
    /// a wrong passphrase, a foreign file, and clobbering a live wallet. A
    /// backup that cannot restore is worse than no backup — the user believes
    /// they are covered.
    #[test]
    fn backup_roundtrips_and_refuses_bad_input() {
        let tmp = std::env::temp_dir().join(format!("zkas-backup-test-{}", std::process::id()));
        let dir = tmp.to_string_lossy().to_string();
        std::fs::create_dir_all(&dir).unwrap();
        let seed = [0x5au8; 32];

        // A device wallet encrypted under the device passphrase.
        save_seed(&dir, "src", "mainnet", &seed, 4242, Some("device-passphrase")).unwrap();
        assert_eq!(vault_state(&dir, "src"), VaultState::Encrypted);

        let json = export_backup(&dir, "src", Some("device-passphrase"), "backup-passphrase").unwrap();
        // The backup must not be readable without its own passphrase.
        assert!(!json.contains(&hex(&seed)), "backup must not carry the seed in the clear");

        // Restoring on a "new device" (a different wallet dir) recovers the seed.
        let dir2 = format!("{dir}-restore");
        std::fs::create_dir_all(&dir2).unwrap();
        import_backup(&dir2, "dst", &json, "backup-passphrase", "new-device-pass").unwrap();
        let (key, birthday, _) = load_wallet_meta(&dir2, "dst", Some("new-device-pass")).unwrap();
        assert_eq!(birthday, 4242, "birthday survives so the restore does not rescan from genesis");
        match key {
            WalletKey::Seed(s) => assert_eq!(s, seed, "restored seed is identical"),
            WalletKey::Fvk(_) => panic!("expected a seed wallet"),
        }
        assert_eq!(vault_state(&dir2, "dst"), VaultState::Encrypted, "restored wallet is encrypted at rest");

        // Wrong backup passphrase, foreign file, and clobbering are all refused.
        let dir3 = format!("{dir}-neg");
        std::fs::create_dir_all(&dir3).unwrap();
        assert!(import_backup(&dir3, "x", &json, "not-the-passphrase", "new-device-pass").is_err());
        assert!(import_backup(&dir3, "x", "{\"hello\":1}", "backup-passphrase", "new-device-pass").is_err());
        assert!(
            import_backup(&dir2, "dst", &json, "backup-passphrase", "new-device-pass").is_err(),
            "must not overwrite an existing wallet"
        );

        // Wrong DEVICE passphrase cannot export.
        assert!(export_backup(&dir, "src", Some("wrong"), "backup-passphrase").is_err());

        // A legacy cleartext wallet encrypts in place, then still exports.
        save_seed(&dir, "legacy", "mainnet", &seed, 0, None).unwrap();
        assert_eq!(vault_state(&dir, "legacy"), VaultState::Plaintext);
        encrypt_wallet_in_place(&dir, "legacy", "device-passphrase").unwrap();
        assert_eq!(vault_state(&dir, "legacy"), VaultState::Encrypted);
        assert!(verify_wallet_secret(&dir, "legacy", "device-passphrase"));
        assert!(!verify_wallet_secret(&dir, "legacy", "nope"));
        assert!(export_backup(&dir, "legacy", Some("device-passphrase"), "backup-passphrase").is_ok());

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&dir2).ok();
        std::fs::remove_dir_all(&dir3).ok();
    }

    /// "Enter the seed on a second device → synced at once": a registration whose
    /// viewing key another token already scanned must clone that checkpoint, and
    /// the clone must parse under EITHER key form (the desktop imported the seed;
    /// the phone registers only the FVK — same wallet, same checkpoint).
    #[test]
    fn twin_checkpoint_adoption_clones_and_verifies() {
        let tmp = std::env::temp_dir().join(format!("zkas-adopt-test-{}", std::process::id()));
        let dir = tmp.to_string_lossy().to_string();
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let genesis = RpcHash::from_bytes([7u8; 32]);
        let seed = [0x5au8; 32];
        let db = WalletDb::from_seed(seed).expect("valid seed");
        let fvk = db.fvk().to_bytes();

        // Donor: a seed wallet with a persisted, complete-view checkpoint.
        save_seed(&dir, "donor", "mainnet", &seed, 4242, None).unwrap();
        let boundaries: VecDeque<(u64, u64)> = VecDeque::from([(100, 0)]);
        save_checkpoint(&dir, "donor", &genesis, &RpcHash::from_bytes([9u8; 32]), 777, &db, &boundaries, 100, 0).unwrap();

        // The index build finds the donor by viewing key.
        let index = build_fvk_index(&dir, None);
        assert_eq!(index.get(&fvk).map(|s| s.contains("donor")), Some(true), "index must find the donor by FVK");
        let candidates: Vec<String> = index.get(&fvk).unwrap().iter().cloned().collect();

        // A fresh FVK registration adopts the donor's checkpoint, keeping the
        // EARLIER birthday so a later cold rescan can't skip either wallet's notes.
        let (donor, birthday) = adopt_twin_checkpoint(&dir, "phone", &fvk, 9999, false, &genesis, None, &candidates).expect("must adopt");
        assert_eq!(donor, "donor");
        assert_eq!(birthday, 4242, "keeps the earlier of donor/requested birthdays");
        let restored =
            load_checkpoint(&dir, "phone", WalletKey::Fvk(fvk), &genesis, None).expect("clone parses under the FVK key form");
        assert_eq!(restored.2, 777, "scanned-block cursor survives the clone");

        // A DIFFERENT key must never adopt, however many donors exist.
        let other = WalletDb::from_seed([0x33u8; 32]).unwrap().fvk().to_bytes();
        assert!(
            adopt_twin_checkpoint(&dir, "other", &other, 0, false, &genesis, None, &candidates).is_none(),
            "foreign viewing key must not clone someone else's checkpoint"
        );

        // A donor that is BLIND below its fast-sync base must not serve a restore that
        // claims an EARLIER birthday than the donor's...
        save_checkpoint(&dir, "donor", &genesis, &RpcHash::from_bytes([9u8; 32]), 777, &db, &boundaries, 100, 555).unwrap();
        std::fs::remove_file(scan_path(&dir, "phone")).unwrap();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 1000, false, &genesis, None, &candidates).is_none(),
            "a blind donor must not answer a restore born before it"
        );
        // ...but a registration with NO birthday opinion (0) adopts the donor AND its
        // birthday, instead of rescanning from genesis and persisting 0.
        let (_, adopted) = adopt_twin_checkpoint(&dir, "phone", &fvk, 0, false, &genesis, None, &candidates).expect("unknown birthday adopts");
        assert_eq!(adopted, 4242, "the donor's birthday is adopted when the client has none");
        std::fs::remove_file(scan_path(&dir, "phone")).unwrap();
        // ...and one that asked for the same-or-later birthday.
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 5000, false, &genesis, None, &candidates).is_some(),
            "a blind donor is fine for a restore born at/after the donor"
        );

        // A wallet that keeps history must not clone a donor that does not: the donor's
        // checkpoint has no rows, and the History tab would go empty (2026-09-19).
        std::fs::remove_file(scan_path(&dir, "phone")).ok();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 5000, true, &genesis, None, &candidates).is_none(),
            "a history-on wallet must not adopt a history-off donor"
        );
        save_seed(&dir, "donor", "mainnet", &seed, 4242, None).unwrap();
        std::fs::write(wallet_path(&dir, "donor"), std::fs::read_to_string(wallet_path(&dir, "donor")).unwrap().replace("\"recoverable_history\": false", "\"recoverable_history\": true")).unwrap();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 5000, true, &genesis, None, &candidates).is_some(),
            "a history-on donor serves a history-on wallet"
        );
        std::fs::write(wallet_path(&dir, "donor"), std::fs::read_to_string(wallet_path(&dir, "donor")).unwrap().replace("\"recoverable_history\": true", "\"recoverable_history\": false")).unwrap();

        // A wrong-genesis (relaunched-chain) checkpoint must never be adopted.
        std::fs::remove_file(scan_path(&dir, "phone")).unwrap();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 9999, false, &RpcHash::from_bytes([8u8; 32]), None, &candidates).is_none(),
            "checkpoint for another chain must not be adopted"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The SDK republishes this daemon's timing constants and genesis so that
    /// external wallets hold back / anchor exactly like the production engine.
    /// They are separate definitions in separate crates — this is the tripwire
    /// that keeps them the same numbers.
    #[test]
    fn sdk_network_config_matches_walletd_and_consensus() {
        let cfg = zkas_sdk::NetworkConfig::mainnet();
        assert_eq!(cfg.settlement_blue_score, SYNC_TIP_MARGIN, "SDK settlement margin drifted from walletd");
        assert_eq!(cfg.anchor_depth, DEFAULT_ANCHOR_DEPTH, "SDK anchor depth drifted from walletd");
        assert_eq!(
            cfg.genesis,
            kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes(),
            "SDK genesis drifted from consensus"
        );
    }

    #[test]
    fn decode_block_prefers_node_commitment_and_keeps_legacy_fallback() {
        let db = WalletDb::from_seed([0x31; 32]).expect("valid test seed");
        let recipient = db.my_address_bytes();
        let txid = RpcHash::from_bytes([0x42; 32]);
        let mut seed = Vec::with_capacity(36);
        seed.extend_from_slice(&txid.as_bytes());
        seed.extend_from_slice(&0u32.to_le_bytes());
        let desc = derive_coinbase_note_desc(recipient, &seed);
        let value = 60_00000000;
        let expected = kaspa_shielded_core::coinbase::coinbase_note_commitment(&desc, value).unwrap();
        let base = kaspa_rpc_core::RpcShieldedChainBlock {
            hash: RpcHash::from_bytes([1; 32]),
            blue_score: 1,
            daa_score: 1,
            coinbase_txid: txid,
            coinbase_outputs: vec![kaspa_rpc_core::RpcShieldedCoinbaseOutput {
                script_public_key: recipient.to_vec(),
                value,
                commitment: None,
            }],
            accepted_actions: Vec::new(),
            accepted_txids: Vec::new(),
            timestamp: 0,
        };
        let legacy = decode_block(&base);
        assert_eq!(legacy.coinbase[0].2.to_bytes(), expected.to_bytes());

        let mut other_seed = seed;
        other_seed[35] = 1;
        let supplied_cmx =
            kaspa_shielded_core::coinbase::coinbase_note_commitment(&derive_coinbase_note_desc(recipient, &other_seed), value)
                .unwrap();
        let mut with_commitment = base;
        with_commitment.coinbase_outputs[0].commitment = Some(supplied_cmx.to_bytes());
        // Secure default: a supplied-but-wrong commitment is rejected in favour of
        // the locally-derived (PoW-committed-input) value.
        let supplied = decode_block(&with_commitment);
        assert_eq!(supplied.coinbase[0].2.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn select_coinbase_cmx_verifies_and_rejects_wrong_node_value() {
        let db = WalletDb::from_seed([0x37; 32]).expect("valid test seed");
        let recipient = db.my_address_bytes();
        let txid = RpcHash::from_bytes([0x55; 32]);
        let mut seed = Vec::with_capacity(36);
        seed.extend_from_slice(&txid.as_bytes());
        seed.extend_from_slice(&0u32.to_le_bytes());
        let desc = derive_coinbase_note_desc(recipient, &seed);
        let value = 60_00000000u64;
        let derived = kaspa_shielded_core::coinbase::coinbase_note_commitment(&desc, value).unwrap();
        let mut other = seed.clone();
        other[35] = 1;
        let wrong = kaspa_shielded_core::coinbase::coinbase_note_commitment(
            &derive_coinbase_note_desc(recipient, &other),
            value,
        )
        .unwrap();
        assert_ne!(derived.to_bytes(), wrong.to_bytes());

        // verify mode: a wrong supplied value is rejected -> derived wins
        assert_eq!(select_coinbase_cmx(Some(wrong), &desc, value, false).unwrap().to_bytes(), derived.to_bytes());
        // verify mode: honest supplied (== derived) is accepted
        assert_eq!(select_coinbase_cmx(Some(derived), &desc, value, false).unwrap().to_bytes(), derived.to_bytes());
        // verify mode: no supplied value -> derive locally
        assert_eq!(select_coinbase_cmx(None, &desc, value, false).unwrap().to_bytes(), derived.to_bytes());
        // trust mode (opt-in fast path): supplied value used verbatim
        assert_eq!(select_coinbase_cmx(Some(wrong), &desc, value, true).unwrap().to_bytes(), wrong.to_bytes());
    }
}
