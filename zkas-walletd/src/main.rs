//! Thin CLI over the `zkas-walletd` library — flag parsing and bind policy only;
//! the daemon itself (REST API, sync loops, shielded engine) lives in `lib.rs` so
//! the desktop wallet can embed it in-process.

use clap::Parser;
use std::net::SocketAddr;
use zkas_walletd::{Config, default_wallet_dir, serve};

#[derive(Parser, Debug)]
#[command(name = "zkas-walletd", about = "ZKas shielded wallet daemon (self-hosted or hosted)")]
struct Cli {
    /// ZKas node gRPC endpoint (host:port). In hosted mode, a public node.
    #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
    rpc_server: String,
    /// Address:port to serve the wallet REST API on. Loopback by default.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8501")]
    listen: String,
    /// Directory holding one wallet file per token. Default: ~/.ZKas/wallets.
    #[arg(long)]
    wallet_dir: Option<String>,
    /// Network: mainnet | testnet | devnet | simnet.
    #[arg(long, default_value = "mainnet")]
    network: String,
    /// Stop the daemon after N minutes with no wallet API request (0 or unset = run
    /// forever, the default).
    ///
    /// Meant for a daemon exposed on a network to pair a phone: it holds the viewing
    /// keys of every wallet it serves, and it is routinely left running long after the
    /// payment that needed it. `/health` does not count as use, so an uptime monitor
    /// cannot hold the door open. In-flight requests finish; the process then exits and
    /// a supervisor may restart it on demand.
    #[arg(long, value_name = "MINUTES")]
    idle_timeout: Option<u64>,
    /// Permit binding a non-loopback address directly (prefer a TLS proxy instead).
    #[arg(long, default_value_t = false)]
    allow_remote: bool,
    /// Browser origin allowed to call the wallet API via CORS (repeatable, e.g.
    /// `--allow-origin https://wallet.ZKas.info`). With none given, cross-origin
    /// browser requests are refused (same-origin only) — this closes the drive-by
    /// wallet-read/drain vector where any page a user visits could reach the daemon.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// Permit the tokenless "default" wallet when no `X-Wallet-Token` header is sent.
    /// Off by default: every request must carry a token, so another local process
    /// can't read the default wallet. Enable only for a trusted single-user localhost.
    #[arg(long, default_value_t = false)]
    allow_default_token: bool,
    /// Serve the multi-party bundle endpoints (`/api/bundle/offer|prepare|submit`), so
    /// two or more parties can settle atomically in ONE Orchard bundle — an NFT sale, a
    /// swap, an escrow release. Off by default: the coordinator role sees every
    /// participant's VIEWING key (enough to read their notes, never to spend them), so
    /// this is a deliberate deployment choice.
    #[arg(long, default_value_t = false)]
    enable_multiparty: bool,
    /// Secret used to encrypt wallet seed files at rest (XChaCha20-Poly1305, Argon2
    /// key). May also be set via the `ZKAS_WALLET_SECRET` env var (the legacy
    /// `FIRECASH_WALLET_SECRET` is still honored). If unset, seeds are stored in
    /// plaintext (0600 on unix) and a warning is logged at startup.
    #[arg(long)]
    wallet_secret: Option<String>,
    /// Keep custodial wallets under this many notes by merging their oldest notes in
    /// the background, one transaction at a time, whenever nothing else is proving.
    ///
    /// ON BY DEFAULT. Halo2 proving costs a flat ~2.4 core-seconds PER NOTE SPENT, so a
    /// wallet that accrues notes without bound (a miner or pool takes one coinbase note
    /// per block) eventually cannot be spent from in reasonable time: measured live, a
    /// 47,000-note treasury needed 237 transactions and ~2 hours for one payment. The
    /// ceiling is what makes the default safe — an ordinary wallet holds a handful of
    /// notes and is never touched, so it never pays a fee. Only wallets far past normal
    /// usage are merged, at ~0.05% of the merged value. Watch-only wallets are skipped
    /// (the daemon holds no seed and cannot spend for them).
    ///
    /// Raise it to merge less often, lower it to keep wallets tighter.
    #[arg(long, value_name = "MAX_NOTES", default_value_t = zkas_walletd::AUTO_CONSOLIDATE_DEFAULT)]
    auto_consolidate: usize,
    /// Turn background consolidation off entirely. Wallets then keep every note they
    /// receive, and a note-heavy wallet's payments get slower without bound.
    #[arg(long, default_value_t = false)]
    no_auto_consolidate: bool,
    /// Stage W of uniform transactions (spec 02), opt-in: every send, payout and merge this daemon
    /// builds has one public shape (4 actions, exact fee 0.031178 ZKAS, anchor at the epoch
    /// opener) and is released at a scheduled random time: interactive sends after a hold
    /// (`--uniform-hold`), large payments as <= 8 independently released siblings, payouts one
    /// payee per transaction over a 300 s window. Changes fees and latency of the legacy
    /// endpoints; the `/api/wallet/uniform/*` endpoints work without it.
    #[arg(long, default_value_t = false)]
    uniform_v1: bool,
    /// With --uniform-v1: send change to the wallet's internal address. Only when every client
    /// that holds these seeds/viewing keys runs the internal-key trigger scan of this release.
    #[arg(long, default_value_t = false)]
    uniform_internal_change: bool,
    /// Default interactive hold under Stage W: immediate | standard (U[0,120 s]) | private (U[0,30 min]).
    #[arg(long, default_value = "standard")]
    uniform_hold: String,
    /// Stage W background merges (W9): custodial wallets above 8 notes merge 4 -> 1 at Poisson
    /// times. Replaces the --auto-consolidate merger. Spends those wallets' fees.
    #[arg(long, default_value_t = false)]
    uniform_merge: bool,
    /// Cap the CPU threads Halo2 proving may use. Default: every core.
    ///
    /// This is a THROTTLE, not a tuning knob — lowering it makes payments slower, and
    /// measurably so (38 spends: 29.7s on 4 threads, 37.6s on 3, 50.1s on 2, 91.7s on 1).
    /// Its purpose is to stop the wallet daemon starving something else on the same box:
    /// on a machine also running a node and a pool, `--proof-threads $(( $(nproc) - 2 ))`
    /// leaves the node headroom at a known, bounded cost to payment latency.
    ///
    /// Total CPU *work* is fixed at ~2.4 core-seconds per note spent whatever you set
    /// here; this only decides how many cores divide it.
    #[arg(long, value_name = "N")]
    proof_threads: Option<usize>,
    /// Tokio worker threads serving HTTP, RPC, and background coordination.
    /// Default: twice the available CPU count, so CPU-heavy scan tasks cannot
    /// occupy every runtime worker and starve status/health requests.
    #[arg(long, value_name = "N")]
    runtime_threads: Option<usize>,
    /// Offline admin: print each wallet's note/base/STRANDED-note report and exit.
    /// Run with the daemon stopped.
    #[arg(long, default_value_t = false)]
    diagnose: bool,
    /// Offline admin: repair a stranded wallet by grafting the leaf stream from an
    /// older snapshot of the same wallet (format: `TOKEN:/path/to/older.scan`).
    /// Run with the daemon stopped.
    #[arg(long)]
    graft: Option<String>,
    /// Self-hosting mode: serve the wallet API on `<addr:port>` over auto-provisioned
    /// TLS (self-signed, cert minted under --wallet-dir/../api) and print a pairing QR a
    /// mobile wallet scans to connect — no reverse proxy, no domain, no certbot. Implies
    /// a required bearer token. Example: `--serve-public 0.0.0.0:8443`.
    #[arg(long, value_name = "ADDR:PORT")]
    serve_public: Option<String>,
    /// With --serve-public, serve plaintext HTTP instead of TLS. Only safe behind a
    /// VPN/Tailscale — your viewing key and balances would otherwise cross the wire in
    /// the clear.
    #[arg(long, default_value_t = false)]
    insecure: bool,
    /// With --serve-public, the public IP/host baked into the printed pairing URI (and
    /// TLS cert SAN). If omitted the URI carries a `<YOUR-PUBLIC-IP>` placeholder.
    #[arg(long)]
    public_host: Option<String>,
    /// With --serve-public, override the generated bearer token (otherwise one is minted
    /// and persisted next to the cert).
    #[arg(long)]
    api_token: Option<String>,
    /// Disable every custodial (seed-holding) endpoint: create, import, send,
    /// send_many, reveal, consolidate, sign all return 403. The daemon then serves
    /// ONLY the watch-only model (watch + prepare + submit) and holds no seeds at
    /// all — the right posture for a hosted multi-tenant deployment (see
    /// OPERATIONS.md). Off by default so existing self-host/gateway setups are
    /// unaffected.
    #[arg(long, default_value_t = false)]
    no_custodial: bool,
    /// Cap how many `/api/wallet/prepare` proofs run at once. Each proof saturates
    /// every core (~2.4 core-seconds per input note), so on a hosted daemon an
    /// unbounded count is a CPU denial-of-service; excess callers queue briefly,
    /// then get a retry-friendly 503. Default: min(2, available cores).
    #[arg(long, value_name = "N")]
    max_concurrent_proves: Option<usize>,
    /// Maximum wallet scans advanced concurrently (default: hardware-derived).
    #[arg(long, value_name = "N")]
    sync_wallets: Option<usize>,
    /// Estimated free memory required per concurrent wallet scan.
    #[arg(long, value_name = "MIB")]
    sync_wallet_memory_mb: Option<u64>,
    /// Maximum checkpoints loaded concurrently.
    #[arg(long, value_name = "N")]
    load_wallets: Option<usize>,
    /// Maximum one-time cold witness warmups running concurrently.
    #[arg(long, value_name = "N")]
    warm_wallets: Option<usize>,
    /// Keep the N most recently active wallets resident and fully prepared, never
    /// evicted. Costs roughly 100-190 MiB of RAM each; 0 (the default) keeps the old
    /// behaviour. This is what removes the 10-15s "reopen a synced wallet and wait
    /// before you can send" — the wallet is still there, so there is nothing to rebuild.
    #[arg(long, value_name = "N")]
    warm_always: Option<usize>,
    /// Ceiling on 1-minute load average per core, as a percent, above which the
    /// background warm sweep stops starting new cold work. Recently active wallets are
    /// never gated by it; progressively older ones get a progressively smaller share, so
    /// dormant wallets are prepared out of genuinely idle capacity. Default 60.
    #[arg(long, value_name = "PCT")]
    warm_budget: Option<u64>,
    /// Threads used to decode each shared shielded-block page.
    #[arg(long, value_name = "N")]
    page_decode_threads: Option<usize>,
    /// Maximum decoded shielded-block pages retained in the shared cache.
    #[arg(long, value_name = "N")]
    page_cache_entries: Option<usize>,
    /// Seconds a decoded page remains reusable.
    #[arg(long, value_name = "SECONDS")]
    page_cache_ttl: Option<u64>,
    /// Keep syncing a wallet for this many seconds after its last API request.
    #[arg(long, value_name = "SECONDS")]
    active_sync_window: Option<u64>,
    /// Evict a checkpoint from RAM after this many idle seconds.
    #[arg(long, value_name = "SECONDS")]
    idle_evict: Option<u64>,
    /// SOFT cap on wallet checkpoints resident in RAM: its overflow rule never evicts a
    /// wallet touched within --active-sync-window. See --hard-max-resident-wallets.
    #[arg(long, value_name = "N")]
    max_resident_wallets: Option<usize>,
    /// HARD cap on resident wallets: a load first evicts the least recently used wallet
    /// whatever its age (pins last, never a busy one), else it is deferred. 0 = none.
    #[arg(long, value_name = "N")]
    hard_max_resident_wallets: Option<usize>,
    /// Resident-wallet byte budget in MiB (estimated heap). 0 (default) = 70% of this
    /// process's cgroup memory.high/memory.max when finite; see --no-resident-budget.
    #[arg(long, value_name = "MIB")]
    resident_budget_mb: Option<u64>,
    /// Disable the resident byte budget entirely.
    #[arg(long)]
    no_resident_budget: bool,
    /// Write checkpoints that reference the shared chain tree's leaf stream (format v11)
    /// instead of embedding a per-wallet copy. Off by default: a build that predates v11
    /// cannot read those checkpoints, so this is a one-way door for every wallet it rewrites.
    #[arg(long)]
    shared_leaf_store: bool,
    /// Phase 1 of the multi-wallet scan engine: wallets ingesting the same page share one
    /// multi-key trial-decryption pass (identical results; ephemeral-key work paid once per
    /// action for the cohort). Off by default. Kernel: ZKAS_ENGINE_KERNEL=comb|ladder (default comb).
    #[arg(long)]
    shared_scan_engine: bool,
    /// Phase 2 of the multi-wallet scan engine (with `--shared-scan-engine`): run THIS process
    /// as the engine instead of the per-wallet daemon. One follower stores the chain once in
    /// DIR; the wallets of `--wallet-dir` are migrated from their checkpoints without a rescan
    /// (never writing to `--wallet-dir`); `/api/*` READS are served from the engine (no sends).
    #[arg(long, value_name = "DIR")]
    engine_dir: Option<String>,
    /// Engine mode: compare each wallet with the LIVE daemon's checkpoints in DIR whenever one
    /// is rewritten (reads headers and private sections only; never writes there).
    #[arg(long, value_name = "DIR")]
    engine_compare_live: Option<String>,
    /// Engine mode: ingest no block above this DAA score (experiments).
    #[arg(long, value_name = "DAA")]
    engine_stop_at_daa: Option<u64>,
    /// Engine mode: snapshot every wallet file when the follower passes tip minus each of these
    /// many seconds (comma-separated), for dormant catch-up measurements.
    #[arg(long, value_name = "SECS,...", value_delimiter = ',')]
    engine_dormant_marks: Vec<u64>,
    /// Engine mode: do not keep the compact block archive (fixed when the store is created).
    #[arg(long)]
    engine_no_archive: bool,
    /// Engine mode: old-path twins (a per-wallet `WalletDb` per migrated wallet, fed the same
    /// blocks and compared with the engine) within this total memory estimate (MB; 0 = none).
    #[arg(long, value_name = "MB", default_value_t = 0)]
    engine_twin_max_mb: u64,
    /// Engine mode: pause the follower below this much free space (MB).
    #[arg(long, value_name = "MB", default_value_t = 4096)]
    engine_min_free_mb: u64,
    /// Defer optional subtree-index builds below this MemAvailable value.
    #[arg(long, value_name = "MIB")]
    subtree_free_floor_mb: Option<u64>,
    /// Full `GetShieldedBlocks` pages to fetch CONCURRENTLY ahead of the ingest cursor
    /// during a deep scan. 1 = fetch one page at a time (the old built-in default).
    ///
    /// Worth tuning because page fetch is 80-93% of sync wall time, and the default of 1
    /// assumed the hosted daemon's node is local and therefore cheap. Measured on this
    /// deployment it is 415 ms/page against 127.0.0.1 — `GetShieldedBlocks` on an archival
    /// node is disk-bound, not network-bound — so the loop waits on I/O with the cores
    /// idle, exactly the shape the flag's own docs describe for a phone on a remote node.
    ///
    /// Raising it is NOT free: the extra fetches land on the same disk, so past the point
    /// where the node's I/O saturates it buys queueing instead of throughput. A flag rather
    /// than a new baked-in number, so the trade can be measured on the box it runs on.
    #[arg(long, value_name = "N")]
    prefetch_depth: Option<usize>,
    /// Read the pages published chain files cover from them instead of the node: an
    /// `https://` base URL or a local directory with `manifest.json` (see `chain_export`).
    #[arg(long, value_name = "URL_OR_DIR")]
    chain_files: Option<String>,
    /// Do not build the daemon-wide shared chain tree: every wallet keeps its own, as the
    /// on-device engines (phone, desktop) do. For measuring and running that configuration.
    #[arg(long)]
    no_shared_tree: bool,
    /// Seconds before a wallet that has advanced is checkpointed on the time rule (default 60).
    ///
    /// Checkpoint writes are the dominant disk I/O on a hosted daemon: a far-behind wallet
    /// saves on this rule alone and each save is the whole growing leaf stream (~150-300 MB
    /// until it catches up). Measured on the 8,400-wallet deployment: 95.3 GB written in 12
    /// minutes at 69% iowait. The built-in 60 is tuned for a PHONE, which can be force-stopped
    /// without a shutdown; a supervised server flushes on SIGTERM, so it can afford a longer
    /// interval. A hard kill then costs at most this many seconds of re-scanning per wallet.
    #[arg(long, value_name = "SECONDS")]
    checkpoint_interval: Option<u64>,
    /// Seconds before a FAR-BEHIND wallet is checkpointed on the time rule (default: same as
    /// --checkpoint-interval).
    ///
    /// Catching-up wallets are where the write volume is: one retains every leaf since its
    /// birthday until it is caught up, and each checkpoint re-serialises that whole growing
    /// blob — ~700 MB per write on the 8,400-wallet deployment, every interval. Raising this
    /// alone leaves caught-up wallets persisting promptly while cutting the writes that
    /// actually saturate the disk. The cost is re-scan time after an ungraceful exit, for a
    /// wallet that is already re-scanning.
    #[arg(long, value_name = "SECONDS")]
    catchup_checkpoint_interval: Option<u64>,
}

// Oversubscribe worker threads (2x cores). The background sync loop does CPU-bound
// work (trial decryption, witness advance) on the runtime; with only `ncpu` workers a
// mass initial scan of many wallets pins every worker and HTTP handlers — which only
// read in-memory state — starve for seconds (observed live: public /api/status timing
// out at 15s during a 170-wallet rescan). With more workers than cores, a newly
// runnable HTTP handler is always schedulable within a time slice, so status stays
// responsive while scans grind in the background.
fn main() {
    kaspa_core::log::try_init_logger("info");
    let cli = Cli::parse();
    let Some(uniform_hold) = zkas_wallet_engine::HoldMode::parse(&cli.uniform_hold) else {
        eprintln!("--uniform-hold must be immediate, standard or private, not {:?}", cli.uniform_hold);
        std::process::exit(2);
    };
    zkas_walletd::set_uniform_policy(zkas_walletd::UniformPolicy {
        enabled: cli.uniform_v1,
        internal_change: cli.uniform_v1 && cli.uniform_internal_change,
        hold: uniform_hold,
        merge: cli.uniform_merge,
    });
    if cli.uniform_v1 || cli.uniform_merge {
        log::info!(
            "uniform transactions (Stage W): send path {}, internal change {}, hold {:?}, background merges {}",
            if cli.uniform_v1 { "ON" } else { "off" },
            if cli.uniform_v1 && cli.uniform_internal_change { "ON" } else { "off" },
            uniform_hold,
            if cli.uniform_merge { "ON" } else { "off" }
        );
    }
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let runtime_threads = cli.runtime_threads.filter(|n| *n > 0).unwrap_or_else(|| cores.saturating_mul(2).max(2));
    // Before the runtime's worker threads exist, so the arena cap applies to all of them.
    zkas_walletd::alloc_tune::at_start();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(runtime_threads)
        .thread_name("wallet-runtime")
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("cannot build Tokio runtime with {runtime_threads} threads: {e}");
            std::process::exit(1);
        });
    runtime.block_on(run(cli));
}

async fn run(cli: Cli) {
    log::info!(
        "wallet runtime threads: {}",
        cli.runtime_threads
            .filter(|n| *n > 0)
            .unwrap_or_else(|| { std::thread::available_parallelism().map(|n| n.get().saturating_mul(2).max(2)).unwrap_or(2) })
    );

    // Size the rayon pool Halo2 proves in, before anything can touch it — `build_global`
    // is one-shot and silently loses to whichever code path initialises rayon first.
    if let Some(n) = cli.proof_threads.filter(|n| *n > 0) {
        match rayon::ThreadPoolBuilder::new().num_threads(n).build_global() {
            Ok(()) => log::info!("proving is capped at {n} thread(s) (--proof-threads); payments trade latency for headroom"),
            Err(e) => log::warn!("could not cap proving threads at {n}: {e}; using every core"),
        }
    }

    let mut resources = zkas_walletd::ResourceLimits::default();
    if let Some(v) = cli.sync_wallets.filter(|v| *v > 0) {
        resources.sync_wallets = v;
    }
    if let Some(v) = cli.sync_wallet_memory_mb.filter(|v| *v > 0) {
        resources.sync_wallet_memory_mb = v;
    }
    if let Some(v) = cli.load_wallets.filter(|v| *v > 0) {
        resources.load_wallets = v;
    }
    if let Some(v) = cli.warm_wallets.filter(|v| *v > 0) {
        resources.warm_wallets = v;
    }
    if let Some(v) = cli.warm_always {
        resources.warm_always = v;
    }
    if let Some(v) = cli.warm_budget.filter(|v| *v > 0) {
        resources.warm_budget_pct = v;
    }
    if let Some(v) = cli.page_decode_threads.filter(|v| *v > 0) {
        resources.page_decode_threads = v;
    }
    if let Some(v) = cli.page_cache_entries.filter(|v| *v > 0) {
        resources.page_cache_entries = v;
    }
    if let Some(v) = cli.page_cache_ttl.filter(|v| *v > 0) {
        resources.page_cache_ttl_secs = v;
    }
    if let Some(v) = cli.active_sync_window.filter(|v| *v > 0) {
        resources.active_sync_secs = v;
    }
    if let Some(v) = cli.idle_evict.filter(|v| *v > 0) {
        resources.idle_evict_secs = v;
    }
    if let Some(v) = cli.max_resident_wallets.filter(|v| *v > 0) {
        resources.max_resident_wallets = v;
    }
    if let Some(v) = cli.hard_max_resident_wallets {
        resources.hard_max_resident_wallets = v;
    }
    if let Some(v) = cli.resident_budget_mb {
        resources.resident_budget_mb = Some(v);
    }
    if cli.no_resident_budget {
        resources.resident_budget_mb = None;
    }
    resources.shared_leaf_store = cli.shared_leaf_store;
    resources.shared_scan_engine = cli.shared_scan_engine;
    if let Some(v) = cli.subtree_free_floor_mb {
        resources.subtree_free_floor_mb = v;
    }
    if let Some(v) = cli.prefetch_depth.filter(|v| *v > 0) {
        resources.prefetch_depth = v;
    }
    if let Some(v) = cli.chain_files.clone().filter(|v| !v.trim().is_empty()) {
        resources.chain_files = Some(v);
    }
    if let Some(v) = cli.checkpoint_interval.filter(|v| *v > 0) {
        resources.checkpoint_interval_secs = v;
    }
    if let Some(v) = cli.catchup_checkpoint_interval.filter(|v| *v > 0) {
        resources.catchup_checkpoint_interval_secs = v;
    }

    // Offline admin modes: operate on the wallet files directly and exit.
    let admin_secret = cli
        .wallet_secret
        .clone()
        .or_else(|| std::env::var("ZKAS_WALLET_SECRET").ok())
        .or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok());
    if cli.diagnose || cli.graft.is_some() {
        let dir = cli.wallet_dir.clone().unwrap_or_else(default_wallet_dir);
        if let Some(spec) = &cli.graft {
            let Some((token, older)) = spec.split_once(':') else {
                eprintln!("--graft wants TOKEN:/path/to/older.scan");
                std::process::exit(2);
            };
            match zkas_walletd::graft_wallet(&dir, token, older, admin_secret.as_deref()) {
                Ok(report) => println!("{token}: {report}"),
                Err(e) => {
                    eprintln!("{token}: graft refused: {e}");
                    std::process::exit(1);
                }
            }
        }
        if cli.diagnose {
            print!("{}", zkas_walletd::diagnose_wallets(&dir, admin_secret.as_deref()));
        }
        return;
    }

    let wallet_dir = cli.wallet_dir.clone().unwrap_or_else(default_wallet_dir);
    // Seed-file encryption secret: CLI flag, ZKAS_WALLET_SECRET, or the legacy
    // FIRECASH_WALLET_SECRET env (still honored so pre-rebrand service files work).
    let wallet_secret = cli
        .wallet_secret
        .or_else(|| std::env::var("ZKAS_WALLET_SECRET").ok())
        .or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok());

    // Fire `shutdown` on SIGINT/SIGTERM so the daemon can flush every resident wallet's
    // checkpoint before exiting.
    //
    // This used to be `_shutdown_tx` — held and never fired, so the process simply died
    // on Ctrl-C. A wallet checkpoints only every `CHECKPOINT_EVERY` blocks, so whatever
    // it had scanned since then lived solely in RAM and was lost. For a wallet part-way
    // through its FIRST scan that is the whole difference between the progress bar the
    // user was watching and where it restarts: reported live 2026-08-07 as a wallet
    // going from "syncing 80%" to "syncing 44%" across a restart. Nothing was corrupted
    // and no funds were ever at risk — the work was simply thrown away and redone.
    //
    // Operators restart walletd routinely (deploys, config changes). Making that cost
    // users their scan progress is not acceptable, so shutdown is now a real signal.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("cannot listen for SIGTERM ({e}); shutdown will not flush checkpoints");
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("SIGINT received — flushing wallet checkpoints before exit"),
                _ = term.recv() => log::info!("SIGTERM received — flushing wallet checkpoints before exit"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            log::info!("interrupt received — flushing wallet checkpoints before exit");
        }
        let _ = shutdown_tx.send(());
    });

    // 0 is spelled "never" rather than "shut down immediately", which is the reading
    // a user who types 0 to disable it expects.
    let idle_timeout = cli.idle_timeout.filter(|m| *m > 0).map(|m| std::time::Duration::from_secs(m * 60));

    // Self-hosting mode: one flag gives TLS + bearer + a pairing QR, no proxy.
    if let Some(addr) = cli.serve_public {
        // SelfHostConfig is shared with kaspad's embedded mode and stays custodial;
        // a single-user self-host has no reason to disable its own seed endpoints.
        if cli.no_custodial {
            log::warn!("--no-custodial is ignored with --serve-public (self-host mode serves its owner's seed wallet)");
        }
        let listen: SocketAddr = addr.parse().unwrap_or_else(|e| {
            log::error!("bad --serve-public {addr:?}: {e}");
            std::process::exit(1);
        });
        // Cert/token live next to the wallets, in a sibling `api` dir.
        let state_dir = std::path::Path::new(&wallet_dir).parent().unwrap_or_else(|| std::path::Path::new(".")).join("api");
        let sh = zkas_walletd::SelfHostConfig {
            rpc_server: cli.rpc_server,
            listen,
            wallet_dir,
            state_dir,
            network: cli.network,
            insecure: cli.insecure,
            token: cli.api_token,
            public_host: cli.public_host,
            wallet_secret,
            allow_default_token: cli.allow_default_token,
            resources,
            idle_timeout,
        };
        if let Err(e) = zkas_walletd::run_selfhost(sh, shutdown_rx).await {
            log::error!("{e}");
            std::process::exit(1);
        }
        return;
    }

    let listen: SocketAddr = cli.listen.parse().unwrap_or_else(|e| {
        log::error!("bad --listen {:?}: {e}", cli.listen);
        std::process::exit(1);
    });
    if !listen.ip().is_loopback() && !cli.allow_remote {
        log::error!(
            "refusing to bind non-loopback {} without --allow-remote (put a TLS proxy in front, or use --serve-public for built-in TLS)",
            listen
        );
        std::process::exit(1);
    }

    if let (true, Some(dir)) = (cli.shared_scan_engine, cli.engine_dir.clone()) {
        let ecfg = zkas_walletd::EngineConfig {
            rpc_server: cli.rpc_server,
            listen,
            wallet_dir,
            engine_dir: std::path::PathBuf::from(dir),
            network: cli.network,
            wallet_secret,
            compare_live_dir: cli.engine_compare_live,
            stop_at_daa: cli.engine_stop_at_daa,
            dormant_marks: cli.engine_dormant_marks,
            archive: !cli.engine_no_archive,
            twin_max_mb: cli.engine_twin_max_mb,
            min_free_mb: cli.engine_min_free_mb,
        };
        if let Err(e) = zkas_walletd::serve_engine(ecfg, shutdown_rx).await {
            log::error!("{e}");
            std::process::exit(1);
        }
        return;
    }

    let cfg = Config {
        enable_multiparty: cli.enable_multiparty,
        rpc_server: cli.rpc_server,
        listen,
        wallet_dir,
        network: cli.network,
        allow_origin: cli.allow_origin,
        allow_default_token: cli.allow_default_token,
        wallet_secret,
        // Loopback / proxied deployment: no built-in TLS, no bearer gate.
        tls: None,
        require_bearer: None,
        auto_consolidate: (!cli.no_auto_consolidate).then_some(cli.auto_consolidate),
        build_shared_tree: !cli.no_shared_tree,
        node_socks_proxy: None,
        allow_custodial: !cli.no_custodial,
        // 0 makes no sense (every prepare would 503); fall back to the default.
        max_concurrent_proves: cli
            .max_concurrent_proves
            .filter(|n| *n > 0)
            .unwrap_or_else(zkas_walletd::default_max_concurrent_proves),
        resources,
        idle_timeout,
    };

    if let Err(e) = serve(cfg, shutdown_rx).await {
        log::error!("{e}");
        std::process::exit(1);
    }
}
