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
    /// Hard cap on wallet checkpoints resident in RAM.
    #[arg(long, value_name = "N")]
    max_resident_wallets: Option<usize>,
    /// Defer optional subtree-index builds below this MemAvailable value.
    #[arg(long, value_name = "MIB")]
    subtree_free_floor_mb: Option<u64>,
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
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let runtime_threads = cli.runtime_threads.filter(|n| *n > 0).unwrap_or_else(|| cores.saturating_mul(2).max(2));
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
    if let Some(v) = cli.subtree_free_floor_mb {
        resources.subtree_free_floor_mb = v;
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

    let cfg = Config {
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
        build_shared_tree: true,
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
