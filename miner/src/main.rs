//! `zkas-miner` — a standalone CPU miner for the zkas network
//! (blocker #4). It talks the standard `get_block_template` / `submit_block` RPC to
//! a `kaspad` node, searches the nonce space with the shared kHeavyHash PoW
//! ([`kaspa_pow::State`], the very code the node verifies with), and submits solved
//! blocks. The mining reward is paid to a `zkas:` shielded address, so a
//! bootstrapped chain is private-by-default from its first mined block.
//!
//! This is intentionally a CPU miner: on a fresh, low-difficulty genesis chain a
//! CPU is enough to produce the first blocks and get the network moving. A GPU
//! kernel is a later optimization; the search logic and the node acceptance
//! contract are identical either way (see [`solver`]).

mod merged;
mod solver;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use kaspa_addresses::Address;
use kaspa_consensus_core::header::Header;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

/// CLI arguments.
#[derive(Parser, Debug)]
#[command(name = "zkas-miner", about = "Standalone CPU miner for the ZKas network (kHeavyHash PoW)")]
struct Args {
    /// kaspad gRPC endpoint (host:port).
    #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
    rpc_server: String,

    /// The `zkas:` shielded address the block reward is paid to.
    #[arg(short = 'a', long)]
    mining_address: String,

    /// Worker threads (0 = one per logical CPU).
    #[arg(short = 't', long, default_value_t = 0)]
    threads: usize,

    /// Seconds to mine one template before refetching a fresh one (so the miner
    /// follows new tips instead of wasting work on a stale parent set).
    #[arg(long, default_value_t = 5)]
    refresh_secs: u64,

    /// Skip proof-of-work: submit each template immediately with nonce 0 instead of
    /// grinding a valid hash. Only useful against a node running with
    /// `skip_proof_of_work` (devnet/simnet override), where any nonce is accepted —
    /// lets a local chain grow thousands of blocks quickly for testing (e.g. to reach
    /// shielded-spend maturity). Rejected as invalid PoW on a normal node.
    #[arg(long, default_value_t = false)]
    no_pow: bool,

    /// Merged-mining (AuxPoW) mode: instead of grinding the ZKas header's own
    /// nonce, prove proof-of-work via a parent kHeavyHash block that commits to the
    /// ZKas block hash (Option-2 dual acceptance). Only accepted once merged
    /// mining has activated on the node (see `merged_mining_activation`). This is the
    /// engine the pool reuses to feed ASIC hashrate; here it self-mines a synthetic
    /// parent for testing.
    #[arg(long, default_value_t = false)]
    merged: bool,

    /// Network whose consensus parameters decide the merge-mining form (mainnet, testnet,
    /// devnet, simnet).
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Override the security-fork activation DAA score (for a test network started with an
    /// override-params file). From it, merged blocks use the genesis-bound commitment and the
    /// parent-derived nonce.
    #[arg(long)]
    security_fork_daa: Option<u64>,
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let args = Args::parse();

    let mining_address = match Address::try_from(args.mining_address.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("invalid --mining-address {:?}: {e}", args.mining_address);
            std::process::exit(1);
        }
    };
    let threads = if args.threads == 0 { num_cpus::get() } else { args.threads };

    let client = connect(&args.rpc_server).await;
    log::info!("mining to {} with {threads} threads, refreshing template every {}s", mining_address, args.refresh_secs);

    let mut warned_unsynced = false;
    loop {
        // Fetch a fresh template for the current tips.
        let template = match client.get_block_template(mining_address.clone(), Vec::new()).await {
            Ok(t) => t,
            Err(e) => {
                log::warn!("get_block_template failed: {e}; retrying in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if !template.is_synced && !warned_unsynced {
            log::warn!("node reports NOT synced — solved blocks may be orphaned until it catches up");
            warned_unsynced = true;
        }

        let mut raw_block = template.block;
        let header: Header = match raw_block.header.clone().try_into() {
            Ok(h) => h,
            Err(e) => {
                log::warn!("template header could not be converted: {e}; refetching");
                continue;
            }
        };

        // Merged-mining mode: prove PoW via an AuxPoW parent instead of a native nonce.
        if args.merged {
            let stop = Arc::new(AtomicBool::new(false));
            let deadline = {
                let stop = stop.clone();
                let secs = args.refresh_secs;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    stop.store(true, Ordering::Relaxed);
                })
            };
            let built = {
                let header = header.clone();
                let stop = stop.clone();
                let net = match args.network.as_str() {
                    "testnet" => kaspa_consensus_core::network::NetworkType::Testnet,
                    "devnet" => kaspa_consensus_core::network::NetworkType::Devnet,
                    "simnet" => kaspa_consensus_core::network::NetworkType::Simnet,
                    _ => kaspa_consensus_core::network::NetworkType::Mainnet,
                };
                let params = kaspa_consensus_core::config::params::Params::from(net);
                let bound = match args.security_fork_daa {
                    Some(d) => header.daa_score >= d,
                    None => params.security_fork_activation.is_active(header.daa_score),
                };
                let genesis = params.genesis.hash;
                tokio::task::spawn_blocking(move || {
                    if bound { merged::build_aux_pow_bound(&header, genesis, threads, &stop) } else { merged::build_aux_pow(&header, threads, &stop) }
                })
                .await
                .expect("aux worker panicked")
            };
            deadline.abort();
            let Some((fc_header, aux)) = built else { continue };
            // Attach the aux witness and re-encode as a raw header (hex-encodes the
            // AuxPow into the submit payload). H_fc is unaffected by the aux data.
            let block_hash = fc_header.hash;
            let fc_with_aux = fc_header.with_aux_pow(aux);
            raw_block.header = (&fc_with_aux).into();
            match client.submit_block(raw_block, false).await {
                Ok(resp) if resp.report.is_success() => log::info!("AUX BLOCK ACCEPTED  hash={block_hash}"),
                Ok(resp) => log::warn!("aux block rejected: {:?}  (hash={block_hash})", resp.report),
                Err(e) => log::warn!("submit_block (aux) failed: {e}"),
            }
            continue;
        }

        // Mine this template for up to `refresh_secs`, then abandon it for a fresh one.
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = {
            let stop = stop.clone();
            let secs = args.refresh_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                stop.store(true, Ordering::Relaxed);
            })
        };

        let nonce = if args.no_pow {
            // No-PoW fast path: submit immediately with nonce 0. Only valid against a
            // node with skip_proof_of_work; used to grow a test chain quickly.
            deadline.abort();
            Some(0u64)
        } else {
            let n = {
                let header = header.clone();
                let stop = stop.clone();
                tokio::task::spawn_blocking(move || solver::mine_header(&header, threads, &stop))
                    .await
                    .expect("mining worker panicked")
            };
            deadline.abort();
            n
        };

        let Some(nonce) = nonce else {
            // Template expired without a solution; loop to fetch a fresh one.
            continue;
        };

        // The node recomputes and validates the block hash itself, so setting the
        // winning nonce on the raw header is all that's needed before submitting.
        raw_block.header.nonce = nonce;
        let block_hash = header_hash_with_nonce(&header, nonce);
        match client.submit_block(raw_block, false).await {
            Ok(resp) if resp.report.is_success() => log::info!("BLOCK ACCEPTED  nonce={nonce}  hash={block_hash}"),
            Ok(resp) => log::warn!("block rejected: {:?}  (nonce={nonce})", resp.report),
            Err(e) => log::warn!("submit_block failed: {e}  (nonce={nonce})"),
        }
    }
}

/// Recompute the block hash for logging (the node is the source of truth; this is
/// only so the log line matches what the node will report).
fn header_hash_with_nonce(header: &Header, nonce: u64) -> kaspa_hashes::Hash {
    let mut h = header.clone();
    h.nonce = nonce;
    h.finalize();
    h.hash
}

/// Connect a gRPC client to `address` (Direct notification mode; the miner does not
/// subscribe to notifications, it polls templates).
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
    .unwrap_or_else(|e| {
        log::error!("failed to connect to {address}: {e}");
        std::process::exit(1);
    })
}
