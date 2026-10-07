//! `shielded-pay` — a live shielded-payment client for the ZKas network
//! (PLAN §2.10, blocker #2). It closes the last gap between the shielded wallet
//! primitives and a running node: it reconstructs a mined coinbase note, builds a
//! **real** Orchard spend of it (Halo 2 proof + spend-auth signature) paying a
//! recipient, wraps it in the canonical version-2 shielded transaction, and
//! submits it over gRPC — the same `submit_transaction` path any wallet uses.
//!
//! ## Spend maturity (~10 minutes, all networks)
//!
//! A shielded spend must prove its input note into a **matured** anchor (PLAN
//! §2.5): consensus rejects a spend whose anchor is not yet deep enough
//! (`ShieldedManagerError::UnfinalizedAnchor`). Maturity is governed by the
//! `shielded_anchor_depth` consensus parameter — the anchor as of the chain block
//! `600 * BPS` blue-score units below the sink (~10 minutes at 10 BPS). This is
//! deliberately **decoupled from chain finality** (`finality_depth`, ~12 h): a
//! freshly-mined coinbase note is spendable within ~10 minutes on mainnet, devnet
//! and every other network, while finality/pruning security is unchanged. The
//! trade-off is that spend safety rests on a ~10-minute confirmation window rather
//! than full finality — a reorg deeper than that (economically implausible under
//! GHOSTDAG at 10 BPS) could invalidate a matured anchor. This mirrors the
//! confirmation-depth model every chain uses, just applied to the shielded pool.
//!
//! ## Why the coinbase note, single-leaf
//!
//! The first coinbase note ever minted sits at tree position 0, so its
//! authentication path is the trivial single-leaf path and its anchor is exactly
//! the minting block's anchor. This is the wallet operation with the smallest
//! witness-tracking surface, so it is the one we drive live first (mirrors
//! `consensus::…::real_shielded_spend_through_mined_block`). The client itself is
//! network-agnostic; once the note is ~10 minutes deep, the spend is accepted.

use std::io::Read;

use clap::{Parser, Subcommand};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcHash, RpcShieldedChainBlock, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::expected_wire_len;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::FrontierState;
use kaspa_shielded_core::wallet::CompactActionRecord;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::{build_singleleaf_coinbase_spend, build_wallet_payment};
use kaspa_shielded_core::walletdb::WalletDb;
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};

/// The shielded output script length for a `Version::ShieldedOrchard` address:
/// the 43 raw Orchard address bytes carried in a coinbase reward's script.
const ORCHARD_SCRIPT_LEN: usize = 43;

/// Default shielded-spend anchor maturity (blue-score depth) — must match the
/// consensus `shielded_anchor_depth` (`600 * BPS`, i.e. 6000 at 10 BPS, ~10 min).
/// A note is spendable once its minting block is this deep below the sink.
const DEFAULT_ANCHOR_DEPTH: u64 = 6000;

#[derive(Parser, Debug)]
#[command(name = "shielded-pay", about = "Build and submit a real shielded payment over RPC (ZKas)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a brand-new wallet: a random 32-byte seed and its shielded address.
    /// Keep the seed secret — whoever holds it controls the funds.
    New {
        /// Network prefix: mainnet | testnet | devnet | simnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print the bech32 shielded (Orchard) address for a wallet seed on a network —
    /// e.g. to hand to the miner as `--mining-address`.
    Address {
        /// Real 32-byte wallet seed as 64 hex chars.
        #[arg(long)]
        seed_hex: Option<String>,
        /// Test convenience: the 32-byte seed is `[byte; 32]`. Prefer `--seed-hex`.
        #[arg(long)]
        seed_byte: Option<u8>,
        /// Network prefix: mainnet | testnet | devnet | simnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print the node's current virtual DAA score (a proxy for chain height /
    /// blue score on a young single-chain devnet). Used to gate a spend on the
    /// note having matured past `shielded_anchor_depth` (~10 min at 10 BPS).
    Info {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
        rpc_server: String,
    },
    /// List the transaction ids currently in the node's mempool (transaction pool).
    /// Used to confirm a submitted shielded payment is subsequently mined (leaves
    /// the mempool).
    Mempool {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
        rpc_server: String,
    },
    /// Scan the whole accepted chain, discover every note owned by the wallet seed,
    /// and report the spendable balance and each note's position/value. This is the
    /// real wallet's receive side: it mirrors the consensus note stream and keeps a
    /// witness per owned note (via `WalletDb`), so it works for arbitrary notes, not
    /// just the first coinbase.
    Balance {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
        rpc_server: String,
        /// Real 32-byte wallet seed as 64 hex chars.
        #[arg(long)]
        seed_hex: Option<String>,
        /// Test convenience: the 32-byte seed is `[byte; 32]`. Prefer `--seed-hex`.
        #[arg(long)]
        seed_byte: Option<u8>,
    },
    /// Real wallet payment: scan the chain, pick a **matured** owned note, and pay
    /// `--amount` to `--to`, returning the change to the sender and leaving `--fee`
    /// for the miner. Spends against the finalized anchor `--anchor-depth` blocks
    /// deep, so the note must be at least that old.
    Send {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
        rpc_server: String,
        /// Real 32-byte sender seed as 64 hex chars.
        #[arg(long)]
        owner_seed_hex: Option<String>,
        /// Test convenience: the sender seed is `[byte; 32]`. Prefer `--owner-seed-hex`.
        #[arg(long)]
        owner_seed_byte: Option<u8>,
        /// Recipient bech32 shielded address.
        #[arg(long)]
        to: String,
        /// Amount to pay the recipient (base units).
        #[arg(long)]
        amount: u64,
        /// Public fee left as the bundle's value balance, collected by the miner.
        #[arg(long, default_value_t = 3_000_000)]
        fee: u64,
        /// Anchor maturity depth in blocks (must match consensus shielded_anchor_depth).
        #[arg(long, default_value_t = DEFAULT_ANCHOR_DEPTH)]
        anchor_depth: u64,
    },
    /// Sign a message with a wallet seed, proving control of the wallet's shielded
    /// address WITHOUT spending. Offline (no node needed). The signature discloses
    /// the wallet's full viewing key (needed to bind the signature to the address on
    /// a shielded chain, where the address itself carries no verification key) — this
    /// grants note-detection capability but never spend authority.
    Sign {
        /// Real 32-byte wallet seed as 64 hex chars.
        #[arg(long)]
        seed_hex: Option<String>,
        /// Test convenience: the 32-byte seed is `[byte; 32]`. Prefer `--seed-hex`.
        #[arg(long)]
        seed_byte: Option<u8>,
        /// Read the 64-hex-character seed from standard input. This is mutually
        /// exclusive with --seed-hex and --seed-byte.
        #[arg(long)]
        seed_stdin: bool,
        /// Network prefix: mainnet | testnet | devnet | simnet (scopes the signature).
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// The message to sign.
        #[arg(long)]
        message: String,
    },
    /// Verify a message signature against a shielded address (offline). Confirms the
    /// signer controls `--address` and signed exactly `--message`.
    Verify {
        /// The bech32 shielded address the signature claims to own.
        #[arg(long)]
        address: String,
        /// The message that was signed.
        #[arg(long)]
        message: String,
        /// The signature hex from `sign` (full-viewing-key ‖ signature).
        #[arg(long)]
        sig: String,
    },
    /// Spend the first coinbase note (tree position 0) minted to the owner wallet
    /// and pay it to `--to`, submitting the shielded transaction over gRPC.
    Pay {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16810")]
        rpc_server: String,
        /// Real 32-byte owner seed as 64 hex chars.
        #[arg(long)]
        owner_seed_hex: Option<String>,
        /// Test convenience: the owner seed is `[byte; 32]`. Prefer `--owner-seed-hex`.
        #[arg(long)]
        owner_seed_byte: Option<u8>,
        /// Recipient bech32 shielded address (use the `address` subcommand to derive one).
        #[arg(long)]
        to: String,
        /// Public fee left as the bundle's value balance, collected by the miner.
        #[arg(long, default_value_t = 2_000)]
        fee: u64,
    },
}

fn prefix_from(network: &str) -> Prefix {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Prefix::Mainnet,
        "testnet" => Prefix::Testnet,
        "devnet" => Prefix::Devnet,
        "simnet" => Prefix::Simnet,
        other => {
            log::error!("unknown network {other:?} (expected mainnet|testnet|devnet|simnet)");
            std::process::exit(1);
        }
    }
}

/// Resolve a wallet seed from the mutually-exclusive `--seed-hex` (a real 32-byte
/// hex seed) or `--seed-byte` (the test convenience `[byte; 32]`). Exactly one of the
/// two must be given.
///
/// `--seed-byte` spans only 256 seeds — anyone can enumerate all of them and sweep
/// the wallet — so it is refused unless `ZKAS_TEST_SEED=1` (or the legacy
/// `ZKAS_TEST_SEED=1`) is set in the
/// environment. That gate covers every subcommand at once, including the ones that
/// take an RPC endpoint rather than a network name, so a throwaway test key can
/// never be used against real funds by accident.
fn resolve_seed(seed_hex: Option<String>, seed_byte: Option<u8>) -> [u8; 32] {
    match (seed_hex, seed_byte) {
        (Some(_), Some(_)) => fatal("give either --seed-hex or --seed-byte, not both".into()),
        (None, None) => fatal("a seed is required: pass --seed-hex <64 hex chars> (or --seed-byte <0-255> for a test wallet)".into()),
        (None, Some(b)) => {
            if std::env::var("ZKAS_TEST_SEED").as_deref() != Ok("1") && std::env::var("ZKAS_TEST_SEED").as_deref() != Ok("1") {
                fatal(
                    "--seed-byte derives the seed [byte; 32]: only 256 wallets exist, all trivially sweepable. \
                     Use --seed-hex <64 hex chars> for any wallet holding value. \
                     To use it anyway on a throwaway test wallet, set ZKAS_TEST_SEED=1."
                        .into(),
                );
            }
            [b; 32]
        }
        (Some(h), None) => parse_seed_hex(&h).unwrap_or_else(|err| fatal(err)),
    }
}

fn parse_seed_hex(seed_hex: &str) -> Result<[u8; 32], String> {
    let seed_hex = seed_hex.trim();
    if seed_hex.len() != 64 {
        return Err("--seed-hex must be exactly 32 bytes (64 hex chars)".into());
    }

    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).map_err(|_| "--seed-hex is not valid hex")?;
    }
    Ok(seed)
}

fn seed_from_reader(mut reader: impl Read) -> Result<[u8; 32], String> {
    let mut seed_hex = String::new();
    reader.read_to_string(&mut seed_hex).map_err(|err| format!("failed to read seed from standard input: {err}"))?;
    parse_seed_hex(&seed_hex)
}

/// Resolve a signing seed without putting a real seed in the command line. This
/// input mode deliberately exists only for the offline `sign` subcommand: a
/// seed read from standard input must never be routed into an RPC-spending path.
fn resolve_sign_seed(seed_hex: Option<String>, seed_byte: Option<u8>, seed_stdin: bool) -> [u8; 32] {
    let source_count = usize::from(seed_hex.is_some()) + usize::from(seed_byte.is_some()) + usize::from(seed_stdin);
    if source_count != 1 {
        fatal("give exactly one of --seed-hex, --seed-byte, or --seed-stdin".into());
    }

    if seed_stdin { seed_from_reader(std::io::stdin()).unwrap_or_else(|err| fatal(err)) } else { resolve_seed(seed_hex, seed_byte) }
}

/// Derive the bech32 shielded address string for a seed on a network. Uses
/// `String::from(&addr)` (not `Display`, which appends a `(ShieldedOrchard)` tag).
fn address_string(seed: [u8; 32], prefix: Prefix) -> String {
    let raw = address_bytes_from_seed(seed).unwrap_or_else(|| {
        log::error!("seed is not a valid Orchard spending key");
        std::process::exit(1);
    });
    String::from(&Address::new(prefix, Version::ShieldedOrchard, &raw))
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
    .unwrap_or_else(|e| {
        log::error!("failed to connect to {address}: {e}");
        std::process::exit(1);
    })
}

/// A minted coinbase note located on-chain: the note at global tree position 0.
struct Position0Note {
    coinbase_txid: RpcHash,
    out_index: u32,
    value: u64,
    block: RpcHash,
}

/// Walk the selected chain from genesis and return the first coinbase note ever
/// minted (global tree position 0). The genesis-merging block mints no note, so we
/// scan chain blocks in order and take the first coinbase carrying a shielded
/// (43-byte) output — matching the order consensus appends notes to the tree.
async fn find_position0_note(client: &GrpcClient, genesis: RpcHash) -> Position0Note {
    let chain = client
        .get_virtual_chain_from_block(genesis, false, None)
        .await
        .unwrap_or_else(|e| fatal(format!("get_virtual_chain_from_block failed: {e}")));

    for hash in chain.added_chain_block_hashes {
        if hash == genesis {
            continue;
        }
        let block = client.get_block(hash, true).await.unwrap_or_else(|e| fatal(format!("get_block failed: {e}")));
        let Some(coinbase) = block.transactions.first() else { continue };
        for (out_index, output) in coinbase.outputs.iter().enumerate() {
            if output.script_public_key.script().len() == ORCHARD_SCRIPT_LEN {
                let coinbase_txid = coinbase
                    .verbose_data
                    .as_ref()
                    .unwrap_or_else(|| fatal("coinbase tx missing verbose_data (transaction id)".into()))
                    .transaction_id;
                return Position0Note { coinbase_txid, out_index: out_index as u32, value: output.value, block: hash };
            }
        }
    }
    fatal("no coinbase note minted yet — mine some blocks first".into())
}

fn fatal(msg: String) -> ! {
    log::error!("{msg}");
    std::process::exit(1);
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::seed_from_reader;

    #[test]
    fn reads_a_seed_from_standard_input() {
        let seed = seed_from_reader(Cursor::new("0a".repeat(32) + "\n")).expect("valid stdin seed");
        assert_eq!(seed, [0x0a; 32]);
    }

    #[test]
    fn rejects_an_invalid_standard_input_seed() {
        assert!(seed_from_reader(Cursor::new("not-a-seed")).is_err());
    }
}

/// Sign a message with a wallet seed, proving control of the wallet's shielded
/// address. Offline. Prints the address, the message, and the signature hex.
fn sign(seed: [u8; 32], network: String, message: String) {
    let prefix = prefix_from(&network);
    let tag = prefix.to_string();
    let signed = sign_message(seed, tag.as_bytes(), message.as_bytes(), rand10::rng())
        .unwrap_or_else(|| fatal("seed is not a valid Orchard spending key".into()));

    let addr = String::from(&Address::new(prefix, Version::ShieldedOrchard, &signed.address));
    // The signature blob is `fvk (96) || sig (64)`; the fvk binds it to the address.
    let mut blob = Vec::with_capacity(FVK_LEN + SIG_LEN);
    blob.extend_from_slice(&signed.fvk);
    blob.extend_from_slice(&signed.sig);

    println!("address:   {addr}");
    println!("message:   {message}");
    println!("signature: {}", hex(&blob));
    eprintln!(
        "note: this signature discloses the wallet's viewing key (fvk). It proves \
         ownership and lets others detect this wallet's notes, but reveals NO spend authority."
    );
}

/// Verify a message signature against a shielded address. Offline. Exits non-zero
/// if the signature does not prove control of the address over the message.
fn verify(address: String, message: String, sig: String) {
    let addr = Address::try_from(address.as_str()).unwrap_or_else(|e| fatal(format!("invalid --address {address:?}: {e}")));
    let tag = addr.prefix.to_string();
    let raw = orchard_recipient_bytes(&addr).unwrap_or_else(|| fatal("--address is not a shielded Orchard address".into()));

    let blob = unhex(&sig).unwrap_or_else(|| fatal("--sig is not valid hex".into()));
    if blob.len() != FVK_LEN + SIG_LEN {
        fatal(format!("--sig must be {} hex bytes (fvk||sig); got {}", FVK_LEN + SIG_LEN, blob.len()));
    }
    let fvk: [u8; FVK_LEN] = blob[..FVK_LEN].try_into().expect("checked length");
    let s: [u8; SIG_LEN] = blob[FVK_LEN..].try_into().expect("checked length");

    match verify_message(&raw, tag.as_bytes(), message.as_bytes(), &fvk, &s) {
        Ok(()) => println!("VALID: signature proves control of {address}"),
        Err(e) => {
            println!("INVALID: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Pick the deepest checkpoint this node can actually serve, and return it with its
/// tree frontier: **genesis** when the node holds the whole chain, the pruning point
/// otherwise.
///
/// Anchoring at the pruning point unconditionally is wrong and silently loses money.
/// `--archival` does NOT hold `pruning_point_hash` at genesis — that hash advances on
/// every node — but it does pin the *retention root*, which is what block serving is
/// actually gated on (`consensus/mod.rs`, `get_virtual_chain_from_block`). The shielded
/// stores (tree frontiers, scan archive, nullifiers) are never pruned at all. So an
/// archival node serves genesis and the complete note history, and a scan that starts
/// at the pruning point throws it away for nothing: measured live on 2026-07-31, the
/// pruning point sat at tree position 589,776 of 792,715 — **74% of every note ever
/// minted was below the anchor and never looked at**. A wallet then reports a partial
/// balance as its whole balance, and a spend cannot select the notes it can't see.
///
/// Same fix, and the same reasoning, as `zkas-walletd`'s `full_scan_entry`.
async fn scan_anchor(client: &GrpcClient) -> (RpcHash, kaspa_rpc_core::GetShieldedTreeStateResponse) {
    // Probe genesis first. A node that has pruned it answers with an error or with a
    // different block hash; either way we fall through to the pruning point, which is
    // the most history that node can honestly offer.
    let genesis = resolve_genesis(client).await;
    if let Ok(ts) = client.get_shielded_tree_state(Some(genesis)).await
        && ts.block_hash == genesis
    {
        log::info!("scan anchored at GENESIS — this node serves the complete shielded history");
        return (genesis, ts);
    }

    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let start = dag.pruning_point_hash;
    let ts = client
        .get_shielded_tree_state(Some(start))
        .await
        .unwrap_or_else(|e| fatal(format!("get_shielded_tree_state({start}) failed: {e} — node too old? update it")));
    if ts.block_hash != start {
        fatal("node ignored the explicit tree-state checkpoint (update the node)".into());
    }
    // Not a footnote: any note this wallet received below here is unrecoverable through
    // this node, and the balance printed afterwards is a partial one. Say so loudly
    // rather than let the user read it as the truth.
    log::warn!(
        "scan anchored at the PRUNING POINT (daa {}, tree position {}) — this node cannot serve genesis, so \
         every note minted below that point is INVISIBLE and the balance shown will be PARTIAL. Point --rpc-server \
         at a node started with --archival to see the full history.",
        ts.daa_score,
        ts.size
    );
    (start, ts)
}

/// Build a [`WalletDb`] by replaying the accepted chain's shielded effects in
/// consensus order (PLAN §2.9/§2.10). For every accepted chain block it feeds the
/// coinbase notes (each output's `(recipient, txid||index)` derivation, exactly as
/// consensus mints them) and then the block's accepted shielded bundles, so the
/// wallet's mirrored tree, note positions and witnesses match the node's.
///
/// `ingest_blocks` caps how many chain blocks (after genesis) to replay: `None`
/// walks to the tip (full balance view); `Some(k)` stops at block `k`, so the
/// wallet's anchor is the tree root as of block `k` — used to root a spend to a
/// **finalized** anchor. Returns the db and the total accepted chain length.
///
/// Note (single-chain assumption): this feeds each chain block's own body. On a
/// linear chain (blue_score == index) that is exactly consensus's accepted set and
/// order. Handling wide-DAG mergeset acceptance order is the remaining item in the
/// real-wallet task.
async fn scan_chain(client: &GrpcClient, seed: [u8; 32], matured_margin: Option<u64>) -> (WalletDb, usize) {
    let (start, ts) = scan_anchor(client).await;

    let mut db = WalletDb::from_seed(seed).unwrap_or_else(|| fatal("seed is not a valid Orchard spending key".into()));
    let fs = FrontierState {
        size: ts.size,
        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
        ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
    };
    db.apply_frontier(&fs).unwrap_or_else(|| fatal("inconsistent scan-anchor frontier".into()));

    let mut low = start;
    let mut count = 0usize;
    loop {
        let resp = client
            .get_shielded_blocks(low, 500)
            .await
            .unwrap_or_else(|e| fatal(format!("get_shielded_blocks from {low} failed: {e}")));
        if resp.reorged {
            fatal("chain reorged during the scan; retry".into());
        }
        // `matured_margin = Some(m)` stops `m` blue-score units below the sink, so
        // every recovered note is matured and the wallet's anchor is a matured,
        // canonical chain-block root a spend may prove against.
        let cutoff = matured_margin.map(|m| resp.sink_blue_score.saturating_sub(m)).unwrap_or(u64::MAX);
        let mut advanced = false;
        for b in &resp.blocks {
            if b.blue_score > cutoff {
                return (db, count);
            }
            ingest_shielded_chain_block(&mut db, b);
            low = b.hash;
            count += 1;
            advanced = true;
        }
        if !advanced {
            return (db, count);
        }
    }
}

/// Feed one chain block's shielded effects into the wallet — the node already
/// assembled them (`GetShieldedBlocks`) exactly as the consensus §2.4 transition
/// applied them: the block's own coinbase notes first, then each accepted
/// (post-retain) bundle's actions in consensus order.
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
    // The node serves the compact scan archive (`accepted_actions`): concatenated
    // 148-byte records per accepted tx. Chunk each and ingest via the compact path.
    let compact: Vec<Vec<CompactActionRecord>> = blk
        .accepted_actions
        .iter()
        .filter_map(|b| {
            if b.len() % CompactActionRecord::SERIALIZED_LEN != 0 {
                return None;
            }
            b.chunks_exact(CompactActionRecord::SERIALIZED_LEN).map(CompactActionRecord::from_bytes).collect()
        })
        .collect();
    db.ingest_block_compact_with_meta(&coinbase_notes, &compact, None);
}

/// The shielded sighash **network domain**: the chain's genesis hash — what
/// consensus verifies signatures against (`params.genesis.hash`). Read from the
/// compile-time mainnet params: an RPC walk to genesis fails on pruned nodes.
async fn resolve_genesis(_client: &GrpcClient) -> RpcHash {
    use kaspa_consensus_core::{config::params::Params, network::NetworkType};
    RpcHash::from_bytes(Params::from(NetworkType::Mainnet).genesis.hash.as_bytes())
}

async fn balance(rpc_server: String, seed: [u8; 32]) {
    let client = connect(&rpc_server).await;
    log::info!("scanning accepted chain for notes owned by this wallet...");
    let (db, total) = scan_chain(&client, seed, None).await;
    log::info!("scanned {total} chain blocks; anchor(tip) = {}", hex32(&db.anchor()));
    println!("balance: {} ({} note(s))", db.balance(), db.notes().len());
    for n in db.notes() {
        println!("  note position={} value={}", n.position, n.value());
    }
}

/// This tool builds the pre-fork spend format (no named anchor block). From the security fork every
/// node refuses that format, so refuse up front instead of proving a payment that cannot be mined.
async fn refuse_after_security_fork(client: &GrpcClient) {
    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let params = kaspa_consensus_core::config::params::Params::from(dag.network);
    if params.security_fork_activation.is_active(dag.virtual_daa_score.saturating_add(600)) {
        fatal("shielded-pay builds the pre-upgrade spend format, which the network no longer accepts; send with zkas-walletd".into());
    }
}

async fn send(rpc_server: String, owner_seed: [u8; 32], to: String, amount: u64, fee: u64, anchor_depth: u64) {
    let client = connect(&rpc_server).await;
    refuse_after_security_fork(&client).await;

    let net: [u8; 32] = resolve_genesis(&client).await.as_bytes();

    // Root the spend to a matured, canonical anchor: scan only chain blocks at
    // least `anchor_depth + slack` blue-score units below the sink (consensus
    // measures anchor maturity in blue score), so the wallet's tip anchor is one
    // a spend may prove against.
    log::info!("scanning the matured chain prefix (anchor_depth {anchor_depth})...");
    let db = scan_chain(&client, owner_seed, Some(anchor_depth + 30)).await.0;

    let to_addr = Address::try_from(to.as_str()).unwrap_or_else(|e| fatal(format!("invalid --to address {to:?}: {e}")));
    let recipient = orchard_recipient_bytes(&to_addr).unwrap_or_else(|| fatal("--to is not a shielded Orchard address".into()));

    // Select matured notes to cover amount + fee: greedily take the largest notes
    // first, so the fewest inputs are needed (a smaller, cheaper proof).
    let need = amount.checked_add(fee).unwrap_or_else(|| fatal("amount + fee overflows".into()));
    // Standard-mass cap: transient mass = tx bytes × 4 with a 100,000 cap, and
    // each spent note adds 884 wire + 2,272 proof bytes — at most SIX spends fit
    // one standard transaction (`expected_wire_len`). Refuse an over-cap send
    // up front instead of proving for an hour and getting mempool-rejected.
    let max_spends = {
        let budget = 100_000usize / 4 - 256;
        let mut n = 1usize;
        while expected_wire_len((n + 1).max(2)) <= budget {
            n += 1;
        }
        n
    };
    let mut candidates: Vec<_> = db.notes().to_vec();
    candidates.sort_by(|a, b| b.value().cmp(&a.value())); // descending
    let mut inputs = Vec::new();
    let mut selected = 0u64;
    for n in &candidates {
        if selected >= need || inputs.len() == max_spends {
            break;
        }
        let path = db.witness_path(n.position).unwrap_or_else(|| fatal("matured note has no witness path".into()));
        inputs.push((n.note.clone(), path));
        selected += n.value();
        log::info!("  input: note position={} value={}", n.position, n.value());
    }
    if selected < need {
        let have: u64 = candidates.iter().map(|n| n.value()).sum();
        if have >= need {
            fatal(format!(
                "amount needs more than {max_spends} input notes (standard tx size cap): max sendable in one tx is {} — send in chunks (or consolidate via zkas-walletd /api/wallet/consolidate)",
                selected.saturating_sub(fee)
            ));
        }
        fatal(format!("insufficient matured funds: have {have} across {} matured note(s), need amount+fee={need}", candidates.len()));
    }
    log::info!(
        "spending {} matured note(s) totalling {} (change {}) against anchor {}",
        inputs.len(),
        selected,
        selected - need,
        hex32(&db.anchor())
    );

    let ctx = payment_tx_context();
    log::info!("building real Orchard payment proof (Halo 2) — this takes a few seconds...");
    let payload = build_wallet_payment(owner_seed, inputs, recipient, amount, fee, &net, &ctx, true, [0u8; 512])
        .unwrap_or_else(|e| fatal(format!("failed to build wallet payment: {e:?}")));

    let tx: Transaction = payment_tx(payload);
    let txid = tx.id();
    log::info!("assembled shielded payment tx {txid} (amount={amount}, fee={fee}); submitting over RPC...");
    match client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            log::info!("ACCEPTED: node admitted shielded payment {accepted} to the mempool");
            println!("{accepted}");
        }
        Err(e) => fatal(format!("submit_transaction rejected the shielded payment: {e}")),
    }
}

async fn pay(rpc_server: String, owner_seed: [u8; 32], to: String, fee: u64) {
    let client = connect(&rpc_server).await;
    refuse_after_security_fork(&client).await;

    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let genesis = resolve_genesis(&client).await;
    let net: [u8; 32] = genesis.as_bytes();
    log::info!("network domain (genesis) = {genesis}, virtual daa = {}", dag.virtual_daa_score);

    // Locate the position-0 coinbase note on-chain.
    let note = find_position0_note(&client, genesis).await;
    log::info!(
        "position-0 coinbase note: block={} txid={} out={} value={}",
        note.block,
        note.coinbase_txid,
        note.out_index,
        note.value
    );

    // Recipient address -> raw 43-byte Orchard recipient.
    let to_addr = Address::try_from(to.as_str()).unwrap_or_else(|e| fatal(format!("invalid --to address {to:?}: {e}")));
    let recipient = orchard_recipient_bytes(&to_addr).unwrap_or_else(|| fatal("--to is not a shielded Orchard address".into()));

    let output_value = note.value.checked_sub(fee).unwrap_or_else(|| fatal(format!("fee {fee} exceeds note value {}", note.value)));

    // The bundle binds its signatures to the canonical shielded-tx sighash context;
    // it is payload-independent, so we compute it before building the (heavy) proof.
    let tx_ctx = payment_tx_context();

    log::info!("building real Orchard spend proof (Halo 2) — this takes a few seconds...");
    let payload = build_singleleaf_coinbase_spend(
        owner_seed,
        note.coinbase_txid.as_bytes(),
        note.out_index,
        note.value,
        recipient,
        output_value,
        &net,
        &tx_ctx,
    )
    .unwrap_or_else(|e| fatal(format!("failed to build shielded spend: {e:?}")));

    // Wrap into the canonical version-2 shielded transaction and submit it.
    let tx: Transaction = payment_tx(payload);
    let txid = tx.id();
    log::info!("assembled shielded tx {txid} (value_out={output_value}, fee={fee}); submitting over RPC...");
    let rpc_tx = RpcTransaction::from(&tx);

    match client.submit_transaction(rpc_tx, false).await {
        Ok(accepted) => {
            log::info!("ACCEPTED: node admitted shielded payment {accepted} to the mempool");
            println!("{accepted}");
        }
        Err(e) => fatal(format!("submit_transaction rejected the shielded payment: {e}")),
    }
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    match Cli::parse().cmd {
        Cmd::New { network } => {
            use rand::RngCore;
            let prefix = prefix_from(&network);
            // A random seed that is a valid Orchard spending key (retry the rare miss).
            let mut seed = [0u8; 32];
            let address = loop {
                { use rand10::Rng as _; rand10::rng().fill_bytes(&mut seed); }
                if let Some(raw) = address_bytes_from_seed(seed) {
                    break String::from(&Address::new(prefix, Version::ShieldedOrchard, &raw));
                }
            };
            println!("seed_hex: {}", hex32(&seed));
            println!("address:  {address}");
            eprintln!("KEEP THE SEED SECRET. Whoever holds it controls the funds. Pass it to other commands as --seed-hex.");
        }
        Cmd::Address { seed_hex, seed_byte, network } => {
            println!("{}", address_string(resolve_seed(seed_hex, seed_byte), prefix_from(&network)));
        }
        Cmd::Info { rpc_server } => {
            let client = connect(&rpc_server).await;
            let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
            // Print just the score on stdout so a script can capture it directly.
            println!("{}", dag.virtual_daa_score);
        }
        Cmd::Mempool { rpc_server } => {
            let client = connect(&rpc_server).await;
            // (include_orphan_pool=false, filter_transaction_pool=false) => the
            // transaction pool only (see RpcCoreService::extract_tx_query).
            let entries =
                client.get_mempool_entries(false, false).await.unwrap_or_else(|e| fatal(format!("get_mempool_entries failed: {e}")));
            for entry in entries {
                // `RpcTransaction::id()` recomputes the id from the tx itself.
                println!("{}", Transaction::try_from(entry.transaction).map(|t| t.id().to_string()).unwrap_or_default());
            }
        }
        Cmd::Balance { rpc_server, seed_hex, seed_byte } => {
            balance(rpc_server, resolve_seed(seed_hex, seed_byte)).await;
        }
        Cmd::Send { rpc_server, owner_seed_hex, owner_seed_byte, to, amount, fee, anchor_depth } => {
            send(rpc_server, resolve_seed(owner_seed_hex, owner_seed_byte), to, amount, fee, anchor_depth).await;
        }
        Cmd::Sign { seed_hex, seed_byte, seed_stdin, network, message } => {
            sign(resolve_sign_seed(seed_hex, seed_byte, seed_stdin), network, message);
        }
        Cmd::Verify { address, message, sig } => {
            verify(address, message, sig);
        }
        Cmd::Pay { rpc_server, owner_seed_hex, owner_seed_byte, to, fee } => {
            pay(rpc_server, resolve_seed(owner_seed_hex, owner_seed_byte), to, fee).await;
        }
    }
}
