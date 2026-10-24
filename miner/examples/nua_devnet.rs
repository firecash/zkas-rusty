//! SF-L / NU-A devnet driver (19-sfl-nua-impl.md §4). Test networks only: refuses mainnet.
//!
//! Owns the coinbase notes paid to a fixed test seed (point `zkas-miner -a` at `addr`), replays the
//! node's shielded chain with the reference per-era tracker (`kaspa_shielded_core::era`), and builds
//! REAL spends of those notes with chosen lock time and fee, optionally with a corrupted proof or as
//! many copies. It then either submits them to the mempool or mines its own block carrying them
//! behind the template validator (template + appended txs + new merkle root + PoW), so the node's
//! consensus alone decides. Every outcome is printed as one `RESULT` line.
//!
//!   nua_devnet <grpc://host:port> addr
//!   nua_devnet <grpc://host:port> status
//!   nua_devnet <grpc://host:port> spend <submit|block> [lock=L] [fee=F] [corrupt] [copies=N] [era=E|oldest|newest] [skip=K]
//!   nua_devnet <grpc://host:port> applied <txid>
//!
//! Env: NUA_DAA (NU-A activation of the devnet, for era tracking; default never),
//!      ROLLOVER (tree_rollover_threshold; default mainnet's).

#[path = "../src/solver.rs"]
#[allow(dead_code)]
mod solver;

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{RpcHash, RpcRawBlock, RpcTransaction};
use kaspa_shielded_core::era::{EraPosition, EraTracker};
use std::sync::atomic::AtomicBool;

const SEED: [u8; 32] = [0x5a; 32];
const RECIPIENT_SEED: [u8; 32] = [0x6b; 32];

struct Owned {
    at: EraPosition,
    coinbase_txid: [u8; 32],
    index: u32,
    value: u64,
    daa: u64,
}

/// Replays chain blocks up to DAA `max_daa` (inclusive), so the tip, which anchors current-era
/// witnesses, can be held a maturity depth below the virtual.
async fn replay(client: &GrpcClient, genesis: RpcHash, tracker: &mut EraTracker, max_daa: u64) -> (Vec<Owned>, RpcHash, u64) {
    let me = kaspa_shielded_core::wallet::address_bytes_from_seed(SEED).unwrap();
    let mut owned = Vec::new();
    let mut cursor = genesis;
    let mut last_daa = 0;
    loop {
        let page = client.get_shielded_blocks(cursor, 500).await.expect("get_shielded_blocks");
        if page.reorged {
            panic!("cursor reorged; rerun");
        }
        if page.blocks.is_empty() {
            break;
        }
        let mut done = false;
        for b in &page.blocks {
            if b.daa_score > max_daa {
                done = true;
                break;
            }
            let mut leaves = Vec::new();
            let mut mine = Vec::new();
            for (i, o) in b.coinbase_outputs.iter().enumerate() {
                if o.script_public_key.len() < 43 {
                    continue;
                }
                let recipient: [u8; 43] = o.script_public_key[..43].try_into().unwrap();
                let mut seed = b.coinbase_txid.as_bytes().to_vec();
                seed.extend_from_slice(&(i as u32).to_le_bytes());
                let desc = kaspa_shielded_core::coinbase::derive_coinbase_note_desc(recipient, &seed);
                let note = kaspa_shielded_core::coinbase::coinbase_note(&desc, o.value).expect("canonical coinbase note");
                leaves.push(note.commitment.to_bytes());
                if recipient == me {
                    mine.push((leaves.len() - 1, i as u32, o.value));
                }
            }
            for acts in &b.accepted_actions {
                for rec in acts.chunks(kaspa_shielded_core::wallet::CompactActionRecord::SERIALIZED_LEN) {
                    let r = kaspa_shielded_core::wallet::CompactActionRecord::from_bytes(rec).expect("compact record");
                    leaves.push(r.cmx);
                }
            }
            let pos = tracker.apply_block(b.hash.as_bytes(), b.blue_score, b.daa_score, &leaves);
            for (leaf_idx, index, value) in mine {
                owned.push(Owned { at: pos[leaf_idx], coinbase_txid: b.coinbase_txid.as_bytes(), index, value, daa: b.daa_score });
            }
            cursor = b.hash;
            last_daa = b.daa_score;
        }
        if done {
            break;
        }
    }
    (owned, cursor, last_daa)
}

fn arg<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let url = args[0].clone();
    let cmd = args.get(1).map(String::as_str).unwrap_or("status");
    let params = kaspa_consensus_core::config::params::DEVNET_PARAMS;
    let genesis = params.genesis.hash;
    let net_domain = genesis.as_bytes();
    let me = kaspa_shielded_core::wallet::address_bytes_from_seed(SEED).unwrap();
    let my_addr = Address::new(Prefix::Devnet, Version::ShieldedOrchard, &me);
    if cmd == "addr" {
        println!("{my_addr}");
        return;
    }
    let client = GrpcClient::connect(url.clone()).await.expect("connect");
    let info = client.get_block_dag_info().await.expect("dag info");
    assert!(info.network.to_string().contains("devnet") || info.network.to_string().contains("simnet"), "test networks only: {}", info.network);
    let nua_daa = std::env::var("NUA_DAA").ok().and_then(|v| v.parse().ok()).unwrap_or(u64::MAX);
    let rollover = std::env::var("ROLLOVER").ok().and_then(|v| v.parse().ok()).unwrap_or(params.tree_rollover_threshold);
    let mut tracker = EraTracker::new(rollover, nua_daa);
    // `spend` anchors at a block `depth=` (default 45) DAA below the virtual, deeper than the
    // devnet's shielded_anchor_depth (30), so current-era spends are mature when mined.
    let depth: u64 = if cmd == "spend" { arg(&args, "depth").map(|v| v.parse().unwrap()).unwrap_or(45) } else { 0 };
    let (owned, tip, tip_daa) = replay(&client, genesis, &mut tracker, info.virtual_daa_score.saturating_sub(depth)).await;

    match cmd {
        "status" => {
            println!(
                "RESULT status virtual_daa={} scanned_tip={} tip_daa={} era={} era_sizes={:?} owned_notes={}",
                info.virtual_daa_score,
                tip,
                tip_daa,
                tracker.era(),
                tracker.eras().iter().map(|e| e.leaves.len()).collect::<Vec<_>>(),
                owned.len()
            );
            for e in 0..=tracker.era() {
                println!("  era {e} root {} frozen_at {:?}", hex(&tracker.root(e)), tracker.eras()[e as usize].frozen_at.map(|(b, s)| (hex(&b), s)));
            }
        }
        "applied" => {
            let want: RpcHash = args[2].parse().expect("txid");
            let mut cursor = genesis;
            let mut found = None;
            loop {
                let page = client.get_shielded_blocks(cursor, 500).await.unwrap();
                if page.blocks.is_empty() {
                    break;
                }
                for b in &page.blocks {
                    if b.accepted_txids.contains(&want) {
                        found = Some((b.hash, b.daa_score));
                    }
                    cursor = b.hash;
                }
            }
            println!("RESULT applied txid={want} {}", found.map(|(h, d)| format!("YES chain_block={h} daa={d}")).unwrap_or("NO".into()));
        }
        "spend" => {
            let mode = args.get(2).map(String::as_str).expect("submit|block");
            let rest = &args[3..];
            let lock: u64 = arg(rest, "lock").map(|v| v.parse().unwrap()).unwrap_or(0);
            let fee: u64 = arg(rest, "fee").map(|v| v.parse().unwrap()).unwrap_or(3_000_000);
            let copies: u64 = arg(rest, "copies").map(|v| v.parse().unwrap()).unwrap_or(1);
            let skip: usize = arg(rest, "skip").map(|v| v.parse().unwrap()).unwrap_or(0);
            let corrupt = rest.iter().any(|a| a == "corrupt");
            // Notes deep enough to be mature (shielded_anchor_depth of the devnet is passed by the
            // caller's choice of era; the newest-but-one block is used for current-era notes).
            let pick: Vec<&Owned> = match arg(rest, "era") {
                Some("newest") | None => owned.iter().filter(|o| o.at.era == tracker.era()).collect(),
                Some("oldest") => owned.iter().filter(|o| o.at.era == 0).collect(),
                Some(e) => owned.iter().filter(|o| o.at.era == e.parse::<u32>().unwrap()).collect(),
            };
            let note = pick.get(skip).copied().expect("no owned note in that era (mine to `addr` first)");
            let w = tracker.witness(note.at).expect("witness");
            let n = kaspa_shielded_core::wallet::build::coinbase_note_for(SEED, note.coinbase_txid, note.index, note.value).unwrap();
            let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed(RECIPIENT_SEED).unwrap();
            let amount = note.value.checked_sub(fee).expect("fee above note value") / 2;
            let mut txs = Vec::new();
            for c in 0..copies {
                // Copies differ in lock time only (distinct txids); with SF-L active that is a
                // real lock, so `copies` is meant for the cap test on a network without SF-L.
                let mut tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], lock + c, SUBNETWORK_ID_NATIVE, 0, vec![]);
                let tx_ctx = tx.shielded_sighash_context();
                if c == 0 || txs.is_empty() {
                    tx.payload = kaspa_shielded_core::wallet::build::build_wallet_payment_anchored(
                        SEED,
                        vec![(n.clone(), w.path.clone())],
                        recipient,
                        amount,
                        fee,
                        &net_domain,
                        &tx_ctx,
                        false,
                        [0u8; 512],
                        Some(w.anchor_block),
                    )
                    .expect("build spend");
                } else {
                    tx.payload = txs.first().map(|t: &Transaction| t.payload.clone()).unwrap();
                }
                if corrupt {
                    let mut b = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&tx.payload, true).unwrap();
                    let i = b.proof.len() / 2;
                    b.proof[i] ^= 1;
                    tx.payload = b.to_bytes();
                }
                tx.finalize();
                txs.push(tx);
            }
            let actions: usize = txs.iter().map(|t| kaspa_shielded_core::bundle::action_count_from_bytes(&t.payload).unwrap()).sum();
            println!(
                "built {} tx(s), {actions} actions, note era {} pos {} (minted daa {}), anchor {} frozen={} lock={lock} fee={fee} corrupt={corrupt}; virtual daa {}",
                txs.len(),
                note.at.era,
                note.at.position,
                note.daa,
                hex(&w.anchor_block),
                w.frozen,
                info.virtual_daa_score
            );
            for t in &txs {
                println!("  txid {}", t.id());
            }
            match mode {
                "submit" => {
                    for t in &txs {
                        let r = client.submit_transaction(RpcTransaction::from(t), false).await;
                        println!("RESULT submit txid={} {}", t.id(), match r {
                            Ok(id) => format!("ACCEPTED {id}"),
                            Err(e) => format!("REJECTED {e}"),
                        });
                    }
                }
                "block" => {
                    let t = client.get_block_template(my_addr.clone(), vec![]).await.expect("template");
                    let mut block: Block = t.block.try_into().expect("template converts");
                    let mut header: Header = (*block.header).clone();
                    let mut all = block.transactions.to_vec();
                    all.extend(txs.iter().cloned());
                    header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(all.iter());
                    let stop = AtomicBool::new(false);
                    let nonce = solver::mine_header(&header, 4, &stop).expect("solve");
                    header.nonce = nonce;
                    header.finalize();
                    block = Block::new(header, all);
                    let hash = block.hash();
                    let daa = block.header.daa_score;
                    let r = client.submit_block(RpcRawBlock::from(&block), false).await;
                    println!("RESULT block hash={hash} daa={daa} {}", match r {
                        Ok(resp) if resp.report.is_success() => "ACCEPTED".to_string(),
                        Ok(resp) => format!("REJECTED {:?} {:?}", resp.report, resp),
                        Err(e) => format!("ERROR {e}"),
                    });
                }
                _ => panic!("mode"),
            }
        }
        _ => panic!("unknown command {cmd}"),
    }
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
