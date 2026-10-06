//! Read-only pre-activation check: does any live ZKas block carry a merge-mining commitment
//! (`ZKMM`/`ZKM1`, well-formed, the exact test consensus applies) in its OWN coinbase?
//!
//! From the security fork such a block is invalid. A pool whose bridge writes the tag into the ZKas
//! template as well as the Kaspa one would lose every block, so this must read zero on mainnet before
//! the activation score is chosen.
//!
//! ```text
//! cargo run --release -p zkas-api --example coinbase_tag_scan -- <node:port> [max_blocks]
//! ```
//! Walks every DAG block (chain and non-chain) from the pruning point, at most `max_blocks`.

use std::{collections::BTreeMap, error::Error};

use kaspa_consensus_core::auxpow::AuxPow;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:16110".into());
    let max_blocks: usize = std::env::args().nth(2).and_then(|v| v.parse().ok()).unwrap_or(20_000);
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{rpc}"),
        None,
        false,
        None,
        false,
        Some(120_000),
        Default::default(),
    )
    .await?;
    let info = client.get_block_dag_info().await?;
    let mut low = info.pruning_point_hash;
    let (mut scanned, mut flagged) = (0usize, 0usize);
    let mut by_tag: BTreeMap<String, usize> = BTreeMap::new();
    while scanned < max_blocks {
        let resp = client.get_blocks(Some(low), true, true).await?;
        let new: Vec<_> = resp.blocks.into_iter().filter(|b| b.header.hash != low).collect();
        if new.is_empty() {
            break;
        }
        for b in &new {
            scanned += 1;
            let Some(cb) = b.transactions.first() else { continue };
            if AuxPow::payload_carries_commitment(&cb.payload) {
                flagged += 1;
                if flagged <= 20 {
                    println!("FLAGGED block {} daa {}", b.header.hash, b.header.daa_score);
                }
            }
            // Coarse census of miner tags (printable tail of the payload), to see who mines.
            let tail: String = cb.payload.iter().rev().take(24).rev().map(|&c| if c.is_ascii_graphic() { c as char } else { '.' }).collect();
            *by_tag.entry(tail).or_default() += 1;
        }
        low = new.last().unwrap().header.hash;
    }
    println!("scanned={scanned} flagged={flagged} from_pruning_point={}", info.pruning_point_hash);
    let mut tags: Vec<_> = by_tag.into_iter().collect();
    tags.sort_by(|a, b| b.1.cmp(&a.1));
    for (t, n) in tags.into_iter().take(15) {
        println!("  {n:>7}  {t}");
    }
    println!("{}", if flagged == 0 { "RESULT=CLEAN no live ZKas coinbase carries a commitment" } else { "RESULT=FOUND blocks that would be invalid after the fork" });
    Ok(())
}
