//! Collects real shielded transactions from a node into a proof corpus (see
//! `shielded-core/examples/proof_corpus.rs`): one line per transaction,
//! `network_domain_hex tx_context_hex bundle_wire_hex`. Read-only.
//!
//! ```text
//! cargo run --release -p zkas-api --example proof_corpus_collect -- <node:port> <out> [max_txs]
//! ```

use std::{collections::HashSet, error::Error};

use kaspa_consensus_core::{config::params::MAINNET_PARAMS, tx::Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::args().nth(1).ok_or("missing node")?;
    let out_path = std::env::args().nth(2).ok_or("missing output file")?;
    let max: usize = std::env::args().nth(3).and_then(|v| v.parse().ok()).unwrap_or(2_000);
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
    let domain = MAINNET_PARAMS.genesis.hash.as_bytes();
    let info = client.get_block_dag_info().await?;
    let mut low = info.pruning_point_hash;
    let (mut seen, mut out, mut blocks) = (HashSet::new(), String::new(), 0usize);
    while seen.len() < max {
        let resp = client.get_blocks(Some(low), true, true).await?;
        let new: Vec<_> = resp.blocks.into_iter().filter(|b| b.header.hash != low).collect();
        if new.is_empty() {
            break;
        }
        for b in &new {
            blocks += 1;
            for rtx in b.transactions.iter().skip(1) {
                let tx: Transaction = match rtx.clone().try_into() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if !tx.is_shielded() || tx.payload.is_empty() || !seen.insert(tx.id()) {
                    continue;
                }
                out.push_str(&format!("{} {} {}\n", hex(&domain), hex(&tx.shielded_sighash_context()), hex(&tx.payload)));
            }
        }
        low = new.last().unwrap().header.hash;
    }
    std::fs::write(&out_path, out)?;
    println!("collected {} shielded txs from {blocks} blocks -> {out_path}", seen.len());
    Ok(())
}
