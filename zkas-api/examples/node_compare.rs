//! Read-only: print DAA score, sink, pruning point, shielded tree size/root at a common block, for
//! several nodes, so rehearsals can check that nodes agree on state (not just height).
//!
//! ```text
//! cargo run --release -p zkas-api --example node_compare -- 127.0.0.1:26710 127.0.0.1:26720 ...
//! ```

use std::error::Error;

use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nodes: Vec<String> = std::env::args().skip(1).collect();
    let mut clients = Vec::new();
    for n in &nodes {
        let c = GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{n}"),
            None,
            false,
            None,
            false,
            Some(30_000),
            Default::default(),
        )
        .await;
        clients.push(c.ok());
    }
    // The first node's virtual chain block a fixed depth below its sink: all synced nodes hold it.
    let mut probe = None;
    for (n, c) in nodes.iter().zip(&clients) {
        let Some(c) = c else {
            println!("{n}: unreachable");
            continue;
        };
        match c.get_block_dag_info().await {
            Ok(i) => {
                println!(
                    "{n}: daa={} blocks={} sink={} pp={} synced={}",
                    i.virtual_daa_score,
                    i.block_count,
                    i.sink,
                    i.pruning_point_hash,
                    c.get_sync_status().await.unwrap_or(false)
                );
                if probe.is_none() {
                    probe = Some(i.sink);
                }
            }
            Err(e) => println!("{n}: error {e}"),
        }
    }
    if let Some(block) = probe {
        for (n, c) in nodes.iter().zip(&clients) {
            let Some(c) = c else { continue };
            match c.get_shielded_tree_state(Some(block)).await {
                Ok(ts) => println!("{n}: at {block}: tree size={} leaf={} answered_for={}", ts.size, ts.leaf, ts.block_hash),
                Err(e) => println!("{n}: at {block}: no tree state ({e})"),
            }
        }
    }
    Ok(())
}
