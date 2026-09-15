//! Operator probe: ask a node for the shielded tree state at given chain blocks and for one
//! shielded page after a block, printing what a wallet would see. No key material involved.
//!
//!   rpc_probe <grpc://host:port> tree <hash>...
//!   rpc_probe <grpc://host:port> page <low_hash> [limit]      (prints blocks that carry actions)
//!   rpc_probe <grpc://host:port> concurrent <low_hash> [n]     (n parallel tree-state calls, checks routing)

use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::RpcHash;
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let url = args.first().expect("url").clone();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("tree");
    let client = Arc::new(GrpcClient::connect(url.clone()).await.expect("connect"));
    let info = client.get_block_dag_info().await.expect("dag info");
    println!("node {url}: sink {} pruning point {} daa {}", &info.sink.to_string()[..12], &info.pruning_point_hash.to_string()[..12], info.virtual_daa_score);
    match mode {
        "tree" => {
            for h in &args[2..] {
                let hash = RpcHash::from_str(h).expect("hash");
                match client.get_shielded_tree_state(Some(hash)).await {
                    Ok(ts) => println!(
                        "  {} -> served {} daa {} size {} ommers {} history_from {} complete {}",
                        &h[..12],
                        &ts.block_hash.to_string()[..12],
                        ts.daa_score,
                        ts.size,
                        ts.ommers.len(),
                        ts.history_from_daa_score,
                        ts.history_complete
                    ),
                    Err(e) => println!("  {} -> ERROR {e}", &h[..12]),
                }
            }
            match client.get_shielded_tree_state(None).await {
                Ok(ts) => println!("  finality checkpoint: block {} daa {} size {}", &ts.block_hash.to_string()[..12], ts.daa_score, ts.size),
                Err(e) => println!("  finality checkpoint: ERROR {e}"),
            }
        }
        "page" => {
            let low = RpcHash::from_str(&args[2]).expect("low hash");
            let limit: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(500);
            let page = client.get_shielded_blocks(low, limit).await.expect("page");
            let with = page.blocks.iter().filter(|b| !b.accepted_actions.is_empty()).count();
            println!("  reorged {} blocks {} with_actions {}", page.reorged, page.blocks.len(), with);
            let mut mismatched = 0;
            for b in page.blocks.iter().filter(|b| !b.accepted_actions.is_empty()).take(8) {
                println!(
                    "  block {} daa {} timestamp {} coinbase_outputs {} accepted_actions {} (bytes {:?}) accepted_txids {}",
                    &b.hash.to_string()[..12],
                    b.daa_score,
                    b.timestamp,
                    b.coinbase_outputs.len(),
                    b.accepted_actions.len(),
                    b.accepted_actions.iter().map(|a| a.len()).collect::<Vec<_>>(),
                    b.accepted_txids.len()
                );
            }
            for b in &page.blocks {
                if b.timestamp == 0 || b.accepted_txids.len() != b.accepted_actions.len() {
                    mismatched += 1;
                }
            }
            println!("  blocks where walletd would skip history (timestamp 0 or txids != actions): {mismatched}");
        }
        "concurrent" => {
            let low = RpcHash::from_str(&args[2]).expect("low hash");
            let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(32);
            let page = client.get_shielded_blocks(low, n as u64).await.expect("page");
            let hashes: Vec<(RpcHash, u64)> = page.blocks.iter().map(|b| (b.hash, b.daa_score)).collect();
            println!("  firing {} parallel tree-state requests on one client", hashes.len());
            let mut tasks = Vec::new();
            for (h, daa) in hashes.clone() {
                let c = client.clone();
                tasks.push(tokio::spawn(async move { (h, daa, c.get_shielded_tree_state(Some(h)).await) }));
            }
            let mut bad = 0;
            let mut sizes = Vec::new();
            for t in tasks {
                let (h, daa, r) = t.await.unwrap();
                match r {
                    Ok(ts) => {
                        if ts.block_hash != h || ts.daa_score != daa {
                            bad += 1;
                            println!("  MISMATCH asked {} daa {} got {} daa {} size {}", &h.to_string()[..12], daa, &ts.block_hash.to_string()[..12], ts.daa_score, ts.size);
                        }
                        sizes.push((daa, ts.size));
                    }
                    Err(e) => {
                        bad += 1;
                        println!("  ERROR for {}: {e}", &h.to_string()[..12]);
                    }
                }
            }
            sizes.sort();
            let monotone = sizes.windows(2).all(|w| w[0].1 <= w[1].1);
            println!("  mismatches/errors: {bad}; sizes monotone with daa: {monotone}; span {:?}..{:?}", sizes.first(), sizes.last());
        }
        "mixed" => {
            // Recent blocks (exact frontier expected) interleaved with blocks far below the
            // pruning point (served at-or-after, slow forward search) — fired together on ONE
            // client, to catch responses being matched to the wrong request under mixed latency.
            let recent_low = RpcHash::from_str(&args[2]).expect("recent low hash");
            let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(40);
            let recent = client.get_shielded_blocks(recent_low, n as u64).await.expect("recent page");
            let genesis = RpcHash::from_str("b63f7fe8e50402af34790265e299bb1ba63e943b91a59a670e5971b7a9e84e6f").unwrap();
            let old = client.get_shielded_block_metadata(genesis, n as u64).await.expect("old page");
            let mut tasks = Vec::new();
            for (b, o) in recent.blocks.iter().zip(old.blocks.iter()) {
                for (h, daa, exact) in [(b.hash, b.daa_score, true), (o.hash, o.daa_score, false)] {
                    let c = client.clone();
                    tasks.push(tokio::spawn(async move { (h, daa, exact, c.get_shielded_tree_state(Some(h)).await) }));
                }
            }
            println!("  fired {} mixed requests", tasks.len());
            let (mut bad, mut ok, mut errs) = (0, 0, 0);
            for t in tasks {
                let (h, daa, exact, r) = t.await.unwrap();
                match r {
                    Ok(ts) => {
                        let fine = if exact { ts.block_hash == h && ts.daa_score == daa } else { ts.daa_score >= daa && ts.daa_score - daa < 3000 };
                        if fine { ok += 1 } else { bad += 1; println!("  BAD exact={exact} asked {} daa {} got {} daa {} size {}", &h.to_string()[..12], daa, &ts.block_hash.to_string()[..12], ts.daa_score, ts.size); }
                    }
                    Err(e) => { errs += 1; if errs <= 3 { println!("  ERROR {}: {e}", &h.to_string()[..12]); } }
                }
            }
            println!("  ok {ok} bad {bad} errors {errs}");
        }
        _ => eprintln!("mode: tree | page | concurrent | mixed"),
    }
}
