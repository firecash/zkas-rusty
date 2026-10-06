//! Read-only rehearsal check of the dev-fee schedule on real blocks. Walks every block from the
//! pruning point and, for each block, finds coinbase outputs paying the dev recipient. Against the
//! block's own selected parent it checks the rule:
//! - before `end`: a dev note only when the DAA score crosses a multiple of `interval`;
//! - the first block at or past `end` (its parent below it): may carry one final dev note;
//! - every later block: no dev note.
//!
//! Chain blocks are what consensus enforced; non-chain blocks show what honest templates built.
//!
//! ```text
//! cargo run --release -p zkas-api --example dev_fee_audit -- <node:port> <end_daa> <interval> [accrual_start]
//! ```
//!
//! Before `accrual_start` (default 0) the dev fee is paid in every block, so those blocks are not
//! judged. A block may legitimately carry more than one output to the dev script when a miner pays
//! to that address; those are reported, not counted as violations.
use std::{collections::HashMap, error::Error};

use kaspa_consensus_core::config::params::ZKAS_DEV_FEE_RECIPIENT;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let rpc = args.next().unwrap_or_else(|| "127.0.0.1:16110".into());
    let end: u64 = args.next().and_then(|v| v.parse().ok()).expect("end_daa");
    let interval: u64 = args.next().and_then(|v| v.parse().ok()).expect("interval");
    let accrual_start: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
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
    let pp = client.get_block(info.pruning_point_hash, false).await?;
    let mut daa_of: HashMap<_, u64> = HashMap::new();
    daa_of.insert(pp.header.hash, pp.header.daa_score);

    let mut low = info.pruning_point_hash;
    // `get_blocks` pages overlap; judge and count each block once.
    let mut seen = std::collections::HashSet::new();
    let (mut scanned, mut chain, mut violations) = (0usize, 0usize, 0usize);
    let (mut pre_notes, mut final_notes, mut post_blocks) = (0usize, 0usize, 0usize);
    let (mut dev_paid_chain, mut final_value) = (0u128, 0u64);
    loop {
        let resp = client.get_blocks(Some(low), true, true).await?;
        let new: Vec<_> = resp.blocks.into_iter().filter(|b| b.header.hash != low).collect();
        if new.is_empty() {
            break;
        }
        for b in &new {
            daa_of.insert(b.header.hash, b.header.daa_score);
        }
        for b in &new {
            if !seen.insert(b.header.hash) {
                continue;
            }
            scanned += 1;
            let daa = b.header.daa_score;
            let Some(vd) = b.verbose_data.as_ref() else { continue };
            let is_chain = vd.is_chain_block;
            let Some(&pdaa) = daa_of.get(&vd.selected_parent_hash) else { continue };
            let Some(cb) = b.transactions.first() else { continue };
            let dev: Vec<u64> =
                cb.outputs.iter().filter(|o| o.script_public_key.script() == ZKAS_DEV_FEE_RECIPIENT.as_slice()).map(|o| o.value).collect();
            let crossed = daa / interval > pdaa / interval;
            let first_ended = daa >= end && pdaa < end;
            if dev.len() > 1 {
                println!("NOTE block {} daa {daa}: {} outputs to the dev script {dev:?}", b.header.hash, dev.len());
            }
            let ok = if daa < accrual_start {
                true
            } else if daa < end {
                dev.is_empty() || crossed
            } else if first_ended {
                true
            } else {
                dev.is_empty()
            };
            if is_chain {
                chain += 1;
                dev_paid_chain += dev.iter().map(|v| *v as u128).sum::<u128>();
                if daa < end && !dev.is_empty() {
                    pre_notes += 1;
                }
                if first_ended && !dev.is_empty() {
                    final_notes += 1;
                    final_value = dev[0];
                    println!("final dev note: block {} daa {daa} (parent {pdaa}) value {}", b.header.hash, dev[0]);
                }
                if daa >= end && !first_ended {
                    post_blocks += 1;
                }
            }
            if !ok {
                violations += 1;
                println!("VIOLATION chain={is_chain} block {} daa {daa} parent {pdaa} dev {dev:?}", b.header.hash);
            }
        }
        low = new.last().unwrap().header.hash;
    }
    println!(
        "scanned={scanned} chain={chain} pre_end_dev_notes={pre_notes} final_notes={final_notes} final_value={final_value} \
         post_end_chain_blocks={post_blocks} dev_paid_on_chain={dev_paid_chain} violations={violations} sink_daa={}",
        info.virtual_daa_score
    );
    println!("{}", if violations == 0 { "RESULT=OK" } else { "RESULT=VIOLATIONS" });
    Ok(())
}
