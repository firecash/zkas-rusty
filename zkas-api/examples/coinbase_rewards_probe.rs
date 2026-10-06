//! Prints what `GetShieldedCoinbaseRewards` reports for one recipient: paid rewards in the scanned
//! range and, from the security fork, the amount accruing in the sink's miner slot.
//!
//! ```text
//! cargo run --release -p zkas-api --example coinbase_rewards_probe -- <node:port> <zkas address>
//! ```

use std::error::Error;

use kaspa_addresses::Address;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::args().nth(1).ok_or("missing node")?;
    let address = Address::try_from(std::env::args().nth(2).ok_or("missing address")?.as_str())?;
    let recipient = address.payload.to_vec();
    if recipient.len() != 43 {
        return Err(format!("expected a 43-byte shielded address payload, got {}", recipient.len()).into());
    }
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{rpc}"),
        None,
        false,
        None,
        false,
        Some(60_000),
        Default::default(),
    )
    .await?;
    let start = client.get_block_dag_info().await?.pruning_point_hash;
    let r = client.get_shielded_coinbase_rewards(vec![recipient], start, 2_000).await?;
    let paid: u64 = r.rewards.iter().map(|x| x.value).sum();
    println!("scanned={} paid_notes={} paid_total={} pending_value={} pending_recipient_set={}", r.scanned_blocks, r.rewards.len(), paid, r.pending_value, !r.pending_recipient.is_empty());
    Ok(())
}
