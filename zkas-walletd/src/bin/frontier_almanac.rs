//! Writes the frontier almanac: one note-commitment tree frontier per DAA day, from a node
//! that validated its shielded history itself (an archival node synced from genesis).
//!
//!   frontier_almanac <node host:port> > zkas-walletd/almanac/frontier-almanac-mainnet.jsonl
//!
//! Line 1 is a header naming the network genesis; every other line is one day. Only days at
//! least two days below the tip are written, far past any reorg.
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use kaspa_rpc_core::GetShieldedTreeStateRequest;

const DAY: u64 = 86_400;

#[tokio::main]
async fn main() {
    let rpc = std::env::args().nth(1).expect("usage: frontier_almanac <node host:port>");
    let c = GrpcClient::connect_with_args(NotificationMode::Direct, format!("grpc://{rpc}"), None, true, None, false, Some(500_000), Default::default())
        .await
        .expect("connect");
    let tip = c.get_block_dag_info().await.expect("dag info").virtual_daa_score;
    let genesis = kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash;
    println!("{{\"zkas_frontier_almanac\":1,\"genesis\":\"{genesis}\",\"tip_daa\":{tip}}}");
    let mut day = DAY;
    let mut last_daa = 0u64;
    while day + 2 * DAY <= tip {
        let req = GetShieldedTreeStateRequest { block_hash: None, below_daa_score: Some(day) };
        let ts = c.get_shielded_tree_state_call(None, req).await.unwrap_or_else(|e| panic!("day {day}: {e}"));
        assert!(ts.daa_score < day, "day {day}: the node answered daa {} (no locator?)", ts.daa_score);
        assert!(ts.daa_score > last_daa, "day {day}: daa {} does not advance past {last_daa}", ts.daa_score);
        last_daa = ts.daa_score;
        let ommers: Vec<String> = ts.ommers.iter().map(|o| format!("\"{o}\"")).collect();
        println!(
            "{{\"day_daa\":{day},\"block\":\"{}\",\"daa\":{},\"size\":{},\"leaf\":\"{}\",\"ommers\":[{}]}}",
            ts.block_hash, ts.daa_score, ts.size, ts.leaf, ommers.join(",")
        );
        day += DAY;
    }
}
