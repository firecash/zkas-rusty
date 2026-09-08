//! Dump the node address manager: every p2p address this node has learned via gossip.
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;

#[tokio::main]
async fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:16110".into());
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{addr}"),
        None, true, None, false, Some(500_000), Default::default(),
    ).await.expect("connect");
    let r = client.get_peer_addresses().await.expect("getPeerAddresses");
    println!("known: {}  banned: {}", r.known_addresses.len(), r.banned_addresses.len());
    for a in r.known_addresses { println!("{a}"); }
}
