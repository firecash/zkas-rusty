//! Shielded chain gateway: the node's public shielded reads over HTTPS, for a wallet that
//! runs in a browser.
//!
//!   chain_gateway <node host:port> <listen addr, e.g. 127.0.0.1:16190>
//!
//! A web page cannot speak gRPC, and the node's WebSocket API does not carry the shielded
//! reads, so a browser wallet had no way to see blocks newer than the published chain files.
//! This serves exactly what a phone engine asks the node for — and nothing else:
//!
//!   GET /blocks?after=<hash>&limit=<n>   one GetShieldedBlocks page, `chain_files::encode_page`
//!   GET /tree?block=<hash> | ?below=<daa>  the node's tree frontier there (JSON)
//!   GET /tip                              virtual DAA score and sink (JSON)
//!   GET /mempool                          the mempool's shielded payloads (JSON hex list)
//!   POST /submit                          a shielded bundle (raw bytes): wrapped as the
//!                                         canonical payment transaction and submitted
//!
//! Everything it returns is public chain data. It learns what a public node learns from a
//! phone: the IP and which blocks are asked for. No key, address or wallet state ever reaches
//! it. Bounded: at most `MAX_IN_FLIGHT` node calls at once and `MAX_LIMIT` blocks a page.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use kaspa_rpc_core::{api::rpc::RpcApi, RpcHash};
use std::{collections::HashMap, sync::Arc};

const MAX_LIMIT: u64 = 1000;
const MAX_IN_FLIGHT: usize = 32;
const NODE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

struct Gw {
    node: kaspa_grpc_client::GrpcClient,
    genesis: RpcHash,
    gate: tokio::sync::Semaphore,
}

fn bad(code: StatusCode, msg: &str) -> Response {
    (code, msg.to_string()).into_response()
}

async fn blocks(State(gw): State<Arc<Gw>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(after) = q.get("after").and_then(|h| h.parse::<RpcHash>().ok()) else {
        return bad(StatusCode::BAD_REQUEST, "after=<block hash> required");
    };
    let limit = q.get("limit").and_then(|l| l.parse::<u64>().ok()).unwrap_or(MAX_LIMIT).clamp(1, MAX_LIMIT);
    let Ok(_permit) = gw.gate.try_acquire() else {
        return bad(StatusCode::SERVICE_UNAVAILABLE, "busy, retry");
    };
    match tokio::time::timeout(NODE_TIMEOUT, gw.node.get_shielded_blocks(after, limit)).await {
        Ok(Ok(page)) => {
            let body = zkas_walletd::chain_files::encode_page(&gw.genesis, &page);
            let mut r = (StatusCode::OK, body).into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Ok(Err(e)) => bad(StatusCode::BAD_GATEWAY, &format!("node: {e}")),
        Err(_) => bad(StatusCode::GATEWAY_TIMEOUT, "node timed out"),
    }
}

async fn tree(State(gw): State<Arc<Gw>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let req = match (q.get("block").and_then(|h| h.parse::<RpcHash>().ok()), q.get("below").and_then(|d| d.parse::<u64>().ok())) {
        (Some(b), _) => kaspa_rpc_core::GetShieldedTreeStateRequest { block_hash: Some(b), below_daa_score: None },
        (None, Some(d)) => kaspa_rpc_core::GetShieldedTreeStateRequest { block_hash: None, below_daa_score: Some(d) },
        _ => return bad(StatusCode::BAD_REQUEST, "block=<hash> or below=<daa> required"),
    };
    let Ok(_permit) = gw.gate.try_acquire() else {
        return bad(StatusCode::SERVICE_UNAVAILABLE, "busy, retry");
    };
    match tokio::time::timeout(NODE_TIMEOUT, gw.node.get_shielded_tree_state_call(None, req)).await {
        Ok(Ok(ts)) => Json(serde_json::json!({
            "block": ts.block_hash.to_string(),
            "daa": ts.daa_score,
            "size": ts.size,
            "leaf": ts.leaf.to_string(),
            "ommers": ts.ommers.iter().map(|o| o.to_string()).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Err(e)) => bad(StatusCode::BAD_GATEWAY, &format!("node: {e}")),
        Err(_) => bad(StatusCode::GATEWAY_TIMEOUT, "node timed out"),
    }
}

async fn tip(State(gw): State<Arc<Gw>>) -> Response {
    match tokio::time::timeout(NODE_TIMEOUT, gw.node.get_block_dag_info()).await {
        Ok(Ok(i)) => Json(serde_json::json!({
            "virtual_daa_score": i.virtual_daa_score,
            "sink": i.sink.to_string(),
            "network": i.network.to_string(),
        }))
        .into_response(),
        Ok(Err(e)) => bad(StatusCode::BAD_GATEWAY, &format!("node: {e}")),
        Err(_) => bad(StatusCode::GATEWAY_TIMEOUT, "node timed out"),
    }
}

/// The mempool's shielded transactions, as their bundle payloads. Public data: every node
/// relays them. A browser wallet trial-decrypts them to show an incoming payment at once.
async fn mempool(State(gw): State<Arc<Gw>>) -> Response {
    let Ok(_permit) = gw.gate.try_acquire() else {
        return bad(StatusCode::SERVICE_UNAVAILABLE, "busy, retry");
    };
    match tokio::time::timeout(NODE_TIMEOUT, gw.node.get_mempool_entries(false, false)).await {
        Ok(Ok(entries)) => {
            let list: Vec<String> = entries
                .iter()
                .filter(|e| e.transaction.version == kaspa_consensus_core::tx::TX_VERSION_SHIELDED)
                .map(|e| hex::encode(&e.transaction.payload))
                .collect();
            let mut r = Json(list).into_response();
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Ok(Err(e)) => bad(StatusCode::BAD_GATEWAY, &format!("node: {e}")),
        Err(_) => bad(StatusCode::GATEWAY_TIMEOUT, "node timed out"),
    }
}

/// Largest bundle accepted for submission (a 38-spend bundle is ~120 KB).
const MAX_SUBMIT_BYTES: usize = 512 * 1024;

/// Submit a shielded payment built in a browser: the raw bundle, wrapped here in the one
/// transaction shape consensus accepts for it (`payment_tx`, as walletd does). The bundle is
/// already proven and signed; the gateway only relays it, like any node's submit RPC.
async fn submit(State(gw): State<Arc<Gw>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > MAX_SUBMIT_BYTES {
        return bad(StatusCode::BAD_REQUEST, "expected a shielded bundle");
    }
    if kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&body, true).is_err() {
        return bad(StatusCode::BAD_REQUEST, "not a shielded bundle");
    }
    let Ok(_permit) = gw.gate.try_acquire() else {
        return bad(StatusCode::SERVICE_UNAVAILABLE, "busy, retry");
    };
    let tx = kaspa_shielded_wallet::tx::payment_tx(body.to_vec());
    match tokio::time::timeout(NODE_TIMEOUT, gw.node.submit_transaction((&tx).into(), false)).await {
        Ok(Ok(id)) => Json(serde_json::json!({ "txid": id.to_string() })).into_response(),
        Ok(Err(e)) => bad(StatusCode::UNPROCESSABLE_ENTITY, &format!("the node refused the payment: {e}")),
        Err(_) => bad(StatusCode::GATEWAY_TIMEOUT, "node timed out"),
    }
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: chain_gateway <node host:port> <listen addr>");
        std::process::exit(2);
    }
    let node = kaspa_grpc_client::GrpcClient::connect_with_args(
        kaspa_rpc_core::notify::mode::NotificationMode::Direct,
        format!("grpc://{}", a[1]),
        None,
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("connect {}: {e}", a[1]);
        std::process::exit(1);
    });
    let genesis = RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
    let gw = Arc::new(Gw { node, genesis, gate: tokio::sync::Semaphore::new(MAX_IN_FLIGHT) });
    // Public data, read-only: any origin may read it (the browser wallet is one of them).
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::CONTENT_TYPE]);
    let app = Router::new()
        .route("/blocks", get(blocks))
        .route("/tree", get(tree))
        .route("/tip", get(tip))
        .route("/mempool", get(mempool))
        .route("/submit", post(submit))
        .layer(DefaultBodyLimit::max(MAX_SUBMIT_BYTES))
        .layer(cors)
        .with_state(gw);
    let listener = tokio::net::TcpListener::bind(&a[2]).await.unwrap_or_else(|e| {
        eprintln!("bind {}: {e}", a[2]);
        std::process::exit(1);
    });
    log::info!("chain gateway on {} for node {}", a[2], a[1]);
    axum::serve(listener, app).await.expect("serve");
}
