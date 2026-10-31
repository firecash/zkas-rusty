//! Publish the shielded chain as 12-hour segment files (see `zkas_walletd::chain_files`).
//!
//!   chain_export <archival node host:port> <out dir> [max new segments, default 30]
//!
//! Incremental: segments already in `<out dir>/manifest.json` are kept; each new one is
//! verified against the node's frontiers before it is written. Run it every 12 hours.
#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: chain_export <node host:port> <out dir> [max new segments]");
        std::process::exit(2);
    }
    let max_new = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
    match zkas_walletd::chain_files::export(&a[1], std::path::Path::new(&a[2]), max_new).await {
        Ok(n) => log::info!("chain_export: {n} new segment(s)"),
        Err(e) => {
            log::error!("chain_export: {e}");
            std::process::exit(1);
        }
    }
}
