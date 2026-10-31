//! Publish the shielded chain as 12-hour segment files (see `zkas_walletd::chain_files`).
//!
//!   chain_export <archival node host:port> <out dir> [max new segments, default 30]
//!   chain_export keygen <secret key path>
//!
//! With `ZKAS_CHAIN_FILES_KEY=<secret key path>` the manifest is signed (required by clients
//! that fetch it over HTTP).
//!
//! Incremental: segments already in `<out dir>/manifest.json` are kept; each new one is
//! verified against the node's frontiers before it is written. Run it every 12 hours.
#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let a: Vec<String> = std::env::args().collect();
    // `chain_export keygen <path>`: a new publisher key, secret written 0600 to <path>, the
    // x-only public key printed for `chain_files::PUBLISHER_KEYS`. Refuses to overwrite.
    if a.get(1).map(String::as_str) == Some("keygen") {
        let Some(path) = a.get(2) else {
            eprintln!("usage: chain_export keygen <secret key path>");
            std::process::exit(2);
        };
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let kp = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
        let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{path}: {e}");
                std::process::exit(1);
            }
        };
        writeln!(f, "{}", kp.display_secret()).expect("write the key");
        println!("{}", kp.x_only_public_key().0);
        return;
    }
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
