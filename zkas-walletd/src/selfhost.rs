//! Self-hosting mode: turn a running node into the *whole* wallet backend for a phone
//! — no reverse proxy, no domain, no Let's Encrypt, no separate daemon to babysit.
//!
//! Why this exists: Kaspium is trivial to self-host because Kaspa is transparent — the
//! node already knows every UTXO, so the wallet is a thin client. ZKas is shielded:
//! discovering a note means trial-decrypting outputs with your viewing key, which is
//! what `zkas-walletd` does. So a wallet backend must exist somewhere. This module lets
//! the node *be* that backend behind one flag: on first run it mints a self-signed TLS
//! cert + a random bearer token under the datadir, serves HTTPS directly, and prints a
//! pairing QR the mobile wallet scans to pin the cert.
//!
//! Why not plaintext like Kaspium: a transparent balance query in the clear is harmless;
//! a ZKas FVK in the clear discloses your entire transaction history to anyone on-path.
//! So TLS is the default. `insecure` (plaintext) is an explicit opt-in for operators who
//! already tunnel over a VPN / Tailscale.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A TLS identity to serve HTTPS with (PEM cert chain + private key), plus the SHA-256
/// fingerprint of the DER cert — the value the mobile client pins so it trusts *this*
/// node's self-signed cert and nothing else.
#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub fingerprint: String,
}

/// Everything the node (or the standalone binary) hands to [`run_selfhost`].
pub struct SelfHostConfig {
    /// Node gRPC endpoint the embedded daemon drives, e.g. `127.0.0.1:16810`.
    pub rpc_server: String,
    /// Public bind for the wallet API, e.g. `0.0.0.0:8443`.
    pub listen: SocketAddr,
    /// Directory holding one wallet file per token.
    pub wallet_dir: String,
    /// Where the TLS cert + bearer token are minted/stored (persist across restarts so a
    /// paired phone keeps trusting the same fingerprint). Typically `<appdir>/wallet-api`.
    pub state_dir: PathBuf,
    /// mainnet | testnet | devnet | simnet.
    pub network: String,
    /// Serve plaintext HTTP instead of TLS. Only for operators tunnelling over a VPN.
    pub insecure: bool,
    /// Override the bearer token; otherwise one is generated and persisted.
    pub token: Option<String>,
    /// The operator's public IP/host for the printed pairing URI (and cert SAN). If
    /// unknown, the URI carries a `<YOUR-PUBLIC-IP>` placeholder for the user to fill in.
    pub public_host: Option<String>,
    /// Seed-file encryption secret (passed through to the daemon).
    pub wallet_secret: Option<String>,
    /// Permit the tokenless "default" wallet (single-user self-host convenience).
    pub allow_default_token: bool,
    /// Runtime resource policy supplied by the standalone CLI or embedding node.
    pub resources: crate::ResourceLimits,
    /// Stop after this long with no wallet API request. A self-hosted daemon is the
    /// one most likely to be left exposed and forgotten, so the bound matters most
    /// here — but it stays opt-in, because a daemon that vanishes mid-sync would be
    /// its own kind of surprise.
    pub idle_timeout: Option<std::time::Duration>,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn fingerprint_of_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Load an existing self-signed cert from `dir`, or mint a fresh one. Stable across
/// restarts. SANs cover `localhost` plus every entry in `sans` (the operator's public
/// host, if known) — though a pinning client validates the fingerprint, not the name.
pub fn ensure_cert(dir: &Path, sans: &[String]) -> Result<TlsIdentity, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let fp_path = dir.join("fingerprint");
    if cert_path.exists() && key_path.exists() && fp_path.exists() {
        let cert_pem = std::fs::read(&cert_path).map_err(|e| e.to_string())?;
        let key_pem = std::fs::read(&key_path).map_err(|e| e.to_string())?;
        let fingerprint = std::fs::read_to_string(&fp_path).map_err(|e| e.to_string())?.trim().to_string();
        return Ok(TlsIdentity { cert_pem, key_pem, fingerprint });
    }
    let mut subject_alt_names: Vec<String> = vec!["localhost".into()];
    subject_alt_names.extend(sans.iter().filter(|s| !s.is_empty()).cloned());
    let certified = rcgen::generate_simple_self_signed(subject_alt_names).map_err(|e| format!("cert gen: {e}"))?;
    let fingerprint = fingerprint_of_der(certified.cert.der().as_ref());
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.key_pair.serialize_pem().into_bytes();
    std::fs::write(&cert_path, &cert_pem).map_err(|e| e.to_string())?;
    write_private(&key_path, &key_pem)?;
    write_private(&fp_path, format!("{fingerprint}\n").as_bytes())?;
    Ok(TlsIdentity { cert_pem, key_pem, fingerprint })
}

/// Load the persisted bearer token or mint a fresh 32-byte one (hex). The phone stores
/// this from the pairing QR and sends it as `Authorization: Bearer <token>`.
pub fn ensure_token(dir: &Path, override_token: Option<String>) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    if let Some(t) = override_token {
        return Ok(t);
    }
    let path = dir.join("token");
    if path.exists() {
        return Ok(std::fs::read_to_string(&path).map_err(|e| e.to_string())?.trim().to_string());
    }
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = hex::encode(raw);
    write_private(&path, format!("{token}\n").as_bytes())?;
    Ok(token)
}

/// The single string a mobile wallet consumes to connect: scheme, host, port, and the
/// two secrets it must pin (token + cert fingerprint). Fragment (`#…`) keeps the secrets
/// out of any request line if the URI is ever pasted somewhere that logs the path.
pub fn pairing_uri(cfg: &SelfHostConfig, token: &str, fingerprint: Option<&str>) -> String {
    let scheme = if cfg.insecure { "zkas+http" } else { "zkas+https" };
    let host = cfg.public_host.clone().unwrap_or_else(|| "<YOUR-PUBLIC-IP>".into());
    let port = cfg.listen.port();
    let mut frag = format!("token={token}&net={}", cfg.network);
    if let Some(fp) = fingerprint {
        frag.push_str(&format!("&fp={fp}"));
    }
    format!("{scheme}://{host}:{port}#{frag}")
}

/// Print the pairing URI and an ASCII QR to stdout so the operator can point a phone
/// camera at their terminal / SSH session and be connected — no copy-paste of secrets.
fn print_pairing(uri: &str) {
    use qrcode::QrCode;
    use qrcode::render::unicode;
    println!("\n────────────────────────────────────────────────────────────");
    println!(" ZKas wallet API — scan this in the mobile wallet to pair:");
    println!("────────────────────────────────────────────────────────────");
    match QrCode::new(uri.as_bytes()) {
        Ok(code) => {
            let rendered =
                code.render::<unicode::Dense1x2>().dark_color(unicode::Dense1x2::Light).light_color(unicode::Dense1x2::Dark).build();
            println!("{rendered}");
        }
        Err(e) => log::warn!("could not render pairing QR ({e}); use the URI below"),
    }
    println!(" {uri}");
    println!("────────────────────────────────────────────────────────────\n");
}

/// Mint (or load) the cert + token, print the pairing QR, and run the daemon over TLS
/// (or plaintext when `insecure`). Runs until `shutdown` resolves.
pub async fn run_selfhost(cfg: SelfHostConfig, shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
    let token = ensure_token(&cfg.state_dir, cfg.token.clone())?;

    let tls = if cfg.insecure {
        log::warn!(
            "wallet API is running in --insecure (plaintext HTTP) mode on {} — your viewing key and balances cross the wire UNENCRYPTED. Only do this behind a VPN/Tailscale.",
            cfg.listen
        );
        None
    } else {
        // Install a process-default rustls crypto provider (ring) for axum-server's TLS.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let sans: Vec<String> = cfg.public_host.iter().cloned().collect();
        Some(ensure_cert(&cfg.state_dir, &sans)?)
    };

    let fp = tls.as_ref().map(|t| t.fingerprint.clone());
    print_pairing(&pairing_uri(&cfg, &token, fp.as_deref()));

    let daemon = crate::Config {
        enable_multiparty: false,
        rpc_server: cfg.rpc_server,
        listen: cfg.listen,
        wallet_dir: cfg.wallet_dir,
        network: cfg.network,
        // Native mobile clients don't enforce CORS; leave it same-origin-only for any
        // browser. The bearer gate below is what actually authenticates the phone.
        allow_origin: Vec::new(),
        allow_default_token: cfg.allow_default_token,
        wallet_secret: cfg.wallet_secret,
        tls,
        require_bearer: Some(token),
        // Same default as the CLI: a self-hosted wallet that mines fragments exactly
        // like a treasury, and the ceiling leaves an ordinary wallet untouched.
        auto_consolidate: Some(crate::AUTO_CONSOLIDATE_DEFAULT),
        build_shared_tree: true,
        node_socks_proxy: None,
        // A self-host is the owner's own daemon: custodial endpoints stay enabled.
        allow_custodial: true,
        max_concurrent_proves: crate::default_max_concurrent_proves(),
        resources: cfg.resources,
        idle_timeout: cfg.idle_timeout,
    };
    crate::serve(daemon, shutdown).await
}
