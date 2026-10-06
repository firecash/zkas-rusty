use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use kaspa_addresses::{Address, Prefix};
use qrcode::{QrCode, render::svg};
use serde::Deserialize;
use serde_json::{Value, json};
use zkas_payment_gateway::{CreateInvoice, Gateway, GatewaySnapshot, Invoice, WebhookEvent, sign_webhook};

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    public_url: String,
    api_key: String,
    fvk: [u8; 96],
    prefix: Prefix,
    state_file: PathBuf,
    walletd_url: String,
    wallet_token: String,
    webhook_url: Option<String>,
    webhook_secret: String,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    gateway: Arc<Mutex<Gateway>>,
    http: reqwest::Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInvoiceBody {
    order_id: String,
    amount_sompi: String,
    expires_in: Option<u64>,
    required_blue_score: Option<u64>,
    redirect_url: Option<String>,
    metadata: Option<HashMap<String, String>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn api_error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message.into() })))
}

/// Length-checked, difference-accumulating comparison. `==` on `str` short-circuits at the first
/// differing byte, which turns the merchant API key into a timing oracle; this leaks only the
/// length. Not worth a new dependency, but not worth leaving either.
fn secret_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|key| secret_eq(key.as_bytes(), state.config.api_key.as_bytes()))
}

async fn create_invoice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateInvoiceBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !authorized(&headers, &state) {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid API key"));
    }
    let amount_sompi = body
        .amount_sompi
        .parse::<u64>()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "amountSompi must be an unsigned decimal u64 string"))?;
    let idempotency_key = headers.get("idempotency-key").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let invoice = {
        let mut gateway = state.gateway.lock().map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "state lock poisoned"))?;
        let invoice = gateway
            .create_invoice(CreateInvoice {
                order_id: body.order_id,
                amount_sompi,
                now: now(),
                expires_in: body.expires_in.unwrap_or(900),
                required_blue_score: body.required_blue_score.unwrap_or(10),
                redirect_url: body.redirect_url,
                metadata: body.metadata.unwrap_or_default(),
                idempotency_key,
            })
            .map_err(|error| api_error(StatusCode::BAD_REQUEST, error.to_string()))?;
        persist(&state.config.state_file, &gateway.snapshot()).map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
        invoice
    };
    Ok(Json(invoice_json(&invoice)))
}

async fn get_invoice(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let gateway = state.gateway.lock().map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "state lock poisoned"))?;
    let invoice = gateway.invoice(&id).ok_or_else(|| api_error(StatusCode::NOT_FOUND, "invoice not found"))?;
    Ok(Json(invoice_json(invoice)))
}

async fn checkout(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> impl IntoResponse {
    let invoice = state.gateway.lock().ok().and_then(|gateway| gateway.invoice(&id).cloned());
    let Some(invoice) = invoice else { return (StatusCode::NOT_FOUND, Html(String::from("invoice not found"))).into_response() };
    let amount = format_units(invoice.amount_sompi);
    // The wallet parses `?amount=` as a DECIMAL ZKAS coin value (e.g. `1.5`), not
    // sompi — encoding raw sompi here made the payer's wallet prefill a
    // 100,000,000x overpayment. Use the same decimal string we display.
    let payment_uri = format!("{}?amount={}", invoice.address, amount);
    let qr = QrCode::new(payment_uri.as_bytes())
        .map(|code| code.render::<svg::Color>().min_dimensions(220, 220).build())
        .unwrap_or_default();
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Pay with ZKAS</title><style>body{{font:16px system-ui;background:#0b1020;color:#eef;display:grid;place-items:center;min-height:100vh}}main{{max-width:560px;padding:32px;background:#151c31;border-radius:18px;text-align:center}}svg{{background:white;padding:10px;border-radius:12px}}code{{word-break:break-all;background:#080c17;padding:12px;display:block;border-radius:8px;text-align:left}}button{{padding:12px;margin-top:10px}}.status{{font-size:1.2rem}}</style></head><body><main><h1>Pay with ZKAS</h1><div>{qr}</div><p>Send exactly <strong>{amount} ZKAS</strong></p><code id="address">{address}</code><button onclick="navigator.clipboard.writeText(document.getElementById('address').textContent)">Copy address</button><p class="status" id="status">Waiting for payment…</p></main><script>const id={id:?};setInterval(async()=>{{const r=await fetch('/api/v1/invoices/'+id);const i=await r.json();document.getElementById('status').textContent=i.status;if((i.status==='confirmed'||i.status==='overpaid')&&i.redirectUrl)setTimeout(()=>location.href=i.redirectUrl,1200)}},3000)</script></body></html>"#,
        address = invoice.address
    );
    Html(html).into_response()
}

fn invoice_json(invoice: &Invoice) -> Value {
    json!({
        "id": invoice.id,
        "orderId": invoice.order_id,
        "address": invoice.address,
        "amountSompi": invoice.amount_sompi.to_string(),
        "paidSompi": invoice.paid_sompi.to_string(),
        "status": invoice.status,
        "createdAt": invoice.created_at,
        "expiresAt": invoice.expires_at,
        "checkoutUrl": invoice.checkout_url,
        "redirectUrl": invoice.redirect_url,
        "metadata": invoice.metadata,
    })
}

fn format_units(value: u64) -> String {
    let whole = value / 100_000_000;
    let fractional = format!("{:08}", value % 100_000_000).trim_end_matches('0').to_owned();
    if fractional.is_empty() { whole.to_string() } else { format!("{whole}.{fractional}") }
}

fn persist(path: &Path, snapshot: &GatewaySnapshot) -> Result<(), String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

async fn observer(state: AppState) {
    loop {
        if let Err(error) = poll_wallet(&state).await {
            eprintln!("gateway wallet observer: {error}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// The node's current virtual DAA score, via walletd `/api/status`. This is the
/// confirmation reference: an invoice is `Confirmed` only once the tip is
/// `required_blue_score` DAA beyond the paying transaction. Walletd's history
/// exposes each payment's DAA score (not its blue score), so confirmations are
/// measured in selected-chain DAA depth — monotonic and reorg-safe.
/// The node tip as walletd reports it, and whether walletd's view is complete enough to judge a
/// payment's absence (synced and not reloading). A zero tip is no tip: walletd reports it while
/// it starts, and using it would make every payment shallow.
async fn node_tip_daa(state: &AppState) -> Result<(u64, bool), String> {
    let response = state
        .http
        .get(format!("{}/api/status", state.config.walletd_url.trim_end_matches('/')))
        .header("x-wallet-token", &state.config.wallet_token)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("walletd status returned {}", response.status()));
    }
    let body: Value = response.json().await.map_err(|error| error.to_string())?;
    let tip = body.get("daa_score").and_then(Value::as_u64).ok_or_else(|| "walletd status missing daa_score".to_string())?;
    if tip == 0 {
        return Err("walletd reports no tip yet".to_string());
    }
    let synced = body.get("synced").and_then(Value::as_bool).unwrap_or(false)
        && !body.get("loading").and_then(Value::as_bool).unwrap_or(true);
    Ok((tip, synced))
}

async fn poll_wallet(state: &AppState) -> Result<(), String> {
    // Fetch the tip first: without a real reference every payment would confirm
    // instantly (the old code fabricated `daa + 10_000` / `u64::MAX` as the
    // sink), so a merchant would treat a 0-conf payment as final. On a failed
    // fetch we skip this cycle rather than over-confirm.
    let (tip_daa, wallet_synced) = node_tip_daa(state).await?;
    let response = state
        .http
        .get(format!("{}/api/wallet/history?limit=5000", state.config.walletd_url.trim_end_matches('/')))
        .header("x-wallet-token", &state.config.wallet_token)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("walletd history returned {}", response.status()));
    }
    let body: Value = response.json().await.map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    // Every txid this cycle actually saw on chain, for the reorg reconciliation below.
    let mut seen_txids: HashSet<[u8; 32]> = HashSet::new();
    {
        let mut gateway = state.gateway.lock().map_err(|_| "state lock poisoned")?;
        for row in body.get("rows").and_then(Value::as_array).into_iter().flatten() {
            if row.get("kind").and_then(Value::as_str) != Some("received") {
                continue;
            }
            let Some(recipient) = row.get("recipient").and_then(Value::as_str) else { continue };
            let Ok(address) = Address::try_from(recipient) else { continue };
            let Ok(raw) = <[u8; 43]>::try_from(address.payload.as_slice()) else { continue };
            let Some(txid) = row.get("txid").and_then(Value::as_str).and_then(|v| hex::decode(v).ok()).and_then(|v| v.try_into().ok())
            else {
                continue;
            };
            let amount = row
                .get("amountSompiExact")
                .and_then(Value::as_str)
                .and_then(|v| v.parse().ok())
                .or_else(|| row.get("amountSompi").and_then(Value::as_u64))
                .unwrap_or(0);
            // The row is on chain, so record it for reconciliation even if the depth below is
            // unreadable — otherwise this cycle would retract a payment that never went away.
            seen_txids.insert(txid);
            // A missing or non-numeric score must SKIP the row, never default to 0: at 0 the depth
            // test `tip - 0 >= required` is trivially true and the payment confirms instantly.
            // walletd emits this as a u64 today, but it already serialises other amounts as
            // strings for JS precision (`amountSompiExact`), so one such change here would
            // silently confirm every invoice. Fail closed, exactly as the tip fetch does.
            let Some(daa) = row.get("daaScore").and_then(Value::as_u64) else {
                eprintln!("gateway: history row {} has no numeric daaScore; skipping", hex::encode(txid));
                continue;
            };
            if let Ok(Some(event)) = gateway.observe_payment(raw, txid, amount, daa, daa, tip_daa, now()) {
                events.push(event);
            }
        }
        // Withdraw shallow payments the chain no longer shows (reorg / double-spend) BEFORE
        // re-evaluating, so `advance` recomputes against corrected totals rather than a credit
        // that has gone away.
        // Only judge absence against a complete view: while walletd rescans or reloads, its
        // history is empty or partial with a 200 and would reverse real payments.
        if wallet_synced {
            for event in gateway.retract_absent_shallow(&seen_txids, tip_daa, now()) {
                events.push(event);
            }
        }
        // Re-evaluate open invoices against the current tip so Paid -> Confirmed
        // fires as depth accrues, and unpaid invoices expire.
        for event in gateway.advance(now(), tip_daa) {
            events.push(event);
        }
        persist(&state.config.state_file, &gateway.snapshot())?;
    }
    for event in events {
        deliver_webhook(state, &event).await;
    }
    Ok(())
}

async fn deliver_webhook(state: &AppState, event: &WebhookEvent) {
    let Some(url) = state.config.webhook_url.as_ref() else { return };
    let Ok(body) = serde_json::to_vec(event) else { return };
    let timestamp = now();
    let signature = sign_webhook(state.config.webhook_secret.as_bytes(), timestamp, &body);
    let _ =
        state.http.post(url).header("content-type", "application/json").header("zkas-signature", signature).body(body).send().await;
}

fn config() -> Result<Config, String> {
    let required = |name: &str| env::var(name).map_err(|_| format!("missing {name}"));
    let fvk: [u8; 96] = hex::decode(required("ZKAS_GATEWAY_FVK")?)
        .map_err(|_| "ZKAS_GATEWAY_FVK is not hex")?
        .try_into()
        .map_err(|_| "ZKAS_GATEWAY_FVK must be 96 bytes")?;
    Ok(Config {
        listen: env::var("ZKAS_GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8510".into()).parse().map_err(|_| "invalid listen")?,
        public_url: required("ZKAS_GATEWAY_PUBLIC_URL")?,
        api_key: required("ZKAS_GATEWAY_API_KEY")?,
        fvk,
        prefix: Prefix::Mainnet,
        state_file: env::var("ZKAS_GATEWAY_STATE").unwrap_or_else(|_| "zkas-gateway.json".into()).into(),
        walletd_url: env::var("ZKAS_WALLETD_URL").unwrap_or_else(|_| "http://127.0.0.1:8501".into()),
        wallet_token: required("ZKAS_WALLET_TOKEN")?,
        webhook_url: env::var("ZKAS_GATEWAY_WEBHOOK_URL").ok(),
        webhook_secret: required("ZKAS_GATEWAY_WEBHOOK_SECRET")?,
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let config = config()?;
    let gateway = match fs::read(&config.state_file) {
        Ok(bytes) => Gateway::restore(
            &config.fvk,
            config.prefix,
            &config.public_url,
            serde_json::from_slice(&bytes).map_err(|error| format!("bad gateway state: {error}"))?,
        )
        .map_err(|error| error.to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Gateway::new(&config.fvk, config.prefix, &config.public_url).map_err(|error| error.to_string())?
        }
        Err(error) => return Err(error.to_string()),
    };
    let state = AppState { config: config.clone(), gateway: Arc::new(Mutex::new(gateway)), http: reqwest::Client::new() };
    tokio::spawn(observer(state.clone()));
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/api/v1/invoices", post(create_invoice))
        .route("/api/v1/invoices/:id", get(get_invoice))
        .route("/checkout/:id", get(checkout))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await.map_err(|error| error.to_string())?;
    println!("ZKas gateway listening on {}", config.listen);
    axum::serve(listener, app).await.map_err(|error| error.to_string())
}
