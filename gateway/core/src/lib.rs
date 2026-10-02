//! ZKas merchant invoice state machine.
//!
//! Each invoice receives a unique Orchard diversified address derived from the
//! merchant FVK. The gateway can detect and reconcile payments but cannot spend
//! merchant funds. Confirmation uses blue-score distance, not block height.

use std::collections::{HashMap, HashSet};

use hmac::{Hmac, Mac};
use kaspa_addresses::{Address, Prefix, Version};
use orchard::keys::{FullViewingKey, Scope};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    New,
    Partial,
    Paid,
    Confirmed,
    Overpaid,
    PaidLate,
    Expired,
}

impl InvoiceStatus {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::Overpaid | Self::PaidLate | Self::Expired)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Payment {
    pub transaction_id: [u8; 32],
    pub amount_sompi: u64,
    pub blue_score: u64,
    pub daa_score: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invoice {
    pub id: String,
    pub order_id: String,
    pub address: String,
    pub diversifier_index: u32,
    pub amount_sompi: u64,
    pub paid_sompi: u64,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_blue_score: u64,
    pub checkout_url: String,
    pub redirect_url: Option<String>,
    pub metadata: HashMap<String, String>,
    pub payments: Vec<Payment>,
}

#[derive(Clone, Debug)]
pub struct CreateInvoice {
    pub order_id: String,
    pub amount_sompi: u64,
    pub now: u64,
    pub expires_in: u64,
    pub required_blue_score: u64,
    pub redirect_url: Option<String>,
    pub metadata: HashMap<String, String>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEvent {
    pub id: String,
    pub event_type: String,
    pub created_at: u64,
    pub invoice: Invoice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySnapshot {
    pub version: u16,
    pub next_diversifier: u32,
    pub invoices: Vec<Invoice>,
    pub idempotency: HashMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayError {
    InvalidViewingKey,
    InvalidAmount,
    InvalidExpiry,
    DiversifierExhausted,
    UnknownInvoice,
    AddressMismatch,
    AmountOverflow,
}

impl core::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GatewayError {}

pub struct Gateway {
    fvk: FullViewingKey,
    prefix: Prefix,
    public_url: String,
    next_diversifier: u32,
    invoices: HashMap<String, Invoice>,
    by_address: HashMap<[u8; 43], String>,
    idempotency: HashMap<String, String>,
    seen_transactions: HashSet<([u8; 32], String)>,
}

impl Gateway {
    pub fn new(fvk: &[u8; 96], prefix: Prefix, public_url: impl Into<String>) -> Result<Self, GatewayError> {
        let fvk = FullViewingKey::from_bytes(fvk).ok_or(GatewayError::InvalidViewingKey)?;
        Ok(Self {
            fvk,
            prefix,
            public_url: public_url.into().trim_end_matches('/').to_owned(),
            next_diversifier: 1,
            invoices: HashMap::new(),
            by_address: HashMap::new(),
            idempotency: HashMap::new(),
            seen_transactions: HashSet::new(),
        })
    }

    pub fn create_invoice(&mut self, request: CreateInvoice) -> Result<Invoice, GatewayError> {
        if request.amount_sompi == 0 {
            return Err(GatewayError::InvalidAmount);
        }
        if request.expires_in == 0 {
            return Err(GatewayError::InvalidExpiry);
        }
        if let Some(key) = request.idempotency_key.as_ref() {
            if let Some(id) = self.idempotency.get(key) {
                return Ok(self.invoices[id].clone());
            }
        }
        let index = self.next_diversifier;
        self.next_diversifier = self.next_diversifier.checked_add(1).ok_or(GatewayError::DiversifierExhausted)?;
        let raw = self.fvk.address_at(index, Scope::External).to_raw_address_bytes();
        let address = String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &raw));
        let id = random_id("inv");
        let expires_at = request.now.checked_add(request.expires_in).ok_or(GatewayError::InvalidExpiry)?;
        let invoice = Invoice {
            id: id.clone(),
            order_id: request.order_id,
            address,
            diversifier_index: index,
            amount_sompi: request.amount_sompi,
            paid_sompi: 0,
            status: InvoiceStatus::New,
            created_at: request.now,
            expires_at,
            required_blue_score: request.required_blue_score,
            checkout_url: format!("{}/checkout/{id}", self.public_url),
            redirect_url: request.redirect_url,
            metadata: request.metadata,
            payments: vec![],
        };
        self.by_address.insert(raw, id.clone());
        if let Some(key) = request.idempotency_key {
            self.idempotency.insert(key, id.clone());
        }
        self.invoices.insert(id, invoice.clone());
        Ok(invoice)
    }

    pub fn invoice(&self, id: &str) -> Option<&Invoice> {
        self.invoices.get(id)
    }

    pub fn snapshot(&self) -> GatewaySnapshot {
        GatewaySnapshot {
            version: 1,
            next_diversifier: self.next_diversifier,
            invoices: self.invoices.values().cloned().collect(),
            idempotency: self.idempotency.clone(),
        }
    }

    pub fn restore(
        fvk: &[u8; 96],
        prefix: Prefix,
        public_url: impl Into<String>,
        snapshot: GatewaySnapshot,
    ) -> Result<Self, GatewayError> {
        let mut gateway = Self::new(fvk, prefix, public_url)?;
        gateway.next_diversifier = snapshot.next_diversifier;
        gateway.idempotency = snapshot.idempotency;
        for invoice in snapshot.invoices {
            let address = Address::try_from(invoice.address.as_str()).map_err(|_| GatewayError::AddressMismatch)?;
            let raw: [u8; 43] = address.payload.as_slice().try_into().map_err(|_| GatewayError::AddressMismatch)?;
            for payment in &invoice.payments {
                gateway.seen_transactions.insert((payment.transaction_id, invoice.id.clone()));
            }
            gateway.by_address.insert(raw, invoice.id.clone());
            gateway.invoices.insert(invoice.id.clone(), invoice);
        }
        Ok(gateway)
    }

    /// Reconcile a decrypted received note. Duplicate transaction/invoice pairs
    /// are ignored, making scanner retries safe.
    pub fn observe_payment(
        &mut self,
        recipient: [u8; 43],
        transaction_id: [u8; 32],
        amount_sompi: u64,
        blue_score: u64,
        daa_score: u64,
        sink_blue_score: u64,
        observed_at: u64,
    ) -> Result<Option<WebhookEvent>, GatewayError> {
        let id = self.by_address.get(&recipient).cloned().ok_or(GatewayError::AddressMismatch)?;
        if !self.seen_transactions.insert((transaction_id, id.clone())) {
            return Ok(None);
        }
        let invoice = self.invoices.get_mut(&id).ok_or(GatewayError::UnknownInvoice)?;
        invoice.paid_sompi = invoice.paid_sompi.checked_add(amount_sompi).ok_or(GatewayError::AmountOverflow)?;
        invoice.payments.push(Payment { transaction_id, amount_sompi, blue_score, daa_score });
        let old = invoice.status;
        invoice.status = if old == InvoiceStatus::Expired || observed_at >= invoice.expires_at {
            InvoiceStatus::PaidLate
        } else {
            payment_status(invoice, sink_blue_score)
        };
        Ok((old != invoice.status).then(|| event("invoice.updated", invoice.clone(), invoice.created_at)))
    }

    pub fn advance(&mut self, now: u64, sink_blue_score: u64) -> Vec<WebhookEvent> {
        let mut events = Vec::new();
        for invoice in self.invoices.values_mut() {
            let old = invoice.status;
            if invoice.paid_sompi == 0 && now >= invoice.expires_at {
                invoice.status = InvoiceStatus::Expired;
            } else if invoice.paid_sompi >= invoice.amount_sompi {
                invoice.status = payment_status(invoice, sink_blue_score);
            }
            if invoice.status != old {
                events.push(event("invoice.updated", invoice.clone(), now));
            }
        }
        events
    }

    /// Withdraw recorded payments that the chain no longer shows.
    ///
    /// `paid_sompi` was previously only ever `checked_add`-ed and `seen_transactions` stopped a
    /// txid being re-read, so a payment reorged out — or replaced by a double-spend — stayed
    /// credited forever. `seen` is the set of txids the poller found in THIS cycle.
    ///
    /// Only payments that are still shallower than the invoice's own confirmation requirement are
    /// withdrawn. That is both sufficient and necessary: a reorg cannot reach a payment that is
    /// already deep, while a paged history view can legitimately omit old rows, and retracting on
    /// that would invent a reversal that never happened.
    pub fn retract_absent_shallow(
        &mut self,
        seen: &HashSet<[u8; 32]>,
        sink_blue_score: u64,
        now: u64,
    ) -> Vec<WebhookEvent> {
        let mut dropped: Vec<(String, [u8; 32])> = Vec::new();
        for (id, invoice) in self.invoices.iter() {
            for payment in &invoice.payments {
                let deep = sink_blue_score.saturating_sub(payment.blue_score) >= invoice.required_blue_score;
                if !deep && !seen.contains(&payment.transaction_id) {
                    dropped.push((id.clone(), payment.transaction_id));
                }
            }
        }
        let mut events = Vec::new();
        for (id, txid) in dropped {
            // Forget it was seen, so an identical txid reappearing on the winning chain is
            // credited again rather than silently ignored.
            self.seen_transactions.remove(&(txid, id.clone()));
            let Some(invoice) = self.invoices.get_mut(&id) else { continue };
            invoice.payments.retain(|payment| payment.transaction_id != txid);
            // Recompute rather than subtract: the sum is authoritative and cannot underflow.
            invoice.paid_sompi = invoice.payments.iter().map(|payment| payment.amount_sompi).sum();
            let old = invoice.status;
            invoice.status = if invoice.paid_sompi == 0 {
                if now >= invoice.expires_at { InvoiceStatus::Expired } else { InvoiceStatus::New }
            } else {
                payment_status(invoice, sink_blue_score)
            };
            if invoice.status != old {
                events.push(event("invoice.updated", invoice.clone(), now));
            }
        }
        events
    }
}

fn payment_status(invoice: &Invoice, sink_blue_score: u64) -> InvoiceStatus {
    if invoice.paid_sompi < invoice.amount_sompi {
        return InvoiceStatus::Partial;
    }
    // Confirmation depth is decided BEFORE the over/exact split. `Overpaid` is terminal
    // (`InvoiceStatus::terminal`), so returning it on sight let a merchant fulfil against a
    // zero-confirmation overpayment that a reorg or double-spend could then withdraw — and the
    // hosted checkout page redirected on it. A fully funded but still shallow invoice is `Paid`,
    // which is NOT terminal; it becomes `Overpaid`/`Confirmed` only once every payment is deep.
    let confirmed =
        invoice.payments.iter().all(|payment| sink_blue_score.saturating_sub(payment.blue_score) >= invoice.required_blue_score);
    if !confirmed {
        return InvoiceStatus::Paid;
    }
    if invoice.paid_sompi > invoice.amount_sompi { InvoiceStatus::Overpaid } else { InvoiceStatus::Confirmed }
}

fn event(kind: &str, invoice: Invoice, now: u64) -> WebhookEvent {
    WebhookEvent { id: random_id("evt"), event_type: kind.into(), created_at: now, invoice }
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

/// BTCPay/Stripe-style webhook signature over the exact HTTP body.
pub fn sign_webhook(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={timestamp},v1={}", hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_webhook(secret: &[u8], signature: &str, body: &[u8], now: u64, tolerance: u64) -> bool {
    let Some((time, digest)) = signature.split_once(",v1=") else { return false };
    let Ok(timestamp) = time.strip_prefix("t=").unwrap_or("").parse::<u64>() else { return false };
    if now.abs_diff(timestamp) > tolerance {
        return false;
    }
    let Ok(digest) = hex::decode(digest) else { return false };
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&digest).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_shielded_core::message::fvk_bytes_from_seed;

    fn gateway() -> Gateway {
        Gateway::new(&fvk_bytes_from_seed([7; 32]).unwrap(), Prefix::Mainnet, "https://pay.zkas.info").unwrap()
    }

    fn request(key: Option<&str>) -> CreateInvoice {
        CreateInvoice {
            order_id: "order-42".into(),
            amount_sompi: 100,
            now: 1_000,
            expires_in: 900,
            required_blue_score: 10,
            redirect_url: None,
            metadata: HashMap::new(),
            idempotency_key: key.map(str::to_owned),
        }
    }

    #[test]
    fn idempotency_reuses_invoice_but_new_orders_get_unique_addresses() {
        let mut gateway = gateway();
        let first = gateway.create_invoice(request(Some("checkout-42"))).unwrap();
        let retry = gateway.create_invoice(request(Some("checkout-42"))).unwrap();
        let next = gateway.create_invoice(request(Some("checkout-43"))).unwrap();
        assert_eq!(first.id, retry.id);
        assert_ne!(first.address, next.address);
    }

    #[test]
    fn partial_paid_confirmed_and_duplicate_states_are_deterministic() {
        let mut gateway = gateway();
        let invoice = gateway.create_invoice(request(None)).unwrap();
        let raw: [u8; 43] = Address::try_from(invoice.address.as_str()).unwrap().payload.as_slice().try_into().unwrap();
        let tx1 = [1; 32];
        gateway.observe_payment(raw, tx1, 40, 100, 100, 100, 1_100).unwrap();
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Partial);
        assert!(gateway.observe_payment(raw, tx1, 40, 100, 100, 100, 1_100).unwrap().is_none());
        gateway.observe_payment(raw, [2; 32], 60, 105, 105, 105, 1_100).unwrap();
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Paid);
        gateway.advance(1_100, 115);
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Confirmed);
    }

    /// `Overpaid` is terminal and the hosted checkout redirects on it, so returning it before the
    /// depth check let a merchant ship against a zero-confirmation overpayment.
    #[test]
    fn an_overpayment_is_not_terminal_until_it_is_deep() {
        let mut gateway = gateway();
        let invoice = gateway.create_invoice(request(None)).unwrap();
        let raw: [u8; 43] = Address::try_from(invoice.address.as_str()).unwrap().payload.as_slice().try_into().unwrap();
        // 150 against a 100 invoice, observed right at the tip: fully funded, zero depth.
        gateway.observe_payment(raw, [3; 32], 150, 100, 100, 100, 1_100).unwrap();
        let status = gateway.invoice(&invoice.id).unwrap().status;
        assert_eq!(status, InvoiceStatus::Paid, "an unconfirmed overpayment must not read as Overpaid");
        assert!(!status.terminal(), "and must not be terminal — merchants fulfil on terminal");
        gateway.advance(1_100, 110);
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Overpaid);
    }

    /// `paid_sompi` used to only ever grow, so a reorged-out or double-spent payment stayed
    /// credited forever — and `seen_transactions` stopped the txid ever being re-read.
    #[test]
    fn a_shallow_payment_the_chain_dropped_is_withdrawn_but_a_deep_one_is_not() {
        let mut gateway = gateway();
        let invoice = gateway.create_invoice(request(None)).unwrap();
        let raw: [u8; 43] = Address::try_from(invoice.address.as_str()).unwrap().payload.as_slice().try_into().unwrap();
        gateway.observe_payment(raw, [4; 32], 100, 100, 100, 100, 1_100).unwrap();
        assert_eq!(gateway.invoice(&invoice.id).unwrap().paid_sompi, 100);

        // Tip has not moved, so the payment is still shallow — and it is gone from history.
        let events = gateway.retract_absent_shallow(&HashSet::new(), 100, 1_200);
        assert_eq!(gateway.invoice(&invoice.id).unwrap().paid_sompi, 0, "the credit is withdrawn");
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::New);
        assert_eq!(events.len(), 1, "and the withdrawal is reported to the merchant");

        // The same txid winning on the other chain must be credited again, not deduplicated away.
        gateway.observe_payment(raw, [4; 32], 100, 100, 100, 100, 1_300).unwrap();
        assert_eq!(gateway.invoice(&invoice.id).unwrap().paid_sompi, 100);

        // Once deep, an absent row is a history-paging artefact, never a reversal.
        gateway.advance(1_300, 120);
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Confirmed);
        gateway.retract_absent_shallow(&HashSet::new(), 120, 1_400);
        assert_eq!(gateway.invoice(&invoice.id).unwrap().paid_sompi, 100, "a deep payment is never retracted");
        assert_eq!(gateway.invoice(&invoice.id).unwrap().status, InvoiceStatus::Confirmed);
    }

    #[test]
    fn webhooks_are_signed_and_timestamp_bounded() {
        let body = br#"{"type":"invoice.confirmed"}"#;
        let signature = sign_webhook(b"secret", 1_000, body);
        assert!(verify_webhook(b"secret", &signature, body, 1_010, 30));
        assert!(!verify_webhook(b"wrong", &signature, body, 1_010, 30));
        assert!(!verify_webhook(b"secret", &signature, body, 2_000, 30));
    }

    #[test]
    fn snapshot_restore_preserves_idempotency_and_payment_deduplication() {
        let fvk = fvk_bytes_from_seed([7; 32]).unwrap();
        let mut first = Gateway::new(&fvk, Prefix::Mainnet, "https://pay.zkas.info").unwrap();
        let invoice = first.create_invoice(request(Some("stable-key"))).unwrap();
        let raw: [u8; 43] = Address::try_from(invoice.address.as_str()).unwrap().payload.as_slice().try_into().unwrap();
        first.observe_payment(raw, [5; 32], 100, 10, 10, 20, 1_100).unwrap();
        let mut restored = Gateway::restore(&fvk, Prefix::Mainnet, "https://pay.zkas.info", first.snapshot()).unwrap();
        assert_eq!(restored.create_invoice(request(Some("stable-key"))).unwrap().id, invoice.id);
        assert!(restored.observe_payment(raw, [5; 32], 100, 10, 10, 20, 1_100).unwrap().is_none());
    }
}
