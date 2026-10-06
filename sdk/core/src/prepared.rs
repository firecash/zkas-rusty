use core::str::FromStr;

use kaspa_shielded_core::{bundle::ShieldedBundle, payment_check::ActionDisclosure};
use serde::{Deserialize, Serialize};
use zkas_signer::{ClaimedIntent, PreparedPayment, SpendAuthRequest};

use crate::{address::ShieldedAddress, network::Network};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureV1 {
    pub spend_value: String,
    pub out_value: String,
    pub out_recipient: String,
    pub out_rseed: String,
    pub rcv: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendAuthV1 {
    pub action_index: usize,
    pub alpha: String,
}

/// Portable prepared-payment envelope used between an untrusted prover and a
/// local SDK signer. Integer values are decimal strings and binary fields are
/// lowercase hex so JavaScript never loses u64 precision.
///
/// Version 2 embeds the prover's claimed intent — recipient (`zkas:` address),
/// amount, and fee — so a detached signer (hardware wallet, CLI, another
/// device) can *display* the payment from the envelope alone. Claims are never
/// trusted: the signer cross-checks them against the user's approval and the
/// bundle itself, and reads the real fee from the bundle's value balance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPaymentEnvelope {
    pub format: String,
    pub version: u16,
    pub network_domain: String,
    /// Claimed recipient as a `zkas:` shielded address (display form).
    pub recipient: String,
    /// Claimed amount paid to the recipient, sompi, decimal string.
    pub amount: String,
    /// Claimed public fee, sompi, decimal string. Must equal the bundle's value
    /// balance — the signer refuses an envelope that claims one fee and pays
    /// another.
    pub fee: String,
    pub tx_context: String,
    pub bundle: String,
    pub disclosure: Vec<DisclosureV1>,
    pub spend_auth: Vec<SpendAuthV1>,
    pub checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    WrongFormat,
    UnsupportedVersion(u16),
    BadHex(&'static str),
    BadLength(&'static str),
    BadInteger(&'static str),
    BadAddress,
    InvalidBundle,
    ChecksumMismatch,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WireError {}

impl PreparedPaymentEnvelope {
    pub const FORMAT: &'static str = "zkas-prepared-payment";

    pub fn from_typed(payment: &PreparedPayment, network: &Network) -> Result<Self, WireError> {
        let recipient = ShieldedAddress::from_raw(network, payment.claimed.recipient).map_err(|_| WireError::BadAddress)?.to_string();
        let mut wire = Self {
            format: Self::FORMAT.into(),
            version: payment.version,
            network_domain: hex::encode(payment.network_domain),
            recipient,
            amount: payment.claimed.amount.to_string(),
            fee: payment.claimed.fee.to_string(),
            tx_context: hex::encode(&payment.tx_context),
            bundle: hex::encode(payment.bundle.to_bytes()),
            disclosure: payment
                .disclosure
                .iter()
                .map(|d| DisclosureV1 {
                    spend_value: d.spend_value.to_string(),
                    out_value: d.out_value.to_string(),
                    out_recipient: hex::encode(d.out_recipient),
                    out_rseed: hex::encode(d.out_rseed),
                    rcv: hex::encode(d.rcv),
                })
                .collect(),
            spend_auth: payment
                .spend_auth
                .iter()
                .map(|r| SpendAuthV1 { action_index: r.action_index, alpha: hex::encode(r.alpha) })
                .collect(),
            checksum: String::new(),
        };
        wire.checksum = wire.calculate_checksum();
        Ok(wire)
    }

    pub fn to_typed(&self) -> Result<PreparedPayment, WireError> {
        if self.format != Self::FORMAT {
            return Err(WireError::WrongFormat);
        }
        if self.version != PreparedPayment::VERSION {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        if self.checksum != self.calculate_checksum() {
            return Err(WireError::ChecksumMismatch);
        }
        let network_domain = fixed::<32>(&self.network_domain, "networkDomain")?;
        let recipient = ShieldedAddress::from_str(&self.recipient).map_err(|_| WireError::BadAddress)?.raw();
        let claimed = ClaimedIntent {
            recipient,
            amount: self.amount.parse().map_err(|_| WireError::BadInteger("amount"))?,
            fee: self.fee.parse().map_err(|_| WireError::BadInteger("fee"))?,
        };
        let tx_context = decode(&self.tx_context, "txContext")?;
        let bundle = ShieldedBundle::from_bytes(&decode(&self.bundle, "bundle")?).map_err(|_| WireError::InvalidBundle)?;
        let disclosure = self
            .disclosure
            .iter()
            .map(|d| {
                Ok(ActionDisclosure {
                    spend_value: d.spend_value.parse().map_err(|_| WireError::BadInteger("spendValue"))?,
                    out_value: d.out_value.parse().map_err(|_| WireError::BadInteger("outValue"))?,
                    out_recipient: fixed::<43>(&d.out_recipient, "outRecipient")?,
                    out_rseed: fixed::<32>(&d.out_rseed, "outRseed")?,
                    rcv: fixed::<32>(&d.rcv, "rcv")?,
                })
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        let spend_auth = self
            .spend_auth
            .iter()
            .map(|r| Ok(SpendAuthRequest { action_index: r.action_index, alpha: fixed::<32>(&r.alpha, "alpha")? }))
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(PreparedPayment { version: self.version, network_domain, tx_context, bundle, disclosure, spend_auth, claimed })
    }

    fn calculate_checksum(&self) -> String {
        let mut copy = self.clone();
        copy.checksum.clear();
        let encoded = serde_json::to_vec(&copy).expect("serializing a fixed SDK structure cannot fail");
        blake3::hash(&encoded).to_hex().to_string()
    }
}

fn decode(value: &str, field: &'static str) -> Result<Vec<u8>, WireError> {
    hex::decode(value).map_err(|_| WireError::BadHex(field))
}

fn fixed<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], WireError> {
    decode(value, field)?.try_into().map_err(|_| WireError::BadLength(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkas_signer::SpendAuthRequest;

    fn typed() -> PreparedPayment {
        PreparedPayment {
            version: PreparedPayment::VERSION,
            network_domain: [7; 32],
            tx_context: vec![2, 0, 0, 0],
            bundle: ShieldedBundle {
                actions: vec![],
                flags: 0,
                value_balance: 3_000_000,
                anchor: [0; 32],
                proof: vec![],
                binding_sig: [0; 64],
                burn: None,
                anchor_block: None,
            },
            disclosure: vec![],
            spend_auth: vec![SpendAuthRequest { action_index: 3, alpha: [9; 32] }],
            claimed: ClaimedIntent { recipient: [7; 43], amount: 1_500_000_000, fee: 3_000_000 },
        }
    }

    #[test]
    fn portable_envelope_roundtrips() {
        let original = typed();
        let json = serde_json::to_string(&PreparedPaymentEnvelope::from_typed(&original, &Network::Mainnet).unwrap()).unwrap();
        let decoded: PreparedPaymentEnvelope = serde_json::from_str(&json).unwrap();
        let restored = decoded.to_typed().unwrap();
        assert_eq!(restored.version, original.version);
        assert_eq!(restored.network_domain, original.network_domain);
        assert_eq!(restored.tx_context, original.tx_context);
        assert_eq!(restored.bundle, original.bundle);
        assert_eq!(restored.spend_auth[0], original.spend_auth[0]);
        assert_eq!(restored.claimed, original.claimed);
    }

    #[test]
    fn any_field_tampering_breaks_checksum() {
        let mut wire = PreparedPaymentEnvelope::from_typed(&typed(), &Network::Mainnet).unwrap();
        wire.network_domain.replace_range(0..2, "ff");
        assert!(matches!(wire.to_typed(), Err(WireError::ChecksumMismatch)));
        let mut wire = PreparedPaymentEnvelope::from_typed(&typed(), &Network::Mainnet).unwrap();
        wire.fee = "999999999".into();
        assert!(matches!(wire.to_typed(), Err(WireError::ChecksumMismatch)));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let wire = PreparedPaymentEnvelope::from_typed(&typed(), &Network::Mainnet).unwrap();
        let mut value = serde_json::to_value(wire).unwrap();
        value.as_object_mut().unwrap().insert("serverSighash".into(), serde_json::json!("untrusted"));
        assert!(serde_json::from_value::<PreparedPaymentEnvelope>(value).is_err());
    }

    #[test]
    fn version_1_envelopes_without_claims_are_refused() {
        let mut wire = PreparedPaymentEnvelope::from_typed(&typed(), &Network::Mainnet).unwrap();
        wire.version = 1;
        wire.checksum = String::new();
        wire.checksum = wire.calculate_checksum();
        assert!(matches!(wire.to_typed(), Err(WireError::UnsupportedVersion(1))));
    }

    /// The exact serialized form is a cross-language contract: the TypeScript
    /// SDK types mirror these field names, and reordering/renaming any field
    /// silently breaks foreign parsers and checksums. This golden vector pins
    /// the layout.
    #[test]
    fn golden_vector_pins_the_wire_layout() {
        let wire = PreparedPaymentEnvelope::from_typed(&typed(), &Network::Mainnet).unwrap();
        let json = serde_json::to_string(&wire).unwrap();
        for key in [
            "\"format\":\"zkas-prepared-payment\"",
            "\"version\":2",
            "\"networkDomain\":",
            "\"recipient\":\"zkas:",
            "\"amount\":\"1500000000\"",
            "\"fee\":\"3000000\"",
            "\"txContext\":",
            "\"bundle\":",
            "\"disclosure\":",
            "\"spendAuth\":[{\"actionIndex\":3,",
            "\"checksum\":",
        ] {
            assert!(json.contains(key), "wire layout changed: {key} missing from {json}");
        }
    }
}
