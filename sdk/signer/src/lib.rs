//! Software signing policy shared by native and WASM ZKas clients.
//!
//! The signer never proves transactions. It verifies a prover's disclosed
//! payment against the unsigned bundle, recomputes the sighash locally, and only
//! then authorizes the real Orchard spends.

use kaspa_shielded_core::{
    bundle::ShieldedBundle,
    message::{FVK_LEN, SignedMessage, fvk_bytes_from_seed, sign_message, sign_spend_auth_from_seed},
    payment_check::{ActionDisclosure, PaymentCheckError, check_prepared_payment},
    verify::sighash,
    wallet::address_bytes_from_seed,
};
use orchard::keys::FullViewingKey;
use zeroize::Zeroizing;

/// Payment the user explicitly approved in the application UI.
///
/// `max_fee` is a **ceiling**, not the fee itself. The fee a prepared payment
/// actually pays is read from the bundle it authorizes (its public value
/// balance), never from a number the prover reports out-of-band: a prover that
/// could name its own "agreed fee" could burn the user's entire change as fee
/// (collectable by a miner, plausibly the prover's own pool) while every
/// commitment check still passed. The signer refuses any fee above this bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentIntent {
    pub recipient: [u8; 43],
    pub amount: u64,
    /// Largest total fee the user approved for this transaction, in sompi.
    pub max_fee: u64,
}

/// What the prover *claims* the payment is, embedded in the prepared envelope so
/// a detached signer (hardware wallet, CLI, another device) can display the
/// payment from the envelope alone. Claims are cross-checked against both the
/// user's approved [`PaymentIntent`] and the bundle itself before signing — a
/// claim is never trusted, only required to be consistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimedIntent {
    pub recipient: [u8; 43],
    pub amount: u64,
    pub fee: u64,
}

/// One real Orchard spend authorization requested by the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendAuthRequest {
    pub action_index: usize,
    pub alpha: [u8; 32],
}

/// Versioned, typed material a prover gives to a signer.
///
/// Bindings may encode this as JSON, CBOR, or another versioned wire format, but
/// all of them must construct this type before invoking signing policy.
#[derive(Clone, Debug)]
pub struct PreparedPayment {
    pub version: u16,
    pub network_domain: [u8; 32],
    pub tx_context: Vec<u8>,
    pub bundle: ShieldedBundle,
    pub disclosure: Vec<ActionDisclosure>,
    pub spend_auth: Vec<SpendAuthRequest>,
    /// The prover's own statement of what this payment is (recipient, amount,
    /// fee). Verified against the user's intent and the bundle before signing.
    pub claimed: ClaimedIntent,
}

impl PreparedPayment {
    /// Version 2 added the embedded [`ClaimedIntent`]; version 1 envelopes,
    /// which carried intent out-of-band, are no longer accepted.
    pub const VERSION: u16 = 2;
}

/// Signature returned for one action. The prover/finalizer applies it only at
/// the corresponding action index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceSignature {
    pub action_index: usize,
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub enum SignerError {
    InvalidSeed,
    UnsupportedPreparedVersion(u16),
    WrongNetwork,
    InvalidViewingKey,
    PaymentRejected(PaymentCheckError),
    InvalidSpendRandomizer {
        action_index: usize,
    },
    DuplicateAction {
        action_index: usize,
    },
    MissingAction {
        action_index: usize,
    },
    /// The bundle's public value balance is zero or negative, so it pays no fee
    /// — a shielded payment always pays a positive public fee.
    NonPositiveFee {
        value_balance: i64,
    },
    /// The bundle pays a larger fee than the user approved.
    FeeAboveApprovedMaximum {
        fee: u64,
        max_fee: u64,
    },
    /// The envelope's claimed intent does not match what the user approved or
    /// what the bundle actually pays.
    ClaimedIntentMismatch(&'static str),
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSeed => f.write_str("seed is not a valid Orchard spending key"),
            Self::UnsupportedPreparedVersion(version) => write!(f, "unsupported prepared-payment version {version}"),
            Self::WrongNetwork => f.write_str("prepared payment belongs to a different network"),
            Self::InvalidViewingKey => f.write_str("derived full viewing key is invalid"),
            Self::PaymentRejected(error) => write!(f, "refusing to sign: {error}"),
            Self::InvalidSpendRandomizer { action_index } => write!(f, "action {action_index} has an invalid spend randomizer"),
            Self::DuplicateAction { action_index } => write!(f, "action {action_index} is requested more than once"),
            Self::MissingAction { action_index } => write!(f, "bundle action {action_index} does not exist"),
            Self::NonPositiveFee { value_balance } => {
                write!(f, "bundle's value balance is {value_balance}; a payment must pay a positive public fee")
            }
            Self::FeeAboveApprovedMaximum { fee, max_fee } => {
                write!(f, "refusing to sign: bundle pays a fee of {fee} sompi, above the approved maximum of {max_fee}")
            }
            Self::ClaimedIntentMismatch(what) => {
                write!(f, "refusing to sign: the envelope's claimed {what} does not match the approved payment")
            }
        }
    }
}

impl std::error::Error for SignerError {}

/// In-memory software signer. Bindings should keep this object inside the
/// smallest available security boundary and avoid repeatedly converting seeds
/// to strings. Seed bytes are zeroized when it is dropped.
pub struct SoftwareSigner {
    seed: Zeroizing<[u8; 32]>,
}

impl SoftwareSigner {
    pub fn new(seed: [u8; 32]) -> Result<Self, SignerError> {
        address_bytes_from_seed(seed).ok_or(SignerError::InvalidSeed)?;
        Ok(Self { seed: Zeroizing::new(seed) })
    }

    pub fn address_bytes(&self) -> [u8; 43] {
        address_bytes_from_seed(*self.seed).expect("seed was validated at construction")
    }

    pub fn full_viewing_key(&self) -> [u8; FVK_LEN] {
        fvk_bytes_from_seed(*self.seed).expect("seed was validated at construction")
    }

    pub fn sign_message(&self, domain: &[u8], message: &[u8]) -> SignedMessage {
        sign_message(*self.seed, domain, message, rand::rng()).expect("seed was validated at construction")
    }

    /// Verify user intent and authorize a prepared payment. `expected_network`
    /// comes from trusted application configuration, never from the prover.
    pub fn verify_and_sign(
        &self,
        expected_network: &[u8; 32],
        intent: &PaymentIntent,
        prepared: &PreparedPayment,
    ) -> Result<Vec<DeviceSignature>, SignerError> {
        if prepared.version != PreparedPayment::VERSION {
            return Err(SignerError::UnsupportedPreparedVersion(prepared.version));
        }
        if &prepared.network_domain != expected_network {
            return Err(SignerError::WrongNetwork);
        }

        // The fee is what the BUNDLE pays — its public value balance — never a
        // number the prover reported alongside it. The user bounds it; anything
        // above the bound is refused before any signature exists.
        let fee = match u64::try_from(prepared.bundle.value_balance) {
            Ok(fee) if fee > 0 => fee,
            _ => return Err(SignerError::NonPositiveFee { value_balance: prepared.bundle.value_balance }),
        };
        if fee > intent.max_fee {
            return Err(SignerError::FeeAboveApprovedMaximum { fee, max_fee: intent.max_fee });
        }

        // The claims a detached signer would display must be the payment the
        // user approved and the payment the bundle pays. A prover that shows one
        // thing and pays another is refused here.
        if prepared.claimed.recipient != intent.recipient {
            return Err(SignerError::ClaimedIntentMismatch("recipient"));
        }
        if prepared.claimed.amount != intent.amount {
            return Err(SignerError::ClaimedIntentMismatch("amount"));
        }
        if prepared.claimed.fee != fee {
            return Err(SignerError::ClaimedIntentMismatch("fee"));
        }

        let fvk = FullViewingKey::from_bytes(&self.full_viewing_key()).ok_or(SignerError::InvalidViewingKey)?;
        check_prepared_payment(&prepared.bundle, &prepared.disclosure, &fvk, &intent.recipient, intent.amount, fee)
            .map_err(SignerError::PaymentRejected)?;

        let action_count = prepared.bundle.actions.len();
        let mut seen = vec![false; action_count];
        let message = sighash(&prepared.bundle, &prepared.network_domain, &prepared.tx_context);
        let mut signatures = Vec::with_capacity(prepared.spend_auth.len());
        for request in &prepared.spend_auth {
            if request.action_index >= action_count {
                return Err(SignerError::MissingAction { action_index: request.action_index });
            }
            if core::mem::replace(&mut seen[request.action_index], true) {
                return Err(SignerError::DuplicateAction { action_index: request.action_index });
            }
            let signature = sign_spend_auth_from_seed(*self.seed, request.alpha, message)
                .ok_or(SignerError::InvalidSpendRandomizer { action_index: request.action_index })?;
            signatures.push(DeviceSignature { action_index: request.action_index, signature });
        }
        Ok(signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_derives_stable_public_material() {
        let signer = SoftwareSigner::new([7; 32]).unwrap();
        assert_eq!(signer.address_bytes(), address_bytes_from_seed([7; 32]).unwrap());
        assert_eq!(signer.full_viewing_key(), fvk_bytes_from_seed([7; 32]).unwrap());
    }

    fn prepared(value_balance: i64, claimed: ClaimedIntent) -> PreparedPayment {
        PreparedPayment {
            version: PreparedPayment::VERSION,
            network_domain: [1; 32],
            tx_context: vec![2, 0],
            bundle: ShieldedBundle {
                actions: vec![],
                flags: 0,
                value_balance,
                anchor: [0; 32],
                proof: vec![],
                binding_sig: [0; 64],
                burn: None,
                anchor_block: None,
            },
            disclosure: vec![],
            spend_auth: vec![],
            claimed,
        }
    }

    fn intent(signer: &SoftwareSigner, amount: u64, max_fee: u64) -> PaymentIntent {
        PaymentIntent { recipient: signer.address_bytes(), amount, max_fee }
    }

    #[test]
    fn fee_is_read_from_the_bundle_and_bounded_by_the_user() {
        let signer = SoftwareSigner::new([7; 32]).unwrap();
        let approved = intent(&signer, 1_000, 50);
        let claimed = ClaimedIntent { recipient: approved.recipient, amount: 1_000, fee: 100 };
        // The bundle pays 100 sompi of fee; the user approved at most 50.
        match signer.verify_and_sign(&[1; 32], &approved, &prepared(100, claimed)) {
            Err(SignerError::FeeAboveApprovedMaximum { fee: 100, max_fee: 50 }) => {}
            other => panic!("expected fee refusal, got {other:?}"),
        }
    }

    #[test]
    fn zero_or_negative_fee_bundles_are_refused() {
        let signer = SoftwareSigner::new([7; 32]).unwrap();
        let approved = intent(&signer, 1_000, 50);
        let claimed = ClaimedIntent { recipient: approved.recipient, amount: 1_000, fee: 0 };
        for value_balance in [0i64, -5] {
            match signer.verify_and_sign(&[1; 32], &approved, &prepared(value_balance, claimed)) {
                Err(SignerError::NonPositiveFee { .. }) => {}
                other => panic!("expected non-positive-fee refusal for {value_balance}, got {other:?}"),
            }
        }
    }

    #[test]
    fn claims_must_match_the_approved_payment_and_the_bundle() {
        let signer = SoftwareSigner::new([7; 32]).unwrap();
        let approved = intent(&signer, 1_000, 50);
        let honest = ClaimedIntent { recipient: approved.recipient, amount: 1_000, fee: 30 };

        let mut wrong_recipient = honest;
        wrong_recipient.recipient = [9; 43];
        let mut wrong_amount = honest;
        wrong_amount.amount = 999;
        let mut wrong_fee = honest;
        wrong_fee.fee = 20; // bundle pays 30

        for (claimed, what) in [(wrong_recipient, "recipient"), (wrong_amount, "amount"), (wrong_fee, "fee")] {
            match signer.verify_and_sign(&[1; 32], &approved, &prepared(30, claimed)) {
                Err(SignerError::ClaimedIntentMismatch(field)) => assert_eq!(field, what),
                other => panic!("expected claimed-{what} refusal, got {other:?}"),
            }
        }

        // Honest claims within the fee bound pass every intent gate; the empty
        // test bundle is then rejected by the commitment checks, proving the
        // full payment check still runs after the new gates.
        match signer.verify_and_sign(&[1; 32], &approved, &prepared(30, honest)) {
            Err(SignerError::PaymentRejected(PaymentCheckError::ValueImbalance)) => {}
            other => panic!("expected the payment check to run, got {other:?}"),
        }
    }

    #[test]
    fn message_signing_is_bound_to_domain_and_message() {
        use kaspa_shielded_core::message::verify_message;

        let signer = SoftwareSigner::new([9; 32]).unwrap();
        let signed = signer.sign_message(b"zkas-mainnet", b"approved");
        assert!(verify_message(&signed.address, b"zkas-mainnet", b"approved", &signed.fvk, &signed.sig).is_ok());
        assert!(verify_message(&signed.address, b"zkas-mainnet", b"changed", &signed.fvk, &signed.sig).is_err());
    }
}
