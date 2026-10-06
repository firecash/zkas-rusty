//! Device-side payment verification — the guard against a malicious prover.
//!
//! In the non-custodial (mobile) flow a daemon builds and proves a payment from the
//! wallet's viewing key, then asks the device to sign it. If the device signs the
//! bare sighash the daemon hands back, a compromised daemon can substitute the
//! sighash of a payment to *itself* — the device would be blind-signing. This module
//! lets the device instead verify, from the daemon's disclosure and the unsigned
//! bundle, that the payment really is the one the user asked for, using only note and
//! value commitments — no proving circuit, so it is available to a WASM light wallet.

use crate::bundle::ShieldedBundle;
use orchard::{
    Address,
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note},
    value::NoteValue,
};

/// What the prover must disclose about one action so the device can check the
/// payment **before** signing it. Every field is already in the PCZT the prover
/// built; disclosing them lets the device recompute the action's note commitment
/// and value commitment and compare them against the bundle it is about to
/// authorize. Without this the device signs a bare 32-byte hash it cannot
/// interpret — and a malicious prover can get a signature over a payment to
/// itself (blind signing).
///
/// None of it is secret to the device: it is the plaintext of a payment the
/// device's own key is about to authorize.
#[derive(Clone, Copy, Debug)]
pub struct ActionDisclosure {
    /// Value of the note this action spends (0 for a padding dummy).
    pub spend_value: u64,
    /// Value of the note this action creates.
    pub out_value: u64,
    /// Raw address the created note pays.
    pub out_recipient: [u8; 43],
    /// The created note's random seed — with the recipient, value and rho it
    /// reproduces the note commitment exactly.
    pub out_rseed: [u8; 32],
    /// Value-commitment trapdoor, so `cv_net` can be recomputed from the values.
    pub rcv: [u8; 32],
}

/// Why a device refused to sign a prepared payment. Every variant means the prover
/// handed over a bundle that does not match the payment the user asked for — i.e. a
/// buggy or malicious daemon — and the device must not sign.
#[derive(Debug, PartialEq, Eq)]
pub enum PaymentCheckError {
    /// Disclosure does not cover every action in the bundle.
    ActionCountMismatch,
    /// An action's output note commitment does not match the disclosed
    /// (recipient, value, rseed): the bundle pays something other than what the
    /// prover claims.
    CommitmentMismatch(usize),
    /// An action's `cv_net` does not match the disclosed values: the prover lied
    /// about an amount.
    ValueCommitmentMismatch(usize),
    /// Spends minus outputs does not equal the bundle's public value balance.
    ValueImbalance,
    /// The public value balance is not the fee the user agreed to.
    FeeMismatch { got: i64, want: u64 },
    /// No action pays the intended recipient the intended amount.
    RecipientNotPaid,
    /// More than one action pays the recipient the intended amount, so the bundle
    /// pays a multiple of what the user approved.
    RecipientPaidTwice { times: usize },
    /// The bundle pays someone who is neither the recipient nor this wallet.
    UnexpectedRecipient(usize),
    /// A disclosed field is not a valid Orchard value.
    Malformed(usize),
}

impl core::fmt::Display for PaymentCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActionCountMismatch => write!(f, "prover disclosed the wrong number of actions"),
            Self::CommitmentMismatch(i) => write!(f, "action {i}: the note it creates is not the one disclosed"),
            Self::ValueCommitmentMismatch(i) => write!(f, "action {i}: value commitment does not match the disclosed amounts"),
            Self::ValueImbalance => write!(f, "spends minus outputs does not equal the bundle's value balance"),
            Self::FeeMismatch { got, want } => write!(f, "bundle pays a fee of {got}, not the {want} agreed"),
            Self::RecipientNotPaid => write!(f, "no output pays the intended recipient the intended amount"),
            Self::RecipientPaidTwice { times } => {
                write!(f, "the bundle pays the recipient {times} times, moving a multiple of the approved amount")
            }
            Self::UnexpectedRecipient(i) => write!(f, "action {i} pays an address that is neither the recipient nor this wallet"),
            Self::Malformed(i) => write!(f, "action {i}: disclosed note fields are not valid"),
        }
    }
}

/// **The device's guard against a malicious prover.** Verifies that `wire` — the
/// unsigned bundle a daemon prepared — really is the payment the user asked for,
/// using only the wallet's own viewing key and the prover's disclosure. Call this
/// before signing anything; on `Ok`, sign the sighash **recomputed locally** from
/// `wire`, never a hash the prover supplies.
///
/// The prover cannot lie about anything that matters:
///
/// - Each action's output note commitment (`cmx`) is recomputed from the disclosed
///   `(recipient, value, rseed)` and rho (= that action's nullifier). `cmx` is in
///   the bundle and binds the note, so a hidden output paying an attacker cannot
///   masquerade as a zero-value dummy.
/// - Each `cv_net` is recomputed from the disclosed values and `rcv`, so the amounts
///   are pinned too.
/// - The declared values must sum to the bundle's public `value_balance`, which must
///   be exactly the agreed fee.
/// - Every created note must therefore pay either the intended recipient (exactly
///   once, exactly `amount`) or this wallet (change), or be worth zero.
///
/// A prover that forges any of these produces a bundle whose proof consensus
/// rejects, so the worst it can do is waste its own time.
pub fn check_prepared_payment(
    wire: &ShieldedBundle,
    disclosure: &[ActionDisclosure],
    fvk: &FullViewingKey,
    to: &[u8; 43],
    amount: u64,
    fee: u64,
) -> Result<(), PaymentCheckError> {
    use orchard::{
        note::{RandomSeed, Rho},
        value::{ValueCommitTrapdoor, ValueCommitment},
    };

    if disclosure.len() != wire.actions.len() {
        return Err(PaymentCheckError::ActionCountMismatch);
    }
    let mine = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();

    let mut spent_total: i128 = 0;
    let mut out_total: i128 = 0;
    let mut paid_recipient = 0usize;

    for (i, (act, d)) in wire.actions.iter().zip(disclosure).enumerate() {
        // rho of the note an action creates IS the nullifier of the note it spends,
        // and the wire carries that nullifier — so the device derives rho from the
        // bundle itself, not from anything the prover asserts.
        let rho = Option::<Rho>::from(Rho::from_bytes(&act.nullifier)).ok_or(PaymentCheckError::Malformed(i))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(d.out_rseed, &rho)).ok_or(PaymentCheckError::Malformed(i))?;
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&d.out_recipient)).ok_or(PaymentCheckError::Malformed(i))?;
        let out_value = NoteValue::from_raw(d.out_value);
        let note = Option::<Note>::from(Note::from_parts(recipient, out_value, rho, rseed, orchard::note::NoteVersion::V2)).ok_or(PaymentCheckError::Malformed(i))?;

        // (1) The note this action really creates is the note the prover disclosed.
        if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != act.cmx {
            return Err(PaymentCheckError::CommitmentMismatch(i));
        }

        // (2) ...and it moves exactly the disclosed amounts.
        let rcv =
            Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(d.rcv)).ok_or(PaymentCheckError::Malformed(i))?;
        let spend_value = NoteValue::from_raw(d.spend_value);
        if ValueCommitment::derive(spend_value - out_value, rcv).to_bytes() != act.cv_net {
            return Err(PaymentCheckError::ValueCommitmentMismatch(i));
        }

        // (3) Every created note goes to the recipient, back to us, or nowhere.
        if d.out_recipient == *to && d.out_value == amount {
            paid_recipient += 1;
        } else if d.out_recipient != mine && d.out_value != 0 {
            return Err(PaymentCheckError::UnexpectedRecipient(i));
        }

        spent_total += d.spend_value as i128;
        out_total += d.out_value as i128;
    }

    // (4) Nothing leaks: what we spend, minus what the notes above carry, is the fee.
    let balance = spent_total - out_total;
    if balance != wire.value_balance as i128 {
        return Err(PaymentCheckError::ValueImbalance);
    }
    if wire.value_balance != fee as i64 {
        return Err(PaymentCheckError::FeeMismatch { got: wire.value_balance, want: fee });
    }
    // (5) EXACTLY one action pays the recipient.
    //
    // Requiring only "at least one" was a way to lose money. Two actions each
    // paying exactly `amount` to `to` both satisfied check (3), and every other
    // check still passed: the balance holds because the user own notes cover the
    // extra, and `value_balance` still equals the fee. So a prover could take a
    // payment the user approved for X and have the device sign one paying N*X —
    // to the intended recipient, which is what made it look legitimate, and up to
    // the wallet whole balance.
    //
    // Exactly one is the right bound, not a conservative one: an action creates a
    // single output note, so a payment of `amount` is one output of `amount`.
    // Splitting it produces outputs that are not equal to `amount`, which check
    // (3) already refuses as an unexpected recipient.
    if paid_recipient == 0 {
        return Err(PaymentCheckError::RecipientNotPaid);
    }
    if paid_recipient > 1 {
        return Err(PaymentCheckError::RecipientPaidTwice { times: paid_recipient });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ActionWire;
    use orchard::{
        keys::SpendingKey,
        note::{RandomSeed, Rho},
        value::{ValueCommitTrapdoor, ValueCommitment},
    };

    // This file guards the one thing a device cannot delegate: that the payment it
    // is about to sign is the payment the user asked for. It had NO tests.

    fn fvk_for(seed: [u8; 32]) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes(seed).unwrap())
    }

    /// Build one action plus its disclosure, consistent by construction — the
    /// same derivation the checker performs, so anything it rejects is rejected
    /// on the merits rather than because the fixture was malformed.
    fn action(nullifier: [u8; 32], spend_value: u64, out_value: u64, to: [u8; 43]) -> (ActionWire, ActionDisclosure) {
        let rho = Option::<Rho>::from(Rho::from_bytes(&nullifier)).unwrap();
        let rseed_bytes = [7u8; 32];
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&to)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(recipient, NoteValue::from_raw(out_value), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

        let rcv_bytes = [3u8; 32];
        let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(rcv_bytes)).unwrap();
        let cv_net =
            ValueCommitment::derive(NoteValue::from_raw(spend_value) - NoteValue::from_raw(out_value), rcv).to_bytes();

        (
            ActionWire {
                nullifier,
                cmx,
                cv_net,
                rk: [0; 32],
                ephemeral_key: [0; 32],
                enc_ciphertext: [0; 580],
                out_ciphertext: [0; 80],
                spend_auth_sig: [0; 64],
            },
            ActionDisclosure { spend_value, out_value, out_recipient: to, out_rseed: rseed_bytes, rcv: rcv_bytes },
        )
    }

    fn bundle(parts: Vec<(ActionWire, ActionDisclosure)>, fee: i64) -> (ShieldedBundle, Vec<ActionDisclosure>) {
        let (actions, disc): (Vec<_>, Vec<_>) = parts.into_iter().unzip();
        (
            ShieldedBundle {
                actions,
                flags: 3,
                value_balance: fee,
                anchor: [0; 32],
                proof: Vec::new(),
                binding_sig: [0; 64],
                burn: None,
                anchor_block: None,
            },
            disc,
        )
    }

    #[test]
    fn a_payment_of_the_approved_amount_is_accepted() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(vec![action([9; 32], 1_100, 1_000, to)], 100);
        assert_eq!(check_prepared_payment(&b, &d, &fvk, &to, 1_000, 100), Ok(()));
    }

    #[test]
    fn paying_the_recipient_twice_is_refused() {
        // The hole this test exists for. Two actions each paying exactly the
        // approved amount used to satisfy every check: "at least one pays the
        // recipient" was true, the balance held because the user's own notes
        // covered the extra, and value_balance still equalled the fee. The user
        // approved 1,000 and the device would have signed 2,000.
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(
            vec![action([9; 32], 1_050, 1_000, to), action([8; 32], 1_050, 1_000, to)],
            100,
        );
        assert_eq!(
            check_prepared_payment(&b, &d, &fvk, &to, 1_000, 100),
            Err(PaymentCheckError::RecipientPaidTwice { times: 2 })
        );
    }

    #[test]
    fn paying_a_stranger_is_refused() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let stranger = fvk_for([3; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(vec![action([9; 32], 1_100, 1_000, stranger)], 100);
        assert!(matches!(
            check_prepared_payment(&b, &d, &fvk, &to, 1_000, 100),
            Err(PaymentCheckError::UnexpectedRecipient(0))
        ));
    }

    #[test]
    fn a_bundle_that_never_pays_the_recipient_is_refused() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let mine = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(vec![action([9; 32], 1_100, 1_000, mine)], 100);
        assert_eq!(check_prepared_payment(&b, &d, &fvk, &to, 1_000, 100), Err(PaymentCheckError::RecipientNotPaid));
    }

    #[test]
    fn change_back_to_this_wallet_is_allowed_alongside_the_payment() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let mine = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(
            vec![action([9; 32], 1_100, 1_000, to), action([8; 32], 500, 400, mine)],
            200,
        );
        assert_eq!(check_prepared_payment(&b, &d, &fvk, &to, 1_000, 200), Ok(()));
    }

    #[test]
    fn a_disclosure_that_does_not_cover_every_action_is_refused() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, mut d) = bundle(vec![action([9; 32], 1_100, 1_000, to)], 100);
        d.clear();
        assert_eq!(check_prepared_payment(&b, &d, &fvk, &to, 1_000, 100), Err(PaymentCheckError::ActionCountMismatch));
    }

    #[test]
    fn a_fee_that_is_not_the_one_agreed_is_refused() {
        let fvk = fvk_for([1; 32]);
        let to = fvk_for([2; 32]).address_at(0u32, Scope::External).to_raw_address_bytes();
        let (b, d) = bundle(vec![action([9; 32], 1_100, 1_000, to)], 100);
        assert!(matches!(
            check_prepared_payment(&b, &d, &fvk, &to, 1_000, 50),
            Err(PaymentCheckError::FeeMismatch { .. })
        ));
    }
}
