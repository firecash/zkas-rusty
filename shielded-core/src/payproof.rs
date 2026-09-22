//! Payment proofs: prove that a transaction paid a given address a given amount,
//! without revealing anything else about it.
//!
//! # Why this can exist
//!
//! On-chain an output is only a commitment `cmx` — a binding, hiding commitment to
//! (recipient address, value, rho, rseed). Two of those are public: `cmx` and `rho`
//! (the action's nullifier). So a party who knows the other three can disclose them,
//! and anybody can recompute the commitment and check it against the block. Because
//! the commitment is *binding*, no other (address, value, rseed) triple produces the
//! same `cmx`: a proof cannot be forged for a different recipient or a different
//! amount.
//!
//! The sender knows those fields because the wallet encrypts every output to its own
//! outgoing viewing key (see [`crate::walletdb`] history). The recipient knows them
//! from its incoming viewing key. Nobody else can produce a disclosure, and disclosing
//! one output says nothing about the sender's other outputs, inputs or balance.
//!
//! This is the shielded analogue of showing a bank statement line, and it is what
//! Monero calls an out-proof. Zcash specified it (ZIP-310 payment disclosure) but
//! never shipped it.
//!
//! # What a disclosure does NOT prove
//!
//! It proves the payment exists on chain and where it went — not who sent it. A third
//! party could repeat someone else's disclosure verbatim. Bind it to an identity by
//! signing the disclosure with the sending address (`crate::message`), which is what
//! the wallet's "Prove payment" does.
use crate::bundle::{ActionWire, ShieldedBundle};
use crate::wallet::scan::{reconstruct_action, trim_memo};
use orchard::{
    Address,
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    note_encryption::OrchardDomain,
    value::NoteValue,
};
use serde::{Deserialize, Serialize};
use zcash_note_encryption::try_output_recovery_with_ovk;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// One disclosed output of one transaction.
///
/// Wire format is JSON with hex/base64-free plain fields so a proof can be pasted into
/// a chat window; `verify` needs nothing but this plus the chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentDisclosure {
    /// Proof format version, so a verifier can refuse what it does not understand.
    #[serde(default = "one")]
    pub v: u8,
    /// Transaction that contains the payment, hex.
    pub txid: String,
    /// DAA score of the chain block that accepted the transaction. Not a secret (a
    /// txid already locates the block for anyone with a node) and it saves a verifier
    /// from scanning: it asks the node for the chain block at this score and looks the
    /// transaction up there.
    #[serde(default)]
    pub daa: u64,
    /// Which action of that transaction carries the disclosed output.
    pub action_index: u32,
    /// Raw Orchard address that was paid, hex (43 bytes — what a `zkas:` address
    /// decodes to; the caller renders it as bech32 for humans).
    pub recipient: String,
    /// Amount delivered to that address, in sompi.
    pub value: u64,
    /// The note's random seed, hex — the only secret a disclosure reveals, and only
    /// for this one output.
    pub rseed: String,
    /// The memo carried by the output, when the discloser chooses to include it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memo: Vec<u8>,
}

fn one() -> u8 {
    1
}

impl PaymentDisclosure {
    /// The recipient as raw address bytes, or `None` if the field is malformed.
    pub fn recipient_bytes(&self) -> Option<[u8; 43]> {
        unhex::<43>(&self.recipient)
    }
    /// The transaction id as bytes, or `None` if the field is malformed.
    pub fn txid_bytes(&self) -> Option<[u8; 32]> {
        unhex::<32>(&self.txid)
    }
}

/// Rebuild the note a disclosure describes and return its commitment, or `None` when
/// the disclosed fields are not a well-formed Orchard note.
fn commitment_of(d: &PaymentDisclosure, rho_bytes: &[u8; 32]) -> Option<ExtractedNoteCommitment> {
    let recipient: Address = Option::from(Address::from_raw_address_bytes(&d.recipient_bytes()?))?;
    let rho: Rho = Option::from(Rho::from_bytes(rho_bytes))?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(unhex::<32>(&d.rseed)?, &rho))?;
    let note: Note =
        Option::from(Note::from_parts(recipient, NoteValue::from_raw(d.value), rho, rseed, orchard::note::NoteVersion::V2))?;
    Some(ExtractedNoteCommitment::from(note.commitment()))
}

/// Every output of `bundle` that our OVK recovers and that is NOT our own change.
///
/// `my_address` is the wallet's own address: change returns to it and is not a payment
/// to anyone, so disclosing it would only leak the wallet's own balance movement.
pub fn disclose(
    txid: &[u8; 32],
    daa: u64,
    bundle: &ShieldedBundle,
    ovk: &OutgoingViewingKey,
    my_address: &[u8; 43],
) -> Vec<PaymentDisclosure> {
    let mut out = Vec::new();
    for (i, a) in bundle.actions.iter().enumerate() {
        let Some(action) = reconstruct_action(a) else { continue };
        let domain = OrchardDomain::for_action(&action);
        let Some((note, addr, memo)) = try_output_recovery_with_ovk(&domain, ovk, &action, action.cv_net(), &a.out_ciphertext)
        else {
            continue;
        };
        let recipient = addr.to_raw_address_bytes();
        if &recipient == my_address {
            continue;
        }
        out.push(PaymentDisclosure {
            v: 1,
            txid: hex(txid),
            daa,
            action_index: i as u32,
            recipient: hex(&recipient),
            value: note.value().inner(),
            rseed: hex(note.rseed().as_bytes()),
            memo: trim_memo(&memo),
        });
    }
    out
}

/// Why a disclosure did not check out. Every variant is a reason to reject the claim,
/// not a transient error: the caller has the transaction in hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The transaction has no action at `action_index`.
    NoSuchAction,
    /// The disclosed fields are not a well-formed note (bad address, bad rseed).
    Malformed,
    /// The rebuilt commitment does not equal the one on chain: the disclosure does not
    /// describe this output.
    CommitmentMismatch,
}

/// Check a disclosure against the actions of the transaction it names.
///
/// `actions` must come from the chain (the caller fetched the transaction by
/// `d.txid`); this function trusts nothing else.
pub fn verify(d: &PaymentDisclosure, actions: &[ActionWire]) -> Result<(), ProofError> {
    let a = actions.get(d.action_index as usize).ok_or(ProofError::NoSuchAction)?;
    let cmx = commitment_of(d, &a.nullifier).ok_or(ProofError::Malformed)?;
    if cmx.to_bytes() == a.cmx {
        Ok(())
    } else {
        Err(ProofError::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    /// The commitment binds the disclosure: rebuilding with the disclosed fields
    /// reproduces the on-chain `cmx`, and changing the recipient or the amount by one
    /// sompi does not. That is the whole security property, and it needs no bundle —
    /// only the note algebra the chain itself uses.
    #[test]
    fn a_disclosure_binds_recipient_and_amount() {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([11u8; 32])).expect("valid seed");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let rho_bytes = {
            // Any canonical field element is a valid rho; take one the same way the
            // coinbase path does.
            let mut b = [0u8; 32];
            b[0] = 3;
            b
        };
        let rho: Rho = Option::from(Rho::from_bytes(&rho_bytes)).expect("canonical rho");
        let rseed: RandomSeed = Option::from(RandomSeed::from_bytes([5u8; 32], &rho)).expect("valid rseed");
        let note: Note = Option::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(5_000),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .expect("valid note");
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

        let good = PaymentDisclosure {
            v: 1,
            txid: hex(&[1u8; 32]),
            daa: 0,
            action_index: 0,
            recipient: hex(&recipient.to_raw_address_bytes()),
            value: 5_000,
            rseed: hex(&[5u8; 32]),
            memo: Vec::new(),
        };
        assert_eq!(commitment_of(&good, &rho_bytes).map(|c| c.to_bytes()), Some(cmx));

        let mut wrong_amount = good.clone();
        wrong_amount.value = 5_001;
        assert_ne!(commitment_of(&wrong_amount, &rho_bytes).map(|c| c.to_bytes()), Some(cmx));

        let other = FullViewingKey::from(&Option::<SpendingKey>::from(SpendingKey::from_bytes([12u8; 32])).unwrap())
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes();
        let mut wrong_recipient = good.clone();
        wrong_recipient.recipient = hex(&other);
        assert_ne!(commitment_of(&wrong_recipient, &rho_bytes).map(|c| c.to_bytes()), Some(cmx));
    }
}
