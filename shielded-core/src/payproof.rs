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
//! # The memo
//!
//! A disclosure may carry the output's memo. The memo is not in the commitment, but it is
//! in the output's `enc_ciphertext`, and Orchard derives the encryption's ephemeral secret
//! from the note's own `rseed` (`Domain::derive_esk`). So the verifier, which has rebuilt the
//! note, re-encrypts (note, memo) to the recipient and compares with the chain byte for byte:
//! a memo that was not the one encrypted cannot match. No extra secret is disclosed and no
//! wallet has to have saved anything at send time, so every proof the wallet can produce
//! today can bind its memo. Checking needs the full ciphertext, i.e. the block body; a pruned
//! node keeps bodies for about 30 hours, after which only the commitment can be checked
//! ([`verify_compact`]) and the memo stays unchecked.
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
    note_encryption::{OrchardDomain, OrchardNoteEncryption},
    value::NoteValue,
};
use serde::{Deserialize, Serialize};
use zcash_note_encryption::{Domain, try_output_recovery_with_ovk};

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

/// Rebuild the note a disclosure describes, or `None` when the disclosed fields are not a
/// well-formed Orchard note.
fn note_of(d: &PaymentDisclosure, rho_bytes: &[u8; 32]) -> Option<Note> {
    let recipient: Address = Option::from(Address::from_raw_address_bytes(&d.recipient_bytes()?))?;
    let rho: Rho = Option::from(Rho::from_bytes(rho_bytes))?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(unhex::<32>(&d.rseed)?, &rho))?;
    Option::from(Note::from_parts(recipient, NoteValue::from_raw(d.value), rho, rseed, orchard::note::NoteVersion::V2))
}

/// The commitment of the note a disclosure describes.
fn commitment_of(d: &PaymentDisclosure, rho_bytes: &[u8; 32]) -> Option<ExtractedNoteCommitment> {
    Some(ExtractedNoteCommitment::from(note_of(d, rho_bytes)?.commitment()))
}

/// Whether `memo` (as disclosed: trailing zeros trimmed) is exactly what `note`'s output
/// encrypted: same ephemeral key, same 580-byte ciphertext. Encryption is deterministic
/// given the note (esk comes from its rseed), so this is a byte comparison, not a search.
fn memo_matches(note: Note, memo: &[u8], ephemeral_key: &[u8; 32], enc_ciphertext: &[u8]) -> bool {
    if memo.len() > 512 {
        return false;
    }
    let mut full = [0u8; 512];
    full[..memo.len()].copy_from_slice(memo);
    let enc = OrchardNoteEncryption::new(None, note, full);
    OrchardDomain::epk_bytes(enc.epk()).0 == *ephemeral_key && enc.encrypt_note_plaintext().as_ref() == enc_ciphertext
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
    /// The recipient and amount check out, but the disclosed memo is not the one this
    /// output encrypted (it was edited, or belongs to another payment).
    MemoMismatch,
}

/// Check a disclosure against the actions of the transaction it names: recipient and
/// amount always, and the memo too when the disclosure carries one (`Ok` then means the
/// memo is bound; see the module notes).
///
/// `actions` must come from the chain (the caller fetched the transaction by
/// `d.txid`); this function trusts nothing else.
pub fn verify(d: &PaymentDisclosure, actions: &[ActionWire]) -> Result<(), ProofError> {
    let a = actions.get(d.action_index as usize).ok_or(ProofError::NoSuchAction)?;
    let note = note_of(d, &a.nullifier).ok_or(ProofError::Malformed)?;
    if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != a.cmx {
        return Err(ProofError::CommitmentMismatch);
    }
    if d.memo.len() > 512 {
        return Err(ProofError::Malformed);
    }
    if !d.memo.is_empty() && !memo_matches(note, &d.memo, &a.ephemeral_key, &a.enc_ciphertext) {
        return Err(ProofError::MemoMismatch);
    }
    Ok(())
}

/// Length of one compact action record as the node serves it (`GetShieldedBlocks`
/// `accepted_actions`, the chain files): nullifier ‖ cmx ‖ epk ‖ the first 52 bytes of
/// the note ciphertext.
pub const COMPACT_RECORD_LEN: usize = 148;

/// Check recipient and amount against the compact records of the transaction (its
/// concatenated 148-byte records, as accepted). This is what still answers once the
/// block body is pruned; the memo cannot be checked from a compact record and is ignored.
pub fn verify_compact(d: &PaymentDisclosure, records: &[u8]) -> Result<(), ProofError> {
    if records.len() % COMPACT_RECORD_LEN != 0 {
        return Err(ProofError::NoSuchAction);
    }
    let at = d.action_index as usize * COMPACT_RECORD_LEN;
    let rec = records.get(at..at + COMPACT_RECORD_LEN).ok_or(ProofError::NoSuchAction)?;
    let nf: [u8; 32] = rec[..32].try_into().expect("32-byte slice");
    let cmx = commitment_of(d, &nf).ok_or(ProofError::Malformed)?;
    if cmx.to_bytes()[..] == rec[32..64] { Ok(()) } else { Err(ProofError::CommitmentMismatch) }
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

    /// One encrypted output as the chain carries it, plus the disclosure of it.
    fn encrypted_output(memo_text: &[u8]) -> (ActionWire, PaymentDisclosure) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([21u8; 32])).expect("valid seed");
        let recipient = FullViewingKey::from(&sk).address_at(7u32, Scope::External);
        let mut rho_bytes = [0u8; 32];
        rho_bytes[0] = 9;
        let rho: Rho = Option::from(Rho::from_bytes(&rho_bytes)).expect("canonical rho");
        let rseed: RandomSeed = Option::from(RandomSeed::from_bytes([33u8; 32], &rho)).expect("valid rseed");
        let note: Note = Option::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(123_456),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .expect("valid note");
        let mut memo = [0u8; 512];
        memo[..memo_text.len()].copy_from_slice(memo_text);
        let enc = OrchardNoteEncryption::new(None, note, memo);
        let mut enc_ciphertext = [0u8; 580];
        enc_ciphertext.copy_from_slice(enc.encrypt_note_plaintext().as_ref());
        let action = ActionWire {
            nullifier: rho_bytes,
            rk: [0u8; 32],
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            cv_net: [0u8; 32],
            ephemeral_key: OrchardDomain::epk_bytes(enc.epk()).0,
            enc_ciphertext,
            out_ciphertext: [0u8; 80],
            spend_auth_sig: [0u8; 64],
        };
        let d = PaymentDisclosure {
            v: 1,
            txid: hex(&[2u8; 32]),
            daa: 0,
            action_index: 0,
            recipient: hex(&recipient.to_raw_address_bytes()),
            value: 123_456,
            rseed: hex(&[33u8; 32]),
            memo: trim_memo(&memo),
        };
        (action, d)
    }

    /// The memo is bound: the disclosed memo verifies, any rewrite of it fails, and a
    /// disclosure without a memo still proves recipient and amount.
    #[test]
    fn a_disclosed_memo_is_bound_to_the_output() {
        let (action, d) = encrypted_output(b"invoice 2026-11-0042");
        assert_eq!(verify(&d, std::slice::from_ref(&action)), Ok(()));

        let mut edited = d.clone();
        edited.memo = b"invoice 2026-11-0043".to_vec();
        assert_eq!(verify(&edited, std::slice::from_ref(&action)), Err(ProofError::MemoMismatch));

        let mut longer = d.clone();
        longer.memo.push(b'!');
        assert_eq!(verify(&longer, std::slice::from_ref(&action)), Err(ProofError::MemoMismatch));

        let mut bare = d.clone();
        bare.memo.clear();
        assert_eq!(verify(&bare, std::slice::from_ref(&action)), Ok(()), "no memo claimed: only recipient and amount");

        let mut oversized = d.clone();
        oversized.memo = vec![1u8; 513];
        assert_eq!(verify(&oversized, std::slice::from_ref(&action)), Err(ProofError::Malformed));

        let mut wrong_value = d.clone();
        wrong_value.value += 1;
        assert_eq!(verify(&wrong_value, std::slice::from_ref(&action)), Err(ProofError::CommitmentMismatch));
    }

    /// A transaction's compact records (what a pruned node still serves) prove recipient
    /// and amount for the right action index, and nothing for a wrong one.
    #[test]
    fn compact_records_prove_recipient_and_amount() {
        let (action, d) = encrypted_output(b"");
        let record = |a: &ActionWire| {
            let mut r = Vec::with_capacity(COMPACT_RECORD_LEN);
            r.extend_from_slice(&a.nullifier);
            r.extend_from_slice(&a.cmx);
            r.extend_from_slice(&a.ephemeral_key);
            r.extend_from_slice(&a.enc_ciphertext[..52]);
            r
        };
        let (other, _) = encrypted_output(b"x");
        let mut other = other;
        other.cmx = [7u8; 32];
        let mut records = record(&other);
        records.extend(record(&action));

        let mut at1 = d.clone();
        at1.action_index = 1;
        assert_eq!(verify_compact(&at1, &records), Ok(()));
        assert_eq!(verify_compact(&d, &records), Err(ProofError::CommitmentMismatch), "index 0 is another output");
        let mut at2 = d.clone();
        at2.action_index = 2;
        assert_eq!(verify_compact(&at2, &records), Err(ProofError::NoSuchAction));
        assert_eq!(verify_compact(&at1, &records[..200]), Err(ProofError::NoSuchAction), "a torn record list is refused");
        let mut wrong = at1.clone();
        wrong.value -= 1;
        assert_eq!(verify_compact(&wrong, &records), Err(ProofError::CommitmentMismatch));
    }
}
