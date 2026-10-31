//! Coinbase note issuance — the one transparent seam (PLAN §2.7).
//!
//! Mining rewards are created from nothing, so a coinbase note has no input note
//! to prove. Instead it is a note commitment with a **publicly stated value** —
//! the block subsidy, which consensus checks against the emission schedule. The
//! coinbase transaction states the note's recipient and randomness publicly, so
//! consensus can **deterministically recompute** the note commitment and add it
//! to the global tree. After the miner spends it once (with a normal Orchard
//! proof) it is indistinguishable from any other note.
//!
//! ## Why this is sound
//!
//! For a *private* output, the value is hidden and is bound to the bundle by the
//! binding signature. A coinbase note is different: its value is **public**, and
//! consensus recomputes the commitment from `(recipient, value, ρ, rseed)`. The
//! commitment is a binding commitment to the value, so a miner cannot have the
//! recorded commitment open to anything other than the stated subsidy — there is
//! no freedom to mint extra value into the note. The subsidy enters the turnstile
//! accounting exactly once, as `cumulative_coinbase += subsidy` (§2.6).
//!
//! `ρ` (rho) must be unique per coinbase note so that the note's eventual
//! nullifier is unique; consensus derives it deterministically from the coinbase
//! transaction (e.g. its id), which this module treats as an opaque input.

use group::ff::{FromUniformBytes, PrimeField};
use orchard::{
    Address,
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    value::NoteValue,
};
use pasta_curves::pallas;

use crate::state::{CoinbaseMint, CoinbaseNote};

/// Whether `script` is a canonical Orchard payout address: exactly 43 bytes that
/// decode to a valid Orchard [`Address`].
///
/// On a shielded-coinbase network every block's declared coinbase payout MUST
/// satisfy this. Consensus validates it at **body acceptance** (before the block
/// enters the DAG), because otherwise a block declaring a non-address payout would
/// be accepted, and any *later* block that merges it — and must pay it — could not
/// mint the reward note ([`coinbase_note`] would fail on a non-canonical
/// recipient), which under the accepted-order model would stall every merger of
/// that block. Rejecting the bad block up front (its own data) removes the hazard
/// at the source. Requiring exactly 43 bytes also removes any ambiguity about
/// trailing bytes after the address.
pub fn is_canonical_orchard_payout(script: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 43]>::try_from(script) else {
        return false;
    };
    Option::<Address>::from(Address::from_raw_address_bytes(&bytes)).is_some()
}

/// Deterministically derive a **canonical** coinbase note description for
/// `recipient` from a unique `seed` (e.g. the coinbase transaction id followed by
/// the reward's index). Consensus and the recipient's wallet both run this to get
/// the *identical* note, so the note — and its future nullifier — is fixed by
/// public data and the miner has no freedom to alter it (the value is bound
/// separately by [`coinbase_note_commitment`]).
///
/// `rho` is reduced into the Pallas base field, so it is always a canonical `Rho`;
/// `rseed` is derived with a domain counter until it yields a valid ZIP-212 seed
/// for that `rho` (the first candidate succeeds with overwhelming probability).
pub fn derive_coinbase_note_desc(recipient: [u8; 43], seed: &[u8]) -> CoinbaseNoteDesc {
    // rho: hash to 64 bytes and reduce into the field for a guaranteed-canonical value.
    let mut h = blake2b_simd::Params::new().hash_length(64).personal(b"zkas_cb_rho_0000").to_state();
    h.update(seed);
    let rho_field = pallas::Base::from_uniform_bytes(h.finalize().as_array());
    let rho_bytes = rho_field.to_repr();
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).expect("reduced field element is a canonical rho");

    // rseed: derive with a counter until it is a valid ZIP-212 seed for this rho.
    let mut ctr: u32 = 0;
    let rseed = loop {
        let mut hr = blake2b_simd::Params::new().hash_length(32).personal(b"zkas_cb_seed0000").to_state();
        hr.update(seed);
        hr.update(&ctr.to_le_bytes());
        let cand: [u8; 32] = hr.finalize().as_bytes().try_into().expect("32-byte digest");
        if bool::from(RandomSeed::from_bytes(cand, &rho).is_some()) {
            break cand;
        }
        ctr += 1;
    };
    CoinbaseNoteDesc { recipient, rho: rho_bytes, rseed }
}

/// The public description of a coinbase note: everything besides the public value
/// (the subsidy) needed to recompute its commitment. Carried by the coinbase
/// transaction; consensus supplies the subsidy from the emission schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseNoteDesc {
    /// Raw Orchard address of the reward recipient (the miner).
    pub recipient: [u8; 43],
    /// The note's `ρ`, derived deterministically from the coinbase transaction so
    /// that the resulting note (and its future nullifier) is unique.
    pub rho: [u8; 32],
    /// The note's random seed.
    pub rseed: [u8; 32],
}

/// Why a coinbase note description could not be turned into a commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinbaseNoteError {
    /// `recipient` is not a canonical Orchard address.
    BadRecipient,
    /// `rho` is not a canonical encoding.
    BadRho,
    /// `rseed` is not valid for this `rho`.
    BadRseed,
    /// The resulting note has no valid commitment.
    BadNote,
}

/// Recompute the coinbase note's extracted commitment from its public description
/// and public `value` (the rewarded block's subsidy + fees). Consensus uses this
/// to derive the global-tree leaf and to bind the commitment to the emission- and
/// fee-checked value.
pub fn coinbase_note_commitment(desc: &CoinbaseNoteDesc, value: u64) -> Result<ExtractedNoteCommitment, CoinbaseNoteError> {
    let recipient: Address = Option::from(Address::from_raw_address_bytes(&desc.recipient)).ok_or(CoinbaseNoteError::BadRecipient)?;
    let rho: Rho = Option::from(Rho::from_bytes(&desc.rho)).ok_or(CoinbaseNoteError::BadRho)?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(desc.rseed, &rho)).ok_or(CoinbaseNoteError::BadRseed)?;
    // One NoteCommit, not two: `from_parts` must derive the commitment to validate the
    // note, and `from_parts_with_commitment` hands that same value back instead of
    // discarding it and recomputing it via `note.commitment()`. Same `None` cases.
    let (_note, cm) =
        Note::from_parts_with_commitment(recipient, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2)
            .ok_or(CoinbaseNoteError::BadNote)?;
    Ok(ExtractedNoteCommitment::from(cm))
}

/// [`coinbase_note_commitment`], several times faster, for WALLETS. The same commitment on
/// every input (see `Note::from_parts_with_commitment_vartime`) and the same errors, but
/// not constant time — fine, because a coinbase note's description and value are public.
///
/// Wallet decode only. Consensus keeps [`coinbase_note_commitment`]: the fast path's
/// hash evaluator differs from the reference only on an input exhibiting a discrete-log
/// relation, and a node must not depend on even that argument for what it accepts.
pub fn coinbase_note_commitment_vartime(desc: &CoinbaseNoteDesc, value: u64) -> Result<ExtractedNoteCommitment, CoinbaseNoteError> {
    let recipient = cached_recipient(&desc.recipient)?;
    let rho: Rho = Option::from(Rho::from_bytes(&desc.rho)).ok_or(CoinbaseNoteError::BadRho)?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(desc.rseed, &rho)).ok_or(CoinbaseNoteError::BadRseed)?;
    let (_note, cm) =
        Note::from_parts_with_commitment_vartime(recipient, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2)
            .ok_or(CoinbaseNoteError::BadNote)?;
    Ok(ExtractedNoteCommitment::from(cm))
}

/// Parsing a raw address decompresses `pk_d` and checks `g_d`; a chain's coinbase pays a
/// few hundred recipients over and over, so do it once per recipient per thread.
fn cached_recipient(raw: &[u8; 43]) -> Result<Address, CoinbaseNoteError> {
    use std::{cell::RefCell, collections::HashMap};
    thread_local! {
        static RECIPIENTS: RefCell<HashMap<[u8; 43], Option<Address>>> = RefCell::new(HashMap::new());
    }
    RECIPIENTS.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(hit) = cache.get(raw) {
            return hit.ok_or(CoinbaseNoteError::BadRecipient);
        }
        if cache.len() >= 4096 {
            cache.clear();
        }
        let parsed: Option<Address> = Option::from(Address::from_raw_address_bytes(raw));
        cache.insert(*raw, parsed);
        parsed.ok_or(CoinbaseNoteError::BadRecipient)
    })
}

/// Build a single [`CoinbaseNote`] (value + commitment) from its public
/// description and the emission- and fee-checked value.
pub fn coinbase_note(desc: &CoinbaseNoteDesc, value: u64) -> Result<CoinbaseNote, CoinbaseNoteError> {
    Ok(CoinbaseNote { value, commitment: coinbase_note_commitment(desc, value)? })
}

/// Build the [`CoinbaseMint`] for the shielded state transition from a coinbase
/// transaction's `(description, value)` pairs — one per rewarded mergeset block.
pub fn coinbase_mint(notes: &[(CoinbaseNoteDesc, u64)]) -> Result<CoinbaseMint, CoinbaseNoteError> {
    let notes = notes.iter().map(|(desc, value)| coinbase_note(desc, *value)).collect::<Result<Vec<_>, _>>()?;
    Ok(CoinbaseMint::new(notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wallet fast path is the consensus derivation, byte for byte, on many notes — real
    /// recipients from many keys and diversifiers, many seeds and values — and fails the same
    /// way on every malformed field.
    #[test]
    fn vartime_commitment_is_the_reference_commitment() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        let mut checked = 0usize;
        for k in 0u8..12 {
            let mut skb = [0u8; 32];
            skb[0] = k.wrapping_mul(37).wrapping_add(1);
            skb[31] = k;
            let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(skb)) else { continue };
            let fvk = FullViewingKey::from(&sk);
            for j in 0u32..8 {
                let recipient = fvk.address_at(j * 7919 + u32::from(k), Scope::External).to_raw_address_bytes();
                for s in 0u32..12 {
                    let mut seed = [0u8; 64];
                    seed[..4].copy_from_slice(&s.to_le_bytes());
                    seed[4] = k;
                    seed[5..9].copy_from_slice(&j.to_le_bytes());
                    let desc = derive_coinbase_note_desc(recipient, &seed);
                    let value = (u64::from(s) * 1_234_567_891).wrapping_add(u64::from(j) << 40) % 21_000_000_0000_0000;
                    let reference = coinbase_note_commitment(&desc, value).map(|c| c.to_bytes());
                    let fast = coinbase_note_commitment_vartime(&desc, value).map(|c| c.to_bytes());
                    assert_eq!(fast, reference, "key {k} addr {j} seed {s} value {value}");
                    checked += 1;
                }
            }
        }
        assert!(checked >= 1000, "{checked}");
        // Same value twice (cache hit) and the extremes of the value range.
        let recipient = FullViewingKey::from(&SpendingKey::from_bytes([3u8; 32]).unwrap()).address_at(0u32, Scope::External).to_raw_address_bytes();
        let desc = derive_coinbase_note_desc(recipient, &[9u8; 64]);
        for value in [0u64, 1, u64::MAX >> 1, 2_100_000_000_000_000] {
            for _ in 0..2 {
                assert_eq!(
                    coinbase_note_commitment_vartime(&desc, value).map(|c| c.to_bytes()),
                    coinbase_note_commitment(&desc, value).map(|c| c.to_bytes())
                );
            }
        }
        // Malformed fields fail identically.
        let mut bad = desc.clone();
        bad.recipient = [0xff; 43];
        assert_eq!(coinbase_note_commitment_vartime(&bad, 1).err(), coinbase_note_commitment(&bad, 1).err());
        let mut bad = desc.clone();
        bad.rho = [0xff; 32];
        assert_eq!(coinbase_note_commitment_vartime(&bad, 1).err(), coinbase_note_commitment(&bad, 1).err());
    }
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    fn canon32(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = seed;
        b
    }

    fn test_recipient() -> Address {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).expect("valid sk");
        FullViewingKey::from(&sk).address_at(0u32, Scope::External)
    }

    /// Our consensus-side recomputation yields exactly the commitment Orchard's
    /// own `Note::commitment` produces — so a node and the miner agree on the leaf.
    #[test]
    fn matches_orchard_note_commitment() {
        let recipient = test_recipient();
        let rho: Rho = Option::from(Rho::from_bytes(&canon32(1))).unwrap();
        let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(canon32(2), &rho)).unwrap();
        let subsidy = 5_000_000_000u64;

        let note: Note = Option::from(Note::from_parts(recipient, NoteValue::from_raw(subsidy), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
        let expected = ExtractedNoteCommitment::from(note.commitment());

        let desc = CoinbaseNoteDesc { recipient: recipient.to_raw_address_bytes(), rho: canon32(1), rseed: canon32(2) };
        let got = coinbase_note_commitment(&desc, subsidy).unwrap();
        assert_eq!(got.to_bytes(), expected.to_bytes());
    }

    /// The commitment is deterministic and **binds the public value**: changing
    /// the subsidy changes the commitment, so a miner cannot claim a value other
    /// than the one consensus checked against emission.
    #[test]
    fn deterministic_and_binds_value() {
        let desc = CoinbaseNoteDesc { recipient: test_recipient().to_raw_address_bytes(), rho: canon32(1), rseed: canon32(2) };
        let a = coinbase_note_commitment(&desc, 100).unwrap();
        let b = coinbase_note_commitment(&desc, 100).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes(), "deterministic");
        let c = coinbase_note_commitment(&desc, 101).unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes(), "commitment binds the public value");
    }

    /// The deterministic derivation yields a canonical, spendable note that every
    /// node recomputes identically, and different seeds give different notes.
    #[test]
    fn derived_coinbase_note_is_canonical_spendable_and_deterministic() {
        let recipient = test_recipient();
        let raw = recipient.to_raw_address_bytes();
        let value = 5_000_000_000u64;

        let desc = derive_coinbase_note_desc(raw, b"coinbase-txid||0");
        // Deterministic: same recipient + seed -> same description on every node.
        assert_eq!(derive_coinbase_note_desc(raw, b"coinbase-txid||0"), desc);
        // A different reward index (seed) gives a different note.
        assert_ne!(derive_coinbase_note_desc(raw, b"coinbase-txid||1"), desc);

        // The derived (rho, rseed) reconstruct a valid, spendable Orchard note...
        let rho: Rho = Option::from(Rho::from_bytes(&desc.rho)).unwrap();
        let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(desc.rseed, &rho)).unwrap();
        let note: Note = Option::from(Note::from_parts(recipient, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
        // ...whose commitment equals the consensus recompute of the same desc+value.
        assert_eq!(
            coinbase_note_commitment(&desc, value).unwrap().to_bytes(),
            ExtractedNoteCommitment::from(note.commitment()).to_bytes()
        );
    }

    #[test]
    fn rejects_bad_recipient() {
        let desc = CoinbaseNoteDesc { recipient: [0xff; 43], rho: canon32(1), rseed: canon32(2) };
        assert!(matches!(coinbase_note_commitment(&desc, 100), Err(CoinbaseNoteError::BadRecipient)));
    }

    /// `coinbase_note_commitment` now takes the commitment `from_parts` computed while
    /// validating (one NoteCommit) instead of computing it a second time. Pin that this is
    /// value-identical to the old two-step derivation (`from_parts`, then
    /// `note.commitment()`) over many real-shaped descriptions, and that both refuse the
    /// same inputs. A leaf that differed here would fork every wallet's tree.
    #[test]
    fn commitment_once_equals_from_parts_then_commitment() {
        let recipient = test_recipient().to_raw_address_bytes();
        let mut checked = 0;
        for i in 0u32..512 {
            let mut seed = b"coinbase-txid-for-the-differential||".to_vec();
            seed.extend_from_slice(&i.to_le_bytes());
            let desc = derive_coinbase_note_desc(recipient, &seed);
            let value = 1u64 + (i as u64) * 7_919_000_003;
            let old: Option<ExtractedNoteCommitment> = (|| {
                let addr: Address = Option::from(Address::from_raw_address_bytes(&desc.recipient))?;
                let rho: Rho = Option::from(Rho::from_bytes(&desc.rho))?;
                let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(desc.rseed, &rho))?;
                let note: Note =
                    Option::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2))?;
                Some(ExtractedNoteCommitment::from(note.commitment()))
            })();
            let new = coinbase_note_commitment(&desc, value).ok();
            assert_eq!(old.map(|c| c.to_bytes()), new.map(|c| c.to_bytes()), "seed {i}");
            if new.is_some() {
                checked += 1;
            }
        }
        assert!(checked > 500, "the sweep must exercise the success path, not only refusals ({checked})");
        // A recipient that is not an address is refused before any commitment.
        let bad = CoinbaseNoteDesc { recipient: [0xff; 43], rho: canon32(1), rseed: canon32(2) };
        assert!(coinbase_note_commitment(&bad, 1).is_err());
    }

    /// A coinbase note feeds the state transition as a mint of exactly its public
    /// value (subsidy + fees); multiple rewarded blocks become multiple notes.
    #[test]
    fn coinbase_mint_carries_note_values() {
        let d1 = CoinbaseNoteDesc { recipient: test_recipient().to_raw_address_bytes(), rho: canon32(3), rseed: canon32(4) };
        let d2 = CoinbaseNoteDesc { recipient: test_recipient().to_raw_address_bytes(), rho: canon32(5), rseed: canon32(6) };
        let mint = coinbase_mint(&[(d1, 12_345), (d2, 678)]).unwrap();
        assert_eq!(mint.notes.len(), 2);
        assert_eq!(mint.notes[0].value, 12_345);
        assert_eq!(mint.notes[1].value, 678);
        assert_eq!(mint.total_value(), 13_023);
    }
}
