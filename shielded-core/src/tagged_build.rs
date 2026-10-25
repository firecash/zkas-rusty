//! Building tagged-channel bundles (fork topic 01 §A, devnet prototype).
//!
//! Orchard's builder draws every output's `rseed` from its RNG. A tagged output needs
//! `rseed = H(K ‖ ctr)` so that the receiver can rebuild the note from the channel alone. This
//! module therefore builds through Orchard's own PCZT roles (Creator → IO finalizer → Prover →
//! Signer → Extractor, the flow spec 01 S-R6 adopts), and between Creator and Prover it replaces
//! each output's `rseed` (and so its `cmx`) with the channel-derived one, the `epk` with the
//! channel's `kem`, and blanks the two Orchard ciphertexts (they are not on the tagged wire). No
//! Orchard code is patched: every step uses a public PCZT entry point, and the prover proves the
//! rewritten output note like any other (`Circuit::from_action_context`).

use std::collections::BTreeMap;

use group::ff::PrimeField;
use orchard::{
    Address, Anchor,
    builder::{Builder, BundleType},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    pczt,
    tree::MerklePath,
    value::NoteValue,
};
use rand_core::{CryptoRng, Rng};

use crate::bundle::{ActionWire, ShieldedBundle, TAGGED_FLAGS, TaggedFields, sizes};
use crate::channel::{ChannelOutput, Kind, PT_LEN, Plaintext};
use crate::wallet::build::{BuildError, proving_key};

fn err(e: impl std::fmt::Debug) -> BuildError {
    BuildError::Builder(format!("{e:?}"))
}

/// Re-parse a PCZT spend from its getters (pczt types are not `Clone`).
fn reparse_spend(s: &pczt::Spend) -> Result<pczt::Spend, BuildError> {
    if s.zip32_derivation().is_some() {
        return Err(BuildError::Builder("tagged build: unexpected zip32 derivation on a spend".into()));
    }
    let witness = s.witness().as_ref().map(|w| (w.position(), w.auth_path().map(|h| h.to_bytes())));
    pczt::Spend::parse(
        s.nullifier().to_bytes(),
        <[u8; 32]>::from(s.rk()),
        s.spend_auth_sig().as_ref().map(|sig| <[u8; 64]>::from(sig)),
        s.recipient().map(|a| a.to_raw_address_bytes()),
        s.value().map(|v| v.inner()),
        s.rho().map(|r| r.to_bytes()),
        s.rseed().map(|r| *r.as_bytes()),
        s.fvk().as_ref().map(|f| f.to_bytes()),
        witness,
        s.alpha().map(|a| a.to_repr()),
        None,
        s.dummy_sk().as_ref().map(|sk| *sk.to_bytes()),
        *s.note_version(),
        s.proprietary().clone(),
    )
    .map_err(err)
}

/// One output after the rewrite: what goes on the wire for it.
struct Delivery {
    kem: [u8; 32],
    fields: TaggedFields,
}

/// Build, prove and sign a tagged-channel bundle that spends `inputs` and creates `outputs`
/// (payments and change, each on its channel), leaving `fee` as the value balance. Padding
/// actions get random tags, random kem points and random ciphertexts, so they look like every
/// other output. `anchor_block` names the block whose tree root the witnesses were taken at.
#[allow(clippy::too_many_arguments)]
pub fn build_tagged_bundle(
    owner_sk: [u8; 32],
    inputs: Vec<(Note, MerklePath)>,
    outputs: &[ChannelOutput],
    fee: u64,
    anchor_block: [u8; 32],
    network_domain: &[u8; 32],
    tx_context: &[u8],
    mut rng: impl Rng + CryptoRng,
) -> Result<ShieldedBundle, BuildError> {
    let (first_note, first_path) = inputs.first().ok_or(BuildError::Empty)?;
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(owner_sk)).ok_or(BuildError::Empty)?;
    let fvk = FullViewingKey::from(&sk);
    let total_in: u64 = inputs.iter().map(|(n, _)| n.value().inner()).sum();
    let total_out = outputs.iter().try_fold(0u64, |a, o| a.checked_add(o.value)).ok_or(BuildError::Empty)?;
    if total_out.checked_add(fee) != Some(total_in) {
        return Err(BuildError::Builder(format!("tagged build: inputs {total_in} != outputs {total_out} + fee {fee}")));
    }
    let anchor: Anchor = first_path.root(ExtractedNoteCommitment::from(first_note.commitment()));
    let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor)
        .map_err(err)?;
    for (note, path) in inputs {
        builder.add_spend(fvk.clone(), note, path).map_err(err)?;
    }
    for o in outputs {
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&o.address)).ok_or(BuildError::Empty)?;
        builder.add_output(None, addr, NoteValue::from_raw(o.value), [0u8; 512]).map_err(err)?;
    }
    let (mut bundle, meta) = builder.build_for_pczt(&mut rng).map_err(err)?;
    let n = bundle.actions().len();
    let mut ours: Vec<Option<&ChannelOutput>> = vec![None; n];
    for (i, o) in outputs.iter().enumerate() {
        ours[meta.output_action_index(i).ok_or(BuildError::Empty)?] = Some(o);
    }

    // Rewrite every output: channel outputs get the derived rseed (hence a new cmx) and their kem;
    // padding outputs keep their note and get random delivery fields.
    let mut deliveries = Vec::with_capacity(n);
    let mut rebuilt = Vec::with_capacity(n);
    for (j, a) in bundle.actions().iter().enumerate() {
        let nf = *a.spend().nullifier();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let (recipient, value, rseed_bytes, delivery) = match ours[j] {
            Some(o) => {
                let rs = crate::channel::rseed(&o.k, o.ctr);
                (o.address, o.value, rs, Delivery { kem: o.kem, fields: TaggedFields { tag: o.tag, ct: o.ciphertext() } })
            }
            None => {
                let out = a.output();
                let recipient = out.recipient().ok_or(BuildError::Empty)?.to_raw_address_bytes();
                let value = out.value().ok_or(BuildError::Empty)?.inner();
                let rs = *out.rseed().as_ref().ok_or(BuildError::Empty)?.as_bytes();
                let mut tag = [0u8; 16];
                let mut ct = [0u8; 64];
                rng.fill_bytes(&mut tag);
                rng.fill_bytes(&mut ct);
                (recipient, value, rs, Delivery { kem: crate::channel::random_kem(&mut rng), fields: TaggedFields { tag, ct } })
            }
        };
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&recipient)).ok_or(BuildError::Empty)?;
        let rs = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho))
            .ok_or_else(|| BuildError::Builder("channel rseed is invalid for this rho (p ~ 2^-250)".into()))?;
        let note = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rs, NoteVersion::V2))
            .ok_or_else(|| BuildError::Builder("channel note has no commitment".into()))?;
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        let output = pczt::Output::parse(
            nf,
            cmx,
            delivery.kem,
            vec![0u8; sizes::ENC_CIPHERTEXT],
            vec![0u8; sizes::OUT_CIPHERTEXT],
            Some(recipient),
            Some(value),
            Some(rseed_bytes),
            None,
            None,
            None,
            NoteVersion::V2,
            BTreeMap::new(),
        )
        .map_err(err)?;
        let action = pczt::Action::parse(a.cv_net().to_bytes(), reparse_spend(a.spend())?, output, a.rcv().as_ref().map(|r| r.to_bytes()))
            .map_err(err)?;
        rebuilt.push(action);
        deliveries.push(delivery);
    }
    let (mag, sign) = bundle.value_sum().magnitude_sign();
    bundle = pczt::Bundle::parse(
        rebuilt,
        bundle.flag_byte(),
        *bundle.bundle_version(),
        (mag, matches!(sign, orchard::value::Sign::Negative)),
        bundle.anchor().to_bytes(),
        None,
        None,
    )
    .map_err(err)?;

    // The effects (signatures and proof excluded) and their sighash.
    let effects_of = |b: &pczt::Bundle| -> ShieldedBundle {
        let actions = b
            .actions()
            .iter()
            .zip(&deliveries)
            .map(|(a, d)| ActionWire {
                nullifier: a.spend().nullifier().to_bytes(),
                rk: <[u8; 32]>::from(a.spend().rk()),
                cmx: a.output().cmx().to_bytes(),
                cv_net: a.cv_net().to_bytes(),
                ephemeral_key: d.kem,
                enc_ciphertext: [0u8; sizes::ENC_CIPHERTEXT],
                out_ciphertext: [0u8; sizes::OUT_CIPHERTEXT],
                spend_auth_sig: [0u8; 64],
            })
            .collect();
        ShieldedBundle {
            actions,
            flags: TAGGED_FLAGS,
            value_balance: fee as i64,
            anchor: b.anchor().to_bytes(),
            proof: Vec::new(),
            binding_sig: [0u8; 64],
            burn: None,
            anchor_block: Some(anchor_block),
            tagged: Some(deliveries.iter().map(|d| d.fields).collect()),
        }
    };
    let mut wire = effects_of(&bundle);
    let sighash = crate::verify::sighash(&wire, network_domain, tx_context);

    bundle.create_proof(proving_key(), &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;
    bundle.finalize_io(sighash, &mut rng).map_err(err)?;
    let ask = SpendAuthorizingKey::from(&sk);
    for a in bundle.actions_mut() {
        if a.spend().spend_auth_sig().is_none() {
            a.sign(sighash, &ask, &mut rng).map_err(err)?;
        }
    }
    let unbound = bundle.extract::<i64>().map_err(err)?.ok_or(BuildError::Empty)?;
    let authorized = unbound
        .apply_binding_signature(sighash, &mut rng)
        .ok_or_else(|| BuildError::Proof("binding signature did not apply".into()))?;
    for (w, a) in wire.actions.iter_mut().zip(authorized.actions().iter()) {
        debug_assert_eq!(w.cmx, a.cmx().to_bytes());
        w.spend_auth_sig = <[u8; 64]>::from(a.authorization());
    }
    wire.proof = authorized.authorization().proof().as_ref().to_vec();
    wire.binding_sig = <[u8; 64]>::from(authorized.authorization().binding_signature());
    Ok(wire)
}

/// The coinbase note `owner` received as output `out_index` of `coinbase_txid`, when it is the
/// single leaf (position 0) of the tree, with its single-leaf witness. Mirrors
/// `wallet::build::build_singleleaf_coinbase_spend` (devnet tests spend a block reward).
pub fn singleleaf_coinbase_note(owner_sk: [u8; 32], coinbase_txid: [u8; 32], out_index: u32, value: u64) -> Option<(Note, MerklePath)> {
    use incrementalmerkletree::{Hashable, Level};
    use orchard::tree::MerkleHashOrchard;
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(owner_sk))?;
    let addr = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
    let mut seed = Vec::with_capacity(36);
    seed.extend_from_slice(&coinbase_txid);
    seed.extend_from_slice(&out_index.to_le_bytes());
    let desc = crate::coinbase::derive_coinbase_note_desc(addr.to_raw_address_bytes(), &seed);
    let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho))?;
    let rs = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho))?;
    let note = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rs, NoteVersion::V2))?;
    let auth: [MerkleHashOrchard; 32] = core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
    Some((note, MerklePath::from_parts(0, auth)))
}

/// The wallet's own address for its self channel: internal scope, index 0.
pub fn self_address(owner_sk: &[u8; 32]) -> Option<[u8; 43]> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(*owner_sk))?;
    Some(FullViewingKey::from(&sk).address_at(0u32, Scope::Internal).to_raw_address_bytes())
}

/// The address a payment request `i` pays to: external scope, index `REQ_BASE + i`.
pub fn request_address(owner_sk: &[u8; 32], i: u32) -> Option<[u8; 43]> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(*owner_sk))?;
    Some(FullViewingKey::from(&sk).address_at(crate::channel::REQ_BASE + i, Scope::External).to_raw_address_bytes())
}

/// Plaintext of a padding output, for completeness (nobody decrypts one).
pub fn dummy_plaintext() -> Plaintext {
    Plaintext { value: 0, kind: Kind::Dummy, aux: [0u8; PT_LEN - 9] }
}

/// End-to-end with a real Halo 2 proof: a tagged payment to a request channel plus change on the
/// self channel verifies under the unchanged verifying key, round-trips the wire at the claimed
/// size, and is found by both wallets by lookup alone.
#[cfg(test)]
mod e2e {
    use super::*;
    use crate::bundle::expected_tagged_wire_len;
    use crate::tagged_wallet::{ColumnBlock, OutputRecord, TaggedWallet, pay_request};
    use crate::verify::{BundleVerifyError, sighash, verify_bundle, verify_bundles_batched};
    use incrementalmerkletree::{Hashable, Level};
    use orchard::tree::MerkleHashOrchard;

    fn sk(b: u8) -> [u8; 32] {
        let mut s = [b; 32];
        while Option::<SpendingKey>::from(SpendingKey::from_bytes(s)).is_none() {
            s[0] = s[0].wrapping_add(1);
        }
        s
    }

    /// A spendable single-leaf note of `value` for `owner` (leaf 0 of an otherwise empty tree).
    fn leaf_note(owner: &[u8; 32], value: u64) -> (Note, MerklePath) {
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes(*owner).unwrap());
        let mut c = [0u8; 32];
        c[0] = 1;
        let rho = Rho::from_bytes(&c).unwrap();
        c[0] = 2;
        let rs = RandomSeed::from_bytes(c, &rho).unwrap();
        let note = Note::from_parts(fvk.address_at(0u32, Scope::External), NoteValue::from_raw(value), rho, rs, NoteVersion::V2).unwrap();
        let auth: [MerkleHashOrchard; 32] = core::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8)));
        (note, MerklePath::from_parts(0, auth))
    }

    #[test]
    fn tagged_payment_proves_verifies_and_is_found_by_lookup() {
        let mut rng = rand::rng();
        let (alice_sk, bob_sk) = (sk(21), sk(22));
        let mut alice = TaggedWallet::new(alice_sk, 3).unwrap();
        let mut bob = TaggedWallet::new(bob_sk, 3).unwrap();
        let req = bob.issue_request(7_000);
        let (note, path) = leaf_note(&alice_sk, 10_000);
        let pay = pay_request(&req, 7_000, 0, &mut rng);
        let change = alice.change_output(2_000, &[], 3, &mut rng);
        let (net, ctx) = ([0x42u8; 32], b"tagged-e2e".as_slice());
        let wire = build_tagged_bundle(alice_sk, vec![(note, path)], &[pay, change], 1_000, [0x5a; 32], &net, ctx, &mut rng)
            .expect("tagged bundle builds and proves");

        // The circuit is untouched: the chain's verifying key verifies it.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("a tagged bundle verifies under the unchanged VK");
        verify_bundles_batched(&[(&wire, msg), (&wire, msg)], rand::rng()).expect("and in a batch");
        let bytes = wire.to_bytes();
        assert_eq!(bytes.len(), expected_tagged_wire_len(2), "2 actions = 8,014 bytes");
        let back = ShieldedBundle::from_bytes_with(&bytes, true, true).unwrap();
        assert_eq!(back, wire);

        // The ciphertexts are not circuit inputs (verify.rs Instance::from_parts): rewriting the
        // kem, the tag or the ciphertext of an action leaves the PROOF valid; only the signatures
        // (which sign the tagged sighash) catch it.
        for which in 0..3 {
            let mut bad = wire.clone();
            match which {
                0 => bad.actions[0].ephemeral_key = crate::channel::random_kem(&mut rng),
                1 => bad.tagged.as_mut().unwrap()[0].tag[0] ^= 1,
                _ => bad.tagged.as_mut().unwrap()[1].ct[5] ^= 1,
            }
            let m = sighash(&bad, &net, ctx);
            assert_eq!(verify_bundle(&bad, &m), Err(BundleVerifyError::BindingSigInvalid), "field {which}: proof ok, signatures refuse");
        }
        // And the original signatures over the original digest refuse the rewritten bundle too.
        let mut bad = wire.clone();
        bad.tagged.as_mut().unwrap()[0].tag[0] ^= 1;
        assert!(verify_bundle(&bad, &sighash(&bad, &net, ctx)).is_err());

        // Both receivers find their output by tag, with the cmx self-check, no key agreement.
        let tags: Vec<[u8; 16]> = wire.tagged.as_ref().unwrap().iter().map(|t| t.tag).collect();
        let records: Vec<OutputRecord> = wire
            .actions
            .iter()
            .zip(wire.tagged.as_ref().unwrap())
            .map(|(a, t)| OutputRecord::from_compact(&crate::wallet::scan::CompactActionRecord::from_tagged(a, t).to_bytes()).unwrap())
            .collect();
        let blk = ColumnBlock { hash: [1; 32], txs: vec![crate::tag_log::TaggedTxColumn { first_leaf: 1, tags }] };
        bob.scan_block(&blk, |p| records.get((p - 1) as usize).copied());
        alice.scan_block(&blk, |p| records.get((p - 1) as usize).copied());
        assert_eq!(bob.found.len(), 1);
        assert_eq!(bob.found[0].value(), 7_000);
        assert_eq!(alice.found.len(), 1);
        assert_eq!(alice.found[0].value(), 2_000);
        let ledger = crate::channel::RecoveryLedger::from_aux(&alice.found[0].aux).expect("the change carries the ledger");
        assert_eq!((ledger.lwm_self, ledger.n_unspent, ledger.epoch), (0, 1, 3));
        assert_eq!(bob.stats.open_lane_trials + alice.stats.open_lane_trials, 0);
        // The found note is the on-chain one: its commitment is the action's cmx.
        let cmx_bob = ExtractedNoteCommitment::from(bob.found[0].note.commitment()).to_bytes();
        assert!(wire.actions.iter().any(|a| a.cmx == cmx_bob));
    }

    /// A static-address payment in a tagged bundle (open lane) proves and is found by the fallback.
    #[test]
    fn open_lane_payment_in_a_real_bundle() {
        let mut rng = rand::rng();
        let (alice_sk, carol_sk) = (sk(23), sk(24));
        let mut carol = TaggedWallet::new(carol_sk, 2).unwrap();
        let mut alice = TaggedWallet::new(alice_sk, 2).unwrap();
        let (note, path) = leaf_note(&alice_sk, 5_000);
        let pay = ChannelOutput::open_lane(carol.static_address(), 4_000, &mut rng).unwrap();
        let change = alice.change_output(500, &[], 0, &mut rng);
        let (net, ctx) = ([7u8; 32], b"open".as_slice());
        let wire = build_tagged_bundle(alice_sk, vec![(note, path)], &[pay, change], 500, [1; 32], &net, ctx, &mut rng).unwrap();
        verify_bundle(&wire, &sighash(&wire, &net, ctx)).unwrap();
        let recs: Vec<OutputRecord> = wire
            .actions
            .iter()
            .zip(wire.tagged.as_ref().unwrap())
            .map(|(a, t)| OutputRecord::from_compact(&crate::wallet::scan::CompactActionRecord::from_tagged(a, t).to_bytes()).unwrap())
            .collect();
        let triples: Vec<_> =
            recs.iter().zip(wire.tagged.as_ref().unwrap()).enumerate().map(|(i, (r, t))| (i as u64, t.tag, r.kem)).collect();
        carol.scan_open_lane(&triples, |p| recs.get(p as usize).copied());
        assert_eq!(carol.found.len(), 1);
        assert_eq!(carol.found[0].value(), 4_000);
    }
}
