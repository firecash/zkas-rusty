//! Cryptographic verification of a shielded bundle — the audit-critical layer
//! (PLAN §2.1, §3; non-negotiable #4 in §5).
//!
//! A bundle is *sound* iff three independent checks pass. Together they are what
//! make the private value layer trustworthy: no value is created, every spent
//! note really exists and is authorized, and nothing can be replayed.
//!
//! 1. **Balance (no inflation).** The binding signature verifies under the
//!    *binding validating key*
//!    ```text
//!    bvk = ( Σ_actions cv_net )  −  ValueCommit(value_balance, 0)
//!    ```
//!    Value commitments are Pedersen commitments `cv = [v]·V + [rcv]·R`, additively
//!    homomorphic in both the value `v` and the trapdoor `rcv`. So
//!    `Σ cv_net = [Σv]·V + [Σrcv]·R`, and subtracting `ValueCommit(value_balance,0)
//!    = [value_balance]·V` leaves `[Σv − value_balance]·V + [Σrcv]·R`. The binding
//!    signature is a Schnorr signature whose public key is `bvk` and whose secret
//!    key the prover only knows when the `V` component vanishes, i.e. when
//!    `Σ v_net = value_balance`. A valid binding signature therefore *proves the
//!    bundle balances* — the homomorphic anti-inflation guarantee (§2.6).
//!
//! 2. **Membership + authority + nullifier integrity (the Halo 2 proof).** For
//!    each action the action circuit proves, in zero knowledge, that: the spent
//!    note's commitment is in the note-commitment tree with root `anchor`; the
//!    spender knows the spend authority (`rk = ak + [α]·G`); the value commitment
//!    `cv_net` opens to `v_old − v_new`; the new commitment `cmx` is well formed;
//!    and the revealed nullifier `nf` is the correct PRF output for the spent
//!    note. Verified by `Proof::verify` against the per-action public inputs
//!    (`Instance`). This is the part a missing constraint broke in Orchard for
//!    four years — we verify against the audited upstream circuit, unmodified.
//!
//! 3. **Spend authorization.** Each action's `spend_auth_sig` verifies under its
//!    randomized key `rk` over the [`sighash`], binding the authorization to this
//!    exact bundle and transaction.
//!
//! ## Encoding consensus rules (Zcash April-2026 disclosure; spec §5.4.9.4)
//!
//! Every action's randomized key `rk` and ephemeral key `epk` MUST encode
//! non-identity points on Pallas. A crafted identity `rk` could panic a verifier
//! and split consensus (it did, latently, across zcashd/Zebra). We reject such
//! bundles while parsing, before any proof work.

use blake2b_simd::Params;

use crate::bundle::ShieldedBundle;

/// Personalization for the shielded-transaction sighash (must be 16 bytes).
const SIGHASH_PERSONALIZATION: &[u8; 16] = b"zkas_tx_sighash0";

/// Why a shielded bundle failed cryptographic verification. Any of these makes
/// the carrying transaction invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleVerifyError {
    /// The bundle carries no actions.
    NoActions,
    /// A 32-byte field was not a canonical encoding of its type.
    NonCanonicalField(&'static str),
    /// An action's randomized key `rk` is the identity point (consensus rule).
    IdentityRk,
    /// An action's ephemeral key `epk` is the identity point (consensus rule).
    IdentityEpk,
    /// The flags byte has bits set outside the two defined flags (non-canonical).
    NonCanonicalFlags,
    /// The proof length is not the canonical length for this action count
    /// (rejects padded / malleated proofs).
    BadProofLength { expected: usize, got: usize },
    /// The Halo 2 proof did not verify.
    ProofInvalid,
    /// The binding signature did not verify (the bundle does not balance).
    BindingSigInvalid,
    /// An action's spend-authorization signature did not verify.
    SpendAuthSigInvalid(usize),
}

/// The canonical message that a shielded bundle's spend-auth and binding
/// signatures commit to.
///
/// It is a BLAKE2b-256 commitment to the bundle's **effects** — every field
/// except the proof and the signatures themselves (which sign this digest, so
/// including them would be circular) — together with the `network_domain` and
/// the caller-supplied `tx_context`. Committing to the effects (nullifiers, note
/// commitments, value commitments, `rk`, ciphertexts, anchor, value balance,
/// flags) binds the signatures to *this* bundle; `tx_context` (e.g. the
/// transaction's version, subnetwork, lock-time and gas) binds them to *this*
/// transaction, so a valid bundle cannot be lifted into a different one.
///
/// `network_domain` is a 32-byte per-network separator (the genesis hash) that
/// binds the signatures to *this chain*. Without it a bundle signed on one
/// network (e.g. testnet) could be replayed verbatim on another (mainnet), since
/// the anchor and nullifiers could coincide across a shared history. It is a
/// mandatory, non-defaultable parameter so no caller can silently omit it.
pub fn sighash(bundle: &ShieldedBundle, network_domain: &[u8; 32], tx_context: &[u8]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(SIGHASH_PERSONALIZATION).to_state();
    h.update(network_domain);
    h.update(&[bundle.flags]);
    h.update(&bundle.value_balance.to_le_bytes());
    h.update(&bundle.anchor);
    h.update(&(bundle.actions.len() as u32).to_le_bytes());
    for a in &bundle.actions {
        h.update(&a.nullifier);
        h.update(&a.rk);
        h.update(&a.cmx);
        h.update(&a.cv_net);
        h.update(&a.ephemeral_key);
        h.update(&a.enc_ciphertext);
        h.update(&a.out_ciphertext);
        // NB: spend_auth_sig is intentionally excluded — it signs this digest.
    }
    h.update(&(tx_context.len() as u32).to_le_bytes());
    h.update(tx_context);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(feature = "circuit")]
mod circuit_verify {
    use super::*;
    use group::{Group, GroupEncoding};
    use nonempty::NonEmpty;
    use orchard::{
        Action, ActionFromPartsError, Bundle, Proof,
        bundle::{Authorized, BatchValidator, Flags},
        circuit::{Instance, VerifyingKey},
        note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
        primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey},
        tree::Anchor,
        value::ValueCommitment,
    };
    use pasta_curves::pallas;
    use rand_core::{CryptoRng, RngCore};
    use std::sync::OnceLock;

    /// The Orchard action-circuit verifying key. Building it is expensive (it
    /// regenerates the circuit's verifying key), so it is built once and cached.
    /// Pinned to the audited upstream circuit version (PLAN §5).
    pub fn verifying_key() -> &'static VerifyingKey {
        static VK: OnceLock<VerifyingKey> = OnceLock::new();
        VK.get_or_init(|| VerifyingKey::build(crate::verify::CIRCUIT_VERSION))
    }

    /// Verify a shielded bundle's full cryptography against `sighash` using the
    /// cached verifying key. See the module docs for the three checks and the
    /// encoding rules. Returns `Ok(())` iff the bundle is sound.
    pub fn verify_bundle(bundle: &ShieldedBundle, sighash: &[u8; 32]) -> Result<(), BundleVerifyError> {
        verify_bundle_with_vk(bundle, sighash, verifying_key())
    }

    /// As [`verify_bundle`], but with a caller-provided verifying key (e.g. for
    /// batching across many bundles without re-fetching the static).
    pub fn verify_bundle_with_vk(bundle: &ShieldedBundle, sighash: &[u8; 32], vk: &VerifyingKey) -> Result<(), BundleVerifyError> {
        if bundle.actions.is_empty() {
            return Err(BundleVerifyError::NoActions);
        }

        let anchor: Anchor = Option::from(Anchor::from_bytes(bundle.anchor)).ok_or(BundleVerifyError::NonCanonicalField("anchor"))?;
        // Orchard flag bits: bit 0 = spends enabled, bit 1 = outputs enabled. Any
        // other bit set is a non-canonical encoding (matches Orchard `Flags::from_byte`).
        if bundle.flags & !0b11 != 0 {
            return Err(BundleVerifyError::NonCanonicalFlags);
        }
        let flags = Flags::from_byte(bundle.flags, crate::verify::BUNDLE_VERSION).ok_or(BundleVerifyError::NonCanonicalFlags)?;

        let mut instances = Vec::with_capacity(bundle.actions.len());
        let mut rks = Vec::with_capacity(bundle.actions.len());
        let mut cv_sum: Option<ValueCommitment> = None;

        for a in &bundle.actions {
            let nf: Nullifier =
                Option::from(Nullifier::from_bytes(&a.nullifier)).ok_or(BundleVerifyError::NonCanonicalField("nullifier"))?;
            let cmx: ExtractedNoteCommitment =
                Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or(BundleVerifyError::NonCanonicalField("cmx"))?;
            let cv_net: ValueCommitment =
                Option::from(ValueCommitment::from_bytes(&a.cv_net)).ok_or(BundleVerifyError::NonCanonicalField("cv_net"))?;
            let rk = VerificationKey::<SpendAuth>::try_from(a.rk).map_err(|_| BundleVerifyError::NonCanonicalField("rk"))?;

            // Consensus encoding rules (April-2026 disclosure): rk and epk must be
            // non-identity points, else a verifier could panic / consensus split.
            if rk.is_identity() {
                return Err(BundleVerifyError::IdentityRk);
            }
            let epk: pallas::Point =
                Option::from(pallas::Point::from_bytes(&a.ephemeral_key)).ok_or(BundleVerifyError::NonCanonicalField("epk"))?;
            if bool::from(epk.is_identity()) {
                return Err(BundleVerifyError::IdentityEpk);
            }

            // `Instance::from_parts` itself returns None on an identity rk — a
            // second, independent line of defence against the same bug class.
            let instance = Instance::from_parts(anchor, cv_net.clone(), nf, rk.clone(), cmx, flags.clone())
                .ok_or(BundleVerifyError::IdentityRk)?;
            instances.push(instance);

            cv_sum = Some(match cv_sum.take() {
                None => cv_net,
                Some(acc) => acc + &cv_net,
            });
            rks.push(rk);
        }

        // --- Check 2: the Halo 2 proof. Reject non-canonical (padded) proofs first. ---
        let expected = Proof::expected_proof_size(bundle.actions.len());
        if bundle.proof.len() != expected {
            return Err(BundleVerifyError::BadProofLength { expected, got: bundle.proof.len() });
        }
        let proof = Proof::new(bundle.proof.clone());
        proof.verify(vk, &instances).map_err(|_| BundleVerifyError::ProofInvalid)?;

        // --- Check 1: balance via the binding signature. ---
        // bvk = Σ cv_net − ValueCommit(value_balance, 0), reinterpreted as a
        // RedPallas verification key (this is exactly Orchard's into_bvk).
        let cv_sum = cv_sum.expect("actions are non-empty");
        let vb_commit = crate::turnstile::commit(bundle.value_balance, crate::turnstile::zero_trapdoor());
        let bvk_point = cv_sum - vb_commit;
        let bvk = VerificationKey::<Binding>::try_from(bvk_point.to_bytes()).map_err(|_| BundleVerifyError::BindingSigInvalid)?;
        let binding_sig = Signature::<Binding>::from(bundle.binding_sig);
        bvk.verify(sighash, &binding_sig).map_err(|_| BundleVerifyError::BindingSigInvalid)?;

        // --- Check 3: per-action spend authorization. ---
        for (i, (a, rk)) in bundle.actions.iter().zip(rks.iter()).enumerate() {
            let sig = Signature::<SpendAuth>::from(a.spend_auth_sig);
            rk.verify(sighash, &sig).map_err(|_| BundleVerifyError::SpendAuthSigInvalid(i))?;
        }

        Ok(())
    }

    /// Reconstruct an `orchard::Bundle<Authorized, i64>` from our wire format,
    /// enforcing the encoding consensus rules via Orchard's own audited
    /// constructors: `Action::from_parts` rejects identity `rk`/`epk`, and
    /// `try_from_parts` (Strict) rejects non-canonical proof lengths.
    fn to_orchard_bundle(wire: &ShieldedBundle) -> Result<Bundle<Authorized, i64>, BundleVerifyError> {
        let anchor: Anchor = Option::from(Anchor::from_bytes(wire.anchor)).ok_or(BundleVerifyError::NonCanonicalField("anchor"))?;
        let flags = Flags::from_byte(wire.flags, crate::verify::BUNDLE_VERSION).ok_or(BundleVerifyError::NonCanonicalFlags)?;

        let mut actions = Vec::with_capacity(wire.actions.len());
        for a in &wire.actions {
            let nf: Nullifier =
                Option::from(Nullifier::from_bytes(&a.nullifier)).ok_or(BundleVerifyError::NonCanonicalField("nullifier"))?;
            let rk = VerificationKey::<SpendAuth>::try_from(a.rk).map_err(|_| BundleVerifyError::NonCanonicalField("rk"))?;
            let cmx: ExtractedNoteCommitment =
                Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or(BundleVerifyError::NonCanonicalField("cmx"))?;
            let cv_net: ValueCommitment =
                Option::from(ValueCommitment::from_bytes(&a.cv_net)).ok_or(BundleVerifyError::NonCanonicalField("cv_net"))?;
            let ct = TransmittedNoteCiphertext {
                epk_bytes: a.ephemeral_key,
                enc_ciphertext: a.enc_ciphertext,
                out_ciphertext: a.out_ciphertext,
            };
            let sig = Signature::<SpendAuth>::from(a.spend_auth_sig);
            let action = Action::from_parts(nf, rk, cmx, ct, cv_net, sig).map_err(|e| match e {
                ActionFromPartsError::IdentityRk => BundleVerifyError::IdentityRk,
                _ => BundleVerifyError::IdentityEpk,
            })?;
            actions.push(action);
        }
        let actions = NonEmpty::from_vec(actions).ok_or(BundleVerifyError::NoActions)?;

        let auth = Authorized::from_parts(Proof::new(wire.proof.clone()), Signature::<Binding>::from(wire.binding_sig));
        Bundle::try_from_parts(actions, flags, wire.value_balance, anchor, auth, crate::verify::BUNDLE_VERSION).map_err(|_| {
            BundleVerifyError::BadProofLength { expected: Proof::expected_proof_size(wire.actions.len()), got: wire.proof.len() }
        })
    }

    /// Batch-verify the proofs **and** RedPallas signatures of many bundles at
    /// once (PLAN §2.8 — "the real unlock" for verification throughput). Halo 2
    /// IPA openings and RedPallas signatures both batch, so a block's worth of
    /// bundles costs far less than verifying each independently.
    ///
    /// All-or-nothing: returns `Ok(())` iff *every* bundle's proof and signatures
    /// are valid. On failure the caller should fall back to per-bundle
    /// [`verify_bundle`] to identify the offending transaction.
    pub fn verify_bundles_batched(
        items: &[(&ShieldedBundle, [u8; 32])],
        rng: impl RngCore + CryptoRng,
    ) -> Result<(), BundleVerifyError> {
        let mut batch = BatchValidator::new(verifying_key());
        for (wire, sighash) in items {
            let bundle = to_orchard_bundle(wire)?;
            batch.add_bundle(&bundle, *sighash).map_err(|_| BundleVerifyError::ProofInvalid)?;
        }
        if batch.validate(rng) { Ok(()) } else { Err(BundleVerifyError::ProofInvalid) }
    }
}

#[cfg(feature = "circuit")]
pub use circuit_verify::{verify_bundle, verify_bundle_with_vk, verify_bundles_batched, verifying_key};

/// Gold-standard end-to-end validation of the cryptographic verifier: build a
/// *real* Orchard bundle (real Halo 2 proof + real RedPallas signatures over our
/// sighash), serialize it to our wire format, and confirm [`verify_bundle`]
/// accepts it and rejects tampering. This is the test that proves the
/// verification math is actually correct (it requires the `circuit` feature, and
/// is expensive: it builds a proving key and produces a real proof).
#[cfg(all(test, feature = "circuit"))]
mod e2e {
    use super::*;
    use crate::bundle::{ActionWire, ShieldedBundle};
    use orchard::{
        Action, Anchor, Bundle,
        builder::{Builder, BundleType},
        bundle::{Authorization, Authorized},
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendingKey},
        value::NoteValue,
    };

    /// Extract the effect fields shared by proven and authorized bundles, with a
    /// caller-supplied per-action spend-auth signature and bundle-level proof /
    /// binding signature (zeroed when only the sighash is needed).
    fn build_wire<T: Authorization>(
        bundle: &Bundle<T, i64>,
        spend_auth_sig: impl Fn(&Action<T::SpendAuth>) -> [u8; 64],
        proof: Vec<u8>,
        binding_sig: [u8; 64],
    ) -> ShieldedBundle {
        let actions = bundle
            .actions()
            .iter()
            .map(|a| {
                let ct = a.encrypted_note();
                ActionWire {
                    nullifier: a.nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(a.rk()),
                    cmx: a.cmx().to_bytes(),
                    cv_net: a.cv_net().to_bytes(),
                    ephemeral_key: ct.epk_bytes,
                    enc_ciphertext: ct.enc_ciphertext,
                    out_ciphertext: ct.out_ciphertext,
                    spend_auth_sig: spend_auth_sig(a),
                }
            })
            .collect();
        ShieldedBundle {
            actions,
            flags: bundle.flags().to_byte(crate::verify::BUNDLE_VERSION).expect("orchard v2 flags are always encodable"),
            value_balance: *bundle.value_balance(),
            anchor: bundle.anchor().to_bytes(),
            proof,
            binding_sig,
            burn: None,
        }
    }

    /// The Orchard stack is pinned by value, not by semver. A bump that is not
    /// reflected here is a consensus change made by accident.
    #[test]
    fn orchard_stack_is_pinned() {
        assert_eq!(crate::verify::CIRCUIT_VERSION, orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2);
        assert_eq!(
            crate::verify::ORCHARD_CRATE,
            "zakura-orchard 1.0.1 79f40234883ea702da695f1cbf470a0ba3b9fe0ac51d24af588a058afc383d68"
        );
        assert_eq!(
            crate::verify::HALO2_GADGETS_CRATE,
            "zakura-halo2-gadgets 1.0.1 c601160505e513507664516f16a38b8e875a31b48155a93964b6e97c1e07d315"
        );
    }

    #[test]
    fn real_bundle_verifies_and_rejects_tampering() {
        let mut rng = rand::rng();
        let ctx = b"zkas-e2e-tx-context";

        // 1. Keys + an output-only bundle (dummy spends are auto-signed), anchored
        //    at the empty tree (no real spend, so no Merkle path needed).
        let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([7u8; 32])).expect("valid spending key");
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, Anchor::empty_tree()).expect("orchard v2 ENABLED flags are always representable");
        builder.add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512]).unwrap();
        let (unauth, _meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();

        // 2. Produce the real Halo 2 proof.
        let proven = unauth.create_proof(&pk, &mut rng).unwrap();

        // 3. Compute our sighash over the bundle effects (sigs/proof excluded, so
        //    placeholders are fine here).
        let effects_wire = build_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let net = [0x42u8; 32];
        let msg = sighash(&effects_wire, &net, ctx);

        // 4. Sign over our sighash (no real spend keys: output-only dummy spends).
        let authorized: Bundle<Authorized, i64> = proven.apply_signatures(&mut rng, msg, &[]).unwrap();

        // 5. Serialize the fully authorized bundle to our wire format.
        let wire = build_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        );
        // Signing does not change the effects, so the sighash is stable.
        assert_eq!(sighash(&wire, &net, ctx), msg, "effects unchanged by signing");

        // 6. THE validation: the real bundle verifies.
        verify_bundle(&wire, &msg).expect("a valid Orchard bundle must verify");

        // 7. Tamper detection.
        let mut bad_proof = wire.clone();
        bad_proof.proof[0] ^= 1;
        assert_eq!(verify_bundle(&bad_proof, &msg), Err(BundleVerifyError::ProofInvalid));

        let mut bad_balance = wire.clone();
        bad_balance.value_balance += 1; // breaks the binding-signature balance
        assert_eq!(verify_bundle(&bad_balance, &msg), Err(BundleVerifyError::BindingSigInvalid));

        let mut bad_sig = wire.clone();
        bad_sig.actions[0].spend_auth_sig[0] ^= 1;
        assert!(matches!(verify_bundle(&bad_sig, &msg), Err(BundleVerifyError::SpendAuthSigInvalid(0))));

        let mut bad_cv = wire.clone();
        bad_cv.actions[0].cv_net[0] ^= 1; // a different canonical point breaks proof+balance
        assert!(verify_bundle(&bad_cv, &msg).is_err());

        // 8. Batch verification (PLAN §2.8): a batch of valid bundles verifies;
        //    a batch containing a tampered bundle fails.
        super::verify_bundles_batched(&[(&wire, msg), (&wire, msg)], rand::rng()).expect("batch of valid bundles verifies");
        assert!(super::verify_bundles_batched(&[(&wire, msg), (&bad_proof, msg)], rand::rng()).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{ActionWire, sizes};

    fn action(seed: u8) -> ActionWire {
        ActionWire {
            nullifier: [seed; sizes::FIELD],
            rk: [seed.wrapping_add(1); sizes::FIELD],
            cmx: [seed.wrapping_add(2); sizes::FIELD],
            cv_net: [seed.wrapping_add(3); sizes::FIELD],
            ephemeral_key: [seed.wrapping_add(4); sizes::FIELD],
            enc_ciphertext: [seed.wrapping_add(5); sizes::ENC_CIPHERTEXT],
            out_ciphertext: [seed.wrapping_add(6); sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [seed.wrapping_add(7); sizes::SIG],
        }
    }

    fn bundle(n: u8) -> ShieldedBundle {
        ShieldedBundle {
            actions: (0..n).map(action).collect(),
            flags: 0b11,
            value_balance: 7,
            anchor: [1u8; 32],
            proof: vec![0u8; 100],
            binding_sig: [0u8; 64],
            burn: None,
        }
    }

    /// A fixed per-network domain (stands in for a genesis hash) for tests.
    const NET_A: [u8; 32] = [0xA1; 32];
    const NET_B: [u8; 32] = [0xB2; 32];

    #[test]
    fn sighash_is_deterministic_and_effect_sensitive() {
        let b = bundle(2);
        let s1 = sighash(&b, &NET_A, b"ctx");
        let s2 = sighash(&b, &NET_A, b"ctx");
        assert_eq!(s1, s2, "sighash is deterministic");

        // Changing any effect changes the sighash.
        let mut b2 = b.clone();
        b2.value_balance += 1;
        assert_ne!(sighash(&b2, &NET_A, b"ctx"), s1);

        let mut b3 = b.clone();
        b3.actions[0].cmx[0] ^= 1;
        assert_ne!(sighash(&b3, &NET_A, b"ctx"), s1);

        // Changing tx context changes the sighash.
        assert_ne!(sighash(&b, &NET_A, b"other"), s1);

        // Changing the network domain changes the sighash (replay protection):
        // the same bundle+context signed for network A is not valid for network B.
        assert_ne!(sighash(&b, &NET_B, b"ctx"), s1);
    }

    /// The spend-auth signature is excluded from the sighash (it signs it), so
    /// flipping a signature byte must NOT change the sighash.
    #[test]
    fn sighash_excludes_authorizing_data() {
        let b = bundle(1);
        let s = sighash(&b, &NET_A, b"");
        let mut b2 = b.clone();
        b2.actions[0].spend_auth_sig[0] ^= 1;
        b2.binding_sig[0] ^= 1;
        b2.proof[0] ^= 1;
        assert_eq!(sighash(&b2, &NET_A, b""), s, "sighash must not cover proof/signatures");
    }
}

/// Wire semantics of the bundle `flags` byte: Orchard pool, v5-style flags — bits 0/1 only,
/// bit 2 MUST be zero, cross-address transfers always permitted. Exactly what the chain has
/// always enforced (`flags & !0b11 != 0` is rejected as non-canonical).
pub const BUNDLE_VERSION: orchard::bundle::BundleVersion = orchard::bundle::BundleVersion::orchard_v2();

/// The Orchard Action circuit the chain's verifying key is built from. `FixedPostNu6_2` is the
/// anchored-base circuit of halo2_gadgets 0.5.0 / orchard 0.14.0 — the circuit every proof on
/// the live chain has been verified against. `PostNu6_3` adds a constrained public input and is
/// a DIFFERENT circuit: changing this constant is a hard fork.
#[cfg(feature = "circuit")]
pub const CIRCUIT_VERSION: orchard::circuit::OrchardCircuitVersion = orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2;

/// The Orchard crate this build links, as `name version sha256` read from the
/// workspace `Cargo.lock` at build time (see `build.rs`). With
/// [`CIRCUIT_VERSION`] this fixes the verifying key; both are reported by
/// [`circuit_identity`] so a running node can be checked against a peer.
pub const ORCHARD_CRATE: &str = env!("ZKAS_ORCHARD_CRATE");
/// The halo2_gadgets crate this build links (`name version sha256`); the ECC
/// gadget carrying the June-2026 base-anchoring fix lives here.
pub const HALO2_GADGETS_CRATE: &str = env!("ZKAS_HALO2_GADGETS_CRATE");

/// One line identifying the shielded circuit this node verifies against.
/// Intended for the startup log and for `getInfo`-style RPC exposure.
pub fn circuit_identity() -> String {
    #[cfg(feature = "circuit")]
    let version = format!("{CIRCUIT_VERSION:?}");
    #[cfg(not(feature = "circuit"))]
    let version = "no-circuit-feature".to_string();
    format!("circuit={version} orchard=[{ORCHARD_CRATE}] halo2_gadgets=[{HALO2_GADGETS_CRATE}]")
}
