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

/// The Orchard flags byte of a wire bundle, after the ZKas encoding checks on the flags byte.
///
/// This is the ONE place the flags byte is interpreted for verification; the single path
/// ([`verify_bundle_with_vk`]) and the batched path ([`verify_bundles_batched`]) both call it.
/// Orchard flag bits: bit 0 = spends enabled, bit 1 = outputs enabled. The only other bit this
/// verifier admits is the ZKas anchor-block extension ([`crate::bundle::BUNDLE_FLAG_ANCHOR_BLOCK`]),
/// which is not an Orchard flag and is masked off before Orchard sees the byte; its presence must
/// match the `anchor_block` field exactly. WHEN the extension is allowed (only from the security
/// fork) is a consensus-context rule, enforced by the transaction validator, not here.
///
/// The batched path used to hand the raw byte to Orchard, so every post-fork bundle (flags `0x0b`)
/// failed it with `NonCanonicalFlags` while the single path accepted it.
pub fn canonical_orchard_flags_byte(bundle: &ShieldedBundle) -> Result<u8, BundleVerifyError> {
    let ext = crate::bundle::BUNDLE_FLAG_ANCHOR_BLOCK;
    if bundle.flags & !(0b11 | ext) != 0 || ((bundle.flags & ext) != 0) != bundle.anchor_block.is_some() {
        return Err(BundleVerifyError::NonCanonicalFlags);
    }
    Ok(bundle.flags & 0b11)
}

/// Most bundles in one batched verification (08 R1.3.3). A full block today is at most ~40 bundles,
/// so a block forms 1-3 batches that verify in parallel, while the batch still amortises the
/// ~16 ms per-bundle fixed cost (measured gain 5.2x at 10 two-action bundles).
pub const MAX_BATCH_BUNDLES: usize = 16;
/// Most actions in one batched verification (08 R1.3.3).
pub const MAX_BATCH_ACTIONS: usize = 160;

/// Split items with the given action counts, in order, into consecutive ranges of at most
/// [`MAX_BATCH_BUNDLES`] items and [`MAX_BATCH_ACTIONS`] actions. An item larger than the action
/// cap on its own forms its own range. Every index is covered exactly once.
pub fn plan_verify_batches(action_counts: &[usize]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut actions = 0usize;
    for (i, &n) in action_counts.iter().enumerate() {
        let len = i - start;
        if len > 0 && (len >= MAX_BATCH_BUNDLES || actions + n > MAX_BATCH_ACTIONS) {
            out.push(start..i);
            start = i;
            actions = 0;
        }
        actions += n;
    }
    if start < action_counts.len() {
        out.push(start..action_counts.len());
    }
    out
}

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
/// Whether `sig` is a valid spend-authorization signature by the randomized key `rk` over
/// `sighash`. Lets a party that collects signatures (a multi-party bundle session) refuse a bad one
/// on arrival instead of discovering it only when the whole bundle fails to finalize.
pub fn verify_spend_auth_sig(rk: &[u8; 32], sighash: &[u8; 32], sig: &[u8; 64]) -> bool {
    use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
    match VerificationKey::<SpendAuth>::try_from(*rk) {
        Ok(vk) => vk.verify(sighash, &Signature::<SpendAuth>::from(*sig)).is_ok(),
        Err(_) => false,
    }
}

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
    // The bridge peg-out declaration, hashed ONLY when one is present.
    //
    // These 40 bytes (`value || kaspa_recipient`) were outside the sighash entirely, while the flag
    // bit that gates them was inside it. Signatures and the Halo 2 proof therefore said nothing
    // about them, so any party relaying a peg-out could rewrite the value and the recipient, keep
    // every signature valid, and redirect up to the whole `value_balance` to themselves — the
    // victim's nullifiers being spent either way, so the original could not be re-mined.
    //
    // Hashing it conditionally keeps the digest of every non-burn bundle byte-for-byte identical, so
    // this needs no fork. No burn has ever been mined (`burn::BRIDGE_ENABLED` is false, and
    // `verify_bundle` rejects the flag bit as non-canonical), so there is nothing to stay compatible
    // with on the burn side either.
    if let Some((value, recipient)) = bundle.burn.as_ref() {
        h.update(&value.to_le_bytes());
        h.update(recipient);
    }
    // The named anchor block (security fork), hashed only when present so every pre-fork digest
    // is unchanged. The flags byte above already binds whether it is present.
    if let Some(block) = bundle.anchor_block.as_ref() {
        h.update(block);
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

    /// Orchard `Flags` of a wire bundle via the shared mask ([`super::canonical_orchard_flags_byte`]).
    fn orchard_flags(bundle: &ShieldedBundle) -> Result<Flags, BundleVerifyError> {
        let byte = super::canonical_orchard_flags_byte(bundle)?;
        Flags::from_byte(byte, crate::verify::BUNDLE_VERSION).ok_or(BundleVerifyError::NonCanonicalFlags)
    }

    /// The decoded public parts of a bundle that passed every encoding rule.
    struct CheckedParts {
        instances: Vec<Instance>,
        rks: Vec<VerificationKey<SpendAuth>>,
        cv_sum: ValueCommitment,
    }

    /// Every encoding rule of a bundle, in one function shared by the single and the batched path
    /// (08 R1.2.1/R1.2.2): non-empty, canonical anchor and flags, canonical per-action fields,
    /// non-identity `rk` and `epk`, and the canonical proof length. The batched path runs it before
    /// handing the bundle to Orchard's `BatchValidator`, so both paths reject exactly the same
    /// encodings.
    fn checked_parts(bundle: &ShieldedBundle) -> Result<CheckedParts, BundleVerifyError> {
        if bundle.actions.is_empty() {
            return Err(BundleVerifyError::NoActions);
        }

        let anchor: Anchor = Option::from(Anchor::from_bytes(bundle.anchor)).ok_or(BundleVerifyError::NonCanonicalField("anchor"))?;
        let flags = orchard_flags(bundle)?;

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

        // Reject non-canonical (padded / truncated) proofs before any proof work.
        let expected = Proof::expected_proof_size(bundle.actions.len());
        if bundle.proof.len() != expected {
            return Err(BundleVerifyError::BadProofLength { expected, got: bundle.proof.len() });
        }
        Ok(CheckedParts { instances, rks, cv_sum: cv_sum.expect("actions are non-empty") })
    }

    /// As [`verify_bundle`], but with a caller-provided verifying key (e.g. for
    /// batching across many bundles without re-fetching the static).
    pub fn verify_bundle_with_vk(bundle: &ShieldedBundle, sighash: &[u8; 32], vk: &VerifyingKey) -> Result<(), BundleVerifyError> {
        let CheckedParts { instances, rks, cv_sum } = checked_parts(bundle)?;

        // --- Check 2: the Halo 2 proof (length already checked in `checked_parts`). ---
        let proof = Proof::new(bundle.proof.clone());
        proof.verify(vk, &instances).map_err(|_| BundleVerifyError::ProofInvalid)?;

        // --- Check 1: balance via the binding signature. ---
        // bvk = Σ cv_net − ValueCommit(value_balance, 0), reinterpreted as a
        // RedPallas verification key (this is exactly Orchard's into_bvk).
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
        if wire.actions.is_empty() {
            return Err(BundleVerifyError::NoActions);
        }
        let anchor: Anchor = Option::from(Anchor::from_bytes(wire.anchor)).ok_or(BundleVerifyError::NonCanonicalField("anchor"))?;
        // The shared mask (was `Flags::from_byte(wire.flags, ..)`, which rejected every post-fork
        // bundle: their byte carries the anchor-block bit).
        let flags = orchard_flags(wire)?;

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
            // Same encoding rules as the single path, by the same function.
            checked_parts(wire)?;
            let bundle = to_orchard_bundle(wire)?;
            batch.add_bundle(&bundle, *sighash).map_err(|_| BundleVerifyError::ProofInvalid)?;
        }
        if batch.validate(rng) { Ok(()) } else { Err(BundleVerifyError::ProofInvalid) }
    }

    /// Per-item verdicts for many bundles, verified in batches of at most
    /// [`super::MAX_BATCH_BUNDLES`] bundles / [`super::MAX_BATCH_ACTIONS`] actions, the batches in
    /// parallel (08 R1.3.1/R1.3.3).
    ///
    /// A batch that verifies proves every bundle in it valid. A batch that fails is re-verified one
    /// bundle at a time with [`verify_bundle`], so the returned verdict of every item is exactly what
    /// [`verify_bundle`] would return for it (up to the batch's negligible soundness error). The
    /// batch randomness is the thread-local CSPRNG seeded from the OS, never derived from the
    /// bundles, which an attacker chooses (R1.2.3).
    pub fn verify_bundles_in_batches(items: &[(&ShieldedBundle, [u8; 32])]) -> Vec<Result<(), BundleVerifyError>> {
        use rayon::prelude::*;
        let counts: Vec<usize> = items.iter().map(|(b, _)| b.actions.len()).collect();
        let plan = super::plan_verify_batches(&counts);
        let per_batch: Vec<Vec<Result<(), BundleVerifyError>>> = plan
            .into_par_iter()
            .map(|range| {
                let chunk = &items[range];
                if verify_bundles_batched(chunk, rand::rng()).is_ok() {
                    vec![Ok(()); chunk.len()]
                } else {
                    chunk.iter().map(|(b, s)| verify_bundle(b, s)).collect()
                }
            })
            .collect();
        per_batch.into_iter().flatten().collect()
    }

    /// One batched pass over many bundles for a caller that does NOT need a verdict for every
    /// failing item (N1, spec 08 R1.3), in one of two modes:
    ///
    /// - [`super::BatchPassMode::Accelerate`] (block bodies, before the virtual processor's
    ///   per-transaction check, which stays the authority): every batch runs, in parallel; a failed
    ///   batch is NOT re-verified, its items are just "not proven". Isolation: one bad bundle costs
    ///   only its own batch's speed-up; the other batches are still proven. A garbage block therefore
    ///   costs about one batched pass more than today, not one more full per-bundle pass.
    /// - [`super::BatchPassMode::StopAtFirstFailure`] (one peer's relayed batch, which is discarded
    ///   whole on any failure): batches run in waves of the pool's width; after a wave with a failed
    ///   batch, nothing later is verified, and the first failed batch is re-verified bundle by bundle
    ///   only up to its first failing bundle, which is reported. The cost of a junk batch is one wave
    ///   plus at most one batch of single checks, whatever the peer sent.
    ///
    /// `proven[i]` is true only for items whose validity this pass established (a passed batch, or an
    /// individual check). Randomness: the thread CSPRNG, never derived from attacker data (R1.2.3).
    pub fn verify_bundles_pass(items: &[(&ShieldedBundle, [u8; 32])], mode: super::BatchPassMode) -> super::BatchPass {
        use rayon::prelude::*;
        let counts: Vec<usize> = items.iter().map(|(b, _)| b.actions.len()).collect();
        let plan = super::plan_verify_batches(&counts);
        let mut proven = vec![false; items.len()];
        match mode {
            super::BatchPassMode::Accelerate => {
                let oks: Vec<bool> = plan.par_iter().map(|r| verify_bundles_batched(&items[r.clone()], rand::rng()).is_ok()).collect();
                for (r, ok) in plan.iter().zip(oks) {
                    if ok {
                        proven[r.clone()].iter_mut().for_each(|p| *p = true);
                    }
                }
                super::BatchPass { proven, first_failure: None }
            }
            super::BatchPassMode::StopAtFirstFailure => {
                let wave = rayon::current_num_threads().max(1);
                for batches in plan.chunks(wave) {
                    let oks: Vec<bool> =
                        batches.par_iter().map(|r| verify_bundles_batched(&items[r.clone()], rand::rng()).is_ok()).collect();
                    for (r, ok) in batches.iter().zip(&oks) {
                        if *ok {
                            proven[r.clone()].iter_mut().for_each(|p| *p = true);
                        }
                    }
                    if let Some(bad) = batches.iter().zip(&oks).find(|(_, ok)| !**ok).map(|(r, _)| r.clone()) {
                        for i in bad {
                            match verify_bundle(items[i].0, &items[i].1) {
                                Ok(()) => proven[i] = true,
                                Err(e) => return super::BatchPass { proven, first_failure: Some((i, e)) },
                            }
                        }
                        // Every member verified alone: the batch failure was the batch's negligible
                        // soundness slack (or a transient), not a bad bundle. Keep going.
                    }
                }
                super::BatchPass { proven, first_failure: None }
            }
        }
    }
}

#[cfg(feature = "circuit")]
pub use circuit_verify::{
    verify_bundle, verify_bundle_with_vk, verify_bundles_batched, verify_bundles_in_batches, verify_bundles_pass, verifying_key,
};

/// How [`verify_bundles_pass`] treats a failed batch (N1, spec 08 R1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchPassMode {
    /// Run every batch; a failed batch's items are left unproven (no per-bundle fallback).
    Accelerate,
    /// Stop after the first wave with a failed batch and name the first failing bundle.
    StopAtFirstFailure,
}

/// Result of [`verify_bundles_pass`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPass {
    /// Per item: validity established by this pass.
    pub proven: Vec<bool>,
    /// [`BatchPassMode::StopAtFirstFailure`] only: the first failing item and why.
    pub first_failure: Option<(usize, BundleVerifyError)>,
}

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
            anchor_block: None,
        }
    }

    /// The Orchard stack is pinned by value, not by semver. A bump that is not
    /// reflected here is a consensus change made by accident.
    #[test]
    fn orchard_stack_is_pinned() {
        assert_eq!(crate::verify::CIRCUIT_VERSION, orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2);
        // 2.2.0 (2026-09-30): proving/verifier performance only; the pinned circuit description,
        // the k=11 params and the proof test vectors are byte-identical to 1.0.1, and the key
        // fingerprint below is unchanged.
        assert_eq!(
            crate::verify::ORCHARD_CRATE,
            // walletd-scale 2026-10-21: the registry crate (checksum unchanged) plus the one
            // additive function `orchard_patch_is_one_additive_function` below proves.
            "zakura-orchard 2.2.0 b460a562603ba2e9820cb988b5f873ef470bd007c6c2f86e50abaa91b45e241e+zkas-patch:from_parts_with_commitment+vartime"
        );
        assert_eq!(
            crate::verify::HALO2_GADGETS_CRATE,
            "zakura-halo2-gadgets 2.2.0 1ee6ebb179f9c77243d320b81f30216c5fc7f76244290a1c546762dd06e20702"
        );
    }

    /// The verifying key itself, not just the crate versions: a dependency that changes the circuit
    /// changes this fingerprint and fails here (and the node refuses to start).
    #[test]
    fn verifying_key_fingerprint_is_pinned() {
        crate::verify::check_verifying_key().expect("verifying key matches the chain's");
    }

    /// The `[patch]`ed zakura-orchard is the registry 2.2.0 source with exactly one
    /// additive function and nothing else: every other source file hashes to the
    /// registry crate's manifest (pinned below, computed from
    /// ~/.cargo/registry/src/*/zakura-orchard-2.2.0 on 2026-10-21), `note.rs.orig` is the
    /// registry `note.rs`, and the patched `note.rs` is that file plus ONE contiguous
    /// insertion that defines `from_parts_with_commitment` and no other item. The circuit,
    /// and so the verifying key, cannot have moved.
    #[test]
    fn orchard_patch_is_one_additive_function() {
        use sha2::{Digest, Sha256};
        fn hexd(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).expect("read_dir") {
                let p = e.expect("entry").path();
                if p.is_dir() {
                    walk(&p, root, out);
                } else {
                    out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../patches/zakura-orchard-2.2.0");
        let mut files = Vec::new();
        walk(&root.join("src"), &root, &mut files);
        files.retain(|f| f != "src/note.rs");
        files.sort();
        let mut manifest = String::new();
        for f in &files {
            manifest.push_str(f);
            manifest.push('\n');
            manifest.push_str(&hexd(&Sha256::digest(std::fs::read(root.join(f)).unwrap())));
            manifest.push('\n');
        }
        assert_eq!(
            hexd(&Sha256::digest(manifest.as_bytes())),
            "244dd7b1da5c60d68cbbd0864f0ef495f8a2988051198efc2b2160efe1b4a55f",
            "a source file other than note.rs differs from registry zakura-orchard 2.2.0"
        );
        let orig = std::fs::read_to_string(root.join("note.rs.orig")).unwrap();
        assert_eq!(
            hexd(&Sha256::digest(orig.as_bytes())),
            "a8233a2fb5b9ed2045ef9e6b62454cca93bc453e37850b0b426a33342cc65781",
            "note.rs.orig is not the registry note.rs"
        );
        let patched = std::fs::read_to_string(root.join("src/note.rs")).unwrap();
        let (o, p) = (orig.as_bytes(), patched.as_bytes());
        let pre = o.iter().zip(p.iter()).take_while(|(a, b)| a == b).count();
        let suf = o.iter().rev().zip(p.iter().rev()).take_while(|(a, b)| a == b).count().min(o.len() - pre);
        assert_eq!(pre + suf, o.len(), "the patch must only INSERT (nothing of the original removed or changed)");
        let inserted = &patched[pre..p.len() - suf];
        // 2026-10-31: plus the public-note fast path, `from_parts_with_commitment_vartime`, and
        // its private helpers. Two public items, both named here; the circuit is untouched.
        assert_eq!(inserted.matches("pub fn ").count(), 2, "exactly two public functions inserted");
        assert!(inserted.contains("pub fn from_parts_with_commitment("), "the documented one");
        assert!(inserted.contains("pub fn from_parts_with_commitment_vartime("), "and its public-note fast path");
        assert_eq!(inserted.matches("fn ").count(), 6, "plus exactly four private helpers");
        for helper in ["fn commitment_vartime(", "fn note_commit_vartime_tables(", "fn fixed_base_mul(", "fn g_d_bytes_cached("] {
            assert!(inserted.contains(helper), "{helper}");
        }
        assert!(!inserted.contains("unsafe"), "no unsafe code");
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

    /// 08 R1.2 / T1: the batched path and the single path agree on REAL post-fork bundles (flags
    /// `0x0b`, a named anchor block, a positive fee), on output-only bundles (negative and zero
    /// value balance), and on every mutation class below. Before the shared flag mask the batched
    /// path rejected every post-fork bundle with `NonCanonicalFlags` (verify.rs:271 at d8301eca).
    #[test]
    fn batched_and_single_verification_agree_on_post_fork_bundles() {
        use crate::wallet::{address_bytes_from_seed, build::build_singleleaf_coinbase_spend_anchored};
        let net = [0x5au8; 32];
        let ctx: &[u8] = b"n1-t1-differential";
        let recipient = address_bytes_from_seed([6u8; 32]).unwrap();

        // Three real anchored spends (distinct notes => distinct proofs), fee = note - output.
        let mut real: Vec<(ShieldedBundle, [u8; 32])> = Vec::new();
        for (i, (note, out)) in [(10_000u64, 8_000u64), (50_000, 1), (3_000_000, 0)].into_iter().enumerate() {
            let bytes = build_singleleaf_coinbase_spend_anchored(
                [5u8; 32],
                [9u8 + i as u8; 32],
                0,
                note,
                recipient,
                out,
                &net,
                ctx,
                Some([0xabu8 + i as u8; 32]),
            )
            .expect("anchored spend builds");
            let wire = ShieldedBundle::from_bytes_at(&bytes, true).expect("post-fork bundle decodes");
            assert_eq!(wire.flags, 0x0b, "a post-fork payment carries the anchor-block bit");
            assert!(wire.value_balance > 0, "a spend pays a positive fee");
            let msg = sighash(&wire, &net, ctx);
            assert_eq!(verify_bundle(&wire, &msg), Ok(()), "the real bundle verifies on the single path");
            real.push((wire, msg));
        }

        // Output-only bundles: negative and zero value balance, pre-fork flags 0x03.
        let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let addr = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        for value in [5_000u64, 0] {
            let mut rng = rand::rng();
            let mut b = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, Anchor::empty_tree())
                .unwrap();
            b.add_output(None, addr, NoteValue::from_raw(value), [0u8; 512]).unwrap();
            let (unauth, _) = b.build::<i64>(&mut rng).unwrap().unwrap();
            let proven = unauth.create_proof(&pk, &mut rng).unwrap();
            let msg = sighash(&build_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]), &[0x5a; 32], ctx);
            let authorized: Bundle<Authorized, i64> = proven.apply_signatures(&mut rng, msg, &[]).unwrap();
            let wire = build_wire(
                &authorized,
                |a| <[u8; 64]>::from(a.authorization()),
                authorized.authorization().proof().as_ref().to_vec(),
                <[u8; 64]>::from(authorized.authorization().binding_signature()),
            );
            assert_eq!(wire.value_balance, -(value as i64));
            assert_eq!(verify_bundle(&wire, &msg), Ok(()));
            real.push((wire, msg));
        }

        // Mutation classes (each applied to a copy of a real bundle; the sighash is recomputed where
        // the mutated field is covered by it, so the signatures, not just the digest, are tested).
        let mut cases: Vec<(String, ShieldedBundle, [u8; 32])> = Vec::new();
        for (k, (w, m)) in real.iter().enumerate() {
            cases.push((format!("real#{k}"), w.clone(), *m));
            for flags in [0x03u8, 0x0b, 0x07, 0x0f, 0x13, 0x08, 0x00, 0x01, 0x02, 0x83] {
                let mut b = w.clone();
                b.flags = flags;
                cases.push((format!("flags {flags:#04x} on #{k}"), b, *m));
            }
            let mut b = w.clone();
            b.anchor_block = if b.anchor_block.is_some() { None } else { Some([1u8; 32]) };
            cases.push((format!("anchor_block presence flipped on #{k}"), b, *m));
            let mut b = w.clone();
            b.actions[0].rk = [0u8; 32]; // identity encoding
            cases.push((format!("identity rk on #{k}"), b, *m));
            let mut b = w.clone();
            b.actions[0].ephemeral_key = [0u8; 32];
            cases.push((format!("identity epk on #{k}"), b, *m));
            let mut b = w.clone();
            b.actions[0].ephemeral_key = [0xffu8; 32]; // not a point
            cases.push((format!("non-canonical epk on #{k}"), b, *m));
            let mut b = w.clone();
            b.proof.pop();
            cases.push((format!("short proof on #{k}"), b, *m));
            let mut b = w.clone();
            b.proof.push(0);
            cases.push((format!("long proof on #{k}"), b, *m));
            let mut b = w.clone();
            b.proof[10] ^= 1;
            cases.push((format!("flipped proof byte on #{k}"), b, *m));
            let mut b = w.clone();
            b.binding_sig[3] ^= 1;
            cases.push((format!("flipped binding sig on #{k}"), b, *m));
            let mut b = w.clone();
            b.actions[1].spend_auth_sig[5] ^= 1;
            cases.push((format!("flipped spend-auth sig on #{k}"), b, *m));
            for vb in [0i64, 1, -1, i64::MAX, i64::MIN, w.value_balance + 1] {
                let mut b = w.clone();
                b.value_balance = vb;
                let s = sighash(&b, &net, ctx);
                cases.push((format!("value_balance {vb} on #{k}"), b, s));
            }
            let mut b = w.clone();
            b.actions.clear();
            cases.push((format!("no actions on #{k}"), b, *m));
            cases.push((format!("wrong sighash on #{k}"), w.clone(), [0x11u8; 32]));
        }

        // (1) Batch of one == single, for every case.
        let mut valid = 0;
        for (name, b, s) in &cases {
            let single = verify_bundle(b, s);
            let batched = super::verify_bundles_batched(&[(b, *s)], rand::rng());
            assert_eq!(single.is_ok(), batched.is_ok(), "{name}: single {single:?} vs batched {batched:?}");
            if single.is_ok() {
                valid += 1;
            }
        }
        // Valid: each real bundle, its unchanged copy in the flags sweep (0x0b for the spends, 0x03
        // for the output-only bundles), and the zero-value bundle's "value_balance 0" copy, which
        // is byte-identical to it. Every other mutation must fail on both paths.
        assert_eq!(valid, real.len() * 2 + 1, "exactly the unmutated bundles verify");
        for (name, b, s) in &cases {
            if name.starts_with("real#") {
                assert_eq!(verify_bundle(b, s), Ok(()), "{name}");
            }
        }

        // (2) Mixed batches of 16: a batch verifies iff every member verifies alone, and the
        // per-item batched API returns exactly the single verdicts.
        let items: Vec<(&ShieldedBundle, [u8; 32])> = cases.iter().map(|(_, b, s)| (b, *s)).collect();
        let singles: Vec<bool> = items.iter().map(|(b, s)| verify_bundle(b, s).is_ok()).collect();
        for (c, chunk) in items.chunks(16).enumerate() {
            let all_ok = singles[c * 16..c * 16 + chunk.len()].iter().all(|x| *x);
            assert_eq!(super::verify_bundles_batched(chunk, rand::rng()).is_ok(), all_ok, "mixed batch {c}");
        }
        let all_valid: Vec<(&ShieldedBundle, [u8; 32])> = real.iter().map(|(b, s)| (b, *s)).cycle().take(16).collect();
        super::verify_bundles_batched(&all_valid, rand::rng()).expect("16 valid post-fork + output-only bundles batch-verify");
        let per_item = super::verify_bundles_in_batches(&items);
        assert_eq!(per_item.iter().map(|r| r.is_ok()).collect::<Vec<_>>(), singles, "per-item batched verdicts == single verdicts");

        // (3) The two pass modes (N1). Accelerate proves exactly the items of batches whose members
        // are all valid and never claims an invalid item; StopAtFirstFailure names the FIRST invalid
        // item and verifies nothing after the wave that held it.
        let acc = super::verify_bundles_pass(&items, super::BatchPassMode::Accelerate);
        assert_eq!(acc.first_failure, None);
        let counts: Vec<usize> = items.iter().map(|(b, _)| b.actions.len()).collect();
        for r in super::plan_verify_batches(&counts) {
            let all_ok = singles[r.clone()].iter().all(|x| *x);
            for i in r {
                assert_eq!(acc.proven[i], all_ok, "accelerate: item {i} proven iff its whole batch is valid");
                assert!(!acc.proven[i] || singles[i], "accelerate never proves an invalid item");
            }
        }
        let stop = super::verify_bundles_pass(&items, super::BatchPassMode::StopAtFirstFailure);
        let first_bad = singles.iter().position(|ok| !*ok).expect("the case list holds invalid items");
        let (idx, _) = stop.first_failure.clone().expect("a failure is reported");
        assert_eq!(idx, first_bad, "the reported failure is the first invalid item");
        assert!(stop.proven.iter().enumerate().all(|(i, p)| !*p || singles[i]), "stop mode never proves an invalid item");
        let all_good = super::verify_bundles_pass(&all_valid, super::BatchPassMode::StopAtFirstFailure);
        assert_eq!(all_good.first_failure, None);
        assert!(all_good.proven.iter().all(|p| *p), "an all-valid batch is proven whole");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{ActionWire, ShieldedBundle, sizes};

    /// The burn declaration carries a VALUE and a RECIPIENT, and it was outside the sighash while the
    /// flag bit gating it was inside — so signatures and the proof said nothing about those 40 bytes
    /// and any relaying party could redirect someone else's peg-out to themselves.
    ///
    /// Also pins the property that makes the fix deployable without a fork: a bundle with no burn
    /// hashes to exactly what it hashed before, because the field is only folded in when present.
    #[test]
    fn the_sighash_covers_the_burn_declaration_without_disturbing_other_bundles() {
        let domain = [7u8; 32];
        let ctx = [1u8, 2, 3, 4];
        let mut bundle = ShieldedBundle::sample_for_test(2);

        assert!(bundle.burn.is_none());
        let no_burn = sighash(&bundle, &domain, &ctx);

        bundle.burn = Some((1_000, [9u8; sizes::FIELD]));
        let declared = sighash(&bundle, &domain, &ctx);
        assert_ne!(no_burn, declared, "declaring a burn must change the digest");

        bundle.burn = Some((1_001, [9u8; sizes::FIELD]));
        assert_ne!(declared, sighash(&bundle, &domain, &ctx), "rewriting the burn VALUE must change the digest");

        bundle.burn = Some((1_000, [8u8; sizes::FIELD]));
        assert_ne!(declared, sighash(&bundle, &domain, &ctx), "rewriting the burn RECIPIENT must change the digest");

        // The compatibility half: removing the burn returns the digest to its original value, so no
        // bundle that has ever existed on any ZKas chain has its signatures invalidated by this.
        bundle.burn = None;
        assert_eq!(no_burn, sighash(&bundle, &domain, &ctx), "a non-burn bundle's digest is unchanged");
    }

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
            anchor_block: None,
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

    /// The one flag mask both verification paths use: post-fork `0x0b` (with its anchor block) maps
    /// to Orchard `0b11`; every other bit, and a presence mismatch, is non-canonical.
    #[test]
    fn shared_flag_mask_accepts_post_fork_and_rejects_the_rest() {
        let mut b = bundle(2);
        for byte in 0u8..=255 {
            for has_block in [false, true] {
                b.flags = byte;
                b.anchor_block = has_block.then_some([3u8; 32]);
                let ext = crate::bundle::BUNDLE_FLAG_ANCHOR_BLOCK;
                let canonical = byte & !(0b11 | ext) == 0 && ((byte & ext) != 0) == has_block;
                match canonical_orchard_flags_byte(&b) {
                    Ok(o) => {
                        assert!(canonical, "{byte:#04x}/{has_block} must be rejected");
                        assert_eq!(o, byte & 0b11);
                    }
                    Err(e) => {
                        assert!(!canonical, "{byte:#04x}/{has_block} must be accepted");
                        assert_eq!(e, BundleVerifyError::NonCanonicalFlags);
                    }
                }
            }
        }
        b.flags = 0x0b;
        b.anchor_block = Some([1u8; 32]);
        assert_eq!(canonical_orchard_flags_byte(&b), Ok(0b11), "every live bundle's byte");
    }

    #[test]
    fn verify_batch_plan_covers_every_item_within_both_caps() {
        let cases: Vec<Vec<usize>> = vec![
            vec![],
            vec![2],
            vec![2; 40],
            vec![38, 38],
            vec![1; 100],
            vec![200, 2, 2],
            vec![2, 200, 2],
            (0..97).map(|i| 1 + (i * 7) % 39).collect(),
        ];
        for counts in cases {
            let plan = plan_verify_batches(&counts);
            let mut next = 0;
            for r in &plan {
                assert_eq!(r.start, next, "contiguous, in order");
                assert!(!r.is_empty());
                assert!(r.len() <= MAX_BATCH_BUNDLES);
                let actions: usize = counts[r.clone()].iter().sum();
                assert!(actions <= MAX_BATCH_ACTIONS || r.len() == 1, "{counts:?}: {r:?} has {actions} actions");
                next = r.end;
            }
            assert_eq!(next, counts.len(), "every item covered");
        }
        // A full block today (2 x 38 actions) is one batch; 40 two-action bundles are three.
        assert_eq!(plan_verify_batches(&[38, 38]).len(), 1);
        assert_eq!(plan_verify_batches(&[2; 40]).len(), 3);
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

/// Fingerprint of the verifying key every proof on this chain is checked against:
/// `VerifyingKey::fingerprint` (BLAKE2b-256, personal `Orchard-VkFprint`, over the pinned circuit
/// description) of [`CIRCUIT_VERSION`]. The description file is byte-identical in zakura-orchard
/// 1.0.1 and 2.2.0, so the key is the same across that upgrade. A node whose built key does not
/// match refuses to start: a circuit change must be a deliberate hard fork, never a dependency bump.
pub const VERIFYING_KEY_FINGERPRINT: [u8; 32] = [
    0x1b, 0xee, 0x04, 0x9a, 0xd3, 0xff, 0x02, 0x7c, 0x8d, 0x44, 0x8e, 0x64, 0xb4, 0x41, 0x3b, 0x3c, 0x4a, 0x48, 0x3a, 0x74, 0x3b, 0x5f, 0x39,
    0xbc, 0xfb, 0xb6, 0x10, 0x2f, 0x62, 0x65, 0x91, 0xfb,
];

/// Builds (and caches) the verifying key and checks it against [`VERIFYING_KEY_FINGERPRINT`].
#[cfg(feature = "circuit")]
pub fn check_verifying_key() -> Result<(), String> {
    let got = verifying_key().fingerprint();
    if got == VERIFYING_KEY_FINGERPRINT {
        Ok(())
    } else {
        Err(format!(
            "the Orchard verifying key this build constructs ({}) is not the chain's ({}); {}",
            got.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            VERIFYING_KEY_FINGERPRINT.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            circuit_identity()
        ))
    }
}

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
