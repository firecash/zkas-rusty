//! Wallet-side shielded transaction construction — the prover, the inverse of
//! [`crate::verify`] (PLAN §2.10 / §3 wallet).
//!
//! This is what *produces* a shielded transaction: it derives keys, builds an
//! Orchard bundle, creates the Halo 2 proof, and signs the binding + spend-auth
//! signatures over the ZKas sighash — emitting a [`ShieldedBundle`] in our
//! canonical wire format, ready to carry in a transaction payload and be
//! accepted by the consensus verifier.
//!
//! The whole module requires the `circuit` feature (proving needs the proving
//! key). Proving is the heavy operation; PLAN §2.10 anticipates GPU-assisted and
//! delegated proving for light wallets — by Orchard's key separation, a delegated
//! prover never gains spend authority. This module is the local-proving core.

/// Wallet scanning — the receive side (§2.10). Trial-decrypts a bundle's outputs
/// with an incoming viewing key to recover notes sent to the holder. Pure
/// decryption; no proving circuit required, so this is available without the
/// `circuit` feature. (Under mandatory privacy, everyone always scans — this is
/// the hot path a light-wallet indexer accelerates.)
pub mod scan {
    use crate::bundle::{ActionWire, ShieldedBundle};
    use group::GroupEncoding;
    use orchard::{
        Action,
        keys::{Diversifier, FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext},
        note_encryption::{CompactAction, OrchardDomain},
        primitives::redpallas::{Signature, SpendAuth, VerificationKey},
        value::{NoteValue, ValueCommitment},
    };
    use pasta_curves::pallas;
    use zcash_note_encryption::{EphemeralKeyBytes, batch};

    /// A note recovered from a bundle: which action carried it (its position
    /// offset within the block's outputs, needed to build a witness later) and
    /// the recovered [`Note`], which the wallet can subsequently spend.
    #[derive(Clone)]
    pub struct ReceivedNote {
        /// Index of the action within the bundle that carried this output.
        pub action_index: usize,
        /// The recovered note (spendable via `wallet::build_spend_bundle`).
        pub note: Note,
        /// The output's memo, trimmed ([`trim_memo`]); empty = no memo.
        pub memo: Vec<u8>,
    }

    impl ReceivedNote {
        /// The note's value in the base unit.
        pub fn value(&self) -> u64 {
            self.note.value().inner()
        }
    }

    /// Derive an external incoming viewing key from a wallet seed.
    pub fn ivk_from_seed(seed: [u8; 32]) -> Option<IncomingViewingKey> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        Some(FullViewingKey::from(&sk).to_ivk(Scope::External))
    }

    /// Derive the raw 43-byte external Orchard address for a wallet seed — the
    /// bytes a miner puts in a shielded-coinbase reward's `script_public_key` so
    /// consensus pays the block reward to this wallet as a coinbase note (§2.7).
    pub fn address_bytes_from_seed(seed: [u8; 32]) -> Option<[u8; 43]> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        Some(FullViewingKey::from(&sk).address_at(0u32, Scope::External).to_raw_address_bytes())
    }

    /// Strip a memo to its meaningful bytes: trailing zeros go (our builders
    /// zero-fill), and the Zcash "no memo" marker (a lone leading `0xF6`) reads
    /// as empty too.
    pub fn trim_memo(memo: &[u8]) -> Vec<u8> {
        let end = memo.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let trimmed = &memo[..end];
        if trimmed == [0xf6] { Vec::new() } else { trimmed.to_vec() }
    }

    /// Reconstruct an Orchard action from its wire form (auth = its spend-auth
    /// signature). Returns `None` if any field is malformed (such an action can
    /// carry no note for us). This mirrors the verifier's reconstruction and thus
    /// enforces the identity `rk`/`epk` rules via `Action::from_parts`. Crate-public:
    /// `walletdb`'s history recorder reuses it for OVK output recovery.
    pub(crate) fn reconstruct_action(a: &ActionWire) -> Option<Action<Signature<SpendAuth>>> {
        let nf: Nullifier = Option::from(Nullifier::from_bytes(&a.nullifier))?;
        let rk = VerificationKey::<SpendAuth>::try_from(a.rk).ok()?;
        let cmx: ExtractedNoteCommitment = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx))?;
        let cv: ValueCommitment = Option::from(ValueCommitment::from_bytes(&a.cv_net))?;
        let ct = TransmittedNoteCiphertext {
            epk_bytes: a.ephemeral_key,
            enc_ciphertext: a.enc_ciphertext,
            out_ciphertext: a.out_ciphertext,
        };
        let sig = Signature::<SpendAuth>::from(a.spend_auth_sig);
        Action::from_parts(nf, rk, cmx, ct, cv, sig).ok()
    }

    /// Scan a bundle with an incoming viewing key, returning every note addressed
    /// to the key's holder (trial decryption, §2.10). Convenience wrapper that
    /// prepares the ivk on each call; callers scanning many bundles (the wallet
    /// sync loop) should prepare once and use [`scan_bundle_prepared`].
    pub fn scan_bundle(ivk: &IncomingViewingKey, bundle: &ShieldedBundle) -> Vec<ReceivedNote> {
        scan_bundle_prepared(&ivk.prepare(), bundle)
    }

    /// Trial-decrypt a bundle with an **already-prepared** ivk, batching the
    /// per-action `epk^ivk` Diffie–Hellman across all of the bundle's actions.
    ///
    /// Two wins over the naive per-action loop:
    /// - The ivk precomputation ([`IncomingViewingKey::prepare`]) is done **once**
    ///   by the caller and reused for every bundle in a scan, instead of per bundle.
    /// - [`zcash_note_encryption::batch::try_note_decryption`] shares one batched
    ///   ephemeral-key preparation (`batch_epk`) across every action, so the field
    ///   inversion that dominates each trial decryption is amortized (Montgomery's
    ///   trick) instead of paid per action. This is the same primitive Zcash's
    ///   light-client batch scanner uses.
    ///
    /// Recovery semantics are byte-for-byte identical to the per-action path: the
    /// batch returns one result per output, in input order, so each recovered note
    /// is mapped back to the exact action index it came from.
    pub fn scan_bundle_prepared(prepared: &PreparedIncomingViewingKey, bundle: &ShieldedBundle) -> Vec<ReceivedNote> {
        // Reconstruct the valid actions, remembering each one's original index (a
        // malformed action carries no note for us and is simply skipped, exactly as
        // in the per-action path).
        let mut idx_map: Vec<usize> = Vec::with_capacity(bundle.actions.len());
        let mut outputs: Vec<(OrchardDomain, Action<Signature<SpendAuth>>)> = Vec::with_capacity(bundle.actions.len());
        for (i, a) in bundle.actions.iter().enumerate() {
            let Some(action) = reconstruct_action(a) else { continue };
            let domain = OrchardDomain::for_action(&action);
            idx_map.push(i);
            outputs.push((domain, action));
        }
        if outputs.is_empty() {
            return Vec::new();
        }
        // One ivk, many outputs: the returned Vec has the same length and order as
        // `outputs`, each entry `Some(((note, _addr, _memo), ivk_index))` on a hit.
        let results = batch::try_note_decryption(std::slice::from_ref(prepared), &outputs);
        let mut received = Vec::new();
        for (pos, r) in results.into_iter().enumerate() {
            if let Some(((note, _addr, memo), _ivk_index)) = r {
                received.push(ReceivedNote { action_index: idx_map[pos], note, memo: trim_memo(&memo) });
            }
        }
        received
    }

    // ---- Compact scan records (ZKas compact block; ZIP-307 / lightwalletd style) ----

    /// One shielded action in **compact** form — the 148 bytes a receiver needs to
    /// trial-decrypt and, on a hit, reconstruct a *spendable* note: the nullifier
    /// (which is also the output note's `rho`), the note commitment (its tree leaf),
    /// the ephemeral key, and the 52-byte compact note-ciphertext prefix. It carries
    /// no proof, spend-auth signature, or value commitment — none of which a receiver
    /// needs — so it is ~4.7% of a full action (148 B vs ~3,156 B). This is the unit
    /// of the node's pruning-survivable shielded scan archive, mirroring a Zcash
    /// light-client `CompactOutput`. What is NOT recoverable from it is the memo
    /// (that lives in the full 580-byte ciphertext); value and spendability are.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct CompactActionRecord {
        pub nullifier: [u8; 32],
        pub cmx: [u8; 32],
        pub ephemeral_key: [u8; 32],
        pub enc_ciphertext: [u8; 52],
    }

    impl CompactActionRecord {
        /// Serialized size: nullifier + cmx + epk + compact ciphertext = 148 bytes.
        pub const SERIALIZED_LEN: usize = 32 + 32 + 32 + 52;

        /// Distill a full action wire down to its compact record — what the node
        /// keeps in the scan archive once the full block body (proof, sigs) can be
        /// pruned. Reads only fields a receiver uses, so it can never drift from the
        /// bundle it came from.
        pub fn from_wire(a: &ActionWire) -> Self {
            let mut enc_ciphertext = [0u8; 52];
            enc_ciphertext.copy_from_slice(&a.enc_ciphertext[..52]);
            Self { nullifier: a.nullifier, cmx: a.cmx, ephemeral_key: a.ephemeral_key, enc_ciphertext }
        }

        /// Fixed-layout encoding for the consensus scan-archive store.
        pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
            let mut out = [0u8; Self::SERIALIZED_LEN];
            out[0..32].copy_from_slice(&self.nullifier);
            out[32..64].copy_from_slice(&self.cmx);
            out[64..96].copy_from_slice(&self.ephemeral_key);
            out[96..148].copy_from_slice(&self.enc_ciphertext);
            out
        }

        /// Decode a 148-byte record; `None` on a wrong-length slice.
        pub fn from_bytes(b: &[u8]) -> Option<Self> {
            if b.len() != Self::SERIALIZED_LEN {
                return None;
            }
            let mut nullifier = [0u8; 32];
            let mut cmx = [0u8; 32];
            let mut ephemeral_key = [0u8; 32];
            let mut enc_ciphertext = [0u8; 52];
            nullifier.copy_from_slice(&b[0..32]);
            cmx.copy_from_slice(&b[32..64]);
            ephemeral_key.copy_from_slice(&b[64..96]);
            enc_ciphertext.copy_from_slice(&b[96..148]);
            Some(Self { nullifier, cmx, ephemeral_key, enc_ciphertext })
        }

        /// Reconstruct the orchard [`CompactAction`] for trial decryption. `None`
        /// if the nullifier or commitment is not a canonical encoding.
        fn to_compact_action(&self) -> Option<CompactAction> {
            let nf = Option::from(Nullifier::from_bytes(&self.nullifier))?;
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&self.cmx))?;
            Some(CompactAction::from_parts(nf, cmx, EphemeralKeyBytes(self.ephemeral_key), self.enc_ciphertext))
        }
    }

    /// Trial-decrypt a sequence of compact action records with an already-prepared
    /// ivk, recovering exactly the receiver's notes — identical to
    /// [`scan_bundle_prepared`] but from 148-byte records carrying no proof or
    /// signatures. Memos are not carried in compact form, so [`ReceivedNote::memo`]
    /// is empty here; value and spendability are fully recovered. This is the scan
    /// path over the node's compact shielded archive.
    /// The process-wide GPU backend, installed once by the daemon at startup.
    ///
    /// A hook rather than a parameter so that every existing ingest path picks the
    /// device up without threading a handle through code that has no business knowing
    /// about GPUs. Unset (the default, and every non-GPU host) means the CPU path, and
    /// the results are identical either way.
    type AgreeFn = dyn Fn(&pallas::Scalar, &[Option<pallas::Point>]) -> Option<Vec<Option<pallas::Affine>>> + Send + Sync;
    static GPU_AGREE: std::sync::OnceLock<Box<AgreeFn>> = std::sync::OnceLock::new();

    /// Install the device backend. Idempotent; the first call wins.
    pub fn install_gpu_agree(f: Box<AgreeFn>) {
        let _ = GPU_AGREE.set(f);
    }

    /// Whether a device backend is installed.
    pub fn gpu_enabled() -> bool {
        GPU_AGREE.get().is_some()
    }

    /// Trial-decrypt compact records, on the device when one is installed.
    ///
    /// The GPU path is a filter whose verdicts still come from orchard (see
    /// [`scan_compact_gpu`]); if it declines for any reason the CPU path runs and the
    /// caller cannot tell the difference except in speed.
    pub fn scan_compact_prepared(prepared: &PreparedIncomingViewingKey, actions: &[CompactActionRecord]) -> Vec<ReceivedNote> {
        scan_compact_cpu(prepared, actions)
    }

    /// Trial-decrypt on the device when one is installed, else on the CPU.
    ///
    /// Takes the agreement scalar explicitly rather than digging it out of a
    /// `PreparedIncomingViewingKey` (which does not expose it) or stashing it in a
    /// thread-local. The caller already holds the viewing key, so it can derive the
    /// scalar once — see [`ivk_agreement_scalar`] — and the dependency stays visible in
    /// the signature instead of hiding in ambient state.
    pub fn scan_compact_auto(
        prepared: &PreparedIncomingViewingKey,
        agree_scalar: Option<&pallas::Scalar>,
        actions: &[CompactActionRecord],
    ) -> Vec<ReceivedNote> {
        // Below this, the device is not worth asking — measured against the code that
        // would otherwise run, which is the correction that matters here.
        //
        // The old threshold (256) came from comparing the GPU with `cpu_batch_agree`, a
        // naive single-threaded `p * ivk` at ~192 us/pt. The daemon would never run that:
        // orchard uses a PREPARED-Wnaf multiply (74.98 us/pt) and the path below spreads
        // it over every core. So the honest baseline is ~15-17 us/pt, and the device has
        // to clear a bar an order of magnitude higher than the one it was calibrated on.
        //
        // Re-measured on an RTX 2080 Ti against parallel prepared-Wnaf on 12 threads:
        //
        //     batch      500    1000    2000    4000    8000   16000   32000
        //     GPU      32.05   13.68    7.06    3.93    2.52    2.95    2.87  us/pt
        //     CPU-par  16.06   15.70   15.41   18.01   16.79   15.19   17.13  us/pt
        //     GPU wins    NO   1.15x   2.18x   4.58x   6.65x   5.14x   5.96x
        //
        // The shape is not a fixed launch overhead, which is what I first assumed. It is
        // the LATENCY OF ONE LADDER: ~12 ms, flat from n=2 all the way to n=1000, and
        // only growing once n passes the device's core count, in waves. A quarter-full
        // device costs the same wall-clock as a full one.
        //
        // Hence 256 — restored to the value that actually measured fastest end to end.
        //
        // I raised this to 2048, then 32768, chasing a per-batch table that said bigger
        // batches suit the device. Both made the live daemon SLOWER, and a user watching
        // a scan reported the estimate climbing. The table was measured with ONE caller;
        // the daemon runs 8 wallets against a device held by a single global mutex
        // (`g_lock` in pallas.cu), so per-call efficiency and end-to-end throughput are
        // different questions and only the second one matters.
        //
        // End-to-end, cold wallet from birthday 0, only this and the page size changing:
        //
        //     256  + page 1000    2,219 blocks/s   <- fastest, restored
        //     2048 + page 2000      892 blocks/s
        //
        // The lesson is not about a number. Every time this constant moved on the
        // strength of a microbenchmark it got worse, and every regression was visible in
        // the live counters within minutes. Change it only against a cold-scan blocks/s
        // measurement, and only with no unrelated test wallets syncing.
        const GPU_MIN_BATCH: usize = 256;

        if actions.len() >= GPU_MIN_BATCH {
            if let (Some(f), Some(sc)) = (GPU_AGREE.get(), agree_scalar) {
                if let Some(found) = scan_compact_gpu(prepared, actions, |epks| f(sc, epks)) {
                    return found;
                }
            }
        }

        // No device (or too small a batch): spread the batch across cores. Trial
        // decryption is per-action independent — one key agreement, one KDF, one
        // ChaCha20 — so it parallelises cleanly, and it is now ~99% of a scan's cost.
        //
        // Only worth the split when there is enough to divide: below this the rayon
        // fork/join costs more than the work, which is the same mistake the GPU guard
        // above exists to prevent. `action_index` is restored to be page-relative so
        // callers cannot tell the batch was split.
        const PAR_MIN_BATCH: usize = 512;
        if actions.len() >= PAR_MIN_BATCH {
            use rayon::prelude::*;
            let chunk = (actions.len() / rayon::current_num_threads().max(1)).max(128);
            return actions
                .par_chunks(chunk)
                .enumerate()
                .flat_map_iter(|(ci, part)| {
                    let base = ci * chunk;
                    scan_compact_cpu(prepared, part).into_iter().map(move |mut n| {
                        n.action_index += base;
                        n
                    })
                })
                .collect();
        }
        scan_compact_cpu(prepared, actions)
    }

    /// The CPU path: orchard's batch API, unchanged. Also what the GPU filter uses to
    /// confirm its candidates, which is why it is separate — calling the public entry
    /// point there would recurse.
    pub fn scan_compact_cpu(prepared: &PreparedIncomingViewingKey, actions: &[CompactActionRecord]) -> Vec<ReceivedNote> {
        let mut idx_map: Vec<usize> = Vec::with_capacity(actions.len());
        let mut outputs: Vec<(OrchardDomain, CompactAction)> = Vec::with_capacity(actions.len());
        for (i, rec) in actions.iter().enumerate() {
            let Some(ca) = rec.to_compact_action() else { continue };
            let domain = OrchardDomain::for_compact_action(&ca);
            idx_map.push(i);
            outputs.push((domain, ca));
        }
        if outputs.is_empty() {
            return Vec::new();
        }
        let results = batch::try_compact_note_decryption(std::slice::from_ref(prepared), &outputs);
        let mut received = Vec::new();
        for (pos, r) in results.into_iter().enumerate() {
            if let Some(((note, _addr), _ivk_index)) = r {
                received.push(ReceivedNote { action_index: idx_map[pos], note, memo: Vec::new() });
            }
        }
        received
    }

    /// The raw key-agreement scalar behind an incoming viewing key, so the Pallas
    /// multiplication can be handed to a device.
    ///
    /// `IncomingViewingKey::to_bytes()` is public and its second 32 bytes are exactly
    /// that scalar, canonical little-endian. Orchard stores it as a base-field element
    /// and uses it as a group scalar; that reinterpretation is exact here because
    /// Pallas's base modulus is SMALLER than its scalar modulus, so every base-field
    /// element is already a valid scalar with the same integer value. (If that were
    /// ever false the value would silently wrap and no note would ever be found — which
    /// is precisely what `gpu_scan_path_finds_exactly_what_orchard_finds` would catch,
    /// since it recovers a real note end to end.)
    ///
    /// This exposes nothing new: any caller holding the viewing key already holds this.
    pub fn ivk_agreement_scalar(ivk: &IncomingViewingKey) -> Option<pallas::Scalar> {
        use group::ff::PrimeField;
        let b = ivk.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&b[32..64]);
        Option::from(pallas::Scalar::from_repr(s))
    }

    /// GPU-assisted trial decryption: identical results to
    /// [`scan_compact_prepared`], with the Pallas key agreement done on a device.
    ///
    /// # How, and why it is safe
    ///
    /// This is a FILTER, not a reimplementation of note decryption. For every action it
    /// does the cheap half — key agreement (on the GPU), the Orchard KDF, and the
    /// ChaCha20 keystream — and then looks at ONE byte: the note-plaintext version.
    /// Orchard writes `0x02` there for every note it produces, so any action that is
    /// genuinely ours must show `0x02`. Everything that survives is handed to orchard's
    /// own `try_compact_note_decryption`, which decides.
    ///
    /// The correctness argument is therefore short: the filter's condition is implied
    /// by orchard's, so the set it passes through is a SUPERSET of orchard's. It cannot
    /// miss a note — the only failure that matters, since a missed note is a user's
    /// coins appearing to vanish. False positives cost nothing: orchard discards them,
    /// and at one byte of discrimination only ~1 action in 256 survives by chance.
    ///
    /// That ratio is also where the speed comes from. The expensive part of orchard's
    /// path is the key agreement, and this skips it for ~255 of every 256 actions —
    /// which is why the gain is not bounded by the share the key agreement takes.
    ///
    /// Deliberately reconstructs NO note and derives NO address: those need orchard
    /// internals, and needing none of them is what keeps this a filter rather than a
    /// second implementation of consensus-adjacent cryptography.
    ///
    /// Returns `None` if the device could not answer, and the caller uses the CPU path.
    pub fn scan_compact_gpu(
        prepared: &PreparedIncomingViewingKey,
        actions: &[CompactActionRecord],
        agree: impl FnOnce(&[Option<pallas::Point>]) -> Option<Vec<Option<pallas::Affine>>>,
    ) -> Option<Vec<ReceivedNote>> {
        use blake2b_simd::Params;
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

        if actions.is_empty() {
            return Some(Vec::new());
        }
        // An ephemeral key that is not a valid encoding can never yield a note; it is
        // carried as `None` so positions stay aligned with `actions`.
        // Decompressing an ephemeral key is CURVE ARITHMETIC, not parsing.
        //
        // `from_bytes` recovers y from x, which needs a modular square root — an
        // exponentiation costing 6.79 us/action measured, versus 0.15 for the KDF and
        // 0.12 for ChaCha20. It was running serially on one core here, immediately
        // before handing the batch to a device, which is the same mistake as the serial
        // filter below it: offload one half of the curve work and leave the other half
        // single-threaded.
        //
        // I had reported the non-agreement cost as a ~26.7 us/action "floor" for the
        // hash and cipher. That figure was a residual (105.6 - 78.87), never a
        // measurement, and measuring it directly showed the hash and cipher are 1% of
        // it. Decompression is the part that was real.
        let decompress = |r: &CompactActionRecord| {
            Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&r.ephemeral_key)).map(pallas::Point::from)
        };
        const DECOMPRESS_PAR_MIN: usize = 512;
        let epks: Vec<Option<pallas::Point>> = if actions.len() >= DECOMPRESS_PAR_MIN {
            use rayon::prelude::*;
            actions.par_iter().map(decompress).collect()
        } else {
            actions.iter().map(decompress).collect()
        };

        let secrets = agree(&epks)?;
        if secrets.len() != actions.len() {
            return None;
        }

        // The filter below is per-action independent, so it runs across cores.
        //
        // This mattered more than the device did. Handing the key agreement to the GPU
        // made that part nearly free (74.98 -> ~3.1 us/action) but left the KDF and
        // ChaCha20 — the other 25% — running SERIALLY on one core, and this function
        // returns before it can ever reach the rayon path below. So the whole GPU win
        // was capped by the one piece still single-threaded: 3.1 + 26.7 = 29.8 us/action
        // predicted, against 31.4 measured live. The device was waiting on a for-loop.
        let filter = |i: usize, rec: &CompactActionRecord, secret: &Option<pallas::Affine>| -> Option<usize> {
            let secret = secret.as_ref()?;
            // The Orchard KDF, exactly as the spec defines it (§5.4.5.6): BLAKE2b-256
            // personalised "Zcash_OrchardKDF" over the affine shared secret then the
            // ephemeral key bytes.
            let key = Params::new()
                .hash_length(32)
                .personal(b"Zcash_OrchardKDF")
                .to_state()
                .update(&secret.to_bytes())
                .update(&rec.ephemeral_key)
                .finalize();
            // ChaCha20, zero nonce, SEEKED TO BYTE 64 — block 0 is the Poly1305 keying
            // output and is skipped. Spelled out because getting it wrong decrypts to
            // noise and then silently finds nothing at all.
            let mut pt = rec.enc_ciphertext;
            let mut cipher = chacha20::ChaCha20::new(key.as_bytes().into(), &[0u8; 12].into());
            cipher.seek(64u32);
            cipher.apply_keystream(&mut pt);
            (pt[0] == 0x02).then_some(i)
        };

        // Same threshold reasoning as the CPU path: below this the fork/join costs more
        // than the work. `collect` on an indexed parallel iterator preserves order, so
        // `candidates` stays ascending either way — which the index remap below needs.
        const FILTER_PAR_MIN: usize = 512;
        let candidates: Vec<usize> = if actions.len() >= FILTER_PAR_MIN {
            use rayon::prelude::*;
            actions
                .par_iter()
                .zip(secrets.par_iter())
                .enumerate()
                .filter_map(|(i, (rec, secret))| filter(i, rec, secret))
                .collect()
        } else {
            actions
                .iter()
                .zip(secrets.iter())
                .enumerate()
                .filter_map(|(i, (rec, secret))| filter(i, rec, secret))
                .collect()
        };

        if candidates.is_empty() {
            return Some(Vec::new());
        }
        // Orchard decides. Whatever this function returns is its verdict, not ours.
        let subset: Vec<CompactActionRecord> = candidates.iter().map(|&i| actions[i]).collect();
        Some(
            scan_compact_cpu(prepared, &subset)
                .into_iter()
                .map(|mut n| {
                    n.action_index = candidates[n.action_index];
                    n
                })
                .collect(),
        )
    }

    /// Convenience wrapper that prepares the ivk once (see [`scan_compact_prepared`]).
    pub fn scan_compact(ivk: &IncomingViewingKey, actions: &[CompactActionRecord]) -> Vec<ReceivedNote> {
        scan_compact_prepared(&ivk.prepare(), actions)
    }
}

pub use scan::{
    CompactActionRecord, ReceivedNote, address_bytes_from_seed, gpu_enabled, install_gpu_agree, ivk_agreement_scalar, ivk_from_seed,
    scan_bundle, scan_bundle_prepared, scan_compact, scan_compact_auto, scan_compact_cpu, scan_compact_gpu,
    scan_compact_prepared, trim_memo,
};

#[cfg(feature = "circuit")]
pub mod build {
    use crate::bundle::{ActionWire, ShieldedBundle};
    use crate::verify::sighash;
    use orchard::{
        Action, Address, Anchor, Bundle,
        builder::{Builder, BundleType},
        bundle::{Authorization, Authorized},
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{ExtractedNoteCommitment, Note},
        primitives::redpallas::{Signature, SpendAuth},
        tree::MerklePath,
        value::NoteValue,
    };
    use pasta_curves::pallas;
    use rand_core::{CryptoRng, RngCore};
    use std::sync::OnceLock;

    pub use crate::payment_check::{ActionDisclosure, PaymentCheckError, check_prepared_payment};

    /// The process-wide Orchard [`ProvingKey`], built once and reused.
    ///
    /// `ProvingKey::build(crate::verify::CIRCUIT_VERSION)` is a multi-minute Halo 2 keygen; rebuilding it per
    /// payment (as the wallet builders originally did) dominated every send —
    /// live pool payouts measured ~5 minutes each, almost all of it keygen.
    /// The key is deterministic and read-only, so one shared instance serves
    /// every proof for the life of the process. Callers that want to hide the
    /// one-time cost can invoke this at startup from a background thread.
    pub fn proving_key() -> &'static ProvingKey {
        static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
        PROVING_KEY.get_or_init(|| ProvingKey::build(crate::verify::CIRCUIT_VERSION))
    }

    /// A wallet's Orchard keys, derived from a 32-byte seed.
    pub struct ShieldedKeys {
        sk: SpendingKey,
        fvk: FullViewingKey,
    }

    impl ShieldedKeys {
        /// Derive keys from a seed. Returns `None` if the seed is not a valid
        /// Orchard spending key (negligibly rare).
        pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
            let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
            let fvk = FullViewingKey::from(&sk);
            Some(Self { sk, fvk })
        }

        /// The wallet's default external receiving address.
        pub fn address(&self) -> Address {
            self.fvk.address_at(0u32, Scope::External)
        }
    }

    /// Errors building a shielded bundle.
    #[derive(Debug)]
    pub enum BuildError {
        /// The Orchard bundle builder failed (e.g. unsatisfiable bundle type).
        Builder(String),
        /// Proof creation failed.
        Proof(String),
        /// The builder produced no bundle (nothing to spend or output).
        Empty,
    }

    /// Serialize an authorized/proven Orchard bundle into our wire format, using
    /// `spend_auth_sig` to extract each action's signature (zeroed before signing)
    /// and the given bundle-level `proof` / `binding_sig`.
    pub fn to_wire<T: Authorization>(
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

    /// Build an **output-only** shielded bundle that mints `value` to
    /// `recipient` (spends disabled — the coinbase / value-entry case, §2.7), with
    /// a real proof and signatures over the sighash derived from `tx_context`.
    ///
    /// Output-only bundles have a negative `value_balance` (value enters the
    /// pool); they balance under the binding signature exactly as any bundle.
    pub fn build_output_only_bundle(
        pk: &ProvingKey,
        recipient: Address,
        value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, Anchor::empty_tree()).expect("orchard v2 ENABLED flags are always representable");
        builder
            .add_output(None, recipient, NoteValue::from_raw(value), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        // Compute the sighash over the effects (proof/sigs excluded), then sign.
        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// Build a **spending** shielded transaction: spend `note` (with its
    /// `merkle_path` proving membership at the anchor it roots to) and send
    /// `output_value` to `recipient`. The remainder, `note.value −
    /// output_value`, becomes the public fee (`value_balance`), collected by the
    /// miner. Proven and signed (with the real spend authority) over the sighash.
    ///
    /// The wallet is responsible for tracking each note's `merkle_path` witness as
    /// the global tree finalizes (PLAN §2.5/§2.10); here it is supplied.
    pub fn build_spend_bundle(
        pk: &ProvingKey,
        keys: &ShieldedKeys,
        note: Note,
        merkle_path: MerklePath,
        recipient: Address,
        output_value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        // The anchor is the root the supplied path proves the note into.
        let anchor = merkle_path.root(ExtractedNoteCommitment::from(note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).expect("orchard v2 ENABLED flags are always representable");
        builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        builder
            .add_output(None, recipient, NoteValue::from_raw(output_value), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        // The real spend is authorized with the spend authorizing key.
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// Build a **payment** shielded transaction with change: spend `note`, pay
    /// `amount` to `recipient`, return the remainder minus `fee` to `change_addr`
    /// (the sender's own address), and leave `fee` as the public `value_balance`
    /// collected by the miner. This is the real wallet spend shape — unlike
    /// [`build_spend_bundle`], the sender keeps the change instead of burning it
    /// into an oversized fee.
    ///
    /// Requires `note.value == amount + change + fee`; the caller (the wallet
    /// facade) sizes `change` from the selected note. Proven and signed with the
    /// sender's spend authority over the sighash.
    #[allow(clippy::too_many_arguments)]
    pub fn build_payment_bundle(
        pk: &ProvingKey,
        keys: &ShieldedKeys,
        note: Note,
        merkle_path: MerklePath,
        recipient: Address,
        amount: u64,
        change_addr: Address,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        let change = note.value().inner().checked_sub(amount).and_then(|v| v.checked_sub(fee)).ok_or(BuildError::Empty)?;

        let anchor = merkle_path.root(ExtractedNoteCommitment::from(note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).expect("orchard v2 ENABLED flags are always representable");
        builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        builder
            .add_output(None, recipient, NoteValue::from_raw(amount), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        // The change output back to the sender keeps the remainder shielded. Even a
        // zero-value change output is a real note, preserving a uniform 2-output
        // shape (better for privacy than a variable output count).
        builder
            .add_output(None, change_addr, NoteValue::from_raw(change), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// End-to-end wallet helper: build a real, proven spend of a coinbase note
    /// that is the SINGLE leaf (position 0) of the finalized global tree, and
    /// return the shielded-bundle wire bytes ready to drop into a version-2
    /// transaction's `payload`.
    ///
    /// The note is reconstructed from its public coinbase description exactly as
    /// consensus recomputes it (`derive_coinbase_note_desc` over
    /// `coinbase_txid || out_index`), so the wallet and consensus agree on the
    /// commitment. The witness is the single-leaf authentication path, so the
    /// bundle's anchor equals the minting block's (finalized) anchor. Builds its
    /// own `ProvingKey`; this is a heavy call (real Halo 2 proof).
    #[allow(clippy::too_many_arguments)]
    pub fn build_singleleaf_coinbase_spend(
        owner_seed: [u8; 32],
        coinbase_txid: [u8; 32],
        out_index: u32,
        note_value: u64,
        recipient_addr: [u8; 43],
        output_value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        use crate::coinbase::derive_coinbase_note_desc;
        use incrementalmerkletree::{Hashable, Level};
        use orchard::note::{RandomSeed, Rho};
        use orchard::tree::MerkleHashOrchard;

        let keys = ShieldedKeys::from_seed(owner_seed).ok_or(BuildError::Empty)?;

        // Reconstruct the coinbase note deterministically (same derivation consensus uses).
        let mut seed = Vec::with_capacity(36);
        seed.extend_from_slice(&coinbase_txid);
        seed.extend_from_slice(&out_index.to_le_bytes());
        let desc = derive_coinbase_note_desc(keys.address().to_raw_address_bytes(), &seed);
        let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho)).ok_or(BuildError::Empty)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho)).ok_or(BuildError::Empty)?;
        let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(note_value), rho, rseed, orchard::note::NoteVersion::V2))
            .ok_or(BuildError::Empty)?;

        // Single-leaf witness: position 0, siblings are the empty-subtree roots.
        let auth_path: [MerkleHashOrchard; 32] =
            core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
        let merkle_path = MerklePath::from_parts(0, auth_path);

        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient_addr)).ok_or(BuildError::Empty)?;
        let pk = proving_key();
        let wire =
            build_spend_bundle(pk, &keys, note, merkle_path, recipient, output_value, network_domain, tx_context, rand::rng())?;
        Ok(wire.to_bytes())
    }

    /// End-to-end wallet payment spending one or more **arbitrary** owned notes
    /// (PLAN §2.10): spend every `(note, merkle_path)` in `inputs`, pay `amount` to
    /// `recipient_addr`, return the remainder minus `fee` as change to the sender,
    /// and leave `fee` as the public value balance. Returns the shielded-bundle wire
    /// bytes ready to drop into a version-2 transaction `payload`.
    ///
    /// All inputs must root to the **same finalized anchor** — the caller (a
    /// [`crate::walletdb::WalletDb`]) supplies live witnesses taken at one tree
    /// state, so this holds. Every spend is authorized by the sender's single spend
    /// authority. Builds its own `ProvingKey`; heavy (a real Halo 2 proof whose cost
    /// grows with the number of inputs).
    /// Every output's details are encrypted to the sender's own OVK (Zcash-standard),
    /// so the wallet's chain-derived history — on any device holding the full viewing
    /// key — can recover the recipient/amount/memo of this send after a restore.
    /// `recoverable` is retained for API compatibility and no longer switches this off
    /// (an unrecoverable send helped nobody: not even the sender could see who was
    /// paid). `memo` rides in the recipient's encrypted note (zeros = no memo).
    #[allow(clippy::too_many_arguments)]
    pub fn build_wallet_payment(
        owner_seed: [u8; 32],
        inputs: Vec<(Note, MerklePath)>,
        recipient_addr: [u8; 43],
        amount: u64,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        recoverable: bool,
        memo: [u8; 512],
    ) -> Result<Vec<u8>, BuildError> {
        build_wallet_payment_multi(owner_seed, inputs, &[(recipient_addr, amount, memo)], fee, network_domain, tx_context, recoverable)
    }

    /// As [`build_wallet_payment`], but paying **several recipients from one
    /// transaction**.
    ///
    /// A payout run — a mining pool crediting its miners — otherwise costs one bundle
    /// per payee: one Halo 2 proof, one witness set and one relay fee each, serially.
    /// Batched, the whole run costs one. An Orchard bundle carries
    /// `max(spends, outputs)` actions, so `k` payees means `k + 1` outputs (the payees
    /// plus change) and therefore at least `k + 1` actions — the caller plans against
    /// the same standard-mass ceiling it already uses for spends.
    ///
    /// Each payee's note is encrypted to that payee alone, so recipients learn nothing
    /// about each other's amounts; the sender's own OVK can always recover the batch
    /// (`recoverable` is retained for API compatibility only). Fails if `payees` is empty, if
    /// any address is malformed, or if the inputs do not cover `sum(amounts) + fee`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_wallet_payment_multi(
        owner_seed: [u8; 32],
        inputs: Vec<(Note, MerklePath)>,
        payees: &[([u8; 43], u64, [u8; 512])],
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        recoverable: bool,
    ) -> Result<Vec<u8>, BuildError> {
        let (first_note, first_path) = inputs.first().ok_or(BuildError::Empty)?;
        if payees.is_empty() {
            return Err(BuildError::Empty);
        }
        let keys = ShieldedKeys::from_seed(owner_seed).ok_or(BuildError::Empty)?;
        let change_addr = keys.address();
        // ALWAYS encrypt outputs to the sender's own external OVK (Zcash-standard). Only a
        // holder of this wallet's full viewing key can read them, so nothing leaks to the
        // chain — and a view-only copy of the wallet (another device, an auditor, the
        // owner after a restore) can recover where every send went. Sends built without
        // it were unrecoverable by ANYONE, forever, which is what a "view key wallet shows
        // no destination" report turned out to be. `recoverable` is kept for API
        // compatibility; it no longer changes the encryption.
        let _ = recoverable;
        let ovk = Some(keys.fvk.to_ovk(Scope::External));

        // Resolve every payee before touching the builder, so a malformed address
        // fails the whole batch rather than emitting a partial one.
        let mut paid: u64 = 0;
        let mut recipients = Vec::with_capacity(payees.len());
        for (addr, amount, memo) in payees {
            let r = Option::<Address>::from(Address::from_raw_address_bytes(addr)).ok_or(BuildError::Empty)?;
            paid = paid.checked_add(*amount).ok_or(BuildError::Empty)?;
            recipients.push((r, *amount, *memo));
        }

        let total_in: u64 = inputs.iter().map(|(n, _)| n.value().inner()).sum();
        let change = total_in.checked_sub(paid).and_then(|v| v.checked_sub(fee)).ok_or(BuildError::Empty)?;

        // The shared anchor: all supplied witnesses were taken at one tree state.
        let anchor = first_path.root(ExtractedNoteCommitment::from(first_note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).expect("orchard v2 ENABLED flags are always representable");
        for (note, merkle_path) in inputs {
            builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        }
        for (recipient, amount, memo) in recipients {
            builder
                .add_output(ovk.clone(), recipient, NoteValue::from_raw(amount), memo)
                .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        }
        builder
            .add_output(ovk, change_addr, NoteValue::from_raw(change), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let pk = proving_key();
        let mut rng = rand::rng();
        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        )
        .to_bytes())
    }

    // ============================================================================
    // Non-custodial payment: the Orchard prove/sign split as a reusable API.
    //
    // `prepare_payment` runs on a SERVER that holds only the full viewing key — it
    // builds the bundle, creates the Halo 2 proof, and signs any throwaway padding
    // dummies, but it CANNOT authorize the real spends. It hands the device a sighash
    // plus one randomizer per real spend. The device runs `sign_spend_auth` with the
    // spend key (which never leaves it) and returns signatures. `finalize_payment`
    // applies them and emits the wire bundle. The server never sees the spend key.
    // Proven end-to-end by `non_custodial_payment_api_roundtrip`.
    // ============================================================================

    /// A payment prepared by the server, awaiting on-device spend-auth signatures.
    pub struct PreparedPayment {
        pczt: orchard::pczt::Bundle,
        /// The 32-byte sighash the device signs.
        pub sighash: [u8; 32],
        /// The unsigned bundle (proof + effects, no spend-auth signatures) the device
        /// must verify and recompute the sighash from — never trust a supplied hash.
        pub effects: ShieldedBundle,
        /// Per-action plaintext so the device can check what it is authorizing
        /// ([`check_prepared_payment`]).
        pub disclosure: Vec<ActionDisclosure>,
        /// Public fee / value balance of the payment.
        pub value_balance: i64,
        /// One `(action_index, alpha)` per real spend the device must authorize.
        pub spend_auth_requests: Vec<(usize, [u8; 32])>,
    }

    /// SERVER role (viewing key + proving key only): build + prove a payment and sign
    /// its padding dummies. Returns the sighash and the per-spend randomizers the
    /// device must sign. Never sees the spend authority.
    /// `recoverable`/`memo`: see [`build_wallet_payment`].
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_payment(
        fvk: &FullViewingKey,
        inputs: Vec<(Note, MerklePath)>,
        recipient_addr: [u8; 43],
        amount: u64,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        recoverable: bool,
        memo: [u8; 512],
    ) -> Result<PreparedPayment, BuildError> {
        use group::ff::PrimeField;
        // Always the sender's own external OVK — see `build_wallet_payment_multi`.
        let _ = recoverable;
        let ovk = Some(fvk.to_ovk(Scope::External));

        let (first_note, first_path) = inputs.first().ok_or(BuildError::Empty)?;
        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient_addr)).ok_or(BuildError::Empty)?;
        let change_addr = fvk.address_at(0u32, Scope::External);
        let total_in: u64 = inputs.iter().map(|(n, _)| n.value().inner()).sum();
        let change = total_in.checked_sub(amount).and_then(|v| v.checked_sub(fee)).ok_or(BuildError::Empty)?;
        let anchor = first_path.root(ExtractedNoteCommitment::from(first_note.commitment()));

        let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).expect("orchard v2 ENABLED flags are always representable");
        for (note, merkle_path) in inputs {
            builder.add_spend(fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        }
        builder
            .add_output(ovk.clone(), recipient, NoteValue::from_raw(amount), memo)
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        if change > 0 {
            builder
                .add_output(ovk, change_addr, NoteValue::from_raw(change), [0u8; 512])
                .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        }

        let pk = proving_key();
        let mut rng = rand::rng();
        let (mut pczt, _meta) = builder.build_for_pczt(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        pczt.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = pczt.extract_effects::<i64>().map_err(|e| BuildError::Proof(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let value_balance = *effects.value_balance();
        let effects_wire = to_wire(&effects, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let sighash = crate::verify::sighash(&effects_wire, network_domain, tx_context);

        // Classify each action: throwaway dummy (server signs) vs real spend (device signs).
        let mut dummies: Vec<(usize, SpendingKey)> = Vec::new();
        let mut spend_auth_requests: Vec<(usize, [u8; 32])> = Vec::new();
        for (i, action) in pczt.actions().iter().enumerate() {
            let spend = action.spend();
            if let Some(sk) = spend.dummy_sk() {
                dummies.push((i, sk.clone()));
            } else if let Some(alpha) = spend.alpha() {
                spend_auth_requests.push((i, alpha.to_repr()));
            }
        }
        for (i, sk) in dummies {
            let ask = SpendAuthorizingKey::from(&sk);
            pczt.actions_mut()[i].sign(sighash, &ask, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;
        }

        // Disclose each action's plaintext so the device can verify the payment instead
        // of blind-signing a hash it cannot interpret.
        let mut disclosure = Vec::with_capacity(pczt.actions().len());
        for action in pczt.actions().iter() {
            let out = action.output();
            let spend = action.spend();
            disclosure.push(ActionDisclosure {
                spend_value: spend.value().map(|v| v.inner()).unwrap_or(0),
                out_value: out.value().ok_or(BuildError::Empty)?.inner(),
                out_recipient: out.recipient().ok_or(BuildError::Empty)?.to_raw_address_bytes(),
                out_rseed: *out.rseed().ok_or(BuildError::Empty)?.as_bytes(),
                rcv: action.rcv().clone().ok_or(BuildError::Empty)?.to_bytes(),
            });
        }

        Ok(PreparedPayment { pczt, sighash, effects: effects_wire, value_balance, spend_auth_requests, disclosure })
    }

    /// DEVICE role (spend key only): produce the RedPallas spend-auth signature for one
    /// real spend, from its `alpha` randomizer and the payment sighash.
    pub fn sign_spend_auth(ask: &SpendAuthorizingKey, alpha: [u8; 32], sighash: [u8; 32]) -> Option<[u8; 64]> {
        use group::ff::PrimeField;
        let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(alpha))?;
        let mut rng = rand::rng();
        let sig = ask.randomize(&alpha).sign(&mut rng, &sighash);
        Some(<[u8; 64]>::from(&sig))
    }

    /// SERVER role: apply the device's spend-auth signatures, finalize IO, and emit the
    /// verifiable wire bundle. Still never touches the spend key.
    pub fn finalize_payment(mut prepared: PreparedPayment, device_sigs: Vec<(usize, [u8; 64])>) -> Result<ShieldedBundle, BuildError> {
        let sighash = prepared.sighash;
        let mut rng = rand::rng();
        for (i, sig) in device_sigs {
            let sig = Signature::<SpendAuth>::from(sig);
            prepared.pczt.actions_mut()[i].apply_signature(sighash, sig).map_err(|e| BuildError::Proof(format!("{e:?}")))?;
        }
        prepared.pczt.finalize_io(sighash, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;
        let unbound = prepared.pczt.extract::<i64>().map_err(|e| BuildError::Proof(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let authorized = unbound.apply_binding_signature(sighash, &mut rng).ok_or_else(|| BuildError::Proof("binding".into()))?;
        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use incrementalmerkletree::{Hashable, Level};
        use orchard::{
            note::{RandomSeed, Rho},
            tree::MerkleHashOrchard,
        };

        fn canon(seed: u8) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0] = seed;
            b
        }

        /// The transfer loop: the wallet spends a note it owns and the consensus
        /// verifier accepts the resulting bundle. The note sits alone at position
        /// 0 of the tree, so its authentication path is the empty-subtree roots.
        #[test]
        fn wallet_spend_bundle_verifies() {
            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let keys = ShieldedKeys::from_seed([5u8; 32]).expect("valid seed");
            let ctx = b"zkas-spend";

            // A note worth 10_000 owned by the wallet.
            let rho = Option::<Rho>::from(Rho::from_bytes(&canon(1))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(2), &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(10_000), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();

            // Single-leaf tree at position 0: siblings are the empty-subtree roots.
            let auth_path: [MerkleHashOrchard; 32] =
                core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
            let merkle_path = MerklePath::from_parts(0, auth_path);

            let recipient = ShieldedKeys::from_seed([6u8; 32]).unwrap().address();
            let net = [0x11u8; 32];
            let wire =
                build_spend_bundle(&pk, &keys, note, merkle_path, recipient, 8_000, &net, ctx, rand::rng()).expect("build");

            let msg = sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("wallet spend bundle must verify");
            // Fee = 10_000 spent − 8_000 output = 2_000 (positive value balance).
            assert_eq!(wire.value_balance, 2_000);
        }

        /// NON-CUSTODIAL SPEND: the Orchard prove/sign split, end to end.
        ///
        /// The **prover** (a server) has only the full viewing key + proving key and
        /// builds the Halo 2 proof — it never sees the spend authority. The **signer**
        /// (the device) has only `ask` and applies the RedPallas spend-auth signatures
        /// over the sighash — it never proves. A server can therefore prepare a spend
        /// it cannot authorize, and a device authorizes it without proving. The
        /// resulting bundle verifies identically to a locally-built one.
        #[test]
        fn non_custodial_split_spend_verifies() {
            use orchard::builder::{Builder, BundleType};
            use orchard::keys::SpendAuthorizingKey;
            use orchard::value::NoteValue;

            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let keys = ShieldedKeys::from_seed([5u8; 32]).expect("valid seed");
            let ctx = b"zkas-noncustodial";
            let net = [0x44u8; 32];

            // A note worth 10_000 owned by the wallet, alone at tree position 0.
            let rho = Option::<Rho>::from(Rho::from_bytes(&canon(1))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(2), &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(10_000), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
            let auth_path: [MerkleHashOrchard; 32] =
                core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
            let merkle_path = MerklePath::from_parts(0, auth_path);
            let anchor = merkle_path.root(ExtractedNoteCommitment::from(note.commitment()));
            let recipient = ShieldedKeys::from_seed([6u8; 32]).unwrap().address();

            // Spend 10_000, send 8_000 to the recipient, no change → fee = 2_000.
            let mut builder = Builder::new(BundleType::DEFAULT, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).expect("orchard v2 ENABLED flags are always representable");
            builder.add_spend(keys.fvk.clone(), note, merkle_path).expect("add_spend");
            builder.add_output(None, recipient, NoteValue::from_raw(8_000), [0u8; 512]).expect("out");

            let mut rng = rand::rng();

            // === SERVER (viewing key + proving key; NO spend authority) ===
            let (mut pczt, _meta) = builder.build_for_pczt(&mut rng).expect("build_for_pczt");
            pczt.create_proof(&pk, &mut rng).expect("prove");

            // Sighash over the effects (proof/sigs excluded) — the message the device signs.
            let effects = pczt.extract_effects::<i64>().expect("effects").expect("some effects");
            let effects_wire = to_wire(&effects, |_| [0u8; 64], Vec::new(), [0u8; 64]);
            let msg = sighash(&effects_wire, &net, ctx);

            // === DEVICE (ONLY `ask`; never proves) ===
            let ask = SpendAuthorizingKey::from(&keys.sk);
            let mut signed = 0;
            for action in pczt.actions_mut() {
                if action.sign(msg, &ask, &mut rng).is_ok() {
                    signed += 1;
                }
            }
            assert_eq!(signed, 1, "exactly the one real spend action is signed on-device");

            // === SERVER (finalize + extract; still no spend authority) ===
            pczt.finalize_io(msg, &mut rng).expect("finalize_io");
            let unbound = pczt.extract::<i64>().expect("extract").expect("some unbound");
            let authorized = unbound.apply_binding_signature(msg, &mut rng).expect("bind");

            let wire = to_wire(
                &authorized,
                |a| <[u8; 64]>::from(a.authorization()),
                authorized.authorization().proof().as_ref().to_vec(),
                <[u8; 64]>::from(authorized.authorization().binding_signature()),
            );

            // The split-built bundle verifies exactly like a locally-built one.
            let m2 = sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &m2).expect("non-custodial split spend must verify");
            assert_eq!(wire.value_balance, 2_000);
        }

        /// The reusable non-custodial API end to end, WITH change (so the bundle carries
        /// a padding dummy the server signs and a real spend the device signs).
        #[test]
        /// THE ANTI-BLIND-SIGNING GUARD. A device must never sign a hash it cannot
        /// interpret: a malicious prover would simply hand back the sighash of a payment
        /// to *itself*. Here the prover is hostile — it prepares a payment to an attacker
        /// while claiming the user's recipient — and the device catches it with nothing
        /// but its own viewing key and the prover's disclosure.
        #[test]
        fn device_refuses_a_payment_it_did_not_ask_for() {
            let keys = ShieldedKeys::from_seed([12u8; 32]).unwrap();
            let net = [0x66u8; 32];
            let ctx = b"zkas-blind-sign";

            let rho = Option::<Rho>::from(Rho::from_bytes(&canon(5))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(6), &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(10_000), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
            let auth_path: [MerkleHashOrchard; 32] =
                core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
            let merkle_path = MerklePath::from_parts(0, auth_path);

            let intended = ShieldedKeys::from_seed([13u8; 32]).unwrap().address().to_raw_address_bytes();
            let attacker = ShieldedKeys::from_seed([66u8; 32]).unwrap().address().to_raw_address_bytes();

            // The HOSTILE prover: the user asked to pay `intended` 6_000, but it builds a
            // bundle paying `attacker` instead. (Everything else is honest, so only the
            // device's checks stand between the user and the theft.)
            let evil = prepare_payment(
                &keys.fvk,
                vec![(note.clone(), merkle_path.clone())],
                attacker,
                6_000,
                1_000,
                &net,
                ctx,
                true,
                [0u8; 512],
            )
            .unwrap();

            // The device checks the bundle against what the USER asked for, and refuses.
            // (Which action index carries the theft depends on the builder's shuffle.)
            let verdict = check_prepared_payment(&evil.effects, &evil.disclosure, &keys.fvk, &intended, 6_000, 1_000);
            assert!(
                matches!(verdict, Err(PaymentCheckError::UnexpectedRecipient(_))),
                "device must refuse to pay the attacker, got {verdict:?}"
            );

            // And the honest payment it DID ask for passes.
            let good =
                prepare_payment(&keys.fvk, vec![(note, merkle_path)], intended, 6_000, 1_000, &net, ctx, true, [0u8; 512]).unwrap();
            check_prepared_payment(&good.effects, &good.disclosure, &keys.fvk, &intended, 6_000, 1_000)
                .expect("the payment the user asked for must verify");

            // A prover that lies in its disclosure to make a bad bundle look good is caught
            // by the commitments, which are in the bundle and bind the real note.
            for i in 0..good.disclosure.len() {
                let mut lying = good.disclosure.clone();
                lying[i].out_value = lying[i].out_value.wrapping_add(1); // "it's smaller than it looks"
                assert!(
                    matches!(
                        check_prepared_payment(&good.effects, &lying, &keys.fvk, &intended, 6_000, 1_000),
                        Err(PaymentCheckError::CommitmentMismatch(_)) | Err(PaymentCheckError::Malformed(_))
                    ),
                    "a lie about an amount must break the note commitment (action {i})"
                );

                let mut lying = good.disclosure.clone();
                lying[i].out_recipient = attacker; // "it went to them, but call it the recipient"
                assert!(
                    matches!(
                        check_prepared_payment(&good.effects, &lying, &keys.fvk, &intended, 6_000, 1_000),
                        Err(PaymentCheckError::CommitmentMismatch(_))
                    ),
                    "a lie about a recipient must break the note commitment (action {i})"
                );
            }

            // A prover that inflates the fee (skimming the difference) is caught too.
            assert!(matches!(
                check_prepared_payment(&good.effects, &good.disclosure, &keys.fvk, &intended, 6_000, 999),
                Err(PaymentCheckError::FeeMismatch { .. })
            ));

            // As is one that quietly drops the payment the user wanted to make.
            let other = ShieldedKeys::from_seed([77u8; 32]).unwrap().address().to_raw_address_bytes();
            assert!(matches!(
                check_prepared_payment(&good.effects, &good.disclosure, &keys.fvk, &other, 6_000, 1_000),
                Err(PaymentCheckError::UnexpectedRecipient(_))
            ));
        }

        #[test]
        fn non_custodial_payment_api_roundtrip() {
            let keys = ShieldedKeys::from_seed([7u8; 32]).unwrap();
            let net = [0x55u8; 32];
            let ctx = b"zkas-nc-api";

            let rho = Option::<Rho>::from(Rho::from_bytes(&canon(3))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(4), &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(10_000), rho, rseed, orchard::note::NoteVersion::V2)).unwrap();
            let auth_path: [MerkleHashOrchard; 32] =
                core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
            let merkle_path = MerklePath::from_parts(0, auth_path);
            let recipient = ShieldedKeys::from_seed([8u8; 32]).unwrap().address();

            // SERVER (viewing key only): pay 6_000, fee 1_000 → change 3_000.
            let prepared = prepare_payment(
                &keys.fvk,
                vec![(note, merkle_path)],
                recipient.to_raw_address_bytes(),
                6_000,
                1_000,
                &net,
                ctx,
                true,
                [0u8; 512],
            )
            .expect("prepare");
            assert_eq!(prepared.value_balance, 1_000);
            assert_eq!(prepared.spend_auth_requests.len(), 1, "exactly one real spend to authorize");
            let sh = prepared.sighash;

            // DEVICE (spend key only): sign each requested spend.
            let ask = SpendAuthorizingKey::from(&keys.sk);
            let device_sigs: Vec<(usize, [u8; 64])> = prepared
                .spend_auth_requests
                .iter()
                .map(|(i, alpha)| (*i, sign_spend_auth(&ask, *alpha, sh).expect("device sign")))
                .collect();

            // SERVER: finalize + verify.
            let wire = finalize_payment(prepared, device_sigs).expect("finalize");
            let msg = crate::verify::sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("non-custodial payment must verify");
            assert_eq!(wire.value_balance, 1_000);
        }

        /// The full loop: the wallet builds a real shielded bundle, and the
        /// consensus verifier accepts it under the same sighash.
        #[test]
        fn wallet_built_bundle_verifies() {
            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let keys = ShieldedKeys::from_seed([3u8; 32]).expect("valid seed");
            let ctx = b"zkas-wallet-roundtrip";
            let net = [0x22u8; 32];

            let wire = build_output_only_bundle(&pk, keys.address(), 1_000, &net, ctx, rand::rng()).expect("build");

            let msg = sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("wallet-built bundle must verify");

            // A different tx context must not verify under the wallet's sighash.
            let other = sighash(&wire, &net, b"different-context");
            assert!(crate::verify::verify_bundle(&wire, &other).is_err());

            // A different network domain must not verify either (replay protection):
            // this bundle signed for network `net` is invalid on another chain.
            let other_net = sighash(&wire, &[0x23u8; 32], ctx);
            assert!(crate::verify::verify_bundle(&wire, &other_net).is_err());
        }

        /// Send → receive: a bundle built to a recipient's address is recovered by
        /// that recipient's incoming viewing key (and by no one else's).
        #[test]
        fn scan_recovers_sent_note() {
            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let recipient = ShieldedKeys::from_seed([2u8; 32]).expect("valid seed");
            let wire =
                build_output_only_bundle(&pk, recipient.address(), 4242, &[0x33u8; 32], b"ctx", rand::rng()).expect("build");

            let ivk = crate::wallet::ivk_from_seed([2u8; 32]).unwrap();
            let received = crate::wallet::scan_bundle(&ivk, &wire);
            assert_eq!(received.len(), 1, "recipient recovers exactly the note sent to it");
            assert_eq!(received[0].value(), 4242);

            // A stranger's viewing key recovers nothing.
            let stranger = crate::wallet::ivk_from_seed([9u8; 32]).unwrap();
            assert!(crate::wallet::scan_bundle(&stranger, &wire).is_empty());
        }

        /// The crux of the compact-archive design: scanning the 148-byte compact
        /// records (no proof, no signatures) recovers the *identical* note as
        /// scanning the full bundle. If this holds, the node can prune the 76%
        /// verify-only bulk and still serve wallets a complete, scannable history.
        #[test]
        fn compact_scan_matches_full_scan() {
            use crate::wallet::CompactActionRecord;
            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let recipient = ShieldedKeys::from_seed([2u8; 32]).expect("valid seed");
            let wire =
                build_output_only_bundle(&pk, recipient.address(), 4242, &[0x33u8; 32], b"ctx", rand::rng()).expect("build");

            let ivk = crate::wallet::ivk_from_seed([2u8; 32]).unwrap();

            // Baseline: full-bundle scan recovers the note.
            let full = crate::wallet::scan_bundle(&ivk, &wire);
            assert_eq!(full.len(), 1, "full scan recovers the note");

            // Distill every action to its 148-byte compact record; serialization roundtrips.
            let compact: Vec<CompactActionRecord> = wire.actions.iter().map(CompactActionRecord::from_wire).collect();
            for rec in &compact {
                assert_eq!(rec.to_bytes().len(), CompactActionRecord::SERIALIZED_LEN);
                assert_eq!(CompactActionRecord::from_bytes(&rec.to_bytes()), Some(*rec));
            }

            // Compact scan recovers the SAME note: same position, same value.
            let via_compact = crate::wallet::scan_compact(&ivk, &compact);
            assert_eq!(via_compact.len(), 1, "compact scan recovers exactly the note");
            assert_eq!(via_compact[0].action_index, full[0].action_index, "same action position");
            assert_eq!(via_compact[0].value(), full[0].value(), "compact recovers the same value");
            assert_eq!(via_compact[0].value(), 4242);

            // And the compact-recovered note is spendable-consistent: its commitment
            // equals the on-chain cmx carried in the compact record.
            let cmx = orchard::note::ExtractedNoteCommitment::from(via_compact[0].note.commitment());
            assert_eq!(cmx.to_bytes(), compact[via_compact[0].action_index].cmx, "recovered note commits to the archived cmx");

            // A stranger recovers nothing from the compact records either.
            let stranger = crate::wallet::ivk_from_seed([9u8; 32]).unwrap();
            assert!(crate::wallet::scan_compact(&stranger, &compact).is_empty());
        }

        /// The GPU scan path finds exactly what orchard finds — on real notes.
        ///
        /// `scan_compact_gpu` reimplements the cheap half of trial decryption (KDF,
        /// ChaCha20, plaintext parse, commitment check) so the expensive half (the
        /// Pallas key agreement) can run on a device. A mistake in that reimplementation
        /// means missed notes, which a user experiences as their coins vanishing — so it
        /// is checked against orchard on a real bundle rather than reasoned about.
        ///
        /// The key agreement is done on the CPU here, so this tests the pipeline itself
        /// and passes on any machine. The device is checked separately (`zkas-gpu`),
        /// where 1024 points came back byte-identical to `pasta_curves`.
        #[test]
        fn gpu_scan_path_finds_exactly_what_orchard_finds() {
            use crate::wallet::CompactActionRecord;
            use group::Curve;
            let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
            let recipient = ShieldedKeys::from_seed([2u8; 32]).expect("valid seed");
            let wire =
                build_output_only_bundle(&pk, recipient.address(), 4242, &[0x33u8; 32], b"ctx", rand::rng()).expect("build");
            let compact: Vec<CompactActionRecord> = wire.actions.iter().map(CompactActionRecord::from_wire).collect();

            let ivk = crate::wallet::ivk_from_seed([2u8; 32]).unwrap();
            let prepared = ivk.prepare();
            // Stand in for the device: the same ivk·epk, on the CPU.
            let ivk_scalar = crate::wallet::ivk_agreement_scalar(&ivk).unwrap();
            let agree = |epks: &[Option<pasta_curves::pallas::Point>]| {
                Some(epks.iter().map(|e| e.map(|p| (p * ivk_scalar).to_affine())).collect())
            };

            let via_gpu = crate::wallet::scan_compact_gpu(&prepared, &compact, agree).expect("path ran");
            let via_cpu = crate::wallet::scan_compact_prepared(&prepared, &compact);
            assert_eq!(via_gpu.len(), via_cpu.len(), "same number of notes");
            assert_eq!(via_gpu.len(), 1, "and it is the note we planted");
            assert_eq!(via_gpu[0].action_index, via_cpu[0].action_index, "same action position");
            assert_eq!(via_gpu[0].value(), via_cpu[0].value(), "same value");
            assert_eq!(via_gpu[0].value(), 4242);

            // A stranger's key finds nothing down the GPU path either — the filter must
            // not be loose in the direction that matters for privacy.
            let stranger = crate::wallet::ivk_from_seed([9u8; 32]).unwrap();
            let s_scalar = crate::wallet::ivk_agreement_scalar(&stranger).unwrap();
            let s_agree = |epks: &[Option<pasta_curves::pallas::Point>]| {
                Some(epks.iter().map(|e| e.map(|p| (p * s_scalar).to_affine())).collect())
            };
            let s_gpu = crate::wallet::scan_compact_gpu(&stranger.prepare(), &compact, s_agree).expect("ran");
            assert!(s_gpu.is_empty(), "a stranger recovers nothing");

            // A refusing device means "use the CPU", never "no notes".
            let refuse = |_: &[Option<pasta_curves::pallas::Point>]| None;
            assert!(crate::wallet::scan_compact_gpu(&prepared, &compact, refuse).is_none());
        }
    }
}

#[cfg(feature = "circuit")]
pub use build::{
    BuildError, PreparedPayment, ShieldedKeys, build_output_only_bundle, build_payment_bundle, build_spend_bundle, finalize_payment,
    prepare_payment, sign_spend_auth, to_wire,
};
