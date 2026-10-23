//! Multi-tenant scan engine, phase 1 (walletd-scale task E1; design in
//! `audit-2026-10-05/walletd-2026-10-21/02-multitenant-engine.md` §2–§5).
//!
//! Today every hosted wallet follows the chain on its own: it trial-decrypts every action with
//! one viewing key, keeps its own copy of the commitment stream, its own applied-nullifier set
//! and its own mirror tree. This module is the other shape — the chain is followed ONCE:
//!
//! 1. [`SharedPage`]: one fetch and one decode per page for every registered wallet (coinbase
//!    commitments, compact records, ephemeral keys decompressed once).
//! 2. [`detect`]: multi-IVK trial decryption. The ephemeral-key preparation is paid once per
//!    action and shared by every viewing key; the key agreement runs batched across keys
//!    through a pluggable [`AgreeKernel`] ([`LadderKernel`] = the shared GLV table that the
//!    daemon's CPU path already uses, [`CombKernel`] = the fixed-base comb of 02 §4.3,
//!    experiment M-A). A kernel is a FILTER: it proposes a superset of hits (lead byte 0x02
//!    after the KDF and ChaCha20) and orchard's own `try_compact_note_decryption` decides
//!    every candidate, exactly as the existing GPU/epk-reuse paths do.
//! 3. [`SharedChain`]: one keyless tree and one applied-nullifier set (the consensus drop
//!    rule) for all wallets; witnesses are computed from it on demand.
//! 4. [`WalletLite`]: per-wallet state is only the wallet's own notes, pending spends,
//!    history and the nullifiers of its own notes. Nothing proportional to the chain.
//! 5. [`ScanEngine`]: drives 1–4 over pages, delivering a hit only to the wallets it
//!    concerns (a global owned-nullifier map for spends and a recipient map for coinbase).
//!
//! Correctness is defined as equality with the per-wallet [`WalletDb`] path: the same notes
//! (position, value, nullifier, commitment), balance, pending spends, history rows, tree root
//! and witnesses. The differential tests in this module and the real-day shadow harness in
//! `zkas-walletd` (`engine_shadow_tests`) assert exactly that.

use std::collections::{HashMap, HashSet};

use group::{Curve, Group, GroupEncoding};
use orchard::{
    Address,
    keys::{FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::MerklePath,
    value::NoteValue,
};
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::glv::{Decomposed, GlvParams, Table};
use pasta_curves::pallas;

use crate::coinbase::CoinbaseNoteDesc;
use crate::tree::FrontierState;
use crate::wallet::scan::{CompactActionRecord, ReceivedNote, decompress_epk, ivk_agreement_scalar, scan_compact_cpu};
use crate::walletdb::{BlockMeta, Credit, HistoryEntry, HistoryKind, OwnedNote, PendingSpend, WalletDb};

// =====================================================================================
// (1) The shared block pipeline
// =====================================================================================

/// One accepted chain block, decoded once for every wallet. `coinbase` holds only the notes
/// that commit, in coinbase order, with their commitment computed once (what
/// `WalletDb::ingest_block_compact_precomputed_with_meta` takes); `txs` are the accepted
/// transactions' compact records in accepted order; `meta` is the dating metadata the daemon
/// would hand `WalletDb` for this block (`None` = no history rows, as there).
#[derive(Clone)]
pub struct SharedBlock {
    pub hash: [u8; 32],
    pub blue_score: u64,
    pub daa_score: u64,
    pub coinbase: Vec<(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)>,
    pub txs: Vec<Vec<CompactActionRecord>>,
    pub meta: Option<BlockMeta>,
}

/// A page of [`SharedBlock`]s with its actions flattened in ingest order (block, then
/// transaction, then action) and every ephemeral key decompressed once.
pub struct SharedPage {
    pub blocks: Vec<SharedBlock>,
    /// Every action of the page, in ingest order. A detector's `action_index` indexes this.
    pub actions: Vec<CompactActionRecord>,
    /// `decompress_epk` of each action, parallel to `actions`; `None` = not a valid encoding.
    pub epks: Vec<Option<pallas::Point>>,
}

impl SharedPage {
    /// Flatten and decompress (in parallel above a small batch).
    pub fn new(blocks: Vec<SharedBlock>) -> Self {
        let actions: Vec<CompactActionRecord> = blocks.iter().flat_map(|b| b.txs.iter().flatten().copied()).collect();
        let epks: Vec<Option<pallas::Point>> = if actions.len() >= 512 {
            use rayon::prelude::*;
            actions.par_iter().map(|r| decompress_epk(&r.ephemeral_key)).collect()
        } else {
            actions.iter().map(|r| decompress_epk(&r.ephemeral_key)).collect()
        };
        Self { blocks, actions, epks }
    }

    /// As [`Self::new`] with ephemeral keys somebody already decompressed (the daemon's page
    /// cache does). A length mismatch decompresses afresh: a drift costs time, never a note.
    pub fn with_epks(blocks: Vec<SharedBlock>, epks: Vec<Option<pallas::Point>>) -> Self {
        let actions: Vec<CompactActionRecord> = blocks.iter().flat_map(|b| b.txs.iter().flatten().copied()).collect();
        if epks.len() != actions.len() {
            return Self::new(blocks);
        }
        Self { blocks, actions, epks }
    }
}

// =====================================================================================
// (2) Multi-IVK trial decryption
// =====================================================================================

/// One viewing key, prepared once at registration for every kernel: orchard's prepared ivk
/// (the judge), the raw agreement scalar, its GLV decomposition + joint recoding (ladder
/// kernel) and its signed fixed-window digits (comb kernel).
pub struct IvkKey {
    prepared: PreparedIncomingViewingKey,
    scalar: pallas::Scalar,
    decomposed: Decomposed<pallas::Point>,
    comb: CombScalar,
    /// `IncomingViewingKey::to_bytes()`, to deduplicate twins (two wallets, one key).
    id: [u8; 64],
}

impl IvkKey {
    pub fn from_ivk(ivk: &IncomingViewingKey) -> Option<Self> {
        let scalar = ivk_agreement_scalar(ivk)?;
        Some(Self {
            prepared: ivk.prepare(),
            decomposed: Decomposed::<pallas::Point>::new(&scalar),
            comb: CombScalar::new(&scalar),
            scalar,
            id: ivk.to_bytes(),
        })
    }

    /// The external-scope key, which is the scope `WalletDb` scans.
    pub fn from_fvk(fvk: &FullViewingKey) -> Option<Self> {
        Self::from_ivk(&fvk.to_ivk(Scope::External))
    }

    pub fn prepared(&self) -> &PreparedIncomingViewingKey {
        &self.prepared
    }

    pub fn scalar(&self) -> &pallas::Scalar {
        &self.scalar
    }

    /// `IncomingViewingKey::to_bytes()` of the key: equal for twins.
    pub fn id(&self) -> [u8; 64] {
        self.id
    }
}

/// The key-agreement half of trial decryption for many keys at once.
///
/// A kernel answers, for every key, which actions survive the cheap filter (agreement, the
/// Orchard KDF, ChaCha20, plaintext lead byte 0x02). That set must be a SUPERSET of the
/// actions orchard would decrypt with the key: [`detect`] hands every candidate to orchard,
/// which decides, so a false positive costs one orchard call and a false negative would cost
/// a user's note. `None` means "could not answer" and [`detect`] then runs the reference
/// per-key path. A device (GPU) kernel plugs in here with the same contract.
pub trait AgreeKernel: Send + Sync {
    fn name(&self) -> &'static str;
    /// `out[k]` = ascending action indices that pass for `keys[k]`.
    fn candidates(&self, keys: &[&IvkKey], actions: &[CompactActionRecord], epks: &[Option<pallas::Point>]) -> Option<Vec<Vec<u32>>>;
}

/// The Orchard KDF + ChaCha20 lead-byte test of one (shared secret, action) pair — the same
/// condition as `scan_compact_gpu_inner`'s filter: BLAKE2b-256 "Zcash_OrchardKDF" over the
/// affine shared secret then the ephemeral key bytes; ChaCha20, zero nonce, seeked to byte 64;
/// note-plaintext version byte must be 0x02. Only plaintext byte 0 is read, so only one
/// keystream byte is generated.
pub fn lead_byte_passes(secret: &pallas::Affine, rec: &CompactActionRecord) -> bool {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let key = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Zcash_OrchardKDF")
        .to_state()
        .update(&secret.to_bytes())
        .update(&rec.ephemeral_key)
        .finalize();
    let mut pt = [rec.enc_ciphertext[0]];
    let mut cipher = chacha20::ChaCha20::new(key.as_bytes().into(), &[0u8; 12].into());
    cipher.seek(64u32);
    cipher.apply_keystream(&mut pt);
    pt[0] == 0x02
}

/// Indices of the actions whose ephemeral key is a valid, non-identity point. Orchard refuses
/// an identity or non-canonical ephemeral key, so excluding them is a restriction of orchard's
/// own behaviour (the same rule `cpu_agree_points` applies).
fn live_actions(epks: &[Option<pallas::Point>]) -> Vec<u32> {
    epks.iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            Some(p) if !bool::from(p.is_identity()) => Some(i as u32),
            _ => None,
        })
        .collect()
}

/// Work items for a (keys × action-chunks) grid: enough chunks that a small key set still
/// spreads across the pool, few enough that a large one does not fragment the tables.
fn chunking(n_keys: usize, n_live: usize) -> usize {
    let threads = rayon::current_num_threads().max(1);
    let want_chunks = (threads * 2).div_ceil(n_keys.max(1)).max(1);
    n_live.div_ceil(want_chunks).max(64)
}

/// The shared GLV table path: ONE `Table::batch` over the page's ephemeral keys (the epk
/// preparation, shared by every key), then per key one `mul_decomposed_batch` against those
/// tables with the key's decomposition hoisted to registration — the arithmetic
/// `cpu_agree_points` does for one key, with the per-page half paid once for all keys.
pub struct LadderKernel;

impl AgreeKernel for LadderKernel {
    fn name(&self) -> &'static str {
        "ladder"
    }

    fn candidates(&self, keys: &[&IvkKey], actions: &[CompactActionRecord], epks: &[Option<pallas::Point>]) -> Option<Vec<Vec<u32>>> {
        use rayon::prelude::*;
        if epks.len() != actions.len() {
            return None;
        }
        let live = live_actions(epks);
        if live.is_empty() || keys.is_empty() {
            return Some(vec![Vec::new(); keys.len()]);
        }
        let points: Vec<pallas::Point> = live.iter().map(|&i| epks[i as usize].expect("live")).collect();
        let tables = Table::<pallas::Point>::batch(&points);
        let refs: Vec<&Table<pallas::Point>> = tables.iter().collect();
        let chunk = chunking(keys.len(), live.len());
        let n_chunks = live.len().div_ceil(chunk);
        let parts: Vec<(usize, Vec<u32>)> = (0..keys.len() * n_chunks)
            .into_par_iter()
            .map(|job| {
                let (k, c) = (job / n_chunks, job % n_chunks);
                let lo = c * chunk;
                let hi = (lo + chunk).min(live.len());
                let products = Table::mul_decomposed_batch(&refs[lo..hi], &keys[k].decomposed);
                let mut affine = vec![pallas::Affine::default(); products.len()];
                pallas::Point::batch_normalize(&products, &mut affine);
                let hits: Vec<u32> = (lo..hi)
                    .filter(|&j| lead_byte_passes(&affine[j - lo], &actions[live[j] as usize]))
                    .map(|j| live[j])
                    .collect();
                (k, hits)
            })
            .collect();
        let mut out = vec![Vec::new(); keys.len()];
        for (k, mut h) in parts {
            out[k].append(&mut h);
        }
        for v in &mut out {
            v.sort_unstable();
        }
        Some(out)
    }
}

// ---- The fixed-base comb (02 §4.3, experiment M-A) --------------------------------------

/// Most digits a 128-bit GLV half needs at the smallest supported window (w = 2), plus one.
const COMB_MAX_DIGITS: usize = 65;

/// `k = k1 + k2·λ (mod n)`, each half as `(negative, |half| < 2^127)` — Babai rounding against
/// the crate's published short lattice basis (`GlvParams` constants), the same computation as
/// `pasta_curves::glv::decompose` (which is private). `decomposition_reconstructs_the_scalar`
/// checks `k1 + k2·ZETA == k` on random scalars, so a transcription error cannot pass.
fn glv_decompose(k: &pallas::Scalar) -> ((bool, u128), (bool, u128)) {
    use group::ff::PrimeField;
    fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
        let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
        (t as u64, (t >> 64) as u64)
    }
    fn schoolbook(a: &[u64], b: &[u64], prod: &mut [u64]) {
        for (i, &ai) in a.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &bj) in b.iter().enumerate() {
                let (limb, c) = mac(prod[i + j], ai, bj, carry);
                prod[i + j] = limb;
                carry = c;
            }
            prod[i + b.len()] = carry;
        }
    }
    fn round_mul_shift(g: &[u64; 5], k: &[u64; 4]) -> u128 {
        let mut prod = [0u64; 9];
        schoolbook(g, k, &mut prod);
        let round = prod[5] >> 63;
        (u128::from(prod[6]) | (u128::from(prod[7]) << 64)).wrapping_add(u128::from(round))
    }
    fn mul_u128(a: u128, b: u128) -> [u64; 4] {
        let mut prod = [0u64; 4];
        schoolbook(&[a as u64, (a >> 64) as u64], &[b as u64, (b >> 64) as u64], &mut prod);
        prod
    }
    fn sub256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = (b1 | b2) as u64;
        }
        out
    }
    fn signed(x: [u64; 4]) -> (bool, u128) {
        let low = u128::from(x[0]) | (u128::from(x[1]) << 64);
        if x[3] >> 63 == 0 { (false, low) } else { (true, (!low).wrapping_add(1)) }
    }
    let bytes = k.to_repr();
    let mut kl = [0u64; 4];
    for (i, limb) in kl.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
    }
    type C = pallas::Point;
    let c1 = round_mul_shift(&<C as GlvParams>::G1, &kl);
    let c2 = round_mul_shift(&<C as GlvParams>::G2, &kl);
    let k1 = sub256(sub256(kl, mul_u128(c1, <C as GlvParams>::V1A)), mul_u128(c2, <C as GlvParams>::V2A));
    let k2 = sub256(mul_u128(c1, <C as GlvParams>::V1B_NEG), mul_u128(c2, <C as GlvParams>::V2B));
    (signed(k1), signed(k2))
}

/// Signed radix-2^w digits of a non-negative value below 2^127: `Σ d_j 2^{wj}` with
/// `d_j ∈ [-2^{w-1}, 2^{w-1}]`, so a window table needs only the 2^{w-1} positive multiples
/// (a negative digit is a y negation).
fn signed_digits(mut v: u128, w: u32, out: &mut [i16; COMB_MAX_DIGITS]) -> usize {
    let mask = (1u128 << w) - 1;
    let half = 1i32 << (w - 1);
    let mut n = 0;
    let mut carry = 0i32;
    while v != 0 || carry != 0 {
        let t = (v & mask) as i32 + carry;
        v >>= w;
        let (d, c) = if t > half { (t - (1 << w), 1) } else { (t, 0) };
        out[n] = d as i16;
        carry = c;
        n += 1;
    }
    n
}

/// A key in the comb's form: both GLV halves recoded as signed fixed windows for every window
/// width the comb may use. Computed once at registration (≈ 0.5 KB per key).
struct CombScalar {
    neg: [bool; 2],
    /// `digits[w - COMB_W_MIN][half]`, with its length.
    digits: Vec<[([i16; COMB_MAX_DIGITS], usize); 2]>,
}

const COMB_W_MIN: u32 = 2;
const COMB_W_MAX: u32 = 8;

impl CombScalar {
    fn new(k: &pallas::Scalar) -> Self {
        let ((n1, a1), (n2, a2)) = glv_decompose(k);
        let mut digits = Vec::new();
        for w in COMB_W_MIN..=COMB_W_MAX {
            let mut d1 = [0i16; COMB_MAX_DIGITS];
            let mut d2 = [0i16; COMB_MAX_DIGITS];
            let l1 = signed_digits(a1, w, &mut d1);
            let l2 = signed_digits(a2, w, &mut d2);
            digits.push([(d1, l1), (d2, l2)]);
        }
        Self { neg: [n1, n2], digits }
    }
}

/// Fixed-base comb over the ephemeral key (02 §4.3): within one action the BASE is shared and
/// N scalars vary, so a table `T[j][m] = (m+1)·2^{wj}·epk` built once per action turns each
/// key's agreement into ≈ 2·⌈128/w⌉ mixed additions with no doublings (the GLV endomorphism
/// φ(x, y) = (ζx, y) = λ·P serves the second half from the same table, applied once to the
/// second accumulator). `w = None` picks the width from the key count, and below
/// [`COMB_MIN_KEYS`] keys hands the batch to [`LadderKernel`] (the table cannot amortise).
///
/// Measured (M-A, `08-engine-phase1.md` §3, real pages, 4 threads, CPU-µs per (action, key)):
/// today's per-wallet path 36.9–38.7 at every N; comb 21.4 at N = 64, 13.8 at 1,024, 13.1–13.9
/// at 4,096; crossover with the ladder at N ≈ 16; identical hit sets throughout.
pub struct CombKernel {
    pub w: Option<u32>,
}

/// Below this many keys the auto-width comb defers to the ladder (measured crossover, M-A).
pub const COMB_MIN_KEYS: usize = 16;

impl CombKernel {
    /// Window width minimising (table build)/N + per-key additions, from the cost model
    /// (build ≈ ⌈128/w⌉·(2^{w-1}) mixed adds; per key ≈ 2·⌈128/w⌉). Overridden by `w`.
    pub fn width_for(&self, n_keys: usize) -> u32 {
        if let Some(w) = self.w {
            return w.clamp(COMB_W_MIN, COMB_W_MAX);
        }
        let n = n_keys.max(1) as f64;
        (COMB_W_MIN..=COMB_W_MAX)
            .min_by(|&a, &b| {
                let cost = |w: u32| {
                    let nw = 128f64 / w as f64;
                    nw * (1u64 << (w - 1)) as f64 / n + 2.0 * nw
                };
                cost(a).partial_cmp(&cost(b)).expect("finite")
            })
            .expect("non-empty range")
    }

    /// The comb table for one base: `nw` windows of `2^{w-1}` affine multiples, row-major.
    fn table(p: &pallas::Point, w: u32, nw: usize, scratch: &mut Vec<pallas::Point>, out: &mut Vec<pallas::Affine>) {
        let h = 1usize << (w - 1);
        // Window bases B_j = 2^{wj}·P, normalised together (one inversion).
        let mut bases_p = Vec::with_capacity(nw);
        let mut b = *p;
        for j in 0..nw {
            if j > 0 {
                for _ in 0..w {
                    b = b.double();
                }
            }
            bases_p.push(b);
        }
        let mut bases = vec![pallas::Affine::default(); nw];
        pallas::Point::batch_normalize(&bases_p, &mut bases);
        scratch.clear();
        for (j, ba) in bases.iter().enumerate() {
            let mut acc = bases_p[j];
            scratch.push(acc);
            for _ in 1..h {
                acc += ba;
                scratch.push(acc);
            }
        }
        out.clear();
        out.resize(scratch.len(), pallas::Affine::default());
        pallas::Point::batch_normalize(scratch, out);
    }

    fn agree(table: &[pallas::Affine], h: usize, key: &CombScalar, wi: usize) -> pallas::Point {
        let mut acc = [pallas::Point::identity(), pallas::Point::identity()];
        for half in 0..2 {
            let (d, len) = &key.digits[wi][half];
            for (j, &dj) in d[..*len].iter().enumerate() {
                if dj > 0 {
                    acc[half] += &table[j * h + dj as usize - 1];
                } else if dj < 0 {
                    acc[half] += &(-&table[j * h + (-dj) as usize - 1]);
                }
            }
            if key.neg[half] {
                acc[half] = -acc[half];
            }
        }
        acc[0] + acc[1].endo()
    }
}

impl AgreeKernel for CombKernel {
    fn name(&self) -> &'static str {
        "comb"
    }

    fn candidates(&self, keys: &[&IvkKey], actions: &[CompactActionRecord], epks: &[Option<pallas::Point>]) -> Option<Vec<Vec<u32>>> {
        use rayon::prelude::*;
        if epks.len() != actions.len() {
            return None;
        }
        if self.w.is_none() && keys.len() < COMB_MIN_KEYS {
            return LadderKernel.candidates(keys, actions, epks);
        }
        let live = live_actions(epks);
        if live.is_empty() || keys.is_empty() {
            return Some(vec![Vec::new(); keys.len()]);
        }
        let w = self.width_for(keys.len());
        let wi = (w - COMB_W_MIN) as usize;
        let h = 1usize << (w - 1);
        // Every key's digit strings have the same bound; size the table for the longest.
        let nw = keys.iter().map(|k| k.comb.digits[wi][0].1.max(k.comb.digits[wi][1].1)).max().unwrap_or(1).max(1);
        // Per action: build its table once, run every key against it, normalise the N
        // products together (one inversion across keys), filter. Actions run in parallel.
        let pairs: Vec<(u32, u32)> = live
            .par_iter()
            .map_init(
                || (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
                |(scratch, table, prods, aff): &mut (Vec<pallas::Point>, Vec<pallas::Affine>, Vec<pallas::Point>, Vec<pallas::Affine>), &ai| {
                    let p = epks[ai as usize].expect("live");
                    Self::table(&p, w, nw, scratch, table);
                    prods.clear();
                    for k in keys {
                        prods.push(Self::agree(table, h, &k.comb, wi));
                    }
                    aff.clear();
                    aff.resize(prods.len(), pallas::Affine::default());
                    pallas::Point::batch_normalize(prods, aff);
                    let rec = &actions[ai as usize];
                    aff.iter().enumerate().filter(|(_, s)| lead_byte_passes(s, rec)).map(|(k, _)| (k as u32, ai)).collect::<Vec<_>>()
                },
            )
            .flatten()
            .collect();
        let mut out = vec![Vec::new(); keys.len()];
        for (k, a) in pairs {
            out[k as usize].push(a);
        }
        for v in &mut out {
            v.sort_unstable();
        }
        Some(out)
    }
}

/// Trial-decrypt `actions` with every key: kernel filter, then orchard decides each candidate.
///
/// `out[k]` is exactly what `scan_compact_auto_cached(keys[k].prepared(), Some(scalar),
/// actions, Some(epks))` returns for that key (same notes, same `action_index` into
/// `actions`, ascending): the kernel's candidates are a superset of orchard's hits and orchard
/// is the judge of every one. If the kernel declines, the reference per-key path runs.
pub fn detect(kernel: &dyn AgreeKernel, keys: &[&IvkKey], actions: &[CompactActionRecord], epks: &[Option<pallas::Point>]) -> Vec<Vec<ReceivedNote>> {
    use rayon::prelude::*;
    if actions.is_empty() {
        return vec![Vec::new(); keys.len()];
    }
    let Some(cands) = kernel.candidates(keys, actions, epks) else {
        return keys
            .par_iter()
            .map(|k| crate::wallet::scan::scan_compact_auto_cached(&k.prepared, Some(&k.scalar), actions, Some(epks)))
            .collect();
    };
    keys.par_iter()
        .zip(cands.par_iter())
        .map(|(k, c)| {
            if c.is_empty() {
                return Vec::new();
            }
            let subset: Vec<CompactActionRecord> = c.iter().map(|&i| actions[i as usize]).collect();
            scan_compact_cpu(&k.prepared, &subset)
                .into_iter()
                .map(|mut n| {
                    n.action_index = c[n.action_index] as usize;
                    n
                })
                .collect()
        })
        .collect()
}

// =====================================================================================
// (3) One tree, one drop-rule nullifier set
// =====================================================================================

/// The seed of the keyless tree wallet (never owns a note; `set_leaves_only`). The same
/// constant the daemon's `__chain.tree__` uses.
pub const SHARED_CHAIN_SEED: [u8; 32] = *b"zkas-shared-chain-tree-v1-notele";

/// The chain, once: the commitment stream since its base, the applied-nullifier set the
/// consensus drop rule reads, and the tip frontier. A keyless [`WalletDb`] in leaves-only mode
/// IS that structure (the daemon's shared chain tree is the same thing), so the engine reuses
/// it rather than re-implementing the tree: same append order, same drop rule, same witness
/// code.
pub struct SharedChain {
    tree: WalletDb,
}

impl SharedChain {
    /// Start at a node frontier (fast-sync point).
    pub fn from_frontier(fs: &FrontierState) -> Option<Self> {
        let mut tree = WalletDb::from_seed(SHARED_CHAIN_SEED)?;
        tree.apply_frontier(fs)?;
        tree.set_leaves_only(true);
        Some(Self { tree })
    }

    /// Adopt an existing keyless tree (e.g. the daemon's `__chain.tree__`).
    pub fn from_tree(mut tree: WalletDb) -> Self {
        tree.set_leaves_only(true);
        Self { tree }
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    pub fn anchor(&self) -> [u8; 32] {
        self.tree.anchor()
    }

    pub fn base_size(&self) -> u64 {
        self.tree.base_size()
    }

    /// Has this nullifier been applied by the stream since the base?
    pub fn nf_seen(&self, nf: &[u8; 32]) -> bool {
        self.tree.applied_nullifier(nf)
    }

    pub fn nf_len(&self) -> usize {
        self.tree.nf_len()
    }

    pub fn poisoned(&self) -> bool {
        self.tree.poisoned()
    }

    /// Witnesses for `positions`, rooted at the tree after `matured_leaves` leaves.
    pub fn witness_paths_at(&self, positions: &[u64], matured_leaves: u64) -> Vec<Option<MerklePath>> {
        self.tree.witness_paths_at(positions, matured_leaves)
    }

    pub fn tree(&self) -> &WalletDb {
        &self.tree
    }

    pub fn approx_heap_bytes(&self) -> usize {
        self.tree.approx_heap_bytes()
    }

    fn ingest(&mut self, b: &SharedBlock) {
        self.tree.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, None);
    }
}

// =====================================================================================
// (4) Per-wallet state: own notes, own nullifiers, own history
// =====================================================================================

/// A wallet reduced to its private output: its keys, its unspent notes (each with its leaf
/// position and nullifier), pending spends, history rows and chain clock. No commitment
/// stream, no tree, no applied-nullifier set; witnesses come from [`SharedChain`].
///
/// Every state transition mirrors `WalletDb`'s ingest exactly (order of retains, history
/// rules, the "spent before it appeared" rule), because equality with `WalletDb` is the
/// definition of correct here.
pub struct WalletLite {
    fvk: FullViewingKey,
    my_address: [u8; 43],
    notes: Vec<OwnedNote>,
    pending_spends: Vec<PendingSpend>,
    pending_change: HashMap<[u8; 32], u64>,
    history: Vec<HistoryEntry>,
    history_enabled: bool,
    last_daa: u64,
    poisoned: bool,
    /// Tree size at registration: the wallet's state is consistent from here on.
    registered_at: u64,
}

impl WalletLite {
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }
    pub fn balance(&self) -> u128 {
        self.notes.iter().map(|n| n.value() as u128).sum()
    }
    pub fn pending_spends(&self) -> &[PendingSpend] {
        &self.pending_spends
    }
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }
    pub fn last_daa(&self) -> u64 {
        self.last_daa
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn registered_at(&self) -> u64 {
        self.registered_at
    }
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    /// The wallet's default (index 0) external address.
    pub fn my_address(&self) -> [u8; 43] {
        self.my_address
    }
    pub fn set_history_enabled(&mut self, on: bool) {
        self.history_enabled = on;
        if !on {
            self.history.clear();
        }
    }

    /// As `WalletDb::approx_heap_bytes`, for the parts this type has.
    pub fn approx_heap_bytes(&self) -> usize {
        self.notes.capacity() * std::mem::size_of::<OwnedNote>()
            + self.pending_spends.capacity() * std::mem::size_of::<PendingSpend>()
            + self.history.capacity() * std::mem::size_of::<HistoryEntry>()
            + self.history.iter().map(|h| h.memo.capacity() + h.credits.capacity() * std::mem::size_of::<Credit>()).sum::<usize>()
            + self.pending_change.capacity() * 48
    }

    /// `WalletDb::mark_spent`, unchanged.
    pub fn mark_spent(&mut self, position: u64, txid: [u8; 32], submitted_daa: u64) {
        if let Some(i) = self.notes.iter().position(|n| n.position == position) {
            let note = self.notes.remove(i);
            self.pending_spends.push(PendingSpend { note, txid, submitted_daa });
        }
    }

    /// `WalletDb::note_pending_outflow`, unchanged.
    pub fn note_pending_outflow(&mut self, txid: [u8; 32], outflow: u64) {
        let parked: u64 = self.pending_spends.iter().filter(|p| p.txid == txid).map(|p| p.note.value()).sum();
        if parked == 0 {
            return;
        }
        let change = parked.saturating_sub(outflow);
        if change > 0 {
            self.pending_change.insert(txid, change);
        } else {
            self.pending_change.remove(&txid);
        }
    }

    /// `WalletDb::pending_change`, unchanged.
    pub fn pending_change(&self) -> u128 {
        self.pending_change.iter().filter(|(t, _)| self.pending_spends.iter().any(|p| &p.txid == *t)).map(|(_, v)| *v as u128).sum()
    }

    /// `WalletDb::reclaim_expired`, unchanged.
    pub fn reclaim_expired(&mut self, now_daa: u64, max_age_daa: u64) -> Vec<([u8; 32], u64)> {
        let mut reclaimed = Vec::new();
        let mut i = 0;
        while i < self.pending_spends.len() {
            let origin = self.pending_spends[i].submitted_daa;
            if origin != 0 && now_daa.saturating_sub(origin) > max_age_daa {
                let p = self.pending_spends.remove(i);
                reclaimed.push((p.txid, p.note.value()));
                let at = self.notes.iter().position(|n| n.position > p.note.position).unwrap_or(self.notes.len());
                self.notes.insert(at, p.note);
            } else {
                i += 1;
            }
        }
        self.prune_pending_change();
        reclaimed
    }

    fn prune_pending_change(&mut self) {
        if self.pending_change.is_empty() {
            return;
        }
        let ps = &self.pending_spends;
        self.pending_change.retain(|t, _| ps.iter().any(|p| &p.txid == t));
    }

    fn owns(&self, nf: &[u8; 32]) -> bool {
        self.notes.iter().any(|n| &n.nullifier() == nf) || self.pending_spends.iter().any(|p| &p.note.nullifier() == nf)
    }

    fn owned_note_value(&self, nf: &[u8; 32]) -> Option<u64> {
        self.notes
            .iter()
            .find(|n| &n.nullifier() == nf)
            .or_else(|| self.pending_spends.iter().map(|p| &p.note).find(|n| &n.nullifier() == nf))
            .map(|n| n.value())
    }

    fn push_history(&mut self, entry: HistoryEntry) {
        if self.history.len() >= crate::walletdb::HISTORY_CAP {
            self.history.drain(..crate::walletdb::HISTORY_CAP / 2);
        }
        self.history.push(entry);
    }

    /// `WalletDb::recover_coinbase_note` minus the address test (the engine's recipient map
    /// already matched it).
    fn coinbase_note(desc: &CoinbaseNoteDesc, value: u64) -> Option<Note> {
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&desc.recipient))?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho))?;
        Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2))
    }

    /// `WalletDb::append_leaf`'s ownership half: keep the note unless the stream already
    /// carried its nullifier. Returns the nullifier when the note was kept.
    fn append_owned(&mut self, note: Note, position: u64, seen: impl Fn(&[u8; 32]) -> bool) -> Option<[u8; 32]> {
        let nullifier = note.nullifier(&self.fvk).to_bytes();
        if seen(&nullifier) {
            return None;
        }
        self.notes.push(OwnedNote::new(note, position, nullifier));
        Some(nullifier)
    }

    /// A coinbase leaf paid to one of this wallet's addresses, at `position`.
    fn fold_coinbase(&mut self, desc: &CoinbaseNoteDesc, value: u64, position: u64, meta: Option<&BlockMeta>, seen: impl Fn(&[u8; 32]) -> bool) -> Option<[u8; 32]> {
        let note = Self::coinbase_note(desc, value)?;
        if let Some(m) = meta {
            if self.history_enabled {
                self.push_history(HistoryEntry {
                    kind: HistoryKind::Coinbase,
                    txid: m.coinbase_txid,
                    daa_score: m.daa_score,
                    timestamp_ms: m.timestamp_ms,
                    amount: value,
                    fee: 0,
                    amount_is_net_outflow: false,
                    fee_known: true,
                    recipient: None,
                    memo: Vec::new(),
                    credits: Vec::new(),
                });
            }
        }
        self.append_owned(note, position, seen)
    }

    /// One APPLIED transaction that concerns this wallet (a hit, or one of its nullifiers),
    /// in `WalletDb::ingest_bundles_compact`'s order. `received` carries tx-relative
    /// `action_index`; `positions[i]` is the leaf position of action i (`None` = non-canonical
    /// cmx, no leaf); `seen(nf, i)` = was `nf` applied by the stream up to and including
    /// action i. Returns the nullifiers of notes it gained.
    #[allow(clippy::too_many_arguments)]
    fn fold_tx(
        &mut self,
        records: &[CompactActionRecord],
        received: &[ReceivedNote],
        positions: &[Option<u64>],
        seen: impl Fn(&[u8; 32], usize) -> bool,
        meta: Option<&BlockMeta>,
        txid: Option<[u8; 32]>,
    ) -> Vec<[u8; 32]> {
        let spent: u64 = records.iter().filter_map(|a| self.owned_note_value(&a.nullifier)).sum();
        let mut gained = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            self.notes.retain(|n| n.nullifier() != rec.nullifier);
            self.pending_spends.retain(|p| p.note.nullifier() != rec.nullifier);
            self.prune_pending_change();
            let Some(pos) = positions[i] else { continue };
            if let Some(r) = received.iter().find(|r| r.action_index == i) {
                if let Some(nf) = self.append_owned(r.note.clone(), pos, |nf| seen(nf, i)) {
                    gained.push(nf);
                }
            }
        }
        if let (Some(m), Some(txid)) = (meta, txid) {
            self.record_history_compact(spent, received, txid, m);
        }
        gained
    }

    /// `WalletDb::record_history_compact`, unchanged.
    fn record_history_compact(&mut self, spent: u64, received: &[ReceivedNote], txid: [u8; 32], meta: &BlockMeta) {
        if !self.history_enabled {
            return;
        }
        let received_value: u64 = received.iter().map(|r| r.value()).sum();
        if spent > 0 {
            self.push_history(HistoryEntry {
                kind: HistoryKind::Sent,
                txid,
                daa_score: meta.daa_score,
                timestamp_ms: meta.timestamp_ms,
                amount: spent.saturating_sub(received_value),
                fee: 0,
                amount_is_net_outflow: true,
                fee_known: false,
                recipient: None,
                memo: Vec::new(),
                credits: Vec::new(),
            });
            return;
        }
        if received_value == 0 {
            return;
        }
        self.push_history(HistoryEntry {
            kind: HistoryKind::Received,
            txid,
            daa_score: meta.daa_score,
            timestamp_ms: meta.timestamp_ms,
            amount: received_value,
            fee: 0,
            amount_is_net_outflow: false,
            fee_known: true,
            recipient: received.first().map(|note| note.note.recipient().to_raw_address_bytes()),
            memo: Vec::new(),
            credits: crate::walletdb::credits_from_received(received),
        });
    }
}

// =====================================================================================
// (5) The engine: one pass over the chain for every registered wallet
// =====================================================================================

/// Counters for one engine, cumulative.
#[derive(Default, Clone, Copy, Debug)]
pub struct EngineStats {
    pub pages: u64,
    pub blocks: u64,
    pub actions: u64,
    /// (action, key) pairs offered to the kernel.
    pub pairs: u64,
    /// Orchard-confirmed (key, action) hits and coinbase recipient hits.
    pub hits: u64,
    pub coinbase_hits: u64,
    /// Wallet-transaction folds (a wallet touched by a transaction).
    pub folds: u64,
    pub detect_ns: u128,
    pub tree_ns: u128,
    pub fold_ns: u128,
}

/// Wallet handle inside one [`ScanEngine`].
pub type WalletId = u32;

/// One chain follower's worth of state for N wallets. Feed it pages in chain order with
/// [`Self::ingest_page`]; every registered wallet then reflects exactly the blocks ingested
/// since its registration.
pub struct ScanEngine {
    chain: SharedChain,
    wallets: Vec<WalletLite>,
    keys: Vec<IvkKey>,
    key_index: HashMap<[u8; 64], u32>,
    key_wallets: Vec<Vec<WalletId>>,
    wallet_key: Vec<u32>,
    /// Recipient → wallets, over each wallet's `COINBASE_DIVERSIFIER_SCAN` addresses (the
    /// same set `WalletDb::known_addresses` holds, for parity).
    addr_map: HashMap<[u8; 43], Vec<WalletId>>,
    /// Nullifier of every unspent or pending note of every wallet → its owners.
    owned_nf: HashMap<[u8; 32], Vec<WalletId>>,
    kernel: Box<dyn AgreeKernel>,
    stats: EngineStats,
}

impl ScanEngine {
    pub fn new(chain: SharedChain, kernel: Box<dyn AgreeKernel>) -> Self {
        Self {
            chain,
            wallets: Vec::new(),
            keys: Vec::new(),
            key_index: HashMap::new(),
            key_wallets: Vec::new(),
            wallet_key: Vec::new(),
            addr_map: HashMap::new(),
            owned_nf: HashMap::new(),
            kernel,
            stats: EngineStats::default(),
        }
    }

    /// Register a wallet at the chain's current height (phase 1 has no catch-up: a wallet is
    /// consistent from `registered_at` on, which is exactly a `WalletDb` fast-synced from the
    /// same frontier).
    pub fn register(&mut self, fvk: FullViewingKey) -> Option<WalletId> {
        let ivk = fvk.to_ivk(Scope::External);
        let id = self.wallets.len() as WalletId;
        let kid = match self.key_index.get(&ivk.to_bytes()) {
            Some(&k) => k,
            None => {
                let key = IvkKey::from_ivk(&ivk)?;
                let k = self.keys.len() as u32;
                self.key_index.insert(key.id, k);
                self.keys.push(key);
                self.key_wallets.push(Vec::new());
                k
            }
        };
        self.key_wallets[kid as usize].push(id);
        self.wallet_key.push(kid);
        let my_address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let mut addrs: HashSet<[u8; 43]> = (0..crate::walletdb::COINBASE_DIVERSIFIER_SCAN).map(|i| fvk.address_at(i, Scope::External).to_raw_address_bytes()).collect();
        addrs.insert(my_address);
        for a in addrs {
            self.addr_map.entry(a).or_default().push(id);
        }
        self.wallets.push(WalletLite {
            fvk,
            my_address,
            notes: Vec::new(),
            pending_spends: Vec::new(),
            pending_change: HashMap::new(),
            history: Vec::new(),
            history_enabled: true,
            last_daa: 0,
            poisoned: false,
            registered_at: self.chain.size(),
        });
        Some(id)
    }

    pub fn chain(&self) -> &SharedChain {
        &self.chain
    }
    pub fn wallet(&self, id: WalletId) -> &WalletLite {
        &self.wallets[id as usize]
    }
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
    pub fn stats(&self) -> EngineStats {
        self.stats
    }
    pub fn kernel_name(&self) -> &'static str {
        self.kernel.name()
    }

    /// `WalletLite::mark_spent` through the engine (the note's nullifier stays owned).
    pub fn mark_spent(&mut self, id: WalletId, position: u64, txid: [u8; 32], submitted_daa: u64) {
        self.wallets[id as usize].mark_spent(position, txid, submitted_daa);
    }

    /// `WalletLite::note_pending_outflow` through the engine.
    pub fn note_pending_outflow(&mut self, id: WalletId, txid: [u8; 32], outflow: u64) {
        self.wallets[id as usize].note_pending_outflow(txid, outflow);
    }

    /// `WalletLite::reclaim_expired` through the engine.
    pub fn reclaim_expired(&mut self, id: WalletId, now_daa: u64, max_age_daa: u64) -> Vec<([u8; 32], u64)> {
        self.wallets[id as usize].reclaim_expired(now_daa, max_age_daa)
    }

    /// Witnesses for a wallet's own note positions, from the one shared tree.
    pub fn witness_paths_at(&self, positions: &[u64], matured_leaves: u64) -> Vec<Option<MerklePath>> {
        self.chain.witness_paths_at(positions, matured_leaves)
    }

    /// Heap held by the engine: the shared chain once, plus each wallet's private part.
    pub fn approx_heap_bytes(&self) -> (usize, usize) {
        let per_wallet: usize = self.wallets.iter().map(|w| w.approx_heap_bytes()).sum::<usize>()
            + self.addr_map.capacity() * (43 + 24 + 8)
            + self.owned_nf.capacity() * (32 + 24 + 8)
            + self.keys.len() * (std::mem::size_of::<IvkKey>() + 7 * 2 * COMB_MAX_DIGITS * 2);
        (self.chain.approx_heap_bytes(), per_wallet)
    }

    fn own(&mut self, nf: [u8; 32], w: WalletId) {
        self.owned_nf.entry(nf).or_default().push(w);
    }

    /// Ingest one page for every wallet: one detection pass over all keys, then one walk
    /// over the blocks that touches only the wallets a block concerns, then the shared tree.
    pub fn ingest_page(&mut self, page: &SharedPage) {
        self.stats.pages += 1;
        self.stats.actions += page.actions.len() as u64;
        self.stats.pairs += (page.actions.len() * self.keys.len()) as u64;
        // (2) one detection pass: flat action index -> [(key, note)].
        let t = std::time::Instant::now();
        let mut hits_at: HashMap<usize, Vec<(u32, ReceivedNote)>> = HashMap::new();
        if !page.actions.is_empty() && !self.keys.is_empty() {
            let keys: Vec<&IvkKey> = self.keys.iter().collect();
            let found = detect(self.kernel.as_ref(), &keys, &page.actions, &page.epks);
            for (k, notes) in found.into_iter().enumerate() {
                for n in notes {
                    self.stats.hits += 1;
                    hits_at.entry(n.action_index).or_default().push((k as u32, n));
                }
            }
        }
        self.stats.detect_ns += t.elapsed().as_nanos();
        let mut flat = 0usize;
        for b in &page.blocks {
            self.ingest_block(b, &mut flat, &hits_at);
        }
        // `WalletDb` raises its clock on every block with meta; the maximum is the same.
        if let Some(d) = page.blocks.iter().filter_map(|b| b.meta.as_ref().map(|m| m.daa_score)).max() {
            for w in &mut self.wallets {
                w.last_daa = w.last_daa.max(d);
            }
        }
    }

    fn ingest_block(&mut self, b: &SharedBlock, flat: &mut usize, hits_at: &HashMap<usize, Vec<(u32, ReceivedNote)>>) {
        self.stats.blocks += 1;
        let t_fold = std::time::Instant::now();
        let size0 = self.chain.size();
        let meta = b.meta.as_ref();
        // Nullifiers applied by earlier transactions of THIS block (the chain set is still at
        // the block's start; the tree ingests the block after the walk).
        let mut block_nfs: HashSet<[u8; 32]> = HashSet::new();
        // Coinbase leaves come first, at size0 + k.
        for (k, (desc, value, _cmx)) in b.coinbase.iter().enumerate() {
            let Some(ws) = self.addr_map.get(&desc.recipient).cloned() else { continue };
            for w in ws {
                self.stats.coinbase_hits += 1;
                let chain = &self.chain;
                if let Some(nf) = self.wallets[w as usize].fold_coinbase(desc, *value, size0 + k as u64, meta, |nf| chain.nf_seen(nf)) {
                    self.own(nf, w);
                }
            }
        }
        let mut pos = size0 + b.coinbase.len() as u64;
        for (bi, records) in b.txs.iter().enumerate() {
            let f0 = *flat;
            *flat += records.len();
            // The consensus drop rule, exactly as `ingest_bundles_compact` applies it.
            if records.iter().any(|a| self.chain.nf_seen(&a.nullifier) || block_nfs.contains(&a.nullifier)) {
                for w in &mut self.wallets {
                    w.poisoned = true;
                }
                continue;
            }
            let positions: Vec<Option<u64>> = records
                .iter()
                .map(|r| {
                    Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&r.cmx)).map(|_| {
                        pos += 1;
                        pos - 1
                    })
                })
                .collect();
            // Wallets this transaction concerns: a detector hit, or one of their nullifiers.
            let mut received: HashMap<WalletId, Vec<ReceivedNote>> = HashMap::new();
            for i in 0..records.len() {
                if let Some(hs) = hits_at.get(&(f0 + i)) {
                    for (k, n) in hs {
                        for &w in &self.key_wallets[*k as usize] {
                            let mut n = n.clone();
                            n.action_index = i;
                            received.entry(w).or_default().push(n);
                        }
                    }
                }
            }
            let mut touched: Vec<WalletId> = received.keys().copied().collect();
            for r in records {
                if let Some(ws) = self.owned_nf.get(&r.nullifier) {
                    touched.extend(ws.iter().copied());
                }
            }
            touched.sort_unstable();
            touched.dedup();
            let txid = meta.and_then(|m| m.txids.get(bi).copied());
            for w in touched {
                self.stats.folds += 1;
                let rec = received.remove(&w).unwrap_or_default();
                let chain = &self.chain;
                let block_nfs = &block_nfs;
                let seen = |nf: &[u8; 32], i: usize| chain.nf_seen(nf) || block_nfs.contains(nf) || records[..=i].iter().any(|r| &r.nullifier == nf);
                let gained = self.wallets[w as usize].fold_tx(records, &rec, &positions, seen, meta, txid);
                // Keep the owned-nullifier map exact: drop what the fold spent, add what it gained.
                for r in records {
                    if let Some(ws) = self.owned_nf.get_mut(&r.nullifier) {
                        if ws.contains(&w) && !self.wallets[w as usize].owns(&r.nullifier) {
                            ws.retain(|x| *x != w);
                        }
                        if ws.is_empty() {
                            self.owned_nf.remove(&r.nullifier);
                        }
                    }
                }
                for nf in gained {
                    self.own(nf, w);
                }
            }
            block_nfs.extend(records.iter().map(|r| r.nullifier));
        }
        self.stats.fold_ns += t_fold.elapsed().as_nanos();
        let t_tree = std::time::Instant::now();
        self.chain.ingest(b);
        self.stats.tree_ns += t_tree.elapsed().as_nanos();
        debug_assert_eq!(self.chain.size(), pos, "engine leaf positions drifted from the shared tree");
        assert_eq!(self.chain.size(), pos, "engine leaf positions drifted from the shared tree");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::derive_coinbase_note_desc as derive_desc;
    use crate::coinbase::coinbase_note_commitment;
    use group::ff::{Field, PrimeField, WithSmallOrderMulGroup};
    use orchard::keys::SpendingKey;
    use orchard::note_encryption::{OrchardDomain, OrchardNoteEncryption};
    use zcash_note_encryption::Domain;

    /// splitmix64 stream, deterministic.
    struct Det(u64);
    impl Det {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
        fn b32(&mut self) -> [u8; 32] {
            let mut o = [0u8; 32];
            for c in o.chunks_mut(8) {
                c.copy_from_slice(&self.next().to_le_bytes());
            }
            o
        }
        fn scalar(&mut self) -> pallas::Scalar {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&self.b32());
            wide[32..].copy_from_slice(&self.b32());
            <pallas::Scalar as group::ff::FromUniformBytes<64>>::from_uniform_bytes(&wide)
        }
    }

    fn fvk(r: &mut Det) -> FullViewingKey {
        loop {
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(r.b32())) {
                return FullViewingKey::from(&sk);
            }
        }
    }

    /// A compact record carrying a real note to `addr` (nf doubles as rho).
    fn plant(addr: Address, value: u64, r: &mut Det) -> CompactActionRecord {
        loop {
            let mut nf = r.b32();
            nf[31] &= 0x3f;
            let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&nf)) else { continue };
            let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(r.b32(), &rho)) else { continue };
            let Some(note) = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2)) else { continue };
            let enc = OrchardNoteEncryption::new(None, note, [0u8; 512]);
            let epk = OrchardDomain::epk_bytes(enc.epk()).0;
            let ct = enc.encrypt_note_plaintext();
            let mut c52 = [0u8; 52];
            c52.copy_from_slice(&ct[..52]);
            return CompactActionRecord { nullifier: nf, cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(), ephemeral_key: epk, enc_ciphertext: c52 };
        }
    }

    #[test]
    fn decomposition_reconstructs_the_scalar() {
        let mut r = Det(1);
        let lambda = pallas::Scalar::ZETA;
        for _ in 0..2000 {
            let k = r.scalar();
            let ((n1, a1), (n2, a2)) = glv_decompose(&k);
            assert!(a1 >> 127 == 0 && a2 >> 127 == 0, "half exceeds 127 bits");
            let s = |neg: bool, a: u128| {
                let v = pallas::Scalar::from_u128(a);
                if neg { -v } else { v }
            };
            assert_eq!(s(n1, a1) + s(n2, a2) * lambda, k);
        }
        // Edge scalars.
        for k in [pallas::Scalar::ZERO, pallas::Scalar::ONE, -pallas::Scalar::ONE, lambda, -lambda] {
            let ((n1, a1), (n2, a2)) = glv_decompose(&k);
            let s = |neg: bool, a: u128| {
                let v = pallas::Scalar::from_u128(a);
                if neg { -v } else { v }
            };
            assert_eq!(s(n1, a1) + s(n2, a2) * lambda, k);
        }
    }

    #[test]
    fn the_endomorphism_is_multiplication_by_zeta() {
        let mut r = Det(2);
        for _ in 0..50 {
            let p = pallas::Point::generator() * r.scalar();
            assert_eq!(p.endo(), p * pallas::Scalar::ZETA);
        }
    }

    #[test]
    fn signed_digits_reconstruct() {
        let mut r = Det(3);
        for w in COMB_W_MIN..=COMB_W_MAX {
            for _ in 0..500 {
                let v = (u128::from(r.next()) | (u128::from(r.next()) << 64)) >> 1;
                let mut d = [0i16; COMB_MAX_DIGITS];
                let n = signed_digits(v, w, &mut d);
                let half = 1i32 << (w - 1);
                let mut acc: i128 = 0;
                for j in (0..n).rev() {
                    assert!((d[j] as i32).abs() <= half);
                    acc = (acc << w) + d[j] as i128;
                }
                assert_eq!(acc as u128, v);
                assert!(n <= COMB_MAX_DIGITS);
            }
        }
    }

    /// The comb and the shared ladder compute exactly `ivk · epk` for random pairs at every
    /// window width, including the identity-free edge of small and negated scalars.
    #[test]
    fn comb_and_ladder_agree_with_scalar_multiplication() {
        let mut r = Det(4);
        let points: Vec<pallas::Point> = (0..40).map(|_| pallas::Point::generator() * r.scalar()).collect();
        let mut scalars: Vec<pallas::Scalar> = (0..40).map(|_| r.scalar()).collect();
        scalars.extend([pallas::Scalar::ONE, -pallas::Scalar::ONE, pallas::Scalar::from(2u64), pallas::Scalar::ZETA]);
        for w in COMB_W_MIN..=COMB_W_MAX {
            let h = 1usize << (w - 1);
            let wi = (w - COMB_W_MIN) as usize;
            let combs: Vec<CombScalar> = scalars.iter().map(CombScalar::new).collect();
            let nw = combs.iter().map(|c| c.digits[wi][0].1.max(c.digits[wi][1].1)).max().unwrap();
            let (mut scratch, mut table) = (Vec::new(), Vec::new());
            for p in &points {
                CombKernel::table(p, w, nw, &mut scratch, &mut table);
                for (k, c) in scalars.iter().zip(&combs) {
                    assert_eq!(CombKernel::agree(&table, h, c, wi), p * k, "w={w}");
                }
            }
        }
        let tables = Table::<pallas::Point>::batch(&points);
        let refs: Vec<_> = tables.iter().collect();
        for k in &scalars {
            let got = Table::mul_decomposed_batch(&refs, &Decomposed::<pallas::Point>::new(k));
            for (g, p) in got.iter().zip(&points) {
                assert_eq!(*g, p * k);
            }
        }
    }

    /// Every kernel finds exactly what the daemon's own per-key path finds, over a page of
    /// strangers' actions with planted notes, hostile encodings and twins.
    #[test]
    fn detect_matches_the_per_key_path_for_every_kernel() {
        let mut r = Det(5);
        let fvks: Vec<FullViewingKey> = (0..24).map(|_| fvk(&mut r)).collect();
        let stranger = fvk(&mut r).address_at(3u32, Scope::External);
        let mut actions: Vec<CompactActionRecord> = (0..700).map(|_| plant(stranger, 1 + r.next() % 999, &mut r)).collect();
        for i in 0..60 {
            let w = (r.next() % fvks.len() as u64) as usize;
            let to = fvks[w].address_at((r.next() % 300) as u32, Scope::External);
            let at = (r.next() % (actions.len() as u64 + 1)) as usize;
            actions.insert(at, plant(to, 1000 + i, &mut r));
        }
        // Hostile: identity / invalid epk, non-canonical cmx.
        for (i, a) in actions.iter_mut().enumerate().filter(|(i, _)| i % 97 == 0) {
            match i % 3 {
                0 => a.ephemeral_key = [0u8; 32],
                1 => a.ephemeral_key = [0xff; 32],
                _ => a.cmx = [0xff; 32],
            }
        }
        let epks: Vec<_> = actions.iter().map(|a| decompress_epk(&a.ephemeral_key)).collect();
        let mut keys: Vec<IvkKey> = fvks.iter().map(|f| IvkKey::from_fvk(f).unwrap()).collect();
        keys.push(IvkKey::from_fvk(&fvks[0]).unwrap()); // a twin
        let refs: Vec<&IvkKey> = keys.iter().collect();
        let want: Vec<Vec<(usize, u64)>> = keys
            .iter()
            .map(|k| {
                crate::wallet::scan::scan_compact_auto_cached(&k.prepared, Some(&k.scalar), &actions, Some(&epks))
                    .iter()
                    .map(|n| (n.action_index, n.note.value().inner()))
                    .collect()
            })
            .collect();
        assert!(want.iter().map(|v| v.len()).sum::<usize>() >= 50, "planted notes must be found");
        let kernels: Vec<Box<dyn AgreeKernel>> =
            vec![Box::new(LadderKernel), Box::new(CombKernel { w: None }), Box::new(CombKernel { w: Some(2) }), Box::new(CombKernel { w: Some(8) })];
        for kern in &kernels {
            let got: Vec<Vec<(usize, u64)>> =
                detect(kern.as_ref(), &refs, &actions, &epks).iter().map(|v| v.iter().map(|n| (n.action_index, n.note.value().inner())).collect()).collect();
            assert_eq!(got, want, "kernel {}", kern.name());
        }
    }

    /// A synthetic chain (no node): coinbase to our diversified addresses, receipts, spends,
    /// spends of pending notes, a dropped (repeated-nullifier) transaction, hostile encodings.
    /// N per-wallet `WalletDb`s and one `ScanEngine` must agree on every observable.
    #[test]
    fn engine_equals_per_wallet_walletdb_on_a_synthetic_chain() {
        let mut r = Det(6);
        let n_wallets = 6usize;
        let fvks: Vec<FullViewingKey> = (0..n_wallets).map(|_| fvk(&mut r)).collect();
        let stranger = fvk(&mut r).address_at(0u32, Scope::External);
        let fs0 = FrontierState { size: 0, leaf: None, ommers: Vec::new() };
        let mut old: Vec<WalletDb> = fvks
            .iter()
            .map(|f| {
                let mut d = WalletDb::from_fvk(&f.to_bytes()).unwrap();
                d.apply_frontier(&fs0).unwrap();
                d
            })
            .collect();
        // The daemon's `--shared-scan-engine` path: per-wallet WalletDbs fed by ONE cohort
        // detection (`install_predecrypted`) instead of their own `predecrypt_page_cached`.
        let mut cohort: Vec<WalletDb> = fvks
            .iter()
            .map(|f| {
                let mut d = WalletDb::from_fvk(&f.to_bytes()).unwrap();
                d.apply_frontier(&fs0).unwrap();
                d
            })
            .collect();
        let mut eng = ScanEngine::new(SharedChain::from_frontier(&fs0).unwrap(), Box::new(LadderKernel));
        let ids: Vec<WalletId> = fvks.iter().map(|f| eng.register(f.clone()).unwrap()).collect();
        // Wallet 5 is a twin of wallet 0 (same key, two tokens).
        let twin = eng.register(fvks[0].clone()).unwrap();
        let mut old_twin = WalletDb::from_fvk(&fvks[0].to_bytes()).unwrap();
        old_twin.apply_frontier(&fs0).unwrap();
        let mut spent_once: HashSet<[u8; 32]> = HashSet::new();
        let mut daa = 1000u64;
        for page in 0..6 {
            let mut blocks = Vec::new();
            for bn in 0..40 {
                daa += 1;
                let mut coinbase = Vec::new();
                for c in 0..2 {
                    let to = if r.next() % 5 == 0 {
                        fvks[(r.next() % n_wallets as u64) as usize].address_at((r.next() % 256) as u32, Scope::External).to_raw_address_bytes()
                    } else {
                        stranger.to_raw_address_bytes()
                    };
                    let mut seed = r.b32().to_vec();
                    seed.push(c);
                    let desc = derive_desc(to, &seed);
                    let value = 1 + r.next() % 1_000_000;
                    if let Ok(cmx) = coinbase_note_commitment(&desc, value) {
                        coinbase.push((desc, value, cmx));
                    }
                }
                let mut txs: Vec<Vec<CompactActionRecord>> = Vec::new();
                // A spend of one of wallet notes (each at most once), sometimes paired with change.
                let held: Vec<[u8; 32]> = old.iter().flat_map(|w| w.notes().iter().map(|n| n.nullifier()).chain(w.pending_spends().iter().map(|p| p.note.nullifier()))).filter(|nf| !spent_once.contains(nf)).collect();
                if !held.is_empty() && r.next() % 4 == 0 {
                    let nf = held[(r.next() % held.len() as u64) as usize];
                    spent_once.insert(nf);
                    let mut a = plant(stranger, 5, &mut r);
                    a.nullifier = nf;
                    let mut tx = vec![a];
                    if r.next() % 2 == 0 {
                        tx.push(plant(fvks[(r.next() % n_wallets as u64) as usize].address_at(1u32, Scope::External), 77, &mut r));
                    }
                    txs.push(tx);
                }
                // Receipts.
                if r.next() % 3 == 0 {
                    let w = (r.next() % n_wallets as u64) as usize;
                    let mut tx = vec![plant(stranger, 3, &mut r), plant(fvks[w].address_at((r.next() % 300) as u32, Scope::External), 1 + r.next() % 1_000_000_000, &mut r)];
                    if r.next() % 3 == 0 {
                        let mut bad = plant(stranger, 9, &mut r);
                        match r.next() % 3 {
                            0 => bad.ephemeral_key = [0u8; 32],
                            1 => bad.ephemeral_key = [0xff; 32],
                            _ => bad.cmx = [0xff; 32],
                        }
                        tx.push(bad);
                    }
                    txs.push(tx);
                }
                // Strangers.
                txs.push((0..(r.next() % 4)).map(|_| plant(stranger, 1, &mut r)).collect());
                // A dropped transaction (repeats a nullifier already applied in this block).
                if page == 3 && bn == 7 {
                    let a = plant(stranger, 2, &mut r);
                    txs.push(vec![a]);
                    txs.push(vec![a]);
                }
                let txids: Vec<[u8; 32]> = txs.iter().map(|_| r.b32()).collect();
                let meta = Some(BlockMeta { coinbase_txid: r.b32(), txids, timestamp_ms: 1_700_000_000_000 + daa, daa_score: daa });
                blocks.push(SharedBlock { hash: r.b32(), blue_score: daa, daa_score: daa, coinbase, txs, meta });
            }
            let sp = SharedPage::new(blocks.clone());
            for (w, db) in old.iter_mut().chain(std::iter::once(&mut old_twin)).enumerate() {
                db.predecrypt_page_cached(&sp.actions, Some(&sp.epks));
                for b in &blocks {
                    db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, b.meta.as_ref());
                }
                db.end_page();
                let _ = w;
            }
            eng.ingest_page(&sp);
            {
                let keys: Vec<IvkKey> = cohort.iter().map(|d| IvkKey::from_ivk(d.incoming_viewing_key()).unwrap()).collect();
                let refs: Vec<&IvkKey> = keys.iter().collect();
                let found = detect(&CombKernel { w: Some(4) }, &refs, &sp.actions, &sp.epks);
                for (db, f) in cohort.iter_mut().zip(found) {
                    db.install_predecrypted(&sp.actions, f, 0);
                    for b in &blocks {
                        db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, b.meta.as_ref());
                    }
                    db.end_page();
                }
            }
            // Park a note as a pending spend on every side now and then.
            if page % 2 == 1 {
                for (w, db) in old.iter_mut().enumerate() {
                    if let Some(p) = db.notes().first().map(|n| n.position) {
                        db.mark_spent(p, [page as u8; 32], daa);
                        eng.mark_spent(ids[w], p, [page as u8; 32], daa);
                        cohort[w].mark_spent(p, [page as u8; 32], daa);
                    }
                }
            }
            if page == 4 {
                for (w, db) in old.iter_mut().enumerate() {
                    let a = db.reclaim_expired(daa + 10_000, 100);
                    assert_eq!(a, eng.reclaim_expired(ids[w], daa + 10_000, 100));
                    assert_eq!(a, cohort[w].reclaim_expired(daa + 10_000, 100));
                }
            }
            for (w, db) in old.iter().enumerate() {
                assert_same_db(db, &cohort[w], &format!("page {page} cohort wallet {w}"));
            }
            for (w, db) in old.iter().enumerate() {
                assert_same(db, &eng, ids[w], &format!("page {page} wallet {w}"));
            }
            assert_same(&old_twin, &eng, twin, &format!("page {page} twin"));
        }
        let found: usize = old.iter().map(|d| d.notes().len() + d.pending_spends().len()).sum();
        assert!(found > 20, "the comparison must not be vacuous ({found} notes)");
        assert!(old.iter().all(|d| d.poisoned()), "the dropped transaction poisons every per-wallet db");
        // Witnesses from the shared tree equal each wallet's own.
        let size = eng.chain().size();
        for (w, db) in old.iter().enumerate() {
            let pos: Vec<u64> = db.notes().iter().map(|n| n.position).collect();
            let a = db.witness_paths_at(&pos, size);
            let b = eng.witness_paths_at(&pos, size);
            for ((pa, pb), p) in a.iter().zip(&b).zip(&pos) {
                let (pa, pb) = (pa.as_ref().expect("own witness"), pb.as_ref().expect("shared witness"));
                assert_eq!(format!("{pa:?}"), format!("{pb:?}"), "wallet {w} witness at {p}");
            }
        }
    }

    /// Two per-wallet databases with identical observable state.
    pub(crate) fn assert_same_db(a: &WalletDb, b: &WalletDb, ctx: &str) {
        let key = |n: &OwnedNote| (n.position, n.value(), n.nullifier(), ExtractedNoteCommitment::from(n.note.commitment()).to_bytes());
        assert_eq!(a.notes().iter().map(key).collect::<Vec<_>>(), b.notes().iter().map(key).collect::<Vec<_>>(), "{ctx}: notes");
        let pk = |p: &PendingSpend| (key(&p.note), p.txid, p.submitted_daa);
        assert_eq!(a.pending_spends().iter().map(pk).collect::<Vec<_>>(), b.pending_spends().iter().map(pk).collect::<Vec<_>>(), "{ctx}: pending");
        assert_eq!(format!("{:?}", a.history()), format!("{:?}", b.history()), "{ctx}: history");
        assert_eq!((a.size(), a.anchor(), a.nf_len(), a.poisoned(), a.last_daa()), (b.size(), b.anchor(), b.nf_len(), b.poisoned(), b.last_daa()), "{ctx}: tree");
    }

    pub(crate) fn assert_same(db: &WalletDb, eng: &ScanEngine, id: WalletId, ctx: &str) {
        let w = eng.wallet(id);
        let key = |n: &OwnedNote| (n.position, n.value(), n.nullifier(), ExtractedNoteCommitment::from(n.note.commitment()).to_bytes());
        assert_eq!(db.notes().iter().map(key).collect::<Vec<_>>(), w.notes().iter().map(key).collect::<Vec<_>>(), "{ctx}: notes");
        assert_eq!(db.balance(), w.balance(), "{ctx}: balance");
        let pk = |p: &PendingSpend| (key(&p.note), p.txid, p.submitted_daa);
        assert_eq!(db.pending_spends().iter().map(pk).collect::<Vec<_>>(), w.pending_spends().iter().map(pk).collect::<Vec<_>>(), "{ctx}: pending");
        assert_eq!(db.pending_change(), w.pending_change(), "{ctx}: pending change");
        assert_eq!(format!("{:?}", db.history()), format!("{:?}", w.history()), "{ctx}: history");
        assert_eq!(db.last_daa(), w.last_daa(), "{ctx}: last_daa");
        assert_eq!(db.poisoned(), w.poisoned(), "{ctx}: poisoned");
        assert_eq!(db.size(), eng.chain().size(), "{ctx}: tree size");
        assert_eq!(db.anchor(), eng.chain().anchor(), "{ctx}: anchor");
        assert_eq!(db.nf_len(), eng.chain().nf_len(), "{ctx}: applied nullifiers");
        for n in db.notes() {
            assert_eq!(db.applied_nullifier(&n.nullifier()), eng.chain().nf_seen(&n.nullifier()), "{ctx}: nf state");
        }
    }

}
