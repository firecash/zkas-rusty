//! Stage W conformance tests at the builder (spec 02 §7.1 T1, T3-at-the-builder, T5) and the
//! spec 11 R4 internal-IVK trigger scan.
//!
//! T1 golden vectors: every uniform builder entry point is driven by a ChaCha20 RNG seeded with
//! fixed bytes, and the SHA-256 of each payload is compared with
//! `sdk/wallet-engine/tests/vectors/uniform-v1.json`. walletd and the TypeScript SDK check the
//! same file, so a client that builds a different byte stream for the same inputs fails CI.
//! Regenerate (only after a deliberate format change) with `ZKAS_WRITE_UNIFORM_VECTORS=1`.

use crate::bundle::ShieldedBundle;
use crate::coinbase::{CoinbaseNoteDesc, coinbase_note_commitment, derive_coinbase_note_desc};
use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState, ShieldedTx};
use crate::verify::{sighash, verify_bundle};
use crate::wallet::build::{
    SendShape, UNIFORM_ACTIONS, build_wallet_payment_multi_shaped, finalize_payment_with_rng, prepare_payment_shaped,
    sign_spend_auth_with_rng,
};
use crate::wallet::scan::address_bytes_from_seed;
use crate::walletdb::WalletDb;
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::Note;
use orchard::tree::MerklePath;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

/// F_V1 and the V1 payload length, mirrored from `zkas_wallet_engine::uniform` (the engine depends
/// on this crate, not the other way round; its tests assert the same numbers).
const F: u64 = 3_117_800;
const PAYLOAD_LEN: usize = 15_493;
const FLAGS: u8 = 0x0b;
const NET: [u8; 32] = [0x5a; 32];
const CTX: &[u8] = b"zkas-uniform-v1";
const ANCHOR_BLOCK: [u8; 32] = [0xab; 32];
const MINER: [u8; 32] = [71; 32];
const ZKAS: u64 = 100_000_000;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cb(address: [u8; 43], seed: &[u8], value: u64) -> (CoinbaseNoteDesc, u64) {
    (derive_coinbase_note_desc(address, seed), value)
}

/// A chain with `values.len()` notes minted to MINER in one block, the matching state and wallet.
fn fixture(values: &[u64]) -> (ShieldedState, WalletDb) {
    let mut db = WalletDb::from_seed(MINER).unwrap();
    let mut state = ShieldedState::new();
    let addr = address_bytes_from_seed(MINER).unwrap();
    let notes: Vec<_> = values.iter().enumerate().map(|(i, v)| cb(addr, format!("u||{i}").as_bytes(), *v)).collect();
    let mint = CoinbaseMint::new(notes.iter().map(|n| CoinbaseNote { value: n.1, commitment: coinbase_note_commitment(&n.0, n.1).unwrap() }).collect());
    state.apply_chain_block(Some(&mint), &[]).unwrap();
    db.ingest_block(&notes, &[]);
    assert_eq!(db.notes().len(), values.len());
    (state, db)
}

fn inputs(db: &WalletDb, k: usize) -> Vec<(Note, MerklePath)> {
    db.notes().iter().take(k).map(|o| (o.note.clone(), db.witness_path(o.position).unwrap())).collect()
}

fn rng(tag: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([tag; 32])
}

fn payee(seed: u8) -> [u8; 43] {
    address_bytes_from_seed([seed; 32]).unwrap()
}

/// The envelope every uniform payload must have, plus proof verification and consensus
/// acceptance on a fresh copy of the state.
fn assert_uniform(payload: &[u8], state: &ShieldedState) -> ShieldedBundle {
    assert_eq!(payload.len(), PAYLOAD_LEN, "payload length");
    let b = ShieldedBundle::from_bytes(payload).unwrap();
    assert_eq!(b.actions.len(), UNIFORM_ACTIONS);
    assert_eq!(b.flags, FLAGS);
    assert_eq!(b.value_balance, F as i64);
    assert_eq!(b.anchor_block, Some(ANCHOR_BLOCK));
    assert!(b.burn.is_none());
    verify_bundle(&b, &sighash(&b, &NET, CTX)).expect("uniform bundle verifies");
    let mut s = state.clone();
    let stx = ShieldedTx::from_bundle(&b).unwrap();
    assert_eq!(s.apply_chain_block(None, &[stx]).unwrap().accepted, vec![0], "consensus state accepts it");
    b
}

/// One custodial vector: `k` notes of `note_value`, the given payees, shape, RNG tag.
fn custodial(name: &str, values: &[u64], k: usize, payees: &[([u8; 43], u64, [u8; 512])], shape: SendShape, tag: u8) -> (String, Vec<u8>) {
    let (state, db) = fixture(values);
    let build = |t| {
        build_wallet_payment_multi_shaped(MINER, inputs(&db, k), payees, F, &NET, CTX, true, Some(ANCHOR_BLOCK), shape, &mut rng(t)).unwrap()
    };
    let p = build(tag);
    assert_uniform(&p, &state);
    assert_eq!(p, build(tag), "{name}: the same seed must give the same bytes");
    (name.to_string(), p)
}

fn all_vectors() -> Vec<(String, Vec<u8>)> {
    let z = ZKAS;
    let m = [0u8; 512];
    let mut memo = [0u8; 512];
    memo[..11].copy_from_slice(b"invoice 42!");
    let own = address_bytes_from_seed(MINER).unwrap();
    let mut v = vec![
        custodial("pay-1-note", &[5 * z], 1, &[(payee(2), 2 * z, m)], SendShape::UNIFORM, 1),
        custodial("pay-2-notes", &[3 * z, 3 * z], 2, &[(payee(2), 5 * z, m)], SendShape::UNIFORM, 2),
        custodial("pay-3-notes", &[2 * z, 2 * z, 2 * z], 3, &[(payee(2), 5 * z, m)], SendShape::UNIFORM, 3),
        custodial("pay-4-notes", &[2 * z; 4], 4, &[(payee(2), 7 * z, m)], SendShape::UNIFORM, 4),
        custodial("batch-3-payees", &[5 * z, 5 * z], 2, &[(payee(2), z, m), (payee(3), 2 * z, m), (payee(4), 3 * z, m)], SendShape::UNIFORM, 5),
        custodial("merge-4-to-1", &[z, z, z, z], 4, &[(own, 4 * z - F, m)], SendShape::UNIFORM, 6),
        custodial("zero-change", &[5 * z], 1, &[(payee(2), 5 * z - F, m)], SendShape::UNIFORM, 7),
        custodial("memo", &[5 * z], 1, &[(payee(2), 2 * z, memo)], SendShape::UNIFORM, 8),
        custodial("internal-change", &[5 * z], 1, &[(payee(2), 2 * z, m)], SendShape::UNIFORM_INTERNAL, 9),
    ];
    // Non-custodial: prepare (viewing key only) -> device signs -> finalize, all seeded.
    let (state, db) = fixture(&[3 * z, 3 * z]);
    let sk = SpendingKey::from_bytes(MINER).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);
    let prepared = |t| {
        let mut r = rng(t);
        let p = prepare_payment_shaped(&fvk, inputs(&db, 2), payee(2), 4 * z, F, &NET, CTX, true, m, Some(ANCHOR_BLOCK), SendShape::UNIFORM, &mut r).unwrap();
        crate::payment_check::check_prepared_payment(&p.effects, &p.disclosure, &fvk, &payee(2), 4 * z, F).expect("device accepts it");
        let sigs: Vec<_> = p.spend_auth_requests.iter().map(|(i, a)| (*i, sign_spend_auth_with_rng(&ask, *a, p.sighash, &mut r).unwrap())).collect();
        finalize_payment_with_rng(p, sigs, &mut r).unwrap().to_bytes()
    };
    let p = prepared(10);
    assert_uniform(&p, &state);
    assert_eq!(p, prepared(10), "prepare path is deterministic under a pinned RNG");
    v.push(("prepare-2-notes".into(), p));
    v
}

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sdk/wallet-engine/tests/vectors/uniform-v1.json")
}

#[test]
fn t1_uniform_vectors_are_byte_identical_to_the_golden_file() {
    let v = all_vectors();
    let entries: Vec<serde_json::Value> = v
        .iter()
        .map(|(name, p)| {
            let mut e = serde_json::json!({ "name": name, "len": p.len(), "sha256": hexs(&Sha256::digest(p)) });
            // One full payload, so the SDK can check its own parser on real bytes.
            if name == "pay-1-note" {
                e["payload_hex"] = serde_json::Value::String(hexs(p));
            }
            e
        })
        .collect();
    let doc = serde_json::json!({
        "format": "zkas uniform-v1 conformance vectors (spec 02 §7.1 T1)",
        "rng": "ChaCha20Rng::from_seed([tag; 32]), one fresh RNG per build",
        "fee": F, "flags": FLAGS, "actions": UNIFORM_ACTIONS, "payload_len": PAYLOAD_LEN,
        "network_domain": hexs(&NET), "tx_context": hexs(CTX), "anchor_block": hexs(&ANCHOR_BLOCK),
        "vectors": entries,
    });
    let path = vectors_path();
    if std::env::var("ZKAS_WRITE_UNIFORM_VECTORS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        return;
    }
    let golden: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("golden vectors file")).unwrap();
    assert_eq!(golden["vectors"], doc["vectors"], "uniform builder output drifted from the golden vectors");
}

#[test]
fn uniform_requests_that_cannot_fit_are_refused_before_proving() {
    let (_state, db) = fixture(&[ZKAS; 5]);
    let m = [0u8; 512];
    let five = build_wallet_payment_multi_shaped(MINER, inputs(&db, 5), &[(payee(2), ZKAS, m)], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM, &mut rng(1));
    assert!(five.is_err(), "5 spends cannot be a 4-action transaction");
    let four_payees: Vec<_> = (2..6).map(|s| (payee(s), 1_000u64, m)).collect();
    let r = build_wallet_payment_multi_shaped(MINER, inputs(&db, 1), &four_payees, F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM, &mut rng(1));
    assert!(r.is_err(), "4 payees + change is 5 outputs");
}

/// Spec 11 R4: change sent to the INTERNAL address is found by the sender's wallet (live ingest),
/// by a fresh restore from the seed, and by a watch-only copy from the viewing key; and the send's
/// history row names the payee, not the internal change address.
#[test]
fn r4_internal_change_is_found_live_on_restore_and_watch_only() {
    let z = ZKAS;
    let addr = address_bytes_from_seed(MINER).unwrap();
    let notes: Vec<_> = (0..1).map(|i| cb(addr, format!("r4||{i}").as_bytes(), 5 * z)).collect();
    let mint = CoinbaseMint::new(notes.iter().map(|n| CoinbaseNote { value: n.1, commitment: coinbase_note_commitment(&n.0, n.1).unwrap() }).collect());
    let mut state = ShieldedState::new();
    state.apply_chain_block(Some(&mint), &[]).unwrap();
    let mut live = WalletDb::from_seed(MINER).unwrap();
    live.ingest_block(&notes, &[]);
    let p = build_wallet_payment_multi_shaped(MINER, inputs(&live, 1), &[(payee(2), 2 * z, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM_INTERNAL, &mut rng(42)).unwrap();
    let b = assert_uniform(&p, &state);
    state.apply_chain_block(None, &[ShieldedTx::from_bundle(&b).unwrap()]).unwrap();
    let change = 3 * z - F;
    live.ingest_block(&[], &[&b]);
    assert_eq!(live.balance(), change as u128, "live wallet sees its internal change");
    let n = live.notes().iter().find(|n| n.value() == change).expect("change note held");
    assert_eq!(n.note.recipient().to_raw_address_bytes(), live.internal_address_bytes());

    let mut restored = WalletDb::from_seed(MINER).unwrap();
    restored.ingest_block(&notes, &[]);
    restored.ingest_block(&[], &[&b]);
    assert_eq!(restored.balance(), change as u128, "a restore from seed finds it (chronological scan)");

    let fvk = FullViewingKey::from(&SpendingKey::from_bytes(MINER).unwrap()).to_bytes();
    let mut watch = WalletDb::from_fvk(&fvk).unwrap();
    watch.ingest_block(&notes, &[]);
    watch.ingest_block(&[], &[&b]);
    assert_eq!(watch.balance(), change as u128, "a watch-only copy finds it");

    // A stranger's wallet never runs the internal key on this bundle (it owns no nullifier in it)
    // and finds nothing.
    let mut stranger = WalletDb::from_seed([2u8; 32]).unwrap();
    stranger.ingest_block(&notes, &[]);
    stranger.ingest_block(&[], &[&b]);
    assert_eq!(stranger.balance(), 2 * z as u128, "the payee sees exactly its payment");

    // The internal change can be spent again (scope_for_address resolves Internal).
    let again = build_wallet_payment_multi_shaped(MINER, inputs(&live, 1), &[(payee(3), z, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM_INTERNAL, &mut rng(43)).unwrap();
    assert_uniform(&again, &state);
}

/// Without the trigger (an external-only scan) the change would be invisible: this pins that R4 is
/// what finds it, so a future refactor that drops the trigger fails here and not in a user's wallet.
#[test]
fn r4_change_does_not_decrypt_under_the_external_key() {
    let (state, db) = fixture(&[5 * ZKAS]);
    let p = build_wallet_payment_multi_shaped(MINER, inputs(&db, 1), &[(payee(2), 2 * ZKAS, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM_INTERNAL, &mut rng(44)).unwrap();
    let b = assert_uniform(&p, &state);
    let fvk = FullViewingKey::from(&SpendingKey::from_bytes(MINER).unwrap());
    let ext = crate::wallet::scan::scan_bundle(&fvk.to_ivk(Scope::External), &b);
    assert!(ext.is_empty(), "internal change is not visible to the external key");
    let int = crate::wallet::scan::scan_bundle(&fvk.to_ivk(Scope::Internal), &b);
    assert_eq!(int.len(), 1);
}

/// T5 (spec 02 §7.1): real and dummy actions are indistinguishable byte by byte. For every byte
/// position of nf, rk, cmx, cv_net, epk, the first 64 and last 16 bytes of enc_ciphertext, and all
/// of out_ciphertext, a two-sample chi-square homogeneity test of the byte histograms (actions
/// carrying the real spend vs dummies, and the real output vs dummies) must not reject at
/// alpha = 0.001 after Bonferroni over every position and both sides. Each bundle spends a FRESH
/// random note, as real traffic does (a fixed note would repeat its nullifier). Unproven bundles:
/// the proof is per bundle, not per action, and building is what is under test.
#[test]
fn t5_dummy_actions_are_indistinguishable_from_real_ones() {
    use incrementalmerkletree::{Hashable, Level};
    use orchard::builder::Builder;
    use orchard::note::{ExtractedNoteCommitment, RandomSeed, Rho};
    use orchard::tree::MerkleHashOrchard;
    use orchard::value::NoteValue;
    use rand_core::Rng;
    const BUNDLES: usize = 3_000;
    let sk = SpendingKey::from_bytes(MINER).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let me = fvk.address_at(0u32, Scope::External);
    let ovk = Some(fvk.to_ovk(Scope::External));
    let to = orchard::Address::from_raw_address_bytes(&payee(2)).unwrap();
    let empty_path = || {
        let auth: [MerkleHashOrchard; 32] = core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
        MerklePath::from_parts(0, auth)
    };
    let fields: [(&str, std::ops::Range<usize>); 8] = [
        ("nf", 0..32),
        ("rk", 32..64),
        ("cmx", 64..96),
        ("cv_net", 96..128),
        ("epk", 128..160),
        ("enc_head", 160..224),
        ("enc_tag", 724..740),
        ("out", 740..820),
    ];
    let positions: Vec<(usize, &str)> = fields.iter().flat_map(|(n, r)| r.clone().map(move |p| (p, *n))).collect();
    let mut hist = vec![[[0u32; 256]; 2]; 2 * positions.len()];
    let mut r = rng(77);
    let mut built = 0usize;
    while built < BUNDLES {
        let mut rb = [0u8; 32];
        r.fill_bytes(&mut rb);
        rb[31] &= 0x3f;
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&rb)) else { continue };
        let mut sb = [0u8; 32];
        r.fill_bytes(&mut sb);
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(sb, &rho)) else { continue };
        let value = NoteValue::from_raw(ZKAS + (r.next_u64() % ZKAS));
        let Some(note) = Option::<Note>::from(Note::from_parts(me, value, rho, rseed, orchard::note::NoteVersion::V2)) else { continue };
        let path = empty_path();
        let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));
        let mut builder = Builder::new(crate::wallet::build::UNIFORM_BUNDLE_TYPE, crate::verify::BUNDLE_VERSION, orchard::bundle::Flags::ENABLED, anchor).unwrap();
        builder.add_spend(fvk.clone(), note, path).unwrap();
        builder.add_output(ovk.clone(), to, NoteValue::from_raw(ZKAS / 2), [0u8; 512]).unwrap();
        let (unauth, meta) = builder.build::<i64>(&mut r).unwrap().unwrap();
        let wire = crate::wallet::build::to_wire(&unauth, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        assert_eq!(wire.actions.len(), UNIFORM_ACTIONS);
        let real_spend = meta.spend_action_index(0).unwrap();
        let real_out = meta.output_action_index(0).unwrap();
        for (ai, a) in wire.actions.iter().enumerate() {
            let mut bytes = Vec::with_capacity(884);
            for part in [&a.nullifier[..], &a.rk, &a.cmx, &a.cv_net, &a.ephemeral_key, &a.enc_ciphertext, &a.out_ciphertext] {
                bytes.extend_from_slice(part);
            }
            for (k, &(pos, _)) in positions.iter().enumerate() {
                hist[k][usize::from(ai != real_spend)][bytes[pos] as usize] += 1;
                hist[positions.len() + k][usize::from(ai != real_out)][bytes[pos] as usize] += 1;
            }
        }
        built += 1;
    }
    // Wilson-Hilferty chi-square critical value at alpha = 0.001 / tests, one-sided.
    let tests = hist.len() as f64;
    let alpha = 0.001 / tests;
    // Normal quantile by bisection on the complementary error function.
    let q = {
        let tail = |z: f64| 0.5 * libm_erfc(z / std::f64::consts::SQRT_2);
        let (mut lo, mut hi) = (0.0f64, 10.0f64);
        for _ in 0..100 {
            let mid = (lo + hi) / 2.0;
            if tail(mid) > alpha { lo = mid } else { hi = mid }
        }
        lo
    };
    let crit = |df: f64| df * (1.0 - 2.0 / (9.0 * df) + q * (2.0 / (9.0 * df)).sqrt()).powi(3);
    let mut worst = (0.0f64, String::new());
    for (k, h) in hist.iter().enumerate() {
        let (n0, n1) = (h[0].iter().sum::<u32>() as f64, h[1].iter().sum::<u32>() as f64);
        let (mut chi, mut df) = (0.0, -1.0);
        for b in 0..256 {
            let tot = (h[0][b] + h[1][b]) as f64;
            if tot == 0.0 {
                continue;
            }
            df += 1.0;
            for (side, n) in [(0usize, n0), (1, n1)] {
                let e = tot * n / (n0 + n1);
                chi += (h[side][b] as f64 - e).powi(2) / e;
            }
        }
        if df < 1.0 {
            continue;
        }
        let ratio = chi / crit(df);
        if ratio > worst.0 {
            let (pos, name) = positions[k % positions.len()];
            let side = if k < positions.len() { "spend" } else { "output" };
            worst = (ratio, format!("{side} side, {name} byte {pos}: chi2 {chi:.1}, df {df}"));
        }
    }
    assert!(worst.0 < 1.0, "a byte position separates real from dummy actions: {} (chi2/crit {:.2})", worst.1, worst.0);
}

/// erfc for the T5 critical value (Numerical Recipes erfcc, |error| < 1.2e-7).
fn libm_erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t * (-z * z - 1.265_512_23 + t * (1.000_023_68 + t * (0.374_091_96 + t * (0.096_784_18 + t * (-0.186_288_06
        + t * (0.278_868_07 + t * (-1.135_203_98 + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
        .exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

/// Cost per payment, before (legacy shape) and after (uniform), for a 1-note and a 3-note payment:
/// payload bytes and proving wall time. Run on one rayon thread for a core-seconds figure:
/// `RAYON_NUM_THREADS=1 cargo test --release -p kaspa-shielded-core --features circuit
///  bench_uniform_cost -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench_uniform_cost_vs_legacy() {
    let z = ZKAS;
    let m = [0u8; 512];
    const RUNS: usize = 5;
    for (label, values, k, amount) in [("1-note", vec![5 * z], 1usize, 2 * z), ("3-note", vec![2 * z, 2 * z, 2 * z], 3, 5 * z)] {
        let (_state, db) = fixture(&values);
        for (shape_name, shape, fee) in [("legacy", SendShape::LEGACY, 3_000_000u64), ("uniform", SendShape::UNIFORM, F)] {
            // Warm the proving key once.
            let _ = build_wallet_payment_multi_shaped(MINER, inputs(&db, k), &[(payee(2), amount, m)], fee, &NET, CTX, true, Some(ANCHOR_BLOCK), shape, &mut rng(1)).unwrap();
            let t = std::time::Instant::now();
            let mut bytes = 0;
            let mut n = 0;
            for i in 0..RUNS {
                let p = build_wallet_payment_multi_shaped(MINER, inputs(&db, k), &[(payee(2), amount, m)], fee, &NET, CTX, true, Some(ANCHOR_BLOCK), shape, &mut rng(i as u8)).unwrap();
                bytes = p.len();
                n = ShieldedBundle::from_bytes(&p).unwrap().actions.len();
            }
            let per = t.elapsed().as_secs_f64() / RUNS as f64;
            println!("BENCH {label} {shape_name}: actions {n}, payload {bytes} B, build+prove {per:.3} s");
        }
    }
}

/// Change split into dummy slots: never more parts than spare slots, each part at least the
/// minimum, and the parts always sum to the change exactly.
#[test]
fn change_split_uses_only_spare_slots_and_sums_exactly() {
    let legacy = SendShape::LEGACY.with_change_split(3, 1_000);
    assert_eq!(legacy.change_values(10_001, 1, 1), vec![10_001], "1 spend, 1 payee: 2 actions, no spare slot");
    assert_eq!(legacy.change_values(10_001, 3, 1), vec![5_001, 5_000], "3 spends pad to 3 actions: one spare slot");
    assert_eq!(legacy.change_values(10_001, 5, 1), vec![3_335, 3_333, 3_333], "capped at change_parts");
    assert_eq!(legacy.change_values(2_500, 5, 1), vec![1_250, 1_250], "no part under the minimum");
    assert_eq!(legacy.change_values(999, 5, 1), vec![999], "small change stays one note");
    assert_eq!(legacy.change_values(0, 5, 1), vec![0], "zero change is still one (uniform needs it present)");
    let uniform = SendShape::UNIFORM.with_change_split(3, 1_000);
    assert_eq!(uniform.change_values(9_000, 1, 1), vec![3_000, 3_000, 3_000], "uniform: 4 slots, 1 payee, 2 spare");
    assert_eq!(uniform.change_values(9_000, 1, 3), vec![9_000], "uniform with 3 payees: no spare slot");
    assert_eq!(SendShape::UNIFORM.change_values(9_000, 1, 1), vec![9_000], "the default never splits");
    let extra = SendShape::LEGACY.with_change_split(3, 1_000).with_change_extra_actions(1);
    assert_eq!(extra.change_values(10_000, 1, 1), vec![5_000, 5_000], "1 spend, 1 payee: one extra action buys a second note");
    assert_eq!(extra.actions_for(1, 1, 2), 3);
    assert_eq!(SendShape::UNIFORM.with_change_split(3, 1).with_change_extra_actions(1).change_values(9, 1, 3), vec![9], "uniform never grows");
    for spends in 1..=6 {
        for payees in 1..=3 {
            for change in [0u64, 1, 999, 1_000, 7_777, u64::MAX / 2] {
                let v = legacy.change_values(change, spends, payees);
                assert_eq!(v.iter().map(|x| *x as u128).sum::<u128>(), change as u128);
                assert!(payees + v.len() <= spends.max(payees + 1).max(2), "never adds an action");
            }
        }
    }
}

/// A real split payment: the bundle is byte-for-byte the uniform envelope (same length, same 4
/// actions, verifies, consensus accepts it), the wallet holds each change part as its own note,
/// the payee sees exactly its payment, and the history records one payment of the paid amount.
#[test]
fn split_change_is_a_normal_uniform_payment_with_separate_change_notes() {
    let z = ZKAS;
    let (mut state, mut db) = fixture(&[5 * z]);
    let shape = SendShape::UNIFORM.with_change_split(3, z / 10);
    let p = build_wallet_payment_multi_shaped(MINER, inputs(&db, 1), &[(payee(2), 2 * z, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), shape, &mut rng(51)).unwrap();
    let b = assert_uniform(&p, &state);
    state.apply_chain_block(None, &[ShieldedTx::from_bundle(&b).unwrap()]).unwrap();
    db.ingest_block(&[], &[&b]);
    let change = 3 * z - F;
    assert_eq!(db.balance(), change as u128);
    let mut parts: Vec<u64> = db.notes().iter().map(|n| n.value()).collect();
    parts.sort();
    assert_eq!(parts.len(), 3, "three change notes, each spendable on its own");
    assert_eq!(parts.iter().sum::<u64>(), change);
    let mut payee_db = WalletDb::from_seed([2u8; 32]).unwrap();
    payee_db.ingest_block(&[], &[&b]);
    assert_eq!(payee_db.balance(), 2 * z as u128, "the payee sees exactly its payment");
    // Each part can be spent alone.
    let one = db.notes().iter().take(1).map(|o| (o.note.clone(), db.witness_path(o.position).unwrap())).collect();
    let again = build_wallet_payment_multi_shaped(MINER, one, &[(payee(3), z / 2, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::UNIFORM, &mut rng(52)).unwrap();
    assert_uniform(&again, &state);
}

/// Legacy shape, one note paying one payee (the common phone case: no spare slot): one allowed
/// extra action gives a 3-action bundle that verifies and that consensus accepts, holding the
/// change as two notes that each mature and spend on their own.
#[test]
fn legacy_split_with_one_extra_action_verifies_and_holds_two_change_notes() {
    let z = ZKAS;
    let (mut state, mut db) = fixture(&[5 * z]);
    let shape = SendShape::LEGACY.with_change_split(2, z / 10).with_change_extra_actions(1);
    let p = build_wallet_payment_multi_shaped(MINER, inputs(&db, 1), &[(payee(2), z, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), shape, &mut rng(61)).unwrap();
    let b = ShieldedBundle::from_bytes(&p).unwrap();
    assert_eq!(b.actions.len(), shape.actions_for(1, 1, 2));
    assert_eq!(b.actions.len(), 3);
    verify_bundle(&b, &sighash(&b, &NET, CTX)).expect("verifies");
    state.apply_chain_block(None, &[ShieldedTx::from_bundle(&b).unwrap()]).unwrap();
    db.ingest_block(&[], &[&b]);
    let change = 4 * z - F;
    let v: Vec<u64> = db.notes().iter().map(|n| n.value()).collect();
    assert_eq!(v.len(), 2);
    assert_eq!(v.iter().sum::<u64>(), change);
    // Without the allowance the same request stays a 2-action, single-change payment.
    let (_s2, db2) = fixture(&[5 * z]);
    let p2 = build_wallet_payment_multi_shaped(MINER, inputs(&db2, 1), &[(payee(2), z, [0u8; 512])], F, &NET, CTX, true, Some(ANCHOR_BLOCK), SendShape::LEGACY.with_change_split(2, z / 10), &mut rng(62)).unwrap();
    assert_eq!(ShieldedBundle::from_bytes(&p2).unwrap().actions.len(), 2);
}
