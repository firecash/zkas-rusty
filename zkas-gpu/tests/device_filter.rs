//! The device filter finds EXACTLY what orchard finds, on real notes.
//!
//! # Why this test is shaped the way it is
//!
//! The device now runs the whole per-action filter: the key agreement, the Jacobian to
//! affine inversion, the Orchard KDF, ChaCha20 and the ZIP-212 lead-byte test. That is
//! a reimplementation of cryptography whose only failure mode is SILENCE. Get the
//! BLAKE2b personalisation, the parameter block, the compressed-point sign bit or the
//! ChaCha20 block counter wrong and the device returns "no candidates" — which is
//! indistinguishable from "this wallet owns nothing" right up until a user reports
//! their coins have vanished.
//!
//! So this test PLANTS REAL NOTES at known positions and asserts they are found. A
//! filter that returns nothing at all passes any test made only of misses, and a test
//! made only of misses is the one that would have let every one of those bugs through.
//! There are decoys too, in bulk, because a filter that returns EVERYTHING also has to
//! fail here — on the direction that costs speed rather than coins.
//!
//! It runs against the real GPU. With no device, or a library without the filter ABI,
//! it reports that and passes: "no GPU" is a valid configuration and the CPU path is
//! the same answer.

use group::{Curve, Group, GroupEncoding, ff::Field};
use kaspa_shielded_core::wallet::{self, CompactActionRecord};
use pasta_curves::pallas;
use zkas_gpu::Gpu;

/// Enough actions to look like a page, and past every parallel threshold in the scan
/// path.
const DECOYS: usize = 4000;

fn load() -> Option<Gpu> {
    // Prefer the build under test; the loader falls back to the installed library, and
    // an old one simply has no filter symbol.
    if std::env::var("ZKAS_GPU_LIB").is_err() {
        std::env::set_var("ZKAS_GPU_LIB", "/root/zkas/rk-gpu2/gpu/libzkas_gpu2.so");
    }
    Gpu::load()
}

/// A page of plausible-looking actions nobody owns, plus the planted ones.
///
/// Decoys reuse a real action's nullifier and commitment so `to_compact_action`
/// succeeds and orchard genuinely attempts each one — a decoy orchard skipped on
/// parsing would not be testing anything.
fn build_page(planted: &[(usize, CompactActionRecord)]) -> Vec<CompactActionRecord> {
    let mut rng = rand::rng();
    let template = planted[0].1;
    let mut page: Vec<CompactActionRecord> = (0..DECOYS)
        .map(|_| {
            let mut r = template;
            r.ephemeral_key = pallas::Point::random(&mut rng).to_affine().to_bytes();
            for b in r.enc_ciphertext.iter_mut() {
                *b = rand::random::<u8>();
            }
            r
        })
        .collect();
    for (at, rec) in planted {
        page[*at] = *rec;
    }
    page
}

fn epks_of(page: &[CompactActionRecord]) -> Vec<Option<pallas::Point>> {
    page.iter().map(|r| wallet::decompress_epk(&r.ephemeral_key)).collect()
}

#[test]
fn device_filter_finds_exactly_what_orchard_finds() {
    let Some(gpu) = load() else {
        eprintln!("no GPU library — the CPU path is the same answer, so this passes");
        return;
    };
    if !gpu.has_filter() {
        eprintln!("library has no filter ABI (or it failed its self-test) — nothing to check here");
        return;
    }

    // Two REAL notes, to two different wallets, built through the same code that mints
    // them on chain.
    // The process-wide cached proving key: building one is a multi-minute Halo 2
    // keygen, and this test needs real bundles rather than a cheap imitation of them.
    let pk = wallet::build::proving_key();
    let alice_seed = [2u8; 32];
    let bob_seed = [5u8; 32];
    let alice = wallet::ShieldedKeys::from_seed(alice_seed).expect("seed");
    let bob = wallet::ShieldedKeys::from_seed(bob_seed).expect("seed");
    let wire_a = wallet::build_output_only_bundle(pk, alice.address(), 4242, &[0x33u8; 32], b"ctx", rand::rng())
        .expect("build alice");
    let wire_b =
        wallet::build_output_only_bundle(pk, bob.address(), 777, &[0x33u8; 32], b"ctx", rand::rng()).expect("build bob");
    let rec_a: Vec<CompactActionRecord> = wire_a.actions.iter().map(CompactActionRecord::from_wire).collect();
    let rec_b: Vec<CompactActionRecord> = wire_b.actions.iter().map(CompactActionRecord::from_wire).collect();

    // Planted at positions chosen to land inside a decoy page rather than at its edges:
    // one early, one late, neither on a 128-thread block boundary.
    const AT_A: usize = 777;
    const AT_B: usize = 3001;
    // A bundle is padded, so the real note is not necessarily its first action. Ask
    // orchard which one carries it rather than assuming: the point of this test is to
    // know the exact position the note was planted at.
    let off_a = wallet::scan_compact(&wallet::ivk_from_seed(alice_seed).unwrap(), &rec_a)[0].action_index;
    let off_b = wallet::scan_compact(&wallet::ivk_from_seed(bob_seed).unwrap(), &rec_b)[0].action_index;
    let mut planted = vec![(AT_A, rec_a[0]), (AT_B, rec_b[0])];
    for (k, r) in rec_a.iter().enumerate().skip(1) {
        planted.push((AT_A + k, *r));
    }
    for (k, r) in rec_b.iter().enumerate().skip(1) {
        planted.push((AT_B + k, *r));
    }
    let page = build_page(&planted);
    let epks = epks_of(&page);
    let prep = wallet::prepare_epks(&epks);
    assert_eq!(prep.len(), page.len(), "one slot per action");

    // Alice, Bob, and a stranger who owns nothing here.
    // A stranger is not an afterthought here: a filter that passes everything would
    // satisfy every assertion about alice and bob.
    let cases: [(&str, [u8; 32], usize, u64); 3] =
        [("alice", alice_seed, 1, 4242), ("bob", bob_seed, 1, 777), ("stranger", [9u8; 32], 0, 0)];

    for (who, seed, expect_n, expect_value) in cases {
        let ivk = wallet::ivk_from_seed(seed).unwrap();
        let prepared = ivk.prepare();
        let sc = wallet::ivk_agreement_scalar(&ivk).unwrap();

        // Orchard's own answer over the whole page — the judge.
        let want = wallet::scan_compact_prepared(&prepared, &page);
        assert_eq!(want.len(), expect_n, "{who}: orchard's own count");

        // The device's answer, through the production entry point.
        let got = wallet::scan_compact_gpu_filter(&prepared, &page, &prep, |xy, rows, ct0| {
            gpu.batch_filter(&sc, xy, rows, ct0)
        })
        .unwrap_or_else(|| panic!("{who}: the device declined; a decline is legal but then nothing is tested"));

        assert_eq!(got.len(), want.len(), "{who}: same number of notes as orchard");
        for (g, w) in got.iter().zip(want.iter()) {
            assert_eq!(g.action_index, w.action_index, "{who}: same action position");
            assert_eq!(g.value(), w.value(), "{who}: same value");
        }
        if expect_n > 0 {
            assert_eq!(got[0].value(), expect_value, "{who}: the planted value");
            let at = if who == "alice" { AT_A + off_a } else { AT_B + off_b };
            assert_eq!(got[0].action_index, at, "{who}: found at the position it was planted");
        }

        // And the mask itself is a SUPERSET of orchard's verdict, which is the property
        // the whole design rests on. Checked directly rather than inferred from the
        // note count, because a mask can be wrong in ways that happen to cancel.
        let mask = gpu.batch_filter(&sc, prep.xy(), prep.rows(), &ct0_of(&page, &prep)).expect("mask");
        for n in &want {
            let slot = prep.slot(n.action_index);
            assert!(slot >= 0, "{who}: orchard found a note whose epk was not sent to the device");
            assert_eq!(mask[slot as usize], 1, "{who}: the device dropped a note orchard found — this is the bug that loses coins");
        }
        let hits = mask.iter().filter(|&&b| b != 0).count();
        assert!(
            hits < page.len() / 8,
            "{who}: the device passed {hits} of {} actions — that is not a filter, and a filter that passes everything would also pass this test if the assertion above were all there was",
            page.len()
        );
    }
}

/// The one ciphertext byte per row that the device is given, gathered through the slot
/// table so the test indexes the batch exactly as the scan path does.
fn ct0_of(page: &[CompactActionRecord], prep: &wallet::PreparedEpks) -> Vec<u8> {
    let mut v = vec![0u8; prep.rows()];
    for (i, rec) in page.iter().enumerate() {
        let s = prep.slot(i);
        if s >= 0 {
            v[s as usize] = rec.enc_ciphertext[0];
        }
    }
    v
}

/// A device that declines means "use the CPU", never "no notes".
///
/// This is the single most important line in the file. Every other assertion says the
/// filter is right; this one says that when it is not available the caller is told so
/// rather than handed an empty answer that looks exactly like a scan that found
/// nothing.
#[test]
fn a_declining_device_is_not_an_empty_answer() {
    let ivk = wallet::ivk_from_seed([2u8; 32]).unwrap();
    let prepared = ivk.prepare();
    let mut rng = rand::rng();
    let mut rec = CompactActionRecord {
        nullifier: [0u8; 32],
        cmx: [0u8; 32],
        ephemeral_key: [0u8; 32],
        enc_ciphertext: [0u8; 52],
    };
    rec.ephemeral_key = pallas::Point::random(&mut rng).to_affine().to_bytes();
    let page = vec![rec; 1000];
    let prep = wallet::prepare_epks(&epks_of(&page));
    assert!(wallet::scan_compact_gpu_filter(&prepared, &page, &prep, |_, _, _| None).is_none());
}

/// An ephemeral key the device cannot be asked about is handed to orchard anyway.
///
/// The identity has no affine coordinates to send. Dropping it would be a SUBSET of
/// orchard's answer, and failing the whole page over it would let anybody who writes
/// one action push every wallet in the cohort onto the CPU path. It is forced through
/// instead, which costs one wasted `try_compact_note_decryption`.
#[test]
fn an_unsendable_ephemeral_key_is_forced_through_not_dropped() {
    let epks = vec![Some(pallas::Point::identity()), Some(pallas::Point::generator()), None];
    let prep = wallet::prepare_epks(&epks);
    assert_eq!(prep.rows(), 1, "only the generator can be sent");
    assert_eq!(prep.len(), 3);

    let ivk = wallet::ivk_from_seed([2u8; 32]).unwrap();
    let prepared = ivk.prepare();
    let mut rec =
        CompactActionRecord { nullifier: [0u8; 32], cmx: [0u8; 32], ephemeral_key: [0u8; 32], enc_ciphertext: [0u8; 52] };
    rec.ephemeral_key = pallas::Point::generator().to_affine().to_bytes();
    let page = vec![rec; 3];

    assert_eq!(prep.slot(0), wallet::PreparedEpks::FORCE, "the identity is forced, not dropped");
    assert_eq!(prep.slot(1), 0, "the generator is row 0");
    assert_eq!(prep.slot(2), wallet::PreparedEpks::ABSENT, "an unparseable key is absent");

    // A device that rejects every row it is shown. The identity was never one of them,
    // so it must still be handed to orchard -- and orchard, not the filter, decides.
    let mut asked = 0usize;
    let out = wallet::scan_compact_gpu_filter(&prepared, &page, &prep, |_, rows, _| {
        asked += 1;
        assert_eq!(rows, 1, "only the sendable key is sent");
        Some(vec![0u8; rows])
    })
    .expect("ran, rather than declining");
    assert_eq!(asked, 1);
    // Nothing here is actually decryptable, so orchard returns nothing. What this
    // asserts is the path: `Some(empty)` after orchard was consulted, never an empty
    // answer produced by dropping the slot the device could not be asked about.
    assert!(out.is_empty());
}

/// The device's intermediate values equal the host's, stage by stage.
///
/// When the end-to-end test fails this says WHICH stage: a wrong shared secret is the
/// ladder or the inversion, a wrong key is the KDF, a wrong keystream byte is ChaCha20.
/// Without it, "the filter found nothing" is bisected by hand.
#[test]
fn device_intermediates_match_the_host_stage_by_stage() {
    let Some(gpu) = load() else {
        eprintln!("no GPU library");
        return;
    };
    let mut rng = rand::rng();
    let ivk = pallas::Scalar::random(&mut rng);
    const N: usize = 256;
    let pts: Vec<pallas::Affine> = (0..N).map(|_| pallas::Point::random(&mut rng).to_affine()).collect();
    let epks: Vec<Option<pallas::Point>> = pts.iter().map(|p| Some(pallas::Point::from(*p))).collect();
    let prep = wallet::prepare_epks(&epks);
    assert_eq!(prep.rows(), N);

    let Some(dbg) = gpu.debug_kdf(&ivk, prep.xy(), N) else {
        eprintln!("library has no debug ABI");
        return;
    };

    use blake2b_simd::Params;
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    for i in 0..N {
        let secret = (pallas::Point::from(pts[i]) * ivk).to_affine();
        let want_sec = secret.to_bytes();
        let got_sec: Vec<u8> =
            (0..8).flat_map(|k| dbg[i * 17 + k].to_le_bytes()).collect();
        assert_eq!(&got_sec[..], &want_sec[..], "shared secret differs at {i}: the ladder or the inversion");

        let want_key = Params::new()
            .hash_length(32)
            .personal(b"Zcash_OrchardKDF")
            .to_state()
            .update(&want_sec)
            .update(&pts[i].to_bytes())
            .finalize();
        let got_key: Vec<u8> = (8..16).flat_map(|k| dbg[i * 17 + k].to_le_bytes()).collect();
        assert_eq!(&got_key[..], want_key.as_bytes(), "KDF differs at {i}: BLAKE2b personalisation or parameter block");

        let mut b = [0u8; 1];
        let mut c = chacha20::ChaCha20::new(want_key.as_bytes().into(), &[0u8; 12].into());
        c.seek(64u32);
        c.apply_keystream(&mut b);
        assert_eq!(dbg[i * 17 + 16] as u8, b[0], "keystream byte differs at {i}: ChaCha20 block counter or key order");
    }
}
