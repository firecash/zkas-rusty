//! The browser engine against walletd and the real published chain files.
//!   ZKAS_CHAIN_FILES_DIR=/root/zkas/chainfiles cargo test -p zkas-web-engine --release
//! Skipped (passes trivially) when the directory is not set.
use zkas_web_engine::*;

fn dir() -> Option<String> {
    std::env::var("ZKAS_CHAIN_FILES_DIR").ok()
}

fn manifest(d: &str) -> (String, Manifest) {
    let j = std::fs::read_to_string(format!("{d}/manifest-v2.json")).unwrap();
    let m: Manifest = serde_json::from_str(&verify_manifest_str(&j).expect("the published manifest verifies")).unwrap();
    (j, m)
}

#[test]
fn the_published_manifest_verifies_and_a_tampered_one_does_not() {
    let Some(d) = dir() else { return };
    let (j, _) = manifest(&d);
    let mut raw: serde_json::Value = serde_json::from_str(&j).unwrap();
    raw["segments"][3]["sha256"] = serde_json::Value::String("00".repeat(32));
    assert!(verify_manifest_str(&raw.to_string()).is_err(), "a changed file hash breaks the signature");
}

#[test]
fn segment_blocks_match_walletd_and_three_segments_rebuild_the_published_frontier() {
    let Some(d) = dir() else { return };
    let (_, m) = manifest(&d);
    let genesis = kaspa_rpc_core::RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
    // A run of three consecutive segments well inside the chain.
    let k = m.segments.iter().position(|s| s.index == 150).expect("segment 150 published");
    let run = &m.segments[k..k + 3];
    for w in run.windows(2) {
        assert_eq!(w[0].to.block, w[1].from.block, "consecutive segments chain");
    }
    // Hashes and hex agree with walletd's own decoder.
    let bytes = std::fs::read(format!("{d}/{}", run[0].file)).unwrap();
    assert!(segment_matches(&bytes, &run[0].sha256, run[0].bytes));
    let ours = parse_segment(&bytes, run[0].index).unwrap();
    let theirs = zkas_walletd::chain_files::decode_segment(&bytes, &genesis, run[0].index).unwrap();
    assert_eq!(ours.len(), theirs.len());
    for (a, b) in ours.iter().zip(&theirs) {
        assert_eq!(hex::encode(a.hash), b.hash.to_string());
        assert_eq!(a.daa_score, b.daa_score);
    }
    // A wallet started at the run's first boundary, fed the three segments by the browser
    // engine, must end with exactly the frontier the manifest records (node-verified).
    let fvk = kaspa_shielded_core::walletdb::WalletDb::from_seed([7; 32]).unwrap().fvk().to_bytes();
    let mut e = Engine::create(&hex::encode(fvk), &serde_json::to_string(&run[0].from).unwrap(), run[0].from.daa).unwrap();
    for s in run {
        let b = std::fs::read(format!("{d}/{}", s.file)).unwrap();
        e.segment(&b, s.index, &s.from.block).unwrap();
    }
    assert_eq!(e.low(), run[2].to.block);
    let got: serde_json::Value = serde_json::from_str(&e.tip_frontier().expect("own tree")).unwrap();
    let want = run[2].to.frontier().unwrap();
    assert_eq!(got["size"].as_u64().unwrap(), want.size);
    assert_eq!(got["leaf"].as_str().map(|s| s.to_string()), want.leaf.map(hex::encode));
    assert_eq!(got["ommers"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string()).collect::<Vec<_>>(), want.ommers.iter().map(hex::encode).collect::<Vec<_>>());

    // Checkpoint, restore, and resume mid-run: the same tree.
    let mut half = Engine::create(&hex::encode(fvk), &serde_json::to_string(&run[0].from).unwrap(), run[0].from.daa).unwrap();
    half.segment(&std::fs::read(format!("{d}/{}", run[0].file)).unwrap(), run[0].index, &run[0].from.block).unwrap();
    let ck = half.checkpoint();
    let mut back = Engine::restore_from(&hex::encode(fvk), &ck).unwrap();
    assert_eq!(back.low(), run[0].to.block);
    for s in &run[1..] {
        back.segment(&std::fs::read(format!("{d}/{}", s.file)).unwrap(), s.index, &s.from.block).unwrap();
    }
    assert_eq!(back.tip_frontier(), e.tip_frontier(), "restored + resumed == straight through");
    // Re-feeding a segment already ingested adds nothing.
    let before = back.tip_frontier();
    back.segment(&std::fs::read(format!("{d}/{}", run[2].file)).unwrap(), run[2].index, &run[2].from.block).unwrap();
    assert_eq!(back.tip_frontier(), before);
    // A segment the wallet has passed is refused, not ingested twice.
    assert!(back.segment(&std::fs::read(format!("{d}/{}", run[1].file)).unwrap(), run[1].index, &run[1].from.block).is_err());
    assert_eq!(back.tip_frontier(), before);
}
