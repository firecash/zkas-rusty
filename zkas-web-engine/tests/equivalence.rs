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
        e.segment(&b, s.index, &s.from.block, &serde_json::to_string(&s.to).unwrap()).unwrap();
    }
    assert_eq!(e.low(), run[2].to.block);
    // The skipping engine adopted each segment's signed frontier; one that hashes every leaf
    // must reach the identical tree, and walletd's independent replay must reproduce the
    // manifest's frontier from the segment's own leaves.
    let mut hashed = Engine::create(&hex::encode(fvk), &serde_json::to_string(&run[0].from).unwrap(), run[0].from.daa).unwrap();
    hashed.set_hash_every_leaf(true);
    for s in run {
        let b = std::fs::read(format!("{d}/{}", s.file)).unwrap();
        hashed.segment(&b, s.index, &s.from.block, &serde_json::to_string(&s.to).unwrap()).unwrap();
        let wd_from: zkas_walletd::chain_files::Boundary = serde_json::from_value(serde_json::to_value(&s.from).unwrap()).unwrap();
        let blocks = zkas_walletd::chain_files::decode_segment(&b, &genesis, s.index).unwrap();
        let replayed = zkas_walletd::chain_files::end_frontier(&wd_from, &blocks).unwrap();
        let want = s.to.frontier().unwrap();
        assert_eq!((replayed.size, replayed.leaf, replayed.ommers.clone()), (want.size, want.leaf, want.ommers.clone()), "segment {} replays to its signed frontier", s.index);
    }
    assert_eq!(hashed.tip_frontier(), e.tip_frontier(), "skipping and hashing reach the same tree");
    let got: serde_json::Value = serde_json::from_str(&e.tip_frontier().expect("own tree")).unwrap();
    let want = run[2].to.frontier().unwrap();
    assert_eq!(got["size"].as_u64().unwrap(), want.size);
    assert_eq!(got["leaf"].as_str().map(|s| s.to_string()), want.leaf.map(hex::encode));
    assert_eq!(got["ommers"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string()).collect::<Vec<_>>(), want.ommers.iter().map(hex::encode).collect::<Vec<_>>());

    // Checkpoint, restore, and resume mid-run: the same tree.
    let mut half = Engine::create(&hex::encode(fvk), &serde_json::to_string(&run[0].from).unwrap(), run[0].from.daa).unwrap();
    half.segment(&std::fs::read(format!("{d}/{}", run[0].file)).unwrap(), run[0].index, &run[0].from.block, &serde_json::to_string(&run[0].to).unwrap()).unwrap();
    let ck = half.checkpoint();
    let mut back = Engine::restore_from(&hex::encode(fvk), &ck).unwrap();
    assert_eq!(back.low(), run[0].to.block);
    for s in &run[1..] {
        back.segment(&std::fs::read(format!("{d}/{}", s.file)).unwrap(), s.index, &s.from.block, &serde_json::to_string(&s.to).unwrap()).unwrap();
    }
    assert_eq!(back.tip_frontier(), e.tip_frontier(), "restored + resumed == straight through");
    // Re-feeding a segment already ingested adds nothing.
    let before = back.tip_frontier();
    back.segment(&std::fs::read(format!("{d}/{}", run[2].file)).unwrap(), run[2].index, &run[2].from.block, &serde_json::to_string(&run[2].to).unwrap()).unwrap();
    assert_eq!(back.tip_frontier(), before);
    // A segment the wallet has passed is refused, not ingested twice.
    assert!(back.segment(&std::fs::read(format!("{d}/{}", run[1].file)).unwrap(), run[1].index, &run[1].from.block, &serde_json::to_string(&run[1].to).unwrap()).is_err());
    assert_eq!(back.tip_frontier(), before);
}

/// Parallel page streams: the browser fetches the range in several streams at once, each ending
/// exactly where the next one starts (a block in the middle of a page), and ingests them in order.
/// The wallet must end with exactly the tree a straight run reaches, the segment's signed frontier.
#[test]
fn page_streams_that_meet_mid_page_rebuild_the_signed_frontier() {
    let Some(d) = dir() else { return };
    let (_, m) = manifest(&d);
    let genesis = kaspa_rpc_core::RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
    let s = m.segments.iter().find(|s| s.index == 150).expect("segment 150 published");
    let bytes = std::fs::read(format!("{d}/{}", s.file)).unwrap();
    let blocks = zkas_walletd::chain_files::decode_segment(&bytes, &genesis, s.index).unwrap();
    assert!(blocks.len() > 3000);
    let sink = blocks.last().unwrap().blue_score + 100_000;
    let page = |from: usize, n: usize| {
        let end = (from + n).min(blocks.len());
        zkas_walletd::chain_files::encode_page(
            &genesis,
            &kaspa_rpc_core::GetShieldedBlocksResponse { blocks: blocks[from..end].to_vec(), reorged: false, sink_blue_score: sink },
        )
    };
    // Stream A: from the segment start; it must stop at block 1499, inside its second page.
    // Stream B: the pages after block 1499, to the segment's end.
    let meet = blocks[1499].hash.to_string();
    let a2 = page(1000, 1000);
    assert_eq!(page_index_of(&a2, &meet).unwrap(), 499);
    assert_eq!(page_index_of(&page(0, 1000), &meet).unwrap(), -1);
    let fvk = kaspa_shielded_core::walletdb::WalletDb::from_seed([8; 32]).unwrap().fvk().to_bytes();
    let mut e = Engine::create(&hex::encode(fvk), &serde_json::to_string(&s.from).unwrap(), s.from.daa).unwrap();
    e.page_until(&page(0, 1000), None).unwrap();
    e.page_until(&a2, Some(blocks[1499].hash.as_bytes())).unwrap();
    assert_eq!(e.low(), meet, "stream A ends exactly at the meeting block");
    let mut at = 1500;
    while at < blocks.len() {
        e.page(&page(at, 1000)).unwrap();
        at += 1000;
    }
    assert_eq!(e.low(), s.to.block);
    let got: serde_json::Value = serde_json::from_str(&e.tip_frontier().expect("own tree")).unwrap();
    let want = s.to.frontier().unwrap();
    assert_eq!(got["size"].as_u64().unwrap(), want.size, "every leaf exactly once");
    assert_eq!(got["leaf"].as_str().map(|x| x.to_string()), want.leaf.map(hex::encode));
    assert_eq!(got["ommers"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string()).collect::<Vec<_>>(), want.ommers.iter().map(hex::encode).collect::<Vec<_>>());
    // The page cursor names the last block of a page, as low() does.
    let c: serde_json::Value = serde_json::from_str(&page_cursor(&page(0, 1000)).unwrap()).unwrap();
    assert_eq!(c["last"].as_str().unwrap(), blocks[999].hash.to_string());
    assert_eq!(c["count"], 1000);
}

#[test]
fn a_viewing_key_gives_the_address_walletd_gives() {
    // walletd's own answer for this seed (POST /api/wallet/import on 142, 1 Nov).
    let seed: [u8; 32] = hex::decode("65bc8908745793238284d5fd365d14ca66e79ec046a77d7b7413bb0693f5595d").unwrap().try_into().unwrap();
    let fvk = kaspa_shielded_core::walletdb::WalletDb::from_seed(seed).unwrap().fvk().to_bytes();
    assert_eq!(
        address_of_fvk_str(&hex::encode(fvk)).unwrap(),
        "zkas:pxs42v89kfawvh6u7zduate3zm728yn77n8hn878frz54hx7td3wgua490d3tyukrn0fcxchm4swd5x"
    );
    assert!(address_of_fvk_str("00").is_err());
}

/// Where a segment's ingest time goes (decode incl. coinbase commitments / trial decryption /
/// apply). Prints only; run with --nocapture.
#[test]
fn profile_segment_ingest() {
    let Some(d) = dir() else { return };
    let (_, m) = manifest(&d);
    let k = m.segments.iter().position(|s| s.index == 150).expect("segment 150 published");
    let mut blocks = Vec::new();
    for s in &m.segments[k..k + 3] {
        blocks.extend(parse_segment(&std::fs::read(format!("{d}/{}", s.file)).unwrap(), s.index).unwrap());
    }
    let (mut outs, mut supplied, mut actions) = (0usize, 0usize, 0usize);
    for b in &blocks {
        outs += b.outputs.len();
        supplied += b.outputs.iter().filter(|o| o.2.is_some()).count();
        actions += b.actions.iter().map(|a| a.len() / kaspa_shielded_core::wallet::CompactActionRecord::SERIALIZED_LEN).sum::<usize>();
    }
    let t = std::time::Instant::now();
    let decoded: Vec<_> = blocks.iter().map(|b| decode(b).unwrap()).collect();
    let t_decode = t.elapsed();
    let fvk = kaspa_shielded_core::walletdb::WalletDb::from_seed([7; 32]).unwrap().fvk().to_bytes();
    let mut db = kaspa_shielded_core::walletdb::WalletDb::from_fvk(&fvk).unwrap();
    db.apply_frontier(&m.segments[k].from.frontier().unwrap()).unwrap();
    let all: Vec<_> = decoded.iter().flat_map(|(_, c)| c.iter().flatten().copied()).collect();
    let t = std::time::Instant::now();
    db.predecrypt_page(&all);
    let t_decrypt = t.elapsed();
    db.set_borrow_tree(true);
    let t = std::time::Instant::now();
    for (cb, c) in &decoded {
        db.ingest_block_compact_precomputed_with_meta(cb, c, None);
    }
    let t_apply = t.elapsed();
    println!(
        "PROFILE {} blocks, {} coinbase outputs ({} with a supplied commitment), {} actions | decode {:.2?} | decrypt {:.2?} | apply {:.2?}",
        blocks.len(), outs, supplied, actions, t_decode, t_decrypt, t_apply
    );
}
