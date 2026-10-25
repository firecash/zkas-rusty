//! Tagged channels on a LIVE devnet node (task C3). Not a test: a client that drives a running
//! `kaspad --devnet` past `tagged_channels_activation` over gRPC.
//!
//!   tagged_devnet addr <seed-hex>          print the devnet address a miner should mine to
//!   tagged_devnet run <grpc-url> <seed-hex> [peer-grpc-url]
//!
//! `run`: rebuilds the note commitment tree from `GetShieldedBlocks` (coinbase commitments, then
//! accepted actions, in chain order), spends the miner's first coinbase note with a real Halo 2
//! proof in a TAGGED bundle (a payment-request payment to Bob plus change on Alice's self channel),
//! submits it, waits until it is applied, then finds both outputs by tag lookup over
//! `GetShieldedTagColumn` (no trial decryption), restores both wallets from seed alone, and checks
//! the replayed tag log against the node's own (and a second node's, if given).

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use incrementalmerkletree::{Hashable, Level};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{RpcHash, RpcShieldedChainBlock, RpcTransaction};
use kaspa_shielded_core::tag_log::{TagLog, TaggedTxColumn};
use kaspa_shielded_core::tagged_wallet::{ColumnBlock, OutputRecord, TagOracle, TaggedWallet, pay_request, restore};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;

/// Devnet security fork (1,500) plus a margin.
const MIN_ANCHOR_DAA: u64 = 1_600;

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn seed(hex: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    faster_hex::hex_decode(hex.as_bytes(), &mut s).expect("32-byte hex seed");
    s
}

fn raw_addr(sk: [u8; 32]) -> [u8; 43] {
    let sk = SpendingKey::from_bytes(sk).expect("valid spending key");
    FullViewingKey::from(&sk).address_at(0u32, Scope::External).to_raw_address_bytes()
}

/// The whole selected chain from `start`, in order.
async fn chain(c: &GrpcClient, start: RpcHash) -> R<Vec<RpcShieldedChainBlock>> {
    let mut out: Vec<RpcShieldedChainBlock> = Vec::new();
    let mut from = start;
    loop {
        let r = c.get_shielded_blocks(from, 1000).await?;
        let new: Vec<_> = r.blocks.into_iter().filter(|b| b.hash != from).collect();
        if new.is_empty() {
            return Ok(out);
        }
        from = new.last().unwrap().hash;
        out.extend(new);
    }
}

/// The tag column over the whole chain `hashes` (genesis first), in windows anchored at known chain
/// hashes: a window of pre-activation blocks comes back empty (they have no column), which must
/// not end the walk. Returns the column and the tag log before its first block.
async fn column(c: &GrpcClient, hashes: &[RpcHash]) -> R<(Vec<ColumnBlock>, TagLog)> {
    const W: usize = 1000;
    let mut out: Vec<ColumnBlock> = Vec::new();
    let mut log0: Option<TagLog> = None;
    for start in hashes.iter().step_by(W) {
        let r = c.get_shielded_tag_column(*start, W as u64).await?;
        for b in r.blocks {
            if b.hash == *start || out.last().is_some_and(|l| l.hash == b.hash.as_bytes()) {
                continue;
            }
            if log0.is_none() {
                // Tag log before the first post-activation block: ask at its predecessor.
                let i = hashes.iter().position(|h| *h == b.hash).ok_or("column block not on the chain")?;
                let p = c.get_shielded_tag_column(hashes[i - 1], 1).await?;
                log0 = Some(TagLog { count: p.log_before_count, peaks: p.log_before_peaks.iter().map(|h| h.as_bytes()).collect() });
            }
            let txs = b
                .txs
                .into_iter()
                .map(|t| TaggedTxColumn { first_leaf: t.first_leaf, tags: t.tags.chunks_exact(16).map(|x| x.try_into().unwrap()).collect() })
                .collect();
            out.push(ColumnBlock { hash: b.hash.as_bytes(), txs });
        }
    }
    Ok((out, log0.unwrap_or_default()))
}

/// Leaves (cmx) in tree order and, per chain block, the tree size after it.
fn leaves(chain: &[RpcShieldedChainBlock]) -> (Vec<[u8; 32]>, HashMap<RpcHash, u64>) {
    let mut l = Vec::new();
    let mut size_at = HashMap::new();
    for b in chain {
        for o in &b.coinbase_outputs {
            if let Some(cm) = o.commitment {
                l.push(cm);
            }
        }
        for acts in &b.accepted_actions {
            for rec in acts.chunks_exact(148) {
                l.push(rec[32..64].try_into().unwrap());
            }
        }
        size_at.insert(b.hash, l.len() as u64);
    }
    (l, size_at)
}

/// Root and auth path of `pos` in the depth-32 tree holding `leaves[..size]`.
fn path(leaves: &[[u8; 32]], size: usize, pos: usize) -> (MerkleHashOrchard, MerklePath) {
    let mut level: Vec<MerkleHashOrchard> =
        leaves[..size].iter().map(|c| MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from_bytes(c).unwrap())).collect();
    let mut auth = Vec::with_capacity(32);
    let mut idx = pos;
    for h in 0..32u8 {
        let empty = MerkleHashOrchard::empty_root(Level::from(h));
        let sib = idx ^ 1;
        auth.push(level.get(sib).copied().unwrap_or(empty));
        let next: Vec<_> = level
            .chunks(2)
            .map(|p| MerkleHashOrchard::combine(Level::from(h), &p[0], p.get(1).unwrap_or(&empty)))
            .collect();
        level = next;
        idx >>= 1;
    }
    let root = level.first().copied().unwrap_or(MerkleHashOrchard::empty_root(Level::from(32)));
    (root, MerklePath::from_parts(pos as u32, auth.try_into().unwrap()))
}

struct Oracle<'a> {
    by_tag: HashMap<[u8; 16], Vec<u64>>,
    records: &'a HashMap<u64, OutputRecord>,
    spent: HashSet<[u8; 32]>,
    queries: u64,
    rounds: u64,
}

impl TagOracle for Oracle<'_> {
    fn lookup(&mut self, tag: &[u8; 16]) -> Vec<(u64, OutputRecord)> {
        self.queries += 1;
        self.by_tag.get(tag).map(|v| v.iter().filter_map(|p| self.records.get(p).map(|r| (*p, *r))).collect()).unwrap_or_default()
    }
    fn deposits(&mut self, _i: u32) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn is_spent(&mut self, nf: &[u8; 32]) -> bool {
        self.queries += 1;
        self.spent.contains(nf)
    }
    fn round(&mut self) {
        self.rounds += 1;
    }
}

#[tokio::main]
async fn main() -> R<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("addr") => {
            let a = Address::new(Prefix::Devnet, Version::ShieldedOrchard, &raw_addr(seed(&args[2])));
            println!("{a}");
            Ok(())
        }
        Some("run") => run(&args[2], seed(&args[3]), args.get(4).map(String::as_str)).await,
        _ => {
            eprintln!("usage: tagged_devnet addr <seed-hex> | run <grpc-url> <seed-hex> [peer-grpc-url]");
            Ok(())
        }
    }
}

async fn run(url: &str, alice_sk: [u8; 32], peer: Option<&str>) -> R<()> {
    let c = GrpcClient::connect(url.to_string()).await?;
    let info = c.get_block_dag_info().await?;
    let genesis = info.pruning_point_hash;
    let me = raw_addr(alice_sk);
    let net = genesis.as_bytes();
    println!("node {url}: network {}, virtual DAA {}, genesis/pruning point {genesis}", info.network, info.virtual_daa_score);

    // 1. The miner's first coinbase note, its position, and an anchor block deep enough. Devnet's
    // shielded_anchor_depth is 600 s x 10 BPS = 6,000 DAA (ANCHOR_DEPTH overrides); the spend must
    // also land past tagged_channels_activation (devnet DAA 2,000).
    let depth: u64 = std::env::var("ANCHOR_DEPTH").ok().and_then(|v| v.parse().ok()).unwrap_or(6_100);
    let wait_until = Instant::now() + Duration::from_secs(3600);
    let all = loop {
        let all = chain(&c, genesis).await?;
        let first_cb = all.iter().find(|b| b.coinbase_outputs.iter().any(|o| o.script_public_key.ends_with(&me) && o.value > 0));
        let tip = all.last().map_or(0, |b| b.daa_score);
        let tip_blue = all.last().map_or(0, |b| b.blue_score);
        if let Some(f) = first_cb {
            // The anchor must be a chain block at or after devnet's security fork (DAA 1,500): the
            // anchor-block window only records blocks from there on ("unresolved" otherwise).
            let ok_anchor = all.iter().any(|b| b.daa_score >= MIN_ANCHOR_DAA && b.daa_score >= f.daa_score && b.blue_score + depth <= tip_blue);
            if ok_anchor && tip >= 2_100 {
                break all;
            }
        }
        if Instant::now() > wait_until {
            return Err("no mature coinbase note within an hour".into());
        }
        println!("waiting: tip DAA {tip}, first own coinbase at {:?}", first_cb.map(|b| b.daa_score));
        tokio::time::sleep(Duration::from_secs(20)).await;
    };
    let (cb_block, out_index, value, position) = {
        let mut pos = 0u64;
        let mut found = None;
        'outer: for b in &all {
            for (i, o) in b.coinbase_outputs.iter().enumerate() {
                if o.commitment.is_some() {
                    if o.script_public_key.ends_with(&me) && o.value > 0 {
                        found = Some((b.clone(), i as u32, o.value, pos));
                        break 'outer;
                    }
                    pos += 1;
                }
            }
            for a in &b.accepted_actions {
                pos += (a.len() / 148) as u64;
            }
        }
        found.ok_or("no coinbase note for this seed yet: mine to `tagged_devnet addr <seed>`")?
    };
    let mut seed_bytes = cb_block.coinbase_txid.as_bytes().to_vec();
    seed_bytes.extend_from_slice(&out_index.to_le_bytes());
    let desc = kaspa_shielded_core::coinbase::derive_coinbase_note_desc(me, &seed_bytes);
    let rho = Rho::from_bytes(&desc.rho).unwrap();
    let addr = orchard::Address::from_raw_address_bytes(&me).unwrap();
    let note = orchard::Note::from_parts(addr, NoteValue::from_raw(value), rho, RandomSeed::from_bytes(desc.rseed, &rho).unwrap(), NoteVersion::V2)
        .unwrap();
    println!("coinbase note: block {} (DAA {}), output {out_index}, value {value}, leaf {position}", cb_block.hash, cb_block.daa_score);

    // Anchor: the youngest chain block at least `depth` below the tip in BLUE SCORE (the unit of
    // shielded_anchor_depth; DAA runs ahead of it on a wide, fast devnet DAG).
    let tip_blue = all.last().unwrap().blue_score;
    let anchor = all.iter().rev().find(|b| b.blue_score + depth <= tip_blue && b.daa_score >= cb_block.daa_score && b.daa_score >= MIN_ANCHOR_DAA).ok_or("chain too short")?;
    let (lv, size_at) = leaves(&all);
    let size = size_at[&anchor.hash] as usize;
    let (root, mpath) = path(&lv, size, position as usize);
    let ts = c.get_shielded_tree_state(Some(anchor.hash)).await?;
    assert_eq!(ts.size, size as u64, "rebuilt tree size matches the node's frontier at the anchor block");
    assert_eq!(mpath.root(ExtractedNoteCommitment::from(note.commitment())), orchard::Anchor::from(root), "the note is in the tree");
    println!("anchor block {} (DAA {}, blue {} of tip {tip_blue}), tree size {size} (node agrees)", anchor.hash, anchor.daa_score, anchor.blue_score);

    // 2. Bob issues a request; Alice pays it, change to her self channel.
    let mut rng = rand10::rng();
    let mut alice = TaggedWallet::new(alice_sk, 3).unwrap();
    let bob_sk = {
        let mut s = [9u8; 32];
        while Option::<SpendingKey>::from(SpendingKey::from_bytes(s)).is_none() {
            s[0] += 1;
        }
        s
    };
    let mut bob = TaggedWallet::new(bob_sk, 3).unwrap();
    let amount = value / 3;
    let req = bob.issue_request(amount);
    let fee = 5_000_000u64;
    let pay = pay_request(&req, amount, 0, &mut rng);
    let change = alice.change_output(value - amount - fee, &[], 0, &mut rng);
    let mut tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = tx.shielded_sighash_context();
    let t0 = Instant::now();
    let bundle = kaspa_shielded_core::tagged_build::build_tagged_bundle(
        alice_sk,
        vec![(note, mpath)],
        &[pay, change],
        fee,
        anchor.hash.as_bytes(),
        &net,
        &tx_ctx,
        &mut rng,
    )
    .map_err(|e| format!("build_tagged_bundle: {e:?}"))?;
    let prove_s = t0.elapsed().as_secs_f64();
    tx.payload = bundle.to_bytes();
    tx.finalize();
    let txid = tx.id();
    println!(
        "tagged tx {txid}: {} actions, payload {} B (format byte 0x{:02x}), built+proved in {prove_s:.2} s",
        bundle.actions.len(),
        tx.payload.len(),
        tx.payload[0]
    );
    // The node judges maturity against its own virtual; retry while the anchor is still maturing.
    let mut tries = 0;
    let submitted = loop {
        match c.submit_transaction(RpcTransaction::from(&tx), false).await {
            Ok(id) => break id,
            Err(e) if tries < 30 && e.to_string().contains("anchor not final") => {
                tries += 1;
                println!("not yet final ({tries}): {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("submitted: {submitted}");

    // 3. Wait until a chain block applies it.
    let deadline = Instant::now() + Duration::from_secs(180);
    let all = loop {
        let all = chain(&c, genesis).await?;
        if all.iter().any(|b| b.accepted_txids.contains(&txid)) {
            break all;
        }
        if Instant::now() > deadline {
            return Err("tagged tx not applied within 180 s".into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let applied = all.iter().find(|b| b.accepted_txids.contains(&txid)).unwrap();
    println!("applied by chain block {} (DAA {})", applied.hash, applied.daa_score);

    // 4. Light client: tag column + only the hit records.
    let t1 = Instant::now();
    let hashes: Vec<RpcHash> = std::iter::once(genesis).chain(all.iter().map(|b| b.hash)).collect();
    let (col, log0) = column(&c, &hashes).await?;
    let col_s = t1.elapsed().as_secs_f64();
    // The chain kept growing while the column was fetched: re-read it so every column block is known.
    let all = chain(&c, genesis).await?;
    let mut records = HashMap::new();
    let mut spent = HashSet::new();
    let by_hash: HashMap<[u8; 32], &RpcShieldedChainBlock> = all.iter().map(|b| (b.hash.as_bytes(), b)).collect();
    for cb in &col {
        let b = by_hash[&cb.hash];
        // Every tx on this devnet is tagged, so column tx i is accepted tx i.
        assert_eq!(cb.txs.len(), b.accepted_actions.len());
        for (t, acts) in cb.txs.iter().zip(&b.accepted_actions) {
            for (j, rec) in acts.chunks_exact(148).enumerate() {
                let r = OutputRecord::from_compact(rec).unwrap();
                spent.insert(r.nullifier);
                records.insert(t.first_leaf + j as u64, r);
            }
        }
    }
    let n_tags: usize = col.iter().flat_map(|b| &b.txs).map(|t| t.tags.len()).sum();
    let t2 = Instant::now();
    for blk in &col {
        bob.scan_block(blk, |p| records.get(&p).copied());
        alice.scan_block(blk, |p| records.get(&p).copied());
    }
    let scan_s = t2.elapsed().as_secs_f64();
    println!(
        "column: {} post-activation chain blocks, {n_tags} tags, fetched in {col_s:.3} s; scan {scan_s:.6} s; trial decryptions {}",
        col.len(),
        bob.stats.open_lane_trials + alice.stats.open_lane_trials
    );
    println!("  Bob found {} note(s), balance {} (expected {amount})", bob.found.len(), bob.balance());
    println!("  Alice found {} note(s), balance {} (expected {})", alice.found.len(), alice.balance(), value - amount - fee);
    assert_eq!(bob.balance(), amount);
    assert_eq!(alice.balance(), value - amount - fee);

    // 5. The column replays to the node's tag log (the one zkas_state_root2 commits).
    let replayed = TagLog::replay_blocks(&log0, col.iter().map(|b| (&b.hash, b.txs.as_slice())))?;
    let tip = RpcHash::from_bytes(col.last().ok_or("empty column")?.hash);
    let at_tip = c.get_shielded_tag_column(tip, 1).await?;
    let node_log = TagLog { count: at_tip.log_before_count, peaks: at_tip.log_before_peaks.iter().map(|h| h.as_bytes()).collect() };
    assert_eq!(replayed.commitment(), node_log.commitment(), "replayed column == node tag log");
    println!("tag log: {} entries, commitment {} == node", node_log.count, faster_hex::hex_string(&node_log.commitment()));
    if let Some(p) = peer {
        let c2 = GrpcClient::connect(p.to_string()).await?;
        let mut tries = 0;
        loop {
            match c2.get_shielded_tag_column(tip, 1).await {
                Ok(r) => {
                    let l = TagLog { count: r.log_before_count, peaks: r.log_before_peaks.iter().map(|h| h.as_bytes()).collect() };
                    assert_eq!(l.commitment(), node_log.commitment(), "peer node computed the same tag log");
                    println!("peer {p}: same tag log at {tip}");
                    break;
                }
                Err(e) if tries < 30 => {
                    tries += 1;
                    eprintln!("peer not there yet: {e}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    // 6. Birthday-free restore of both wallets from the seed alone (T-mode oracle over the column).
    let mut by_tag: HashMap<[u8; 16], Vec<u64>> = HashMap::new();
    for t in col.iter().flat_map(|b| &b.txs) {
        for (j, tg) in t.tags.iter().enumerate() {
            by_tag.entry(*tg).or_default().push(t.first_leaf + j as u64);
        }
    }
    for (who, sk, want) in [("Alice", alice_sk, value - amount - fee), ("Bob", bob_sk, amount)] {
        let mut o = Oracle { by_tag: by_tag.clone(), records: &records, spent: spent.clone(), queries: 0, rounds: 0 };
        let (_, rep) = restore(sk, &mut o, 20, 3).ok_or("restore")?;
        println!(
            "restore {who} from seed: {} notes, balance {} (want {want}), complete={}, {} queries / {} rounds",
            rep.notes_found, rep.balance, rep.complete, o.queries, o.rounds
        );
    }
    println!("TAGGED DEVNET RUN OK");
    Ok(())
}
