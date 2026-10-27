use super::*;
use crate::coinbase::{coinbase_note_commitment, derive_coinbase_note_desc};
use crate::engine::{CombKernel, LadderKernel, SharedPage, WalletId};
use crate::walletdb::{HistoryEntry, OwnedNote, PendingSpend};
use orchard::Address;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{Note, RandomSeed, Rho};
use orchard::note_encryption::{OrchardDomain, OrchardNoteEncryption};
use orchard::value::NoteValue;
use zcash_note_encryption::Domain;

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
}

fn fvk(r: &mut Det) -> FullViewingKey {
    loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(r.b32())) {
            return FullViewingKey::from(&sk);
        }
    }
}

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

const GENESIS: [u8; 32] = [7u8; 32];
const N_WALLETS: usize = 4;
const PAGES: u64 = 8;

fn fvks() -> Vec<FullViewingKey> {
    let mut r = Det(42);
    (0..N_WALLETS).map(|_| fvk(&mut r)).collect()
}

fn key16(i: usize) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0] = 0xa0 | i as u8;
    k
}

/// Page `k` of a deterministic synthetic chain: coinbase to our addresses, receipts, spends
/// of whatever the wallets hold (a function of the state, so a resumed run regenerates the
/// same page only if its state is right), hostile records.
fn page(k: u64, eng: &ScanEngine, fv: &[FullViewingKey]) -> Vec<SharedBlock> {
    let mut r = Det(1000 + k);
    let stranger = fvk(&mut Det(9)).address_at(0u32, Scope::External);
    let mut held: Vec<[u8; 32]> =
        (0..eng.wallet_count()).flat_map(|w| eng.wallet(w as WalletId).notes().iter().map(|n| n.nullifier()).collect::<Vec<_>>()).collect();
    let mut blocks = Vec::new();
    for bn in 0..12u64 {
        let daa = 10_000 + k * 100 + bn;
        let mut coinbase = Vec::new();
        for c in 0..2u8 {
            let to = if r.next() % 3 == 0 {
                fv[(r.next() % N_WALLETS as u64) as usize].address_at((r.next() % 256) as u32, Scope::External).to_raw_address_bytes()
            } else {
                stranger.to_raw_address_bytes()
            };
            let mut seed = r.b32().to_vec();
            seed.push(c);
            let desc = derive_coinbase_note_desc(to, &seed);
            let value = 1 + r.next() % 1_000_000;
            if let Ok(cmx) = coinbase_note_commitment(&desc, value) {
                coinbase.push((desc, value, cmx));
            }
        }
        let mut txs: Vec<Vec<CompactActionRecord>> = Vec::new();
        if !held.is_empty() && r.next() % 3 == 0 {
            let nf = held.swap_remove((r.next() % held.len() as u64) as usize);
            let mut a = plant(stranger, 5, &mut r);
            a.nullifier = nf;
            let mut tx = vec![a];
            if r.next() % 2 == 0 {
                tx.push(plant(fv[(r.next() % N_WALLETS as u64) as usize].address_at(1u32, Scope::External), 77, &mut r));
            }
            txs.push(tx);
        }
        if r.next() % 2 == 0 {
            let w = (r.next() % N_WALLETS as u64) as usize;
            let mut tx = vec![plant(stranger, 3, &mut r), plant(fv[w].address_at((r.next() % 300) as u32, Scope::External), 1 + r.next() % 1_000_000_000, &mut r)];
            if r.next() % 4 == 0 {
                let mut bad = plant(stranger, 9, &mut r);
                bad.cmx = [0xff; 32];
                tx.push(bad);
            }
            txs.push(tx);
        }
        txs.push((0..(r.next() % 3)).map(|_| plant(stranger, 1, &mut r)).collect());
        let txids: Vec<[u8; 32]> = txs.iter().map(|_| r.b32()).collect();
        let meta = if bn == 5 { None } else { Some(BlockMeta { coinbase_txid: r.b32(), txids, timestamp_ms: 1_700_000_000_000 + daa, daa_score: daa }) };
        blocks.push(SharedBlock { hash: r.b32(), blue_score: daa, daa_score: daa, coinbase, txs, meta });
    }
    blocks
}

fn state_key(w: &WalletLite) -> String {
    let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
    let pk = |p: &PendingSpend| (nk(&p.note), p.txid, p.submitted_daa);
    let h: &[HistoryEntry] = w.history();
    format!(
        "{:?}|{:?}|{:?}|{}|{}",
        w.notes().iter().map(nk).collect::<Vec<_>>(),
        w.pending_spends().iter().map(pk).collect::<Vec<_>>(),
        h,
        w.last_daa(),
        w.balance()
    )
}

/// Open the store in `dir`, rebuild the engine and every wallet (from its `.w2` + the
/// journal, or fresh at the base), as a restarting host does.
fn reopen(dir: &Path, fv: &[FullViewingKey]) -> (ChainStore, ScanEngine) {
    let archive = std::fs::read(dir.join("committed")).ok().and_then(|b| Committed::decode(&b)).map(|c| c.archive).unwrap_or(true);
    let (store, chain) = ChainStore::open_with(dir, GENESIS, archive).expect("open");
    let mut eng = ScanEngine::resume(chain, Box::new(LadderKernel), store.committed().seq);
    for (i, f) in fv.iter().enumerate() {
        let p = store.wallet_path(&format!("w{i}"));
        let mut w = match std::fs::read(&p) {
            Ok(b) => {
                let (h, s) = decode_w2(&b).expect("w2 decodes");
                assert!(h.seq <= store.committed().seq && h.journal_off <= store.committed().journal_len, "a wallet file claims past committed");
                let mut w = WalletLite::new(f.clone(), s, h.size, h.seq, h.key16);
                let (_, _) = store.catch_up(&mut w, h.journal_off).expect("catch up");
                w
            }
            Err(_) => {
                // Registered at the base: everything is in the journal.
                let mut w = WalletLite::new(f.clone(), WalletState { history_enabled: true, ..Default::default() }, 0, 0, key16(i));
                store.catch_up(&mut w, 0).expect("catch up");
                w
            }
        };
        w.advance_to(store.committed().seq);
        assert_eq!(eng.register_wallet(w), Some(i as WalletId));
    }
    (store, eng)
}

fn write_wallets(store: &ChainStore, eng: &ScanEngine, which: impl Fn(usize) -> bool) {
    for i in 0..eng.wallet_count() {
        if !which(i) {
            continue;
        }
        let w = eng.wallet(i as WalletId);
        let c = store.committed();
        let h = W2Head { genesis: GENESIS, key16: w.key16(), seq: c.seq, size: c.leaves, journal_off: c.journal_len, blind_below: 0 };
        write_atomic(&store.wallet_path(&format!("w{i}")), &encode_w2(&h, &w.state())).expect("w2");
    }
}

/// Run pages `[start, PAGES)` on an open store, writing wallet files on pages where `k % 3 == 0`.
fn run(dir: &Path, fv: &[FullViewingKey], fault_at: Option<(u64, CommitFault)>) -> Result<(), String> {
    let (mut store, mut eng) = reopen(dir, fv);
    let start = store.committed().seq / 12;
    for k in start..PAGES {
        let blocks = page(k, &eng, fv);
        let sp = SharedPage::new(blocks.clone());
        let folds = eng.ingest_page(&sp);
        let fault = match fault_at {
            Some((fk, f)) if fk == k => f,
            _ => CommitFault::None,
        };
        store.commit_page(&blocks, &folds, &eng, fault)?;
        write_wallets(&store, &eng, |i| (k + i as u64) % 3 == 0);
    }
    Ok(())
}

fn snapshot(dir: &Path, fv: &[FullViewingKey]) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let mut files = Vec::new();
    for n in ["chain.ccs", "blocks.idx", "leaves.bin", "nfs.bin", "journal.bin", "committed"] {
        files.push((n.to_string(), std::fs::read(dir.join(n)).unwrap_or_default()));
    }
    let (_store, eng) = reopen(dir, fv);
    let states = (0..eng.wallet_count()).map(|i| state_key(eng.wallet(i as WalletId))).collect();
    (files, states)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zkas-engine-store-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn block_and_record_codecs_roundtrip() {
    let fv = fvks();
    let (_s, chain) = ChainStore::open(&tmpdir("codec"), GENESIS).unwrap();
    let eng = ScanEngine::new(chain, Box::new(LadderKernel));
    for b in page(0, &eng, &fv) {
        let back = decode_block(&encode_block(&b)).expect("decodes");
        assert_eq!(encode_block(&back), encode_block(&b));
        assert_eq!(back.hash, b.hash);
        assert_eq!(back.txs, b.txs);
        assert_eq!(back.coinbase.len(), b.coinbase.len());
    }
    let recs = vec![
        FoldRecord::Clock { daa: 9 },
        FoldRecord::Coinbase { position: 3, recipient: [1; 43], rho: [2; 32], rseed: [3; 32], value: 4, meta: None, seen: true },
        FoldRecord::Tx {
            meta: Some(RecMeta { txid: [5; 32], daa_score: 6, timestamp_ms: 7 }),
            nullifiers: vec![[8; 32], [9; 32]],
            positions: vec![Some(10), None],
            received: vec![RecvNote { action_index: 0, recipient: [11; 43], value: 12, rho: [13; 32], rseed: [14; 32], memo: vec![1, 2, 3], seen: false }],
        },
    ];
    for r in recs {
        assert_eq!(decode_record(&encode_record(&r)), Some(r));
    }
    // A flipped byte in a framed record is refused, not misread.
    let mut f = Vec::new();
    frame(b"hello", &mut f);
    f[5] ^= 1;
    assert!(read_frame(&mut f.as_slice()).is_err());
}

/// The reference run, then for every page and every commit step: run until that step "dies",
/// reopen (must equal the previous commit exactly: files truncated, wallets caught up from
/// their files + journal), continue to the end, and require byte-identical files and equal
/// wallet states to the uninterrupted run.
#[test]
fn a_crash_at_every_commit_step_recovers_to_the_uninterrupted_result() {
    let fv = fvks();
    let rdir = tmpdir("ref");
    // Reference, with the committed record after every page.
    let mut after: Vec<Committed> = vec![ChainStore::open(&rdir, GENESIS).unwrap().0.committed().clone()];
    {
        let (mut store, mut eng) = reopen(&rdir, &fv);
        for k in 0..PAGES {
            let blocks = page(k, &eng, &fv);
            let folds = eng.ingest_page(&SharedPage::new(blocks.clone()));
            store.commit_page(&blocks, &folds, &eng, CommitFault::None).unwrap();
            write_wallets(&store, &eng, |i| (k + i as u64) % 3 == 0);
            after.push(store.committed().clone());
        }
    }
    let reference = snapshot(&rdir, &fv);
    let notes: usize = reference.1.iter().map(|s| s.matches("), (").count()).sum();
    assert!(reference.0[4].1.len() > 1000 && notes > 4, "the run must exercise the journal and own notes");
    let faults = [CommitFault::AfterChain, CommitFault::AfterIdx, CommitFault::AfterLeaves, CommitFault::AfterNfs, CommitFault::AfterJournal, CommitFault::BeforeCommitted];
    for k in [0, 3, PAGES - 1] {
        for f in faults {
            let d = tmpdir(&format!("f{k}{f:?}"));
            assert!(run(&d, &fv, Some((k, f))).is_err(), "page {k} {f:?} must fail");
            // Reopen: exactly the commit before the faulted page.
            let (store, _eng) = reopen(&d, &fv);
            assert_eq!(store.committed(), &after[k as usize], "page {k} {f:?}: reopened state");
            drop(store);
            run(&d, &fv, None).unwrap();
            let got = snapshot(&d, &fv);
            for ((n, a), (_, b)) in got.0.iter().zip(&reference.0) {
                assert!(a == b, "page {k} {f:?}: {n} differs from the uninterrupted run");
            }
            assert_eq!(got.1, reference.1, "page {k} {f:?}: wallet states");
            let _ = std::fs::remove_dir_all(&d);
        }
    }
    // Torn garbage past the committed end of every append file is cut on open.
    let d = tmpdir("torn");
    run(&d, &fv, Some((4, CommitFault::None))).unwrap();
    for n in ["chain.ccs", "blocks.idx", "leaves.bin", "nfs.bin", "journal.bin"] {
        let mut f = OpenOptions::new().append(true).open(d.join(n)).unwrap();
        f.write_all(&[0xab; 77]).unwrap();
    }
    // Opening cuts every tail back to the committed length; only then are the files compared.
    drop(ChainStore::open(&d, GENESIS).expect("opens past a torn tail"));
    assert_eq!(snapshot(&d, &fv).0, reference.0);
    // A file SHORTER than committed is refused (acknowledged data lost), never guessed.
    let f = OpenOptions::new().write(true).open(d.join("leaves.bin")).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len - 32).unwrap();
    assert!(ChainStore::open(&d, GENESIS).is_err());
    // A corrupt committed record is refused.
    let d2 = tmpdir("cmt");
    run(&d2, &fv, None).unwrap();
    let mut c = std::fs::read(d2.join("committed")).unwrap();
    c[10] ^= 1;
    std::fs::write(d2.join("committed"), c).unwrap();
    assert!(ChainStore::open(&d2, GENESIS).is_err());
    for x in [rdir, d, d2] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// The same crash matrix (fewer points) on a store that keeps no block archive: identical
/// recovery, `chain.ccs` stays empty, replays are refused, and the flag cannot be flipped.
#[test]
fn a_store_without_the_block_archive_recovers_the_same_and_refuses_to_flip() {
    let fv = fvks();
    let rdir = tmpdir("noarch-ref");
    {
        let (_s, _) = ChainStore::open_with(&rdir, GENESIS, false).unwrap();
    }
    run(&rdir, &fv, None).unwrap();
    let reference = snapshot(&rdir, &fv);
    assert!(reference.0[0].1.is_empty(), "no archive bytes");
    for f in [CommitFault::AfterChain, CommitFault::AfterJournal, CommitFault::BeforeCommitted] {
        let d = tmpdir(&format!("noarch-{f:?}"));
        {
            let (_s, _) = ChainStore::open_with(&d, GENESIS, false).unwrap();
        }
        assert!(run(&d, &fv, Some((3, f))).is_err());
        run(&d, &fv, None).unwrap();
        assert_eq!(snapshot(&d, &fv), reference, "{f:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
    let (s, _) = ChainStore::open_with(&rdir, GENESIS, false).unwrap();
    assert!(s.blocks(1, 2).is_err(), "no archive: replays are refused, not invented");
    // A read-only open beside a writer: same commit, nothing cut.
    let lens: Vec<u64> = ["leaves.bin", "journal.bin"].iter().map(|n| std::fs::metadata(rdir.join(n)).unwrap().len()).collect();
    {
        let mut f = OpenOptions::new().append(true).open(rdir.join("journal.bin")).unwrap();
        f.write_all(&[1u8; 40]).unwrap();
    }
    let r = ChainStore::open_readonly(&rdir, GENESIS).unwrap();
    assert_eq!(r.committed(), s.committed());
    assert_eq!(std::fs::metadata(rdir.join("journal.bin")).unwrap().len(), lens[1] + 40, "a reader truncates nothing");
    assert_eq!(r.journal_from(0).unwrap().len() as u64, s.committed().journal_records);
    drop(s);
    assert!(ChainStore::open_with(&rdir, GENESIS, true).is_err(), "the archive flag is fixed at creation");
    let _ = std::fs::remove_dir_all(&rdir);
}

/// Real process death: a child runs the pipeline and is SIGKILLed at random moments, over
/// and over; each restart resumes from disk. The end state must equal the uninterrupted run.
#[test]
#[cfg(unix)]
fn sigkill_at_random_moments_recovers_to_the_uninterrupted_result() {
    let fv = fvks();
    if let Ok(d) = std::env::var("ZKAS_STORE_KILL_CHILD") {
        // Child mode: resume and run to the end, slowly enough to be killed mid-commit.
        let _ = run(Path::new(&d), &fv, None);
        return;
    }
    let rdir = tmpdir("kref");
    run(&rdir, &fv, None).unwrap();
    let reference = snapshot(&rdir, &fv);
    let d = tmpdir("kill");
    let exe = std::env::current_exe().unwrap();
    let mut r = Det(77);
    let mut kills = 0;
    for _ in 0..40 {
        let mut child = std::process::Command::new(&exe)
            .args(["--exact", "engine_store::tests::sigkill_at_random_moments_recovers_to_the_uninterrupted_result", "--nocapture", "--test-threads=1"])
            .env("ZKAS_STORE_KILL_CHILD", &d)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20 + r.next() % 400));
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
            kills += 1;
        }
        child.wait().unwrap();
        // Every intermediate state must open cleanly.
        let (s, _) = ChainStore::open(&d, GENESIS).expect("opens after a kill");
        if s.committed().seq == PAGES * 12 {
            break;
        }
    }
    // Finish whatever remains, then compare.
    run(&d, &fv, None).unwrap();
    assert!(kills >= 3, "the child must actually have been killed ({kills})");
    let got = snapshot(&d, &fv);
    for ((n, a), (_, b)) in got.0.iter().zip(&reference.0) {
        assert!(a == b, "{n} differs after {kills} kills");
    }
    assert_eq!(got.1, reference.1);
    let _ = std::fs::remove_dir_all(&rdir);
    let _ = std::fs::remove_dir_all(&d);
}

/// The comb kernel and the journal agree: a wallet rebuilt purely from the journal equals the
/// live one, and a `.w2` round-trips its state.
#[test]
fn journal_replay_equals_live_state_and_w2_roundtrips() {
    let fv = fvks();
    let d = tmpdir("replay");
    let (mut store, chain) = ChainStore::open(&d, GENESIS).unwrap();
    let mut eng = ScanEngine::new(chain, Box::new(CombKernel { w: None }));
    for (i, f) in fv.iter().enumerate() {
        eng.register_wallet(WalletLite::new(f.clone(), WalletState { history_enabled: true, ..Default::default() }, 0, 0, key16(i))).unwrap();
    }
    for k in 0..PAGES {
        let blocks = page(k, &eng, &fv);
        let folds = eng.ingest_page(&SharedPage::new(blocks.clone()));
        store.commit_page(&blocks, &folds, &eng, CommitFault::None).unwrap();
    }
    for (i, f) in fv.iter().enumerate() {
        let mut w = WalletLite::new(f.clone(), WalletState { history_enabled: true, ..Default::default() }, 0, 0, key16(i));
        let (n, end) = store.catch_up(&mut w, 0).unwrap();
        assert!(n > 0);
        assert_eq!(end, store.committed().journal_len);
        assert_eq!(state_key(&w), state_key(eng.wallet(i as WalletId)), "wallet {i}");
        let h = W2Head { genesis: GENESIS, key16: key16(i), seq: 1, size: 2, journal_off: 3, blind_below: 4 };
        let (h2, s2) = decode_w2(&encode_w2(&h, &w.state())).unwrap();
        assert_eq!(h2, h);
        assert_eq!(state_key(&WalletLite::new(f.clone(), s2, 0, 0, key16(i))), state_key(&w));
    }
    // A flipped byte anywhere in a .w2 is refused.
    let mut b = encode_w2(&W2Head { genesis: GENESIS, key16: key16(0), seq: 1, size: 2, journal_off: 3, blind_below: 0 }, &eng.wallet(0).state());
    let mid = b.len() / 2;
    b[mid] ^= 1;
    assert!(decode_w2(&b).is_err());
    let _ = std::fs::remove_dir_all(&d);
}
