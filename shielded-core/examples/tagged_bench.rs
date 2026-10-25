//! Tagged-channel measurements (task C3, fork topic 01 §A): receiver-side cost per chain-day at
//! today's mainnet rate and 10x, the trial-decryption baseline on the same outputs, and a
//! birthday-free seed restore of a 1,000-tx wallet. Receiver work needs no proofs, so the chain is
//! synthetic: foreign outputs carry random tags and records; the wallet's own outputs are real
//! Orchard notes whose `cmx` the self-check verifies.
//!
//! cargo run --release -p kaspa-shielded-core --example tagged_bench -- [load_multiplier...]

use std::collections::{HashMap, HashSet};

use kaspa_shielded_core::channel::{self, CT_COMPACT_LEN, ChannelOutput, PaymentRequest, TAG_LEN};
use kaspa_shielded_core::tag_log::{TagLog, TaggedTxColumn};
use kaspa_shielded_core::tagged_wallet::{ColumnBlock, OutputRecord, TagOracle, TaggedWallet, pay_request, restore};
use orchard::keys::SpendingKey;
use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::Rng;

const ACTIONS_PER_DAY_1X: u64 = 68_659; // [MEASURED 01 §6]
const TXS_PER_DAY_1X: u64 = 3_435;
const BLOCKS_PER_DAY: u64 = 86_400;

/// CPU seconds consumed by this thread (wall time is meaningless on the shared, loaded box).
fn cpu() -> f64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
    t.tv_sec as f64 + t.tv_nsec as f64 * 1e-9
}

fn sk(b: u8) -> [u8; 32] {
    let mut s = [b; 32];
    while Option::<SpendingKey>::from(SpendingKey::from_bytes(s)).is_none() {
        s[0] = s[0].wrapping_add(1);
    }
    s
}

fn real_record(o: &ChannelOutput, rng: &mut StdRng) -> OutputRecord {
    let mut nf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut nf);
        nf[31] &= 0x3f;
        let Some(n) = Option::<orchard::note::Nullifier>::from(orchard::note::Nullifier::from_bytes(&nf)) else { continue };
        let rho = Rho::from_bytes(&n.to_bytes()).unwrap();
        let Some(rs) = Option::<RandomSeed>::from(RandomSeed::from_bytes(channel::rseed(&o.k, o.ctr), &rho)) else { continue };
        let addr = orchard::Address::from_raw_address_bytes(&o.address).unwrap();
        let note = orchard::Note::from_parts(addr, orchard::value::NoteValue::from_raw(o.value), rho, rs, NoteVersion::V2).unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        return OutputRecord { nullifier: nf, cmx, kem: o.kem, ct: o.ciphertext()[..CT_COMPACT_LEN].try_into().unwrap() };
    }
}

/// One chain-day at `mult`x load, with `planted` payments to `wallet` spread over it.
fn chain_day(mult: u64, wallet_reqs: &[PaymentRequest], planted: usize, rng: &mut StdRng) -> (Vec<ColumnBlock>, HashMap<u64, OutputRecord>, Vec<[u8; 32]>) {
    let actions = ACTIONS_PER_DAY_1X * mult;
    let txs = TXS_PER_DAY_1X * mult;
    let mut blocks: Vec<ColumnBlock> = (0..BLOCKS_PER_DAY).map(|b| ColumnBlock { hash: (b as u128).to_le_bytes().repeat(2).try_into().unwrap(), txs: vec![] }).collect();
    let mut records = HashMap::new();
    let mut kems = Vec::new();
    let mut leaf = 0u64;
    let plant_at: HashSet<u64> = (0..planted).map(|i| (i as u64 * txs) / planted as u64).collect();
    let mut ctrs = vec![0u32; wallet_reqs.len()];
    for t in 0..txs {
        let b = (t * BLOCKS_PER_DAY / txs) as usize;
        let per_tx = (t + 1) * actions / txs - t * actions / txs;
        let mut tags = Vec::with_capacity(per_tx as usize);
        for j in 0..per_tx {
            if j == 0 && plant_at.contains(&t) {
                let r = (t as usize) % wallet_reqs.len();
                let o = pay_request(&wallet_reqs[r], 1_000 + t, ctrs[r], rng);
                ctrs[r] += 1;
                records.insert(leaf, real_record(&o, rng));
                tags.push(o.tag);
                kems.push(o.kem);
            } else {
                let mut tg = [0u8; TAG_LEN];
                rng.fill_bytes(&mut tg);
                tags.push(tg);
                if kems.len() < 20_000 {
                    kems.push(channel::random_kem(rng));
                }
            }
            leaf += 1;
        }
        let first = leaf - per_tx;
        blocks[b].txs.push(TaggedTxColumn { first_leaf: first, tags });
    }
    (blocks, records, kems)
}

fn column_bytes(blocks: &[ColumnBlock]) -> (u64, u64) {
    // tags only, and the full wire (per block: 32-B hash + u32 tx count; per tx: u64 first leaf + u32 count).
    let tags: u64 = blocks.iter().flat_map(|b| &b.txs).map(|t| 16 * t.tags.len() as u64).sum();
    let txs: u64 = blocks.iter().map(|b| b.txs.len() as u64).sum();
    (tags, tags + 12 * txs + 36 * blocks.len() as u64)
}

fn sync_day(mult: u64) {
    let mut rng = StdRng::seed_from_u64(mult);
    let mut w = TaggedWallet::new(sk(1), 3).unwrap();
    let reqs: Vec<PaymentRequest> = (0..10).map(|_| w.issue_request(0)).collect();
    let (blocks, records, kems) = chain_day(mult, &reqs, 20, &mut rng);
    let n_out: u64 = blocks.iter().flat_map(|b| &b.txs).map(|t| t.tags.len() as u64).sum();
    let t0 = cpu();
    for b in &blocks {
        w.scan_block(b, |p| records.get(&p).copied());
    }
    let scan = cpu() - t0;
    let t1 = cpu();
    let log = TagLog::replay_blocks(&TagLog::default(), blocks.iter().map(|b| (&b.hash, b.txs.as_slice()))).unwrap();
    let replay = cpu() - t1;
    std::hint::black_box(log.commitment());
    // Baseline on the same outputs: the open-lane key agreement (= the per-output trial-decryption
    // work an ECDH scan pays), timed on a sample and scaled.
    let ivk = kaspa_shielded_core::wallet::scan::ivk_agreement_scalar(
        &orchard::keys::FullViewingKey::from(&SpendingKey::from_bytes(sk(1)).unwrap()).to_ivk(orchard::keys::Scope::External),
    )
    .unwrap();
    let sample = kems.len().min(5_000);
    let t2 = cpu();
    for k in &kems[..sample] {
        std::hint::black_box(channel::open_lane_k(&ivk, k));
    }
    let per_trial = (cpu() - t2) / sample as f64;
    let (tag_b, wire_b) = column_bytes(&blocks);
    let fetched = w.stats.hits * 148;
    println!(
        "SYNC {mult}x: outputs/day {n_out}  expected tags {}  found {}  rejected {}\n  scan {:.3} s  tag-log replay {:.3} s  (thread CPU time)\n  column {:.2} MB tags / {:.2} MB wire, + {} B fetched for {} hits\n  baseline ECDH per output {:.1} us -> {:.1} s/day single thread (no key agreement in lookup mode)",
        w.expected_len(),
        w.found.len(),
        w.stats.rejected,
        scan,
        replay,
        tag_b as f64 / 1e6,
        wire_b as f64 / 1e6,
        fetched,
        w.stats.hits,
        per_trial * 1e6,
        per_trial * n_out as f64,
    );
}

struct Chain {
    outputs: Vec<([u8; TAG_LEN], OutputRecord)>,
    by_tag: HashMap<[u8; TAG_LEN], Vec<u64>>,
    spent: HashSet<[u8; 32]>,
    queries: u64,
    rounds: u64,
    per_round: Vec<u64>,
}

impl TagOracle for Chain {
    fn lookup(&mut self, tag: &[u8; TAG_LEN]) -> Vec<(u64, OutputRecord)> {
        self.queries += 1;
        *self.per_round.last_mut().unwrap() += 1;
        self.by_tag.get(tag).map(|v| v.iter().map(|&p| (p, self.outputs[p as usize].1)).collect()).unwrap_or_default()
    }
    fn deposits(&mut self, _i: u32) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn is_spent(&mut self, nf: &[u8; 32]) -> bool {
        self.queries += 1;
        *self.per_round.last_mut().unwrap() += 1;
        self.spent.contains(nf)
    }
    fn round(&mut self) {
        self.rounds += 1;
        self.per_round.push(0);
    }
}

fn restore_bench(n_tx: u32, n_req: u32) {
    let mut rng = StdRng::seed_from_u64(77);
    let key = sk(9);
    let mut w = TaggedWallet::new(key, 3).unwrap();
    let mut chain = Chain { outputs: vec![], by_tag: HashMap::new(), spent: HashSet::new(), queries: 0, rounds: 0, per_round: vec![0] };
    let mut push = |c: &mut Chain, t: [u8; TAG_LEN], r: OutputRecord| {
        c.by_tag.entry(t).or_default().push(c.outputs.len() as u64);
        c.outputs.push((t, r));
        c.outputs.len() as u64 - 1
    };
    let reqs: Vec<PaymentRequest> = (0..n_req).map(|_| w.issue_request(0)).collect();
    let mut req_ctr = vec![0u32; n_req as usize];
    for t in 0..n_tx {
        for _ in 0..20 {
            let mut tg = [0u8; TAG_LEN];
            rng.fill_bytes(&mut tg);
            push(&mut chain, tg, OutputRecord { nullifier: [0; 32], cmx: [0; 32], kem: [0; 32], ct: [0; CT_COMPACT_LEN] });
        }
        if t % 4 == 0 {
            let r = (t / 4 % n_req) as usize;
            if req_ctr[r] < 3 {
                let o = pay_request(&reqs[r], 10_000 + t as u64, req_ctr[r], &mut rng);
                req_ctr[r] += 1;
                let rec = real_record(&o, &mut rng);
                let p = push(&mut chain, o.tag, rec);
                w.accept(&o.tag, p, &rec);
                continue;
            }
        }
        let live: Vec<usize> = (0..w.found.len()).filter(|&i| !w.found[i].spent).collect();
        let (spend, v): (Vec<[u8; 32]>, u64) = match live.iter().max_by_key(|&&i| w.found[i].value()) {
            Some(&i) => (vec![w.found[i].nullifier], w.found[i].value() - w.found[i].value() / 10),
            None => (vec![], 50_000),
        };
        let o = w.change_output(v, &spend, t / 100, &mut rng);
        for nf in &spend {
            chain.spent.insert(*nf);
        }
        w.mark_spent(&spend);
        let rec = real_record(&o, &mut rng);
        let p = push(&mut chain, o.tag, rec);
        w.accept(&o.tag, p, &rec);
    }
    let (want_bal, want_unspent) = (w.balance(), w.found.iter().filter(|f| !f.spent).count());
    let t0 = cpu();
    let (_, rep) = restore(key, &mut chain, 20, 3).unwrap();
    let cpu_s = cpu() - t0;
    assert_eq!(rep.balance, want_bal);
    assert_eq!(rep.unspent, want_unspent);
    let max_round = chain.per_round.iter().copied().max().unwrap_or(0);
    println!(
        "RESTORE {n_tx} txs / {n_req} requests, no birthday, chain {} outputs: found {} notes, {} unspent, balance ok, complete={}\n  {} queries in {} rounds (largest round {} queries), client CPU {:.3} s",
        chain.outputs.len(),
        rep.notes_found,
        rep.unspent,
        rep.complete,
        chain.queries,
        chain.rounds,
        max_round,
        cpu_s
    );
    // Wall-time models. P-mode with work-b4's MEASURED YPIR on 4.23 GB (3.29 s server, 1.14 MB per
    // query), Tor RTT 0.5-1 s [UNCHECKED, 10 §5.1], 10 Mbit/s; queries in a round go out together
    // and the server runs them on 8 cores.
    let (srv, comm, cores) = (3.29f64, 1.144e6f64, 8.0f64);
    for rtt in [0.5f64, 1.0] {
        let wall: f64 = chain.per_round.iter().filter(|&&q| q > 0).map(|&q| rtt + srv * (q as f64 / cores).ceil() + q as f64 * comm * 8.0 / 10e6).sum();
        println!("  P-mode (YPIR 4.23 GB measured) at RTT {rtt}: {:.0} s wall, {:.0} MB transferred", wall, chain.queries as f64 * comm / 1e6);
        // Respire, 1 GB of 256-B records: 3.6-3.9 s end-to-end per query MEASURED by work-b4; its
        // communication was not logged, so this is a lower bound that counts server time only.
        let wall_r: f64 = chain.per_round.iter().filter(|&&q| q > 0).map(|&q| rtt + 3.75 * (q as f64 / cores).ceil()).sum();
        println!("  P-mode (Respire 1 GB measured, communication not counted) at RTT {rtt}: >= {:.0} s wall", wall_r);
    }
    let lookups = chain.queries - chain.per_round.iter().rev().take(1).sum::<u64>();
    println!("  of which spentness checks in the last round: {}, tag lookups: {}", chain.per_round.last().unwrap(), lookups);
}

fn main() {
    let mults: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    for m in if mults.is_empty() { vec![1, 10] } else { mults } {
        sync_day(m);
    }
    restore_bench(1_000, 50);
}
