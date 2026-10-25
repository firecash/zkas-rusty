//! The tagged-channel wallet engine (fork topic 01 §3.3–3.7; devnet prototype).
//!
//! A wallet finds channel payments by **lookup**, not trial decryption: it keeps a hash set of the
//! next `L` tags of every channel it owns, streams the chain's tag column (16 bytes per output, no
//! cryptography), and on a hit fetches that one output's record and authenticates it with the
//! `cmx` self-check ([`crate::channel::open_channel_output`]). The only trial decryption left is
//! the **open lane** — unsolicited payments to a static address — which costs one scalar
//! multiplication per output and is run only by a wallet that has published a static address
//! ([`TaggedWallet::scan_open_lane`]).
//!
//! Restore from seed needs no birthday ([`restore`]): every channel key is derived from the seed,
//! the newest self output is found by an exponential/binary search over the self counter, and its
//! recovery ledger names the ranges of every channel family that can still hold funds.

use std::collections::HashMap;

use orchard::keys::{Diversifier, FullViewingKey, Scope, SpendingKey};

use crate::channel::{
    self, AUX_LEN, CT_COMPACT_LEN, ChannelKeys, ChannelOutput, Kind, PaymentRequest, Plaintext, RecoveryLedger, TAG_LEN,
};
use crate::tag_log::TaggedTxColumn;

/// One chain block of the tag column, as a node serves it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColumnBlock {
    pub hash: [u8; 32],
    pub txs: Vec<TaggedTxColumn>,
}

/// The part of one output a wallet fetches after a tag hit (the 148-byte compact scan record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputRecord {
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub kem: [u8; 32],
    pub ct: [u8; CT_COMPACT_LEN],
}

impl OutputRecord {
    /// From a 148-byte `CompactActionRecord` of a tagged action.
    pub fn from_compact(b: &[u8]) -> Option<Self> {
        if b.len() != 148 {
            return None;
        }
        Some(Self {
            nullifier: b[0..32].try_into().ok()?,
            cmx: b[32..64].try_into().ok()?,
            kem: b[64..96].try_into().ok()?,
            ct: b[96..148].try_into().ok()?,
        })
    }
}

/// The kinds of channel a wallet owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    SelfChannel,
    Request,
    Intro,
}

/// A wallet-local channel record (≈ 80 bytes of state).
#[derive(Clone, Debug)]
pub struct ChannelRecord {
    pub kind: ChannelKind,
    pub index: u32,
    pub k: [u8; 32],
    pub address: [u8; 43],
    /// Next counter not yet seen on chain.
    pub next_ctr: u32,
}

/// A note the wallet found.
#[derive(Clone)]
pub struct FoundNote {
    pub position: u64,
    pub note: orchard::Note,
    pub nullifier: [u8; 32],
    pub kind: Kind,
    pub channel: Option<usize>,
    pub ctr: u32,
    pub aux: [u8; AUX_LEN],
    pub spent: bool,
}

impl FoundNote {
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
}

/// Work counters (what the measurements report).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanStats {
    /// Tags streamed and probed against the expected set.
    pub tags_probed: u64,
    /// Expected-set hits (records fetched).
    pub hits: u64,
    /// Hits whose record failed the `cmx` self-check (tag spam on a known channel).
    pub rejected: u64,
    /// Open-lane key agreements (the trial-decryption fallback).
    pub open_lane_trials: u64,
}

/// The wallet engine.
pub struct TaggedWallet {
    sk: [u8; 32],
    fvk: FullViewingKey,
    ivk_scalar: pasta_curves::pallas::Scalar,
    keys: ChannelKeys,
    pub channels: Vec<ChannelRecord>,
    /// Tags looked ahead per channel.
    pub lookahead: u32,
    expected: HashMap<[u8; TAG_LEN], (usize, u32)>,
    pub found: Vec<FoundNote>,
    pub stats: ScanStats,
    /// Next self counter to allocate.
    pub next_self_ctr: u32,
    /// Next request index to issue.
    pub next_request: u32,
    /// Intro tokens uploaded so far (exclusive bound).
    pub intro_hwm: u32,
}

impl TaggedWallet {
    /// A wallet for spending key bytes `sk`, with lookahead `L` (01 §3.5: 2–4).
    pub fn new(sk: [u8; 32], lookahead: u32) -> Option<Self> {
        let s = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk))?;
        let fvk = FullViewingKey::from(&s);
        let ivk_scalar = crate::wallet::scan::ivk_agreement_scalar(&fvk.to_ivk(Scope::External))?;
        let keys = ChannelKeys::from_spending_key(&sk);
        let self_addr = fvk.address_at(0u32, Scope::Internal).to_raw_address_bytes();
        let mut w = Self {
            sk,
            fvk,
            ivk_scalar,
            keys: keys.clone(),
            channels: Vec::new(),
            lookahead,
            expected: HashMap::new(),
            found: Vec::new(),
            stats: ScanStats::default(),
            next_self_ctr: 0,
            next_request: 0,
            intro_hwm: 0,
        };
        w.add_channel(ChannelRecord { kind: ChannelKind::SelfChannel, index: 0, k: keys.k_self(), address: self_addr, next_ctr: 0 });
        Some(w)
    }

    pub fn spending_key(&self) -> [u8; 32] {
        self.sk
    }

    pub fn keys(&self) -> &ChannelKeys {
        &self.keys
    }

    /// The published static address (open lane).
    pub fn static_address(&self) -> [u8; 43] {
        self.fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
    }

    fn add_channel(&mut self, rec: ChannelRecord) -> usize {
        let id = self.channels.len();
        for c in rec.next_ctr..rec.next_ctr + self.lookahead {
            self.expected.insert(channel::tag(&rec.k, c), (id, c));
        }
        self.channels.push(rec);
        id
    }

    /// Issue payment request `next_request` (mode S): a fresh address and its channel key.
    pub fn issue_request(&mut self, amount: u64) -> PaymentRequest {
        let i = self.next_request;
        self.next_request += 1;
        self.watch_request(i);
        let c = self.channels.last().unwrap();
        PaymentRequest { address: c.address, k: c.k, ctr0: 0, amount }
    }

    fn watch_request(&mut self, i: u32) -> usize {
        let address = self.fvk.address_at(channel::REQ_BASE + i, Scope::External).to_raw_address_bytes();
        self.add_channel(ChannelRecord { kind: ChannelKind::Request, index: i, k: self.keys.k_req(i), address, next_ctr: 0 })
    }

    /// Watch intro token `i`, given the `kem` a payer deposited at the intro service.
    pub fn watch_intro(&mut self, i: u32, kem: &[u8; 32]) -> Option<usize> {
        let k = self.keys.intro_k(i, kem)?;
        let address = self.static_address();
        self.intro_hwm = self.intro_hwm.max(i + 1);
        Some(self.add_channel(ChannelRecord { kind: ChannelKind::Intro, index: i, k, address, next_ctr: 0 }))
    }

    /// Number of tags currently looked for.
    pub fn expected_len(&self) -> usize {
        self.expected.len()
    }

    /// Whether a tag is one this wallet expects (a pure hash-set probe).
    pub fn expects(&self, t: &[u8; TAG_LEN]) -> bool {
        self.expected.contains_key(t)
    }

    /// Accept a record found under an expected tag at `position`. Returns the index into
    /// [`Self::found`], or `None` if the record fails the self-check (spam, wrong channel).
    pub fn accept(&mut self, t: &[u8; TAG_LEN], position: u64, rec: &OutputRecord) -> Option<usize> {
        let &(ch, ctr) = self.expected.get(t)?;
        self.stats.hits += 1;
        let c = &self.channels[ch];
        let pt = channel::open_compact(&c.k, ctr, &rec.ct);
        let note = pt.and_then(|pt| channel::open_channel_output(&c.address, pt.value, &c.k, ctr, &rec.nullifier, &rec.cmx));
        let (Some(pt), Some(note)) = (pt, note) else {
            self.stats.rejected += 1;
            return None;
        };
        if self.found.iter().any(|f| f.position == position) {
            return None;
        }
        // Advance the channel window past `ctr` (duplicate counters stay found: the tag stays expected).
        let k = c.k;
        let next = self.channels[ch].next_ctr.max(ctr + 1);
        for c2 in self.channels[ch].next_ctr + self.lookahead..next + self.lookahead {
            self.expected.insert(channel::tag(&k, c2), (ch, c2));
        }
        self.channels[ch].next_ctr = next;
        if self.channels[ch].kind == ChannelKind::SelfChannel {
            self.next_self_ctr = self.next_self_ctr.max(next);
        }
        let nullifier = note.nullifier(&self.fvk).to_bytes();
        self.found.push(FoundNote { position, note, nullifier, kind: pt.kind, channel: Some(ch), ctr, aux: pt.aux, spent: false });
        Some(self.found.len() - 1)
    }

    /// Scan one block of the tag column. `fetch` returns the record at an absolute tree position
    /// (a Tor fetch with decoys, or chunk PIR: spec 05 §5). Returns the indices of new notes.
    pub fn scan_block(&mut self, blk: &ColumnBlock, mut fetch: impl FnMut(u64) -> Option<OutputRecord>) -> Vec<usize> {
        let mut out = Vec::new();
        for tx in &blk.txs {
            for (j, t) in tx.tags.iter().enumerate() {
                self.stats.tags_probed += 1;
                if self.expected.contains_key(t) {
                    let pos = tx.first_leaf + j as u64;
                    if let Some(rec) = fetch(pos)
                        && let Some(i) = self.accept(t, pos, &rec)
                    {
                        out.push(i);
                    }
                }
            }
        }
        out
    }

    /// The trial-decryption fallback for the open lane: one key agreement per output, for
    /// wallets that published a static address. `outputs` are `(position, tag, kem)` triples of
    /// every output in the range; on a match the record is fetched and self-checked.
    pub fn scan_open_lane(
        &mut self,
        outputs: &[(u64, [u8; TAG_LEN], [u8; 32])],
        mut fetch: impl FnMut(u64) -> Option<OutputRecord>,
    ) -> Vec<usize> {
        let mut out = Vec::new();
        for (pos, t, kem) in outputs {
            self.stats.open_lane_trials += 1;
            let Some(k) = channel::open_lane_k(&self.ivk_scalar, kem) else { continue };
            if !channel::is_open_lane_tag(&k, t) {
                continue;
            }
            let Some(rec) = fetch(*pos) else { continue };
            let Some(pt) = channel::open_compact(&k, 0, &rec.ct) else { continue };
            if pt.kind != Kind::OpenLane {
                continue;
            }
            let d: [u8; 11] = pt.aux[..11].try_into().unwrap();
            let addr = self.fvk.address(Diversifier::from_bytes(d), Scope::External).to_raw_address_bytes();
            let Some(note) = channel::open_channel_output(&addr, pt.value, &k, 0, &rec.nullifier, &rec.cmx) else {
                self.stats.rejected += 1;
                continue;
            };
            if self.found.iter().any(|f| f.position == *pos) {
                continue;
            }
            let nullifier = note.nullifier(&self.fvk).to_bytes();
            self.found.push(FoundNote { position: *pos, note, nullifier, kind: Kind::OpenLane, channel: None, ctr: 0, aux: pt.aux, spent: false });
            out.push(self.found.len() - 1);
        }
        out
    }

    /// Mark notes spent by the given nullifiers (the wallet's own spends, or a spentness query).
    pub fn mark_spent(&mut self, nfs: &[[u8; 32]]) {
        for f in &mut self.found {
            if nfs.contains(&f.nullifier) {
                f.spent = true;
            }
        }
    }

    pub fn balance(&self) -> u64 {
        self.found.iter().filter(|f| !f.spent).map(|f| f.value()).sum()
    }

    /// The recovery ledger as of now, assuming the notes in `spending` are about to be spent and
    /// one more self output (counter `self_ctr`) is about to be created.
    pub fn ledger(&self, spending: &[[u8; 32]], self_ctr: u32, epoch: u32) -> RecoveryLedger {
        let live: Vec<&FoundNote> = self.found.iter().filter(|f| !f.spent && !spending.contains(&f.nullifier)).collect();
        let min_of = |kind: ChannelKind, default: u32| {
            live.iter()
                .filter_map(|f| f.channel.filter(|&c| self.channels[c].kind == kind).map(|c| match kind {
                    ChannelKind::SelfChannel => f.ctr,
                    _ => self.channels[c].index,
                }))
                .min()
                .unwrap_or(default)
        };
        RecoveryLedger {
            lwm_self: min_of(ChannelKind::SelfChannel, self_ctr).min(self_ctr),
            lwm_req: min_of(ChannelKind::Request, self.next_request),
            hwm_req: self.next_request,
            lwm_int: min_of(ChannelKind::Intro, self.intro_hwm),
            hwm_int: self.intro_hwm,
            epoch,
            n_unspent: (live.len() + 1).min(u16::MAX as usize) as u16,
            svc_hint: 0,
        }
    }

    /// The change output of a spend of `spending`: the next self counter, carrying the ledger.
    pub fn change_output(
        &mut self,
        value: u64,
        spending: &[[u8; 32]],
        epoch: u32,
        rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
    ) -> ChannelOutput {
        let ctr = self.next_self_ctr;
        self.next_self_ctr += 1;
        let ledger = self.ledger(spending, ctr, epoch);
        let c = &self.channels[0];
        ChannelOutput::on_channel(c.address, value, c.k, ctr, Kind::SelfChannel, ledger.to_aux(), rng)
    }
}

/// A payer's output paying request `req` at counter `ctr`.
pub fn pay_request(
    req: &PaymentRequest,
    value: u64,
    ctr: u32,
    rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
) -> ChannelOutput {
    ChannelOutput::on_channel(req.address, value, req.k, ctr, Kind::Request, [0u8; AUX_LEN], rng)
}

/// What a restoring wallet can ask of its lookup service (T-mode index or keyword PIR). Every
/// call is one query; [`TagOracle::round`] marks a network round trip (the queries since the last
/// round go out together).
pub trait TagOracle {
    /// All outputs carrying `tag`, with their absolute positions.
    fn lookup(&mut self, tag: &[u8; TAG_LEN]) -> Vec<(u64, OutputRecord)>;
    /// The `kem` deposits an intro service holds for token `i`.
    fn deposits(&mut self, i: u32) -> Vec<[u8; 32]>;
    /// Whether a nullifier is in the chain's nullifier set.
    fn is_spent(&mut self, nf: &[u8; 32]) -> bool;
    /// Mark the end of a round trip.
    fn round(&mut self);
}

/// The outcome of a restore.
#[derive(Clone, Debug, Default)]
pub struct RestoreReport {
    pub newest_self_ctr: Option<u32>,
    pub ledger: Option<RecoveryLedger>,
    pub notes_found: usize,
    pub unspent: usize,
    pub balance: u64,
    /// `n_unspent` of the newest ledger is consistent with what was found.
    pub complete: bool,
}

/// RESTORE(seed) (01 §3.7), birthday-free. Gap limits: `req_gap` request indices past the
/// ledger's high-water mark, and `ctr_gap` consecutive missing counters end a channel.
pub fn restore(sk: [u8; 32], oracle: &mut impl TagOracle, req_gap: u32, ctr_gap: u32) -> Option<(TaggedWallet, RestoreReport)> {
    let mut w = TaggedWallet::new(sk, ctr_gap.max(1))?;
    let k_self = w.keys.k_self();
    let mut report = RestoreReport::default();

    // 1. The newest self output: exponential, then binary search over the self counter.
    let probe = |o: &mut dyn FnMut(&[u8; TAG_LEN]) -> bool, c: u32| o(&channel::tag(&k_self, c));
    let mut hit = |t: &[u8; TAG_LEN]| {
        let r = !oracle.lookup(t).is_empty();
        oracle.round();
        r
    };
    let newest = if !probe(&mut hit, 0) {
        None
    } else {
        let (mut lo, mut hi) = (0u32, 1u32);
        while probe(&mut hit, hi) {
            lo = hi;
            hi = hi.saturating_mul(2);
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if probe(&mut hit, mid) { lo = mid } else { hi = mid }
        }
        Some(lo)
    };
    report.newest_self_ctr = newest;

    // 2. The ledger from the newest self output.
    let fetch_into = |w: &mut TaggedWallet, oracle: &mut dyn TagOracle, tags: &[[u8; TAG_LEN]]| {
        let mut any = vec![false; tags.len()];
        for (i, t) in tags.iter().enumerate() {
            for (pos, rec) in oracle.lookup(t) {
                if w.accept(t, pos, &rec).is_some() {
                    any[i] = true;
                }
            }
        }
        oracle.round();
        any
    };
    if let Some(n) = newest {
        // Make the newest counter's tag expected, then fetch it.
        w.channels[0].next_ctr = n;
        for c in n..n + w.lookahead {
            w.expected.insert(channel::tag(&k_self, c), (0, c));
        }
        fetch_into(&mut w, &mut *oracle, &[channel::tag(&k_self, n)]);
        report.ledger = w.found.iter().find(|f| f.kind == Kind::SelfChannel && f.ctr == n).and_then(|f| RecoveryLedger::from_aux(&f.aux));
    }
    let ledger = report.ledger.unwrap_or_default();

    // 3a. Self outputs [LWM_self, newest), in one round.
    if let Some(n) = newest {
        for c in ledger.lwm_self..n {
            w.expected.insert(channel::tag(&k_self, c), (0, c));
        }
        let tags: Vec<_> = (ledger.lwm_self..n).map(|c| channel::tag(&k_self, c)).collect();
        fetch_into(&mut w, &mut *oracle, &tags);
        w.next_self_ctr = n + 1;
    }
    // 3b. Requests [LWM_req, HWM_req + gap): counter 0.. until `ctr_gap` consecutive misses.
    let req_hi = ledger.hwm_req + req_gap;
    let mut live: Vec<(usize, u32, u32)> = (ledger.lwm_req..req_hi).map(|i| (w.watch_request(i), 0u32, 0u32)).collect();
    w.next_request = req_hi;
    while !live.is_empty() {
        let tags: Vec<_> = live.iter().map(|&(ch, ctr, _)| channel::tag(&w.channels[ch].k, ctr)).collect();
        let hits = fetch_into(&mut w, &mut *oracle, &tags);
        let mut next = Vec::new();
        for (&(ch, ctr, misses), h) in live.iter().zip(hits) {
            let misses = if h { 0 } else { misses + 1 };
            if misses < ctr_gap {
                next.push((ch, ctr + 1, misses));
            }
        }
        live = next;
    }
    // 3c. Intro tokens [LWM_int, HWM_int): deposits, then the first-contact tag of each.
    for i in ledger.lwm_int..ledger.hwm_int {
        let kems = oracle.deposits(i);
        let mut tags = Vec::new();
        for kem in kems {
            if let Some(ch) = w.watch_intro(i, &kem) {
                tags.push(channel::tag(&w.channels[ch].k, 0));
            }
        }
        if !tags.is_empty() {
            fetch_into(&mut w, &mut *oracle, &tags);
        }
    }
    // 4. Spentness.
    let nfs: Vec<[u8; 32]> = w.found.iter().map(|f| f.nullifier).collect();
    let spent: Vec<[u8; 32]> = nfs.into_iter().filter(|nf| oracle.is_spent(nf)).collect();
    oracle.round();
    w.mark_spent(&spent);
    report.notes_found = w.found.len();
    report.unspent = w.found.iter().filter(|f| !f.spent).count();
    report.balance = w.balance();
    report.complete = report.ledger.is_none_or(|l| report.unspent >= l.n_unspent as usize);
    Some((w, report))
}

/// Sanity helper: an unused plaintext is never mistaken for a ledger.
pub fn is_ledger(pt: &Plaintext) -> bool {
    pt.kind == Kind::SelfChannel && RecoveryLedger::from_aux(&pt.aux).is_some()
}

#[cfg(test)]
mod tests_support {
    pub(crate) use super::tests::{Chain, Index, history, sk};
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
    use rand::{SeedableRng, rngs::StdRng};
use rand_core::Rng;

    /// A synthetic chain of tagged outputs without proofs (the receiver side needs none): each
    /// output is `(position, tag, record)`; wallet outputs carry real notes with real `cmx`.
    pub(crate) struct Chain {
        pub outputs: Vec<([u8; TAG_LEN], OutputRecord)>,
        pub spent: std::collections::HashSet<[u8; 32]>,
        pub deposits: HashMap<u32, Vec<[u8; 32]>>,
    }

    impl Chain {
        pub fn new() -> Self {
            Self { outputs: Vec::new(), spent: Default::default(), deposits: HashMap::new() }
        }

        /// Append a foreign (random) output.
        pub fn noise(&mut self, rng: &mut StdRng) {
            let mut t = [0u8; TAG_LEN];
            let mut nf = [0u8; 32];
            let mut ct = [0u8; CT_COMPACT_LEN];
            rng.fill_bytes(&mut t);
            rng.fill_bytes(&mut nf);
            nf[31] &= 0x3f;
            rng.fill_bytes(&mut ct);
            self.outputs.push((t, OutputRecord { nullifier: nf, cmx: [1u8; 32], kem: channel::random_kem(rng), ct }));
        }

        /// Append a real output for `o`, returning its position.
        pub fn put(&mut self, o: &ChannelOutput, rng: &mut StdRng) -> u64 {
            let mut nf = [0u8; 32];
            loop {
                rng.fill_bytes(&mut nf);
                nf[31] &= 0x3f;
                let n = Option::<orchard::note::Nullifier>::from(orchard::note::Nullifier::from_bytes(&nf));
                let Some(n) = n else { continue };
                let rho = Rho::from_bytes(&n.to_bytes()).unwrap();
                let Some(rs) = Option::<RandomSeed>::from(RandomSeed::from_bytes(channel::rseed(&o.k, o.ctr), &rho)) else { continue };
                let addr = orchard::Address::from_raw_address_bytes(&o.address).unwrap();
                let note = orchard::Note::from_parts(addr, orchard::value::NoteValue::from_raw(o.value), rho, rs, NoteVersion::V2).unwrap();
                let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
                let ct = o.ciphertext();
                self.outputs.push((o.tag, OutputRecord { nullifier: nf, cmx, kem: o.kem, ct: ct[..CT_COMPACT_LEN].try_into().unwrap() }));
                return self.outputs.len() as u64 - 1;
            }
        }

        pub fn column(&self, per_block: usize) -> Vec<ColumnBlock> {
            self.outputs
                .chunks(per_block)
                .enumerate()
                .map(|(b, ch)| ColumnBlock {
                    hash: [b as u8; 32],
                    txs: vec![TaggedTxColumn { first_leaf: (b * per_block) as u64, tags: ch.iter().map(|(t, _)| *t).collect() }],
                })
                .collect()
        }
    }

    /// A T-mode oracle over the synthetic chain: an index from tag to positions.
    pub(crate) struct Index<'a> {
        pub chain: &'a Chain,
        pub by_tag: HashMap<[u8; TAG_LEN], Vec<u64>>,
        pub queries: u64,
        pub rounds: u64,
    }

    impl<'a> Index<'a> {
        pub fn new(chain: &'a Chain) -> Self {
            let mut by_tag: HashMap<[u8; TAG_LEN], Vec<u64>> = HashMap::new();
            for (i, (t, _)) in chain.outputs.iter().enumerate() {
                by_tag.entry(*t).or_default().push(i as u64);
            }
            Self { chain, by_tag, queries: 0, rounds: 0 }
        }
    }

    impl TagOracle for Index<'_> {
        fn lookup(&mut self, tag: &[u8; TAG_LEN]) -> Vec<(u64, OutputRecord)> {
            self.queries += 1;
            self.by_tag.get(tag).map(|v| v.iter().map(|&p| (p, self.chain.outputs[p as usize].1)).collect()).unwrap_or_default()
        }
        fn deposits(&mut self, i: u32) -> Vec<[u8; 32]> {
            self.queries += 1;
            self.chain.deposits.get(&i).cloned().unwrap_or_default()
        }
        fn is_spent(&mut self, nf: &[u8; 32]) -> bool {
            self.queries += 1;
            self.chain.spent.contains(nf)
        }
        fn round(&mut self) {
            self.rounds += 1;
        }
    }

    pub(crate) fn sk(b: u8) -> [u8; 32] {
        let mut s = [b; 32];
        while Option::<SpendingKey>::from(SpendingKey::from_bytes(s)).is_none() {
            s[0] = s[0].wrapping_add(1);
        }
        s
    }

    #[test]
    fn lookup_finds_request_and_self_payments_and_nothing_else() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut chain = Chain::new();
        let mut alice = TaggedWallet::new(sk(1), 3).unwrap();
        let mut bob = TaggedWallet::new(sk(2), 3).unwrap();
        let req = alice.issue_request(5_000);
        let mut want = Vec::new();
        for i in 0..2000 {
            if i % 397 == 5 {
                let ctr = want.len() as u32;
                want.push(chain.put(&pay_request(&req, 1_000 + ctr as u64, ctr, &mut rng), &mut rng));
            } else if i == 1000 {
                let o = bob.change_output(77, &[], 1, &mut rng);
                chain.put(&o, &mut rng);
            } else {
                chain.noise(&mut rng);
            }
        }
        let col = chain.column(97);
        for b in &col {
            alice.scan_block(b, |p| Some(chain.outputs[p as usize].1));
        }
        let got: Vec<u64> = alice.found.iter().map(|f| f.position).collect();
        assert_eq!(got, want, "every request payment is found, at its position, and nothing else");
        assert_eq!(alice.stats.tags_probed, 2000);
        assert_eq!(alice.stats.open_lane_trials, 0, "channel payments cost no key agreement");
        assert_eq!(alice.balance(), (0..want.len() as u64).map(|c| 1_000 + c).sum::<u64>());
        // Bob's self output is found by Bob only.
        for b in &col {
            bob.scan_block(b, |p| Some(chain.outputs[p as usize].1));
        }
        assert_eq!(bob.found.len(), 1);
        assert_eq!(bob.found[0].value(), 77);
        assert_eq!(bob.found[0].kind, Kind::SelfChannel);
    }

    /// A payer who knows K writes outputs under the channel's future tags with garbage
    /// ciphertexts or wrong notes: the `cmx` self-check rejects them all.
    #[test]
    fn tag_spam_on_a_known_channel_is_rejected_by_the_cmx_check() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut chain = Chain::new();
        let mut alice = TaggedWallet::new(sk(3), 4).unwrap();
        let req = alice.issue_request(0);
        // Garbage ciphertext under the right tag.
        let mut ct = [0u8; CT_COMPACT_LEN];
        rng.fill_bytes(&mut ct);
        chain.outputs.push((channel::tag(&req.k, 0), OutputRecord { nullifier: [5u8; 32], cmx: [6u8; 32], kem: channel::random_kem(&mut rng), ct }));
        // A correct ciphertext but a commitment to a different note (value lied about).
        let real = pay_request(&req, 10, 1, &mut rng);
        let p = chain.put(&real, &mut rng);
        let lie = ChannelOutput { value: 1_000_000, ..real };
        chain.outputs[p as usize].1.ct = lie.ciphertext()[..CT_COMPACT_LEN].try_into().unwrap();
        // Then an honest payment at counter 2.
        chain.put(&pay_request(&req, 42, 2, &mut rng), &mut rng);
        for b in &chain.column(10) {
            alice.scan_block(b, |q| Some(chain.outputs[q as usize].1));
        }
        assert_eq!(alice.found.len(), 1);
        assert_eq!(alice.found[0].value(), 42);
        assert_eq!(alice.stats.rejected, 2);
    }

    /// Open lane: a static-address payment is found by the fallback (one key agreement per output)
    /// and by nobody else; channel scanning never sees it.
    #[test]
    fn open_lane_fallback_finds_static_payments() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut chain = Chain::new();
        let mut alice = TaggedWallet::new(sk(4), 2).unwrap();
        let mut eve = TaggedWallet::new(sk(5), 2).unwrap();
        for i in 0..300 {
            if i == 123 {
                let o = ChannelOutput::open_lane(alice.static_address(), 9_999, &mut rng).unwrap();
                chain.put(&o, &mut rng);
            } else {
                chain.noise(&mut rng);
            }
        }
        for b in &chain.column(50) {
            alice.scan_block(b, |q| Some(chain.outputs[q as usize].1));
        }
        assert!(alice.found.is_empty(), "the open lane is invisible to lookup");
        let triples: Vec<_> = chain.outputs.iter().enumerate().map(|(i, (t, r))| (i as u64, *t, r.kem)).collect();
        alice.scan_open_lane(&triples, |q| Some(chain.outputs[q as usize].1));
        assert_eq!(alice.found.len(), 1);
        assert_eq!(alice.found[0].position, 123);
        assert_eq!(alice.found[0].value(), 9_999);
        assert_eq!(alice.stats.open_lane_trials, 300);
        eve.scan_open_lane(&triples, |q| Some(chain.outputs[q as usize].1));
        assert!(eve.found.is_empty());
    }

    /// Intro tokens: the payer's first contact is found from the deposited kem alone.
    #[test]
    fn intro_first_contact_is_found_from_the_deposit() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut chain = Chain::new();
        let mut alice = TaggedWallet::new(sk(6), 2).unwrap();
        let ek = alice.keys().intro_public(7);
        let (kem, k) = channel::intro_contact(&ek, &mut rng).unwrap();
        for _ in 0..50 {
            chain.noise(&mut rng);
        }
        chain.put(&ChannelOutput::intro(alice.static_address(), 500, kem, k), &mut rng);
        alice.watch_intro(7, &kem).unwrap();
        for b in &chain.column(16) {
            alice.scan_block(b, |q| Some(chain.outputs[q as usize].1));
        }
        assert_eq!(alice.found.len(), 1);
        assert_eq!(alice.found[0].kind, Kind::Intro);
    }

    /// Build a wallet history: `n_tx` self-channel transactions, `n_req` requests paid
    /// `pays_per_req` times, spends marked on the chain; then restore from the seed alone.
    pub(crate) fn history(n_tx: u32, n_req: u32, pays_per_req: u32, noise_per_tx: usize, seed: u64) -> (Chain, [u8; 32], u64, usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut chain = Chain::new();
        let key = sk(9);
        let mut w = TaggedWallet::new(key, 3).unwrap();
        let reqs: Vec<PaymentRequest> = (0..n_req).map(|_| w.issue_request(0)).collect();
        let mut req_ctr = vec![0u32; n_req as usize];
        let mut pending_req = 0usize;
        for t in 0..n_tx {
            for _ in 0..noise_per_tx {
                chain.noise(&mut rng);
            }
            // Every 4th tx is an incoming request payment, the rest are sends with change.
            if t % 4 == 0 && n_req > 0 {
                let r = pending_req % n_req as usize;
                if req_ctr[r] < pays_per_req {
                    let o = pay_request(&reqs[r], 10_000 + t as u64, req_ctr[r], &mut rng);
                    req_ctr[r] += 1;
                    let p = chain.put(&o, &mut rng);
                    let rec = chain.outputs[p as usize].1;
                    w.accept(&o.tag, p, &rec);
                }
                pending_req += 1;
                continue;
            }
            // Spend the largest unspent note, keep 90% as change.
            let Some(i) = (0..w.found.len()).filter(|&i| !w.found[i].spent).max_by_key(|&i| w.found[i].value()) else {
                // Nothing to spend yet: an incoming self top-up (e.g. a consolidation from another device).
                let o = w.change_output(50_000, &[], t, &mut rng);
                let p = chain.put(&o, &mut rng);
                let rec = chain.outputs[p as usize].1;
                w.accept(&o.tag, p, &rec);
                continue;
            };
            let nf = w.found[i].nullifier;
            let v = w.found[i].value();
            let o = w.change_output(v - v / 10, &[nf], t, &mut rng);
            chain.spent.insert(nf);
            w.mark_spent(&[nf]);
            let p = chain.put(&o, &mut rng);
            let rec = chain.outputs[p as usize].1;
            w.accept(&o.tag, p, &rec);
        }
        let unspent = w.found.iter().filter(|f| !f.spent).count();
        (chain, key, w.balance(), unspent)
    }

    #[test]
    fn restore_from_seed_finds_every_unspent_note_without_a_birthday() {
        let (chain, key, balance, unspent) = history(400, 20, 3, 3, 11);
        let mut idx = Index::new(&chain);
        let (_, rep) = restore(key, &mut idx, 5, 3).unwrap();
        assert!(rep.newest_self_ctr.is_some());
        assert_eq!(rep.balance, balance, "the restored balance equals the wallet's");
        assert_eq!(rep.unspent, unspent);
        assert!(rep.complete, "n_unspent from the ledger is satisfied: {rep:?}");
        // Birthday-free and O(own): the queries depend on the wallet's history, not the chain size.
        let (q1, r1) = (idx.queries, idx.rounds);
        let (chain2, key2, _, _) = history(400, 20, 3, 30, 11);
        let mut idx2 = Index::new(&chain2);
        restore(key2, &mut idx2, 5, 3).unwrap();
        assert_eq!((idx2.queries, idx2.rounds), (q1, r1), "10x more foreign outputs cost no extra query");
        assert!(chain2.outputs.len() > 5 * chain.outputs.len());
    }

    /// The restore of a different seed over the same chain finds nothing.
    #[test]
    fn restore_of_a_stranger_finds_nothing() {
        let (chain, _, _, _) = history(100, 5, 2, 3, 12);
        let mut idx = Index::new(&chain);
        let (_, rep) = restore(sk(77), &mut idx, 5, 3).unwrap();
        assert_eq!(rep.notes_found, 0);
        assert_eq!(rep.newest_self_ctr, None);
    }
}

/// What the tag log and a lookup service learn (task C3 §6). Each test states one property.
#[cfg(test)]
mod privacy {
    use super::tests_support::*;
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use rand_core::Rng;

    /// Bit-level uniformity of a tag population: every bit position within 5 sigma of 1/2, and the
    /// first two bytes (the open lane's DTAG slot) uniform too. A distinguisher that cannot tell a
    /// wallet's tags from random cannot link them.
    fn assert_uniform(tags: &[[u8; TAG_LEN]], what: &str) {
        let n = tags.len() as f64;
        for bit in 0..128 {
            let ones = tags.iter().filter(|t| t[bit / 8] >> (bit % 8) & 1 == 1).count() as f64;
            let z = (ones - n / 2.0) / (n / 4.0).sqrt();
            assert!(z.abs() < 5.0, "{what}: bit {bit} biased (z = {z:.1})");
        }
    }

    /// Unlinkability across channels: the tags one wallet receives on 200 different channels (50
    /// requests, the self channel, intro tokens) are indistinguishable from random tags, and share
    /// no prefix structure that would let an observer group them.
    #[test]
    fn one_wallets_tags_across_channels_look_random() {
        let keys = ChannelKeys::from_spending_key(&[3u8; 32]);
        let mut tags = Vec::new();
        for i in 0..200u32 {
            for c in 0..20u32 {
                tags.push(channel::tag(&keys.k_req(i), c));
            }
        }
        for c in 0..4000u32 {
            tags.push(channel::tag(&keys.k_self(), c));
        }
        assert_uniform(&tags, "one wallet, many channels");
        // No 4-byte prefix repeats more than chance allows (8,000 tags in 2^32 prefixes).
        let mut seen = std::collections::HashSet::new();
        let dup = tags.iter().filter(|t| !seen.insert([t[0], t[1], t[2], t[3]])).count();
        assert!(dup <= 2, "prefix collisions {dup}");
        // The open-lane DTAG slot is random, so open-lane outputs do not stand out either.
        let mut rng = StdRng::seed_from_u64(8);
        let w = TaggedWallet::new(sk(4), 2).unwrap();
        let open: Vec<_> = (0..4000).map(|_| ChannelOutput::open_lane(w.static_address(), 1, &mut rng).unwrap().tag).collect();
        assert_uniform(&open, "open lane");
    }

    /// On chain the four kinds of output are byte-for-byte the same shape: a 16-byte tag, a
    /// canonical non-identity kem point, a 64-byte ciphertext. Nothing marks a channel payment,
    /// a change output, a first contact or an open-lane payment.
    #[test]
    fn output_kinds_are_indistinguishable_in_shape() {
        use group::{Group, GroupEncoding};
        let mut rng = StdRng::seed_from_u64(9);
        let mut w = TaggedWallet::new(sk(5), 2).unwrap();
        let req = w.issue_request(0);
        let (kem_i, k_i) = channel::intro_contact(&w.keys().intro_public(0), &mut rng).unwrap();
        let outs = [
            pay_request(&req, 5, 0, &mut rng),
            w.change_output(5, &[], 0, &mut rng),
            ChannelOutput::intro(w.static_address(), 5, kem_i, k_i),
            ChannelOutput::open_lane(w.static_address(), 5, &mut rng).unwrap(),
        ];
        for o in &outs {
            let p = Option::<pasta_curves::pallas::Point>::from(pasta_curves::pallas::Point::from_bytes(&o.kem)).expect("canonical");
            assert!(!bool::from(p.is_identity()));
            assert_eq!(o.ciphertext().len(), channel::CT_LEN);
        }
    }

    /// What a payer learns: its own channel's future tags (so it can find its own later
    /// payments — the same knowledge it has as their author), and nothing about any other channel
    /// of the same receiver: knowing `K_req[0]` gives no tag of `K_req[1]` or of the self channel.
    #[test]
    fn a_payer_learns_its_channel_and_nothing_else() {
        let (chain, key, _, _) = history(200, 10, 3, 2, 21);
        let keys = ChannelKeys::from_spending_key(&key);
        let my_k = keys.k_req(0);
        let mine: std::collections::HashSet<_> = (0..64).map(|c| channel::tag(&my_k, c)).collect();
        let others: std::collections::HashSet<_> =
            (1..10).flat_map(|i| (0..8).map(move |c| (i, c))).map(|(i, c)| channel::tag(&keys.k_req(i), c)).chain((0..200).map(|c| channel::tag(&keys.k_self(), c))).collect();
        let on_chain: Vec<_> = chain.outputs.iter().map(|(t, _)| *t).collect();
        let found_by_payer = on_chain.iter().filter(|t| mine.contains(*t)).count();
        let others_on_chain = on_chain.iter().filter(|t| others.contains(*t)).count();
        assert!(found_by_payer > 0 && others_on_chain > 0);
        // The payer's view: only its own tags match its candidate set.
        assert!(on_chain.iter().filter(|t| mine.contains(*t)).all(|t| !others.contains(t)));
    }

    /// The intro service holds `ek_int[i]` and the payer's deposited `kem`. Neither the natural
    /// guesses from what it holds (`H(ek)`-style first-contact tags, a KDF of `ek ‖ kem`) nor any
    /// tag under a key derived from public values equals the on-chain tag: computing `K` needs
    /// `sk_int` or `r`. So the service can link "a payment attempt to address X at time t" but
    /// not the transaction.
    #[test]
    fn the_intro_service_cannot_find_the_transaction() {
        let mut rng = StdRng::seed_from_u64(10);
        let keys = ChannelKeys::from_spending_key(&[6u8; 32]);
        let ek = keys.intro_public(3);
        let (kem, k) = channel::intro_contact(&ek, &mut rng).unwrap();
        let on_chain = channel::tag(&k, 0);
        let guesses = [
            channel::tag(&ek, 0),
            channel::tag(&kem, 0),
            channel::tag(&blake2b_simd::blake2b(&[ek, kem].concat()).as_bytes()[..32].try_into().unwrap(), 0),
        ];
        assert!(guesses.iter().all(|g| *g != on_chain));
        assert_eq!(keys.intro_k(3, &kem), Some(k), "while the receiver recovers K from the deposit");
    }

    /// What a non-private lookup server learns (the reason P-mode needs PIR and T-mode downloads
    /// everything): every query names a tag, and every answer names a position, so a plain
    /// tag-index server serving a restore learns exactly the wallet's outputs — all of them, and
    /// that they belong together. This test makes that leak explicit: the set of positions the
    /// server answered equals the wallet's own outputs.
    #[test]
    fn a_plain_lookup_server_learns_the_wallets_outputs() {
        let (chain, key, _, _) = history(120, 6, 2, 5, 22);
        let mut idx = Index::new(&chain);
        let (w, _) = restore(key, &mut idx, 5, 3).unwrap();
        let answered: std::collections::BTreeSet<u64> = w.found.iter().map(|f| f.position).collect();
        assert!(!answered.is_empty());
        // The server's view (queries -> answers) reconstructs this set exactly.
        let mut server_view = std::collections::BTreeSet::new();
        for f in &w.found {
            server_view.extend(idx.by_tag[&chain.outputs[f.position as usize].0].iter().copied());
        }
        assert_eq!(server_view, answered, "without PIR the lookup server links the wallet's whole note set");
        // In T-mode the client asks nothing per tag: it downloads the column, so the server's view is
        // the same for every client.
    }

    /// A mode-S payment request is a bearer secret: anyone who sees it finds the payment and reads
    /// its value (01 §3.10, the "new leak" row). Requests must travel privately.
    #[test]
    fn whoever_sees_a_mode_s_request_finds_the_payment() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut chain = Chain::new();
        let mut bob = TaggedWallet::new(sk(7), 2).unwrap();
        let req = bob.issue_request(0);
        for _ in 0..30 {
            chain.noise(&mut rng);
        }
        let p = chain.put(&pay_request(&req, 4242, 0, &mut rng), &mut rng);
        let seen = PaymentRequest::from_bytes(&req.to_bytes()).unwrap();
        let hit = chain.outputs.iter().position(|(t, _)| *t == channel::tag(&seen.k, 0)).unwrap() as u64;
        assert_eq!(hit, p);
        let pt = channel::open_compact(&seen.k, 0, &chain.outputs[p as usize].1.ct).unwrap();
        assert_eq!(pt.value, 4242);
        let _ = rng.next_u32();
    }
}
