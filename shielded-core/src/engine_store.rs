//! Persistence for the multi-wallet scan engine (walletd-scale task E2, phase 2; design in
//! `02-multitenant-engine.md` §7, results in `09-engine-phase2.md`).
//!
//! One directory holds the chain ONCE for every wallet, append-only, plus one small file per
//! wallet:
//!
//! | file | content | write pattern |
//! |---|---|---|
//! | `chain.ccs` | every ingested chain block as the engine saw it (coinbase notes with their commitment, accepted transactions' compact records, dating metadata), framed and checksummed | append |
//! | `blocks.idx` | per block: hash, blue score, DAA score, tree size after it, offset in `chain.ccs` (64 B) | append |
//! | `leaves.bin` | the commitment stream from the chain base, 32 B per leaf | append |
//! | `nfs.bin` | every applied nullifier, chain order, 32 B each | append |
//! | `journal.bin` | the hit journal: every [`FoldRecord`] the engine folded, with its block sequence and wallet key, framed and checksummed | append |
//! | `committed` | the lengths of all of the above, the last block, and the tip frontier, checksummed | tmp + fsync + rename + dir fsync |
//! | `wallets/<name>.w2` | one wallet's private state, the block it is consistent through and the journal offset it has folded through | tmp + fsync + rename + dir fsync, only when it changed |
//!
//! **Invariant.** `committed` is written only after every append it describes is fsync'd, and
//! a wallet file never claims a block or journal offset past `committed`. Opening the store
//! truncates every append file back to its committed length (whatever lies beyond is a page
//! that was never committed) and refuses to open if a file is SHORTER than committed (data
//! that was acknowledged is gone: fail closed, never guess). A crash at any point therefore
//! loses at most the page in flight, which the follower fetches again; wallet files fold the
//! journal from their own offset, so a wallet file older than the journal is caught up, never
//! wrong.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use orchard::note::ExtractedNoteCommitment;

use crate::coinbase::CoinbaseNoteDesc;
use crate::engine::{FoldRecord, PageFolds, RecMeta, RecvNote, SHARED_CHAIN_SEED, ScanEngine, SharedBlock, SharedChain, WalletLite, WalletState};
use crate::tree::FrontierState;
use crate::wallet::scan::CompactActionRecord;
use crate::walletdb::{BlockMeta, WalletDb, decode_history, decode_notes, decode_pending, encode_history, encode_notes, encode_pending};

const COMMITTED_MAGIC: &[u8; 4] = b"ZKEC";
const COMMITTED_VERSION: u8 = 1;
const W2_MAGIC: &[u8; 4] = b"ZKW2";
const W2_VERSION: u8 = 1;
/// Bytes per `blocks.idx` entry.
pub const IDX_ENTRY: u64 = 64;

fn h8(parts: &[&[u8]]) -> [u8; 8] {
    let mut st = blake2b_simd::Params::new().hash_length(8).personal(b"zkas-engine-rec1").to_state();
    for p in parts {
        st.update(p);
    }
    st.finalize().as_bytes().try_into().expect("8 bytes")
}

fn h32(parts: &[&[u8]]) -> [u8; 32] {
    let mut st = blake2b_simd::Params::new().hash_length(32).personal(b"zkas-engine-cmt1").to_state();
    for p in parts {
        st.update(p);
    }
    st.finalize().as_bytes().try_into().expect("32 bytes")
}

/// A wallet's stable 16-byte engine name, from the host's own identifier (a token): the
/// journal key and `.w2` file stem. A keyed hash, so no file carries the identifier itself.
pub fn wallet_key16(id: &[u8]) -> [u8; 16] {
    let h = blake2b_simd::Params::new().hash_length(16).personal(b"zkas-engine-wkey").hash(id);
    h.as_bytes().try_into().expect("16 bytes")
}

/// Write `bytes` to `path` atomically and durably: a unique tmp file in the same directory,
/// fsync, rename over `path`, fsync the directory. A crash leaves either the old file or the
/// new one, never a torn one (a stray `.tmp` is ignored by every reader).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension(format!("{}.{}.tmp", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let r = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

// ---------------------------------------------------------------------------------------
// Byte codecs
// ---------------------------------------------------------------------------------------

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let e = self.p.checked_add(n)?;
        let s = self.b.get(self.p..e)?;
        self.p = e;
        Some(s)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
    fn done(&self) -> bool {
        self.p == self.b.len()
    }
    fn left(&self) -> usize {
        self.b.len() - self.p
    }
}

fn put_meta(o: &mut Vec<u8>, m: &Option<RecMeta>) {
    match m {
        None => o.push(0),
        Some(m) => {
            o.push(1);
            o.extend_from_slice(&m.txid);
            o.extend_from_slice(&m.daa_score.to_le_bytes());
            o.extend_from_slice(&m.timestamp_ms.to_le_bytes());
        }
    }
}

fn get_meta(r: &mut Rd<'_>) -> Option<Option<RecMeta>> {
    match r.u8()? {
        0 => Some(None),
        1 => Some(Some(RecMeta { txid: r.arr()?, daa_score: r.u64()?, timestamp_ms: r.u64()? })),
        _ => None,
    }
}

/// A fold record's bytes (journal payload).
pub fn encode_record(rec: &FoldRecord) -> Vec<u8> {
    let mut o = Vec::new();
    match rec {
        FoldRecord::Clock { daa } => {
            o.push(0);
            o.extend_from_slice(&daa.to_le_bytes());
        }
        FoldRecord::Coinbase { position, recipient, rho, rseed, value, meta, seen } => {
            o.push(1);
            o.extend_from_slice(&position.to_le_bytes());
            o.extend_from_slice(recipient);
            o.extend_from_slice(rho);
            o.extend_from_slice(rseed);
            o.extend_from_slice(&value.to_le_bytes());
            put_meta(&mut o, meta);
            o.push(*seen as u8);
        }
        FoldRecord::Tx { meta, nullifiers, positions, received } => {
            o.push(2);
            put_meta(&mut o, meta);
            o.extend_from_slice(&(nullifiers.len() as u32).to_le_bytes());
            for (nf, p) in nullifiers.iter().zip(positions) {
                o.extend_from_slice(nf);
                match p {
                    None => o.push(0),
                    Some(p) => {
                        o.push(1);
                        o.extend_from_slice(&p.to_le_bytes());
                    }
                }
            }
            o.extend_from_slice(&(received.len() as u32).to_le_bytes());
            for r in received {
                o.extend_from_slice(&r.action_index.to_le_bytes());
                o.extend_from_slice(&r.recipient);
                o.extend_from_slice(&r.value.to_le_bytes());
                o.extend_from_slice(&r.rho);
                o.extend_from_slice(&r.rseed);
                let ml = r.memo.len().min(u16::MAX as usize);
                o.extend_from_slice(&(ml as u16).to_le_bytes());
                o.extend_from_slice(&r.memo[..ml]);
                o.push(r.seen as u8);
            }
        }
    }
    o
}

pub fn decode_record(b: &[u8]) -> Option<FoldRecord> {
    let mut r = Rd::new(b);
    let rec = match r.u8()? {
        0 => FoldRecord::Clock { daa: r.u64()? },
        1 => FoldRecord::Coinbase {
            position: r.u64()?,
            recipient: r.arr()?,
            rho: r.arr()?,
            rseed: r.arr()?,
            value: r.u64()?,
            meta: get_meta(&mut r)?,
            seen: r.u8()? != 0,
        },
        2 => {
            let meta = get_meta(&mut r)?;
            let n = r.u32()? as usize;
            if n > r.left() / 33 {
                return None;
            }
            let (mut nullifiers, mut positions) = (Vec::with_capacity(n), Vec::with_capacity(n));
            for _ in 0..n {
                nullifiers.push(r.arr()?);
                positions.push(match r.u8()? {
                    0 => None,
                    1 => Some(r.u64()?),
                    _ => return None,
                });
            }
            let m = r.u32()? as usize;
            // action index 2 + recipient 43 + value 8 + rho 32 + rseed 32 + memo length 2 + seen 1.
            if m > r.left() / 120 {
                return None;
            }
            let mut received = Vec::with_capacity(m);
            for _ in 0..m {
                let action_index = r.u16()?;
                let recipient = r.arr()?;
                let value = r.u64()?;
                let rho = r.arr()?;
                let rseed = r.arr()?;
                let ml = r.u16()? as usize;
                let memo = r.take(ml)?.to_vec();
                let seen = r.u8()? != 0;
                received.push(RecvNote { action_index, recipient, value, rho, rseed, memo, seen });
            }
            FoldRecord::Tx { meta, nullifiers, positions, received }
        }
        _ => return None,
    };
    r.done().then_some(rec)
}

fn put_action(o: &mut Vec<u8>, a: &CompactActionRecord) {
    o.extend_from_slice(&a.nullifier);
    o.extend_from_slice(&a.cmx);
    o.extend_from_slice(&a.ephemeral_key);
    o.extend_from_slice(&a.enc_ciphertext);
}

/// One chain block's bytes (the `chain.ccs` payload). Coinbase commitments are stored as the
/// engine verified them, so a replay never re-derives a NoteCommit.
pub fn encode_block(b: &SharedBlock) -> Vec<u8> {
    let n_act: usize = b.txs.iter().map(|t| t.len()).sum();
    let mut o = Vec::with_capacity(96 + b.coinbase.len() * 147 + b.txs.len() * 40 + n_act * 148);
    o.extend_from_slice(&b.hash);
    o.extend_from_slice(&b.blue_score.to_le_bytes());
    o.extend_from_slice(&b.daa_score.to_le_bytes());
    match &b.meta {
        None => o.push(0),
        Some(m) => {
            o.push(1);
            o.extend_from_slice(&m.coinbase_txid);
            o.extend_from_slice(&m.timestamp_ms.to_le_bytes());
            o.extend_from_slice(&m.daa_score.to_le_bytes());
            o.extend_from_slice(&(m.txids.len() as u32).to_le_bytes());
            for t in &m.txids {
                o.extend_from_slice(t);
            }
        }
    }
    o.extend_from_slice(&(b.coinbase.len() as u32).to_le_bytes());
    for (d, v, cmx) in &b.coinbase {
        o.extend_from_slice(&d.recipient);
        o.extend_from_slice(&d.rho);
        o.extend_from_slice(&d.rseed);
        o.extend_from_slice(&v.to_le_bytes());
        o.extend_from_slice(&cmx.to_bytes());
    }
    o.extend_from_slice(&(b.txs.len() as u32).to_le_bytes());
    for t in &b.txs {
        o.extend_from_slice(&(t.len() as u32).to_le_bytes());
        for a in t {
            put_action(&mut o, a);
        }
    }
    o
}

pub fn decode_block(buf: &[u8]) -> Option<SharedBlock> {
    let mut r = Rd::new(buf);
    let hash = r.arr()?;
    let blue_score = r.u64()?;
    let daa_score = r.u64()?;
    let meta = match r.u8()? {
        0 => None,
        1 => {
            let coinbase_txid = r.arr()?;
            let timestamp_ms = r.u64()?;
            let mdaa = r.u64()?;
            let n = r.u32()? as usize;
            if n > r.left() / 32 {
                return None;
            }
            let mut txids = Vec::with_capacity(n);
            for _ in 0..n {
                txids.push(r.arr()?);
            }
            Some(BlockMeta { coinbase_txid, txids, timestamp_ms, daa_score: mdaa })
        }
        _ => return None,
    };
    let nc = r.u32()? as usize;
    if nc > r.left() / 147 {
        return None;
    }
    let mut coinbase = Vec::with_capacity(nc);
    for _ in 0..nc {
        let desc = CoinbaseNoteDesc { recipient: r.arr()?, rho: r.arr()?, rseed: r.arr()? };
        let v = r.u64()?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&r.arr()?))?;
        coinbase.push((desc, v, cmx));
    }
    let nt = r.u32()? as usize;
    if nt > r.left() / 4 {
        return None;
    }
    let mut txs = Vec::with_capacity(nt);
    for _ in 0..nt {
        let na = r.u32()? as usize;
        if na > r.left() / 148 {
            return None;
        }
        let mut t = Vec::with_capacity(na);
        for _ in 0..na {
            t.push(CompactActionRecord { nullifier: r.arr()?, cmx: r.arr()?, ephemeral_key: r.arr()?, enc_ciphertext: r.arr()? });
        }
        txs.push(t);
    }
    r.done().then_some(SharedBlock { hash, blue_score, daa_score, coinbase, txs, meta })
}

/// `[len:u32][payload][h8(payload)]`.
fn frame(payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&h8(&[payload]));
}

/// Read one frame from a reader; `Ok(None)` at a clean end.
fn read_frame(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(len) as usize;
    let mut p = vec![0u8; n];
    r.read_exact(&mut p)?;
    let mut h = [0u8; 8];
    r.read_exact(&mut h)?;
    if h != h8(&[&p]) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame checksum mismatch"));
    }
    Ok(Some(p))
}

fn put_frontier(o: &mut Vec<u8>, f: &FrontierState) {
    o.extend_from_slice(&f.size.to_le_bytes());
    match &f.leaf {
        None => o.push(0),
        Some(l) => {
            o.push(1);
            o.extend_from_slice(l);
        }
    }
    o.extend_from_slice(&(f.ommers.len() as u32).to_le_bytes());
    for x in &f.ommers {
        o.extend_from_slice(x);
    }
}

fn get_frontier(r: &mut Rd<'_>) -> Option<FrontierState> {
    let size = r.u64()?;
    let leaf = match r.u8()? {
        0 => None,
        1 => Some(r.arr()?),
        _ => return None,
    };
    let n = r.u32()? as usize;
    if n > 32 {
        return None;
    }
    let mut ommers = Vec::with_capacity(n);
    for _ in 0..n {
        ommers.push(r.arr()?);
    }
    Some(FrontierState { size, leaf, ommers })
}

// ---------------------------------------------------------------------------------------
// The committed record
// ---------------------------------------------------------------------------------------

/// What `committed` says: how far every append file is valid, and where the chain is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub genesis: [u8; 32],
    /// Blocks ingested since the chain base (= the last block's sequence number).
    pub seq: u64,
    pub chain_len: u64,
    pub leaves: u64,
    pub nfs: u64,
    pub journal_len: u64,
    pub journal_records: u64,
    pub last_hash: [u8; 32],
    pub last_daa: u64,
    pub last_blue: u64,
    pub tip: FrontierState,
    /// Whether `chain.ccs` (the compact block archive) is kept. Fixed when the store is
    /// created: an archive with a hole cannot serve a replay, so it can never be switched on
    /// later (or off).
    pub archive: bool,
}

impl Committed {
    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(COMMITTED_MAGIC);
        o.push(COMMITTED_VERSION);
        o.extend_from_slice(&self.genesis);
        for v in [self.seq, self.chain_len, self.leaves, self.nfs, self.journal_len, self.journal_records] {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o.extend_from_slice(&self.last_hash);
        o.extend_from_slice(&self.last_daa.to_le_bytes());
        o.extend_from_slice(&self.last_blue.to_le_bytes());
        put_frontier(&mut o, &self.tip);
        o.push(self.archive as u8);
        let h = h32(&[&o]);
        o.extend_from_slice(&h);
        o
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 32 + 5 {
            return None;
        }
        let (body, h) = b.split_at(b.len() - 32);
        if h != h32(&[body]) {
            return None;
        }
        let mut r = Rd::new(body);
        if r.take(4)? != COMMITTED_MAGIC || r.u8()? != COMMITTED_VERSION {
            return None;
        }
        let c = Self {
            genesis: r.arr()?,
            seq: r.u64()?,
            chain_len: r.u64()?,
            leaves: r.u64()?,
            nfs: r.u64()?,
            journal_len: r.u64()?,
            journal_records: r.u64()?,
            last_hash: r.arr()?,
            last_daa: r.u64()?,
            last_blue: r.u64()?,
            tip: get_frontier(&mut r)?,
            archive: match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            },
        };
        r.done().then_some(c)
    }
}

/// Where a commit stops early, for crash tests: the process "dies" right after this step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFault {
    None,
    AfterChain,
    AfterIdx,
    AfterLeaves,
    AfterNfs,
    AfterJournal,
    /// Everything appended and fsync'd, `committed` not yet replaced.
    BeforeCommitted,
}

/// One entry of `blocks.idx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdxEntry {
    pub hash: [u8; 32],
    pub blue: u64,
    pub daa: u64,
    /// Tree size after the block.
    pub size_after: u64,
    pub chain_off: u64,
}

impl IdxEntry {
    fn encode(&self) -> [u8; IDX_ENTRY as usize] {
        let mut o = [0u8; IDX_ENTRY as usize];
        o[..32].copy_from_slice(&self.hash);
        o[32..40].copy_from_slice(&self.blue.to_le_bytes());
        o[40..48].copy_from_slice(&self.daa.to_le_bytes());
        o[48..56].copy_from_slice(&self.size_after.to_le_bytes());
        o[56..64].copy_from_slice(&self.chain_off.to_le_bytes());
        o
    }
    fn decode(b: &[u8]) -> Self {
        let u = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8"));
        Self { hash: b[..32].try_into().expect("32"), blue: u(32), daa: u(40), size_after: u(48), chain_off: u(56) }
    }
}

/// The open store: the append files, the committed record, and the shared chain rebuilt
/// from them.
pub struct ChainStore {
    dir: PathBuf,
    chain: File,
    idx: File,
    leaves: File,
    nfs: File,
    journal: File,
    committed: Committed,
}

fn open_append(p: &Path) -> std::io::Result<File> {
    let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Bring an append file to exactly `want` bytes: cut an uncommitted tail, refuse a loss.
fn settle(f: &File, want: u64, name: &str) -> Result<(), String> {
    let have = f.metadata().map_err(|e| format!("{name}: {e}"))?.len();
    if have < want {
        return Err(format!("{name}: {have} bytes on disk but {want} committed — committed data is missing; refusing to open"));
    }
    if have > want {
        f.set_len(want).map_err(|e| format!("{name}: truncate: {e}"))?;
        f.sync_all().map_err(|e| format!("{name}: fsync: {e}"))?;
    }
    Ok(())
}

impl ChainStore {
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn committed(&self) -> &Committed {
        &self.committed
    }

    /// Open (or create) the store in `dir` and rebuild the shared chain from it. A new store
    /// starts at the empty tree (genesis). Returns the store and the chain.
    pub fn open(dir: &Path, genesis: [u8; 32]) -> Result<(Self, SharedChain), String> {
        Self::open_with(dir, genesis, true)
    }

    /// [`Self::open`]; `archive` says whether a NEW store keeps the compact block archive
    /// (`chain.ccs`, ~20 MB per chain-day). An existing store keeps what it was created with;
    /// asking for the other answer is refused.
    pub fn open_with(dir: &Path, genesis: [u8; 32], archive: bool) -> Result<(Self, SharedChain), String> {
        std::fs::create_dir_all(dir.join("wallets")).map_err(|e| format!("mkdir: {e}"))?;
        let f = |n: &str| open_append(&dir.join(n)).map_err(|e| format!("{n}: {e}"));
        let (chain, idx, leaves, nfs, journal) = (f("chain.ccs")?, f("blocks.idx")?, f("leaves.bin")?, f("nfs.bin")?, f("journal.bin")?);
        let committed = match std::fs::read(dir.join("committed")) {
            Ok(b) => Committed::decode(&b).ok_or("committed: corrupt or wrong version; refusing to open")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A new store: every append file must be empty (bytes without a committed record
                // were never committed), and the empty record is written at once so the
                // creation-time choices are durable.
                for (f, n) in [(&chain, "chain.ccs"), (&idx, "blocks.idx"), (&leaves, "leaves.bin"), (&nfs, "nfs.bin"), (&journal, "journal.bin")] {
                    settle(f, 0, n)?;
                }
                let c = Committed {
                genesis,
                seq: 0,
                chain_len: 0,
                leaves: 0,
                nfs: 0,
                journal_len: 0,
                journal_records: 0,
                last_hash: genesis,
                last_daa: 0,
                last_blue: 0,
                tip: FrontierState { size: 0, leaf: None, ommers: Vec::new() },
                archive,
                };
                write_atomic(&dir.join("committed"), &c.encode()).map_err(|e| format!("committed: {e}"))?;
                c
            }
            Err(e) => return Err(format!("committed: {e}")),
        };
        if committed.archive != archive {
            return Err(format!("store was created with archive={}, asked for archive={archive}", committed.archive));
        }
        if committed.genesis != genesis {
            return Err("store belongs to another chain (genesis mismatch)".into());
        }
        settle(&chain, committed.chain_len, "chain.ccs")?;
        settle(&idx, committed.seq * IDX_ENTRY, "blocks.idx")?;
        settle(&leaves, committed.leaves * 32, "leaves.bin")?;
        settle(&nfs, committed.nfs * 32, "nfs.bin")?;
        settle(&journal, committed.journal_len, "journal.bin")?;
        let read_all = |mut f: &File, n: u64| -> Result<Vec<[u8; 32]>, String> {
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut raw = vec![0u8; (n * 32) as usize];
            f.read_exact(&mut raw).map_err(|e| e.to_string())?;
            Ok(raw.chunks_exact(32).map(|c| c.try_into().expect("32")).collect())
        };
        let lv = read_all(&leaves, committed.leaves)?;
        let nv = read_all(&nfs, committed.nfs)?;
        if committed.tip.size != committed.leaves {
            return Err("committed tip frontier does not describe the leaf count".into());
        }
        let tree = WalletDb::leaves_only_from_parts(SHARED_CHAIN_SEED, &lv, nv, &committed.tip).ok_or("leaves.bin does not end in the committed tip frontier")?;
        let store = Self { dir: dir.to_path_buf(), chain, idx, leaves, nfs, journal, committed };
        Ok((store, SharedChain::from_tree(tree)))
    }

    /// Open a store that another process may be writing, for reading only: nothing is
    /// truncated, created or written, and the shared tree is not rebuilt. Sees exactly the
    /// commit that was current at open (every file is at least that long, or it refuses).
    pub fn open_readonly(dir: &Path, genesis: [u8; 32]) -> Result<Self, String> {
        let committed = Committed::decode(&std::fs::read(dir.join("committed")).map_err(|e| format!("committed: {e}"))?).ok_or("committed: corrupt")?;
        if committed.genesis != genesis {
            return Err("store belongs to another chain (genesis mismatch)".into());
        }
        let ro = |n: &str, want: u64| -> Result<File, String> {
            let f = File::open(dir.join(n)).map_err(|e| format!("{n}: {e}"))?;
            let have = f.metadata().map_err(|e| e.to_string())?.len();
            if have < want {
                return Err(format!("{n}: shorter than committed"));
            }
            Ok(f)
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            chain: ro("chain.ccs", committed.chain_len)?,
            idx: ro("blocks.idx", committed.seq * IDX_ENTRY)?,
            leaves: ro("leaves.bin", committed.leaves * 32)?,
            nfs: ro("nfs.bin", committed.nfs * 32)?,
            journal: ro("journal.bin", committed.journal_len)?,
            committed,
        })
    }

    /// Persist one page the engine has ingested: its blocks, their index, the new leaves,
    /// the applied nullifiers and the fold records, then `committed`. The engine must have
    /// ingested exactly `blocks` since the last commit. On `Err` (or a fault) nothing is
    /// committed and the caller must reopen the store; the engine's RAM is then ahead of disk
    /// and must be discarded too.
    pub fn commit_page(&mut self, blocks: &[SharedBlock], folds: &PageFolds, engine: &ScanEngine, fault: CommitFault) -> Result<(), String> {
        let c = self.committed.clone();
        if engine.seq() != c.seq + blocks.len() as u64 || folds.first_seq != c.seq + 1 {
            return Err(format!("commit out of step: engine at {}, store at {}, page of {}", engine.seq(), c.seq, blocks.len()));
        }
        let io = |e: std::io::Error| e.to_string();
        // chain.ccs + blocks.idx
        if folds.sizes_after.len() != blocks.len() {
            return Err("page folds do not describe the page".into());
        }
        let mut cbuf = Vec::new();
        let mut ibuf = Vec::new();
        for (b, &size_after) in blocks.iter().zip(&folds.sizes_after) {
            let off = if c.archive { c.chain_len + cbuf.len() as u64 } else { 0 };
            frame(&encode_block(b), &mut cbuf);
            ibuf.extend_from_slice(&IdxEntry { hash: b.hash, blue: b.blue_score, daa: b.daa_score, size_after, chain_off: off }.encode());
        }
        let new_leaves = engine.chain().size();
        if folds.sizes_after.last().copied().unwrap_or(c.leaves) != new_leaves {
            return Err("page leaf count disagrees with the shared tree".into());
        }
        let append = |f: &mut File, at: u64, bytes: &[u8]| -> Result<(), String> {
            f.seek(SeekFrom::Start(at)).map_err(io)?;
            f.write_all(bytes).map_err(io)?;
            f.sync_data().map_err(io)
        };
        if !c.archive {
            cbuf.clear();
        }
        append(&mut self.chain, c.chain_len, &cbuf)?;
        if fault == CommitFault::AfterChain {
            return Err("fault: after chain".into());
        }
        append(&mut self.idx, c.seq * IDX_ENTRY, &ibuf)?;
        if fault == CommitFault::AfterIdx {
            return Err("fault: after idx".into());
        }
        let mut lbuf = Vec::with_capacity(((new_leaves - c.leaves) * 32) as usize);
        for p in c.leaves..new_leaves {
            lbuf.extend_from_slice(&engine.chain().tree().leaf_at(p).ok_or("shared tree lost a leaf")?);
        }
        append(&mut self.leaves, c.leaves * 32, &lbuf)?;
        if fault == CommitFault::AfterLeaves {
            return Err("fault: after leaves".into());
        }
        let nbuf: Vec<u8> = folds.applied_nullifiers.iter().flatten().copied().collect();
        append(&mut self.nfs, c.nfs * 32, &nbuf)?;
        if fault == CommitFault::AfterNfs {
            return Err("fault: after nfs".into());
        }
        let mut jbuf = Vec::new();
        for (seq, w, rec) in &folds.records {
            let mut p = Vec::new();
            p.extend_from_slice(&seq.to_le_bytes());
            match w {
                None => p.push(0),
                Some(w) => {
                    p.push(1);
                    p.extend_from_slice(&engine.wallet(*w).key16());
                }
            }
            p.extend_from_slice(&encode_record(rec));
            frame(&p, &mut jbuf);
        }
        append(&mut self.journal, c.journal_len, &jbuf)?;
        if fault == CommitFault::AfterJournal {
            return Err("fault: after journal".into());
        }
        let last = blocks.last();
        let next = Committed {
            genesis: c.genesis,
            seq: engine.seq(),
            chain_len: c.chain_len + cbuf.len() as u64,
            leaves: new_leaves,
            nfs: c.nfs + folds.applied_nullifiers.len() as u64,
            journal_len: c.journal_len + jbuf.len() as u64,
            journal_records: c.journal_records + folds.records.len() as u64,
            last_hash: last.map(|b| b.hash).unwrap_or(c.last_hash),
            last_daa: last.map(|b| b.daa_score).unwrap_or(c.last_daa),
            last_blue: last.map(|b| b.blue_score).unwrap_or(c.last_blue),
            tip: engine.chain().tree().tip_frontier_state().ok_or("shared tree has no valid tip frontier")?,
            archive: c.archive,
        };
        if fault == CommitFault::BeforeCommitted {
            return Err("fault: before committed".into());
        }
        write_atomic(&self.dir.join("committed"), &next.encode()).map_err(io)?;
        self.committed = next;
        Ok(())
    }

    /// The index entry of block `seq` (1-based).
    pub fn idx(&self, seq: u64) -> Result<IdxEntry, String> {
        if seq == 0 || seq > self.committed.seq {
            return Err(format!("block {seq} not in the store"));
        }
        let mut b = [0u8; IDX_ENTRY as usize];
        let mut f = &self.idx;
        f.seek(SeekFrom::Start((seq - 1) * IDX_ENTRY)).map_err(|e| e.to_string())?;
        f.read_exact(&mut b).map_err(|e| e.to_string())?;
        Ok(IdxEntry::decode(&b))
    }

    /// Every index entry, in order (one sequential read).
    pub fn idx_all(&self) -> Result<Vec<IdxEntry>, String> {
        let mut f = &self.idx;
        f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut raw = vec![0u8; (self.committed.seq * IDX_ENTRY) as usize];
        f.read_exact(&mut raw).map_err(|e| e.to_string())?;
        Ok(raw.chunks_exact(IDX_ENTRY as usize).map(IdxEntry::decode).collect())
    }

    /// The sequence of the block with this hash (`Some(0)` = the chain base / genesis).
    pub fn find_seq(&self, hash: &[u8; 32]) -> Result<Option<u64>, String> {
        if *hash == self.committed.genesis {
            return Ok(Some(0));
        }
        let mut r = BufReader::with_capacity(1 << 20, &self.idx);
        r.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut b = [0u8; IDX_ENTRY as usize];
        for seq in 1..=self.committed.seq {
            r.read_exact(&mut b).map_err(|e| e.to_string())?;
            if &b[..32] == hash {
                return Ok(Some(seq));
            }
        }
        Ok(None)
    }

    /// Blocks `from..=to` (1-based sequences) from `chain.ccs`, checksums verified.
    pub fn blocks(&self, from: u64, to: u64) -> Result<Vec<SharedBlock>, String> {
        if !self.committed.archive {
            return Err("this store keeps no block archive (created with archive=false)".into());
        }
        if from == 0 || to > self.committed.seq || from > to {
            return Ok(Vec::new());
        }
        let start = self.idx(from)?.chain_off;
        let mut r = BufReader::with_capacity(1 << 20, &self.chain);
        r.seek(SeekFrom::Start(start)).map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity((to - from + 1) as usize);
        for _ in from..=to {
            let p = read_frame(&mut r).map_err(|e| e.to_string())?.ok_or("chain.ccs ends early")?;
            out.push(decode_block(&p).ok_or("chain.ccs: malformed block")?);
        }
        Ok(out)
    }

    /// Journal records from byte `offset` to the committed end: `(end offset of the record,
    /// block seq, wallet key (None = global), record)`. Checksums verified; fails closed.
    pub fn journal_from(&self, offset: u64) -> Result<Vec<(u64, u64, Option<[u8; 16]>, FoldRecord)>, String> {
        let end = self.committed.journal_len;
        if offset > end {
            return Err("journal offset beyond the committed end".into());
        }
        let mut r = BufReader::with_capacity(1 << 20, &self.journal);
        r.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        let mut pos = offset;
        let mut out = Vec::new();
        while pos < end {
            let p = read_frame(&mut r).map_err(|e| e.to_string())?.ok_or("journal ends early")?;
            pos += 4 + p.len() as u64 + 8;
            let mut rd = Rd::new(&p);
            let seq = rd.u64().ok_or("journal: short record")?;
            let w = match rd.u8().ok_or("journal: short record")? {
                0 => None,
                1 => Some(rd.arr::<16>().ok_or("journal: short record")?),
                _ => return Err("journal: bad wallet tag".into()),
            };
            let rec = decode_record(&p[rd.p..]).ok_or("journal: malformed record")?;
            out.push((pos, seq, w, rec));
        }
        Ok(out)
    }

    /// Fold every journal record after `offset` that concerns wallet `w` (or is global) into
    /// it, in order — dormant-wallet catch-up. Returns (records folded, new offset).
    pub fn catch_up(&self, w: &mut WalletLite, offset: u64) -> Result<(usize, u64), String> {
        let mut n = 0;
        let mut end = offset;
        let key = w.key16();
        let from = w.start_seq();
        for (e, seq, k, rec) in self.journal_from(offset)? {
            end = e;
            if seq <= from {
                continue;
            }
            if k.is_none() || k == Some(key) {
                w.fold(&rec);
                n += 1;
            }
        }
        Ok((n, end))
    }

    /// Path of a wallet's per-wallet file.
    pub fn wallet_path(&self, name: &str) -> PathBuf {
        self.dir.join("wallets").join(format!("{name}.w2"))
    }
}

// ---------------------------------------------------------------------------------------
// Per-wallet file (.w2)
// ---------------------------------------------------------------------------------------

/// What a wallet's `.w2` file holds besides its private state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W2Head {
    pub genesis: [u8; 32],
    pub key16: [u8; 16],
    /// Block sequence the state is consistent through.
    pub seq: u64,
    /// Tree size after that block.
    pub size: u64,
    /// Journal byte offset folded through (records before it are in the state).
    pub journal_off: u64,
    /// The wallet's `blind_below` (0 = complete view), carried over from its checkpoint.
    pub blind_below: u64,
}

pub fn encode_w2(h: &W2Head, s: &WalletState) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(W2_MAGIC);
    o.push(W2_VERSION);
    o.extend_from_slice(&h.genesis);
    o.extend_from_slice(&h.key16);
    for v in [h.seq, h.size, h.journal_off, h.blind_below] {
        o.extend_from_slice(&v.to_le_bytes());
    }
    o.push(s.history_enabled as u8);
    for sec in [encode_notes(&s.notes), encode_history(&s.history), encode_pending(s.last_daa, &s.pending_spends)] {
        o.extend_from_slice(&(sec.len() as u64).to_le_bytes());
        o.extend_from_slice(&sec);
    }
    let h = h32(&[&o]);
    o.extend_from_slice(&h);
    o
}

pub fn decode_w2(b: &[u8]) -> Result<(W2Head, WalletState), String> {
    if b.len() < 32 + 5 {
        return Err("w2: short".into());
    }
    let (body, h) = b.split_at(b.len() - 32);
    if h != h32(&[body]) {
        return Err("w2: checksum mismatch".into());
    }
    let mut r = Rd::new(body);
    if r.take(4) != Some(W2_MAGIC.as_slice()) || r.u8() != Some(W2_VERSION) {
        return Err("w2: magic/version".into());
    }
    let bad = || "w2: malformed".to_string();
    let head = W2Head {
        genesis: r.arr().ok_or_else(bad)?,
        key16: r.arr().ok_or_else(bad)?,
        seq: r.u64().ok_or_else(bad)?,
        size: r.u64().ok_or_else(bad)?,
        journal_off: r.u64().ok_or_else(bad)?,
        blind_below: r.u64().ok_or_else(bad)?,
    };
    let history_enabled = r.u8().ok_or_else(bad)? != 0;
    let mut sec = || -> Result<&[u8], String> {
        let n = r.u64().ok_or_else(bad)? as usize;
        r.take(n).ok_or_else(bad)
    };
    let notes = decode_notes(sec()?).ok_or("w2: notes")?;
    let history = decode_history(sec()?).ok_or("w2: history")?;
    let (last_daa, pending_spends) = decode_pending(sec()?).ok_or("w2: pending")?;
    if !r.done() {
        return Err("w2: trailing bytes".into());
    }
    Ok((head, WalletState { notes, pending_spends, history, history_enabled, last_daa }))
}

#[cfg(test)]
#[path = "engine_store_tests.rs"]
mod tests;
