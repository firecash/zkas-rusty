//! Streamed, sorted, range-split and resumable import of the pruning-point spent-nullifier set
//! (N1; spec 08 R3 as revised by 16 F8).
//!
//! The importer used to append every streamed nullifier to one `Vec<[u8; 32]>`, fold MuHash over it
//! after the stream, and stage the clear plus the whole seed in ONE RocksDB `WriteBatch`; the 2^26
//! count cap (2 GiB of nullifiers) existed only to bound that memory. Once the honest set passes
//! 2^26 every fresh pruned node fails to sync (spec 15 A7: a fee-free miner gets there in ~11 days).
//!
//! Here the set never sits in memory:
//! - the 32-byte key space is split into [`RANGE_COUNT`] fixed ranges by the top nibble of the
//!   first byte. Each range is fetched (from any source that serves ranged streams) and staged on
//!   its own, so up to four sources can stream disjoint ranges at once (R3.4.1), and a range that
//!   a slow or vanished source left half done is resumed from its last staged nullifier;
//! - inside a range every element must be strictly above the previous one and inside the range
//!   (every exporter, old or new, iterates the nullifier store in key order); a violation is caught
//!   at the first bad chunk instead of at the end;
//! - elements are written to RocksDB SST files keyed exactly as the live nullifier store, one file
//!   per [`NULLIFIERS_PER_SST`] elements or per stream, and folded into a MuHash accumulator per
//!   file (in parallel sub-accumulators; MuHash is a multiset hash, so the per-file accumulators
//!   combine to the whole set's);
//! - after each finished file a small manifest (files, counts, last keys, accumulators) is written
//!   atomically, so a killed node resumes the import where its last finished file ended;
//! - the commit replaces the live set with a `DeleteRange` over the store prefix plus an
//!   `IngestExternalFile` of the staged files.
//!
//! Peak memory is one chunk plus one SST writer block buffer per active range, independent of the
//! set size.

use kaspa_database::prelude::DB;
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use parking_lot::Mutex;
use rayon::prelude::*;
use rocksdb::{IngestExternalFileOptions, Options, SstFileWriter};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed key ranges of a staged import (top nibble of the first byte).
pub const RANGE_COUNT: usize = 16;

/// Nullifiers per staged SST file at most (2^20 = 32 MiB of raw keys). A process kill loses at most
/// the file being written per active range.
pub const NULLIFIERS_PER_SST: u64 = 1 << 20;

/// Disk bytes reserved per declared nullifier before an import starts (spec 08 R3.6: 2 x 48 B; the
/// 48 B/nullifier on-disk figure is UNCHECKED, lens 02 range 34-60).
pub const IMPORT_DISK_BYTES_PER_NULLIFIER: u64 = 2 * 48;

const MANIFEST: &str = "manifest.bin";
const MANIFEST_VERSION: u32 = 1;

/// The value the live store keeps for a spent nullifier: `bincode(u8)`, the era tag
/// `DbNullifierSetStore::insert_batch` writes for the current tree era (spec 08 R5.1).
fn marker_value() -> [u8; 1] {
    [crate::model::stores::shielded::nullifier_era_tag(crate::model::stores::shielded::CURRENT_TREE_ERA)]
}

/// The range a nullifier belongs to.
pub fn range_of(nf: &[u8; 32]) -> usize {
    (nf[0] >> 4) as usize
}

/// The smallest key of range `i` (inclusive).
pub fn range_start(i: usize) -> [u8; 32] {
    assert!(i < RANGE_COUNT);
    let mut b = [0u8; 32];
    b[0] = (i as u8) << 4;
    b
}

/// The first key above range `i` (exclusive), `None` for the last range.
pub fn range_end(i: usize) -> Option<[u8; 32]> {
    (i + 1 < RANGE_COUNT).then(|| range_start(i + 1))
}

/// The next 32-byte value in big-endian order, `None` above the maximum.
pub fn successor(nf: &[u8; 32]) -> Option<[u8; 32]> {
    let mut b = *nf;
    for i in (0..32).rev() {
        if b[i] == 0xff {
            b[i] = 0;
        } else {
            b[i] += 1;
            return Some(b);
        }
    }
    None
}

/// Why a chunk or the import was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamImportError {
    /// More nullifiers arrived than the metadata declared.
    Overrun { declared: u64 },
    /// An element is not strictly greater than the one before it (out of order or duplicate).
    NotAscending { index: u64 },
    /// An element lies outside the range the stream was asked for.
    OutOfRange { range: usize },
    /// The range is complete, or another stream is staging it right now.
    RangeUnavailable { range: usize },
    /// A full (unranged) stream needs an empty staging.
    NotFresh,
    /// The local disk cannot hold the staged set.
    InsufficientDisk { needed: u64, available: u64 },
    /// A filesystem or RocksDB failure.
    Io(String),
}

impl std::fmt::Display for StreamImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overrun { declared } => write!(f, "streamed nullifiers exceed the declared count {declared}"),
            Self::NotAscending { index } => {
                write!(f, "streamed nullifier #{index} is not strictly above the previous one (out of order or duplicate)")
            }
            Self::OutOfRange { range } => write!(f, "streamed nullifier outside the requested range {range}"),
            Self::RangeUnavailable { range } => write!(f, "nullifier range {range} is complete or already being staged"),
            Self::NotFresh => write!(f, "a full nullifier stream needs an empty staging"),
            Self::InsufficientDisk { needed, available } => {
                write!(f, "shielded import needs {needed} bytes of free disk for staging, {available} available")
            }
            Self::Io(e) => write!(f, "shielded import staging I/O: {e}"),
        }
    }
}

/// One finished staged file.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileRec {
    name: String,
    count: u64,
    last: [u8; 32],
    acc: MuHash,
}

/// One key range of the staged set.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RangeState {
    files: Vec<FileRec>,
    complete: bool,
    /// A stream is staging this range now (never persisted as true).
    #[serde(skip)]
    busy: bool,
}

impl RangeState {
    fn received(&self) -> u64 {
        self.files.iter().map(|f| f.count).sum()
    }
    fn last(&self) -> Option<[u8; 32]> {
        self.files.last().map(|f| f.last)
    }
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    pruning_point: Hash,
    declared_muhash: [u8; 32],
    declared: u64,
    next_file: u64,
    ranges: Vec<RangeState>,
}

/// Where one range stands: what to ask a source for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeResume {
    pub range: usize,
    /// First key still missing (inclusive); `None` when the range is complete.
    pub from: Option<[u8; 32]>,
    /// First key above the range (exclusive); `None` for the last range.
    pub before: Option<[u8; 32]>,
    pub received: u64,
    pub complete: bool,
}

/// Which part of the key space one `consume` call stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamScope {
    /// The whole set in one ascending stream (an older peer's full export): elements are routed to
    /// their ranges, and a range is complete once the stream moves past it.
    Full,
    /// One range, continuing after its last staged element.
    Range(usize),
}

/// The staged state of one pruning point's nullifier import. Survives an interrupted stream and a
/// process restart, so a later attempt with the same pruning point and the same committed set
/// resumes it.
pub struct NullifierStaging {
    /// Identifies the set: the pruning point and the declared accumulator + count (both bound to
    /// the PoW-committed root by the caller before any chunk is accepted).
    pub pruning_point: Hash,
    pub declared_muhash: [u8; 32],
    pub declared: u64,
    dir: PathBuf,
    state: Mutex<(u64, Vec<RangeState>)>,
    total: AtomicU64,
    prefix: u8,
}

impl NullifierStaging {
    /// Start a staging area in `dir` (created; any leftover content is removed first).
    pub fn new(dir: PathBuf, pruning_point: Hash, declared_muhash: [u8; 32], declared: u64) -> Result<Self, StreamImportError> {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| StreamImportError::Io(format!("clearing {}: {e}", dir.display())))?;
        }
        std::fs::create_dir_all(&dir).map_err(|e| StreamImportError::Io(format!("creating {}: {e}", dir.display())))?;
        let s = Self {
            pruning_point,
            declared_muhash,
            declared,
            dir,
            state: Mutex::new((0, vec![RangeState::default(); RANGE_COUNT])),
            total: AtomicU64::new(0),
            prefix: DatabaseStorePrefixes::ShieldedNullifiers.into(),
        };
        s.write_manifest(&s.state.lock())?;
        Ok(s)
    }

    /// Reopen a staging a previous process left in `dir`. Files that no manifest entry names (a file
    /// the process was writing when it died) are deleted. `None` (and the directory removed) when
    /// there is no usable manifest.
    pub fn load(dir: PathBuf) -> Option<Self> {
        let bytes = std::fs::read(dir.join(MANIFEST)).ok();
        let manifest: Option<Manifest> = bytes.and_then(|b| bincode::deserialize(&b).ok());
        let Some(m) = manifest.filter(|m| m.version == MANIFEST_VERSION && m.ranges.len() == RANGE_COUNT) else {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        };
        let named: std::collections::HashSet<String> = m.ranges.iter().flat_map(|r| r.files.iter().map(|f| f.name.clone())).collect();
        if named.iter().any(|n| !dir.join(n).is_file()) {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name != MANIFEST && !named.contains(&name) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let total = m.ranges.iter().map(|r| r.received()).sum();
        Some(Self {
            pruning_point: m.pruning_point,
            declared_muhash: m.declared_muhash,
            declared: m.declared,
            dir,
            state: Mutex::new((m.next_file, m.ranges)),
            total: AtomicU64::new(total),
            prefix: DatabaseStorePrefixes::ShieldedNullifiers.into(),
        })
    }

    /// Refuse to start when the disk holding `dir` has less than the reserve for `declared`
    /// nullifiers (spec 08 R3.6), with an operator-readable error.
    pub fn check_disk(dir: &Path, declared: u64) -> Result<(), StreamImportError> {
        let needed = declared.saturating_mul(IMPORT_DISK_BYTES_PER_NULLIFIER);
        let probe = dir.ancestors().find(|p| p.exists()).unwrap_or(Path::new("/"));
        match fs_free_bytes(probe) {
            Some(available) if available < needed => Err(StreamImportError::InsufficientDisk { needed, available }),
            _ => Ok(()),
        }
    }

    /// Whether this staging holds (part of) the set identified by these values.
    pub fn matches(&self, pruning_point: Hash, declared_muhash: [u8; 32], declared: u64) -> bool {
        self.pruning_point == pruning_point && self.declared_muhash == declared_muhash && self.declared == declared
    }

    /// Nullifiers staged so far, over all ranges.
    pub fn received(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }

    /// Whether every declared nullifier is staged.
    pub fn is_complete(&self) -> bool {
        self.received() == self.declared
    }

    /// Where every range stands.
    pub fn resume_points(&self) -> Vec<RangeResume> {
        let g = self.state.lock();
        g.1.iter()
            .enumerate()
            .map(|(i, r)| {
                let from = if r.complete {
                    None
                } else {
                    match r.last() {
                        Some(last) => successor(&last).filter(|s| range_end(i).is_none_or(|e| *s < e)),
                        None => Some(range_start(i)),
                    }
                };
                RangeResume { range: i, from, before: range_end(i), received: r.received(), complete: r.complete || from.is_none() }
            })
            .collect()
    }

    /// Mark a range complete: its source signalled the end of the range.
    pub fn complete_range(&self, range: usize) -> Result<(), StreamImportError> {
        let mut g = self.state.lock();
        g.1[range].complete = true;
        self.write_manifest(&g)
    }

    fn write_manifest(&self, g: &(u64, Vec<RangeState>)) -> Result<(), StreamImportError> {
        let m = Manifest {
            version: MANIFEST_VERSION,
            pruning_point: self.pruning_point,
            declared_muhash: self.declared_muhash,
            declared: self.declared,
            next_file: g.0,
            ranges: g.1.clone(),
        };
        let bytes = bincode::serialize(&m).map_err(|e| StreamImportError::Io(format!("encoding the staging manifest: {e}")))?;
        let tmp = self.dir.join(format!("{MANIFEST}.tmp"));
        let io = |e: std::io::Error| StreamImportError::Io(format!("writing the staging manifest: {e}"));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(io)?;
            f.write_all(&bytes).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, self.dir.join(MANIFEST)).map_err(io)?;
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Stage chunks for `scope` until the iterator ends. On a refused chunk nothing of that chunk is
    /// kept and the error is returned (the caller discards the staging: the source has shown it does
    /// not stream the committed set honestly). An iterator that ends early (peer stalled or
    /// disconnected) is not an error: what arrived is staged in finished files, and
    /// [`Self::resume_points`] says where to continue. Returns the number staged by this call.
    pub fn consume<I>(&self, scope: StreamScope, chunks: I) -> Result<u64, StreamImportError>
    where
        I: IntoIterator<Item = Vec<[u8; 32]>>,
    {
        // Claim the range(s).
        let (mut range, mut prev) = {
            let mut g = self.state.lock();
            match scope {
                StreamScope::Full => {
                    if g.1.iter().any(|r| r.busy || r.complete || !r.files.is_empty()) {
                        return Err(StreamImportError::NotFresh);
                    }
                    g.1.iter_mut().for_each(|r| r.busy = true);
                    (0usize, None)
                }
                StreamScope::Range(i) => {
                    let r = &mut g.1[i];
                    if r.busy || r.complete {
                        return Err(StreamImportError::RangeUnavailable { range: i });
                    }
                    r.busy = true;
                    (i, r.last())
                }
            }
        };
        let result = self.consume_claimed(scope, &mut range, &mut prev, chunks);
        let mut g = self.state.lock();
        match scope {
            StreamScope::Full => g.1.iter_mut().for_each(|r| r.busy = false),
            StreamScope::Range(i) => g.1[i].busy = false,
        }
        let _ = self.write_manifest(&g);
        result
    }

    fn consume_claimed<I>(&self, scope: StreamScope, range: &mut usize, prev: &mut Option<[u8; 32]>, chunks: I) -> Result<u64, StreamImportError>
    where
        I: IntoIterator<Item = Vec<[u8; 32]>>,
    {
        let opts = Options::default();
        let mut staged = 0u64;
        let mut file: Option<OpenFile<'_>> = None;
        let mut key = [0u8; 33];
        key[0] = self.prefix;
        let value = marker_value();
        let mut outcome = Ok(());
        'chunks: for chunk in chunks {
            if chunk.is_empty() {
                continue;
            }
            let base = self.received();
            if base + chunk.len() as u64 > self.declared {
                outcome = Err(StreamImportError::Overrun { declared: self.declared });
                break;
            }
            // Validate the whole chunk before writing any of it.
            let mut p = *prev;
            for (k, nf) in chunk.iter().enumerate() {
                if p.is_some_and(|q| *nf <= q) {
                    outcome = Err(StreamImportError::NotAscending { index: base + k as u64 });
                    break 'chunks;
                }
                let nr = range_of(nf);
                match scope {
                    StreamScope::Range(i) if nr != i => {
                        outcome = Err(StreamImportError::OutOfRange { range: i });
                        break 'chunks;
                    }
                    _ => {}
                }
                p = Some(*nf);
            }
            // Write it, segment by segment (a segment ends at a range change or a full file).
            let mut pos = 0usize;
            while pos < chunk.len() {
                let seg_range = range_of(&chunk[pos]);
                if seg_range != *range {
                    // Full stream moved past `range`: finish its file and mark it (and any empty
                    // ranges skipped over) complete.
                    if let Some(f) = file.take() {
                        self.finish_file(*range, f)?;
                    }
                    let mut g = self.state.lock();
                    for done in *range..seg_range {
                        g.1[done].complete = true;
                    }
                    self.write_manifest(&g)?;
                    *range = seg_range;
                }
                if file.is_none() {
                    file = Some(self.open_file(&opts)?);
                }
                let f = file.as_mut().unwrap();
                let room = (NULLIFIERS_PER_SST - f.count) as usize;
                let end = chunk[pos..].iter().position(|nf| range_of(nf) != seg_range).map_or(chunk.len(), |o| pos + o).min(pos + room);
                let seg = &chunk[pos..end];
                for nf in seg {
                    key[1..].copy_from_slice(nf);
                    f.writer.put(key, value).map_err(|e| StreamImportError::Io(format!("writing a staged nullifier: {e}")))?;
                }
                f.acc.combine(&fold(seg));
                f.count += seg.len() as u64;
                f.last = *seg.last().unwrap();
                self.total.fetch_add(seg.len() as u64, Ordering::SeqCst);
                staged += seg.len() as u64;
                pos = end;
                if f.count == NULLIFIERS_PER_SST {
                    let f = file.take().unwrap();
                    self.finish_file(*range, f)?;
                }
            }
            *prev = p;
        }
        if let Some(f) = file.take() {
            self.finish_file(*range, f)?;
        }
        if outcome.is_ok() && scope == StreamScope::Full && self.is_complete() {
            let mut g = self.state.lock();
            g.1.iter_mut().for_each(|r| r.complete = true);
            self.write_manifest(&g)?;
        }
        outcome.map(|_| staged)
    }

    fn open_file<'o>(&self, opts: &'o Options) -> Result<OpenFile<'o>, StreamImportError> {
        let name = {
            let mut g = self.state.lock();
            g.0 += 1;
            format!("nf-{:08}.sst", g.0)
        };
        let path = self.dir.join(&name);
        let writer = SstFileWriter::create(opts);
        writer.open(&path).map_err(|e| StreamImportError::Io(format!("opening {}: {e}", path.display())))?;
        Ok(OpenFile { writer, name, count: 0, last: [0u8; 32], acc: MuHash::new() })
    }

    fn finish_file(&self, range: usize, mut f: OpenFile<'_>) -> Result<(), StreamImportError> {
        if f.count == 0 {
            return Ok(());
        }
        f.writer.finish().map_err(|e| StreamImportError::Io(format!("finishing a staged file: {e}")))?;
        let mut g = self.state.lock();
        g.1[range].files.push(FileRec { name: f.name, count: f.count, last: f.last, acc: f.acc });
        self.write_manifest(&g)
    }

    /// The folded accumulator and element count over every staged file, for the final check
    /// against the committed metadata.
    pub fn folded(&self) -> (u64, MuHash) {
        let g = self.state.lock();
        let mut acc = MuHash::new();
        let mut n = 0u64;
        for f in g.1.iter().flat_map(|r| r.files.iter()) {
            acc.combine(&f.acc);
            n += f.count;
        }
        (n, acc)
    }

    /// The staged files, in key order.
    pub fn files(&self) -> Vec<PathBuf> {
        let g = self.state.lock();
        g.1.iter().flat_map(|r| r.files.iter()).map(|f| self.dir.join(&f.name)).collect()
    }

    /// Replace the live nullifier set with the staged one: ingest the staged files (moved, not
    /// copied, when the staging dir is on the database's filesystem). The caller has already written
    /// a batch that deletes the live set (`DeleteRange` over the store prefix) and lowered the stable
    /// flag; ingested files get a newer sequence number than that tombstone, so their keys are
    /// visible. The caller must clear the store cache afterwards.
    pub fn ingest_into(&self, db: &DB) -> Result<(), StreamImportError> {
        let files = self.files();
        if files.is_empty() {
            return Ok(());
        }
        let mut opts = IngestExternalFileOptions::default();
        opts.set_move_files(true);
        db.ingest_external_file_opts(&opts, files).map_err(|e| StreamImportError::Io(format!("ingesting staged nullifiers: {e}")))
    }

    /// Remove the staging directory (a stream still writing into it fails at its next file).
    pub fn discard(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct OpenFile<'o> {
    writer: SstFileWriter<'o>,
    name: String,
    count: u64,
    last: [u8; 32],
    acc: MuHash,
}

fn fold(nfs: &[[u8; 32]]) -> MuHash {
    nfs.par_chunks(256)
        .map(|part| {
            let mut m = MuHash::new();
            for nf in part {
                m.add_element(nf);
            }
            m
        })
        .reduce(MuHash::new, |mut a, b| {
            a.combine(&b);
            a
        })
}

/// Free bytes on the filesystem holding `path`, `None` if it cannot be determined.
fn fs_free_bytes(path: &Path) -> Option<u64> {
    // `df` is the portable way without a libc dependency here; failing to read it only skips the
    // precheck (the import then fails on the first write instead, with the same state left behind).
    let out = std::process::Command::new("df").arg("-Pk").arg(path).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let line = text.lines().nth(1)?;
    let avail_kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(avail_kib.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    /// A deterministic set spread over the whole key space, sorted.
    fn set(n: u64) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(0x1234_5678);
                let mut b = [0u8; 32];
                for k in 0..4 {
                    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                    x ^= x >> 31;
                    b[8 * k..8 * k + 8].copy_from_slice(&x.to_be_bytes());
                }
                b
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }

    fn chunks(v: &[[u8; 32]], size: usize) -> Vec<Vec<[u8; 32]>> {
        v.chunks(size).map(|c| c.to_vec()).collect()
    }

    fn reference(v: &[[u8; 32]]) -> MuHash {
        let mut m = MuHash::new();
        for nf in v {
            m.add_element(nf);
        }
        m
    }

    fn staging(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("n1-nf-staging-{tag}-{}", std::process::id()))
    }

    fn in_range(v: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
        v.iter().filter(|nf| range_of(nf) == i).copied().collect()
    }

    /// R3.1: no count cap. A declared set above the former 2^26 cap stages like any other (memory
    /// does not depend on the count; only the committed note count bounds it, checked by the caller).
    #[test]
    fn a_declared_count_above_the_former_cap_is_accepted() {
        let v = set(1_000);
        let declared = (1u64 << 26) + 1_000;
        let st = NullifierStaging::new(staging("nocap"), 3.into(), [4u8; 32], declared).unwrap();
        st.consume(StreamScope::Full, chunks(&v, 256)).unwrap();
        assert_eq!(st.received(), 1_000);
        assert!(!st.is_complete());
        st.discard();
    }

    #[test]
    fn range_bounds_partition_the_key_space() {
        assert_eq!(range_start(0), [0u8; 32]);
        assert_eq!(range_end(RANGE_COUNT - 1), None);
        for i in 0..RANGE_COUNT {
            assert_eq!(range_of(&range_start(i)), i);
            if let Some(e) = range_end(i) {
                let mut below = e;
                below[0] -= 1;
                below[1..].iter_mut().for_each(|b| *b = 0xff);
                assert_eq!(range_of(&below), i);
            }
        }
        assert_eq!(successor(&[0xffu8; 32]), None);
        let mut x = [0u8; 32];
        x[31] = 0xff;
        let mut y = [0u8; 32];
        y[30] = 1;
        assert_eq!(successor(&x), Some(y));
    }

    /// A full stream (an older peer) fills the ranges in order, folds the same accumulator as the
    /// whole set, and marks every range complete.
    #[test]
    fn full_stream_folds_the_whole_set() {
        let v = set(20_000);
        let st = NullifierStaging::new(staging("full"), 7.into(), [1u8; 32], v.len() as u64).unwrap();
        assert_eq!(st.consume(StreamScope::Full, chunks(&v, 4096)).unwrap(), v.len() as u64);
        assert!(st.is_complete());
        let (n, mut acc) = st.folded();
        assert_eq!(n, v.len() as u64);
        assert_eq!(acc.finalize(), reference(&v).finalize());
        assert!(st.resume_points().iter().all(|r| r.complete));
        assert!(st.files().len() >= RANGE_COUNT, "one file per range at least");
        st.discard();
    }

    /// Ranged streams from several "sources" in any order, one of them interrupted and resumed by
    /// another, fold the same accumulator; and a restarted process (`load`) resumes from the
    /// manifest with the unfinished file dropped.
    #[test]
    fn ranged_streams_resume_across_sources_and_restarts() {
        let v = set(30_000);
        let dir = staging("ranged");
        let st = NullifierStaging::new(dir.clone(), 9.into(), [2u8; 32], v.len() as u64).unwrap();
        // Ranges in reverse order; range 3 is cut short (its source vanished after 2 chunks).
        for i in (0..RANGE_COUNT).rev() {
            let part = in_range(&v, i);
            let cs = chunks(&part, 300);
            if i == 3 {
                st.consume(StreamScope::Range(3), cs[..2].iter().cloned()).unwrap();
                continue;
            }
            st.consume(StreamScope::Range(i), cs).unwrap();
            st.complete_range(i).unwrap();
        }
        assert!(!st.is_complete());
        let r3 = st.resume_points()[3];
        assert!(!r3.complete);
        assert_eq!(r3.received, 600);
        let part3 = in_range(&v, 3);
        assert_eq!(r3.from, successor(&part3[599]));

        // The process dies; a stray half-written file is left behind.
        drop(st);
        std::fs::write(dir.join("nf-99999999.sst"), b"partial").unwrap();
        let st = NullifierStaging::load(dir.clone()).expect("manifest reloads");
        assert!(!dir.join("nf-99999999.sst").exists(), "an unnamed file is removed on load");
        assert!(st.matches(9.into(), [2u8; 32], v.len() as u64));
        assert_eq!(st.received(), v.len() as u64 - (part3.len() as u64 - 600));
        // Another source resumes range 3 after its last staged element.
        let rest: Vec<[u8; 32]> = part3.iter().copied().filter(|nf| Some(*nf) >= r3.from).collect();
        st.consume(StreamScope::Range(3), chunks(&rest, 512)).unwrap();
        st.complete_range(3).unwrap();
        assert!(st.is_complete());
        let (_, mut acc) = st.folded();
        assert_eq!(acc.finalize(), reference(&v).finalize(), "range-split + resumed fold == whole-set fold");
        st.discard();
    }

    #[test]
    fn out_of_order_duplicate_out_of_range_and_overrun_are_caught_at_the_first_bad_chunk() {
        let v = set(5_000);
        let r0 = in_range(&v, 0);
        let st = NullifierStaging::new(staging("bad"), 7.into(), [1u8; 32], 100).unwrap();
        st.consume(StreamScope::Range(0), vec![vec![r0[0], r0[1]]]).unwrap();
        // A resend of the previous element (duplicate) and a step back (out of order).
        assert_eq!(st.consume(StreamScope::Range(0), vec![vec![r0[1], r0[2]]]), Err(StreamImportError::NotAscending { index: 2 }));
        assert_eq!(st.consume(StreamScope::Range(0), vec![vec![r0[3], r0[2]]]), Err(StreamImportError::NotAscending { index: 3 }));
        // An element of another range.
        let r5 = in_range(&v, 5);
        assert_eq!(st.consume(StreamScope::Range(0), vec![vec![r0[2], r5[0]]]), Err(StreamImportError::OutOfRange { range: 0 }));
        // Nothing of a refused chunk is kept.
        assert_eq!(st.received(), 2);
        // More than declared.
        assert_eq!(st.consume(StreamScope::Range(5), vec![r5[..r5.len().min(200)].to_vec()]), Err(StreamImportError::Overrun { declared: 100 }));
        // A full stream needs an empty staging; a complete range cannot be restaged.
        assert_eq!(st.consume(StreamScope::Full, vec![vec![r0[0]]]), Err(StreamImportError::NotFresh));
        st.complete_range(0).unwrap();
        assert_eq!(st.consume(StreamScope::Range(0), vec![vec![r0[9]]]), Err(StreamImportError::RangeUnavailable { range: 0 }));
        st.discard();
    }

    /// The ingest path: the staged files land in the live store's key space with the live store's
    /// value, the old set is gone, and the set iterates back in key order. 2.2 x NULLIFIERS_PER_SST
    /// elements in one range forces several files per range.
    #[test]
    fn staged_files_ingest_into_the_live_store_keyspace() {
        use crate::model::stores::shielded::{DbNullifierSetStore, NullifierSetStore, NullifierSetStoreReader};
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbNullifierSetStore::new(db.clone(), kaspa_database::prelude::CachePolicy::Count(16));
        // An old live set, to be replaced.
        let mut batch = rocksdb::WriteBatch::default();
        store.insert_batch(&mut batch, [0xffu8; 32]).unwrap();
        db.write(batch).unwrap();

        let mut v = set(10_000);
        // Plus a dense block inside range 2 that spans three files.
        let dense = (NULLIFIERS_PER_SST as f64 * 2.2) as u64;
        for i in 0..dense {
            let mut b = [0u8; 32];
            b[0] = 0x2a;
            b[24..].copy_from_slice(&i.to_be_bytes());
            v.push(b);
        }
        v.sort();
        v.dedup();
        let st = NullifierStaging::new(db.path().parent().unwrap().join("staging-ingest"), 7.into(), [1u8; 32], v.len() as u64).unwrap();
        st.consume(StreamScope::Full, chunks(&v, 4096)).unwrap();
        assert!(st.files().len() >= RANGE_COUNT + 2);
        // The commit protocol: delete the live set by range, then ingest.
        let mut batch = rocksdb::WriteBatch::default();
        store.delete_all_batch(&mut batch).unwrap();
        db.write(batch).unwrap();
        st.ingest_into(&db).unwrap();
        store.clear_cache();

        assert!(!store.contains(&[0xffu8; 32]).unwrap(), "the old set is gone");
        for nf in [v[0], v[1], v[777], v[v.len() / 2], v[v.len() - 1]] {
            assert!(store.contains(&nf).unwrap(), "a staged nullifier is in the live store");
        }
        let listed: Vec<[u8; 32]> = store.iter_all().map(|r| r.unwrap()).collect();
        assert_eq!(listed.len(), v.len());
        assert!(listed == v, "iterated in key order, values decode as the store's marker");
        st.discard();
    }
}
