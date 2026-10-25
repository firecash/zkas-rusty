//! The multi-wallet scan engine as a walletd (task E2, phase 2; `09-engine-phase2.md`).
//!
//! Behind `--shared-scan-engine --engine-dir DIR` (default OFF, and nothing here runs
//! without both). One follower ingests the chain ONCE into [`ChainStore`]; every wallet in
//! `--wallet-dir` is migrated from its `.scan` checkpoint WITHOUT a rescan — only its private
//! sections are read ([`read_scan_private`]), it is registered at exactly its cursor block
//! while the follower passes that block, and at that moment its tree size and tip frontier
//! must equal the shared tree's and every note's commitment must equal the shared leaf at
//! its position ([`bind_to_chain`]). From then on the wallet is folded from the follower's
//! records, journaled, and persisted in a small `.w2` file. `/api/*` reads are rendered by
//! the SAME functions the per-wallet daemon uses (`snap_from_entry`, `balance_resp`,
//! `history_json`) over a [`WalletEntry`] built from engine state, so equal state renders
//! byte-identical answers. Spending is not served in phase 2 (no route).
//!
//! **It never writes to `--wallet-dir`**, and with `--engine-compare-live DIR` it reads only
//! the header and private sections of the checkpoints there (never a seed, never a write).

use super::*;
use kaspa_shielded_core::engine::{CombKernel, LadderKernel, ScanEngine, SharedBlock, SharedChain, SharedPage, WalletId, WalletLite, WalletState};
use kaspa_shielded_core::engine_store::{ChainStore, CommitFault, W2Head, decode_w2, encode_w2, write_atomic};
use kaspa_shielded_core::walletdb::{CheckpointPrivate, read_checkpoint_private};
use kaspa_shielded_core::engine::WalletFvk as FullViewingKey;
use std::path::{Path, PathBuf};

/// A wallet's stable 16-byte engine name: journal key and `.w2` file stem. A keyed hash of
/// the token, so neither the journal nor a file name carries the token itself.
pub(crate) fn wallet_key16(token: &str) -> [u8; 16] {
    kaspa_shielded_core::engine_store::wallet_key16(token.as_bytes())
}

fn hex16(k: &[u8; 16]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------
// Migration: the private sections of a `.scan`
// ---------------------------------------------------------------------------------------

/// What a hosted `.scan` holds that belongs to the wallet, plus its cursor and the trailer.
#[derive(Clone)]
pub(crate) struct ScanPrivate {
    pub genesis: RpcHash,
    pub low: RpcHash,
    pub scanned: u64,
    pub p: CheckpointPrivate,
    pub boundaries: VecDeque<(u64, u64)>,
    pub sink_blue: u64,
    pub blind_below: u64,
    pub file_len: u64,
    pub bytes_read: u64,
}

/// Read a `.scan` checkpoint's header, private blob sections and trailer, seeking past the
/// leaf stream, nullifier set, witnesses and subtree index. Never writes. The container is
/// [`checkpoint_bytes`]'s; the blob is read by `read_checkpoint_private`, which uses the
/// restore's own section parsers.
pub(crate) fn read_scan_private(path: &Path) -> Result<ScanPrivate, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let file_len = f.metadata().map_err(|e| e.to_string())?.len();
    let mut head = [0u8; SCAN_HEADER_LEN + 8];
    f.read_exact(&mut head).map_err(|e| format!("header: {e}"))?;
    if &head[0..4] != SCAN_MAGIC || !matches!(head[4], SCAN_VERSION | SCAN_VERSION_PREV) {
        return Err("not a checkpoint (magic/version)".into());
    }
    let version = head[4];
    let genesis = RpcHash::from_bytes(head[5..37].try_into().expect("32"));
    let low = RpcHash::from_bytes(head[37..69].try_into().expect("32"));
    let scanned = u64::from_le_bytes(head[69..77].try_into().expect("8"));
    let blob_len = u64::from_le_bytes(head[77..85].try_into().expect("8"));
    if (SCAN_HEADER_LEN as u64 + 8).checked_add(blob_len).is_none_or(|e| e > file_len) {
        return Err("blob length exceeds the file".into());
    }
    let p = read_checkpoint_private(&mut f, blob_len)?;
    let tail_at = SCAN_HEADER_LEN as u64 + 8 + blob_len;
    f.seek(SeekFrom::Start(tail_at)).map_err(|e| e.to_string())?;
    let tail_len = file_len - tail_at;
    if tail_len > 4 + (MATURED_RING as u64 + 1024) * 16 + 16 {
        return Err("trailer too long".into());
    }
    let mut tail = vec![0u8; tail_len as usize];
    f.read_exact(&mut tail).map_err(|e| e.to_string())?;
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8], String> {
        let s = tail.get(pos..pos + n).ok_or("trailer truncated")?;
        pos += n;
        Ok(s)
    };
    let ring_len = u32::from_le_bytes(take(4)?.try_into().expect("4")) as usize;
    let mut boundaries = VecDeque::with_capacity(ring_len.min(MATURED_RING));
    for _ in 0..ring_len {
        let blue = u64::from_le_bytes(take(8)?.try_into().expect("8"));
        let leaves = u64::from_le_bytes(take(8)?.try_into().expect("8"));
        boundaries.push_back((blue, leaves));
    }
    let sink_blue = u64::from_le_bytes(take(8)?.try_into().expect("8"));
    let blind_below = if version == SCAN_VERSION { u64::from_le_bytes(take(8)?.try_into().expect("8")) } else { 0 };
    if pos != tail.len() {
        return Err("trailing bytes after the trailer".into());
    }
    let bytes_read = SCAN_HEADER_LEN as u64 + 8 + p.bytes_read + tail_len;
    Ok(ScanPrivate { genesis, low, scanned, p, boundaries, sink_blue, blind_below, file_len, bytes_read })
}

/// How a migrated checkpoint binds to the shared chain at its cursor.
#[derive(Clone, Debug, Default)]
pub(crate) struct Binding {
    /// The shared tree's size equals the checkpoint's at the cursor.
    pub size_ok: bool,
    /// The checkpoint's tip frontier equals the shared tree's (None = the checkpoint records none).
    pub frontier_ok: Option<bool>,
    /// Notes and pending notes checked.
    pub notes: usize,
    pub cmx_ok: usize,
    pub nf_ok: usize,
    /// Unspent/pending notes whose nullifier the chain had ALREADY applied at the cursor.
    pub already_spent: usize,
    pub failures: Vec<String>,
}

impl Binding {
    pub fn clean(&self) -> bool {
        self.size_ok && self.frontier_ok != Some(false) && self.cmx_ok == self.notes && self.nf_ok == self.notes && self.already_spent == 0
    }
}

/// Check a checkpoint against the shared chain, which must be exactly at its cursor: size,
/// tip frontier, and for every note and pending note the commitment at its position and the
/// nullifier this key derives. Reports; never drops a note.
pub(crate) fn bind_to_chain(sp: &ScanPrivate, fvk: &FullViewingKey, chain: &SharedChain) -> Binding {
    let mut b = Binding { size_ok: chain.size() == sp.p.size, ..Default::default() };
    if let Some(t) = &sp.p.tip {
        b.frontier_ok = Some(chain.tree().tip_frontier_state().as_ref() == Some(t));
    }
    let all = sp.p.notes.iter().chain(sp.p.pending.iter().map(|p| &p.note));
    for n in all {
        b.notes += 1;
        let cmx = kaspa_shielded_core::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes();
        match chain.tree().leaf_at(n.position) {
            Some(l) if l == cmx => b.cmx_ok += 1,
            Some(_) => b.failures.push(format!("note at {}: commitment differs from the shared leaf", n.position)),
            None => b.failures.push(format!("note at {}: position beyond the shared stream", n.position)),
        }
        if n.note.nullifier(fvk).to_bytes() == n.nullifier() {
            b.nf_ok += 1;
        } else {
            b.failures.push(format!("note at {}: nullifier is not this key's", n.position));
        }
        if chain.nf_seen(&n.nullifier()) {
            b.already_spent += 1;
        }
    }
    b
}

/// The engine's block from the daemon's decoded block, with `sync_chunk`'s meta rule.
pub(crate) fn shared_block_of(b: &DecodedBlock) -> SharedBlock {
    SharedBlock {
        hash: b.hash.as_bytes(),
        blue_score: b.blue_score,
        daa_score: b.daa_score,
        coinbase: b.coinbase.clone(),
        txs: b.compact.clone(),
        meta: (b.timestamp > 0 && b.txids.len() == b.compact.len()).then(|| BlockMeta {
            coinbase_txid: b.coinbase_txid,
            txids: b.txids.clone(),
            timestamp_ms: b.timestamp,
            daa_score: b.daa_score,
        }),
    }
}

pub(crate) fn fvk_of(key: &WalletKey) -> Option<FullViewingKey> {
    FullViewingKey::from_bytes(&key.fvk_bytes()?)
}

/// Everything about a wallet entry that is not the wallet's own state: the daemon's view of
/// the chain at that moment. Two entries rendered with the same context and equal wallet
/// state render byte-identical `/api/*` answers.
#[derive(Clone, Debug)]
pub(crate) struct EntryContext {
    pub chain_len: u64,
    pub caught_up: bool,
    pub sink_live: bool,
    pub updated_unix: u64,
    pub spend_fast_ready: bool,
}

/// A [`WalletEntry`] over a read-only view of a wallet's state (`WalletDb::view_from_parts`):
/// what the engine serves `/api/*` reads from.
#[allow(clippy::too_many_arguments)]
pub(crate) fn view_entry(
    key: WalletKey,
    genesis: RpcHash,
    state: WalletState,
    tip: &kaspa_shielded_core::tree::FrontierState,
    low: RpcHash,
    scanned: u64,
    boundaries: VecDeque<(u64, u64)>,
    sink_blue: u64,
    blind_below: u64,
    ctx: &EntryContext,
) -> Option<WalletEntry> {
    let fvk = fvk_of(&key)?;
    let db = WalletDb::view_from_parts(&fvk, state.notes, state.pending_spends, state.history, state.history_enabled, state.last_daa, tip)?;
    let mut e = WalletEntry::from_parts(key, true, db, genesis, low, scanned as usize, boundaries, sink_blue);
    apply_context(&mut e, ctx);
    e.blind_below = blind_below;
    Some(e)
}

pub(crate) fn apply_context(e: &mut WalletEntry, ctx: &EntryContext) {
    e.chain_len = ctx.chain_len;
    e.caught_up = ctx.caught_up;
    e.sink_live = ctx.sink_live;
    e.updated_unix = ctx.updated_unix;
    e.spend_fast_ready = ctx.spend_fast_ready;
}

/// The three read answers for one entry, as bytes: `/api/status` (wallet part), balance
/// with notes, history.
pub(crate) fn render(prefix: Prefix, network: &str, address: String, e: &WalletEntry) -> [Vec<u8>; 3] {
    let mut resp = status_base(network, true, e.chain_len);
    let snap = snap_from_entry(address, e, e.chain_len);
    fill_status_from_snap(&mut resp, &snap);
    [
        serde_json::to_vec(&resp).unwrap_or_default(),
        serde_json::to_vec(&balance_resp(prefix, e, true)).unwrap_or_default(),
        serde_json::to_vec(&history_json(prefix, e, Some(5_000), None)).unwrap_or_default(),
    ]
}

// ---------------------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct EngineConfig {
    pub rpc_server: String,
    pub listen: SocketAddr,
    /// The wallet directory the engine serves (a COPY on the shadow run). Read-only.
    pub wallet_dir: String,
    pub engine_dir: PathBuf,
    pub network: String,
    pub wallet_secret: Option<String>,
    /// The LIVE daemon's wallet directory, to compare against (headers + private sections only).
    pub compare_live_dir: Option<String>,
    /// Do not ingest blocks with a DAA score above this (a fixed end for experiments).
    pub stop_at_daa: Option<u64>,
    /// Seconds before the node tip at start: snapshot every wallet's `.w2` when the follower
    /// passes `tip − s` (dormant catch-up measurements).
    pub dormant_marks: Vec<u64>,
    /// Keep the compact block archive (`chain.ccs`). Fixed at store creation.
    pub archive: bool,
    /// Old-path twins: migrated wallets get a per-wallet `WalletDb` restored from the same
    /// checkpoint and fed exactly the blocks the engine ingests, compared with the engine's
    /// wallet as it goes, while their estimated final heap (their own leaf copy to the tip,
    /// the old daemon's cost) fits this many MB in total (0 = none).
    pub twin_max_mb: u64,
    /// Pause the follower while the engine directory's filesystem has less free space.
    pub min_free_mb: u64,
}

/// An old-path twin: the per-wallet database the hosted daemon would hold for this wallet,
/// fed the same blocks, borrowing the shared tree as the live daemon's wallets do.
struct Twin {
    db: WalletDb,
    ingest_ns: u128,
    blocks: u64,
    compares: u64,
    mismatch: Option<String>,
}

struct HostWallet {
    token: String,
    key: WalletKey,
    key16: [u8; 16],
    id: Option<WalletId>,
    blind_below: u64,
    examined: usize,
    dirty: bool,
    /// The migrated state, for comparisons at any later cursor: (state, seq, size, journal offset).
    t0: Option<(WalletState, u64, u64, u64)>,
    binding: Option<Binding>,
    status: String,
    live_mtime: Option<std::time::SystemTime>,
    twin: Option<Twin>,
}

pub(crate) struct Host {
    cfg: EngineConfig,
    genesis: RpcHash,
    prefix: Prefix,
    store: ChainStore,
    engine: ScanEngine,
    wallets: Vec<HostWallet>,
    by_token: HashMap<String, usize>,
    /// Cursor block hash → wallets waiting to register when the follower passes it.
    pending_at: HashMap<[u8; 32], Vec<(usize, Box<ScanPrivate>)>>,
    /// DAA score of every stored block, by sequence − 1 (strictly increasing on the chain).
    daa_of: Vec<u64>,
    ring: VecDeque<(u64, u64)>,
    sink_blue: u64,
    tip_daa: u64,
    caught_up: bool,
    marks: Vec<(u64, u64)>,
    stats: HostStats,
    twin_budget_left: u64,
    /// The node's tree size at start (for twin memory estimates).
    tip_size_hint: u64,
}

#[derive(Default, Clone, Debug, Serialize)]
pub(crate) struct HostStats {
    pages: u64,
    blocks: u64,
    rpc_ms: u64,
    decode_ms: u64,
    ingest_ms: u64,
    commit_ms: u64,
    w2_writes: u64,
    registered: usize,
    compares: u64,
    compare_mismatches: u64,
    started_unix: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn kernel_from_env() -> Box<dyn kaspa_shielded_core::engine::AgreeKernel> {
    match std::env::var("ZKAS_ENGINE_KERNEL").as_deref() {
        Ok("ladder") => Box::new(LadderKernel),
        _ => Box::new(CombKernel { w: None }),
    }
}

impl Host {
    /// Open the store, then register every wallet of the wallet directory: from its `.w2`
    /// (+ journal) if the engine already holds it, else migrate its `.scan` at its cursor.
    pub(crate) fn open(cfg: EngineConfig, genesis: RpcHash, tip_size_hint: u64) -> Result<Self, String> {
        let (store, chain) = ChainStore::open_with(&cfg.engine_dir, genesis.as_bytes(), cfg.archive)?;
        let seq = store.committed().seq;
        let engine = ScanEngine::resume(chain, kernel_from_env(), seq);
        let idx = store.idx_all()?;
        let daa_of: Vec<u64> = idx.iter().map(|e| e.daa).collect();
        let ring: VecDeque<(u64, u64)> = idx.iter().rev().take(MATURED_RING).rev().map(|e| (e.blue, e.size_after)).collect();
        drop(idx);
        let prefix = prefix_from(&cfg.network);
        let mut host = Self {
            cfg,
            genesis,
            prefix,
            store,
            engine,
            wallets: Vec::new(),
            by_token: HashMap::new(),
            pending_at: HashMap::new(),
            daa_of,
            ring,
            sink_blue: 0,
            tip_daa: 0,
            caught_up: false,
            marks: Vec::new(),
            stats: HostStats { started_unix: now_unix(), ..Default::default() },
            twin_budget_left: 0,
            tip_size_hint: 0,
        };
        host.twin_budget_left = host.cfg.twin_max_mb << 20;
        host.tip_size_hint = tip_size_hint;
        host.register_dir()?;
        Ok(host)
    }

    fn register_dir(&mut self) -> Result<(), String> {
        let mut tokens: Vec<String> = std::fs::read_dir(&self.cfg.wallet_dir)
            .map_err(|e| format!("wallet dir: {e}"))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_string))
            .filter(|t| sanitize_token(t).as_deref() == Some(t.as_str()))
            .collect();
        tokens.sort();
        for token in tokens {
            let i = self.wallets.len();
            let Some((key, _birthday, _)) = load_wallet_meta(&self.cfg.wallet_dir, &token, self.cfg.wallet_secret.as_deref()) else {
                log::warn!("engine: wallet {} has no usable key; skipped", log_pseudonym(&token));
                continue;
            };
            let key16 = wallet_key16(&token);
            self.by_token.insert(token.clone(), i);
            self.wallets.push(HostWallet {
                token: token.clone(),
                key,
                key16,
                id: None,
                blind_below: 0,
                examined: 0,
                dirty: false,
                t0: None,
                binding: None,
                status: "unregistered".into(),
                live_mtime: None,
                twin: None,
            });
            if let Err(e) = self.register_one(i) {
                log::warn!("engine: wallet {}: {e}", log_pseudonym(&token));
                self.wallets[i].status = e;
            }
        }
        Ok(())
    }

    fn register_one(&mut self, i: usize) -> Result<(), String> {
        let fvk = fvk_of(&self.wallets[i].key).ok_or("no viewing key")?;
        let name = hex16(&self.wallets[i].key16);
        // Already in the engine: its file + the journal since.
        if let Ok(bytes) = std::fs::read(self.store.wallet_path(&name)) {
            let (h, s) = decode_w2(&bytes)?;
            if h.genesis != self.genesis.as_bytes() || h.key16 != self.wallets[i].key16 {
                return Err("w2 belongs to another chain or wallet".into());
            }
            let c = self.store.committed().clone();
            if h.seq > c.seq || h.journal_off > c.journal_len {
                return Err("w2 claims past the committed store; refusing".into());
            }
            let mut w = WalletLite::new(fvk, s, h.size, h.seq, h.key16);
            self.store.catch_up(&mut w, h.journal_off)?;
            w.advance_to(c.seq);
            self.wallets[i].blind_below = h.blind_below;
            if let Ok(t) = std::fs::read(self.store.wallet_path(&format!("{name}.t0"))) {
                if let Ok((th, ts)) = decode_w2(&t) {
                    self.wallets[i].t0 = Some((ts, th.seq, th.size, th.journal_off));
                }
            }
            let id = self.engine.register_wallet(w).ok_or("engine refused the wallet")?;
            self.wallets[i].id = Some(id);
            self.wallets[i].status = "resumed".into();
            self.stats.registered += 1;
            return Ok(());
        }
        let scan = scan_path(&self.cfg.wallet_dir, &self.wallets[i].token);
        if !Path::new(&scan).exists() {
            if self.engine.seq() == 0 {
                // No checkpoint: the whole chain, from genesis (a complete view).
                let w = WalletLite::new(fvk, WalletState { history_enabled: true, ..Default::default() }, 0, 0, self.wallets[i].key16);
                let id = self.engine.register_wallet(w).ok_or("engine refused the wallet")?;
                self.wallets[i].id = Some(id);
                self.wallets[i].status = "from genesis (no checkpoint)".into();
                self.stats.registered += 1;
                self.write_w2(i, true)?;
                return Ok(());
            }
            return Err("no checkpoint and the engine is past genesis: needs a historical replay (not in phase 2)".into());
        }
        let sp = read_scan_private(Path::new(&scan))?;
        if sp.genesis != self.genesis {
            return Err("checkpoint is for another chain; left to the old path".into());
        }
        let seq = if sp.low == self.genesis { Some(0) } else { self.store.find_seq(&sp.low.as_bytes())? };
        match seq {
            Some(s) if s == self.engine.seq() => self.register_migrated(i, sp),
            Some(_) => Err("cursor is behind the engine: needs a historical replay (not in phase 2); left to the old path".into()),
            None => {
                self.wallets[i].status = "waiting for its cursor block".into();
                self.pending_at.entry(sp.low.as_bytes()).or_default().push((i, Box::new(sp)));
                Ok(())
            }
        }
    }

    /// Register a migrated wallet: the shared chain is exactly at its cursor right now.
    fn register_migrated(&mut self, i: usize, sp: ScanPrivate) -> Result<(), String> {
        let fvk = fvk_of(&self.wallets[i].key).ok_or("no viewing key")?;
        let b = bind_to_chain(&sp, &fvk, self.engine.chain());
        let pseud = log_pseudonym(&self.wallets[i].token);
        log::info!(
            "engine: migrating {pseud} at seq {}: size {} frontier {:?} notes {} cmx {} nf {} already-spent {} ({} of {} bytes read)",
            self.engine.seq(),
            if b.size_ok { "ok" } else { "MISMATCH" },
            b.frontier_ok,
            b.notes,
            b.cmx_ok,
            b.nf_ok,
            b.already_spent,
            sp.bytes_read,
            sp.file_len
        );
        for f in b.failures.iter().take(5) {
            log::warn!("engine: migrating {pseud}: {f}");
        }
        if !b.size_ok {
            self.wallets[i].binding = Some(b);
            return Err("checkpoint size does not match the shared tree at its cursor; left to the old path".into());
        }
        // Estimated final heap of an old-path twin: its own leaf stream from its base to the tip
        // (the per-wallet copy the old daemon keeps) plus its notes.
        let est = (self.tip_size_hint.saturating_sub(sp.p.base_size)) * 32 + sp.p.notes.len() as u64 * 300 + (64 << 20);
        let twin = if self.cfg.twin_max_mb > 0 && est <= self.twin_budget_left {
            let scan = scan_path(&self.cfg.wallet_dir, &self.wallets[i].token);
            match std::fs::read(&scan).ok().and_then(|buf| parse_scan_bytes(&buf, self.wallets[i].key, None, None)) {
                Some((_, (mut db, ..))) => {
                    db.set_borrow_tree(true);
                    self.twin_budget_left -= est;
                    Some(Twin { db, ingest_ns: 0, blocks: 0, compares: 0, mismatch: None })
                }
                None => {
                    log::warn!("engine: {pseud}: the old path cannot restore its own checkpoint; no twin");
                    None
                }
            }
        } else {
            None
        };
        let state = WalletState { notes: sp.p.notes, pending_spends: sp.p.pending, history: sp.p.history, history_enabled: true, last_daa: sp.p.last_daa };
        let seq = self.engine.seq();
        let size = self.engine.chain().size();
        let w = WalletLite::new(fvk, state.clone(), size, seq, self.wallets[i].key16);
        let id = self.engine.register_wallet(w).ok_or("engine refused the wallet")?;
        let hw = &mut self.wallets[i];
        hw.id = Some(id);
        hw.blind_below = sp.blind_below;
        hw.binding = Some(b);
        hw.status = "migrated".into();
        hw.twin = twin;
        let jo = self.store.committed().journal_len;
        hw.t0 = Some((state.clone(), seq, size, jo));
        let name = hex16(&hw.key16);
        let head = W2Head { genesis: self.genesis.as_bytes(), key16: hw.key16, seq, size, journal_off: jo, blind_below: sp.blind_below };
        write_atomic(&self.store.wallet_path(&format!("{name}.t0")), &encode_w2(&head, &state)).map_err(|e| e.to_string())?;
        self.stats.registered += 1;
        self.write_w2(i, true)
    }

    fn write_w2(&mut self, i: usize, force: bool) -> Result<(), String> {
        let hw = &mut self.wallets[i];
        let Some(id) = hw.id else { return Ok(()) };
        if !force && !hw.dirty {
            return Ok(());
        }
        let c = self.store.committed();
        let w = self.engine.wallet(id);
        let head = W2Head { genesis: c.genesis, key16: hw.key16, seq: c.seq, size: c.leaves, journal_off: c.journal_len, blind_below: hw.blind_below };
        write_atomic(&self.store.wallet_path(&hex16(&hw.key16)), &encode_w2(&head, &w.state())).map_err(|e| e.to_string())?;
        hw.dirty = false;
        self.stats.w2_writes += 1;
        Ok(())
    }

    /// Ingest and commit one run of settled blocks, registering waiting wallets exactly at
    /// their cursor blocks. Any commit error is fatal for the process (RAM is ahead of disk).
    fn ingest(&mut self, blocks: Vec<SharedBlock>) -> Result<(), String> {
        let mut start = 0;
        while start < blocks.len() {
            // Cut the run right after the first block some wallet is waiting for.
            let end = (start..blocks.len()).find(|&j| self.pending_at.contains_key(&blocks[j].hash)).map(|j| j + 1).unwrap_or(blocks.len());
            let chunk = &blocks[start..end];
            let t = std::time::Instant::now();
            let page = SharedPage::new(chunk.to_vec());
            let folds = self.engine.ingest_page(&page);
            self.stats.ingest_ms += t.elapsed().as_millis() as u64;
            if (0..self.engine.wallet_count()).any(|w| self.engine.wallet(w as WalletId).poisoned()) || self.engine.chain().poisoned() {
                return Err("the node served a repeated nullifier; refusing to commit (fatal)".into());
            }
            let t = std::time::Instant::now();
            self.store.commit_page(chunk, &folds, &self.engine, CommitFault::None)?;
            self.stats.commit_ms += t.elapsed().as_millis() as u64;
            for (b, &size_after) in chunk.iter().zip(&folds.sizes_after) {
                self.daa_of.push(b.daa_score);
                self.ring.push_back((b.blue_score, size_after));
                if self.ring.len() > MATURED_RING {
                    self.ring.pop_front();
                }
            }
            self.feed_twins(&page);
            let ids: HashSet<WalletId> = folds.records.iter().filter_map(|(_, w, _)| *w).collect();
            for hw in &mut self.wallets {
                if hw.id.is_some_and(|id| ids.contains(&id)) {
                    hw.dirty = true;
                }
            }
            self.stats.blocks += chunk.len() as u64;
            // Dormant marks crossed by this chunk: snapshot every registered wallet.
            let last_daa = chunk.last().map(|b| b.daa_score).unwrap_or(0);
            let crossed: Vec<u64> = self.marks.iter().filter(|(_, d)| *d <= last_daa).map(|(s, _)| *s).collect();
            if !crossed.is_empty() {
                self.marks.retain(|(_, d)| *d > last_daa);
                for s in crossed {
                    self.snapshot_all(&format!("mark{s}"))?;
                }
            }
            for i in 0..self.wallets.len() {
                self.write_w2(i, false)?;
            }
            if let Some(waiting) = chunk.last().and_then(|b| self.pending_at.remove(&b.hash)) {
                for (i, sp) in waiting {
                    if let Err(e) = self.register_migrated(i, *sp) {
                        log::warn!("engine: wallet {}: {e}", log_pseudonym(&self.wallets[i].token));
                        self.wallets[i].status = e;
                    }
                }
            }
            start = end;
        }
        self.stats.pages += 1;
        Ok(())
    }

    /// Feed the old-path twins the chunk the engine just committed, exactly as `sync_chunk`
    /// would (one page memo, compact precomputed ingest, the shared tree's frontier adopted),
    /// and compare each with its engine wallet every 25 chunks and whenever it was touched.
    fn feed_twins(&mut self, page: &SharedPage) {
        let tip = self.engine.chain().tree().tip_frontier_state();
        let compare_all = self.stats.pages % 25 == 0;
        for i in 0..self.wallets.len() {
            let Some(id) = self.wallets[i].id else { continue };
            let Some(tw) = self.wallets[i].twin.as_mut() else { continue };
            let t = std::time::Instant::now();
            tw.db.predecrypt_page_cached(&page.actions, Some(&page.epks));
            let before = (tw.db.notes().len(), tw.db.pending_spends().len(), tw.db.history().len());
            for b in &page.blocks {
                tw.db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, b.meta.as_ref());
            }
            tw.db.end_page();
            if let Some(fs) = &tip {
                tw.db.adopt_tip_frontier(fs);
            }
            tw.ingest_ns += t.elapsed().as_nanos();
            tw.blocks += page.blocks.len() as u64;
            let touched = before != (tw.db.notes().len(), tw.db.pending_spends().len(), tw.db.history().len());
            if (compare_all || touched) && tw.mismatch.is_none() {
                tw.compares += 1;
                let w = self.engine.wallet(id);
                let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
                let why = if tw.db.notes().iter().map(nk).ne(w.notes().iter().map(nk)) {
                    Some("notes")
                } else if tw.db.pending_spends().iter().map(|p| (nk(&p.note), p.txid)).ne(w.pending_spends().iter().map(|p| (nk(&p.note), p.txid))) {
                    Some("pending")
                } else if format!("{:?}", tw.db.history()) != format!("{:?}", w.history()) {
                    Some("history")
                } else if tw.db.last_daa() != w.last_daa() {
                    Some("clock")
                } else if tw.db.size() != self.engine.chain().size() || tw.db.anchor() != self.engine.chain().anchor() {
                    Some("tree size/anchor")
                } else {
                    None
                };
                if let Some(why) = why {
                    log::error!("engine: twin MISMATCH for {} at seq {}: {why}", log_pseudonym(&self.wallets[i].token), self.engine.seq());
                    self.wallets[i].twin.as_mut().expect("twin").mismatch = Some(format!("{why} at seq {}", self.engine.seq()));
                }
            }
        }
    }

    /// Copy every registered wallet's current file to `<name>.<tag>.w2` (dormant snapshots).
    fn snapshot_all(&mut self, tag: &str) -> Result<(), String> {
        for i in 0..self.wallets.len() {
            self.write_w2(i, true)?;
            let name = hex16(&self.wallets[i].key16);
            if self.wallets[i].id.is_some() {
                let from = self.store.wallet_path(&name);
                let to = self.store.wallet_path(&format!("{name}.{tag}"));
                let b = std::fs::read(&from).map_err(|e| e.to_string())?;
                write_atomic(&to, &b).map_err(|e| e.to_string())?;
            }
        }
        log::info!("engine: dormant snapshot {tag} at seq {}", self.engine.seq());
        Ok(())
    }

    /// The seq of the stored block with this hash and DAA score (binary search on DAA).
    fn seq_of(&self, hash: &RpcHash, daa: u64) -> Option<u64> {
        let i = self.daa_of.binary_search(&daa).ok()?;
        let seq = i as u64 + 1;
        (self.store.idx(seq).ok()?.hash == hash.as_bytes()).then_some(seq)
    }

    /// The boundary ring as of block `seq`.
    fn ring_at(&self, seq: u64) -> VecDeque<(u64, u64)> {
        let from = seq.saturating_sub(MATURED_RING as u64 - 1).max(1);
        (from..=seq).filter_map(|s| self.store.idx(s).ok()).map(|e| (e.blue, e.size_after)).collect()
    }

    fn ctx(&self) -> EntryContext {
        EntryContext { chain_len: self.tip_daa, caught_up: self.caught_up, sink_live: true, updated_unix: now_unix(), spend_fast_ready: true }
    }

    /// The live engine entry for a token.
    fn entry(&self, token: &str) -> Option<WalletEntry> {
        let hw = &self.wallets[*self.by_token.get(token)?];
        let w = self.engine.wallet(hw.id?);
        let c = self.store.committed();
        view_entry(hw.key, self.genesis, w.state(), &c.tip, RpcHash::from_bytes(c.last_hash), c.last_daa, self.ring.clone(), self.sink_blue, hw.blind_below, &self.ctx())
    }

    fn address(&self, e: &WalletEntry) -> String {
        String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &e.db.my_address_bytes()))
    }

    /// Reclaim lost sends exactly as `sync_one_wallet` does once caught up.
    fn reclaim(&mut self) {
        let now = self.store.committed().last_daa;
        for i in 0..self.wallets.len() {
            let Some(id) = self.wallets[i].id else { continue };
            if self.engine.wallet(id).pending_spends().is_empty() {
                continue;
            }
            let got = self.engine.reclaim_expired(id, now, PENDING_SPEND_EXPIRY_DAA);
            if !got.is_empty() {
                log::warn!("engine: wallet {}: {} submitted spend(s) never appeared on chain; notes returned", log_pseudonym(&self.wallets[i].token), got.len());
                self.wallets[i].dirty = true;
            }
        }
    }

    /// Compare every live checkpoint rewritten since the last look with the engine's state
    /// at exactly that cursor (migrated state + journal through that block). Reads only the
    /// live file's header and private sections; never writes there.
    /// Live checkpoints rewritten since the last look: (wallet index, private read).
    fn live_candidates(&mut self) -> Vec<(usize, Result<ScanPrivate, String>)> {
        let Some(live) = self.cfg.compare_live_dir.clone() else { return Vec::new() };
        let mut out = Vec::new();
        for i in 0..self.wallets.len() {
            if self.wallets[i].id.is_none() || self.wallets[i].t0.is_none() {
                continue;
            }
            let path = scan_path(&live, &self.wallets[i].token);
            let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) else { continue };
            if self.wallets[i].live_mtime == Some(m) {
                continue;
            }
            self.wallets[i].live_mtime = Some(m);
            out.push((i, read_scan_private(Path::new(&path))));
        }
        out
    }

    /// Compare the candidates (`tips[k]` = the node's frontier at candidate k's cursor, for a
    /// checkpoint written while borrowing the shared tree, exactly what the load path adopts).
    fn compare_candidates(&mut self, cands: Vec<(usize, Result<ScanPrivate, String>)>, tips: Vec<Option<kaspa_shielded_core::tree::FrontierState>>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        for ((i, sp), node_tip) in cands.into_iter().zip(tips) {
            let pseud = log_pseudonym(&self.wallets[i].token);
            let (Some(id), Some(t0)) = (self.wallets[i].id, self.wallets[i].t0.clone()) else { continue };
            let mut sp = match sp {
                Ok(sp) => sp,
                Err(e) => {
                    out.push(serde_json::json!({"wallet": pseud, "result": "unreadable", "why": e}));
                    continue;
                }
            };
            if sp.p.tip.is_none() {
                sp.p.tip = node_tip.filter(|t| t.size == sp.p.size);
            }
            let Some(seq) = (if sp.low == self.genesis { Some(0) } else { self.seq_of(&sp.low, sp.scanned) }) else {
                out.push(serde_json::json!({"wallet": pseud, "result": "cursor not in the engine store (live ahead of the engine or off-chain)", "live_daa": sp.scanned}));
                continue;
            };
            if seq < t0.1 {
                out.push(serde_json::json!({"wallet": pseud, "result": "live cursor before the migration point", "seq": seq}));
                continue;
            }
            let r = self.compare_one(i, id, &t0, seq, &sp);
            self.stats.compares += 1;
            if r.get("result").and_then(|v| v.as_str()) != Some("equal") {
                self.stats.compare_mismatches += 1;
            }
            out.push(r);
        }
        out
    }

    #[allow(dead_code)]
    fn compare_live(&mut self) -> Vec<serde_json::Value> {
        let Some(live) = self.cfg.compare_live_dir.clone() else { return Vec::new() };
        let mut out = Vec::new();
        for i in 0..self.wallets.len() {
            let (Some(id), Some(t0)) = (self.wallets[i].id, self.wallets[i].t0.clone()) else { continue };
            let path = scan_path(&live, &self.wallets[i].token);
            let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) else { continue };
            if self.wallets[i].live_mtime == Some(m) {
                continue;
            }
            self.wallets[i].live_mtime = Some(m);
            let pseud = log_pseudonym(&self.wallets[i].token);
            let sp = match read_scan_private(Path::new(&path)) {
                Ok(sp) => sp,
                Err(e) => {
                    out.push(serde_json::json!({"wallet": pseud, "result": "unreadable", "why": e}));
                    continue;
                }
            };
            let Some(seq) = (if sp.low == self.genesis { Some(0) } else { self.seq_of(&sp.low, sp.scanned) }) else {
                out.push(serde_json::json!({"wallet": pseud, "result": "cursor not in the engine store (live ahead of the engine or off-chain)", "live_daa": sp.scanned}));
                continue;
            };
            if seq < t0.1 {
                out.push(serde_json::json!({"wallet": pseud, "result": "live cursor before the migration point", "seq": seq}));
                continue;
            }
            let r = self.compare_one(i, id, &t0, seq, &sp);
            self.stats.compares += 1;
            if r.get("result").and_then(|v| v.as_str()) != Some("equal") {
                self.stats.compare_mismatches += 1;
            }
            out.push(r);
        }
        out
    }

    fn compare_one(&self, i: usize, id: WalletId, t0: &(WalletState, u64, u64, u64), seq: u64, sp: &ScanPrivate) -> serde_json::Value {
        let hw = &self.wallets[i];
        let pseud = log_pseudonym(&hw.token);
        let Some(fvk) = fvk_of(&hw.key) else { return serde_json::json!({"wallet": pseud, "result": "no key"}) };
        let mut w = WalletLite::new(fvk, t0.0.clone(), t0.2, t0.1, hw.key16);
        let mut folded = 0usize;
        match self.store.journal_from(t0.3) {
            Ok(recs) => {
                for (_, s, k, rec) in recs {
                    if s <= t0.1 || s > seq {
                        continue;
                    }
                    if k.is_none() || k == Some(hw.key16) {
                        w.fold(&rec);
                        folded += 1;
                    }
                }
            }
            Err(e) => return serde_json::json!({"wallet": pseud, "result": "journal unreadable", "why": e}),
        }
        // Send details the engine recovered since (same OVK recovery the live daemon runs).
        let live_w = self.engine.wallet(id);
        let mut st = w.state();
        for h in st.history.iter_mut() {
            if h.kind == HistoryKind::Sent && h.recipient.is_none() && !h.fee_known {
                if let Some(r) = live_w.history().iter().find(|x| x.kind == HistoryKind::Sent && x.txid == h.txid && x.fee_known) {
                    *h = r.clone();
                }
            }
        }
        let key = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
        let (en, ln): (Vec<_>, Vec<_>) = (st.notes.iter().map(key).collect(), sp.p.notes.iter().map(key).collect());
        let (ep, lp): (Vec<_>, Vec<_>) = (
            st.pending_spends.iter().map(|p| (key(&p.note), p.txid, p.submitted_daa)).collect(),
            sp.p.pending.iter().map(|p| (key(&p.note), p.txid, p.submitted_daa)).collect(),
        );
        let hist_eq = format!("{:?}", st.history) == format!("{:?}", sp.p.history);
        let mut diffs: Vec<&str> = Vec::new();
        if en != ln {
            diffs.push("notes");
        }
        if ep != lp {
            diffs.push("pending");
        }
        if !hist_eq {
            diffs.push("history");
        }
        if st.last_daa != sp.p.last_daa {
            diffs.push("clock");
        }
        let ring = self.ring_at(seq);
        if ring != sp.boundaries {
            diffs.push("boundary ring");
        }
        // The API answers, rendered by the same functions from both states, same context.
        let ctx = EntryContext { chain_len: sp.scanned + 1000, caught_up: true, sink_live: true, updated_unix: 1, spend_fast_ready: true };
        let api = match sp.p.tip.clone() {
            Some(tip) => {
                let a = view_entry(hw.key, self.genesis, st.clone(), &tip, sp.low, sp.scanned, ring.clone(), sp.sink_blue, sp.blind_below, &ctx);
                let lstate = WalletState {
                    notes: sp.p.notes.clone(),
                    pending_spends: sp.p.pending.clone(),
                    history: sp.p.history.clone(),
                    history_enabled: true,
                    last_daa: sp.p.last_daa,
                };
                let b = view_entry(hw.key, self.genesis, lstate, &tip, sp.low, sp.scanned, sp.boundaries.clone(), sp.sink_blue, sp.blind_below, &ctx);
                match (a, b) {
                    (Some(a), Some(b)) => {
                        let (ra, rb) = (render(self.prefix, &self.cfg.network, self.address(&a), &a), render(self.prefix, &self.cfg.network, self.address(&b), &b));
                        ["status", "balance", "history"].iter().zip(ra.iter().zip(rb.iter())).filter(|(_, (x, y))| x != y).map(|(n, _)| *n).collect::<Vec<_>>()
                    }
                    _ => vec!["view"],
                }
            }
            None => vec![],
        };
        for d in &api {
            diffs.push(match *d {
                "status" => "api:status",
                "balance" => "api:balance",
                "history" => "api:history",
                _ => "api:view",
            });
        }
        // Classify the expected differences (anything else is UNEXPLAINED).
        let live_send = ep != lp && {
            let eset: HashSet<_> = en.iter().chain(ep.iter().map(|p| &p.0)).collect();
            let lset: HashSet<_> = ln.iter().chain(lp.iter().map(|p| &p.0)).collect();
            eset == lset
        };
        serde_json::json!({
            "wallet": pseud,
            "seq": seq,
            "live_daa": sp.scanned,
            "folded": folded,
            "notes": ln.len(),
            "pending": lp.len(),
            "history": sp.p.history.len(),
            "balance_live": sp.p.notes.iter().map(|n| n.value() as u128).sum::<u128>().to_string(),
            "balance_engine": st.notes.iter().map(|n| n.value() as u128).sum::<u128>().to_string(),
            "result": if diffs.is_empty() { "equal" } else if live_send && diffs.iter().all(|d| *d == "pending" || d.starts_with("api:")) { "live-only send event (parked/reclaimed on the live daemon; not a chain event)" } else { "MISMATCH" },
            "diffs": diffs,
        })
    }
}

/// Run the engine host until shutdown: follower + maintenance + read-only API.
pub async fn serve_engine(cfg: EngineConfig, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
    let params = kaspa_consensus_core::config::params::Params::from(state_prefix_network(&cfg.network));
    let genesis = RpcHash::from_bytes(params.genesis.hash.as_bytes());
    COINBASE_SEED_ACTIVATION_DAA.store(params.shielded_coinbase_seed_activation.daa_score(), std::sync::atomic::Ordering::Relaxed);
    MAX_ANCHOR_AGE.store(params.max_shielded_anchor_age(), std::sync::atomic::Ordering::Relaxed);
    SECURITY_FORK_DAA.store(params.security_fork_activation.daa_score(), std::sync::atomic::Ordering::Relaxed);
    let client = loop {
        match GrpcClient::connect_with_args(NotificationMode::Direct, format!("grpc://{}", cfg.rpc_server), None, true, None, false, Some(500_000), Default::default()).await {
            Ok(c) => break c,
            Err(e) => {
                log::warn!("engine: node not reachable ({e}); retrying in 3 s");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    };
    let t_open = std::time::Instant::now();
    // The live daemon's configuration: one process-wide nullifier table, a bitset per database.
    WalletDb::set_default_nullifier_interner(kaspa_shielded_core::walletdb::NullifierInterner::new());
    let tip_size = client.get_shielded_tree_state(None).await.map(|t| t.size).unwrap_or(0);
    let host = tokio::task::block_in_place(|| Host::open(cfg.clone(), genesis, tip_size))?;
    log::info!(
        "engine: store open at seq {} ({} leaves, {} nullifiers) with {} wallets registered, {} waiting for their cursor, in {:.1} s",
        host.store.committed().seq,
        host.store.committed().leaves,
        host.store.committed().nfs,
        host.stats.registered,
        host.pending_at.values().map(|v| v.len()).sum::<usize>(),
        t_open.elapsed().as_secs_f64()
    );
    let host = Arc::new(std::sync::Mutex::new(host));
    // Dormant marks relative to the node tip now.
    if let Ok(info) = client.get_block_dag_info().await {
        let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
        h.tip_daa = info.virtual_daa_score;
        h.marks = cfg.dormant_marks.iter().map(|s| (*s, info.virtual_daa_score.saturating_sub(*s))).collect();
    }
    let app = axum::Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/status", get(engine_status))
        .route("/api/wallet/balance", get(engine_balance))
        .route("/api/wallet/history", get(engine_history))
        .route("/api/wallet/address", get(engine_address))
        .route("/api/engine/stats", get(engine_stats))
        .with_state(host.clone());
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    log::info!("engine: read-only API on {}", cfg.listen);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let compare_log = cfg.engine_dir.join("compare.jsonl");
    let mut last_compare = std::time::Instant::now() - std::time::Duration::from_secs(3600);
    let mut prefetch: Option<tokio::task::JoinHandle<Option<kaspa_rpc_core::GetShieldedBlocksResponse>>> = None;
    let mut prefetch_low = RpcHash::from_bytes([0u8; 32]);
    let free_mb = |p: &Path| -> u64 {
        std::process::Command::new("df")
            .args(["-B1M", "--output=avail"])
            .arg(p)
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().nth(1).and_then(|l| l.trim().parse().ok()))
            .unwrap_or(u64::MAX)
    };
    let mut n_loop = 0u64;
    loop {
        if shutdown.try_recv().is_ok() {
            break;
        }
        n_loop += 1;
        if n_loop % 10 == 1 {
            let f = free_mb(&cfg.engine_dir);
            if f < cfg.min_free_mb {
                log::warn!("engine: only {f} MB free on the engine filesystem (floor {} MB); follower paused", cfg.min_free_mb);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                n_loop = 0;
                continue;
            }
        }
        let low = RpcHash::from_bytes(host.lock().unwrap_or_else(|p| p.into_inner()).store.committed().last_hash);
        let t = std::time::Instant::now();
        let resp = match prefetch.take() {
            Some(h) if prefetch_low == low => h.await.ok().flatten(),
            _ => None,
        };
        let resp = match resp {
            Some(r) => Some(r),
            None => tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_shielded_blocks(low, SHIELDED_PAGE)).await.ok().and_then(|r| r.ok()),
        };
        let rpc_ms = t.elapsed().as_millis() as u64;
        let Some(resp) = resp else {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        if resp.reorged {
            log::error!("engine: the chain reorged below the committed cursor; the follower stops here (no rescan, alarm)");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            continue;
        }
        let settled = resp.sink_blue_score.saturating_sub(SYNC_TIP_MARGIN);
        let stop = cfg.stop_at_daa.unwrap_or(u64::MAX);
        let full = resp.blocks.len() as u64 == SHIELDED_PAGE;
        let raw: Vec<&RpcShieldedChainBlock> = resp.blocks.iter().take_while(|b| b.blue_score <= settled && b.daa_score <= stop).collect();
        // Prefetch the next page while this one is ingested (fetch is the follower's critical path).
        if full && raw.len() == resp.blocks.len() {
            if let Some(next) = resp.blocks.last().map(|b| b.hash) {
                let c = client.clone();
                prefetch_low = next;
                prefetch = Some(tokio::spawn(async move { tokio::time::timeout(SYNC_RPC_TIMEOUT, c.get_shielded_blocks(next, SHIELDED_PAGE)).await.ok().and_then(|r| r.ok()) }));
            }
        }
        let t = std::time::Instant::now();
        let decoded: Result<Vec<DecodedBlock>, String> = tokio::task::block_in_place(|| {
            use rayon::prelude::*;
            raw.par_iter().map(|b| decode_block(b)).collect()
        });
        let decode_ms = t.elapsed().as_millis() as u64;
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => {
                log::warn!("engine: page refused ({e}); retrying");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };
        let at_margin = decoded.len() < resp.blocks.len() || !full;
        {
            let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
            h.sink_blue = resp.sink_blue_score;
            h.stats.rpc_ms += rpc_ms;
            h.stats.decode_ms += decode_ms;
            if !decoded.is_empty() {
                let blocks: Vec<SharedBlock> = decoded.iter().map(shared_block_of).collect();
                if let Err(e) = tokio::task::block_in_place(|| h.ingest(blocks)) {
                    log::error!("engine: {e}");
                    return Err(e);
                }
            }
            if h.stats.pages % 50 == 0 && !decoded.is_empty() {
                let c = h.store.committed();
                log::info!("engine: seq {} daa {} leaves {} nfs {} journal {} B; {:?}", c.seq, c.last_daa, c.leaves, c.nfs, c.journal_len, h.stats);
            }
            h.caught_up = at_margin;
        }
        if at_margin {
            if let Ok(info) = client.get_block_dag_info().await {
                host.lock().unwrap_or_else(|p| p.into_inner()).tip_daa = info.virtual_daa_score;
            }
            maintenance(&host, &client).await;
            if last_compare.elapsed() >= std::time::Duration::from_secs(120) {
                last_compare = std::time::Instant::now();
                let cands = tokio::task::block_in_place(|| host.lock().unwrap_or_else(|p| p.into_inner()).live_candidates());
                let mut tips = Vec::with_capacity(cands.len());
                for (_, sp) in &cands {
                    let t = match sp {
                        Ok(sp) if sp.p.tip.is_none() => client.get_shielded_tree_state(Some(sp.low)).await.ok().map(|ts| kaspa_shielded_core::tree::FrontierState {
                            size: ts.size,
                            leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
                            ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
                        }),
                        _ => None,
                    };
                    tips.push(t);
                }
                let rows = tokio::task::block_in_place(|| host.lock().unwrap_or_else(|p| p.into_inner()).compare_candidates(cands, tips));
                if !rows.is_empty() {
                    use std::io::Write as _;
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&compare_log) {
                        for r in rows {
                            let _ = writeln!(f, "{}", serde_json::json!({"t": now_unix(), "row": r}));
                        }
                    }
                }
            }
            if cfg.stop_at_daa.is_none() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        }
    }
    let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
    for i in 0..h.wallets.len() {
        let _ = h.write_w2(i, false);
    }
    log::info!("engine: stopped at seq {}", h.store.committed().seq);
    Ok(())
}

/// Caught-up chores, as the per-wallet sync loop does them: reclaim lost sends, recover own
/// sends' details from the full transaction (OVK), persist what changed.
async fn maintenance(host: &Arc<std::sync::Mutex<Host>>, client: &GrpcClient) {
    let work: Vec<(usize, Vec<([u8; 32], u64)>)> = {
        let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
        h.reclaim();
        let mut v = Vec::new();
        for i in 0..h.wallets.len() {
            let Some(id) = h.wallets[i].id else { continue };
            let from = h.wallets[i].examined.min(h.engine.wallet(id).history().len());
            let pending = h.engine.wallet(id).unrecovered_sends(from);
            h.wallets[i].examined = h.engine.wallet(id).history().len();
            if !pending.is_empty() {
                v.push((i, pending.into_iter().take(8).collect()));
            }
        }
        v
    };
    for (i, sends) in work {
        for (txid, daa) in sends {
            let chain = {
                let h = host.lock().unwrap_or_else(|p| p.into_inner());
                h.daa_of.binary_search(&daa).ok().and_then(|k| h.store.idx(k as u64 + 1).ok()).map(|e| RpcHash::from_bytes(e.hash))
            };
            let Some(chain) = chain else { continue };
            let Some(bundle) = fetch_bundle_for_tx(client, chain, &txid).await else { continue };
            let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(id) = h.wallets[i].id {
                h.engine.wallet_mut(id).recover_sent_from_bundle(&txid, &bundle);
                h.wallets[i].dirty = true;
            }
        }
    }
    let mut h = host.lock().unwrap_or_else(|p| p.into_inner());
    for i in 0..h.wallets.len() {
        if let Err(e) = h.write_w2(i, false) {
            log::error!("engine: wallet file write failed: {e}");
        }
    }
}

type HostState = State<Arc<std::sync::Mutex<Host>>>;

fn engine_token(h: &Host, headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let t = token_from(headers, false)?;
    if !h.by_token.contains_key(&t) {
        return Err(err(StatusCode::NOT_FOUND, "no wallet in the engine for this token"));
    }
    Ok(t)
}

async fn engine_status(State(host): HostState, headers: HeaderMap) -> Json<StatusResp> {
    let h = host.lock().unwrap_or_else(|p| p.into_inner());
    let mut resp = status_base(&h.cfg.network, true, h.tip_daa);
    if let Ok(token) = engine_token(&h, &headers) {
        if let Some(e) = h.entry(&token) {
            let snap = snap_from_entry(h.address(&e), &e, h.tip_daa);
            fill_status_from_snap(&mut resp, &snap);
            resp.birthday = wallet_birthday_on_disk(&h.cfg.wallet_dir, &token);
            resp.private_sends = private_sends(&h.cfg.wallet_dir, &token);
        } else {
            resp.has_wallet = true;
            resp.loading = true;
        }
    }
    Json(resp)
}

async fn engine_balance(State(host): HostState, Query(query): Query<BalanceQuery>, headers: HeaderMap) -> Result<Json<BalanceResp>, (StatusCode, Json<serde_json::Value>)> {
    let h = host.lock().unwrap_or_else(|p| p.into_inner());
    let token = engine_token(&h, &headers)?;
    let e = h.entry(&token).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "wallet not yet registered in the engine"))?;
    let want_notes = matches!(query.notes.as_deref(), Some("1" | "true" | "yes"));
    Ok(Json(balance_resp(h.prefix, &e, want_notes)))
}

async fn engine_history(State(host): HostState, headers: HeaderMap, Query(query): Query<HistoryQuery>) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let h = host.lock().unwrap_or_else(|p| p.into_inner());
    let token = engine_token(&h, &headers)?;
    let e = h.entry(&token).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "wallet not yet registered in the engine"))?;
    Ok(Json(history_json(h.prefix, &e, query.limit, query.offset)))
}

async fn engine_address(State(host): HostState, headers: HeaderMap, Query(query): Query<AddressQuery>) -> Result<Json<AddressResp>, (StatusCode, Json<serde_json::Value>)> {
    let h = host.lock().unwrap_or_else(|p| p.into_inner());
    let token = engine_token(&h, &headers)?;
    let e = h.entry(&token).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "wallet not yet registered in the engine"))?;
    let index = query.index.unwrap_or(0);
    let address = if index == 0 { h.address(&e) } else { String::from(&Address::new(h.prefix, Version::ShieldedOrchard, &e.db.address_bytes_at(index))) };
    Ok(Json(AddressResp { address, index }))
}

/// Process and engine counters, by pseudonym only.
async fn engine_stats(State(host): HostState) -> Json<serde_json::Value> {
    let h = host.lock().unwrap_or_else(|p| p.into_inner());
    let c = h.store.committed();
    let (chain_heap, wallet_heap) = h.engine.approx_heap_bytes();
    let status_kb = |k: &str| -> u64 {
        std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
    };
    let cpu = {
        let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
        let f: Vec<&str> = s.rsplit_once(") ").map(|x| x.1).unwrap_or("").split_whitespace().collect();
        let g = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        (g(11) + g(12)) / 100.0
    };
    let wallets: Vec<serde_json::Value> = h
        .wallets
        .iter()
        .map(|w| {
            let notes = w.id.map(|id| h.engine.wallet(id).notes().len());
            let twin = w.twin.as_ref().map(|t| serde_json::json!({"blocks": t.blocks, "ingest_ms": (t.ingest_ns / 1_000_000) as u64, "compares": t.compares, "mismatch": t.mismatch, "heap": t.db.approx_heap_bytes()}));
            serde_json::json!({"wallet": log_pseudonym(&w.token), "status": w.status, "notes": notes, "binding": w.binding.as_ref().map(|b| format!("{b:?}")), "twin": twin})
        })
        .collect();
    Json(serde_json::json!({
        "seq": c.seq, "daa": c.last_daa, "leaves": c.leaves, "nfs": c.nfs, "journal_bytes": c.journal_len, "journal_records": c.journal_records,
        "caught_up": h.caught_up, "tip_daa": h.tip_daa, "kernel": h.engine.kernel_name(), "keys": h.engine.key_count(),
        "heap_chain": chain_heap, "heap_wallets": wallet_heap, "rss_kb": status_kb("VmRSS:"), "hwm_kb": status_kb("VmHWM:"), "cpu_s": cpu,
        "stats": h.stats, "engine": format!("{:?}", h.engine.stats()), "wallets": wallets,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::day_diff_tests::{Det, plant_retry, seed_wallet};
    use super::*;
    use kaspa_shielded_core::coinbase::coinbase_note_commitment;
    use orchard::Address as OAddr;
    use orchard::keys::Scope;

    const GEN: [u8; 32] = [3u8; 32];

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zkas-engine-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A synthetic chain of `n` blocks paying wallets `fv` (coinbase to diversified
    /// addresses, receipts, spends of what `held` lists, strangers).
    fn blocks(r: &mut Det, n: usize, daa0: u64, fv: &[FullViewingKey], held: &mut Vec<[u8; 32]>) -> Vec<SharedBlock> {
        let stranger = OAddr::from_raw_address_bytes(&seed_wallet(b"stranger", 1).0.address_bytes_at(3)).unwrap();
        (0..n)
            .map(|k| {
                let daa = daa0 + k as u64;
                let mut coinbase = Vec::new();
                for c in 0..2u8 {
                    let to = if r.next() % 3 == 0 { fv[(r.next() % fv.len() as u64) as usize].address_at((r.next() % 256) as u32, Scope::External).to_raw_address_bytes() } else { stranger.to_raw_address_bytes() };
                    let mut seed = r.b32().to_vec();
                    seed.push(c);
                    let desc = derive_coinbase_note_desc(to, &seed);
                    let v = 1 + r.next() % 1_000_000;
                    if let Ok(cmx) = coinbase_note_commitment(&desc, v) {
                        coinbase.push((desc, v, cmx));
                    }
                }
                let mut txs = Vec::new();
                if !held.is_empty() && r.next() % 4 == 0 {
                    let nf = held.swap_remove((r.next() % held.len() as u64) as usize);
                    let mut a = plant_retry(stranger, 5, r);
                    a.nullifier = nf;
                    txs.push(vec![a, plant_retry(OAddr::from_raw_address_bytes(&fv[0].address_at(2u32, Scope::External).to_raw_address_bytes()).unwrap(), 9, r)]);
                }
                if r.next() % 2 == 0 {
                    let w = (r.next() % fv.len() as u64) as usize;
                    let to = OAddr::from_raw_address_bytes(&fv[w].address_at((r.next() % 300) as u32, Scope::External).to_raw_address_bytes()).unwrap();
                    txs.push(vec![plant_retry(stranger, 2, r), plant_retry(to, 1 + r.next() % 1_000_000, r)]);
                }
                txs.push((0..(r.next() % 3)).map(|_| plant_retry(stranger, 1, r)).collect());
                let txids = txs.iter().map(|_| r.b32()).collect();
                let meta = Some(BlockMeta { coinbase_txid: r.b32(), txids, timestamp_ms: 1_700_000_000_000 + daa, daa_score: daa });
                SharedBlock { hash: r.b32(), blue_score: daa, daa_score: daa, coinbase, txs, meta }
            })
            .collect()
    }

    /// The per-wallet daemon's ingest of one block, as `sync_chunk` does it.
    fn old_ingest(db: &mut WalletDb, ring: &mut VecDeque<(u64, u64)>, b: &SharedBlock) {
        let acts: Vec<CompactActionRecord> = b.txs.iter().flatten().copied().collect();
        db.predecrypt_page(&acts);
        db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, b.meta.as_ref());
        db.end_page();
        ring.push_back((b.blue_score, db.size()));
        if ring.len() > MATURED_RING {
            ring.pop_front();
        }
    }

    fn ctx() -> EntryContext {
        EntryContext { chain_len: 50_000, caught_up: true, sink_live: true, updated_unix: 7, spend_fast_ready: true }
    }

    fn cfg(wallet_dir: &Path, engine_dir: &Path) -> EngineConfig {
        EngineConfig {
            rpc_server: String::new(),
            listen: "127.0.0.1:0".parse().unwrap(),
            wallet_dir: wallet_dir.to_str().unwrap().to_string(),
            engine_dir: engine_dir.to_path_buf(),
            network: "mainnet".into(),
            wallet_secret: None,
            compare_live_dir: None,
            stop_at_daa: None,
            dormant_marks: Vec::new(),
            archive: true,
            twin_max_mb: 1000,
            min_free_mb: 0,
        }
    }

    /// End to end without a node: two wallets' per-wallet databases scan part of a chain and
    /// write REAL `.scan` checkpoints at different cursors; the engine host opens an empty
    /// store, sees both wallets waiting, follows the whole chain, registers each at exactly
    /// its cursor (size + frontier + every note bound), and folds the rest. The per-wallet
    /// databases keep scanning to the end. Then: notes/pending/history/clock equal, and
    /// `/api/status`, `/api/wallet/balance?notes=1`, `/api/wallet/history` byte-identical
    /// through the shared renderers. Then a restart: the host reopens from its files and
    /// answers the same bytes.
    #[test]
    fn host_migrates_at_the_cursor_follows_and_serves_byte_identical_answers() {
        let genesis = RpcHash::from_bytes(GEN);
        let wdir = tmp("w");
        let edir = tmp("e");
        let tokens = ["e2testwalletA0123456789abcdef001", "e2testwalletB0123456789abcdef002"];
        let seeds: Vec<[u8; 32]> = (0..2).map(|i| seed_wallet(b"e2-host", i).1).collect();
        let fv: Vec<FullViewingKey> = seeds.iter().map(|s| WalletDb::from_seed(*s).unwrap().fvk().clone()).collect();
        // Built in segments so later blocks spend notes the wallets really hold on this chain.
        let cut = [37usize, 61];
        let mut r = Det::from(&[b"e2-host-chain"]);
        let mut chain: Vec<SharedBlock> = Vec::new();
        let mut scratch: Vec<(WalletDb, VecDeque<(u64, u64)>)> = seeds.iter().map(|s| (WalletDb::from_seed(*s).unwrap(), VecDeque::new())).collect();
        for seg in 0..4u64 {
            let mut held: Vec<[u8; 32]> = scratch.iter().flat_map(|(d, _)| d.notes().iter().map(|n| n.nullifier()).collect::<Vec<_>>()).collect();
            let bs = blocks(&mut r, 30, 1000 + seg * 30, &fv, &mut held);
            for b in &bs {
                for (d, rg) in scratch.iter_mut() {
                    old_ingest(d, rg, b);
                }
            }
            chain.extend(bs);
        }
        drop(scratch);
        let mut old: Vec<(WalletDb, VecDeque<(u64, u64)>)> = seeds.iter().map(|s| (WalletDb::from_seed(*s).unwrap(), VecDeque::new())).collect();
        for (w, t) in tokens.iter().enumerate() {
            save_seed(wdir.to_str().unwrap(), t, "mainnet", &seeds[w], 0, None).unwrap();
        }
        for (k, b) in chain.iter().enumerate() {
            for (w, (db, ring)) in old.iter_mut().enumerate() {
                old_ingest(db, ring, b);
                if k + 1 == cut[w] {
                    // A pending spend in the checkpoint, as a send would leave it.
                    if let Some(p) = db.notes().first().map(|n| n.position) {
                        db.mark_spent(p, [9u8; 32], b.daa_score);
                    }
                    let parts = checkpoint_bytes(0, &genesis, &RpcHash::from_bytes(b.hash), b.daa_score, db, ring, b.blue_score + 300, 0);
                    write_checkpoint_bytes(wdir.to_str().unwrap(), tokens[w], &parts).unwrap();
                }
            }
        }
        let n_notes: usize = old.iter().map(|(d, _)| d.notes().len() + d.pending_spends().len()).sum();
        assert!(n_notes > 6, "non-vacuous ({n_notes} notes)");
        let mut host = Host::open(cfg(&wdir, &edir), genesis, 0).unwrap();
        assert_eq!(host.pending_at.values().map(|v| v.len()).sum::<usize>(), 2, "both wallets wait for their cursor");
        host.ingest(chain[..50].to_vec()).unwrap();
        host.ingest(chain[50..].to_vec()).unwrap();
        for (w, t) in tokens.iter().enumerate() {
            let hw = &host.wallets[host.by_token[*t]];
            assert_eq!(hw.status, "migrated", "wallet {w}");
            let b = hw.binding.as_ref().unwrap();
            assert!(b.clean() && b.frontier_ok == Some(true) && b.notes > 0, "wallet {w}: {b:?}");
            let (db, ring) = &old[w];
            let lw = host.engine.wallet(hw.id.unwrap());
            let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
            assert_eq!(db.notes().iter().map(nk).collect::<Vec<_>>(), lw.notes().iter().map(nk).collect::<Vec<_>>(), "wallet {w} notes");
            assert_eq!(db.pending_spends().len(), lw.pending_spends().len(), "wallet {w} pending");
            assert_eq!(format!("{:?}", db.history()), format!("{:?}", lw.history()), "wallet {w} history");
            assert_eq!(db.last_daa(), lw.last_daa(), "wallet {w} clock");
            assert_eq!(*ring, host.ring, "wallet {w} boundary ring");
            // The API, through the same renderers.
            let key = WalletKey::Seed(seeds[w]);
            let sink = chain.last().unwrap().blue_score + 300;
            let low = RpcHash::from_bytes(chain.last().unwrap().hash);
            let scanned = chain.last().unwrap().daa_score;
            let db_full = {
                let mut d = WalletDb::from_seed(seeds[w]).unwrap();
                let mut rg = VecDeque::new();
                for (k, b) in chain.iter().enumerate() {
                    old_ingest(&mut d, &mut rg, b);
                    if k + 1 == cut[w] {
                        if let Some(p) = d.notes().first().map(|n| n.position) {
                            d.mark_spent(p, [9u8; 32], b.daa_score);
                        }
                    }
                }
                d
            };
            let mut eo = WalletEntry::from_parts(key, true, db_full, genesis, low, scanned as usize, ring.clone(), sink);
            apply_context(&mut eo, &ctx());
            host.sink_blue = sink;
            let mut en = host.entry(t).unwrap();
            apply_context(&mut en, &ctx());
            let ro = render(host.prefix, "mainnet", host.address(&eo), &eo);
            let rn = render(host.prefix, "mainnet", host.address(&en), &en);
            for (name, (a, b)) in ["status", "balance", "history"].iter().zip(ro.iter().zip(rn.iter())) {
                assert!(a == b, "wallet {w}: /api {name} differs:\nold {}\nnew {}", String::from_utf8_lossy(a), String::from_utf8_lossy(b));
            }
            assert!(rn[1].len() > 100 && rn[2].len() > 100, "non-vacuous answers");
        }
        // Restart: everything from the files.
        let before: Vec<[Vec<u8>; 3]> = tokens
            .iter()
            .map(|t| {
                let mut e = host.entry(t).unwrap();
                apply_context(&mut e, &ctx());
                render(host.prefix, "mainnet", host.address(&e), &e)
            })
            .collect();
        let sink = host.sink_blue;
        drop(host);
        let mut host = Host::open(cfg(&wdir, &edir), genesis, 0).unwrap();
        host.sink_blue = sink;
        for (w, t) in tokens.iter().enumerate() {
            assert_eq!(host.wallets[host.by_token[*t]].status, "resumed");
            let mut e = host.entry(t).unwrap();
            apply_context(&mut e, &ctx());
            assert!(render(host.prefix, "mainnet", host.address(&e), &e) == before[w], "wallet {w}: answers after a restart");
        }
        // The engine never wrote to the wallet directory.
        let mut names: Vec<String> = std::fs::read_dir(&wdir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names.len(), 4, "only the two .json and two .scan files: {names:?}");
        let _ = std::fs::remove_dir_all(&wdir);
        let _ = std::fs::remove_dir_all(&edir);
    }

    /// The private reader against the full restore on real checkpoint bytes, intact and
    /// damaged: same notes, pending, history, clock, cursor, ring, sink, blind; refused
    /// wherever the restore refuses inside the sections it reads.
    #[test]
    fn scan_private_reader_matches_the_restore_and_its_refusals() {
        let genesis = RpcHash::from_bytes(GEN);
        let dir = tmp("rd");
        let (mut db, seed) = seed_wallet(b"e2-reader", 0);
        let fv = vec![db.fvk().clone()];
        let mut r = Det::from(&[b"e2-reader"]);
        let mut ring = VecDeque::new();
        for b in blocks(&mut r, 40, 500, &fv, &mut Vec::new()) {
            old_ingest(&mut db, &mut ring, &b);
        }
        if let Some(p) = db.notes().first().map(|n| n.position) {
            db.mark_spent(p, [1u8; 32], 520);
        }
        assert!(!db.notes().is_empty() && !db.history().is_empty());
        let parts = checkpoint_bytes(0, &genesis, &RpcHash::from_bytes([4u8; 32]), 539, &db, &ring, 900, 77);
        write_checkpoint_bytes(dir.to_str().unwrap(), "tok", &parts).unwrap();
        let path = PathBuf::from(scan_path(dir.to_str().unwrap(), "tok"));
        let bytes = std::fs::read(&path).unwrap();
        let key = WalletKey::Seed(seed);
        let check = |b: &[u8]| -> (bool, bool) {
            std::fs::write(&path, b).unwrap();
            let old = parse_scan_bytes(b, key, None, None);
            let new = read_scan_private(&path);
            if let (Some((g, (d, low, scanned, rg, sink, blind))), Ok(sp)) = (&old, &new) {
                let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
                assert_eq!(*g, sp.genesis);
                assert_eq!((*low, *scanned as u64, rg.clone(), *sink, *blind), (sp.low, sp.scanned, sp.boundaries.clone(), sp.sink_blue, sp.blind_below));
                assert_eq!(d.notes().iter().map(nk).collect::<Vec<_>>(), sp.p.notes.iter().map(nk).collect::<Vec<_>>());
                assert_eq!(d.pending_spends().iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>(), sp.p.pending.iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>());
                assert_eq!(format!("{:?}", d.history()), format!("{:?}", sp.p.history));
                assert_eq!(d.last_daa(), sp.p.last_daa);
                assert_eq!(d.size(), sp.p.size);
                assert_eq!(d.tip_frontier_state(), sp.p.tip);
                assert!(sp.bytes_read < sp.file_len);
            }
            (old.is_some(), new.is_ok())
        };
        assert_eq!(check(&bytes), (true, true));
        // Truncations anywhere: both refuse.
        for cut in [10usize, 80, 200, bytes.len() / 2, bytes.len() - 9, bytes.len() - 1] {
            assert_eq!(check(&bytes[..cut]), (false, false), "cut at {cut}");
        }
        // A trailing byte: both refuse.
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(check(&long), (false, false));
        // Wrong magic / container version: both refuse.
        let mut bad = bytes.clone();
        bad[4] = 9;
        assert_eq!(check(&bad), (false, false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------- real-data harnesses (copies only; need MIGRATE_DIR etc.) ----------------

    fn picks() -> Vec<(String, String)> {
        let f = std::env::var("MIGRATE_PICKS").expect("MIGRATE_PICKS");
        std::fs::read_to_string(f).unwrap().lines().filter_map(|l| l.split_once('\t')).map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn rss_kb() -> u64 {
        std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    /// T1: every copy, old full restore vs the private reader, field by field and through the
    /// API renderers (byte-identical). Prints pseudonyms and counts only.
    #[test]
    #[ignore = "real checkpoint copies: MIGRATE_DIR, MIGRATE_PICKS"]
    fn migrate_real_copies() {
        let dir = std::env::var("MIGRATE_DIR").expect("MIGRATE_DIR");
        let genesis = RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
        MAX_ANCHOR_AGE.store(kaspa_consensus_core::config::params::MAINNET_PARAMS.max_shielded_anchor_age(), std::sync::atomic::Ordering::Relaxed);
        let prefix = prefix_from("mainnet");
        // The node frontier at each cursor (read-only RPC), as the load path binds a checkpoint.
        let rpc = std::env::var("MIGRATE_RPC").ok();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let client = rpc.as_ref().map(|r| rt.block_on(super::super::day_diff_tests::connect(r)));
        let (mut ok, mut n) = (0, 0);
        for (id, token) in picks() {
            n += 1;
            let path = PathBuf::from(scan_path(&dir, &token));
            let (key, _, _) = load_wallet_meta(&dir, &token, None).expect("key");
            let t = std::time::Instant::now();
            let sp = read_scan_private(&path);
            let new_ms = t.elapsed().as_secs_f64() * 1e3;
            let node_tip = match (&client, &sp) {
                (Some(c), Ok(sp)) => rt.block_on(c.get_shielded_tree_state(Some(sp.low))).ok().map(|ts| super::super::day_diff_tests::frontier(&ts)),
                _ => None,
            };
            let rss0 = rss_kb();
            let t = std::time::Instant::now();
            let buf = std::fs::read(&path).unwrap();
            let old = parse_scan_bytes(&buf, key, node_tip.as_ref(), None);
            let old_ms = t.elapsed().as_secs_f64() * 1e3;
            let old_rss = rss_kb().saturating_sub(rss0);
            drop(buf);
            let (Some((g, (db, low, scanned, ring, sink, blind))), Ok(sp)) = (old, sp) else {
                println!("MIGRATE {id} REFUSED old/new");
                continue;
            };
            let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
            let mut diffs = Vec::new();
            if g != sp.genesis || low != sp.low || scanned as u64 != sp.scanned {
                diffs.push("header");
            }
            if ring != sp.boundaries || sink != sp.sink_blue || blind != sp.blind_below {
                diffs.push("trailer");
            }
            if db.notes().iter().map(nk).collect::<Vec<_>>() != sp.p.notes.iter().map(nk).collect::<Vec<_>>() {
                diffs.push("notes");
            }
            if db.pending_spends().iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>() != sp.p.pending.iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>() {
                diffs.push("pending");
            }
            if format!("{:?}", db.history()) != format!("{:?}", sp.p.history) {
                diffs.push("history");
            }
            if db.last_daa() != sp.p.last_daa || db.size() != sp.p.size || (sp.p.tip.is_some() && db.tip_frontier_state() != sp.p.tip) {
                diffs.push("clock/size/frontier");
            }
            let (notes, hist, pend, size, ver) = (sp.p.notes.len(), sp.p.history.len(), sp.p.pending.len(), sp.p.size, sp.p.version);
            let heap = db.approx_heap_bytes();
            let node_bound = node_tip.as_ref().map(|t| t.size == sp.p.size);
            let api = match sp.p.tip.clone().or(node_tip.clone()) {
                Some(tip) => {
                    let mut eo = WalletEntry::from_parts(key, true, db, g, low, scanned, ring, sink);
                    apply_context(&mut eo, &ctx());
                    eo.blind_below = blind;
                    let st = WalletState { notes: sp.p.notes.clone(), pending_spends: sp.p.pending.clone(), history: sp.p.history.clone(), history_enabled: true, last_daa: sp.p.last_daa };
                    let en = view_entry(key, g, st, &tip, sp.low, sp.scanned, sp.boundaries.clone(), sp.sink_blue, sp.blind_below, &ctx()).unwrap();
                    let addr = |e: &WalletEntry| String::from(&Address::new(prefix, Version::ShieldedOrchard, &e.db.my_address_bytes()));
                    let (a, b) = (render(prefix, "mainnet", addr(&eo), &eo), render(prefix, "mainnet", addr(&en), &en));
                    if a == b { "identical" } else { "DIFFERENT" }
                }
                None => "no tip frontier recorded",
            };
            if api == "DIFFERENT" {
                diffs.push("api");
            }
            if diffs.is_empty() {
                ok += 1;
            }
            println!(
                "MIGRATE {id} v{ver} file={:.1}MB read={:.3}MB ({:.4}%) notes={notes} pending={pend} history={hist} size={size} old_restore={old_ms:.0}ms old_rss+={:.0}MB old_heap={:.0}MB reader={new_ms:.1}ms tip={} node_bound={node_bound:?} api={api} genesis_ok={} diffs={diffs:?}",
                sp.file_len as f64 / 1e6,
                sp.bytes_read as f64 / 1e6,
                100.0 * sp.bytes_read as f64 / sp.file_len as f64,
                old_rss as f64 / 1024.0,
                heap as f64 / 1048576.0,
                if sp.p.tip.is_some() { "recorded" } else { "none (borrowing writer)" },
                g == genesis
            );
        }
        println!("MIGRATE SUMMARY {ok}/{n} equal");
        assert_eq!(ok, n, "every copy must read identically");
    }

    /// T2: catch-up equality on real data. For every copy the engine migrated (its `.t0.w2`
    /// in CATCHUP_STORE), the OLD per-wallet path restores the same copy and ingests the
    /// stored blocks from its cursor to the store's end; the engine replays its journal from
    /// the migration point. Equal notes, pending, history, clock; timings for both.
    #[test]
    #[ignore = "real copies + a built engine store: MIGRATE_DIR, MIGRATE_PICKS, CATCHUP_STORE"]
    fn catchup_old_path_vs_engine_journal() {
        let dir = std::env::var("MIGRATE_DIR").expect("MIGRATE_DIR");
        let store_dir = std::env::var("CATCHUP_STORE").expect("CATCHUP_STORE");
        let max_mb: u64 = std::env::var("CATCHUP_MAX_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(u64::MAX);
        let genesis = RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
        COINBASE_SEED_ACTIVATION_DAA.store(kaspa_consensus_core::config::params::MAINNET_PARAMS.shielded_coinbase_seed_activation.daa_score(), std::sync::atomic::Ordering::Relaxed);
        let store = ChainStore::open_readonly(Path::new(&store_dir), genesis.as_bytes()).expect("store");
        let end = store.committed().seq;
        let (mut ok, mut n) = (0, 0);
        for (id, token) in picks() {
            let path = PathBuf::from(scan_path(&dir, &token));
            let file_mb = std::fs::metadata(&path).map(|m| m.len() / 1_000_000).unwrap_or(0);
            let name = hex16(&wallet_key16(&token));
            let Ok(t0b) = std::fs::read(store.wallet_path(&format!("{name}.t0"))) else {
                println!("CATCHUP {id} not migrated by the engine (no t0)");
                continue;
            };
            if file_mb > max_mb {
                println!("CATCHUP {id} skipped ({file_mb} MB > CATCHUP_MAX_MB)");
                continue;
            }
            n += 1;
            let (h, s0) = decode_w2(&t0b).unwrap();
            let (key, _, _) = load_wallet_meta(&dir, &token, None).expect("key");
            let fvk = fvk_of(&key).unwrap();
            // Engine: migrated state + its journal.
            let t = std::time::Instant::now();
            let mut w = WalletLite::new(fvk, s0, h.size, h.seq, h.key16);
            let (folded, _) = store.catch_up(&mut w, h.journal_off).unwrap();
            let eng_ms = t.elapsed().as_secs_f64() * 1e3;
            // Old path: full restore + ingest every stored block after the cursor.
            let t = std::time::Instant::now();
            let buf = std::fs::read(&path).unwrap();
            let (_, (mut db, _low, _sc, _ring, _sink, _blind)) = parse_scan_bytes(&buf, key, None, None).expect("restore");
            drop(buf);
            let load_ms = t.elapsed().as_secs_f64() * 1e3;
            assert_eq!(db.size(), h.size, "{id}: the old checkpoint's size at its cursor");
            let t = std::time::Instant::now();
            let mut seq = h.seq + 1;
            let mut actions = 0usize;
            while seq <= end {
                let to = (seq + 999).min(end);
                let page = store.blocks(seq, to).unwrap();
                let acts: Vec<CompactActionRecord> = page.iter().flat_map(|b| b.txs.iter().flatten().copied()).collect();
                actions += acts.len();
                db.predecrypt_page(&acts);
                for b in &page {
                    db.ingest_block_compact_precomputed_with_meta(&b.coinbase, &b.txs, b.meta.as_ref());
                }
                db.end_page();
                seq = to + 1;
            }
            let old_ms = t.elapsed().as_secs_f64() * 1e3;
            let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
            let mut diffs = Vec::new();
            if db.notes().iter().map(nk).collect::<Vec<_>>() != w.notes().iter().map(nk).collect::<Vec<_>>() {
                diffs.push("notes");
            }
            if db.pending_spends().iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>() != w.pending_spends().iter().map(|p| (nk(&p.note), p.txid, p.submitted_daa)).collect::<Vec<_>>() {
                diffs.push("pending");
            }
            if format!("{:?}", db.history()) != format!("{:?}", w.history()) {
                diffs.push("history");
            }
            if db.last_daa() != w.last_daa() {
                diffs.push("clock");
            }
            if db.size() != store.committed().leaves {
                diffs.push("tree size");
            }
            if diffs.is_empty() {
                ok += 1;
            }
            println!(
                "CATCHUP {id} blocks={} actions={actions} notes={} history={} engine_replay={eng_ms:.1}ms ({folded} records) old_load={load_ms:.0}ms old_ingest={old_ms:.0}ms old_heap={:.0}MB diffs={diffs:?}",
                end - h.seq,
                w.notes().len(),
                w.history().len(),
                db.approx_heap_bytes() as f64 / 1048576.0
            );
        }
        println!("CATCHUP SUMMARY {ok}/{n} equal");
        assert_eq!(ok, n);
    }

    /// T3: dormant catch-up from the hit journal: each wallet's snapshot from `markS` (taken
    /// when the follower passed tip − S seconds) + the journal since must equal its current
    /// file; time-to-tip measured.
    #[test]
    #[ignore = "a built engine store with dormant marks: CATCHUP_STORE, MIGRATE_DIR, MIGRATE_PICKS"]
    fn dormant_catchup_from_the_journal() {
        let dir = std::env::var("MIGRATE_DIR").expect("MIGRATE_DIR");
        let store_dir = std::env::var("CATCHUP_STORE").expect("CATCHUP_STORE");
        let genesis = RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
        let store = ChainStore::open_readonly(Path::new(&store_dir), genesis.as_bytes()).expect("store");
        let marks: Vec<u64> = std::env::var("DORMANT_MARKS").unwrap_or_else(|_| "86400,604800,2592000".into()).split(',').filter_map(|v| v.parse().ok()).collect();
        let (mut ok, mut n) = (0, 0);
        for (id, token) in picks() {
            let name = hex16(&wallet_key16(&token));
            let Ok(cur) = std::fs::read(store.wallet_path(&name)) else { continue };
            let (ch, cs) = decode_w2(&cur).unwrap();
            let (key, _, _) = load_wallet_meta(&dir, &token, None).expect("key");
            let fvk = fvk_of(&key).unwrap();
            let mut now = WalletLite::new(fvk.clone(), cs, ch.size, ch.seq, ch.key16);
            store.catch_up(&mut now, ch.journal_off).unwrap();
            for m in &marks {
                let Ok(b) = std::fs::read(store.wallet_path(&format!("{name}.mark{m}"))) else { continue };
                n += 1;
                let t = std::time::Instant::now();
                let (h, s) = decode_w2(&b).unwrap();
                let mut w = WalletLite::new(fvk.clone(), s, h.size, h.seq, h.key16);
                let (folded, _) = store.catch_up(&mut w, h.journal_off).unwrap();
                let ms = t.elapsed().as_secs_f64() * 1e3;
                let nk = |n: &OwnedNote| (n.position, n.value(), n.nullifier());
                let equal = w.notes().iter().map(nk).collect::<Vec<_>>() == now.notes().iter().map(nk).collect::<Vec<_>>()
                    && format!("{:?}", w.history()) == format!("{:?}", now.history())
                    && w.last_daa() == now.last_daa()
                    && w.pending_spends().len() == now.pending_spends().len();
                if equal {
                    ok += 1;
                }
                println!(
                    "DORMANT {id} idle={}d blocks={} journal_bytes={} records={folded} time_to_tip={ms:.2}ms equal={equal}",
                    m / 86400,
                    store.committed().seq - h.seq,
                    store.committed().journal_len - h.journal_off
                );
            }
        }
        println!("DORMANT SUMMARY {ok}/{n} equal");
        assert_eq!(ok, n);
    }
}
