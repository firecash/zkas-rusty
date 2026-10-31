//! Chain files: the shielded chain published as immutable 12-hour segments.
//!
//! Every wallet used to pull the same public chain from a node, page by page. Measured on the
//! public node (2026-10-31): a page costs the node 0.25-0.46 ms per block to assemble, the node
//! saturates at ~5,000 blocks/s however many pages are in flight (4 cores), and every phone
//! shares that one ceiling. Through the network a page also pays ~2 round trips, and the
//! linked-cursor paging can overlap only one page ahead.
//!
//! These files move that work off the node. One exporter, beside a node that validated its
//! shielded history itself (the archival node), writes each 12-hour DAA window once as an
//! immutable segment; nginx and any CDN serve the same bytes to everyone. A wallet reads a
//! segment in one request and the sync loop is fed from it exactly as it is fed from the node:
//! [`ChainFiles::page`] answers the same `(cursor, limit)` question `GetShieldedBlocks` does,
//! so reorg handling, the settlement margin, previews and checkpoints are all unchanged. The
//! node still serves everything newer than the newest segment.
//!
//! **Integrity.** A segment carries the tree frontier at its start and end block, both read
//! from the node with the frontier locator. The exporter publishes a segment only after
//! re-ingesting it with the wallet's own leaf rules (a leaves-only `WalletDb`) from the start
//! frontier and reproducing the end frontier exactly. The manifest lists every file's SHA-256,
//! and a wallet discards any file whose bytes differ — a mirror or CDN cannot alter, drop or
//! reorder anything. In this first form the wallet still builds its own tree from the leaves,
//! so its checkpoints and spends are verified against the node exactly as before.
//!
//! Everything here is optional: a missing manifest, a bad file, a cursor no segment covers or
//! a Tor-routed engine (the file fetch must not bypass the proxy) all fall back to the node.

use kaspa_rpc_core::{GetShieldedBlocksResponse, RpcHash, RpcShieldedChainBlock, RpcShieldedCoinbaseOutput};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Width of a segment in DAA units: 12 hours at 1 block per second.
pub const SEGMENT_DAA: u64 = 43_200;
/// A segment ends at least this far below the tip when it is exported (2 hours), far past any
/// reorg on this chain.
pub const EXPORT_TIP_MARGIN_DAA: u64 = 7_200;
/// Segments kept decoded in memory: the one being ingested and one read ahead. A decoded
/// 12-hour segment is ~100 MB of block structures (measured on the phone configuration), so
/// on a phone this is the bound that matters.
const LOADED_SEGMENTS: usize = 2;
/// How long a fetched manifest is trusted before it is fetched again.
const MANIFEST_TTL: std::time::Duration = std::time::Duration::from_secs(600);
const MAGIC: &[u8; 8] = b"ZKASSEG1";
const MANIFEST_VERSION: u32 = 1;

/// A tree frontier at a chain block: where a segment starts or ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub block: String,
    pub daa: u64,
    pub size: u64,
    pub leaf: String,
    pub ommers: Vec<String>,
}

impl Boundary {
    pub fn hash(&self) -> Option<RpcHash> {
        self.block.parse().ok()
    }

    pub fn frontier_state(&self) -> Option<kaspa_shielded_core::tree::FrontierState> {
        let leaf: RpcHash = self.leaf.parse().ok()?;
        let ommers = self.ommers.iter().map(|o| o.parse::<RpcHash>().ok().map(|h| h.as_bytes())).collect::<Option<Vec<_>>>()?;
        Some(kaspa_shielded_core::tree::FrontierState { size: self.size, leaf: (self.size > 0).then(|| leaf.as_bytes()), ommers })
    }

    fn from_tree_state(ts: &kaspa_rpc_core::GetShieldedTreeStateResponse) -> Self {
        Self {
            block: ts.block_hash.to_string(),
            daa: ts.daa_score,
            size: ts.size,
            leaf: ts.leaf.to_string(),
            ommers: ts.ommers.iter().map(|o| o.to_string()).collect(),
        }
    }

    fn same_frontier(&self, fs: &kaspa_shielded_core::tree::FrontierState) -> bool {
        self.frontier_state().is_some_and(|mine| mine.size == fs.size && mine.leaf == fs.leaf && mine.ommers == fs.ommers)
    }
}

/// One published segment, as listed in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentEntry {
    /// Segment `index` covers the selected chain strictly after `from` up to and including `to`;
    /// `from` is the block the frontier locator places below DAA `index * SEGMENT_DAA`.
    pub index: u64,
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    pub blocks: u64,
    pub from: Boundary,
    pub to: Boundary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub zkas_chain_files: u32,
    pub genesis: String,
    pub segment_daa: u64,
    pub segments: Vec<SegmentEntry>,
}

impl Manifest {
    fn check(&self, genesis: &RpcHash) -> Result<(), String> {
        if self.zkas_chain_files != MANIFEST_VERSION {
            return Err(format!("unsupported manifest version {}", self.zkas_chain_files));
        }
        if self.genesis.parse::<RpcHash>().ok().as_ref() != Some(genesis) {
            return Err("manifest is for another network".into());
        }
        if self.segment_daa != SEGMENT_DAA {
            return Err(format!("segment width {} != {SEGMENT_DAA}", self.segment_daa));
        }
        Ok(())
    }
}

/// Where ZKas publishes its chain files.
pub const PUBLIC_CHAIN_FILES: &str = "https://zkas.info/shielded-chain";

/// The chain files an engine talking to `node` should use: the public ones when `node` is one
/// of ZKas's public nodes — the same operator already sees that engine's page requests, so no
/// new party learns anything — and none otherwise. A user's own node is never paired with a
/// server the user did not choose. Callers must also leave them off when the engine is routed
/// through Tor (the file fetch does not use that proxy).
pub fn default_for_node(node: &str) -> Option<String> {
    let node = node.trim().to_ascii_lowercase();
    let host = match node.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or("").to_string(),
        None => node.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(node.clone()),
    };
    let public = host == "zkas.info" || host.ends_with(".zkas.info") || ["185.147.157.125", "160.187.211.153"].contains(&host.as_str());
    public.then(|| PUBLIC_CHAIN_FILES.to_string())
}

// ---------------------------------------------------------------------------------------------
// Segment file format: gzip( MAGIC | genesis 32 | index u64 | block count u32 | blocks ).
// Each block: hash 32 | blue u64 | daa u64 | timestamp u64 | coinbase txid 32 |
//   outputs u32 { script len u16 | script | value u64 | has commitment u8 | [commitment 32] } |
//   actions u32 { len u32 | bytes } | txids u32 { 32 }.
// The coinbase commitment is kept (the node's own binary RPC encoding drops it).
// ---------------------------------------------------------------------------------------------

fn put_u16(w: &mut Vec<u8>, v: u16) {
    w.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_le_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or("truncated segment")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn hash(&mut self) -> Result<RpcHash, String> {
        Ok(RpcHash::from_bytes(self.take(32)?.try_into().unwrap()))
    }
}

pub fn encode_segment(genesis: &RpcHash, index: u64, blocks: &[RpcShieldedChainBlock]) -> Vec<u8> {
    let mut w = Vec::with_capacity(blocks.len() * 512);
    w.extend_from_slice(MAGIC);
    w.extend_from_slice(&genesis.as_bytes());
    put_u64(&mut w, index);
    put_u32(&mut w, blocks.len() as u32);
    encode_blocks(&mut w, blocks);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    gz.write_all(&w).expect("writing to a Vec cannot fail");
    gz.finish().expect("writing to a Vec cannot fail")
}

/// SHA-256 over the canonical encoding of `blocks`: equal exactly when every field of every
/// block is equal, commitments included. How a page read from files is compared with the node.
pub fn blocks_digest(blocks: &[RpcShieldedChainBlock]) -> [u8; 32] {
    let mut w = Vec::with_capacity(blocks.len() * 512);
    encode_blocks(&mut w, blocks);
    Sha256::digest(&w).into()
}

fn encode_blocks(w: &mut Vec<u8>, blocks: &[RpcShieldedChainBlock]) {
    for b in blocks {
        w.extend_from_slice(&b.hash.as_bytes());
        put_u64(w, b.blue_score);
        put_u64(w, b.daa_score);
        put_u64(w, b.timestamp);
        w.extend_from_slice(&b.coinbase_txid.as_bytes());
        put_u32(w, b.coinbase_outputs.len() as u32);
        for o in &b.coinbase_outputs {
            put_u16(w, o.script_public_key.len() as u16);
            w.extend_from_slice(&o.script_public_key);
            put_u64(w, o.value);
            match o.commitment {
                Some(c) => {
                    w.push(1);
                    w.extend_from_slice(&c);
                }
                None => w.push(0),
            }
        }
        put_u32(w, b.accepted_actions.len() as u32);
        for a in &b.accepted_actions {
            put_u32(w, a.len() as u32);
            w.extend_from_slice(a);
        }
        put_u32(w, b.accepted_txids.len() as u32);
        for t in &b.accepted_txids {
            w.extend_from_slice(&t.as_bytes());
        }
    }
}

/// Decompress a segment file and check its header: for `genesis`, segment `index`. Returns the
/// block-record bytes and the block count.
fn segment_body(file: &[u8], genesis: &RpcHash, index: u64) -> Result<(Vec<u8>, usize), String> {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(file).read_to_end(&mut raw).map_err(|e| format!("gzip: {e}"))?;
    let mut r = Reader { b: &raw, at: 0 };
    if r.take(8)? != MAGIC {
        return Err("not a segment file".into());
    }
    if &r.hash()? != genesis {
        return Err("segment is for another network".into());
    }
    if r.u64()? != index {
        return Err("segment index does not match the manifest".into());
    }
    let n = r.u32()? as usize;
    let at = r.at;
    raw.drain(..at);
    Ok((raw, n))
}

fn read_block(r: &mut Reader<'_>) -> Result<RpcShieldedChainBlock, String> {
    let hash = r.hash()?;
    let blue_score = r.u64()?;
    let daa_score = r.u64()?;
    let timestamp = r.u64()?;
    let coinbase_txid = r.hash()?;
    let outputs = r.u32()? as usize;
    let mut coinbase_outputs = Vec::with_capacity(outputs.min(4096));
    for _ in 0..outputs {
        let len = r.u16()? as usize;
        let script_public_key = r.take(len)?.to_vec();
        let value = r.u64()?;
        let commitment = match r.take(1)?[0] {
            0 => None,
            1 => Some(<[u8; 32]>::try_from(r.take(32)?).unwrap()),
            _ => return Err("bad commitment flag".into()),
        };
        coinbase_outputs.push(RpcShieldedCoinbaseOutput { script_public_key, value, commitment });
    }
    let actions = r.u32()? as usize;
    let mut accepted_actions = Vec::with_capacity(actions.min(4096));
    for _ in 0..actions {
        let len = r.u32()? as usize;
        accepted_actions.push(r.take(len)?.to_vec());
    }
    let txids = r.u32()? as usize;
    let mut accepted_txids = Vec::with_capacity(txids.min(4096));
    for _ in 0..txids {
        accepted_txids.push(r.hash()?);
    }
    Ok(RpcShieldedChainBlock { hash, blue_score, daa_score, coinbase_txid, coinbase_outputs, accepted_actions, accepted_txids, timestamp })
}

/// Index a segment body without building its blocks: `(hash, daa, byte offset)` per block.
/// Validates every record's framing, so a page later decoded from it cannot run off the end.
fn index_body(body: &[u8], n: usize) -> Result<Vec<(RpcHash, u64, usize)>, String> {
    let mut r = Reader { b: body, at: 0 };
    let mut out = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        let at = r.at;
        let hash = r.hash()?;
        let _blue = r.u64()?;
        let daa = r.u64()?;
        r.take(8 + 32)?;
        for _ in 0..r.u32()? {
            let len = r.u16()? as usize;
            r.take(len + 8)?;
            if r.take(1)?[0] == 1 {
                r.take(32)?;
            }
        }
        for _ in 0..r.u32()? {
            let len = r.u32()? as usize;
            r.take(len)?;
        }
        let txids = r.u32()? as usize;
        r.take(txids * 32)?;
        out.push((hash, daa, at));
    }
    if r.at != body.len() {
        return Err("trailing bytes in segment".into());
    }
    Ok(out)
}

/// Decode a whole segment file (exporter checks and tests; the wallet decodes lazily).
pub fn decode_segment(file: &[u8], genesis: &RpcHash, index: u64) -> Result<Vec<RpcShieldedChainBlock>, String> {
    let (body, n) = segment_body(file, genesis, index)?;
    index_body(&body, n)?;
    let mut r = Reader { b: &body, at: 0 };
    (0..n).map(|_| read_block(&mut r)).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Re-ingest `blocks` with the wallet's own leaf rules (a leaves-only `WalletDb` started at
/// `from`) and require the resulting tree to be exactly `to`. This is what makes a segment
/// publishable: its content reproduces the node's own frontiers under the code every wallet runs.
pub fn verify_segment(from: &Boundary, to: &Boundary, blocks: &[RpcShieldedChainBlock]) -> Result<(), String> {
    let fs = from.frontier_state().ok_or("bad start frontier")?;
    let mut db = kaspa_shielded_core::walletdb::WalletDb::from_frontier([0x5a; 32], &fs).ok_or("start frontier does not build a tree")?;
    db.set_leaves_only(true);
    let mut expect_parent = from.block.clone();
    for b in blocks {
        let d = crate::decode_block(b)?;
        db.ingest_block_compact_precomputed_with_meta(&d.coinbase, &d.compact, None);
        if db.poisoned() {
            return Err(format!("block {} repeats a nullifier", b.hash));
        }
        expect_parent = b.hash.to_string();
    }
    db.end_page();
    if expect_parent != to.block {
        return Err(format!("segment ends at {expect_parent}, not at {}", to.block));
    }
    let got = db.tip_frontier_state().ok_or("no tree after the segment")?;
    if !to.same_frontier(&got) {
        return Err(format!("re-ingested tree has {} leaves, the node's frontier at the end has {}", got.size, to.size));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Exporter
// ---------------------------------------------------------------------------------------------

/// Write every complete segment not yet in `out_dir`, newest first, at most `max_new` of them,
/// then the manifest. Reads from `node`, which must hold frontiers for the whole range (an
/// archival node synced from genesis). Each segment is verified before it is written.
pub async fn export(node: &str, out_dir: &std::path::Path, max_new: usize) -> Result<usize, String> {
    use kaspa_rpc_core::api::rpc::RpcApi;
    let client = kaspa_grpc_client::GrpcClient::connect_with_args(
        kaspa_rpc_core::notify::mode::NotificationMode::Direct,
        format!("grpc://{node}"),
        None,
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .map_err(|e| format!("connect {node}: {e}"))?;
    let genesis = RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes());
    let tip = client.get_block_dag_info().await.map_err(|e| e.to_string())?.virtual_daa_score;
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let manifest_path = out_dir.join("manifest.json");
    let mut manifest = match std::fs::read(&manifest_path) {
        Ok(b) => serde_json::from_slice::<Manifest>(&b).map_err(|e| format!("existing manifest: {e}"))?,
        Err(_) => Manifest { zkas_chain_files: MANIFEST_VERSION, genesis: genesis.to_string(), segment_daa: SEGMENT_DAA, segments: Vec::new() },
    };
    manifest.check(&genesis)?;
    let have: HashSet<u64> = manifest.segments.iter().map(|s| s.index).collect();
    let place = |daa: u64| {
        let c = client.clone();
        async move {
            let req = kaspa_rpc_core::GetShieldedTreeStateRequest { block_hash: None, below_daa_score: Some(daa) };
            let ts = c.get_shielded_tree_state_call(None, req).await.map_err(|e| format!("place {daa}: {e}"))?;
            if ts.daa_score >= daa {
                return Err(format!("node has no frontier locator (placed {daa} at {})", ts.daa_score));
            }
            Ok::<_, String>(Boundary::from_tree_state(&ts))
        }
    };
    // Segment k ends at the block placed below (k + 1) * SEGMENT_DAA, which must clear the margin.
    let last = (tip.saturating_sub(EXPORT_TIP_MARGIN_DAA) / SEGMENT_DAA).saturating_sub(1);
    let mut written = 0usize;
    let mut k = last;
    while k >= 1 && written < max_new {
        if !have.contains(&k) {
            let t0 = std::time::Instant::now();
            let from = place(k * SEGMENT_DAA).await?;
            let to = place((k + 1) * SEGMENT_DAA).await?;
            let to_hash = to.hash().ok_or("bad end hash")?;
            let mut cursor = from.hash().ok_or("bad start hash")?;
            let mut blocks: Vec<RpcShieldedChainBlock> = Vec::new();
            'pages: loop {
                let page = client.get_shielded_blocks(cursor, 2000).await.map_err(|e| format!("segment {k}: {e}"))?;
                if page.reorged {
                    return Err(format!("segment {k}: the node reports a reorg below the cursor"));
                }
                if page.blocks.is_empty() {
                    return Err(format!("segment {k}: reached the tip before the end block"));
                }
                for b in page.blocks {
                    if b.daa_score > to.daa {
                        return Err(format!("segment {k}: passed daa {} without meeting the end block", to.daa));
                    }
                    cursor = b.hash;
                    let end = b.hash == to_hash;
                    blocks.push(b);
                    if end {
                        break 'pages;
                    }
                }
            }
            verify_segment(&from, &to, &blocks).map_err(|e| format!("segment {k} failed verification: {e}"))?;
            let bytes = encode_segment(&genesis, k, &blocks);
            let sha = sha256_hex(&bytes);
            let file = format!("seg-{k:06}-{}.zks", &sha[..16]);
            let tmp = out_dir.join(format!("{file}.tmp"));
            std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, out_dir.join(&file)).map_err(|e| e.to_string())?;
            log::info!(
                "chain files: segment {k} written: {} blocks, {} leaves, {} KB, verified, {:.1} s",
                blocks.len(),
                to.size - from.size,
                bytes.len() / 1024,
                t0.elapsed().as_secs_f64()
            );
            manifest.segments.push(SegmentEntry { index: k, file, sha256: sha, bytes: bytes.len() as u64, blocks: blocks.len() as u64, from, to });
            manifest.segments.sort_by_key(|s| s.index);
            let tmp = out_dir.join("manifest.json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &manifest_path).map_err(|e| e.to_string())?;
            written += 1;
        }
        k -= 1;
    }
    Ok(written)
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// A loaded segment, kept as its raw block records (~10 MB for 12 hours) plus an offset per
/// block; a page decodes only its own blocks. Holding the decoded blocks instead cost ~100 MB
/// per segment (measured: 30 days behind on the phone configuration peaked at 1.27 GB).
struct Loaded {
    index: u64,
    from: RpcHash,
    to: RpcHash,
    to_daa: u64,
    body: Vec<u8>,
    /// Byte offset of each block in `body`, in chain order.
    offsets: Vec<usize>,
    /// Block hash -> its position in `offsets`.
    pos: HashMap<RpcHash, usize>,
}

impl Loaded {
    fn len(&self) -> usize {
        self.offsets.len()
    }
    fn block(&self, i: usize) -> Option<RpcShieldedChainBlock> {
        let mut r = Reader { b: &self.body, at: *self.offsets.get(i)? };
        read_block(&mut r).ok()
    }
}

/// The wallet side: answers page requests from published segments where it can.
pub struct ChainFiles {
    base: String,
    http: Option<reqwest::Client>,
    genesis: RpcHash,
    manifest: tokio::sync::Mutex<Option<(std::time::Instant, Arc<Manifest>)>>,
    loaded: Mutex<VecDeque<Arc<Loaded>>>,
    loading: Mutex<HashSet<u64>>,
    /// The node's sink blue score as last seen, for the settlement margin a page carries.
    sink: AtomicU64,
    /// DAA score of the newest block a page was served up to: segments wholly below it are done.
    cursor_daa: AtomicU64,
    /// Set the first time a file page disagrees with the node: from then on this process
    /// reads everything from the node, so a poisoned source cannot be re-adopted by the
    /// rebuild it triggers.
    disabled: std::sync::atomic::AtomicBool,
    pub pages_served: AtomicU64,
    pub segments_loaded: AtomicU64,
}

impl ChainFiles {
    /// `base` is an `https://…` URL or a local directory holding `manifest.json` and the files.
    pub fn new(base: &str, genesis: RpcHash) -> Arc<Self> {
        let base = base.trim_end_matches('/').to_string();
        let http = (base.starts_with("http://") || base.starts_with("https://"))
            .then(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().ok())
            .flatten();
        Arc::new(Self {
            base,
            http,
            genesis,
            manifest: tokio::sync::Mutex::new(None),
            loaded: Mutex::new(VecDeque::new()),
            loading: Mutex::new(HashSet::new()),
            sink: AtomicU64::new(0),
            cursor_daa: AtomicU64::new(0),
            disabled: std::sync::atomic::AtomicBool::new(false),
            pages_served: AtomicU64::new(0),
            segments_loaded: AtomicU64::new(0),
        })
    }

    async fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        match &self.http {
            Some(c) => {
                let r = c.get(format!("{}/{name}", self.base)).send().await.map_err(|e| e.to_string())?;
                if !r.status().is_success() {
                    return Err(format!("HTTP {}", r.status()));
                }
                Ok(r.bytes().await.map_err(|e| e.to_string())?.to_vec())
            }
            None => tokio::fs::read(format!("{}/{name}", self.base)).await.map_err(|e| e.to_string()),
        }
    }

    async fn manifest(&self) -> Option<Arc<Manifest>> {
        let mut m = self.manifest.lock().await;
        if let Some((at, man)) = m.as_ref() {
            if at.elapsed() < MANIFEST_TTL {
                return Some(man.clone());
            }
        }
        let fetched = self.get("manifest.json").await.and_then(|b| serde_json::from_slice::<Manifest>(&b).map_err(|e| e.to_string()));
        match fetched.and_then(|man| man.check(&self.genesis).map(|_| man)) {
            Ok(man) => {
                let man = Arc::new(man);
                *m = Some((std::time::Instant::now(), man.clone()));
                Some(man)
            }
            Err(e) => {
                log::warn!("chain files: manifest unavailable ({e}); reading from the node");
                // Keep a stale one if there is one: published segments never change.
                m.as_ref().map(|(_, man)| man.clone())
            }
        }
    }

    pub fn note_sink(&self, sink_blue: u64) {
        self.sink.fetch_max(sink_blue, Ordering::Relaxed);
    }

    /// The page `GetShieldedBlocks(low, limit)` would return, from loaded segments, when they
    /// cover it. Runs on into the next loaded segment so pages stay full across a boundary.
    /// Stop using files for the rest of this process (a page disagreed with the node).
    pub fn disable(&self, why: &str) {
        if !self.disabled.swap(true, Ordering::SeqCst) {
            log::error!("chain files DISABLED: {why}; every page now comes from the node");
        }
        self.loaded.lock().unwrap().clear();
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::SeqCst)
    }

    pub fn page(&self, low: RpcHash, limit: u64) -> Option<GetShieldedBlocksResponse> {
        if self.is_disabled() {
            return None;
        }
        let sink = self.sink.load(Ordering::Relaxed);
        if sink == 0 {
            return None;
        }
        let loaded = self.loaded.lock().unwrap();
        let find = |h: &RpcHash| -> Option<(Arc<Loaded>, usize)> {
            for s in loaded.iter() {
                if &s.from == h {
                    return Some((s.clone(), 0));
                }
                if let Some(&i) = s.pos.get(h) {
                    return Some((s.clone(), i + 1));
                }
            }
            None
        };
        let (mut seg, mut at) = find(&low)?;
        let mut blocks = Vec::with_capacity(limit as usize);
        while (blocks.len() as u64) < limit {
            if at < seg.len() {
                blocks.push(seg.block(at)?);
                at += 1;
                continue;
            }
            match loaded.iter().find(|s| s.index == seg.index + 1 && s.from == seg.to) {
                Some(next) => {
                    seg = next.clone();
                    at = 0;
                }
                None => break,
            }
        }
        if blocks.is_empty() {
            return None;
        }
        self.pages_served.fetch_add(1, Ordering::Relaxed);
        Some(GetShieldedBlocksResponse { blocks, reorged: false, sink_blue_score: sink })
    }

    /// Make sure the segments from the one covering `daa` onward are loading, in the background.
    pub fn prefetch_from(self: &Arc<Self>, daa: u64) {
        if self.is_disabled() {
            return;
        }
        self.cursor_daa.fetch_max(daa, Ordering::Relaxed);
        {
            // Done with: wholly below the cursor. Dropping them here, not only on insert, is
            // what keeps the decoded segments to the ones still ahead of the wallet.
            let mut loaded = self.loaded.lock().unwrap();
            loaded.retain(|s| s.to_daa > daa);
        }
        let me = self.clone();
        tokio::spawn(async move {
            let Some(man) = me.manifest().await else { return };
            let wanted: Vec<SegmentEntry> = man.segments.iter().filter(|s| s.to.daa > daa).take(LOADED_SEGMENTS).cloned().collect();
            // (the bound above also caps how many downloads run at once)
            for entry in wanted {
                let skip = {
                    let loaded = me.loaded.lock().unwrap();
                    let mut loading = me.loading.lock().unwrap();
                    loaded.iter().any(|s| s.index == entry.index) || !loading.insert(entry.index)
                };
                if skip {
                    continue;
                }
                let me2 = me.clone();
                tokio::spawn(async move {
                    let t0 = std::time::Instant::now();
                    let r = me2.load(&entry).await;
                    me2.loading.lock().unwrap().remove(&entry.index);
                    match r {
                        Ok(n) => log::info!(
                            "chain files: segment {} ready: {n} blocks, {} KB, {} ms",
                            entry.index,
                            entry.bytes / 1024,
                            t0.elapsed().as_millis()
                        ),
                        Err(e) => log::warn!("chain files: segment {} not used ({e}); the node serves that range", entry.index),
                    }
                });
            }
        });
    }

    async fn load(&self, entry: &SegmentEntry) -> Result<usize, String> {
        let bytes = self.get(&entry.file).await?;
        if bytes.len() as u64 != entry.bytes || sha256_hex(&bytes) != entry.sha256 {
            return Err("file does not match the manifest".into());
        }
        let genesis = self.genesis;
        let index = entry.index;
        let (body, idx) = tokio::task::spawn_blocking(move || {
            let (body, n) = segment_body(&bytes, &genesis, index)?;
            let idx = index_body(&body, n)?;
            Ok::<_, String>((body, idx))
        })
        .await
        .map_err(|e| e.to_string())??;
        if idx.len() as u64 != entry.blocks || idx.last().map(|b| b.0.to_string()).as_deref() != Some(entry.to.block.as_str()) {
            return Err("segment content does not match the manifest".into());
        }
        let pos = idx.iter().enumerate().map(|(i, b)| (b.0, i)).collect();
        let offsets = idx.iter().map(|b| b.2).collect();
        let n = idx.len();
        let seg = Arc::new(Loaded {
            index,
            from: entry.from.hash().ok_or("bad start hash")?,
            to: entry.to.hash().ok_or("bad end hash")?,
            to_daa: entry.to.daa,
            body,
            offsets,
            pos,
        });
        let cursor = self.cursor_daa.load(Ordering::Relaxed);
        let mut loaded = self.loaded.lock().unwrap();
        if seg.to_daa <= cursor {
            return Ok(n); // the wallet already went past it while it was downloading
        }
        loaded.retain(|s| s.index != index && s.to_daa > cursor);
        loaded.push_back(seg);
        // Over the bound: drop the segment furthest AHEAD (it is re-read when needed); the one
        // being ingested is the lowest and is never the one dropped.
        while loaded.len() > LOADED_SEGMENTS {
            let far = loaded.iter().enumerate().max_by_key(|(_, s)| s.index).map(|(i, _)| i).unwrap();
            loaded.remove(far);
        }
        self.segments_loaded.fetch_add(1, Ordering::Relaxed);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(i: u8, cb: usize, acts: usize) -> RpcShieldedChainBlock {
        RpcShieldedChainBlock {
            hash: RpcHash::from_bytes([i; 32]),
            blue_score: 1000 + i as u64,
            daa_score: 2000 + i as u64,
            coinbase_txid: RpcHash::from_bytes([i.wrapping_add(1); 32]),
            coinbase_outputs: (0..cb)
                .map(|j| RpcShieldedCoinbaseOutput {
                    script_public_key: vec![j as u8; 43],
                    value: 7 + j as u64,
                    commitment: (j % 2 == 0).then_some([j as u8; 32]),
                })
                .collect(),
            accepted_actions: (0..acts).map(|j| vec![j as u8; 148 * (j + 1)]).collect(),
            accepted_txids: (0..acts).map(|j| RpcHash::from_bytes([j as u8; 32])).collect(),
            timestamp: 1_700_000_000_000 + i as u64,
        }
    }

    #[test]
    fn public_files_only_for_public_nodes() {
        for n in ["seed.zkas.info:16110", "SEED.ZKAS.INFO:16110", "185.147.157.125:16110", "160.187.211.153:16110", "zkas.info"] {
            assert_eq!(default_for_node(n).as_deref(), Some(PUBLIC_CHAIN_FILES), "{n}");
        }
        for n in ["127.0.0.1:16810", "192.168.1.5:16110", "evilzkas.info:16110", "zkas.info.evil.com:16110", "[::1]:16110", "my-node:16110", ""] {
            assert_eq!(default_for_node(n), None, "{n}");
        }
    }

    #[test]
    fn a_segment_round_trips_exactly() {
        let g = RpcHash::from_bytes([9; 32]);
        let blocks: Vec<_> = (0..20u8).map(|i| block(i, (i % 3) as usize, (i % 4) as usize)).collect();
        let file = encode_segment(&g, 42, &blocks);
        let back = decode_segment(&file, &g, 42).unwrap();
        assert_eq!(back.len(), blocks.len());
        for (a, b) in blocks.iter().zip(&back) {
            assert_eq!(a.hash, b.hash);
            assert_eq!((a.blue_score, a.daa_score, a.timestamp), (b.blue_score, b.daa_score, b.timestamp));
            assert_eq!(a.coinbase_txid, b.coinbase_txid);
            assert_eq!(a.accepted_actions, b.accepted_actions);
            assert_eq!(a.accepted_txids, b.accepted_txids);
            assert_eq!(a.coinbase_outputs.len(), b.coinbase_outputs.len());
            for (x, y) in a.coinbase_outputs.iter().zip(&b.coinbase_outputs) {
                assert_eq!((&x.script_public_key, x.value, x.commitment), (&y.script_public_key, y.value, y.commitment));
            }
        }
    }

    #[test]
    fn a_segment_for_another_network_or_index_or_corrupted_is_refused() {
        let g = RpcHash::from_bytes([9; 32]);
        let file = encode_segment(&g, 42, &[block(1, 2, 2)]);
        assert!(decode_segment(&file, &RpcHash::from_bytes([8; 32]), 42).is_err());
        assert!(decode_segment(&file, &g, 41).is_err());
        let mut cut = file.clone();
        cut.truncate(cut.len() / 2);
        assert!(decode_segment(&cut, &g, 42).is_err());
        assert!(decode_segment(b"not a segment", &g, 42).is_err());
    }

    #[test]
    fn pages_follow_get_shielded_blocks_semantics_across_segments() {
        let g = RpcHash::from_bytes([9; 32]);
        let cf = ChainFiles::new("/nonexistent", g);
        let mk = |index: u64, from: u8, range: std::ops::Range<u8>| {
            let blocks: Vec<_> = range.map(|i| block(i, 1, 1)).collect();
            let to = blocks.last().unwrap().hash;
            let (body, n) = segment_body(&encode_segment(&g, index, &blocks), &g, index).unwrap();
            let idx = index_body(&body, n).unwrap();
            let pos = idx.iter().enumerate().map(|(i, b)| (b.0, i)).collect();
            let offsets = idx.iter().map(|b| b.2).collect();
            Arc::new(Loaded { index, from: RpcHash::from_bytes([from; 32]), to, to_daa: u64::MAX, body, offsets, pos })
        };
        cf.loaded.lock().unwrap().push_back(mk(1, 0, 1..11)); // blocks 1..=10, after block 0
        cf.loaded.lock().unwrap().push_back(mk(2, 10, 11..21)); // blocks 11..=20, after block 10
        assert!(cf.page(RpcHash::from_bytes([0; 32]), 5).is_none(), "no sink known yet: the node serves it");
        cf.note_sink(5_000);
        let p = cf.page(RpcHash::from_bytes([0; 32]), 5).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5], "from a segment start");
        let p = cf.page(RpcHash::from_bytes([4; 32]), 3).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![5, 6, 7], "exclusive cursor inside a segment");
        let p = cf.page(RpcHash::from_bytes([8; 32]), 6).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![9, 10, 11, 12, 13, 14], "runs on into the next segment");
        assert_eq!(p.sink_blue_score, 5_000);
        assert!(!p.reorged);
        assert!(cf.page(RpcHash::from_bytes([20; 32]), 5).is_none(), "the last block of the last segment: the node serves what follows");
        assert!(cf.page(RpcHash::from_bytes([99; 32]), 5).is_none(), "an unknown cursor");
    }
}
