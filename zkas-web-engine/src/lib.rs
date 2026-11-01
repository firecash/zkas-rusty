//! The ZKas wallet engine for a web page.
//!
//! The phone and desktop engines are walletd: an HTTP server, gRPC to a node, threads, files.
//! None of that exists in a browser. What does is the wallet itself — `kaspa_shielded_core::
//! walletdb::WalletDb`, the same code those engines run — so this crate is the thin layer a
//! page needs around it:
//!
//! * data in: the published chain files (signed manifest, hash-checked segments) and, past the
//!   newest segment, pages from the chain gateway — both in the segment block encoding;
//! * decoding exactly as walletd does (coinbase commitments derived locally and refused when a
//!   source disagrees; the coinbase seed activation height from the consensus parameters);
//! * a starting point from the signed manifest's segment boundaries (no almanac, no node);
//! * reorg safety: gateway blocks are ingested only once 200 blue score below the sink;
//! * a checkpoint the page keeps in IndexedDB, and the tip frontier for checking against the
//!   node (the phone's rule 3).
//!
//! The viewing key is handed in by the page (derived there from the seed it holds) and never
//! leaves this module.

use kaspa_shielded_core::{
    coinbase::{coinbase_note_commitment_vartime, derive_coinbase_note_desc, CoinbaseNoteDesc},
    tree::FrontierState,
    wallet::CompactActionRecord,
    walletdb::{BlockMeta, WalletDb},
    ExtractedNoteCommitment,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use wasm_bindgen::prelude::*;

const SEGMENT_MAGIC: &[u8; 8] = b"ZKASSEG1";
const PAGE_MAGIC: &[u8; 8] = b"ZKASPG01";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ZKWEBCK1";
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Blocks within this blue score of the sink are never ingested (walletd's SYNC_TIP_MARGIN):
/// the append-only tree must not take a block a routine reorg can remove.
pub const TIP_MARGIN: u64 = 200;
/// The manifest publisher keys (walletd `chain_files::PUBLISHER_KEYS`).
pub const PUBLISHER_KEYS: &[&str] = &["e8603874d997c626e6d29ef4e76da894bbdb001478b7454d1cb548ae3bfc6fc1"];
const MANIFEST_VERSION: u32 = 2;

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn genesis() -> [u8; 32] {
    kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes()
}

fn seed_activation_daa() -> u64 {
    kaspa_consensus_core::config::params::MAINNET_PARAMS.shielded_coinbase_seed_activation.daa_score()
}

// ---------------------------------------------------------------------------------------------
// The segment block encoding (walletd `chain_files::encode_blocks`)
// ---------------------------------------------------------------------------------------------

pub struct Block {
    pub hash: [u8; 32],
    pub blue_score: u64,
    pub daa_score: u64,
    pub timestamp: u64,
    pub coinbase_txid: [u8; 32],
    pub outputs: Vec<(Vec<u8>, u64, Option<[u8; 32]>)>,
    pub actions: Vec<Vec<u8>>,
    pub txids: Vec<[u8; 32]>,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or("truncated")?;
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
    fn h32(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

fn read_block(r: &mut Reader<'_>) -> Result<Block, String> {
    let hash = r.h32()?;
    let blue_score = r.u64()?;
    let daa_score = r.u64()?;
    let timestamp = r.u64()?;
    let coinbase_txid = r.h32()?;
    let n = r.u32()? as usize;
    let mut outputs = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let len = r.u16()? as usize;
        let script = r.take(len)?.to_vec();
        let value = r.u64()?;
        let commitment = match r.take(1)?[0] {
            0 => None,
            1 => Some(r.h32()?),
            _ => return Err("bad commitment flag".into()),
        };
        outputs.push((script, value, commitment));
    }
    let n = r.u32()? as usize;
    let mut actions = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let len = r.u32()? as usize;
        actions.push(r.take(len)?.to_vec());
    }
    let n = r.u32()? as usize;
    let mut txids = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        txids.push(r.h32()?);
    }
    Ok(Block { hash, blue_score, daa_score, timestamp, coinbase_txid, outputs, actions, txids })
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(bytes).read_to_end(&mut raw).map_err(|e| format!("gzip: {e}"))?;
    Ok(raw)
}

/// A segment file's blocks, after checking it is for this network and this index.
pub fn parse_segment(bytes: &[u8], index: u64) -> Result<Vec<Block>, String> {
    let raw = gunzip(bytes)?;
    let mut r = Reader { b: &raw, at: 0 };
    if r.take(8)? != SEGMENT_MAGIC {
        return Err("not a segment file".into());
    }
    if r.h32()? != genesis() {
        return Err("segment is for another network".into());
    }
    if r.u64()? != index {
        return Err("segment index does not match the manifest".into());
    }
    let n = r.u32()? as usize;
    (0..n).map(|_| read_block(&mut r)).collect()
}

/// A gateway page: (sink blue score, reorged, blocks).
pub fn parse_page(bytes: &[u8]) -> Result<(u64, bool, Vec<Block>), String> {
    let raw = gunzip(bytes)?;
    let mut r = Reader { b: &raw, at: 0 };
    if r.take(8)? != PAGE_MAGIC {
        return Err("not a page".into());
    }
    if r.h32()? != genesis() {
        return Err("page is for another network".into());
    }
    let sink = r.u64()?;
    let reorged = r.take(1)?[0] != 0;
    let n = r.u32()? as usize;
    let blocks = (0..n).map(|_| read_block(&mut r)).collect::<Result<Vec<_>, _>>()?;
    Ok((sink, reorged, blocks))
}

// ---------------------------------------------------------------------------------------------
// Decoding (walletd `decode_block`)
// ---------------------------------------------------------------------------------------------

type Coinbase = Vec<(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)>;

fn coinbase_note_seed(b: &Block, index: usize) -> Vec<u8> {
    let mut seed = Vec::with_capacity(68);
    if b.daa_score >= seed_activation_daa() {
        seed.extend_from_slice(&b.hash);
    }
    seed.extend_from_slice(&b.coinbase_txid);
    seed.extend_from_slice(&(index as u32).to_le_bytes());
    seed
}

/// The coinbase notes and compact actions of `b`, as walletd decodes them. A commitment the
/// source supplies must equal the one derived here, or the block is refused.
pub fn decode(b: &Block) -> Result<(Coinbase, Vec<Vec<CompactActionRecord>>), String> {
    let mut coinbase = Vec::with_capacity(b.outputs.len());
    for (i, (script, value, supplied)) in b.outputs.iter().enumerate() {
        if script.len() < ORCHARD_SCRIPT_LEN {
            return Err(format!("coinbase output {i} has a {}-byte script", script.len()));
        }
        let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
        recipient.copy_from_slice(&script[..ORCHARD_SCRIPT_LEN]);
        let desc = derive_coinbase_note_desc(recipient, &coinbase_note_seed(b, i));
        let derived = coinbase_note_commitment_vartime(&desc, *value).map_err(|_| format!("coinbase output {i} derives no commitment"))?;
        if let Some(s) = supplied {
            if *s != derived.to_bytes() {
                return Err(format!("coinbase output {i}: supplied commitment disagrees with the derived one"));
            }
        }
        coinbase.push((desc, *value, derived));
    }
    let mut compact = Vec::with_capacity(b.actions.len());
    for (i, blob) in b.actions.iter().enumerate() {
        if blob.len() % CompactActionRecord::SERIALIZED_LEN != 0 {
            return Err(format!("accepted tx {i} carries a malformed action blob"));
        }
        let recs = blob
            .chunks_exact(CompactActionRecord::SERIALIZED_LEN)
            .map(CompactActionRecord::from_bytes)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("accepted tx {i}: undecodable action"))?;
        compact.push(recs);
    }
    Ok((coinbase, compact))
}

// ---------------------------------------------------------------------------------------------
// Manifest (walletd `chain_files::Manifest`; the same field order, so the same signing bytes)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Boundary {
    pub block: String,
    pub daa: u64,
    pub size: u64,
    pub leaf: String,
    pub ommers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentEntry {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn h32_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|_| format!("not hex: {s}"))?;
    v.try_into().map_err(|_| "not 32 bytes".to_string())
}

impl Boundary {
    pub fn frontier(&self) -> Result<FrontierState, String> {
        let ommers = self.ommers.iter().map(|o| h32_hex(o)).collect::<Result<Vec<_>, _>>()?;
        Ok(FrontierState { size: self.size, leaf: (self.size > 0).then(|| h32_hex(&self.leaf)).transpose()?, ommers })
    }
}

impl Manifest {
    pub fn verify(&self) -> Result<(), String> {
        if self.zkas_chain_files != MANIFEST_VERSION {
            return Err(format!("unsupported manifest version {}", self.zkas_chain_files));
        }
        if h32_hex(&self.genesis)? != genesis() {
            return Err("manifest is for another network".into());
        }
        let sig = self.signature.as_deref().ok_or("manifest is not signed")?;
        let sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(sig).map_err(|_| "signature is not hex")?).map_err(|e| e.to_string())?;
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let payload = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
        let d: [u8; 32] = Sha256::digest(&payload).into();
        let msg = secp256k1::Message::from_digest(d);
        let secp = secp256k1::Secp256k1::verification_only();
        for k in PUBLISHER_KEYS {
            if let Ok(pk) = k.parse::<secp256k1::XOnlyPublicKey>() {
                if secp.verify_schnorr(&sig, &msg, &pk).is_ok() {
                    return Ok(());
                }
            }
        }
        Err("manifest signature does not match the publisher key".into())
    }
}

/// Parse and verify a manifest; returns it as JSON (segments sorted by index).
pub fn verify_manifest_str(json: &str) -> Result<String, String> {
    let mut m: Manifest = serde_json::from_str(json).map_err(|e| e.to_string())?;
    m.verify()?;
    m.segments.sort_by_key(|s| s.index);
    serde_json::to_string(&m).map_err(|e| e.to_string())
}

/// The page's entry point for [`verify_manifest_str`].
#[wasm_bindgen]
pub fn verify_manifest(json: &str) -> Result<String, JsValue> {
    verify_manifest_str(json).map_err(err)
}

/// Does a downloaded segment match its manifest entry (size and SHA-256)?
#[wasm_bindgen]
pub fn segment_matches(bytes: &[u8], sha256_hex: &str, size: u64) -> bool {
    bytes.len() as u64 == size && hex::encode(Sha256::digest(bytes)) == sha256_hex
}

// ---------------------------------------------------------------------------------------------
// The wallet
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Engine {
    db: WalletDb,
    /// The last block ingested (the next page starts after it).
    low: [u8; 32],
    scanned: u64,
    birthday: u64,
}

#[derive(Serialize)]
struct Status {
    low: String,
    scanned: u64,
    birthday: u64,
    leaves: u64,
    balance_sompi: String,
    notes: usize,
    history: usize,
}

#[derive(Serialize)]
struct Ingested {
    ingested: usize,
    low: String,
    scanned: u64,
    /// The page stopped at the tip margin: the wallet is as current as it may be.
    at_margin: bool,
    /// The page's sink blue score (pages only).
    sink_blue_score: u64,
}

fn parse_fvk(fvk_hex: &str) -> Result<[u8; 96], String> {
    let v = hex::decode(fvk_hex.trim()).map_err(|_| "fvk is not hex".to_string())?;
    v.try_into().map_err(|_| "fvk must be 96 bytes".to_string())
}

/// The wallet operations with plain `String` errors: what tests and native callers use. The
/// `#[wasm_bindgen]` methods below are the same calls with JavaScript errors.
impl Engine {
    pub fn create(fvk_hex: &str, boundary_json: &str, birthday: u64) -> Result<Engine, String> {
        let fvk = parse_fvk(fvk_hex)?;
        let b: Boundary = serde_json::from_str(boundary_json).map_err(|e| e.to_string())?;
        let fs = b.frontier()?;
        let mut db = WalletDb::from_fvk(&fvk).ok_or("not a valid full viewing key")?;
        db.apply_frontier(&fs).ok_or("the boundary frontier does not build a tree")?;
        Ok(Engine { db, low: h32_hex(&b.block)?, scanned: b.daa, birthday })
    }

    pub fn restore_from(fvk_hex: &str, bytes: &[u8]) -> Result<Engine, String> {
        let fvk = parse_fvk(fvk_hex)?;
        let mut r = Reader { b: bytes, at: 0 };
        if r.take(8)? != CHECKPOINT_MAGIC {
            return Err("not a browser wallet checkpoint".into());
        }
        let low = r.h32()?;
        let scanned = r.u64()?;
        let birthday = r.u64()?;
        let len = r.u64()? as usize;
        let body = r.take(len)?;
        let db = WalletDb::from_checkpoint_fvk(&fvk, body).ok_or("checkpoint does not restore for this key")?;
        Ok(Engine { db, low, scanned, birthday })
    }

    /// Ingest segment `index` (whose manifest `from` block is `from_block_hex`) from its first
    /// block after this wallet's cursor, so a segment already partly ingested resumes exactly.
    /// Refused unless the cursor IS `from` or a block inside the segment: a segment the wallet
    /// has passed, or one that does not continue it, would otherwise be ingested twice.
    pub fn segment(&mut self, bytes: &[u8], index: u64, from_block_hex: &str) -> Result<String, String> {
        let blocks = parse_segment(bytes, index)?;
        let from = h32_hex(from_block_hex)?;
        let start = if self.low == from {
            0
        } else {
            match blocks.iter().position(|b| b.hash == self.low) {
                Some(i) => i + 1,
                None => return Err("this segment does not continue the wallet's cursor".into()),
            }
        };
        let n = self.ingest(&blocks[start..], None)?;
        serde_json::to_string(&Ingested { ingested: n, low: self.low(), scanned: self.scanned, at_margin: false, sink_blue_score: 0 }).map_err(|e| e.to_string())
    }

    /// Ingest a gateway page fetched with `after=low()`. Stops at the tip margin.
    pub fn page(&mut self, bytes: &[u8]) -> Result<String, String> {
        let (sink, reorged, blocks) = parse_page(bytes)?;
        if reorged {
            return Err("reorged: the cursor is no longer on the selected chain".into());
        }
        let limit = sink.saturating_sub(TIP_MARGIN);
        let n = self.ingest(&blocks, Some(limit))?;
        let at_margin = n < blocks.len() || blocks.is_empty();
        serde_json::to_string(&Ingested { ingested: n, low: self.low(), scanned: self.scanned, at_margin, sink_blue_score: sink }).map_err(|e| e.to_string())
    }
}

#[wasm_bindgen]
impl Engine {
    /// A new wallet watching `fvk_hex`, starting at a manifest segment boundary (`from` of the
    /// segment the birthday falls in: its frontier and block). `birthday` is kept for status.
    #[wasm_bindgen(constructor)]
    pub fn new(fvk_hex: &str, boundary_json: &str, birthday: u64) -> Result<Engine, JsValue> {
        Engine::create(fvk_hex, boundary_json, birthday).map_err(err)
    }

    /// A wallet restored from `checkpoint()` bytes.
    pub fn restore(fvk_hex: &str, bytes: &[u8]) -> Result<Engine, JsValue> {
        Engine::restore_from(fvk_hex, bytes).map_err(err)
    }

    /// Everything needed to resume: kept by the page (IndexedDB) and given to `restore`.
    pub fn checkpoint(&self) -> Vec<u8> {
        let body = self.db.to_checkpoint();
        let mut out = Vec::with_capacity(body.len() + 64);
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.extend_from_slice(&self.low);
        out.extend_from_slice(&self.scanned.to_le_bytes());
        out.extend_from_slice(&self.birthday.to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn low(&self) -> String {
        hex::encode(self.low)
    }

    pub fn scanned(&self) -> u64 {
        self.scanned
    }

    /// See [`Engine::segment`].
    pub fn ingest_segment(&mut self, bytes: &[u8], index: u64, from_block_hex: &str) -> Result<String, JsValue> {
        self.segment(bytes, index, from_block_hex).map_err(err)
    }

    /// See [`Engine::page`].
    pub fn ingest_page(&mut self, bytes: &[u8]) -> Result<String, JsValue> {
        self.page(bytes).map_err(err)
    }

    /// This wallet's tree frontier at `low()`, as the gateway's /tree answers it — for the
    /// check against the node. Undefined while the wallet holds no tree of its own.
    pub fn tip_frontier(&self) -> Option<String> {
        let fs = self.db.tip_frontier_state()?;
        serde_json::to_string(&serde_json::json!({
            "block": self.low(),
            "size": fs.size,
            "leaf": fs.leaf.map(hex::encode),
            "ommers": fs.ommers.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
        .ok()
    }

    pub fn status(&self) -> String {
        serde_json::to_string(&Status {
            low: self.low(),
            scanned: self.scanned,
            birthday: self.birthday,
            leaves: self.db.size(),
            balance_sompi: self.db.balance().to_string(),
            notes: self.db.notes().len(),
            history: self.db.history().len(),
        })
        .unwrap_or_default()
    }
}

impl Engine {
    fn ingest(&mut self, blocks: &[Block], blue_limit: Option<u64>) -> Result<usize, String> {
        let mut n = 0;
        for b in blocks {
            if blue_limit.is_some_and(|l| b.blue_score > l) {
                break;
            }
            let (coinbase, compact) = decode(b).map_err(|e| format!("block {}: {e}", hex::encode(b.hash)))?;
            let meta = BlockMeta { coinbase_txid: b.coinbase_txid, txids: b.txids.clone(), timestamp_ms: b.timestamp, daa_score: b.daa_score };
            self.db.ingest_block_compact_precomputed_with_meta(&coinbase, &compact, Some(&meta));
            if self.db.poisoned() {
                return Err(format!("block {} repeats a nullifier: inconsistent data", hex::encode(b.hash)));
            }
            self.low = b.hash;
            self.scanned = b.daa_score;
            n += 1;
        }
        self.db.end_page();
        Ok(n)
    }
}
