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
    walletdb::{BlockMeta, Preview, WalletDb},
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
/// The mainnet `zkas:` address a full viewing key receives at — the encoding the signer uses
/// (`address_from_seed`), from the key alone, so a watch-only wallet needs no service for it.
pub fn address_of_fvk_str(fvk_hex: &str) -> Result<String, String> {
    let fvk = parse_fvk(fvk_hex)?;
    let db = WalletDb::from_fvk(&fvk).ok_or("not a valid full viewing key")?;
    let raw = db.my_address_bytes();
    Ok(String::from(&kaspa_addresses::Address::new(kaspa_addresses::Prefix::Mainnet, kaspa_addresses::Version::ShieldedOrchard, &raw)))
}

#[wasm_bindgen]
pub fn address_of_fvk(fvk_hex: &str) -> Result<String, JsValue> {
    address_of_fvk_str(fvk_hex).map_err(err)
}

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
    /// Hash every leaf even where a segment's signed frontier could be adopted (tests compare
    /// the two paths). Not persisted; off by default.
    hash_every_leaf: bool,
    /// What the blocks inside the tip margin (seen, not ingested) would do to this wallet, and
    /// their nullifiers (so the mempool preview does not count a just-mined bundle twice).
    unsettled: Preview,
    unsettled_nfs: std::collections::HashSet<[u8; 32]>,
    /// What the node's mempool would do to this wallet.
    mempool: Preview,
    /// The matured anchor (see [`Engine::set_anchor`]): leaf count, block, tree root.
    anchor: Option<(u64, [u8; 32], [u8; 32])>,
}

/// A spend parked this long (DAA) without its nullifier appearing goes back to the wallet
/// (walletd's PENDING_SPEND_EXPIRY_DAA): the send was lost.
pub const PENDING_SPEND_EXPIRY_DAA: u64 = 3_600;

#[derive(Serialize)]
struct Status {
    low: String,
    scanned: u64,
    birthday: u64,
    leaves: u64,
    balance_sompi: String,
    notes: usize,
    history: usize,
    /// walletd's status fields, same meaning: spendable at the matured anchor, the rest of the
    /// balance maturing, 0-conf in/out (unsettled blocks + mempool), change owed by own sends.
    spendable_sompi: String,
    maturing_sompi: String,
    pending_in_sompi: String,
    pending_out_sompi: String,
    pending_change_sompi: String,
    /// A matured anchor is known: a send can be built.
    spend_ready: bool,
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
        Ok(Engine { db, low: h32_hex(&b.block)?, scanned: b.daa, birthday, hash_every_leaf: false, unsettled: Preview::default(), unsettled_nfs: Default::default(), mempool: Preview::default(), anchor: None })
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
        Ok(Engine { db, low, scanned, birthday, hash_every_leaf: false, unsettled: Preview::default(), unsettled_nfs: Default::default(), mempool: Preview::default(), anchor: None })
    }

    /// See [`Engine::hash_every_leaf`].
    pub fn set_hash_every_leaf(&mut self, on: bool) {
        self.hash_every_leaf = on;
    }

    /// Ingest segment `index` (whose manifest `from` block is `from_block_hex`) from its first
    /// block after this wallet's cursor, so a segment already partly ingested resumes exactly.
    /// Refused unless the cursor IS `from` or a block inside the segment: a segment the wallet
    /// has passed, or one that does not continue it, would otherwise be ingested twice.
    pub fn segment(&mut self, bytes: &[u8], index: u64, from_block_hex: &str, to_boundary_json: &str) -> Result<String, String> {
        let blocks = parse_segment(bytes, index)?;
        let from = h32_hex(from_block_hex)?;
        let to: Boundary = serde_json::from_str(to_boundary_json).map_err(|e| format!("segment end: {e}"))?;
        let to_block = h32_hex(&to.block)?;
        let start = if self.low == from {
            0
        } else {
            match blocks.iter().position(|b| b.hash == self.low) {
                Some(i) => i + 1,
                None => return Err("this segment does not continue the wallet's cursor".into()),
            }
        };
        // A wallet holding no note needs its tree exact only at the end, and the segment's signed
        // `to` frontier IS the tree there: skip hashing (~60% of a scan) and adopt it. The leaves
        // are kept, so a note found inside the segment — or a segment not ingested to its end —
        // rebuilds the tree from them instead.
        let skip = !self.hash_every_leaf && self.db.notes().is_empty() && self.db.pending_spends().is_empty();
        self.db.set_borrow_tree(skip);
        let res = self.ingest(&blocks[start..], None);
        self.db.set_borrow_tree(false);
        if !self.db.tree_is_valid() {
            let adopted = self.low == to_block && to.frontier().is_ok_and(|fs| self.db.adopt_tip_frontier(&fs));
            if !adopted && !self.db.rebuild_tree_from_leaves() {
                return Err("the wallet tree could not be rebuilt after a segment".into());
            }
            self.db.compact_if_holding_nothing();
        }
        let n = res?;
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
        // The blocks inside the margin are not ingested (a reorg may still replace them), but
        // what they pay this wallet is shown at once, as walletd shows it: a trial-decrypt that
        // changes nothing. Without it a payment stayed invisible for its first ~200 blocks.
        if at_margin {
            let mut pv = Preview::default();
            let mut nfs = std::collections::HashSet::new();
            for b in &blocks[n..] {
                let (cb, compact) = decode(b).map_err(|e| format!("block {}: {e}", hex::encode(b.hash)))?;
                let cbp: Vec<_> = cb.iter().map(|(d, v, _)| (d.clone(), *v)).collect();
                pv.add(self.db.preview_block_compact(&cbp, &compact));
                nfs.extend(compact.iter().flatten().map(|r| r.nullifier));
            }
            self.unsettled = pv;
            self.unsettled_nfs = nfs;
            // A send whose nullifier never appeared within the expiry was lost: its notes return.
            self.db.reclaim_expired(self.scanned, PENDING_SPEND_EXPIRY_DAA);
        }
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
    pub fn ingest_segment(&mut self, bytes: &[u8], index: u64, from_block_hex: &str, to_boundary_json: &str) -> Result<String, JsValue> {
        self.segment(bytes, index, from_block_hex, to_boundary_json).map_err(err)
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

    /// This wallet's history in walletd's `/api/wallet/history` shape, newest first, so the app's
    /// history view reads it unchanged. Recipient addresses and the per-address breakdown are not
    /// rendered here yet (they need the address encoding), and stay null / empty.
    pub fn history(&self, limit: u32, offset: u32) -> String {
        use kaspa_shielded_core::walletdb::HistoryKind;
        const SOMPI_PER_ZKAS: f64 = 100_000_000.0;
        let all = self.db.history();
        let rows: Vec<serde_json::Value> = all
            .iter()
            .rev()
            .skip(offset as usize)
            .take((limit as usize).clamp(1, 5_000))
            .map(|h| {
                serde_json::json!({
                    "kind": match h.kind { HistoryKind::Coinbase => "coinbase", HistoryKind::Received => "received", HistoryKind::Sent => "sent" },
                    "txid": hex::encode(h.txid),
                    "daaScore": h.daa_score,
                    "timestamp": h.timestamp_ms,
                    "amountSompi": h.amount,
                    "amountSompiExact": h.amount.to_string(),
                    "amountZkas": h.amount as f64 / SOMPI_PER_ZKAS,
                    "amountKind": if h.amount_is_net_outflow { "netOutflow" } else { "paid" },
                    "feeSompi": h.fee,
                    "feeSompiExact": h.fee.to_string(),
                    "feeKnown": h.fee_known,
                    "recipient": null,
                    "memo": (!h.memo.is_empty()).then(|| String::from_utf8_lossy(&h.memo).into_owned()),
                    "credits": [],
                })
            })
            .collect();
        serde_json::json!({ "recoverableHistory": true, "total": all.len(), "rows": rows }).to_string()
    }

    /// The mempool's shielded bundles (hex payloads, from the gateway's `/mempool`): what they
    /// would do to this wallet once mined. Bundles already counted from the unsettled blocks
    /// are skipped, so a payment crossing from mempool to block is counted once.
    pub fn set_mempool(&mut self, payloads_json: &str) -> Result<(), String> {
        let list: Vec<String> = serde_json::from_str(payloads_json).map_err(|e| e.to_string())?;
        let mut pv = Preview::default();
        for h in list {
            let Ok(bytes) = hex::decode(h.trim()) else { continue };
            let Ok(b) = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&bytes, true).or_else(|_| kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&bytes)) else { continue };
            if b.actions.iter().any(|a| self.unsettled_nfs.contains(&a.nullifier)) {
                continue;
            }
            pv.add(self.db.preview_block(&[], &[&b]));
        }
        self.mempool = pv;
        Ok(())
    }

    /// The matured anchor: the node's tree frontier at a chain block deep enough that a spend
    /// rooted there is final when mined (the gateway's `/tree?below=<tip - margin>`). Notes
    /// below its leaf count are spendable; the rest are maturing. Witnesses are advanced to it
    /// here, a little at a time, so a send is a lookup.
    pub fn set_anchor(&mut self, boundary_json: &str) -> Result<(), String> {
        let b: Boundary = serde_json::from_str(boundary_json).map_err(|e| e.to_string())?;
        let fs = b.frontier()?;
        if fs.size > self.db.size() || fs.size < self.db.base_size() {
            return Ok(()); // not yet ingested here, or below what this wallet holds: keep the last one
        }
        let gt = kaspa_shielded_core::tree::GlobalTree::from_state(&fs).map_err(|e| format!("{e:?}"))?;
        let root = gt.frontier().root().to_bytes();
        let block = h32_hex(&b.block)?;
        if !self.db.notes().is_empty() {
            self.db.set_witness_budget(self.db.notes().len().clamp(1, 32));
            if self.db.witnessed_upto() < fs.size {
                self.db.advance_witnesses(fs.size);
            }
        }
        self.anchor = Some((fs.size, block, root));
        Ok(())
    }

    fn spendable(&self) -> u128 {
        match self.anchor {
            Some((s, _, _)) => self.db.notes().iter().filter(|n| n.position < s).map(|n| n.value() as u128).sum(),
            None => 0,
        }
    }

    /// Build and prove a payment of `amount` sompi to `to` (a `zkas:` address) from this
    /// wallet's matured notes, rooted at the matured anchor. `sk_hex` is the wallet's 32-byte
    /// spending key; it is used for this call only. Returns the bundle to submit, the leaf
    /// positions it spends and the fee. Nothing is marked spent until [`Engine::mark_sent`].
    pub fn prepare_send(&self, sk_hex: &str, to: &str, amount: u64, memo: &str) -> Result<String, String> {
        use zkas_wallet_engine::payment::{max_spends_per_tx, select_spend_count, single_note_target, spend_order_key, DEFAULT_FEE_SOMPI};
        if self.db.poisoned() {
            return Err("this wallet received inconsistent chain data; it is being rebuilt".into());
        }
        let (s, block, root) = self.anchor.ok_or("the wallet is still finding a settled point in the chain to pay from; try again in a moment")?;
        let sk: [u8; 32] = hex::decode(sk_hex.trim()).ok().and_then(|v| v.try_into().ok()).ok_or("the spending key must be 32 bytes of hex")?;
        let owner = WalletDb::from_seed(sk).ok_or("not a valid spending key")?;
        if owner.my_address_bytes() != self.db.my_address_bytes() {
            return Err("this key does not belong to this wallet".into());
        }
        let addr = kaspa_addresses::Address::try_from(to.trim()).map_err(|e| format!("not a ZKAS address: {e}"))?;
        if addr.version != kaspa_addresses::Version::ShieldedOrchard || addr.prefix != kaspa_addresses::Prefix::Mainnet {
            return Err("not a mainnet ZKAS address".into());
        }
        let recipient: [u8; 43] = addr.payload.as_slice().try_into().map_err(|_| "address payload is not 43 bytes".to_string())?;
        if amount == 0 {
            return Err("the amount must be more than zero".into());
        }
        let target = single_note_target(amount, DEFAULT_FEE_SOMPI);
        let mut cands: Vec<_> = self.db.notes().iter().filter(|n| n.position < s).collect();
        cands.sort_by_key(|n| spend_order_key(n.value(), target));
        let values: Vec<u64> = cands.iter().map(|n| n.value()).collect();
        let (take, fee) = select_spend_count(&values, amount, DEFAULT_FEE_SOMPI, max_spends_per_tx()).map_err(|e| format!("{e:?}"))?;
        let have: u64 = values[..take.min(values.len())].iter().sum();
        if take == 0 || have < amount.saturating_add(fee) {
            let spendable: u64 = values.iter().sum();
            return Err(format!(
                "not enough settled funds: {} ZKAS ready to spend, {} ZKAS needed (amount plus a {} ZKAS fee). Received coins become spendable about 10 minutes after they are mined.",
                spendable as f64 / 1e8,
                amount.saturating_add(fee) as f64 / 1e8,
                fee as f64 / 1e8
            ));
        }
        let mut inputs = Vec::with_capacity(take);
        let mut positions = Vec::with_capacity(take);
        for n in &cands[..take] {
            let path = self.db.witness_path_at(n.position, s).ok_or("a coin to spend has no path in this wallet's tree")?;
            let cmx = ExtractedNoteCommitment::from(n.note.commitment());
            // The node's own root at the anchor: a tree that drifted declines here instead of
            // proving a payment consensus would reject.
            if path.root(cmx).to_bytes() != root {
                return Err("this wallet's tree disagrees with the node at the anchor; it will rebuild".into());
            }
            inputs.push((n.note.clone(), path));
            positions.push(n.position);
        }
        let mut memo_b = [0u8; 512];
        let mb = memo.as_bytes();
        if mb.len() > 512 {
            return Err("the memo is longer than 512 bytes".into());
        }
        memo_b[..mb.len()].copy_from_slice(mb);
        let net: [u8; 32] = kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes();
        let ctx = kaspa_shielded_wallet::tx::payment_tx_context();
        let bundle = kaspa_shielded_core::wallet::build::build_wallet_payment_multi_anchored(sk, inputs, &[(recipient, amount, memo_b)], fee, &net, &ctx, true, Some(block))
            .map_err(|e| format!("building the payment failed: {e:?}"))?;
        Ok(serde_json::json!({ "bundle_hex": hex::encode(bundle), "positions": positions, "fee": fee, "outflow": amount + fee }).to_string())
    }

    /// The payment `txid` was accepted by the node: park its notes (they leave the balance, and
    /// return on their own if the payment is never mined) and record the change coming back.
    pub fn mark_sent(&mut self, positions_json: &str, txid_hex: &str, outflow: u64) -> Result<(), String> {
        let positions: Vec<u64> = serde_json::from_str(positions_json).map_err(|e| e.to_string())?;
        let txid = h32_hex(txid_hex)?;
        for p in positions {
            self.db.mark_spent(p, txid, self.scanned);
        }
        self.db.note_pending_outflow(txid, outflow);
        Ok(())
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
            spendable_sompi: self.spendable().to_string(),
            maturing_sompi: self.db.balance().saturating_sub(self.spendable()).to_string(),
            pending_in_sompi: (self.unsettled.incoming + self.mempool.incoming).to_string(),
            pending_out_sompi: (self.unsettled.outgoing + self.mempool.outgoing).to_string(),
            pending_change_sompi: self.db.pending_change().to_string(),
            spend_ready: self.anchor.is_some(),
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
        // Holding no note, the wallet needs none of these leaves: drop them (O(1)), so the
        // checkpoint in IndexedDB stays small for a wallet with nothing in it yet.
        self.db.compact_if_holding_nothing();
        Ok(n)
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;
    use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
    use kaspa_shielded_core::wallet::scan::address_bytes_from_seed;

    fn zkas(raw: &[u8; 43]) -> String {
        String::from(&kaspa_addresses::Address::new(kaspa_addresses::Prefix::Mainnet, kaspa_addresses::Version::ShieldedOrchard, raw))
    }

    /// A wallet funded with coinbase notes, anchored at its tip, builds a payment the consensus
    /// verifier accepts — proof, signatures and the named anchor block — and then parks its
    /// notes with the change owed back.
    #[test]
    fn a_browser_payment_verifies_and_parks_its_notes() {
        let sk = [21u8; 32];
        let mine = address_bytes_from_seed(sk).unwrap();
        let mut db = WalletDb::from_seed(sk).unwrap();
        for b in 0..6u8 {
            let theirs = (derive_coinbase_note_desc(address_bytes_from_seed([b.wrapping_add(90); 32]).unwrap(), &[b, 1, 1]), 7_000_000u64);
            let ours = (derive_coinbase_note_desc(mine, &[b, 2, 2]), 500_000_000u64);
            db.ingest_block(&[theirs, ours], &[]);
        }
        let fvk_hex = hex::encode(db.fvk().to_bytes());
        let mut e = Engine::restore_from(&fvk_hex, &{
            // through the real checkpoint path, as the worker restores it
            let mut out = CHECKPOINT_MAGIC.to_vec();
            out.extend_from_slice(&[0u8; 32]);
            out.extend_from_slice(&1000u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            let body = db.to_checkpoint();
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&body);
            out
        })
        .unwrap();
        let fs = e.db.tip_frontier_state().unwrap();
        let block = [77u8; 32];
        let boundary = Boundary {
            block: hex::encode(block),
            daa: 1000,
            size: fs.size,
            leaf: hex::encode(fs.leaf.unwrap()),
            ommers: fs.ommers.iter().map(hex::encode).collect(),
        };
        e.set_anchor(&serde_json::to_string(&boundary).unwrap()).unwrap();
        let st: serde_json::Value = serde_json::from_str(&e.status()).unwrap();
        assert_eq!(st["spendable_sompi"], "3000000000");
        assert_eq!(st["maturing_sompi"], "0");
        assert_eq!(st["spend_ready"], true);

        let to = zkas(&address_bytes_from_seed([99u8; 32]).unwrap());
        // Refusals first: a key that is not this wallet's, and more than it holds.
        assert!(e.prepare_send(&hex::encode([22u8; 32]), &to, 100_000_000, "").unwrap_err().contains("does not belong"));
        assert!(e.prepare_send(&hex::encode(sk), &to, 40_000_000_000, "").unwrap_err().contains("not enough settled funds"));

        let amount = 700_000_000u64; // two notes needed
        let r: serde_json::Value = serde_json::from_str(&e.prepare_send(&hex::encode(sk), &to, amount, "thanks").unwrap()).unwrap();
        let bytes = hex::decode(r["bundle_hex"].as_str().unwrap()).unwrap();
        let bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&bytes, true).unwrap();
        assert_eq!(bundle.anchor_block, Some(block), "the spend names its anchor block");
        let net: [u8; 32] = kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes();
        let ctx = kaspa_shielded_wallet::tx::payment_tx_context();
        let sighash = kaspa_shielded_core::verify::sighash(&bundle, &net, &ctx);
        kaspa_shielded_core::verify::verify_bundle(&bundle, &sighash).expect("the consensus verifier accepts the browser's payment");
        let fee = r["fee"].as_u64().unwrap();
        assert_eq!(bundle.value_balance, fee as i64, "the fee is the bundle's public value balance");

        let positions = r["positions"].to_string();
        assert_eq!(r["positions"].as_array().unwrap().len(), 2);
        e.mark_sent(&positions, &hex::encode([5u8; 32]), amount + fee).unwrap();
        let st: serde_json::Value = serde_json::from_str(&e.status()).unwrap();
        assert_eq!(st["balance_sompi"], "2000000000", "the two spent notes left the balance");
        assert_eq!(st["pending_change_sompi"], (1_000_000_000 - amount - fee).to_string(), "change owed back");
    }
}

#[cfg(test)]
mod wasm_prover_fixture {
    //! The wasm prover checked by the consensus verifier, without funds:
    //!   ZKAS_SEND_FIXTURE=dir cargo test ... wasm_prover_fixture::write   (funded wallet + anchor)
    //!   node: wasm Engine.restore + set_anchor + prepare_send -> dir/bundle.hex
    //!   ZKAS_SEND_FIXTURE=dir cargo test ... wasm_prover_fixture::verify  (verify_bundle)
    use super::*;
    use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
    use kaspa_shielded_core::wallet::scan::address_bytes_from_seed;

    #[test]
    fn write() {
        let Ok(dir) = std::env::var("ZKAS_SEND_FIXTURE") else { return };
        let sk = [31u8; 32];
        let mine = address_bytes_from_seed(sk).unwrap();
        let mut db = WalletDb::from_seed(sk).unwrap();
        for b in 0..4u8 {
            db.ingest_block(&[(derive_coinbase_note_desc(mine, &[b, 3, 3]), 500_000_000)], &[]);
        }
        let e = Engine { db, low: [1; 32], scanned: 1000, birthday: 0, hash_every_leaf: false, unsettled: Preview::default(), unsettled_nfs: Default::default(), mempool: Preview::default(), anchor: None };
        let fs = e.db.tip_frontier_state().unwrap();
        let boundary = Boundary { block: hex::encode([78u8; 32]), daa: 1000, size: fs.size, leaf: hex::encode(fs.leaf.unwrap()), ommers: fs.ommers.iter().map(hex::encode).collect() };
        std::fs::write(format!("{dir}/checkpoint.bin"), e.checkpoint()).unwrap();
        std::fs::write(format!("{dir}/fvk.hex"), hex::encode(e.db.fvk().to_bytes())).unwrap();
        std::fs::write(format!("{dir}/anchor.json"), serde_json::to_string(&boundary).unwrap()).unwrap();
        std::fs::write(format!("{dir}/sk.hex"), hex::encode(sk)).unwrap();
        let to = String::from(&kaspa_addresses::Address::new(kaspa_addresses::Prefix::Mainnet, kaspa_addresses::Version::ShieldedOrchard, &address_bytes_from_seed([98u8; 32]).unwrap()));
        std::fs::write(format!("{dir}/to.txt"), to).unwrap();
    }

    #[test]
    fn verify() {
        let Ok(dir) = std::env::var("ZKAS_SEND_FIXTURE") else { return };
        let Ok(h) = std::fs::read_to_string(format!("{dir}/bundle.hex")) else { return };
        let bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes_at(&hex::decode(h.trim()).unwrap(), true).unwrap();
        assert_eq!(bundle.anchor_block, Some([78u8; 32]));
        let net: [u8; 32] = kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes();
        let sighash = kaspa_shielded_core::verify::sighash(&bundle, &net, &kaspa_shielded_wallet::tx::payment_tx_context());
        kaspa_shielded_core::verify::verify_bundle(&bundle, &sighash).expect("the WASM-built payment verifies");
        std::fs::write(format!("{dir}/VERIFIED"), "ok").unwrap();
    }
}
