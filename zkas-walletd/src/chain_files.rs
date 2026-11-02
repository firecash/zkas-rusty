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
/// Segments read ahead of a page's end.
const READ_AHEAD_SEGMENTS: usize = 2;
/// Decoded segments held at once, shared by every wallet in the process. Two wallets catching
/// up at different heights each need their current and next segment, so this must be at least
/// 2 x READ_AHEAD_SEGMENTS or they evict each other's and re-download on every page.
const LOADED_SEGMENTS: usize = 4;
/// How long the files rest after a page that changed a wallet could not be confirmed with the
/// node (see `ChainFiles::pause`).
pub const UNCONFIRMED_PAUSE: std::time::Duration = std::time::Duration::from_secs(120);
/// A segment no page has read for this long is dropped.
// 10 minutes, not 2: the cap (LOADED_SEGMENTS) already bounds memory, and a phone's engine
// paused in the background for a few minutes came back to find the segment its wallet was in
// dropped and downloaded it again (9 MB, 13.6 s, logged 1 Nov).
const SEGMENT_IDLE: std::time::Duration = std::time::Duration::from_secs(600);
/// How long a fetched manifest is trusted before it is fetched again.
const MANIFEST_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// After every mirror failed, how long before they are asked again. Without it each page
/// re-asked: 72 manifest requests and 144 warnings in 90 s against a refused mirror.
const MANIFEST_RETRY: std::time::Duration = std::time::Duration::from_secs(60);
const MAGIC: &[u8; 8] = b"ZKASSEG1";
/// 2 since the signed manifest. The segment files did not change; the number did so that the
/// 1.0.52-rc20 client — whose shared-cursor cache re-downloaded segments in a loop when two
/// wallets synced at different heights — refuses the published manifest and reads from the
/// node instead, which is correct, only slower. Version-1 manifests are upgraded on export.
const MANIFEST_VERSION: u32 = 2;
/// The published manifest's file name. Not `manifest.json`: rc20 refetches a manifest it
/// refuses on EVERY page (it has no back-off), so the old name is retired to a tiny 404 rather
/// than left serving a 200 KB file rc20 would download and reject in a loop.
pub const MANIFEST_FILE: &str = "manifest-v2.json";

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
    /// BIP-340 Schnorr signature (hex) by the publisher over SHA-256 of `signing_payload()`:
    /// this manifest with `signature` left out, as compact JSON. Inside the file rather than
    /// beside it, so a mirror can never pair a new list with an old signature mid-update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The publisher keys (BIP-340 x-only, hex) a manifest fetched over HTTP must be signed by.
/// The segment files are pinned by the manifest's SHA-256s, so this one signature is what
/// stops a mirror, a CDN or anything on the path from substituting the whole set. Rules 2 and
/// 3 (the node cross-checks) still apply on top: a signed file that disagrees with the node is
/// dropped like any other.
pub const PUBLISHER_KEYS: &[&str] = &["e8603874d997c626e6d29ef4e76da894bbdb001478b7454d1cb548ae3bfc6fc1"];

impl Manifest {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut m = self.clone();
        m.signature = None;
        serde_json::to_vec(&m).expect("a manifest always serialises")
    }

    fn digest(&self) -> secp256k1::Message {
        let d: [u8; 32] = Sha256::digest(self.signing_payload()).into();
        secp256k1::Message::from_digest(d)
    }

    pub fn sign(&mut self, key: &secp256k1::Keypair) {
        self.signature = None;
        let sig = secp256k1::SECP256K1.sign_schnorr(&self.digest(), key);
        self.signature = Some(hex::encode(sig.as_ref()));
    }

    pub fn verify_signature(&self, keys: &[&str]) -> Result<(), String> {
        let sig = self.signature.as_deref().ok_or("manifest is not signed")?;
        let sig = hex::decode(sig).map_err(|_| "manifest signature is not hex".to_string())?;
        let sig = secp256k1::schnorr::Signature::from_slice(&sig).map_err(|e| format!("manifest signature: {e}"))?;
        let msg = self.digest();
        for k in keys {
            let Ok(pk) = k.parse::<secp256k1::XOnlyPublicKey>() else { continue };
            if secp256k1::SECP256K1.verify_schnorr(&sig, &msg, &pk).is_ok() {
                return Ok(());
            }
        }
        Err("manifest signature does not match the publisher key".into())
    }

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

/// Where ZKas publishes its chain files: Cloudflare R2 (a CDN, so a third party that sees the
/// downloading device's IP — the app says so) and zkas.info itself. Every segment comes from R2,
/// zkas.info only when R2 fails; the manifest must carry the ZKas publisher
/// signature whichever serves it, so neither can substitute files. The node is the last fallback.
pub const PUBLIC_CHAIN_FILES: &str = "https://pub-ae5ed92258b2437e985b69ab9947ef60.r2.dev,https://zkas.info/shielded-chain";

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
const PAGE_MAGIC: &[u8; 8] = b"ZKASPG01";

/// One `GetShieldedBlocks` answer in the segment block encoding, for the browser gateway:
/// gzip( PAGE_MAGIC | genesis 32 | sink_blue_score u64 | reorged u8 | count u32 | blocks ).
/// A browser cannot speak gRPC, so the gateway serves the node's pages over HTTPS in the same
/// encoding as the published segments — one decoder for both.
pub fn encode_page(genesis: &RpcHash, page: &GetShieldedBlocksResponse) -> Vec<u8> {
    let mut w = Vec::with_capacity(page.blocks.len() * 512 + 64);
    w.extend_from_slice(PAGE_MAGIC);
    w.extend_from_slice(&genesis.as_bytes());
    put_u64(&mut w, page.sink_blue_score);
    w.push(page.reorged as u8);
    put_u32(&mut w, page.blocks.len() as u32);
    encode_blocks(&mut w, &page.blocks);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    gz.write_all(&w).expect("writing to a Vec cannot fail");
    gz.finish().expect("writing to a Vec cannot fail")
}

/// The inverse of [`encode_page`]; refuses another network's page.
pub fn decode_page(bytes: &[u8], genesis: &RpcHash) -> Result<GetShieldedBlocksResponse, String> {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(bytes).read_to_end(&mut raw).map_err(|e| format!("gzip: {e}"))?;
    let mut r = Reader { b: &raw, at: 0 };
    if r.take(8)? != PAGE_MAGIC {
        return Err("not a page".into());
    }
    if &r.hash()? != genesis {
        return Err("page is for another network".into());
    }
    let sink_blue_score = r.u64()?;
    let reorged = r.take(1)?[0] != 0;
    let n = r.u32()? as usize;
    let mut blocks = Vec::with_capacity(n.min(100_000));
    for _ in 0..n {
        blocks.push(read_block(&mut r)?);
    }
    Ok(GetShieldedBlocksResponse { blocks, reorged, sink_blue_score })
}

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
    let end = blocks.last().map(|b| b.hash.to_string()).unwrap_or_else(|| from.block.clone());
    if end != to.block {
        return Err(format!("segment ends at {end}, not at {}", to.block));
    }
    let got = end_frontier(from, blocks)?;
    if !to.same_frontier(&got) {
        return Err(format!("re-ingested tree has {} leaves, the node's frontier at the end has {}", got.size, to.size));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Exporter
// ---------------------------------------------------------------------------------------------

/// Read the publisher's secret key (64 hex chars) from the file `ZKAS_CHAIN_FILES_KEY` names.
pub fn publisher_key_from_env() -> Result<Option<secp256k1::Keypair>, String> {
    let Ok(path) = std::env::var("ZKAS_CHAIN_FILES_KEY") else { return Ok(None) };
    let hexkey = std::fs::read_to_string(&path).map_err(|e| format!("publisher key {path}: {e}"))?;
    let raw = hex::decode(hexkey.trim()).map_err(|_| format!("publisher key {path} is not hex"))?;
    secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &raw).map(Some).map_err(|e| format!("publisher key {path}: {e}"))
}

fn write_manifest(path: &std::path::Path, manifest: &mut Manifest, key: Option<&secp256k1::Keypair>) -> Result<(), String> {
    match key {
        Some(k) => manifest.sign(k),
        None => manifest.signature = None,
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Write every complete segment not yet in `out_dir`, at most `max_new` of them, updating the
/// signed manifest after each. Any node with the complete shielded HISTORY will do — an
/// ordinary pruned node included; an archival node is not needed:
///
/// 1. newest first, while the node can place frontiers (an archival node: everywhere; a pruned
///    one: its recent window), each segment verified against the node's own two frontiers;
/// 2. below that, replayed upward from genesis (or from the end of the highest segment already
///    published below the gap), each end frontier COMPUTED by the leaf rules every wallet runs.
///    Where the replay meets a published segment, or reaches blocks the node can place, the
///    computed frontier must equal the recorded one; a frontier commits to every leaf before
///    it, so one match verifies the whole replay below it.
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
    let manifest_path = out_dir.join(MANIFEST_FILE);
    // First run after the rename: carry the version-1 list over instead of re-exporting it.
    let existing = std::fs::read(&manifest_path).or_else(|_| std::fs::read(out_dir.join("manifest.json")));
    let mut manifest = match existing {
        Ok(b) => serde_json::from_slice::<Manifest>(&b).map_err(|e| format!("existing manifest: {e}"))?,
        Err(_) => Manifest { zkas_chain_files: MANIFEST_VERSION, genesis: genesis.to_string(), segment_daa: SEGMENT_DAA, segments: Vec::new(), signature: None },
    };
    if manifest.zkas_chain_files == 1 {
        manifest.zkas_chain_files = MANIFEST_VERSION;
        manifest.signature = None; // re-signed just below
        log::info!("chain files: manifest upgraded to version {MANIFEST_VERSION}");
    }
    manifest.check(&genesis)?;
    let key = publisher_key_from_env()?;
    // A manifest written before signing existed, or by another key: re-sign it now rather than
    // wait for the next new segment, or every HTTP client keeps refusing it.
    if let Some(k) = key.as_ref() {
        let pk = k.x_only_public_key().0.to_string();
        if manifest.verify_signature(&[pk.as_str()]).is_err() {
            write_manifest(&manifest_path, &mut manifest, Some(k))?;
            log::info!("chain files: manifest (re)signed by {pk}");
        }
    }
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
            // A pruned node places frontiers only in its recent window: below it, phase 2.
            let (from, to) = match (place(k * SEGMENT_DAA).await, place((k + 1) * SEGMENT_DAA).await) {
                (Ok(f), Ok(t)) => (f, t),
                (Err(e), _) | (_, Err(e)) => {
                    log::info!("chain files: the node cannot place segment {k} ({e}); older segments are replayed from genesis");
                    break;
                }
            };
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
            publish_segment(out_dir, &genesis, k, &blocks, from, to, &mut manifest, &manifest_path, key.as_ref(), "verified against the node", t0)?;
            written += 1;
        }
        k -= 1;
    }

    // Phase 2: replay upward below what the node could place.
    let genesis_boundary = Boundary {
        block: genesis.to_string(),
        daa: kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.daa_score,
        size: 0,
        leaf: RpcHash::from_bytes([0; 32]).to_string(),
        ommers: Vec::new(),
    };
    let mut k = 0u64;
    let mut from = genesis_boundary;
    while let Some(s) = manifest.segments.iter().find(|s| s.index == k) {
        from = s.to.clone();
        k += 1;
    }
    while k <= last && written < max_new && !manifest.segments.iter().any(|s| s.index == k) {
        let t0 = std::time::Instant::now();
        // Where the replay meets a published segment it must end exactly at that segment's
        // start; otherwise at the last chain block below (k + 1) * SEGMENT_DAA.
        let junction = manifest.segments.iter().find(|s| s.index == k + 1).map(|s| s.from.clone());
        let limit = (k + 1) * SEGMENT_DAA;
        let mut cursor = from.hash().ok_or("bad start hash")?;
        let mut blocks: Vec<RpcShieldedChainBlock> = Vec::new();
        'replay: loop {
            let page = client.get_shielded_blocks(cursor, 2000).await.map_err(|e| format!("replay segment {k}: {e}"))?;
            if page.reorged {
                return Err(format!("replay segment {k}: the node reports a reorg below the cursor"));
            }
            if page.blocks.is_empty() {
                return Err(format!("replay segment {k}: reached the tip before the end of the segment"));
            }
            for b in page.blocks {
                match &junction {
                    Some(j) => {
                        if b.daa_score > j.daa {
                            return Err(format!("replay segment {k}: passed daa {} without meeting the next segment's start", j.daa));
                        }
                        cursor = b.hash;
                        let end = b.hash.to_string() == j.block;
                        blocks.push(b);
                        if end {
                            break 'replay;
                        }
                    }
                    None => {
                        if b.daa_score >= limit {
                            break 'replay;
                        }
                        cursor = b.hash;
                        blocks.push(b);
                    }
                }
            }
        }
        let last_block = blocks.last().ok_or_else(|| format!("replay segment {k} has no blocks"))?;
        let got = end_frontier(&from, &blocks).map_err(|e| format!("replay segment {k}: {e}"))?;
        let to = Boundary {
            block: last_block.hash.to_string(),
            daa: last_block.daa_score,
            size: got.size,
            leaf: got.leaf.map(|l| RpcHash::from_bytes(l).to_string()).unwrap_or_else(|| RpcHash::from_bytes([0; 32]).to_string()),
            ommers: got.ommers.iter().map(|o| RpcHash::from_bytes(*o).to_string()).collect(),
        };
        let how = if let Some(j) = &junction {
            if !j.same_frontier(&got) {
                return Err(format!(
                    "replay segment {k}: the computed tree ({} leaves) differs from the published start of segment {} ({} leaves); nothing written",
                    got.size,
                    k + 1,
                    j.size
                ));
            }
            "replayed; matches the next published segment"
        } else {
            match place(limit).await {
                Ok(n) if n.block == to.block && !n.same_frontier(&got) => {
                    return Err(format!("replay segment {k}: the computed tree ({} leaves) differs from the node's ({} leaves)", got.size, n.size));
                }
                Ok(n) if n.block == to.block => "replayed; matches the node's frontier",
                _ => "replayed from genesis",
            }
        };
        let next_from = to.clone();
        publish_segment(out_dir, &genesis, k, &blocks, from, to, &mut manifest, &manifest_path, key.as_ref(), how, t0)?;
        from = next_from;
        written += 1;
        k += 1;
    }
    Ok(written)
}

/// The frontier `blocks` leave behind on top of `from`, by the leaf rules every wallet runs.
pub fn end_frontier(from: &Boundary, blocks: &[RpcShieldedChainBlock]) -> Result<kaspa_shielded_core::tree::FrontierState, String> {
    let fs = from.frontier_state().ok_or("bad start frontier")?;
    let mut db = kaspa_shielded_core::walletdb::WalletDb::from_frontier([0x5a; 32], &fs).ok_or("start frontier does not build a tree")?;
    db.set_leaves_only(true);
    for b in blocks {
        let d = crate::decode_block(b)?;
        db.ingest_block_compact_precomputed_with_meta(&d.coinbase, &d.compact, None);
        if db.poisoned() {
            return Err(format!("block {} repeats a nullifier", b.hash));
        }
    }
    db.end_page();
    db.tip_frontier_state().ok_or_else(|| "no tree after the segment".to_string())
}

#[allow(clippy::too_many_arguments)]
fn publish_segment(
    out_dir: &std::path::Path,
    genesis: &RpcHash,
    k: u64,
    blocks: &[RpcShieldedChainBlock],
    from: Boundary,
    to: Boundary,
    manifest: &mut Manifest,
    manifest_path: &std::path::Path,
    key: Option<&secp256k1::Keypair>,
    how: &str,
    t0: std::time::Instant,
) -> Result<(), String> {
    let bytes = encode_segment(genesis, k, blocks);
    let sha = sha256_hex(&bytes);
    let file = format!("seg-{k:06}-{}.zks", &sha[..16]);
    let tmp = out_dir.join(format!("{file}.tmp"));
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, out_dir.join(&file)).map_err(|e| e.to_string())?;
    log::info!(
        "chain files: segment {k} written: {} blocks, {} leaves, {} KB, {how}, {:.1} s",
        blocks.len(),
        to.size - from.size,
        bytes.len() / 1024,
        t0.elapsed().as_secs_f64()
    );
    manifest.segments.push(SegmentEntry { index: k, file, sha256: sha, bytes: bytes.len() as u64, blocks: blocks.len() as u64, from, to });
    manifest.segments.sort_by_key(|s| s.index);
    write_manifest(manifest_path, manifest, key)
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
    /// The signed tree frontier after `to` (see [`ChainFiles::frontier_at`]).
    to_frontier: Option<kaspa_shielded_core::tree::FrontierState>,
    body: Vec<u8>,
    /// Byte offset of each block in `body`, in chain order.
    offsets: Vec<usize>,
    /// Block hash -> its position in `offsets`.
    pos: HashMap<RpcHash, usize>,
    /// Milliseconds since `ChainFiles::epoch` a page last read from this segment.
    used_ms: AtomicU64,
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

fn is_http(base: &str) -> bool {
    base.starts_with("http://") || base.starts_with("https://")
}

/// The wallet side: answers page requests from published segments where it can.
pub struct ChainFiles {
    /// Mirrors, each an `https://…` URL or a local directory. Segment `k` is fetched from
    /// the first mirror listed (the CDN) and from the others only if that fails or serves the wrong bytes.
    bases: Vec<String>,
    http: Option<reqwest::Client>,
    genesis: RpcHash,
    manifest: tokio::sync::Mutex<Option<(std::time::Instant, Arc<Manifest>)>>,
    /// When every mirror last failed to serve a usable manifest (see `MANIFEST_RETRY`).
    manifest_failed: Mutex<Option<std::time::Instant>>,
    /// Until when `page` answers nothing (see `pause`).
    paused_until: Mutex<Option<std::time::Instant>>,
    loaded: Mutex<VecDeque<Arc<Loaded>>>,
    loading: Mutex<HashSet<u64>>,
    /// The node's sink blue score as last seen, for the settlement margin a page carries.
    sink: AtomicU64,
    /// Base for `Loaded::used_ms`.
    epoch: std::time::Instant,
    /// Set the first time a file page disagrees with the node: from then on this process
    /// reads everything from the node, so a poisoned source cannot be re-adopted by the
    /// rebuild it triggers.
    disabled: std::sync::atomic::AtomicBool,
    pub pages_served: AtomicU64,
    pub segments_loaded: AtomicU64,
    /// Bytes of segment files fetched this process, and how often each segment was fetched:
    /// a segment fetched more than twice means the cache is fighting itself, which costs a
    /// phone its data plan and is the first thing a log should say.
    pub bytes_downloaded: AtomicU64,
    fetches: Mutex<HashMap<u64, u32>>,
}

/// What `/api/status` reports about the chain files.
#[derive(serde::Serialize, Clone, Debug)]
pub struct Stats {
    pub source: String,
    pub disabled: bool,
    pub pages_served: u64,
    pub segments_loaded: u64,
    pub downloaded_mb: f64,
    /// Segments fetched more than once this process.
    pub refetched_segments: u64,
}

impl ChainFiles {
    /// `bases` is one or more comma-separated mirrors: `https://…` URLs or local directories
    /// holding `manifest-v2.json` (`MANIFEST_FILE`) and the files.
    pub fn new(bases: &str, genesis: RpcHash) -> Arc<Self> {
        let bases: Vec<String> =
            bases.split(',').map(|b| b.trim().trim_end_matches('/').to_string()).filter(|b| !b.is_empty()).collect();
        let http = bases
            .iter()
            .any(|b| is_http(b))
            .then(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().ok())
            .flatten();
        Arc::new(Self {
            bases,
            http,
            genesis,
            manifest: tokio::sync::Mutex::new(None),
            manifest_failed: Mutex::new(None),
            paused_until: Mutex::new(None),
            loaded: Mutex::new(VecDeque::new()),
            loading: Mutex::new(HashSet::new()),
            sink: AtomicU64::new(0),
            epoch: std::time::Instant::now(),
            disabled: std::sync::atomic::AtomicBool::new(false),
            pages_served: AtomicU64::new(0),
            segments_loaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            fetches: Mutex::new(HashMap::new()),
        })
    }

    async fn get_from(&self, base: &str, name: &str) -> Result<Vec<u8>, String> {
        if is_http(base) {
            let c = self.http.as_ref().ok_or("no HTTP client")?;
            let r = c.get(format!("{base}/{name}")).send().await.map_err(|e| e.to_string())?;
            if !r.status().is_success() {
                return Err(format!("HTTP {}", r.status()));
            }
            Ok(r.bytes().await.map_err(|e| e.to_string())?.to_vec())
        } else {
            tokio::fs::read(format!("{base}/{name}")).await.map_err(|e| e.to_string())
        }
    }

    /// The manifest one mirror serves, if it is well formed, for this network and — when it
    /// came over HTTP — signed by the publisher.
    async fn manifest_from(&self, base: &str) -> Result<Manifest, String> {
        let b = self.get_from(base, MANIFEST_FILE).await?;
        let man = serde_json::from_slice::<Manifest>(&b).map_err(|e| e.to_string())?;
        man.check(&self.genesis)?;
        if is_http(base) {
            man.verify_signature(PUBLISHER_KEYS)?;
        }
        Ok(man)
    }

    async fn manifest(&self) -> Option<Arc<Manifest>> {
        let mut m = self.manifest.lock().await;
        if let Some((at, man)) = m.as_ref() {
            if at.elapsed() < MANIFEST_TTL {
                return Some(man.clone());
            }
        }
        if self.manifest_failed.lock().unwrap().is_some_and(|at| at.elapsed() < MANIFEST_RETRY) {
            return m.as_ref().map(|(_, man)| man.clone());
        }
        let mut why = Vec::new();
        for base in &self.bases {
            match self.manifest_from(base).await {
                Ok(man) => {
                    let man = Arc::new(man);
                    *m = Some((std::time::Instant::now(), man.clone()));
                    *self.manifest_failed.lock().unwrap() = None;
                    return Some(man);
                }
                Err(e) => {
                    log::warn!("chain files: manifest from {base} not used ({e})");
                    why.push(e);
                }
            }
        }
        *self.manifest_failed.lock().unwrap() = Some(std::time::Instant::now());
        if m.is_none() {
            log::warn!("chain files: no mirror served a usable manifest; reading from the node (asking again in {} s)", MANIFEST_RETRY.as_secs());
        }
        // Keep a stale one if there is one: published segments never change.
        m.as_ref().map(|(_, man)| man.clone())
    }

    /// One segment's bytes, matching the manifest's size and SHA-256, from the first mirror that
    /// serves them, in the configured order: the CDN first, the others only when it fails.
    /// (Rotating the start by segment index sent half of every download to zkas.info.)
    async fn fetch_segment(&self, entry: &SegmentEntry) -> Result<Vec<u8>, String> {
        let mut last = String::from("no mirrors configured");
        for base in &self.bases {
            match self.get_from(base, &entry.file).await {
                Ok(bytes) if bytes.len() as u64 == entry.bytes && sha256_hex(&bytes) == entry.sha256 => return Ok(bytes),
                Ok(bytes) => {
                    self.bytes_downloaded.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    log::warn!("chain files: {base} served segment {} that does not match the manifest; trying another mirror", entry.index);
                    last = "file does not match the manifest".into();
                }
                Err(e) => {
                    log::warn!("chain files: segment {} from {base} failed ({e}); trying another mirror", entry.index);
                    last = e;
                }
            }
        }
        Err(last)
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

    /// Serve nothing for `d`: the node could not confirm a file page just now (a network
    /// blip, not a bad file), so the reloaded wallet reads from the node for a while rather
    /// than immediately needing the same confirmation again.
    pub fn pause(&self, d: std::time::Duration) {
        *self.paused_until.lock().unwrap() = Some(std::time::Instant::now() + d);
        log::info!("chain files: paused for {} s; the node serves pages meanwhile", d.as_secs());
    }

    fn is_paused(&self) -> bool {
        self.paused_until.lock().unwrap().is_some_and(|t| std::time::Instant::now() < t)
    }

    pub fn page(&self, low: RpcHash, limit: u64) -> Option<GetShieldedBlocksResponse> {
        if self.is_disabled() || self.is_paused() {
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
        let now_ms = self.now_ms();
        seg.used_ms.store(now_ms, Ordering::Relaxed);
        let mut blocks = Vec::with_capacity(limit as usize);
        while (blocks.len() as u64) < limit {
            if at < seg.len() {
                blocks.push(seg.block(at)?);
                at += 1;
                continue;
            }
            // A page ends at its segment's end. A wallet that skips hashing adopts the segment's
            // signed frontier only when its cursor is EXACTLY the segment's last block; pages
            // running across the boundary almost never left it there, so nothing was adopted or
            // compacted during the whole catch-up and every leaf stayed in RAM (11-16 M leaves,
            // ~1 GB, measured on a genesis restore). One extra page per ~20 k-block segment.
            if !blocks.is_empty() {
                break;
            }
            match loaded.iter().find(|s| s.index == seg.index + 1 && s.from == seg.to) {
                Some(next) => {
                    seg = next.clone();
                    seg.used_ms.store(now_ms, Ordering::Relaxed);
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

    /// Will the next page after `low` come from the files? True when a loaded segment holds
    /// blocks after `low`: `low` is its start, or a block inside it other than its last (at the
    /// last block, only if the next segment is loaded too). A wallet holding no note uses this
    /// to skip hashing its tree until it reaches the segment's end (see [`Self::frontier_at`]).
    pub fn covers(&self, low: &RpcHash) -> bool {
        if self.is_disabled() || self.is_paused() || self.sink.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let loaded = self.loaded.lock().unwrap();
        loaded.iter().any(|s| &s.from == low || (&s.to != low && s.pos.contains_key(low)))
    }

    /// The tree frontier right after block `block`, when `block` ends a loaded segment: the
    /// manifest's signed `to` frontier, which the exporter reproduced from the segment's own
    /// leaves and the node confirmed. `WalletDb::adopt_tip_frontier` accepts it only at exactly
    /// the wallet's leaf count, so a wallet that skipped hashing a segment it holds no note in
    /// becomes exact again at its end.
    pub fn frontier_at(&self, block: &RpcHash) -> Option<kaspa_shielded_core::tree::FrontierState> {
        if self.is_disabled() {
            return None;
        }
        let loaded = self.loaded.lock().unwrap();
        loaded.iter().find(|s| &s.to == block).and_then(|s| s.to_frontier.clone())
    }

    pub fn stats(&self) -> Stats {
        Stats {
            source: self.bases.join(","),
            disabled: self.is_disabled(),
            pages_served: self.pages_served.load(Ordering::Relaxed),
            segments_loaded: self.segments_loaded.load(Ordering::Relaxed),
            downloaded_mb: (self.bytes_downloaded.load(Ordering::Relaxed) as f64 / 1_048_576.0 * 10.0).round() / 10.0,
            refetched_segments: self.fetches.lock().unwrap().values().filter(|&&n| n > 1).count() as u64,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Make sure the segments from the one covering `daa` onward are loading, in the background.
    ///
    /// `daa` is where THIS page ended. Several wallets read at once, each at its own height, so
    /// nothing here may assume one cursor for the process: an earlier version kept the highest
    /// `daa` seen and dropped every segment below it, so a wallet near the tip made a new
    /// 30-day-old wallet's segment be discarded the moment it finished downloading — on a phone,
    /// the same 10 MB file fetched 32 times in five minutes. Eviction is by last use instead.
    pub fn prefetch_from(self: &Arc<Self>, daa: u64) {
        if self.is_disabled() {
            return;
        }
        {
            let now = self.now_ms();
            let idle = SEGMENT_IDLE.as_millis() as u64;
            self.loaded.lock().unwrap().retain(|s| now.saturating_sub(s.used_ms.load(Ordering::Relaxed)) < idle);
        }
        let me = self.clone();
        tokio::spawn(async move {
            let Some(man) = me.manifest().await else { return };
            let wanted = segments_within_reach(&man.segments, daa);
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
                            "chain files: segment {} ready: {n} blocks, {} KB, {} ms ({} MB downloaded this session, {} pages served from files)",
                            entry.index,
                            entry.bytes / 1024,
                            t0.elapsed().as_millis(),
                            me2.bytes_downloaded.load(Ordering::Relaxed) / 1_048_576,
                            me2.pages_served.load(Ordering::Relaxed)
                        ),
                        Err(e) => log::warn!("chain files: segment {} not used ({e}); the node serves that range", entry.index),
                    }
                });
            }
        });
    }

    async fn load(&self, entry: &SegmentEntry) -> Result<usize, String> {
        let bytes = self.fetch_segment(entry).await?;
        let total = self.bytes_downloaded.fetch_add(bytes.len() as u64, Ordering::Relaxed) + bytes.len() as u64;
        let times = {
            let mut f = self.fetches.lock().unwrap();
            let n = f.entry(entry.index).or_insert(0);
            *n += 1;
            *n
        };
        if times > 2 {
            log::warn!(
                "chain files: segment {} fetched {times} times this session ({} MB downloaded in total) — the segment cache is evicting what a wallet still reads",
                entry.index,
                total / 1_048_576
            );
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
            to_frontier: entry.to.frontier_state(),
            body,
            offsets,
            pos,
            used_ms: AtomicU64::new(self.now_ms()),
        });
        let mut loaded = self.loaded.lock().unwrap();
        loaded.retain(|s| s.index != index);
        insert_bounded(&mut loaded, seg, LOADED_SEGMENTS);
        self.segments_loaded.fetch_add(1, Ordering::Relaxed);
        Ok(n)
    }
}

/// The segments worth reading ahead for a page that ended at `daa`: the one covering it and
/// the next, and only if they START within `READ_AHEAD_SEGMENTS` segment widths of `daa`. A
/// wallet far below the oldest published segment must not download it: nothing reads it for
/// hours, the idle rule drops it after two minutes and the next page fetched it again — a
/// phone 60 days behind spent ~18 MB every two minutes that way (1.0.52-rc21).
fn segments_within_reach(segments: &[SegmentEntry], daa: u64) -> Vec<SegmentEntry> {
    let reach = daa.saturating_add(READ_AHEAD_SEGMENTS as u64 * SEGMENT_DAA);
    segments.iter().filter(|s| s.to.daa > daa && s.from.daa <= reach).take(READ_AHEAD_SEGMENTS).cloned().collect()
}

/// Add `seg`, then drop least-recently-read segments (never `seg` itself) down to `cap`. A
/// segment a wallet has moved past stops being read and goes first; the ones wallets are
/// reading are touched on every page and stay.
fn insert_bounded(loaded: &mut VecDeque<Arc<Loaded>>, seg: Arc<Loaded>, cap: usize) {
    let index = seg.index;
    loaded.push_back(seg);
    while loaded.len() > cap {
        let Some(lru) = loaded
            .iter()
            .enumerate()
            .filter(|(_, s)| s.index != index)
            .min_by_key(|(_, s)| s.used_ms.load(Ordering::Relaxed))
            .map(|(i, _)| i)
        else {
            break;
        };
        loaded.remove(lru);
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
            Arc::new(Loaded { index, from: RpcHash::from_bytes([from; 32]), to, to_daa: u64::MAX, to_frontier: None, body, offsets, pos, used_ms: AtomicU64::new(0) })
        };
        cf.loaded.lock().unwrap().push_back(mk(1, 0, 1..11)); // blocks 1..=10, after block 0
        cf.loaded.lock().unwrap().push_back(mk(2, 10, 11..21)); // blocks 11..=20, after block 10
        assert!(cf.page(RpcHash::from_bytes([0; 32]), 5).is_none(), "no sink known yet: the node serves it");
        cf.note_sink(5_000);
        let p = cf.page(RpcHash::from_bytes([0; 32]), 5).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5], "from a segment start");
        let p = cf.page(RpcHash::from_bytes([4; 32]), 3).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![5, 6, 7], "exclusive cursor inside a segment");
        // A page ends at its segment's last block (a cursor exactly there is where a wallet that
        // skipped hashing adopts the signed frontier), and the next page continues from the
        // following segment's first block: nothing skipped, nothing repeated.
        let p = cf.page(RpcHash::from_bytes([8; 32]), 6).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![9, 10], "stops at the segment's end");
        let p = cf.page(RpcHash::from_bytes([10; 32]), 6).unwrap();
        assert_eq!(p.blocks.iter().map(|b| b.hash.as_bytes()[0]).collect::<Vec<_>>(), vec![11, 12, 13, 14, 15, 16], "continues in the next segment");
        assert_eq!(p.sink_blue_score, 5_000);
        assert!(!p.reorged);
        assert!(cf.page(RpcHash::from_bytes([20; 32]), 5).is_none(), "the last block of the last segment: the node serves what follows");
        assert!(cf.page(RpcHash::from_bytes([99; 32]), 5).is_none(), "an unknown cursor");
        // A pause (the node could not confirm a page) serves nothing until it ends; it is
        // not a disable, so pages come back afterwards.
        cf.pause(std::time::Duration::from_secs(3600));
        assert!(cf.page(RpcHash::from_bytes([0; 32]), 5).is_none(), "paused");
        assert!(!cf.is_disabled());
        *cf.paused_until.lock().unwrap() = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
        assert!(cf.page(RpcHash::from_bytes([0; 32]), 5).is_some(), "the pause ended");
    }

    /// Two wallets catching up at different heights share the decoded segments. Each must keep
    /// the segment it is reading while the other loads its own: the shared-cursor version threw
    /// away a lower wallet's segment as soon as it downloaded, and the phone re-fetched it forever.
    #[test]
    fn two_wallets_at_different_heights_do_not_evict_each_other() {
        let g = RpcHash::from_bytes([9; 32]);
        let mk = |index: u64, used: u64| {
            let blocks = vec![block(index as u8, 1, 1)];
            let to = blocks[0].hash;
            let (body, n) = segment_body(&encode_segment(&g, index, &blocks), &g, index).unwrap();
            let idx = index_body(&body, n).unwrap();
            Arc::new(Loaded {
                index,
                from: RpcHash::from_bytes([index as u8; 32]),
                to,
                to_daa: index * 100,
                to_frontier: None,
                pos: idx.iter().enumerate().map(|(i, b)| (b.0, i)).collect(),
                offsets: idx.iter().map(|b| b.2).collect(),
                body,
                used_ms: AtomicU64::new(used),
            })
        };
        let held = |l: &VecDeque<Arc<Loaded>>| {
            let mut v: Vec<u64> = l.iter().map(|s| s.index).collect();
            v.sort();
            v
        };
        let mut l = VecDeque::new();
        // The tip-side wallet reads segments 50 and 51; the new 30-day wallet then loads 10 and
        // 11, BELOW it. All four are kept.
        insert_bounded(&mut l, mk(50, 1), LOADED_SEGMENTS);
        insert_bounded(&mut l, mk(51, 2), LOADED_SEGMENTS);
        insert_bounded(&mut l, mk(10, 3), LOADED_SEGMENTS);
        insert_bounded(&mut l, mk(11, 4), LOADED_SEGMENTS);
        assert_eq!(held(&l), vec![10, 11, 50, 51]);
        // Both keep reading their current segment (10 and 51); 50 and 11 are not read again.
        for s in l.iter() {
            match s.index {
                10 => s.used_ms.store(10, Ordering::Relaxed),
                51 => s.used_ms.store(11, Ordering::Relaxed),
                _ => {}
            }
        }
        // The low wallet's read-ahead loads 12: the least recently read (50, which the tip-side
        // wallet moved past) goes — not either wallet's current segment.
        insert_bounded(&mut l, mk(12, 12), LOADED_SEGMENTS);
        assert_eq!(held(&l), vec![10, 11, 12, 51]);
        // A segment that was just inserted is never the one evicted, even if older ones were
        // read more recently.
        let mut l2 = VecDeque::new();
        for i in 0..LOADED_SEGMENTS as u64 {
            insert_bounded(&mut l2, mk(i, 100), LOADED_SEGMENTS);
        }
        insert_bounded(&mut l2, mk(99, 0), LOADED_SEGMENTS);
        assert!(held(&l2).contains(&99));
        assert_eq!(l2.len(), LOADED_SEGMENTS);
    }

    fn manifest_for_test() -> Manifest {
        let b = Boundary { block: RpcHash::from_bytes([1; 32]).to_string(), daa: 10, size: 3, leaf: RpcHash::from_bytes([2; 32]).to_string(), ommers: vec![] };
        Manifest {
            zkas_chain_files: MANIFEST_VERSION,
            genesis: RpcHash::from_bytes([9; 32]).to_string(),
            segment_daa: SEGMENT_DAA,
            segments: vec![SegmentEntry { index: 7, file: "seg-7.zks".into(), sha256: "ab".repeat(32), bytes: 5, blocks: 1, from: b.clone(), to: b }],
            signature: None,
        }
    }

    /// The signature covers every field a client acts on, survives the JSON round trip the
    /// file goes through, and only the publisher's key verifies it.
    #[test]
    fn manifest_signature_binds_the_segment_list() {
        let kp = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
        let pk = kp.x_only_public_key().0.to_string();
        let mut m = manifest_for_test();
        assert!(m.verify_signature(&[pk.as_str()]).is_err(), "unsigned is refused");
        m.sign(&kp);
        let back: Manifest = serde_json::from_slice(&serde_json::to_vec_pretty(&m).unwrap()).unwrap();
        back.verify_signature(&[pk.as_str()]).expect("signed by the publisher");
        let other = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
        assert!(back.verify_signature(&[other.x_only_public_key().0.to_string().as_str()]).is_err(), "another key");
        let mut t = back.clone();
        t.segments[0].sha256 = "cd".repeat(32);
        assert!(t.verify_signature(&[pk.as_str()]).is_err(), "a swapped file hash");
        let mut t = back.clone();
        t.segments.push(t.segments[0].clone());
        assert!(t.verify_signature(&[pk.as_str()]).is_err(), "an added segment");
        let mut t = back;
        t.signature = Some("00".repeat(64));
        assert!(t.verify_signature(&[pk.as_str()]).is_err(), "a junk signature");
    }

    #[test]
    fn the_built_in_publisher_key_parses() {
        for k in PUBLISHER_KEYS {
            k.parse::<secp256k1::XOnlyPublicKey>().expect("PUBLISHER_KEYS entries are x-only keys");
        }
    }

    /// A mirror that serves a wrong file is skipped and the next mirror's copy is used; a
    /// segment no mirror serves correctly is refused.
    #[tokio::test]
    async fn a_bad_mirror_falls_back_to_a_good_one() {
        let g = RpcHash::from_bytes([9; 32]);
        let good = encode_segment(&g, 7, &[block(1, 1, 1)]);
        let dir = std::env::temp_dir().join(format!("cf-mirrors-{}", std::process::id()));
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("seg-7.zks"), b"poisoned").unwrap();
        std::fs::write(b.join("seg-7.zks"), &good).unwrap();
        let mut entry = manifest_for_test().segments.remove(0);
        entry.bytes = good.len() as u64;
        entry.sha256 = sha256_hex(&good);
        // Segment 7 of two mirrors starts at mirror 7 % 2 = 1, the second listed: the bad one.
        let cf = ChainFiles::new(&format!("{},{}", b.display(), a.display()), g);
        assert_eq!(cf.fetch_segment(&entry).await.unwrap(), good, "bad mirror a first, good b after");
        std::fs::write(b.join("seg-7.zks"), b"poisoned too").unwrap();
        assert!(cf.fetch_segment(&entry).await.is_err(), "no mirror has the right bytes");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(cf.stats().source, format!("{},{}", b.display(), a.display()));
    }

    /// A refused manifest is not re-requested on every page: one attempt, then quiet until
    /// `MANIFEST_RETRY` has passed.
    #[tokio::test]
    async fn a_refused_manifest_is_not_refetched_on_every_page() {
        let dir = std::env::temp_dir().join(format!("cf-nomanifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MANIFEST_FILE), b"not json").unwrap();
        let cf = ChainFiles::new(&dir.display().to_string(), RpcHash::from_bytes([9; 32]));
        assert!(cf.manifest().await.is_none());
        let first = *cf.manifest_failed.lock().unwrap();
        assert!(first.is_some());
        // Now a good manifest appears; inside the back-off window it is not even looked at.
        let mut m = manifest_for_test();
        m.segments.clear();
        std::fs::write(dir.join(MANIFEST_FILE), serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(cf.manifest().await.is_none(), "still backing off");
        assert_eq!(*cf.manifest_failed.lock().unwrap(), first, "no new attempt was made");
        // Once the window has passed it is fetched and used.
        *cf.manifest_failed.lock().unwrap() = Some(std::time::Instant::now() - MANIFEST_RETRY - std::time::Duration::from_secs(1));
        assert!(cf.manifest().await.is_some());
        assert!(cf.manifest_failed.lock().unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Version 1 is what the looping 1.0.52-rc20 cache reads; the published manifest must not be
    /// one, and a client of this version must not accept one either.
    #[test]
    fn version_one_manifests_are_not_used() {
        let g = RpcHash::from_bytes([9; 32]);
        let mut m = manifest_for_test();
        assert!(m.check(&g).is_ok());
        m.zkas_chain_files = 1;
        assert!(m.check(&g).is_err());
        assert_eq!(MANIFEST_VERSION, 2);
    }

    /// A wallet far below the published range reads nothing ahead; one inside it, or about to
    /// enter it, reads the covering segment and the next.
    #[test]
    fn read_ahead_only_within_reach() {
        let seg = |index: u64| {
            let mut e = manifest_for_test().segments.remove(0);
            e.index = index;
            e.from.daa = index * SEGMENT_DAA - 100;
            e.to.daa = (index + 1) * SEGMENT_DAA - 100;
            e
        };
        let published: Vec<_> = (90..95).map(seg).collect();
        let idx = |v: Vec<SegmentEntry>| v.iter().map(|s| s.index).collect::<Vec<_>>();
        assert!(segments_within_reach(&published, 72 * SEGMENT_DAA).is_empty(), "18 segments below: nothing");
        assert_eq!(idx(segments_within_reach(&published, 89 * SEGMENT_DAA)), vec![90, 91], "one segment below: ready when it arrives");
        assert_eq!(idx(segments_within_reach(&published, 91 * SEGMENT_DAA)), vec![91, 92], "inside: covering + next");
        assert!(segments_within_reach(&published, 96 * SEGMENT_DAA).is_empty(), "past the newest: the node");
    }

    #[test]
    fn a_gateway_page_round_trips_and_names_its_network() {
        let g = RpcHash::from_bytes([9; 32]);
        let page = GetShieldedBlocksResponse { blocks: (0..7u8).map(|i| block(i, (i % 3) as usize, (i % 2) as usize)).collect(), reorged: true, sink_blue_score: 777 };
        let bytes = encode_page(&g, &page);
        let back = decode_page(&bytes, &g).unwrap();
        assert_eq!(back.sink_blue_score, 777);
        assert!(back.reorged);
        assert_eq!(blocks_digest(&back.blocks), blocks_digest(&page.blocks));
        assert!(decode_page(&bytes, &RpcHash::from_bytes([8; 32])).is_err());
        assert!(decode_page(b"junk", &g).is_err());
    }
}

