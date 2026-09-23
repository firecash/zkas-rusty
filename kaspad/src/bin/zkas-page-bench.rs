//! Where the time in a `GetShieldedBlocks` page actually goes.
//!
//! Page fetch is the dominant term in wallet sync wall-clock, and the split between
//! "the node reads the archive" and "the node dresses the archive up for the wire"
//! had never been measured — only assumed. This times each phase separately so the
//! assumption can be replaced with numbers.
//!
//! Two modes, deliberately separate:
//!
//! * `--db <consensus-NNN>` — server-side phases, measured by doing exactly what
//!   `get_shielded_blocks_call` does, against a **read-only** open of the database.
//!   Read-only means this is safe to point at a running node (same guarantee
//!   `zkas-scan-dump` relies on), so the archive being measured is the real one with
//!   its real record-layout mix, not a synthetic.
//! * `--rpc <host:port>` — end-to-end client-observed page latency against a node,
//!   which is the number a wallet actually pays. Point this at a SCRATCH node.
//!
//! The difference between the two is dispatch + protobuf framing + loopback + client
//! decode, and that residual is the point of running both.

use kaspa_consensus::model::stores::selected_chain::{DbSelectedChainStore, SelectedChainStoreReader};
use kaspa_consensus::model::stores::shielded::{
    DbShieldedScanBlockStore, ShieldedScanBlockData, ShieldedScanBlockStoreReader, ShieldedScanTx,
};
use kaspa_database::prelude::{CachePolicy, ConnBuilder, DbKey};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_rpc_core::model::hex_cnv::*;
use kaspa_rpc_core::{RpcShieldedChainBlock, RpcShieldedCoinbaseOutput};
use serde::Deserialize;
use std::time::{Duration, Instant};

/// `ShieldedScanBlockData` as written before `coinbase_commitments` existed. Mirrored
/// here (the consensus copy is private) so the bench can report how much of the archive
/// still takes the legacy re-read path — a cost that is invisible from the outside.
#[derive(Deserialize)]
#[allow(dead_code)]
struct LegacyScan {
    blue_score: u64,
    daa_score: u64,
    timestamp: u64,
    coinbase_txid: Hash,
    coinbase_outputs: Vec<(Vec<u8>, u64)>,
    accepted: Vec<ShieldedScanTx>,
}

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

fn argn<T: std::str::FromStr>(name: &str, default: T) -> T {
    arg(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[derive(Default)]
struct Phases {
    chain_index: Duration,
    raw_get: Duration,
    bincode_decode: Duration,
    legacy_retry: Duration,
    store_get_total: Duration,
    build_rpc: Duration,
    hex_encode: Duration,
    proto_encode: Duration,
    proto_encode_bytes: Duration,
    hex_decode: Duration,
    gzip_compress: Duration,
    gzip_decompress: Duration,
    proto_decode: Duration,
    gzip_wire_bytes: usize,
    gzip_wire_bytes_as_bytes: usize,
    legacy_records: usize,
    records: usize,
    actions: usize,
    action_bytes: usize,
    proto_wire_bytes: usize,
    proto_wire_bytes_as_bytes: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(addr) = arg("--rpc") {
        return rpc_mode(&addr);
    }
    let Some(db_path) = arg("--db") else {
        eprintln!("usage:");
        eprintln!("  zkas-page-bench --db <consensus-NNN> [--start <chain index>] [--pages N] [--limit N]");
        eprintln!("  zkas-page-bench --rpc <host:port> --start-hash <hash> [--pages N] [--limit N]");
        std::process::exit(2);
    };
    let pages: usize = argn("--pages", 10);
    let limit: usize = argn("--limit", 1000);

    let db = ConnBuilder::default().with_db_path(db_path.into()).with_files_limit(128).build_readonly()?;
    // `CachePolicy::Empty` on purpose: a warm in-process cache would measure the cache,
    // not the archive read a real page pays on a cold cursor.
    let scans = DbShieldedScanBlockStore::new(db.clone(), CachePolicy::Empty);
    let chain = DbSelectedChainStore::new(db.clone(), CachePolicy::Empty);
    let (tip_index, _) = chain.get_tip()?;
    let start: u64 = argn("--start", tip_index.saturating_sub((pages * limit) as u64 + 5_000));
    eprintln!("chain tip index {tip_index}, benching {pages} pages of {limit} from index {start}");

    let mut p = Phases::default();
    let overall = Instant::now();
    let mut per_page_ms: Vec<f64> = Vec::new();

    for page in 0..pages {
        let page_started = Instant::now();
        let lo = start + (page * limit) as u64;

        // Phase 1 — enumerate the page's hashes from the retained chain index.
        let t = Instant::now();
        let mut hashes = Vec::with_capacity(limit);
        for i in lo..(lo + limit as u64).min(tip_index) {
            if let Ok(h) = chain.get_by_index(i) {
                hashes.push(h);
            }
        }
        p.chain_index += t.elapsed();

        let mut blocks: Vec<RpcShieldedChainBlock> = Vec::with_capacity(hashes.len());
        for hash in &hashes {
            // Phase 2a — raw RocksDB read, no decode. This is the disk/page-cache term.
            let key = DbKey::new(&[DatabaseStorePrefixes::ShieldedScanBlock.into()][..], *hash);
            let t = Instant::now();
            let raw = db.get_pinned(&key)?;
            p.raw_get += t.elapsed();
            let Some(raw) = raw else { continue };

            // Phase 2b — bincode decode of the current layout.
            let t = Instant::now();
            let decoded = bincode::deserialize::<ShieldedScanBlockData>(&raw);
            p.bincode_decode += t.elapsed();

            let data = match decoded {
                Ok(d) => d,
                Err(_) => {
                    // Phase 2c — the `5d94f7f` legacy fallback: the current-layout decode
                    // ran off the end, so the bytes are re-decoded as the pre-field layout.
                    // Counted separately because a mostly-legacy archive pays decode twice
                    // per block and nothing upstream reports it.
                    let t = Instant::now();
                    let l = bincode::deserialize::<LegacyScan>(&raw)?;
                    p.legacy_retry += t.elapsed();
                    p.legacy_records += 1;
                    ShieldedScanBlockData {
                        blue_score: l.blue_score,
                        daa_score: l.daa_score,
                        timestamp: l.timestamp,
                        coinbase_txid: l.coinbase_txid,
                        coinbase_outputs: l.coinbase_outputs,
                        coinbase_commitments: Vec::new(),
                        accepted: l.accepted,
                    }
                }
            };
            p.records += 1;

            // Control: what the production path actually costs end to end, fallback included.
            let t = Instant::now();
            let _ = scans.get(*hash)?;
            p.store_get_total += t.elapsed();

            // Phase 3 — assemble the RPC model (the clones `get_shielded_blocks_call` makes).
            let t = Instant::now();
            let coinbase_outputs: Vec<RpcShieldedCoinbaseOutput> = data
                .coinbase_outputs
                .iter()
                .enumerate()
                .map(|(i, (spk, value))| RpcShieldedCoinbaseOutput {
                    script_public_key: spk.clone(),
                    value: *value,
                    commitment: data.coinbase_commitments.get(i).copied(),
                })
                .collect();
            let accepted_actions: Vec<Vec<u8>> = data.accepted.iter().map(|tx| tx.action_bytes.clone()).collect();
            let accepted_txids: Vec<Hash> = data.accepted.iter().map(|tx| tx.txid).collect();
            for a in &accepted_actions {
                p.actions += a.len() / 148;
                p.action_bytes += a.len();
            }
            blocks.push(RpcShieldedChainBlock {
                hash: *hash,
                blue_score: data.blue_score,
                daa_score: data.daa_score,
                coinbase_txid: data.coinbase_txid,
                coinbase_outputs,
                accepted_actions,
                accepted_txids,
                timestamp: data.timestamp,
            });
            p.build_rpc += t.elapsed();
        }

        // Phase 4 — hex-encode every compact record, which is what the wire format
        // currently demands (`repeated string acceptedActions`).
        let t = Instant::now();
        let hexed: Vec<Vec<String>> =
            blocks.iter().map(|b| b.accepted_actions.iter().map(|a| a.to_rpc_hex()).collect()).collect();
        p.hex_encode += t.elapsed();

        // Phase 5 — protobuf serialisation, both ways, on identical data.
        let t = Instant::now();
        let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
        prost_encode_hex(&blocks, &hexed, &mut buf);
        p.proto_encode += t.elapsed();
        p.proto_wire_bytes += buf.len();

        let t = Instant::now();
        let mut buf2: Vec<u8> = Vec::with_capacity(1 << 20);
        prost_encode_bytes(&blocks, &mut buf2);
        p.proto_encode_bytes += t.elapsed();
        p.proto_wire_bytes_as_bytes += buf2.len();

        // Phase 6 — the client's side of the hex tax.
        let t = Instant::now();
        let mut sink = 0usize;
        for blk in &hexed {
            for h in blk {
                sink += Vec::<u8>::from_rpc_hex(h)?.len();
            }
        }
        p.hex_decode += t.elapsed();
        std::hint::black_box(sink);

        // Phase 7 — gzip. tonic is configured `send_compressed(Gzip)` /
        // `accept_compressed(Gzip)` on both the server and the client
        // (`connection_handler.rs:137`, `client/src/lib.rs:605`), unconditionally and
        // for every method, so EVERY byte of this page is deflated on the way out and
        // inflated on the way in — including over loopback, where there is no link to
        // save. Nothing in the fetch path reports this, so it is priced here.
        let t = Instant::now();
        let gz = {
            use flate2::{Compression, write::GzEncoder};
            use std::io::Write;
            let mut e = GzEncoder::new(Vec::with_capacity(buf.len() / 2), Compression::default());
            e.write_all(&buf).unwrap();
            e.finish().unwrap()
        };
        p.gzip_compress += t.elapsed();
        p.gzip_wire_bytes += gz.len();

        let t = Instant::now();
        {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut d = GzDecoder::new(&gz[..]);
            let mut out = Vec::with_capacity(buf.len());
            d.read_to_end(&mut out).unwrap();
            std::hint::black_box(out.len());
        }
        p.gzip_decompress += t.elapsed();

        // The same page carried as bytes, gzipped, so the wire comparison is like for like.
        {
            use flate2::{Compression, write::GzEncoder};
            use std::io::Write;
            let mut e = GzEncoder::new(Vec::with_capacity(buf2.len() / 2), Compression::default());
            e.write_all(&buf2).unwrap();
            p.gzip_wire_bytes_as_bytes += e.finish().unwrap().len();
        }

        // Phase 8 — what the client pays to turn the page back into RPC types:
        // prost decode plus the `try_from` conversion, which is where the hex comes off.
        let t = Instant::now();
        {
            use kaspa_grpc_core::protowire;
            use prost::Message;
            let decoded = protowire::GetShieldedBlocksResponseMessage::decode(&buf[..]).unwrap();
            let back: Result<kaspa_rpc_core::GetShieldedBlocksResponse, _> = (&decoded).try_into();
            std::hint::black_box(back.map(|r| r.blocks.len()).unwrap_or(0));
        }
        p.proto_decode += t.elapsed();

        per_page_ms.push(ms(page_started.elapsed()));
    }

    let total = overall.elapsed();
    let n = pages as f64;
    println!("\n=== server-side page phases, {pages} pages x {limit} blocks ===");
    println!("records decoded          {} ({} legacy-layout re-reads)", p.records, p.legacy_records);
    println!("compact actions          {} ({:.1} KiB raw)", p.actions, p.action_bytes as f64 / 1024.0);
    println!("--- per page (mean ms) ---");
    println!("chain index enumerate    {:8.2}", ms(p.chain_index) / n);
    println!("rocksdb get_pinned       {:8.2}", ms(p.raw_get) / n);
    println!("bincode decode           {:8.2}", ms(p.bincode_decode) / n);
    println!("  legacy-layout retry    {:8.2}", ms(p.legacy_retry) / n);
    println!("build RPC model (clones) {:8.2}", ms(p.build_rpc) / n);
    println!("hex ENCODE actions       {:8.2}", ms(p.hex_encode) / n);
    println!("protobuf encode (hex)    {:8.2}   -> {:.1} KiB wire", ms(p.proto_encode) / n, p.proto_wire_bytes as f64 / 1024.0 / n);
    println!("protobuf encode (bytes)  {:8.2}   -> {:.1} KiB wire", ms(p.proto_encode_bytes) / n, p.proto_wire_bytes_as_bytes as f64 / 1024.0 / n);
    println!("hex DECODE (client side) {:8.2}", ms(p.hex_decode) / n);
    println!("gzip COMPRESS (server)   {:8.2}   -> {:.1} KiB on the wire", ms(p.gzip_compress) / n, p.gzip_wire_bytes as f64 / 1024.0 / n);
    println!("gzip DECOMPRESS (client) {:8.2}", ms(p.gzip_decompress) / n);
    println!("prost decode + try_from  {:8.2}   (client)", ms(p.proto_decode) / n);
    println!("  [bytes wire, gzipped]  {:8}   -> {:.1} KiB", "", p.gzip_wire_bytes_as_bytes as f64 / 1024.0 / n);
    println!("[control] store.get()    {:8.2}  (production read path, fallback included)", ms(p.store_get_total) / n);
    println!("--- total wall ---");
    println!("bench wall per page      {:8.2}", ms(total) / n);
    println!("per-page ms: {per_page_ms:?}");
    Ok(())
}

/// Encode the response exactly as the current wire does: actions as hex strings.
fn prost_encode_hex(blocks: &[RpcShieldedChainBlock], hexed: &[Vec<String>], out: &mut Vec<u8>) {
    use kaspa_grpc_core::protowire;
    use prost::Message;
    let msg = protowire::GetShieldedBlocksResponseMessage {
        blocks: blocks
            .iter()
            .zip(hexed)
            .map(|(b, h)| protowire::RpcShieldedChainBlock {
                hash: b.hash.to_string(),
                blue_score: b.blue_score,
                daa_score: b.daa_score,
                coinbase_txid: b.coinbase_txid.to_string(),
                coinbase_outputs: b
                    .coinbase_outputs
                    .iter()
                    .map(|o| protowire::RpcShieldedCoinbaseOutput {
                        script_public_key: o.script_public_key.to_rpc_hex(),
                        value: o.value,
                        commitment: o.commitment.map(|c| c.to_vec()).unwrap_or_default(),
                    })
                    .collect(),
                accepted_actions: h.clone(),
                accepted_txids: b.accepted_txids.iter().map(|t| t.to_string()).collect(),
                timestamp: b.timestamp,
                accepted_actions_bin: Vec::new(),
            })
            .collect(),
        reorged: false,
        sink_blue_score: 0,
        actions_are_binary: false,
        error: None,
    };
    msg.encode(out).expect("encode");
}

/// Encode the same response with the actions carried as raw bytes, so the two wire
/// shapes are compared on identical data in the same process.
fn prost_encode_bytes(blocks: &[RpcShieldedChainBlock], out: &mut Vec<u8>) {
    use prost::Message;
    // Hand-rolled: field 6 of RpcShieldedChainBlock as length-delimited bytes.
    // Encoding the real message type would require the proto change to be in place;
    // this reproduces its exact wire cost without it.
    let mut blocks_buf: Vec<u8> = Vec::with_capacity(1 << 20);
    for b in blocks {
        let mut f: Vec<u8> = Vec::with_capacity(4096);
        prost::encoding::string::encode(1, &b.hash.to_string(), &mut f);
        prost::encoding::uint64::encode(2, &b.blue_score, &mut f);
        prost::encoding::uint64::encode(3, &b.daa_score, &mut f);
        prost::encoding::string::encode(4, &b.coinbase_txid.to_string(), &mut f);
        for o in &b.coinbase_outputs {
            let mut of: Vec<u8> = Vec::with_capacity(128);
            prost::encoding::string::encode(1, &o.script_public_key.to_rpc_hex(), &mut of);
            prost::encoding::uint64::encode(2, &o.value, &mut of);
            if let Some(c) = o.commitment {
                prost::encoding::bytes::encode(3, &c.to_vec(), &mut of);
            }
            prost::encoding::encode_key(5, prost::encoding::WireType::LengthDelimited, &mut f);
            prost::encoding::encode_varint(of.len() as u64, &mut f);
            f.extend_from_slice(&of);
        }
        for a in &b.accepted_actions {
            prost::encoding::bytes::encode(6, a, &mut f);
        }
        for t in &b.accepted_txids {
            prost::encoding::string::encode(7, &t.to_string(), &mut f);
        }
        prost::encoding::uint64::encode(8, &b.timestamp, &mut f);
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, &mut blocks_buf);
        prost::encoding::encode_varint(f.len() as u64, &mut blocks_buf);
        blocks_buf.extend_from_slice(&f);
    }
    out.extend_from_slice(&blocks_buf);
    let _ = Message::encoded_len(&prost::bytes::Bytes::new());
}

#[tokio::main(flavor = "multi_thread")]
async fn rpc_mode(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    use kaspa_grpc_client::GrpcClient;
    use kaspa_rpc_core::api::rpc::RpcApi;
    use std::str::FromStr;

    let pages: usize = argn("--pages", 10);
    let limit: u64 = argn("--limit", 1000);
    let url = if addr.starts_with("grpc://") { addr.to_string() } else { format!("grpc://{addr}") };
    let client = GrpcClient::connect(url).await?;

    let mut cursor = match arg("--start-hash") {
        Some(h) => Hash::from_str(&h)?,
        None => {
            // Default to a deep cursor: the DAA-locator walk a wallet does is not what
            // is being measured, so start from the node's own history floor instead.
            let info = client.get_block_dag_info().await?;
            info.pruning_point_hash
        }
    };

    // Control: the cheapest RPC this node serves, on the same connection. Whatever it
    // costs is the floor under EVERY call — session acquisition, blocking-pool dispatch,
    // tonic framing, loopback, scheduler — and none of it is attributable to page size,
    // archive reads or the action encoding. Without this the residual after the measured
    // server phases is just an unexplained number.
    let mut floor = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let _ = client.get_block_dag_info().await?;
        floor.push(ms(t.elapsed()));
    }
    floor.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("control: trivial RPC (GetBlockDagInfo) median {:.2} ms, p90 {:.2} ms", floor[10], floor[18]);

    println!("=== end-to-end GetShieldedBlocks, {pages} pages x {limit} blocks ===");
    // `--hex` asks the node for the legacy hex encoding, so before/after can be compared
    // on ONE binary against ONE node process. Rebuilding between arms would fold compiler
    // and page-cache differences into the number being attributed to the wire change.
    let want_binary = !std::env::args().any(|a| a == "--hex");
    println!("encoding requested: {}", if want_binary { "binary (acceptedActionsBin)" } else { "hex (acceptedActions)" });
    let mut times = Vec::new();
    let mut total_actions = 0usize;
    let mut total_bytes = 0usize;
    for i in 0..pages {
        let t = Instant::now();
        let resp = client
            .get_shielded_blocks_call(
                None,
                kaspa_rpc_core::GetShieldedBlocksRequest {
                    start_hash: cursor,
                    limit,
                    metadata_only: false,
                    binary_actions: want_binary,
                },
            )
            .await?;
        if resp.actions_are_binary != want_binary {
            println!("  NOTE: node answered actions_are_binary={} (asked {want_binary})", resp.actions_are_binary);
        }
        let dt = t.elapsed();
        let actions: usize = resp.blocks.iter().flat_map(|b| b.accepted_actions.iter()).map(|a| a.len() / 148).sum();
        let bytes: usize = resp.blocks.iter().flat_map(|b| b.accepted_actions.iter()).map(|a| a.len()).sum();
        total_actions += actions;
        total_bytes += bytes;
        let n = resp.blocks.len();
        println!("page {i:3}  {:8.2} ms  {n:5} blocks  {actions:6} actions  reorged={}", ms(dt), resp.reorged);
        times.push(ms(dt));
        match resp.blocks.last() {
            Some(b) => cursor = b.hash,
            None => break,
        }
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean: f64 = times.iter().sum::<f64>() / times.len() as f64;
    let blocks_per_s = (limit as f64) / (mean / 1000.0);
    println!("\nmean {mean:.1} ms/page   median {:.1} ms   {blocks_per_s:.0} blocks/s", times[times.len() / 2]);
    println!("payload {:.1} KiB raw compact actions over {pages} pages ({total_actions} actions)", total_bytes as f64 / 1024.0);
    Ok(())
}
