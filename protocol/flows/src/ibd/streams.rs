//!
//! Logical stream abstractions used throughout the IBD negotiation protocols
//!

use kaspa_consensus_core::{
    errors::consensus::ConsensusError,
    header::Header,
    tx::{TransactionOutpoint, UtxoEntry},
};
use kaspa_core::{debug, info};
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::{DEFAULT_TIMEOUT, ProtocolError},
    convert::{header::HeaderFormat, header::Versioned, model::trusted::TrustedDataEntry},
    make_message,
    pb::{
        RequestNextHeadersMessage, RequestNextPruningPointAndItsAnticoneBlocksMessage, RequestNextPruningPointShieldedChunkMessage,
        RequestNextPruningPointSmtChunkMessage, RequestNextPruningPointUtxoSetChunkMessage, kaspad_message::Payload,
    },
};
use std::sync::Arc;
use tokio::time::timeout;

pub const IBD_BATCH_SIZE: usize = 99;

/// Most block hashes one `RequestIbdBlocks`, `RequestBlockBodies` or `RequestRelayBlocks` may name.
///
/// The serving flows answered whatever list arrived, one block per hash, and the only bound on the
/// list was the 256 MB transport cap -- ~7.9M hashes, i.e. millions of block reads and responses
/// from a single message. Every requester in this tree names at most [`IBD_BATCH_SIZE`] per message
/// (IBD chunks its hash lists by it; relay and orphan resolution ask for one block at a time), so
/// an honest peer never comes near this; the factor 2 is headroom, not a need.
pub const MAX_REQUESTED_BLOCKS: usize = 2 * IBD_BATCH_SIZE;

/// Refuses a block request naming more than [`MAX_REQUESTED_BLOCKS`] hashes. Checked on the decoded
/// message before its hashes are converted, and before any block is read.
pub fn check_requested_blocks(kind: &'static str, count: usize) -> Result<(), ProtocolError> {
    if count > MAX_REQUESTED_BLOCKS {
        return Err(ProtocolError::OtherOwned(format!("{kind} names {count} blocks, above the {MAX_REQUESTED_BLOCKS} ceiling")));
    }
    Ok(())
}

/// The `max_blocks` floor the `RequestHeaders` server walks per chunk (see [`request_headers_max_blocks`]).
pub const REQUEST_HEADERS_MAX_BLOCKS: usize = 1 << 10;

/// The `max_blocks` the `RequestHeaders` server walks per chunk: [`REQUEST_HEADERS_MAX_BLOCKS`], raised
/// to `mergeset_size_limit + 1` where that is larger (consensus requires `max_blocks > mergeset_size_limit`).
pub fn request_headers_max_blocks(mergeset_size_limit: u64) -> usize {
    REQUEST_HEADERS_MAX_BLOCKS.max(mergeset_size_limit as usize + 1)
}

/// The `RequestAntipast` server bounds its traversal to this many mergesets (see [`antipast_traversal_limit`]).
pub const ANTIPAST_TRAVERSAL_MERGESETS: u64 = 4;

/// The traversal limit the `RequestAntipast` server passes to `get_antipast_from_pov`.
pub fn antipast_traversal_limit(mergeset_size_limit: u64) -> u64 {
    mergeset_size_limit * ANTIPAST_TRAVERSAL_MERGESETS
}

/// Most headers one `BlockHeaders` message may carry, for a network with `mergeset_size_limit`.
///
/// A syncer's header chunk was bounded only by the 256 MB transport cap (~1M headers), and each
/// header in it becomes a concurrent validation job before the first one is judged. The honest
/// senders are bounded by construction:
/// * a `RequestHeaders` chunk holds at most [`request_headers_max_blocks`]` + 1`
///   headers (`antipast_hashes_between` stops before a chain block's mergeset would pass
///   `max_blocks`, then appends the highest chain block reached);
/// * a `RequestAntipast` reply holds at most [`antipast_traversal_limit`] = `4 * mergeset` (the
///   output is a subset of what it traverses).
///
/// `REQUEST_HEADERS_MAX_BLOCKS + 4 * mergeset + 2` is above both, and the factor 2 is headroom.
/// Mainnet (`mergeset_size_limit` 180): 2 * (1024 + 720 + 2) = 3,492.
pub fn max_headers_per_message(mergeset_size_limit: u64) -> usize {
    let mergeset = usize::try_from(mergeset_size_limit).unwrap_or(usize::MAX);
    REQUEST_HEADERS_MAX_BLOCKS
        .saturating_add(mergeset.saturating_mul(ANTIPAST_TRAVERSAL_MERGESETS as usize))
        .saturating_add(2)
        .saturating_mul(2)
}

/// UTXOs the pruning-point UTXO set server puts in one chunk.
pub const PRUNING_POINT_UTXO_CHUNK_SIZE: usize = 1000;

/// Most UTXOs one `PruningPointUtxoSetChunk` may carry: twice what an honest server sends.
pub const MAX_PRUNING_POINT_UTXO_CHUNK_LEN: usize = 2 * PRUNING_POINT_UTXO_CHUNK_SIZE;

/// Maximum number of SMT lane entries carried by a single `SmtLaneChunkMessage`.
#[cfg(not(feature = "test-smt-small-chunks"))]
pub const SMT_CHUNK_SIZE: usize = 4096;
#[cfg(feature = "test-smt-small-chunks")]
pub const SMT_CHUNK_SIZE: usize = 4;

/// After receiving every `SMT_FLOW_CONTROL_WINDOW`-th chunk the receiver asks for
/// more. Each chunk already batches thousands of lanes, so 10 is plenty of
/// round-trips while keeping the in-flight message count far below the 256
/// incoming-route capacity.
#[cfg(not(feature = "test-smt-small-chunks"))]
pub const SMT_FLOW_CONTROL_WINDOW: usize = 10;
#[cfg(feature = "test-smt-small-chunks")]
pub const SMT_FLOW_CONTROL_WINDOW: usize = 2;

/// Maximum number of 32-byte nullifiers carried by a single `ShieldedNullifierChunkMessage`.
#[cfg(not(feature = "test-smt-small-chunks"))]
pub const SHIELDED_CHUNK_SIZE: usize = 4096;
#[cfg(feature = "test-smt-small-chunks")]
pub const SHIELDED_CHUNK_SIZE: usize = 4;

/// Chunks a pruning-point export server (SMT lanes, shielded nullifiers) may have read from disk
/// ahead of the one it is sending.
///
/// The export is read on a blocking thread and handed to the flow through a channel that sits
/// BEFORE `Router::enqueue_paced`, so the router's per-connection byte budget never sees what is
/// buffered in it. With 256 slots of 4096 entries it read ~34 MB (more for SMT lanes with proofs)
/// ahead of a peer that asked for the export and then never requested the next window. The flow
/// only ever sends one chunk at a time, so one chunk of read-ahead keeps the disk read overlapped
/// with the send and nothing more.
pub const EXPORT_READ_AHEAD_CHUNKS: usize = 1;

/// How long a pruning-point export server waits for the peer's request for the next window.
/// Generous: a small syncing node may take minutes between windows while it imports. Bounded: a
/// requester that never asks would otherwise hold the flow, its open store iterator and the
/// blocking reader thread for the life of the connection.
pub const EXPORT_NEXT_WINDOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

pub struct TrustedEntryStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    header_format: HeaderFormat,
    i: usize,
}

impl<'a, 'b> TrustedEntryStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute, header_format: HeaderFormat) -> Self {
        Self { router, incoming_route, header_format, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<TrustedDataEntry>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockWithTrustedDataV4(payload)) => {
                            let entry: TrustedDataEntry = Versioned(self.header_format, payload).try_into()?;
                            Ok(Some(entry))
                        }
                        Some(Payload::DoneBlocksWithTrustedData(_)) => {
                            debug!("trusted entry stream completed after {} items", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockWithTrustedDataV4 | Payload::DoneBlocksWithTrustedData),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            self.i += 1;
            if self.i.is_multiple_of(IBD_BATCH_SIZE) {
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointAndItsAnticoneBlocks,
                        RequestNextPruningPointAndItsAnticoneBlocksMessage {}
                    ))
                    .await?;
            }
        }

        res
    }
}

/// A chunk of headers
pub type HeadersChunk = Vec<Arc<Header>>;

pub struct HeadersChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    header_format: HeaderFormat,
    /// See [`max_headers_per_message`].
    max_headers: usize,
    i: usize,
}

impl<'a, 'b> HeadersChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute, header_format: HeaderFormat, max_headers: usize) -> Self {
        Self { router, incoming_route, header_format, max_headers, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<HeadersChunk>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockHeaders(payload)) => {
                            if payload.block_headers.is_empty() {
                                // The syncer should have sent a done message if the search completed, and not an empty list
                                Err(ProtocolError::Other("Received an empty headers message"))
                            } else if payload.block_headers.len() > self.max_headers {
                                Err(ProtocolError::OtherOwned(format!(
                                    "Received a headers message of {} headers, above the {} ceiling",
                                    payload.block_headers.len(),
                                    self.max_headers
                                )))
                            } else {
                                Ok(Some(Versioned(self.header_format, payload).try_into()?))
                            }
                        }
                        Some(Payload::DoneHeaders(_)) => {
                            debug!("headers chunk stream completed after {} chunks", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockHeaders | Payload::DoneHeaders),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            self.i += 1;
            self.router.enqueue(make_message!(Payload::RequestNextHeaders, RequestNextHeadersMessage {})).await?;
        }

        res
    }
}

/// A chunk of UTXOs
pub type UtxosetChunk = Vec<(TransactionOutpoint, UtxoEntry)>;

pub struct PruningPointUtxosetChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize, // Chunk index
    utxo_count: usize,
}

impl<'a, 'b> PruningPointUtxosetChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0, utxo_count: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<UtxosetChunk>, ProtocolError> {
        let res: Result<Option<UtxosetChunk>, ProtocolError> = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::PruningPointUtxoSetChunk(payload)) => {
                            if payload.outpoint_and_utxo_entry_pairs.len() > MAX_PRUNING_POINT_UTXO_CHUNK_LEN {
                                return Err(ProtocolError::OtherOwned(format!(
                                    "Received a UTXO set chunk of {} entries, above the {MAX_PRUNING_POINT_UTXO_CHUNK_LEN} ceiling",
                                    payload.outpoint_and_utxo_entry_pairs.len()
                                )));
                            }
                            Ok(Some(payload.try_into()?))
                        }
                        Some(Payload::DonePruningPointUtxoSetChunks(_)) => {
                            info!("Finished receiving the UTXO set. Total UTXOs: {}", self.utxo_count);
                            Ok(None)
                        }
                        Some(Payload::UnexpectedPruningPoint(_)) => {
                            // Although this can happen also to an honest syncer (if his pruning point moves during the sync),
                            // we prefer erring and disconnecting to avoid possible exploits by a syncer repeating this failure
                            Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint))
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(
                                Payload::PruningPointUtxoSetChunk
                                    | Payload::DonePruningPointUtxoSetChunks
                                    | Payload::UnexpectedPruningPoint
                            ),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(chunk)) = res {
            self.i += 1;
            self.utxo_count += chunk.len();
            if self.i.is_multiple_of(IBD_BATCH_SIZE) {
                info!("Received {} UTXO set chunks so far, totaling in {} UTXOs", self.i, self.utxo_count);
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointUtxoSetChunk,
                        RequestNextPruningPointUtxoSetChunkMessage {}
                    ))
                    .await?;
            }
            Ok(Some(chunk))
        } else {
            res
        }
    }
}

const SMT_PROOF_INTERVAL: usize = kaspa_consensus_core::api::SMT_PROOF_INTERVAL;

/// Stream of SMT lane chunks. Flow-controlled: after every [`SMT_FLOW_CONTROL_WINDOW`]
/// chunks received the stream enqueues a [`RequestNextPruningPointSmtChunkMessage`]
/// back to the peer. The total number of lanes is conveyed via the metadata header
/// (`active_lanes_count`), so no explicit `Done` sentinel is required — both sides
/// terminate naturally once that many lanes have been transferred.
///
/// Enforces that the first and every [`SMT_PROOF_INTERVAL`]-th entry carries proof bytes.
pub struct SmtStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    expected_count: u64,
    lane_count: u64,
    chunks_received: usize,
}

impl<'a, 'b> SmtStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, expected_count: 0, lane_count: 0, chunks_received: 0 }
    }

    pub async fn recv_metadata(&mut self) -> Result<kaspa_consensus_core::api::SmtExportMetadata, ProtocolError> {
        match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::SmtMetadata(payload)) => {
                    use kaspa_consensus_core::api::SmtExportMetadata;
                    // Wire: 96 bytes = lanes_root || payload_and_ctx_digest || parent_seq_commit.
                    let (chunks, rem) = payload.data.as_chunks::<32>();
                    if !rem.is_empty() {
                        return Err(ProtocolError::Other("SmtMetadata data length not a multiple of 32 bytes"));
                    }
                    self.expected_count = payload.active_lanes_count;
                    let md = match *chunks {
                        [lanes_root, payload_and_ctx_digest, parent_seq_commit] => {
                            let [lanes_root, payload_and_ctx_digest, parent_seq_commit] =
                                [lanes_root, payload_and_ctx_digest, parent_seq_commit].map(Hash::from_bytes);
                            SmtExportMetadata {
                                lanes_root,
                                payload_and_ctx_digest,
                                parent_seq_commit,
                                active_lanes_count: payload.active_lanes_count,
                            }
                        }
                        _ => return Err(ProtocolError::Other("SmtMetadata data must be 96 bytes")),
                    };
                    Ok(md)
                }
                Some(Payload::UnexpectedPruningPoint(_)) => Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint)),
                _ => Err(ProtocolError::UnexpectedMessage(stringify!(Payload::SmtMetadata), msg.payload.as_ref().map(|v| v.into()))),
            },
            Ok(None) => Err(ProtocolError::ConnectionClosed),
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        }
    }

    /// Receives the next chunk of lanes from the peer. Returns `Ok(None)` once
    /// `active_lanes_count` lanes have been consumed.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<kaspa_consensus_core::api::ImportLane>>, ProtocolError> {
        if self.lane_count >= self.expected_count {
            return Ok(None);
        }

        let payload = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::SmtLaneChunk(payload)) => payload,
                Some(Payload::UnexpectedPruningPoint(_)) => {
                    return Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint));
                }
                _ => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::SmtLaneChunk),
                        msg.payload.as_ref().map(|v| v.into()),
                    ));
                }
            },
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        if payload.entries.is_empty() {
            return Err(ProtocolError::Other("received an empty SmtLaneChunk"));
        }

        if payload.entries.len() > SMT_CHUNK_SIZE {
            return Err(ProtocolError::Other("SmtLaneChunk exceeds SMT_CHUNK_SIZE"));
        }

        let remaining = self.expected_count - self.lane_count;
        if payload.entries.len() as u64 > remaining {
            return Err(ProtocolError::Other("received more SMT lane entries than active_lanes_count"));
        }

        let mut lanes = Vec::with_capacity(payload.entries.len());
        for entry in payload.entries {
            let Some((&key_bytes, rem)) = entry.data.split_first_chunk::<32>() else {
                return Err(ProtocolError::Other("SmtLaneEntry data too short for lane_key"));
            };
            let Some(&tip_bytes) = rem.first_chunk::<32>() else {
                return Err(ProtocolError::Other("SmtLaneEntry data too short for lane_tip"));
            };
            if rem.len() != 32 {
                return Err(ProtocolError::Other("SmtLaneEntry data must be exactly 64 bytes"));
            }
            let lane_key = Hash::from_bytes(key_bytes);
            let lane_tip = Hash::from_bytes(tip_bytes);

            let proof = if (self.lane_count as usize).is_multiple_of(SMT_PROOF_INTERVAL) {
                Some(
                    kaspa_smt::proof::OwnedSmtProof::from_bytes(&entry.proof)
                        .map_err(|e| ProtocolError::OtherOwned(format!("invalid SMT proof: {e}")))?,
                )
            } else {
                None
            };

            lanes.push(kaspa_consensus_core::api::ImportLane { lane_key, lane_tip, blue_score: entry.blue_score, proof });
            self.lane_count += 1;
        }

        self.chunks_received += 1;

        // Enqueue RequestNext for the next window — but only if more lanes remain.
        // When `lane_count == expected_count` the caller will stop iterating and the
        // sender's loop has already exhausted its DB iteration, so no further signal
        // is needed (and would dead-lock the sender past its last chunk).
        if self.lane_count < self.expected_count && self.chunks_received.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
            self.router
                .enqueue(make_message!(Payload::RequestNextPruningPointSmtChunk, RequestNextPruningPointSmtChunkMessage {}))
                .await?;
        }

        Ok(Some(lanes))
    }

    pub fn lane_count(&self) -> u64 {
        self.lane_count
    }
}

/// Stream of shielded-pool nullifier chunks for pruning-point IBD (PLAN §2.8/§2.9).
/// Flow-controlled: after every [`SMT_FLOW_CONTROL_WINDOW`]-th chunk the receiver
/// asks the sender for the next window.
pub struct ShieldedStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    expected_count: u64,
    nullifier_count: u64,
    chunks_received: usize,
}

impl<'a, 'b> ShieldedStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, expected_count: 0, nullifier_count: 0, chunks_received: 0 }
    }

    /// Receive the metadata frame: the opaque shielded-state encoding plus the
    /// number of nullifiers that will follow in chunks. Empty `data` signals the
    /// pruning point has no shielded state (nothing to import).
    pub async fn recv_metadata(&mut self) -> Result<kaspa_consensus_core::api::ShieldedExportMetadata, ProtocolError> {
        match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::ShieldedMetadata(payload)) => {
                    self.expected_count = payload.nullifier_count;
                    Ok(kaspa_consensus_core::api::ShieldedExportMetadata {
                        data: payload.data,
                        nullifier_count: payload.nullifier_count,
                    })
                }
                Some(Payload::UnexpectedPruningPoint(_)) => Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint)),
                _ => Err(ProtocolError::UnexpectedMessage(
                    stringify!(Payload::ShieldedMetadata),
                    msg.payload.as_ref().map(|v| v.into()),
                )),
            },
            Ok(None) => Err(ProtocolError::ConnectionClosed),
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        }
    }

    /// Receive the next chunk of nullifiers. Returns `Ok(None)` once
    /// `nullifier_count` nullifiers have been consumed.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<[u8; 32]>>, ProtocolError> {
        if self.nullifier_count >= self.expected_count {
            return Ok(None);
        }

        let payload = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::ShieldedNullifierChunk(payload)) => payload,
                Some(Payload::UnexpectedPruningPoint(_)) => {
                    return Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint));
                }
                _ => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::ShieldedNullifierChunk),
                        msg.payload.as_ref().map(|v| v.into()),
                    ));
                }
            },
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        if payload.nullifiers.is_empty() {
            return Err(ProtocolError::Other("received an empty ShieldedNullifierChunk"));
        }
        if payload.nullifiers.len() > SHIELDED_CHUNK_SIZE {
            return Err(ProtocolError::Other("ShieldedNullifierChunk exceeds SHIELDED_CHUNK_SIZE"));
        }
        let remaining = self.expected_count - self.nullifier_count;
        if payload.nullifiers.len() as u64 > remaining {
            return Err(ProtocolError::Other("received more nullifiers than nullifier_count"));
        }

        let mut out = Vec::with_capacity(payload.nullifiers.len());
        for nf in payload.nullifiers {
            let bytes: [u8; 32] = nf.as_slice().try_into().map_err(|_| ProtocolError::Other("nullifier must be exactly 32 bytes"))?;
            out.push(bytes);
            self.nullifier_count += 1;
        }

        self.chunks_received += 1;

        if self.nullifier_count < self.expected_count && self.chunks_received.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
            self.router
                .enqueue(make_message!(Payload::RequestNextPruningPointShieldedChunk, RequestNextPruningPointShieldedChunkMessage {}))
                .await?;
        }

        Ok(Some(out))
    }

    pub fn count(&self) -> u64 {
        self.nullifier_count
    }
}

/// One key range of the pruning-point nullifier set from a peer that advertises
/// `SERVICE_NF_SORTED_STREAM` (N1, spec 08 R3.3/R3.4.1): optionally the metadata frame, then
/// ascending chunks, then one empty chunk that ends the range. The requester does not know the
/// range's size, so after every [`SMT_FLOW_CONTROL_WINDOW`]-th chunk it always asks for the next
/// window (the server always waits for it in this mode).
pub struct ShieldedRangeStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    chunks_received: usize,
    received: u64,
    done: bool,
}

impl<'a, 'b> ShieldedRangeStream<'a, 'b> {
    /// Send the range request and return the stream that reads its answer.
    pub async fn request(
        router: &'a Router,
        incoming_route: &'b mut IncomingRoute,
        pruning_point: Hash,
        from: Option<[u8; 32]>,
        before: Option<[u8; 32]>,
        with_metadata: bool,
    ) -> Result<ShieldedRangeStream<'a, 'b>, ProtocolError> {
        router
            .enqueue(make_message!(
                Payload::RequestPruningPointShieldedChunkFrom,
                kaspa_p2p_lib::pb::RequestPruningPointShieldedChunkFromMessage {
                    pruning_point_hash: Some(pruning_point.into()),
                    from_key: from.map(|b| b.to_vec()).unwrap_or_default(),
                    before_key: before.map(|b| b.to_vec()).unwrap_or_default(),
                    with_metadata,
                }
            ))
            .await?;
        Ok(Self { router, incoming_route, chunks_received: 0, received: 0, done: false })
    }

    /// The metadata frame (only when the request asked for it).
    pub async fn recv_metadata(&mut self) -> Result<kaspa_consensus_core::api::ShieldedExportMetadata, ProtocolError> {
        match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::ShieldedMetadata(payload)) => {
                    Ok(kaspa_consensus_core::api::ShieldedExportMetadata { data: payload.data, nullifier_count: payload.nullifier_count })
                }
                Some(Payload::UnexpectedPruningPoint(_)) => Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint)),
                _ => Err(ProtocolError::UnexpectedMessage(stringify!(Payload::ShieldedMetadata), msg.payload.as_ref().map(|v| v.into()))),
            },
            Ok(None) => Err(ProtocolError::ConnectionClosed),
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        }
    }

    /// The next chunk, `Ok(None)` at the end of the range.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<[u8; 32]>>, ProtocolError> {
        if self.done {
            return Ok(None);
        }
        let payload = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::ShieldedNullifierChunk(payload)) => payload,
                Some(Payload::UnexpectedPruningPoint(_)) => {
                    return Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint));
                }
                _ => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::ShieldedNullifierChunk),
                        msg.payload.as_ref().map(|v| v.into()),
                    ));
                }
            },
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };
        if payload.nullifiers.is_empty() {
            self.done = true;
            return Ok(None);
        }
        if payload.nullifiers.len() > SHIELDED_CHUNK_SIZE {
            return Err(ProtocolError::Other("ShieldedNullifierChunk exceeds SHIELDED_CHUNK_SIZE"));
        }
        let mut out = Vec::with_capacity(payload.nullifiers.len());
        for nf in payload.nullifiers {
            let bytes: [u8; 32] = nf.as_slice().try_into().map_err(|_| ProtocolError::Other("nullifier must be exactly 32 bytes"))?;
            out.push(bytes);
        }
        self.received += out.len() as u64;
        self.chunks_received += 1;
        if self.chunks_received.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
            self.router
                .enqueue(make_message!(Payload::RequestNextPruningPointShieldedChunk, RequestNextPruningPointShieldedChunkMessage {}))
                .await?;
        }
        Ok(Some(out))
    }

    /// Whether the end-of-range marker arrived.
    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn count(&self) -> u64 {
        self.received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_requests_up_to_the_ceiling_are_served() {
        // What every requester in this tree sends, and the ceiling itself.
        assert!(check_requested_blocks("RequestIbdBlocks", 1).is_ok());
        assert!(check_requested_blocks("RequestIbdBlocks", IBD_BATCH_SIZE).is_ok());
        assert!(check_requested_blocks("RequestIbdBlocks", MAX_REQUESTED_BLOCKS).is_ok());
        assert!(check_requested_blocks("RequestIbdBlocks", MAX_REQUESTED_BLOCKS + 1).is_err());
    }

    #[test]
    fn header_ceiling_covers_every_honest_sender() {
        use kaspa_consensus_core::config::{bps::Bps, params};
        // Mainnet is 1 BPS (mergeset 180); `Bps::mergeset_size_limit` clamps every rate to [180, 512].
        assert_eq!(max_headers_per_message(180), 3_492);
        let networks = [params::MAINNET_PARAMS, params::TESTNET_PARAMS, params::SIMNET_PARAMS, params::DEVNET_PARAMS];
        let rates = [Bps::<1>::mergeset_size_limit(), Bps::<10>::mergeset_size_limit(), Bps::<32>::mergeset_size_limit()];
        for mergeset in networks.iter().map(|p| p.mergeset_size_limit()).chain(rates).chain([180u64, 300, 512]) {
            let ceiling = max_headers_per_message(mergeset);
            // `RequestHeaders`: the limits the server itself walks with, plus the appended chain block.
            assert!(ceiling >= request_headers_max_blocks(mergeset) + 1, "mergeset {mergeset}");
            // `RequestAntipast`: at most the traversal limit the server itself passes.
            assert!(ceiling as u64 >= antipast_traversal_limit(mergeset), "mergeset {mergeset}");
        }
        // An absurd configured value saturates instead of wrapping.
        assert_eq!(max_headers_per_message(u64::MAX), usize::MAX);
    }
}
