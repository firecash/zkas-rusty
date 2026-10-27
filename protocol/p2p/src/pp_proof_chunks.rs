//! Chunked transfer of the pruning-point proof.
//!
//! The proof used to travel as ONE `PruningPointProofMessage`: 220,930,010 bytes on mainnet
//! (measured 2026-10-16, 78,450 header entries over 226 levels), which is why the transport decode
//! cap (`P2P_MAX_MESSAGE_SIZE`) cannot drop below ~256 MB. Here the same `Vec<Vec<Arc<Header>>>` is
//! cut into `PruningPointProofChunkMessage`s of about [`PP_PROOF_CHUNK_TARGET_BYTES`] each, and put
//! back together by [`ProofAssembler`], which checks every bound on a chunk BEFORE converting a
//! single header of it.
//!
//! Wire rules (both sides):
//! * a chunk holds headers of ONE level, `level`, in the order they have in that level;
//! * `level` never decreases across the stream; a level that never appears is empty (an honest
//!   proof has empty upper levels only when the chain is young, but the legacy form allowed them);
//! * every chunk repeats `levelCount`, the number of levels of the whole proof (consensus requires
//!   exactly `max_block_level + 1`; the receiver refuses more before allocating anything);
//! * `seq` numbers the chunks 0, 1, 2, ... in sending order; the receiver refuses any other value,
//!   so a duplicated, replayed, skipped or reordered chunk is refused at the P2P layer;
//! * only the final chunk has `done`, and only the final chunk may be empty (a proof with no
//!   headers at all, which consensus then rejects, is one empty `done` chunk);
//! * flow control: after every [`PP_PROOF_CHUNK_WINDOW`]-th chunk that is not `done`, the receiver
//!   sends `RequestNextPruningPointProofChunk` and the server sends nothing more until it arrives
//!   (see [`requests_next_after`]).
//!
//! Negotiation: a node that serves this form sets [`SERVICE_PRUNING_PROOF_CHUNKS`] in its
//! `VersionMessage.services`. A requester asks for the chunked form only from a peer advertising
//! it; every other peer is asked with the legacy `RequestPruningPointProof`, which both old and
//! new nodes keep serving.

use crate::{
    common::ProtocolError,
    convert::header::{HeaderFormat, Versioned},
    pb as protowire,
};
use kaspa_consensus_core::{header::Header, pruning::PruningPointProof};
use kaspa_hashes::Hash;
use prost::Message;
use std::{collections::HashMap, sync::Arc};

/// `VersionMessage.services` bit: this node serves `RequestPruningPointProofChunks`.
///
/// Upstream kaspad sends `services = 0` and never reads the field, so a ZKas-only bit in the high
/// half cannot collide with anything an upstream peer means by it.
pub const SERVICE_PRUNING_PROOF_CHUNKS: u64 = 1 << 40;

/// Encoded bytes a server aims for in one chunk. A chunk is closed at the first header that would
/// take it past this, so it ends at most one header above it (a header is ~2.8 KB on mainnet).
pub const PP_PROOF_CHUNK_TARGET_BYTES: usize = 8 * 1024 * 1024;

/// Headers a server puts in one chunk at most, whatever their size.
pub const PP_PROOF_CHUNK_MAX_HEADERS: usize = 8192;

/// Receiver ceiling on one chunk's encoded size: twice the server target, so a future server with
/// a larger target or unusually large headers is not refused, while one message stays small next
/// to the transport cap.
pub const MAX_PP_PROOF_CHUNK_BYTES: usize = 2 * PP_PROOF_CHUNK_TARGET_BYTES;

/// Receiver ceiling on headers in one chunk: twice what an honest server sends.
pub const MAX_PP_PROOF_CHUNK_HEADERS: usize = 2 * PP_PROOF_CHUNK_MAX_HEADERS;

/// Receiver ceiling on the encoded size of the whole proof, summed chunk by chunk before each one
/// is converted. The legacy single message was bounded by the transport cap (256 MiB); chunking
/// removes that bound, so this replaces it. 2.4x the measured mainnet proof (210.7 MiB); the proof
/// grows by about one level (~5.9 MB) per doubling of total chain work.
pub const MAX_PP_PROOF_TOTAL_BYTES: usize = 512 * 1024 * 1024;

/// Chunks a server may send before it waits for `RequestNextPruningPointProofChunk`. With
/// [`PP_PROOF_CHUNK_TARGET_BYTES`] that is ~32 MiB in flight, the same as the outgoing pacing mark,
/// and at most this many chunks wait in the receiver's incoming route.
pub const PP_PROOF_CHUNK_WINDOW: usize = 4;

/// Whether the receiver must ask for the next window after the `chunks_so_far`-th chunk (counting
/// from 1), and so whether the server must wait for that ask. Both sides use this one function so
/// they cannot disagree: no ask after the `done` chunk, since the server sends nothing more.
pub fn requests_next_after(chunks_so_far: usize, done: bool) -> bool {
    !done && chunks_so_far > 0 && chunks_so_far.is_multiple_of(PP_PROOF_CHUNK_WINDOW)
}

/// Bytes one header adds to a chunk: its encoding plus the field key and length prefix.
fn header_field_len(header: &protowire::BlockHeader) -> usize {
    let len = header.encoded_len();
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// Cuts a proof into chunks lazily: each `next()` converts one chunk's headers and nothing more, so
/// a serve holds one converted chunk at a time instead of the whole converted proof.
pub struct ProofChunker {
    proof: Arc<PruningPointProof>,
    header_format: HeaderFormat,
    target_bytes: usize,
    max_headers: usize,
    level: usize,
    index: usize,
    seq: u32,
    finished: bool,
}

impl ProofChunker {
    pub fn new(proof: Arc<PruningPointProof>, header_format: HeaderFormat) -> Self {
        Self::with_limits(proof, header_format, PP_PROOF_CHUNK_TARGET_BYTES, PP_PROOF_CHUNK_MAX_HEADERS)
    }

    pub fn with_limits(proof: Arc<PruningPointProof>, header_format: HeaderFormat, target_bytes: usize, max_headers: usize) -> Self {
        let mut chunker =
            Self { proof, header_format, target_bytes, max_headers: max_headers.max(1), level: 0, index: 0, seq: 0, finished: false };
        chunker.skip_exhausted_levels();
        chunker
    }

    /// Moves to the first level at or after the current one that still has headers to send.
    fn skip_exhausted_levels(&mut self) {
        while self.level < self.proof.len() && self.index >= self.proof[self.level].len() {
            self.level += 1;
            self.index = 0;
        }
    }

    fn level_count(&self) -> u32 {
        u32::try_from(self.proof.len()).unwrap_or(u32::MAX)
    }
}

impl Iterator for ProofChunker {
    type Item = protowire::PruningPointProofChunkMessage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.level >= self.proof.len() {
            // Only reached when the proof holds no header at all: one empty `done` chunk says so.
            self.finished = true;
            return Some(protowire::PruningPointProofChunkMessage {
                level_count: self.level_count(),
                level: 0,
                headers: vec![],
                done: true,
                seq: self.seq,
            });
        }
        let level = self.level;
        let source = &self.proof[level];
        let mut headers = Vec::new();
        let mut bytes = 0usize;
        while self.index < source.len() && headers.len() < self.max_headers {
            let header: protowire::BlockHeader = (self.header_format, source[self.index].as_ref()).into();
            let len = header_field_len(&header);
            if !headers.is_empty() && bytes.saturating_add(len) > self.target_bytes {
                break;
            }
            bytes = bytes.saturating_add(len);
            headers.push(header);
            self.index += 1;
        }
        self.skip_exhausted_levels();
        let done = self.level >= self.proof.len();
        self.finished = done;
        let seq = self.seq;
        // A proof needs far fewer than 2^32 chunks (the receiver's total budget caps it near 2^16);
        // saturate rather than wrap, so an absurd proof is refused by the receiver, never a panic here.
        self.seq = self.seq.saturating_add(1);
        Some(protowire::PruningPointProofChunkMessage {
            level_count: self.level_count(),
            level: u32::try_from(level).unwrap_or(u32::MAX),
            headers,
            done,
            seq,
        })
    }
}

/// Receiver-side ceilings, see the `MAX_PP_PROOF_*` constants.
#[derive(Clone, Copy, Debug)]
pub struct ProofChunkLimits {
    pub max_levels: usize,
    pub max_chunk_headers: usize,
    pub max_chunk_bytes: usize,
    pub max_total_bytes: usize,
}

impl ProofChunkLimits {
    /// The production limits for a network whose proofs have `max_levels` (`max_block_level + 1`) levels.
    pub fn new(max_levels: usize) -> Self {
        Self {
            max_levels,
            max_chunk_headers: MAX_PP_PROOF_CHUNK_HEADERS,
            max_chunk_bytes: MAX_PP_PROOF_CHUNK_BYTES,
            max_total_bytes: MAX_PP_PROOF_TOTAL_BYTES,
        }
    }
}

/// Puts a chunked proof back together, refusing a chunk on any bound before converting it.
///
/// The result is the same `PruningPointProof` the legacy conversion produces, including one `Arc`
/// per distinct header across levels (the proof repeats many headers between levels).
pub struct ProofAssembler {
    header_format: HeaderFormat,
    limits: ProofChunkLimits,
    levels: Vec<Vec<Arc<Header>>>,
    level_count: Option<usize>,
    current_level: usize,
    total_bytes: usize,
    chunks: usize,
    done: bool,
    cache: HashMap<Hash, Arc<Header>>,
}

fn refuse(reason: String) -> ProtocolError {
    ProtocolError::OtherOwned(format!("pruning point proof chunk refused: {reason}"))
}

impl ProofAssembler {
    pub fn new(header_format: HeaderFormat, limits: ProofChunkLimits) -> Self {
        Self {
            header_format,
            limits,
            levels: Vec::new(),
            level_count: None,
            current_level: 0,
            total_bytes: 0,
            chunks: 0,
            done: false,
            cache: HashMap::new(),
        }
    }

    pub fn chunks(&self) -> usize {
        self.chunks
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Checks `chunk` against every bound, then converts and appends its headers. Returns whether
    /// it was the final chunk.
    pub fn push(&mut self, chunk: protowire::PruningPointProofChunkMessage) -> Result<bool, ProtocolError> {
        if self.done {
            return Err(refuse("a chunk arrived after the final one".into()));
        }
        // `chunks` counts accepted chunks only, so it is exactly the next expected `seq`.
        if chunk.seq as usize != self.chunks {
            return Err(refuse(format!("chunk seq {} where seq {} was expected (duplicate, skipped or reordered)", chunk.seq, self.chunks)));
        }
        let level_count = chunk.level_count as usize;
        if level_count == 0 || level_count > self.limits.max_levels {
            return Err(refuse(format!("level count {level_count} outside 1..={}", self.limits.max_levels)));
        }
        if let Some(expected) = self.level_count
            && expected != level_count
        {
            return Err(refuse(format!("level count changed from {expected} to {level_count}")));
        }
        let level = chunk.level as usize;
        if level >= level_count {
            return Err(refuse(format!("level {level} is not below the level count {level_count}")));
        }
        if level < self.current_level {
            return Err(refuse(format!("level {level} arrived after level {}", self.current_level)));
        }
        if chunk.headers.len() > self.limits.max_chunk_headers {
            return Err(refuse(format!("{} headers, above the {} ceiling", chunk.headers.len(), self.limits.max_chunk_headers)));
        }
        if chunk.headers.is_empty() && !chunk.done {
            return Err(refuse("an empty chunk that is not the final one".into()));
        }
        let bytes = chunk.encoded_len();
        if bytes > self.limits.max_chunk_bytes {
            return Err(refuse(format!("{bytes} bytes, above the {} ceiling", self.limits.max_chunk_bytes)));
        }
        let total = self.total_bytes.saturating_add(bytes);
        if total > self.limits.max_total_bytes {
            return Err(refuse(format!("the proof passes {} bytes, above the {} ceiling", total, self.limits.max_total_bytes)));
        }

        // Every bound holds: only now is anything allocated or converted.
        if self.level_count.is_none() {
            self.level_count = Some(level_count);
            self.levels = vec![Vec::new(); level_count];
        }
        self.total_bytes = total;
        self.current_level = level;
        self.chunks += 1;
        let header_format = self.header_format;
        let target = &mut self.levels[level];
        target.reserve(chunk.headers.len());
        for header in chunk.headers {
            let header: Header = Versioned(header_format, header).try_into()?;
            target.push(self.cache.entry(header.hash).or_insert_with(|| Arc::new(header)).clone());
        }
        self.done = chunk.done;
        Ok(self.done)
    }

    /// The assembled proof. Fails unless the final chunk was received.
    pub fn finish(self) -> Result<PruningPointProof, ProtocolError> {
        if !self.done {
            return Err(refuse("the stream ended before the final chunk".into()));
        }
        Ok(self.levels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::BlueWorkType;

    fn header(n: u64, parents: usize) -> Arc<Header> {
        let parents = vec![(0..parents as u64).map(|p| Hash::from_u64_word(n * 1000 + p + 1)).collect::<Vec<_>>()];
        Arc::new(Header::new_finalized(
            1,
            parents.try_into().unwrap(),
            Hash::from_u64_word(n),
            Default::default(),
            Default::default(),
            n,
            0x1e7fffff,
            n,
            n,
            BlueWorkType::from_u64(n),
            n,
            Default::default(),
        ))
    }

    /// A proof shaped like the real one: a big level 0, levels that repeat headers of the levels
    /// below (shared `Arc`s), and empty levels in between and at the top.
    fn sample_proof() -> PruningPointProof {
        let level0: Vec<_> = (0..300).map(|n| header(n, 3)).collect();
        let level1: Vec<_> = level0.iter().step_by(2).cloned().collect();
        let level3: Vec<_> = level0.iter().step_by(7).cloned().chain((1000..1010).map(|n| header(n, 1))).collect();
        vec![level0, level1, vec![], level3, vec![], vec![]]
    }

    fn legacy_round_trip(proof: &PruningPointProof, format: HeaderFormat) -> PruningPointProof {
        let msg = protowire::PruningPointProofMessage { headers: proof.iter().map(|level| (format, level).into()).collect(), ..Default::default() };
        Versioned(format, msg).try_into().unwrap()
    }

    fn assemble(
        chunks: Vec<protowire::PruningPointProofChunkMessage>,
        format: HeaderFormat,
        limits: ProofChunkLimits,
    ) -> Result<PruningPointProof, ProtocolError> {
        let mut asm = ProofAssembler::new(format, limits);
        for chunk in chunks {
            asm.push(chunk)?;
        }
        asm.finish()
    }

    fn hashes(proof: &PruningPointProof) -> Vec<Vec<Hash>> {
        proof.iter().map(|level| level.iter().map(|h| h.hash).collect()).collect()
    }

    #[test]
    fn chunked_transfer_rebuilds_exactly_what_the_legacy_message_does() {
        let proof = Arc::new(sample_proof());
        for format in [HeaderFormat::Legacy, HeaderFormat::Compressed] {
            for (target, max_headers) in
                [(PP_PROOF_CHUNK_TARGET_BYTES, PP_PROOF_CHUNK_MAX_HEADERS), (2_000, 1000), (1, 1), (50_000, 7)]
            {
                let chunks: Vec<_> = ProofChunker::with_limits(proof.clone(), format, target, max_headers).collect();
                assert!(chunks.last().unwrap().done);
                assert_eq!(chunks.iter().filter(|c| c.done).count(), 1, "exactly one final chunk");
                let rebuilt = assemble(chunks, format, ProofChunkLimits::new(6)).unwrap();
                let legacy = legacy_round_trip(&proof, format);
                assert_eq!(hashes(&rebuilt), hashes(&legacy));
                assert_eq!(hashes(&rebuilt), hashes(&proof));
                // Same dedup as the legacy conversion: a header repeated across levels is one Arc.
                assert!(Arc::ptr_eq(&rebuilt[0][0], &rebuilt[1][0]));
                assert!(Arc::ptr_eq(&rebuilt[0][14], &rebuilt[3][2]));
                assert_eq!(rebuilt.len(), 6, "empty levels, including trailing ones, survive");
            }
        }
    }

    #[test]
    fn chunks_respect_the_byte_target_and_header_count_and_never_span_levels() {
        let proof = Arc::new(sample_proof());
        let one = header_field_len(&(HeaderFormat::Compressed, proof[0][0].as_ref()).into());
        let target = one * 10 + one / 2;
        let chunks: Vec<_> = ProofChunker::with_limits(proof.clone(), HeaderFormat::Compressed, target, 1000).collect();
        for c in &chunks {
            let bytes: usize = c.headers.iter().map(header_field_len).sum();
            assert!(bytes <= target, "{bytes} > {target}");
            assert!(!c.headers.is_empty());
        }
        assert!((9..=11).contains(&chunks[0].headers.len()), "{}", chunks[0].headers.len());
        let levels: Vec<u32> = chunks.iter().map(|c| c.level).collect();
        assert!(levels.windows(2).all(|w| w[0] <= w[1]));
        assert!(!levels.contains(&2) && !levels.contains(&4) && !levels.contains(&5), "empty levels send no chunk");
        let capped: Vec<_> = ProofChunker::with_limits(proof, HeaderFormat::Compressed, usize::MAX, 64).collect();
        assert!(capped.iter().all(|c| c.headers.len() <= 64));
        assert_eq!(capped.iter().map(|c| c.headers.len()).sum::<usize>(), 300 + 150 + 53);
    }

    #[test]
    fn a_header_above_the_target_still_travels_alone() {
        let proof = Arc::new(vec![vec![header(1, 5), header(2, 5)]]);
        let chunks: Vec<_> = ProofChunker::with_limits(proof, HeaderFormat::Compressed, 1, 100).collect();
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|c| c.headers.len() == 1));
        assert!(!chunks[0].done && chunks[1].done);
    }

    #[test]
    fn an_empty_proof_is_one_empty_final_chunk() {
        let proof = Arc::new(vec![vec![], vec![]]);
        let chunks: Vec<_> = ProofChunker::new(proof, HeaderFormat::Compressed).collect();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].done && chunks[0].headers.is_empty());
        let rebuilt = assemble(chunks, HeaderFormat::Compressed, ProofChunkLimits::new(226)).unwrap();
        assert_eq!(hashes(&rebuilt), vec![Vec::<Hash>::new(), vec![]]);
    }

    fn chunk_seq(seq: u32, level_count: u32, level: u32, headers: Vec<Arc<Header>>, done: bool) -> protowire::PruningPointProofChunkMessage {
        protowire::PruningPointProofChunkMessage {
            level_count,
            level,
            headers: headers.iter().map(|h| (HeaderFormat::Compressed, h.as_ref()).into()).collect(),
            done,
            seq,
        }
    }

    /// A first chunk (`seq` 0).
    fn chunk(level_count: u32, level: u32, headers: Vec<Arc<Header>>, done: bool) -> protowire::PruningPointProofChunkMessage {
        chunk_seq(0, level_count, level, headers, done)
    }

    fn refused(asm: &mut ProofAssembler, c: protowire::PruningPointProofChunkMessage, why: &str) {
        let err = asm.push(c).expect_err(why);
        assert!(matches!(err, ProtocolError::OtherOwned(ref s) if s.starts_with("pruning point proof chunk refused")), "{why}: {err}");
    }

    #[test]
    fn the_assembler_refuses_malformed_streams_before_converting() {
        let limits =
            ProofChunkLimits { max_levels: 4, max_chunk_headers: 3, max_chunk_bytes: usize::MAX, max_total_bytes: usize::MAX };
        let fmt = HeaderFormat::Compressed;
        let h = |n| header(n, 1);

        refused(&mut ProofAssembler::new(fmt, limits), chunk(0, 0, vec![h(1)], false), "zero levels");
        refused(&mut ProofAssembler::new(fmt, limits), chunk(5, 0, vec![h(1)], false), "more levels than the network has");
        refused(&mut ProofAssembler::new(fmt, limits), chunk(u32::MAX, 0, vec![h(1)], false), "a huge level count allocates nothing");
        refused(&mut ProofAssembler::new(fmt, limits), chunk(4, 4, vec![h(1)], false), "level at the level count");
        refused(&mut ProofAssembler::new(fmt, limits), chunk(4, 0, vec![h(1), h(2), h(3), h(4)], false), "too many headers");
        refused(&mut ProofAssembler::new(fmt, limits), chunk(4, 0, vec![], false), "empty non-final chunk");

        let mut asm = ProofAssembler::new(fmt, limits);
        asm.push(chunk(4, 2, vec![h(1)], false)).unwrap();
        refused(&mut asm, chunk_seq(1, 4, 1, vec![h(2)], false), "a level going backwards");
        refused(&mut asm, chunk_seq(1, 3, 2, vec![h(2)], false), "a changed level count");
        assert!(asm.push(chunk_seq(1, 4, 3, vec![h(3)], true)).unwrap());
        refused(&mut asm, chunk_seq(2, 4, 3, vec![h(4)], true), "a chunk after the final one");
        let proof = asm.finish().unwrap();
        assert_eq!(hashes(&proof), vec![vec![], vec![], vec![h(1).hash], vec![h(3).hash]]);

        let mut asm = ProofAssembler::new(fmt, limits);
        asm.push(chunk(4, 0, vec![h(1)], false)).unwrap();
        assert!(asm.finish().is_err(), "a stream cut before the final chunk yields no proof");
    }

    #[test]
    fn the_assembler_enforces_chunk_and_total_byte_budgets() {
        let fmt = HeaderFormat::Compressed;
        let c = chunk(1, 0, vec![header(1, 4), header(2, 4)], false);
        let one = c.encoded_len();

        let limits = ProofChunkLimits { max_levels: 1, max_chunk_headers: 100, max_chunk_bytes: one - 1, max_total_bytes: usize::MAX };
        refused(&mut ProofAssembler::new(fmt, limits), c.clone(), "a chunk above the byte ceiling");

        // A non-zero seq adds its own field bytes, so the budget is set from the real encodings.
        let with_seq = |seq| protowire::PruningPointProofChunkMessage { seq, ..c.clone() };
        let (first, second) = (with_seq(0).encoded_len(), with_seq(1).encoded_len());
        let limits =
            ProofChunkLimits { max_levels: 1, max_chunk_headers: 100, max_chunk_bytes: second, max_total_bytes: first + second };
        let mut asm = ProofAssembler::new(fmt, limits);
        asm.push(with_seq(0)).unwrap();
        asm.push(with_seq(1)).unwrap();
        assert_eq!(asm.total_bytes(), first + second);
        refused(&mut asm, with_seq(2), "the total byte budget is spent");
        assert_eq!(asm.chunks(), 2, "a refused chunk is not counted");
    }

    #[test]
    fn duplicate_skipped_and_reordered_chunks_are_refused_by_seq() {
        let proof = Arc::new(sample_proof());
        let fmt = HeaderFormat::Compressed;
        let chunks: Vec<_> = ProofChunker::with_limits(proof.clone(), fmt, 2_000, 1000).collect();
        assert!(chunks.len() >= 4, "{}", chunks.len());
        assert!(chunks.iter().enumerate().all(|(i, c)| c.seq as usize == i), "the server numbers chunks 0, 1, 2, ...");
        let limits = ProofChunkLimits::new(6);

        // Duplicate: chunk 1 sent twice. It is the same level (a level check alone accepts it).
        let mut asm = ProofAssembler::new(fmt, limits);
        asm.push(chunks[0].clone()).unwrap();
        asm.push(chunks[1].clone()).unwrap();
        assert_eq!(chunks[1].level, chunks[2].level, "the duplicate would pass the level-order check");
        refused(&mut asm, chunks[1].clone(), "a duplicated chunk");
        // The stream is still usable after a refusal only in tests; production drops the peer.
        refused(&mut asm, chunks[3].clone(), "a skipped chunk");

        // Reordered: 0, 2, 1.
        let mut asm = ProofAssembler::new(fmt, limits);
        asm.push(chunks[0].clone()).unwrap();
        refused(&mut asm, chunks[2].clone(), "a chunk ahead of its turn");

        // A first chunk that is not seq 0, including the largest seq.
        refused(&mut ProofAssembler::new(fmt, limits), chunks[1].clone(), "a stream starting mid-way");
        let mut huge = chunks[0].clone();
        huge.seq = u32::MAX;
        refused(&mut ProofAssembler::new(fmt, limits), huge, "seq u32::MAX");

        // The honest order still rebuilds the proof.
        assert_eq!(hashes(&assemble(chunks, fmt, limits).unwrap()), hashes(&proof));
    }

    #[test]
    fn both_sides_agree_on_when_the_next_window_is_requested() {
        // The server waits exactly when the receiver asks, for a stream of any length.
        for total in 1..=3 * PP_PROOF_CHUNK_WINDOW + 1 {
            let asks: Vec<usize> = (1..=total).filter(|&i| requests_next_after(i, i == total)).collect();
            let expected: Vec<usize> = (1..total).filter(|i| i % PP_PROOF_CHUNK_WINDOW == 0).collect();
            assert_eq!(asks, expected, "stream of {total} chunks");
        }
        assert!(!requests_next_after(0, false));
    }

    #[test]
    fn production_limits_hold_an_honest_server_chunk() {
        // An honest chunk sits under the receiver's per-chunk ceilings by construction.
        const { assert!(PP_PROOF_CHUNK_TARGET_BYTES < MAX_PP_PROOF_CHUNK_BYTES) };
        const { assert!(PP_PROOF_CHUNK_MAX_HEADERS <= MAX_PP_PROOF_CHUNK_HEADERS) };
        // The measured mainnet proof (220,930,010 bytes) fits the total budget with room.
        const { assert!(220_930_010 * 2 < MAX_PP_PROOF_TOTAL_BYTES) };
    }
}
