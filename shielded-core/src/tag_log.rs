//! The consensus tag log (fork topic 01 §3.5 "Integrity"; devnet prototype).
//!
//! Every chain block at or after `Params::tagged_channels_activation` appends one leaf
//! `H(block ‖ tag_digest)` to an append-only Merkle mountain range, where `tag_digest` commits to
//! the delivery tags the block applied, each tagged tx with the absolute tree position of its
//! first output. The log's commitment is folded into the state root
//! ([`crate::commitment::shielded_state_root_v2`]) that the next block's coinbase commits and
//! proof-of-work binds.
//!
//! What it buys a light client: spec 05 §3.6 notes that nothing binds `epk`/`enc`, so a lying
//! stream server can **hide** a payment (drop or alter its delivery data) without being caught;
//! the tree root binds only `cmx`. Under tagged channels the delivery data a client needs is the
//! tag column, and this log binds it: a client that replays the column it streamed onto the log
//! state at its start and compares the result with the PoW-committed root at its verified point
//! catches any dropped, altered, reordered or misplaced tag ([`TagLog::replay_blocks`]).
//!
//! The MMR is the anchor log's construction ([`crate::anchor_window`]) with its own
//! personalizations, so no tag-log hash can equal an anchor-log hash.

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

use crate::channel::TAG_LEN;

const LEAF_PERSONAL: &[u8; 16] = b"zkas_taglog_leaf";
const NODE_PERSONAL: &[u8; 16] = b"zkas_taglog_node";
const ROOT_PERSONAL: &[u8; 16] = b"zkas_taglog_root";
const BLOCK_PERSONAL: &[u8; 16] = b"zkas_taglog_blck";

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(personal).to_state();
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// One applied tagged transaction's contribution to its chain block's column: the absolute tree
/// position of its first output and its tags in action order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaggedTxColumn {
    pub first_leaf: u64,
    pub tags: Vec<[u8; TAG_LEN]>,
}

/// The digest of one chain block's tag column (applied order). An empty column has a digest too,
/// so a server cannot pass off a block that applied tags as one that applied none.
pub fn block_tag_digest(txs: &[TaggedTxColumn]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(BLOCK_PERSONAL).to_state();
    h.update(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        h.update(&tx.first_leaf.to_le_bytes());
        h.update(&(tx.tags.len() as u32).to_le_bytes());
        for t in &tx.tags {
            h.update(t);
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// The log after some number of blocks: the count and the mountain-range peaks, highest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagLog {
    pub count: u64,
    pub peaks: Vec<[u8; 32]>,
}

impl TagLog {
    pub fn is_well_formed(&self) -> bool {
        self.peaks.len() == self.count.count_ones() as usize && self.peaks.len() <= 64
    }

    /// The log after appending chain block `block` with column digest `digest`.
    pub fn append(&self, block: &[u8; 32], digest: &[u8; 32]) -> Result<Self, &'static str> {
        if !self.is_well_formed() {
            return Err("malformed tag log");
        }
        let count = self.count.checked_add(1).ok_or("tag log is full")?;
        let mut peaks = self.peaks.clone();
        let mut node = hash(LEAF_PERSONAL, &[block, digest]);
        let mut bits = self.count;
        while bits & 1 == 1 {
            let left = peaks.pop().expect("a set bit always has a peak");
            node = hash(NODE_PERSONAL, &[&left, &node]);
            bits >>= 1;
        }
        peaks.push(node);
        Ok(Self { count, peaks })
    }

    /// Replay a streamed column onto `prefix`: `(block hash, that block's tagged txs)` per chain
    /// block, in chain order. Equal to the committed log exactly when the stream is exactly the
    /// chain's blocks and columns.
    pub fn replay_blocks<'a>(
        prefix: &Self,
        blocks: impl IntoIterator<Item = (&'a [u8; 32], &'a [TaggedTxColumn])>,
    ) -> Result<Self, &'static str> {
        let mut log = prefix.clone();
        for (b, col) in blocks {
            log = log.append(b, &block_tag_digest(col))?;
        }
        Ok(log)
    }

    /// The 32-byte value folded into the v2 state root.
    pub fn commitment(&self) -> [u8; 32] {
        let count = self.count.to_le_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(self.peaks.len() + 1);
        parts.push(&count);
        for p in &self.peaks {
            parts.push(p);
        }
        hash(ROOT_PERSONAL, &parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(seed: u8, n: usize) -> Vec<TaggedTxColumn> {
        (0..n).map(|i| TaggedTxColumn { first_leaf: 100 + i as u64 * 4, tags: vec![[seed ^ i as u8; 16]; 2] }).collect()
    }

    #[test]
    fn replay_matches_incremental_append_and_catches_every_lie() {
        let blocks: Vec<([u8; 32], Vec<TaggedTxColumn>)> = (0..37u8).map(|i| ([i; 32], col(i, (i % 3) as usize))).collect();
        let mut log = TagLog::default();
        for (b, c) in &blocks {
            log = log.append(b, &block_tag_digest(c)).unwrap();
        }
        assert!(log.is_well_formed());
        let honest = TagLog::replay_blocks(&TagLog::default(), blocks.iter().map(|(b, c)| (b, c.as_slice()))).unwrap();
        assert_eq!(honest.commitment(), log.commitment());

        // A server that drops a tag, alters one, moves a tx's position, drops a whole tx, swaps two
        // blocks or omits a block produces a different commitment.
        let lies: Vec<Box<dyn Fn(&mut Vec<([u8; 32], Vec<TaggedTxColumn>)>)>> = vec![
            Box::new(|v| {
                v[4].1[0].tags.pop();
            }),
            Box::new(|v| v[5].1[1].tags[0][7] ^= 1),
            Box::new(|v| v[7].1[0].first_leaf += 1),
            Box::new(|v| {
                v[8].1.remove(1);
            }),
            Box::new(|v| v.swap(10, 11)),
            Box::new(|v| {
                v.remove(20);
            }),
            Box::new(|v| v[2].1 = Vec::new()),
        ];
        for (i, lie) in lies.iter().enumerate() {
            let mut v = blocks.clone();
            lie(&mut v);
            let r = TagLog::replay_blocks(&TagLog::default(), v.iter().map(|(b, c)| (b, c.as_slice()))).unwrap();
            assert_ne!(r.commitment(), log.commitment(), "lie {i} must be caught");
        }
    }

    #[test]
    fn replay_from_a_mid_prefix_equals_full_replay() {
        let blocks: Vec<([u8; 32], Vec<TaggedTxColumn>)> = (0..20u8).map(|i| ([i; 32], col(i, 1))).collect();
        let full = TagLog::replay_blocks(&TagLog::default(), blocks.iter().map(|(b, c)| (b, c.as_slice()))).unwrap();
        let prefix = TagLog::replay_blocks(&TagLog::default(), blocks[..9].iter().map(|(b, c)| (b, c.as_slice()))).unwrap();
        let rest = TagLog::replay_blocks(&prefix, blocks[9..].iter().map(|(b, c)| (b, c.as_slice()))).unwrap();
        assert_eq!(full, rest);
    }

    #[test]
    fn empty_column_still_commits() {
        assert_ne!(block_tag_digest(&[]), block_tag_digest(&[TaggedTxColumn { first_leaf: 0, tags: vec![] }]));
    }
}
