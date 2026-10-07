//! Anchor log commitment (security fork, 2026-10).
//!
//! Every chain block at or after the fork appends one entry `(block, parent, own_tree_root,
//! blue_score)` to an append-only log, a Merkle mountain range whose root is folded into
//! `zkas_state_root1`.
//!
//! Why: a node that fast-syncs to a pruning point has no tree roots for the chain blocks just below
//! it, yet spends mined just above it may name those blocks as anchors. Before the fork the syncing
//! node took `(root, block)` pairs from its sync peer on trust. With the log committed, the peer
//! sends the log state just below the anchor window plus the window's entries; the syncing node
//! appends them and must reproduce the PoW-committed log, so every imported pair is proven.
//!
//! Properties:
//! - A block's log is its selected parent's log plus its own entry, so it is identical on every node
//!   that agrees on the selected chain, and a reorg simply reloads the new parent's log.
//! - Appending costs O(log n) hashes and needs no other data.
//! - The root commits the entry count, so nothing can be added, dropped, reordered or slipped in
//!   anywhere, including below the window: a replay matches exactly when the entries are the log's
//!   last ones, in order.
//! - Entries carry their selected parent, so a node with no chain index below its pruning point can
//!   still walk them back from the pruning point to serve a later sync.

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

const LEAF_PERSONAL: &[u8; 16] = b"zkas_anchorlog_l";
const NODE_PERSONAL: &[u8; 16] = b"zkas_anchorlog_n";
const ROOT_PERSONAL: &[u8; 16] = b"zkas_anchorlog_r";

/// The most peaks a well-formed log can have (one per bit of a `u64` count).
pub const MAX_PEAKS: usize = 64;

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(personal).to_state();
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// One chain block's contribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowEntry {
    pub block: [u8; 32],
    /// The block's selected parent. Committed, and lets any node (including a fast-synced one with no
    /// chain index below its pruning point) walk the entries back by parent links.
    pub parent: [u8; 32],
    pub root: [u8; 32],
    pub blue_score: u64,
}

impl WindowEntry {
    pub fn hash(&self) -> [u8; 32] {
        hash(LEAF_PERSONAL, &[&self.block, &self.parent, &self.root, &self.blue_score.to_le_bytes()])
    }
}

/// The log after some number of entries: the count and the mountain-range peaks, highest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorLog {
    pub count: u64,
    pub peaks: Vec<[u8; 32]>,
}

impl AnchorLog {
    /// Whether the peaks match the count. Anything received from a peer must pass this before use.
    pub fn is_well_formed(&self) -> bool {
        self.peaks.len() == self.count.count_ones() as usize && self.peaks.len() <= MAX_PEAKS
    }

    /// The log after appending `entry`. Fails only on a malformed log or a count that would overflow.
    pub fn append(&self, entry: &WindowEntry) -> Result<Self, &'static str> {
        if !self.is_well_formed() {
            return Err("malformed anchor log");
        }
        let count = self.count.checked_add(1).ok_or("anchor log is full")?;
        let mut peaks = self.peaks.clone();
        let mut node = entry.hash();
        let mut height_bits = self.count;
        while height_bits & 1 == 1 {
            let left = peaks.pop().expect("a set bit always has a peak");
            node = hash(NODE_PERSONAL, &[&left, &node]);
            height_bits >>= 1;
        }
        peaks.push(node);
        Ok(Self { count, peaks })
    }

    /// Replay peer-supplied `entries` onto `prefix`, as a syncing node does. The entries must be
    /// strictly increasing in blue score and each must name the previous one as its parent (both
    /// hold for any stretch of a selected chain). The result equals the committed log exactly when
    /// the entries are its last `entries.len()` ones, in order.
    pub fn replay<'a>(prefix: &Self, entries: impl IntoIterator<Item = &'a WindowEntry>) -> Result<Self, &'static str> {
        let mut log = prefix.clone();
        let mut last: Option<&WindowEntry> = None;
        for e in entries {
            if let Some(prev) = last {
                if e.blue_score <= prev.blue_score {
                    return Err("anchor log entries are not strictly increasing in blue score");
                }
                if e.parent != prev.block {
                    return Err("anchor log entry does not name the previous entry as its parent");
                }
            }
            log = log.append(e)?;
            last = Some(e);
        }
        Ok(log)
    }

    /// The 32-byte value folded into `zkas_state_root1`.
    pub fn commitment(&self) -> [u8; 32] {
        let count = self.count.to_le_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(self.peaks.len() + 1);
        parts.push(&count);
        for peak in &self.peaks {
            parts.push(peak);
        }
        hash(ROOT_PERSONAL, &parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A selected-chain-shaped run: each entry names the previous as its parent.
    fn chain(n: u64, start_bs: u64) -> Vec<WindowEntry> {
        (0..n)
            .map(|i| WindowEntry {
                block: block_id(i),
                parent: if i == 0 { [0xAA; 32] } else { block_id(i - 1) },
                root: [(i % 251) as u8 ^ 0x33; 32],
                blue_score: start_bs + i * 10 + (i % 7),
            })
            .collect()
    }

    fn block_id(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_le_bytes());
        b[31] = 0xB1;
        b
    }

    fn all_states(entries: &[WindowEntry]) -> Vec<AnchorLog> {
        let mut log = AnchorLog::default();
        let mut out = vec![log.clone()];
        for e in entries {
            log = log.append(e).unwrap();
            out.push(log.clone());
        }
        out
    }

    /// The textbook root of a mountain range, built from scratch rather than by appending.
    fn root_from_scratch(entries: &[WindowEntry]) -> [u8; 32] {
        let mut peaks = Vec::new();
        let mut start = 0usize;
        let n = entries.len();
        for bit in (0..64).rev() {
            let size = 1usize << bit;
            if n & size != 0 {
                let mut level: Vec<[u8; 32]> = entries[start..start + size].iter().map(WindowEntry::hash).collect();
                while level.len() > 1 {
                    level = level.chunks(2).map(|p| hash(NODE_PERSONAL, &[&p[0], &p[1]])).collect();
                }
                peaks.push(level[0]);
                start += size;
            }
        }
        AnchorLog { count: n as u64, peaks }.commitment()
    }

    #[test]
    fn appending_matches_the_mountain_range_built_from_scratch() {
        let entries = chain(300, 10);
        let states = all_states(&entries);
        assert_eq!(states[0].commitment(), root_from_scratch(&[]));
        for i in 1..=entries.len() {
            assert!(states[i].is_well_formed());
            assert_eq!(states[i].commitment(), root_from_scratch(&entries[..i]), "after {i} entries");
        }
    }

    /// The served tail rebuilds the log from any split point.
    #[test]
    fn a_prefix_plus_the_tail_reproduces_the_log() {
        let entries = chain(200, 5);
        let states = all_states(&entries);
        for split in [0, 1, 2, 63, 64, 65, 127, 199, 200] {
            assert_eq!(AnchorLog::replay(&states[split], &entries[split..]).unwrap(), states[200], "split {split}");
        }
    }

    /// Exhaustive, not sampled: for every log size up to 33 and every split, flipping any single bit
    /// of any entry field, any prefix peak, or the prefix count makes the replay miss the committed
    /// root (or be refused).
    #[test]
    fn every_single_bit_lie_misses_the_committed_root() {
        let entries = chain(33, 100);
        let mut checked = 0u64;
        for n in (1..=17).chain([31, 32, 33]) {
            let states = all_states(&entries[..n]);
            let target = states[n].commitment();
            let reaches = |prefix: &AnchorLog, tail: &[WindowEntry]| AnchorLog::replay(prefix, tail).map(|l| l.commitment()).ok() == Some(target);
            for split in 0..=n {
                let tail = entries[split..n].to_vec();
                assert!(reaches(&states[split], &tail));
                for i in 0..tail.len() {
                    for bit in 0..(32 * 3 + 8) * 8 {
                        let mut t = tail.clone();
                        let e = &mut t[i];
                        match bit / 8 {
                            b @ 0..32 => e.block[b] ^= 1 << (bit % 8),
                            b @ 32..64 => e.parent[b - 32] ^= 1 << (bit % 8),
                            b @ 64..96 => e.root[b - 64] ^= 1 << (bit % 8),
                            _ => e.blue_score ^= 1 << (bit - 768),
                        }
                        assert!(!reaches(&states[split], &t), "n={n} split={split} entry={i} bit={bit}");
                        checked += 1;
                    }
                }
                for peak in 0..states[split].peaks.len() {
                    for bit in 0..256 {
                        let mut p = states[split].clone();
                        p.peaks[peak][bit / 8] ^= 1 << (bit % 8);
                        assert!(!reaches(&p, &tail), "n={n} split={split} peak={peak} bit={bit}");
                        checked += 1;
                    }
                }
                for bit in 0..64 {
                    let mut p = states[split].clone();
                    p.count ^= 1 << bit;
                    assert!(!reaches(&p, &tail), "n={n} split={split} count bit={bit}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 100_000, "the sweep must be exhaustive, checked {checked}");
    }

    /// From any real prefix, only the exact true tail reaches the root: nothing can be dropped,
    /// added, cut short or slipped in below, which is what closes the "entries below the floor" class.
    #[test]
    fn only_the_true_tail_reaches_the_root_from_any_real_prefix() {
        let entries = chain(40, 1);
        let states = all_states(&entries);
        let n = entries.len();
        let target = states[n].commitment();
        for (split, prefix) in states.iter().enumerate() {
            for start in 0..=n {
                for end in start..=n {
                    let reaches = AnchorLog::replay(prefix, &entries[start..end]).map(|l| l.commitment()).ok() == Some(target);
                    let honest = (start == split && end == n) || (split == n && start == end);
                    assert_eq!(reaches, honest, "split={split} entries={start}..{end}");
                }
            }
        }
        // A real entry prepended to the honest tail (below the window) changes the count: refused.
        let mut t = entries[10..].to_vec();
        t.insert(0, entries[9]);
        assert_ne!(AnchorLog::replay(&states[10], &t).map(|l| l.commitment()).ok(), Some(target));
    }

    #[test]
    fn peer_lists_must_be_chain_shaped() {
        let entries = chain(10, 50);
        let mut repeated = entries.clone();
        repeated[4].blue_score = repeated[3].blue_score;
        assert!(AnchorLog::replay(&AnchorLog::default(), &repeated).is_err(), "a repeated blue score is refused");
        let mut swapped = entries.clone();
        swapped.swap(3, 4);
        assert!(AnchorLog::replay(&AnchorLog::default(), &swapped).is_err(), "out of order is refused");
        let mut unlinked = entries.clone();
        unlinked[6].parent = [0xEE; 32];
        assert!(AnchorLog::replay(&AnchorLog::default(), &unlinked).is_err(), "a broken parent link is refused");
    }

    /// Differential and associativity checks at random sizes up to a few thousand entries.
    #[test]
    fn appending_agrees_with_scratch_and_is_associative_at_random_sizes() {
        let mut rng = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for _ in 0..12 {
            let n = (next() % 5000) as usize;
            let entries = chain(n as u64, next() % 1000);
            let states = all_states(&entries);
            assert_eq!(states[n].commitment(), root_from_scratch(&entries), "n={n}");
            for _ in 0..8 {
                let a = (next() as usize) % (n + 1);
                let b = a + (next() as usize) % (n - a + 1);
                let mid = AnchorLog::replay(&states[a], &entries[a..b]).unwrap();
                assert_eq!(mid, states[b]);
                assert_eq!(AnchorLog::replay(&mid, &entries[b..]).unwrap(), states[n], "n={n} a={a} b={b}");
            }
        }
    }

    #[test]
    fn counts_and_hash_domains_are_separated() {
        let peaks = vec![[9u8; 32]];
        let one = AnchorLog { count: 1, peaks: peaks.clone() }.commitment();
        let two = AnchorLog { count: 2, peaks: peaks.clone() }.commitment();
        assert_ne!(one, two);
        let e = chain(1, 0)[0];
        let parts: [&[u8]; 4] = [&e.block, &e.parent, &e.root, &e.blue_score.to_le_bytes()];
        assert_ne!(hash(LEAF_PERSONAL, &parts), hash(NODE_PERSONAL, &parts));
        assert_ne!(hash(LEAF_PERSONAL, &parts), hash(ROOT_PERSONAL, &parts));
    }

    #[test]
    fn malformed_logs_are_refused_not_trusted() {
        let bad = AnchorLog { count: 3, peaks: vec![[0; 32]] };
        assert!(!bad.is_well_formed());
        assert!(bad.append(&chain(1, 0)[0]).is_err());
        let full = AnchorLog { count: u64::MAX, peaks: vec![[0; 32]; 64] };
        assert!(full.append(&chain(1, 0)[0]).is_err(), "a full log cannot grow");
    }
}
