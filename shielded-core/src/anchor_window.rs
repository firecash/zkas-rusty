//! Anchor window commitment (security fork, 2026-10).
//!
//! Every chain block at or after the fork appends one entry `(block, own_tree_root, blue_score)`.
//! Entries are folded into hash chains, one per bucket of [`BUCKET_SPAN`] blue score, and a block
//! keeps only the buckets that can still hold a usable anchor source. The commitment is a hash over
//! the retained `(bucket_index, chain_hash)` pairs and is folded into `zkas_state_root1`.
//!
//! Why: a node that fast-syncs to a pruning point has no tree roots for the chain blocks just below
//! it, yet spends mined just above it may name those blocks as anchors. Before the fork the syncing
//! node took `(root, block)` pairs from its sync peer on trust. With the window committed, the peer
//! must send exactly the entries that re-fold to the PoW-committed value, so every imported pair
//! is proven.
//!
//! Properties:
//! - A block's window is derived only from its selected parent's window plus its own entry, so it
//!   is identical on every node that agrees on the selected chain, and a reorg simply reloads the
//!   new parent's window.
//! - Per-block cost is one hash for the entry and one over at most `keep + 1` bucket pairs.
//! - Folding the entries of the retained buckets in ascending blue score reproduces the window
//!   exactly ([`AnchorWindow::from_entries`]), which is what a syncing node checks.

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

/// Blue-score width of one bucket.
pub const BUCKET_SPAN: u64 = 1_000;

const ENTRY_PERSONAL: &[u8; 16] = b"zkas_anchor_win1";
const COMMIT_PERSONAL: &[u8; 16] = b"zkas_anchor_cmt1";

/// One chain block's contribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowEntry {
    pub block: [u8; 32],
    /// The block's selected parent. Folded in, so the chain order of the entries is committed, and
    /// it lets any node (including a fast-synced one with no chain index below its pruning point)
    /// enumerate the window by following parent links.
    pub parent: [u8; 32],
    pub root: [u8; 32],
    pub blue_score: u64,
}

/// The retained buckets, ascending by bucket index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorWindow {
    pub buckets: Vec<(u64, [u8; 32])>,
}

/// How many buckets below the newest one are retained: enough that every source within
/// `max_anchor_age` blue score of any block that can use this window is covered.
pub fn buckets_to_keep(max_anchor_age: u64) -> u64 {
    max_anchor_age.div_ceil(BUCKET_SPAN) + 1
}

impl AnchorWindow {
    /// The window after appending `entry`. Entries must arrive in strictly increasing blue score.
    /// Consensus appends selected-chain blocks, whose blue scores strictly increase; peer-supplied
    /// lists go through [`Self::from_entries`], which refuses any non-increasing score. This method
    /// itself only refuses an entry that goes back a whole bucket (it keeps no per-entry score).
    pub fn append(&self, entry: &WindowEntry, keep: u64) -> Result<Self, &'static str> {
        let idx = entry.blue_score / BUCKET_SPAN;
        let mut buckets = self.buckets.clone();
        match buckets.last_mut() {
            Some((last_idx, chain)) if *last_idx == idx => *chain = fold(chain, entry),
            Some((last_idx, _)) if *last_idx > idx => return Err("anchor window entry goes backwards in blue score"),
            _ => buckets.push((idx, fold(&[0u8; 32], entry))),
        }
        let floor = idx.saturating_sub(keep);
        buckets.retain(|(i, _)| *i >= floor);
        Ok(Self { buckets })
    }

    /// Rebuild a window from its entries (ascending blue score), as a syncing node does.
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = &'a WindowEntry>, keep: u64) -> Result<Self, &'static str> {
        let mut w = Self::default();
        let mut last: Option<u64> = None;
        for e in entries {
            if last.is_some_and(|l| e.blue_score <= l) {
                return Err("anchor window entries are not strictly increasing in blue score");
            }
            last = Some(e.blue_score);
            w = w.append(e, keep)?;
        }
        Ok(w)
    }

    /// The lowest bucket index still retained, i.e. the floor from which a serving node must send
    /// entries for a syncing node to reproduce this window.
    pub fn floor_bucket(&self) -> Option<u64> {
        self.buckets.first().map(|(i, _)| *i)
    }

    /// The 32-byte value folded into `zkas_state_root1`.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Params::new().hash_length(32).personal(COMMIT_PERSONAL).to_state();
        h.update(&(self.buckets.len() as u32).to_le_bytes());
        for (i, chain) in &self.buckets {
            h.update(&i.to_le_bytes());
            h.update(chain);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

fn fold(prev: &[u8; 32], e: &WindowEntry) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(ENTRY_PERSONAL).to_state();
    h.update(prev);
    h.update(&e.block);
    h.update(&e.parent);
    h.update(&e.root);
    h.update(&e.blue_score.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(n: u8, bs: u64) -> WindowEntry {
        WindowEntry { block: [n; 32], parent: [n.wrapping_sub(1); 32], root: [n.wrapping_add(100); 32], blue_score: bs }
    }

    /// Random windows (random retention, random blue-score jumps including jumps past the whole
    /// window): the served tail always rebuilds the exact window, and every manipulation a lying peer
    /// can make to that tail (change any field of any entry, drop, duplicate, reorder, drop the
    /// oldest entries of the floor bucket, append a foreign entry) is either refused or produces a
    /// different commitment.
    #[test]
    fn random_windows_rebuild_exactly_and_every_tampering_is_caught() {
        let mut x: u64 = 0x0123_4567_89ab_cdef;
        let mut rnd = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n.max(1)
        };
        for case in 0..200 {
            let keep = 1 + rnd(5);
            let mut bs = rnd(3_000);
            let mut entries = vec![];
            let mut w = AnchorWindow::default();
            for i in 0..(5 + rnd(400)) {
                bs += 1 + if rnd(20) == 0 { rnd(8_000) } else { rnd(300) };
                let en = WindowEntry {
                    block: [(i % 256) as u8; 32],
                    parent: [(i % 256) as u8 ^ 0x5a; 32],
                    root: [(rnd(256)) as u8; 32],
                    blue_score: bs,
                };
                w = w.append(&en, keep).unwrap();
                entries.push(en);
            }
            assert!(w.append(&WindowEntry { blue_score: bs.saturating_sub(BUCKET_SPAN), ..entries[0] }, keep).is_err() || bs < BUCKET_SPAN, "a bucket going backwards is refused");
            let floor = w.floor_bucket().unwrap();
            let tail: Vec<WindowEntry> = entries.iter().copied().filter(|e| e.blue_score / BUCKET_SPAN >= floor).collect();
            let good = AnchorWindow::from_entries(tail.iter(), keep).unwrap();
            assert_eq!(good, w, "case {case}: the served tail rebuilds the window");
            let caught = |t: &[WindowEntry]| match AnchorWindow::from_entries(t.iter(), keep) {
                Err(_) => true,
                Ok(r) => r.commitment() != w.commitment(),
            };
            let n = tail.len();
            let i = rnd(n as u64) as usize;
            let mut t = tail.clone();
            match rnd(4) {
                0 => t[i].root[rnd(32) as usize] ^= 1,
                1 => t[i].block[rnd(32) as usize] ^= 1,
                2 => t[i].parent[rnd(32) as usize] ^= 1,
                _ => t[i].blue_score ^= 1 + rnd(3),
            }
            // A blue-score edit that keeps strict order AND the bucket can only be caught by the fold.
            assert!(caught(&t), "case {case}: field tampering of entry {i}/{n}");
            let mut t = tail.clone();
            t.remove(i);
            assert!(n == 1 || caught(&t), "case {case}: dropped entry");
            let mut t = tail.clone();
            t.insert(i, tail[i]);
            assert!(caught(&t), "case {case}: duplicated entry");
            if n > 1 {
                let mut t = tail.clone();
                let j = (i + 1) % n;
                t.swap(i, j);
                assert!(caught(&t), "case {case}: reordered entries");
                assert!(caught(&tail[1..]), "case {case}: oldest entry of the floor bucket dropped");
            }
            let mut t = tail.clone();
            t.push(WindowEntry { blue_score: bs + 1, ..tail[n - 1] });
            assert!(caught(&t), "case {case}: foreign entry appended");
            // A peer list repeating a blue score is refused outright, wherever the repeat is.
            let mut t = tail.clone();
            t.insert(i + 1, WindowEntry { root: [0xee; 32], ..tail[i] });
            assert!(AnchorWindow::from_entries(t.iter(), keep).is_err(), "case {case}: equal score in a peer list refused");
        }
    }

    #[test]
    fn incremental_equals_rebuild_and_old_buckets_drop() {
        let keep = buckets_to_keep(27_000);
        let entries: Vec<WindowEntry> = (0..400u64).map(|i| e((i % 251) as u8, i * 97 + 5)).collect();
        let mut w = AnchorWindow::default();
        for x in &entries {
            w = w.append(x, keep).unwrap();
        }
        // A syncing node only gets the entries of the retained buckets.
        let floor = w.floor_bucket().unwrap();
        let tail: Vec<&WindowEntry> = entries.iter().filter(|x| x.blue_score / BUCKET_SPAN >= floor).collect();
        let rebuilt = AnchorWindow::from_entries(tail.into_iter(), keep).unwrap();
        assert_eq!(rebuilt, w);
        assert_eq!(rebuilt.commitment(), w.commitment());
        assert!(w.buckets.len() as u64 <= keep + 1);
    }

    #[test]
    fn any_change_moves_the_commitment() {
        let keep = buckets_to_keep(27_000);
        let base: Vec<WindowEntry> = (0..50u64).map(|i| e(i as u8, i * 300)).collect();
        let c = AnchorWindow::from_entries(base.iter(), keep).unwrap().commitment();
        let mut fake_root = base.clone();
        fake_root[20].root = [0xEE; 32];
        assert_ne!(AnchorWindow::from_entries(fake_root.iter(), keep).unwrap().commitment(), c, "a substituted root");
        let mut fake_block = base.clone();
        fake_block[20].block = [0xEE; 32];
        assert_ne!(AnchorWindow::from_entries(fake_block.iter(), keep).unwrap().commitment(), c, "a substituted block");
        let mut omitted = base.clone();
        omitted.remove(20);
        assert_ne!(AnchorWindow::from_entries(omitted.iter(), keep).unwrap().commitment(), c, "an omitted entry");
        let mut reparented = base.clone();
        reparented[20].parent = [0xEE; 32];
        assert_ne!(AnchorWindow::from_entries(reparented.iter(), keep).unwrap().commitment(), c, "a changed parent link");
        let mut rescored = base.clone();
        rescored[20].blue_score += 1;
        assert_ne!(AnchorWindow::from_entries(rescored.iter(), keep).unwrap().commitment(), c, "a changed blue score");
    }

    #[test]
    fn out_of_order_entries_are_refused() {
        let keep = buckets_to_keep(27_000);
        assert!(AnchorWindow::from_entries([e(1, 10), e(2, 10)].iter(), keep).is_err());
        assert!(AnchorWindow::from_entries([e(1, 2_500), e(2, 1_200)].iter(), keep).is_err());
    }
}
