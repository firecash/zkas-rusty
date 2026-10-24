//! NU-A tree eras on the wallet side (spec 08 R4.2.7): a reference per-era witness tracker.
//!
//! From NU-A, a chain block whose selected parent's era holds at least the rollover threshold of
//! leaves starts a new era on an empty tree ([`crate::commitment::starts_new_tree_era`], the same
//! predicate consensus applies). A wallet must then
//! - keep one tree per era: positions restart at 0 in every era;
//! - freeze an era's witnesses at its final root (they never change again), and anchor a spend of
//!   such a note to `(freeze_block, final_root)`, which consensus exempts from the maximum anchor age;
//! - never mix notes of two eras in one bundle (one bundle has one anchor).
//!
//! This tracker keeps every leaf and recomputes authentication paths on demand (O(era size) hashes
//! per witness), so it is meant for tools, tests and devnets, and as the executable specification
//! for the production engine (walletd / the mobile engine), whose incremental witness store must
//! reproduce exactly these anchors.

use incrementalmerkletree::{Hashable, Level};
use orchard::tree::{MerkleHashOrchard, MerklePath};

use crate::commitment::starts_new_tree_era;

/// Depth of the Orchard note-commitment tree.
const DEPTH: usize = 32;

/// One era's leaves and, once closed, its freeze record.
#[derive(Clone, Debug, Default)]
pub struct EraLeaves {
    /// The era's leaves in tree order.
    pub leaves: Vec<MerkleHashOrchard>,
    /// `(freeze_block, freeze_blue_score)` once the era is frozen.
    pub frozen_at: Option<([u8; 32], u64)>,
}

/// Where a wallet's note lives: its era and its position inside that era.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EraPosition {
    pub era: u32,
    pub position: u64,
}

/// A spendable witness: the path, the root it proves against and the block a spend must name.
#[derive(Clone, Debug)]
pub struct EraWitness {
    pub path: MerklePath,
    pub root: [u8; 32],
    pub anchor_block: [u8; 32],
    /// Whether the anchor is a frozen era's final root (exempt from the maximum anchor age).
    pub frozen: bool,
}

/// Replays chain blocks in selected-chain order and tracks every era.
#[derive(Clone, Debug)]
pub struct EraTracker {
    rollover_threshold: u64,
    /// DAA score from which NU-A is active (`u64::MAX` = never).
    nua_activation_daa: u64,
    eras: Vec<EraLeaves>,
    /// The last applied chain block (hash, blue score): the anchor block of current-era spends.
    tip: Option<([u8; 32], u64)>,
}

impl EraTracker {
    pub fn new(rollover_threshold: u64, nua_activation_daa: u64) -> Self {
        Self { rollover_threshold, nua_activation_daa, eras: vec![EraLeaves::default()], tip: None }
    }

    /// The current era.
    pub fn era(&self) -> u32 {
        (self.eras.len() - 1) as u32
    }

    pub fn eras(&self) -> &[EraLeaves] {
        &self.eras
    }

    /// Apply one chain block's leaves (coinbase notes first, then accepted actions, as consensus
    /// appends them). Returns the positions the leaves got.
    pub fn apply_block(&mut self, block: [u8; 32], blue_score: u64, daa_score: u64, leaves: &[[u8; 32]]) -> Vec<EraPosition> {
        let current = self.eras.last().expect("at least one era").leaves.len() as u64;
        if starts_new_tree_era(daa_score >= self.nua_activation_daa, current, self.rollover_threshold) {
            let (parent, parent_blue) = self.tip.expect("an era with leaves has a tip");
            self.eras.last_mut().unwrap().frozen_at = Some((parent, parent_blue));
            self.eras.push(EraLeaves::default());
        }
        let era = self.era();
        let cur = self.eras.last_mut().unwrap();
        let mut out = Vec::with_capacity(leaves.len());
        for l in leaves {
            let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(l)).expect("canonical leaf");
            out.push(EraPosition { era, position: cur.leaves.len() as u64 });
            cur.leaves.push(leaf);
        }
        self.tip = Some((block, blue_score));
        out
    }

    /// The root of `era` (its final root if frozen, its current root otherwise).
    pub fn root(&self, era: u32) -> [u8; 32] {
        let (root, _) = Self::root_and_path(&self.eras[era as usize].leaves, None);
        root.to_bytes()
    }

    /// The witness a spend of the note at `at` must use: against the frozen root naming the freeze
    /// block for a frozen era, against the current root naming the tip for the current era.
    pub fn witness(&self, at: EraPosition) -> Option<EraWitness> {
        let e = self.eras.get(at.era as usize)?;
        if at.position >= e.leaves.len() as u64 {
            return None;
        }
        let (root, path) = Self::root_and_path(&e.leaves, Some(at.position));
        let (anchor_block, frozen) = match e.frozen_at {
            Some((b, _)) => (b, true),
            None => (self.tip?.0, false),
        };
        Some(EraWitness { path: MerklePath::from_parts(at.position as u32, path.expect("position given")), root: root.to_bytes(), anchor_block, frozen })
    }

    /// Root over `leaves` (depth 32, empty-subtree padding) and the authentication path of `pos`.
    fn root_and_path(leaves: &[MerkleHashOrchard], pos: Option<u64>) -> (MerkleHashOrchard, Option<[MerkleHashOrchard; DEPTH]>) {
        let mut level: Vec<MerkleHashOrchard> = leaves.to_vec();
        let mut path = [MerkleHashOrchard::empty_root(Level::from(0)); DEPTH];
        let mut idx = pos.unwrap_or(0) as usize;
        for (d, slot) in path.iter_mut().enumerate() {
            let empty = MerkleHashOrchard::empty_root(Level::from(d as u8));
            let sibling = idx ^ 1;
            *slot = level.get(sibling).copied().unwrap_or(empty);
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let l = pair[0];
                let r = pair.get(1).copied().unwrap_or(empty);
                next.push(MerkleHashOrchard::combine(Level::from(d as u8), &l, &r));
            }
            level = next;
            idx /= 2;
        }
        let root = level.first().copied().unwrap_or(MerkleHashOrchard::empty_root(Level::from(DEPTH as u8)));
        (root, pos.map(|_| path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{ChainBlockSubtree, GlobalTree, NoteCommitmentTree};
    use orchard::note::ExtractedNoteCommitment;

    fn cmx(n: u32) -> ExtractedNoteCommitment {
        // A canonical field element: small integers are.
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        Option::from(ExtractedNoteCommitment::from_bytes(&b)).unwrap()
    }

    /// The tracker's eras, roots and freeze points equal what consensus's rule produces over the
    /// same block stream (GlobalTree + `starts_new_tree_era`), and every witness roots to its era's root.
    #[test]
    fn tracker_matches_consensus_rollover_and_witnesses_root() {
        let threshold = 5;
        let activation = 4; // blocks with DAA >= 4 are NU-A
        let mut tracker = EraTracker::new(threshold, activation);
        let mut tree = GlobalTree::new();
        let mut frozen: Vec<([u8; 32], [u8; 32])> = Vec::new(); // (freeze block, final root)
        let mut parent = [0u8; 32];
        let mut owned = Vec::new();
        let mut n = 1u32;
        for daa in 1u64..30 {
            let block = [daa as u8; 32];
            if starts_new_tree_era(daa >= activation, tree.size(), threshold) {
                frozen.push((parent, tree.anchor().to_bytes()));
                tree = GlobalTree::new();
            }
            let k = (daa % 3 + 1) as u32; // 1..3 leaves per block
            let leaves: Vec<_> = (0..k).map(|i| cmx(n + i)).collect();
            n += k;
            let mut st = ChainBlockSubtree::new();
            leaves.iter().for_each(|c| st.push(*c));
            tree.append_subtree(&st).unwrap();
            let pos = tracker.apply_block(block, daa, daa, &leaves.iter().map(|c| c.to_bytes()).collect::<Vec<_>>());
            owned.push(pos[0]);
            parent = block;
        }
        assert_eq!(tracker.era() as usize, frozen.len(), "same number of rollovers");
        assert!(frozen.len() >= 3);
        for (e, (fb, root)) in frozen.iter().enumerate() {
            assert_eq!(tracker.eras()[e].frozen_at.unwrap().0, *fb, "era {e} freeze block");
            assert_eq!(tracker.root(e as u32), *root, "era {e} final root");
        }
        assert_eq!(tracker.root(tracker.era()), tree.anchor().to_bytes(), "current era root");
        // The first era started before activation: it only rolled once NU-A was active.
        assert!(tracker.eras()[0].leaves.len() as u64 >= threshold);
        for at in owned {
            let w = tracker.witness(at).unwrap();
            let leaf = tracker.eras()[at.era as usize].leaves[at.position as usize];
            let c = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&leaf.to_bytes())).unwrap();
            assert_eq!(w.path.root(c).to_bytes(), w.root, "witness of {at:?} roots to its era");
            assert_eq!(w.frozen, (at.era as usize) < frozen.len());
            if w.frozen {
                assert_eq!((w.anchor_block, w.root), frozen[at.era as usize]);
            }
        }
    }

    #[test]
    fn no_rollover_without_nua() {
        let mut t = EraTracker::new(2, u64::MAX);
        for d in 0..10u64 {
            t.apply_block([d as u8; 32], d, d, &[cmx(d as u32 + 1).to_bytes()]);
        }
        assert_eq!(t.era(), 0);
        assert_eq!(t.eras()[0].leaves.len(), 10);
    }
}
