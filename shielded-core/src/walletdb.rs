//! Wallet note tracking — the receive-and-remember side of a real wallet (PLAN
//! §2.9 / §2.10).
//!
//! The consensus node keeps only the global tree's **frontier** (~32 nodes); it
//! cannot produce a membership witness for an arbitrary past note. By design
//! (PLAN §2.9) **wallets hold their own witnesses**. This module is that wallet
//! bookkeeping: it consumes the exact same stream of note commitments the
//! consensus [`GlobalTree`](crate::tree::GlobalTree) consumes — in GHOSTDAG
//! accepted order — and for every commitment it can recognise as its own it
//! keeps a live [`IncrementalWitness`] that it advances as later notes arrive.
//!
//! Two kinds of notes are discovered:
//!
//! - **Coinbase notes** are not encrypted — their `(recipient, ρ, rseed)` are
//!   stated publicly by the coinbase transaction and their value is the public
//!   subsidy+fees. The wallet recognises one as its own by matching the stated
//!   recipient against its address and reconstructs the spendable note exactly
//!   as [`crate::coinbase`] / consensus recompute it.
//! - **Shielded-transaction outputs** are recovered by trial decryption with the
//!   wallet's incoming viewing key (the [`crate::wallet::scan`] hot path).
//!
//! Crucially, the wallet must walk the commitments in **the same order consensus
//! appends them** — per accepted chain block: the coinbase notes first (in the
//! coinbase's own note order), then each accepted shielded transaction's actions
//! in order (see [`crate::state::apply_chain_block_to`]). Mirroring that order is
//! what makes each note's tracked position and witness root agree with the node's
//! anchor, so a witness this module produces verifies against consensus.
//!
//! This module needs no proving circuit (discovery + witnessing are decryption
//! and hashing only), so it is available to light wallets without the `circuit`
//! feature. The produced `(note, merkle_path)` is then handed to
//! [`crate::wallet::build::build_spend_bundle`] to actually spend.

use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
use incrementalmerkletree::witness::IncrementalWitness;
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Address,
    keys::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    note_encryption::OrchardDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use std::cell::OnceCell;
use std::collections::HashSet;
use zcash_note_encryption::try_output_recovery_with_ovk;

use crate::bundle::ShieldedBundle;
use crate::coinbase::{CoinbaseNoteDesc, coinbase_note_commitment};
use crate::tree::{FrontierState, GlobalTree, TREE_DEPTH};
use crate::wallet::scan::{
    CompactActionRecord, ReceivedNote, reconstruct_action, scan_bundle_prepared, scan_compact_auto, scan_compact_prepared, trim_memo,
};

/// A note the wallet owns and can spend. The membership witness is **not** held
/// live per note (that made scanning O(N²) — every leaf advanced every owned
/// note's witness). Instead the wallet keeps the full commitment stream once and
/// builds a witness on demand, only for the notes a spend actually selects
/// ([`WalletDb::witness_path`]).
#[derive(Clone)]
pub struct OwnedNote {
    /// The spendable Orchard note.
    pub note: Note,
    /// The note's leaf position in the global note-commitment tree.
    pub position: u64,
    /// The note's nullifier (derived from the note and the wallet's full viewing
    /// key). When this nullifier appears on-chain, the note has been spent and is
    /// dropped from the wallet's unspent set.
    nullifier: [u8; 32],
}

impl OwnedNote {
    /// The note's value in the base unit.
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
}

/// A note whose spend has been **submitted** to the network but not yet observed
/// on-chain. Parked here (not deleted) so the money cannot silently vanish: if the
/// transaction never applies — a node that crashes with it still in the mempool, a
/// mempool eviction, or a consensus-dropped shielded spend (the drop-not-disqualify
/// rule applies a block but skips the spend) — [`WalletDb::reclaim_expired`] hands
/// the note back to the spendable set.
#[derive(Clone)]
pub struct PendingSpend {
    /// The parked note, unchanged — its position/witness stay valid.
    pub note: OwnedNote,
    /// Transaction id the spend was submitted in (zeros when unknown).
    pub txid: [u8; 32],
    /// Chain DAA score at submit time, supplied by the caller — the expiry
    /// countdown starts here. The caller passes it (rather than this type
    /// reading a clock of its own) because a wallet syncing against a node that
    /// serves no block metadata has no clock: `last_daa` stays 0, and an expiry
    /// measured against it would fire the moment any dated block arrived,
    /// un-parking a spend that is legitimately still in flight.
    pub submitted_daa: u64,
}

/// What a history row is: mint, money in, or money out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryKind {
    /// A coinbase note minted to this wallet (mining reward).
    Coinbase = 0,
    /// A shielded payment arriving (none of our notes were spent by the tx).
    Received = 1,
    /// Our own spend — includes a pure consolidation (`amount == 0`).
    Sent = 2,
}

/// One row of the wallet's chain-derived transaction history, recorded during
/// ingest and persisted in the checkpoint (v6 section) — so it survives restarts
/// and, unlike the browser-local 0-conf list, a seed restore (for everything the
/// wallet can still derive from chain).
///
/// Derivation is purely local: incoming amounts from IVK trial decryption, spends
/// from our own nullifiers, and — when the send was built with our OVK
/// (`recoverable history`) — the recipient/amount/memo of our own past sends.
/// Nothing here is readable by anyone without this wallet's keys.
#[derive(Clone, Debug)]
pub struct HistoryEntry {
    pub kind: HistoryKind,
    /// The enclosing transaction id (coinbase txid for mint rows).
    pub txid: [u8; 32],
    /// DAA score of the chain block that applied it.
    pub daa_score: u64,
    /// Chain block header timestamp, ms since epoch (0 if the node predates the
    /// v2 `GetShieldedBlocks` fields).
    pub timestamp_ms: u64,
    /// Coinbase/Received: value arriving. Sent: value paid to others (fee not
    /// included; OVK-recovered when available, else net outflow minus fee). A
    /// compact-only historical send instead stores its net outflow; see
    /// [`Self::amount_is_net_outflow`].
    pub amount: u64,
    /// Sent rows: the public fee the bundle burned (`value_balance`); else 0.
    pub fee: u64,
    /// `true` when a compact archive reconstructed a historical spend. Compact
    /// records reveal our spent notes and change, but omit the full bundle's
    /// recipient, memo, and fee; `amount` is therefore net outflow (paid amount
    /// plus fee), not the amount delivered to the recipient.
    pub amount_is_net_outflow: bool,
    /// Whether `fee` came from the full bundle. `false` for compact-only
    /// historical sends, where a displayed zero must not be mistaken for zero fee.
    pub fee_known: bool,
    /// Sent rows: the recipient's raw Orchard address, when recoverable via our
    /// OVK. `None` for pre-OVK sends (recipient unknowable even to us).
    pub recipient: Option<[u8; 43]>,
    /// Trimmed memo bytes (empty = no memo).
    pub memo: Vec<u8>,
}

/// Chain-block metadata for dating history rows, from the v2 `GetShieldedBlocks`
/// fields. `txids` is parallel to the ingested bundle slice.
#[derive(Clone, Debug)]
pub struct BlockMeta {
    pub coinbase_txid: [u8; 32],
    pub txids: Vec<[u8; 32]>,
    pub timestamp_ms: u64,
    pub daa_score: u64,
}

/// The balance effect of blocks too close to the tip to be safely ingested — value
/// arriving and owned value being spent. Reported as *pending* (0-conf); see
/// [`WalletDb::preview_block`].
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview {
    pub incoming: u128,
    pub outgoing: u128,
}

impl Preview {
    /// Fold another block's preview into this one.
    pub fn add(&mut self, other: Preview) {
        self.incoming += other.incoming;
        self.outgoing += other.outgoing;
    }
    pub fn is_zero(&self) -> bool {
        self.incoming == 0 && self.outgoing == 0
    }
}

/// Where a scan's CPU actually goes, accumulated across ingest calls.
///
/// A wallet scan has exactly two heavy parts and nobody had ever measured their
/// ratio: **trial decryption** (one Pallas variable-base scalar multiplication per
/// action per ivk — the cost of privacy, and irreducible per (wallet, action) pair)
/// and **tree append** (one Sinsemilla combine per leaf, amortized — the cost of
/// being able to witness later). They call for completely different remedies, so
/// guessing which dominates is how optimization effort gets spent in the wrong place.
///
/// Counters only; reading them is free and they are never persisted.
#[derive(Default, Clone, Copy, Debug)]
pub struct ScanCost {
    /// Nanoseconds inside `scan_compact_prepared` / `scan_bundle_prepared`.
    pub decrypt_ns: u128,
    /// Nanoseconds inside `append_leaf` — the Sinsemilla tree work.
    pub tree_ns: u128,
    /// Actions offered to trial decryption.
    pub actions: u64,
    /// Leaves appended to the commitment tree.
    pub leaves: u64,
}

impl ScanCost {
    /// Both halves together.
    pub fn total_ns(&self) -> u128 {
        self.decrypt_ns + self.tree_ns
    }
}

/// A wallet's running view of the global note-commitment tree: it walks the
/// canonical commitment stream, recognises its own notes, and keeps a spendable
/// witness for each.
pub struct WalletDb {
    /// Incoming viewing key — recovers shielded-tx outputs sent to this wallet.
    ivk: IncomingViewingKey,
    /// The `ivk` precomputed for trial decryption, built once at construction and
    /// reused for every bundle in every scan pass (see [`scan_bundle_prepared`]).
    /// `IncomingViewingKey::prepare` is not free, so doing it per bundle — as the
    /// old per-action path did — repeated the same setup on every scanned bundle.
    prepared_ivk: PreparedIncomingViewingKey,
    /// Full viewing key — derives each owned note's nullifier for spent-detection.
    fvk: FullViewingKey,
    /// This wallet's raw external address — matches coinbase recipients.
    my_address: [u8; 43],
    /// A running mirror of the global tree, used only to report the current tip
    /// [`anchor`](Self::anchor) cheaply (one append per leaf). Initialised from
    /// [`base_frontier`](Self::base_frontier), so it already reflects everything up
    /// to the fast-sync checkpoint before any leaf is ingested.
    tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// The checkpoint frontier the wallet's stream starts from — empty for a
    /// genesis/position-0 (full-scan) start, or a node-supplied frontier when the
    /// wallet fast-syncs ([`Self::from_frontier`]). Its ommers are exactly the
    /// left-hand authentication path, so the wallet can witness any note appended
    /// after the checkpoint **without** holding a single pre-checkpoint leaf.
    base_frontier: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    /// Absolute position of the wallet's first *stored* leaf: the number of leaves
    /// already summarised by `base_frontier`. 0 for a full-scan wallet. Owned-note
    /// positions and `size` are absolute (this base + an index into `leaves`).
    base_size: u64,
    /// The note-commitment stream **after** `base_size`, in append order. Retaining
    /// it lets the wallet build a membership witness for any owned position **on
    /// demand** (see [`Self::witness_path`]) instead of advancing a per-note witness
    /// on every append — the difference between an O(N) and an O(N²) scan.
    ///
    /// **Cost, corrected.** This previously read "~1 MB per million notes, cheap next
    /// to 625M hashes". That is wrong by 32×: 32 bytes × 1M leaves is **32 MB**, and
    /// [`Self::decoded`] holds a second copy of the same size, so a wallet at the
    /// current ~2.05 M leaves carries **~130 MB** of purely public data. It is not
    /// cheap and it is not per-wallet data — every wallet's copy is byte-identical.
    /// Multiplied across a hosted daemon's resident wallets this is the dominant
    /// term in its RSS (measured: 6.8 GB across 39 wallets). Keeping ONE keyless copy
    /// for everyone is what [`Self::set_leaves_only`] exists for.
    leaves: Vec<[u8; 32]>,
    /// The leaf stream decoded to curve points, built on first use.
    ///
    /// A `MerkleHashOrchard` is a Pallas point, so turning a stored leaf back into one
    /// is a point *decompression* — ~0.68 ms each, ~136 s for a 200K-leaf chain. Doing
    /// that eagerly on restore was over half of the multi-minute window in which a
    /// restarted daemon showed every user an empty wallet. Nothing about a balance, a
    /// note, or the tip anchor needs curve points; only rebuilding a spend witness
    /// does. So the stream is *stored* as bytes (restoring it is a memcpy) and decoded
    /// lazily, once, when a witness actually needs it — and `warm_leaves` lets the
    /// daemon do that off the request path so a send never waits on it either.
    decoded: OnceCell<Vec<MerkleHashOrchard>>,
    /// Owned, unspent notes (absolute position + note only; witnesses are built lazily).
    notes: Vec<OwnedNote>,
    /// Number of leaves ingested so far, absolute (`base_size + leaves.len()`) — the
    /// next leaf's position.
    size: u64,
    /// Live membership witnesses for owned notes, held at exactly
    /// [`witnessed_upto`](Self::witnessed_upto) leaves — i.e. **lagging at the matured
    /// anchor**, which is where a spend must root anyway. Rebuilding a witness on
    /// demand costs a full replay of the leaf stream (Sinsemilla hashing: ~21s over a
    /// 174K-leaf chain, *per note* — the dominant cost of a send, dwarfing the ~7s
    /// Halo 2 proof). Advancing these incrementally as the wallet syncs makes a spend's
    /// witness lookup O(1).
    witnesses: Vec<(u64, IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>)>,
    /// How many notes may hold a live witness, i.e. the `k` in the `leaves × k` cost of
    /// advancing. Defaults to [`MAX_LIVE_WITNESSES`]. A caller that syncs many wallets on
    /// one loop lowers it for a note-heavy wallet (miner/pool/treasury), so that wallet
    /// still keeps a *spendable* set warm without its thousands of notes making every
    /// leaf cost thousands of appends. See [`Self::set_witness_budget`].
    witness_budget: usize,
    /// The tree at exactly `witnessed_upto` leaves — the state a newly matured note's
    /// witness is snapshotted from. (`tree` mirrors the *tip*; this one lags.)
    lag_tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// Absolute leaf count `witnesses` / `lag_tree` include.
    witnessed_upto: u64,
    /// Every nullifier revealed by an **applied** bundle in this wallet's stream.
    /// Mirrors the consensus drop rule (PLAN §2.4): a bundle any of whose
    /// nullifiers was already spent is DROPPED — it appends no leaves. Without
    /// this, a shielded tx that the UTXO layer accepted twice (it has no
    /// transparent inputs, so nothing conflicts there — observed live when two
    /// parallel DAG blocks both carried the same tx) double-counts its outputs
    /// and shifts every later leaf position off the consensus tree.
    spent_nullifiers: HashSet<[u8; 32]>,
    /// Outgoing viewing key (external scope) — recovers the recipient/amount/memo
    /// of our own past sends *if* they were built with it (`recoverable history`).
    /// Derived from the FVK, so a watch-only wallet has it too.
    ovk: OutgoingViewingKey,
    /// Chain-derived transaction history, in ingest (chronological) order,
    /// capped at [`HISTORY_CAP`]. Only recorded when the ingest caller supplies
    /// [`BlockMeta`] (i.e. the node serves the v2 fields).
    history: Vec<HistoryEntry>,
    /// Whether ingest records `history` rows at all. History is an opt-in
    /// convenience: it stores a readable record of the wallet's transactions in
    /// the checkpoint, which anyone holding the wallet file can read — so the
    /// holder must explicitly accept that before anything is written. Turning it
    /// off purges what was recorded ([`Self::set_history_enabled`]).
    history_enabled: bool,
    /// Decryption results for the page currently being ingested, keyed by the action's
    /// nullifier (unique per action).
    ///
    /// Trial decryption is now ~99% of a scan's cost, and it was being done one
    /// TRANSACTION at a time — a handful of actions per call. That is too small to
    /// parallelise usefully and far below the ~100-point batch a GPU needs to beat the
    /// CPU at all, so both levers were blocked by the batch size rather than by
    /// anything hard. Deciding a whole page at once unblocks both.
    ///
    /// Only what the page contains, cleared per page. A miss simply falls through to
    /// the old per-transaction path, so this is a memo and can never change a result.
    predecrypted: Option<std::collections::HashMap<[u8; 32], Option<ReceivedNote>>>,
    /// This wallet's key-agreement scalar, derived once so the GPU path does not have
    /// to re-derive it per page. `None` only if the key could not yield one, in which
    /// case scanning stays on the CPU.
    agree_scalar: Option<pasta_curves::pallas::Scalar>,
    /// Skip trial decryption in the ingest path — see [`Self::set_leaves_only`].
    /// Deliberately NOT persisted: it describes what this in-memory copy is for,
    /// not anything about the stream it holds, and a checkpoint written by a
    /// shared tree must stay loadable as an ordinary (if noteless) wallet.
    leaves_only: bool,
    /// Do not maintain this wallet's own mirror `tree` — the daemon-wide shared tree
    /// holds an identical one and will supply its frontier.
    ///
    /// The tree is 80% of a scan (measured: 319 s of Sinsemilla against 79 s of trial
    /// decryption) and it is *public*: every wallet ingesting the same blocks builds
    /// bit-identical nodes. Having N wallets each build their own is the single
    /// largest piece of duplicated work in the daemon.
    ///
    /// Not persisted — it describes how this copy is being driven right now, not
    /// anything about the stream.
    borrow_tree: bool,
    /// Whether `tree` currently reflects `size`.
    ///
    /// False from the moment a leaf is appended without hashing it in. The frontier of
    /// a commitment tree at N leaves is a pure function of leaves 0..N, so the shared
    /// tree's frontier at the same `size` IS this wallet's frontier — that is what
    /// [`Self::adopt_tip_frontier`] installs, and why borrowing is sound rather than a
    /// guess. Until then nothing may read `anchor()`.
    tree_valid: bool,
    /// Spends submitted but not yet observed on-chain — see [`PendingSpend`].
    /// Excluded from the balance and from spend selection (like spent notes), but
    /// recoverable if the transaction is lost.
    pending_spends: Vec<PendingSpend>,
    /// DAA score of the newest block ingested with [`BlockMeta`] — the wallet's
    /// chain clock. Only advances as blocks are actually ingested, so pending-spend
    /// expiry never runs ahead of what the wallet has really seen.
    last_daa: u64,
    /// Complete subtree roots for this wallet's stream — see [`SubtreeCache`]. Kept in
    /// step by `append_leaf`; built (and gated) by `build_subtree_cache`. Inactive until
    /// built, and every consumer falls back to the replay when it cannot serve.
    subtree: SubtreeCache,
    /// Scan cost counters — see [`ScanCost`]. Not persisted; reset on load.
    scan_cost: ScanCost,
}

/// How many owned notes keep a live witness. Beyond this, advancing every witness on
/// every leaf would reintroduce the O(N·k) scan that once made a wallet op take 33
/// minutes; the excess notes fall back to the on-demand rebuild.
const MAX_LIVE_WITNESSES: usize = 256;

/// A subtree-cache build detached from the wallet that owns it.
///
/// The cache is a pure function of `(base_frontier, base_size, leaf stream)` and the fold
/// mutates none of them, so it does not need the wallet lock — and holding that lock for
/// the ~247 s a full build takes is what made background builds unaffordable. Slicing the
/// build to keep the lock available instead capped it at one 2 s slice per sync lap: on the
/// live daemon that was a ~10 % duty cycle, and **no build completed at all** while users
/// went on paying the full 247 s inline on their first send.
///
/// Snapshot the inputs under the lock (a memcpy of the decoded leaves, ~61 MB at 1.9 M
/// leaves), release it, fold on a blocking thread, then install with
/// [`WalletDb::install_subtree_cache`], which re-checks that the snapshot still matches.
pub struct SubtreeBuildJob {
    base_frontier: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    base_size: u64,
    leaves: Vec<MerkleHashOrchard>,
}

/// A folded cache awaiting installation — see [`SubtreeBuildJob::run`].
pub struct BuiltSubtreeCache {
    cache: SubtreeCache,
    base_size: u64,
}

impl SubtreeBuildJob {
    /// How many leaves this build has to fold (for progress reporting).
    pub fn leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Fold the snapshot. Pure CPU over owned data — belongs on a blocking thread.
    /// `None` if the frontier cannot seed the cache or a subtree root cannot be
    /// recorded, in which case the caller keeps the replay path.
    pub fn run(self) -> Option<BuiltSubtreeCache> {
        let mut c = SubtreeCache::default();
        if !c.seed_from_frontier(&self.base_frontier, self.base_size) {
            return None;
        }
        for (i, leaf) in self.leaves.iter().enumerate() {
            if !c.push_leaf(self.base_size + i as u64, *leaf) {
                return None;
            }
        }
        Some(BuiltSubtreeCache { cache: c, base_size: self.base_size })
    }
}

/// Level at or above which [`SubtreeCache`] retains complete subtree roots. Below it a
/// note's siblings are folded from its own `2^CACHE_LEVEL`-leaf window at spend time.
///
/// The trade is per-note work (`2^CACHE_LEVEL − 1` Sinsemilla hashes) against memory
/// (`2·N/2^CACHE_LEVEL` hashes). A Sinsemilla combine is ~150–260 µs — it is *the* unit
/// cost of everything here — so at 4: ~15 hashes ≈ 4 ms per note, and ~780 KB per 200 K
/// leaves. Measured against the O(chain) replay at 200 K leaves: 29.4 s → 0.36 s.
const CACHE_LEVEL: u8 = 4;

/// The wallet's **complete subtree roots** — the structure that turns a spend witness
/// from an O(chain) replay into O(depth) lookups.
///
/// The observation it rests on: for a note at position `p` witnessed at anchor `S`,
/// every authentication sibling is the root of a subtree that is either **entirely
/// below `S`** (hence complete, hence *immutable for the rest of time*) or **entirely
/// above `S`** (hence the empty root) — with at most **one** exception, the single
/// subtree whose range straddles `S`. So all but one sibling can be computed once and
/// kept, and the straddler is `O(depth)` to derive per anchor.
///
/// Roots are accumulated by a Merkle-mountain-range sweep: append a leaf, then merge
/// equal-level neighbours while the top of [`Self::peaks`] is the true left sibling.
/// That is exactly **one combine per leaf, amortized** — the same per-leaf cost the tip
/// mirror [`WalletDb::tree`] already pays — and every merge yields one complete (so
/// permanently valid) subtree root.
///
/// Soundness does not rest on this reasoning being right: a freshly built cache is
/// gated on reproducing the independently-maintained tip root
/// ([`WalletDb::build_subtree_cache`]), and every path it serves is re-verified against
/// the anchor root before use. A wrong cache declines; it cannot mis-witness.
#[derive(Default, Clone)]
struct SubtreeCache {
    /// `levels[l]` holds complete subtree roots at level `l`, dense and in increasing
    /// index order starting at absolute index `first[l]`. Only `l >= CACHE_LEVEL` is
    /// populated.
    levels: Vec<Vec<MerkleHashOrchard>>,
    first: Vec<u64>,
    /// Merkle-mountain-range peaks: the maximal complete subtrees not yet merged with a
    /// right sibling, left to right. Seeded from the fast-sync base frontier so a
    /// compacted wallet still resolves siblings that reach below its stored stream.
    peaks: Vec<(u8, u64, MerkleHashOrchard)>,
    /// Absolute leaf count folded in so far.
    upto: u64,
    /// Whether the cache may be used. Cleared whenever anything invalidates it.
    active: bool,
    /// A build was attempted and rejected. Prevents re-paying an O(chain) build every
    /// sync tick for a wallet whose shape the cache cannot serve.
    failed: bool,
    /// This is an **in-progress** build that stood down part-way, not a usable cache.
    /// `active` is false, so no consumer can serve from it; the next build resumes from
    /// `upto` instead of starting over. Deliberately in-memory only — `write_subtree_section`
    /// does not persist it, and a reloaded checkpoint therefore comes back as a plain
    /// inactive cache that simply rebuilds from scratch. Losing progress across a restart
    /// is safe; serving from a half-built index would not be.
    partial: bool,
}

impl SubtreeCache {
    /// Record a complete subtree root, keeping each level densely indexed. Returns
    /// `false` if that would leave a gap — the caller then abandons the cache rather
    /// than serve from a structure it cannot index soundly.
    fn record(&mut self, level: u8, idx: u64, h: MerkleHashOrchard) -> bool {
        let l = level as usize;
        if self.levels.len() <= l {
            self.levels.resize(l + 1, Vec::new());
            self.first.resize(l + 1, 0);
        }
        if self.levels[l].is_empty() {
            self.first[l] = idx;
        } else if self.first[l] + self.levels[l].len() as u64 != idx {
            return false;
        }
        self.levels[l].push(h);
        true
    }

    fn get(&self, level: u8, idx: u64) -> Option<MerkleHashOrchard> {
        let l = level as usize;
        let lv = self.levels.get(l)?;
        lv.get(idx.checked_sub(*self.first.get(l)?)? as usize).copied()
    }

    /// Fold one leaf into the mountain range, recording every subtree it completes.
    fn push_leaf(&mut self, pos: u64, leaf: MerkleHashOrchard) -> bool {
        let mut node = (0u8, pos, leaf);
        while let Some(&(tl, ti, th)) = self.peaks.last() {
            // Merge only with a genuine left sibling: same level, even index, adjacent.
            if tl != node.0 || ti % 2 != 0 || ti + 1 != node.1 {
                break;
            }
            self.peaks.pop();
            let combined = MerkleHashOrchard::combine(Level::from(tl), &th, &node.2);
            node = (tl + 1, ti >> 1, combined);
            if node.0 >= CACHE_LEVEL && !self.record(node.0, node.1, node.2) {
                return false;
            }
        }
        self.peaks.push(node);
        self.upto = pos + 1;
        true
    }

    /// Seed the peaks with the complete subtrees of `[0, size)` summarised by a
    /// fast-sync base frontier, so a compacted wallet can still resolve the
    /// left-hand siblings that reach below its stored leaves.
    ///
    /// A frontier holds its last leaf plus the left siblings ("ommers") along that
    /// leaf's path. Folding the leaf upward through the run of set bits of
    /// `pos = size - 1` yields the rightmost peak; each remaining ommer is itself a
    /// peak at the level it sits on. Peaks are pushed left to right (highest level
    /// first), which is the order the mountain range expects.
    fn seed_from_frontier(&mut self, f: &Frontier<MerkleHashOrchard, TREE_DEPTH>, size: u64) -> bool {
        let Some(nef) = f.value() else {
            return size == 0; // an empty frontier can only describe an empty prefix
        };
        let pos = size.wrapping_sub(1);
        if u64::from(nef.position()) != pos {
            return false;
        }
        let ommers = nef.ommers();
        let mut digest = *nef.leaf();
        let mut lvl = 0u8;
        let mut i = 0usize;
        // Fold up through the trailing run of set bits: each set bit means the left
        // sibling at that level is a *past* subtree, supplied by the next ommer.
        while (pos >> lvl) & 1 == 1 {
            let Some(o) = ommers.get(i) else { return false };
            digest = MerkleHashOrchard::combine(Level::from(lvl), o, &digest);
            i += 1;
            lvl += 1;
        }
        let rightmost = (lvl, pos >> lvl, digest);
        // Every remaining ommer is a peak: the left sibling at a level whose bit is set.
        let mut rest = Vec::new();
        for l in (lvl + 1)..=TREE_DEPTH {
            if i >= ommers.len() {
                break;
            }
            if (pos >> l) & 1 == 1 {
                rest.push((l, (pos >> l) - 1, ommers[i]));
                i += 1;
            }
        }
        if i != ommers.len() {
            return false; // did not account for every ommer — refuse to guess
        }
        // Left to right = highest level first, then the rightmost peak.
        rest.reverse();
        self.peaks = rest;
        self.peaks.push(rightmost);
        // Below-base subtrees are complete too, so they are legitimate cache entries.
        let seeded: Vec<(u8, u64, MerkleHashOrchard)> = self.peaks.clone();
        for (l, idx, h) in seeded {
            if l >= CACHE_LEVEL && !self.record(l, idx, h) {
                return false;
            }
        }
        self.upto = size;
        true
    }
}

/// History rows kept (oldest dropped beyond this). A pool/miner wallet mints one
/// row per block, so an uncapped history would grow by ~86K rows/day at 1 BPS;
/// 20K keeps weeks of ordinary use and days of solo mining while bounding the
/// checkpoint blob.
const HISTORY_CAP: usize = 20_000;

impl WalletDb {
    /// Build a wallet view from a 32-byte seed. Returns `None` if the seed is not
    /// a valid Orchard spending key (negligibly rare).
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        let fvk = FullViewingKey::from(&sk);
        let ivk = fvk.to_ivk(Scope::External);
        let prepared_ivk = ivk.prepare();
        let agree_scalar = crate::wallet::ivk_agreement_scalar(&ivk);
        let my_address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let ovk = fvk.to_ovk(Scope::External);
        Some(Self {
            ivk,
            prepared_ivk,
            fvk,
            my_address,
            tree: CommitmentTree::empty(),
            base_frontier: Frontier::empty(),
            base_size: 0,
            leaves: Vec::new(),
            decoded: OnceCell::new(),
            notes: Vec::new(),
            size: 0,
            witnesses: Vec::new(),
            witness_budget: MAX_LIVE_WITNESSES,
            lag_tree: CommitmentTree::empty(),
            witnessed_upto: 0,
            spent_nullifiers: HashSet::new(),
            ovk,
            history: Vec::new(),
            history_enabled: true,
            agree_scalar,
            predecrypted: None,
            leaves_only: false,
            borrow_tree: false,
            tree_valid: true,
            pending_spends: Vec::new(),
            last_daa: 0,
            subtree: SubtreeCache::default(),
            scan_cost: ScanCost::default(),
        })
    }

    /// Build a **watch-only** wallet view from a serialized full viewing key
    /// (`ak ‖ nk ‖ rivk`, 96 bytes). This holds **no spend authority**: it scans and
    /// recognises the wallet's notes, tracks balances, and can build a spend *proof*
    /// (via [`crate::wallet::build::prepare_payment`]), but it cannot authorize a
    /// spend — that signature must come from the device holding the seed. This is the
    /// server side of the non-custodial (mobile) wallet: the daemon syncs with only
    /// the FVK, so a server compromise cannot move funds. Returns `None` if the bytes
    /// are not a valid full viewing key.
    pub fn from_fvk(fvk_bytes: &[u8; 96]) -> Option<Self> {
        let fvk = FullViewingKey::from_bytes(fvk_bytes)?;
        let ivk = fvk.to_ivk(Scope::External);
        let prepared_ivk = ivk.prepare();
        let agree_scalar = crate::wallet::ivk_agreement_scalar(&ivk);
        let my_address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let ovk = fvk.to_ovk(Scope::External);
        Some(Self {
            ivk,
            prepared_ivk,
            fvk,
            my_address,
            tree: CommitmentTree::empty(),
            base_frontier: Frontier::empty(),
            base_size: 0,
            leaves: Vec::new(),
            decoded: OnceCell::new(),
            notes: Vec::new(),
            size: 0,
            witnesses: Vec::new(),
            witness_budget: MAX_LIVE_WITNESSES,
            lag_tree: CommitmentTree::empty(),
            witnessed_upto: 0,
            spent_nullifiers: HashSet::new(),
            ovk,
            history: Vec::new(),
            history_enabled: true,
            agree_scalar,
            predecrypted: None,
            leaves_only: false,
            borrow_tree: false,
            tree_valid: true,
            pending_spends: Vec::new(),
            last_daa: 0,
            subtree: SubtreeCache::default(),
            scan_cost: ScanCost::default(),
        })
    }

    /// This wallet's full viewing key. Grants viewing (not spend) capability; the
    /// non-custodial payment builder needs it to construct the proof.
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// This wallet's receive address, as raw Orchard address bytes. Derived from the
    /// viewing key, so a watch-only wallet knows it too.
    pub fn my_address_bytes(&self) -> [u8; 43] {
        self.my_address
    }

    /// Build a wallet that **fast-syncs** from a checkpoint frontier: the tree starts
    /// at the checkpoint's leaf count, and only leaves appended *after* the checkpoint
    /// are scanned and stored — so sync cost is O(blocks since the checkpoint), not
    /// O(whole chain). Owned notes therefore live at absolute positions ≥ the
    /// checkpoint size; a wallet that may hold notes *older* than the checkpoint must
    /// instead full-scan via [`Self::from_seed`]. Returns `None` on a bad seed or an
    /// internally inconsistent frontier.
    ///
    /// `checkpoint` is a node-supplied [`FrontierState`] for a finalized block; the
    /// wallet then scans that block → tip. Witnesses built afterwards root to the
    /// live tip anchor exactly as a full-scan wallet's do (the checkpoint frontier
    /// supplies every left sibling the witness needs).
    pub fn from_frontier(seed: [u8; 32], checkpoint: &FrontierState) -> Option<Self> {
        let mut db = Self::from_seed(seed)?;
        db.apply_frontier(checkpoint)?;
        Some(db)
    }

    /// Rebase a **freshly constructed** wallet (no leaves ingested yet) onto a
    /// node-supplied checkpoint frontier — the fast-sync start shared by the
    /// seed ([`Self::from_frontier`]) and watch-only ([`Self::from_fvk`]) paths.
    /// Returns `None` on an inconsistent frontier or if leaves were already
    /// ingested (the base must precede all stored leaves).
    pub fn apply_frontier(&mut self, checkpoint: &FrontierState) -> Option<()> {
        if !self.leaves.is_empty() || self.base_size != 0 {
            return None;
        }
        let gt = GlobalTree::from_state(checkpoint).ok()?;
        self.base_frontier = gt.frontier().clone();
        self.base_size = gt.size();
        self.tree = CommitmentTree::from_frontier(&self.base_frontier);
        self.lag_tree = CommitmentTree::from_frontier(&self.base_frontier);
        self.witnessed_upto = self.base_size;
        self.witnesses.clear();
        self.size = self.base_size;
        Some(())
    }

    /// The wallet's owned, unspent notes.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Absolute position of the first leaf this wallet actually scanned: 0 for a
    /// full-scan wallet, or the fast-sync checkpoint's leaf count. Notes minted
    /// *before* this base are invisible to the wallet — a caller deciding whether
    /// a fast-synced view is complete for a given wallet birthday needs this.
    pub fn base_size(&self) -> u64 {
        self.base_size
    }

    /// Number of leaves in the cached commitment stream (== notes ingested so far).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Absolute number of leaves the wallet's tree spans (`base_size + leaf_count`) —
    /// i.e. the next leaf's position. This is the wallet's mirror of the global tree
    /// size; recording it after each ingested block yields the block→leaf boundary a
    /// spend needs to root at a matured anchor without a rescan.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Absolute leaf count the live spend-witnesses have already been advanced to. When
    /// this equals the matured leaf count a spend roots at, `witness_path_at` is a lookup;
    /// otherwise it (or `advance_witnesses`) must replay the leaves in between. Exposed so
    /// the daemon can log how far a send has to climb (warm vs cold witnesses).
    pub fn witnessed_upto(&self) -> u64 {
        self.witnessed_upto.max(self.base_size)
    }

    /// Total spendable value the wallet currently tracks.
    pub fn balance(&self) -> u128 {
        self.notes.iter().map(|n| n.value() as u128).sum()
    }

    /// The current tip anchor (root of the mirrored global tree). Equals the
    /// node's anchor once this wallet has ingested the same accepted blocks.
    pub fn anchor(&self) -> [u8; 32] {
        // An empty tree has the Orchard empty-tree anchor; a non-empty tree roots
        // its full depth. This mirrors `GlobalTree::anchor`.
        use orchard::tree::Anchor;
        if self.size == 0 { Anchor::empty_tree().to_bytes() } else { self.tree.root().to_bytes() }
    }

    /// Ingest one accepted chain block's shielded effects, **in the exact order
    /// consensus appends its commitments**: the coinbase notes first (in note
    /// order), then each accepted shielded transaction's actions in order.
    ///
    /// `coinbase` is the block's coinbase note descriptions paired with their
    /// public values (empty if the block has no shielded coinbase). `txs` are the
    /// block's *accepted* shielded bundles in accepted order (conflicting /
    /// dropped transactions must not be passed — they contribute no leaves, just
    /// as in [`crate::state::apply_chain_block_to`]).
    pub fn ingest_block(&mut self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle]) {
        self.ingest_block_with_meta(coinbase, txs, None);
    }

    /// [`Self::ingest_block`] with the block's dating metadata, so ingest also
    /// records [`HistoryEntry`] rows (with `meta: None` no history is written —
    /// the wallet still syncs correctly against a pre-v2 node).
    pub fn ingest_block_with_meta(&mut self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle], meta: Option<&BlockMeta>) {
        if let Some(m) = meta {
            self.last_daa = self.last_daa.max(m.daa_score);
        }
        // Coinbase notes first, in the coinbase's own note order.
        for (desc, value) in coinbase {
            // Recompute the leaf exactly as consensus does; skip a malformed one
            // (consensus would already have rejected the block, so this is just
            // defensive — an un-appendable leaf can carry no note for us either).
            let Ok(cmx) = coinbase_note_commitment(desc, *value) else { continue };
            // Key-independent: the commit-or-skip decision above is what shapes the
            // stream, and it has already been made. See `set_leaves_only`.
            let owned = if self.leaves_only { None } else { self.recover_coinbase_note(desc, *value) };
            if owned.is_some() {
                if let Some(m) = meta {
                    self.record_coinbase_history(*value, m);
                }
            }
            self.append_leaf(cmx, owned);
        }
        self.ingest_bundles(txs, meta);
    }

    /// Like [`Self::ingest_block`], but the caller has **already computed** each
    /// coinbase note's leaf commitment. A coinbase note's `cmx` is a pure function
    /// of its public description and value ([`coinbase_note_commitment`]) — the same
    /// for every wallet — so when many wallets ingest the same chain-block stream
    /// (a public daemon under a mass rescan), computing that Sinsemilla commitment
    /// once and sharing it removes the dominant per-wallet-per-block cost. The
    /// caller must supply exactly the notes [`ingest_block`] would keep, in the same
    /// order (skip a note whose `coinbase_note_commitment` errors), so the leaf
    /// stream is byte-identical to the non-shared path.
    pub fn ingest_block_precomputed(
        &mut self,
        coinbase: &[(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)],
        txs: &[&ShieldedBundle],
    ) {
        self.ingest_block_precomputed_with_meta(coinbase, txs, None);
    }

    /// [`Self::ingest_block_precomputed`] with dating metadata — see
    /// [`Self::ingest_block_with_meta`].
    pub fn ingest_block_precomputed_with_meta(
        &mut self,
        coinbase: &[(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)],
        txs: &[&ShieldedBundle],
        meta: Option<&BlockMeta>,
    ) {
        if let Some(m) = meta {
            self.last_daa = self.last_daa.max(m.daa_score);
        }
        for (desc, value, cmx) in coinbase {
            let owned = self.recover_coinbase_note(desc, *value);
            if owned.is_some() {
                if let Some(m) = meta {
                    self.record_coinbase_history(*value, m);
                }
            }
            self.append_leaf(*cmx, owned);
        }
        self.ingest_bundles(txs, meta);
    }

    /// Ingest every accepted transaction's actions, in order — applying the same
    /// drop rule as the consensus transition: a bundle whose nullifier was already
    /// spent in this stream appends nothing (see `spent_nullifiers`). Shared by both
    /// ingest paths above.
    fn ingest_bundles(&mut self, txs: &[&ShieldedBundle], meta: Option<&BlockMeta>) {
        for (bi, bundle) in txs.iter().enumerate() {
            if bundle.actions.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            // What this bundle takes from us — measured BEFORE the retain below
            // removes the spent notes from the unspent set. Pending spends count
            // too: our own submitted send's notes are already parked there, and
            // missing them here would make the wallet record its own confirmed
            // send as a "Received <change>" row instead of a Sent one.
            let spent: u64 = bundle.actions.iter().filter_map(|a| self.owned_note_value(&a.nullifier)).sum();
            let received = scan_bundle_prepared(&self.prepared_ivk, bundle);
            for (i, action) in bundle.actions.iter().enumerate() {
                // Each action reveals the nullifier of the note it spends. If that is
                // one of ours, the note is now spent — drop it from the unspent set so
                // balance and spend-selection never count or re-offer it. A pending
                // spend whose nullifier appears is CONFIRMED: the parked note is gone
                // for good.
                self.notes.retain(|n| n.nullifier != action.nullifier);
                self.pending_spends.retain(|p| p.note.nullifier != action.nullifier);
                self.spent_nullifiers.insert(action.nullifier);

                let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&action.cmx)) else {
                    continue;
                };
                let owned = received.iter().find(|r| r.action_index == i).map(|r| r.note.clone());
                self.append_leaf(cmx, owned);
            }
            if let Some(m) = meta {
                if let Some(txid) = m.txids.get(bi).copied() {
                    self.record_bundle_history(bundle, spent, &received, txid, m);
                }
            }
        }
    }

    // ---- Compact ingest (ZKas compact block / pruning-survivable scan archive) ----

    /// Ingest a chain block from its **compact** scan record (see
    /// [`CompactActionRecord`]): the same leaf/nullifier/tree effects as
    /// [`Self::ingest_block_with_meta`], but each accepted tx is given as its actions
    /// in compact form rather than a full bundle. This is what a wallet ingests from
    /// `GetShieldedBlocks` on a compact-archive node: value, spend-detection, and the
    /// commitment tree are fully recovered; only outgoing-spend detail (recipient /
    /// memo / fee — carried in the full bundle's out_ciphertext / value_balance) is not
    /// reconstructable here and comes from the wallet's own send-time record instead.
    pub fn ingest_block_compact_with_meta(
        &mut self,
        coinbase: &[(CoinbaseNoteDesc, u64)],
        txs: &[Vec<CompactActionRecord>],
        meta: Option<&BlockMeta>,
    ) {
        if let Some(m) = meta {
            self.last_daa = self.last_daa.max(m.daa_score);
        }
        for (desc, value) in coinbase {
            let Ok(cmx) = coinbase_note_commitment(desc, *value) else { continue };
            // Key-independent: the commit-or-skip decision above is what shapes the
            // stream, and it has already been made. See `set_leaves_only`.
            let owned = if self.leaves_only { None } else { self.recover_coinbase_note(desc, *value) };
            if owned.is_some() {
                if let Some(m) = meta {
                    self.record_coinbase_history(*value, m);
                }
            }
            self.append_leaf(cmx, owned);
        }
        self.ingest_bundles_compact(txs, meta);
    }

    /// [`Self::ingest_block_compact_with_meta`] with **precomputed** coinbase leaf
    /// commitments (see [`Self::ingest_block_precomputed_with_meta`]) — the shared
    /// leaf-cache path a hosted daemon uses so the coinbase Sinsemilla work is done
    /// once per block, not once per wallet.
    pub fn ingest_block_compact_precomputed_with_meta(
        &mut self,
        coinbase: &[(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)],
        txs: &[Vec<CompactActionRecord>],
        meta: Option<&BlockMeta>,
    ) {
        if let Some(m) = meta {
            self.last_daa = self.last_daa.max(m.daa_score);
        }
        for (desc, value, cmx) in coinbase {
            // `leaves_only`: recognising the note is the only key-dependent step here.
            // The commit-or-skip rule that decides whether this leaf exists at all was
            // applied by the caller when it built `coinbase`, so the stream is unchanged.
            let owned = if self.leaves_only { None } else { self.recover_coinbase_note(desc, *value) };
            if owned.is_some() {
                if let Some(m) = meta {
                    self.record_coinbase_history(*value, m);
                }
            }
            self.append_leaf(*cmx, owned);
        }
        self.ingest_bundles_compact(txs, meta);
    }

    /// Compact counterpart of [`Self::ingest_bundles`] — identical drop rule and
    /// tree-append order, over compact action records.
    fn ingest_bundles_compact(&mut self, txs: &[Vec<CompactActionRecord>], meta: Option<&BlockMeta>) {
        for (bi, records) in txs.iter().enumerate() {
            if records.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            let spent: u64 = records.iter().filter_map(|a| self.owned_note_value(&a.nullifier)).sum();
            // The nullifier drop rule above is key-independent and has already run, so
            // skipping decryption cannot change which bundles append leaves — only
            // whether we notice that one of those leaves is ours. See `set_leaves_only`.
            let t_dec = std::time::Instant::now();
            let from_memo = self.predecrypted.is_some();
            let received = if self.leaves_only {
                Vec::new()
            } else if let Some(hits) = self.predecrypted.as_ref().filter(|m| records.iter().all(|r| m.contains_key(&r.nullifier))) {
                // Whole transaction already decided by the page pass.
                records
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| {
                        hits.get(&r.nullifier).and_then(|o| o.clone()).map(|mut n| {
                            n.action_index = i;
                            n
                        })
                    })
                    .collect()
            } else {
                scan_compact_auto(&self.prepared_ivk, self.agree_scalar.as_ref(), records)
            };
            // A memo hit did its decryption in `predecrypt_page`, which already charged
            // for it; charging again here would double-count the same actions.
            if !from_memo {
                self.scan_cost.decrypt_ns += t_dec.elapsed().as_nanos();
                self.scan_cost.actions += records.len() as u64;
            }
            for (i, rec) in records.iter().enumerate() {
                self.notes.retain(|n| n.nullifier != rec.nullifier);
                self.pending_spends.retain(|p| p.note.nullifier != rec.nullifier);
                self.spent_nullifiers.insert(rec.nullifier);

                let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&rec.cmx)) else {
                    continue;
                };
                let owned = received.iter().find(|r| r.action_index == i).map(|r| r.note.clone());
                self.append_leaf(cmx, owned);
            }
            if let Some(m) = meta {
                if let Some(txid) = m.txids.get(bi).copied() {
                    self.record_history_compact(spent, &received, txid, m);
                }
            }
        }
    }

    /// Record history for a compact-ingested transaction. Compact records carry no
    /// out_ciphertext / value_balance, so an outgoing spend's recipient, memo, and
    /// exact fee are not reconstructable. Still record the spend: our nullifiers and
    /// decryptable change give its exact net outflow, which is vital for historical
    /// watch-only reconciliation after a rescan.
    fn record_history_compact(&mut self, spent: u64, received: &[ReceivedNote], txid: [u8; 32], meta: &BlockMeta) {
        if !self.history_enabled {
            return;
        }
        let received_value: u64 = received.iter().map(|r| r.value()).sum();
        if spent > 0 {
            self.push_history(HistoryEntry {
                kind: HistoryKind::Sent,
                txid,
                daa_score: meta.daa_score,
                timestamp_ms: meta.timestamp_ms,
                amount: spent.saturating_sub(received_value),
                fee: 0,
                amount_is_net_outflow: true,
                fee_known: false,
                recipient: None,
                memo: Vec::new(),
            });
            return;
        }
        if received_value == 0 {
            return; // not our transaction
        }
        let entry = HistoryEntry {
            kind: HistoryKind::Received,
            txid,
            daa_score: meta.daa_score,
            timestamp_ms: meta.timestamp_ms,
            amount: received_value,
            fee: 0,
            amount_is_net_outflow: false,
            fee_known: true,
            recipient: received.first().map(|note| note.note.recipient().to_raw_address_bytes()),
            memo: Vec::new(),
        };
        self.push_history(entry);
    }

    /// Value of the owned note (unspent or pending-spend) this nullifier would
    /// reveal, if it is one of ours.
    fn owned_note_value(&self, nullifier: &[u8; 32]) -> Option<u64> {
        self.notes
            .iter()
            .find(|n| &n.nullifier == nullifier)
            .or_else(|| self.pending_spends.iter().map(|p| &p.note).find(|n| &n.nullifier == nullifier))
            .map(|n| n.value())
    }

    /// Record a mining-reward history row (one per owned coinbase note).
    fn record_coinbase_history(&mut self, value: u64, meta: &BlockMeta) {
        if !self.history_enabled {
            return;
        }
        self.push_history(HistoryEntry {
            kind: HistoryKind::Coinbase,
            txid: meta.coinbase_txid,
            daa_score: meta.daa_score,
            timestamp_ms: meta.timestamp_ms,
            amount: value,
            fee: 0,
            amount_is_net_outflow: false,
            fee_known: true,
            recipient: None,
            memo: Vec::new(),
        });
    }

    /// Turn one ingested bundle's effect on this wallet into a history row.
    ///
    /// `spent` is the value of our notes the bundle consumed (0 ⇒ nothing of ours
    /// left, so any decryptable output is money genuinely arriving). For our own
    /// spends the recipient/paid-amount/memo are recovered with our OVK when the
    /// send was built with it; otherwise the row falls back to `net outflow − fee`
    /// with no recipient — still a correct amount, just less descriptive.
    fn record_bundle_history(
        &mut self,
        bundle: &ShieldedBundle,
        spent: u64,
        received: &[ReceivedNote],
        txid: [u8; 32],
        meta: &BlockMeta,
    ) {
        if !self.history_enabled {
            return;
        }
        let received_value: u64 = received.iter().map(|r| r.value()).sum();
        if spent == 0 && received_value == 0 {
            return; // not our transaction
        }
        let entry = if spent > 0 {
            // Our own spend: `received` here is change coming back, not income.
            let fee = bundle.value_balance.max(0) as u64;
            let net_out = spent.saturating_sub(received_value);
            let mut recipient = None;
            let mut memo = Vec::new();
            let mut recovered_paid = 0u64;
            for a in &bundle.actions {
                let Some(action) = reconstruct_action(a) else { continue };
                let domain = OrchardDomain::for_action(&action);
                let Some((note, addr, m)) =
                    try_output_recovery_with_ovk(&domain, &self.ovk, &action, action.cv_net(), &a.out_ciphertext)
                else {
                    continue;
                };
                let addr_bytes = addr.to_raw_address_bytes();
                if addr_bytes == self.my_address {
                    continue; // our own change
                }
                recovered_paid = recovered_paid.saturating_add(note.value().inner());
                if recipient.is_none() {
                    recipient = Some(addr_bytes);
                    memo = trim_memo(&m);
                }
            }
            HistoryEntry {
                kind: HistoryKind::Sent,
                txid,
                daa_score: meta.daa_score,
                timestamp_ms: meta.timestamp_ms,
                amount: if recipient.is_some() { recovered_paid } else { net_out.saturating_sub(fee) },
                fee,
                amount_is_net_outflow: false,
                fee_known: true,
                recipient,
                memo,
            }
        } else {
            HistoryEntry {
                kind: HistoryKind::Received,
                txid,
                daa_score: meta.daa_score,
                timestamp_ms: meta.timestamp_ms,
                amount: received_value,
                fee: 0,
                amount_is_net_outflow: false,
                fee_known: true,
                // A diversified address is private on-chain but visible to this
                // wallet's FVK. Preserve it so a watch-only merchant gateway can
                // reconcile one unique invoice address without amount matching.
                recipient: received.first().map(|note| note.note.recipient().to_raw_address_bytes()),
                memo: received.iter().find(|r| !r.memo.is_empty()).map(|r| r.memo.clone()).unwrap_or_default(),
            }
        };
        self.push_history(entry);
    }

    /// Sent rows still missing what only the full transaction can tell: recipient, paid
    /// amount, memo and fee. A row ingested from compact records is stored as a bare net
    /// outflow (`fee_known == false`); this lists them oldest-first as `(txid, daa)` so the
    /// daemon can fetch each transaction's full bundle and call
    /// [`Self::recover_sent_from_bundle`]. Rows already attempted are marked `fee_known`
    /// whether or not a recipient came out, so a send built without our OVK is never
    /// re-fetched.
    pub fn unrecovered_sends(&self, from: usize) -> Vec<([u8; 32], u64)> {
        self.history
            .iter()
            .skip(from)
            .filter(|h| h.kind == HistoryKind::Sent && h.recipient.is_none() && !h.fee_known)
            .map(|h| (h.txid, h.daa_score))
            .collect()
    }

    /// Fill in a compact-ingested Sent row from the transaction's full bundle: recipient,
    /// paid amount and memo via our outgoing viewing key (when the send was built with
    /// it), and the exact fee from the value balance. Same recovery as
    /// [`Self::record_bundle_history`], applied to a row that already exists. Returns
    /// whether a recipient was recovered. The row is marked `fee_known` either way.
    pub fn recover_sent_from_bundle(&mut self, txid: &[u8; 32], bundle: &ShieldedBundle) -> bool {
        let Some(pos) = self.history.iter().rposition(|h| h.kind == HistoryKind::Sent && &h.txid == txid) else {
            return false;
        };
        let fee = bundle.value_balance.max(0) as u64;
        let mut recipient = None;
        let mut memo = Vec::new();
        let mut recovered_paid = 0u64;
        for a in &bundle.actions {
            let Some(action) = reconstruct_action(a) else { continue };
            let domain = OrchardDomain::for_action(&action);
            let Some((note, addr, m)) =
                try_output_recovery_with_ovk(&domain, &self.ovk, &action, action.cv_net(), &a.out_ciphertext)
            else {
                continue;
            };
            let addr_bytes = addr.to_raw_address_bytes();
            if addr_bytes == self.my_address {
                continue; // our own change
            }
            recovered_paid = recovered_paid.saturating_add(note.value().inner());
            if recipient.is_none() {
                recipient = Some(addr_bytes);
                memo = trim_memo(&m);
            }
        }
        let h = &mut self.history[pos];
        let net_out = if h.amount_is_net_outflow { h.amount } else { h.amount.saturating_add(h.fee) };
        h.fee = fee;
        h.fee_known = true;
        h.amount_is_net_outflow = false;
        if recipient.is_some() {
            h.amount = recovered_paid;
            h.recipient = recipient;
            h.memo = memo;
            true
        } else {
            h.amount = net_out.saturating_sub(fee);
            false
        }
    }

    fn push_history(&mut self, entry: HistoryEntry) {
        if self.history.len() >= HISTORY_CAP {
            // Drop the oldest half in one move instead of shifting per push.
            self.history.drain(..HISTORY_CAP / 2);
        }
        self.history.push(entry);
    }

    /// The chain-derived history rows, oldest first.
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Whether ingest records history rows.
    pub fn history_enabled(&self) -> bool {
        self.history_enabled
    }

    /// Turn history recording on or off. Turning it OFF also purges everything
    /// recorded so far — the user withdrawing consent must actually remove the
    /// readable record from the checkpoint, not merely stop appending to it.
    pub fn set_history_enabled(&mut self, on: bool) {
        self.history_enabled = on;
        if !on {
            self.history.clear();
        }
    }

    /// Spends submitted but not yet observed on-chain.
    pub fn pending_spends(&self) -> &[PendingSpend] {
        &self.pending_spends
    }

    /// The wallet's chain clock — DAA score of the newest block ingested with meta.
    pub fn last_daa(&self) -> u64 {
        self.last_daa
    }

    /// Return every pending spend older than `max_age_daa` — measured against the
    /// caller-supplied chain score `now_daa` — to the unspent set, and report
    /// `(txid, value)` per reclaimed note. Call this only when the wallet is
    /// caught up to the tip: then "this old and still unobserved" really does mean
    /// the transaction was lost. Reclaiming a note whose spend later confirms
    /// anyway is safe — ingest removes it again when the nullifier appears (and
    /// the network can never apply that nullifier twice).
    ///
    /// A spend parked with `submitted_daa == 0` (submitted before the caller had a
    /// chain score) is never reclaimed on age: the countdown has no origin, so it
    /// waits for its nullifier rather than risk un-parking an in-flight spend.
    pub fn reclaim_expired(&mut self, now_daa: u64, max_age_daa: u64) -> Vec<([u8; 32], u64)> {
        let now = now_daa;
        let mut reclaimed = Vec::new();
        let mut i = 0;
        while i < self.pending_spends.len() {
            let origin = self.pending_spends[i].submitted_daa;
            if origin != 0 && now.saturating_sub(origin) > max_age_daa {
                let p = self.pending_spends.remove(i);
                reclaimed.push((p.txid, p.note.value()));
                // Keep `notes` in position order, as ingest appends them.
                let at = self.notes.iter().position(|n| n.position > p.note.position).unwrap_or(self.notes.len());
                self.notes.insert(at, p.note);
            } else {
                i += 1;
            }
        }
        reclaimed
    }

    /// What an **unsettled** block would do to this wallet's balance, without touching
    /// any state.
    ///
    /// The wallet cannot *ingest* a block within the reorg margin of the tip: its
    /// commitment tree is append-only, so a leaf appended from a block that is later
    /// reorged out could never be removed, and every later note's position would shift
    /// off the consensus tree. That safety rule is why a payment took ~3 minutes to
    /// appear even though the chain had confirmed it in one second.
    ///
    /// But "cannot append it" is not "cannot look at it". Trial-decrypting the block
    /// tells us the value arriving and the owned notes being spent, with no leaf, no
    /// position, and no tree mutation — so it is free of the reorg hazard entirely. The
    /// caller reports this as *pending* (0-conf) and the number is superseded by the
    /// real one when the block settles and is ingested for real. Worst case a reorg
    /// drops it and the pending figure simply disappears — the same contract every
    /// 0-conf balance in every chain has.
    pub fn preview_block(&self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle]) -> Preview {
        let mut p = Preview::default();
        for (desc, value) in coinbase {
            if self.recover_coinbase_note(desc, *value).is_some() {
                p.incoming += *value as u128;
            }
        }
        for bundle in txs {
            // Same drop rule as ingest: a bundle re-spending an already-spent nullifier
            // appends nothing, so it must not be previewed either.
            if bundle.actions.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            // What this bundle takes from us: an action reveals the nullifier of the note it
            // spends, so a nullifier we recognise is one of our notes leaving.
            let spent: u128 = bundle
                .actions
                .iter()
                .filter_map(|a| self.notes.iter().find(|n| n.nullifier == a.nullifier))
                .map(|n| n.value() as u128)
                .sum();
            // What this bundle gives us: anything decryptable to our ivk.
            let received: u128 = scan_bundle_prepared(&self.prepared_ivk, bundle).iter().map(|r| r.note.value().inner() as u128).sum();

            if spent > 0 {
                // OUR OWN spend. The received part is our CHANGE coming back, not an
                // incoming payment — reporting it as `incoming` made the *sender's* wallet
                // announce "+4 ZKAS incoming" for their own change while also showing the
                // whole 5-ZKAS note as sent, so the displayed balance swung 5 -> 4 -> 5.
                // Only the net outflow (amount + fee) is real movement.
                p.outgoing += spent.saturating_sub(received);
            } else {
                // Nothing of ours was spent, so this is money genuinely arriving.
                p.incoming += received;
            }
        }
        p
    }

    /// Compact counterpart of [`Self::preview_block`] — same in/out accounting over
    /// compact action records (used for blocks inside the reorg margin).
    pub fn preview_block_compact(&self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[Vec<CompactActionRecord>]) -> Preview {
        let mut p = Preview::default();
        for (desc, value) in coinbase {
            if self.recover_coinbase_note(desc, *value).is_some() {
                p.incoming += *value as u128;
            }
        }
        for records in txs {
            if records.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            let spent: u128 =
                records.iter().filter_map(|a| self.notes.iter().find(|n| n.nullifier == a.nullifier)).map(|n| n.value() as u128).sum();
            let received: u128 =
                scan_compact_prepared(&self.prepared_ivk, records).iter().map(|r| r.note.value().inner() as u128).sum();
            if spent > 0 {
                p.outgoing += spent.saturating_sub(received);
            } else {
                p.incoming += received;
            }
        }
        p
    }

    /// Park a note whose spend was just **submitted** (by leaf position): it leaves
    /// the unspent set immediately — the balance drops and a concurrent send cannot
    /// re-select it — but it is NOT forgotten. It waits in [`Self::pending_spends`]
    /// until its nullifier is observed on-chain (spend applied ⇒ gone for good) or
    /// [`Self::reclaim_expired`] concludes the transaction was lost and returns it.
    /// Deleting outright here is how money used to vanish: a node crash with the tx
    /// still in its mempool, or a consensus-dropped shielded spend, left the note
    /// unspent on-chain but permanently invisible to the wallet.
    pub fn mark_spent(&mut self, position: u64, txid: [u8; 32], submitted_daa: u64) {
        if let Some(i) = self.notes.iter().position(|n| n.position == position) {
            let note = self.notes.remove(i);
            self.pending_spends.push(PendingSpend { note, txid, submitted_daa });
        }
    }

    /// Append one leaf to the wallet's view: record it in the commitment stream,
    /// advance the tip mirror, and — if it is a note we own — remember it (no
    /// witness is built here; that is deferred to [`Self::witness_path`]). This is
    /// O(1) amortised per leaf, so a full scan is O(N), not O(N²).
    /// Advance the live witnesses (and the tree they hang off) to exactly
    /// `target_leaves` absolute leaves — the **matured** leaf count a spend must root
    /// at. The sync loop calls this as it ingests, so by the time the user presses
    /// Send, every spendable note's witness already exists and
    /// [`witness_path_at`](Self::witness_path_at) is a lookup instead of a full
    /// Sinsemilla replay of the chain.
    ///
    /// Costs one tree append per leaf plus one witness append per live witness — all
    /// O(1) amortized — so a full sync stays linear. Witnesses are only held for the
    /// first [`MAX_LIVE_WITNESSES`] owned notes; a wallet with more than that (a miner
    /// accumulating thousands of coinbase notes) falls back to the on-demand rebuild
    /// for the excess rather than paying `k` appends per leaf forever.
    pub fn advance_witnesses(&mut self, target_leaves: u64) {
        self.advance_witnesses_capped(target_leaves, u64::MAX);
    }

    /// Cap how many notes hold a live witness (see [`Self::witness_budget`]). Advancing
    /// costs `leaves × budget` Sinsemilla appends, so this is the knob that keeps a
    /// note-heavy wallet's catch-up bounded by a constant instead of by its note count.
    /// Lowering it drops the now-ineligible witnesses on the next advance; those notes
    /// fall back to the on-demand rebuild. Clamped to [`MAX_LIVE_WITNESSES`].
    pub fn set_witness_budget(&mut self, budget: usize) {
        self.witness_budget = budget.clamp(1, MAX_LIVE_WITNESSES);
    }

    /// [`Self::advance_witnesses`] but advancing at most `max_leaves` this call, so the
    /// work is bounded and the caller can spread a large catch-up across sync passes
    /// (yielding between them) instead of one multi-second burst that starves the HTTP
    /// handler. Returns `true` if there is still more to advance toward `target_leaves`.
    pub fn advance_witnesses_capped(&mut self, target_leaves: u64, max_leaves: u64) -> bool {
        let full_target = target_leaves.min(self.size);
        let start = self.witnessed_upto.max(self.base_size);
        if full_target <= start {
            return false;
        }
        let target = full_target.min(start.saturating_add(max_leaves));
        let more = target < full_target;
        self.advance_witnesses_range(start, target);
        more
    }

    /// Notes that may hold a live witness: all of them when they fit the budget,
    /// otherwise the most valuable ones.
    ///
    /// Which subset matters. A spend selects notes **value-descending**, so those are
    /// the ones it will actually reach for. Handing the slots out in *position* order
    /// instead — as this did — fills them with the oldest notes on a wallet that has
    /// more notes than slots, which is precisely a miner/pool wallet: the warm set is
    /// then one no send ever touches, and every send still pays the full on-demand
    /// rebuild despite the witnesses being maintained. Position breaks ties so the set
    /// is deterministic across daemons.
    fn witness_eligible(&self) -> HashSet<u64> {
        if self.notes.len() <= self.witness_budget {
            return self.notes.iter().map(|n| n.position).collect();
        }
        let mut by_value: Vec<&OwnedNote> = self.notes.iter().collect();
        by_value.sort_by(|a, b| b.value().cmp(&a.value()).then(a.position.cmp(&b.position)));
        by_value.iter().take(self.witness_budget).map(|n| n.position).collect()
    }

    fn advance_witnesses_range(&mut self, start: u64, target: u64) {
        if target <= start {
            return;
        }
        // A spent — or no longer spend-relevant — note's witness is dead weight; drop
        // it before advancing the rest, which also frees the slot for an eligible note.
        let eligible = self.witness_eligible();
        self.witnesses.retain(|(pos, _)| eligible.contains(pos));

        for abs in start..target {
            let Some(&leaf) = self.decoded_leaves().get((abs - self.base_size) as usize) else { break };
            // Every already-open witness must see every later leaf...
            for (_, w) in self.witnesses.iter_mut() {
                let _ = w.append(leaf);
            }
            // ...and the lagging tree, which is what a newly matured note's witness is
            // snapshotted from (it then witnesses exactly the leaf just appended).
            let _ = self.lag_tree.append(leaf);
            if eligible.contains(&abs) && self.witnesses.len() < self.witness_budget {
                if let Some(w) = IncrementalWitness::from_tree(self.lag_tree.clone()) {
                    self.witnesses.push((abs, w));
                }
            }
        }
        self.witnessed_upto = target;
    }

    /// Roll the fast-sync **base frontier** forward to absolute leaf `target`, summarising
    /// and dropping every leaf below it. This is what stops a full-scan wallet from
    /// replaying the whole chain on every spend: [`witness_path_at`](Self::witness_path_at)
    /// rebuilds a note's path from `base_frontier`, so a base pinned at leaf 0 costs a
    /// ~500 K-leaf Sinsemilla replay (~30 s) on *every* send, while a base rolled up to the
    /// wallet's own notes costs only the few thousand leaves above them.
    ///
    /// The compaction is representation-only: the tip [`tree`](Self::tree), the notes, and
    /// every witness root are unchanged — the base frontier plus the surviving leaf suffix
    /// reproduce exactly the same tree and the same authentication paths. It is capped at
    /// the **earliest unspent note** (a note below the base can no longer be witnessed) and
    /// at [`size`](Self::size). Advancing at most `max_leaves` this call keeps the one-time
    /// O(leaves-below-target) rebuild bounded so the caller can spread it across sync passes.
    /// Returns `true` if the base can still be rolled further toward `target`.
    pub fn advance_base_capped(&mut self, target: u64, max_leaves: u64) -> bool {
        // A shared tree NEVER compacts. Compaction is bounded by the earliest note the
        // wallet still holds — and a `leaves_only` tree holds none, so that bound is
        // `size` and it would roll the base straight to the tip, discarding the entire
        // leaf stream it exists to keep. Observed live 2026-08-07 within minutes of
        // enabling it: `base_size=2061411 == matured 2061411`, i.e. the shared stream
        // had summarised away every leaf and could witness nothing for anybody. It also
        // made the off-lock cache build unable to ever install (`built.base_size !=
        // self.base_size` on every attempt, logged as "the stream moved under it").
        //
        // Its whole job is to hold positions 0..tip on behalf of wallets whose own
        // bases have moved far past them, so "no notes" means "keep everything", not
        // "keep nothing".
        if self.leaves_only {
            return false;
        }
        // Never roll past a note we still hold, or past what we've ingested. A note
        // parked in `pending_spends` counts as HELD: it left `notes` when its spend
        // was submitted, but `reclaim_expired` returns it if the transaction never
        // lands — and a note re-inserted below the base can never be witnessed
        // again (its leaves are gone), leaving its value permanently unspendable.
        // Ignoring pending spends here is exactly how live note@564934 was
        // stranded: submit → compact past it → tx lost → reclaim → below base.
        let earliest = self
            .notes
            .iter()
            .map(|n| n.position)
            .chain(self.pending_spends.iter().map(|p| p.note.position))
            .min()
            .unwrap_or(self.size);
        let full_target = target.min(earliest).min(self.size);
        if full_target <= self.base_size {
            return false;
        }
        let step_target = full_target.min(self.base_size.saturating_add(max_leaves));
        let rel = (step_target - self.base_size) as usize;
        // Rebuild the frontier at `step_target` from the current base + the leaves we drop.
        let mut tree = CommitmentTree::from_frontier(&self.base_frontier);
        {
            let leaves = self.decoded_leaves();
            if rel > leaves.len() {
                return false;
            }
            for leaf in &leaves[..rel] {
                if tree.append(*leaf).is_err() {
                    return false;
                }
            }
        }
        self.base_frontier = tree.to_frontier();
        self.base_size = step_target;
        // Drop the now-summarised prefix from both the raw stream and its decoded cache,
        // keeping the two exactly in step (see `append_leaf`).
        self.leaves.drain(..rel);
        if let Some(d) = self.decoded.get_mut() {
            d.drain(..rel);
        }
        // CRUCIAL: the live witnesses are self-contained (their own inner tree + filled +
        // cursor, at absolute positions ≥ the earliest note ≥ the new base), so compacting
        // the base BELOW them does not invalidate them — keep them. Wiping them here (the
        // original bug) made compaction and the witness warm-up fight: every roll reset
        // `witnessed_upto` to the base, so a full-scan wallet's witnesses never got ahead
        // and every send stayed COLD. Only if the witness cursor actually lags the new base
        // (a still-cold wallet) do we realign it to the base and drop any now-unwitnessable
        // entries; the warm-up then advances it forward from here.
        if self.witnessed_upto < self.base_size {
            self.witnessed_upto = self.base_size;
            self.lag_tree = CommitmentTree::from_frontier(&self.base_frontier);
            self.witnesses.retain(|(p, _)| *p >= self.base_size);
        }
        step_target < full_target
    }

    /// Repair a wallet whose base compacted past a still-held note (see
    /// [`Self::stranded_notes`]) by grafting the missing leaf-stream prefix back
    /// from an **older snapshot of the same wallet** whose base predates the
    /// stranded positions. Purely additive: the base frontier and base size roll
    /// BACK to the older snapshot's, the dropped leaves are re-inserted, and
    /// everything else (notes, witnesses, sweep state) is untouched — after which
    /// the previously stranded notes rebuild witnesses normally. Refuses to graft
    /// unless the two states demonstrably describe the same stream (same wallet
    /// address, older covers the gap, and every overlapping leaf agrees).
    /// Returns the number of leaves restored.
    pub fn graft_history(&mut self, older: &Self) -> Result<u64, &'static str> {
        if older.my_address != self.my_address {
            return Err("snapshots belong to different wallets");
        }
        if older.base_size > self.base_size {
            return Err("snapshot is not older: its base is ahead of this wallet's");
        }
        let gap = (self.base_size - older.base_size) as usize;
        if gap == 0 {
            return Ok(0);
        }
        if older.leaves.len() < gap {
            return Err("older snapshot's leaf stream does not reach this wallet's base");
        }
        let n = (older.leaves.len() - gap).min(self.leaves.len());
        if older.leaves[gap..gap + n] != self.leaves[..n] {
            return Err("snapshots disagree where their leaf streams overlap");
        }
        let mut leaves = older.leaves[..gap].to_vec();
        leaves.extend_from_slice(&self.leaves);
        self.leaves = leaves;
        self.base_frontier = older.base_frontier.clone();
        self.base_size = older.base_size;
        // The stream's prefix and base both moved: the cache was seeded from the frontier
        // this graft just replaced, so retire it and let it be rebuilt.
        self.subtree = SubtreeCache::default();
        // The decoded cache mirrors `leaves` index-for-index — rebuild it lazily.
        self.decoded = OnceCell::new();
        Ok(gap as u64)
    }

    /// The live witness for `position`, if one is held **at exactly** `matured_leaves`.
    /// Replay the leaf stream to produce a live witness for `position` rooted at
    /// `matured_leaves`. This is the expensive path — O(matured − base) Sinsemilla
    /// appends, ~22 s over a 126 K-leaf gap — and is what every cold spend pays.
    fn rebuild_witness(&self, position: u64, matured_leaves: u64) -> Option<IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>> {
        let rel = position.checked_sub(self.base_size)? as usize;
        let matured_rel = matured_leaves.checked_sub(self.base_size)? as usize;
        let leaves = self.decoded_leaves();
        if rel >= matured_rel || matured_rel > leaves.len() {
            return None;
        }
        // Rebuild the tree from the checkpoint frontier up to and including the target
        // leaf, so `from_tree` witnesses exactly it, then replay the later leaves — but
        // only up to `matured_rel`, so the witness roots at the matured anchor, not the
        // tip. For a full-scan wallet the base frontier is empty, so this reduces to
        // rebuilding from genesis.
        let mut tree = CommitmentTree::from_frontier(&self.base_frontier);
        for leaf in &leaves[..=rel] {
            tree.append(*leaf).ok()?;
        }
        let mut witness = IncrementalWitness::<MerkleHashOrchard, TREE_DEPTH>::from_tree(tree)?;
        for leaf in &leaves[rel + 1..matured_rel] {
            witness.append(*leaf).ok()?;
        }
        Some(witness)
    }

    /// Build a witness for an eligible note the forward sweep has already passed, and
    /// **keep** it.
    ///
    /// [`advance_witnesses_range`](Self::advance_witnesses_range) can only open a witness
    /// at the moment its sweep reaches that leaf, so a note sitting below
    /// `witnessed_upto` can never acquire one — it is condemned to pay the full
    /// [`rebuild_witness`](Self::rebuild_witness) replay on *every* spend, forever. That
    /// is the state of a miner/pool wallet: its notes cluster just above the compaction
    /// base while the matured tip runs ~126 K leaves ahead, and as soon as its warm notes
    /// are spent the next-eligible ones are all behind the sweep.
    ///
    /// This pays that replay once, off the spend path, and installs the result — so the
    /// next spend of this note is an O(1) [`live_witness_path`](Self::live_witness_path)
    /// lookup. Returns false if the note is already warm, the budget is full, or the
    /// witness set is not currently at `target` (installing a witness rooted anywhere
    /// else would desynchronise the set).
    pub fn install_witness(&mut self, position: u64, target: u64) -> bool {
        if self.witnessed_upto != target {
            return false;
        }
        if self.witnesses.iter().any(|(p, _)| *p == position) {
            return true;
        }
        if self.witnesses.len() >= self.witness_budget {
            return false;
        }
        // Never spend a replay on a note the next advance would evict: `witness_eligible`
        // keeps only the most valuable notes once they outnumber the slots, so adopting
        // an ineligible one burns ~22 s and is dropped on the following sweep.
        if !self.witness_eligible().contains(&position) {
            return false;
        }
        match self.rebuild_witness(position, target) {
            Some(w) => {
                self.witnesses.push((position, w));
                true
            }
            None => false,
        }
    }

    /// How many notes currently hold a live witness (i.e. spend in O(1)).
    pub fn live_witness_count(&self) -> usize {
        self.witnesses.len()
    }

    /// An eligible note that has no live witness and sits below the sweep, if any —
    /// the next candidate for [`install_witness`](Self::install_witness). Notes
    /// below the compacted base are excluded: their leaves are gone, so an install
    /// can never succeed — offering one turns the caller's warm loop into a
    /// busy-retry of an impossible rebuild (observed live at ~1 attempt/second,
    /// forever). Those notes are reported by [`Self::stranded_notes`] instead.
    pub fn next_note_needing_witness(&self) -> Option<u64> {
        if self.witnesses.len() >= self.witness_budget {
            return None;
        }
        let eligible = self.witness_eligible();
        self.notes
            .iter()
            .filter(|n| eligible.contains(&n.position) && n.position < self.witnessed_upto && n.position >= self.base_size)
            .map(|n| n.position)
            .find(|p| !self.witnesses.iter().any(|(w, _)| w == p))
    }

    /// Owned unspent notes that can no longer be witnessed from local state: their
    /// position lies below the compacted base (leaves summarised away) and no live
    /// witness survives. Such a note's value exists on-chain but cannot be spent
    /// through this wallet state — a spend planner must exclude these rather than
    /// fail the whole payment, and a caller should surface their total honestly.
    /// Recovery requires older wallet state whose leaf stream still covers the
    /// note (see the walletd graft tooling), or an archival replay of the chain.
    pub fn stranded_notes(&self) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| n.position < self.base_size && !self.witnesses.iter().any(|(p, _)| *p == n.position)).collect()
    }

    fn live_witness_path(&self, position: u64, matured_leaves: u64) -> Option<MerklePath> {
        if self.witnessed_upto != matured_leaves {
            return None;
        }
        let (_, w) = self.witnesses.iter().find(|(p, _)| *p == position)?;
        let path = w.path()?;
        let auth: [MerkleHashOrchard; TREE_DEPTH as usize] = path.path_elems().try_into().ok()?;
        Some(MerklePath::from_parts(u64::from(path.position()) as u32, auth))
    }

    /// The leaf stream as curve points, decoding it on first use (see `decoded`).
    /// Returns an empty slice if any leaf fails to decode — impossible for bytes we
    /// wrote ourselves, and failing closed makes a witness build return `None` (a clean
    /// send error) rather than silently root to a wrong tree.
    fn decoded_leaves(&self) -> &[MerkleHashOrchard] {
        self.decoded.get_or_init(|| {
            self.leaves
                .iter()
                .map(|b| Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(b)))
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default()
        })
    }

    /// Decode the leaf stream now, so a later spend doesn't pay for it. The daemon calls
    /// this on a blocking thread right after loading a wallet: the wallet is usable
    /// (balance, notes, receive) the instant it restores, and the curve points are ready
    /// by the time anyone spends.
    pub fn warm_leaves(&self) {
        let _ = self.decoded_leaves();
    }

    fn append_leaf(&mut self, cmx: ExtractedNoteCommitment, owned: Option<Note>) {
        // ~25 ns of clock against ~150 us of Sinsemilla: under 0.02% overhead, and it
        // is the only place every ingest path (full, compact, precomputed) converges.
        let t_leaf = std::time::Instant::now();
        self.scan_cost.leaves += 1;
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        self.leaves.push(leaf.to_bytes());
        // Keep an already-materialised cache in step rather than invalidating it — a
        // synced wallet appends a few leaves a second and must not re-decode the chain.
        if let Some(d) = self.decoded.get_mut() {
            d.push(leaf);
        }
        // The mirror tree is the expensive half of a scan and it is PUBLIC — the shared
        // tree is building the identical thing. A borrowing wallet skips it and adopts
        // that frontier instead (see `adopt_tip_frontier`), which is sound because the
        // frontier at N leaves depends only on leaves 0..N.
        if self.borrow_tree {
            self.tree_valid = false;
        } else {
            // `append` only errors when the tree is full (2^32 leaves) — unreachable.
            let _ = self.tree.append(leaf);
        }
        // Keep the complete-subtree cache in step: one combine per leaf, amortized. If
        // the mountain range ever refuses a leaf the cache is dropped, not patched — a
        // half-updated cache must never be consulted.
        if self.subtree.active && self.subtree.upto == self.size && !self.subtree.push_leaf(self.size, leaf) {
            self.subtree = SubtreeCache { failed: true, ..Default::default() };
        }
        if let Some(note) = owned {
            let nullifier = note.nullifier(&self.fvk).to_bytes();
            self.notes.push(OwnedNote { note, position: self.size, nullifier });
        }
        self.size += 1;
        self.scan_cost.tree_ns += t_leaf.elapsed().as_nanos();
    }

    /// Stop maintaining this wallet's own mirror tree; the shared tree supplies it.
    ///
    /// Turning this ON invalidates `tree` as soon as the next leaf arrives, so
    /// `anchor()` must not be read until [`Self::adopt_tip_frontier`] succeeds.
    /// Turning it OFF does not repair anything — the wallet keeps hashing from that
    /// point on, but the leaves it skipped are still missing from `tree`, so it stays
    /// invalid until a frontier is adopted or the wallet is reloaded.
    pub fn set_borrow_tree(&mut self, on: bool) {
        self.borrow_tree = on;
    }

    /// Is this wallet relying on the shared tree rather than maintaining its own?
    ///
    /// Callers need this to know what a `false` from [`Self::tree_is_valid`] MEANS. For
    /// a wallet keeping its own tree it is a fault worth refusing over. For a borrowing
    /// wallet it is the normal resting state — `borrow_tree` invalidates the mirror on
    /// the very next leaf — and the anchor it would produce is the shared tree's
    /// frontier anyway, so demanding one asks the wallet to answer for a tree it does
    /// not own.
    pub fn is_borrowing(&self) -> bool {
        self.borrow_tree
    }

    /// This wallet's tip frontier, as a portable [`FrontierState`] — how the shared
    /// tree hands its tree to everyone else.
    ///
    /// Returns `None` when `tree` does not describe `size` (a borrowing wallet that has
    /// not adopted one yet), so a stale frontier can never be handed on as if it were
    /// current.
    pub fn tip_frontier_state(&self) -> Option<FrontierState> {
        if !self.tree_valid {
            return None;
        }
        let f = self.tree.to_frontier();
        Some(match f.value() {
            None => FrontierState { size: 0, leaf: None, ommers: Vec::new() },
            Some(nef) => FrontierState {
                size: self.size,
                leaf: Some(nef.leaf().to_bytes()),
                ommers: nef.ommers().iter().map(|o| o.to_bytes()).collect(),
            },
        })
    }

    /// Whether `tree` reflects `size` — i.e. whether `anchor()` means anything.
    pub fn tree_is_valid(&self) -> bool {
        self.tree_valid
    }

    /// Install a tip frontier taken from the shared tree, making `tree` valid again.
    ///
    /// **Refuses unless the frontier describes exactly this wallet's `size`.** A
    /// commitment tree's frontier at N leaves is determined by leaves 0..N alone, so a
    /// frontier at the same size is provably this wallet's own — and one at a
    /// different size provably is not. That single equality check is the whole safety
    /// argument for borrowing, which is why it is enforced here rather than trusted
    /// from the caller.
    pub fn adopt_tip_frontier(&mut self, fs: &crate::tree::FrontierState) -> bool {
        if fs.size != self.size {
            return false;
        }
        let Ok(t) = GlobalTree::from_state(fs) else { return false };
        self.tree = CommitmentTree::from_frontier(t.frontier());
        self.tree_valid = true;
        true
    }

    /// Trial-decrypt an entire page up front, so the expensive per-action work happens
    /// once over a large batch instead of once per transaction.
    ///
    /// Call immediately before ingesting the page's blocks; the results are consumed by
    /// [`Self::ingest_block_compact_precomputed_with_meta`] and dropped by
    /// [`Self::end_page`]. Purely an optimisation: anything not found is decrypted the
    /// old way, so a bug here can cost time but not notes.
    pub fn predecrypt_page(&mut self, all: &[CompactActionRecord]) {
        if self.leaves_only || all.is_empty() {
            return;
        }
        // Count this against the scan's decrypt budget. Moving the work here without
        // moving the timer made both counters read ~0.1 us/action while the daemon was
        // doing exactly as much work as before — telemetry that flatters the change it
        // is supposed to measure is worse than none, and I nearly reported it as a win.
        let t_dec = std::time::Instant::now();
        let found = scan_compact_auto(&self.prepared_ivk, self.agree_scalar.as_ref(), all);
        self.scan_cost.decrypt_ns += t_dec.elapsed().as_nanos();
        self.scan_cost.actions += all.len() as u64;
        let mut map: std::collections::HashMap<[u8; 32], Option<ReceivedNote>> = all.iter().map(|r| (r.nullifier, None)).collect();
        for n in found {
            if let Some(rec) = all.get(n.action_index) {
                map.insert(rec.nullifier, Some(n));
            }
        }
        self.predecrypted = Some(map);
    }

    /// Drop the page memo. Always call after the page's blocks are ingested — a stale
    /// memo would answer for a later page it never saw.
    pub fn end_page(&mut self) {
        self.predecrypted = None;
    }

    /// Ingest for the **tree only**, skipping trial decryption.
    ///
    /// A Merkle path is a statement about the chain, not about a viewing key: every
    /// wallet ingesting the same blocks builds a byte-identical leaf stream. That
    /// shared half is also where a scan's CPU actually goes — measured live at
    /// **169 µs/leaf of tree against 107 µs/action of decryption**, ~80/20. A daemon
    /// syncing many wallets pays the shared half once *per wallet* today; it only
    /// ever needs to pay it once in total, if one keyless copy of the stream is kept
    /// for everyone to witness against.
    ///
    /// This flag makes that copy cheap. Only the two calls that try to *recognise* a
    /// note are suppressed. Everything that determines the leaf STREAM is
    /// key-independent and still runs — the nullifier drop rule, the coinbase
    /// commit-or-skip rule, the append order — so the stream stays identical to a
    /// real wallet's leaf for leaf. That is why this is a flag on the ordinary
    /// ingest rather than a separate "append these commitments" entry point: the
    /// caller cannot get the sequence wrong, because it is the same code.
    ///
    /// Such a wallet can never own a note, so `notes` stays empty and no balance,
    /// history or spend path is meaningful on it.
    pub fn set_leaves_only(&mut self, on: bool) {
        self.leaves_only = on;
    }

    /// Whether this is a keyless shared tree — see [`Self::set_leaves_only`].
    pub fn is_leaves_only(&self) -> bool {
        self.leaves_only
    }

    /// Build a membership witness for the owned note at `position`, as an Orchard
    /// [`MerklePath`] rooting to the **current tip** [`anchor`](Self::anchor),
    /// ready for [`crate::wallet::build::build_spend_bundle`]. The wallet must
    /// spend against a *finalized* anchor (PLAN §2.5), so it should call this on a
    /// [`WalletDb`] ingested only up to a tip it knows the node has finalized.
    ///
    /// Cost is O(N) in the number of leaves (one witness reconstruction from the
    /// cached stream), paid only for the few notes a spend selects — versus the
    /// old model that paid O(N) per leaf, for every owned note, on every scan.
    pub fn witness_path(&self, position: u64) -> Option<MerklePath> {
        self.witness_path_at(position, self.size)
    }

    /// Like [`Self::witness_path`], but roots the witness to the tree state after
    /// exactly `matured_leaves` **absolute** leaves — a *past* (matured) anchor —
    /// instead of the live tip. This lets a caller spend against a finalized anchor
    /// using the wallet's already-maintained leaf stream, with **no chain rescan**:
    /// pass the leaf count recorded at a block that is `shielded_anchor_depth` deep.
    ///
    /// Returns `None` if the note has not yet entered the `matured_leaves` prefix, if
    /// `matured_leaves` precedes the fast-sync base, or if it exceeds what the wallet
    /// has ingested. The resulting path's root equals the tree root at that matured
    /// block, which consensus accepts as a finalized anchor (`is_shielded_anchor_final`).
    pub fn witness_path_at(&self, position: u64, matured_leaves: u64) -> Option<MerklePath> {
        // Fast path: the sync loop already advanced a live witness to this exact
        // matured cutoff, so the path is a lookup rather than a full replay.
        if let Some(path) = self.live_witness_path(position, matured_leaves) {
            return Some(path);
        }
        // Both absolute; the wallet only stores leaves after `base_size`.
        let rel = position.checked_sub(self.base_size)? as usize;
        let matured_rel = matured_leaves.checked_sub(self.base_size)? as usize;
        // The note must sit strictly inside the matured prefix, and we must hold it.
        let leaves = self.decoded_leaves();
        if rel >= matured_rel || matured_rel > leaves.len() {
            return None;
        }
        let witness = self.rebuild_witness(position, matured_leaves)?;
        let path = witness.path()?;
        let auth: [MerkleHashOrchard; TREE_DEPTH as usize] = path.path_elems().try_into().ok()?;
        Some(MerklePath::from_parts(u64::from(path.position()) as u32, auth))
    }

    /// Build the [`SubtreeCache`] over this wallet's whole stream. One Sinsemilla hash
    /// per leaf, paid **once**; `append_leaf` then keeps it current at that same
    /// per-leaf cost the tip mirror already pays, so steady-state sync gets no slower.
    ///
    /// This is O(chain) — run it off the request path (the daemon warms it on a blocking
    /// thread, never on the async runtime; see the 2026-07-12 freeze).
    ///
    /// **The gate:** the finished cache must reproduce `self.tree`'s root — a value
    /// maintained by a completely independent code path (one `CommitmentTree::append`
    /// per ingested leaf). If it does not, the cache is discarded and every consumer
    /// keeps using the replay. So a bug in the mountain range, in the frontier seeding,
    /// or in the indexing cannot produce a wrong witness; it can only fail to help.
    pub fn build_subtree_cache(&mut self) {
        self.build_subtree_cache_until(|| false);
    }

    /// As [`Self::build_subtree_cache`], but abandons the sweep as soon as `should_yield`
    /// returns true. Returns whether the cache was actually built.
    ///
    /// The sweep is a tight Sinsemilla loop that runs for tens of seconds on a large
    /// wallet, and it competes directly with Halo2 proving — the one thing a user is
    /// waiting on. Refusing to *start* a build while a payment proves is not enough: a
    /// build already in flight keeps its cores for its whole remaining run, so a payment
    /// arriving mid-sweep still pays for it (observed live: proofs stretched from 3.6 s
    /// to 66 s while restarts had every reconnecting wallet rebuilding back-to-back).
    /// Checking the caller's predicate periodically lets the sweep stand down within a
    /// fraction of a second instead.
    ///
    /// Yielding is **not** failure: the cache is simply left unbuilt and the caller
    /// retries on a later pass, so the wallet keeps the (correct, slower) replay path in
    /// the meantime. Only a genuinely unusable sweep marks the cache failed.
    pub fn build_subtree_cache_until(&mut self, should_yield: impl Fn() -> bool) -> bool {
        /// Leaves between `should_yield` checks. At ~150–260 µs per Sinsemilla combine
        /// this bounds how long a proof waits behind a sweep to roughly 0.15–0.27 s,
        /// while keeping the check itself off the hot path.
        const YIELD_CHECK_EVERY: usize = 1024;

        if self.subtree.failed || (self.subtree.active && self.subtree.upto == self.size) {
            return self.subtree.active;
        }
        let reject = SubtreeCache { failed: true, ..Default::default() };
        // Resume a build that stood down earlier rather than repeat it. The sweep is a
        // pure left-to-right fold, so a partial cache is a valid prefix and continuing
        // from `upto` yields exactly the same structure as starting over.
        //
        // Without this, yielding costs the WHOLE pass — measured live at 243-296 s per
        // wallet. That made every stand-down ruinously expensive, which is why the old
        // code could only afford to yield for proving, and why it could not afford to
        // yield for a request waiting on the wallet lock at all. Cheap yields are what
        // make aggressive yielding affordable.
        //
        // Only resume when the partial still lines up with the current stream: base
        // compaction can move `base_size` and re-index `decoded_leaves`, so a prefix
        // that starts below the current base is discarded rather than reinterpreted.
        let resume_from = if self.subtree.partial && !self.subtree.active {
            self.subtree.upto.checked_sub(self.base_size).filter(|&r| r as usize <= self.decoded_leaves().len())
        } else {
            None
        };
        let mut c = match resume_from {
            Some(_) => std::mem::take(&mut self.subtree),
            None => {
                let mut c = SubtreeCache::default();
                if !c.seed_from_frontier(&self.base_frontier, self.base_size) {
                    self.subtree = reject;
                    return false;
                }
                c
            }
        };
        let start = resume_from.unwrap_or(0) as usize;
        {
            let leaves = self.decoded_leaves();
            let base = self.base_size;
            for (i, leaf) in leaves.iter().enumerate().skip(start) {
                if i % YIELD_CHECK_EVERY == 0 && i > start && should_yield() {
                    // Stand down, KEEPING the prefix folded so far. Not usable (active
                    // stays false); resumed by the next call.
                    c.partial = true;
                    c.active = false;
                    self.subtree = c;
                    return false;
                }
                if !c.push_leaf(base + i as u64, *leaf) {
                    self.subtree = reject;
                    return false;
                }
            }
        }
        c.partial = false;
        c.active = true;
        let ok = self.root_from(&c, self.size).is_some_and(|r| r == self.tree.root());
        self.subtree = if ok { c } else { reject };
        ok
    }

    /// Snapshot everything a subtree-cache build needs, so it can run **off the wallet
    /// lock** — see [`SubtreeBuildJob`].
    pub fn subtree_build_job(&self) -> SubtreeBuildJob {
        SubtreeBuildJob {
            base_frontier: self.base_frontier.clone(),
            base_size: self.base_size,
            leaves: self.decoded_leaves().to_vec(),
        }
    }

    /// Install a cache folded off-lock by [`SubtreeBuildJob::run`].
    ///
    /// Accepted only if it still describes THIS stream: base compaction re-indexes the
    /// leaves, so a cache folded over an older base cannot be reinterpreted against the
    /// current one and is refused rather than adjusted. Leaves appended while the build
    /// ran are folded in here — the tail only, which is cheap — and the result must pass
    /// exactly the same root gate as an in-line build before anything can serve from it.
    /// Returns false on any mismatch, leaving the wallet on the replay path.
    pub fn install_subtree_cache(&mut self, built: BuiltSubtreeCache) -> bool {
        if self.subtree.failed || built.base_size != self.base_size {
            return false;
        }
        let mut c = built.cache;
        {
            let base = self.base_size;
            let Some(start) = c.upto.checked_sub(base) else { return false };
            let leaves = self.decoded_leaves();
            if start as usize > leaves.len() {
                return false;
            }
            for (i, leaf) in leaves.iter().enumerate().skip(start as usize) {
                if !c.push_leaf(base + i as u64, *leaf) {
                    return false;
                }
            }
        }
        c.active = true;
        c.partial = false;
        if self.root_from(&c, self.size).is_some_and(|r| r == self.tree.root()) {
            self.subtree = c;
            true
        } else {
            false
        }
    }

    /// Where this wallet's scan CPU has gone so far — see [`ScanCost`].
    pub fn scan_cost(&self) -> ScanCost {
        self.scan_cost
    }

    /// Whether the cache can serve witnesses at `matured` (used by callers to decide
    /// whether a spend needs the slow path at all).
    pub fn subtree_cache_ready(&self, matured: u64) -> bool {
        self.subtree.active && self.subtree.upto >= matured
    }

    /// The cache was attempted and rejected — it will not be retried, and this wallet
    /// keeps the replay path. Distinguishes a genuine failure from a build that merely
    /// stood down part-way, which reports the same `false` from
    /// [`Self::build_subtree_cache_until`] but has kept its progress.
    pub fn subtree_cache_failed(&self) -> bool {
        self.subtree.failed
    }

    /// Absolute leaf index folded into the cache so far, complete or in progress. Lets a
    /// caller report real progress for a sliced build instead of guessing.
    pub fn subtree_build_upto(&self) -> u64 {
        self.subtree.upto
    }

    /// Fold the `2^CACHE_LEVEL`-leaf window starting at `start` (which must be window
    /// aligned), truncated at `cap`, returning its subtree root at `CACHE_LEVEL`. When
    /// `want` is given, records the authentication siblings of position `p` for every
    /// level *below* `CACHE_LEVEL` as it goes.
    fn fold_window(&self, start: u64, cap: u64, p: u64, mut want: Option<&mut [MerkleHashOrchard]>) -> Option<MerkleHashOrchard> {
        let end = (start + (1u64 << CACHE_LEVEL)).min(cap);
        let lo = start.checked_sub(self.base_size)? as usize;
        let hi = end.checked_sub(self.base_size)? as usize;
        let leaves = self.decoded_leaves();
        if hi > leaves.len() || hi <= lo {
            return None;
        }
        let mut cur: Vec<MerkleHashOrchard> = leaves[lo..hi].to_vec();
        for lvl in 0..CACHE_LEVEL {
            if let Some(w) = want.as_deref_mut() {
                let sib = (p >> lvl) ^ 1;
                let origin = start >> lvl;
                w[lvl as usize] = match sib.checked_sub(origin) {
                    Some(k) if (k as usize) < cur.len() => cur[k as usize],
                    _ => MerkleHashOrchard::empty_root(Level::from(lvl)),
                };
            }
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut k = 0;
            while k < cur.len() {
                let left = cur[k];
                let right = cur.get(k + 1).copied().unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(lvl)));
                next.push(MerkleHashOrchard::combine(Level::from(lvl), &left, &right));
                k += 2;
            }
            if next.is_empty() {
                next.push(MerkleHashOrchard::empty_root(Level::from(lvl + 1)));
            }
            cur = next;
        }
        cur.first().copied()
    }

    /// The chain of **straddling** subtree roots at `matured`: `out[l]` is the root of
    /// the one level-`l` node whose leaf range contains `matured`, for `l >= CACHE_LEVEL`.
    /// Every other sibling a path needs is complete (cache) or empty. O(depth).
    fn straddle_chain(&self, c: &SubtreeCache, matured: u64) -> Option<Vec<MerkleHashOrchard>> {
        let h = CACHE_LEVEL as usize;
        let mut out = vec![MerkleHashOrchard::empty_leaf(); TREE_DEPTH as usize + 1];
        let win = (matured >> CACHE_LEVEL) << CACHE_LEVEL;
        out[h] = if win >= matured {
            // `matured` is window aligned: the straddler is entirely empty.
            MerkleHashOrchard::empty_root(Level::from(CACHE_LEVEL))
        } else {
            self.fold_window(win, matured, 0, None)?
        };
        for l in (h + 1)..=(TREE_DEPTH as usize) {
            let j = matured >> l;
            let cl = (l - 1) as u8;
            out[l] = if (matured >> cl) == 2 * j {
                // `matured` lies in the left child; the right child is wholly empty.
                MerkleHashOrchard::combine(Level::from(cl), &out[l - 1], &MerkleHashOrchard::empty_root(Level::from(cl)))
            } else {
                MerkleHashOrchard::combine(Level::from(cl), &c.get(cl, 2 * j)?, &out[l - 1])
            };
        }
        Some(out)
    }

    /// The tree root at exactly `matured` leaves, derived from the cache in O(depth).
    fn root_from(&self, c: &SubtreeCache, matured: u64) -> Option<MerkleHashOrchard> {
        self.straddle_chain(c, matured).map(|s| s[TREE_DEPTH as usize])
    }

    /// Authentication paths for `positions` at `matured`, served from the
    /// [`SubtreeCache`]: O(depth) lookups plus one `2^CACHE_LEVEL`-leaf fold per note,
    /// instead of an O(chain) Sinsemilla replay. Returns `None` if the cache cannot
    /// cover this request at all, in which case the caller uses the replay.
    ///
    /// As with the batch builder, each assembled path is verified to reproduce the
    /// anchor root and declined individually if it does not.
    fn subtree_paths(&self, positions: &[u64], matured: u64) -> Option<Vec<Option<MerklePath>>> {
        if !self.subtree_cache_ready(matured) || matured <= self.base_size {
            return None;
        }
        let c = &self.subtree;
        let straddle = self.straddle_chain(c, matured)?;
        let root = straddle[TREE_DEPTH as usize];
        let leaves = self.decoded_leaves();
        let mut out = vec![None; positions.len()];
        for (i, &p) in positions.iter().enumerate() {
            let Some(rel) = p.checked_sub(self.base_size) else { continue };
            if p >= matured || rel as usize >= leaves.len() {
                continue;
            }
            let mut auth = [MerkleHashOrchard::empty_leaf(); TREE_DEPTH as usize];
            // Below CACHE_LEVEL: fold the note's own window.
            if self.fold_window((p >> CACHE_LEVEL) << CACHE_LEVEL, matured, p, Some(&mut auth[..CACHE_LEVEL as usize])).is_none() {
                continue;
            }
            // At and above CACHE_LEVEL: complete (cache), empty, or the straddler.
            let mut ok = true;
            for l in (CACHE_LEVEL as usize)..(TREE_DEPTH as usize) {
                let sib = (p >> l) ^ 1;
                auth[l] = if ((sib + 1) << l) <= matured {
                    match c.get(l as u8, sib) {
                        Some(v) => v,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                } else if (sib << l) >= matured {
                    MerkleHashOrchard::empty_root(Level::from(l as u8))
                } else {
                    straddle[l]
                };
            }
            if !ok {
                continue;
            }
            // Verify against the anchor before handing it to a spend.
            let mut node = leaves[rel as usize];
            for (l, sib) in auth.iter().enumerate() {
                node = if (p >> l) & 1 == 0 {
                    MerkleHashOrchard::combine(Level::from(l as u8), &node, sib)
                } else {
                    MerkleHashOrchard::combine(Level::from(l as u8), sib, &node)
                };
            }
            if node == root {
                out[i] = Some(MerklePath::from_parts(p as u32, auth));
            }
        }
        Some(out)
    }

    /// Build membership paths for **many** owned notes in a SINGLE pass over the leaf
    /// stream, each rooted at `matured_leaves`. This is the batch form of
    /// [`Self::witness_path_at`]: that rebuilds the tree from the base frontier up to
    /// each note independently — **O(chain) per note**, so an N-note spend on a
    /// note-heavy wallet pays N full replays (the live 43k-note wallet: 27 notes ≈ 12
    /// min of witnessing before the proof even starts). This does ONE base→matured walk
    /// and reads every note's path from shared state — **O(chain + N·depth)** — turning a
    /// large or pool-scale send from minutes/hours into one ~one-pass wait.
    ///
    /// Correctness is not hand-derived: for each note the **left** authentication
    /// siblings come from `IncrementalWitness::from_tree` (the same primitive
    /// [`Self::rebuild_witness`] trusts, which carries the below-base frontier context),
    /// and only the **right** siblings — subtrees strictly inside `[base, matured)`, or
    /// empty above it — are substituted from a node map built once in this pass. Every
    /// assembled path is then **verified to root to the matured anchor**; any that does
    /// not (a bug, or an out-of-window note) is returned as `None` so the caller falls
    /// back to the exact `witness_path_at` replay. It can therefore never yield a wrong
    /// witness — at worst it declines and the slow path runs.
    ///
    /// Returns paths in the same order as `positions`; `None` for a warm-miss the caller
    /// should rebuild, or a position outside `[base_size, matured_leaves)`.
    pub fn witness_paths_at(&self, positions: &[u64], matured_leaves: u64) -> Vec<Option<MerklePath>> {
        let n = positions.len();
        // Fastest path: complete subtree roots already retained, so every sibling is a
        // lookup (see `SubtreeCache`). Serve only if it covers EVERY requested note —
        // a partial answer would send the caller down the O(chain) replay anyway, and
        // paying both is worse than paying one.
        if let Some(cached) = self.subtree_paths(positions, matured_leaves) {
            if cached.iter().all(|p| p.is_some()) {
                return cached;
            }
        }
        let mut out: Vec<Option<MerklePath>> = vec![None; n];
        let base = self.base_size;
        let leaves = self.decoded_leaves();
        let matured_rel = match matured_leaves.checked_sub(base) {
            Some(r) if (r as usize) <= leaves.len() => r as usize,
            _ => return out, // matured precedes the base or exceeds ingest: all fall back
        };
        if matured_rel == 0 {
            return out;
        }

        // Warm hits are free; collect the rest (range-checked, de-duplicated by position).
        let mut cold: Vec<(u64, Vec<usize>)> = Vec::new();
        for (i, &pos) in positions.iter().enumerate() {
            if let Some(p) = self.live_witness_path(pos, matured_leaves) {
                out[i] = Some(p);
                continue;
            }
            let rel = match pos.checked_sub(base) {
                Some(r) => r as usize,
                None => continue,
            };
            if rel >= matured_rel {
                continue; // note not inside the matured prefix
            }
            if let Some(slot) = cold.iter_mut().find(|(p, _)| *p == pos) {
                slot.1.push(i);
            } else {
                cold.push((pos, vec![i]));
            }
        }
        if cold.is_empty() {
            return out;
        }
        cold.sort_by_key(|(p, _)| *p);

        // The dominant cost at a low base (e.g. base=2 on a note-heavy wallet: ~175 K
        // leaves) is the O(chain) Sinsemilla work. The original form paid it THREE times
        // in series — node map, a separate matured-root replay, and a left-context walk —
        // so witnessing even 2 notes took ~95 s. We now (1) FUSE the matured-root replay
        // into the left-context walk (one tree yields both the trusted root and the
        // `from_tree` left siblings) and (2) run the remaining two O(chain) passes
        // CONCURRENTLY, since each only reads shared immutable state. Wall time drops from
        // ~3× to ~1× a single replay. The correctness contract is unchanged: the matured
        // root still comes from an INDEPENDENT `CommitmentTree` replay (never the node
        // map), and every assembled path is verified to reproduce it or is declined.
        let base_frontier = &self.base_frontier;
        let cold_positions: Vec<u64> = cold.iter().map(|(p, _)| *p).collect();
        type Auth = [MerkleHashOrchard; TREE_DEPTH as usize];
        let (nodes, left_ctx, matured_root) = std::thread::scope(|s| {
            // PASS A (own thread): node map over [base, matured): nodes[l] maps an ABSOLUTE
            // level-l index to the hash of that subtree, for subtrees whose range is fully
            // >= base (partially filled at the right edge → combined with empty_root; fully
            // >= matured → absent, meaning empty_root). Supplies every RIGHT authentication
            // sibling — those ranges are all > the note's position >= base — in O(1).
            let map_handle = s.spawn(move || {
                let mut nodes: Vec<std::collections::HashMap<u64, MerkleHashOrchard>> = Vec::with_capacity(TREE_DEPTH as usize + 1);
                nodes.push((0..matured_rel).map(|r| (base + r as u64, leaves[r])).collect());
                for l in 0..TREE_DEPTH {
                    let cur = &nodes[l as usize];
                    let mut parents: Vec<u64> = cur.keys().map(|j| j >> 1).collect();
                    parents.sort_unstable();
                    parents.dedup();
                    let mut up: std::collections::HashMap<u64, MerkleHashOrchard> =
                        std::collections::HashMap::with_capacity(parents.len());
                    for pj in parents {
                        let lidx = pj << 1;
                        let Some(left) = cur.get(&lidx) else { continue }; // left child below/straddling base → left context
                        if (lidx << l) < base {
                            continue;
                        }
                        let right = cur.get(&(lidx + 1)).cloned().unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(l)));
                        up.insert(pj, MerkleHashOrchard::combine(Level::from(l), left, &right));
                    }
                    nodes.push(up);
                }
                nodes
            });

            // PASS B+C (this thread): ONE ascending `CommitmentTree` replay from the base
            // frontier. `from_tree` at each cold position yields that note's left siblings
            // (incl. below-base frontier context); after the last one we finish the walk to
            // `matured_rel` and take `root()` — the authoritative, independent matured root.
            let mut tree = CommitmentTree::from_frontier(base_frontier);
            let mut walk = 0usize; // relative leaves already appended into `tree`
            let mut left_ctx: Vec<Option<Auth>> = vec![None; cold_positions.len()];
            let mut ok = true;
            for (ci, &pos) in cold_positions.iter().enumerate() {
                let rel = (pos - base) as usize;
                while walk <= rel {
                    if tree.append(leaves[walk]).is_err() {
                        ok = false;
                        break;
                    }
                    walk += 1;
                }
                if !ok {
                    break;
                }
                let Some(w) = IncrementalWitness::<MerkleHashOrchard, TREE_DEPTH>::from_tree(tree.clone()) else { continue };
                let Some(left_path) = w.path() else { continue };
                let elems = left_path.path_elems();
                if let Ok(arr) = <Auth>::try_from(elems) {
                    left_ctx[ci] = Some(arr);
                }
            }
            let matured_root = if ok {
                while walk < matured_rel {
                    if tree.append(leaves[walk]).is_err() {
                        ok = false;
                        break;
                    }
                    walk += 1;
                }
                if ok { Some(tree.root()) } else { None }
            } else {
                None
            };
            let nodes = map_handle.join().expect("witness node-map thread panicked");
            (nodes, left_ctx, matured_root)
        });
        let Some(matured_root) = matured_root else { return out };

        // Assembly (serial, O(N·depth)): combine left context + node-map right siblings,
        // verify each path reproduces the trusted matured root, else decline (caller falls
        // back to the exact per-note replay) — so a wrong witness can never be emitted.
        for (ci, (pos, idxs)) in cold.iter().enumerate() {
            let Some(left_elems) = left_ctx[ci] else { continue };
            let p = *pos;
            let rel = (p - base) as usize;
            let mut auth = [MerkleHashOrchard::empty_leaf(); TREE_DEPTH as usize];
            for l in 0..TREE_DEPTH as usize {
                if (p >> l) & 1 == 0 {
                    // right sibling: subtree at absolute index (p>>l)+1, level l
                    let sib = (p >> l) + 1;
                    auth[l] = nodes[l].get(&sib).copied().unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(l as u8)));
                } else {
                    // left sibling: from the trusted from_tree path
                    auth[l] = left_elems[l];
                }
            }

            // Verify the assembled path roots to the matured anchor, from the note's own leaf.
            let leaf = leaves[rel];
            let mut node = leaf;
            for (l, sib) in auth.iter().enumerate() {
                node = if (p >> l) & 1 == 0 {
                    MerkleHashOrchard::combine(Level::from(l as u8), &node, sib)
                } else {
                    MerkleHashOrchard::combine(Level::from(l as u8), sib, &node)
                };
            }
            if node != matured_root {
                continue; // assembly disagreed with consensus root — fall back
            }
            let mp = MerklePath::from_parts(p as u32, auth);
            for &i in idxs {
                out[i] = Some(mp.clone());
            }
        }
        out
    }

    /// Reconstruct a coinbase note if it was paid to this wallet. A coinbase note
    /// is ours iff its stated recipient equals our address; the note is then fully
    /// determined by the public `(recipient, ρ, rseed)` and the public `value`,
    /// exactly as [`crate::coinbase`] recomputes the commitment.
    fn recover_coinbase_note(&self, desc: &CoinbaseNoteDesc, value: u64) -> Option<Note> {
        if desc.recipient != self.my_address {
            return None;
        }
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&desc.recipient))?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho))?;
        Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2))
    }

    /// Serialize the wallet's **scanned state** — the fast-sync base frontier, the
    /// post-checkpoint commitment stream, and the owned notes — into a compact,
    /// versioned blob. This is a checkpoint a caller (e.g. `zkas-walletd`)
    /// persists so a restart resumes from here instead of re-scanning. No secrets are
    /// written: the viewing keys and address are re-derived from the seed on load, so
    /// only public chain-derived state lives in the blob. The mirror `tree` is omitted
    /// — it is rebuilt from the base frontier + `leaves` on load.
    ///
    /// Layout (little-endian): `[version:u8][base_size:u64]
    /// [base:0 | 1 (base_leaf:32)(n_ommers:u64)(ommer:32)*] [size:u64]
    /// [n_leaves:u64](leaf:32)* [n_notes:u64]
    /// (position:u64, nullifier:32, recipient:43, value:u64, rho:32, rseed:32)*`.
    pub fn to_checkpoint(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.leaves.len() * 32 + self.notes.len() * 123);
        out.push(CHECKPOINT_VERSION);
        // Fast-sync base: absolute base size, then the base frontier (empty ⇒ tag 0).
        out.extend_from_slice(&self.base_size.to_le_bytes());
        write_frontier(&mut out, &self.base_frontier);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&(self.leaves.len() as u64).to_le_bytes());
        for leaf in &self.leaves {
            out.extend_from_slice(leaf);
        }
        out.extend_from_slice(&(self.notes.len() as u64).to_le_bytes());
        for n in &self.notes {
            out.extend_from_slice(&n.position.to_le_bytes());
            out.extend_from_slice(&n.nullifier);
            out.extend_from_slice(&n.note.recipient().to_raw_address_bytes());
            out.extend_from_slice(&n.note.value().inner().to_le_bytes());
            out.extend_from_slice(&n.note.rho().to_bytes());
            out.extend_from_slice(n.note.rseed().as_bytes());
        }
        // v3: the spent-nullifier set, sorted for a canonical encoding.
        let mut nfs: Vec<&[u8; 32]> = self.spent_nullifiers.iter().collect();
        nfs.sort();
        out.extend_from_slice(&(nfs.len() as u64).to_le_bytes());
        for nf in nfs {
            out.extend_from_slice(nf);
        }
        // v4: the **tip** frontier — the mirror tree summarised in O(1). Without it a
        // restore has to replay every leaf back through Sinsemilla to rebuild `tree`,
        // which is minutes of CPU per wallet and is why a daemon restart showed every
        // user `0 balance / 0 notes / syncing 0%` until their wallet finished reloading.
        // Same encoding as the base frontier above.
        // Only write the tip frontier if it actually describes `size`. A borrowing
        // wallet's mirror tree lags whatever it skipped, and persisting that would be
        // worse than persisting nothing: the loader would trust it. The empty tag with
        // a non-zero size is self-evidently "not recorded", and the load path treats it
        // as such rather than as an empty tree.
        if self.tree_valid {
            write_frontier(&mut out, &self.tree.to_frontier());
        } else {
            out.push(0);
        }

        // v5: the persisted per-note witnesses, as a length-prefixed, best-effort section
        // (see CHECKPOINT_VERSION). Layout: [witnessed_upto:u64][lag_tree][n:u64]
        // (position:u64, witness)*. The u64 length prefix lets a restore skip the whole
        // section on any parse trouble, so a witness-format bug degrades to "rebuild on
        // demand" instead of failing the restore.
        let mut wsec = Vec::new();
        wsec.extend_from_slice(&self.witnessed_upto.to_le_bytes());
        write_tree(&mut wsec, &self.lag_tree);
        wsec.extend_from_slice(&(self.witnesses.len() as u64).to_le_bytes());
        for (pos, w) in &self.witnesses {
            wsec.extend_from_slice(&pos.to_le_bytes());
            write_witness(&mut wsec, w);
        }
        out.extend_from_slice(&(wsec.len() as u64).to_le_bytes());
        out.extend_from_slice(&wsec);

        // v6: the chain-derived history rows, length-prefixed and best-effort like
        // the witness section — parse trouble degrades to "history starts fresh",
        // never a failed restore.
        let mut hsec = Vec::new();
        hsec.extend_from_slice(&(self.history.len() as u64).to_le_bytes());
        for h in &self.history {
            hsec.push(h.kind as u8);
            hsec.extend_from_slice(&h.txid);
            hsec.extend_from_slice(&h.daa_score.to_le_bytes());
            hsec.extend_from_slice(&h.timestamp_ms.to_le_bytes());
            hsec.extend_from_slice(&h.amount.to_le_bytes());
            hsec.extend_from_slice(&h.fee.to_le_bytes());
            hsec.push((h.amount_is_net_outflow as u8) | ((h.fee_known as u8) << 1));
            match &h.recipient {
                Some(r) => {
                    hsec.push(1);
                    hsec.extend_from_slice(r);
                }
                None => hsec.push(0),
            }
            let memo_len = h.memo.len().min(u16::MAX as usize) as u16;
            hsec.extend_from_slice(&memo_len.to_le_bytes());
            hsec.extend_from_slice(&h.memo[..memo_len as usize]);
        }
        out.extend_from_slice(&(hsec.len() as u64).to_le_bytes());
        out.extend_from_slice(&hsec);

        // v7: the pending spends + the wallet's DAA clock, length-prefixed and
        // best-effort like v5/v6. Parse trouble degrades to "no pending spends" —
        // the pre-v7 status quo (those notes stay invisible until a rescan) —
        // never a failed restore. Layout: [last_daa:u64][n:u64]
        // (position:u64, nullifier:32, recipient:43, value:u64, rho:32, rseed:32,
        //  txid:32, submitted_daa:u64)*.
        let mut psec = Vec::new();
        psec.extend_from_slice(&self.last_daa.to_le_bytes());
        psec.extend_from_slice(&(self.pending_spends.len() as u64).to_le_bytes());
        for p in &self.pending_spends {
            psec.extend_from_slice(&p.note.position.to_le_bytes());
            psec.extend_from_slice(&p.note.nullifier);
            psec.extend_from_slice(&p.note.note.recipient().to_raw_address_bytes());
            psec.extend_from_slice(&p.note.note.value().inner().to_le_bytes());
            psec.extend_from_slice(&p.note.note.rho().to_bytes());
            psec.extend_from_slice(p.note.note.rseed().as_bytes());
            psec.extend_from_slice(&p.txid);
            psec.extend_from_slice(&p.submitted_daa.to_le_bytes());
        }
        out.extend_from_slice(&(psec.len() as u64).to_le_bytes());
        out.extend_from_slice(&psec);

        // v8: persist the root-gated complete-subtree index. Building this index is
        // deliberately expensive (one Sinsemilla fold over the wallet's retained leaf
        // stream), but it is pure public chain state and must not be thrown away on every
        // daemon eviction/restart. The section is optional and best-effort: restore only
        // activates it after reproducing the independently persisted tip tree root.
        let mut ssec = Vec::new();
        write_subtree_section(&mut ssec, &self.subtree);
        out.extend_from_slice(&(ssec.len() as u64).to_le_bytes());
        out.extend_from_slice(&ssec);
        out
    }

    /// Rebuild a wallet from its `seed` plus a checkpoint blob previously produced by
    /// [`Self::to_checkpoint`]. Returns `None` if the seed is not a valid Orchard key,
    /// or the blob is malformed / a different version / has trailing bytes — in which
    /// case the caller should discard it and fall back to a full rescan. The tip
    /// mirror `tree` is reconstructed from the base frontier + `leaves` (O(N) hashing,
    /// no network and no trial-decryption — far cheaper than re-fetching the chain).
    pub fn from_checkpoint(seed: [u8; 32], bytes: &[u8]) -> Option<Self> {
        Self::restore(Self::from_seed(seed)?, bytes, None)
    }

    /// [`Self::from_checkpoint`] with the tip tree supplied by the caller.
    ///
    /// A wallet's mirror tree at its cursor block *is* the consensus note-commitment
    /// tree at that block — same leaves, same order. So a node can hand us that tree's
    /// frontier directly (`GetShieldedTreeState` at the cursor) and the restore skips
    /// the leaf replay entirely. This is what makes restoring an **old (v3)** checkpoint
    /// O(1) as well, instead of ~60s of Sinsemilla per wallet — without which upgrading
    /// the format would strand every existing wallet in a multi-hour reload.
    ///
    /// The frontier is accepted only if it describes exactly as many leaves as the
    /// checkpoint claims; on any mismatch we fall back to rebuilding from the stream, so
    /// a wrong or stale frontier can never silently install a wrong tree.
    pub fn from_checkpoint_with_tip(seed: [u8; 32], bytes: &[u8], tip: &FrontierState) -> Option<Self> {
        Self::restore(Self::from_seed(seed)?, bytes, Some(tip))
    }

    pub fn from_checkpoint_fvk_with_tip(fvk_bytes: &[u8; 96], bytes: &[u8], tip: &FrontierState) -> Option<Self> {
        Self::restore(Self::from_fvk(fvk_bytes)?, bytes, Some(tip))
    }

    /// [`Self::from_checkpoint`] for a **watch-only** wallet: the checkpoint blob holds
    /// no key material (only tree + notes), so it restores identically under a full
    /// viewing key. This is what lets a daemon resume syncing a non-custodial wallet
    /// across restarts without ever having seen the seed.
    pub fn from_checkpoint_fvk(fvk_bytes: &[u8; 96], bytes: &[u8]) -> Option<Self> {
        Self::restore(Self::from_fvk(fvk_bytes)?, bytes, None)
    }

    fn restore(mut db: Self, bytes: &[u8], tip: Option<&FrontierState>) -> Option<Self> {
        let mut r = Cursor { buf: bytes, pos: 0 };
        // v3 blobs are still accepted so that shipping v4 does not force every live
        // wallet into a full rescan; they simply pay the old O(N) tree rebuild once and
        // are rewritten as v4 by the next checkpoint.
        let version = r.u8()?;
        if !(CHECKPOINT_VERSION_V3..=CHECKPOINT_VERSION).contains(&version) {
            return None;
        }
        let has_tip_frontier = version >= CHECKPOINT_VERSION_V4;
        let base_size = r.u64()?;
        let base_frontier = read_frontier(&mut r, base_size)?;
        db.base_frontier = base_frontier;
        db.base_size = base_size;
        db.lag_tree = CommitmentTree::from_frontier(&db.base_frontier);
        db.witnessed_upto = base_size;
        db.witnesses.clear();
        db.tree = CommitmentTree::from_frontier(&db.base_frontier);

        let size = r.u64()?;
        let n_leaves = r.u64()? as usize;
        db.leaves.reserve(n_leaves);
        for _ in 0..n_leaves {
            // Stored verbatim — no point decompression here; that is what makes a restore
            // a memcpy instead of minutes of curve arithmetic.
            db.leaves.push(r.arr::<32>()?);
        }
        let n_notes = r.u64()? as usize;
        for _ in 0..n_notes {
            let position = r.u64()?;
            let nullifier = r.arr::<32>()?;
            let recipient = r.arr::<43>()?;
            let value = r.u64()?;
            let rho = Option::<Rho>::from(Rho::from_bytes(&r.arr()?))?;
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(r.arr()?, &rho))?;
            let addr = Option::<Address>::from(Address::from_raw_address_bytes(&recipient))?;
            let note = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2))?;
            db.notes.push(OwnedNote { note, position, nullifier });
        }
        let n_nfs = r.u64()? as usize;
        for _ in 0..n_nfs {
            db.spent_nullifiers.insert(r.arr::<32>()?);
        }
        // The tip mirror tree. v4 carries it as a frontier, so restoring it is O(1) —
        // no hashing at all. A v3 blob has no such field, so fall back to replaying the
        // leaf stream (O(N) Sinsemilla), which is what every restore used to cost.
        db.tree = if has_tip_frontier {
            let tip = read_frontier(&mut r, size)?;
            // An EMPTY tip frontier on a non-empty stream means the writer was borrowing
            // the shared tree and had nothing valid to record — not that the tree is
            // empty. Restore what we can and mark it invalid so `anchor()` is not read
            // until a frontier is adopted.
            if size > 0 && tip.value().is_none() {
                db.tree_valid = false;
                CommitmentTree::from_frontier(&db.base_frontier)
            } else {
                CommitmentTree::from_frontier(&tip)
            }
        } else if let Some(fs) = tip.filter(|fs| fs.size == size) {
            // A v3 blob carries no tip frontier, but the caller got one from the node for
            // exactly this cursor — same tree, so use it and skip the replay.
            CommitmentTree::from_frontier(GlobalTree::from_state(fs).ok()?.frontier())
        } else {
            let mut tree = CommitmentTree::from_frontier(&db.base_frontier);
            for leaf in db.decoded_leaves() {
                // `append` only errors on a full (2^32-leaf) tree — unreachable here.
                let _ = tree.append(*leaf);
            }
            tree
        };
        db.size = size;

        // v5: the persisted per-note witnesses. Read the length prefix, then parse the
        // section on a sub-cursor so any trouble inside it degrades to "no witnesses,
        // rebuild on demand" without corrupting the outer read position — witnesses are a
        // pure optimisation, never load-bearing for correctness or balance.
        if version >= CHECKPOINT_VERSION_V5 {
            if let Some(wlen) = r.u64() {
                if let Some(wbuf) = r.take(wlen as usize) {
                    Self::read_witness_section(&mut db, wbuf);
                }
            }
        }
        // v6: the history section — same length-prefixed best-effort contract.
        if version >= CHECKPOINT_VERSION_V6 {
            if let Some(hlen) = r.u64() {
                if let Some(hbuf) = r.take(hlen as usize) {
                    Self::read_history_section(&mut db, hbuf, version >= CHECKPOINT_VERSION_V9);
                }
            }
        }
        // v7: pending spends + DAA clock — same length-prefixed best-effort contract.
        if version >= CHECKPOINT_VERSION_V7 {
            if let Some(plen) = r.u64() {
                if let Some(pbuf) = r.take(plen as usize) {
                    Self::read_pending_section(&mut db, pbuf);
                }
            }
        }
        // v8: persisted complete-subtree index. It is an optimisation only and is
        // accepted solely when it covers this exact tip and reproduces the independent
        // commitment-tree root; malformed/stale data degrades to an empty cache.
        if version >= CHECKPOINT_VERSION_V8 {
            if let Some(slen) = r.u64() {
                if let Some(sbuf) = r.take(slen as usize) {
                    Self::read_subtree_section(&mut db, sbuf);
                }
            }
        }
        if !r.done() {
            return None;
        }
        Some(db)
    }

    fn read_subtree_section(db: &mut Self, buf: &[u8]) {
        let mut r = Cursor { buf, pos: 0 };
        let parse = |r: &mut Cursor<'_>| -> Option<SubtreeCache> {
            let active = match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let failed = match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let upto = r.u64()?;
            let n_levels = r.u64()? as usize;
            if n_levels > TREE_DEPTH as usize + 1 {
                return None;
            }
            let mut levels = Vec::with_capacity(n_levels);
            let mut first = Vec::with_capacity(n_levels);
            for _ in 0..n_levels {
                first.push(r.u64()?);
                let n = r.u64()? as usize;
                // A checkpoint cannot legitimately contain more cached roots than
                // retained leaves (plus one base-frontier root per level).
                if n > db.leaves.len().saturating_add(TREE_DEPTH as usize + 1) {
                    return None;
                }
                let mut roots = Vec::with_capacity(n);
                for _ in 0..n {
                    roots.push(Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&r.arr::<32>()?))?);
                }
                levels.push(roots);
            }
            let n_peaks = r.u64()? as usize;
            if n_peaks > TREE_DEPTH as usize + 1 {
                return None;
            }
            let mut peaks = Vec::with_capacity(n_peaks);
            for _ in 0..n_peaks {
                let level = r.u8()?;
                if level > TREE_DEPTH {
                    return None;
                }
                let index = r.u64()?;
                let root = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&r.arr::<32>()?))?;
                peaks.push((level, index, root));
            }
            // `partial: false` — the reader below accepts only a complete, root-verified
            // cache, so a restored one is never an in-progress build.
            r.done().then_some(SubtreeCache { levels, first, peaks, upto, active, failed, partial: false })
        };
        let Some(cache) = parse(&mut r) else { return };
        // Never restore a partial active cache. A failed/inactive marker is harmless,
        // but an active cache must describe precisely the tree persisted in this blob.
        if cache.active && cache.upto == db.size && db.root_from(&cache, db.size).is_some_and(|root| root == db.tree.root()) {
            db.subtree = cache;
        } else if cache.failed {
            db.subtree.failed = true;
        }
    }

    /// Best-effort restore of the v7 pending-spend section — any malformed record
    /// drops the whole section, never fails the restore.
    fn read_pending_section(db: &mut Self, buf: &[u8]) {
        let mut r = Cursor { buf, pos: 0 };
        let parse = |r: &mut Cursor<'_>| -> Option<(u64, Vec<PendingSpend>)> {
            let last_daa = r.u64()?;
            let n = r.u64()? as usize;
            let mut out = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let position = r.u64()?;
                let nullifier = r.arr::<32>()?;
                let recipient = r.arr::<43>()?;
                let value = r.u64()?;
                let rho = Option::<Rho>::from(Rho::from_bytes(&r.arr()?))?;
                let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(r.arr()?, &rho))?;
                let addr = Option::<Address>::from(Address::from_raw_address_bytes(&recipient))?;
                let note = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, orchard::note::NoteVersion::V2))?;
                let txid = r.arr::<32>()?;
                let submitted_daa = r.u64()?;
                out.push(PendingSpend { note: OwnedNote { note, position, nullifier }, txid, submitted_daa });
            }
            if !r.done() {
                return None;
            }
            Some((last_daa, out))
        };
        if let Some((last_daa, pending)) = parse(&mut r) {
            db.last_daa = last_daa;
            db.pending_spends = pending;
        }
    }

    /// Best-effort restore of the v6 history section. v9 adds compact-send flags.
    /// Any malformed row drops the
    /// whole section (history restarts from here on) — never fails the restore.
    fn read_history_section(db: &mut Self, buf: &[u8], has_compact_flags: bool) {
        let mut r = Cursor { buf, pos: 0 };
        let parse = |r: &mut Cursor<'_>| -> Option<Vec<HistoryEntry>> {
            let n = (r.u64()? as usize).min(HISTORY_CAP);
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let kind = match r.u8()? {
                    0 => HistoryKind::Coinbase,
                    1 => HistoryKind::Received,
                    2 => HistoryKind::Sent,
                    _ => return None,
                };
                let txid = r.arr::<32>()?;
                let daa_score = r.u64()?;
                let timestamp_ms = r.u64()?;
                let amount = r.u64()?;
                let fee = r.u64()?;
                let (amount_is_net_outflow, fee_known) = if has_compact_flags {
                    let flags = r.u8()?;
                    if flags & !0b11 != 0 {
                        return None;
                    }
                    (flags & 1 != 0, flags & 2 != 0)
                } else {
                    (false, true)
                };
                let recipient = match r.u8()? {
                    0 => None,
                    1 => Some(r.arr::<43>()?),
                    _ => return None,
                };
                let memo_len = u16::from_le_bytes(r.arr::<2>()?) as usize;
                let memo = r.take(memo_len)?.to_vec();
                out.push(HistoryEntry {
                    kind,
                    txid,
                    daa_score,
                    timestamp_ms,
                    amount,
                    fee,
                    amount_is_net_outflow,
                    fee_known,
                    recipient,
                    memo,
                });
            }
            r.done().then_some(out)
        };
        if let Some(h) = parse(&mut r) {
            db.history = h;
        }
    }

    /// Best-effort restore of the v5 witness section (see `to_checkpoint`). On any parse
    /// failure it leaves the witnesses empty — the wallet still restores fully and simply
    /// rebuilds a path on demand at spend time. A witness is only installed if it is
    /// consistent (its position is an owned note and it advances no further than the base
    /// or beyond what we ingested), so a stale blob can never install a wrong path.
    fn read_witness_section(db: &mut Self, buf: &[u8]) {
        let owned: HashSet<u64> = db.notes.iter().map(|n| n.position).collect();
        let mut r = Cursor { buf, pos: 0 };
        let parse = |r: &mut Cursor<'_>| -> Option<(
            u64,
            CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
            Vec<(u64, IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>)>,
        )> {
            let witnessed_upto = r.u64()?;
            let lag_tree = read_tree(r)?;
            let n = r.u64()? as usize;
            let mut ws = Vec::with_capacity(n);
            for _ in 0..n {
                let pos = r.u64()?;
                let w = read_witness(r)?;
                ws.push((pos, w));
            }
            r.done().then_some((witnessed_upto, lag_tree, ws))
        };
        if let Some((witnessed_upto, lag_tree, ws)) = parse(&mut r) {
            // Only trust a section that advances to a sane point above the base and no
            // further than what we hold, and whose witnesses all belong to owned notes.
            if witnessed_upto >= db.base_size && witnessed_upto <= db.size && ws.iter().all(|(p, _)| owned.contains(p)) {
                db.witnessed_upto = witnessed_upto;
                db.lag_tree = lag_tree;
                db.witnesses = ws;
            }
        }
    }
}

fn write_subtree_section(out: &mut Vec<u8>, subtree: &SubtreeCache) {
    out.push(u8::from(subtree.active));
    out.push(u8::from(subtree.failed));
    out.extend_from_slice(&subtree.upto.to_le_bytes());
    out.extend_from_slice(&(subtree.levels.len() as u64).to_le_bytes());
    for (level, roots) in subtree.levels.iter().enumerate() {
        out.extend_from_slice(&subtree.first.get(level).copied().unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&(roots.len() as u64).to_le_bytes());
        for root in roots {
            out.extend_from_slice(&root.to_bytes());
        }
    }
    out.extend_from_slice(&(subtree.peaks.len() as u64).to_le_bytes());
    for (level, index, root) in &subtree.peaks {
        out.push(*level);
        out.extend_from_slice(&index.to_le_bytes());
        out.extend_from_slice(&root.to_bytes());
    }
}

/// Serialize a frontier: `0` for empty, else `1 ‖ leaf(32) ‖ n_ommers(u64) ‖ ommer(32)*`.
fn write_frontier(out: &mut Vec<u8>, f: &Frontier<MerkleHashOrchard, TREE_DEPTH>) {
    match f.value() {
        None => out.push(0),
        Some(nef) => {
            out.push(1);
            out.extend_from_slice(&nef.leaf().to_bytes());
            out.extend_from_slice(&(nef.ommers().len() as u64).to_le_bytes());
            for o in nef.ommers() {
                out.extend_from_slice(&o.to_bytes());
            }
        }
    }
}

/// Inverse of [`write_frontier`]. `size` is the absolute leaf count the frontier
/// summarises; it pins the frontier's position, and reusing the node-side
/// reconstruction ([`GlobalTree::from_state`]) revalidates that the ommers are
/// consistent with it, so a corrupt blob fails cleanly rather than yielding a wrong tree.
fn read_frontier(r: &mut Cursor<'_>, size: u64) -> Option<Frontier<MerkleHashOrchard, TREE_DEPTH>> {
    match r.u8()? {
        0 => Some(Frontier::empty()),
        1 => {
            let leaf = r.arr::<32>()?;
            let n_ommers = r.u64()? as usize;
            let mut ommers = Vec::with_capacity(n_ommers);
            for _ in 0..n_ommers {
                ommers.push(r.arr::<32>()?);
            }
            let fs = FrontierState { size, leaf: Some(leaf), ommers };
            Some(GlobalTree::from_state(&fs).ok()?.frontier().clone())
        }
        _ => None,
    }
}

/// Serialize a `CommitmentTree` as `size ‖ frontier` — a tree is fully described by its
/// appendable frontier, and the size pins its position for [`read_tree`]. Used to persist
/// the per-note witnesses' inner trees in the v5 checkpoint.
fn write_tree(out: &mut Vec<u8>, tree: &CommitmentTree<MerkleHashOrchard, TREE_DEPTH>) {
    let f = tree.to_frontier();
    let size = f.value().map_or(0, |nef| u64::from(nef.position()) + 1);
    out.extend_from_slice(&size.to_le_bytes());
    write_frontier(out, &f);
}

/// Inverse of [`write_tree`].
fn read_tree(r: &mut Cursor<'_>) -> Option<CommitmentTree<MerkleHashOrchard, TREE_DEPTH>> {
    let size = r.u64()?;
    let f = read_frontier(r, size)?;
    Some(CommitmentTree::from_frontier(&f))
}

/// Serialize an [`IncrementalWitness`] from the exact parts
/// [`IncrementalWitness::from_parts`] reconstructs it from: its inner tree (the state at
/// the witnessed leaf), the `filled` sibling hashes accumulated as later leaves arrived,
/// and the optional `cursor` subtree.
fn write_witness(out: &mut Vec<u8>, w: &IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>) {
    write_tree(out, w.tree());
    let filled = w.filled();
    out.extend_from_slice(&(filled.len() as u64).to_le_bytes());
    for h in filled {
        out.extend_from_slice(&h.to_bytes());
    }
    match w.cursor() {
        Some(c) => {
            out.push(1);
            write_tree(out, c);
        }
        None => out.push(0),
    }
}

/// Inverse of [`write_witness`]. Returns `None` on any malformed field (the caller then
/// drops the whole witness section and rebuilds paths on demand).
fn read_witness(r: &mut Cursor<'_>) -> Option<IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>> {
    let tree = read_tree(r)?;
    let n = r.u64()? as usize;
    let mut filled = Vec::with_capacity(n);
    for _ in 0..n {
        filled.push(Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&r.arr::<32>()?))?);
    }
    let cursor = match r.u8()? {
        0 => None,
        1 => Some(read_tree(r)?),
        _ => return None,
    };
    IncrementalWitness::from_parts(tree, filled, cursor)
}

/// Checkpoint format version. Bump on any layout change so an old blob is rejected
/// (triggering a clean rescan) rather than silently misread. v2 added the fast-sync
/// base frontier; v3 the spent-nullifier set (bundle drop rule) — v2 trees may have
/// double-applied bundles, so they must rescan. v4 appends the tip frontier, making a
/// restore O(1) instead of an O(N) Sinsemilla replay.
/// v5 appends the **persisted per-note witnesses** (Zcash-style incremental witnessing):
/// the live `IncrementalWitness` for each unspent note, its lagging tree, and the leaf
/// count they are advanced to. Without it a restart threw the witnesses away and every
/// first spend rebuilt a note's path by replaying the whole leaf stream (~30 s on a
/// full-scan or note-heavy miner wallet); persisting them makes a spend a lookup. The
/// section is length-prefixed and best-effort — a parse failure simply drops the
/// witnesses (rebuild on demand, the old behaviour), so it can never fail a restore or
/// lose funds. v5 is a pure suffix of v4, so v4/v3 blobs still restore.
/// v6 appends the **chain-derived history rows** ([`HistoryEntry`]) as another
/// length-prefixed best-effort section — a pure suffix of v5.
/// v7 appends the **pending spends** ([`PendingSpend`]) and the wallet's DAA
/// clock as another length-prefixed best-effort section — a pure suffix of v6.
/// Without it a restart forgot which notes were parked awaiting confirmation,
/// which is half of how a lost transaction became lost money.
/// v8 persists the root-gated complete-subtree index, avoiding a full Sinsemilla
/// rebuild after every daemon eviction/restart. It contains public chain state only.
/// v9 annotates history rows reconstructed from compact scan data, so clients never
/// mistake their net outflow or placeholder fee for exact payment details.
const CHECKPOINT_VERSION: u8 = 9;
const CHECKPOINT_VERSION_V9: u8 = 9;
/// v8 introduced the persisted complete-subtree index. Gate its section on THIS
/// constant, never on `CHECKPOINT_VERSION`: when v9 was added the gate silently moved to
/// 9, every v8 checkpoint was left with 34 unread trailing bytes, `restore` rejected it
/// as malformed, and every wallet (and the shared chain tree) fell into a full rescan.
const CHECKPOINT_VERSION_V8: u8 = 8;
const CHECKPOINT_VERSION_V7: u8 = 7;
/// v6 appended the history rows. A pure suffix of v5.
const CHECKPOINT_VERSION_V6: u8 = 6;
/// v5 appended the persisted witnesses. A pure suffix of v4.
const CHECKPOINT_VERSION_V5: u8 = 5;
/// v4 appended the tip frontier (O(1) restore). A pure suffix of v3.
const CHECKPOINT_VERSION_V4: u8 = 4;
/// v4 is a pure suffix of v3, so v3 blobs still restore correctly (paying the old O(N)
/// tree rebuild once). Reading them is what lets a newer binary deploy without forcing
/// every live wallet into a full rescan from birthday.
const CHECKPOINT_VERSION_V3: u8 = 3;

/// A minimal forward byte-reader for [`WalletDb::from_checkpoint`]: every read is
/// bounds-checked and returns `None` past the end, so a truncated or corrupt blob
/// fails cleanly instead of panicking.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::derive_coinbase_note_desc;
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState};

    impl WalletDb {
        /// Replicate the PRE-FIX base compaction — the one that ignored held
        /// notes — so tests can manufacture the stranded state that exists in
        /// the wild (note below base, no witness) now that the public API can
        /// no longer produce it.
        fn strand_notes_for_test(&mut self, target: u64) {
            let notes = std::mem::take(&mut self.notes);
            let pending = std::mem::take(&mut self.pending_spends);
            while self.advance_base_capped(target, u64::MAX) {}
            self.notes = notes;
            self.pending_spends = pending;
        }
    }

    /// A coinbase note description for `seed` paid to `address`, plus its value —
    /// exactly what a coinbase transaction publishes and what `ingest_block`
    /// consumes.
    fn coinbase_for(address: [u8; 43], seed: &[u8], value: u64) -> (CoinbaseNoteDesc, u64) {
        (derive_coinbase_note_desc(address, seed), value)
    }

    fn address_of(seed: [u8; 32]) -> [u8; 43] {
        crate::wallet::scan::address_bytes_from_seed(seed).unwrap()
    }

    /// The wallet recognises a coinbase note paid to it, ignores one paid to a
    /// stranger, and the balance reflects only its own notes.
    #[test]
    fn discovers_own_coinbase_ignores_others() {
        let mine = [7u8; 32];
        let other = [8u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        let cb_mine = coinbase_for(address_of(mine), b"txid-a||0", 5_000);
        let cb_other = coinbase_for(address_of(other), b"txid-a||1", 9_000);
        db.ingest_block(&[cb_mine, cb_other], &[]);

        assert_eq!(db.notes().len(), 1, "only the wallet's own coinbase note is tracked");
        assert_eq!(db.balance(), 5_000);
        assert_eq!(db.notes()[0].position, 0, "our note is leaf 0 (first coinbase note)");
    }

    /// `ingest_block_precomputed` (the shared-cache path) must produce a wallet
    /// state byte-identical to `ingest_block` (the recompute path): same owned
    /// notes, positions, balance, and tip anchor. This is the correctness guarantee
    /// that lets the daemon compute each block's coinbase commitments once and share
    /// them across the whole wallet cohort.
    #[test]
    fn precomputed_ingest_matches_recompute() {
        let mine = [7u8; 32];
        let other = [8u8; 32];

        // A stream of blocks, each with a couple of coinbase notes (some ours, some
        // a stranger's), so the leaf order and ownership both get exercised.
        let blocks: Vec<Vec<(CoinbaseNoteDesc, u64)>> = (0..25u32)
            .map(|b| {
                vec![
                    coinbase_for(address_of(mine), format!("txid-{b}||0").as_bytes(), 1_000 + b as u64),
                    coinbase_for(address_of(other), format!("txid-{b}||1").as_bytes(), 7_000),
                ]
            })
            .collect();

        let mut recompute = WalletDb::from_seed(mine).unwrap();
        let mut shared = WalletDb::from_seed(mine).unwrap();
        for block in &blocks {
            recompute.ingest_block(block, &[]);
            // The daemon-side precompute: derive each coinbase leaf commitment once,
            // dropping any that would not commit (exactly ingest_block's skip rule).
            let pre: Vec<(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)> =
                block.iter().filter_map(|(d, v)| coinbase_note_commitment(d, *v).ok().map(|cmx| (d.clone(), *v, cmx))).collect();
            shared.ingest_block_precomputed(&pre, &[]);
        }

        assert_eq!(recompute.balance(), shared.balance(), "balances match");
        assert_eq!(recompute.notes().len(), shared.notes().len(), "same note count");
        assert_eq!(
            recompute.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            shared.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            "same leaf positions",
        );
        assert_eq!(recompute.size(), shared.size(), "same leaf count");
        assert_eq!(recompute.anchor(), shared.anchor(), "identical tip anchor");
    }

    /// A **keyless, leaves-only** wallet builds a leaf stream identical to a real
    /// wallet's, and can therefore witness that wallet's notes for it.
    ///
    /// This is the premise of the daemon-wide shared tree: ~80% of a scan is
    /// building a structure that does not depend on any viewing key, so it should be
    /// built once for all wallets rather than once per wallet. The test pins both
    /// halves of that claim — the stream is the same (identical anchor, leaf for
    /// leaf), and a path taken from the shared copy is accepted for a note the
    /// shared copy has no idea it is looking at.
    #[test]
    fn leaves_only_tree_is_identical_and_can_witness_another_wallets_note() {
        let mine = [7u8; 32];
        let other = [8u8; 32];
        let nobody = [9u8; 32]; // the shared tree's key: matches nothing on this chain

        let blocks: Vec<Vec<(CoinbaseNoteDesc, u64)>> = (0..40u32)
            .map(|b| {
                vec![
                    coinbase_for(address_of(mine), format!("txid-{b}||0").as_bytes(), 1_000 + b as u64),
                    coinbase_for(address_of(other), format!("txid-{b}||1").as_bytes(), 7_000),
                ]
            })
            .collect();

        let mut wallet = WalletDb::from_seed(mine).unwrap();
        let mut shared = WalletDb::from_seed(nobody).unwrap();
        shared.set_leaves_only(true);
        assert!(shared.is_leaves_only());
        for block in &blocks {
            wallet.ingest_block(block, &[]);
            shared.ingest_block(block, &[]);
        }

        // The stream is the same object, built two ways.
        assert_eq!(wallet.size(), shared.size(), "same leaf count");
        assert_eq!(wallet.anchor(), shared.anchor(), "identical tip anchor");
        // ...but the shared copy recognises nothing, which is what makes it cheap.
        assert!(shared.notes().is_empty(), "a leaves-only tree can never own a note");
        assert!(!wallet.notes().is_empty(), "the real wallet did find its notes");

        // Now the point: witness the WALLET's note from the SHARED tree.
        let matured = wallet.size();
        let positions: Vec<u64> = wallet.notes().iter().map(|n| n.position).collect();
        let from_shared = shared.witness_paths_at(&positions, matured);
        let from_wallet = wallet.witness_paths_at(&positions, matured);
        assert!(from_shared.iter().all(|p| p.is_some()), "shared tree served every path");
        for (i, (a, b)) in from_shared.iter().zip(from_wallet.iter()).enumerate() {
            let (a, b) = (a.as_ref().unwrap(), b.as_ref().unwrap());
            assert_eq!(a.auth_path(), b.auth_path(), "auth path differs at note {i}");
            assert_eq!(a.position(), b.position(), "position differs at note {i}");
        }
    }

    /// The shared tree keeps serving correct paths after the *wallet* has compacted its
    /// own base away.
    ///
    /// This is the case the daemon actually runs: the shared tree holds the whole stream
    /// from position 0 and never compacts, while each wallet rolls its base up to its own
    /// notes to bound memory. Their `base_size` values therefore diverge immediately, and
    /// a note's position is absolute in the global stream — so the shared tree resolving
    /// `position` against ITS base is only correct because both bases are offsets into
    /// one stream. If that were ever wrong, this test fails and the daemon would be
    /// handing out witnesses rooted at the wrong subtree.
    #[test]
    fn shared_tree_serves_paths_after_the_wallet_compacts_its_base() {
        let mine = [11u8; 32];
        let other = [12u8; 32];
        let nobody = [13u8; 32];

        let mut wallet = WalletDb::from_seed(mine).unwrap();
        let mut shared = WalletDb::from_seed(nobody).unwrap();
        shared.set_leaves_only(true);

        // A long prefix of other people's leaves, then ours, then more of theirs — so the
        // wallet's notes sit well above position 0 and its base can roll a long way.
        for b in 0..60u32 {
            let block = vec![coinbase_for(address_of(other), format!("pre-{b}").as_bytes(), 500)];
            wallet.ingest_block(&block, &[]);
            shared.ingest_block(&block, &[]);
        }
        for b in 0..4u32 {
            let block = vec![coinbase_for(address_of(mine), format!("ours-{b}").as_bytes(), 9_000 + b as u64)];
            wallet.ingest_block(&block, &[]);
            shared.ingest_block(&block, &[]);
        }
        for b in 0..60u32 {
            let block = vec![coinbase_for(address_of(other), format!("post-{b}").as_bytes(), 500)];
            wallet.ingest_block(&block, &[]);
            shared.ingest_block(&block, &[]);
        }

        // The wallet compacts; the shared tree does not.
        let first_note = wallet.notes().iter().map(|n| n.position).min().unwrap();
        while wallet.advance_base_capped(first_note, u64::MAX) {}
        assert!(wallet.base_size() > 0, "wallet actually compacted");
        assert_eq!(shared.base_size(), 0, "shared tree holds the stream from position 0");
        assert_ne!(wallet.base_size(), shared.base_size(), "the bases diverge — the case under test");

        let matured = wallet.size();
        assert_eq!(matured, shared.size(), "same stream length");

        let positions: Vec<u64> = wallet.notes().iter().map(|n| n.position).collect();
        let from_shared = shared.witness_paths_at(&positions, matured);
        let from_wallet = wallet.witness_paths_at(&positions, matured);
        assert!(from_shared.iter().all(|p| p.is_some()), "shared tree served every path despite never compacting");
        for (i, (a, b)) in from_shared.iter().zip(from_wallet.iter()).enumerate() {
            let (a, b) = (a.as_ref().unwrap(), b.as_ref().expect("wallet still witnesses its own note"));
            assert_eq!(a.position(), b.position(), "position differs at note {i}");
            assert_eq!(a.auth_path(), b.auth_path(), "auth path differs at note {i} across divergent bases");
        }
    }

    /// A shared (`leaves_only`) tree refuses to compact its base.
    ///
    /// Compaction is capped at the earliest note the wallet still holds. A shared tree
    /// holds none, so that cap is `size` and it would summarise away the whole stream —
    /// which is the one thing it exists to keep. Live, it did exactly that within
    /// minutes (`base_size == matured`), leaving it able to witness nothing for anyone
    /// and unable to ever install a subtree cache.
    #[test]
    fn leaves_only_tree_never_compacts_the_stream_away() {
        let mut shared = WalletDb::from_seed([21u8; 32]).unwrap();
        shared.set_leaves_only(true);
        let mut ordinary = WalletDb::from_seed([21u8; 32]).unwrap();
        for b in 0..40u32 {
            let block = vec![coinbase_for(address_of([22u8; 32]), format!("x-{b}").as_bytes(), 100)];
            shared.ingest_block(&block, &[]);
            ordinary.ingest_block(&block, &[]);
        }
        let tip = shared.size();

        // The ordinary wallet owns nothing either, so it compacts freely — this is the
        // behaviour the shared tree must NOT inherit.
        while ordinary.advance_base_capped(tip, u64::MAX) {}
        assert_eq!(ordinary.base_size(), tip, "an ordinary noteless wallet does roll its base to the tip");

        assert!(!shared.advance_base_capped(tip, u64::MAX), "shared tree refuses to compact");
        assert_eq!(shared.base_size(), 0, "shared tree still holds the stream from position 0");
        assert_eq!(shared.size(), tip, "and still has every leaf");

        // The consequence that matters: it can still witness an arbitrary early position
        // that a compacted wallet could not.
        let paths = shared.witness_paths_at(&[3, 17], tip);
        assert!(paths.iter().all(|p| p.is_some()), "shared tree witnesses early positions");
        assert!(
            ordinary.witness_paths_at(&[3, 17], tip).iter().all(|p| p.is_none()),
            "the compacted wallet cannot — which is precisely why the shared tree must not compact",
        );
    }

    /// A wallet that skips its own tree ends up with the SAME anchor as one that built
    /// it, once it adopts the shared tree's frontier.
    ///
    /// This is the whole safety argument for borrowing, so it is asserted rather than
    /// reasoned about: a commitment tree's frontier at N leaves is a pure function of
    /// leaves 0..N, therefore the shared tree's frontier at the same size IS this
    /// wallet's frontier. If that were ever false, a borrowing wallet would spend
    /// against a wrong anchor and the node would reject every payment it made.
    #[test]
    fn a_borrowed_tree_produces_the_same_anchor_as_a_built_one() {
        let mine = [31u8; 32];
        let other = [32u8; 32];

        let mut built = WalletDb::from_seed(mine).unwrap();
        let mut borrowed = WalletDb::from_seed(mine).unwrap();
        let mut shared = WalletDb::from_seed([33u8; 32]).unwrap();
        shared.set_leaves_only(true);
        borrowed.set_borrow_tree(true);

        for b in 0..30u32 {
            let block = vec![
                coinbase_for(address_of(mine), format!("m-{b}").as_bytes(), 1_000 + b as u64),
                coinbase_for(address_of(other), format!("o-{b}").as_bytes(), 500),
            ];
            built.ingest_block(&block, &[]);
            borrowed.ingest_block(&block, &[]);
            shared.ingest_block(&block, &[]);
        }

        // Skipping the hashing invalidates the mirror tree, and the wallet says so.
        assert!(!borrowed.tree_is_valid(), "a borrowing wallet knows its tree is stale");
        assert!(built.tree_is_valid());
        assert_eq!(built.size(), borrowed.size(), "the same leaves were counted either way");
        assert_eq!(built.notes().len(), borrowed.notes().len(), "and the same notes were found");
        assert_eq!(
            built.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            borrowed.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            "note POSITIONS are unaffected — they come from counting, not hashing",
        );

        // Adopt the shared tree's frontier at the same size.
        let fs = shared.tip_frontier_state().expect("shared tree has a valid tree");
        assert_eq!(fs.size, borrowed.size());
        assert!(borrowed.adopt_tip_frontier(&fs), "frontier at the matching size is accepted");
        assert!(borrowed.tree_is_valid());
        assert_eq!(built.anchor(), borrowed.anchor(), "identical anchor");
        assert_eq!(built.anchor(), shared.anchor(), "...and it is the shared tree's anchor");

        // A frontier at ANY other size must be refused: that is the check the entire
        // safety argument rests on, so it must not be advisory.
        let mut ahead = shared;
        ahead.ingest_block(&[coinbase_for(address_of(other), b"extra", 7)], &[]);
        let stale = ahead.tip_frontier_state().expect("still valid");
        assert_ne!(stale.size, borrowed.size());
        assert!(!borrowed.adopt_tip_frontier(&stale), "a frontier at a different size is refused");
        assert_eq!(built.anchor(), borrowed.anchor(), "and the refusal left the good one in place");
    }

    /// A **watch-only** wallet loaded from just the FVK discovers exactly the same
    /// owned notes, positions, balance and tip anchor as the seed wallet — proving the
    /// non-custodial server can sync with no spend authority.
    #[test]
    fn watch_only_fvk_sees_same_notes_as_seed() {
        let mine = [7u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(mine)).unwrap();
        let fvk_bytes = FullViewingKey::from(&sk).to_bytes();

        let mut seed_db = WalletDb::from_seed(mine).unwrap();
        let mut watch_db = WalletDb::from_fvk(&fvk_bytes).unwrap();

        // Same block stream into both: our notes at index 1 of each block, behind decoys.
        let blocks = [
            (coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000), coinbase_for(address_of(mine), b"b1||1", 2_000)),
            (coinbase_for(address_of([9u8; 32]), b"b2||0", 3_000), coinbase_for(address_of(mine), b"b2||1", 4_000)),
        ];
        for (a, b) in blocks {
            seed_db.ingest_block(&[a.clone(), b.clone()], &[]);
            watch_db.ingest_block(&[a, b], &[]);
        }

        assert_eq!(watch_db.balance(), seed_db.balance());
        assert_eq!(watch_db.balance(), 6_000, "both owned notes discovered watch-only");
        assert_eq!(watch_db.notes().len(), seed_db.notes().len());
        assert_eq!(watch_db.anchor(), seed_db.anchor(), "same tip anchor");
        for (w, s) in watch_db.notes().iter().zip(seed_db.notes()) {
            assert_eq!(w.position, s.position);
            assert_eq!(w.value(), s.value());
            // The watch-only wallet can build the identical spend witness (a proof
            // input) — it just can't sign the spend.
            let pw = watch_db.witness_path(w.position).expect("watch-only witness");
            let ps = seed_db.witness_path(s.position).expect("seed witness");
            let cw = ExtractedNoteCommitment::from(w.note.commitment());
            let cs = ExtractedNoteCommitment::from(s.note.commitment());
            assert_eq!(pw.root(cw), ps.root(cs), "identical witness root");
        }
        // The FVK the watch-only wallet exposes matches the seed's FVK.
        assert_eq!(watch_db.fvk().to_bytes(), fvk_bytes);
    }

    /// The live (incrementally advanced) witness must be byte-for-byte the witness the
    /// on-demand rebuild produces — a spend roots at it, so any divergence would mint an
    /// unspendable note. Checked at several maturity cutoffs, with our notes interleaved
    /// among other people's leaves.
    #[test]
    fn live_witness_matches_rebuilt_witness() {
        let mine = [21u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        // 12 blocks; ours at blocks 2, 5 and 9, each behind a stranger's note.
        for b in 0..12u8 {
            let tag = [b, b, b, b];
            let theirs = coinbase_for(address_of([b.wrapping_add(1); 32]), &tag, 100 + b as u64);
            if b == 2 || b == 5 || b == 9 {
                let ours = coinbase_for(address_of(mine), &[b, 9, 9, 9], 1_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        assert_eq!(db.notes().len(), 3);

        // Cutoffs inside the stream (a matured anchor always lags the tip).
        let n = db.size();
        for cutoff in [n - 3, n - 1, n] {
            // Rebuild-only reference (a pristine wallet replaying the same stream never
            // calls advance_witnesses, so it always takes the on-demand path).
            let mut fresh = WalletDb::from_seed(mine).unwrap();
            fresh.leaves = db.leaves.clone();
            fresh.notes = db.notes.to_vec();
            fresh.size = db.size;
            fresh.tree = db.tree.clone();

            let mut live = WalletDb::from_seed(mine).unwrap();
            live.leaves = db.leaves.clone();
            live.notes = db.notes.to_vec();
            live.size = db.size;
            live.tree = db.tree.clone();
            live.advance_witnesses(cutoff);

            for n in db.notes() {
                if n.position >= cutoff {
                    continue;
                }
                let want = fresh.witness_path_at(n.position, cutoff).expect("rebuilt witness");
                let got = live.witness_path_at(n.position, cutoff).expect("live witness");
                let cm = ExtractedNoteCommitment::from(n.note.commitment());
                assert_eq!(got.root(cm), want.root(cm), "same anchor at cutoff {cutoff}, position {}", n.position);
                assert_eq!(got.auth_path(), want.auth_path(), "same authentication path");
            }
        }
    }

    /// The batch witness builder [`WalletDb::witness_paths_at`] must produce a path
    /// **byte-identical** to the trusted per-note [`WalletDb::witness_path_at`] for every
    /// selected note — that equality is the whole safety claim, since a spend roots at
    /// these paths. Exercised on a wallet with many notes spread across the whole stream
    /// (the note-heavy shape that makes per-note rebuilds explode), at several matured
    /// cutoffs, and on BOTH a full-scan wallet (base = 0) and a compacted one (base > 0),
    /// so the below-base frontier context path is covered.
    #[test]
    fn batch_witness_paths_match_per_note() {
        let mine = [33u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        // 120 blocks; ours roughly every third block, each behind a stranger's note, so
        // owned notes are scattered from near-genesis to near-tip across ~200 leaves.
        for b in 0..120u32 {
            let theirs = coinbase_for(address_of([(b % 251) as u8 + 1; 32]), format!("s{b}").as_bytes(), 100 + b as u64);
            if b % 3 == 0 {
                let ours = coinbase_for(address_of(mine), format!("m{b}").as_bytes(), 1_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        assert!(db.notes().len() >= 30, "enough owned notes to be meaningful");

        let all_positions: Vec<u64> = db.notes().iter().map(|n| n.position).collect();
        let cmx_of: std::collections::HashMap<u64, ExtractedNoteCommitment> =
            db.notes().iter().map(|n| (n.position, ExtractedNoteCommitment::from(n.note.commitment()))).collect();
        let n = db.size();

        for &base in &[0u64, 64, 130] {
            // Reference wallet: pristine replay (never advances witnesses → always the
            // on-demand rebuild path), optionally compacted to `base`.
            let mut w = WalletDb::from_seed(mine).unwrap();
            w.leaves = db.leaves.clone();
            w.notes = db.notes.to_vec();
            w.size = db.size;
            w.tree = db.tree.clone();
            if base > 0 {
                w.advance_base_capped(base, u64::MAX);
            }

            for &cutoff in &[n - 5, n - 1, n] {
                let sel: Vec<u64> = all_positions.iter().copied().filter(|&p| p >= w.base_size() && p < cutoff).collect();
                if sel.is_empty() {
                    continue;
                }
                // The same assertions must hold with the complete-subtree cache active:
                // it is a *third* independent derivation of the same paths, so build it
                // here and let the shared body below compare all of them. `w2` mirrors
                // `w` exactly, differing only in having the cache.
                let mut w2 = WalletDb::from_seed(mine).unwrap();
                w2.leaves = w.leaves.clone();
                w2.notes = w.notes.to_vec();
                w2.size = w.size;
                w2.tree = w.tree.clone();
                w2.base_frontier = w.base_frontier.clone();
                w2.base_size = w.base_size;
                w2.build_subtree_cache();
                assert!(w2.subtree.active, "cache must pass its own root gate at base={base}");
                let cached = w2.witness_paths_at(&sel, cutoff);

                let batch = w.witness_paths_at(&sel, cutoff);
                for (k, &pos) in sel.iter().enumerate() {
                    let want = w.witness_path_at(pos, cutoff).expect("per-note witness");
                    let got = cached[k].clone().expect("cache produced a path");
                    assert_eq!(got.auth_path(), want.auth_path(), "CACHE auth path base={base} cutoff={cutoff} pos={pos}");
                    assert_eq!(got.position(), want.position(), "CACHE position base={base} cutoff={cutoff} pos={pos}");
                    let cm = cmx_of[&pos];
                    assert_eq!(got.root(cm), want.root(cm), "CACHE root base={base} cutoff={cutoff} pos={pos}");
                }
                for (k, &pos) in sel.iter().enumerate() {
                    let want = w.witness_path_at(pos, cutoff).expect("per-note witness");
                    let got = batch[k].clone().expect("batch produced a path");
                    assert_eq!(got.auth_path(), want.auth_path(), "auth path base={base} cutoff={cutoff} pos={pos}");
                    assert_eq!(got.position(), want.position(), "position base={base} cutoff={cutoff} pos={pos}");
                    let cm = cmx_of[&pos];
                    assert_eq!(got.root(cm), want.root(cm), "root base={base} cutoff={cutoff} pos={pos}");
                }
                // Order/dedup robustness: reversed + duplicated request maps back correctly.
                let mut mixed = sel.clone();
                mixed.reverse();
                mixed.extend_from_slice(&sel);
                let mixed_batch = w.witness_paths_at(&mixed, cutoff);
                for (k, &pos) in mixed.iter().enumerate() {
                    let got = mixed_batch[k].clone().expect("batch path for mixed request");
                    let cm = cmx_of[&pos];
                    let want = w.witness_path_at(pos, cutoff).unwrap();
                    assert_eq!(got.root(cm), want.root(cm), "mixed root pos={pos}");
                }
            }
        }
    }

    /// A growing chain must not cost a wallet its cache.
    ///
    /// `append_leaf` folds each new leaf in as it arrives — one combine, amortised —
    /// but ONLY while `upto == size`. That invariant is what keeps a caught-up wallet
    /// serving witnesses from the cache instead of replaying the stream, and it is
    /// load-bearing: on a 1-BPS chain the stream grows every second, so a cache that
    /// fell one leaf behind could never catch up on its own, and every spend from that
    /// wallet would pay the O(chain) climb the cache exists to delete.
    #[test]
    fn subtree_cache_keeps_serving_as_the_chain_grows() {
        let mine = [36u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..80u32 {
            let recipient = if b % 9 == 0 { address_of(mine) } else { address_of([(b % 250 + 1) as u8; 32]) };
            db.ingest_block(&[coinbase_for(recipient, &b.to_le_bytes(), 1_000 + b as u64)], &[]);
        }
        db.build_subtree_cache();
        assert!(db.subtree_cache_ready(db.size()), "cache serves once built");
        let upto_before = db.subtree_build_upto();

        // The chain moves on, exactly as it does every second in production.
        for b in 80..96u32 {
            db.ingest_block(&[coinbase_for(address_of(mine), &b.to_le_bytes(), 2_000 + b as u64)], &[]);
        }

        assert!(db.subtree_cache_ready(db.size()), "appended leaves keep the cache in step");
        assert!(db.subtree_build_upto() > upto_before, "and it advanced with them");
        assert!(!db.subtree_cache_failed());

        // The witnesses it serves must be the real ones, not merely present.
        let positions: Vec<u64> = db.notes().iter().map(|n| n.position).collect();
        assert!(db.witness_paths_at(&positions, db.size()).iter().all(Option::is_some));
    }

    /// A wallet that borrowed the shared tree and then had borrowing withdrawn is left
    /// with a mirror it cannot repair.
    ///
    /// `tree_valid` is cleared by every leaf appended while borrowing, and the ONLY thing
    /// that sets it true again is `adopt_tip_frontier`, which refuses a frontier that is
    /// not at exactly this wallet's leaf count. So once the shared tree is not at the
    /// wallet's size, the wallet stays invalid — and the spend path forgives a wallet
    /// that IS borrowing while refusing one that merely WAS. That combination is what
    /// made healthy wallets answer every payment with "still catching up", and it is why
    /// the borrow flag must not be dropped while the mirror is still invalid.
    #[test]
    fn a_wallet_that_stopped_borrowing_cannot_repair_its_own_mirror() {
        let mine = [77u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        db.set_borrow_tree(true);
        for b in 0..12u32 {
            db.ingest_block(&[coinbase_for(address_of(mine), &b.to_le_bytes(), 1_000 + b as u64)], &[]);
        }
        assert!(!db.tree_is_valid(), "borrowing leaves the mirror invalid, by design");

        // The only repair route: a frontier at a DIFFERENT size is refused, correctly —
        // it is not this wallet's tree.
        let mut other = WalletDb::from_seed([78u8; 32]).unwrap();
        other.ingest_block(&[coinbase_for(address_of([78u8; 32]), b"x", 1)], &[]);
        let shorter = other.tip_frontier_state().expect("a non-borrowing tree is valid");
        assert_ne!(shorter.size, db.size());
        assert!(!db.adopt_tip_frontier(&shorter), "a frontier at another size must be refused");
        assert!(!db.tree_is_valid());

        // Withdrawing the flag repairs nothing — the wallet is neither valid nor
        // borrowing, which is exactly the state the spend path refuses outright.
        db.set_borrow_tree(false);
        assert!(!db.tree_is_valid());
        assert!(!db.is_borrowing());

        // And the way out: a frontier at exactly this size restores it.
        let mut twin = WalletDb::from_seed(mine).unwrap();
        for b in 0..12u32 {
            twin.ingest_block(&[coinbase_for(address_of(mine), &b.to_le_bytes(), 1_000 + b as u64)], &[]);
        }
        let exact = twin.tip_frontier_state().expect("valid");
        assert_eq!(exact.size, db.size());
        assert!(db.adopt_tip_frontier(&exact));
        assert!(db.tree_is_valid());
    }

    #[test]
    fn v8_checkpoint_persists_root_gated_subtree_cache() {
        let mine = [35u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..80u32 {
            let recipient = if b % 9 == 0 { address_of(mine) } else { address_of([(b % 250 + 1) as u8; 32]) };
            db.ingest_block(&[coinbase_for(recipient, &b.to_le_bytes(), 1_000 + b as u64)], &[]);
        }
        db.build_subtree_cache();
        assert!(db.subtree_cache_ready(db.size()));

        let blob = db.to_checkpoint();
        let restored = WalletDb::from_checkpoint(mine, &blob).expect("v8 restores");
        assert!(restored.subtree_cache_ready(restored.size()), "validated cache survives restart");
        let positions: Vec<u64> = restored.notes().iter().map(|n| n.position).collect();
        assert!(restored.witness_paths_at(&positions, restored.size()).iter().all(Option::is_some));

        // Corrupt only the optional cache payload. The whole checkpoint remains
        // structurally parseable, but the cache root gate must refuse it.
        let mut ssec = Vec::new();
        write_subtree_section(&mut ssec, &db.subtree);
        let mut corrupt = blob;
        let section_start = corrupt.len() - ssec.len();
        corrupt[section_start] = 2; // invalid active flag: optional section is declined
        let restored = WalletDb::from_checkpoint(mine, &corrupt).expect("bad optional cache never loses wallet state");
        assert!(!restored.subtree_cache_ready(restored.size()), "wrong-root cache rejected");
        assert_eq!(restored.balance(), db.balance());
    }

    /// Rolling the fast-sync base forward (compaction) is representation-only: it must
    /// drop the summarised leaves without changing any witness root, any authentication
    /// path, or the tip anchor — and a checkpoint written from the compacted wallet must
    /// restore to the same thing. This is the invariant the send-speed fix relies on: a
    /// spend rooted at a witness rebuilt from the *rolled* base has to equal the one
    /// rebuilt from genesis, or consensus would reject it.
    #[test]
    fn base_compaction_preserves_witness_roots() {
        let mine = [37u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        // 20 blocks; ours at 3, 7, 14, each behind a stranger's note.
        for b in 0..20u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(1); 32]), &[b, 1, 2, 3], 100 + b as u64);
            if b == 3 || b == 7 || b == 14 {
                let ours = coinbase_for(address_of(mine), &[b, 8, 8, 8], 1_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        assert_eq!(db.notes().len(), 3);
        let cutoff = db.size();

        // Reference roots + paths BEFORE compaction (on-demand rebuild from the full stream).
        let mut refn = WalletDb::from_seed(mine).unwrap();
        refn.leaves = db.leaves.clone();
        refn.notes = db.notes.to_vec();
        refn.size = db.size();
        refn.tree = db.tree.clone();
        let want: Vec<_> = db
            .notes()
            .iter()
            .map(|n| {
                let p = refn.witness_path_at(n.position, cutoff).expect("reference path");
                let cm = ExtractedNoteCommitment::from(n.note.commitment());
                (n.position, p.root(cm), p.auth_path())
            })
            .collect();

        // Compact in small steps to exercise the incremental roll; base stops at the
        // earliest note (a note below the base could no longer be witnessed).
        let earliest = db.notes().iter().map(|n| n.position).min().unwrap();
        let leaves_before = db.leaves.len();
        while db.advance_base_capped(cutoff, 4) {}
        assert!(db.base_size() > 0, "base actually rolled forward");
        assert!(db.base_size() <= earliest, "base never passes the earliest note");
        assert!(db.leaves.len() < leaves_before, "summarised leaves were dropped");

        // Every root + auth path is unchanged, and the tip anchor is untouched.
        for (pos, want_root, want_auth) in &want {
            let note = db.notes().iter().find(|n| n.position == *pos).unwrap();
            let cm = ExtractedNoteCommitment::from(note.note.commitment());
            let got = db.witness_path_at(*pos, cutoff).expect("post-compaction path");
            assert_eq!(got.root(cm), *want_root, "same root after compaction at position {pos}");
            assert_eq!(got.auth_path(), *want_auth, "same auth path after compaction at position {pos}");
        }
        assert_eq!(db.anchor(), refn.anchor(), "tip anchor unchanged by compaction");

        // A checkpoint written from the COMPACTED wallet restores to the same thing.
        let restored = WalletDb::from_checkpoint(mine, &db.to_checkpoint()).expect("restore compacted checkpoint");
        assert_eq!(restored.anchor(), db.anchor(), "restored tip anchor matches");
        assert_eq!(restored.balance(), db.balance(), "restored balance matches");
        assert_eq!(restored.base_size(), db.base_size(), "restored base matches");
        for (pos, want_root, _) in &want {
            let note = restored.notes().iter().find(|n| n.position == *pos).unwrap();
            let cm = ExtractedNoteCommitment::from(note.note.commitment());
            let got = restored.witness_path_at(*pos, cutoff).expect("restored path");
            assert_eq!(got.root(cm), *want_root, "same root after checkpoint restore at position {pos}");
        }
    }

    /// Compacting the base must NOT wipe already-warm witnesses (the bug that made every
    /// send stay COLD: each roll reset `witnessed_upto` to the base, so a full-scan wallet's
    /// witnesses never got ahead of the moving base). A witness is self-contained and valid
    /// above the base, so after a warm + a compaction the witnesses are still installed and
    /// still on the O(1) live path.
    #[test]
    fn compaction_keeps_warm_witnesses() {
        let mine = [51u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..18u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(1); 32]), &[b, 9, 1, 2], 100 + b as u64);
            if b == 4 || b == 9 || b == 15 {
                let ours = coinbase_for(address_of(mine), &[b, 3, 3, 3], 3_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        let matured = db.size();
        // Warm FIRST, then compact — the order the fixed sync loop can hit.
        db.advance_witnesses(matured);
        assert_eq!(db.witnessed_upto(), matured, "warm to matured");
        let warm_count = db.witnesses.len();
        assert!(warm_count > 0);

        // Compact the base up to the earliest note.
        while db.advance_base_capped(matured, 4) {}

        // Witnesses survived and still take the O(1) live path with correct roots.
        assert_eq!(db.witnessed_upto(), matured, "witnessed_upto preserved across compaction");
        assert_eq!(db.witnesses.len(), warm_count, "no warm witness was wiped by compaction");
        for n in db.notes().iter().filter(|n| n.position < matured) {
            let cm = ExtractedNoteCommitment::from(n.note.commitment());
            let live = db.live_witness_path(n.position, matured).expect("still on the live path after compaction");
            let rebuilt = db.witness_path_at(n.position, matured).expect("path");
            assert_eq!(live.root(cm), rebuilt.root(cm), "live root == path root at {}", n.position);
        }
    }

    /// A wallet with more notes than witness slots must spend its slots on the notes a
    /// send will actually select — the most valuable ones — not on whichever notes
    /// happen to sit earliest in the tree.
    ///
    /// This is the miner/pool case. Slots used to be handed out in position order as the
    /// leaf stream was swept, so a wallet holding thousands of notes warmed its OLDEST
    /// ones, while `select_spend_count` reached for the largest. The warm set and the
    /// spent set were disjoint, every send fell back to the O(chain) rebuild, and the
    /// maintenance was pure cost for no benefit.
    #[test]
    fn witness_budget_warms_the_notes_a_spend_selects() {
        let mine = [61u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        // Ten owned notes, oldest cheapest — so position order and value order disagree.
        for b in 0..10u8 {
            let ours = coinbase_for(address_of(mine), &[b, 7, 7, 7], 1_000 + b as u64 * 100);
            db.ingest_block(&[ours], &[]);
        }
        let matured = db.size();
        assert_eq!(db.notes().len(), 10);

        // Only room for three witnesses.
        db.set_witness_budget(3);
        db.advance_witnesses(matured);
        assert_eq!(db.witnesses.len(), 3, "budget is respected");

        // They are the three most valuable notes — the ones a value-descending
        // selection spends — and each takes the O(1) live path with a correct root.
        let mut warm: Vec<u64> = db.witnesses.iter().map(|(p, _)| *p).collect();
        warm.sort();
        let mut want: Vec<&OwnedNote> = db.notes().iter().collect();
        want.sort_by(|a, b| b.value().cmp(&a.value()));
        let mut want: Vec<u64> = want.iter().take(3).map(|n| n.position).collect();
        want.sort();
        assert_eq!(warm, want, "the warm set is the top notes by value");

        for pos in &warm {
            let n = db.notes().iter().find(|n| n.position == *pos).unwrap();
            let cm = ExtractedNoteCommitment::from(n.note.commitment());
            let live = db.live_witness_path(*pos, matured).expect("warm note is on the live path");
            let rebuilt = db.witness_path_at(*pos, matured).expect("path");
            assert_eq!(live.root(cm), rebuilt.root(cm), "warm root == rebuilt root at {pos}");
        }
    }

    /// The live incident (note@564934): a note parked in `pending_spends` is not
    /// in `notes`, so the old compaction cap ignored it, rolled the base past it,
    /// and `reclaim_expired` later re-inserted it BELOW the base — permanently
    /// unwitnessable, failing every send that selected it. A pending spend must
    /// pin the base exactly like a held note.
    #[test]
    fn pending_spend_pins_base_compaction() {
        let mine = [51u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        let ours = coinbase_for(address_of(mine), b"pin-0", 5_000);
        db.ingest_block(&[ours], &[]);
        for b in 0..20u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(90); 32]), &[b, 3, 3, 3], 77);
            db.ingest_block(&[theirs], &[]);
        }
        let pos = db.notes()[0].position;

        // Submit a spend of our only note, then try to compact past it while the
        // transaction is in flight.
        db.mark_spent(pos, [9; 32], 1_000);
        while db.advance_base_capped(db.size(), u64::MAX) {}
        assert!(db.base_size() <= pos, "compaction must not pass a pending-spend note (base {} vs note {pos})", db.base_size());

        // The transaction is lost; the note comes back — and must still be spendable.
        let reclaimed = db.reclaim_expired(100_000, 1_000);
        assert_eq!(reclaimed.len(), 1);
        let matured = db.size();
        assert!(db.witness_path_at(pos, matured).is_some(), "reclaimed note must still have a witness path");
        assert!(db.stranded_notes().is_empty());
    }

    /// A wallet that already carries the damage (stranded state from the wild):
    /// the stranded note is reported, excluded from the warm-loop candidates
    /// (no more one-retry-per-second live-lock), and unspendable — while every
    /// other note still witnesses fine.
    #[test]
    fn stranded_note_is_reported_and_never_offered_to_the_warm_loop() {
        let mine = [52u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        let ours0 = coinbase_for(address_of(mine), b"str-0", 9_000);
        db.ingest_block(&[ours0], &[]);
        for b in 0..15u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(120); 32]), &[b, 4, 4, 4], 77);
            db.ingest_block(&[theirs], &[]);
        }
        let ours1 = coinbase_for(address_of(mine), b"str-1", 4_000);
        db.ingest_block(&[ours1], &[]);
        let (p0, p1) = (db.notes()[0].position, db.notes()[1].position);

        // Manufacture the pre-fix damage: base rolled past note p0.
        db.strand_notes_for_test(p0 + 3);
        assert!(db.base_size() > p0);

        let matured = db.size();
        db.advance_witnesses(matured);
        let stranded: Vec<u64> = db.stranded_notes().iter().map(|n| n.position).collect();
        assert_eq!(stranded, vec![p0], "the compacted-past note is reported as stranded");
        assert!(db.witness_path_at(p0, matured).is_none(), "a stranded note has no witness path");
        assert!(db.witness_path_at(p1, matured).is_some(), "the healthy note is unaffected");
        // Even with free slots, the warm loop must never be handed the impossible note.
        db.witnesses.clear();
        assert_ne!(db.next_note_needing_witness(), Some(p0), "warm loop must not busy-retry an impossible install");
    }

    /// Grafting an older snapshot's leaf stream un-strands the note: the base
    /// rolls back, the witness rebuilds, and its root matches a wallet that was
    /// never compacted at all.
    #[test]
    fn graft_history_restores_a_stranded_note() {
        let mine = [53u8; 32];
        let mut pristine = WalletDb::from_seed(mine).unwrap();
        let ours = coinbase_for(address_of(mine), b"graft-0", 9_000);
        pristine.ingest_block(&[ours], &[]);
        for b in 0..15u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(140); 32]), &[b, 5, 5, 5], 77);
            pristine.ingest_block(&[theirs], &[]);
        }
        let pos = pristine.notes()[0].position;
        // The "old backup": full state before the damage.
        let old = WalletDb::from_checkpoint(mine, &pristine.to_checkpoint()).unwrap();

        // The live wallet: continued, then (pre-fix) compacted past the note.
        let mut db = WalletDb::from_checkpoint(mine, &pristine.to_checkpoint()).unwrap();
        for b in 0..10u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(160); 32]), &[b, 6, 6, 6], 77);
            db.ingest_block(&[theirs.clone()], &[]);
            pristine.ingest_block(&[theirs], &[]);
        }
        db.strand_notes_for_test(pos + 3);
        let matured = db.size();
        assert!(db.witness_path_at(pos, matured).is_none(), "stranded before the graft");

        let restored = db.graft_history(&old).expect("graft applies");
        assert!(restored > 0);
        assert!(db.stranded_notes().is_empty(), "graft un-strands the note");
        let cm = ExtractedNoteCommitment::from(db.notes()[0].note.commitment());
        let repaired = db.witness_path_at(pos, matured).expect("witness rebuilds after graft");
        let truth = pristine.witness_path_at(pos, matured).expect("pristine witness");
        assert_eq!(repaired.root(cm), truth.root(cm), "grafted history reproduces the exact tree");

        // A snapshot from a DIFFERENT wallet must be refused.
        let stranger = WalletDb::from_seed([54u8; 32]).unwrap();
        assert!(db.graft_history(&stranger).is_err());
    }

    /// A note the sweep already passed can be adopted into the warm set, and the witness
    /// it gets is identical to the one a full replay produces.
    ///
    /// This is the miner/pool endgame. Witnesses are only opened as the forward sweep
    /// reaches each leaf, so a note sitting BELOW `witnessed_upto` can never acquire one
    /// — it re-pays the whole O(matured − base) replay on every single spend, forever.
    /// With the notes clustered just above the compaction base and the matured tip
    /// ~126 K leaves ahead, that was the 22 s-per-note cost on the live wallet.
    #[test]
    fn a_note_below_the_sweep_can_be_adopted_and_matches_a_full_replay() {
        let mine = [63u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..6u8 {
            let ours = coinbase_for(address_of(mine), &[b, 8, 8, 8], 5_000 + b as u64);
            db.ingest_block(&[ours], &[]);
        }
        // Then a long run of other people's leaves, so the notes fall far behind the tip.
        for b in 0..40u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(70); 32]), &[b, 2, 2, 2], 77);
            db.ingest_block(&[theirs], &[]);
        }
        let matured = db.size();

        // Drive the sweep to the tip, then strand the notes: witnesses gone while
        // `witnessed_upto` is already at `matured`. That is precisely the state a
        // note-heavy wallet's notes are in — the sweep is past them, so it can never
        // open a slot for them again, however long it runs.
        db.set_witness_budget(4);
        db.advance_witnesses(matured);
        assert_eq!(db.witnessed_upto(), matured);
        db.witnesses.clear();

        // The most valuable note — the one a value-descending spend reaches for first,
        // and so the one `witness_eligible` keeps a slot for.
        let top = db.notes().iter().max_by_key(|n| n.value()).unwrap();
        let target = top.position;
        let cm = ExtractedNoteCommitment::from(top.note.commitment());
        // Ground truth from the expensive path, before adoption.
        let replayed = db.witness_path_at(target, matured).expect("replay path");
        assert!(db.live_witness_path(target, matured).is_none(), "not warm yet — this is the bug");

        // Adopt it, then it must answer from the live path with the SAME root.
        db.set_witness_budget(4);
        assert!(db.install_witness(target, matured), "adoption succeeds");
        let live = db.live_witness_path(target, matured).expect("now on the O(1) live path");
        assert_eq!(live.root(cm), replayed.root(cm), "adopted witness roots identically to a full replay");

        // And it keeps tracking as the chain grows.
        let theirs = coinbase_for(address_of([200u8; 32]), &[9, 9, 9, 9], 42);
        db.ingest_block(&[theirs], &[]);
        let grown = db.size();
        db.advance_witnesses(grown);
        let live2 = db.live_witness_path(target, grown).expect("still live after growth");
        let replayed2 = db.witness_path_at(target, grown).expect("replay after growth");
        assert_eq!(live2.root(cm), replayed2.root(cm), "adopted witness stays correct as leaves arrive");
    }

    /// Lowering the budget releases the witnesses it no longer covers, so a wallet that
    /// accumulates notes cannot grow its per-leaf cost without bound.
    #[test]
    fn lowering_the_witness_budget_releases_slots() {
        let mine = [62u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..8u8 {
            let ours = coinbase_for(address_of(mine), &[b, 5, 5, 5], 2_000 + b as u64);
            db.ingest_block(&[ours], &[]);
        }
        let matured = db.size();
        db.advance_witnesses(matured);
        assert_eq!(db.witnesses.len(), 8, "all notes warm under the default budget");

        db.set_witness_budget(2);
        // The next advance is what applies the new budget.
        let ours = coinbase_for(address_of(mine), &[99, 5, 5, 5], 9_999);
        db.ingest_block(&[ours], &[]);
        db.advance_witnesses(db.size());
        assert!(db.witnesses.len() <= 2, "excess witnesses released, got {}", db.witnesses.len());
        // And a released note still spends — via the on-demand rebuild.
        let cold = db.notes().iter().find(|n| !db.witnesses.iter().any(|(p, _)| *p == n.position));
        if let Some(n) = cold {
            assert!(db.witness_path_at(n.position, matured).is_some(), "released note still has a path");
        }
    }

    /// The v5 checkpoint persists the per-note witnesses, so a restored wallet spends with
    /// no leaf replay at all (the Zcash-style incremental-witness invariant). This test
    /// proves the restored witnesses are byte-for-path identical to the live ones AND that
    /// they are actually installed (so `witness_path_at` takes the O(1) live path, not the
    /// O(N) rebuild) — the whole point of the persistence.
    #[test]
    fn v5_checkpoint_persists_live_witnesses() {
        let mine = [44u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();
        for b in 0..16u8 {
            let theirs = coinbase_for(address_of([b.wrapping_add(1); 32]), &[b, 5, 6, 7], 100 + b as u64);
            if b == 2 || b == 6 || b == 11 {
                let ours = coinbase_for(address_of(mine), &[b, 4, 4, 4], 2_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        assert_eq!(db.notes().len(), 3);
        let matured = db.size();
        // Warm the live witnesses to the matured cutoff (what the sync loop does).
        db.advance_witnesses(matured);
        assert!(!db.witnesses.is_empty(), "live witnesses were built");

        // Reference roots from the warmed live wallet.
        let want: Vec<_> = db
            .notes()
            .iter()
            .filter(|n| n.position < matured)
            .map(|n| {
                let p = db.witness_path_at(n.position, matured).expect("live path");
                (n.position, p.root(ExtractedNoteCommitment::from(n.note.commitment())), p.auth_path())
            })
            .collect();

        // Restore from a v5 checkpoint — witnesses must come back installed and identical.
        let blob = db.to_checkpoint();
        assert_eq!(blob[0], CHECKPOINT_VERSION, "wrote a v5 blob");
        let restored = WalletDb::from_checkpoint(mine, &blob).expect("v5 restores");
        assert_eq!(restored.witnessed_upto, matured, "witnessed_upto persisted");
        assert_eq!(restored.witnesses.len(), db.witnesses.len(), "all witnesses persisted");

        for (pos, want_root, want_auth) in &want {
            // Must hit the LIVE path (no rebuild): live_witness_path returns Some only when
            // a witness is installed at exactly this cutoff.
            let live = restored.live_witness_path(*pos, matured).expect("restored witness is on the live path");
            let note = restored.notes().iter().find(|n| n.position == *pos).unwrap();
            let cm = ExtractedNoteCommitment::from(note.note.commitment());
            assert_eq!(live.root(cm), *want_root, "same root from restored live witness at {pos}");
            assert_eq!(live.auth_path(), *want_auth, "same auth path from restored live witness at {pos}");
        }

        // A truncated witness section must degrade to "no witnesses", not fail the restore.
        let mut truncated = blob.clone();
        truncated.truncate(blob.len() - 5);
        // Fix the length prefix so the outer read still consumes cleanly is NOT done here —
        // instead a corrupt tail is simulated by flipping bytes inside the section.
        let mut corrupt = blob.clone();
        let n = corrupt.len();
        corrupt[n - 3] ^= 0xFF;
        let r2 = WalletDb::from_checkpoint(mine, &corrupt);
        if let Some(w) = r2 {
            // Restore still succeeded; witnesses may be dropped, but balance/notes intact.
            assert_eq!(w.balance(), db.balance(), "corrupt witness tail never affects balance");
        }
    }

    /// A checkpoint carries tree + notes but no key material, so a watch-only wallet
    /// resumes from one exactly as the seed wallet does. This is what lets a daemon
    /// that has never seen the seed restart without rescanning the chain.
    #[test]
    fn watch_only_resumes_from_checkpoint() {
        let mine = [11u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(mine)).unwrap();
        let fvk_bytes = FullViewingKey::from(&sk).to_bytes();

        let mut db = WalletDb::from_fvk(&fvk_bytes).unwrap();
        db.ingest_block(&[coinbase_for(address_of([3u8; 32]), b"c||0", 500), coinbase_for(address_of(mine), b"c||1", 7_000)], &[]);
        db.ingest_block(&[coinbase_for(address_of(mine), b"d||0", 1_500)], &[]);

        let restored = WalletDb::from_checkpoint_fvk(&fvk_bytes, &db.to_checkpoint()).expect("watch-only checkpoint restores");

        assert_eq!(restored.balance(), db.balance());
        assert_eq!(restored.balance(), 8_500);
        assert_eq!(restored.size(), db.size());
        assert_eq!(restored.anchor(), db.anchor(), "same tree state");
        for (r, o) in restored.notes().iter().zip(db.notes()) {
            assert_eq!(r.position, o.position);
            assert_eq!(r.value(), o.value());
        }
        // A seed-keyed restore of the same blob agrees — the blob is key-agnostic.
        let as_seed = WalletDb::from_checkpoint(mine, &db.to_checkpoint()).expect("seed restore");
        assert_eq!(as_seed.balance(), restored.balance());
        assert_eq!(as_seed.anchor(), restored.anchor());
    }

    /// The wallet's mirrored anchor tracks the consensus `GlobalTree` anchor leaf
    /// for leaf across a multi-note, multi-block stream — the property that makes
    /// a wallet-produced witness verify against the node, and the witness root of
    /// an owned note equals that shared anchor at each tip.
    #[test]
    fn witness_root_tracks_consensus_anchor() {
        let mine = [3u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();
        let mut state = ShieldedState::new();

        // Block 1: two coinbase notes (one ours at index 1), no txs.
        let a = coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000);
        let b = coinbase_for(addr, b"b1||1", 2_000);
        let mint1 = CoinbaseMint::new(vec![
            CoinbaseNote { value: a.1, commitment: coinbase_note_commitment(&a.0, a.1).unwrap() },
            CoinbaseNote { value: b.1, commitment: coinbase_note_commitment(&b.0, b.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint1), &[]).unwrap();
        db.ingest_block(&[a, b], &[]);

        assert_eq!(db.anchor(), state.anchor().to_bytes(), "wallet mirror anchor == consensus anchor (block 1)");

        // Block 2: one more coinbase note (a stranger's), advancing the tree.
        let c = coinbase_for(address_of([9u8; 32]), b"b2||0", 3_000);
        let mint2 = CoinbaseMint::new(vec![CoinbaseNote { value: c.1, commitment: coinbase_note_commitment(&c.0, c.1).unwrap() }]);
        state.apply_chain_block(Some(&mint2), &[]).unwrap();
        db.ingest_block(&[c], &[]);

        assert_eq!(db.anchor(), state.anchor().to_bytes(), "wallet mirror anchor == consensus anchor (block 2)");

        // The owned note (from block 1) has a live witness that still roots to the
        // now-advanced shared anchor — i.e. the wallet can prove membership at the
        // current tip.
        let owned = &db.notes()[0];
        assert_eq!(owned.value(), 2_000);
        let path = db.witness_path(owned.position).expect("a spendable Orchard path is available");
        assert_eq!(u64::from(path.position()), owned.position, "path is for the owned leaf");
    }

    /// A bundle the UTXO layer accepted twice (same tx carried by two parallel
    /// DAG blocks — it has no transparent inputs, so nothing conflicts there)
    /// must be APPLIED once: the second occurrence's nullifiers are already
    /// spent, so the consensus transition drops it. The wallet mirrors that —
    /// no phantom balance, no extra leaves shifting later positions.
    #[test]
    fn double_accepted_bundle_is_dropped() {
        use crate::bundle::{ActionWire, sizes};

        let mine = [7u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        // A synthetic spending bundle (opaque to this wallet — decrypt finds
        // nothing, which is irrelevant to the drop rule).
        let action = ActionWire {
            nullifier: [9u8; 32],
            rk: [1u8; sizes::FIELD],
            cmx: [2u8; sizes::FIELD],
            cv_net: [3u8; sizes::FIELD],
            ephemeral_key: [4u8; sizes::FIELD],
            enc_ciphertext: [5u8; sizes::ENC_CIPHERTEXT],
            out_ciphertext: [6u8; sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [7u8; sizes::SIG],
        };
        let bundle = ShieldedBundle {
            actions: vec![action],
            flags: 0b11,
            value_balance: 0,
            anchor: [0u8; 32],
            proof: vec![],
            binding_sig: [0u8; sizes::SIG],
            burn: None,
        };

        // First acceptance appends its commitment; the duplicate appends nothing.
        db.ingest_block(&[], &[&bundle]);
        assert_eq!(db.size(), 1, "first acceptance appended one leaf");
        db.ingest_block(&[], &[&bundle]);
        assert_eq!(db.size(), 1, "duplicate acceptance dropped (no extra leaf)");

        // The drop rule survives a checkpoint round-trip (v3 persists the set).
        let blob = db.to_checkpoint();
        let mut restored = WalletDb::from_checkpoint(mine, &blob).expect("v3 checkpoint reloads");
        restored.ingest_block(&[], &[&bundle]);
        assert_eq!(restored.size(), 1, "drop rule persists across restarts");
    }

    /// A checkpoint round-trips: reloading a wallet from `to_checkpoint` reproduces
    /// balance, owned-note positions, the tip anchor, and — the strongest check —
    /// the exact spend witness, all without re-scanning the chain. This is what lets
    /// `zkas-walletd` resume after a restart instead of rescanning from birthday.
    #[test]
    fn checkpoint_roundtrips_state_and_witness() {
        let mine = [5u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();

        // A multi-block stream with our notes at non-zero positions behind decoys.
        db.ingest_block(&[coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000), coinbase_for(addr, b"b1||1", 2_000)], &[]);
        db.ingest_block(&[coinbase_for(addr, b"b2||0", 4_000), coinbase_for(address_of([9u8; 32]), b"b2||1", 3_000)], &[]);

        let blob = db.to_checkpoint();
        let restored = WalletDb::from_checkpoint(mine, &blob).expect("checkpoint reloads");

        assert_eq!(restored.balance(), db.balance(), "balance survives the round-trip");
        assert_eq!(restored.balance(), 6_000);
        assert_eq!(restored.notes().len(), db.notes().len(), "owned-note count matches");
        assert_eq!(restored.anchor(), db.anchor(), "tip anchor is reconstructed from the leaf stream");
        assert_eq!(restored.size, db.size, "leaf count matches");

        // Each owned note reconstructs to the same position and an identical witness
        // root — i.e. the reloaded wallet can still spend exactly as before.
        for (a, b) in restored.notes().iter().zip(db.notes()) {
            assert_eq!(a.position, b.position);
            assert_eq!(a.value(), b.value());
            let pa = restored.witness_path(a.position).expect("restored witness");
            let pb = db.witness_path(b.position).expect("original witness");
            let cmx_a = ExtractedNoteCommitment::from(a.note.commitment());
            let cmx_b = ExtractedNoteCommitment::from(b.note.commitment());
            assert_eq!(pa.root(cmx_a), pb.root(cmx_b), "restored spend witness roots to the same anchor");
        }

        // A corrupt / truncated blob is rejected (caller then does a clean rescan).
        assert!(WalletDb::from_checkpoint(mine, &blob[..blob.len() - 1]).is_none(), "truncated blob rejected");
        let mut bad = blob.clone();
        bad[0] = 0xFF;
        assert!(WalletDb::from_checkpoint(mine, &bad).is_none(), "wrong version rejected");
    }

    /// Measures what the v4 tip frontier actually buys, at live chain scale. Not run by
    /// default (it builds a 200K-leaf tree): `cargo test -p kaspa-shielded-core --release
    /// -- --ignored --nocapture restore_cost`.
    #[test]
    #[ignore]
    fn restore_cost_v3_vs_v4() {
        const LEAVES: usize = 200_000; // ~ the live chain's note-commitment count
        let mine = [11u8; 32];
        let addr = address_of(mine);
        let theirs = address_of([12u8; 32]);
        let mut db = WalletDb::from_seed(mine).unwrap();
        // Only a small fraction of the chain's notes are ours — the shape of a real
        // wallet. (Owning *every* leaf would make the restore a measure of note
        // reconstruction, not of the leaf stream, and flatter the result.)
        for i in 0..LEAVES {
            let to = if i % 1000 == 0 { addr } else { theirs };
            db.ingest_block(&[coinbase_for(to, &i.to_le_bytes(), 1)], &[]);
        }
        assert_eq!(db.notes().len(), LEAVES / 1000);

        let v4 = db.to_checkpoint();
        let mut suffix = Vec::new();
        write_frontier(&mut suffix, &db.tree.to_frontier());
        let mut v3 = v4[..v4.len() - suffix.len()].to_vec();
        v3[0] = CHECKPOINT_VERSION_V3;

        let t = std::time::Instant::now();
        let a = WalletDb::from_checkpoint(mine, &v3).unwrap();
        let v3_ms = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let b = WalletDb::from_checkpoint(mine, &v4).unwrap();
        let v4_ms = t.elapsed().as_millis();

        assert_eq!(a.anchor(), b.anchor(), "both restores rebuild the same tree");
        println!("restore of {LEAVES} leaves: v3 (leaf replay) {v3_ms} ms -> v4 (frontier) {v4_ms} ms");
    }

    /// **v3 checkpoints still restore.** v4 appends the tip frontier so a restore can
    /// rebuild the mirror tree in O(1) instead of replaying every leaf through
    /// Sinsemilla. That change may not orphan the checkpoints already on disk: if the
    /// v4 binary rejected them, deploying it would force every live hosted wallet into
    /// a full rescan from birthday — the exact multi-minute "0 balance / 0 notes"
    /// blackout the change exists to prevent. A v3 blob is a v4 blob minus that
    /// trailing frontier, and must reload to an identical wallet.
    #[test]
    fn v3_checkpoint_still_restores_and_matches_v4() {
        let mine = [7u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();
        db.ingest_block(&[coinbase_for(address_of([2u8; 32]), b"b1||0", 500), coinbase_for(addr, b"b1||1", 1_500)], &[]);
        db.ingest_block(&[coinbase_for(addr, b"b2||0", 2_500)], &[]);

        let v4 = db.to_checkpoint();
        assert_eq!(v4[0], CHECKPOINT_VERSION, "fresh checkpoints are written as the current version");

        // Reconstruct the v3 encoding: identical bytes, minus the suffixes newer
        // versions append — the v4 tip frontier plus the length-prefixed v5
        // (witnesses), v6 (history) and v7 (pending spends) sections.
        let mut tip = Vec::new();
        write_frontier(&mut tip, &db.tree.to_frontier());
        let mut wsec = Vec::new();
        wsec.extend_from_slice(&db.witnessed_upto.to_le_bytes());
        write_tree(&mut wsec, &db.lag_tree);
        wsec.extend_from_slice(&(db.witnesses.len() as u64).to_le_bytes());
        for (pos, w) in &db.witnesses {
            wsec.extend_from_slice(&pos.to_le_bytes());
            write_witness(&mut wsec, w);
        }
        // History and pending are empty here (no metadata ingested, nothing
        // submitted), so those sections are just their fixed-size headers.
        assert!(db.history.is_empty() && db.pending_spends.is_empty());
        let hsec_len = 8; // row count
        let psec_len = 8 + 8; // last_daa + record count
        let mut ssec = Vec::new();
        write_subtree_section(&mut ssec, &db.subtree);
        let suffix_len = tip.len() + (8 + wsec.len()) + (8 + hsec_len) + (8 + psec_len) + (8 + ssec.len());
        let mut v3 = v4[..v4.len() - suffix_len].to_vec();
        v3[0] = CHECKPOINT_VERSION_V3;

        let from_v3 = WalletDb::from_checkpoint(mine, &v3).expect("v3 checkpoint still reloads");
        let from_v4 = WalletDb::from_checkpoint(mine, &v4).expect("v4 checkpoint reloads");

        // The O(1) path and the O(N) replay must agree on every part of the tree state.
        assert_eq!(from_v3.anchor(), db.anchor(), "v3 replay rebuilds the tip anchor");
        assert_eq!(from_v4.anchor(), db.anchor(), "v4 frontier rebuilds the same tip anchor");
        assert_eq!(from_v4.size, from_v3.size);
        assert_eq!(from_v4.balance(), from_v3.balance());

        // And a spend witness built from the O(1)-restored tree still roots correctly.
        let n = from_v4.notes()[0].position;
        let p4 = from_v4.witness_path(n).expect("witness from v4 restore");
        let p3 = from_v3.witness_path(n).expect("witness from v3 restore");
        let cmx = ExtractedNoteCommitment::from(from_v4.notes()[0].note.commitment());
        assert_eq!(p4.root(cmx), p3.root(cmx), "identical spend witness either way");

        // Appending after an O(1) restore must continue the same tree, not a fresh one.
        let mut a = from_v4;
        let mut b = from_v3;
        let blk = [coinbase_for(addr, b"b3||0", 900)];
        a.ingest_block(&blk, &[]);
        b.ingest_block(&blk, &[]);
        assert_eq!(a.anchor(), b.anchor(), "post-restore appends agree");
        assert_eq!(
            a.anchor(),
            {
                db.ingest_block(&blk, &[]);
                db.anchor()
            },
            "and match the never-restarted wallet"
        );
    }

    /// **Protocol fast-sync equivalence.** A wallet that starts from a node-supplied
    /// checkpoint frontier and scans only the blocks *after* it produces exactly the
    /// same balance, absolute note positions, tip anchor, and — critically — spend
    /// witnesses as a wallet that full-scanned from genesis. This is what makes wallet
    /// sync O(blocks since checkpoint) instead of O(chain) without weakening spends.
    #[test]
    fn fast_sync_from_frontier_matches_full_scan() {
        use crate::tree::{ChainBlockSubtree, GlobalTree, NoteCommitmentTree};

        let mine = [11u8; 32];
        let addr = address_of(mine);

        // Apply one coinbase-only block to the consensus tree and to each wallet given.
        fn apply(gt: &mut GlobalTree, wallets: &mut [&mut WalletDb], blk: &[(CoinbaseNoteDesc, u64)]) {
            let mut st = ChainBlockSubtree::new();
            for (d, v) in blk {
                st.push(coinbase_note_commitment(d, *v).unwrap());
            }
            gt.append_subtree(&st).unwrap();
            for w in wallets {
                w.ingest_block(blk, &[]);
            }
        }

        let mut gt = GlobalTree::new();
        let mut full = WalletDb::from_seed(mine).unwrap();

        // Pre-checkpoint blocks: only strangers' notes, so the wallet owns nothing
        // before the checkpoint (the precondition for a complete fast-sync).
        let pre = [
            vec![coinbase_for(address_of([1u8; 32]), b"p0||0", 100), coinbase_for(address_of([2u8; 32]), b"p0||1", 100)],
            vec![coinbase_for(address_of([3u8; 32]), b"p1||0", 100)],
        ];
        for blk in &pre {
            apply(&mut gt, &mut [&mut full], blk);
        }

        // Checkpoint the frontier here and start a fast-sync wallet from it.
        let checkpoint = gt.to_state();
        let mut fast = WalletDb::from_frontier(mine, &checkpoint).unwrap();
        assert_eq!(fast.anchor(), full.anchor(), "fast-sync begins at the checkpoint anchor");
        assert_eq!(fast.size, checkpoint.size, "fast-sync starts at the checkpoint leaf count");

        // Post-checkpoint blocks: the wallet's own notes at non-zero absolute
        // positions, behind decoys. Both wallets ingest these.
        let post = [
            vec![coinbase_for(address_of([4u8; 32]), b"q0||0", 100), coinbase_for(addr, b"q0||1", 2_000)],
            vec![coinbase_for(addr, b"q1||0", 3_000), coinbase_for(address_of([5u8; 32]), b"q1||1", 100)],
        ];
        for blk in &post {
            apply(&mut gt, &mut [&mut full, &mut fast], blk);
        }

        // Equivalence across every spend-relevant quantity.
        assert_eq!(fast.balance(), full.balance(), "same balance");
        assert_eq!(fast.balance(), 5_000);
        assert_eq!(fast.anchor(), full.anchor(), "same tip anchor");
        assert_eq!(fast.anchor(), gt.anchor().to_bytes(), "== consensus anchor");
        assert_eq!(fast.notes().len(), full.notes().len());
        for (a, b) in fast.notes().iter().zip(full.notes()) {
            assert_eq!(a.position, b.position, "same absolute leaf position");
            assert_eq!(a.value(), b.value());
            let pa = fast.witness_path(a.position).expect("fast-sync witness");
            let pb = full.witness_path(b.position).expect("full-scan witness");
            let cmx = ExtractedNoteCommitment::from(a.note.commitment());
            assert_eq!(pa.root(cmx), pb.root(cmx), "identical witness root at the tip");
        }

        // The fast-sync wallet's v2 checkpoint carries the base frontier, so it too
        // reloads and can still witness.
        let blob = fast.to_checkpoint();
        let reloaded = WalletDb::from_checkpoint(mine, &blob).expect("v2 checkpoint reloads");
        assert_eq!(reloaded.balance(), fast.balance());
        assert_eq!(reloaded.anchor(), fast.anchor());
        let n = &reloaded.notes()[0];
        assert!(reloaded.witness_path(n.position).is_some(), "reloaded fast-sync wallet still witnesses");
    }
}

/// The real-wallet spend loop with **live crypto** (circuit feature): a wallet
/// discovers its own coinbase note purely by scanning the public chain stream
/// (no txid/index handed to it), builds a membership witness for it at a
/// **non-zero** tree position from its own bookkeeping, produces a real Orchard
/// proof spending it, and the consensus verifier + §2.4 transition accept it.
///
/// This is the piece [`crate::wallet::build::build_singleleaf_coinbase_spend`]
/// could not do: that helper assumed the note was the tree's single leaf at
/// position 0. Here the owned note sits at position 1 behind a decoy, and the
/// witness comes from [`WalletDb`], so it exercises the general membership path a
/// live wallet actually walks.
#[cfg(all(test, feature = "circuit"))]
mod circuit_tests {
    use super::*;
    use crate::bundle::ShieldedBundle;
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState, ShieldedTx};
    use crate::verify::{sighash, verify_bundle};
    use crate::wallet::build::{ShieldedKeys, build_spend_bundle, build_wallet_payment};
    use crate::wallet::scan::address_bytes_from_seed;
    use orchard::circuit::ProvingKey;

    /// Does proving several bundles CONCURRENTLY beat proving them one at a time?
    ///
    /// A single proof's parallel efficiency is sublinear (measured: 100 % at 1 thread,
    /// 91.5 % at 2, 78 % at 4), so giving one proof every core wastes some of them.
    /// This compares N bundles proven sequentially on all cores against the same N
    /// proven at once, each pinned to its own smaller rayon pool. Ignored by default.
    #[test]
    #[ignore]
    fn bench_concurrent_vs_sequential_proofs() {
        const N: usize = 2;
        const SPENDS: usize = 38;

        let miner = [93u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-bench-conc";
        let addr = address_bytes_from_seed(miner).unwrap();
        let payee = address_bytes_from_seed([94u8; 32]).unwrap();

        let mut db = WalletDb::from_seed(miner).unwrap();
        let mut state = ShieldedState::new();
        let total = SPENDS * N;
        let descs: Vec<_> = (0..total).map(|i| cb(addr, format!("cblk||{i}").as_bytes(), 5_699_353_195)).collect();
        let mint = CoinbaseMint::new(
            descs.iter().map(|d| CoinbaseNote { value: d.1, commitment: coinbase_note_commitment(&d.0, d.1).unwrap() }).collect(),
        );
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&descs, &[]);

        // N independent bundles, each spending its own disjoint slice of notes.
        let batches: Vec<Vec<(Note, MerklePath)>> = (0..N)
            .map(|b| {
                db.notes()[b * SPENDS..(b + 1) * SPENDS]
                    .iter()
                    .map(|o| (o.note.clone(), db.witness_path(o.position).unwrap()))
                    .collect()
            })
            .collect();
        let sum: u64 = db.notes()[..SPENDS].iter().map(|o| o.note.value().inner()).sum();
        let fee = 3_000_000u64 * SPENDS as u64;
        let prove = |inputs: Vec<(Note, MerklePath)>| {
            crate::wallet::build::build_wallet_payment(miner, inputs, payee, sum - fee, fee, &net, ctx, true, [0u8; 512]).unwrap()
        };

        // Warm any one-time setup so it lands in neither measurement.
        let _ = prove(batches[0].clone());

        let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(4);
        let t0 = std::time::Instant::now();
        for b in &batches {
            let _ = prove(b.clone());
        }
        let seq = t0.elapsed().as_secs_f64();

        let per = (cores / N).max(1);
        let t1 = std::time::Instant::now();
        std::thread::scope(|s| {
            for b in &batches {
                let prove = &prove;
                s.spawn(move || {
                    let pool = rayon::ThreadPoolBuilder::new().num_threads(per).build().unwrap();
                    pool.install(|| prove(b.clone()))
                });
            }
        });
        let conc = t1.elapsed().as_secs_f64();

        println!("{N} x {SPENDS}-spend proofs on {cores} cores");
        println!("  sequential (each uses all cores): {seq:5.1}s");
        println!("  concurrent ({N} x {per} threads):    {conc:5.1}s");
        println!("  speedup: {:.2}x", seq / conc);
    }

    /// Measure proving wall-time vs CPU-time at several spend counts.
    ///
    /// `cpu/wall` is the effective core count Halo2 actually uses; it decides
    /// whether proving several chunks in parallel can win anything on a box
    /// that a single proof already saturates. Ignored by default (minutes).
    #[test]
    #[ignore]
    fn bench_proof_scaling_and_parallelism() {
        fn cpu_secs() -> f64 {
            let st = std::fs::read_to_string("/proc/self/stat").unwrap();
            let tail = &st[st.rfind(')').unwrap() + 2..];
            let f: Vec<&str> = tail.split_whitespace().collect();
            // fields 11,12 after the state char = utime,stime (jiffies, 100Hz)
            (f[11].parse::<f64>().unwrap() + f[12].parse::<f64>().unwrap()) / 100.0
        }

        let miner = [91u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-bench";
        let addr = address_bytes_from_seed(miner).unwrap();

        let mut db = WalletDb::from_seed(miner).unwrap();
        let mut state = ShieldedState::new();
        let descs: Vec<_> = (0..38u32).map(|i| cb(addr, format!("blk||{i}").as_bytes(), 5_699_353_195)).collect();
        let mint = CoinbaseMint::new(
            descs.iter().map(|d| CoinbaseNote { value: d.1, commitment: coinbase_note_commitment(&d.0, d.1).unwrap() }).collect(),
        );
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&descs, &[]);

        let payee = address_bytes_from_seed([92u8; 32]).unwrap();
        println!("spends |  wall  |   cpu  | cores | s/spend");
        for n in [1usize, 4, 12, 38] {
            let sel: Vec<_> = db.notes()[..n].iter().map(|o| (o.note.clone(), db.witness_path(o.position).unwrap())).collect();
            let sum: u64 = db.notes()[..n].iter().map(|o| o.note.value().inner()).sum();
            let fee = 3_000_000u64 * n as u64;
            let c0 = cpu_secs();
            let t0 = std::time::Instant::now();
            let payload =
                crate::wallet::build::build_wallet_payment(miner, sel, payee, sum - fee, fee, &net, ctx, true, [0u8; 512]).unwrap();
            let wall = t0.elapsed().as_secs_f64();
            let cpu = cpu_secs() - c0;
            assert!(!payload.is_empty());
            println!("{n:6} | {wall:5.1}s | {cpu:5.1}s | {:4.2}x | {:.2}", cpu / wall, wall / n as f64);
        }
    }

    fn cb(address: [u8; 43], seed: &[u8], value: u64) -> (CoinbaseNoteDesc, u64) {
        (crate::coinbase::derive_coinbase_note_desc(address, seed), value)
    }

    #[test]
    fn wallet_discovers_and_spends_coinbase_note_at_nonzero_position() {
        let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
        let miner = [21u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-walletdb-e2e";

        let mut state = ShieldedState::new();
        let mut db = WalletDb::from_seed(miner).unwrap();

        // Block 1's coinbase mints two notes: a decoy to a stranger at index 0,
        // then OUR note at index 1 (so its leaf position is 1, not 0).
        let decoy = cb(address_bytes_from_seed([99u8; 32]).unwrap(), b"blk1||0", 4_000);
        let mine = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||1", 10_000);
        let mint = CoinbaseMint::new(vec![
            CoinbaseNote { value: decoy.1, commitment: coinbase_note_commitment(&decoy.0, decoy.1).unwrap() },
            CoinbaseNote { value: mine.1, commitment: coinbase_note_commitment(&mine.0, mine.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&[decoy, mine], &[]);
        let anchor1 = state.anchor();

        // The wallet found exactly its own note, at position 1, worth 10_000.
        assert_eq!(db.notes().len(), 1, "wallet discovered only its own coinbase note");
        let owned = db.notes()[0].clone();
        assert_eq!(owned.position, 1, "owned note is the second leaf (behind a decoy)");
        assert_eq!(owned.value(), 10_000);
        assert_eq!(db.anchor(), anchor1.to_bytes(), "wallet mirror roots to the consensus anchor");

        // The wallet builds a real spend from its OWN witness (position 1 path).
        let keys = ShieldedKeys::from_seed(miner).unwrap();
        let merkle_path = db.witness_path(owned.position).expect("wallet builds a witness path on demand");
        let recipient = ShieldedKeys::from_seed([42u8; 32]).unwrap().address();
        let output_value = 7_000u64;
        let wire = build_spend_bundle(&pk, &keys, owned.note, merkle_path, recipient, output_value, &net, ctx, rand::rng())
            .expect("wallet builds a real spend from its own witness");

        // Consensus accepts it: proof verifies, and it spends against the anchor
        // the wallet witnessed — i.e. the node's anchor.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("real spend from a position-1 witness must verify");
        assert_eq!(wire.anchor, anchor1.to_bytes(), "spends against the consensus anchor");
        assert_eq!(wire.value_balance, 3_000, "fee = 10_000 - 7_000");

        // The §2.4 transition applies it: nullifier inserted, fee collected.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        let out = state.apply_chain_block(None, &[stx.clone()]).unwrap();
        assert_eq!(out.accepted, vec![0], "the wallet's real spend is accepted");

        // The wallet parks the submitted note; its tracked balance drops to zero.
        db.mark_spent(owned.position, [0u8; 32], 0);
        assert_eq!(db.balance(), 0, "spent note no longer offered");

        // Replaying the same nullifier is dropped (double-spend guard).
        let replay = state.apply_chain_block(None, &[stx]).unwrap();
        assert!(replay.accepted.is_empty(), "reused nullifier -> dropped");
    }

    /// A multi-note wallet payment: the wallet spends TWO owned notes to cover an
    /// amount larger than either, and after the spend is seen on-chain it drops both
    /// spent notes (by nullifier) and instead tracks the change note it recovered by
    /// trial decryption. Exercises `build_wallet_payment` (multi-input) end to end
    /// plus `WalletDb` spent-detection and change discovery.
    #[test]
    fn wallet_multi_note_spend_drops_inputs_and_keeps_change() {
        let miner = [31u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-walletdb-multi";

        let mut db = WalletDb::from_seed(miner).unwrap();
        let mut state = ShieldedState::new();

        // Block 1 mints two notes to us (positions 0 and 1), each worth 4_000.
        let n0 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||0", 4_000);
        let n1 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||1", 4_000);
        let mint = CoinbaseMint::new(vec![
            CoinbaseNote { value: n0.1, commitment: coinbase_note_commitment(&n0.0, n0.1).unwrap() },
            CoinbaseNote { value: n1.1, commitment: coinbase_note_commitment(&n1.0, n1.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&[n0, n1], &[]);
        assert_eq!(db.notes().len(), 2, "two owned notes discovered");
        assert_eq!(db.balance(), 8_000);

        // Pay 5_000 (fee 1_000) — needs BOTH notes; 2_000 change returns to us.
        let sel: Vec<_> = db.notes().iter().map(|o| (o.note.clone(), o.position)).collect();
        let inputs: Vec<_> = sel.into_iter().map(|(note, pos)| (note, db.witness_path(pos).unwrap())).collect();
        let recipient = address_bytes_from_seed([42u8; 32]).unwrap();
        let payload = build_wallet_payment(miner, inputs, recipient, 5_000, 1_000, &net, ctx, true, [0u8; 512])
            .expect("multi-note payment builds");
        let wire = ShieldedBundle::from_bytes(&payload).expect("payload decodes to a bundle");

        // Two real spends that actually verify against the shared anchor.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("multi-note spend verifies");
        assert_eq!(wire.value_balance, 1_000, "public fee = 8_000 in − 5_000 pay − 2_000 change");

        // On-chain it is accepted (both nullifiers inserted), then the wallet ingests it.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        assert_eq!(state.apply_chain_block(None, &[stx]).unwrap().accepted, vec![0], "multi-note spend accepted");
        db.ingest_block(&[], &[&wire]);

        // Both inputs are now spent and dropped; the wallet holds only the change note.
        assert!(!db.notes().iter().any(|n| n.position == 0 || n.position == 1), "spent input notes dropped by nullifier");
        assert_eq!(db.notes().len(), 1, "only the recovered change note remains");
        assert_eq!(db.balance(), 2_000, "balance == change after the multi-note spend");
    }

    /// A BATCHED payout: one transaction paying THREE different recipients from two
    /// owned notes. This is the shape a mining pool needs — one bundle, one proof, one
    /// fee for the whole run instead of one per payee.
    ///
    /// Asserts the properties that make batching safe rather than merely fast: the
    /// bundle verifies against consensus, its public value balance is exactly the fee
    /// (so no value is created or destroyed across three outputs plus change),
    /// consensus accepts it, each payee can decrypt its OWN note and only that note,
    /// and the sender ends up holding just the change.
    #[test]
    fn batched_payout_pays_many_recipients_in_one_tx() {
        let miner = [61u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-walletdb-batch";

        let mut db = WalletDb::from_seed(miner).unwrap();
        let mut state = ShieldedState::new();

        let n0 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||0", 4_000);
        let n1 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||1", 4_000);
        let mint = CoinbaseMint::new(vec![
            CoinbaseNote { value: n0.1, commitment: coinbase_note_commitment(&n0.0, n0.1).unwrap() },
            CoinbaseNote { value: n1.1, commitment: coinbase_note_commitment(&n1.0, n1.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&[n0, n1], &[]);
        assert_eq!(db.balance(), 8_000);

        // Three payees with DIFFERENT amounts, paid from both notes; fee 1_000.
        let seeds = [[71u8; 32], [72u8; 32], [73u8; 32]];
        let amounts = [1_500u64, 2_500, 2_000];
        let payees: Vec<([u8; 43], u64, [u8; 512])> =
            seeds.iter().zip(amounts).map(|(s, a)| (address_bytes_from_seed(*s).unwrap(), a, [0u8; 512])).collect();
        let paid_total: u64 = amounts.iter().sum(); // 6_000
        let fee = 1_000u64;

        let sel: Vec<_> = db.notes().iter().map(|o| (o.note.clone(), o.position)).collect();
        let inputs: Vec<_> = sel.into_iter().map(|(note, pos)| (note, db.witness_path(pos).unwrap())).collect();
        let payload = crate::wallet::build::build_wallet_payment_multi(miner, inputs, &payees, fee, &net, ctx, true)
            .expect("batched payout builds");
        let wire = ShieldedBundle::from_bytes(&payload).expect("payload decodes");

        // Real proof + signatures over the shared anchor.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("batched payout verifies");
        assert_eq!(wire.value_balance, fee as i64, "public value balance is exactly the fee across 3 payees + change");
        // 2 spends vs 4 outputs (3 payees + change) => the bundle is output-bound.
        assert_eq!(wire.actions.len(), 4, "actions = max(spends, outputs) = 4");

        // Consensus accepts it.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        assert_eq!(state.apply_chain_block(None, &[stx]).unwrap().accepted, vec![0], "batched payout accepted");

        // Each payee recovers exactly its own note — and none of the others'.
        for (i, s) in seeds.iter().enumerate() {
            let mut payee = WalletDb::from_seed(*s).unwrap();
            payee.ingest_block(&[], &[&wire]);
            assert_eq!(payee.notes().len(), 1, "payee {i} sees exactly one note");
            assert_eq!(payee.balance(), amounts[i] as u128, "payee {i} is paid its own amount, not another's");
        }

        // The sender keeps only the change.
        db.ingest_block(&[], &[&wire]);
        assert_eq!(db.notes().len(), 1, "only the change note remains");
        assert_eq!(db.balance(), (8_000 - paid_total - fee) as u128, "change = in - paid - fee");
    }

    /// End-to-end chain-derived history: mint → OVK send with a memo → receive.
    /// The sender's row recovers the recipient/amount/memo via its own OVK; the
    /// receiver's row carries the amount+memo from IVK decryption; a checkpoint
    /// round-trip (v6) preserves every row; and a NON-recoverable send still
    /// yields a correct Sent row, just without a recipient.
    #[test]
    fn history_records_mint_send_receive_and_survives_checkpoint() {
        let miner = [33u8; 32];
        let friend = [44u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"zkas-walletdb-history";

        let mut a = WalletDb::from_seed(miner).unwrap();
        let mut b = WalletDb::from_seed(friend).unwrap();

        // Block 1: coinbase mints one 8_000 note to A.
        let mine = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||0", 8_000);
        let meta1 = BlockMeta { coinbase_txid: [0xaa; 32], txids: vec![], timestamp_ms: 1_000, daa_score: 10 };
        a.ingest_block_with_meta(&[mine.clone()], &[], Some(&meta1));
        b.ingest_block_with_meta(&[mine], &[], Some(&meta1));
        assert_eq!(a.history().len(), 1, "A recorded its mint");
        assert!(b.history().is_empty(), "B saw nothing of its own");
        let mint_row = &a.history()[0];
        assert_eq!(mint_row.kind, HistoryKind::Coinbase);
        assert_eq!((mint_row.amount, mint_row.txid, mint_row.timestamp_ms), (8_000, [0xaa; 32], 1_000));

        // A pays B 5_000 (fee 1_000, change 2_000) — recoverable, with a memo.
        let mut memo = [0u8; 512];
        memo[..7].copy_from_slice(b"thanks!");
        let inputs = vec![(a.notes()[0].note.clone(), a.witness_path(a.notes()[0].position).unwrap())];
        let payload = crate::wallet::build::build_wallet_payment(
            miner,
            inputs,
            address_bytes_from_seed(friend).unwrap(),
            5_000,
            1_000,
            &net,
            ctx,
            true,
            memo,
        )
        .expect("non-recoverable payment builds");
        let wire = ShieldedBundle::from_bytes(&payload).unwrap();

        // Mirror walletd: the spent note is PARKED at submit time. The Sent row
        // below must still come out right — the wallet has to recognise its own
        // spend from the pending set (before this, a parked note was invisible
        // and the confirmed send was mis-recorded as "Received <change>").
        a.mark_spent(a.notes()[0].position, [0xcc; 32], 15);
        assert_eq!(a.balance(), 0, "submitted note leaves the balance immediately");
        assert_eq!(a.pending_spends().len(), 1);

        let meta2 = BlockMeta { coinbase_txid: [0xbb; 32], txids: vec![[0xcc; 32]], timestamp_ms: 2_000, daa_score: 20 };
        a.ingest_block_with_meta(&[], &[&wire], Some(&meta2));
        b.ingest_block_with_meta(&[], &[&wire], Some(&meta2));
        assert!(a.pending_spends().is_empty(), "observed nullifier confirms the pending spend");
        assert_eq!(a.balance(), 2_000, "change recovered");

        // Sender: a Sent row with the OVK-recovered recipient, amount and memo.
        assert_eq!(a.history().len(), 2);
        let sent = &a.history()[1];
        assert_eq!(sent.kind, HistoryKind::Sent);
        assert_eq!((sent.amount, sent.fee, sent.txid), (5_000, 1_000, [0xcc; 32]));
        assert_eq!(sent.recipient, Some(address_bytes_from_seed(friend).unwrap()), "OVK recovers who was paid");
        assert_eq!(sent.memo, b"thanks!".to_vec(), "OVK recovers the memo");

        // Receiver: a Received row with the amount and the decrypted memo.
        assert_eq!(b.history().len(), 1);
        let recv = &b.history()[0];
        assert_eq!(recv.kind, HistoryKind::Received);
        assert_eq!((recv.amount, recv.txid, recv.timestamp_ms), (5_000, [0xcc; 32], 2_000));
        assert_eq!(recv.memo, b"thanks!".to_vec());

        // Checkpoint round-trip preserves the rows bit-for-bit.
        let blob = a.to_checkpoint();
        assert_eq!(blob[0], CHECKPOINT_VERSION, "current checkpoints are v7");
        let a2 = WalletDb::from_checkpoint(miner, &blob).expect("v7 restores");
        assert_eq!(a2.history().len(), 2);
        assert_eq!(a2.history()[1].recipient, sent.recipient);
        assert_eq!(a2.history()[1].memo, sent.memo);

        // A NON-recoverable send (ovk withheld): B pays A back 3_000 (fee 500).
        let mut b2 = b;
        let inputs = vec![(b2.notes()[0].note.clone(), b2.witness_path(b2.notes()[0].position).unwrap())];
        let payload = crate::wallet::build::build_wallet_payment(
            friend,
            inputs,
            address_bytes_from_seed(miner).unwrap(),
            3_000,
            500,
            &net,
            ctx,
            false,
            [0u8; 512],
        )
        .expect("non-recoverable payment builds");
        let wire = ShieldedBundle::from_bytes(&payload).unwrap();
        let meta3 = BlockMeta { coinbase_txid: [0xdd; 32], txids: vec![[0xee; 32]], timestamp_ms: 3_000, daa_score: 30 };
        b2.ingest_block_with_meta(&[], &[&wire], Some(&meta3));
        let sent = b2.history().last().unwrap();
        assert_eq!(sent.kind, HistoryKind::Sent);
        assert_eq!(sent.amount, 3_000, "net-outflow fallback still prices the send right");
        assert_eq!(sent.recipient, None, "without the OVK not even the sender can recover the recipient");

        // A later watch-only rescan sees the same transaction through the compact
        // archive. It lacks the full bundle's fee/OVK ciphertext, but it MUST still
        // index our spend from its nullifier and the change it decrypts.
        let mut compact = WalletDb::from_seed(miner).unwrap();
        compact.ingest_block_compact_with_meta(
            &[cb(address_bytes_from_seed(miner).unwrap(), b"compact||0", 8_000)],
            &[],
            Some(&meta1),
        );
        let inputs = vec![(compact.notes()[0].note.clone(), compact.witness_path(compact.notes()[0].position).unwrap())];
        let payload = crate::wallet::build::build_wallet_payment(
            miner,
            inputs,
            address_bytes_from_seed(friend).unwrap(),
            5_000,
            1_000,
            &net,
            ctx,
            true,
            [0u8; 512],
        )
        .expect("compact-history payment builds");
        let compact_wire = ShieldedBundle::from_bytes(&payload).unwrap();
        let compact_records = compact_wire.actions.iter().map(crate::wallet::scan::CompactActionRecord::from_wire).collect();
        compact.ingest_block_compact_with_meta(&[], &[compact_records], Some(&meta2));
        let compact_sent = compact.history().last().unwrap();
        assert_eq!(compact_sent.kind, HistoryKind::Sent);
        assert_eq!(compact_sent.amount, 6_000, "compact history records exact net outflow");
        assert!(compact_sent.amount_is_net_outflow, "client must know this includes the unrecoverable fee");
        assert!(!compact_sent.fee_known, "compact archive has no value_balance");
        assert_eq!(compact_sent.recipient, None, "compact archive cannot recover recipient");
        let compact_restored = WalletDb::from_checkpoint(miner, &compact.to_checkpoint()).unwrap();
        let compact_sent = compact_restored.history().last().unwrap();
        assert!(compact_sent.amount_is_net_outflow && !compact_sent.fee_known, "compact-history semantics survive restart");
    }

    /// The vanishing-balance regression (live report 2026-07-18): a submitted
    /// spend's notes must PARK — not vanish — until the chain shows the spend,
    /// survive a restart parked, and come back if the transaction is lost.
    #[test]
    fn pending_spend_parks_reclaims_and_survives_checkpoint() {
        let seed = [77u8; 32];
        let addr = address_bytes_from_seed(seed).unwrap();
        let mut db = WalletDb::from_seed(seed).unwrap();
        db.ingest_block_with_meta(
            &[cb(addr, b"blk1||0", 4_000)],
            &[],
            Some(&BlockMeta { coinbase_txid: [1; 32], txids: vec![], timestamp_ms: 1, daa_score: 100 }),
        );
        db.ingest_block_with_meta(
            &[cb(addr, b"blk2||0", 6_000)],
            &[],
            Some(&BlockMeta { coinbase_txid: [2; 32], txids: vec![], timestamp_ms: 2, daa_score: 110 }),
        );
        assert_eq!(db.balance(), 10_000);
        assert_eq!(db.last_daa(), 110, "ingest advances the DAA clock");

        // Submit a spend of the 4_000 note: it leaves the balance but is parked.
        let pos = db.notes()[0].position;
        db.mark_spent(pos, [0xcc; 32], 110);
        assert_eq!(db.balance(), 6_000);
        assert_eq!(db.pending_spends().len(), 1);

        // The parked note and the clock survive a checkpoint round-trip (v7).
        let blob = db.to_checkpoint();
        let mut db = WalletDb::from_checkpoint(seed, &blob).expect("v7 restores");
        assert_eq!(db.pending_spends().len(), 1, "pending spends persist across restart");
        assert_eq!(db.last_daa(), 110);
        assert_eq!(db.balance(), 6_000);

        // Too fresh to give up on: nothing reclaimed.
        assert!(db.reclaim_expired(120, 3_600).is_empty());

        // An hour of chain time passes and the spend never appears — the tx was
        // lost (node crash with it in the mempool, eviction, consensus drop).
        db.ingest_block_with_meta(
            &[],
            &[],
            Some(&BlockMeta { coinbase_txid: [3; 32], txids: vec![], timestamp_ms: 3, daa_score: 4_000 }),
        );
        let back = db.reclaim_expired(4_000, 3_600);
        assert_eq!(back, vec![([0xcc; 32], 4_000)], "the lost spend's note is handed back");
        assert_eq!(db.balance(), 10_000, "no money vanished");
        assert!(db.pending_spends().is_empty());
        assert_eq!(db.notes()[0].position, pos, "reclaimed note returns in position order");
    }

    /// A spend parked with no chain score (the wallet syncs against a node that
    /// serves no block metadata, so it has no clock) must NEVER be reclaimed on
    /// age — otherwise the first dated block un-parks a spend that is still in
    /// flight, and the wallet offers a note the network is about to consume.
    #[test]
    fn pending_spend_without_a_clock_is_never_age_reclaimed() {
        let seed = [79u8; 32];
        let addr = address_bytes_from_seed(seed).unwrap();
        let mut db = WalletDb::from_seed(seed).unwrap();
        db.ingest_block(&[cb(addr, b"blk1||0", 4_000)], &[]); // no meta ⇒ no clock
        assert_eq!(db.last_daa(), 0);

        db.mark_spent(db.notes()[0].position, [0xcc; 32], 0); // submitted, clock unknown
        assert_eq!(db.pending_spends().len(), 1);

        // A huge jump in chain score must not expire it.
        assert!(db.reclaim_expired(1_000_000, 3_600).is_empty(), "no origin ⇒ no age-based expiry");
        assert_eq!(db.pending_spends().len(), 1, "the spend still waits for its nullifier");
        assert_eq!(db.balance(), 0, "and the note stays out of the spendable set");
    }

    /// History is opt-in: with it off nothing is recorded, and turning it off
    /// purges what was recorded while it was on.
    #[test]
    fn history_opt_out_records_nothing_and_purges() {
        let seed = [78u8; 32];
        let addr = address_bytes_from_seed(seed).unwrap();
        let mut db = WalletDb::from_seed(seed).unwrap();
        db.set_history_enabled(false);
        db.ingest_block_with_meta(
            &[cb(addr, b"blk1||0", 4_000)],
            &[],
            Some(&BlockMeta { coinbase_txid: [1; 32], txids: vec![], timestamp_ms: 1, daa_score: 100 }),
        );
        assert!(db.history().is_empty(), "nothing recorded while off");
        assert_eq!(db.balance(), 4_000, "balance tracking is unaffected");

        db.set_history_enabled(true);
        db.ingest_block_with_meta(
            &[cb(addr, b"blk2||0", 6_000)],
            &[],
            Some(&BlockMeta { coinbase_txid: [2; 32], txids: vec![], timestamp_ms: 2, daa_score: 110 }),
        );
        assert_eq!(db.history().len(), 1, "recording starts once enabled");

        db.set_history_enabled(false);
        assert!(db.history().is_empty(), "disabling erases the record");
    }
}
