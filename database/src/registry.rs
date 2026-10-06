use enum_primitive_derive::Primitive;

/// We use `u8::MAX` which is never a valid block level. Also note that through
/// the [`DatabaseStorePrefixes`] enum we make sure it is not used as a prefix as well
pub const SEPARATOR: u8 = u8::MAX;

#[derive(Primitive, Debug, Clone, Copy)]
#[repr(u8)]
pub enum DatabaseStorePrefixes {
    // ---- Consensus ----
    AcceptanceData = 1,
    BlockTransactions = 2,
    NonDaaMergeset = 3,
    BlockDepth = 4,
    Ghostdag = 5,
    GhostdagCompact = 6,
    HeadersSelectedTip = 7,
    // Legacy headers store prefix. CompressedHeaders is used instead
    Headers = 8,
    HeadersCompact = 9,
    PastPruningPoints = 10,
    PruningUtxoset = 11,
    PruningUtxosetPosition = 12,
    PruningPoint = 13,
    RetentionCheckpoint = 14,
    Reachability = 15,
    ReachabilityReindexRoot = 16,
    ReachabilityRelations = 17,
    RelationsParents = 18,
    RelationsChildren = 19,
    ChainHashByIndex = 20,
    ChainIndexByHash = 21,
    ChainHighestIndex = 22,
    Statuses = 23,
    Tips = 24,
    UtxoDiffs = 25,
    UtxoMultisets = 26,
    VirtualUtxoset = 27,
    VirtualState = 28,
    PruningSamples = 29,

    // ---- Decomposed reachability stores ----
    ReachabilityTreeChildren = 30,
    ReachabilityFutureCoveringSet = 31,

    // Stores headers with run-length encoded parents
    CompressedHeaders = 32,

    // Stores a succinct pruning proof descriptor
    PruningProofDescriptor = 33,

    // ---- Ghostdag Proof
    TempGhostdag = 40,
    TempGhostdagCompact = 41,
    TempRelationsParents = 42,
    TempRelationsChildren = 43,

    // ---- Retention Period Root ----
    RetentionPeriodRoot = 50,

    // ---- Pruning metadata ----
    PruningUtxosetSyncFlag = 60,
    BodyMissingAnticone = 61,

    // ---- Metadata ----
    MultiConsensusMetadata = 124,
    ConsensusEntries = 125,

    // ---- Components ----
    Addresses = 128,
    BannedAddresses = 129,

    // ---- Indexes ----
    UtxoIndex = 192,
    UtxoIndexTips = 193,
    CirculatingSupply = 194,

    // ---- SMT Versioned Store ----
    SmtBranchVersions = 71,
    SmtLaneVersions = 73,
    SmtScoreIndex = 74,
    SmtSyncFlag = 75,
    SmtSeqCommitMeta = 76,

    // ---- Shielded pool (ZKas) ----
    /// Append-only set of spent nullifiers (PLAN §2.2).
    ShieldedNullifiers = 80,
    /// Persisted frontier of the global note-commitment tree (PLAN §2.9).
    ShieldedTreeFrontier = 81,
    /// Ring buffer of recent finalized anchors that spends reference (PLAN §2.5).
    ShieldedAnchors = 82,
    /// Cumulative coinbase/fee totals for the turnstile invariant (PLAN §2.6).
    ShieldedSupply = 83,
    /// Per-chain-block record of nullifiers added, for reorg revert (D10).
    ShieldedNullifierDiffs = 84,
    /// Per-chain-block MuHash accumulator over the spent-nullifier set, so the
    /// shielded state root can commit to double-spend prevention for fast/pruned
    /// sync without replaying from genesis (PLAN §2.2, §2.10).
    ShieldedNullifierMuHash = 85,
    /// IBD sync-stability flag for the shielded pool state at the pruning point
    /// (mirrors `SmtSyncFlag`): false while a fast-sync node is importing shielded
    /// state, true once complete or when there is no shielded state to import.
    ShieldedSyncFlag = 86,
    /// Per-chain-block **compact scan archive** (ZKas compact block): the exact
    /// applied-set effects (coinbase note descriptors + accepted shielded actions
    /// in compact 148-byte form) recorded at validation time so wallet sync
    /// (`GetShieldedBlocks`) serves the persisted block-time truth instead of
    /// re-deriving it — and so history stays scannable after the full block body
    /// is pruned (PLAN §2.9 pruning). Written in the block-commit batch.
    ShieldedScanBlock = 87,
    /// Per-chain-block snapshot of the **bridge burn accumulator**: the ordered
    /// exit receipts burned out of the shielded pool, whose Merkle root the
    /// shielded state root commits to. Snapshotted per chain block (like the
    /// tree frontier and supply totals) so a reorg reloads the selected parent's
    /// accumulator rather than replaying from genesis.
    ShieldedBurns = 88,
    /// **All** blocks that produced a given shielded tree root, not just the last one
    /// written (`ShieldedAnchors` keeps one and is therefore order-dependent — see
    /// `DbAnchorProducersStore`). Append-only and reorg-safe by construction.
    ShieldedAnchorProducers = 89,
    /// Dev-fee value accrued but not yet paid out, as of each chain block.
    ///
    /// A separate store rather than a field on `SupplyTotals` on purpose: these
    /// stores are bincode-encoded and bincode is not self-describing, so growing
    /// an existing value type makes every already-written row undecodable
    /// (`#[serde(default)]` cannot help — the bytes simply run out). A fresh
    /// prefix has no such problem: a missing key reads as zero, which is exactly
    /// the right answer for every block mined before dev-fee accrual activates.
    ShieldedDevAccrued = 90,
    /// Blue score of each block that produced an in-window anchor below the pruning point,
    /// seeded from `PruningPointShieldedMetadata` during shielded IBD.
    ///
    /// Exists because anchor finality needs the source's blue score and a fast-synced node has
    /// no ghostdag data below its pruning point — so the anchor→source mapping alone leaves
    /// every such anchor judged non-final, which disqualifies the first block above the pruning
    /// point that spends against one. A fresh prefix rather than a field on an existing value:
    /// these stores are bincode-encoded and growing a written value type makes every existing
    /// row undecodable, and a missing key here reads as "not attested", which is exactly the
    /// fail-closed answer for a node that was never given the data.
    ShieldedAnchorSourceScore = 91,
    /// `bool`, set the first time a shielded-history backfill writes chain-index entries
    /// below this node's own validated range. Never cleared: it records that part of the
    /// index came from a peer rather than from this node's own validation.
    ShieldedHistoryBackfilled = 92,
    /// `Hash` of the base block a shielded-history replay was VERIFIED against (the
    /// PoW-anchored frontier it reproduced). Written only in the `Verified` arm.
    ShieldedHistoryVerifiedBase = 93,
    /// Deferred GC queue for the anchor indexes: `blue_score(BE) || anchor || block`
    /// keys enqueued when a block's snapshots are pruned, drained once the entry is
    /// provably outside both the spend window and the IBD anchor export
    /// (see `gc_aged_anchors`). Without it the anchor indexes grow one row per chain
    /// block forever.
    ShieldedAnchorGcQueue = 94,
    /// Security fork: the anchor window (retained bucket chain hashes) as of each chain block at or
    /// after the activation. Pruned below the pruning point with the other per-block snapshots.
    ShieldedAnchorWindow = 95,
    /// Security fork: each post-activation chain block's window entry (its own tree root and blue
    /// score). Kept below the pruning point so the window can be exported to a syncing node, and
    /// garbage-collected with the anchor indexes.
    ShieldedWindowEntry = 96,

    // ---- Separator ----
    /// Reserved as a separator
    Separator = SEPARATOR,
}

impl From<DatabaseStorePrefixes> for Vec<u8> {
    fn from(value: DatabaseStorePrefixes) -> Self {
        [value as u8].to_vec()
    }
}

impl From<DatabaseStorePrefixes> for u8 {
    fn from(value: DatabaseStorePrefixes) -> Self {
        value as u8
    }
}

impl AsRef<[u8]> for DatabaseStorePrefixes {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: enum has repr(u8)
        std::slice::from_ref(unsafe { &*(self as *const Self as *const u8) })
    }
}

impl IntoIterator for DatabaseStorePrefixes {
    type Item = u8;
    type IntoIter = <[u8; 1] as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        [self as u8].into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_ref() {
        let prefix = DatabaseStorePrefixes::AcceptanceData;
        assert_eq!(&[prefix as u8], prefix.as_ref());
        assert_eq!(
            size_of::<u8>(),
            size_of::<DatabaseStorePrefixes>(),
            "DatabaseStorePrefixes is expected to have the same memory layout of u8"
        );
    }
}
