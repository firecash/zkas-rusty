use super::{VirtualStateProcessor, bounds::SeqCommitBounds};
use crate::processes::shielded::ComputedBlockShielded;
use crate::processes::shielded_diag;
use crate::{
    errors::{
        BlockProcessResult,
        RuleError::{
            BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidShieldedState,
            InvalidTransactionsInUtxoContext, WrongHeaderPruningPoint, WrongSelectedParentOrder,
        },
    },
    model::stores::{
        block_transactions::BlockTransactionsStoreReader,
        daa::DaaStoreReader,
        ghostdag::{CompactGhostdagData, GhostdagData},
        headers::HeaderStoreReader,
    },
    processes::{
        pruning::PruningPointReply,
        transaction_validator::{
            errors::{TxResult, TxRuleError},
            tx_validation_in_utxo_context::TxValidationFlags,
        },
    },
};
use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;
use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
    acceptance_data::{AcceptedTxEntry, MergesetBlockAcceptanceData},
    api::args::TransactionValidationArgs,
    coinbase::*,
    hashing,
    header::Header,
    muhash::MuHashExtensions,
    tx::{MutableTransaction, PopulatedTransaction, Transaction, ValidatedTransaction, VerifiableTransaction},
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
};
use kaspa_core::{debug, info, trace};
use kaspa_hashes::Hash;
use kaspa_muhash::MuHash;
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::state::ShieldedTx;
use kaspa_shielded_core::wallet::CompactActionRecord;
use kaspa_utils::refs::Refs;

use crate::model::services::seq_commit_accessor::SeqCommitAccessor;
use kaspa_consensus_core::tx::TransactionId;
use rayon::prelude::*;
use smallvec::{SmallVec, smallvec};
use std::{iter::once, ops::Deref};

/// Per-lane activity and miner payload data extracted from a mergeset.
pub(super) struct MergesetSeqData {
    /// Per-lane activity leaves: lane_id → [activity_leaf hashes].
    /// BTreeMap gives sorted iteration over lanes.
    pub lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>>,
    /// One payload leaf hash per merged block, in mergeset order.
    pub miner_payload_leaves: Vec<Hash>,
}

/// A resolved lane update ready for SMT processing.
pub(super) struct ResolvedLaneUpdate {
    pub lane_key: kaspa_smt_store::LaneKey,
    pub new_tip: Hash,
    /// True if this lane had no active canonical version (new or reactivated).
    pub is_new: bool,
}

/// Selected-parent state the current block inherits when building its seq_commit.
pub(super) struct ParentBlockSeqState {
    /// `accepted_id_merkle_root` of the selected parent.
    pub seq_commit: Hash,
    pub blue_score: u64,
    pub lanes_root: Hash,
    pub active_lanes_count: u64,
}

/// A context for processing the UTXO state of a block with respect to its selected parent.
/// Note this can also be the virtual block.
pub(super) struct UtxoProcessingContext<'a> {
    pub ghostdag_data: Refs<'a, GhostdagData>,
    pub multiset_hash: MuHash,
    pub mergeset_diff: UtxoDiff,
    pub accepted_tx_ids: Vec<TransactionId>,
    pub accepted_tx_versions: Vec<u16>,
    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    pub pruning_sample_from_pov: Option<Hash>,
    /// Shielded transactions accepted by this block, in GHOSTDAG accepted order
    /// (PLAN §2.4). Collected during UTXO processing; consumed by the shielded
    /// state transition in verification/commit.
    pub shielded_txs: Vec<ShieldedTx>,
    /// Compact scan records (txid + compact action bytes) for each collected shielded
    /// tx, kept **parallel** to `shielded_txs` through the partition/retain so the
    /// block-time applied set can be archived for wallet sync (`GetShieldedBlocks`)
    /// and pruning (PLAN §2.9). Distilled from the original bundle wire at collection
    /// (the only point the ciphertexts are in hand); `ShieldedTx` itself carries only
    /// commitments, not the ciphertexts a receiver needs.
    pub shielded_scan: Vec<crate::model::stores::shielded::ShieldedScanTx>,
    /// The validated shielded transition for this block, computed during
    /// verification and persisted at commit.
    pub shielded_computed: Option<ComputedBlockShielded>,
    /// Dev fee this block carries forward (parent's accrual + this block's cut, minus
    /// any payout). Produced while rebuilding the expected coinbase — the only place
    /// the per-block cuts are known — and persisted at commit alongside the shielded
    /// state. Always `0` before dev-fee accrual activates.
    pub dev_accrued: u64,
    /// Miner reward this block carries forward (security fork; empty before it). Produced with
    /// the expected coinbase and persisted at commit, like `dev_accrued`.
    pub miner_accrual: kaspa_consensus_core::coinbase::MinerAccrual,
    /// Per-transaction keep/drop detail, populated only when `--consensus-diag` is on and
    /// read only if this block goes on to fail. Empty otherwise, so the cost is one atomic
    /// load per block with shielded activity.
    pub diag_decisions: Vec<shielded_diag::ShieldedDecision>,
    /// Anchor resolutions behind those decisions, deduplicated by anchor.
    pub diag_anchors: Vec<shielded_diag::AnchorResolution>,
}

impl<'a> UtxoProcessingContext<'a> {
    pub fn new(ghostdag_data: Refs<'a, GhostdagData>, selected_parent_multiset_hash: MuHash) -> Self {
        let mergeset_size = ghostdag_data.mergeset_size();
        Self {
            ghostdag_data,
            multiset_hash: selected_parent_multiset_hash,
            mergeset_diff: UtxoDiff::default(),
            accepted_tx_ids: Vec::with_capacity(1), // We expect at least the selected parent coinbase tx
            accepted_tx_versions: Vec::with_capacity(1), // We expect at least the selected parent coinbase tx

            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
            pruning_sample_from_pov: Default::default(),
            shielded_txs: Vec::new(),
            shielded_scan: Vec::new(),
            shielded_computed: None,
            dev_accrued: 0,
            miner_accrual: Default::default(),
            diag_decisions: Vec::new(),
            diag_anchors: Vec::new(),
        }
    }

    pub fn selected_parent(&self) -> Hash {
        self.ghostdag_data.selected_parent
    }
}

impl VirtualStateProcessor {
    /// Calculates UTXO state and transaction acceptance data relative to the selected parent state
    pub(super) fn calculate_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        pov_daa_score: u64,
    ) {
        let selected_parent_transactions = self.block_transactions_store.get(ctx.selected_parent()).unwrap();
        let validated_coinbase = ValidatedTransaction::new_coinbase(&selected_parent_transactions[0]);

        // On a shielded-coinbase network the coinbase's outputs are coinbase-note
        // descriptors, minted into the shielded pool in verify_expected_utxo_state,
        // not spendable UTXOs — so they must not enter the UTXO set or its
        // commitment (coinbase maturity is replaced by anchor finality, §2.5).
        if !self.shielded_coinbase {
            ctx.mergeset_diff.add_transaction(&validated_coinbase, pov_daa_score).unwrap();
            ctx.multiset_hash.add_transaction(&validated_coinbase, pov_daa_score);
        }
        let validated_coinbase_id = validated_coinbase.id();
        ctx.accepted_tx_ids.push(validated_coinbase_id);
        ctx.accepted_tx_versions.push(validated_coinbase.version());

        // Source (merged) block of each entry in `ctx.shielded_txs`, index-aligned.
        // Needed below to attribute a dropped spend's fee back to the one mergeset
        // reward that would otherwise re-mint it.
        let mut shielded_tx_sources: Vec<Hash> = Vec::new();

        for (i, (merged_block, txs)) in once((ctx.selected_parent(), selected_parent_transactions))
            .chain(
                ctx.ghostdag_data
                    .consensus_ordered_mergeset_without_selected_parent(self.ghostdag_store.deref())
                    .map(|b| (b, self.block_transactions_store.get(b).unwrap())),
            )
            .enumerate()
        {
            // Create a composed UTXO view from the selected parent UTXO view + the mergeset UTXO diff
            let composed_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);

            // The first block in the mergeset is always the selected parent
            let is_selected_parent = i == 0;

            // No need to fully validate selected parent transactions: they were already fully validated when
            // the selected parent passed verify_expected_utxo_state, using its own DAA score for both POV and
            // block DAA score, and its selected parent as the seqcommit context.
            //
            // Here we only replay them while building the child's UTXO state. The child's POV DAA score is
            // safe for non-script checks because maturity and sequence-lock checks are monotonic. Seqcommit
            // context is not monotonic (the threshold can be crossed), but it is only used by script checks,
            // which we skip for selected-parent transactions.
            let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };
            let (validated_transactions, inner_multiset) = self.validate_transactions_with_muhash_in_parallel(
                &txs,
                &composed_view,
                pov_daa_score,
                self.headers_store.get_daa_score(merged_block).unwrap(),
                validation_flags,
                ctx.selected_parent(),
            );

            ctx.multiset_hash.combine(&inner_multiset);

            let mut block_fee = 0u64;
            for (validated_tx, _) in validated_transactions.iter() {
                ctx.mergeset_diff.add_transaction(validated_tx, pov_daa_score).unwrap();
                ctx.accepted_tx_ids.push(validated_tx.id());
                ctx.accepted_tx_versions.push(validated_tx.version());
                block_fee += validated_tx.calculated_fee;

                // Collect shielded bundles in accepted order (PLAN §2.4). The cheap
                // version gate means transparent transactions cost nothing here.
                if validated_tx.version() == TX_VERSION_SHIELDED {
                    // A shielded tx only reaches here after Full validation (which parses
                    // and verifies its bundle), so `from_bundle` should always succeed. If
                    // it somehow does not, we DROP that transaction rather than disqualify
                    // the merging block: a single unusable merged tx must never be able to
                    // halt the chain (see the accepted-order drop principle, PLAN §2.4).
                    if let Some((stx, bundle)) = ShieldedBundle::from_bytes(&validated_tx.tx().payload)
                        .ok()
                        .and_then(|b| ShieldedTx::from_bundle(&b).ok().map(|stx| (stx, b)))
                    {
                        // Distill the bundle's actions to compact scan records now, while
                        // the ciphertexts are in hand (kept parallel to shielded_txs).
                        let mut action_bytes = Vec::with_capacity(bundle.actions.len() * CompactActionRecord::SERIALIZED_LEN);
                        for a in &bundle.actions {
                            action_bytes.extend_from_slice(&CompactActionRecord::from_wire(a).to_bytes());
                        }
                        ctx.shielded_scan
                            .push(crate::model::stores::shielded::ShieldedScanTx { txid: validated_tx.id(), action_bytes });
                        ctx.shielded_txs.push(stx);
                        shielded_tx_sources.push(merged_block);
                    } else {
                        // The transition will never apply this tx, so its fee never
                        // leaves the pool — the coinbase must not re-mint it.
                        kaspa_core::warn!(
                            "shielded: bundle of {} in {} failed to parse after full validation; fee refunded",
                            validated_tx.id(),
                            merged_block
                        );
                        block_fee -= validated_tx.calculated_fee;
                    }
                }
            }

            ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
                block_hash: merged_block,
                // For the selected parent, we prepend the coinbase tx
                accepted_transactions: is_selected_parent
                    .then_some(AcceptedTxEntry { transaction_id: validated_coinbase_id, index_within_block: 0 })
                    .into_iter()
                    .chain(
                        validated_transactions
                            .into_iter()
                            .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx }),
                    )
                    .collect(),
            });

            let coinbase_data = self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).unwrap();
            ctx.mergeset_rewards.insert(
                merged_block,
                BlockRewardData::new(coinbase_data.subsidy, block_fee, coinbase_data.miner_data.script_public_key),
            );
        }

        // Anti-inflation (PLAN §2.6): decide NOW — before the coinbase is built
        // (template path) or verified (validation path) from `mergeset_rewards` —
        // which shielded txs the state transition will actually apply, and deduct
        // every dropped spend's fee from its source block's reward. A dropped spend
        // never left the pool, so a coinbase re-minting its fee would create
        // unbacked supply. Both the template builder and the coinbase verifier read
        // the rewards computed here, so honest mining and verification stay
        // byte-for-byte symmetric. The drop rules (anchor finality + accepted-order
        // nullifier conflicts) are exactly those of the transition itself, so
        // feeding `compute` the surviving set leaves its outcome unchanged.
        if !ctx.shielded_txs.is_empty() {
            let selected_parent = ctx.selected_parent();
            let block_blue_score = ctx.ghostdag_data.blue_score;
            let diag = shielded_diag::enabled();
            // Anchor resolutions recorded straight from the predicate validation used, so a
            // report describes the decision that was actually made rather than a re-derivation.
            let mut anchor_records: Vec<shielded_diag::AnchorResolution> = Vec::new();
            let outcomes = self.shielded_state_manager.partition_applied(&ctx.shielded_txs, |stx| {
                let verdict = self.resolve_shielded_anchor(&stx.anchor, stx.anchor_block, selected_parent, block_blue_score, pov_daa_score);
                if diag && !anchor_records.iter().any(|a| a.anchor == shielded_diag::hex32(&stx.anchor)) {
                    // The sibling scan is the expensive part; only worth it for a resolved anchor.
                    let siblings =
                        verdict.source.map(|s| self.source_sibling_blocks(&stx.anchor, s, selected_parent)).unwrap_or_default();
                    // Confirmed beats unverifiable: a sibling proven to carry the same root
                    // settles it, while one we simply never computed only raises the question.
                    let ambiguity = if siblings.iter().any(|b| b.root_matches_anchor == Some(true)) {
                        shielded_diag::Ambiguity::Confirmed
                    } else if siblings.iter().any(|b| !b.shielded_state_persisted) {
                        shielded_diag::Ambiguity::Unverifiable
                    } else {
                        shielded_diag::Ambiguity::None
                    };
                    anchor_records.push(shielded_diag::AnchorResolution {
                        anchor: shielded_diag::hex32(&stx.anchor),
                        source: verdict.source.map(shielded_diag::hash_str),
                        source_blue_score: verdict.source_blue_score,
                        is_chain_ancestor: verdict.is_chain_ancestor,
                        age: verdict.age,
                        window_min: self.shielded_anchor_depth,
                        window_max: self.max_shielded_anchor_age,
                        verdict: verdict.is_final,
                        reject_reason: verdict.reject_reason.map(str::to_string),
                        ambiguity,
                        source_siblings: siblings,
                    });
                }
                verdict.is_final
            });
            if diag {
                ctx.diag_anchors = anchor_records;
                ctx.diag_decisions = ctx
                    .shielded_txs
                    .iter()
                    .zip(outcomes.iter())
                    .enumerate()
                    .map(|(i, (stx, o))| shielded_diag::ShieldedDecision {
                        txid: ctx.shielded_scan.get(i).map(|s| s.txid.to_string()).unwrap_or_default(),
                        source_block: shielded_diag::hash_str(shielded_tx_sources[i]),
                        is_selected_parent: shielded_tx_sources[i] == selected_parent,
                        fee: stx.fee,
                        nullifier_count: stx.nullifiers.len(),
                        anchor: shielded_diag::hex32(&stx.anchor),
                        anchor_ok: o.anchor_ok,
                        conflict_ok: o.conflict_ok,
                        kept: o.kept(),
                        drop_reason: o.drop_reason().map(str::to_string),
                    })
                    .collect();
            }

            let keep: Vec<bool> = outcomes.iter().map(|o| o.kept()).collect();
            let UtxoProcessingContext { shielded_txs, shielded_scan, mergeset_rewards, .. } = ctx;
            let mut idx = 0usize;
            let mut dropped = 0usize;
            shielded_txs.retain(|stx| {
                let keep_it = keep[idx];
                let source = shielded_tx_sources[idx];
                idx += 1;
                if !keep_it {
                    // The fee was accumulated into this source block's `block_fee`
                    // above from the same `value_balance`, so this cannot underflow.
                    mergeset_rewards.get_mut(&source).expect("every collected shielded tx has a rewarded source block").total_fees -=
                        stx.fee;
                    dropped += 1;
                }
                keep_it
            });
            // Keep the parallel scan records aligned with the retained shielded_txs
            // (same keep mask), so `outcome.accepted` indexes both identically.
            let mut sidx = 0usize;
            shielded_scan.retain(|_| {
                let keep_it = keep[sidx];
                sidx += 1;
                keep_it
            });
            if dropped > 0 {
                debug!("shielded: dropped {dropped} spend(s) (non-final anchor or nullifier conflict); their fees are not re-minted");
            }
        }
    }

    /// Verify that the current block fully respects its own UTXO view. We define a block as
    /// UTXO valid if all the following conditions hold:
    ///     1. The block header includes the expected `utxo_commitment`.
    ///     2. The block header includes the expected `accepted_id_merkle_root`.
    ///     3. The block header includes the expected `pruning_point`.
    ///     4. The block coinbase transaction rewards the mergeset blocks correctly.
    ///     5. All non-coinbase block transactions are valid against its own UTXO view.
    pub(super) fn verify_expected_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        header: &Header,
    ) -> BlockProcessResult<Option<kaspa_smt_store::processor::SmtBuild>> {
        // Verify header UTXO commitment
        let expected_commitment = ctx.multiset_hash.finalize();
        if expected_commitment != header.utxo_commitment {
            return Err(BadUTXOCommitment(header.hash, header.utxo_commitment, expected_commitment));
        }
        trace!("correct commitment: {}, {}", header.hash, expected_commitment);

        let (expected_accepted_id_merkle_root, smt_build) = if self.toccata_activation.is_active(header.daa_score) {
            // KIP-21: compute seq_commit from SMT lane processing
            let (hash, build) = self.recompute_seq_commit(ctx, header)?;
            (hash, Some(build))
        } else {
            (self.calc_accepted_id_merkle_root(ctx.accepted_tx_ids.iter().copied(), ctx.selected_parent()), None)
        };

        // Verify header accepted_id_merkle_root
        if expected_accepted_id_merkle_root != header.accepted_id_merkle_root {
            return Err(BadAcceptedIDMerkleRoot(header.hash, header.accepted_id_merkle_root, expected_accepted_id_merkle_root));
        }

        let txs = self.block_transactions_store.get(header.hash).unwrap();

        // Verify coinbase transaction. `ctx.mergeset_rewards` was already corrected
        // in `calculate_utxo_state` to exclude the fees of dropped shielded spends,
        // so this enforces that the coinbase re-mints only fees the shielded
        // transition actually collects (PLAN §2.6).
        let mergeset_non_daa = self.daa_excluded_store.get_mergeset_non_daa(header.hash).unwrap();
        let (dev_accrued, miner_accrual) =
            self.verify_coinbase_transaction(&txs[0], header.hash, header.daa_score, ctx, &mergeset_non_daa)?;
        ctx.dev_accrued = dev_accrued;
        ctx.miner_accrual = miner_accrual;

        // Verify the header pruning point
        let reply = self.verify_header_pruning_point(header, ctx.ghostdag_data.to_compact())?;
        ctx.pruning_sample_from_pov = Some(reply.pruning_sample);

        // Verify the first parent is the selected parent
        //
        // Purpose: Enables seqcommit opcode verification for syncees. By enforcing this rule,
        // a node can trustlessly verify the selected chain segment below the pruning point
        // (PP) simply by walking back through first-parents, avoiding a full GHOSTDAG
        // computation over the historical DAG.
        //
        // Design Note: This is enforced as a chain-qualification rule rather than
        // header-validity. This maintains compatibility with protocols like DAGKNIGHT,
        // which may not compute selected parents for every block, while still securing
        // the pruning point (which is a qualified chain block by definition).
        if self.toccata_activation.is_active(header.daa_score) {
            let selected_parent = ctx.ghostdag_data.selected_parent;
            let first_parent = header.direct_parents()[0];
            if first_parent != selected_parent {
                return Err(WrongSelectedParentOrder(header.hash, selected_parent, first_parent));
            }
        }

        // Final chain qualification condition: verify all transactions are valid in context.
        //
        // We verify this chain block's transactions in the same way they were built and checked by
        // build_block_template -> validate_block_template_transaction: use the block DAA score as the
        // POV DAA score, and use the selected parent as the seqcommit context. Later, calculate_utxo_state
        // relies on this check when replaying this block as a selected parent.
        let current_utxo_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
        let validated_transactions = self.validate_transactions_in_parallel(
            &txs,
            &current_utxo_view,
            header.daa_score,
            header.daa_score,
            TxValidationFlags::Full,
            ctx.selected_parent(),
        );
        if validated_transactions.len() < txs.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(InvalidTransactionsInUtxoContext(txs.len() - 1 - validated_transactions.len(), txs.len() - 1));
        }

        // Shielded state transition (PLAN §2.4). This is a no-op for blocks with no
        // shielded activity.
        //
        // LIVENESS PRINCIPLE (the fix): a shielded transaction that is invalid *in
        // accepted-order context* is DROPPED, never a reason to disqualify the block
        // that merges it — exactly as a transparent (or shielded nullifier)
        // double-spend is dropped, not fatal. The offending tx is immutably embedded
        // in an already-mined merged block, so hard-rejecting the merging block makes
        // that block un-mergeable and halts the whole selected chain (observed live:
        // one spend against a stale anchor froze the virtual chain). Dropping the
        // spend leaves no trace (no nullifier, no note, no fee); the sender simply
        // re-sends against a fresh anchor. Only genuinely block-level invariants
        // (the block's own malformed coinbase, or a turnstile/tree-full violation
        // that by PLAN §2.6 must halt-not-inflate) disqualify the block.

        // On a shielded-coinbase network the block reward enters the pool as
        // coinbase notes derived from the coinbase transaction (PLAN §2.7); the
        // matching outputs are diverted from the UTXO set in `calculate_utxo_state`.
        // This is the block's OWN coinbase, so a malformed one correctly disqualifies
        // it (a competing block with a valid coinbase wins) — it cannot halt the chain.
        let coinbase_mint = if self.shielded_coinbase {
            // F-02: from the activation score on, the block's own hash goes into the note
            // seed so sibling blocks can no longer mint identical notes (and therefore can
            // no longer produce the same tree root). Gated on THIS block's DAA score, never
            // on the tip, so a block is always judged by the rule in force when it was mined
            // — which is also what keeps a reorg across the boundary deterministic.
            let seed_block = self.shielded_coinbase_seed_activation.is_active(header.daa_score).then_some(header.hash);
            match crate::processes::shielded::build_coinbase_mint(&txs[0], seed_block) {
                Ok(mint) => Some(mint),
                Err(e) => return Err(InvalidShieldedState(header.hash, format!("coinbase mint: {e:?}"))),
            }
        } else {
            None
        };

        // Anchor-finality (PLAN §2.5) and nullifier-conflict drops already happened
        // in `calculate_utxo_state` (the partition step), BEFORE the coinbase was
        // verified above — so `ctx.shielded_txs` holds exactly the txs the
        // transition will apply and the coinbase re-mints exactly their fees.
        // `compute`'s own conflict resolution re-runs on this set as defense in
        // depth (it is a no-op for a correctly partitioned set).
        match self.shielded_state_manager.compute(ctx.selected_parent(), coinbase_mint.as_ref(), &ctx.shielded_txs) {
            Ok(mut computed) => {
                // Build the compact scan archive from the block-time applied set:
                // `outcome.accepted` indexes the retained `shielded_txs`, which is kept
                // parallel to `shielded_scan`. Persisting this (in `persist`, commit
                // batch) lets `GetShieldedBlocks` serve the exact applied truth instead
                // of re-deriving it — killing the divergent-anchor drift — and keeps
                // history scannable after the body prunes (PLAN §2.9).
                let accepted = computed.outcome.accepted.iter().map(|&i| ctx.shielded_scan[i].clone()).collect::<Vec<_>>();
                // Coinbase notes exist only on a shielded-coinbase network; on a
                // transparent-coinbase network txs[0]'s outputs are UTXOs, not notes.
                let coinbase_outputs = if self.shielded_coinbase {
                    txs[0].outputs.iter().map(|o| (o.script_public_key.script().to_vec(), o.value)).collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let coinbase_commitments =
                    coinbase_mint.as_ref().map(|m| m.notes.iter().map(|n| n.commitment.to_bytes()).collect()).unwrap_or_default();
                computed.scan_block = Some(crate::model::stores::shielded::ShieldedScanBlockData {
                    blue_score: ctx.ghostdag_data.blue_score,
                    daa_score: header.daa_score,
                    timestamp: header.timestamp,
                    coinbase_txid: txs[0].id(),
                    coinbase_outputs,
                    coinbase_commitments,
                    accepted,
                });
                ctx.shielded_computed = Some(computed);
            }
            Err(crate::processes::shielded::ShieldedManagerError::State(e)) => {
                return Err(InvalidShieldedState(header.hash, format!("{e:?}")));
            }
            Err(e @ crate::processes::shielded::ShieldedManagerError::MalformedCoinbaseNote(_)) => {
                // Not produced by `compute` (only by `build_coinbase_mint` above),
                // but the match must be exhaustive; treat as an invalid state.
                return Err(InvalidShieldedState(header.hash, format!("{e:?}")));
            }
            Err(crate::processes::shielded::ShieldedManagerError::Store(e)) => {
                panic!("shielded store read failed during verification: {e}");
            }
        }

        // Positive anti-inflation invariant (PLAN §2.6), belt-and-suspenders: the
        // shielded pool must grow by EXACTLY the subsidy of the rewarded mergeset
        // blocks — every fee the coinbase re-mints must have been collected from an
        // applied spend in this same transition. (A blue non-DAA block's fees are
        // collected but never re-minted by Kaspa's coinbase rules, hence the
        // subtraction — combinatorically near-impossible, but exact.) On this
        // network no transparent value exists, so any other delta means unbacked
        // supply was minted (or burned) and the block is invalid: halt-not-inflate.
        if self.shielded_coinbase {
            let computed = ctx.shielded_computed.as_ref().expect("set above");
            let parent = self.shielded_state_manager.supply_totals_at(ctx.selected_parent()).unwrap();
            let actual_delta = (computed.supply_totals.cumulative_coinbase - parent.cumulative_coinbase) as i128
                - (computed.supply_totals.cumulative_fees - parent.cumulative_fees) as i128;
            let mut expected_delta: i128 = 0;
            for blue in ctx.ghostdag_data.mergeset_blues.iter() {
                let reward = ctx.mergeset_rewards.get(blue).unwrap();
                if mergeset_non_daa.contains(blue) {
                    expected_delta -= reward.total_fees as i128;
                } else {
                    expected_delta += reward.subsidy as i128;
                }
            }
            for red in ctx.ghostdag_data.mergeset_reds.iter() {
                if !mergeset_non_daa.contains(red) {
                    expected_delta += ctx.mergeset_rewards.get(red).unwrap().subsidy as i128;
                }
            }
            // Dev-fee accrual moves value across the block boundary without changing
            // what is ultimately issued, so the invariant becomes "the pool grew by the
            // subsidy MINUS what this block deferred, PLUS what a previous block
            // deferred and this one paid out". Both terms are zero before activation,
            // leaving the rule byte-identical to the pre-fork check.
            //
            // Getting this wrong is not a rounding error: the first accrual block mints
            // only the miner's 95%, the un-adjusted check reads that as unbacked supply
            // and disqualifies the block, and the chain stops. (Observed exactly that on
            // the rehearsal chain: "pool delta 570000000 != expected 600000000".)
            let parent_accrued = self.shielded_state_manager.dev_accrued_at(ctx.selected_parent()).unwrap() as i128;
            let this_accrued = ctx.dev_accrued as i128;
            expected_delta -= this_accrued - parent_accrued;
            // The miner slot defers and releases value the same way (security fork; both zero before).
            let parent_slot = self.shielded_state_manager.miner_accrual_at(ctx.selected_parent()).unwrap().amount as i128;
            let this_slot = ctx.miner_accrual.amount as i128;
            expected_delta -= this_slot - parent_slot;
            if actual_delta != expected_delta {
                return Err(InvalidShieldedState(
                    header.hash,
                    format!(
                        "shielded pool delta {actual_delta} != expected subsidy delta {expected_delta} \
                         (dev accrual {parent_accrued} -> {this_accrued}, miner accrual {parent_slot} -> {this_slot})"
                    ),
                ));
            }
        }

        Ok(smt_build)
    }

    fn verify_header_pruning_point(
        &self,
        header: &Header,
        ghostdag_data: CompactGhostdagData,
    ) -> BlockProcessResult<PruningPointReply> {
        let reply = self.pruning_point_manager.expected_header_pruning_point(ghostdag_data);
        if reply.pruning_point != header.pruning_point {
            return Err(WrongHeaderPruningPoint(reply.pruning_point, header.pruning_point));
        }
        Ok(reply)
    }

    fn verify_coinbase_transaction(
        &self,
        coinbase: &Transaction,
        block: Hash,
        daa_score: u64,
        ctx: &UtxoProcessingContext,
        mergeset_non_daa: &BlockHashSet,
    ) -> BlockProcessResult<(u64, kaspa_consensus_core::coinbase::MinerAccrual)> {
        let ghostdag_data: &GhostdagData = &ctx.ghostdag_data;
        let mergeset_rewards = &ctx.mergeset_rewards;
        // Extract only miner data from the provided coinbase
        let miner_data = self.coinbase_manager.deserialize_coinbase_payload(&coinbase.payload).unwrap().miner_data;
        // The coinbase must commit to the shielded state root of this block's selected parent
        // (PLAN §2.10). Rebuilding the expected coinbase with that root means a wrong or missing
        // commitment fails the tx-hash comparison below as `BadCoinbaseTransaction`.
        let shielded_commitment = self.shielded_state_root_at(ghostdag_data.selected_parent).unwrap();
        // Dev-fee accrual carries along the selected-parent chain, exactly like the
        // shielded state root above, and is read from the same block for the same
        // reason: the expected coinbase must be rebuilt from what THIS block's parent
        // committed, not from the tip.
        let parent_daa_score = self.headers_store.get_daa_score(ghostdag_data.selected_parent).unwrap();
        let dev_accrued_parent = self.shielded_state_manager.dev_accrued_at(ghostdag_data.selected_parent).unwrap();
        let miner_accrual_parent = self.shielded_state_manager.miner_accrual_at(ghostdag_data.selected_parent).unwrap();
        let expected = self
            .coinbase_manager
            .expected_coinbase_transaction(
                daa_score,
                miner_data,
                ghostdag_data,
                mergeset_rewards,
                mergeset_non_daa,
                shielded_commitment,
                parent_daa_score,
                dev_accrued_parent,
                &miner_accrual_parent,
            )
            .unwrap();
        let expected_coinbase = expected.tx;
        if hashing::tx::hash(coinbase) != hashing::tx::hash(&expected_coinbase) {
            // A single tx-hash comparison says nothing about WHICH input diverged, and the
            // inputs fail for very different reasons: a different applied-spend set shows up in
            // the outputs (a fee re-minted or not), while a diverged shielded state shows up only
            // in the payload commitment. Diagnosing that by reading code has repeatedly picked
            // the wrong one, so emit the whole decision instead.
            self.emit_coinbase_divergence_report(coinbase, &expected_coinbase, block, daa_score, ctx, &shielded_commitment);
            Err(BadCoinbaseTransaction)
        } else {
            Ok((expected.dev_accrued, expected.miner_accrual))
        }
    }

    /// Write a self-contained account of a rejected block's coinbase decision.
    ///
    /// No-op unless `--consensus-diag` is set, apart from one summary log line. See
    /// [`crate::processes::shielded_diag`] for why this exists.
    fn emit_coinbase_divergence_report(
        &self,
        actual: &Transaction,
        expected: &Transaction,
        block: Hash,
        daa_score: u64,
        ctx: &UtxoProcessingContext,
        shielded_commitment: &[u8; 32],
    ) {
        let payload_equal = actual.payload == expected.payload;
        let value_delta: i128 = expected.outputs.iter().map(|o| i128::from(o.value)).sum::<i128>()
            - actual.outputs.iter().map(|o| i128::from(o.value)).sum::<i128>();
        kaspa_core::warn!(
            "coinbase mismatch at daa {daa_score} (block {block}): expected total differs from actual by {value_delta} sompi; payload_equal={payload_equal}"
        );
        if !shielded_diag::enabled() {
            kaspa_core::warn!("consensus-diag is off — rerun with `--consensus-diag` to get a full divergence report for this block");
            return;
        }

        let spk_prefix = |o: &kaspa_consensus_core::tx::TransactionOutput| {
            let s = o.script_public_key.script();
            faster_hex::hex_string(&s[..8.min(s.len())])
        };
        let coinbase_outputs = (0..expected.outputs.len().max(actual.outputs.len()))
            .map(|i| {
                let e = expected.outputs.get(i);
                let a = actual.outputs.get(i);
                shielded_diag::CoinbaseOutputDiff {
                    index: i,
                    expected_value: e.map(|o| o.value),
                    actual_value: a.map(|o| o.value),
                    expected_script_prefix: e.map(spk_prefix),
                    actual_script_prefix: a.map(spk_prefix),
                    matches: match (e, a) {
                        (Some(e), Some(a)) => e.value == a.value && e.script_public_key == a.script_public_key,
                        _ => false,
                    },
                }
            })
            .collect();

        let selected_parent = ctx.selected_parent();
        let (global_set_matches_snapshot, global_nullifier_count) =
            match self.shielded_state_manager.global_set_matches_snapshot(selected_parent) {
                Ok((ok, count)) => (Some(ok), Some(count as u64)),
                Err(_) => (None, None),
            };

        shielded_diag::write_report(shielded_diag::BlockDivergenceReport {
            schema: shielded_diag::BlockDivergenceReport::SCHEMA,
            kind: "coinbase_mismatch",
            block: block.to_string(),
            daa_score,
            blue_score: ctx.ghostdag_data.blue_score,
            selected_parent: selected_parent.to_string(),
            mergeset: ctx.ghostdag_data.unordered_mergeset().map(|h| h.to_string()).collect(),
            payload_equal,
            shielded_commitment_at_selected_parent: Some(faster_hex::hex_string(shielded_commitment)),
            shielded_tree_size_at_selected_parent: self.shielded_state_manager.frontier_at(selected_parent).ok().map(|f| f.size),
            global_nullifier_count,
            global_set_matches_snapshot,
            coinbase_outputs,
            value_delta,
            mergeset_rewards: ctx
                .mergeset_rewards
                .iter()
                .map(|(h, r)| shielded_diag::MergesetReward {
                    block: h.to_string(),
                    subsidy: r.subsidy,
                    total_fees: r.total_fees,
                    is_selected_parent: *h == selected_parent,
                })
                .collect(),
            shielded_decisions: ctx.diag_decisions.clone(),
            anchors: ctx.diag_anchors.clone(),
            verdict_hint: Vec::new(), // filled by write_report
        });
    }

    /// Validates transactions against the provided `utxo_view` and returns a vector with all transactions
    /// which passed the validation along with their original index within the containing block
    pub(crate) fn validate_transactions_in_parallel<'a, V: UtxoView + Sync>(
        &self,
        txs: &'a Vec<Transaction>,
        utxo_view: &V,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
    ) -> Vec<(ValidatedTransaction<'a>, u32)> {
        self.thread_pool.install(|| {
            txs
                .par_iter() // We can do this in parallel without complications since block body validation already ensured
                            // that all txs within each block are independent
                .enumerate()
                .skip(1) // Skip the coinbase tx.
                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score,block_daa_score, flags, selected_parent).ok().map(|vtx| (vtx, i as u32)))
                .collect()
        })
    }

    /// Same as validate_transactions_in_parallel except during the iteration this will also
    /// calculate the muhash in parallel for valid transactions
    pub(crate) fn validate_transactions_with_muhash_in_parallel<'a, V: UtxoView + Sync>(
        &self,
        txs: &'a Vec<Transaction>,
        utxo_view: &V,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
    ) -> (SmallVec<[(ValidatedTransaction<'a>, u32); 2]>, MuHash) {
        self.thread_pool.install(|| {
            txs
                .par_iter() // We can do this in parallel without complications since block body validation already ensured
                            // that all txs within each block are independent
                .enumerate()
                .skip(1) // Skip the coinbase tx.
                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score, block_daa_score, flags, selected_parent).ok().map(|vtx| {
                    let mh = MuHash::from_transaction(&vtx, pov_daa_score);
                    (smallvec![(vtx, i as u32)], mh)
                }
                ))
                .reduce(
                    || (smallvec![], MuHash::new()),
                    |mut a, mut b| {
                        a.0.append(&mut b.0);
                        a.1.combine(&b.1);
                        a
                    },
                )
        })
    }

    /// Attempts to populate the transaction with UTXO entries and performs all utxo-related tx validations
    pub(super) fn validate_transaction_in_utxo_context<'a>(
        &self,
        transaction: &'a Transaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        block_daa_score: u64,
        flags: TxValidationFlags,
        selected_parent: Hash,
    ) -> TxResult<ValidatedTransaction<'a>> {
        let mut entries = Vec::with_capacity(transaction.inputs.len());
        for input in transaction.inputs.iter() {
            if let Some(entry) = utxo_view.get(&input.previous_outpoint) {
                entries.push(entry);
            } else {
                // Missing at least one input. For perf considerations, we report once a single miss is detected and avoid collecting all possible misses.
                return Err(TxRuleError::MissingTxOutpoints);
            }
        }

        let populated_tx = PopulatedTransaction::new(transaction, entries);

        let seq_commit_accessor = if self.toccata_activation.is_active(pov_daa_score) {
            Some(SeqCommitAccessor::new(
                selected_parent,
                &self.reachability_service,
                &self.headers_store,
                self.toccata_activation,
                self.finality_depth,
            ))
        } else {
            None
        };
        let res = self.transaction_validator.validate_populated_transaction_and_get_fee(
            &populated_tx,
            pov_daa_score,
            block_daa_score,
            flags,
            None,
            seq_commit_accessor.as_ref().map(|v| v as _),
        );
        match res {
            Ok(calculated_fee) => Ok(ValidatedTransaction::new(populated_tx, calculated_fee)),
            Err(tx_rule_error) => {
                // TODO (relaxed): aggregate by error types and log through the monitor (in order to not flood the logs)
                info!("Rejecting transaction {} due to transaction rule error: {}", transaction.id(), tx_rule_error);
                Err(tx_rule_error)
            }
        }
    }

    /// Populates the mempool transaction with maximally found UTXO entry data
    pub(crate) fn populate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        let mut has_missing_outpoints = false;
        for i in 0..mutable_tx.tx.inputs.len() {
            if mutable_tx.entries[i].is_some() {
                // We prefer a previously populated entry if such exists
                continue;
            }
            if let Some(entry) = utxo_view.get(&mutable_tx.tx.inputs[i].previous_outpoint) {
                mutable_tx.entries[i] = Some(entry);
            } else {
                // We attempt to fill as much as possible UTXO entries, hence we do not break in this case but rather continue looping
                has_missing_outpoints = true;
            }
        }
        if has_missing_outpoints {
            return Err(TxRuleError::MissingTxOutpoints);
        }
        Ok(())
    }

    /// Would the shielded state transition APPLY this transaction, if it were mined now?
    ///
    /// Answers with the transition's own rules rather than a re-derivation: the same
    /// `partition_applied` and the same anchor resolver block validation runs. A
    /// re-implementation here that drifted would be worse than no check at all, because the
    /// mempool would start refusing transactions consensus is happy with.
    ///
    /// `Ok(())` for anything it cannot evaluate — a malformed payload is the bundle
    /// verifier's business, not this function's, and failing closed on a parse error would
    /// reject transactions on a code path that never had an opinion about them.
    pub(super) fn check_mempool_shielded_appliable(
        &self,
        tx: &kaspa_consensus_core::tx::Transaction,
        selected_parent: Hash,
        blue_score: u64,
        pov_daa_score: u64,
    ) -> TxResult<()> {
        let Ok(bundle) = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&tx.payload) else {
            return Ok(());
        };
        let Ok(stx) = kaspa_shielded_core::state::ShieldedTx::from_bundle(&bundle) else {
            return Ok(());
        };
        // `blue_score` is the VIRTUAL's, supplied by the caller — the context a transaction
        // admitted now would actually be judged in.
        //
        // Deriving it here from the selected parent was wrong twice: it is lower than the
        // virtual's by the whole mergeset, so anchors aged more strictly than the block that
        // will carry them; and a store error fell back to 0, which would have made every
        // anchor look immature and refused every shielded transaction on the node.
        let outcomes = self.shielded_state_manager.partition_applied(std::slice::from_ref(&stx), |stx| {
            self.resolve_shielded_anchor(&stx.anchor, stx.anchor_block, selected_parent, blue_score, pov_daa_score).is_final
        });
        match outcomes.first().and_then(|o| o.drop_reason()) {
            None => Ok(()),
            Some(reason) => Err(TxRuleError::InvalidShieldedTransaction(reason)),
        }
    }

    /// Populates the mempool transaction with maximally found UTXO entry data and proceeds to validation if all found
    pub(super) fn validate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        args: &TransactionValidationArgs,
        selected_parent: Hash,
        virtual_blue_score: u64,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, utxo_view)?;

        // Refuse a shielded spend the state transition would DROP.
        //
        // Admission never consulted the finalized nullifier set or the anchor index, so a
        // spend of an already-spent note, or one proving against an anchor that is not (and
        // may never be) final, was admitted, relayed and included in a block template. It
        // then mined into a block and was dropped during the transition. Two consequences,
        // both observed:
        //
        //   * The sender gets a txid and N confirmations for a transaction that moved
        //     nothing. Anyone crediting on block inclusion — the standard integration
        //     everywhere else — credits value that never arrived.
        //   * A dropped spend pays NO fee (it is filtered out before the transition, so
        //     nothing leaves the sender). Re-offering an already-spent note is therefore
        //     free, repeatable block space, and every node Halo 2-verifies it. Normal spam
        //     economics do not apply because there is nothing to charge.
        //
        // The predicate is exactly the transition's own — `partition_applied` with the same
        // anchor resolver block validation uses — so the mempool cannot disagree with
        // consensus about what is appliable. It is evaluated against the current selected
        // parent, which is the best available stand-in for the block that would carry it.
        //
        // This is RELAY policy, and deliberately one-directional: refusing here removes a
        // transaction that consensus would have dropped anyway, and can never make the node
        // accept something consensus rejects. A verdict can also change with the chain — a
        // nullifier can be reverted by a reorg, an anchor matures as blocks accumulate — so
        // a refusal is not permanent and the transaction stays resubmittable.
        if mutable_tx.tx.is_shielded() {
            self.check_mempool_shielded_appliable(&mutable_tx.tx, selected_parent, virtual_blue_score, pov_daa_score)?;
        }

        // Calc the contextual storage mass
        let contextual_mass = self
            .transaction_validator
            .mass_calculator
            .calc_contextual_masses(&mutable_tx.as_verifiable())
            .ok_or(TxRuleError::MassIncomputable)?;

        // Set the inner mass field
        mutable_tx.tx.set_storage_mass(contextual_mass.storage_mass);

        // At this point we know all UTXO entries are populated, so we can safely pass the tx as verifiable
        let mass_and_feerate_threshold = args.feerate_threshold.map(|threshold| {
            let mass = kaspa_consensus_core::mass::Mass::new(mutable_tx.calculated_non_contextual_masses.unwrap(), contextual_mass);
            (mass.normalized_max(&self.mempool_mass_cofactors.get(pov_daa_score)), threshold)
        });

        let seq_commit_accessor = if self.toccata_activation.is_active(pov_daa_score) {
            Some(SeqCommitAccessor::new(
                selected_parent,
                &self.reachability_service,
                &self.headers_store,
                self.toccata_activation,
                self.finality_depth,
            ))
        } else {
            None
        };

        let calculated_fee = self.transaction_validator.validate_populated_transaction_and_get_fee(
            &mutable_tx.as_verifiable(),
            pov_daa_score,
            pov_daa_score,
            TxValidationFlags::SkipMassCheck, // we can skip the mass check since we just set it
            mass_and_feerate_threshold,
            seq_commit_accessor.as_ref().map(|v| v as _),
        )?;
        mutable_tx.calculated_fee = Some(calculated_fee);
        Ok(())
    }

    // =========================================================================
    // KIP-21: Sequencing commitment — shared helpers
    // =========================================================================

    /// Collect per-lane activity leaves and miner payload leaves from the mergeset.
    /// Build the ordered `miner_payload_leaves` of a mergeset from its acceptance data.
    ///
    /// This is the *single source of truth* for the mergeset leaf ordering that feeds
    /// `miner_payload_root` (and thus `seq_commit`). Both the live seq_commit recomputation
    /// ([`Self::collect_mergeset_seq_data`]) and the canonical-`R` witness RPC
    /// (`get_seq_commit_lane_proof`) call it, so an external witness assembler can never drift
    /// from the exact ordering/leaf convention consensus uses.
    pub(crate) fn mergeset_miner_payload_leaves(&self, mergeset_acceptance_data: &[MergesetBlockAcceptanceData]) -> Vec<Hash> {
        use kaspa_seq_commit::hashing::miner_payload_leaf;
        use kaspa_seq_commit::types::MinerPayloadLeafInput;

        mergeset_acceptance_data
            .iter()
            .map(|block_acceptance| {
                let merged_block = block_acceptance.block_hash;
                let merged_header = self.headers_store.get_header(merged_block).unwrap();
                let block_txs = self.block_transactions_store.get(merged_block).unwrap();
                miner_payload_leaf(MinerPayloadLeafInput {
                    block_hash: &merged_block,
                    blue_work_be_bytes: &merged_header.blue_work.to_be_bytes(),
                    payload: &block_txs[0].payload,
                })
            })
            .collect()
    }

    pub(super) fn collect_mergeset_seq_data(&self, ctx: &UtxoProcessingContext) -> MergesetSeqData {
        use kaspa_seq_commit::hashing::activity_leaf;

        let mut lane_activities: std::collections::BTreeMap<[u8; 20], Vec<Hash>> = std::collections::BTreeMap::new();
        let miner_payload_leaves = self.mergeset_miner_payload_leaves(&ctx.mergeset_acceptance_data);
        let mut global_merge_idx: u32 = 0;

        for block_acceptance in ctx.mergeset_acceptance_data.iter() {
            let merged_block = block_acceptance.block_hash;
            let block_txs = self.block_transactions_store.get(merged_block).unwrap();

            for accepted_tx in block_acceptance.accepted_transactions.iter() {
                let tx = &block_txs[accepted_tx.index_within_block as usize];
                let lane_id: [u8; 20] = *tx.subnetwork_id.as_bytes();
                let al = activity_leaf(&accepted_tx.transaction_id, tx.version, global_merge_idx);
                lane_activities.entry(lane_id).or_default().push(al);
                global_merge_idx += 1;
            }
        }

        MergesetSeqData { lane_activities, miner_payload_leaves }
    }

    /// Resolve lane activities into concrete lane updates: look up existing tips
    /// from DB at the current block's POV, compute new tips via `lane_tip_next`.
    pub(super) fn resolve_lane_updates(
        &self,
        data: &MergesetSeqData,
        context_hash: &Hash,
        current_blue_score: u64,
        parent_blue_score: u64,
        selected_parent: Hash,
        parent_seq_commit: Hash,
    ) -> Vec<ResolvedLaneUpdate> {
        use kaspa_seq_commit::hashing::{activity_digest_lane, lane_key, lane_tip_next};
        use kaspa_seq_commit::types::LaneTipInput;
        let mut updates = Vec::with_capacity(data.lane_activities.len());
        let bounds = SeqCommitBounds::new(parent_blue_score, current_blue_score, self.finality_depth);
        let read_bounds = bounds.selected_parent_read_bounds(); // -> [current - F, parent]

        for (lane_id, activity_leaves) in &data.lane_activities {
            let lk = lane_key(lane_id);
            let ad = activity_digest_lane(activity_leaves.iter().copied());

            // Look up an existing canonical lane tip in [current - F, parent]:
            // the current block supplies the lower cutoff, while target=parent filters
            // anticone entries at (parent, current] at the seek level.
            let existing = self.smt_stores.get_lane(lk, read_bounds, |bh| self.is_smt_canonical(bh, selected_parent));
            // A lane at the window boundary (bs = current - F - 1) is invisible here
            // even though it was active in the parent's window. This is correct: from
            // the current block's POV the lane expired, so a re-touch is a re-activation
            // anchored on parent_seq_commit. The matching expire in `expire_stale_lanes`
            // and this is_new=true cancel in the active_lanes_count arithmetic.
            let is_new = existing.is_none();
            let parent_ref = existing.map(|v| *v.data()).unwrap_or(parent_seq_commit);

            let new_tip = lane_tip_next(&LaneTipInput { parent_ref: &parent_ref, lane_key: &lk, activity_digest: &ad, context_hash });

            updates.push(ResolvedLaneUpdate { lane_key: lk, new_tip, is_new });
        }

        updates
    }

    /// Build the SMT from lane updates + expirations, compute the final seq_commit hash.
    ///
    /// Works with an immutable view of DB state. Returns the commit hash and an `SmtBuild`
    /// containing the diff (updated branches, lane versions, score index) for later persistence.
    ///
    /// `inactivity_shortcut` is folded into `activity_root` next to the active-lanes root.
    pub(super) fn build_seq_commit(
        &self,
        parent: &ParentBlockSeqState,
        context_hash: Hash,
        current_blue_score: u64,
        lane_updates: &[ResolvedLaneUpdate],
        miner_payload_leaves: Vec<Hash>,
        selected_parent: Hash,
        inactivity_shortcut_block: Hash,
        inactivity_shortcut: Hash,
    ) -> (Hash, kaspa_smt_store::processor::SmtBuild) {
        use kaspa_seq_commit::hashing::{activity_root_hash, miner_payload_root, seq_commit, seq_state_root};
        use kaspa_seq_commit::types::{SeqCommitInput, SeqState};
        use kaspa_smt_store::processor::SmtProcessor;

        let bounds = SeqCommitBounds::new(parent.blue_score, current_blue_score, self.finality_depth);
        // 1. Create processor starting from the parent's lanes root
        let mut proc =
            SmtProcessor::new(&self.smt_stores, current_blue_score, bounds.selected_parent_read_bounds(), parent.lanes_root);

        // 2. Expire stale lanes (scans [parent-F, current-F) for lanes with no newer version)
        let expired_count = self.expire_stale_lanes(&mut proc, bounds, selected_parent);

        // 3. Apply lane updates.
        // A lane at the boundary (bs = current-F-1) gets both expired (step 2) and re-added
        // here as is_new=true. This is not wasteful: BlockLaneChanges uses a BTreeMap keyed
        // by lane_key, so update_lane overwrites the expire_lane entry: the walk sees only
        // the final leaf. The two count operations cancel: expired+1, new+1 net zero.
        let mut new_lane_count = 0;
        for lu in lane_updates {
            if lu.is_new {
                new_lane_count += 1;
            }
            proc.update_lane(lu.lane_key, lu.new_tip);
        }

        // 4. Build SMT (skips entirely when no pending leaves: no expirations, no touches)
        let mut build = proc.build(|bh| self.is_smt_canonical(bh, selected_parent)).unwrap();

        // 5. Compute final hash: activity_root -> state_root -> seq_commit.
        let payload_root = miner_payload_root(miner_payload_leaves.into_iter());
        let pd = kaspa_seq_commit::hashing::payload_and_context_digest(&context_hash, &payload_root);
        let activity_root = activity_root_hash(&inactivity_shortcut, &build.root);
        let state_root = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
        let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent.seq_commit, state_root: &state_root });

        // 6. Store metadata on the build for persistence
        build.payload_and_ctx_digest = pd;
        build.active_lanes_count = parent.active_lanes_count + new_lane_count - expired_count;
        build.inactivity_shortcut_block = inactivity_shortcut_block;

        (commit, build)
    }

    /// KIP-21: Recompute the seq_commit for a chain block from its mergeset acceptance
    /// data and SMT state. The caller compares the result against the header to verify
    /// correctness. Returns the SmtBuild to flush so subsequent blocks can read updated state.
    fn recompute_seq_commit(
        &self,
        ctx: &UtxoProcessingContext,
        header: &Header,
    ) -> BlockProcessResult<(Hash, kaspa_smt_store::processor::SmtBuild)> {
        use kaspa_seq_commit::hashing::mergeset_context_hash;
        use kaspa_seq_commit::types::MergesetContext;

        let selected_parent = ctx.selected_parent();
        let parent_header = self.headers_store.get_header(selected_parent).unwrap();
        let current_blue_score = ctx.ghostdag_data.blue_score;

        let inactivity_shortcut_block = self.compute_inactivity_shortcut_block(&ctx.ghostdag_data);
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp: parent_header.timestamp,
            daa_score: header.daa_score,
            blue_score: current_blue_score,
        });
        let inactivity_shortcut = self.inactivity_shortcut(inactivity_shortcut_block);

        let parent_seq_commit = parent_header.accepted_id_merkle_root;
        let data = self.collect_mergeset_seq_data(ctx);
        let lane_updates = self.resolve_lane_updates(
            &data,
            &context_hash,
            current_blue_score,
            parent_header.blue_score,
            selected_parent,
            parent_seq_commit,
        );
        let (parent_lanes_root, parent_active_lanes) = self.get_parent_lanes_root_and_count(selected_parent, parent_header.blue_score);
        let parent_state = ParentBlockSeqState {
            seq_commit: parent_seq_commit,
            blue_score: parent_header.blue_score,
            lanes_root: parent_lanes_root,
            active_lanes_count: parent_active_lanes,
        };

        let (hash, build) = self.build_seq_commit(
            &parent_state,
            context_hash,
            current_blue_score,
            &lane_updates,
            data.miner_payload_leaves,
            selected_parent,
            inactivity_shortcut_block,
            inactivity_shortcut,
        );

        Ok((hash, build))
    }

    /// Calculates the accepted_id_merkle_root based on the current DAA score and the accepted tx ids
    /// refer KIP-15 for more details
    pub(super) fn calc_accepted_id_merkle_root(
        &self,
        accepted_tx_digests: impl ExactSizeIterator<Item = Hash>,
        selected_parent: Hash,
    ) -> Hash {
        kaspa_merkle::merkle_hash(
            self.headers_store.get_header(selected_parent).unwrap().accepted_id_merkle_root,
            kaspa_merkle::calc_merkle_root(accepted_tx_digests),
        )
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn test_rayon_reduce_retains_order() {
        // this is an independent test to replicate the behavior of
        // validate_txs_in_parallel and validate_txs_with_muhash_in_parallel
        // and assert that the order of data is retained when doing par_iter
        let data: Vec<u16> = (1..=1000).collect();

        let collected: Vec<u16> = data
            .par_iter()
            .filter_map(|a| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(*a)
            })
            .collect();

        println!("collected len: {}", collected.len());

        collected.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });

        let reduced: SmallVec<[u16; 2]> = data
            .par_iter()
            .filter_map(|a: &u16| {
                let chance: f64 = rand::random();
                if chance < 0.05 {
                    return None;
                }
                Some(smallvec![*a])
            })
            .reduce(
                || smallvec![],
                |mut arr, mut curr_data| {
                    arr.append(&mut curr_data);
                    arr
                },
            );

        println!("reduced len: {}", reduced.len());

        reduced.iter().tuple_windows().for_each(|(prev, curr)| {
            // Data was originally sorted, so we check if they remain sorted after filtering
            assert!(prev < curr, "expected {} < {} if original sort was preserved", prev, curr);
        });
    }
}
