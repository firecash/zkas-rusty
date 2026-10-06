use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet, hash_map::Entry::Vacant},
    sync::Arc,
};

use itertools::Itertools;
use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet, HashMapCustomHasher, KType,
    blockhash::{BlockHashes, ORIGIN},
    errors::pruning::{PruningImportError, PruningImportResult},
    header::Header,
    pruning::PruningPointProof,
    trusted::TrustedBlock,
};
use kaspa_core::{debug, trace};
use kaspa_database::prelude::StoreResultUnitExt;
use kaspa_hashes::Hash;
use kaspa_utils::{binary_heap::BinaryHeapExtensions, vec::VecExtensions};
use rocksdb::WriteBatch;

use crate::{
    model::{
        services::{reachability::ReachabilityService, seq_commit_accessor::seq_commit_within_threshold},
        stores::{
            ghostdag::{GhostdagData, GhostdagStore},
            headers::HeaderStore,
            pruning::PruningProofDescriptor,
            reachability::StagingReachabilityStore,
            relations::StagingRelationsStore,
            selected_chain::SelectedChainStore,
            virtual_state::{VirtualState, VirtualStateStore},
        },
    },
    processes::{
        ghostdag::{mergeset::unordered_mergeset_without_selected_parent, ordering::SortableBlock},
        reachability::inquirer as reachability,
        relations::RelationsStoreExtensions,
    },
};

use super::PruningProofManager;

impl PruningProofManager {
    pub fn apply_proof(
        &self,
        proof: PruningPointProof,
        trusted_set: &[TrustedBlock],
        header_only_chain_segment: &[Arc<Header>],
    ) -> PruningImportResult<()> {
        // Following validation of a pruning proof, various consensus storages must be updated

        let pruning_point_header = proof[0].last().unwrap().clone();
        let pruning_point = pruning_point_header.hash;

        // Build the descriptor based on the new proof before modifying it
        let descriptor = PruningProofDescriptor::from_proof(&proof, pruning_point, true);

        // Create a copy of the proof, since we're going to be mutating the proof passed to us
        let proof_sets = (0..=self.max_block_level)
            .map(|level| BlockHashSet::from_iter(proof[level as usize].iter().map(|header| header.hash)))
            .collect_vec();

        let mut expanded_proof = proof;
        let mut trusted_gd_map: BlockHashMap<GhostdagData> = BlockHashMap::new();
        let mut trusted_header_map: BlockHashMap<Arc<Header>> = BlockHashMap::new();

        // This loop expands the proof with the headers of the trusted set
        // and creates a hash to ghostdag data map of the trusted set
        for tb in trusted_set.iter() {
            // The peer's ghostdag row is stored as if this node had computed it, and the next
            // header's required blue work is read from it. Take blue score and blue work from the
            // header (PoW-bound; honest rows always equal it) and refuse a structurally impossible
            // mergeset before anything is written. Overlap used to panic in
            // `descending_mergeset_without_selected_parent` (process exit) on the first child.
            let mut gd: GhostdagData = tb.ghostdag.clone().into();
            Self::check_trusted_ghostdag(tb.block.hash(), &gd, self.ghostdag_k)?;
            gd.blue_score = tb.block.header.blue_score;
            gd.blue_work = tb.block.header.blue_work;
            trusted_gd_map.insert(tb.block.hash(), gd);
            trusted_header_map.insert(tb.block.hash(), tb.block.header.clone());
            let tb_block_level = kaspa_pow::calc_block_level_gated(
                &tb.block.header,
                self.max_block_level,
                self.skip_proof_of_work,
                self.merged_mining_activation.is_active(tb.block.header.daa_score),
            );

            (0..=tb_block_level).for_each(|current_proof_level| {
                // If this block was in the original proof, ignore it
                if proof_sets[current_proof_level as usize].contains(&tb.block.hash()) {
                    return;
                }
                // otherwise, add this block to the proof data
                expanded_proof[current_proof_level as usize].push(tb.block.header.clone());
            });
        }
        for header in header_only_chain_segment.iter() {
            if let Vacant(entry) = trusted_header_map.entry(header.hash) {
                entry.insert(header.clone());
            }
        }

        // Topologically sort every level in the proof
        expanded_proof.iter_mut().for_each(|level_proof| {
            level_proof.sort_by_key(|a| a.blue_work);
        });

        // Build selected-parent mapping for the PP chain segment
        let chain_segment_map = self.verify_and_build_chain_segment_map(
            pruning_point,
            &pruning_point_header,
            &trusted_header_map,
            header_only_chain_segment,
        )?;

        // Populate headers/reachability (using the PP chain segment mapping)
        self.populate_reachability_and_headers(&expanded_proof, header_only_chain_segment, &chain_segment_map)?;

        // Sanity check
        {
            let reachability_read = self.reachability_store.read();
            for tb in trusted_set.iter() {
                // A trusted block not in the past of the pruning point is in its anticone and thus must have a body
                if tb.block.is_header_only() && !reachability_read.is_dag_ancestor_of(tb.block.hash(), pruning_point) {
                    return Err(PruningImportError::PruningPointAnticoneMissingBody(tb.block.hash()));
                }

                // Trusted blocks are expected to be in the pruning point anti-future.
                if tb.block.hash() != pruning_point && reachability_read.is_dag_ancestor_of(pruning_point, tb.block.hash()) {
                    return Err(PruningImportError::TrustedBlockInPruningPointFuture(tb.block.hash(), pruning_point));
                }
            }
        }
        // Populate ghostdag_store and relation store for every block in the proof
        trace!("Applying level 0 from the pruning point proof");
        // We are only interested in those ancestors that belong to the pruning proof,
        // so other parents are filtered out.
        // Since the dag is topologically sorted, we can construct the ancestors
        // on the fly rather than constructing it ahead of time
        let mut ancestors: HashSet<Hash> = HashSet::new();
        ancestors.insert(ORIGIN);

        for header in expanded_proof[0].iter() {
            let parents = Arc::new(
                self.parents_manager
                    .parents_at_level(header, 0)
                    .iter()
                    .copied()
                    .filter(|parent| ancestors.contains(parent))
                    .collect_vec()
                    .push_if_empty(ORIGIN),
            );

            self.relations_store.write().insert(header.hash, parents.clone()).unwrap();
            let gd = if let Some(gd) = trusted_gd_map.get(&header.hash) {
                gd.clone()
            } else {
                let calculated_gd = self.ghostdag_manager.ghostdag(&parents);
                // Override the ghostdag data with the real blue score and blue work
                GhostdagData {
                    blue_score: header.blue_score,
                    blue_work: header.blue_work,
                    selected_parent: calculated_gd.selected_parent,
                    mergeset_blues: calculated_gd.mergeset_blues,
                    mergeset_reds: calculated_gd.mergeset_reds,
                    blues_anticone_sizes: calculated_gd.blues_anticone_sizes,
                }
            };
            self.ghostdag_store.insert(header.hash, Arc::new(gd)).unwrap();

            ancestors.insert(header.hash);
        }

        // Once applied, store the descriptor
        self.pruning_point_store.write().set_pruning_proof_descriptor(descriptor).unwrap();

        // Update virtual state based on proof derived pruning point.
        // updating of the utxoset is done separately as it requires downloading the new utxoset in its entirety.
        let virtual_parents = vec![pruning_point];
        let virtual_state = Arc::new(VirtualState {
            parents: virtual_parents.clone(),
            ghostdag_data: self.ghostdag_manager.ghostdag(&virtual_parents),
            ..VirtualState::default()
        });
        self.virtual_stores.write().state.set(virtual_state).unwrap();

        let mut batch = WriteBatch::default();
        self.body_tips_store.write().init_batch(&mut batch, &virtual_parents).unwrap();
        self.headers_selected_tip_store
            .write()
            .set_batch(&mut batch, SortableBlock { hash: pruning_point, blue_work: pruning_point_header.blue_work })
            .unwrap();
        self.selected_chain_store.write().init_with_pruning_point(&mut batch, pruning_point).unwrap();
        self.depth_store.insert_batch(&mut batch, pruning_point, ORIGIN, ORIGIN).unwrap();
        self.db.write(batch).unwrap();

        Ok(())
    }

    pub fn populate_reachability_and_headers(
        &self,
        proof: &PruningPointProof,
        header_only_chain_segment: &[Arc<Header>],
        chain_segment_map: &BlockHashMap<Hash>,
    ) -> PruningImportResult<()> {
        let capacity_estimate = self.estimate_proof_unique_size(proof);
        let mut dag = BlockHashMap::with_capacity(capacity_estimate);
        let mut up_heap = BinaryHeap::with_capacity(capacity_estimate);
        for header in proof.iter().flatten().chain(header_only_chain_segment.iter()).cloned() {
            if let Vacant(e) = dag.entry(header.hash) {
                // pow passing has already been checked during validation
                let block_level = kaspa_pow::calc_block_level_gated(
                    &header,
                    self.max_block_level,
                    self.skip_proof_of_work,
                    self.merged_mining_activation.is_active(header.daa_score),
                );
                self.headers_store.insert(header.hash, header.clone(), block_level).idempotent().unwrap();

                let mut parents = BlockHashSet::with_capacity(header.direct_parents().len() * 2);
                // We collect all available parent relations in order to maximize reachability information.
                // By taking into account parents from all levels we ensure that the induced DAG has valid
                // reachability information for each level-specific sub-DAG -- hence a single reachability
                // oracle can serve them all
                for level in 0..=self.max_block_level {
                    for parent in self.parents_manager.parents_at_level(&header, level) {
                        parents.insert(*parent);
                    }
                }

                struct DagEntry {
                    header: Arc<Header>,
                    parents: Arc<BlockHashSet>,
                }

                up_heap.push(Reverse(SortableBlock { hash: header.hash, blue_work: header.blue_work }));
                e.insert(DagEntry { header, parents: Arc::new(parents) });
            }
        }

        debug!("Estimated proof size: {}, actual size: {}", capacity_estimate, dag.len());

        for reverse_sortable_block in up_heap.into_sorted_iter() {
            // TODO: Convert to into_iter_sorted once it gets stable
            let hash = reverse_sortable_block.0.hash;
            let dag_entry = dag.get(&hash).unwrap();

            // Filter only existing parents
            let parents_in_dag = BinaryHeap::from_iter(
                dag_entry
                    .parents
                    .iter()
                    .cloned()
                    .filter(|parent| dag.contains_key(parent))
                    .map(|parent| SortableBlock { hash: parent, blue_work: dag.get(&parent).unwrap().header.blue_work }),
            );

            let reachability_read = self.reachability_store.upgradable_read();

            // Find the maximal parent antichain from the possibly redundant set of existing parents
            let mut reachability_parents: Vec<SortableBlock> = Vec::new();
            for parent in parents_in_dag.into_sorted_iter() {
                if reachability_read.is_dag_ancestor_of_any(parent.hash, &mut reachability_parents.iter().map(|parent| parent.hash)) {
                    continue;
                }

                reachability_parents.push(parent);
            }
            let reachability_parents_hashes =
                BlockHashes::new(reachability_parents.iter().map(|parent| parent.hash).collect_vec().push_if_empty(ORIGIN));

            // Prefer the specified chain segment parent when provided; otherwise infer as usual.
            let selected_parent = match chain_segment_map.get(&hash).copied() {
                Some(specified_parent) if reachability_parents_hashes.contains(&specified_parent) => specified_parent,
                Some(specified_parent) => {
                    return Err(PruningImportError::TrustedBlockSelectedParentMissing(hash, specified_parent));
                }
                None => reachability_parents.iter().max().map(|parent| parent.hash).unwrap_or(ORIGIN),
            };

            // Prepare batch
            let mut batch = WriteBatch::default();
            let mut reachability_relations_write = self.reachability_relations_store.write();
            let mut staging_reachability = StagingReachabilityStore::new(reachability_read);
            let mut staging_reachability_relations = StagingRelationsStore::new(&mut reachability_relations_write);

            // Stage
            staging_reachability_relations.insert(hash, reachability_parents_hashes.clone()).unwrap();
            let mergeset = unordered_mergeset_without_selected_parent(
                &staging_reachability_relations,
                &staging_reachability,
                selected_parent,
                &reachability_parents_hashes,
            );
            reachability::add_block(&mut staging_reachability, hash, selected_parent, &mut mergeset.iter().copied()).unwrap();

            // Commit
            let reachability_write = staging_reachability.commit(&mut batch).unwrap();
            staging_reachability_relations.commit(&mut batch).unwrap();

            // Write
            self.db.write(batch).unwrap();

            // Drop
            drop(reachability_write);
            drop(reachability_relations_write);
        }

        Ok(())
    }

    /// Verify and build a map from pruning-point chain blocks to their selected parent for reachability seeding.
    ///
    /// The map is populated only for Toccata-activated pruning points and only within the seqcommit
    /// threshold range; it relies on the chain-qualification rule (first direct parent is the selected parent).
    fn verify_and_build_chain_segment_map(
        &self,
        pruning_point: Hash,
        pruning_point_header: &Arc<Header>,
        trusted_header_map: &BlockHashMap<Arc<Header>>,
        header_only_chain_segment: &[Arc<Header>],
    ) -> PruningImportResult<BlockHashMap<Hash>> {
        let mut chain_segment_map: BlockHashMap<Hash> = BlockHashMap::new();
        let mut expected_chain_segment_hashes = BlockHashSet::new();

        if self.toccata_activation.is_active(pruning_point_header.daa_score) {
            // Pruning point txs are validated with the pruning point selected parent as seqcommit context.
            // The selected-parent context carries the full threshold range needed for both
            // seqcommit access and the inactivity shortcut anchor.
            let sp = pruning_point_header.direct_parents().first().copied().unwrap_or(pruning_point); // In case of genesis, we fall back to genesis itself
            let context_blue_score =
                trusted_header_map.get(&sp).ok_or(PruningImportError::MissingPruningPointChainSegment(sp))?.blue_score;

            let threshold = self.finality_depth;
            let mut current = pruning_point;
            loop {
                expected_chain_segment_hashes.insert(current);
                let current_header =
                    trusted_header_map.get(&current).ok_or(PruningImportError::MissingPruningPointChainSegment(current))?;

                // pp.sp.bs context: a block failing the check satisfies `current.bs + F <= pp.sp.bs`,
                // and chain qualification gives pp.sp.bs = pp.bs - 1, so `current.bs <= pp.bs - F - 1`.
                // `pp.inactivity_shortcut` is defined as the highest chain block with that property
                // (see `compute_inactivity_shortcut_block`), so its bs is at least the break block's bs
                // and is reached by the iteration before (or at) the break.
                if !seq_commit_within_threshold(context_blue_score, current_header.blue_score, threshold) {
                    break;
                }

                if !self.toccata_activation.is_active(current_header.daa_score) {
                    // We cannot demand chain-qualification for blocks below the Toccata activation
                    // See the chain-qualification check in the utxo validation code for details as well as
                    // code in SeqCommitAccessor
                    break;
                }

                // Walk the selected-parent chain until we cross the threshold or hit genesis.
                // Relies on the Toccata-activated chain-qualification rule: the first direct parent is the selected parent.
                match current_header.direct_parents().first().copied() {
                    Some(selected_parent) => {
                        chain_segment_map.insert(current, selected_parent);
                        current = selected_parent;
                    }
                    None if current == self.genesis_hash => {
                        break;
                    }
                    None => {
                        return Err(PruningImportError::MissingPruningPointChainSegment(current));
                    }
                }
            }
        }

        for header in header_only_chain_segment {
            if !expected_chain_segment_hashes.contains(&header.hash) {
                return Err(PruningImportError::UnexpectedPruningPointChainSegmentBlock(header.hash));
            }
        }

        Ok(chain_segment_map)
    }
}

impl PruningProofManager {
    /// Structural checks that every honest trusted ghostdag row passes. Deliberately NOT
    /// "selected_parent == mergeset_blues[0]": an honest pruned server rewrites the selected
    /// parent of a kept block to ORIGIN when it lies outside the kept set
    /// (`pruning_processor` keep_relations filtering), so that rule would reject honest proofs.
    fn check_trusted_ghostdag(hash: Hash, gd: &GhostdagData, k: KType) -> PruningImportResult<()> {
        let bad = |why: String| Err(PruningImportError::InvalidTrustedGhostdag(hash, why));
        if gd.mergeset_blues.len() > k as usize + 1 {
            return bad(format!("{} blues exceed k+1 = {}", gd.mergeset_blues.len(), k as usize + 1));
        }
        let mut seen = BlockHashSet::with_capacity(gd.mergeset_blues.len() + gd.mergeset_reds.len());
        for h in gd.mergeset_blues.iter().chain(gd.mergeset_reds.iter()) {
            if !seen.insert(*h) {
                return bad(format!("{h} appears twice in the mergeset (blue/red overlap or duplicate)"));
            }
        }
        if let Some((h, size)) = gd.blues_anticone_sizes.iter().find(|(_, size)| **size > k) {
            return bad(format!("blue {h} has anticone size {size} above k = {k}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod trusted_ghostdag_tests {
    use super::*;
    use std::sync::Arc;

    fn h(n: u8) -> Hash {
        Hash::from_bytes([n; 32])
    }

    fn gd(blues: &[u8], reds: &[u8], anticone: &[(u8, KType)]) -> GhostdagData {
        GhostdagData {
            blue_score: 1,
            blue_work: 1u64.into(),
            selected_parent: h(blues.first().copied().unwrap_or(0)),
            mergeset_blues: Arc::new(blues.iter().map(|&b| h(b)).collect()),
            mergeset_reds: Arc::new(reds.iter().map(|&r| h(r)).collect()),
            blues_anticone_sizes: Arc::new(anticone.iter().map(|&(b, s)| (h(b), s)).collect()),
        }
    }

    #[test]
    fn honest_shaped_rows_pass_including_an_origin_selected_parent() {
        let k: KType = 18;
        PruningProofManager::check_trusted_ghostdag(h(9), &gd(&[1, 2], &[3], &[(1, 0), (2, 1)]), k).unwrap();
        // An honest pruned server rewrites the selected parent to ORIGIN; that must still pass.
        let mut row = gd(&[1, 2], &[], &[]);
        row.selected_parent = ORIGIN;
        PruningProofManager::check_trusted_ghostdag(h(9), &row, k).unwrap();
    }

    #[test]
    fn malformed_rows_are_refused_not_panicked_on() {
        let k: KType = 3;
        let err = |g: GhostdagData| PruningProofManager::check_trusted_ghostdag(h(9), &g, k).is_err();
        assert!(err(gd(&[1, 2], &[2], &[])), "blue/red overlap");
        assert!(err(gd(&[1, 1], &[], &[])), "duplicate blue");
        assert!(err(gd(&[1, 2, 3, 4, 5], &[], &[])), "more than k+1 blues");
        assert!(err(gd(&[1], &[], &[(1, 4)])), "anticone size above k");
    }
}
