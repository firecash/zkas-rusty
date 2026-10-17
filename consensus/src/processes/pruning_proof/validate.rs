use std::{
    ops::{ControlFlow, DerefMut},
    sync::{Arc, atomic::Ordering},
};

use itertools::Itertools;
use kaspa_consensus_core::{
    BlockLevel, BlueWorkType,
    blockhash::{BlockHashExtensions, BlockHashes, ORIGIN},
    errors::pruning::{ProofWeakness, PruningImportError, PruningImportResult},
    header::Header,
    pruning::{PruningPointProof, PruningProofMetadata},
};
use kaspa_core::{info, warn};
use kaspa_database::{
    prelude::{CachePolicy, ConnBuilder, StoreResultUnitExt},
    utils::DbLifetime,
};
use kaspa_hashes::Hash;
use kaspa_pow::calc_block_level_check_pow_gated;
use kaspa_utils::vec::VecExtensions;
use parking_lot::RwLock;
use rocksdb::WriteBatch;

use crate::{
    model::{
        services::reachability::MTReachabilityService,
        stores::{
            ghostdag::{DbGhostdagStore, GhostdagStore, GhostdagStoreReader},
            headers::{DbHeadersStore, HeaderStore, HeaderStoreReader},
            headers_selected_tip::HeadersSelectedTipStoreReader,
            reachability::{DbReachabilityStore, ReachabilityStoreReader},
            relations::{DbRelationsStore, RelationsStoreReader},
        },
    },
    processes::{
        difficulty::level_work, ghostdag::protocol::GhostdagManager, pruning_proof::GhostdagReaderExt,
        reachability::inquirer as reachability, relations::RelationsStoreExtensions,
    },
};

use super::PruningProofManager;

struct ProofContext {
    _headers_store: Arc<DbHeadersStore>,
    ghostdag_stores: Vec<Arc<DbGhostdagStore>>,
    _relations_stores: Vec<DbRelationsStore>,
    _reachability_stores: Vec<Arc<RwLock<DbReachabilityStore>>>,
    _ghostdag_managers:
        Vec<GhostdagManager<DbGhostdagStore, DbRelationsStore, MTReachabilityService<DbReachabilityStore>, DbHeadersStore>>,
    selected_tip_by_level: Vec<Hash>,

    pp_header: Arc<Header>,
    _pp_level: BlockLevel,

    _db_lifetime: DbLifetime,
}

struct ProofLevelContext<'a> {
    ghostdag_store: &'a DbGhostdagStore,
    selected_tip: Hash,
}

impl ProofLevelContext<'_> {
    /// Returns an option of the hash of the challenger and defender's common ancestor at this level.
    /// If no such ancestor exists, returns None.
    fn find_common_ancestor(challenger: &Self, defender: &Self) -> Option<Hash> {
        let mut current = challenger.selected_tip;
        let mut challenger_gd_of_current = challenger.ghostdag_store.get_compact_data(current).unwrap();
        loop {
            if defender.ghostdag_store.has(current).unwrap() {
                break Some(current);
            } else {
                current = challenger_gd_of_current.selected_parent;
                if current.is_origin() {
                    break None;
                }
                challenger_gd_of_current = challenger.ghostdag_store.get_compact_data(current).unwrap();
            };
        }
    }

    /// Returns the blue work difference between the level selected tip and `ancestor`
    fn blue_work_diff(&self, ancestor: Hash) -> BlueWorkType {
        self.ghostdag_store
            .get_blue_work(self.selected_tip)
            .unwrap()
            .saturating_sub(self.ghostdag_store.get_blue_work(ancestor).unwrap())
    }

    /// Returns the overall blue score for this level (essentially the level selected tip blue score)
    fn blue_score(&self) -> u64 {
        self.ghostdag_store.get_blue_score(self.selected_tip).unwrap()
    }
}

impl ProofContext {
    /// Build the full context from the proof
    fn from_proof(
        ppm: &PruningProofManager,
        proof: &PruningPointProof,
        log_validating: bool,
    ) -> Result<ControlFlow<(), ProofContext>, PruningImportError> {
        if proof.len() != ppm.max_block_level as usize + 1 {
            return Err(PruningImportError::ProofNotEnoughLevels(ppm.max_block_level as usize + 1));
        }

        if proof[0].is_empty() {
            return Err(PruningImportError::PruningProofNotEnoughHeaders);
        }

        let ghostdag_k = ppm.ghostdag_k;

        let headers_estimate = ppm.estimate_proof_unique_size(proof);

        //
        // Initialize stores
        //

        let (db_lifetime, db) = kaspa_database::create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let cache_policy = CachePolicy::Count(2 * ppm.pruning_proof_m as usize);
        let headers_store =
            Arc::new(DbHeadersStore::new(db.clone(), CachePolicy::Count(headers_estimate), CachePolicy::Count(headers_estimate)));
        let ghostdag_stores = (0..=ppm.max_block_level)
            .map(|level| Arc::new(DbGhostdagStore::new(db.clone(), level, cache_policy, cache_policy)))
            .collect_vec();
        let mut relations_stores =
            (0..=ppm.max_block_level).map(|level| DbRelationsStore::new(db.clone(), level, cache_policy, cache_policy)).collect_vec();
        let reachability_stores = (0..=ppm.max_block_level)
            .map(|level| Arc::new(RwLock::new(DbReachabilityStore::with_block_level(db.clone(), cache_policy, cache_policy, level))))
            .collect_vec();

        let reachability_services = (0..=ppm.max_block_level)
            .map(|level| MTReachabilityService::new(reachability_stores[level as usize].clone()))
            .collect_vec();

        let ghostdag_managers = ghostdag_stores
            .iter()
            .cloned()
            .enumerate()
            .map(|(level, ghostdag_store)| {
                GhostdagManager::with_level(
                    ppm.genesis_hash,
                    ghostdag_k,
                    ghostdag_store,
                    relations_stores[level].clone(),
                    headers_store.clone(),
                    reachability_services[level].clone(),
                    level as BlockLevel,
                    ppm.max_block_level,
                )
            })
            .collect_vec();

        {
            let mut batch = WriteBatch::default();
            for level in 0..=ppm.max_block_level {
                let level = level as usize;
                reachability::init(reachability_stores[level].write().deref_mut()).unwrap();
                relations_stores[level].insert_batch(&mut batch, ORIGIN, BlockHashes::new(vec![])).unwrap();
                ghostdag_stores[level].insert(ORIGIN, ghostdag_managers[level].origin_ghostdag_data()).unwrap();
            }

            db.write(batch).unwrap();
        }

        let proof_pp_header = proof[0].last().expect("checked if empty").clone();
        let proof_pp_level = kaspa_pow::calc_block_level_gated(
            &proof_pp_header,
            ppm.max_block_level,
            ppm.skip_proof_of_work,
            ppm.aux_rule(&proof_pp_header),
        );
        let proof_pp = proof_pp_header.hash;

        //
        // Populate stores
        //

        let mut selected_tip_by_level = vec![None; ppm.max_block_level as usize + 1];
        for level in (0..=ppm.max_block_level).rev() {
            // Before processing this level, check if the process is exiting so we can end early
            if ppm.is_consensus_exiting.load(Ordering::Relaxed) {
                return Ok(ControlFlow::Break(()));
            }

            if log_validating {
                info!("Validating level {level} from the pruning point proof ({} headers)", proof[level as usize].len());
            }
            let level_idx = level as usize;
            let mut selected_tip =
                proof[level_idx].first().map(|header| header.hash).ok_or(PruningImportError::PruningProofNotEnoughHeaders)?;
            for (i, header) in proof[level_idx].iter().enumerate() {
                // Only genesis has no parents. A fabricated proof is built out of headers whose
                // parent structure is whatever the sender wanted, so refuse the degenerate
                // shape before anything is derived from it. (Upstream rusty-kaspa 2a47b249.)
                if header.parents_by_level.is_empty() && header.hash != ppm.genesis_hash {
                    return Err(PruningImportError::NonGenesisParentlessHeader(header.hash));
                }
                let (header_level, pow_passes) = calc_block_level_check_pow_gated(
                    header,
                    ppm.max_block_level,
                    ppm.skip_proof_of_work,
                    ppm.aux_rule(header),
                );
                if header_level < level {
                    // A merged-mined block missing its aux witness here means the prover
                    // stripped it (or pre-fix peer); log enough to tell that apart from a
                    // genuinely under-leveled header.
                    warn!(
                        "proof header {} at proof level {} computes level {}: daa={} bits={:#x} aux_witness={}",
                        header.hash,
                        level,
                        header_level,
                        header.daa_score,
                        header.bits,
                        header.aux_pow.is_some(),
                    );
                    return Err(PruningImportError::PruningProofWrongBlockLevel(header.hash, header_level, level));
                }
                if !ppm.skip_proof_of_work && !pow_passes {
                    return Err(PruningImportError::ProofOfWorkFailed(header.hash, level));
                }

                headers_store.insert(header.hash, header.clone(), header_level).idempotent().unwrap();

                // Filter out parents that do not appear at the pruning proof:
                let parents = ppm
                    .parents_manager
                    .parents_at_level(header, level)
                    .iter()
                    .copied()
                    .filter(|parent| ghostdag_stores[level_idx].has(*parent).unwrap())
                    .collect_vec();

                // Only the first block at each level is allowed to have no known parents
                if parents.is_empty() && i != 0 {
                    return Err(PruningImportError::PruningProofHeaderWithNoKnownParents(header.hash, level));
                }

                for &parent in parents.iter() {
                    if headers_store.get_header(parent).unwrap().blue_work >= header.blue_work {
                        return Err(PruningImportError::PruningProofInconsistentBlueWork(header.hash, level));
                    }
                }

                let parents: BlockHashes = parents.push_if_empty(ORIGIN).into();

                if relations_stores[level_idx].has(header.hash).unwrap() {
                    return Err(PruningImportError::PruningProofDuplicateHeaderAtLevel(header.hash, level));
                }

                relations_stores[level_idx].insert(header.hash, parents.clone()).unwrap();
                let ghostdag_data = Arc::new(ghostdag_managers[level_idx].ghostdag(&parents));
                ghostdag_stores[level_idx].insert(header.hash, ghostdag_data.clone()).unwrap();

                // Update the selected tip
                selected_tip = ghostdag_managers[level_idx].find_selected_parent([selected_tip, header.hash]);

                let mut level_reachability = reachability_stores[level_idx].write();
                let mut reachability_mergeset = ghostdag_data
                    .unordered_mergeset_without_selected_parent()
                    .filter(|hash| level_reachability.has(*hash).unwrap())
                    .collect_vec()
                    .into_iter();

                reachability::add_block(
                    level_reachability.deref_mut(),
                    header.hash,
                    ghostdag_data.selected_parent,
                    &mut reachability_mergeset,
                )
                .unwrap();

                if selected_tip == header.hash {
                    reachability::hint_virtual_selected_parent(level_reachability.deref_mut(), header.hash).unwrap();
                }
                drop(level_reachability);
            }

            if level < ppm.max_block_level {
                let block_at_depth_m_at_next_level = ghostdag_stores[level_idx + 1]
                    .block_at_depth(selected_tip_by_level[level_idx + 1].unwrap(), ppm.pruning_proof_m)
                    .unwrap();
                if !relations_stores[level_idx].has(block_at_depth_m_at_next_level).unwrap() {
                    return Err(PruningImportError::PruningProofMissingBlockAtDepthMFromNextLevel(level, level + 1));
                }
            }

            // The selected tip at a given level must be anchored to the pruning point:
            // - At levels ≤ the pruning-point level, the selected tip must be the pruning point itself.
            // - At higher levels, it must be a parent of the pruning point at that level.
            if level <= proof_pp_level {
                if selected_tip != proof_pp {
                    return Err(PruningImportError::PruningProofSelectedTipIsNotThePruningPoint(selected_tip, level));
                }
            } else if !ppm.parents_manager.parents_at_level(&proof_pp_header, level).contains(&selected_tip) {
                return Err(PruningImportError::PruningProofSelectedTipNotParentOfPruningPoint(selected_tip, level));
            }

            let level_tip = proof[level_idx].last().expect("checked earlier").hash;
            if level_tip != selected_tip {
                return Err(PruningImportError::PruningProofSelectedTipNotLast(level_tip, selected_tip, level));
            }

            let tip_blue_score = ghostdag_stores[level_idx].get_blue_score(selected_tip).expect("tip expected");
            let level_root = proof[level_idx].first().expect("checked earlier").hash;
            if level_root != ppm.genesis_hash && tip_blue_score < 2 * ppm.pruning_proof_m {
                return Err(PruningImportError::PruningProofSelectedTipNotEnoughBlueScore(selected_tip, level, tip_blue_score));
            }

            selected_tip_by_level[level_idx] = Some(selected_tip);
        }

        let selected_tip_by_level = selected_tip_by_level.into_iter().map(|selected_tip| selected_tip.unwrap()).collect();

        let ctx = ProofContext {
            _db_lifetime: db_lifetime,
            _headers_store: headers_store,
            ghostdag_stores,
            _relations_stores: relations_stores,
            _reachability_stores: reachability_stores,
            _ghostdag_managers: ghostdag_managers,
            selected_tip_by_level,
            pp_header: proof_pp_header,
            _pp_level: proof_pp_level,
        };

        Ok(ControlFlow::Continue(ctx))
    }

    /// Returns a per-level context
    fn level(&self, level: BlockLevel) -> ProofLevelContext<'_> {
        ProofLevelContext {
            ghostdag_store: &self.ghostdag_stores[level as usize],
            selected_tip: self.selected_tip_by_level[level as usize],
        }
    }

    /// The proof-of-work this proof demonstrates through its block levels, in expected hashes (the
    /// unit of `blue_work`). Nothing declared is read: the count at each level is the locally
    /// computed blue score of that level's selected tip, and every header counted there was checked
    /// above to compute a level of at least that level from its own hash. See
    /// [`level_attested_work`] for why that is work the sender cannot have skipped.
    ///
    /// The best estimate wins: the lowest level whose segment reaches genesis counts essentially
    /// the whole chain, lower levels count only their recent segment (an underestimate), and higher
    /// levels count the same chain with fewer, noisier samples. A level with fewer than
    /// [`MIN_ATTESTING_HEADERS`] headers is ignored, so a single lucky high-level header cannot
    /// stand in for a chain's worth of work.
    fn level_attested_work(&self, max_block_level: BlockLevel) -> BlueWorkType {
        (1..=max_block_level)
            .filter_map(|level| {
                // The level's root (a child of ORIGIN) has blue score 0 and each blue adds one, so
                // the tip's blue score counts every blue header of the level but one. When the root
                // is genesis -- free, its maximal level is a convention -- that one is genesis.
                let headers = self.level(level).blue_score();
                (headers >= MIN_ATTESTING_HEADERS).then(|| level_attested_work(headers, level, max_block_level))
            })
            .max()
            .unwrap_or(BlueWorkType::ZERO)
    }
}

/// Fewest headers at one level whose count is taken as evidence of work. A level-`L` header is a
/// `2^-(256 - max_block_level + L)` event per hash, so one of them proves little about how many
/// hashes were spent (the next one could take ten times as long); sixteen bound the estimate to
/// within a small factor. Every honest proof clears it with room to spare: the lowest level whose
/// segment reaches genesis holds about `pruning_proof_m` headers, because the level below it did not
/// reach genesis in `2 * pruning_proof_m`.
const MIN_ATTESTING_HEADERS: u64 = 16;

/// Expected hashes behind `headers` proof headers whose computed level is at least `level` (`>= 1`).
///
/// A block's level is `max_block_level - bits(pow)` (`kaspa_pow::calc_level_from_pow`): it depends
/// only on the hash value, not on the header's declared `bits`, so a level-`L` header needs
/// `pow < 2^(max_block_level - L)`, which a hash meets with probability `2^-(256 - max_block_level +
/// L)`. That per-header amount is [`level_work`], the same lower bound the level ghostdag above
/// already applies to every block of a level. Level 0 is excluded (its level work is zero): every
/// header has it, so its count proves only the declared `bits`, which is exactly what a fabricated
/// proof chooses. One solution can back at most two headers (a header, and the block it serves as
/// aux parent for, `kaspa_pow::auxpow::check_pow_gated`), so the estimate overstates a forger's real
/// work by at most a factor of two.
fn level_attested_work(headers: u64, level: BlockLevel, max_block_level: BlockLevel) -> BlueWorkType {
    let (work, overflow) = level_work(level, max_block_level).overflowing_mul_u64(headers);
    if overflow { BlueWorkType::MAX } else { work }
}

impl PruningProofManager {
    /// Validates an incoming pruning point proof against the current consensus.
    ///
    /// The function reconstructs temporary stores for both the
    /// challenger proof and the current (defender) consensus, validates all
    /// selected tips, and compares blue work including pruning-period work.
    ///
    /// Returns `Ok(())` if the proof is valid and superior, or an appropriate
    /// `PruningImportError` otherwise.
    pub fn validate_pruning_point_proof(
        &self,
        proof: &PruningPointProof,
        proof_metadata: &PruningProofMetadata,
    ) -> PruningImportResult<()> {
        // Initialize the stores for the incoming pruning proof (the challenger)
        let challenger =
            ProofContext::from_proof(self, proof, true)?.continue_value().ok_or(PruningImportError::PruningValidationInterrupted)?;

        // Get the proof for the current consensus (the defender) and recreate the stores for it
        // This is expected to be fast because if a proof exists, it will be cached.
        let defender_proof = self.get_pruning_point_proof();
        let defender = ProofContext::from_proof(self, &defender_proof, false)
            .expect("local")
            .continue_value()
            .ok_or(PruningImportError::PruningValidationInterrupted)?;

        Ok(self.compare_proofs_inner(
            defender,
            challenger,
            self.headers_selected_tip_store.read().get().unwrap().blue_work,
            proof_metadata.relay_block_blue_work,
        )?)
    }

    /// Compares two MLS pruning proofs and determines whether the challenger supersedes the defender.
    ///
    /// The comparison is performed level-by-level, considering only levels that satisfy the
    /// ≥2M threshold. When a common ancestor exists at a given level, the proofs are
    /// compared by their accumulated blue work from that ancestor onward, including the
    /// respective pruning-period work; otherwise, if no common ancestor is found, the
    /// challenger is considered better only if it possesses a qualifying level where the
    /// defender does not.
    ///
    /// The challenger is considered better only if it is *strictly* superior according to
    /// these criteria. In case of equality, or when no strict advantage can be established,
    /// the defender is favored to preserve stability.
    fn compare_proofs_inner(
        &self,
        defender: ProofContext,
        challenger: ProofContext,
        defender_relay_blue_work: BlueWorkType,
        challenger_relay_blue_work: BlueWorkType,
    ) -> Result<(), ProofWeakness> {
        // A node whose pruning point is still genesis has no proof of its own to weigh a challenger
        // against, and the challenger's headers are checked only against their own declared bits:
        // a chain mined at trivial difficulty from the real genesis wins every comparison below.
        // Where the network sets a floor, require the challenger to attest real work first, by its
        // block levels (see `ProofContext::level_attested_work`). Half the floor, because the
        // estimate is sampled and the floor is read off the real chain: an honest proof attests
        // about the floor or more, a forger has to spend at least a quarter of it (half, less the
        // factor-two aux allowance). This is node-local adoption policy, never a validity rule.
        if defender.pp_header.hash == self.genesis_hash
            && let Some(floor) = self.fresh_sync_proof_work_floor
        {
            let attested = challenger.level_attested_work(self.max_block_level);
            if attested < floor >> 1 {
                return Err(ProofWeakness::BelowFreshSyncWorkFloor(attested, floor));
            }
        }

        // The accumulated blue work of the defender's proof from the pruning point onward
        let defender_pruning_period_work = defender_relay_blue_work.saturating_sub(defender.pp_header.blue_work);

        // The claimed blue work of the challenger's proof from their pruning point and up to the triggering relay block. This work
        // will eventually be verified if the proof is accepted so we can treat it as trusted
        let challenger_claimed_pruning_period_work = challenger_relay_blue_work.saturating_sub(challenger.pp_header.blue_work);

        for level in 0..=self.max_block_level {
            // Init level ctxs
            let challenger_level_ctx = challenger.level(level);
            let defender_level_ctx = defender.level(level);

            // Next check is to see if the challenger's proof is "better" than the defender's
            // Step 1 - look only at levels that have a full proof (at least 2M blocks)
            if challenger_level_ctx.blue_score() < 2 * self.pruning_proof_m {
                continue;
            }

            // Step 2 - if a common ancestor exists between the challenger and defender proofs,
            // compare their accumulated blue work from that ancestor onward.
            // The challenger proof is better iff the blue work difference from the ancestor
            // to the challenger's selected tip, plus its pruning-period work, is strictly
            // greater than the corresponding defender value.
            if let Some(common_ancestor) = ProofLevelContext::find_common_ancestor(&challenger_level_ctx, &defender_level_ctx) {
                if defender_level_ctx.blue_work_diff(common_ancestor).saturating_add(defender_pruning_period_work)
                    >= challenger_level_ctx.blue_work_diff(common_ancestor).saturating_add(challenger_claimed_pruning_period_work)
                {
                    return Err(ProofWeakness::InsufficientBlueWork);
                }

                return Ok(());
            }
        }

        // There used to be an unconditional `Ok(())` here for a defender whose pruning point is
        // still genesis -- a node that has just started. It was reachable with a proof carrying
        // no work at all: Step 1 above skips every level whose CHALLENGER blue score is under
        // 2M, so a proof of two headers (genesis plus one crafted block with easy declared bits
        // and a declared blue work of the attacker's choosing) never reached a single
        // comparison, fell through to the waiver, and was adopted -- with its DECLARED work
        // installed. Whoever was the fresh node's sync source could hand it a chain nobody
        // mined, for free, and it would then refuse the real one.
        //
        // Removing the waiver does not make a fresh node unable to sync: it falls through to
        // the rule written just below for every other defender, and that rule already says
        // exactly the right thing for a defender holding nothing. An honest challenger either
        // shares genesis with the defender -- Step 2 then compares blue work from it, and the
        // defender's is zero on both terms, so the challenger wins -- or it has no common
        // ancestor (a mature chain's level-0 segment does not reach back to genesis) and wins
        // in the loop below, where a genesis-only defender cannot have a 2M level. What no
        // longer passes is a proof that has neither: a structurally empty one.
        //
        // On its own this raises the price of the attack from two headers to a structurally
        // complete proof, but does not make the proof's work real: the headers are checked only
        // against their own declared bits. The fresh-sync work floor at the top of this function
        // closes that for a chain forged from genesis, on networks that set one. It does not
        // close a proof that reuses the real chain's headers up to some point and forges only
        // the part after it; see the floor's documentation in `Params`.

        // If we got here it means there's no level with shared blocks
        // between the challenger and the defender. In this case we
        // consider the challenger to be better if it has at least one level
        // with 2M blue blocks where the defender doesn't.
        for level in (0..=self.max_block_level).rev() {
            if challenger.level(level).blue_score() < 2 * self.pruning_proof_m {
                continue;
            }
            if defender.level(level).blue_score() < 2 * self.pruning_proof_m {
                return Ok(());
            }
        }

        drop(challenger);
        drop(defender);

        Err(ProofWeakness::NotEnoughHeaders)
    }

    /// Compares two MLS pruning proofs and determines whether the challenger supersedes the defender.
    ///
    /// See [`PruningProofManager::compare_proofs_inner`] for more details.
    ///
    /// Exposed here for local revalidation needs.
    pub(crate) fn _compare_proofs(
        &self,
        defender: &PruningPointProof,
        challenger: &PruningPointProof,
        defender_relay_blue_work: BlueWorkType,
        challenger_relay_blue_work: BlueWorkType,
    ) -> ControlFlow<(), Result<(), ProofWeakness>> {
        ControlFlow::Continue(self.compare_proofs_inner(
            ProofContext::from_proof(self, defender, false).expect("local")?,
            ProofContext::from_proof(self, challenger, false).expect("local")?,
            defender_relay_blue_work,
            challenger_relay_blue_work,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::level_attested_work;
    use crate::consensus::test_consensus::TestConsensus;
    use kaspa_consensus_core::{
        BlockLevel, BlueWorkType,
        api::ConsensusApi,
        config::{Config, ConfigBuilder, params::MAINNET_PARAMS},
        errors::pruning::{ProofWeakness, PruningImportError},
        pruning::{PruningPointProof, PruningProofMetadata},
    };
    use kaspa_hashes::Hash;
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    #[test]
    fn level_attested_work_counts_hashes_not_declared_bits() {
        // Mainnet: a level-1 header needs pow < 2^224, i.e. 2^32 hashes in expectation.
        assert_eq!(level_attested_work(1, 1, 225), BlueWorkType::from_u64(1 << 32));
        assert_eq!(level_attested_work(3, 2, 225), BlueWorkType::from_u64(3 << 33));
        assert_eq!(level_attested_work(0, 7, 225), BlueWorkType::ZERO);
        // Level 0 attests nothing: every header has it, whatever bits it declares.
        assert_eq!(level_attested_work(1_000_000, 0, 225), BlueWorkType::ZERO);
        // Above `MAX_WORK_LEVEL` the per-header work stops growing (`level_work`): an undercount,
        // never an overcount.
        assert_eq!(level_attested_work(1, 120, 225), BlueWorkType::from_u64(1) << 128);
    }

    // The scenario below is a test-scale model of mainnet's fresh-node sync, on a network whose
    // block levels populate without real mining: proof-of-work checks are skipped, but a block's
    // level is still `max_block_level - bits(kHeavyHash(header))`, and with `max_block_level = 254`
    // a hash reaches level `L >= 1` with probability `2^-(L + 2)`, so each block is worth one hash
    // and a level-1 header is worth 8 (`level_work(1, 254)`).
    const TEST_MAX_BLOCK_LEVEL: BlockLevel = 254;
    const PROOF_M: u64 = 16;

    fn config(floor: Option<u64>) -> Config {
        ConfigBuilder::new(MAINNET_PARAMS)
            .skip_proof_of_work()
            .edit_consensus_params(|p| {
                // The pruning parameters of the integration `pruning_test`, which advance the
                // pruning point after ~100 blocks of a single chain.
                p.finality_depth = 2;
                p.mergeset_size_limit = 2;
                p.ghostdag_k = 2;
                p.merge_depth = 3;
                p.pruning_depth = 100;
                p.pruning_proof_m = PROOF_M;
                p.max_block_level = TEST_MAX_BLOCK_LEVEL;
                // Empty-script coinbases (transparent), as in the virtual processor tests.
                p.shielded_coinbase = false;
                p.fresh_sync_proof_work_floor = floor.map(BlueWorkType::from_u64);
            })
            .build()
    }

    /// Mine a single chain on a node of its own until its pruning point has at least
    /// `min_pruning_point_blue_score`, and return that node's proof with the metadata a relay
    /// from it would carry.
    async fn mine_chain(hash_base: u64, min_pruning_point_blue_score: u64) -> (Arc<PruningPointProof>, PruningProofMetadata) {
        let config = config(None);
        let tc = TestConsensus::new(&config);
        let wait_handles = tc.init();
        let mut tip = config.genesis.hash;
        let blocks = min_pruning_point_blue_score + config.pruning_depth() + 20;
        for i in 1..=blocks {
            let hash: Hash = (hash_base + i).into();
            tc.add_empty_utxo_valid_block_with_parents(hash, vec![tip]).await.unwrap();
            tip = hash;
        }
        // The pruning point is advanced by the pruning processor, asynchronously.
        let start = Instant::now();
        loop {
            let pp = tc.pruning_point();
            if pp != config.genesis.hash && tc.get_header(pp).unwrap().blue_score >= min_pruning_point_blue_score {
                break;
            }
            // Generous on purpose: every pruning-point move first builds the proof, and with this
            // config's 255 levels one build took 29 s on a loaded build box (measured 2026-10-17;
            // later moves ~1 s). The 30 s this used to allow failed the test on load alone, and its
            // panic, raised with the consensus still open, aborted the whole test binary.
            assert!(start.elapsed() < Duration::from_secs(600), "timed out waiting for the pruning point to advance");
            std::thread::sleep(Duration::from_millis(100));
        }
        let proof = tc.get_pruning_point_proof();
        let metadata = PruningProofMetadata::new(tc.get_header(tc.get_headers_selected_tip()).unwrap().blue_work);
        tc.shutdown(wait_handles);
        (proof, metadata)
    }

    /// The proof that used to be adopted for free: genesis, then one block carrying whatever blue
    /// work its author declared, at level 0 so the proof is otherwise well formed.
    fn two_header_proof(fresh: &TestConsensus) -> PruningPointProof {
        let genesis_hash = fresh.params().genesis.hash;
        let genesis = fresh.get_header(genesis_hash).unwrap();
        let mut forged = fresh.build_header_with_parents(Hash::from_u64_word(0xF4F4_F4F4), vec![genesis_hash]);
        forged.blue_work = BlueWorkType::from_u64(u64::MAX);
        while kaspa_pow::calc_block_level(&forged, TEST_MAX_BLOCK_LEVEL, true) != 0 {
            forged.nonce += 1;
        }
        let forged = Arc::new(forged);
        (0..=TEST_MAX_BLOCK_LEVEL)
            .map(|level| if level == 0 { vec![genesis.clone(), forged.clone()] } else { vec![genesis.clone()] })
            .collect()
    }

    fn is_weakness(result: &Result<(), PruningImportError>, check: impl Fn(&ProofWeakness) -> bool) -> bool {
        matches!(result, Err(PruningImportError::ProofWeaknessError(weakness)) if check(weakness))
    }

    /// `compare_proofs_inner` with a genesis defender: the case of every node's first sync.
    ///
    /// An honest proof from a real (test) node is adopted with or without the floor. A proof of
    /// two headers is refused either way (the waiver removed in 6b565e4 stays removed). A cheap but
    /// structurally complete chain forged from genesis -- the part 6b565e4 could not close -- is
    /// adopted by a node without a floor and refused by a node with one.
    #[tokio::test]
    async fn fresh_node_proof_adoption_needs_attested_work() {
        // Honest chain: pruning point at blue score >= 400, so its proof attests ~400 hashes (at
        // level 1 alone: 2M = 32 headers or more, worth 8 each, i.e. at least 256).
        let (honest, honest_md) = mine_chain(1_000_000, 400).await;
        // Forged chain from the same genesis: long enough to be complete (2M = 32 at level 0),
        // too short to hold MIN_ATTESTING_HEADERS headers at any level >= 1 in expectation.
        let (forged_chain, forged_md) = mine_chain(2_000_000, 40).await;

        // The floor a real network would read off its chain (the honest pruning point's blue score,
        // in this model's units); half of it, 200, must be attested. The honest proof clears that on
        // its level-1 segment alone (at least 2M = 32 headers worth 8, or all ~52 of them). The
        // forged chain's pruning point is at most ~60 blocks deep, so it would need 25 of those to
        // be level 1 (expected ~7), or MIN_ATTESTING_HEADERS of them to be level 2 (expected ~4).
        let floor = 400;

        let open = TestConsensus::new(&config(None));
        let guarded = TestConsensus::new(&config(Some(floor)));
        let open_handles = open.init();
        let guarded_handles = guarded.init();

        let adopted = open.validate_pruning_proof(&honest, &honest_md);
        assert!(adopted.is_ok(), "honest proof refused by an open node: {adopted:?}");
        let adopted = guarded.validate_pruning_proof(&honest, &honest_md);
        assert!(adopted.is_ok(), "honest proof refused by a guarded node: {adopted:?}");

        let two = two_header_proof(&open);
        let md = PruningProofMetadata::new(BlueWorkType::from_u64(u64::MAX));
        let refused = open.validate_pruning_proof(&two, &md);
        assert!(is_weakness(&refused, |w| matches!(w, ProofWeakness::NotEnoughHeaders)), "two-header proof adopted: {refused:?}");
        let refused = guarded.validate_pruning_proof(&two, &md);
        assert!(
            is_weakness(&refused, |w| matches!(w, ProofWeakness::BelowFreshSyncWorkFloor(..))),
            "two-header proof not refused by the floor: {refused:?}"
        );

        // The residual 6b565e4 left open, pinned so the floor is seen to be what closes it.
        let adopted = open.validate_pruning_proof(&forged_chain, &forged_md);
        assert!(adopted.is_ok(), "without a floor a complete low-work chain from genesis is adopted (the gap): {adopted:?}");
        let refused = guarded.validate_pruning_proof(&forged_chain, &forged_md);
        assert!(
            is_weakness(&refused, |w| matches!(w, ProofWeakness::BelowFreshSyncWorkFloor(..))),
            "low-work chain from genesis not refused by the floor: {refused:?}"
        );

        open.shutdown(open_handles);
        guarded.shutdown(guarded_handles);
    }
}
