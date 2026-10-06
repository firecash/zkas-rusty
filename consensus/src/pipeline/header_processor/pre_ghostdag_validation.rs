use super::*;
use crate::errors::{BlockProcessResult, RuleError};
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::statuses::StatusesStoreReader;
use kaspa_consensus_core::BlockLevel;
use kaspa_consensus_core::blockhash::BlockHashExtensions;
use kaspa_consensus_core::blockstatus::BlockStatus::StatusInvalid;
use kaspa_consensus_core::header::Header;
use kaspa_core::time::unix_now;
use kaspa_database::prelude::StoreResultExt;
use kaspa_pow::calc_level_from_pow;

impl HeaderProcessor {
    /// Validates the header in isolation including pow check against header declared bits.
    /// Returns the block level as computed from pow state or a rule error if such was encountered
    pub(super) fn validate_header_in_isolation(&self, header: &Header) -> BlockProcessResult<BlockLevel> {
        self.check_header_version(header)?;
        self.check_block_timestamp_in_isolation(header)?;
        self.check_parents_limit(header)?;
        Self::check_parents_not_origin(header)?;
        self.check_pow_and_calc_block_level(header)
    }

    pub(super) fn validate_parent_relations(&self, header: &Header) -> BlockProcessResult<()> {
        self.check_parents_exist(header)?;
        self.check_parents_incest(header)?;
        Ok(())
    }

    fn check_header_version(&self, _header: &Header) -> BlockProcessResult<()> {
        // TODO(post-toccata): Uncomment this and remove check_header_version_in_context.
        // if header.version != constants::TOCCATA_BLOCK_VERSION {
        //     return Err(RuleError::WrongBlockVersion(header.version));
        // }
        Ok(())
    }

    fn check_block_timestamp_in_isolation(&self, header: &Header) -> BlockProcessResult<()> {
        // Timestamp deviation tolerance is in seconds so we multiply by 1000 to get milliseconds (without BPS dependency)
        let max_block_time = unix_now() + self.timestamp_deviation_tolerance * 1000;
        if header.timestamp > max_block_time {
            return Err(RuleError::TimeTooFarIntoTheFuture(header.timestamp, max_block_time));
        }
        Ok(())
    }

    fn check_parents_limit(&self, header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().is_empty() {
            return Err(RuleError::NoParents);
        }

        let max_block_parents = self.max_block_parents as usize;
        if header.direct_parents().len() > max_block_parents {
            return Err(RuleError::TooManyParents(header.direct_parents().len(), max_block_parents));
        }

        Ok(())
    }

    fn check_parents_not_origin(header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().iter().any(|&parent| parent.is_origin()) {
            return Err(RuleError::OriginParent);
        }

        Ok(())
    }

    fn check_parents_exist(&self, header: &Header) -> BlockProcessResult<()> {
        let mut missing_parents = Vec::new();
        for parent in header.direct_parents() {
            match self.statuses_store.read().get(*parent).optional().unwrap() {
                None => missing_parents.push(*parent),
                Some(StatusInvalid) => {
                    return Err(RuleError::InvalidParent(*parent));
                }
                Some(_) => {}
            }
        }
        if !missing_parents.is_empty() {
            return Err(RuleError::MissingParents(missing_parents));
        }
        Ok(())
    }

    fn check_parents_incest(&self, header: &Header) -> BlockProcessResult<()> {
        let parents = header.direct_parents();
        for parent_a in parents.iter() {
            for parent_b in parents.iter() {
                if parent_a == parent_b {
                    continue;
                }

                if self.reachability_service.is_dag_ancestor_of(*parent_a, *parent_b) {
                    return Err(RuleError::InvalidParentsRelation(*parent_a, *parent_b));
                }
            }
        }

        Ok(())
    }

    fn check_pow_and_calc_block_level(&self, header: &Header) -> BlockProcessResult<BlockLevel> {
        if self.skip_proof_of_work {
            // PoW is not enforced in this mode; the native kHeavyHash value is computed
            // purely to derive the block level. Any AuxPoW witness is ignored here.
            let pow = kaspa_pow::State::new_skip_pow(header).check_pow(header.nonce).1;
            return Ok(calc_level_from_pow(pow, self.max_block_level));
        }
        // Option-2 dual acceptance: past the merged-mining activation a block may satisfy
        // PoW either natively or via a valid AuxPoW proof carried on the header. Before
        // activation the aux witness is ignored and only the native path can pass. Gating
        // on `header.daa_score` (the block's own claimed score) matches the other
        // header-stage fork gates; the score is re-derived and enforced in context, so a
        // block cannot lie about it to unlock aux acceptance early.
        let rule = kaspa_pow::auxpow::AuxRule::for_header(
            self.merged_mining_activation.is_active(header.daa_score),
            self.security_fork_activation.is_active(header.daa_score),
            self.genesis.hash,
        );
        let (passed, pow) = kaspa_pow::auxpow::check_pow_gated(header, header.aux_pow.as_deref(), rule);
        if passed { Ok(calc_level_from_pow(pow, self.max_block_level)) } else { Err(RuleError::InvalidPoW) }
    }
}
