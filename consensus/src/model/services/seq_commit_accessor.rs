use crate::model::services::reachability::{MTReachabilityService, ReachabilityService};
use crate::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use crate::model::stores::reachability::DbReachabilityStore;
use kaspa_consensus_core::config::params::ForkActivation;
use kaspa_database::prelude::StoreResultExt;
use kaspa_hashes::Hash;

/// Shared utility function to keep the "within threshold" definition consistent across callers.
pub fn seq_commit_within_threshold(high_blue_score: u64, low_blue_score: u64, threshold: u64) -> bool {
    // Exact for every input: a sum past u64::MAX is above any `high_blue_score`. A plain `+`
    // panicked under the release build's overflow checks on a peer-supplied blue score (the
    // pruning-point chain segment walk reads headers a syncer sent), and the panic hook exits.
    low_blue_score.checked_add(threshold).is_none_or(|sum| sum > high_blue_score)
}

#[derive(Copy, Clone)]
pub struct SeqCommitAccessor<'a> {
    pub threshold: u64,
    pub selected_parent: Hash,
    pub reachability_service: &'a MTReachabilityService<DbReachabilityStore>,
    pub headers_store: &'a DbHeadersStore,
    pub toccata_activation: ForkActivation,
}

impl<'a> SeqCommitAccessor<'a> {
    pub fn new(
        selected_parent: Hash,
        reachability_service: &'a MTReachabilityService<DbReachabilityStore>,
        headers_store: &'a DbHeadersStore,
        toccata_activation: ForkActivation,
        threshold: u64,
    ) -> Self {
        Self { threshold, selected_parent, reachability_service, headers_store, toccata_activation }
    }
}

impl<'a> kaspa_txscript::SeqCommitAccessor for SeqCommitAccessor<'a> {
    fn is_chain_ancestor_from_pov(&self, block_hash: Hash) -> Option<bool> {
        self.reachability_service.try_is_chain_ancestor_of(block_hash, self.selected_parent).optional().unwrap()
    }

    fn seq_commitment_within_depth(&self, block_hash: Hash) -> Option<Hash> {
        let header = self.headers_store.get_header(block_hash).optional().unwrap()?;
        if !self.toccata_activation.is_active(header.daa_score) {
            return None;
        }
        let sp_blue_score = self.headers_store.get_blue_score(self.selected_parent).unwrap();
        if seq_commit_within_threshold(sp_blue_score, header.blue_score, self.threshold) {
            Some(header.accepted_id_merkle_root)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod threshold_tests {
    use super::seq_commit_within_threshold;

    #[test]
    fn within_threshold_is_exact_and_never_overflows() {
        assert!(seq_commit_within_threshold(10, 10, 1));
        assert!(!seq_commit_within_threshold(11, 10, 1));
        assert!(seq_commit_within_threshold(10, 9, 2));
        // A sum past u64::MAX is above every high score; this used to panic.
        assert!(seq_commit_within_threshold(u64::MAX - 1, u64::MAX, 5));
        assert!(seq_commit_within_threshold(0, u64::MAX, u64::MAX));
    }
}
