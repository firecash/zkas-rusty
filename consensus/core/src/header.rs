use crate::{BlueWorkType, auxpow::AuxPow, hashing};
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Itertools;
use kaspa_hashes::Hash;
use kaspa_utils::{
    iter::{IterExtensions, IterExtensionsRle},
    mem_size::MemSizeEstimator,
};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

/// An efficient run-length encoding for the parent-by-level vector in the block header.
/// The i-th run `(cum_count, parents)` indicates that for all levels in the range `prev_cum_count..cum_count`,
/// the parents are `parents`.
///
/// Example: `[(3, [A]), (5, [B])]` means levels 0-2 have parents `[A]`,
/// and levels 3-4 have parents `[B]`.
/// Upper bound on the TOTAL number of parent hashes a header's run-length encoding may expand to.
///
/// `cum` is a `u8`, so a header has at most 255 levels, and an honest level never carries more than
/// `max_block_parents` (10 on mainnet) — an honest header therefore expands to ~2,550 hashes at
/// most. Nothing bounded the *contents* of a run, though, and header hashing walks
/// `expanded_iter()`, which repeats the same slice `count` times: one run of `(255, [30M hashes])`
/// is ~255 GB of Blake3 input, reached in `validate_header_in_isolation` before any difficulty
/// check and costing the sender no work at all. This bound is ~6x the honest maximum and keeps the
/// hashing input well under a mebibyte.
pub const MAX_EXPANDED_PARENT_HASHES: usize = 255 * 64;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize)]
pub struct CompressedParents(Vec<(u8, Vec<Hash>)>);

/// Borsh decoding routes through the validating [`TryFrom`] rather than filling the inner `Vec`
/// directly.
///
/// This is the aux-PoW witness path, and it is the whole of F-07: `expand_rle` PANICS on
/// cumulative counts that are not strictly increasing (`kaspa_utils::iter`), and the daemon's panic
/// hook turns any panic into `process::exit(1)`. The p2p edge re-ran this check by hand; the RPC
/// edge that serves `submit_block` did not, which left a zero-work remote node kill reachable by
/// anyone who could reach the RPC port. Enforcing the invariant in the type instead of at each edge
/// means a future decode site cannot forget it.
impl BorshDeserialize for CompressedParents {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let raw = Vec::<(u8, Vec<Hash>)>::deserialize_reader(reader)?;
        Self::try_from(raw).map_err(|e| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl CompressedParents {
    pub fn expanded_len(&self) -> usize {
        self.0.last().map(|(cum, _)| *cum as usize).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&[Hash]> {
        if index >= self.expanded_len() {
            return None;
        }
        if index == 0 {
            // Fast path for the common case of getting the first level (direct parents)
            return Some(&self.0[0].1);
        }
        // `partition_point` returns the index of the first element for which the predicate is false.
        // The predicate `cum - 1 < index` checks if a run is before the desired `index`.
        // The first run for which this is false is the one that contains our index.
        let i = self.0.partition_point(|(cum, _)| (*cum as usize) - 1 < index);
        Some(&self.0[i].1)
    }

    pub fn expanded_iter(&self) -> impl Iterator<Item = &'_ [Hash]> {
        self.0.iter().map(|(cum, v)| (*cum as usize, v.as_slice())).expand_rle()
    }

    /// Adds a new level of parents. This extends the last run if parents_at_level
    /// is identical to the last level, otherwise it starts a new run
    pub fn push(&mut self, parents_at_level: Vec<Hash>) {
        match self.0.last_mut() {
            Some((count, last_parents)) if *last_parents == parents_at_level => {
                *count = count.checked_add(1).expect("exceeded max levels of 255");
            }
            Some((count, _)) => {
                let next_cum = count.checked_add(1).expect("exceeded max levels of 255");
                self.0.push((next_cum, parents_at_level));
            }
            None => {
                self.0.push((1, parents_at_level));
            }
        }
    }

    /// Sets the direct parents (level 0) to the given value, preserving all other levels.
    ///
    /// NOTE: inefficient implementation, should be used for testing purposes only.
    pub fn set_direct_parents(&mut self, direct_parents: Vec<Hash>) {
        if self.0.is_empty() {
            self.0.push((1, direct_parents));
            return;
        }
        let mut parents: Vec<Vec<Hash>> = std::mem::take(self).into();
        parents[0] = direct_parents;
        *self = parents.try_into().unwrap();
    }

    /// Returns the internal cumulative-sum run-length encoded representation.
    pub fn raw(&self) -> &[(u8, Vec<Hash>)] {
        &self.0
    }
}

use crate::errors::header::CompressedParentsError;

impl TryFrom<Vec<Vec<Hash>>> for CompressedParents {
    type Error = CompressedParentsError;

    fn try_from(parents: Vec<Vec<Hash>>) -> Result<Self, Self::Error> {
        if parents.len() > u8::MAX as usize {
            return Err(CompressedParentsError::LevelsExceeded);
        }

        // Casting count from usize to u8 is safe because of the check above
        Ok(Self(parents.into_iter().rle_cumulative().map(|(count, level)| (count as u8, level)).collect()))
    }
}

impl TryFrom<Vec<(u8, Vec<Hash>)>> for CompressedParents {
    type Error = CompressedParentsError;
    fn try_from(parents: Vec<(u8, Vec<Hash>)>) -> Result<Self, Self::Error> {
        if matches!(parents.first(), Some((0, _))) {
            return Err(CompressedParentsError::LevelsNotStrictlyIncreasing);
        }

        for ((last_cumulative_level, last_parents), (cumulative_level, parents)) in parents.iter().tuple_windows() {
            // Make sure any next cumulative_level is strictly greater than the last
            if cumulative_level <= last_cumulative_level {
                return Err(CompressedParentsError::LevelsNotStrictlyIncreasing);
            }
            // Verify compression, any consecutive runs must have different parents
            if last_parents == parents {
                return Err(CompressedParentsError::NotFullyCompressed);
            }
        }

        // Bound what this expands to, not just how many runs it has. A run is hashed once per level
        // it covers, so `(255, [n hashes])` costs 255*n — see `MAX_EXPANDED_PARENT_HASHES`.
        let mut expanded_hashes: usize = 0;
        let mut previous_cumulative: usize = 0;
        for (cumulative_level, level_parents) in parents.iter() {
            let span = (*cumulative_level as usize).saturating_sub(previous_cumulative);
            expanded_hashes = expanded_hashes.saturating_add(span.saturating_mul(level_parents.len()));
            previous_cumulative = *cumulative_level as usize;
        }
        if expanded_hashes > MAX_EXPANDED_PARENT_HASHES {
            return Err(CompressedParentsError::ExpandedParentsExceeded(expanded_hashes, MAX_EXPANDED_PARENT_HASHES));
        }

        Ok(Self(parents))
    }
}

impl From<CompressedParents> for Vec<Vec<Hash>> {
    fn from(value: CompressedParents) -> Self {
        value.0.into_iter().map(|(cum, v)| (cum as usize, v)).expand_rle().collect()
    }
}

impl From<&CompressedParents> for Vec<Vec<Hash>> {
    fn from(value: &CompressedParents) -> Self {
        value.expanded_iter().map(|x| x.to_vec()).collect()
    }
}

/// @category Consensus
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Cached hash
    pub hash: Hash,
    pub version: u16,
    pub parents_by_level: CompressedParents,
    pub hash_merkle_root: Hash,
    pub accepted_id_merkle_root: Hash,
    pub utxo_commitment: Hash,
    /// Timestamp is in milliseconds
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub blue_work: BlueWorkType,
    pub blue_score: u64,
    pub pruning_point: Hash,
    /// Optional merged-mining (AuxPoW) proof. **Deliberately excluded from the header
    /// hash** (`hashing::header::hash` serializes only the fields above), so `H_fc`
    /// stays stable whether the block was mined natively or via a parent kHeavyHash
    /// block. It is a witness that travels alongside the header (borsh/serde/p2p) and
    /// is consulted only by the PoW gate once merged mining activates. `None` for a
    /// natively-mined block.
    ///
    /// `#[serde(default)]` (without `skip_serializing_if`) keeps this tolerant of
    /// inputs that omit the field — e.g. RPC JSON — while still always emitting it for
    /// non-self-describing formats like bincode (the header store), where a skipped
    /// field would corrupt the round-trip.
    #[serde(default)]
    pub aux_pow: Option<Box<AuxPow>>,
}

impl Header {
    #[allow(clippy::too_many_arguments)]
    pub fn new_finalized(
        version: u16,
        parents_by_level: CompressedParents,
        hash_merkle_root: Hash,
        accepted_id_merkle_root: Hash,
        utxo_commitment: Hash,
        timestamp: u64,
        bits: u32,
        nonce: u64,
        daa_score: u64,
        blue_work: BlueWorkType,
        blue_score: u64,
        pruning_point: Hash,
    ) -> Self {
        let mut header = Self {
            hash: Default::default(), // Temp init before the finalize below
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            nonce,
            timestamp,
            daa_score,
            bits,
            blue_work,
            blue_score,
            pruning_point,
            aux_pow: None,
        };
        header.finalize();
        header
    }

    /// Attach a merged-mining (AuxPoW) proof to a finalized header. The header hash is
    /// unaffected (aux data is not hashed), so this does not require re-finalizing.
    pub fn with_aux_pow(mut self, aux_pow: AuxPow) -> Self {
        self.aux_pow = Some(Box::new(aux_pow));
        self
    }

    /// Finalizes the header and recomputes the header hash
    pub fn finalize(&mut self) {
        self.hash = hashing::header::hash(self);
    }

    pub fn direct_parents(&self) -> &[Hash] {
        match self.parents_by_level.get(0) {
            Some(parents) => parents,
            None => &[],
        }
    }

    /// Returns the selected parent of this header, relying on the post-Toccata
    /// rule that the first direct parent of a virtual selected chain block is
    /// its selected parent. Callers must verify the header is a post-Toccata
    /// chain block before using this.
    pub fn post_toccata_chainblock_selected_parent(&self) -> Hash {
        self.direct_parents()[0]
    }

    /// WARNING: To be used for test purposes only
    pub fn from_precomputed_hash(hash: Hash, parents: Vec<Hash>) -> Header {
        Header {
            version: crate::constants::BLOCK_VERSION,
            hash,
            parents_by_level: vec![parents].try_into().unwrap(),
            hash_merkle_root: Default::default(),
            accepted_id_merkle_root: Default::default(),
            utxo_commitment: Default::default(),
            nonce: 0,
            timestamp: 0,
            daa_score: 0,
            bits: 0,
            blue_work: 0.into(),
            blue_score: 0,
            pruning_point: Default::default(),
            aux_pow: None,
        }
    }
}

impl AsRef<Header> for Header {
    fn as_ref(&self) -> &Header {
        self
    }
}

impl MemSizeEstimator for Header {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>()
            + self.parents_by_level.0.iter().map(|(_, l)| l.len()).sum::<usize>() * size_of::<Hash>()
            + self.parents_by_level.0.len() * size_of::<(u8, Vec<Hash>)>()
            // The AuxPoW witness lives on the heap (parent header + coinbase + Merkle branch).
            + self.aux_pow.as_ref().map_or(0, |a| {
                size_of::<AuxPow>()
                    + a.parent_header.estimate_mem_bytes()
                    // The whole coinbase, not just its payload: `inputs` carry unbounded
                    // signature scripts and `outputs` unbounded script_public_keys, and counting
                    // them as zero let a witness hold far more RAM than the headers cache's byte
                    // budget believed it was tracking.
                    + a.parent_coinbase.estimate_mem_bytes()
                    + a.coinbase_merkle_branch.len() * size_of::<Hash>()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_math::Uint192;
    use serde_json::Value;

    fn hash(val: u8) -> Hash {
        Hash::from(val as u64)
    }

    fn vec_from(slice: &[u8]) -> Vec<Hash> {
        slice.iter().map(|&v| hash(v)).collect()
    }

    /// Borsh decoding must enforce the same invariant `TryFrom` does.
    ///
    /// This is F-07: the aux-PoW witness is borsh-decoded, and derived borsh filled the inner `Vec`
    /// with no validation at all. `expand_rle` then PANICS on cumulative counts that are not strictly
    /// increasing, and the daemon's panic hook turns a panic into `process::exit(1)` — so a witness
    /// like this was a remote, zero-work node kill. The p2p edge re-checked by hand; the RPC edge
    /// serving `submit_block` did not. Enforcing it in the type means no edge can forget.
    #[test]
    fn borsh_decoding_rejects_parents_that_would_panic_expand_rle() {
        for raw in [
            vec![(0u8, vec_from(&[1]))],                        // first cumulative count is 0
            vec![(5u8, vec_from(&[1])), (2u8, vec_from(&[2]))], // decreasing
            vec![(3u8, vec_from(&[1])), (3u8, vec_from(&[2]))], // repeated
        ] {
            let bytes = borsh::to_vec(&raw).unwrap();
            assert!(
                borsh::from_slice::<CompressedParents>(&bytes).is_err(),
                "borsh must reject {raw:?} rather than hand back a value that panics when hashed"
            );
        }
        // A well-formed encoding still round-trips.
        let good = CompressedParents::try_from(vec![(1u8, vec_from(&[1])), (3u8, vec_from(&[2]))]).unwrap();
        let back: CompressedParents = borsh::from_slice(&borsh::to_vec(&good).unwrap()).unwrap();
        assert_eq!(good, back);
    }

    /// A run is hashed once per level it covers, so the bound has to be on what the encoding EXPANDS
    /// to, not on how many runs it has: one run of `(255, [n hashes])` costs 255*n, which made a
    /// single header worth hundreds of GB of Blake3 input before any difficulty check.
    #[test]
    fn borsh_decoding_bounds_what_the_encoding_expands_to() {
        let wide = vec![hash(1); 70];
        let over = vec![(255u8, wide)]; // 255 * 70 = 17,850 > MAX_EXPANDED_PARENT_HASHES
        assert!(borsh::from_slice::<CompressedParents>(&borsh::to_vec(&over).unwrap()).is_err());
        assert!(CompressedParents::try_from(over).is_err());

        // An honest header is nowhere near the ceiling: 255 levels x max_block_parents (10) = 2,550.
        let honest = vec![(255u8, vec![hash(1); 10])];
        let decoded: CompressedParents = borsh::from_slice(&borsh::to_vec(&honest).unwrap()).unwrap();
        assert_eq!(decoded.expanded_len(), 255);
    }

    fn serialize_parents(parents: &[Vec<Hash>]) -> Vec<u8> {
        let compressed: CompressedParents = (parents.to_vec()).try_into().unwrap();
        bincode::serialize(&compressed).unwrap()
    }

    fn deserialize_parents(bytes: &[u8]) -> bincode::Result<Vec<Vec<Hash>>> {
        let parents: CompressedParents = bincode::deserialize(bytes)?;
        Ok(parents.into())
    }

    #[test]
    fn test_header_ser() {
        let header = Header::new_finalized(
            1,
            vec![vec![1.into()]].try_into().unwrap(),
            Default::default(),
            Default::default(),
            Default::default(),
            234,
            23,
            567,
            0,
            Uint192([0x1234567890abcfed, 0xc0dec0ffeec0ffee, 0x1234567890abcdef]),
            u64::MAX,
            Default::default(),
        );
        let json = serde_json::to_string(&header).unwrap();
        println!("{}", json);

        let v = serde_json::from_str::<Value>(&json).unwrap();
        let blue_work = v.get("blueWork").expect("missing `blueWork` property");
        let blue_work = blue_work.as_str().expect("`blueWork` is not a string");
        assert_eq!(blue_work, "1234567890abcdefc0dec0ffeec0ffee1234567890abcfed");
        let blue_score = v.get("blueScore").expect("missing `blueScore` property");
        let blue_score: u64 = blue_score.as_u64().expect("blueScore is not a u64 compatible value");
        assert_eq!(blue_score, u64::MAX);

        let h = serde_json::from_str::<Header>(&json).unwrap();
        assert!(h.blue_score == header.blue_score && h.blue_work == header.blue_work);
    }

    #[test]
    fn parents_vrle_round_trip_multiple_runs() {
        let parents = vec![
            vec_from(&[1, 2, 3]),
            vec_from(&[1, 2, 3]),
            vec_from(&[1, 2, 3]),
            vec_from(&[4, 5]),
            vec_from(&[4, 5]),
            vec_from(&[6]),
        ];

        let bytes = serialize_parents(&parents);
        let decoded = deserialize_parents(&bytes).unwrap();
        assert_eq!(decoded, parents);
    }

    #[test]
    fn parents_vrle_round_trip_single_run() {
        let repeated = vec_from(&[9, 8, 7]);
        let parents = vec![repeated.clone(), repeated.clone(), repeated.clone()];

        let bytes = serialize_parents(&parents);
        let decoded = deserialize_parents(&bytes).unwrap();
        assert_eq!(decoded, parents);
    }

    #[test]
    fn parents_vrle_round_trip_empty() {
        let bytes = serialize_parents(&[]);
        let decoded = deserialize_parents(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn compressed_parents_len_and_get() {
        // Test with multiple runs of different lengths
        let first = vec_from(&[1]);
        let second = vec_from(&[2, 3]);
        let third = vec_from(&[4]);
        let parents = vec![first.clone(), first.clone(), second.clone(), second.clone(), third.clone()];
        let compressed = CompressedParents::try_from(parents.clone()).unwrap();

        assert_eq!(compressed.expanded_len(), parents.len());
        assert!(!compressed.is_empty());

        // Test `get` at various positions
        assert_eq!(compressed.get(0), Some(first.as_slice()), "get first element");
        assert_eq!(compressed.get(1), Some(first.as_slice()), "get element in the middle of a run");
        assert_eq!(compressed.get(2), Some(second.as_slice()), "get first element of a new run");
        assert_eq!(compressed.get(3), Some(second.as_slice()), "get element in the middle of a new run");
        assert_eq!(compressed.get(4), Some(third.as_slice()), "get last element");
        assert_eq!(compressed.get(5), None, "get out of bounds (just over)");
        assert_eq!(compressed.get(10), None, "get out of bounds (far over)");

        let collected: Vec<&[Hash]> = compressed.expanded_iter().collect();
        let expected: Vec<&[Hash]> = parents.iter().map(|v| v.as_slice()).collect();
        assert_eq!(collected, expected);

        // Test with an empty vec
        let parents_empty: Vec<Vec<Hash>> = vec![];
        let compressed_empty: CompressedParents = parents_empty.try_into().unwrap();
        assert_eq!(compressed_empty.expanded_len(), 0);
        assert!(compressed_empty.is_empty());
        assert_eq!(compressed_empty.get(0), None);

        // Test with a single run
        let parents_single_run = vec![first.clone(), first.clone(), first.clone()];
        let compressed_single_run: CompressedParents = parents_single_run.try_into().unwrap();
        assert_eq!(compressed_single_run.expanded_len(), 3);
        assert_eq!(compressed_single_run.get(0), Some(first.as_slice()));
        assert_eq!(compressed_single_run.get(1), Some(first.as_slice()));
        assert_eq!(compressed_single_run.get(2), Some(first.as_slice()));
        assert_eq!(compressed_single_run.get(3), None);
    }

    #[test]
    fn test_compressed_parents_push() {
        let mut compressed = CompressedParents(Vec::new());
        let level1 = vec_from(&[1, 2]);
        let level2 = vec_from(&[3, 4]);

        // 1. Push to empty
        compressed.push(level1.clone());
        assert_eq!(compressed.expanded_len(), 1);
        assert_eq!(compressed.0, vec![(1, level1.clone())]);

        // 2. Push same (extend run)
        compressed.push(level1.clone());
        assert_eq!(compressed.expanded_len(), 2);
        assert_eq!(compressed.0, vec![(2, level1.clone())]);

        // 3. Push different (new run)
        compressed.push(level2.clone());
        assert_eq!(compressed.expanded_len(), 3);
        assert_eq!(compressed.0, vec![(2, level1), (3, level2)]);
    }

    #[test]
    fn compressed_parents_binary_format_matches_runs() {
        let parents = vec![vec_from(&[1, 2, 3]), vec_from(&[1, 2, 3]), vec_from(&[4])];
        let compressed: CompressedParents = parents.try_into().unwrap();

        let encoded = bincode::serialize(&compressed).unwrap();
        let expected = bincode::serialize(&compressed.0).unwrap();
        assert_eq!(encoded, expected);
    }
}
