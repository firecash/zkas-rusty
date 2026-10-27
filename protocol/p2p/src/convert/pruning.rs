use super::error::ConversionError;
use crate::convert::header::{HeaderFormat, Versioned};
use crate::pb as protowire;
use kaspa_consensus_core::header::Header;
use kaspa_hashes::Hash;
use std::collections::HashMap;
use std::sync::Arc;

/// The deduplicated wire form of a pruning-point proof (N1, spec 13 L1): every distinct header once,
/// in order of first appearance, and per level the indices into that list. The levels of a mainnet
/// proof share most of their headers (79,047 header slots for 12,960 distinct headers measured), so
/// the message shrinks from ~215 MB to ~35 MB.
pub fn dedup_pruning_point_proof(header_format: HeaderFormat, proof: &[Vec<Arc<Header>>]) -> protowire::PruningPointProofMessage {
    let mut index: HashMap<Hash, u32> = HashMap::new();
    let mut distinct: Vec<protowire::BlockHeader> = Vec::new();
    let levels = proof
        .iter()
        .map(|level| protowire::PruningPointProofLevelIndices {
            indices: level
                .iter()
                .map(|h| {
                    *index.entry(h.hash).or_insert_with(|| {
                        distinct.push((header_format, h.as_ref()).into());
                        (distinct.len() - 1) as u32
                    })
                })
                .collect(),
        })
        .collect();
    protowire::PruningPointProofMessage { headers: vec![], distinct_headers: distinct, levels }
}

/// Decode the deduplicated form, with the receiver checks of spec 13 R-1.2, all before the proof is
/// validated: `max_levels` levels at most, every index in range, at most `max_refs` header slots in
/// total, every distinct header referenced at least once, and no two distinct headers with the same
/// hash. The result is the same `Vec<Vec<Arc<Header>>>` the full form decodes to, with one `Arc` per
/// header, so `validate_pruning_point_proof` sees exactly what it always saw.
pub fn undedup_pruning_point_proof(
    header_format: HeaderFormat,
    msg: protowire::PruningPointProofMessage,
    max_levels: usize,
    max_refs: usize,
) -> Result<Vec<Vec<Arc<Header>>>, ConversionError> {
    let bad = |what: &str| ConversionError::MalformedDedupProof(format!("deduplicated pruning point proof: {what}"));
    if !msg.headers.is_empty() {
        return Err(bad("carries both the full and the deduplicated form"));
    }
    if msg.levels.len() > max_levels {
        return Err(bad("more levels than the network has"));
    }
    let refs: usize = msg.levels.iter().map(|l| l.indices.len()).sum();
    if refs > max_refs || msg.distinct_headers.len() > refs {
        return Err(bad("header slot count out of bounds"));
    }
    let headers: Vec<Arc<Header>> = msg
        .distinct_headers
        .into_iter()
        .map(|h| Versioned(header_format, h).try_into().map(Arc::new))
        .collect::<Result<_, ConversionError>>()?;
    let mut seen: std::collections::HashSet<Hash> = std::collections::HashSet::with_capacity(headers.len());
    if !headers.iter().all(|h| seen.insert(h.hash)) {
        return Err(bad("a header is listed twice"));
    }
    let mut used = vec![false; headers.len()];
    let proof = msg
        .levels
        .into_iter()
        .map(|level| {
            level
                .indices
                .into_iter()
                .map(|i| {
                    let h = headers.get(i as usize).ok_or_else(|| bad("index out of range"))?;
                    used[i as usize] = true;
                    Ok(h.clone())
                })
                .collect::<Result<Vec<_>, ConversionError>>()
        })
        .collect::<Result<Vec<_>, ConversionError>>()?;
    if used.iter().any(|u| !u) {
        return Err(bad("a listed header is in no level"));
    }
    Ok(proof)
}

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<(HeaderFormat, &Vec<Arc<Header>>)> for protowire::PruningPointProofHeaderArray {
    fn from(value: (HeaderFormat, &Vec<Arc<Header>>)) -> Self {
        let (header_format, v) = value;
        Self { headers: v.iter().map(|header| (header_format, header.as_ref()).into()).collect() }
    }
}

// ----------------------------------------------------------------------------
// protowire to consensus_core
// ----------------------------------------------------------------------------

impl TryFrom<Versioned<protowire::PruningPointProofHeaderArray>> for Vec<Arc<Header>> {
    type Error = ConversionError;

    fn try_from(value: Versioned<protowire::PruningPointProofHeaderArray>) -> Result<Self, Self::Error> {
        let Versioned(header_format, v) = value;
        v.headers.into_iter().map(|x| Versioned(header_format, x).try_into().map(Arc::new)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(seed: u8) -> Arc<Header> {
        let mut h = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([seed; 32])]);
        h.finalize();
        Arc::new(h)
    }

    /// A proof shaped like mainnet's: levels that share most headers.
    fn proof() -> Vec<Vec<Arc<Header>>> {
        let hs: Vec<Arc<Header>> = (1..=40u8).map(header).collect();
        (0..6).map(|l| hs[l * 3..(l * 3 + 20).min(40)].to_vec()).collect()
    }

    /// N1 (spec 13 L1): the deduplicated form decodes to exactly the proof the full form decodes to,
    /// with one `Arc` per distinct header, and is much smaller on the wire.
    #[test]
    fn dedup_round_trip_equals_the_full_form_and_is_smaller() {
        let p = proof();
        let full = protowire::PruningPointProofMessage {
            headers: p.iter().map(|l| (HeaderFormat::Compressed, l).into()).collect(),
            ..Default::default()
        };
        let dedup = dedup_pruning_point_proof(HeaderFormat::Compressed, &p);
        assert!(dedup.headers.is_empty());
        let distinct: std::collections::HashSet<Hash> = p.iter().flatten().map(|h| h.hash).collect();
        assert_eq!(dedup.distinct_headers.len(), distinct.len(), "each header once");
        let (fb, db) = (prost::Message::encoded_len(&full), prost::Message::encoded_len(&dedup));
        assert!(db * 3 < fb * 2, "deduplicated {db} B vs full {fb} B");
        let back = undedup_pruning_point_proof(HeaderFormat::Compressed, dedup, 64, 10_000).unwrap();
        assert_eq!(back.len(), p.len());
        for (a, b) in back.iter().zip(&p) {
            assert_eq!(a.iter().map(|h| h.hash).collect::<Vec<_>>(), b.iter().map(|h| h.hash).collect::<Vec<_>>());
        }
        let first = &back[0][5];
        let again = back.iter().flatten().find(|h| h.hash == first.hash && !Arc::ptr_eq(h, first));
        assert!(again.is_none(), "one Arc per distinct header");
    }

    /// The receiver checks of spec 13 R-1.2, each refused before any validation.
    #[test]
    fn malformed_dedup_proofs_are_refused() {
        let p = proof();
        let good = || dedup_pruning_point_proof(HeaderFormat::Compressed, &p);
        let refuse = |m: protowire::PruningPointProofMessage, max_levels: usize, max_refs: usize, why: &str| {
            assert!(undedup_pruning_point_proof(HeaderFormat::Compressed, m, max_levels, max_refs).is_err(), "{why}");
        };
        let mut m = good();
        m.levels[2].indices.push(m.distinct_headers.len() as u32);
        refuse(m, 64, 10_000, "an index out of range");
        refuse(good(), 5, 10_000, "more levels than the network has");
        refuse(good(), 64, 50, "more header slots than the bound");
        let mut m = good();
        let dup = m.distinct_headers[0].clone();
        m.distinct_headers.push(dup);
        let last = (m.distinct_headers.len() - 1) as u32;
        m.levels[0].indices.push(last);
        refuse(m, 64, 10_000, "a header listed twice");
        let mut m = good();
        m.distinct_headers.push((HeaderFormat::Compressed, header(200).as_ref()).into());
        refuse(m, 64, 10_000, "a listed header in no level");
        let mut m = good();
        m.headers = vec![(HeaderFormat::Compressed, &p[0]).into()];
        refuse(m, 64, 10_000, "both forms at once");
        assert!(undedup_pruning_point_proof(HeaderFormat::Compressed, good(), 64, 10_000).is_ok());
    }
}
