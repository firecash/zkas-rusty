use crate::pb as protowire;
use kaspa_consensus_core::{BlueWorkType, auxpow::AuxPow, header::Header};
use kaspa_core::debug;
use kaspa_hashes::Hash;

use super::error::ConversionError;
use super::option::TryIntoOptionEx;

#[derive(Copy, Clone)]
pub enum HeaderFormat {
    Legacy,
    Compressed,
}

/// Determines the header format based on the protocol version.
impl From<u32> for HeaderFormat {
    fn from(version: u32) -> Self {
        if version >= 9 { Self::Compressed } else { Self::Legacy }
    }
}

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<(HeaderFormat, &Header)> for protowire::BlockHeader {
    fn from(value: (HeaderFormat, &Header)) -> Self {
        let (header_type, item) = value;

        Self {
            version: item.version.into(),
            parents: match header_type {
                HeaderFormat::Legacy => item.parents_by_level.expanded_iter().map(protowire::BlockLevelParents::from).collect(),
                HeaderFormat::Compressed => item
                    .parents_by_level
                    .raw()
                    .iter()
                    .map(|(cum, hashes)| protowire::BlockLevelParents {
                        cumulative_level: (*cum).into(),
                        parent_hashes: hashes.iter().map(|h| h.into()).collect(),
                    })
                    .collect(),
            },
            hash_merkle_root: Some(item.hash_merkle_root.into()),
            accepted_id_merkle_root: Some(item.accepted_id_merkle_root.into()),
            utxo_commitment: Some(item.utxo_commitment.into()),
            timestamp: item.timestamp.try_into().expect("timestamp is always convertible to i64"),
            bits: item.bits,
            nonce: item.nonce,
            daa_score: item.daa_score,
            // We follow the golang specification of variable big-endian here
            blue_work: item.blue_work.to_be_bytes_var(),
            blue_score: item.blue_score,
            pruning_point: Some(item.pruning_point.into()),
            // Merged-mining witness, borsh-encoded; empty for natively-mined blocks.
            aux_pow: item.aux_pow.as_ref().map(|a| borsh::to_vec(a).expect("AuxPow is always borsh-serializable")).unwrap_or_default(),
        }
    }
}

impl From<&[Hash]> for protowire::BlockLevelParents {
    fn from(item: &[Hash]) -> Self {
        // When converting to legacy p2p header, cumulative_level is set to 0
        Self { parent_hashes: item.iter().map(|h| h.into()).collect(), cumulative_level: 0 }
    }
}

// ----------------------------------------------------------------------------
// protowire to consensus_core
// ----------------------------------------------------------------------------

/// A wrapper for P2P header messages indicating the expected header format during conversion.
pub struct Versioned<T>(pub HeaderFormat, pub T);

impl TryFrom<Versioned<protowire::BlockHeader>> for Header {
    type Error = ConversionError;
    fn try_from(value: Versioned<protowire::BlockHeader>) -> Result<Self, Self::Error> {
        let Versioned(header_format, item) = value;

        let parents_by_level = match header_format {
            HeaderFormat::Compressed => item
                .parents
                .into_iter()
                .map(|p| {
                    let cum = u8::try_from(p.cumulative_level)?;
                    let parents = p.parent_hashes.into_iter().map(Hash::try_from).collect::<Result<_, _>>()?;
                    Ok((cum, parents))
                })
                .collect::<Result<Vec<(u8, Vec<Hash>)>, ConversionError>>()?
                .try_into()?,
            HeaderFormat::Legacy => item
                .parents
                .into_iter()
                .map(|p| p.parent_hashes.into_iter().map(Hash::try_from).collect::<Result<Vec<Hash>, ConversionError>>())
                .collect::<Result<Vec<Vec<Hash>>, ConversionError>>()?
                .try_into()?,
        };

        let header = Header::new_finalized(
            item.version.try_into()?,
            parents_by_level,
            item.hash_merkle_root.try_into_ex()?,
            item.accepted_id_merkle_root.try_into_ex()?,
            item.utxo_commitment.try_into_ex()?,
            item.timestamp.try_into()?,
            item.bits,
            item.nonce,
            item.daa_score,
            // We follow the golang specification of variable big-endian here
            BlueWorkType::from_be_bytes_var(&item.blue_work)?,
            item.blue_score,
            item.pruning_point.try_into_ex()?,
        );
        // Reattach the merged-mining witness if present. It is not part of the header
        // hash, so `with_aux_pow` does not disturb the `H_fc` computed above.
        if item.aux_pow.is_empty() {
            return Ok(header);
        }
        // An unusable witness DISCARDS the witness, never the header.
        //
        // The witness is deliberately outside `H_fc`, so any relay hop, MITM, or peer answering a
        // block request can replace it with junk. `kaspa_pow` is built around the rule that the aux
        // field "must never be able to invalidate a block that already clears the native target" —
        // and returning an error here broke exactly that at the transport layer: a valid natively
        // mined block was discarded and the connection dropped, and because an IBD `BlockHeaders`
        // batch collects over a `Result`, one poisoned header aborted the whole batch and stalled
        // sync from that peer. So the block is judged on its own native PoW; if it really was
        // aux-mined, PoW simply fails, which is a transient rejection rather than a cached-invalid
        // verdict that would never heal.
        //
        // F-07 is now closed inside the type: `CompressedParents` validates itself while borsh
        // decoding, so an aux parent whose cumulative counts would panic `expand_rle` during
        // `parent_pow` hashing fails below instead of reaching header processing.
        match borsh::from_slice::<AuxPow>(&item.aux_pow) {
            Ok(aux) => match aux.validate_structure() {
                Ok(()) => Ok(header.with_aux_pow(aux)),
                Err(reason) => {
                    debug!("discarding unusable aux witness on header {}: {}", header.hash, reason);
                    Ok(header)
                }
            },
            Err(e) => {
                debug!("discarding undecodable aux witness on header {}: {}", header.hash, e);
                Ok(header)
            }
        }
    }
}

impl TryFrom<protowire::BlockLevelParents> for Vec<Hash> {
    type Error = ConversionError;
    fn try_from(item: protowire::BlockLevelParents) -> Result<Self, Self::Error> {
        item.parent_hashes.into_iter().map(|x| x.try_into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{auxpow::AuxPow, subnets::SUBNETWORK_ID_COINBASE, tx::Transaction};

    fn finalized(parent_seed: u8) -> Header {
        let mut h = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([parent_seed; 32])]);
        h.finalize();
        h
    }

    #[test]
    fn aux_pow_survives_p2p_round_trip() {
        let header = finalized(1);
        let hfc = header.hash;
        // Minimal valid-shaped aux: coinbase commits to H_fc (structural checks live in
        // the consensus crates; here we only exercise transport).
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, AuxPow::embed_commitment(&[], hfc, &[]));
        let aux = AuxPow { parent_header: finalized(9), parent_coinbase: cb, coinbase_merkle_branch: vec![] };
        let header = header.with_aux_pow(aux);

        let pb: protowire::BlockHeader = (HeaderFormat::Compressed, &header).into();
        assert!(!pb.aux_pow.is_empty(), "aux is borsh-encoded into the protobuf bytes field");

        let back: Header = Versioned(HeaderFormat::Compressed, pb).try_into().unwrap();
        assert_eq!(back.hash, hfc, "H_fc is stable across the p2p round trip");
        assert_eq!(back.aux_pow.as_ref().expect("aux survives p2p").committed_hash(), Some(hfc));
    }

    #[test]
    fn native_header_round_trips_without_aux() {
        let native = finalized(2);
        let pb: protowire::BlockHeader = (HeaderFormat::Compressed, &native).into();
        assert!(pb.aux_pow.is_empty(), "native header carries no aux bytes");
        let back: Header = Versioned(HeaderFormat::Compressed, pb).try_into().unwrap();
        assert!(back.aux_pow.is_none());
        assert_eq!(back.hash, native.hash);
    }

    /// F-07 regression. An aux parent whose `parents_by_level` cumulative counts are not strictly
    /// increasing PANICS `expand_rle` when `parent_pow` hashes it, and the daemon's panic hook turns
    /// that into `process::exit(1)`.
    ///
    /// The invariant now lives in `CompressedParents`' own borsh decoding (see
    /// `kaspa_consensus_core::header`), so such a witness cannot even be constructed through borsh
    /// any more — which is the point: no decode edge can forget it. Here we assert the transport
    /// consequence, with raw bytes standing in for a hostile sender.
    ///
    /// Note the deliberate change of verdict: the witness is DISCARDED and the header is KEPT.
    /// Returning an error discarded a possibly-valid natively-mined block and dropped the peer,
    /// which contradicted `kaspa_pow`'s rule that the aux field must never be able to invalidate a
    /// block that already clears the native target — and the field is outside `H_fc`, so anyone in
    /// the path can staple junk onto someone else's valid block.
    #[test]
    fn an_unusable_aux_witness_is_discarded_and_the_header_survives() {
        let header = finalized(1);
        let hfc = header.hash;

        // Bytes that are not a decodable `AuxPow` at all, including the F-07 shapes, which now fail
        // inside `CompressedParents`' borsh impl rather than at a hand-written edge check.
        let mut cases: Vec<Vec<u8>> = vec![vec![0xff; 8], vec![], vec![0x01, 0x02, 0x03]];
        let h1 = Hash::from_bytes([7u8; 32]);
        for raw in [
            vec![(0u8, vec![h1])],                // first cumulative count is 0
            vec![(5u8, vec![h1]), (2u8, vec![h1])], // decreasing cumulative counts
            vec![(3u8, vec![h1]), (3u8, vec![h1])], // repeated cumulative count
        ] {
            assert!(
                borsh::from_slice::<kaspa_consensus_core::header::CompressedParents>(&borsh::to_vec(&raw).unwrap()).is_err(),
                "borsh decoding must reject {raw:?} — this is the panic that F-07 was"
            );
            cases.push(borsh::to_vec(&raw).unwrap());
        }

        for bytes in cases {
            let mut pb: protowire::BlockHeader = (HeaderFormat::Compressed, &header).into();
            pb.aux_pow = bytes;
            // Must not panic, must not error, and must not keep the witness.
            let back: Header = Versioned(HeaderFormat::Compressed, pb).try_into().expect("the header survives a junk witness");
            assert_eq!(back.hash, hfc, "H_fc is untouched");
            assert!(back.aux_pow.is_none(), "the unusable witness is dropped");
        }
    }

    /// `AuxPow` holds a `Header`, which holds an `Option<Box<AuxPow>>`, so the two are mutually
    /// recursive with no depth bound against a 1 GiB message ceiling — millions of levels of
    /// recursive borsh decoding, then the same walk again in `MemSizeEstimator` and the `Box` drop
    /// chain. Consensus never reads the nested field.
    ///
    /// Enforced as a LIMIT, deliberately, not as a ban. Merged mining is active from genesis, the
    /// witness is built by an external producer, and nesting would have left no trace precisely
    /// because nothing reads it — so refusing all of it would be a tightening on a consensus-active
    /// path that cannot be confirmed safe from inside this repo, and the witness is load-bearing for
    /// an aux-mined block's PoW, so being wrong would silently stall a fresh sync years back rather
    /// than fail cleanly.
    #[test]
    fn aux_witness_nesting_is_bounded_but_shallow_nesting_still_decodes() {
        let header = finalized(1);
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, AuxPow::embed_commitment(&[], header.hash, &[]));

        let base = AuxPow { parent_header: finalized(9), parent_coinbase: cb.clone(), coinbase_merkle_branch: vec![] };
        let shallow = AuxPow {
            parent_header: finalized(8).with_aux_pow(base.clone()),
            parent_coinbase: cb.clone(),
            coinbase_merkle_branch: vec![],
        };
        assert!(
            borsh::from_slice::<AuxPow>(&borsh::to_vec(&shallow).unwrap()).is_ok(),
            "a plausible amount of nesting must still decode — anything else is an unverifiable tightening"
        );

        let mut deep = base;
        for _ in 0..(kaspa_consensus_core::auxpow::MAX_AUX_POW_NESTING + 2) {
            deep = AuxPow {
                parent_header: finalized(7).with_aux_pow(deep),
                parent_coinbase: cb.clone(),
                coinbase_merkle_branch: vec![],
            };
        }
        assert!(
            borsh::from_slice::<AuxPow>(&borsh::to_vec(&deep).unwrap()).is_err(),
            "past the ceiling it must be refused DURING decoding, before the recursion runs away"
        );

        // And the header still survives such a witness on the p2p path: witness dropped, block kept.
        let mut pb: protowire::BlockHeader = (HeaderFormat::Compressed, &header).into();
        pb.aux_pow = borsh::to_vec(&deep).unwrap();
        let back: Header = Versioned(HeaderFormat::Compressed, pb).try_into().expect("the header still survives");
        assert!(back.aux_pow.is_none(), "the over-nested witness is dropped, not stored");
    }
}
