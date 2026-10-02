use crate::{FromRpcHex, RpcError, ToRpcHex};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_consensus_core::{
    BlueWorkType,
    auxpow::AuxPow,
    header::{CompressedParents, Header},
};

/// Encode a header's optional AuxPoW witness as a borsh hex string (empty if none).
fn aux_pow_to_hex(header: &Header) -> String {
    header.aux_pow.as_ref().map(|a| borsh::to_vec(a).expect("AuxPow is always borsh-serializable").to_rpc_hex()).unwrap_or_default()
}

/// Decode the borsh-hex AuxPoW witness (empty string ⇒ None) and attach it to `header`.
fn attach_aux_pow(header: Header, aux_pow_hex: &str) -> Result<Header, RpcError> {
    if aux_pow_hex.is_empty() {
        return Ok(header);
    }
    let bytes = Vec::<u8>::from_rpc_hex(aux_pow_hex).map_err(|e| RpcError::General(format!("invalid auxPow hex: {e}")))?;
    // `CompressedParents` validates itself while borsh-decoding, so an aux parent whose cumulative
    // counts are not strictly increasing is rejected HERE. It previously reached header processing,
    // where hashing the parent panics `expand_rle` and the panic hook calls `process::exit(1)` — a
    // zero-work remote node kill through `submit_block`. The p2p edge guarded this (F-07); this one,
    // which is the path `submit_block` and `get_block_template` use, did not.
    let aux: AuxPow = borsh::from_slice(&bytes).map_err(|e| RpcError::General(format!("invalid auxPow bytes: {e}")))?;
    // Unlike a relayed witness, a submission is the caller's own work, so report the problem rather
    // than silently discarding the witness and failing the block on native PoW alone.
    aux.validate_structure().map_err(|reason| RpcError::General(format!("invalid auxPow: {reason}")))?;
    Ok(header.with_aux_pow(aux))
}
use kaspa_hashes::Hash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

pub type RpcCompressedParents = CompressedParents;

/// Raw Rpc header type - without a cached header hash.
/// Used for mining APIs (get_block_template & submit_block)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRawHeader {
    pub version: u16,
    pub parents_by_level: Vec<Vec<Hash>>,
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
    /// Optional merged-mining (AuxPoW) witness carried on the submit path, as a hex
    /// string of the borsh-encoded `AuxPow` (empty for a natively-mined block). Not
    /// part of the block hash. This lets a miner submit a merged-mined block via the
    /// standard `submit_block` RPC.
    #[serde(default)]
    pub aux_pow: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcHeader {
    /// Cached hash
    pub hash: Hash,
    pub version: u16,
    pub parents_by_level: Vec<Vec<Hash>>,
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
}

impl RpcHeader {
    pub fn direct_parents(&self) -> &[Hash] {
        if self.parents_by_level.is_empty() { &[] } else { &self.parents_by_level[0] }
    }
}

impl AsRef<RpcHeader> for RpcHeader {
    fn as_ref(&self) -> &RpcHeader {
        self
    }
}

impl From<Header> for RpcHeader {
    fn from(header: Header) -> Self {
        Self {
            hash: header.hash,
            version: header.version,
            parents_by_level: header.parents_by_level.into(),
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
        }
    }
}

impl From<&Header> for RpcHeader {
    fn from(header: &Header) -> Self {
        Self {
            hash: header.hash,
            version: header.version,
            parents_by_level: (&header.parents_by_level).into(),
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
        }
    }
}

impl TryFrom<RpcHeader> for Header {
    type Error = RpcError;
    fn try_from(header: RpcHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: header.hash,
            version: header.version,
            parents_by_level: header.parents_by_level.try_into()?,
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
            // RpcHeader does not carry the merged-mining witness.
            aux_pow: None,
        })
    }
}

impl TryFrom<&RpcHeader> for Header {
    type Error = RpcError;

    fn try_from(header: &RpcHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: header.hash,
            version: header.version,
            parents_by_level: header.parents_by_level.clone().try_into()?,
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
            // RpcHeader does not carry the merged-mining witness.
            aux_pow: None,
        })
    }
}

impl Serializer for RpcHeader {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;

        store!(Hash, &self.hash, writer)?;
        store!(u16, &self.version, writer)?;
        store!(Vec<Vec<Hash>>, &self.parents_by_level, writer)?;
        store!(Hash, &self.hash_merkle_root, writer)?;
        store!(Hash, &self.accepted_id_merkle_root, writer)?;
        store!(Hash, &self.utxo_commitment, writer)?;
        store!(u64, &self.timestamp, writer)?;
        store!(u32, &self.bits, writer)?;
        store!(u64, &self.nonce, writer)?;
        store!(u64, &self.daa_score, writer)?;
        store!(BlueWorkType, &self.blue_work, writer)?;
        store!(u64, &self.blue_score, writer)?;
        store!(Hash, &self.pruning_point, writer)?;

        Ok(())
    }
}

impl Deserializer for RpcHeader {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;

        let hash = load!(Hash, reader)?;
        let version = load!(u16, reader)?;
        let parents_by_level = load!(Vec<Vec<Hash>>, reader)?;
        let hash_merkle_root = load!(Hash, reader)?;
        let accepted_id_merkle_root = load!(Hash, reader)?;
        let utxo_commitment = load!(Hash, reader)?;
        let timestamp = load!(u64, reader)?;
        let bits = load!(u32, reader)?;
        let nonce = load!(u64, reader)?;
        let daa_score = load!(u64, reader)?;
        let blue_work = load!(BlueWorkType, reader)?;
        let blue_score = load!(u64, reader)?;
        let pruning_point = load!(Hash, reader)?;

        Ok(Self {
            hash,
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            timestamp,
            bits,
            nonce,
            daa_score,
            blue_work,
            blue_score,
            pruning_point,
        })
    }
}

impl TryFrom<RpcRawHeader> for Header {
    type Error = RpcError;

    fn try_from(header: RpcRawHeader) -> Result<Self, Self::Error> {
        let built = Self::new_finalized(
            header.version,
            header.parents_by_level.try_into()?,
            header.hash_merkle_root,
            header.accepted_id_merkle_root,
            header.utxo_commitment,
            header.timestamp,
            header.bits,
            header.nonce,
            header.daa_score,
            header.blue_work,
            header.blue_score,
            header.pruning_point,
        );
        attach_aux_pow(built, &header.aux_pow)
    }
}

impl TryFrom<&RpcRawHeader> for Header {
    type Error = RpcError;

    fn try_from(header: &RpcRawHeader) -> Result<Self, Self::Error> {
        let built = Self::new_finalized(
            header.version,
            header.parents_by_level.clone().try_into()?,
            header.hash_merkle_root,
            header.accepted_id_merkle_root,
            header.utxo_commitment,
            header.timestamp,
            header.bits,
            header.nonce,
            header.daa_score,
            header.blue_work,
            header.blue_score,
            header.pruning_point,
        );
        attach_aux_pow(built, &header.aux_pow)
    }
}

impl From<&Header> for RpcRawHeader {
    fn from(header: &Header) -> Self {
        Self {
            version: header.version,
            parents_by_level: header.parents_by_level.clone().into(),
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
            aux_pow: aux_pow_to_hex(header),
        }
    }
}

impl From<Header> for RpcRawHeader {
    fn from(header: Header) -> Self {
        Self {
            version: header.version,
            aux_pow: aux_pow_to_hex(&header),
            parents_by_level: header.parents_by_level.into(),
            hash_merkle_root: header.hash_merkle_root,
            accepted_id_merkle_root: header.accepted_id_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            blue_work: header.blue_work,
            blue_score: header.blue_score,
            pruning_point: header.pruning_point,
        }
    }
}

impl Serializer for RpcRawHeader {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Format version 2 adds the merged-mining `aux_pow` hex field at the end.
        store!(u16, &2, writer)?;

        store!(u16, &self.version, writer)?;
        store!(Vec<Vec<Hash>>, &self.parents_by_level, writer)?;
        store!(Hash, &self.hash_merkle_root, writer)?;
        store!(Hash, &self.accepted_id_merkle_root, writer)?;
        store!(Hash, &self.utxo_commitment, writer)?;
        store!(u64, &self.timestamp, writer)?;
        store!(u32, &self.bits, writer)?;
        store!(u64, &self.nonce, writer)?;
        store!(u64, &self.daa_score, writer)?;
        store!(BlueWorkType, &self.blue_work, writer)?;
        store!(u64, &self.blue_score, writer)?;
        store!(Hash, &self.pruning_point, writer)?;
        store!(String, &self.aux_pow, writer)?;

        Ok(())
    }
}

impl Deserializer for RpcRawHeader {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let format_version = load!(u16, reader)?;

        let version = load!(u16, reader)?;
        let parents_by_level = load!(Vec<Vec<Hash>>, reader)?;
        let hash_merkle_root = load!(Hash, reader)?;
        let accepted_id_merkle_root = load!(Hash, reader)?;
        let utxo_commitment = load!(Hash, reader)?;
        let timestamp = load!(u64, reader)?;
        let bits = load!(u32, reader)?;
        let nonce = load!(u64, reader)?;
        let daa_score = load!(u64, reader)?;
        let blue_work = load!(BlueWorkType, reader)?;
        let blue_score = load!(u64, reader)?;
        let pruning_point = load!(Hash, reader)?;
        // aux_pow is only present in format version >= 2.
        let aux_pow = if format_version >= 2 { load!(String, reader)? } else { String::new() };

        Ok(Self {
            aux_pow,
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            timestamp,
            bits,
            nonce,
            daa_score,
            blue_work,
            blue_score,
            pruning_point,
        })
    }
}
