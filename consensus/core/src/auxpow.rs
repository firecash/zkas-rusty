//! Merged-mining (AuxPoW) support — the data carried by a ZKas block that is
//! mined *on top of* a parent (Kaspa) kHeavyHash block instead of natively
//! (PLAN: merged mining, "Option 2" dual-acceptance). This module owns the
//! **structural** half of AuxPoW verification (commitment extraction + coinbase
//! Merkle inclusion); the **work** half (does the parent header's kHeavyHash clear
//! *our* target) lives in `kaspa_pow::auxpow`, since only that crate has the
//! kHeavyHash `State`.
//!
//! ## The binding chain
//!
//! A ZKas block is identified by its header hash `H_fc` (see
//! [`crate::hashing::header::hash`]) — which does **not** cover any AuxPoW data, so
//! it is a stable commitment. To prove that real kHeavyHash work was spent on this
//! exact block, the miner:
//!
//! 1. embeds `MERGE_MINE_MAGIC || H_fc` in the parent block's **coinbase payload**
//!    (Kaspa's coinbase `extra_data` is miner-controlled, so no Kaspa change is
//!    needed);
//! 2. mines the parent block with kHeavyHash.
//!
//! Verification then follows the chain
//! `pow(parent_header) → parent_header.hash_merkle_root → coinbase → H_fc`:
//! the parent header's PoW commits to its `hash_merkle_root`, the Merkle branch
//! ties the coinbase (leaf 0) to that root, and the coinbase payload commits to
//! `H_fc`. Nothing in the parent needs to be a *valid* Kaspa block — only that
//! enough kHeavyHash work, bound to `H_fc`, was performed. Keeping the coinbase +
//! Merkle structure is what lets the parent be a **real** Kaspa block (where the
//! only miner-writable slot is the coinbase), which is the whole point of merged
//! mining.
//!
//! ## Anti-ambiguity
//!
//! [`MERGE_MINE_MAGIC`] must appear in the coinbase payload **exactly once**. This
//! is the classic AuxPoW hardening (cf. the Bitcoin merged-mining tag rules): if a
//! miner could place two commitments, one parent PoW could be claimed by two
//! conflicting aux blocks. Zero or multiple occurrences ⇒ rejected. The rule errs
//! safe: an accidental second magic makes a block *invalid* (liveness), never
//! makes an invalid block *valid* (soundness).

use crate::{hashing, header::Header, tx::Transaction};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash;
use serde::{Deserialize, Serialize};

/// The 4-byte tag that marks the 32-byte ZKas block commitment inside a parent
/// coinbase payload. "ZKas Merged Mining".
pub const MERGE_MINE_MAGIC: [u8; 4] = *b"ZKMM";

/// Post-fork merge-mining tag (`Params::security_fork_activation`): followed by the hex of
/// [`AuxPow::bound_commitment`], which binds the genesis and the nonce-free header hash.
pub const MERGE_MINE_MAGIC_V1: [u8; 4] = *b"ZKM1";

/// Hard cap on [`AuxPow::coinbase_merkle_branch`] length. The branch has one entry
/// per level of the parent's transaction Merkle tree, so a parent with `n`
/// transactions needs `ceil(log2(n))` entries: 64 admits a parent with 2^64
/// transactions, i.e. every parent block that can physically exist.
///
/// Without a cap the branch is bounded only by the p2p message size, and each entry
/// costs a hash in [`AuxPow::verify_coinbase_inclusion`] — an attacker could attach
/// a multi-million-entry branch to a junk header and make every peer grind through
/// it. Rejecting an over-long branch is free and cannot refuse an honest block.
pub const MAX_COINBASE_MERKLE_BRANCH: usize = 64;

/// Largest serialized aux witness a decode edge will accept.
///
/// Nothing bounded the witness's total size: not `parent_coinbase` (unbounded inputs with unbounded
/// signature scripts, unbounded outputs), not the aux parent's parent hashes. The only ceiling was
/// the ~1 GiB p2p/RPC message limit.
///
/// What makes that worse than an ordinary oversized-message problem is the native path.
/// `check_pow_gated` tries native proof-of-work FIRST and returns the moment it passes, so for a
/// natively mined block the witness is never looked at by consensus at all — yet it is stored
/// verbatim with the header, kept forever, and re-serialized to every peer that requests the block.
/// So a miner can attach hundreds of megabytes of junk to a block it is *paid* for, with no extra
/// work and no consensus rule broken, and every node keeps it. The headers cache made that worse
/// still by accounting the witness at a fraction of its real size (see `Header::estimate_mem_bytes`).
///
/// Enforced at the decode edges, where an unusable witness is DROPPED and the header kept, so this
/// never costs a valid block: an honest natively mined block survives with its junk removed, and an
/// aux-mined block that genuinely needs the witness simply fails proof-of-work and is retried. A real
/// Kaspa coinbase plus a 64-deep branch is a few kilobytes, so this sits orders of magnitude above
/// anything honest.
pub const MAX_AUX_POW_SERIALIZED_LEN: usize = 256 * 1024;

/// The proof that a ZKas block was mined on top of a parent kHeavyHash block.
///
/// Travels alongside the ZKas header (it is deliberately *not* part of the
/// header hash `H_fc`, so the commitment stays stable). Derives borsh only, to
/// match [`Transaction`] and be storable / wire-serializable.
// `Header` implements neither `PartialEq` nor `Eq`, so `AuxPow` cannot derive them.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
#[serde(rename_all = "camelCase")]
pub struct AuxPow {
    /// The parent block header carrying the real kHeavyHash proof-of-work. Its
    /// cached `hash` is never trusted — [`kaspa_pow`] recomputes the PoW from the
    /// header fields.
    pub parent_header: Header,
    /// The parent block's coinbase transaction (leaf 0 of the parent Merkle tree),
    /// whose payload embeds `MERGE_MINE_MAGIC || H_fc`.
    pub parent_coinbase: Transaction,
    /// The Merkle branch from the coinbase (leaf index 0) up to
    /// `parent_header.hash_merkle_root`: the sequence of right-sibling hashes, one
    /// per tree level. Empty iff the parent block has a single transaction (the
    /// coinbase is then the root itself). Because the coinbase is always leaf 0, the
    /// accumulator is always the *left* child at every level — an attacker cannot
    /// pass off a non-leaf-0 transaction, since the fixed left-combine order would
    /// not reproduce the committed root.
    pub coinbase_merkle_branch: Vec<Hash>,
}

/// How deeply `AuxPow` may nest before decoding gives up.
///
/// `AuxPow` holds a [`Header`], which holds an `Option<Box<AuxPow>>`, so the two types are mutually
/// recursive with NO depth bound anywhere, against a 1 GiB message ceiling — roughly 250 bytes per
/// level, so millions of levels. Derived borsh decoding recurses per level (stack overflow, which
/// the panic hook cannot even log), and `MemSizeEstimator` and the `Box` drop chain walk the same
/// chain afterwards.
///
/// Consensus never reads the nested field: `parent_pow` hashes only the parent's header fields
/// (`hashing::header` does not touch `aux_pow`) and `verify_binding` reads only the coinbase, the
/// branch and the merkle root. So it is pure attack surface.
///
/// This is a LIMIT rather than a flat rejection on purpose. Merged mining is active from genesis on
/// mainnet, the witness is produced by an external bridge whose code is not in this repo, and
/// nesting would have left no trace if it ever occurred — nothing reads it. Rejecting any nesting
/// would therefore be a tightening on a consensus-active path with no way to confirm, from here,
/// that no historical witness trips it; and because the witness is load-bearing for an aux-mined
/// block's proof of work, getting that wrong does not fail cleanly — it silently stops a fresh sync
/// at some block years back. A depth of 4 accepts anything a real producer could plausibly emit
/// while bounding the recursion to a constant.
pub const MAX_AUX_POW_NESTING: u32 = 4;

thread_local! {
    static AUX_POW_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Hand-written so the nesting depth above is enforced DURING decoding.
///
/// Stripping the nested field after the fact would not help: the stack overflow happens while borsh
/// is still descending.
/// Releases the nesting counter on EVERY exit path, an unwind included.
///
/// A bare decrement after the decode is skipped by a panic inside borsh — an allocation failure, or
/// any future `.expect` in a nested `deserialize_reader`. The counter is thread-local and these
/// decode on long-lived rayon workers, so one leak would permanently reject every later witness on
/// that worker as "nested too deep", with nothing in the logs to explain it. Release builds unwind
/// (no `panic` setting in `[profile.release]`), so that path is reachable. Same shape as walletd's
/// `ProvingGuard`.
struct AuxDepthGuard;

impl AuxDepthGuard {
    fn enter() -> (Self, u32) {
        let depth = AUX_POW_DEPTH.with(|d| {
            let next = d.get().saturating_add(1);
            d.set(next);
            next
        });
        (Self, depth)
    }
}

impl Drop for AuxDepthGuard {
    fn drop(&mut self) {
        AUX_POW_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

impl BorshDeserialize for AuxPow {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let (_depth_guard, depth) = AuxDepthGuard::enter();
        if depth > MAX_AUX_POW_NESTING {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                format!("aux witness nested deeper than {MAX_AUX_POW_NESTING}"),
            ));
        }
        Ok(AuxPow {
            parent_header: Header::deserialize_reader(reader)?,
            parent_coinbase: Transaction::deserialize_reader(reader)?,
            coinbase_merkle_branch: Vec::<Hash>::deserialize_reader(reader)?,
        })
    }
}

impl AuxPow {
    /// Structural bounds that every decode edge must apply before a witness is stored, relayed or
    /// hashed, so the rules live in one place instead of being re-derived per edge.
    ///
    /// `parents_by_level` is validated by [`CompressedParents`]' own borsh decoding and nesting
    /// depth by [`MAX_AUX_POW_NESTING`], so neither is repeated here. What this adds is the Merkle
    /// branch length: no honest parent needs more than [`MAX_COINBASE_MERKLE_BRANCH`] levels (the
    /// branch is log2 of the parent block's transaction count), the field is otherwise bounded only
    /// by the 1 GiB message ceiling, and the witness is stored with the header forever. The p2p edge
    /// already enforced exactly this bound before the rule moved here, so no block carrying a longer
    /// branch could ever have propagated.
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.coinbase_merkle_branch.len() > MAX_COINBASE_MERKLE_BRANCH {
            return Err(format!(
                "coinbase merkle branch too long: {} > {}",
                self.coinbase_merkle_branch.len(),
                MAX_COINBASE_MERKLE_BRANCH
            ));
        }
        // Total serialized size. The per-field caps above and the nesting bound in
        // `BorshDeserialize` do not bound this: `parent_coinbase` alone can carry unbounded inputs,
        // signature scripts and outputs. See `MAX_AUX_POW_SERIALIZED_LEN` for why a witness that
        // consensus never even reads is still worth refusing.
        match borsh::object_length(self) {
            Ok(len) if len > MAX_AUX_POW_SERIALIZED_LEN => {
                return Err(format!("aux witness too large: {len} > {MAX_AUX_POW_SERIALIZED_LEN} bytes"));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("aux witness is not serializable: {e}")),
        }
        Ok(())
    }

    /// Extract the single commitment tagged by [`MERGE_MINE_MAGIC`] in the parent
    /// coinbase payload. Returns `None` unless the magic occurs **exactly once** and is
    /// followed by a full [`COMMITMENT_HEX_LEN`] lowercase-hex encoding of the 32-byte
    /// hash.
    ///
    /// The commitment is hex (ASCII), not raw bytes, because it travels through Kaspa's
    /// `getBlockTemplate` `extraData` field — a protobuf **string** that must be valid
    /// UTF-8. Real 32-byte block hashes are almost never valid UTF-8, so raw bytes
    /// cannot be carried there; the 64-char hex encoding always can.
    pub fn committed_hash(&self) -> Option<Hash> {
        Self::payload_commitment(self.parent_coinbase.payload.as_slice(), &MERGE_MINE_MAGIC)
    }

    /// The single post-fork (`ZKM1`) commitment in the parent coinbase, same uniqueness and
    /// well-formedness rules as [`Self::committed_hash`].
    pub fn committed_hash_v1(&self) -> Option<Hash> {
        Self::payload_commitment(self.parent_coinbase.payload.as_slice(), &MERGE_MINE_MAGIC_V1)
    }

    /// Whether `payload` carries a well-formed, unique merge-mining commitment under EITHER tag,
    /// i.e. whether a block with this coinbase could serve as somebody's aux parent. From the
    /// security fork a ZKas coinbase must not: that is what stops one ZKas solution from also
    /// counting as the proof-of-work of a second ZKas block. Uses the same scanner as the parent
    /// check so the two can never drift apart.
    pub fn payload_carries_commitment(payload: &[u8]) -> bool {
        Self::payload_commitment(payload, &MERGE_MINE_MAGIC).is_some() || Self::payload_commitment(payload, &MERGE_MINE_MAGIC_V1).is_some()
    }

    /// The post-fork value an aux parent commits to: a hash binding this chain's genesis to the
    /// header hash with the nonce zeroed (`hash_override_nonce_time(header, 0, header.timestamp)`).
    /// The nonce is excluded so that it can afterwards be set to [`Self::nonce_binding`] of the
    /// parent; every other header field, the timestamp included, stays bound.
    pub fn bound_commitment(genesis: Hash, nonce_free_header_hash: Hash) -> Hash {
        use kaspa_hashes::HasherBase;
        let mut hasher = kaspa_hashes::BlockHash::new();
        hasher.update(b"zkas_aux_bind1").update(genesis).update(nonce_free_header_hash);
        hasher.finalize()
    }

    /// The nonce a post-fork aux-accepted block must carry: the first 8 bytes (LE) of its parent
    /// header's hash. Recomputed from the parent's fields, never taken from a cached hash. Because
    /// the full block hash covers the nonce, the block hash then fixes the parent, so one block has
    /// exactly one witness and one level.
    pub fn nonce_binding(parent_header: &Header) -> u64 {
        let h = hashing::header::hash(parent_header).as_bytes();
        u64::from_le_bytes(h[..8].try_into().expect("32-byte hash"))
    }

    /// Post-fork structural binding: the parent coinbase commits (`ZKM1`, exactly once) to
    /// [`Self::bound_commitment`] and is Merkle-included under the parent header.
    pub fn verify_binding_v1(&self, genesis: Hash, nonce_free_header_hash: Hash) -> bool {
        self.committed_hash_v1() == Some(Self::bound_commitment(genesis, nonce_free_header_hash)) && self.verify_coinbase_inclusion()
    }

    /// Miner/test helper for the post-fork form: `prefix || ZKM1 || hex(commitment) || suffix`.
    pub fn embed_commitment_v1(prefix: &[u8], commitment: Hash, suffix: &[u8]) -> Vec<u8> {
        let hex = encode_hex32(&commitment.as_bytes());
        let mut out = Vec::with_capacity(prefix.len() + MERGE_MINE_MAGIC_V1.len() + hex.len() + suffix.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(&MERGE_MINE_MAGIC_V1);
        out.extend_from_slice(&hex);
        out.extend_from_slice(suffix);
        out
    }

    fn payload_commitment(payload: &[u8], magic: &[u8; 4]) -> Option<Hash> {
        let mut found: Option<Hash> = None;
        // Scan every position the 4-byte magic could start at. Requiring a unique
        // occurrence (across the whole payload) is what blocks the two-commitment
        // ambiguity attack, so we must count *all* magics, not stop at the first.
        let mut i = 0usize;
        while i + magic.len() <= payload.len() {
            if payload[i..i + magic.len()] == *magic {
                // A second magic anywhere ⇒ ambiguous ⇒ reject.
                if found.is_some() {
                    return None;
                }
                let start = i + magic.len();
                let end = start + COMMITMENT_HEX_LEN;
                if end > payload.len() {
                    // Magic present but truncated commitment ⇒ malformed ⇒ reject.
                    return None;
                }
                // Magic present but the following bytes aren't valid hex ⇒ malformed ⇒
                // reject (errs safe: never turns an invalid block valid).
                let bytes = decode_hex32(&payload[start..end])?;
                found = Some(Hash::from_bytes(bytes));
                // Continue scanning to ensure the magic is unique.
                i = start; // skip past the magic; overlap-free is fine for uniqueness
            } else {
                i += 1;
            }
        }
        found
    }

    /// Verify the coinbase is included under `parent_header.hash_merkle_root` by
    /// folding the branch as a pure left-path (coinbase = leaf 0), reproducing
    /// Kaspa's tx Merkle tree ([`crate::merkle::calc_hash_merkle_root`]).
    pub fn verify_coinbase_inclusion(&self) -> bool {
        // Refuse an absurd branch before doing any hashing (see MAX_COINBASE_MERKLE_BRANCH).
        if self.coinbase_merkle_branch.len() > MAX_COINBASE_MERKLE_BRANCH {
            return false;
        }
        let mut acc = hashing::tx::hash(&self.parent_coinbase);
        for sibling in &self.coinbase_merkle_branch {
            acc = kaspa_merkle::merkle_hash(acc, *sibling);
        }
        acc == self.parent_header.hash_merkle_root
    }

    /// The structural (PoW-independent) half of AuxPoW verification: the parent
    /// coinbase commits to `expected` (this block's `H_fc`) exactly once, **and**
    /// the coinbase is Merkle-included under the parent header. The remaining check
    /// — that the parent header's kHeavyHash clears our target — is done in
    /// [`kaspa_pow::auxpow`].
    pub fn verify_binding(&self, expected: Hash) -> bool {
        self.committed_hash() == Some(expected) && self.verify_coinbase_inclusion()
    }

    /// Build the coinbase payload bytes a miner should use: `prefix || MAGIC ||
    /// hex(H_fc) || suffix`. The commitment is lowercase-hex (ASCII) so it survives
    /// Kaspa's `getBlockTemplate` `extraData` (a protobuf UTF-8 string). Helper for
    /// miners/tests; consensus never calls this.
    pub fn embed_commitment(prefix: &[u8], commitment: Hash, suffix: &[u8]) -> Vec<u8> {
        let hex = encode_hex32(&commitment.as_bytes());
        let mut out = Vec::with_capacity(prefix.len() + MERGE_MINE_MAGIC.len() + hex.len() + suffix.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(&MERGE_MINE_MAGIC);
        out.extend_from_slice(&hex);
        out.extend_from_slice(suffix);
        out
    }
}

/// The commitment is carried as 64 lowercase-hex ASCII chars (32-byte hash), so it is
/// valid UTF-8 for Kaspa's `getBlockTemplate` `extraData` string field.
pub const COMMITMENT_HEX_LEN: usize = 64;

fn encode_hex32(bytes: &[u8; 32]) -> [u8; COMMITMENT_HEX_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; COMMITMENT_HEX_LEN];
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn decode_hex32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != COMMITMENT_HEX_LEN {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        *o = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None, // uppercase / non-hex rejected: embed_commitment always writes lowercase
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::calc_hash_merkle_root;
    use crate::subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE};
    use crate::tx::Transaction;

    fn hfc() -> Hash {
        Hash::from_bytes([0xABu8; 32])
    }

    /// Drift guard for the canonical-`R` witness. `kaspa_shielded_core::witness_chain::extract_hfc`
    /// replicates this module's `committed_hash` parse (it cannot depend on this crate — that would
    /// be a cycle), so the guarantee is pinned here, where both crates are in scope. If the AuxPoW
    /// commitment layout ever changes, this test fails instead of every peg-out silently losing its
    /// Kaspa PoW binding.
    #[test]
    fn commitment_layout_matches_witness_extract() {
        let commitment = hfc();
        let payload = AuxPow::embed_commitment(&[1, 2, 3, 4, 5], commitment, &[9, 9]);

        // The authoritative extractor (this crate) and the witness extractor must agree.
        let cb = coinbase_committing(commitment);
        let aux = AuxPow {
            parent_header: crate::header::Header::from_precomputed_hash(Hash::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), Some(commitment));
        assert_eq!(kaspa_shielded_core::witness_chain::extract_hfc(&payload), Some(commitment));

        // Two commitments: both must reject (anti-ambiguity).
        let mut doubled = payload.clone();
        doubled.extend_from_slice(&AuxPow::embed_commitment(&[], commitment, &[]));
        assert_eq!(kaspa_shielded_core::witness_chain::extract_hfc(&doubled), None);
    }

    /// A coinbase whose payload carries exactly one MAGIC||H_fc, plus surrounding
    /// bytes (mimicking blue_score/subsidy/script + extra_data).
    fn coinbase_committing(commitment: Hash) -> Transaction {
        let payload = AuxPow::embed_commitment(&[1, 2, 3, 4, 5], commitment, &[9, 9]);
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload)
    }

    fn other_tx(tag: u8) -> Transaction {
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![tag; 8])
    }

    fn parent_with(coinbase: Transaction, others: Vec<Transaction>) -> (Header, Vec<Hash>) {
        let mut txs = vec![coinbase];
        txs.extend(others);
        let root = calc_hash_merkle_root(txs.iter());
        // Branch for leaf 0 (coinbase): right sibling at each level. For <=2 txs the
        // branch is [hash(tx1)] (or empty for a single tx). We only exercise the
        // 1- and 2-tx shapes here; deeper trees are covered in the pow crate's tests.
        let branch = match txs.len() {
            1 => vec![],
            2 => vec![hashing::tx::hash(&txs[1])],
            _ => unreachable!("test helper only builds 1- or 2-tx parents"),
        };
        let mut header = Header::from_precomputed_hash(Hash::from_bytes([0u8; 32]), vec![]);
        header.hash_merkle_root = root;
        (header, branch)
    }

    #[test]
    fn commitment_extracted_when_present_once() {
        let cb = coinbase_committing(hfc());
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), Some(hfc()));
    }

    #[test]
    fn commitment_absent_returns_none() {
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, vec![0u8; 40]);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None);
    }

    #[test]
    fn two_magics_is_ambiguous_and_rejected() {
        // Two well-formed MAGIC || hex(commitment) occurrences → ambiguous → None.
        let mut payload = AuxPow::embed_commitment(&[], Hash::from_bytes([0u8; 32]), &[]);
        payload.extend_from_slice(&AuxPow::embed_commitment(&[], hfc(), &[]));
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None, "two commitments must be rejected as ambiguous");
    }

    #[test]
    fn truncated_commitment_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&MERGE_MINE_MAGIC);
        payload.extend_from_slice(&[b'0'; 10]); // fewer than 64 hex chars follow
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None);
    }

    #[test]
    fn single_tx_parent_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(aux.verify_coinbase_inclusion(), "single-tx: coinbase hash is the root");
        assert!(aux.verify_binding(hfc()));
    }

    #[test]
    fn two_tx_parent_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![other_tx(7)]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(aux.verify_coinbase_inclusion(), "two-tx: coinbase folds with sibling to the root");
        assert!(aux.verify_binding(hfc()));
    }

    #[test]
    fn tampered_branch_fails_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, _branch) = parent_with(cb.clone(), vec![other_tx(7)]);
        let bad = vec![Hash::from_bytes([0xFFu8; 32])];
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: bad };
        assert!(!aux.verify_coinbase_inclusion(), "a wrong sibling must not reproduce the root");
    }

    /// An absurdly long Merkle branch is refused outright, before any hashing: the
    /// field is otherwise bounded only by the p2p message size, so an attacker could
    /// force every peer to fold millions of siblings for a junk header.
    #[test]
    fn over_long_branch_is_rejected_without_hashing() {
        let cb = coinbase_committing(hfc());
        let (header, _branch) = parent_with(cb.clone(), vec![other_tx(1)]);
        let huge = vec![Hash::from_bytes([0x11u8; 32]); MAX_COINBASE_MERKLE_BRANCH + 1];
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: huge };
        assert!(!aux.verify_coinbase_inclusion(), "a branch past the cap is rejected");
        assert!(!aux.verify_binding(hfc()), "and so the binding fails");
    }

    #[test]
    fn header_with_aux_pow_borsh_round_trip_and_stable_hash() {
        // Build a valid aux and attach it to a finalized header.
        let cb = coinbase_committing(hfc());
        let (parent, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };

        let mut header = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([7u8; 32])]);
        header.finalize();
        let hash_before = header.hash;

        let header = header.with_aux_pow(aux);
        assert_eq!(header.hash, hash_before, "attaching the aux witness must not change H_fc");

        // The witness survives a borsh round-trip and the hash stays stable.
        let bytes = borsh::to_vec(&header).unwrap();
        let restored: Header = borsh::from_slice(&bytes).unwrap();
        assert_eq!(restored.hash, hash_before);
        let restored_aux = restored.aux_pow.as_ref().expect("aux survives borsh round-trip");
        assert_eq!(restored_aux.committed_hash(), Some(hfc()));

        // A native header serializes with no aux.
        let mut native = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([8u8; 32])]);
        native.finalize();
        let restored_native: Header = borsh::from_slice(&borsh::to_vec(&native).unwrap()).unwrap();
        assert!(restored_native.aux_pow.is_none());
    }

    #[test]
    fn binding_rejects_wrong_expected() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(!aux.verify_binding(Hash::from_bytes([0x11u8; 32])), "commitment must equal the ZKas block hash");
    }
}
