//! Merged-mining (AuxPoW) proof-of-work verification — the "work" half of
//! Option-2 dual acceptance. The data type and the structural (commitment +
//! coinbase-Merkle) checks live in [`kaspa_consensus_core::auxpow`]; here we add
//! the piece that needs the kHeavyHash [`State`]: does the parent header's PoW
//! clear *our* target.
//!
//! A ZKas block is accepted if it satisfies **either** PoW path against its own
//! target (`header.bits`):
//! - **native** — `kHeavyHash(header)` clears the target (the mode a solo
//!   `zkas-miner` produces); or
//! - **aux** — it carries an [`AuxPow`] whose parent header's kHeavyHash clears the
//!   target and is bound to this block's hash.
//!
//! Both are the *same* hash function against the *same* target, so their work adds
//! directly — which is exactly why the chain runs kHeavyHash. Crucially, the aux
//! target is ZKas's own (set by our DAA), **not** Kaspa's: a single Kaspa hash
//! that fails Kaspa's hard target routinely clears our easy one.

use kaspa_consensus_core::{auxpow::AuxPow, header::Header};
use kaspa_hashes::Hash;
use kaspa_math::Uint256;

use crate::State;

/// The parent header's kHeavyHash value, computed independently of the parent's own
/// `bits` (we compare it against *our* target, not the parent's). This is the work
/// metric for an AuxPoW block.
fn parent_pow(aux: &AuxPow) -> Uint256 {
    State::new(&aux.parent_header).calculate_pow(aux.parent_header.nonce)
}

/// Full AuxPoW verification for a ZKas block with hash `expected` and target
/// `target` (decoded from its `bits`):
/// 1. the parent coinbase commits to `expected` exactly once and is Merkle-included
///    under the parent header ([`AuxPow::verify_binding`]); **and**
/// 2. the parent header's kHeavyHash clears `target`.
pub fn verify_aux_pow(aux: &AuxPow, expected: Hash, target: Uint256) -> bool {
    aux.verify_binding(expected) && parent_pow(aux) <= target
}

/// The Option-2 dual-acceptance PoW gate. Returns `(passed, pow)` mirroring
/// [`State::check_pow`]: `passed` is whether the block's PoW is valid under either
/// path, and `pow` is the work value for block-level math (the parent's kHeavyHash
/// for an aux block, the header's own for a native block).
///
/// `header.hash` is the commitment `H_fc` an aux parent must carry — it is the
/// header hash *excluding* any AuxPoW data, so it is stable regardless of how the
/// block was mined.
pub fn check_pow_dual(header: &Header, aux: Option<&AuxPow>) -> (bool, Uint256) {
    match aux {
        Some(a) => {
            let target = Uint256::from_compact_target_bits(header.bits);
            let pow = parent_pow(a);
            (verify_aux_pow(a, header.hash, target), pow)
        }
        None => State::new(header).check_pow(header.nonce),
    }
}

/// Merged-mining-aware PoW gate — the single entry point the header pipeline calls,
/// so the day-14 activation is the only switch. Acceptance is genuinely *either/or*:
///
/// - A valid **native** nonce always suffices, even if a (possibly bogus) aux witness
///   is also attached. Because the aux field is not covered by `H_fc` and could be
///   stripped or replaced in transit, it must never be able to *invalidate* a block
///   that already clears the native target — so the native path is tried first.
/// - Otherwise, once `merged_mining_active` is `true`, a valid **AuxPoW** proof is
///   accepted, and its work value is the parent's kHeavyHash.
///
/// Before activation the aux witness is ignored entirely. Returns `(passed, pow)` as
/// in [`check_pow_dual`]; `pow` is the work value used for block-level math.
pub fn check_pow_gated(header: &Header, aux: Option<&AuxPow>, rule: impl Into<AuxRule>) -> (bool, Uint256) {
    let (native_ok, native_pow) = State::new(header).check_pow(header.nonce);
    if native_ok {
        return (true, native_pow);
    }
    if let Some(a) = aux {
        let target = Uint256::from_compact_target_bits(header.bits);
        let accepted = match rule.into() {
            AuxRule::Off => false,
            AuxRule::Legacy => verify_aux_pow(a, header.hash, target),
            AuxRule::Bound(genesis) => {
                // Security fork: the parent commits the genesis-bound, nonce-free header hash, and
                // this block's nonce is the parent's hash. The full block hash covers the nonce, so
                // it fixes the parent: one block, one witness, one level. And a ZKas block cannot
                // be the parent, because its coinbase may carry no commitment (body rule).
                //
                // The parent must not ALSO carry a legacy `ZKMM` commitment: otherwise one solution
                // could back a pre-fork block (legacy rule) and a post-fork block (this rule) for the
                // blocks that straddle the activation score.
                let nonce_free = kaspa_consensus_core::hashing::header::hash_override_nonce_time(header, 0, header.timestamp);
                header.nonce == AuxPow::nonce_binding(&a.parent_header)
                    && a.committed_hash().is_none()
                    && a.verify_binding_v1(genesis, nonce_free)
                    && parent_pow(a) <= target
            }
        };
        if accepted {
            return (true, parent_pow(a));
        }
    }
    (false, native_pow)
}

/// Which merge-mining rule applies to a header: none (before merged mining), the original
/// `ZKMM‖hex(H_fc)` binding, or the security-fork binding bound to `genesis`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuxRule {
    Off,
    Legacy,
    Bound(Hash),
}

impl From<bool> for AuxRule {
    fn from(merged_mining_active: bool) -> Self {
        if merged_mining_active { AuxRule::Legacy } else { AuxRule::Off }
    }
}

impl AuxRule {
    /// The rule for a header with DAA score `daa_score`.
    pub fn for_header(merged_mining_active: bool, security_fork_active: bool, genesis: Hash) -> Self {
        match (merged_mining_active, security_fork_active) {
            (false, _) => AuxRule::Off,
            (true, false) => AuxRule::Legacy,
            (true, true) => AuxRule::Bound(genesis),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::auxpow::AuxPow;
    use kaspa_consensus_core::header::Header;
    use kaspa_consensus_core::merkle::calc_hash_merkle_root;
    use kaspa_consensus_core::subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE};
    use kaspa_consensus_core::tx::Transaction;
    use kaspa_consensus_core::{BlueWorkType, hashing};
    use kaspa_hashes::{Hash, ZERO_HASH};
    use kaspa_merkle::merkle_hash;

    const EASY_BITS: u32 = 0x207f_ffff; // target ~2^255 → ~half of nonces pass

    fn target(bits: u32) -> Uint256 {
        Uint256::from_compact_target_bits(bits)
    }

    /// A ZKas block header; its `.hash` is the commitment `H_fc`.
    fn zkas_header(seed: u64, bits: u32) -> Header {
        Header::new_finalized(
            1,
            vec![vec![Hash::from_u64_word(seed)]].try_into().unwrap(),
            Hash::from_u64_word(seed.wrapping_mul(3)),
            ZERO_HASH,
            ZERO_HASH,
            123_456,
            bits,
            0,
            0,
            BlueWorkType::from(0u64),
            0,
            ZERO_HASH,
        )
    }

    /// Fuzz the merge-mining rules over random parent coinbases: 0-3 legacy (`ZKMM`) and 0-3 bound
    /// (`ZKM1`) commitments at random positions, each to the right or a wrong value, between junk.
    /// Bound rule: accept iff exactly one well-formed `ZKM1` naming this block's genesis-bound
    /// nonce-free hash AND the parent is not usable under the legacy rule (it does not carry exactly
    /// one `ZKMM`; L-4). Legacy rule (pre-fork, must stay exactly as before): accept iff exactly one
    /// `ZKMM` naming the block hash, whatever else is there. The property L-4 exists for is checked
    /// directly: no parent is ever accepted by both rules.
    #[test]
    fn fuzz_aux_rules_accept_exactly_the_specified_parents() {
        let genesis = Hash::from_u64_word(0x6e6e);
        let mut x: u64 = 0xdead_beef_cafe_f00d;
        let mut rnd = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n.max(1)
        };
        // Junk never contains 'Z', so it cannot fake or break a tag on its own.
        let junk = |r: &mut dyn FnMut(u64) -> u64, n: u64| -> Vec<u8> { (0..r(n)).map(|_| b'a' + r(25) as u8).collect() };
        let (mut bound_ok, mut legacy_ok, mut both_tried) = (0, 0, 0);
        for case in 0..400u64 {
            let fc0 = zkas_header(1_000 + case, EASY_BITS);
            let nonce_free = kaspa_consensus_core::hashing::header::hash_override_nonce_time(&fc0, 0, fc0.timestamp);
            let right_v1 = AuxPow::bound_commitment(genesis, nonce_free);
            let n_legacy = rnd(4);
            let n_v1 = rnd(4);
            let (mut legacy_right, mut v1_right) = (0, 0);
            let mut payload = junk(&mut rnd, 30);
            let mut pieces: Vec<(bool, Hash)> = vec![];
            for _ in 0..n_legacy {
                let right = rnd(2) == 0;
                pieces.push((false, if right { fc0.hash } else { Hash::from_u64_word(rnd(u64::MAX)) }));
            }
            for _ in 0..n_v1 {
                let right = rnd(2) == 0;
                pieces.push((true, if right { right_v1 } else { AuxPow::bound_commitment(Hash::from_u64_word(rnd(9) + 1), nonce_free) }));
            }
            // Shuffle the pieces.
            for i in (1..pieces.len()).rev() {
                let j = rnd(i as u64 + 1) as usize;
                pieces.swap(i, j);
            }
            for (v1, h) in &pieces {
                if *v1 {
                    payload = AuxPow::embed_commitment_v1(&payload, *h, &junk(&mut rnd, 8));
                    v1_right += (*h == right_v1) as u32;
                } else {
                    payload = AuxPow::embed_commitment(&payload, *h, &junk(&mut rnd, 8));
                    legacy_right += (*h == fc0.hash) as u32;
                }
            }
            let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload.clone());
            let (parent, branch) = mine_parent(std::slice::from_ref(&cb), EASY_BITS);
            let aux = AuxPow { parent_header: parent.clone(), parent_coinbase: cb, coinbase_merkle_branch: branch };

            assert_eq!(AuxPow::payload_carries_commitment(&payload), n_legacy == 1 || n_v1 == 1, "case {case}: detector");

            // Legacy rule on the block as hashed (its own nonce 0).
            let mut legacy_got = None;
            if !State::new(&fc0).check_pow(fc0.nonce).0 {
                let expect = n_legacy == 1 && legacy_right == 1;
                let got = check_pow_gated(&fc0, Some(&aux), AuxRule::Legacy).0;
                assert_eq!(got, expect, "case {case}: legacy rule (legacy {n_legacy}/{legacy_right}, v1 {n_v1})");
                legacy_ok += got as u32;
                legacy_got = Some(got);
            }
            // Bound rule on the block with the parent-derived nonce.
            let mut fc = fc0.clone();
            fc.nonce = AuxPow::nonce_binding(&parent);
            fc.finalize();
            if !State::new(&fc).check_pow(fc.nonce).0 {
                let expect = n_v1 == 1 && v1_right == 1 && n_legacy != 1;
                let got = check_pow_gated(&fc, Some(&aux), AuxRule::Bound(genesis)).0;
                assert_eq!(got, expect, "case {case}: bound rule (legacy {n_legacy}, v1 {n_v1}/{v1_right})");
                bound_ok += got as u32;
                if let Some(l) = legacy_got {
                    both_tried += 1;
                    assert!(!(l && got), "case {case}: one parent backs a legacy AND a bound block");
                }
                // A wrong nonce never passes, whatever the parent.
                let mut wrong = fc.clone();
                wrong.nonce ^= 1;
                wrong.finalize();
                if !State::new(&wrong).check_pow(wrong.nonce).0 {
                    assert!(!check_pow_gated(&wrong, Some(&aux), AuxRule::Bound(genesis)).0, "case {case}: nonce must name the parent");
                }
            }
        }
        assert!(bound_ok > 5 && legacy_ok > 5 && both_tried > 20, "the fuzz reached accepting parents: bound {bound_ok}, legacy {legacy_ok}, both {both_tried}");
    }

    fn coinbase_committing(commitment: Hash) -> Transaction {
        let payload = AuxPow::embed_commitment(&[0xaa, 0xbb], commitment, &[0xcc]);
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload)
    }

    fn tx(tag: u8) -> Transaction {
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, tag as u64, vec![tag; 4])
    }

    /// Compute the leaf-0 (coinbase) Merkle branch, replicating Kaspa's tx-tree
    /// construction *including its None/ZERO propagation for sparse right subtrees*
    /// (see `kaspa_merkle::calc_merkle_root_with_hasher`). Asserted below to
    /// reproduce `calc_hash_merkle_root`, so the verifier and this helper agree.
    fn leaf0_branch(txs: &[Transaction]) -> Vec<Hash> {
        if txs.len() <= 1 {
            return vec![];
        }
        let np = txs.len().next_power_of_two();
        let mut level: Vec<Option<Hash>> = (0..np).map(|i| txs.get(i).map(hashing::tx::hash)).collect();
        let mut branch = vec![];
        while level.len() > 1 {
            branch.push(level[1].unwrap_or(ZERO_HASH));
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut t = 0;
            while t < level.len() {
                let node = match level[t] {
                    None => None, // Kaspa keeps a node None when its left child is None
                    Some(l) => Some(merkle_hash(l, level[t + 1].unwrap_or(ZERO_HASH))),
                };
                next.push(node);
                t += 2;
            }
            level = next;
        }
        branch
    }

    /// Build a parent block over `txs` (coinbase at index 0) and grind its nonce
    /// until its kHeavyHash clears `target`. Returns the mined parent header + the
    /// coinbase leaf-0 branch.
    fn mine_parent(txs: &[Transaction], bits: u32) -> (Header, Vec<Hash>) {
        let root = calc_hash_merkle_root(txs.iter());
        let branch = leaf0_branch(txs);
        // Sanity: our hand-rolled branch must fold back to Kaspa's root.
        let mut acc = hashing::tx::hash(&txs[0]);
        for s in &branch {
            acc = merkle_hash(acc, *s);
        }
        assert_eq!(acc, root, "leaf0_branch must reproduce calc_hash_merkle_root");

        let mut parent = Header::from_precomputed_hash(ZERO_HASH, vec![Hash::from_u64_word(0xdead)]);
        parent.hash_merkle_root = root;
        parent.timestamp = 555;
        parent.bits = bits;

        let state = State::new(&parent);
        let tgt = target(bits);
        let mut nonce = 0u64;
        while state.calculate_pow(nonce) > tgt {
            nonce += 1;
            assert!(nonce < 1 << 20, "easy target should be hit quickly");
        }
        parent.nonce = nonce;
        (parent, branch)
    }

    fn coinbase_committing_v1(commitment: Hash) -> Transaction {
        let payload = AuxPow::embed_commitment_v1(&[0xaa, 0xbb], commitment, &[0xcc]);
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload)
    }

    /// Security fork: one parent backs exactly one block, and one block has exactly one witness.
    #[test]
    fn bound_rule_pins_parent_and_genesis() {
        let genesis = Hash::from_u64_word(0x6e6e);
        for seed in 1..200u64 {
            let mut fc = zkas_header(seed, EASY_BITS);
            let nonce_free = kaspa_consensus_core::hashing::header::hash_override_nonce_time(&fc, 0, fc.timestamp);
            let cb = coinbase_committing_v1(AuxPow::bound_commitment(genesis, nonce_free));
            let (parent, branch) = mine_parent(std::slice::from_ref(&cb), EASY_BITS);
            fc.nonce = AuxPow::nonce_binding(&parent);
            fc.finalize();
            if State::new(&fc).check_pow(fc.nonce).0 {
                continue; // the forced nonce happens to be natively valid; pick a block that needs the witness
            }
            let aux = AuxPow { parent_header: parent.clone(), parent_coinbase: cb.clone(), coinbase_merkle_branch: branch.clone() };
            assert!(check_pow_gated(&fc, Some(&aux), AuxRule::Bound(genesis)).0, "a correctly bound witness passes");
            assert!(!check_pow_gated(&fc, Some(&aux), AuxRule::Legacy).0, "the legacy rule does not read the ZKM1 form");
            assert!(!check_pow_gated(&fc, Some(&aux), AuxRule::Bound(Hash::from_u64_word(1))).0, "another chain's genesis fails");

            // A second, independently mined parent committing the same block: its hash, hence the
            // required nonce, differs, so it cannot back this block.
            let mut other = parent.clone();
            other.timestamp += 1;
            let state = State::new(&other);
            let mut n = 0u64;
            while state.calculate_pow(n) > target(EASY_BITS) {
                n += 1;
            }
            other.nonce = n;
            if AuxPow::nonce_binding(&other) != fc.nonce {
                let aux2 = AuxPow { parent_header: other, parent_coinbase: cb.clone(), coinbase_merkle_branch: branch.clone() };
                assert!(!check_pow_gated(&fc, Some(&aux2), AuxRule::Bound(genesis)).0, "a second parent cannot back the same block");
            }

            // A legacy ZKMM witness over the full hash is refused under the bound rule.
            let legacy_cb = coinbase_committing(fc.hash);
            let (lp, lb) = mine_parent(std::slice::from_ref(&legacy_cb), EASY_BITS);
            let legacy = AuxPow { parent_header: lp, parent_coinbase: legacy_cb, coinbase_merkle_branch: lb };
            assert!(!check_pow_gated(&fc, Some(&legacy), AuxRule::Bound(genesis)).0, "legacy form refused after the fork");

            // A parent coinbase carrying BOTH tags cannot back a post-fork block (L-4: one solution,
            // a pre-fork block and a post-fork block straddling the score).
            let mut dual_payload = coinbase_committing_v1(AuxPow::bound_commitment(genesis, nonce_free)).payload;
            dual_payload.extend_from_slice(&coinbase_committing(Hash::from_u64_word(seed ^ 0x55)).payload);
            let dual_cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, dual_payload);
            let (dp, db) = mine_parent(std::slice::from_ref(&dual_cb), EASY_BITS);
            let mut fc2 = fc.clone();
            fc2.nonce = AuxPow::nonce_binding(&dp);
            fc2.finalize();
            if !State::new(&fc2).check_pow(fc2.nonce).0 {
                let dual = AuxPow { parent_header: dp, parent_coinbase: dual_cb, coinbase_merkle_branch: db };
                assert!(!check_pow_gated(&fc2, Some(&dual), AuxRule::Bound(genesis)).0, "a dual-tagged parent is refused");
            }

            // The commitment detector sees both tags, which the coinbase ban relies on.
            assert!(AuxPow::payload_carries_commitment(&cb.payload));
            assert!(AuxPow::payload_carries_commitment(&coinbase_committing(fc.hash).payload));
            assert!(!AuxPow::payload_carries_commitment(b"ZKM1 not hex, ZKMMshort"));
            return;
        }
        panic!("no seed produced a header that needs its witness");
    }

    #[test]
    fn native_path_unchanged_by_dual_gate() {
        // With no aux proof, check_pow_dual is exactly the native check.
        let mut h = zkas_header(1, EASY_BITS);
        let state = State::new(&h);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        h.nonce = nonce;
        h.finalize();
        assert!(check_pow_dual(&h, None).0, "a valid native nonce passes the dual gate");
    }

    #[test]
    fn aux_pow_accepts_single_tx_parent() {
        let fc = zkas_header(2, EASY_BITS);
        let hfc = fc.hash;
        let cb = coinbase_committing(hfc);
        let (parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };

        assert!(verify_aux_pow(&aux, hfc, target(EASY_BITS)), "real mined parent, correct commitment → valid");
        let (passed, _pow) = check_pow_dual(&fc, Some(&aux));
        assert!(passed, "dual gate accepts the aux block");
    }

    #[test]
    fn aux_pow_accepts_multi_tx_parent() {
        // A deeper (5-tx) parent Merkle tree exercises the sparse-subtree branch.
        let fc = zkas_header(3, EASY_BITS);
        let hfc = fc.hash;
        let cb = coinbase_committing(hfc);
        let txs = vec![cb.clone(), tx(1), tx(2), tx(3), tx(4)];
        let (parent, branch) = mine_parent(&txs, EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(verify_aux_pow(&aux, hfc, target(EASY_BITS)), "5-tx parent, correct commitment → valid");
    }

    #[test]
    fn aux_pow_rejects_wrong_commitment() {
        let fc = zkas_header(4, EASY_BITS);
        let cb = coinbase_committing(fc.hash);
        let (parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };
        // A different ZKas block cannot claim this parent's work.
        let other = zkas_header(999, EASY_BITS).hash;
        assert!(!verify_aux_pow(&aux, other, target(EASY_BITS)), "parent commits to fc, not `other`");
    }

    #[test]
    fn aux_pow_rejects_insufficient_work() {
        // Mine only to the easy target, then demand an impossible one (bits=0 ⇒ target 0).
        let fc = zkas_header(5, EASY_BITS);
        let hfc = fc.hash;
        let cb = coinbase_committing(hfc);
        let (parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(!verify_aux_pow(&aux, hfc, target(0)), "parent PoW does not clear an impossible target");
    }

    #[test]
    fn aux_pow_rejects_tampered_merkle_root() {
        // If the parent's committed merkle root does not match the coinbase+branch,
        // inclusion fails deterministically — the coinbase (and thus H_fc) is no
        // longer proven to be under the PoW-bearing header.
        let fc = zkas_header(6, EASY_BITS);
        let hfc = fc.hash;
        let cb = coinbase_committing(hfc);
        let (mut parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        parent.hash_merkle_root = Hash::from_bytes([0x77u8; 32]); // not the real root
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(!aux.verify_coinbase_inclusion(), "coinbase no longer folds to the (tampered) root");
        assert!(!verify_aux_pow(&aux, hfc, target(EASY_BITS)), "binding failure rejects the block");
    }

    #[test]
    fn gate_ignores_aux_until_active() {
        // A valid aux block: correct commitment + mined parent.
        let fc = zkas_header(42, EASY_BITS);
        let cb = coinbase_committing(fc.hash);
        let (parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };

        // Before activation the aux witness must have *no effect* — the gate is exactly
        // the native-only check (deterministic regardless of whether fc's nonce passes).
        assert_eq!(
            check_pow_gated(&fc, Some(&aux), false),
            check_pow_dual(&fc, None),
            "an inactive gate ignores the aux proof entirely"
        );
        // Once active, the valid aux proof is accepted.
        assert!(check_pow_gated(&fc, Some(&aux), true).0, "an active gate accepts the valid aux proof");
    }

    #[test]
    fn native_block_not_invalidated_by_bogus_aux() {
        // A validly native-mined header ...
        let mut fc = zkas_header(77, EASY_BITS);
        let state = State::new(&fc);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        fc.nonce = nonce;
        fc.finalize();
        // ... with a bogus aux attached (commits to a different block).
        let cb = coinbase_committing(zkas_header(999, EASY_BITS).hash);
        let bogus = AuxPow { parent_header: zkas_header(0, EASY_BITS), parent_coinbase: cb, coinbase_merkle_branch: vec![] };
        // The native path is tried first, so the block is accepted despite the invalid
        // aux — an unhashed, tamperable witness must never invalidate a valid block.
        assert!(check_pow_gated(&fc, Some(&bogus), true).0, "valid native PoW is not invalidated by a bogus aux witness");
    }

    #[test]
    fn aux_pow_rejects_stolen_pow_for_different_block() {
        // The canonical merged-mining attack: reuse one parent's PoW for a *second*
        // ZKas block. The parent commits to fc_a's hash, so fc_b cannot claim it.
        let fc_a = zkas_header(10, EASY_BITS);
        let fc_b = zkas_header(11, EASY_BITS);
        let cb = coinbase_committing(fc_a.hash);
        let (parent, branch) = mine_parent(&[cb.clone()], EASY_BITS);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(verify_aux_pow(&aux, fc_a.hash, target(EASY_BITS)), "legit for fc_a");
        assert!(!verify_aux_pow(&aux, fc_b.hash, target(EASY_BITS)), "same PoW cannot be stolen for fc_b");
        assert!(!check_pow_dual(&fc_b, Some(&aux)).0, "dual gate rejects the stolen-PoW block");
    }

    /// Regression for the IBD headers-proof failure ("level is 0 when it's expected
    /// to be at least N"): a merged-mined block whose native PoW misses its target is
    /// accepted via aux, and its block LEVEL derives from the parent's pow. Any code
    /// that re-derives a stored level (pruning-proof validate/apply) must reproduce
    /// that with `calc_block_level_check_pow_gated` — the native-only calc computes
    /// level 0 for the same header and rejects valid proofs.
    #[test]
    fn aux_accepted_block_level_rederives_consistently() {
        use crate::{calc_block_level_check_pow, calc_block_level_check_pow_gated, calc_level_from_pow};
        // Realistic scale: mainnet max_block_level ≈ 250; a random (failed-native)
        // pow has ~255 leading bits → level ~0, while the Kaspa parent mined to
        // 2^240 (HARD_BITS) yields level ≥ 10 — the gap the proof relies on.
        const MAX_LEVEL: crate::BlockLevel = 250;
        const HARD_BITS: u32 = 0x1f01_0000; // compact target 2^240

        // A ZKas block whose nonce is ground AWAY from the target, so native PoW
        // fails — like a real merged-mined block that only met the Kaspa target.
        let mut fc = zkas_header(20, EASY_BITS);
        let state = State::new(&fc);
        let mut nonce = 0u64;
        while state.check_pow(nonce).0 {
            nonce += 1;
        }
        fc.nonce = nonce;
        fc.finalize();
        let cb = coinbase_committing(fc.hash);
        let (parent, branch) = mine_parent(&[cb.clone()], HARD_BITS);

        let mut header = fc.clone();
        header.aux_pow = Some(Box::new(AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch }));

        // Acceptance-time level (what header validation stores):
        let (passed, pow) = check_pow_gated(&header, header.aux_pow.as_deref(), true);
        assert!(passed, "aux path accepts the block");
        let stored_level = calc_level_from_pow(pow, MAX_LEVEL);

        // Native-only re-derivation DISAGREES (this was the IBD bug)…
        let (native_level, native_ok) = calc_block_level_check_pow(&header, MAX_LEVEL, false);
        assert!(!native_ok, "native pow alone fails for this block");
        assert!(native_level < stored_level, "native-only level under-computes an aux-accepted block");

        // …while the gated re-derivation reproduces the stored level exactly.
        let (gated_level, gated_ok) = calc_block_level_check_pow_gated(&header, MAX_LEVEL, false, true);
        assert!(gated_ok);
        assert_eq!(gated_level, stored_level, "proof validation must re-derive the acceptance-time level");

        // Before activation the gate is off: the same header re-derives native-only,
        // so pre-activation blocks keep their historical levels.
        let (pre_level, pre_ok) = calc_block_level_check_pow_gated(&header, MAX_LEVEL, false, false);
        assert!(!pre_ok);
        assert_eq!(pre_level, native_level);
    }
}
