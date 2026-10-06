//! The on-wire Orchard bundle carried by a shielded transaction (PLAN §2.1).
//!
//! What an observer sees per shielded transaction is a set of **Actions** (each
//! revealing a nullifier, a note commitment `cmx`, and a net value commitment
//! `cv_net`, plus the encrypted note for the receiver and a spend-authorization
//! signature), one Halo 2 **proof**, a **binding signature**, the bundle
//! **flags** and public **value balance**, and a reference to the finalized
//! **anchor** the spends prove against. Amounts, senders and receivers are
//! hidden.
//!
//! # Carriage (decision D7)
//!
//! A shielded transaction carries its bundle in the transaction `payload`,
//! gated by a dedicated transaction version. The payload is already part of the
//! transaction hash, so the bundle is committed by the block merkle root with no
//! change to the `Transaction` struct. This module owns the *canonical* byte
//! encoding used there; it must be deterministic (consensus-critical).
//!
//! This is the wire/representation layer. Converting these bytes into live
//! `orchard` types for proof / binding-signature / value-balance verification is
//! done by the validation layer (a later task), which is where the `orchard`
//! `circuit` feature gets enabled.

use crate::nullifier::NullifierBytes;

// The transaction *version* that selects this wire format is a consensus
// parameter and lives in `kaspa_consensus_core::tx::TX_VERSION_SHIELDED`; this
// crate only owns the byte format of the bundle carried in the payload.

/// Fixed sizes of the cryptographic components, per the Orchard encoding
/// (Zcash protocol spec §7.5). Kept as named constants so the reader/writer and
/// future `orchard`-type conversions agree.
pub mod sizes {
    /// Pallas base/scalar field element or group element encoding.
    pub const FIELD: usize = 32;
    /// Orchard note ciphertext (`enc_ciphertext`).
    pub const ENC_CIPHERTEXT: usize = 580;
    /// Orchard out ciphertext (`out_ciphertext`).
    pub const OUT_CIPHERTEXT: usize = 80;
    /// RedPallas signature (spend-auth and binding).
    pub const SIG: usize = 64;
}

/// Consensus upper bound on the number of Orchard actions a single shielded
/// bundle may carry.
///
/// This is a hard anti-DoS limit, not a style choice. A shielded transaction
/// carries no transparent inputs/outputs, so under KIP-9 it currently has
/// **zero storage mass** (see `consensus/core/src/mass`): nothing at the mass
/// layer bounds how much verification work one transaction can demand. Each
/// action costs one (batched) Halo 2 proof-verification, the single most
/// expensive operation on the validation path (PLAN §2.8). Without a cap, a
/// single near-free transaction could force every node to verify an unbounded
/// proof, and the aggregate over a block would be unbounded. Bounding actions
/// per bundle bounds per-transaction verification cost; block capacity then
/// bounds the rest. 512 is far above any honest bundle (a normal payment has
/// 1–4 actions) while keeping worst-case per-tx proof work finite.
pub const MAX_ACTIONS_PER_BUNDLE: usize = 512;

/// Bundle flag bit marking a **bridge burn declaration** (`crate::burn`).
///
/// Bits 0/1 are Orchard's spends-enabled / outputs-enabled. Bit 2 says this bundle carries a
/// trailing `(burn_value, kaspa_recipient)` peg-out declaration after the proof. Flag-gated so a
/// bundle without a burn is byte-identical to the pre-bridge format.
pub const BUNDLE_FLAG_BURN: u8 = 0b100;

/// Bundle flag bit marking a named **anchor block** (security fork, 2026-10).
///
/// Bit 3 says a trailing 32-byte block hash follows the burn declaration (if any): the block whose
/// own note-commitment tree root is `anchor`. Consensus checks `root(anchor_block) == anchor` and
/// that the block is a matured selected-chain ancestor, instead of searching an index for whichever
/// block produced the root. Mandatory from the activation score, refused before it.
pub const BUNDLE_FLAG_ANCHOR_BLOCK: u8 = 0b1000;

/// Serialized length of a burn declaration: `value(8) | kaspa_recipient(32)`.
pub const BURN_DECL_LEN: usize = 8 + 32;

/// A single Orchard action, as it appears on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionWire {
    /// Nullifier of the note spent by this action (a first-class conflict key).
    pub nullifier: NullifierBytes,
    /// Randomized verification key for the spend-authorization signature (`rk`).
    pub rk: [u8; sizes::FIELD],
    /// Extracted note commitment of the note created by this action (tree leaf).
    pub cmx: [u8; sizes::FIELD],
    /// Net value commitment `cv_net` (homomorphic; feeds the turnstile).
    pub cv_net: [u8; sizes::FIELD],
    /// Ephemeral public key for note encryption (`epk_bytes`).
    pub ephemeral_key: [u8; sizes::FIELD],
    /// Encrypted note plaintext for the receiver.
    pub enc_ciphertext: [u8; sizes::ENC_CIPHERTEXT],
    /// Encrypted note plaintext recoverable with the outgoing viewing key.
    pub out_ciphertext: [u8; sizes::OUT_CIPHERTEXT],
    /// Spend-authorization signature over the action.
    pub spend_auth_sig: [u8; sizes::SIG],
}

impl ActionWire {
    /// Serialized size of one action: five 32-byte field/group elements
    /// (nullifier, rk, cmx, cv_net, ephemeral_key) + both ciphertexts + the
    /// spend-auth signature = 884 bytes.
    pub const SERIALIZED_LEN: usize = sizes::FIELD * 5 + sizes::ENC_CIPHERTEXT + sizes::OUT_CIPHERTEXT + sizes::SIG;
}

/// Size of the Orchard Halo 2 proof for a bundle of `n` actions, in bytes:
/// `2720 + 2272·n`. These constants mirror `orchard::circuit::Proof::
/// expected_proof_size` (guarded there by tests: 4992 bytes at 1 action,
/// 7264 at 2) — the proof grows linearly with the action count.
pub const fn expected_proof_len(n_actions: usize) -> usize {
    2720 + 2272 * n_actions
}

/// Exact serialized size of a [`ShieldedBundle`] with `n` actions and a
/// standard-size proof, per [`ShieldedBundle::to_bytes`]:
/// fixed header (flags 1 + value_balance 8 + anchor 32 + binding_sig 4+64 +
/// action count 4 + proof length prefix 4 = 117) + `n·884` + proof.
///
/// A wallet uses this to bound the number of spends per transaction **before**
/// paying for the (minutes-long) proof: Kaspa's mempool standardness caps
/// per-dimension mass at 100 000, and transient mass = serialized tx bytes × 4,
/// so a standard shielded tx must stay under ~25 000 bytes total.
pub const fn expected_wire_len(n_actions: usize) -> usize {
    117 + n_actions * ActionWire::SERIALIZED_LEN + expected_proof_len(n_actions)
}

/// As [`expected_wire_len`], for a bundle that also carries a burn declaration.
pub const fn expected_wire_len_with_burn(n_actions: usize) -> usize {
    expected_wire_len(n_actions) + BURN_DECL_LEN
}

/// Cheaply read just the action count from a serialized bundle, without parsing
/// (or allocating) the actions or the proof. The header reads mirror
/// [`ShieldedBundle::from_bytes`] exactly, so the two can never disagree.
///
/// The mass calculator uses this to price a shielded transaction's permanent
/// nullifier/commitment footprint (one nullifier + one note commitment per
/// action, both retained indefinitely — the nullifier in the unprunable global
/// set) without a full bundle decode on every mempool/consensus mass check.
/// Returns `None` on a malformed/too-short header or an action count exceeding
/// [`MAX_ACTIONS_PER_BUNDLE`] (such a bundle is rejected in full decode anyway).
pub fn action_count_from_bytes(bytes: &[u8]) -> Option<usize> {
    let mut r = Reader::new(bytes);
    let _flags = r.u8().ok()?;
    let _value_balance = r.i64().ok()?;
    let _anchor = r.array::<{ sizes::FIELD }>().ok()?;
    let _binding_sig = r.var().ok()?;
    let n_actions = r.u32().ok()? as usize;
    if n_actions > MAX_ACTIONS_PER_BUNDLE {
        return None;
    }
    Some(n_actions)
}

/// An Orchard bundle as carried in a shielded transaction's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedBundle {
    /// The actions (merged spend+output units).
    pub actions: Vec<ActionWire>,
    /// Bundle flags (spends-enabled / outputs-enabled bits).
    pub flags: u8,
    /// Public net value balance of the bundle (positive = value leaving the
    /// shielded pool as a fee; negative = value entering, e.g. coinbase).
    pub value_balance: i64,
    /// The finalized anchor the spends prove against (PLAN §2.5).
    pub anchor: [u8; sizes::FIELD],
    /// The Halo 2 proof attesting to the whole bundle.
    pub proof: Vec<u8>,
    /// The binding signature tying the value commitments to `value_balance`.
    pub binding_sig: [u8; sizes::SIG],
    /// Optional bridge peg-out declaration: `(burn_value, kaspa_recipient)`.
    ///
    /// Present iff [`BUNDLE_FLAG_BURN`] is set in `flags`. The declared value is carved out of
    /// `value_balance` (see [`crate::state::ShieldedTx`]), so the binding signature already
    /// constrains it — a burn cannot move value the bundle did not prove is leaving the pool.
    pub burn: Option<(u64, [u8; sizes::FIELD])>,
    /// The block whose tree root is `anchor`. Present iff [`BUNDLE_FLAG_ANCHOR_BLOCK`] is set.
    /// Covered by the sighash, so a relayer cannot repoint it.
    pub anchor_block: Option<[u8; 32]>,
}

/// Error attaching a burn declaration to a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnDeclareError {
    /// A zero-value burn would consume a nullifier and commit a leaf for nothing.
    ZeroValue,
    /// The burn exceeds what the bundle's binding signature proved is leaving the pool.
    ExceedsValueBalance {
        /// Requested burn amount.
        burn: u64,
        /// The bundle's proven `value_balance`.
        value_balance: i64,
    },
}

/// Error decoding a [`ShieldedBundle`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleDecodeError {
    /// Ran out of input before a field was complete.
    UnexpectedEof,
    /// A length prefix exceeded the remaining input (malformed/hostile).
    LengthOverflow,
    /// Trailing bytes remained after decoding.
    TrailingBytes,
    /// The burn flag was set but the trailing declaration was absent or malformed.
    MalformedBurnDeclaration,
    /// A burn declaration named zero value, which would consume a nullifier for nothing.
    ZeroValueBurn,
    /// The bundle declared more actions than [`MAX_ACTIONS_PER_BUNDLE`]
    /// (anti-DoS: rejected before any parse/verification work is done).
    TooManyActions,
}

/// A minimal canonical byte writer (big-endian length prefixes).
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Length-prefixed variable bytes.
    fn var(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }
}

/// A minimal canonical byte reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], BundleDecodeError> {
        let end = self.pos.checked_add(n).ok_or(BundleDecodeError::LengthOverflow)?;
        if end > self.buf.len() {
            return Err(BundleDecodeError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BundleDecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, BundleDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, BundleDecodeError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }
    fn i64(&mut self) -> Result<i64, BundleDecodeError> {
        Ok(i64::from_be_bytes(self.array::<8>()?))
    }
    fn u64(&mut self) -> Result<u64, BundleDecodeError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }
    fn var(&mut self) -> Result<Vec<u8>, BundleDecodeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

impl ShieldedBundle {
    /// Encode to the canonical payload byte form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.flags);
        w.i64(self.value_balance);
        w.bytes(&self.anchor);
        w.var(&self.binding_sig);
        w.u32(self.actions.len() as u32);
        for a in &self.actions {
            w.bytes(&a.nullifier);
            w.bytes(&a.rk);
            w.bytes(&a.cmx);
            w.bytes(&a.cv_net);
            w.bytes(&a.ephemeral_key);
            w.bytes(&a.enc_ciphertext);
            w.bytes(&a.out_ciphertext);
            w.bytes(&a.spend_auth_sig);
        }
        w.var(&self.proof);
        // Trailing, flag-gated: keeps a burn-free bundle byte-identical to the pre-bridge format.
        if let Some((value, recipient)) = &self.burn {
            w.u64(*value);
            w.bytes(recipient);
        }
        if let Some(block) = &self.anchor_block {
            w.bytes(block);
        }
        w.buf
    }

    /// Decode from canonical payload bytes in the security-fork format (a set
    /// [`BUNDLE_FLAG_ANCHOR_BLOCK`] carries a trailing 32-byte block hash). Rejects malformed and
    /// trailing input. Consensus must use [`Self::from_bytes_at`], which picks the format by the
    /// carrying block's DAA score.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleDecodeError> {
        Self::decode(bytes, true)
    }

    /// Decode in the format of the chain at a given point: the security-fork format when
    /// `security_fork_active`, otherwise exactly the format every node parsed before the fork, in
    /// which bit 3 of the flags is an unknown flag that carries no field (the bundle decodes and
    /// is later refused by the verifier for non-canonical flags, as it always was).
    ///
    /// The difference matters before the activation: the parse runs in the context-free block-body
    /// check, so a byte string the two formats judge differently would make old and new nodes
    /// disagree about a block's validity.
    pub fn from_bytes_at(bytes: &[u8], security_fork_active: bool) -> Result<Self, BundleDecodeError> {
        Self::decode(bytes, security_fork_active)
    }

    fn decode(bytes: &[u8], anchor_block_field: bool) -> Result<Self, BundleDecodeError> {
        let mut r = Reader::new(bytes);
        let flags = r.u8()?;
        let value_balance = r.i64()?;
        let anchor = r.array::<{ sizes::FIELD }>()?;
        let binding_sig_vec = r.var()?;
        let binding_sig: [u8; sizes::SIG] = binding_sig_vec.as_slice().try_into().map_err(|_| BundleDecodeError::UnexpectedEof)?;
        let n_actions = r.u32()? as usize;
        // Anti-DoS: reject an oversized action count up front, before allocating
        // or parsing (bounds per-transaction verification work; see
        // MAX_ACTIONS_PER_BUNDLE). A shielded tx has zero storage mass, so this
        // wire-format cap is what keeps proof-verification cost per tx finite.
        if n_actions > MAX_ACTIONS_PER_BUNDLE {
            return Err(BundleDecodeError::TooManyActions);
        }
        let mut actions = Vec::with_capacity(n_actions);
        for _ in 0..n_actions {
            actions.push(ActionWire {
                nullifier: r.array::<{ sizes::FIELD }>()?,
                rk: r.array::<{ sizes::FIELD }>()?,
                cmx: r.array::<{ sizes::FIELD }>()?,
                cv_net: r.array::<{ sizes::FIELD }>()?,
                ephemeral_key: r.array::<{ sizes::FIELD }>()?,
                enc_ciphertext: r.array::<{ sizes::ENC_CIPHERTEXT }>()?,
                out_ciphertext: r.array::<{ sizes::OUT_CIPHERTEXT }>()?,
                spend_auth_sig: r.array::<{ sizes::SIG }>()?,
            });
        }
        let proof = r.var()?;
        // The burn declaration is part of the canonical encoding, so it must be consumed before
        // the trailing-bytes check — otherwise every burn bundle would be rejected as malformed.
        let burn = if flags & BUNDLE_FLAG_BURN != 0 {
            let value = r.u64().map_err(|_| BundleDecodeError::MalformedBurnDeclaration)?;
            let recipient = r.array::<{ sizes::FIELD }>().map_err(|_| BundleDecodeError::MalformedBurnDeclaration)?;
            if value == 0 {
                return Err(BundleDecodeError::ZeroValueBurn);
            }
            Some((value, recipient))
        } else {
            None
        };
        let anchor_block = if anchor_block_field && flags & BUNDLE_FLAG_ANCHOR_BLOCK != 0 {
            Some(r.array::<32>().map_err(|_| BundleDecodeError::UnexpectedEof)?)
        } else {
            None
        };
        if !r.finished() {
            return Err(BundleDecodeError::TrailingBytes);
        }

        Ok(Self { actions, flags, value_balance, anchor, proof, binding_sig, burn, anchor_block })
    }

    /// Name the block whose tree root is `anchor`, setting the flag bit and the field together so
    /// the encoding stays canonical. Must be done BEFORE the sighash is computed and signed.
    pub fn set_anchor_block(&mut self, block: [u8; 32]) {
        self.anchor_block = Some(block);
        self.flags |= BUNDLE_FLAG_ANCHOR_BLOCK;
    }

    /// Attach a bridge peg-out declaration to a proven bundle.
    ///
    /// **`value_balance` must already account for the burn.** A bundle's `value_balance` is what
    /// the binding signature proves is leaving the shielded pool, and it is fixed at proving time;
    /// consensus then splits it into `burn_value` + miner fee. So a wallet must decide the burn
    /// amount *before* proving and build the bundle with `value_balance = fee + burn_value`. This
    /// function only records the declaration — it cannot change what was proven.
    ///
    /// Rejects a burn larger than `value_balance` (consensus would reject the block) and a
    /// zero-value burn (it would consume a nullifier for nothing). A bundle that spends nothing has
    /// no nullifier to key the exit by and is rejected later by `ShieldedTx::from_bundle`.
    pub fn declare_burn(&mut self, burn_value: u64, kaspa_recipient: [u8; sizes::FIELD]) -> Result<(), BurnDeclareError> {
        if burn_value == 0 {
            return Err(BurnDeclareError::ZeroValue);
        }
        if self.value_balance < 0 || burn_value > self.value_balance as u64 {
            return Err(BurnDeclareError::ExceedsValueBalance { burn: burn_value, value_balance: self.value_balance });
        }
        self.flags |= BUNDLE_FLAG_BURN;
        self.burn = Some((burn_value, kaspa_recipient));
        Ok(())
    }

    /// A deterministic sample bundle with `n` actions, for tests in dependent modules.
    #[cfg(test)]
    pub fn sample_for_test(n: u8) -> Self {
        Self {
            actions: (0..n)
                .map(|i| ActionWire {
                    nullifier: [i.wrapping_add(1); sizes::FIELD],
                    rk: [i; sizes::FIELD],
                    // A small little-endian integer is always a canonical Pallas base element.
                    cmx: {
                        let mut c = [0u8; sizes::FIELD];
                        c[0] = i;
                        c
                    },
                    cv_net: [i; sizes::FIELD],
                    ephemeral_key: [i; sizes::FIELD],
                    enc_ciphertext: [i; sizes::ENC_CIPHERTEXT],
                    out_ciphertext: [i; sizes::OUT_CIPHERTEXT],
                    spend_auth_sig: [i; sizes::SIG],
                })
                .collect(),
            flags: 0b11,
            value_balance: 0,
            anchor: [9u8; sizes::FIELD],
            proof: vec![0xab; 32],
            binding_sig: [0xcd; sizes::SIG],
            burn: None,
            anchor_block: None,
        }
    }

    /// The nullifiers revealed by this bundle, in action order (conflict keys).
    pub fn nullifiers(&self) -> impl Iterator<Item = &NullifierBytes> {
        self.actions.iter().map(|a| &a.nullifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action(seed: u8) -> ActionWire {
        ActionWire {
            nullifier: [seed; sizes::FIELD],
            rk: [seed.wrapping_add(1); sizes::FIELD],
            cmx: [seed.wrapping_add(2); sizes::FIELD],
            cv_net: [seed.wrapping_add(3); sizes::FIELD],
            ephemeral_key: [seed.wrapping_add(4); sizes::FIELD],
            enc_ciphertext: [seed.wrapping_add(5); sizes::ENC_CIPHERTEXT],
            out_ciphertext: [seed.wrapping_add(6); sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [seed.wrapping_add(7); sizes::SIG],
        }
    }

    /// The pre-fork and security-fork formats must judge the two bit-3 byte forms oppositely, and the
    /// pre-fork judgement must be exactly the old parser's: bit 3 alone decodes (the verifier later
    /// refuses it), bit 3 with a trailing block hash is trailing garbage. Otherwise old and new nodes
    /// disagree about a block body before the activation.
    #[test]
    fn anchor_block_field_is_format_gated_and_pre_fork_parse_is_unchanged() {
        let mut flag_only = sample_bundle(2);
        flag_only.flags |= BUNDLE_FLAG_ANCHOR_BLOCK;
        flag_only.anchor_block = None;
        let flag_only = flag_only.to_bytes();
        let mut named = sample_bundle(2);
        named.set_anchor_block([0xAB; 32]);
        let named = named.to_bytes();

        let pre = ShieldedBundle::from_bytes_at(&flag_only, false).expect("pre-fork: an unknown flag bit decodes, as it always did");
        assert!(pre.anchor_block.is_none() && pre.flags & BUNDLE_FLAG_ANCHOR_BLOCK != 0);
        assert_eq!(ShieldedBundle::from_bytes_at(&named, false), Err(BundleDecodeError::TrailingBytes), "pre-fork: the field is trailing bytes");
        assert_eq!(ShieldedBundle::from_bytes_at(&flag_only, true), Err(BundleDecodeError::UnexpectedEof), "post-fork: the field is required");
        assert_eq!(ShieldedBundle::from_bytes_at(&named, true).unwrap().anchor_block, Some([0xAB; 32]));
        // A bundle without the bit is the same in both formats.
        let plain = sample_bundle(2).to_bytes();
        assert_eq!(ShieldedBundle::from_bytes_at(&plain, false), ShieldedBundle::from_bytes_at(&plain, true));
    }

    fn sample_bundle(n: u8) -> ShieldedBundle {
        ShieldedBundle {
            actions: (0..n).map(sample_action).collect(),
            flags: 0b11,
            value_balance: -123_456,
            anchor: [9u8; sizes::FIELD],
            proof: vec![0xab; 1000],
            binding_sig: [0xcd; sizes::SIG],
            burn: None,
            anchor_block: None,
        }
    }

    #[test]
    fn round_trips() {
        for n in [0u8, 1, 2, 5] {
            let b = sample_bundle(n);
            let bytes = b.to_bytes();
            let decoded = ShieldedBundle::from_bytes(&bytes).expect("decode");
            assert_eq!(b, decoded);
            // Canonical: re-encoding the decoded value is identical.
            assert_eq!(bytes, decoded.to_bytes());
        }
    }

    #[test]
    fn action_count_matches_full_decode() {
        // The cheap header-only count the mass calculator relies on must never
        // disagree with a full decode, or shielded txs would be mispriced.
        for n in [0u8, 1, 2, 5, 200] {
            let bytes = sample_bundle(n).to_bytes();
            assert_eq!(action_count_from_bytes(&bytes), Some(n as usize));
        }
    }

    #[test]
    fn action_count_rejects_malformed() {
        // Too short to hold even the header → None (mass calc treats as 0 actions;
        // full validation rejects the tx later).
        assert_eq!(action_count_from_bytes(&[]), None);
        assert_eq!(action_count_from_bytes(&[0u8; 10]), None);
        // A hostile oversized count is rejected up front, same bound as from_bytes.
        let mut bytes = sample_bundle(1).to_bytes();
        // action count u32 sits at offset 109 (flags 1 + value_balance 8 + anchor 32
        // + binding_sig [len 4 + 64]); overwrite it with MAX+1.
        let over = (MAX_ACTIONS_PER_BUNDLE as u32 + 1).to_be_bytes();
        bytes[109..113].copy_from_slice(&over);
        assert_eq!(action_count_from_bytes(&bytes), None);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_bundle(1).to_bytes();
        bytes.push(0);
        assert_eq!(ShieldedBundle::from_bytes(&bytes), Err(BundleDecodeError::TrailingBytes));
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample_bundle(2).to_bytes();
        assert_eq!(ShieldedBundle::from_bytes(&bytes[..bytes.len() - 10]), Err(BundleDecodeError::UnexpectedEof));
    }

    #[test]
    fn rejects_hostile_action_count() {
        // flags + value_balance + anchor + binding_sig(len-prefixed) + huge count
        let mut w = Writer::new();
        w.u8(0);
        w.i64(0);
        w.bytes(&[0u8; sizes::FIELD]);
        w.var(&[0u8; sizes::SIG]);
        w.u32(u32::MAX); // claims 4 billion actions
        // Rejected by the anti-DoS action cap before any allocation/parse work.
        assert_eq!(ShieldedBundle::from_bytes(&w.buf), Err(BundleDecodeError::TooManyActions));
    }

    #[test]
    fn rejects_action_count_over_cap() {
        // A count one past the cap is rejected up front; the cap itself decodes
        // structurally (here it fails later on EOF since no action bytes follow).
        let mut w = Writer::new();
        w.u8(0);
        w.i64(0);
        w.bytes(&[0u8; sizes::FIELD]);
        w.var(&[0u8; sizes::SIG]);
        w.u32(MAX_ACTIONS_PER_BUNDLE as u32 + 1);
        assert_eq!(ShieldedBundle::from_bytes(&w.buf), Err(BundleDecodeError::TooManyActions));

        // A real bundle at exactly the cap round-trips (the cap is inclusive).
        let at_cap = ShieldedBundle {
            actions: (0..MAX_ACTIONS_PER_BUNDLE).map(|i| sample_action(i as u8)).collect(),
            flags: 0b11,
            value_balance: 0,
            anchor: [0u8; sizes::FIELD],
            proof: vec![],
            binding_sig: [0u8; sizes::SIG],
            burn: None,
            anchor_block: None,
        };
        assert_eq!(ShieldedBundle::from_bytes(&at_cap.to_bytes()).map(|b| b.actions.len()), Ok(MAX_ACTIONS_PER_BUNDLE));
    }

    /// `declare_burn` refuses anything consensus would reject, so a wallet cannot build an
    /// unspendable transaction after paying for a proof.
    #[test]
    fn declare_burn_enforces_the_value_balance_bound() {
        let mut b = sample_bundle(2);
        b.value_balance = 30;

        assert_eq!(b.declare_burn(0, [1; sizes::FIELD]), Err(BurnDeclareError::ZeroValue));
        assert_eq!(b.declare_burn(31, [1; sizes::FIELD]), Err(BurnDeclareError::ExceedsValueBalance { burn: 31, value_balance: 30 }),);
        assert_eq!(b.burn, None, "a rejected declaration must not mutate the bundle");
        assert_eq!(b.flags & BUNDLE_FLAG_BURN, 0);

        // Burning the whole value_balance (zero miner fee) is legal.
        b.declare_burn(30, [0xA1; sizes::FIELD]).unwrap();
        assert_eq!(b.burn, Some((30, [0xA1; sizes::FIELD])));
        assert_ne!(b.flags & BUNDLE_FLAG_BURN, 0, "the flag must be set so the declaration encodes");

        // And it round-trips through the wire.
        assert_eq!(ShieldedBundle::from_bytes(&b.to_bytes()).unwrap().burn, b.burn);
    }

    /// A coinbase-style bundle (value entering the pool) can never declare a burn.
    #[test]
    fn declare_burn_rejects_a_negative_value_balance() {
        let mut b = sample_bundle(2);
        b.value_balance = -100;
        assert_eq!(
            b.declare_burn(10, [1; sizes::FIELD]),
            Err(BurnDeclareError::ExceedsValueBalance { burn: 10, value_balance: -100 }),
        );
    }

    /// A burn declaration round-trips, and a burn-free bundle stays byte-identical to the
    /// pre-bridge encoding (the flag gate must cost nothing when unused).
    #[test]
    fn burn_declaration_round_trips_and_is_flag_gated() {
        let plain = sample_bundle(3);
        let plain_bytes = plain.to_bytes();
        assert_eq!(ShieldedBundle::from_bytes(&plain_bytes).unwrap().burn, None);

        let mut burning = sample_bundle(3);
        burning.flags |= BUNDLE_FLAG_BURN;
        burning.burn = Some((7_500_000, [0xA1; sizes::FIELD]));
        let bytes = burning.to_bytes();
        // A burn costs exactly the declaration and nothing else.
        assert_eq!(bytes.len(), plain_bytes.len() + BURN_DECL_LEN);
        assert_eq!(expected_wire_len_with_burn(3), expected_wire_len(3) + BURN_DECL_LEN);

        let decoded = ShieldedBundle::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.burn, Some((7_500_000, [0xA1; sizes::FIELD])));
    }

    /// The flag and the trailing bytes must agree in both directions, or a peer could smuggle
    /// unparsed data past the trailing-bytes check.
    #[test]
    fn burn_flag_and_payload_must_agree() {
        // Flag set, no declaration present.
        let mut b = sample_bundle(2);
        b.flags |= BUNDLE_FLAG_BURN;
        b.burn = None;
        assert_eq!(ShieldedBundle::from_bytes(&b.to_bytes()), Err(BundleDecodeError::MalformedBurnDeclaration));

        // Declaration present, flag clear => the bytes are unconsumed trailing input.
        let mut b = sample_bundle(2);
        b.burn = Some((1, [0x01; sizes::FIELD]));
        assert_eq!(ShieldedBundle::from_bytes(&b.to_bytes()), Err(BundleDecodeError::TrailingBytes));

        // Truncated declaration.
        let mut b = sample_bundle(2);
        b.flags |= BUNDLE_FLAG_BURN;
        b.burn = Some((1, [0x01; sizes::FIELD]));
        let mut bytes = b.to_bytes();
        bytes.truncate(bytes.len() - 4);
        assert_eq!(ShieldedBundle::from_bytes(&bytes), Err(BundleDecodeError::MalformedBurnDeclaration));
    }

    /// A zero-value burn would consume a nullifier and commit a leaf for nothing.
    #[test]
    fn zero_value_burn_is_rejected() {
        let mut b = sample_bundle(2);
        b.flags |= BUNDLE_FLAG_BURN;
        b.burn = Some((0, [0x01; sizes::FIELD]));
        assert_eq!(ShieldedBundle::from_bytes(&b.to_bytes()), Err(BundleDecodeError::ZeroValueBurn));
    }

    /// `expected_wire_len` must track `to_bytes` exactly (a wallet sizes its
    /// spends against the standard-mass cap with it *before* proving).
    #[test]
    fn expected_wire_len_matches_encoding() {
        for n in [0usize, 1, 2, 5, 14] {
            let mut b = sample_bundle(n as u8);
            b.proof = vec![0xab; expected_proof_len(n)];
            assert_eq!(b.to_bytes().len(), expected_wire_len(n), "wire length for {n} actions");
        }
        // The real-world datapoint: a 14-spend payment serialized to 47 021
        // payload bytes (rejected at 188 460 transient mass = (payload + 94-byte
        // tx envelope) × 4 against the 100 000 standard cap).
        assert_eq!(expected_wire_len(14), 47_021);
    }

    #[test]
    fn nullifiers_iter_in_order() {
        let b = sample_bundle(3);
        let nfs: Vec<_> = b.nullifiers().copied().collect();
        assert_eq!(nfs, vec![[0u8; 32], [1u8; 32], [2u8; 32]]);
    }
}
