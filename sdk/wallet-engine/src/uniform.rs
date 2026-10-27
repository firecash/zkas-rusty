//! Stage W of uniform transactions (spec 02 §3.1, as revised by spec 15 A1/A5/A6).
//!
//! Every user transaction a Stage W wallet emits has ONE public shape: 4 Orchard actions
//! (real spends and outputs padded with Orchard's native dummies), a fee of exactly
//! [`UNIFORM_FEE_V1`], `lock_time = 0`, bundle flags [`UNIFORM_FLAGS_V1`] and an anchor at the
//! newest matured epoch opener. This module holds the constants, the envelope check every
//! client runs before signing or broadcasting, the epoch-opener anchor rule and the planner.
//! The scheduler (when a transaction is released) lives in [`crate::schedule`].
//!
//! Nothing here changes consensus: today's rules accept every transaction this module plans
//! (any matured selected-chain ancestor is a valid anchor, any fee at or above the relay
//! minimum is valid, and the action count is free). Uniformity is wallet behaviour, so it
//! only helps once every client emits the same shape; that is why the rules live once, here.

use crate::payment::{PlanError, min_relay_fee_for_actions, spend_order_key};
use kaspa_shielded_core::bundle::{BUNDLE_FLAG_ANCHOR_BLOCK, BUNDLE_FLAG_BURN, ShieldedBundle, expected_wire_len};
use serde::{Deserialize, Serialize};

/// Actions in every uniform transaction (spec 02 U0, §3.0 option (a)).
pub const UNIFORM_ACTIONS: usize = 4;

/// Real spends one uniform transaction may carry.
pub const MAX_UNIFORM_SPENDS: usize = UNIFORM_ACTIONS;

/// Payees one uniform transaction may carry: the outputs are the payees plus exactly one
/// change output (W6), so 3. W10 allows more than one payee per transaction only for an
/// operator whose payouts exceed 10% of block capacity; the default is one.
pub const MAX_UNIFORM_PAYEES: usize = UNIFORM_ACTIONS - 1;

/// The exact fee of a V1 uniform transaction, in sompi (spec 02 W4; 15 A6 "Stage W keeps
/// F_V1 until NU-B"). It is today's `chunk_fee(·, 4)` and clears the node's relay minimum for
/// a 4-action transaction (3,117,400 sompi, spec 02 W4). Burned 2,400,000 / tipped 717,800
/// once spec 08's NU-A floor is live; until then all of it goes to the miner, as today.
pub const UNIFORM_FEE_V1: u64 = 3_117_800;

/// V1 bundle flags: spends enabled | outputs enabled | anchor block named; never BURN.
pub const UNIFORM_FLAGS_V1: u8 = 0x0b;

/// Serialized payload length of a V1 uniform bundle: the 4-action wire plus the 32-byte
/// named anchor block (spec 02 W1: 2,869 + 4 x 3,156).
pub const UNIFORM_PAYLOAD_LEN_V1: usize = expected_wire_len(UNIFORM_ACTIONS) + 32;

/// `lock_time` of every uniform transaction (spec 15 A5: 0 for ordinary sends in V1).
pub const UNIFORM_LOCK_TIME: u64 = 0;

/// Most sibling transactions one logical payment may be split into (W8). Above this the
/// wallet consolidates first: 105 back-to-back siblings cannot be hidden by any window.
pub const MAX_SIBLINGS: usize = 8;

/// Spendable-note count above which background consolidation runs (W9).
pub const MERGE_TRIGGER_NOTES: usize = 8;

/// Notes one background merge spends (4 -> 1, one internal change output, 3 dummies).
pub const MERGE_INPUTS: usize = UNIFORM_ACTIONS;

// ---------------------------------------------------------------------------------------------
// Envelope check
// ---------------------------------------------------------------------------------------------

/// Which envelope field of a bundle breaks the uniform shape. Named so a refusal tells the
/// caller exactly what is wrong (spec 02 R1's `RejectNonUniform(field)` uses the same names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "field", content = "value")]
pub enum EnvelopeViolation {
    /// The bundle does not have exactly [`UNIFORM_ACTIONS`] actions.
    ActionCount(usize),
    /// The flags byte is not [`UNIFORM_FLAGS_V1`].
    Flags(u8),
    /// The public value balance is not [`UNIFORM_FEE_V1`].
    Fee(i64),
    /// The bundle carries a burn declaration.
    Burn,
    /// The bundle does not name its anchor block.
    NoAnchorBlock,
    /// The serialized payload is not [`UNIFORM_PAYLOAD_LEN_V1`] bytes.
    PayloadLen(usize),
    /// The payload does not decode as a bundle at all.
    Decode,
}

impl core::fmt::Display for EnvelopeViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActionCount(n) => write!(f, "bundle has {n} actions, a uniform transaction has {UNIFORM_ACTIONS}"),
            Self::Flags(b) => write!(f, "bundle flags are {b:#04x}, a uniform transaction has {UNIFORM_FLAGS_V1:#04x}"),
            Self::Fee(v) => write!(f, "bundle pays a fee of {v} sompi, a uniform transaction pays exactly {UNIFORM_FEE_V1}"),
            Self::Burn => f.write_str("bundle carries a burn declaration"),
            Self::NoAnchorBlock => f.write_str("bundle does not name its anchor block"),
            Self::PayloadLen(n) => write!(f, "payload is {n} bytes, a uniform transaction is {UNIFORM_PAYLOAD_LEN_V1}"),
            Self::Decode => f.write_str("payload is not a shielded bundle"),
        }
    }
}

impl std::error::Error for EnvelopeViolation {}

/// Check the public fields of a bundle against the V1 uniform envelope: action count, flags,
/// exact fee, no burn, named anchor block. Works on an unsigned, unproven effects bundle too
/// (the non-custodial `/prepare` hands one to the device), because it never reads the proof.
pub fn check_uniform_effects(b: &ShieldedBundle) -> Result<(), EnvelopeViolation> {
    if b.actions.len() != UNIFORM_ACTIONS {
        return Err(EnvelopeViolation::ActionCount(b.actions.len()));
    }
    if b.burn.is_some() || b.flags & BUNDLE_FLAG_BURN != 0 {
        return Err(EnvelopeViolation::Burn);
    }
    if b.anchor_block.is_none() || b.flags & BUNDLE_FLAG_ANCHOR_BLOCK == 0 {
        return Err(EnvelopeViolation::NoAnchorBlock);
    }
    if b.flags != UNIFORM_FLAGS_V1 {
        return Err(EnvelopeViolation::Flags(b.flags));
    }
    if b.value_balance != UNIFORM_FEE_V1 as i64 {
        return Err(EnvelopeViolation::Fee(b.value_balance));
    }
    Ok(())
}

/// Full V1 envelope check of a finished transaction payload, proof included: everything
/// [`check_uniform_effects`] checks plus the exact payload length (which pins the proof size
/// and the absence of trailing bytes).
pub fn check_uniform_payload(payload: &[u8]) -> Result<(), EnvelopeViolation> {
    let b = ShieldedBundle::from_bytes(payload).map_err(|_| EnvelopeViolation::Decode)?;
    check_uniform_effects(&b)?;
    if payload.len() != UNIFORM_PAYLOAD_LEN_V1 {
        return Err(EnvelopeViolation::PayloadLen(payload.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Anchor epoch (spec 01 §3.3 E-R1/E-R2 with E = 120, D = 600; spec 15 A1, A8.2)
// ---------------------------------------------------------------------------------------------

/// Anchor epoch length E, in blue score (spec 15 A1).
pub const ANCHOR_EPOCH: u64 = 120;
/// Consensus anchor depth D, in blue score (`shielded_anchor_depth` at 1 BPS).
pub const ANCHOR_DEPTH: u64 = 600;
/// Wallet-only slack below the sink (walletd's existing `ANCHOR_SLACK`; 01 E-R2 W4').
pub const ANCHOR_SLACK: u64 = 30;
/// Near a boundary, wait for the next epoch if it matures within this many blue (01 E-R2 H).
pub const NEAR_BOUNDARY_WAIT: u64 = 20;

/// The anchor-epoch rule's parameters, in blue score. [`AnchorRule::MAINNET`] is the spec's
/// (E 120, D 600, slack 30, H 20 at 1 BPS). Consensus derives the depth as `600 x BPS`
/// (`params.rs shielded_anchor_depth`), so a 10-BPS network (the ZKas devnet) has D = 6,000; the
/// rule for such a network scales every term by the same factor ([`AnchorRule::for_depth`]), which
/// keeps the epochs at the same wall-clock length. Wallets take the rule from the network params,
/// never from these constants alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRule {
    pub epoch: u64,
    pub depth: u64,
    pub slack: u64,
    pub near_wait: u64,
}

impl AnchorRule {
    pub const MAINNET: AnchorRule = AnchorRule { epoch: ANCHOR_EPOCH, depth: ANCHOR_DEPTH, slack: ANCHOR_SLACK, near_wait: NEAR_BOUNDARY_WAIT };

    /// The rule for a network whose consensus anchor depth is `depth` (= 600 x BPS).
    pub const fn for_depth(depth: u64) -> AnchorRule {
        let k = if depth / ANCHOR_DEPTH == 0 { 1 } else { depth / ANCHOR_DEPTH };
        AnchorRule { epoch: ANCHOR_EPOCH * k, depth, slack: ANCHOR_SLACK * k, near_wait: NEAR_BOUNDARY_WAIT * k }
    }

    pub const fn epoch_of(&self, blue: u64) -> u64 {
        blue / self.epoch
    }

    pub const fn is_opener(&self, blue: u64, parent_blue: u64) -> bool {
        self.epoch_of(blue) > self.epoch_of(parent_blue)
    }

    pub const fn matured_epoch(&self, s: u64) -> u64 {
        s.saturating_sub(self.depth) / self.epoch
    }

    pub const fn accepted_at(&self, anchor_blue: u64, s: u64) -> bool {
        s >= anchor_blue + self.depth && self.epoch_of(anchor_blue) + 1 >= self.matured_epoch(s)
    }

    /// The first blue score at which E-R1 no longer accepts an anchor of `anchor_blue`.
    pub const fn valid_until(&self, anchor_blue: u64) -> u64 {
        (self.epoch_of(anchor_blue) + 2) * self.epoch + self.depth
    }

    /// See [`pick_epoch_anchor`].
    pub fn pick(&self, chain_blue: &[u64], sink_blue: u64) -> AnchorPick {
        let view = sink_blue.saturating_sub(self.slack);
        let cutoff = view.saturating_sub(self.depth);
        let mut found: Option<(usize, u64)> = None;
        for i in (1..chain_blue.len()).rev() {
            let (b, p) = (chain_blue[i], chain_blue[i - 1]);
            if b <= cutoff && self.is_opener(b, p) {
                found = Some((i, b));
                break;
            }
        }
        let Some((i, b)) = found else { return AnchorPick { opener: None, wait_blue: None } };
        let next_opener = (i + 1..chain_blue.len()).find(|&j| self.is_opener(chain_blue[j], chain_blue[j - 1])).map(|j| chain_blue[j]);
        let next_matures = next_opener.unwrap_or((self.epoch_of(b) + 1) * self.epoch) + self.depth;
        let until_next = next_matures.saturating_sub(view);
        let too_old = !self.accepted_at(b, sink_blue);
        let wait_blue = (too_old || until_next <= self.near_wait).then_some(until_next.max(1));
        AnchorPick { opener: Some((i, b)), wait_blue }
    }

    /// See [`needs_reanchor`].
    pub fn needs_reanchor(&self, anchor_blue: u64, chain_blue: &[u64], sink_blue: u64) -> bool {
        if !self.accepted_at(anchor_blue, sink_blue) {
            return true;
        }
        match self.pick(chain_blue, sink_blue).opener {
            Some((_, newest)) => newest != anchor_blue,
            None => false,
        }
    }
}

/// The anchor epoch of a block with blue score `blue`.
pub const fn anchor_epoch(blue: u64) -> u64 {
    blue / ANCHOR_EPOCH
}

/// Whether a selected-chain block is an **epoch opener**: its epoch is above its selected
/// parent's (01 §3.3). Each epoch has at most one opener on a chain; an epoch the chain jumps
/// over has none.
pub const fn is_epoch_opener(blue: u64, parent_blue: u64) -> bool {
    anchor_epoch(blue) > anchor_epoch(parent_blue)
}

/// `K(s) = floor((s - D) / E)`: the newest epoch whose nominal start is matured at blue `s`.
pub const fn matured_epoch(s: u64) -> u64 {
    s.saturating_sub(ANCHOR_DEPTH) / ANCHOR_EPOCH
}

/// E-R1 (d) and (e) for an opener at `anchor_blue` judged at a chain block of blue `s`:
/// at least D deep, and of epoch `K(s)` or `K(s) - 1`. Today's consensus only requires the
/// age to lie in `[D, max_shielded_anchor_age]`, which every anchor accepted here satisfies,
/// so a wallet following this rule is valid under both the current and the NU-B rule.
pub const fn opener_accepted_at(anchor_blue: u64, s: u64) -> bool {
    s >= anchor_blue + ANCHOR_DEPTH && anchor_epoch(anchor_blue) + 1 >= matured_epoch(s)
}

/// The result of choosing an anchor over a wallet's view of the selected chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorPick {
    /// The newest matured epoch opener: `(index into the chain slice, its blue score)`. `None`
    /// when the slice holds no matured opener with a known parent.
    pub opener: Option<(usize, u64)>,
    /// When set, the wallet SHOULD wait this many blue scores before building: the next epoch
    /// matures that soon (01 E-R2 near-boundary rule), or the found opener is already too old
    /// for consensus (a chain jump) and the next one must mature first.
    pub wait_blue: Option<u64>,
}

impl AnchorPick {
    /// The opener to build on right now, if building now is allowed.
    pub fn ready(&self) -> Option<(usize, u64)> {
        if self.wait_blue.is_some() { None } else { self.opener }
    }
}

/// Choose the anchor of a Stage W transaction (01 E-R2 W4'): the opener of the newest epoch
/// matured at `sink_blue - ANCHOR_SLACK`.
///
/// `chain_blue` is the wallet's view of consecutive selected-chain blocks, ascending blue score
/// (walletd's matured-anchor ring). Entry 0 has no known parent, so it is never chosen: the
/// opener predicate needs the parent's epoch and a guess would pick a non-opener.
pub fn pick_epoch_anchor(chain_blue: &[u64], sink_blue: u64) -> AnchorPick {
    AnchorRule::MAINNET.pick(chain_blue, sink_blue)
}

/// Whether a built transaction anchored at `anchor_blue` must be re-proved before release
/// (W5 re-prove rule): its anchor is no longer the newest matured opener, or consensus would
/// no longer accept it at the sink.
pub fn needs_reanchor(anchor_blue: u64, chain_blue: &[u64], sink_blue: u64) -> bool {
    AnchorRule::MAINNET.needs_reanchor(anchor_blue, chain_blue, sink_blue)
}

// ---------------------------------------------------------------------------------------------
// Planner (W7, W8, W9)
// ---------------------------------------------------------------------------------------------

/// One uniform transaction of a logical payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniformTx {
    /// Indices into [`UniformPaymentPlan::sorted_note_values`], at most [`MAX_UNIFORM_SPENDS`].
    pub notes: Vec<usize>,
    /// Amount this transaction pays the payee.
    pub amount: u64,
    /// Change back to the wallet (always one output, possibly zero, W6).
    pub change: u64,
}

/// A payment planned as 1..=[`MAX_SIBLINGS`] uniform siblings, each paying exactly
/// [`UNIFORM_FEE_V1`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniformPaymentPlan {
    /// Candidate note values in spend order (see [`sort_for_uniform_spend`]).
    pub sorted_note_values: Vec<u64>,
    pub requested_amount: u64,
    pub siblings: Vec<UniformTx>,
    pub fee_per_tx: u64,
    pub total_fee: u64,
}

/// Why a uniform payment cannot be planned as it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum UniformPlanError {
    ZeroAmount,
    InsufficientFunds,
    AmountOverflow,
    /// The payment needs more than [`MAX_SIBLINGS`] siblings: consolidate first (W8). `siblings`
    /// is how many it would need now.
    NeedsConsolidation { siblings: usize },
}

impl From<PlanError> for UniformPlanError {
    fn from(e: PlanError) -> Self {
        match e {
            PlanError::ZeroAmount => Self::ZeroAmount,
            PlanError::AmountOverflow => Self::AmountOverflow,
            PlanError::InsufficientFunds | PlanError::NoSpendCapacity => Self::InsufficientFunds,
        }
    }
}

impl core::fmt::Display for UniformPlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroAmount => f.write_str("payment amount must be positive"),
            Self::InsufficientFunds => f.write_str("insufficient funds after transaction fees"),
            Self::AmountOverflow => f.write_str("payment values overflow the supported amount range"),
            Self::NeedsConsolidation { siblings } => write!(
                f,
                "this payment needs {siblings} transactions, more than the {MAX_SIBLINGS} a private payment may use; \
                 the wallet must merge its notes first (about 20-40 minutes)"
            ),
        }
    }
}

impl std::error::Error for UniformPlanError {}

/// The smallest a single note must be to pay `amount` alone in a uniform transaction.
pub fn uniform_single_note_target(amount: u64) -> u64 {
    amount.saturating_add(UNIFORM_FEE_V1)
}

/// Put candidate notes in uniform spend order: the notes that cover `amount + F` alone first,
/// smallest first; then the rest largest first (W7, the existing [`spend_order_key`] at F).
pub fn sort_for_uniform_spend(values: &mut [u64], amount: u64) {
    let target = uniform_single_note_target(amount);
    values.sort_unstable_by_key(|v| spend_order_key(*v, target));
}

/// Plan a payment of `amount` as uniform transactions (W7 + W8).
///
/// - One note covers `amount + F`: spend the smallest such note (one transaction).
/// - Otherwise take the fewest notes, largest first, up to 4 per transaction; a payment that
///   does not fit one transaction becomes up to [`MAX_SIBLINGS`] siblings to the same payee.
///   The last sibling spends the smallest single note that covers what is left, if any.
/// - More than [`MAX_SIBLINGS`] siblings: [`UniformPlanError::NeedsConsolidation`].
pub fn plan_uniform_payment(mut note_values: Vec<u64>, amount: u64) -> Result<UniformPaymentPlan, UniformPlanError> {
    if amount == 0 {
        return Err(UniformPlanError::ZeroAmount);
    }
    sort_for_uniform_spend(&mut note_values, amount);
    let fee = UNIFORM_FEE_V1;
    let mut used = vec![false; note_values.len()];
    let mut siblings: Vec<UniformTx> = Vec::new();
    let mut remaining = amount;
    while remaining > 0 {
        let target = remaining.checked_add(fee).ok_or(UniformPlanError::AmountOverflow)?;
        // The smallest unused note that covers the remainder alone, if any (W7's first rule,
        // applied to every sibling so the last one does not break a large note needlessly).
        let single = (0..note_values.len()).filter(|&i| !used[i] && note_values[i] >= target).min_by_key(|&i| (note_values[i], i));
        let take: Vec<usize> = if let Some(i) = single {
            vec![i]
        } else {
            let mut picked = Vec::with_capacity(MAX_UNIFORM_SPENDS);
            let mut sum = 0u64;
            for i in 0..note_values.len() {
                if used[i] {
                    continue;
                }
                picked.push(i);
                sum = sum.checked_add(note_values[i]).ok_or(UniformPlanError::AmountOverflow)?;
                if picked.len() == MAX_UNIFORM_SPENDS || sum >= target {
                    break;
                }
            }
            picked
        };
        let input = take.iter().try_fold(0u64, |s, &i| s.checked_add(note_values[i])).ok_or(UniformPlanError::AmountOverflow)?;
        if take.is_empty() || input <= fee {
            return Err(UniformPlanError::InsufficientFunds);
        }
        let pay = remaining.min(input - fee);
        for &i in &take {
            used[i] = true;
        }
        siblings.push(UniformTx { notes: take, amount: pay, change: input - fee - pay });
        remaining -= pay;
    }
    if siblings.len() > MAX_SIBLINGS {
        return Err(UniformPlanError::NeedsConsolidation { siblings: siblings.len() });
    }
    let total_fee = fee * siblings.len() as u64;
    Ok(UniformPaymentPlan { sorted_note_values: note_values, requested_amount: amount, siblings, fee_per_tx: fee, total_fee })
}

/// Plan one payout transaction paying up to [`MAX_UNIFORM_PAYEES`] payees at once from at most
/// 4 notes (W10 batching, only for high-volume operators). `values` must already be in the
/// caller's spend order; returns the note indices and the change.
pub fn plan_uniform_batch(values: &[u64], payees_total: u64, n_payees: usize) -> Result<(Vec<usize>, u64), UniformPlanError> {
    if n_payees == 0 || payees_total == 0 {
        return Err(UniformPlanError::ZeroAmount);
    }
    if n_payees > MAX_UNIFORM_PAYEES {
        return Err(UniformPlanError::InsufficientFunds);
    }
    let target = payees_total.checked_add(UNIFORM_FEE_V1).ok_or(UniformPlanError::AmountOverflow)?;
    let mut picked = Vec::new();
    let mut sum = 0u64;
    for (i, v) in values.iter().enumerate().take(MAX_UNIFORM_SPENDS) {
        picked.push(i);
        sum = sum.checked_add(*v).ok_or(UniformPlanError::AmountOverflow)?;
        if sum >= target {
            return Ok((picked, sum - target));
        }
    }
    Err(UniformPlanError::InsufficientFunds)
}

/// The 4 notes a background merge spends (W9): the smallest, adjusted so their sum pays the
/// fee and leaves a positive note. `values` are the wallet's matured spendable notes in any
/// order; returns indices into it. `None` when the wallet is at or under the trigger, or when
/// no 4 notes can pay the fee.
pub fn plan_merge(values: &[u64]) -> Option<Vec<usize>> {
    if values.len() <= MERGE_TRIGGER_NOTES {
        return None;
    }
    let mut order: Vec<usize> = (0..values.len()).collect();
    order.sort_by_key(|&i| (values[i], i));
    let mut pick: Vec<usize> = order[..MERGE_INPUTS].to_vec();
    let sum = |p: &[usize]| p.iter().map(|&i| values[i] as u128).sum::<u128>();
    if sum(&pick) > UNIFORM_FEE_V1 as u128 {
        return Some(pick);
    }
    // Dust: keep the three smallest and swap the fourth for the smallest note that lifts the
    // sum over the fee, so the merge still removes three notes of dust.
    let base = sum(&pick[..MERGE_INPUTS - 1]);
    let fourth = order[MERGE_INPUTS..].iter().copied().find(|&i| base + values[i] as u128 > UNIFORM_FEE_V1 as u128)?;
    pick[MERGE_INPUTS - 1] = fourth;
    Some(pick)
}

/// Urgent consolidation for a payment that needs more than [`MAX_SIBLINGS`] siblings (W8):
/// groups of 4 notes, largest first, enough of them that the merged notes cover the payment.
/// One level; after its outputs mature the payment is re-planned (and may need another level).
pub fn plan_urgent_merges(values: &[u64], amount: u64) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..values.len()).collect();
    order.sort_by_key(|&i| (u64::MAX - values[i], i));
    let mut groups = Vec::new();
    let mut covered: u128 = 0;
    // Each merged note will still pay one uniform fee when spent, and each merge pays one now.
    for chunk in order.chunks(MERGE_INPUTS) {
        if chunk.len() < 2 {
            break;
        }
        let s: u128 = chunk.iter().map(|&i| values[i] as u128).sum();
        if s <= 2 * UNIFORM_FEE_V1 as u128 {
            break;
        }
        groups.push(chunk.to_vec());
        covered += s - 2 * UNIFORM_FEE_V1 as u128;
        if covered >= amount as u128 {
            break;
        }
    }
    groups
}

/// Merges needed to bring `notes` down to the trigger, each removing 3 notes.
pub fn merges_to_trigger(notes: usize) -> usize {
    notes.saturating_sub(MERGE_TRIGGER_NOTES).div_ceil(MERGE_INPUTS - 1)
}

/// The fee the planner charges, checked against the node's relay pricing.
pub fn uniform_fee_clears_relay() -> bool {
    UNIFORM_FEE_V1 >= min_relay_fee_for_actions(UNIFORM_ACTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: u64 = 100_000_000; // 1 ZKAS

    #[test]
    fn constants_are_the_spec_values() {
        assert_eq!(UNIFORM_PAYLOAD_LEN_V1, 15_493, "spec 02 W1: 2,869 + 4 x 3,156");
        assert_eq!(UNIFORM_FEE_V1, 3_117_800, "spec 02 W4 / 15 A6 F_V1");
        assert_eq!(UNIFORM_FEE_V1, crate::payment::chunk_fee(crate::DEFAULT_FEE_SOMPI, 4), "F_V1 is today's chunk_fee(4)");
        assert!(uniform_fee_clears_relay());
        // The node's own minimum for a 4-action tx (spec 02 W4): max(15,587 + 4,000, 62,348 / 2)
        // grams x 100 sompi = 3,117,400, below F.
        let serialized = UNIFORM_PAYLOAD_LEN_V1 as u64 + 94;
        let node_min = ((serialized + 4 * 1_000).max(serialized * 4 / 2)) * 100;
        assert_eq!(node_min, 3_117_400);
        assert!(UNIFORM_FEE_V1 >= node_min);
        assert_eq!(UNIFORM_FLAGS_V1, 0b011 | BUNDLE_FLAG_ANCHOR_BLOCK);
        // 16 uniform transactions fit one block's 1,000,000 transient mass (spec 02 §6.1).
        assert_eq!(1_000_000 / (serialized * 4), 16);
    }

    #[test]
    fn opener_predicate_and_matured_epoch() {
        assert!(is_epoch_opener(120, 119));
        assert!(!is_epoch_opener(121, 120));
        assert!(is_epoch_opener(245, 230), "a chain step that crosses a boundary opens the epoch");
        assert!(is_epoch_opener(480, 230), "a jump over epoch 3 makes 480 the opener of epoch 4");
        assert_eq!(matured_epoch(599), 0);
        assert_eq!(matured_epoch(600 + 240), 2);
        // E-R1 (d)/(e): accepted from bs + D until E(k+2) + D.
        let k = 10u64;
        let b = k * ANCHOR_EPOCH + 3;
        assert!(!opener_accepted_at(b, b + ANCHOR_DEPTH - 1));
        assert!(opener_accepted_at(b, b + ANCHOR_DEPTH));
        assert!(opener_accepted_at(b, (k + 2) * ANCHOR_EPOCH + ANCHOR_DEPTH - 1));
        assert!(!opener_accepted_at(b, (k + 2) * ANCHOR_EPOCH + ANCHOR_DEPTH));
    }

    fn chain(from: u64, to: u64) -> Vec<u64> {
        (from..=to).collect()
    }

    #[test]
    fn picks_the_newest_matured_opener() {
        // One chain block per blue score. Sink 10,000: view 9,970, cutoff 9,370; the newest
        // opener at or below is 9,360 (epoch 78).
        let c = chain(9_000, 9_990);
        let p = pick_epoch_anchor(&c, 10_000);
        assert_eq!(p.opener.map(|o| o.1), Some(9_360));
        assert_eq!(p.wait_blue, None);
        assert_eq!(c[p.ready().unwrap().0], 9_360);
        assert!(opener_accepted_at(9_360, 10_000));
    }

    #[test]
    fn waits_near_a_boundary() {
        // View 9,465 + D = the next opener 9,480 matures at 10,080, 15 blue after view + D.
        let c = chain(9_000, 10_050);
        let p = pick_epoch_anchor(&c, 10_065 + 30);
        assert_eq!(p.opener.map(|o| o.1), Some(9_360));
        assert_eq!(p.wait_blue, Some(15));
        assert_eq!(p.ready(), None);
        // 21 blue before it: no wait.
        let p = pick_epoch_anchor(&c, 10_059 + 30);
        assert_eq!(p.wait_blue, None);
    }

    #[test]
    fn a_ring_head_with_no_parent_is_never_chosen() {
        // The only candidate opener is entry 0, whose parent the wallet never saw.
        let c = vec![9_360, 9_361, 9_362];
        assert_eq!(pick_epoch_anchor(&c, 9_362 + 630).opener, None);
    }

    #[test]
    fn a_jump_over_an_epoch_waits_for_the_next_opener() {
        // Chain jumps from 9,470 straight to 9,610 (epochs 78 -> 80; epoch 79 has no opener).
        let mut c = chain(9_000, 9_470);
        c.extend(chain(9_610, 10_400));
        // At sink 10,230 (view 10,200, cutoff 9,600) the newest matured opener is 9,360 (epoch 78).
        // K(10,230) = 80, so epoch 78 is too old for E-R1 (e): wait until 9,610 matures at view
        // 10,210, i.e. 10 blue.
        let p = pick_epoch_anchor(&c, 10_230);
        assert_eq!(p.opener.map(|o| o.1), Some(9_360));
        assert!(!opener_accepted_at(9_360, 10_230));
        assert_eq!(p.wait_blue, Some(10));
        let p = pick_epoch_anchor(&c, 10_240);
        assert_eq!(p.ready().map(|o| o.1), Some(9_610));
        assert!(opener_accepted_at(9_610, 10_240));
    }

    #[test]
    fn the_rule_scales_with_the_network_depth() {
        assert_eq!(AnchorRule::for_depth(600), AnchorRule::MAINNET);
        // The ZKas devnet is 10 BPS: consensus depth 6,000 blue (600 x BPS).
        let r = AnchorRule::for_depth(6_000);
        assert_eq!(r, AnchorRule { epoch: 1_200, depth: 6_000, slack: 300, near_wait: 200 });
        let c: Vec<u64> = (90_000..=100_000).collect();
        let p = r.pick(&c, 100_000).ready().unwrap();
        // view 99,700, cutoff 93,700: newest opener at or below is 93,600.
        assert_eq!(p.1, 93_600);
        assert!(r.accepted_at(93_600, 100_000) && 100_000 - 93_600 >= 6_000, "old enough for today's consensus depth");
        assert_eq!(r.valid_until(93_600), (78 + 2) * 1_200 + 6_000);
    }

    #[test]
    fn reanchor_when_the_epoch_rolls() {
        let c = chain(9_000, 10_400);
        let built = pick_epoch_anchor(&c, 10_000).ready().unwrap().1;
        assert!(!needs_reanchor(built, &c, 10_000));
        assert!(!needs_reanchor(built, &c, 10_000 + 100), "same epoch still newest");
        assert!(needs_reanchor(built, &c, 10_000 + 120), "the next opener matured");
    }

    #[test]
    fn one_covering_note_is_spent_alone_and_smallest() {
        let plan = plan_uniform_payment(vec![10_000 * Z, 102 * Z, 500 * Z], 100 * Z).unwrap();
        assert_eq!(plan.siblings.len(), 1);
        let s = &plan.siblings[0];
        assert_eq!(s.notes.len(), 1);
        assert_eq!(plan.sorted_note_values[s.notes[0]], 102 * Z);
        assert_eq!(s.amount, 100 * Z);
        assert_eq!(s.change, 2 * Z - UNIFORM_FEE_V1);
        assert_eq!(plan.total_fee, UNIFORM_FEE_V1);
    }

    #[test]
    fn fewest_notes_largest_first_up_to_four() {
        let plan = plan_uniform_payment(vec![3 * Z, 9 * Z, Z, 8 * Z, 2 * Z], 16 * Z).unwrap();
        assert_eq!(plan.siblings.len(), 1);
        let vals: Vec<u64> = plan.siblings[0].notes.iter().map(|&i| plan.sorted_note_values[i]).collect();
        assert_eq!(vals, vec![9 * Z, 8 * Z]);
    }

    #[test]
    fn splits_into_siblings_and_conserves_value() {
        // 20 notes of 31.78 ZKAS (coinbase-sized): 500 ZKAS needs 16 notes = 4 siblings.
        let note = 3_178_389_282u64;
        let plan = plan_uniform_payment(vec![note; 20], 500 * Z).unwrap();
        assert_eq!(plan.siblings.len(), 4);
        assert!(plan.siblings.iter().all(|s| s.notes.len() <= MAX_UNIFORM_SPENDS));
        let paid: u64 = plan.siblings.iter().map(|s| s.amount).sum();
        assert_eq!(paid, 500 * Z);
        for s in &plan.siblings {
            let input: u64 = s.notes.iter().map(|&i| plan.sorted_note_values[i]).sum();
            assert_eq!(input, s.amount + s.change + UNIFORM_FEE_V1, "every sibling balances");
        }
        let mut all: Vec<usize> = plan.siblings.iter().flat_map(|s| s.notes.clone()).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), plan.siblings.iter().map(|s| s.notes.len()).sum::<usize>(), "no note spent twice");
    }

    #[test]
    fn more_than_eight_siblings_needs_consolidation() {
        let note = 3_178_389_282u64;
        // 32 notes x 31.78 - 8 fees = 1,016.8 ZKAS is the 8-sibling ceiling.
        assert!(plan_uniform_payment(vec![note; 40], 1_000 * Z).is_ok());
        assert_eq!(plan_uniform_payment(vec![note; 40], 1_100 * Z), Err(UniformPlanError::NeedsConsolidation { siblings: 9 }));
        assert_eq!(plan_uniform_payment(vec![note; 40], 2_000 * Z), Err(UniformPlanError::InsufficientFunds));
        assert_eq!(plan_uniform_payment(vec![note; 40], 0), Err(UniformPlanError::ZeroAmount));
    }

    #[test]
    fn merge_takes_the_four_smallest_above_the_trigger() {
        assert_eq!(plan_merge(&[5; 8]), None, "at the trigger nothing merges");
        let v = vec![9 * Z, Z, 7 * Z, 2 * Z, 3 * Z, 8 * Z, 4 * Z, 6 * Z, 5 * Z];
        let mut m = plan_merge(&v).unwrap();
        m.sort();
        let mut vals: Vec<u64> = m.iter().map(|&i| v[i]).collect();
        vals.sort();
        assert_eq!(vals, vec![Z, 2 * Z, 3 * Z, 4 * Z]);
        // Dust that cannot pay the fee among the four smallest: the fourth is lifted.
        let mut d = vec![1_000u64; 8];
        d.push(4 * Z);
        let m = plan_merge(&d).unwrap();
        assert!(m.iter().map(|&i| d[i]).sum::<u64>() > UNIFORM_FEE_V1);
        assert_eq!(m.len(), 4);
        assert_eq!(merges_to_trigger(9), 1);
        assert_eq!(merges_to_trigger(418), 137);
    }

    #[test]
    fn urgent_merges_cover_the_payment() {
        let note = 3_178_389_282u64;
        let v = vec![note; 100];
        let g = plan_urgent_merges(&v, 2_000 * Z);
        assert!(g.iter().all(|x| x.len() == 4));
        let covered: u64 = g.iter().map(|x| x.iter().map(|&i| v[i]).sum::<u64>() - 2 * UNIFORM_FEE_V1).sum();
        assert!(covered >= 2_000 * Z);
        // After merging, 16 merged notes pay it in 4 siblings.
        let merged: Vec<u64> = g.iter().map(|x| x.iter().map(|&i| v[i]).sum::<u64>() - UNIFORM_FEE_V1).collect();
        assert!(plan_uniform_payment(merged, 2_000 * Z).unwrap().siblings.len() <= MAX_SIBLINGS);
    }

    #[test]
    fn batch_fits_three_payees() {
        let (notes, change) = plan_uniform_batch(&[10 * Z, 5 * Z], 12 * Z, 3).unwrap();
        assert_eq!(notes, vec![0, 1]);
        assert_eq!(change, 3 * Z - UNIFORM_FEE_V1);
        assert!(plan_uniform_batch(&[10 * Z], Z, 4).is_err());
    }
}
