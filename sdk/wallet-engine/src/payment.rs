//! Deterministic shielded-payment planning shared by all wallet front ends.

use kaspa_shielded_core::bundle::expected_wire_len;
use serde::{Deserialize, Serialize};

/// Per-dimension mass ceiling a shielded transaction must fit under to be relayed
/// and mined. This mirrors the node's shielded standardness cap
/// (`check_transaction_standard.rs`): shielded transactions are exempt from the
/// 100 KB pre-Toccata standard cap and bounded only by the block mass limit, so a
/// single payment can spend up to ~38 notes instead of 6. MUST stay equal to the
/// node's block mass limit — if that param changes, this must follow, or the wallet
/// plans transactions the node rejects (too high) or under-packs them (too low).
pub const STANDARD_TX_MASS_CAP: u64 = 500_000;
/// Transient mass charged per serialized byte.
pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;
/// Conservative transaction envelope allowance for the standard-mass limit.
pub const TX_ENVELOPE_MARGIN: usize = 256;
/// Default node relay fee in sompi per kilogram of mass.
pub const RELAY_FEE_PER_KG: u64 = 100_000;
/// Conservative transaction envelope allowance when estimating relay fees.
pub const TX_ENVELOPE_BYTES_FEE: u64 = 128;
/// Wallet fee floor for a shielded payment.
pub const DEFAULT_FEE_SOMPI: u64 = 3_000_000;

/// One transaction in a logical payment that may span multiple transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentChunk {
    /// Indices into [`PaymentPlan::sorted_note_values`].
    pub note_range: core::ops::Range<usize>,
    /// Amount paid to the requested recipient by this transaction.
    pub amount: u64,
    /// Public fee paid by this transaction.
    pub fee: u64,
}

/// Complete deterministic plan for a shielded payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPlan {
    /// Candidate note values in the value-descending order used for selection.
    pub sorted_note_values: Vec<u64>,
    pub requested_amount: u64,
    pub chunks: Vec<PaymentChunk>,
    pub total_fee: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    ZeroAmount,
    NoSpendCapacity,
    InsufficientFunds,
    AmountOverflow,
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroAmount => f.write_str("payment amount must be positive"),
            Self::NoSpendCapacity => f.write_str("maximum spends per transaction must be positive"),
            Self::InsufficientFunds => f.write_str("insufficient funds after transaction fees"),
            Self::AmountOverflow => f.write_str("payment values overflow the supported amount range"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Largest number of note spends whose bundle fits the standard transient-mass
/// budget. This evaluates to six with the current wire format and node policy.
pub fn max_spends_per_tx() -> usize {
    let budget = (STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR) as usize - TX_ENVELOPE_MARGIN;
    let mut n = 1usize;
    while expected_wire_len((n + 1).max(2)) <= budget {
        n += 1;
    }
    n
}

/// Largest number of Orchard **actions** whose bundle fits the standard transient-mass
/// budget. A bundle carries `max(spends, outputs)` actions, so this is the one ceiling
/// both a many-spend payment and a many-payee batch are planned against. Kept separate
/// from [`max_spends_per_tx`], whose (deliberately conservative) `n + 1` accounting is
/// load-bearing for every existing caller and must not shift.
pub fn max_actions_per_tx() -> usize {
    let budget = (STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR) as usize - TX_ENVELOPE_MARGIN;
    let mut a = 2usize;
    while expected_wire_len(a + 1) <= budget {
        a += 1;
    }
    a
}

/// Largest number of recipients one batched payment can pay: the bundle needs one
/// output per payee plus one for change, and actions are `max(spends, outputs)`.
pub fn max_payees_per_tx() -> usize {
    max_actions_per_tx().saturating_sub(1).max(1)
}

/// Minimum fee expected to clear the node relay policy for a bundle of `n_actions`.
pub fn min_relay_fee_for_actions(n_actions: usize) -> u64 {
    let bytes = expected_wire_len(n_actions.max(2)) as u64 + TX_ENVELOPE_BYTES_FEE;
    bytes * TRANSIENT_BYTE_TO_MASS_FACTOR / 2 * RELAY_FEE_PER_KG / 1000
}

/// Minimum fee expected to clear the node relay policy for `n_spends` notes.
pub fn min_relay_fee_for_spends(n_spends: usize) -> u64 {
    let bytes = expected_wire_len(n_spends.max(2)) as u64 + TX_ENVELOPE_BYTES_FEE;
    bytes * TRANSIENT_BYTE_TO_MASS_FACTOR / 2 * RELAY_FEE_PER_KG / 1000
}

/// Effective fee for a transaction: caller policy floor or relay minimum.
pub fn chunk_fee(base_fee: u64, n_spends: usize) -> u64 {
    base_fee.max(min_relay_fee_for_spends(n_spends))
}

/// The smallest a single note must be to pay `amount` on its own, fee included.
pub fn single_note_target(amount: u64, base_fee: u64) -> u64 {
    amount.saturating_add(chunk_fee(base_fee, 1))
}

/// The order notes are spent in, as a sort key (ascending).
///
/// A note that can pay the whole amount BY ITSELF comes first, smallest such note
/// first; everything else follows largest-first.
///
/// The second half is the old rule, and on its own it is why a 100 ZKAS payment
/// from a wallet holding 10 000 and 102 broke the 10 000: ordering was purely
/// value-descending, and selection takes a prefix of that order. Spending the
/// smallest note that covers the payment leaves the large note whole and keeps
/// the change small.
///
/// Largest-first still governs everything else, deliberately: when no single note
/// covers the payment, taking the largest reaches the amount in the FEWEST notes,
/// and the note count sets both the fee (priced per action) and whether the
/// payment fits one transaction at all.
pub fn spend_order_key(value: u64, single_target: u64) -> (u8, u64) {
    if value >= single_target { (0, value) } else { (1, u64::MAX - value) }
}

/// Put candidate notes in spend order. Callers holding the notes themselves must
/// order with [`spend_order_key`] and the same target, or the note they witness
/// will not be the note that was planned.
pub fn sort_for_spend(values: &mut [u64], amount: u64, base_fee: u64) {
    let target = single_note_target(amount, base_fee);
    values.sort_unstable_by_key(|v| spend_order_key(*v, target));
}

/// Find the number of notes needed for a single transaction, taking them in the
/// order given (see [`spend_order_key`]). The note count and byte-priced fee are
/// solved to a fixed point.
pub fn select_spend_count(values: &[u64], amount: u64, base_fee: u64, max_per_tx: usize) -> Result<(usize, u64), PlanError> {
    if amount == 0 {
        return Err(PlanError::ZeroAmount);
    }
    if max_per_tx == 0 {
        return Err(PlanError::NoSpendCapacity);
    }

    let mut fee = chunk_fee(base_fee, 1);
    loop {
        let target = amount.checked_add(fee).ok_or(PlanError::AmountOverflow)?;
        let mut sum = 0u64;
        let mut n = 0usize;
        while n < max_per_tx && n < values.len() && sum < target {
            sum = sum.checked_add(values[n]).ok_or(PlanError::AmountOverflow)?;
            n += 1;
        }
        let required_fee = chunk_fee(base_fee, n.max(1));
        if required_fee <= fee {
            return Ok((n, fee));
        }
        fee = required_fee;
    }
}

/// Plan a logical payment across standard-sized shielded transactions.
/// Candidate notes are sorted internally, so every SDK binding makes the same
/// selection regardless of storage iteration order.
pub fn plan_payment(mut note_values: Vec<u64>, amount: u64, base_fee: u64, max_per_tx: usize) -> Result<PaymentPlan, PlanError> {
    if amount == 0 {
        return Err(PlanError::ZeroAmount);
    }
    if max_per_tx == 0 {
        return Err(PlanError::NoSpendCapacity);
    }
    sort_for_spend(&mut note_values, amount, base_fee);

    let mut chunks = Vec::new();
    let mut remaining = amount;
    let mut cursor = 0usize;
    let mut total_fee = 0u64;
    while remaining > 0 {
        let (count, fee) = select_spend_count(&note_values[cursor..], remaining, base_fee, max_per_tx)?;
        if count == 0 {
            return Err(PlanError::InsufficientFunds);
        }
        let end = cursor.checked_add(count).ok_or(PlanError::AmountOverflow)?;
        let input =
            note_values[cursor..end].iter().try_fold(0u64, |sum, value| sum.checked_add(*value)).ok_or(PlanError::AmountOverflow)?;
        let available = input.checked_sub(fee).ok_or(PlanError::InsufficientFunds)?;
        if available == 0 {
            return Err(PlanError::InsufficientFunds);
        }
        let chunk_amount = remaining.min(available);
        chunks.push(PaymentChunk { note_range: cursor..end, amount: chunk_amount, fee });
        remaining -= chunk_amount;
        total_fee = total_fee.checked_add(fee).ok_or(PlanError::AmountOverflow)?;
        cursor = end;
    }

    Ok(PaymentPlan { sorted_note_values: note_values, requested_amount: amount, chunks, total_fee })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_limit_allows_thirty_eight_spends() {
        // With the shielded cap raised to the block mass limit (500 KB), a single
        // payment spends up to 38 notes instead of 6 — a 6x lift in value-per-tx that
        // stops ordinary payments from shattering into many sequential-proof chunks.
        assert_eq!(max_spends_per_tx(), 38);
        // Sanity: a 38-spend bundle's transient mass stays within the 500 KB block
        // limit (the physical ceiling), so the wallet never plans an unmineable tx.
        let transient = (expected_wire_len(38) as u64 + 94) * TRANSIENT_BYTE_TO_MASS_FACTOR;
        assert!(transient <= STANDARD_TX_MASS_CAP, "38-spend transient {transient} exceeds cap {STANDARD_TX_MASS_CAP}");
    }

    #[test]
    fn dynamic_fee_clears_observed_six_spend_requirement() {
        let observed = (expected_wire_len(6) as u64 + 94) * TRANSIENT_BYTE_TO_MASS_FACTOR / 2 * RELAY_FEE_PER_KG / 1000;
        assert_eq!(observed, 4_373_400);
        assert!(min_relay_fee_for_spends(6) >= observed);
        assert_eq!(chunk_fee(DEFAULT_FEE_SOMPI, 1), DEFAULT_FEE_SOMPI);
        assert!(min_relay_fee_for_spends(4) > DEFAULT_FEE_SOMPI);
    }

    #[test]
    fn spends_the_smallest_note_that_covers_the_payment() {
        // The reported behaviour: a wallet holding 10 000 and 102 paid 100 by
        // breaking the 10 000 note, because the order was purely value-descending
        // and selection takes a prefix of it.
        let fee = DEFAULT_FEE_SOMPI;
        let plan = plan_payment(vec![10_000_000_000_000, 10_200_000_000], 10_000_000_000, fee, 38).unwrap();
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0].note_range, 0..1);
        // The note actually spent is the small one, not the large one.
        assert_eq!(plan.sorted_note_values[0], 10_200_000_000);
    }

    #[test]
    fn picks_the_tightest_fit_among_several_that_would_do() {
        let fee = DEFAULT_FEE_SOMPI;
        let notes = vec![500_000_000_000, 11_000_000_000, 90_000_000_000, 10_500_000_000];
        let plan = plan_payment(notes, 10_000_000_000, fee, 38).unwrap();
        assert_eq!(plan.chunks[0].note_range, 0..1);
        assert_eq!(plan.sorted_note_values[0], 10_500_000_000);
    }

    #[test]
    fn a_note_that_covers_the_amount_but_not_the_fee_is_not_treated_as_enough() {
        // Exactly the amount with nothing left for the fee is NOT a single-note
        // payment: the target is amount + fee, and ignoring that would plan a
        // transaction that cannot pay to be mined.
        let fee = DEFAULT_FEE_SOMPI;
        let amount = 10_000_000_000;
        let plan = plan_payment(vec![amount, 40_000_000_000], amount, fee, 38).unwrap();
        let spent: u64 = plan.sorted_note_values[plan.chunks[0].note_range.clone()].iter().sum();
        assert!(spent >= amount + plan.chunks[0].fee, "planned {spent} for amount {amount} + fee");
        assert_eq!(plan.sorted_note_values[0], 40_000_000_000);
    }

    #[test]
    fn falls_back_to_largest_first_when_no_single_note_covers() {
        // Unchanged from the old rule, and deliberately: the fewest notes means
        // the smallest fee and the best chance of fitting one transaction.
        let fee = DEFAULT_FEE_SOMPI;
        let notes = vec![3_000_000_000, 9_000_000_000, 1_000_000_000, 8_000_000_000];
        let plan = plan_payment(notes, 16_000_000_000, fee, 38).unwrap();
        assert_eq!(plan.sorted_note_values, vec![9_000_000_000, 8_000_000_000, 3_000_000_000, 1_000_000_000]);
        assert_eq!(plan.chunks[0].note_range, 0..2);
    }

    #[test]
    fn the_order_is_total_and_agrees_with_itself() {
        // walletd sorts the NOTES with this key while the engine sorts their
        // VALUES; if the two disagreed, the note witnessed would not be the note
        // planned. Same key, same target, same order.
        let target = single_note_target(10_000_000_000, DEFAULT_FEE_SOMPI);
        let mut values = vec![1, 10_200_000_000, 10_000_000_000_000, 7, 10_000_000_000];
        let mut by_key = values.clone();
        by_key.sort_unstable_by_key(|v| spend_order_key(*v, target));
        sort_for_spend(&mut values, 10_000_000_000, DEFAULT_FEE_SOMPI);
        assert_eq!(values, by_key);
        // Covers-alone notes first (ascending), then the rest descending.
        assert_eq!(values, vec![10_200_000_000, 10_000_000_000_000, 10_000_000_000, 7, 1]);
    }

    #[test]
    fn plan_is_deterministic_and_prices_each_chunk() {
        let plan = plan_payment(vec![6_000_000_000; 6], 29_000_000_000, DEFAULT_FEE_SOMPI, 6).unwrap();
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0].note_range, 0..5);
        assert_eq!(plan.chunks[0].amount, 29_000_000_000);
        assert_eq!(plan.chunks[0].fee, chunk_fee(DEFAULT_FEE_SOMPI, 5));
    }

    #[test]
    fn rejects_overflow_instead_of_saturating() {
        assert_eq!(plan_payment(vec![u64::MAX], u64::MAX, 1, 6), Err(PlanError::AmountOverflow));
    }

    #[test]
    fn rejects_zero_and_insufficient_payments() {
        assert_eq!(plan_payment(vec![10], 0, 1, 6), Err(PlanError::ZeroAmount));
        assert_eq!(plan_payment(vec![10], 10, 1, 6), Err(PlanError::InsufficientFunds));
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    /// The spend cap is consensus-adjacent planning: a wallet that plans more spends
    /// than the node will relay simply cannot send. Pin it, and pin that adding the
    /// batch-payee accounting did not move it.
    #[test]
    fn spend_cap_is_unchanged_by_action_accounting() {
        assert_eq!(max_spends_per_tx(), 38, "spend cap must stay 38");
        assert!(max_actions_per_tx() >= max_spends_per_tx(), "actions bound spends");
        assert!(max_payees_per_tx() >= 2, "batching must be able to pay more than one payee");
        // A bundle of the advertised size must actually fit the mass budget.
        let budget = (STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR) as usize - TX_ENVELOPE_MARGIN;
        assert!(expected_wire_len(max_actions_per_tx()) <= budget, "advertised action count must fit");
        assert!(expected_wire_len(max_payees_per_tx() + 1) <= budget, "payees + change must fit");
    }
}
