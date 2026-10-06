use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
    config::params::{ForkActivation, ForkedParam},
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    subnets,
    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
};
use std::convert::TryInto;

use crate::{constants, model::stores::ghostdag::GhostdagData};

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
const LENGTH_OF_SHIELDED_COMMITMENT: usize = 32;
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    + LENGTH_OF_SUBSIDY
    + LENGTH_OF_SHIELDED_COMMITMENT
    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60
const SECONDS_PER_MONTH: u64 = 2629800;

// ZKas monetary policy: the block subsidy follows the shape of Kaspa's `SUBSIDY_BY_MONTH_TABLE`
// but with two ZKas-specific transforms:
//   1. It halves every 3 months instead of every 12. Kaspa's table encodes a smooth decay with
//      `LEGACY_MONTHS_PER_HALVING` (=12) monthly steps per halving; we traverse it
//      `LEGACY_MONTHS_PER_HALVING / SUBSIDY_HALVING_INTERVAL_MONTHS` = 4× faster so a full halving
//      takes 3 months.
//   2. Every table value is scaled by `REWARD_SCALE_NUM / REWARD_SCALE_DEN` (then divided by BPS),
//      setting the initial reward to 60 FC/s per-second-equivalent (44 FC × 3/22 = 6 FC/block at
//      10 BPS): at the live 1 BPS rate this is 60 FC/block; at 10 BPS it would be 6 FC/block.
// Once the curve decays below the tail floor, a two-step tail subsidy is paid forever: the curve
// crosses the tail rate around month 10, so `TAIL_SUBSIDY_INITIAL_PER_SEC_SOMPI` (6 FC/s) is paid up
// to real month `TAIL_STEP_DOWN_MONTH` (=24), after which it steps down to
// `TAIL_SUBSIDY_FINAL_PER_SEC_SOMPI` (0.6 FC/s) and that floor is paid forever. See the tail-constant
// docs below.
const SUBSIDY_HALVING_INTERVAL_MONTHS: u64 = 3;
// The number of monthly table steps that constitute one halving in Kaspa's original table.
const LEGACY_MONTHS_PER_HALVING: u64 = 12;

// ZKas reward scale (see monetary-policy note above): each Kaspa table value is multiplied by
// REWARD_SCALE_NUM/REWARD_SCALE_DEN before the BPS division. 3/22 sets the initial 10-BPS subsidy to
// 6 FC/block (44 FC × 3/22).
const REWARD_SCALE_NUM: u64 = 3;
const REWARD_SCALE_DEN: u64 = 22;

// Convert a raw Kaspa 1-BPS monthly-table value into the ZKas per-block subsidy for `bps`:
// apply the reward scale, then divide by BPS. u128 intermediate avoids overflow.
#[inline]
fn scaled_subsidy(table_value: u64, bps: u64) -> u64 {
    ((table_value.div_ceil(bps) as u128) * REWARD_SCALE_NUM as u128 / REWARD_SCALE_DEN as u128) as u64
}

// Two-step perpetual tail emission (ZKas): once the deflationary curve decays below the tail
// floor, every rewarded block keeps paying a fixed tail subsidy forever, funding long-term miner
// security after the main emission curve is effectively exhausted. The tail steps down once.
//
// The tail is defined as an absolute per-SECOND emission rate and divided by BPS to obtain the
// per-rewarded-block amount (mirroring how `scaled_subsidy` divides the curve by BPS). This makes
// the wall-clock tail invariant to the network's BPS: at 10 BPS the per-block tail is 0.6/0.06 FC,
// at 1 BPS it is 6/0.6 FC — 6 FC/s and 0.6 FC/s either way.
//   * `TAIL_SUBSIDY_INITIAL_PER_SEC_SOMPI` = 6 FC/s, paid until real month `TAIL_STEP_DOWN_MONTH`.
//     The curve crosses this floor around month 10, so it governs the reward ≈month 10..24.
//     6 FC/s ≈ 189M FC/year.
//   * `TAIL_SUBSIDY_FINAL_PER_SEC_SOMPI`   = 0.6 FC/s, paid forever from month `TAIL_STEP_DOWN_MONTH`.
//     0.6 FC/s ≈ 18.9M FC/year (the perpetual long-run inflation floor) — ~2.2% at tail onset
//     (~yr 2), decaying toward ~1% over decades as supply grows.
const TAIL_SUBSIDY_INITIAL_PER_SEC_SOMPI: u64 = 600_000_000;
const TAIL_SUBSIDY_FINAL_PER_SEC_SOMPI: u64 = 60_000_000;
// Real (calendar) month at which the tail steps down from the initial floor to the final floor.
const TAIL_STEP_DOWN_MONTH: u64 = 24;

pub const SUBSIDY_BY_MONTH_TABLE_SIZE: usize = 426;
pub type SubsidyByMonthTable = [u64; SUBSIDY_BY_MONTH_TABLE_SIZE];

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    deflationary_phase_daa_score: u64,
    pre_deflationary_phase_base_subsidy: u64,
    bps_history: ForkedParam<u64>,
    toccata_activation: ForkActivation,

    /// ZKas dev fee: permille (of subsidy) diverted to `dev_fee_recipient`. 0 disables.
    dev_fee_permille: u64,
    /// ZKas dev fee recipient: raw 43-byte Orchard address. None disables the dev fee.
    dev_fee_recipient: Option<[u8; 43]>,
    /// DAA score at which the dev fee stops being minted every block and starts accruing.
    dev_fee_accrual_activation: ForkActivation,
    /// DAA-score interval between dev-fee payouts once accrual is active.
    dev_fee_payout_interval: u64,
    /// DAA-score interval at which the miner accrual slot is paid out (security fork).
    miner_accrual_payout_interval: u64,
    /// DAA score from which miner rewards accrue in one carried slot (the security fork).
    miner_accrual_activation: ForkActivation,

    /// Precomputed subsidy by month tables (for before and after the Crescendo hardfork)
    subsidy_by_month_table_before: SubsidyByMonthTable,
    subsidy_by_month_table_after: SubsidyByMonthTable,

    /// The crescendo activation DAA score where BPS increased from 1 to 10.
    /// This score is required here long-term (and not only for the actual forking), in
    /// order to correctly determine the subsidy month from the live DAA score of the network   
    crescendo_activation_daa_score: u64,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        bps_history: ForkedParam<u64>,
        toccata_activation: ForkActivation,
        dev_fee_permille: u64,
        dev_fee_recipient: Option<[u8; 43]>,
        dev_fee_accrual_activation: ForkActivation,
        dev_fee_payout_interval: u64,
        miner_accrual_activation: ForkActivation,
        miner_accrual_payout_interval: u64,
    ) -> Self {
        // Precomputed subsidy by month table for the actual block per second rate.
        // Values are rounded up per BPS (keeping the same number of rewarding months as the original
        // 1 BPS table) and then scaled by the ZKas reward scale (see `scaled_subsidy`).
        let subsidy_by_month_table_before: SubsidyByMonthTable =
            core::array::from_fn(|i| scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], bps_history.before()));
        let subsidy_by_month_table_after: SubsidyByMonthTable =
            core::array::from_fn(|i| scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], bps_history.after()));
        Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            deflationary_phase_daa_score,
            pre_deflationary_phase_base_subsidy,
            bps_history,
            toccata_activation,
            dev_fee_permille,
            dev_fee_recipient,
            dev_fee_accrual_activation,
            // A zero interval would make every block a payout block (x % 0 panics, and
            // "always pay" is the pre-fork behaviour anyway); clamp so a misconfigured
            // network degrades to the old shape instead of dividing by zero.
            dev_fee_payout_interval: dev_fee_payout_interval.max(1),
            miner_accrual_activation,
            miner_accrual_payout_interval: miner_accrual_payout_interval.max(1),
            subsidy_by_month_table_before,
            subsidy_by_month_table_after,
            crescendo_activation_daa_score: bps_history.activation().daa_score(),
        }
    }

    /// The dev fee skimmed from a single rewarded block's `subsidy` (permille of subsidy,
    /// rounded down). `0` when the dev fee is disabled (`None` recipient or `0` permille).
    #[inline]
    fn dev_fee_cut(&self, subsidy: u64) -> u64 {
        if self.dev_fee_recipient.is_some() && self.dev_fee_permille > 0 {
            ((subsidy as u128 * self.dev_fee_permille as u128) / 1000) as u64
        } else {
            0
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn bps(&self) -> ForkedParam<u64> {
        self.bps_history
    }

    /// Does a block with `daa_score` pay out the accrued dev fee, given its selected
    /// parent's `parent_daa_score`?
    ///
    /// The test is "crossed a multiple of the interval", not "is a multiple of it":
    /// on a DAG the score advances by the number of blocks merged, so it routinely
    /// steps over the boundary rather than landing on it. Comparing interval indices
    /// makes the rule exact for any step size, and it is judged per block against its
    /// own parent, so every node reaches the same answer for the same block.
    #[inline]
    fn is_dev_fee_payout(&self, parent_daa_score: u64, daa_score: u64) -> bool {
        daa_score / self.dev_fee_payout_interval > parent_daa_score / self.dev_fee_payout_interval
    }

    /// Build the expected coinbase for a block.
    ///
    /// `parent_daa_score` / `dev_accrued_parent` describe the block's **selected
    /// parent** and are only consulted once dev-fee accrual has activated; before
    /// that the output is byte-identical to the pre-fork shape regardless of what
    /// they contain.
    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        daa_score: u64,
        miner_data: MinerData<T>,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
        shielded_commitment: [u8; 32],
        parent_daa_score: u64,
        dev_accrued_parent: u64,
        miner_accrual_parent: &MinerAccrual,
    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
        // Rewards in coinbase order: one per rewarded mergeset blue (paying the script that block
        // reported), then the merged reds' total paying this block's own script. Before the
        // security fork each becomes one output; from it they pass through the accrual slot.
        let mut payments: Vec<(u64, ScriptPublicKey)> = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1);

        // ZKas dev fee: skim `dev_fee_permille` of each rewarded block's subsidy (fees are
        // never skimmed) and accumulate it into a single extra output paid to the dev fund
        // (appended last). Value is conserved — the miner reward is reduced by exactly the
        // skimmed amount — so emission accounting is unchanged.
        let mut dev_fee_accum = 0u64;

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            let dev_cut = self.dev_fee_cut(reward_data.subsidy);
            dev_fee_accum += dev_cut;
            let miner_reward = (reward_data.subsidy - dev_cut) + reward_data.total_fees;
            if miner_reward > 0 {
                payments.push((miner_reward, reward_data.script_public_key.clone()));
            }
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block)
        let mut red_reward = 0u64;

        for red in ghostdag_data.mergeset_reds.iter() {
            let reward_data = mergeset_rewards.get(red).unwrap();
            if mergeset_non_daa.contains(red) {
                red_reward += reward_data.total_fees;
            } else {
                let dev_cut = self.dev_fee_cut(reward_data.subsidy);
                dev_fee_accum += dev_cut;
                red_reward += (reward_data.subsidy - dev_cut) + reward_data.total_fees;
            }
        }

        if red_reward > 0 {
            payments.push((red_reward, miner_data.script_public_key.clone()));
        }

        let (mut outputs, miner_accrual) = if self.miner_accrual_activation.is_active(daa_score) {
            let payout = daa_score / self.miner_accrual_payout_interval > parent_daa_score / self.miner_accrual_payout_interval;
            Self::accrue_miner_rewards(miner_accrual_parent, payments, payout)?
        } else {
            (payments.into_iter().map(|(value, spk)| TransactionOutput::new(value, spk)).collect(), MinerAccrual::default())
        };

        // Dev fee. Pre-accrual: every block mints its own cut as a final coinbase output
        // to the dev-fund Orchard recipient (build_coinbase_mint turns it into a coinbase
        // note; ordering is deterministic because it is always the last output).
        //
        // Post-accrual: the cut is added to what the selected parent carried and the whole
        // balance is paid as ONE note on payout blocks only. Value is conserved either way
        // — the same sompi are paid, just batched — but on a non-payout block nothing is
        // minted, so cumulative supply lags by at most one interval of dev fee.
        let accrual_active = self.dev_fee_accrual_activation.is_active(daa_score);
        let dev_accrued_after = if accrual_active { dev_accrued_parent.saturating_add(dev_fee_accum) } else { 0 };
        let (dev_fee_paid, dev_accrued_after) = if !accrual_active {
            (dev_fee_accum, 0)
        } else if self.is_dev_fee_payout(parent_daa_score, daa_score) {
            (dev_accrued_after, 0)
        } else {
            (0, dev_accrued_after)
        };
        if let Some(recipient) = self.dev_fee_recipient {
            if dev_fee_paid > 0 {
                let dev_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient));
                outputs.push(TransactionOutput::new(dev_fee_paid, dev_spk));
            }
        }

        // Build the current block's payload
        let subsidy = self.calc_block_subsidy(daa_score);
        let payload = self.serialize_coinbase_payload(&CoinbaseData {
            blue_score: ghostdag_data.blue_score,
            subsidy,
            shielded_commitment,
            miner_data,
        })?;

        let tx_version =
            if self.toccata_activation.is_active(daa_score) { constants::TX_VERSION_TOCCATA } else { constants::TX_VERSION };

        Ok(CoinbaseTransactionTemplate {
            tx: Transaction::new(tx_version, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
            has_red_reward: red_reward > 0,
            dev_accrued: dev_accrued_after,
            miner_accrual,
        })
    }

    /// The security-fork miner reward rule (see [`MinerAccrual`]). Pure function of the selected
    /// parent's slot, this block's rewards in coinbase order and whether this block crosses a payout
    /// interval, so every node that agrees on the selected chain builds the same coinbase.
    ///
    /// Value is conserved: the outputs plus the new slot equal the parent slot plus the rewards.
    /// Outputs never exceed `payments.len() + 1`: a payment opens a new streak at most once, and the
    /// payout boundary flushes at most one more.
    pub(crate) fn accrue_miner_rewards(
        parent: &MinerAccrual,
        payments: Vec<(u64, ScriptPublicKey)>,
        payout: bool,
    ) -> CoinbaseResult<(Vec<TransactionOutput>, MinerAccrual)> {
        let mut outputs = Vec::with_capacity(payments.len() + 1);
        let mut slot = parent.clone();
        for (value, spk) in payments {
            if !slot.is_empty() && slot.script_public_key == spk {
                slot.amount = slot.amount.checked_add(value).ok_or(CoinbaseError::AccrualOverflow)?;
            } else {
                if !slot.is_empty() {
                    outputs.push(TransactionOutput::new(slot.amount, slot.script_public_key));
                }
                slot = MinerAccrual { script_public_key: spk, amount: value };
            }
        }
        if payout && !slot.is_empty() {
            outputs.push(TransactionOutput::new(slot.amount, slot.script_public_key));
            slot = MinerAccrual::default();
        }
        Ok((outputs, slot))
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.shielded_commitment.iter().copied())                                    // Shielded state root          (32)
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep blue score, subsidy and the shielded commitment (all independent of miner data).
        // Note that truncate does not modify capacity, so the usual case where the payloads are
        // the same size will not trigger a reallocation
        payload.truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_SHIELDED_COMMITMENT);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let shielded_commitment: [u8; 32] = parser.take(LENGTH_OF_SHIELDED_COMMITMENT).try_into().unwrap();
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData { blue_score, subsidy, shielded_commitment, miner_data: MinerData { script_public_key, extra_data } })
    }

    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Perpetual tail: once the deflationary curve decays below the tail floor, every rewarded
        // block keeps paying the (time-dependent) tail subsidy forever (see the const docs).
        self.curve_subsidy(daa_score).max(self.tail_subsidy(daa_score))
    }

    /// The two-step perpetual tail floor for a given DAA score: `TAIL_SUBSIDY_INITIAL_PER_SEC_SOMPI`
    /// (6 FC/s) up to real month `TAIL_STEP_DOWN_MONTH`, then `TAIL_SUBSIDY_FINAL_PER_SEC_SOMPI`
    /// (0.6 FC/s) forever, each divided by BPS to a per-block amount. Assumes
    /// `daa_score >= deflationary_phase_daa_score`.
    fn tail_subsidy(&self, daa_score: u64) -> u64 {
        // `subsidy_month` returns the table index, which advances `LEGACY_MONTHS_PER_HALVING /
        // SUBSIDY_HALVING_INTERVAL_MONTHS` (=4)× faster than real calendar months; convert back.
        let real_month = self.subsidy_month(daa_score) * SUBSIDY_HALVING_INTERVAL_MONTHS / LEGACY_MONTHS_PER_HALVING;
        let per_sec =
            if real_month < TAIL_STEP_DOWN_MONTH { TAIL_SUBSIDY_INITIAL_PER_SEC_SOMPI } else { TAIL_SUBSIDY_FINAL_PER_SEC_SOMPI };
        // Per-rewarded-block tail = per-second rate / BPS. The tail region is always far past
        // Crescendo activation, so the post-activation (current) BPS applies.
        per_sec.div_ceil(self.bps_history.after())
    }

    /// The deflationary-curve subsidy *without* the perpetual tail floor. Decays to 0 once the
    /// 426-entry monthly table is exhausted. Assumes `daa_score >= deflationary_phase_daa_score`.
    fn curve_subsidy(&self, daa_score: u64) -> u64 {
        let subsidy_month = self.subsidy_month(daa_score) as usize;
        let subsidy_table = if self.bps_history.activation().is_active(daa_score) {
            &self.subsidy_by_month_table_after
        } else {
            &self.subsidy_by_month_table_before
        };
        subsidy_table[subsidy_month.min(subsidy_table.len() - 1)]
    }

    /// Get the subsidy month as function of the current DAA score.
    ///
    /// Note that this function is called only if daa_score >= self.deflationary_phase_daa_score
    fn subsidy_month(&self, daa_score: u64) -> u64 {
        let seconds_since_deflationary_phase_started = if self.crescendo_activation_daa_score < self.deflationary_phase_daa_score {
            // crescendo_activation < deflationary_phase <= daa_score (activated before deflation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.after()
        } else if daa_score < self.crescendo_activation_daa_score {
            // deflationary_phase <= daa_score < crescendo_activation (pre activation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
        } else {
            // Else - deflationary_phase <= crescendo_activation <= daa_score.
            // Count seconds differently before and after Crescendo activation
            (self.crescendo_activation_daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
                + (daa_score - self.crescendo_activation_daa_score) / self.bps_history.after()
        };

        // Traverse Kaspa's monthly table `LEGACY_MONTHS_PER_HALVING / SUBSIDY_HALVING_INTERVAL_MONTHS`×
        // faster so the subsidy halves every `SUBSIDY_HALVING_INTERVAL_MONTHS` (=3) months. u128 math
        // avoids overflow for far-future DAA scores; the index is clamped to the table in the caller.
        ((seconds_since_deflationary_phase_started as u128 * LEGACY_MONTHS_PER_HALVING as u128)
            / (SECONDS_PER_MONTH as u128 * SUBSIDY_HALVING_INTERVAL_MONTHS as u128)) as u64
    }

    #[cfg(test)]
    pub fn legacy_calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Note that this calculation implicitly assumes that block per second = 1 (by assuming daa score diff is in second units).
        // Like `subsidy_month`, the monthly table is traversed 4× faster so the subsidy halves every
        // `SUBSIDY_HALVING_INTERVAL_MONTHS` (=3) months instead of the original 12.
        let table_index = ((daa_score - self.deflationary_phase_daa_score) as u128 * LEGACY_MONTHS_PER_HALVING as u128
            / (SECONDS_PER_MONTH as u128 * SUBSIDY_HALVING_INTERVAL_MONTHS as u128)) as u64;
        assert!(table_index <= usize::MAX as u64);
        let table_index: usize = table_index as usize;
        // 1-BPS curve value with the ZKas reward scale applied (no tail floor; used for tests).
        let table_value = if table_index >= SUBSIDY_BY_MONTH_TABLE.len() {
            *SUBSIDY_BY_MONTH_TABLE.last().unwrap()
        } else {
            SUBSIDY_BY_MONTH_TABLE[table_index]
        };
        scaled_subsidy(table_value, 1)
    }
}

/*
    This table was pre-calculated by calling `calcDeflationaryPeriodBlockSubsidyFloatCalc` (in kaspad-go) for all months until reaching 0 subsidy.
    To regenerate this table, run `TestBuildSubsidyTable` in coinbasemanager_test.go (note the `deflationaryPhaseBaseSubsidy` therein).
    These values represent the reward per second for each month (= reward per block for 1 BPS).
*/
#[rustfmt::skip]
const SUBSIDY_BY_MONTH_TABLE: [u64; 426] = [
	44000000000, 41530469757, 39199543598, 36999442271, 34922823143, 32962755691, 31112698372, 29366476791, 27718263097, 26162556530, 24694165062, 23308188075, 22000000000, 20765234878, 19599771799, 18499721135, 17461411571, 16481377845, 15556349186, 14683238395, 13859131548, 13081278265, 12347082531, 11654094037, 11000000000,
	10382617439, 9799885899, 9249860567, 8730705785, 8240688922, 7778174593, 7341619197, 6929565774, 6540639132, 6173541265, 5827047018, 5500000000, 5191308719, 4899942949, 4624930283, 4365352892, 4120344461, 3889087296, 3670809598, 3464782887, 3270319566, 3086770632, 2913523509, 2750000000, 2595654359,
	2449971474, 2312465141, 2182676446, 2060172230, 1944543648, 1835404799, 1732391443, 1635159783, 1543385316, 1456761754, 1375000000, 1297827179, 1224985737, 1156232570, 1091338223, 1030086115, 972271824, 917702399, 866195721, 817579891, 771692658, 728380877, 687500000, 648913589, 612492868,
	578116285, 545669111, 515043057, 486135912, 458851199, 433097860, 408789945, 385846329, 364190438, 343750000, 324456794, 306246434, 289058142, 272834555, 257521528, 243067956, 229425599, 216548930, 204394972, 192923164, 182095219, 171875000, 162228397, 153123217, 144529071,
	136417277, 128760764, 121533978, 114712799, 108274465, 102197486, 96461582, 91047609, 85937500, 81114198, 76561608, 72264535, 68208638, 64380382, 60766989, 57356399, 54137232, 51098743, 48230791, 45523804, 42968750, 40557099, 38280804, 36132267, 34104319,
	32190191, 30383494, 28678199, 27068616, 25549371, 24115395, 22761902, 21484375, 20278549, 19140402, 18066133, 17052159, 16095095, 15191747, 14339099, 13534308, 12774685, 12057697, 11380951, 10742187, 10139274, 9570201, 9033066, 8526079, 8047547,
	7595873, 7169549, 6767154, 6387342, 6028848, 5690475, 5371093, 5069637, 4785100, 4516533, 4263039, 4023773, 3797936, 3584774, 3383577, 3193671, 3014424, 2845237, 2685546, 2534818, 2392550, 2258266, 2131519, 2011886, 1898968,
	1792387, 1691788, 1596835, 1507212, 1422618, 1342773, 1267409, 1196275, 1129133, 1065759, 1005943, 949484, 896193, 845894, 798417, 753606, 711309, 671386, 633704, 598137, 564566, 532879, 502971, 474742, 448096,
	422947, 399208, 376803, 355654, 335693, 316852, 299068, 282283, 266439, 251485, 237371, 224048, 211473, 199604, 188401, 177827, 167846, 158426, 149534, 141141, 133219, 125742, 118685, 112024, 105736,
	99802, 94200, 88913, 83923, 79213, 74767, 70570, 66609, 62871, 59342, 56012, 52868, 49901, 47100, 44456, 41961, 39606, 37383, 35285, 33304, 31435, 29671, 28006, 26434, 24950,
	23550, 22228, 20980, 19803, 18691, 17642, 16652, 15717, 14835, 14003, 13217, 12475, 11775, 11114, 10490, 9901, 9345, 8821, 8326, 7858, 7417, 7001, 6608, 6237, 5887,
	5557, 5245, 4950, 4672, 4410, 4163, 3929, 3708, 3500, 3304, 3118, 2943, 2778, 2622, 2475, 2336, 2205, 2081, 1964, 1854, 1750, 1652, 1559, 1471, 1389,
	1311, 1237, 1168, 1102, 1040, 982, 927, 875, 826, 779, 735, 694, 655, 618, 584, 551, 520, 491, 463, 437, 413, 389, 367, 347, 327,
	309, 292, 275, 260, 245, 231, 218, 206, 194, 183, 173, 163, 154, 146, 137, 130, 122, 115, 109, 103, 97, 91, 86, 81, 77,
	73, 68, 65, 61, 57, 54, 51, 48, 45, 43, 40, 38, 36, 34, 32, 30, 28, 27, 25, 24, 22, 21, 20, 19, 18,
	17, 16, 15, 14, 13, 12, 12, 11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 6, 6, 5, 5, 5, 4, 4, 4,
	4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET_PARAMS;
    use kaspa_consensus_core::{
        config::params::{ForkActivation, Params, SIMNET_PARAMS},
        constants::SOMPI_PER_KASPA,
        network::{NetworkId, NetworkType},
        tx::scriptvec,
    };

    #[test]
    fn calc_high_bps_total_rewards_delta() {
        let legacy_cbm = create_legacy_manager();
        let pre_deflationary_rewards = legacy_cbm.pre_deflationary_phase_base_subsidy * legacy_cbm.deflationary_phase_daa_score;
        let total_rewards: u64 = pre_deflationary_rewards + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| x * SECONDS_PER_MONTH).sum::<u64>();
        let testnet_11_bps = SIMNET_PARAMS.bps();
        // Reference per-block reward for each month = ZKas-scaled, BPS-rounded table value.
        let total_high_bps_rewards_rounded_up: u64 = pre_deflationary_rewards
            + SUBSIDY_BY_MONTH_TABLE
                .iter()
                .map(|x| scaled_subsidy(*x, testnet_11_bps) * testnet_11_bps * SECONDS_PER_MONTH)
                .sum::<u64>();

        let cbm = create_manager(&SIMNET_PARAMS);
        let total_high_bps_rewards: u64 = pre_deflationary_rewards
            + cbm.subsidy_by_month_table_before.iter().map(|x| x * SECONDS_PER_MONTH * cbm.bps().before()).sum::<u64>();
        assert_eq!(
            total_high_bps_rewards_rounded_up, total_high_bps_rewards,
            "scaled subsidy adjusted to bps must match the precomputed table"
        );

        let delta = total_high_bps_rewards as i64 - total_rewards as i64;

        println!("Total rewards: {} sompi => {} KAS", total_rewards, total_rewards / SOMPI_PER_KASPA);
        println!("Total high bps rewards: {} sompi => {} KAS", total_high_bps_rewards, total_high_bps_rewards / SOMPI_PER_KASPA);
        println!("Delta: {} sompi => {} KAS", delta, delta / SOMPI_PER_KASPA as i64);
    }

    #[test]
    fn subsidy_by_month_table_test() {
        let cbm = create_legacy_manager();
        cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
            assert_eq!(
                scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], 1),
                *x,
                "for 1 BPS, scaled const table and precomputed values must match"
            );
        });

        for network_id in NetworkId::iter() {
            let cbm = create_manager(&network_id.into());
            cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], cbm.bps().before()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
            cbm.subsidy_by_month_table_after.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], cbm.bps().after()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
        }
    }

    /// Takes over 60 seconds, run with the following command line:
    /// `cargo test --release --package kaspa-consensus --lib -- processes::coinbase::tests::verify_crescendo_emission_schedule --exact --nocapture --ignored`
    #[test]
    #[ignore = "long"]
    fn verify_crescendo_emission_schedule() {
        // No need to loop over all nets since the relevant params are only
        // deflation and activation DAA scores (and the test is long anyway)
        for network_id in [NetworkId::new(NetworkType::Mainnet)] {
            let mut params: Params = network_id.into();
            params.crescendo_activation = ForkActivation::never();
            let cbm = create_manager(&params);
            let (baseline_epochs, baseline_total) = calculate_emission(cbm);

            let mut activations = vec![10000, 33444444, 120727479];
            for network_id in NetworkId::iter() {
                let activation = Params::from(network_id).crescendo_activation;
                if activation != ForkActivation::never() && activation != ForkActivation::always() {
                    activations.push(activation.daa_score());
                }
            }

            // Loop over a few random activation points + specified activation points for all nets
            for activation in activations {
                params.crescendo_activation = ForkActivation::new(activation);
                let cbm = create_manager(&params);
                let (new_epochs, new_total) = calculate_emission(cbm);

                // Epochs only represents the number of times the subsidy changed (lower after activation due to rounding)
                println!("BASELINE:\t{}\tepochs, total emission: {}", baseline_epochs, baseline_total);
                println!("CRESCENDO:\t{}\tepochs, total emission: {}, activation: {}", new_epochs, new_total, activation);

                let diff = (new_total as i64 - baseline_total as i64) / SOMPI_PER_KASPA as i64;
                assert!(diff.abs() <= 51, "activation: {}", activation);
                println!("DIFF (KAS): {}", diff);
            }
        }
    }

    fn calculate_emission(cbm: CoinbaseManager) -> (u64, u64) {
        let activation = cbm.bps().activation().daa_score();
        let mut current = 0;
        let mut total = 0;
        let mut epoch = 0u64;
        // Use the tail-free curve subsidy for finite-emission accounting: with the perpetual tail
        // floor `calc_block_subsidy` never reaches 0, so this loop would not terminate.
        let mut prev = cbm.curve_subsidy(0);
        loop {
            let subsidy = cbm.curve_subsidy(current);
            // Pre activation we expect the legacy calc (1bps)
            if current < activation {
                assert_eq!(cbm.legacy_calc_block_subsidy(current), subsidy);
            }
            if subsidy == 0 {
                break;
            }
            total += subsidy;
            if subsidy != prev {
                println!("epoch: {}, subsidy: {}", epoch, subsidy);
                prev = subsidy;
                epoch += 1;
            }
            current += 1;
        }

        (epoch, total)
    }

    #[test]
    fn subsidy_test() {
        const PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY: u64 = 50000000000;
        const DEFLATIONARY_PHASE_INITIAL_SUBSIDY: u64 = 44000000000;
        const SECONDS_PER_MONTH: u64 = 2629800;
        // ZKas halves every 3 months (see SUBSIDY_HALVING_INTERVAL_MONTHS).
        const SECONDS_PER_HALVING: u64 = SECONDS_PER_MONTH * 3;

        for network_id in NetworkId::iter() {
            let mut params: Params = network_id.into();
            if params.crescendo_activation != ForkActivation::always() {
                // We test activation scenarios in verify_crescendo_emission_schedule
                params.crescendo_activation = ForkActivation::never();
            }
            let cbm = create_manager(&params);
            let bps = params.bps_history().before();

            let pre_deflationary_phase_base_subsidy = PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY / bps;
            // Initial deflationary subsidy carries the ZKas reward scale (see `scaled_subsidy`).
            let deflationary_phase_initial_subsidy = scaled_subsidy(DEFLATIONARY_PHASE_INITIAL_SUBSIDY, bps);
            let blocks_per_halving = SECONDS_PER_HALVING * bps;

            struct Test {
                name: &'static str,
                daa_score: u64,
                expected: u64,
            }

            let mut tests = vec![
                Test {
                    name: "first mined block",
                    daa_score: 1,
                    expected: if params.deflationary_phase_daa_score > 0 {
                        pre_deflationary_phase_base_subsidy
                    } else {
                        deflationary_phase_initial_subsidy
                    },
                },
                Test {
                    name: "start of deflationary phase",
                    daa_score: params.deflationary_phase_daa_score,
                    expected: deflationary_phase_initial_subsidy,
                },
                Test {
                    name: "after one halving",
                    daa_score: params.deflationary_phase_daa_score + blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 2,
                },
                Test {
                    name: "after 2 halvings",
                    daa_score: params.deflationary_phase_daa_score + 2 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 4,
                },
                Test {
                    name: "after 5 halvings",
                    daa_score: params.deflationary_phase_daa_score + 5 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 32,
                },
                Test {
                    // Far past the tail crossover (32 halvings = month 96): the curve value here is
                    // a tiny fraction of a sompi after scaling, so the perpetual tail floor is what
                    // actually gets paid — here the final 0.3 FC floor (applied via the
                    // `.max(cbm.tail_subsidy(..))` below, which is past `TAIL_STEP_DOWN_MONTH`).
                    name: "after 32 halvings",
                    daa_score: params.deflationary_phase_daa_score + 32 * blocks_per_halving,
                    expected: scaled_subsidy(DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 2_u64.pow(32), bps),
                },
                Test {
                    name: "just before subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 35 * blocks_per_halving,
                    expected: scaled_subsidy(1, bps),
                },
                Test {
                    name: "after subsidy depleted (curve → 0, tail takes over)",
                    daa_score: params.deflationary_phase_daa_score + 36 * blocks_per_halving,
                    expected: 0,
                },
            ];

            if params.deflationary_phase_daa_score > 0 {
                tests.push(Test {
                    name: "before deflationary phase",
                    daa_score: params.deflationary_phase_daa_score - 1,
                    expected: pre_deflationary_phase_base_subsidy,
                });
            }

            for t in tests {
                // The live subsidy is floored at the two-step perpetual tail; once the curve decays
                // below the tail floor (the deep-halving cases, and even "after 5 halvings" where the
                // scaled curve is already under 0.6 FC) the tail is what actually gets paid. The floor
                // itself is time-dependent (0.6 FC before month 24, 0.3 FC after). The tail (like
                // `subsidy_month`) is only defined once the deflationary phase has started; before it,
                // the flat pre-deflationary base subsidy is paid and no tail floor applies.
                let expected_live = if t.daa_score < params.deflationary_phase_daa_score {
                    t.expected
                } else {
                    t.expected.max(cbm.tail_subsidy(t.daa_score))
                };
                assert_eq!(cbm.calc_block_subsidy(t.daa_score), expected_live, "{} test '{}' failed", network_id, t.name);
                if bps == 1 {
                    // legacy_calc_block_subsidy is the tail-free curve, so it matches the raw expectation.
                    assert_eq!(cbm.legacy_calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                }
            }
        }
    }

    #[test]
    fn payload_serialization_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3];
        let data = CoinbaseData {
            blue_score: 56,
            subsidy: 44000000000,
            // A non-trivial commitment so the round-trip actually exercises the 32 bytes.
            shielded_commitment: core::array::from_fn(|i| i as u8 ^ 0xa5),
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data as &[u8],
            },
        };

        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
        // The commitment occupies exactly 32 bytes between subsidy and the script-pub-key version.
        assert_eq!(&payload[LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY..][..32], &data.shielded_commitment);
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data, deserialized_data);
    }

    #[test]
    fn modify_payload_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3, 23, 98];
        let data = CoinbaseData {
            blue_score: 56345,
            subsidy: 44000000000,
            shielded_commitment: [0x5c; 32],
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data,
            },
        };

        let data2 = CoinbaseData {
            blue_score: data.blue_score,
            subsidy: data.subsidy,
            // The commitment is not miner data, so `modify_coinbase_payload` must preserve it.
            shielded_commitment: data.shielded_commitment,
            miner_data: MinerData {
                // Modify only miner data
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
            },
        };

        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data2, deserialized_data);
    }

    #[test]
    fn expected_coinbase_transaction_selects_version_by_toccata_activation() {
        let mut params = MAINNET_PARAMS.clone();
        params.toccata_activation = ForkActivation::new(100);
        let cbm = create_manager(&params);
        let miner_data = MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![4, 5, 6]);
        let ghostdag_data = GhostdagData::default();
        let mergeset_rewards = Default::default();
        let mergeset_non_daa = Default::default();

        let pre_activation = cbm
            .expected_coinbase_transaction(
                99,
                miner_data.clone(),
                &ghostdag_data,
                &mergeset_rewards,
                &mergeset_non_daa,
                [0u8; 32],
                0,
                0,
                &MinerAccrual::default(),
            )
            .unwrap();
        let post_activation = cbm
            .expected_coinbase_transaction(100, miner_data, &ghostdag_data, &mergeset_rewards, &mergeset_non_daa, [0u8; 32], 0, 0, &MinerAccrual::default())
            .unwrap();

        assert_eq!(pre_activation.tx.version, constants::TX_VERSION);
        assert_eq!(post_activation.tx.version, constants::TX_VERSION_TOCCATA);
    }

    #[test]
    fn dev_fee_skims_subsidy_to_dev_recipient() {
        use kaspa_consensus_core::config::params::ZKAS_DEV_FEE_RECIPIENT;
        use kaspa_hashes::Hash;
        use std::sync::Arc;

        // MAINNET_PARAMS carries the 5% dev fee.
        assert_eq!(MAINNET_PARAMS.dev_fee_permille, 50);
        assert_eq!(MAINNET_PARAMS.dev_fee_recipient, Some(ZKAS_DEV_FEE_RECIPIENT));
        let cbm = create_manager(&MAINNET_PARAMS);

        let subsidy = 1_000_000_000u64;
        let fees = 123_456u64;
        let blue = Hash::from_bytes([7u8; 32]);
        let blue_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[9u8, 9, 9]));

        let mut ghostdag_data = GhostdagData::default();
        ghostdag_data.mergeset_blues = Arc::new(vec![blue]);
        ghostdag_data.blue_score = 1;

        let mut mergeset_rewards: BlockHashMap<BlockRewardData> = Default::default();
        mergeset_rewards.insert(blue, BlockRewardData::new(subsidy, fees, blue_script.clone()));
        let non_daa: BlockHashSet = Default::default();

        let miner_data = MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![]);
        let tx =
            cbm.expected_coinbase_transaction(0, miner_data, &ghostdag_data, &mergeset_rewards, &non_daa, [0u8; 32], 0, 0, &MinerAccrual::default()).unwrap().tx;

        // Exactly two outputs: the reduced miner reward, then the dev fee (appended last).
        assert_eq!(tx.outputs.len(), 2, "one miner output + one dev output");
        let dev_cut = subsidy * 50 / 1000; // 5% of subsidy only
        assert_eq!(tx.outputs[0].value, (subsidy - dev_cut) + fees, "miner reward reduced by dev cut; fees untouched");
        assert_eq!(tx.outputs[0].script_public_key, blue_script);
        assert_eq!(tx.outputs[1].value, dev_cut);
        assert_eq!(tx.outputs[1].script_public_key, ScriptPublicKey::new(0, ScriptVec::from_slice(&ZKAS_DEV_FEE_RECIPIENT)));
        // Value is conserved — the split neither mints nor burns.
        assert_eq!(tx.outputs[0].value + tx.outputs[1].value, subsidy + fees);

        // The dev recipient decodes as a canonical Orchard address and mints a valid coinbase note.
        let recipient: [u8; 43] = tx.outputs[1].script_public_key.script()[..43].try_into().unwrap();
        let mut seed = tx.id().as_bytes().to_vec();
        seed.extend_from_slice(&1u32.to_le_bytes());
        let desc = kaspa_shielded_core::coinbase::derive_coinbase_note_desc(recipient, &seed);
        kaspa_shielded_core::coinbase::coinbase_note(&desc, dev_cut).expect("dev recipient must be a canonical Orchard address");

        // With no recipient the manager produces no dev output and pays the full reward to the miner.
        let no_fee = CoinbaseManager::new(
            150,
            204,
            0,
            50_000_000_000,
            ForkedParam::new_const(1),
            ForkActivation::never(),
            50,
            None,
            ForkActivation::never(),
            1_000,
            ForkActivation::never(),
            100,
        );
        let tx2 = no_fee
            .expected_coinbase_transaction(
                0,
                MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![]),
                &ghostdag_data,
                &mergeset_rewards,
                &non_daa,
                [0u8; 32],
                0,
                0,
                &MinerAccrual::default(),
            )
            .unwrap()
            .tx;
        assert_eq!(tx2.outputs.len(), 1, "no dev recipient => no dev output");
        assert_eq!(tx2.outputs[0].value, subsidy + fees, "full reward to miner when dev fee disabled");
    }

    /// Dev-fee accrual: before activation every block mints its own cut; after it the
    /// cut is carried and paid as one note per interval. The property that matters is
    /// conservation — the same sompi reach the dev fund either way, so the change is a
    /// batching change, not an emission change.
    #[test]
    fn dev_fee_accrual_batches_the_same_value_it_used_to_mint_every_block() {
        use kaspa_consensus_core::BlockHashSet;
        use kaspa_consensus_core::config::params::{MAINNET_PARAMS, ZKAS_DEV_FEE_RECIPIENT};
        use kaspa_hashes::Hash;
        use std::sync::Arc;

        const INTERVAL: u64 = 10;
        const ACTIVATION: u64 = 100;
        let mut params = MAINNET_PARAMS.clone();
        params.dev_fee_accrual_activation = ForkActivation::new(ACTIVATION);
        params.dev_fee_payout_interval = INTERVAL;
        let cbm = create_manager(&params);

        let subsidy = 1_000_000_000u64;
        let dev_cut = subsidy * 50 / 1000;
        let blue = Hash::from_bytes([7u8; 32]);
        let blue_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[9u8, 9, 9]));
        let mut ghostdag_data = GhostdagData::default();
        ghostdag_data.mergeset_blues = Arc::new(vec![blue]);
        ghostdag_data.blue_score = 1;
        let mut mergeset_rewards: BlockHashMap<BlockRewardData> = Default::default();
        mergeset_rewards.insert(blue, BlockRewardData::new(subsidy, 0, blue_script.clone()));
        let non_daa: BlockHashSet = Default::default();
        let dev_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&ZKAS_DEV_FEE_RECIPIENT));

        let build = |daa: u64, parent_daa: u64, accrued: u64| {
            cbm.expected_coinbase_transaction(
                daa,
                MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![]),
                &ghostdag_data,
                &mergeset_rewards,
                &non_daa,
                [0u8; 32],
                parent_daa,
                accrued,
                &MinerAccrual::default(),
            )
            .unwrap()
        };

        // Before activation: a dev note in every block, nothing accrues.
        let before = build(ACTIVATION - 1, ACTIVATION - 2, 0);
        assert_eq!(before.tx.outputs.len(), 2, "pre-activation shape is unchanged");
        assert_eq!(before.tx.outputs[1].value, dev_cut);
        assert_eq!(before.dev_accrued, 0, "nothing is carried before activation");

        // After activation, walk a whole interval one block at a time and total up
        // both what was paid out and what remains carried.
        let (mut accrued, mut paid_out, mut payout_blocks) = (0u64, 0u64, 0usize);
        let first = ACTIVATION;
        let last = ACTIVATION + 2 * INTERVAL;
        for daa in first..last {
            let t = build(daa, daa - 1, accrued);
            let dev_outputs: Vec<_> = t.tx.outputs.iter().filter(|o| o.script_public_key == dev_spk).collect();
            if cbm.is_dev_fee_payout(daa - 1, daa) {
                assert_eq!(dev_outputs.len(), 1, "a payout block pays exactly one dev note (daa {daa})");
                paid_out += dev_outputs[0].value;
                payout_blocks += 1;
                assert_eq!(t.dev_accrued, 0, "the balance resets after paying out");
            } else {
                assert!(dev_outputs.is_empty(), "a non-payout block mints no dev note (daa {daa})");
                assert_eq!(t.dev_accrued, accrued + dev_cut, "the cut is carried, not dropped");
            }
            accrued = t.dev_accrued;
        }

        // Conservation: every sompi the old scheme would have minted is either paid or
        // still carried. This is the invariant the whole change rests on.
        let blocks = (last - first) as u64;
        assert_eq!(paid_out + accrued, dev_cut * blocks, "accrual must neither mint nor burn dev fee");
        assert_eq!(payout_blocks, 2, "one payout per interval crossed");
    }

    fn spk(tag: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[tag; 43]))
    }

    fn slot(tag: u8, amount: u64) -> MinerAccrual {
        MinerAccrual { script_public_key: spk(tag), amount }
    }

    fn total(outputs: &[TransactionOutput], slot: &MinerAccrual) -> u64 {
        outputs.iter().map(|o| o.value).sum::<u64>() + slot.amount
    }

    /// A stable payout script mints nothing until the payout block, then exactly one note of the
    /// whole streak. This is the whole point of the rule.
    #[test]
    fn miner_accrual_one_note_per_streak() {
        let mut carried = MinerAccrual::default();
        let mut minted = Vec::new();
        for i in 0..10u64 {
            let payout = i == 9;
            let (out, next) = CoinbaseManager::accrue_miner_rewards(&carried, vec![(100, spk(1))], payout).unwrap();
            minted.extend(out);
            carried = next;
        }
        assert_eq!(minted.len(), 1, "one note for ten blocks of one miner");
        assert_eq!(minted[0].value, 1_000);
        assert_eq!(minted[0].script_public_key, spk(1));
        assert!(carried.is_empty(), "the payout empties the slot");
        assert_eq!(carried, MinerAccrual::default(), "an empty slot has one encoding");
    }

    #[test]
    fn miner_accrual_switch_pays_the_previous_streak() {
        let (out, next) = CoinbaseManager::accrue_miner_rewards(&slot(1, 50), vec![(10, spk(2))], false).unwrap();
        assert_eq!(out, vec![TransactionOutput::new(50, spk(1))]);
        assert_eq!(next, slot(2, 10));
    }

    #[test]
    fn miner_accrual_walks_rewards_in_coinbase_order() {
        let payments = vec![(1, spk(1)), (2, spk(2)), (3, spk(2)), (4, spk(1))];
        let (out, next) = CoinbaseManager::accrue_miner_rewards(&slot(1, 5), payments, false).unwrap();
        assert_eq!(out, vec![TransactionOutput::new(6, spk(1)), TransactionOutput::new(5, spk(2))]);
        assert_eq!(next, slot(1, 4));
    }

    #[test]
    fn miner_accrual_payout_with_no_rewards_still_flushes() {
        let (out, next) = CoinbaseManager::accrue_miner_rewards(&slot(3, 77), Vec::new(), true).unwrap();
        assert_eq!(out, vec![TransactionOutput::new(77, spk(3))]);
        assert!(next.is_empty());
        let (out, next) = CoinbaseManager::accrue_miner_rewards(&MinerAccrual::default(), Vec::new(), true).unwrap();
        assert!(out.is_empty() && next.is_empty(), "nothing carried, nothing paid");
    }

    /// The bound the isolation cap (k + 4) relies on: a block whose every reward is a new script, on
    /// a payout boundary, with a non-empty slot, emits one output per reward plus one.
    #[test]
    fn miner_accrual_worst_case_output_count() {
        let k = MAINNET_PARAMS.ghostdag_k() as u64;
        let payments: Vec<_> = (0..k + 2).map(|i| (10 + i, spk(100 + i as u8))).collect();
        let n = payments.len();
        let (out, next) = CoinbaseManager::accrue_miner_rewards(&slot(1, 9), payments, true).unwrap();
        assert_eq!(out.len(), n + 1);
        assert!(out.len() as u64 + 1 <= k + 4, "with the dev note it still fits the k + 4 cap");
        assert!(next.is_empty());
    }

    #[test]
    fn miner_accrual_overflow_is_an_error_not_a_wrap() {
        let res = CoinbaseManager::accrue_miner_rewards(&slot(1, u64::MAX), vec![(1, spk(1))], false);
        assert!(matches!(res, Err(CoinbaseError::AccrualOverflow)));
    }

    /// Conservation and the output bound over many random streaks and payout boundaries: whatever
    /// the sequence, the chain mints exactly the rewards, and never more than one output per reward
    /// plus one per block.
    #[test]
    fn miner_accrual_conserves_value_over_random_sequences() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next_rand = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200 {
            let mut carried = MinerAccrual::default();
            let (mut rewarded, mut minted) = (0u64, 0u64);
            for _ in 0..300 {
                let n = (next_rand() % 4) as usize;
                let payments: Vec<_> =
                    (0..n).map(|_| (1 + next_rand() % 1_000, spk((next_rand() % 3) as u8))).collect();
                rewarded += payments.iter().map(|p| p.0).sum::<u64>();
                let before = carried.amount;
                let payout = next_rand() % 20 == 0;
                let (out, next) = CoinbaseManager::accrue_miner_rewards(&carried, payments.clone(), payout).unwrap();
                assert!(out.len() <= n + 1);
                assert_eq!(total(&out, &next), before + payments.iter().map(|p| p.0).sum::<u64>(), "per block");
                assert!(out.iter().all(|o| o.value > 0), "never a zero-value note");
                assert_eq!(next.is_empty(), next == MinerAccrual::default(), "one empty encoding");
                minted += out.iter().map(|o| o.value).sum::<u64>();
                carried = next;
            }
            assert_eq!(minted + carried.amount, rewarded, "nothing minted from nothing, nothing lost");
        }
    }

    /// Through the real coinbase builder: before the fork the shape is untouched; from it a miner's
    /// reward is carried, not minted, and the dev note is unaffected.
    #[test]
    fn expected_coinbase_carries_the_miner_reward_from_the_fork() {
        use kaspa_hashes::Hash;
        let mut params = MAINNET_PARAMS.clone();
        params.security_fork_activation = ForkActivation::new(1_000);
        params.miner_accrual_payout_interval = 100;
        let cbm = create_manager(&params);
        let blue = Hash::from_bytes([7u8; 32]);
        let ghostdag_data = GhostdagData { mergeset_blues: std::sync::Arc::new(vec![blue]), ..Default::default() };
        let mut mergeset_rewards = BlockHashMap::default();
        mergeset_rewards.insert(blue, BlockRewardData::new(1_000_000_000, 5, spk(1)));
        let non_daa = Default::default();
        let build = |daa: u64, parent: &MinerAccrual| {
            cbm.expected_coinbase_transaction(
                daa,
                MinerData::new(spk(9), vec![]),
                &ghostdag_data,
                &mergeset_rewards,
                &non_daa,
                [0u8; 32],
                daa - 1,
                0,
                parent,
            )
            .unwrap()
        };
        let pre = build(999, &MinerAccrual::default());
        assert!(pre.tx.outputs.iter().any(|o| o.script_public_key == spk(1)), "pre-fork: the miner is paid in this block");
        assert!(pre.miner_accrual.is_empty());

        let post = build(1_001, &MinerAccrual::default());
        assert!(post.tx.outputs.iter().all(|o| o.script_public_key != spk(1)), "post-fork: nothing minted for the miner yet");
        let miner_reward = 1_000_000_000 - cbm.dev_fee_cut(1_000_000_000) + 5;
        assert_eq!(post.miner_accrual, slot(1, miner_reward));

        let quiet = build(1_150, &post.miner_accrual);
        assert!(quiet.tx.outputs.iter().all(|o| o.script_public_key != spk(1)), "no payout inside the interval");
        assert_eq!(quiet.miner_accrual.amount, 2 * miner_reward);
        assert!(cbm.is_dev_fee_payout(1_100, 2_000), "the dev interval is separate (1,000 here)");

        let payout = build(1_100, &post.miner_accrual);
        let paid: Vec<_> = payout.tx.outputs.iter().filter(|o| o.script_public_key == spk(1)).collect();
        assert_eq!(paid.len(), 1, "the payout block pays the whole slot as one note");
        assert_eq!(paid[0].value, 2 * miner_reward);
        assert!(payout.miner_accrual.is_empty());
    }

    /// The payout test is "crossed an interval boundary", not "landed on one". A DAG
    /// block's DAA score advances by however many blocks it merged, so it routinely
    /// steps over the boundary — and a rule written as `daa % interval == 0` would skip
    /// the payout entirely, silently stranding the fee forever.
    #[test]
    fn dev_fee_payout_triggers_on_crossing_not_on_landing() {
        use kaspa_consensus_core::config::params::MAINNET_PARAMS;
        let mut params = MAINNET_PARAMS.clone();
        params.dev_fee_payout_interval = 10;
        let cbm = create_manager(&params);

        assert!(cbm.is_dev_fee_payout(9, 10), "landing exactly on the boundary pays");
        assert!(cbm.is_dev_fee_payout(8, 13), "stepping over the boundary pays");
        assert!(!cbm.is_dev_fee_payout(11, 13), "a step inside one interval does not");
        assert!(!cbm.is_dev_fee_payout(10, 10), "no advance, no payout");
        assert!(cbm.is_dev_fee_payout(5, 25), "a multi-interval jump still pays once");
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(
            params.coinbase_payload_script_public_key_max_len,
            params.max_coinbase_payload_len,
            params.deflationary_phase_daa_score,
            params.pre_deflationary_phase_base_subsidy,
            params.bps_history(),
            params.toccata_activation,
            params.dev_fee_permille,
            params.dev_fee_recipient,
            params.dev_fee_accrual_activation,
            params.dev_fee_payout_interval,
            params.security_fork_activation,
            params.miner_accrual_payout_interval,
        )
    }

    /// Return a CoinbaseManager with legacy golang 1 BPS properties
    fn create_legacy_manager() -> CoinbaseManager {
        CoinbaseManager::new(
            150,
            204,
            15778800 - 259200,
            50000000000,
            ForkedParam::new_const(1),
            ForkActivation::never(),
            0,
            None,
            ForkActivation::never(),
            1_000,
            ForkActivation::never(),
            100,
        )
    }
}
