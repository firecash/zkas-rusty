use crate::tx::{ScriptPublicKey, Transaction};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct MinerData<T: AsRef<[u8]> = Vec<u8>> {
    pub script_public_key: ScriptPublicKey,
    pub extra_data: T,
}

impl<T: AsRef<[u8]>> MinerData<T> {
    pub fn new(script_public_key: ScriptPublicKey, extra_data: T) -> Self {
        Self { script_public_key, extra_data }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct CoinbaseData<T: AsRef<[u8]> = Vec<u8>> {
    pub blue_score: u64,
    pub subsidy: u64,
    /// The shielded state root (PLAN §2.10) as of this block's selected parent —
    /// the note-commitment tree root, the nullifier-set accumulator, and the
    /// turnstile totals bound into 32 bytes. Because the coinbase is committed by
    /// the header's `hash_merkle_root` (and thus by proof-of-work), this forms a
    /// PoW-anchored chain of shielded state roots that a fast/pruned node can
    /// verify a checkpoint against without replaying from genesis.
    pub shielded_commitment: [u8; 32],
    pub miner_data: MinerData<T>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockRewardData {
    pub subsidy: u64,
    pub total_fees: u64,
    pub script_public_key: ScriptPublicKey,
}

impl BlockRewardData {
    pub fn new(subsidy: u64, total_fees: u64, script_public_key: ScriptPublicKey) -> Self {
        Self { subsidy, total_fees, script_public_key }
    }
}

/// Security fork: the miner reward a chain block carries forward instead of minting.
///
/// One slot, not a table. Walking a block's rewards in coinbase order, a reward to the slot's
/// script is added to it; a reward to any other script first pays the slot out as one note and
/// then becomes the slot. At every payout interval the slot is paid out and emptied. A stable
/// payout script therefore appends one reward note per interval instead of one per block, while
/// every amount and script stays exactly as public as it is in today's per-block coinbase.
///
/// `amount == 0` means the slot is empty, and the script is then always the default (empty) one,
/// so equal states have one encoding (it is committed in `zkas_state_root1`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerAccrual {
    pub script_public_key: ScriptPublicKey,
    pub amount: u64,
}

impl MinerAccrual {
    pub fn is_empty(&self) -> bool {
        self.amount == 0
    }
}

/// Holds a coinbase transaction along with meta-data obtained during creation
pub struct CoinbaseTransactionTemplate {
    pub tx: Transaction,
    pub has_red_reward: bool, // Does the last output contain reward for red blocks
    /// Dev fee carried forward by this block: what its selected parent had accrued
    /// plus this block's cut, minus anything paid out here. `0` before dev-fee
    /// accrual activates (the fee is minted every block) and `0` on a payout block
    /// (the balance just went out as a note).
    pub dev_accrued: u64,
    /// Miner reward carried forward by this block (security fork; empty before it and on a payout
    /// block). See [`MinerAccrual`].
    pub miner_accrual: MinerAccrual,
}
