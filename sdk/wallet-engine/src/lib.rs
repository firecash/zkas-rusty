//! Transport-independent wallet policy and state machinery for ZKas.
//!
//! This crate is the reusable layer underneath walletd, native applications and
//! future WASM/mobile bindings. It deliberately has no HTTP, node-RPC, UI or
//! runtime dependency. Those are adapters around this engine.
//!
//! [`uniform`], [`schedule`] and [`monitor`] are Stage W of uniform transactions (spec 02):
//! the one transaction shape, when it is released, and the statistics that say whether the
//! network actually looks uniform. Every client calls them; none re-implements them.

pub mod monitor;
pub mod payment;
pub mod schedule;
pub mod uniform;

pub use payment::{
    DEFAULT_FEE_SOMPI, PaymentChunk, PaymentPlan, PlanError, chunk_fee, max_actions_per_tx, max_payees_per_tx, max_spends_per_tx,
    min_relay_fee_for_actions, min_relay_fee_for_spends, plan_payment, select_spend_count, single_note_target,
    sort_for_spend, spend_order_key,
};
pub use schedule::HoldMode;
pub use uniform::{
    EnvelopeViolation, MAX_SIBLINGS, MAX_UNIFORM_PAYEES, MAX_UNIFORM_SPENDS, UNIFORM_ACTIONS, UNIFORM_FEE_V1, UNIFORM_FLAGS_V1,
    UNIFORM_LOCK_TIME, UNIFORM_PAYLOAD_LEN_V1, UniformPaymentPlan, UniformPlanError, UniformTx, check_uniform_effects,
    check_uniform_payload, plan_uniform_payment,
};
