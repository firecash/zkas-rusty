//! ZKas shielded pool core.
//!
//! Wraps Zcash Orchard primitives (Halo 2, Pasta curves) to provide the
//! consensus-side shielded state described in `PLAN.md`:
//!
//! - the three-tier note-commitment tree (bundle -> chain-block -> global),
//!   whose global root is the **anchor** ([`tree`]);
//! - the nullifier set and its first-in-accepted-order conflict resolution
//!   (added in a later task);
//! - the turnstile supply invariant (added in a later task).
//!
//! The membership / tree logic sits behind the [`tree::NoteCommitmentTree`]
//! trait so the argument can later be swapped to FCMP++ / Curve Trees without
//! disturbing the consensus integration (PLAN §1, "Future direction").
//!
//! Crypto is **not** hand-rolled here: we reuse `orchard` and
//! `incrementalmerkletree` and will pin them to audited commits before launch
//! (PLAN §5, non-negotiable #4).

pub mod account;
pub mod attestation;
pub mod bundle;
pub mod burn;
pub mod coinbase;
pub mod commitment;
pub mod message;
pub mod nullifier;
pub mod payment_check;
pub mod payproof;
pub mod state;
pub mod tree;
pub mod turnstile;
pub mod verify;
pub mod wallet;
pub mod walletdb;
pub mod witness_chain;

// The human-facing wallet facade (keys -> zkas: address -> scan -> pay).
pub use account::{PaymentError, ShieldedAccount, orchard_recipient_bytes};

// Re-export the Orchard primitives the consensus layer builds on, so there is a
// single canonical source for these types across the workspace.
pub use orchard::{
    Action, Bundle, NOTE_COMMITMENT_TREE_DEPTH,
    note::{ExtractedNoteCommitment, Note, Nullifier},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitment, ValueSum},
};
