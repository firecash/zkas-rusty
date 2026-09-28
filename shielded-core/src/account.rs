//! The shielded wallet facade — the human-facing wallet a person actually uses
//! (PLAN §2.10, blocker #2). It ties together the primitives built elsewhere in
//! this crate into one end-to-end private-payment loop:
//!
//! - **keys / address**: an Orchard key set derived from a 32-byte seed, exposed
//!   as a `zkas:` receiving [`kaspa_addresses::Address`]
//!   ([`crate::wallet::Version::ShieldedOrchard`]);
//! - **receive**: [`crate::walletdb::WalletDb`] walks the accepted-block
//!   commitment stream, discovers this account's coinbase + received notes, and
//!   keeps a live membership witness for each;
//! - **spend**: [`create_payment`](ShieldedAccount::create_payment) selects a
//!   note, builds a real Orchard payment (recipient + change-to-self) with a Halo 2
//!   proof, and returns the shielded-bundle wire bytes ready to drop into a
//!   version-2 transaction's payload and submit over RPC.
//!
//! The receive/scan/address surface needs no proving circuit (it is decryption +
//! hashing), so a light wallet can track balances without the proving stack; only
//! [`create_payment`](ShieldedAccount::create_payment) (behind the `circuit`
//! feature) does the heavy proving.

use kaspa_addresses::{Address, Prefix, Version};

use crate::bundle::ShieldedBundle;
use crate::coinbase::CoinbaseNoteDesc;
use crate::wallet::scan::address_bytes_from_seed;
use crate::walletdb::WalletDb;

/// Decode the 43-byte raw Orchard address carried by a shielded
/// [`kaspa_addresses::Address`]. Returns `None` for any non-shielded or
/// malformed address — the one gate between the human address format and the
/// Orchard recipient bytes a payment needs.
pub fn orchard_recipient_bytes(address: &Address) -> Option<[u8; 43]> {
    if address.version != Version::ShieldedOrchard {
        return None;
    }
    let payload = address.payload.as_slice();
    if payload.len() != 43 {
        return None;
    }
    let mut out = [0u8; 43];
    out.copy_from_slice(payload);
    Some(out)
}

/// A shielded account: a seed, its receiving address, and a live view of the
/// notes it owns (via [`WalletDb`]).
pub struct ShieldedAccount {
    seed: [u8; 32],
    db: WalletDb,
}

impl ShieldedAccount {
    /// Derive an account from a 32-byte seed. Returns `None` if the seed is not a
    /// valid Orchard spending key (negligibly rare).
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        Some(Self { seed, db: WalletDb::from_seed(seed)? })
    }

    /// This account's human-facing shielded receiving address under `prefix`
    /// (e.g. [`Prefix::Mainnet`] → `zkas:…`). A payer encodes a
    /// shielded output to these bytes; the coinbase reward recipient uses the same
    /// 43-byte payload.
    pub fn receiving_address(&self, prefix: Prefix) -> Address {
        let raw = address_bytes_from_seed(self.seed).expect("seed already validated in from_seed");
        Address::new(prefix, Version::ShieldedOrchard, &raw)
    }

    /// Ingest one accepted chain block's shielded effects (coinbase note
    /// descriptions + accepted shielded bundles, in consensus order) so the
    /// account discovers its own notes and advances its witnesses. Delegates to
    /// [`WalletDb::ingest_block`].
    pub fn ingest_block(&mut self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle]) {
        self.db.ingest_block(coinbase, txs);
    }

    /// Total spendable balance currently tracked (base units).
    pub fn balance(&self) -> u128 {
        self.db.balance()
    }

    /// Read-only access to the tracked notes / underlying wallet db.
    pub fn db(&self) -> &WalletDb {
        &self.db
    }
}

/// Why a payment could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    /// The recipient is not a canonical shielded (`zkas:` / ShieldedOrchard)
    /// address.
    BadRecipient,
    /// No single tracked note holds at least `amount + fee`. (This facade spends a
    /// single note; multi-note joins are a later refinement.)
    InsufficientFunds,
    /// The selected note has no membership witness yet (it has not been ingested
    /// against a finalized tip).
    NoWitness,
    /// `amount + fee` overflows.
    AmountOverflow,
    /// The underlying bundle build/prove failed.
    Build(String),
}

#[cfg(feature = "circuit")]
impl ShieldedAccount {
    /// Build a real, proven shielded **payment**: spend one tracked note worth at
    /// least `amount + fee`, send `amount` to `recipient` (a shielded
    /// `zkas:` address), return the change to this account, and leave `fee`
    /// as the public value balance for the miner. Returns the shielded-bundle wire
    /// bytes to carry in a version-2 transaction's `payload`.
    ///
    /// `network_domain` is the chain's genesis hash and `tx_context` the enclosing
    /// transaction's [`shielded_sighash_context`](../../consensus_core) bytes; both
    /// are bound into the sighash for replay protection (PLAN §2.8/§3). The spent
    /// note is marked spent on success. Heavy: builds a `ProvingKey` and a Halo 2
    /// proof.
    pub fn create_payment(
        &mut self,
        recipient: &Address,
        amount: u64,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
    ) -> Result<Vec<u8>, PaymentError> {
        use crate::wallet::build::{ShieldedKeys, build_payment_bundle};
        use orchard::{Address as OrchardAddress, circuit::ProvingKey};

        let recipient_raw = orchard_recipient_bytes(recipient).ok_or(PaymentError::BadRecipient)?;
        let recipient_addr = Option::<OrchardAddress>::from(OrchardAddress::from_raw_address_bytes(&recipient_raw))
            .ok_or(PaymentError::BadRecipient)?;

        let need = amount.checked_add(fee).ok_or(PaymentError::AmountOverflow)?;

        // Single-note selection: the smallest tracked note that covers amount+fee,
        // to minimize change dust. (Multi-note joins are a later refinement.)
        let selected = self
            .db
            .notes()
            .iter()
            .filter(|n| n.value() >= need)
            .min_by_key(|n| n.value())
            .ok_or(PaymentError::InsufficientFunds)?
            .clone();

        let merkle_path = self.db.witness_path(selected.position).ok_or(PaymentError::NoWitness)?;
        let keys = ShieldedKeys::from_seed(self.seed).ok_or(PaymentError::BadRecipient)?;
        let change_addr = keys.address();

        let pk = ProvingKey::build(crate::verify::CIRCUIT_VERSION);
        let wire = build_payment_bundle(
            &pk,
            &keys,
            selected.note,
            merkle_path,
            recipient_addr,
            amount,
            change_addr,
            fee,
            network_domain,
            tx_context,
            rand::rng(),
        )
        .map_err(|e| PaymentError::Build(format!("{e:?}")))?;

        // The note's spend is now in flight; park it so it is not offered again
        // (txid unknown at build time — the caller submits the wire bytes).
        //
        // Park it against the wallet's own DAA clock, never against 0. `reclaim_expired`
        // skips a spend whose origin is 0 — deliberately, because a wallet with no clock
        // cannot measure an expiry — so parking at 0 here meant that if the caller's
        // submit failed, or the transaction was simply never mined, the note was parked
        // for good: balance gone, nothing to un-park it, and no error to say so.
        let origin = self.db.last_daa();
        self.db.mark_spent(selected.position, [0u8; 32], origin);
        Ok(wire.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiving_address_is_a_shielded_zkas_address() {
        let acct = ShieldedAccount::from_seed([11u8; 32]).unwrap();
        let addr = acct.receiving_address(Prefix::Mainnet);
        assert_eq!(addr.version, Version::ShieldedOrchard);
        assert_eq!(addr.payload.as_slice().len(), 43);
        // Round-trips through the string form under the zkas HRP.
        let s: String = (&addr).into();
        assert!(s.starts_with("zkas:"), "got {s}");
        let decoded: Address = s.try_into().unwrap();
        assert_eq!(decoded, addr);
        // And the recipient bytes decode back to exactly the 43-byte payload.
        assert_eq!(orchard_recipient_bytes(&addr).unwrap(), address_bytes_from_seed([11u8; 32]).unwrap());
    }

    #[test]
    fn recipient_decode_rejects_transparent_address() {
        let transparent = Address::new(Prefix::Mainnet, Version::PubKey, &[0u8; 32]);
        assert_eq!(orchard_recipient_bytes(&transparent), None);
    }

    /// Utility: print a deterministic mainnet mining address for manual node/miner
    /// bring-up. Run with `cargo test -p kaspa-shielded-core --release print_mainnet_mining_address -- --nocapture --ignored`.
    #[test]
    #[ignore = "prints an address for manual bring-up, not an assertion"]
    fn print_mainnet_mining_address() {
        let acct = ShieldedAccount::from_seed([7u8; 32]).unwrap();
        let addr: String = (&acct.receiving_address(Prefix::Mainnet)).into();
        println!("MINING_ADDRESS_SEED07={addr}");
    }
}

/// The complete private-payment loop with live crypto (circuit feature), driven
/// entirely through the wallet facade: Alice mines a shielded coinbase note,
/// discovers it by scanning, pays Bob at his `zkas:` address with a real
/// Halo 2 proof, the consensus verifier + §2.4 transition accept it, and both
/// wallets scan the resulting bundle — Bob receives the amount, Alice keeps the
/// change. This is the end-to-end "a person can send private money" proof.
#[cfg(all(test, feature = "circuit"))]
mod circuit_tests {
    use super::*;
    use crate::coinbase::{coinbase_note_commitment, derive_coinbase_note_desc};
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState, ShieldedTx};
    use crate::verify::{sighash, verify_bundle};

    #[test]
    fn full_private_payment_between_two_wallets() {
        let net = [0x9au8; 32];
        let ctx: &[u8] = b"zkas-payment-context";

        let mut alice = ShieldedAccount::from_seed([1u8; 32]).unwrap();
        let mut bob = ShieldedAccount::from_seed([2u8; 32]).unwrap();
        let bob_addr = bob.receiving_address(Prefix::Mainnet);

        // --- Block 1: the coinbase mints a note to Alice. ---
        let value = 1_000_000u64;
        let alice_raw = address_bytes_from_seed([1u8; 32]).unwrap();
        let desc = derive_coinbase_note_desc(alice_raw, b"blk1||0");
        let cmx = coinbase_note_commitment(&desc, value).unwrap();

        let mut state = ShieldedState::new();
        state.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value, commitment: cmx }])), &[]).unwrap();
        alice.ingest_block(&[(desc, value)], &[]);
        assert_eq!(alice.balance(), value as u128, "Alice discovered her coinbase note by scanning");

        // --- Alice pays Bob (real proof), keeping the change. ---
        let amount = 600_000u64;
        let fee = 10_000u64;
        let payment_bytes = alice.create_payment(&bob_addr, amount, fee, &net, ctx).expect("Alice builds a real payment");

        // The payment is a valid shielded bundle: proof verifies and the fee is public.
        let bundle = ShieldedBundle::from_bytes(&payment_bytes).unwrap();
        let msg = sighash(&bundle, &net, ctx);
        verify_bundle(&bundle, &msg).expect("payment bundle must verify");
        let stx = ShieldedTx::from_bundle(&bundle).unwrap();
        assert_eq!(stx.fee, fee, "public fee == value_balance");

        // --- Block 2: consensus accepts and applies Alice's payment. ---
        let out = state.apply_chain_block(None, &[stx]).unwrap();
        assert_eq!(out.accepted, vec![0], "the payment is accepted by the §2.4 transition");

        // --- Both wallets scan block 2. ---
        bob.ingest_block(&[], &[&bundle]);
        alice.ingest_block(&[], &[&bundle]);

        // Bob received exactly the amount; Alice kept exactly the change.
        assert_eq!(bob.balance(), amount as u128, "Bob receives the private payment");
        assert_eq!(alice.balance(), (value - amount - fee) as u128, "Alice keeps the change, minus the fee");

        // Turnstile sanity: pool = minted coinbase - fee that left the pool.
        assert_eq!(state.supply.pool_value().unwrap(), (value - fee) as u128);
        assert_eq!(bob.balance() + alice.balance(), (value - fee) as u128, "shielded value conserved (Bob + Alice change = pool)");
    }
}
