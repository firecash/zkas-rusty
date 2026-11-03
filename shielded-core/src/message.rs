//! Message signing — prove control of a shielded address without spending.
//!
//! A shielded (Orchard) address is `(diversifier, pk_d)`; it carries **no**
//! signature-verification key, so a signature cannot be checked against the
//! address bytes alone. This module therefore uses the wallet's spend authority:
//!
//! - **sign** derives the spend authorizing key `ask` from the seed and produces a
//!   RedPallas `SpendAuth` signature over `H(network ‖ address ‖ message)`. The
//!   signer publishes its [`FullViewingKey`] alongside the signature.
//! - **verify** re-derives the address from that published FVK — this is what
//!   *binds* the key to the claimed address — and then checks the signature under
//!   the FVK's spend-validating key `ak`.
//!
//! The binding step is the security core: an attacker cannot claim someone else's
//! address, because producing an FVK that derives to a target address requires that
//! target's FVK (which the attacker does not have), and signing under it requires
//! the corresponding `ask`.
//!
//! ## Disclosure
//!
//! Because the address has no standalone verifying key, THIS scheme (a plain RedPallas
//! signature checked against a key derived from the disclosed FVK) has to reveal the FVK
//! (96 bytes). That is a limit of this construction, not of Orchard: an off-chain
//! "statement bundle" (the ZIP-304 technique: a domain-tagged bundle that spends a note
//! of the address and can never be a valid transaction) proves the same ownership with
//! the existing circuit and reveals no viewing key. It is not built yet. The FVK grants
//! **incoming/outgoing viewing** capability (someone holding it can detect this
//! wallet's notes) but **not** spend authority. This disclosure happens only when
//! the holder chooses to sign — it is opt-in, and no funds can move. Callers must
//! surface this to the user.
//!
//! This is pure signing: no proving circuit, so it is available without the
//! `circuit` feature (unlike [`crate::wallet::build`]).

use blake2b_simd::Params;
use group::ff::Field;
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    primitives::redpallas::{Signature, SpendAuth, VerificationKey},
};
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};

/// BLAKE2b personalization for the message-signing digest. The trailing `1` is a
/// scheme version, so a future change gets a distinct domain.
const MSG_PERSONAL: &[u8; 16] = b"zkas_msg_sig_v01";

/// Raw Orchard address length (11-byte diversifier + 32-byte `pk_d`).
pub const ADDRESS_LEN: usize = 43;
/// Serialized [`FullViewingKey`] length (`ak ‖ nk ‖ rivk`).
pub const FVK_LEN: usize = 96;
/// RedPallas signature length.
pub const SIG_LEN: usize = 64;

/// A signed message: the raw address it asserts ownership of, the full viewing key
/// that binds the signature to that address, and the signature itself.
pub struct SignedMessage {
    /// Raw 43-byte Orchard address the signature asserts ownership of.
    pub address: [u8; ADDRESS_LEN],
    /// The signer's full viewing key — binds the signature to `address` and carries
    /// the `ak` that verifies it. Publishing it discloses viewing capability.
    pub fvk: [u8; FVK_LEN],
    /// RedPallas `SpendAuth` signature over the message digest.
    pub sig: [u8; SIG_LEN],
}

/// The digest that is actually signed: binds the network, the exact address, and
/// the message, with unambiguous length-prefixing so no two `(network, address,
/// message)` triples collide.
fn message_digest(network_tag: &[u8], address: &[u8; ADDRESS_LEN], message: &[u8]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(MSG_PERSONAL).to_state();
    h.update(&(network_tag.len() as u64).to_le_bytes());
    h.update(network_tag);
    h.update(address); // fixed 43 bytes
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Sign `message` with the wallet identified by `seed`, asserting ownership of the
/// wallet's default external address, scoped to `network_tag`. Returns `None` only
/// if `seed` is not a valid Orchard spending key (negligibly rare).
pub fn sign_message(seed: [u8; 32], network_tag: &[u8], message: &[u8], mut rng: impl RngCore + CryptoRng) -> Option<SignedMessage> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();

    // `randomize` by the zero scalar yields the (unrandomized) SpendAuth signing key
    // exactly equal to `ask`; its verification key is the FVK's `ak`.
    let signing_key = SpendAuthorizingKey::from(&sk).randomize(&pallas::Scalar::ZERO);
    let digest = message_digest(network_tag, &address, message);
    let sig = signing_key.sign(&mut rng, &digest);

    Some(SignedMessage { address, fvk: fvk.to_bytes(), sig: <[u8; SIG_LEN]>::from(&sig) })
}

/// Reason a signature failed to verify.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The presented FVK bytes are not a valid full viewing key.
    BadFvk,
    /// The FVK does not derive to the claimed address (key/address mismatch).
    AddressMismatch,
    /// The FVK's `ak` is not a valid verification key.
    BadKey,
    /// The signature is not valid over the digest under the FVK's `ak`.
    BadSignature,
}

/// Verify that `sig` proves the holder of the address `address` signed `message`
/// under `network_tag`, given the signer's published `fvk`.
///
/// Soundness rests on the address-binding check: the `fvk` must derive to exactly
/// `address`, and the signature must verify under that same `fvk`'s `ak`.
pub fn verify_message(
    address: &[u8; ADDRESS_LEN],
    network_tag: &[u8],
    message: &[u8],
    fvk: &[u8; FVK_LEN],
    sig: &[u8; SIG_LEN],
) -> Result<(), VerifyError> {
    let full = FullViewingKey::from_bytes(fvk).ok_or(VerifyError::BadFvk)?;

    // Bind key -> address: the published FVK must produce the claimed address.
    if full.address_at(0u32, Scope::External).to_raw_address_bytes() != *address {
        return Err(VerifyError::AddressMismatch);
    }

    // `ak` is the first 32 bytes of the FVK encoding (`ak ‖ nk ‖ rivk`).
    let ak_bytes: [u8; 32] = fvk[..32].try_into().expect("slice is 32 bytes");
    let vk = VerificationKey::<SpendAuth>::try_from(ak_bytes).map_err(|_| VerifyError::BadKey)?;

    let digest = message_digest(network_tag, address, message);
    vk.verify(&digest, &Signature::<SpendAuth>::from(*sig)).map_err(|_| VerifyError::BadSignature)
}

/// Derive the wallet's serialized full viewing key (`ak ‖ nk ‖ rivk`, 96 bytes) from
/// its `seed`, without the proving circuit. The device sends this to the daemon's
/// non-custodial `/prepare` endpoint so the server can scan watch-only and build the
/// payment proof; it grants viewing (not spend) capability. Returns `None` only if
/// `seed` is not a valid Orchard spending key.
pub fn fvk_bytes_from_seed(seed: [u8; 32]) -> Option<[u8; FVK_LEN]> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
    Some(FullViewingKey::from(&sk).to_bytes())
}

/// Device-side spend-auth signing for a **non-custodial payment** (no proving circuit).
///
/// Given the wallet `seed`, a per-action randomizer `alpha` (from the server's
/// `prepare_payment` request), and the payment `sighash`, produce the RedPallas
/// spend-auth signature the server applies via `finalize_payment`. This is the ONLY
/// step that needs the spend key, and it runs entirely on the device. Returns `None`
/// if `seed` is not a valid spending key or `alpha` is not a canonical scalar.
pub fn sign_spend_auth_from_seed(seed: [u8; 32], alpha: [u8; 32], sighash: [u8; 32]) -> Option<[u8; 64]> {
    use group::ff::PrimeField;
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
    let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(alpha))?;
    let ask = SpendAuthorizingKey::from(&sk);
    let sig = ask.randomize(&alpha).sign(rand::rng(), &sighash);
    Some(<[u8; 64]>::from(&sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SysRng;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let signed = sign_message(seed(7), b"zkas-mainnet", b"i own this address", rand::rng()).unwrap();
        assert_eq!(verify_message(&signed.address, b"zkas-mainnet", b"i own this address", &signed.fvk, &signed.sig), Ok(()));
    }

    #[test]
    fn wrong_message_fails() {
        let signed = sign_message(seed(7), b"zkas-mainnet", b"i own this address", rand::rng()).unwrap();
        assert_eq!(
            verify_message(&signed.address, b"zkas-mainnet", b"a different message", &signed.fvk, &signed.sig),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn wrong_network_fails() {
        let signed = sign_message(seed(7), b"zkas-mainnet", b"msg", rand::rng()).unwrap();
        assert_eq!(verify_message(&signed.address, b"zkas-devnet", b"msg", &signed.fvk, &signed.sig), Err(VerifyError::BadSignature));
    }

    #[test]
    fn claiming_another_address_fails() {
        // Attacker signs with their own wallet (seed 9) but swaps in a victim's
        // address (seed 3). The FVK is the attacker's, so the binding check rejects.
        let attacker = sign_message(seed(9), b"net", b"msg", rand::rng()).unwrap();
        let victim = sign_message(seed(3), b"net", b"msg", rand::rng()).unwrap();
        assert_ne!(attacker.address, victim.address);
        assert_eq!(verify_message(&victim.address, b"net", b"msg", &attacker.fvk, &attacker.sig), Err(VerifyError::AddressMismatch));
    }

    #[test]
    fn forged_fvk_for_victim_address_fails() {
        // Even if an attacker presents the victim's real address AND real FVK (both
        // public), they cannot produce a valid signature without the victim's `ask`.
        let victim = sign_message(seed(3), b"net", b"msg", rand::rng()).unwrap();
        let attacker = sign_message(seed(9), b"net", b"msg", rand::rng()).unwrap();
        // Victim's binding holds, but attacker's signature over it does not verify.
        assert_eq!(verify_message(&victim.address, b"net", b"msg", &victim.fvk, &attacker.sig), Err(VerifyError::BadSignature));
    }

    #[test]
    fn tampered_signature_fails() {
        let mut signed = sign_message(seed(1), b"net", b"msg", rand::rng()).unwrap();
        signed.sig[0] ^= 0x01;
        assert!(verify_message(&signed.address, b"net", b"msg", &signed.fvk, &signed.sig).is_err());
    }

    #[test]
    fn garbage_fvk_rejected() {
        let signed = sign_message(seed(1), b"net", b"msg", rand::rng()).unwrap();
        let bad = [0xffu8; FVK_LEN];
        let r = verify_message(&signed.address, b"net", b"msg", &bad, &signed.sig);
        assert!(matches!(r, Err(VerifyError::BadFvk) | Err(VerifyError::AddressMismatch)));
    }
}
