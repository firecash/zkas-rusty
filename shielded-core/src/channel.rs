//! Tagged channels: delivery without trial decryption (fork topic 01 §A, devnet prototype).
//!
//! Every output of a tagged bundle ([`crate::bundle::FORMAT_TAGGED`]) carries, in place of
//! Orchard's `epk ‖ enc_ciphertext ‖ out_ciphertext` (692 bytes):
//!
//! - a 16-byte **delivery tag** `tag = BLAKE2b-128(K ‖ LE32(ctr))`,
//! - a 32-byte **kem** point (a uniformly random Pallas point for channel outputs; `esk·g_d` for
//!   the open lane; `r·G_k` for an intro-token first contact),
//! - a 64-byte **channel ciphertext**, ChaCha20-Poly1305 under `k_ct = BLAKE2b-256(K ‖ ctr)`,
//!   nonce 0, over a 48-byte plaintext `value u64 ‖ kind u8 ‖ aux[39]`.
//!
//! `K` is a 32-byte secret the sender and the receiver share (a *channel*). All the note's
//! randomness is derived from `(K, ctr)` (`rseed = BLAKE2b-256(K ‖ ctr)`), so the receiver, who
//! knows its own address for the channel and reads `value` from the ciphertext, rebuilds the whole
//! Orchard note and **requires its commitment to equal the on-chain `cmx`**
//! ([`open_channel_output`]). That single check authenticates a found record: nobody without `K`
//! can make a record that passes it, and the circuit already proved that `cmx` is the commitment
//! of the note the action created.
//!
//! Nothing here touches the circuit. The Orchard action circuit's public inputs are
//! `(anchor, cv_net, nf, rk, cmx, flags)` (`verify.rs`, `Instance::from_parts`); the ciphertexts
//! only ever entered ZKas's sighash. Replacing them is a wire + sighash change, not a VK change.
//!
//! Key tree (seed-derived; every inbound channel a wallet could ever receive on is re-derivable
//! from the spending key, which is what makes restore-without-birthday possible):
//!
//! ```text
//! chk        = PRF(sk, "root")                 channel root (held by the wallet only)
//! K_self     = PRF(chk, "self")                change, consolidations, self-sends
//! K_req[i]   = PRF(chk, "req" ‖ LE32(i))       payment request i (address: external index REQ_BASE + i)
//! sk_int[i]  = ToScalar(PRF(chk, "intro" ‖ i)) one-time intro token i, ek_int[i] = sk_int[i]·G_k
//! ```

use blake2b_simd::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use group::{Group, GroupEncoding, ff::FromUniformBytes};
use pasta_curves::{arithmetic::CurveExt, pallas};

/// Delivery tag length.
pub const TAG_LEN: usize = 16;
/// Channel ciphertext length (48-byte plaintext + 16-byte Poly1305 tag).
pub const CT_LEN: usize = 64;
/// Channel plaintext length.
pub const PT_LEN: usize = 48;
/// Auxiliary bytes carried in every channel plaintext (the recovery ledger on self outputs).
pub const AUX_LEN: usize = 39;
/// The part of the channel ciphertext a compact (148-byte) scan record keeps: the 48-byte
/// ciphertext body plus the first 4 MAC bytes. A compact record is authenticated by the `cmx`
/// self-check, not by the MAC.
pub const CT_COMPACT_LEN: usize = 52;

/// First external diversifier index used for payment-request addresses (request `i` pays to
/// external index `REQ_BASE + i`). Far above the indices wallets display, so a request address
/// never coincides with a published one.
pub const REQ_BASE: u32 = 1 << 24;

const P_TAG: &[u8; 16] = b"ZKasTagChannel_1";
const P_CTKEY: &[u8; 16] = b"ZKasCtKeyChan__1";
const P_RSEED: &[u8; 16] = b"ZKasRseedChan__1";
const P_ROOT: &[u8; 16] = b"ZKasChannelRoot1";
const P_SUB: &[u8; 16] = b"ZKasChannelSub_1";
const P_OPEN: &[u8; 16] = b"ZKasOpenLaneK__1";
const P_INTRO: &[u8; 16] = b"ZKasIntroK_____1";
const ORCHARD_GD: &str = "z.cash:Orchard-gd";
const GK_DOMAIN: &str = "ZKas:ChannelGk";

fn h256(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Params::new().hash_length(32).personal(personal).to_state();
    for p in parts {
        s.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(s.finalize().as_bytes());
    out
}

fn keyed256(key: &[u8; 32], personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Params::new().hash_length(32).key(key).personal(personal).to_state();
    for p in parts {
        s.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(s.finalize().as_bytes());
    out
}

/// The delivery tag of output `ctr` on channel `k`.
pub fn tag(k: &[u8; 32], ctr: u32) -> [u8; TAG_LEN] {
    let mut s = Params::new().hash_length(TAG_LEN).personal(P_TAG).to_state();
    s.update(k);
    s.update(&ctr.to_le_bytes());
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(s.finalize().as_bytes());
    out
}

/// The per-output AEAD key. Unique per `(K, ctr)`, so nonce 0 is never reused under one key
/// except by a sender that reuses a counter (see [`seal`]).
pub fn ct_key(k: &[u8; 32], ctr: u32) -> [u8; 32] {
    h256(P_CTKEY, &[k, &ctr.to_le_bytes()])
}

/// The note's `rseed`, derived so that the receiver can rebuild the note.
pub fn rseed(k: &[u8; 32], ctr: u32) -> [u8; 32] {
    h256(P_RSEED, &[k, &ctr.to_le_bytes()])
}

/// What an output carries, as its sender declares it (the plaintext `kind` byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A padding output (value 0, random tag; nobody looks it up).
    Dummy = 0,
    /// A payment on a payment-request channel.
    Request = 1,
    /// An output on the wallet's own self channel; `aux` carries the [`RecoveryLedger`].
    SelfChannel = 2,
    /// A first contact through a one-time intro token.
    Intro = 3,
    /// An unsolicited payment to a static address (the open lane); `aux[0..11]` is the
    /// diversifier the payment went to.
    OpenLane = 4,
}

impl Kind {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Kind::Dummy,
            1 => Kind::Request,
            2 => Kind::SelfChannel,
            3 => Kind::Intro,
            4 => Kind::OpenLane,
            _ => return None,
        })
    }
}

/// The 48-byte channel plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plaintext {
    pub value: u64,
    pub kind: Kind,
    pub aux: [u8; AUX_LEN],
}

impl Plaintext {
    pub fn to_bytes(&self) -> [u8; PT_LEN] {
        let mut b = [0u8; PT_LEN];
        b[0..8].copy_from_slice(&self.value.to_le_bytes());
        b[8] = self.kind as u8;
        b[9..].copy_from_slice(&self.aux);
        b
    }

    pub fn from_bytes(b: &[u8; PT_LEN]) -> Option<Self> {
        let value = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let kind = Kind::from_u8(b[8])?;
        let mut aux = [0u8; AUX_LEN];
        aux.copy_from_slice(&b[9..]);
        Some(Self { value, kind, aux })
    }
}

/// Encrypt a plaintext for output `ctr` on channel `k`.
///
/// A sender that reuses a counter on one channel reuses `(key, nonce)` and so leaks the XOR of
/// the two plaintexts to anyone holding `K` (the two parties of the channel, nobody else). The
/// wallet never reuses a counter it allocated; two payer devices sharing a request can (01 §3.11
/// "duplicate counters"). Both notes stay valid and are both found.
pub fn seal(k: &[u8; 32], ctr: u32, pt: &Plaintext) -> [u8; CT_LEN] {
    let key = ct_key(k, ctr);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let mut buf = pt.to_bytes();
    let mac = cipher.encrypt_in_place_detached(GenericArray::from_slice(&[0u8; 12]), &[], &mut buf).expect("48 bytes always encrypt");
    let mut out = [0u8; CT_LEN];
    out[..PT_LEN].copy_from_slice(&buf);
    out[PT_LEN..].copy_from_slice(&mac);
    out
}

/// Decrypt and authenticate a full 64-byte channel ciphertext.
pub fn open(k: &[u8; 32], ctr: u32, ct: &[u8; CT_LEN]) -> Option<Plaintext> {
    let key = ct_key(k, ctr);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let mut buf = [0u8; PT_LEN];
    buf.copy_from_slice(&ct[..PT_LEN]);
    cipher
        .decrypt_in_place_detached(GenericArray::from_slice(&[0u8; 12]), &[], &mut buf, GenericArray::from_slice(&ct[PT_LEN..]))
        .ok()?;
    Plaintext::from_bytes(&buf)
}

/// Decrypt the 52-byte compact form (no MAC check). ChaCha20-Poly1305 encrypts the payload with
/// the ChaCha20 keystream from block counter 1 (block 0 keys Poly1305), so the body decrypts
/// without the tag. The result is unauthenticated: the caller MUST run the `cmx` self-check
/// ([`open_channel_output`] does), which authenticates it completely.
pub fn open_compact(k: &[u8; 32], ctr: u32, ct52: &[u8; CT_COMPACT_LEN]) -> Option<Plaintext> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let key = ct_key(k, ctr);
    let mut c = chacha20::ChaCha20::new(GenericArray::from_slice(&key), GenericArray::from_slice(&[0u8; 12]));
    c.seek(64u64);
    let mut buf = [0u8; PT_LEN];
    buf.copy_from_slice(&ct52[..PT_LEN]);
    c.apply_keystream(&mut buf);
    Plaintext::from_bytes(&buf)
}

/// The receiver's recovery ledger, carried in the `aux` of every self-channel output (01 §3.7).
/// It tells a restoring wallet which ranges of every channel family can still hold funds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryLedger {
    /// Lowest self counter whose output is still unspent.
    pub lwm_self: u32,
    /// Lowest request index with unspent funds or an open subscription.
    pub lwm_req: u32,
    /// Highest request index issued (exclusive: next index to issue).
    pub hwm_req: u32,
    /// Lowest intro token with unspent funds.
    pub lwm_int: u32,
    /// Highest intro token index uploaded (exclusive).
    pub hwm_int: u32,
    /// Coarse creation epoch (DAA / 86,400); aids a reverse search.
    pub epoch: u32,
    /// Count of unspent notes when this output was created, this output included.
    pub n_unspent: u16,
    /// Index into the release's intro-service list.
    pub svc_hint: u8,
}

impl RecoveryLedger {
    pub fn to_aux(&self) -> [u8; AUX_LEN] {
        let mut a = [0u8; AUX_LEN];
        a[0..4].copy_from_slice(&self.lwm_self.to_le_bytes());
        a[4..8].copy_from_slice(&self.lwm_req.to_le_bytes());
        a[8..12].copy_from_slice(&self.hwm_req.to_le_bytes());
        a[12..16].copy_from_slice(&self.lwm_int.to_le_bytes());
        a[16..20].copy_from_slice(&self.hwm_int.to_le_bytes());
        a[20..24].copy_from_slice(&self.epoch.to_le_bytes());
        a[24..26].copy_from_slice(&self.n_unspent.to_le_bytes());
        a[26] = self.svc_hint;
        // a[27..38] reserved, zero.
        a[38] = a[..38].iter().fold(0x5a, |x, b| x ^ b);
        a
    }

    /// `None` if the checksum fails or a reserved byte is set.
    pub fn from_aux(a: &[u8; AUX_LEN]) -> Option<Self> {
        if a[38] != a[..38].iter().fold(0x5a, |x, b| x ^ b) || a[27..38].iter().any(|&b| b != 0) {
            return None;
        }
        let u = |i: usize| u32::from_le_bytes(a[i..i + 4].try_into().unwrap());
        Some(Self {
            lwm_self: u(0),
            lwm_req: u(4),
            hwm_req: u(8),
            lwm_int: u(12),
            hwm_int: u(16),
            epoch: u(20),
            n_unspent: u16::from_le_bytes([a[24], a[25]]),
            svc_hint: a[26],
        })
    }
}

/// The channel root and every key derived from it.
#[derive(Clone)]
pub struct ChannelKeys {
    chk: [u8; 32],
}

impl ChannelKeys {
    /// Derive from the Orchard spending-key bytes (the wallet seed as ZKas uses it).
    pub fn from_spending_key(sk: &[u8; 32]) -> Self {
        Self { chk: keyed256(sk, P_ROOT, &[b"root"]) }
    }

    /// The channel root itself. A watch-only (FVK) wallet holds it to see incoming payments and
    /// the self channel; it grants no spend authority.
    pub fn root(&self) -> [u8; 32] {
        self.chk
    }

    pub fn k_self(&self) -> [u8; 32] {
        keyed256(&self.chk, P_SUB, &[b"self"])
    }

    pub fn k_req(&self, i: u32) -> [u8; 32] {
        keyed256(&self.chk, P_SUB, &[b"req", &i.to_le_bytes()])
    }

    /// The secret scalar of intro token `i`.
    pub fn intro_secret(&self, i: u32) -> pallas::Scalar {
        let a = keyed256(&self.chk, P_SUB, &[b"intro-a", &i.to_le_bytes()]);
        let b = keyed256(&self.chk, P_SUB, &[b"intro-b", &i.to_le_bytes()]);
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&a);
        wide[32..].copy_from_slice(&b);
        pallas::Scalar::from_uniform_bytes(&wide)
    }

    /// The public token `ek_int[i] = sk_int[i]·G_k` a receiver pre-uploads to its intro service.
    pub fn intro_public(&self, i: u32) -> [u8; 32] {
        (g_k() * self.intro_secret(i)).to_bytes()
    }

    /// The channel key of intro token `i`, given the `kem` the payer deposited.
    pub fn intro_k(&self, i: u32, kem: &[u8; 32]) -> Option<[u8; 32]> {
        let p = Option::<pallas::Point>::from(pallas::Point::from_bytes(kem))?;
        if bool::from(p.is_identity()) {
            return None;
        }
        Some(h256(P_INTRO, &[&(p * self.intro_secret(i)).to_bytes(), kem]))
    }
}

/// The intro-token generator `G_k`, domain-separated from every Orchard generator.
pub fn g_k() -> pallas::Point {
    pallas::Point::hash_to_curve(GK_DOMAIN)(b"G")
}

/// Orchard's `DiversifyHash(d)`.
pub fn g_d(d: &[u8; 11]) -> pallas::Point {
    let hasher = pallas::Point::hash_to_curve(ORCHARD_GD);
    let p = hasher(d);
    if bool::from(p.is_identity()) { hasher(&[]) } else { p }
}

fn nonzero_scalar(rng: &mut (impl rand_core::Rng + rand_core::CryptoRng)) -> pallas::Scalar {
    loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let s = pallas::Scalar::from_uniform_bytes(&wide);
        if s != pallas::Scalar::zero() {
            return s;
        }
    }
}

/// A uniformly random, non-identity Pallas point (the `kem` of a channel output).
pub fn random_kem(rng: &mut (impl rand_core::Rng + rand_core::CryptoRng)) -> [u8; 32] {
    loop {
        let p = pallas::Point::generator() * nonzero_scalar(rng);
        if !bool::from(p.is_identity()) {
            return p.to_bytes();
        }
    }
}

/// A payer's first contact through intro token `ek` (01 §3.4.2): returns `(kem, K)`. The payer
/// deposits `kem` at the receiver's intro service; only the holder of `sk_int` (or `r`) can
/// compute `K`, so the service can link a token to a published address but not to a tx.
pub fn intro_contact(ek: &[u8; 32], rng: &mut (impl rand_core::Rng + rand_core::CryptoRng)) -> Option<([u8; 32], [u8; 32])> {
    let ek = Option::<pallas::Point>::from(pallas::Point::from_bytes(ek))?;
    if bool::from(ek.is_identity()) {
        return None;
    }
    let r = nonzero_scalar(rng);
    let kem = (g_k() * r).to_bytes();
    Some((kem, h256(P_INTRO, &[&(ek * r).to_bytes(), &kem])))
}

/// Open-lane sender side (01 §3.6): a payment to a static address `(d, pk_d)` with no shared
/// secret. Returns `(kem = esk·g_d, K)`. The receiver finds it only by one scalar multiplication
/// per output ([`open_lane_k`]) — the trial-decryption fallback, paid only by wallets that publish
/// a static address.
pub fn open_lane_contact(
    addr: &[u8; 43],
    rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
) -> Option<([u8; 32], [u8; 32])> {
    let d: [u8; 11] = addr[..11].try_into().unwrap();
    let pk_d = Option::<pallas::Point>::from(pallas::Point::from_bytes(&addr[11..].try_into().unwrap()))?;
    let esk = nonzero_scalar(rng);
    let kem = (g_d(&d) * esk).to_bytes();
    Some((kem, h256(P_OPEN, &[&(pk_d * esk).to_bytes(), &kem])))
}

/// Open-lane receiver side: `K = H(ivk·kem ‖ kem)`, given the wallet's ivk agreement scalar.
pub fn open_lane_k(ivk_scalar: &pallas::Scalar, kem: &[u8; 32]) -> Option<[u8; 32]> {
    let p = Option::<pallas::Point>::from(pallas::Point::from_bytes(kem))?;
    if bool::from(p.is_identity()) {
        return None;
    }
    Some(h256(P_OPEN, &[&(p * ivk_scalar).to_bytes(), kem]))
}

/// The open-lane tag: bytes 0..2 are the DTAG slot (random until spec 11's DTAG is activated for
/// open-lane receivers), bytes 2..16 the first 14 bytes of `tag(K, 0)`.
pub fn open_lane_tag(k: &[u8; 32], dtag: [u8; 2]) -> [u8; TAG_LEN] {
    let t = tag(k, 0);
    let mut out = [0u8; TAG_LEN];
    out[..2].copy_from_slice(&dtag);
    out[2..].copy_from_slice(&t[..14]);
    out
}

/// Whether `t` is the open-lane tag of `K`.
pub fn is_open_lane_tag(k: &[u8; 32], t: &[u8; TAG_LEN]) -> bool {
    tag(k, 0)[..14] == t[2..]
}

/// A payment request (mode S, 01 §3.4.1): a fresh address plus the channel key, given to the
/// payer privately. Wire: `0x0A ‖ addr 43 ‖ K 32 ‖ ctr0 u32 LE ‖ amount u64 LE` (amount 0 = any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub address: [u8; 43],
    pub k: [u8; 32],
    pub ctr0: u32,
    pub amount: u64,
}

impl PaymentRequest {
    pub const TLV: u8 = 0x0A;
    pub const LEN: usize = 1 + 43 + 32 + 4 + 8;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = Self::TLV;
        b[1..44].copy_from_slice(&self.address);
        b[44..76].copy_from_slice(&self.k);
        b[76..80].copy_from_slice(&self.ctr0.to_le_bytes());
        b[80..88].copy_from_slice(&self.amount.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN || b[0] != Self::TLV {
            return None;
        }
        Some(Self {
            address: b[1..44].try_into().unwrap(),
            k: b[44..76].try_into().unwrap(),
            ctr0: u32::from_le_bytes(b[76..80].try_into().unwrap()),
            amount: u64::from_le_bytes(b[80..88].try_into().unwrap()),
        })
    }
}

/// A channel output as the sender specifies it to the bundle builder.
#[derive(Clone, Copy, Debug)]
pub struct ChannelOutput {
    /// The recipient's raw Orchard address.
    pub address: [u8; 43],
    pub value: u64,
    /// The channel key.
    pub k: [u8; 32],
    pub ctr: u32,
    /// The on-chain tag (normally [`tag`]`(k, ctr)`; the open lane's is [`open_lane_tag`]).
    pub tag: [u8; TAG_LEN],
    /// The on-chain kem point.
    pub kem: [u8; 32],
    pub kind: Kind,
    pub aux: [u8; AUX_LEN],
}

impl ChannelOutput {
    /// An output on a shared-secret channel (request, self): random kem, tag `H(K, ctr)`.
    pub fn on_channel(
        address: [u8; 43],
        value: u64,
        k: [u8; 32],
        ctr: u32,
        kind: Kind,
        aux: [u8; AUX_LEN],
        rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
    ) -> Self {
        Self { address, value, k, ctr, tag: tag(&k, ctr), kem: random_kem(rng), kind, aux }
    }

    /// A first contact through an intro token: kem from [`intro_contact`].
    pub fn intro(address: [u8; 43], value: u64, kem: [u8; 32], k: [u8; 32]) -> Self {
        Self { address, value, k, ctr: 0, tag: tag(&k, 0), kem, kind: Kind::Intro, aux: [0u8; AUX_LEN] }
    }

    /// An unsolicited payment to a static address.
    pub fn open_lane(address: [u8; 43], value: u64, rng: &mut (impl rand_core::Rng + rand_core::CryptoRng)) -> Option<Self> {
        let (kem, k) = open_lane_contact(&address, rng)?;
        let mut dtag = [0u8; 2];
        rng.fill_bytes(&mut dtag);
        let mut aux = [0u8; AUX_LEN];
        aux[..11].copy_from_slice(&address[..11]);
        Some(Self { address, value, k, ctr: 0, tag: open_lane_tag(&k, dtag), kem, kind: Kind::OpenLane, aux })
    }

    pub fn plaintext(&self) -> Plaintext {
        Plaintext { value: self.value, kind: self.kind, aux: self.aux }
    }

    pub fn ciphertext(&self) -> [u8; CT_LEN] {
        seal(&self.k, self.ctr, &self.plaintext())
    }
}

/// Rebuild the Orchard note of a channel output and check it against the on-chain `cmx`.
///
/// `address` is the receiver's own address for this channel, `nf` the action's nullifier (Orchard
/// `ρ` of the output note), `value` from the decrypted plaintext. Returns the note only if its
/// commitment equals `cmx`: the record is then real and was made by a holder of `K`.
pub fn open_channel_output(
    address: &[u8; 43],
    value: u64,
    k: &[u8; 32],
    ctr: u32,
    nf: &[u8; 32],
    cmx: &[u8; 32],
) -> Option<orchard::Note> {
    use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
    let addr = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(address))?;
    let nf = Option::<orchard::note::Nullifier>::from(orchard::note::Nullifier::from_bytes(nf))?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes()))?; // Orchard: rho of an output = the action nf
    let rs = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed(k, ctr), &rho))?;
    let (note, cm) =
        orchard::Note::from_parts_with_commitment(addr, orchard::value::NoteValue::from_raw(value), rho, rs, NoteVersion::V2)?;
    (ExtractedNoteCommitment::from(cm).to_bytes() == *cmx).then_some(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    fn rng() -> rand::rngs::StdRng {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(7)
    }

    #[test]
    fn plaintext_and_ciphertext_round_trip_and_authenticate() {
        let k = [3u8; 32];
        let pt = Plaintext { value: 123_456_789, kind: Kind::Request, aux: [9u8; AUX_LEN] };
        let ct = seal(&k, 5, &pt);
        assert_eq!(open(&k, 5, &ct), Some(pt));
        let mut c52 = [0u8; CT_COMPACT_LEN];
        c52.copy_from_slice(&ct[..CT_COMPACT_LEN]);
        assert_eq!(open_compact(&k, 5, &c52), Some(pt), "the compact form decrypts to the same plaintext");
        assert_eq!(open(&k, 6, &ct), None, "another counter's key does not authenticate");
        assert_eq!(open(&[4u8; 32], 5, &ct), None, "another channel's key does not authenticate");
        for i in 0..CT_LEN {
            let mut bad = ct;
            bad[i] ^= 1;
            assert_eq!(open(&k, 5, &bad), None, "a flipped ciphertext byte {i} is refused");
        }
    }

    #[test]
    fn tags_are_distinct_per_channel_and_counter() {
        let mut seen = std::collections::HashSet::new();
        for c in 0..64u8 {
            for ctr in 0..64u32 {
                assert!(seen.insert(tag(&[c; 32], ctr)));
            }
        }
    }

    #[test]
    fn ledger_round_trips_and_detects_corruption() {
        let l = RecoveryLedger {
            lwm_self: 7,
            lwm_req: 2,
            hwm_req: 50,
            lwm_int: 1,
            hwm_int: 1000,
            epoch: 20_000,
            n_unspent: 30,
            svc_hint: 3,
        };
        let a = l.to_aux();
        assert_eq!(RecoveryLedger::from_aux(&a), Some(l));
        for i in 0..AUX_LEN {
            let mut bad = a;
            bad[i] ^= 0x10;
            assert_eq!(RecoveryLedger::from_aux(&bad), None, "a corrupted byte {i} is refused");
        }
    }

    #[test]
    fn key_tree_is_deterministic_and_separated() {
        let a = ChannelKeys::from_spending_key(&[1u8; 32]);
        let b = ChannelKeys::from_spending_key(&[2u8; 32]);
        assert_eq!(a.k_self(), ChannelKeys::from_spending_key(&[1u8; 32]).k_self());
        assert_ne!(a.k_self(), b.k_self());
        assert_ne!(a.k_req(0), a.k_req(1));
        assert_ne!(a.k_req(0), a.k_self());
        assert_ne!(a.intro_public(0), a.intro_public(1));
    }

    #[test]
    fn intro_contact_agrees_on_both_sides() {
        let keys = ChannelKeys::from_spending_key(&[5u8; 32]);
        let ek = keys.intro_public(17);
        let (kem, k_payer) = intro_contact(&ek, &mut rng()).unwrap();
        assert_eq!(keys.intro_k(17, &kem), Some(k_payer));
        assert_ne!(keys.intro_k(18, &kem), Some(k_payer), "only the token's own secret recovers K");
    }

    /// The open-lane ECDH is Orchard's: `ivk·(esk·g_d) = esk·pk_d` because `pk_d = ivk·g_d`. This
    /// pins our `g_d` to Orchard's DiversifyHash and our ivk scalar to the address the wallet gives.
    #[test]
    fn open_lane_agrees_with_orchard_addresses() {
        let sk = SpendingKey::from_bytes([8u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let ivk = fvk.to_ivk(Scope::External);
        let s = crate::wallet::scan::ivk_agreement_scalar(&ivk).unwrap();
        for j in [0u32, 1, 77, REQ_BASE] {
            let addr = fvk.address_at(j, Scope::External).to_raw_address_bytes();
            let (kem, k) = open_lane_contact(&addr, &mut rng()).unwrap();
            assert_eq!(open_lane_k(&s, &kem), Some(k), "index {j}");
        }
        let other = FullViewingKey::from(&SpendingKey::from_bytes([9u8; 32]).unwrap());
        let s2 = crate::wallet::scan::ivk_agreement_scalar(&other.to_ivk(Scope::External)).unwrap();
        let addr = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let (kem, k) = open_lane_contact(&addr, &mut rng()).unwrap();
        assert_ne!(open_lane_k(&s2, &kem), Some(k));
    }
}
