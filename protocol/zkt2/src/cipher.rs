//! BIP 324 ciphers: FSChaCha20 (packet lengths), FSChaCha20Poly1305 (packet contents), the key
//! schedule, and the packet cipher that combines them.
//!
//! Every function here follows `bip-0324/reference.py` byte for byte; the only ZKas change is the
//! HKDF salt (see [`zkas_salt`]). The tests run the published BIP 324 packet vectors with the
//! Bitcoin salt, which pins the whole construction, and separate vectors with the ZKas salt.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Packets (or length chunks) per key; BIP 324 `REKEY_INTERVAL`.
pub const REKEY_INTERVAL: u64 = 224;
/// Bytes of the encrypted length field.
pub const LENGTH_FIELD_LEN: usize = 3;
/// Bytes of the (encrypted) packet header.
pub const HEADER_LEN: usize = 1;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Ciphertext bytes added to every packet: length field + header + tag.
pub const PACKET_OVERHEAD: usize = LENGTH_FIELD_LEN + HEADER_LEN + TAG_LEN;
/// The header bit marking a decoy packet the receiver must discard.
pub const IGNORE_BIT: u8 = 0x80;
/// BIP 324's limit on one packet's contents (a 3-byte length field).
pub const MAX_CONTENTS_LEN: usize = (1 << 24) - 1;

type HmacSha256 = Hmac<Sha256>;

/// The salt of the Bitcoin v2 transport (`b"bitcoin_v2_shared_secret" || network magic`), used only
/// to check this implementation against the published BIP 324 vectors.
pub fn bitcoin_salt(network_magic: [u8; 4]) -> Vec<u8> {
    let mut salt = b"bitcoin_v2_shared_secret".to_vec();
    salt.extend_from_slice(&network_magic);
    salt
}

/// The ZKT2 salt: `b"zkas_v2_shared_secret" || BLAKE2b-256(network_name)[0..4]` (spec 06 T-2).
///
/// A distinct salt makes a ZKas session and a Bitcoin v2 session non-interoperable on purpose, and
/// the network name in it keeps mainnet, testnet and devnet sessions apart as well.
pub fn zkas_salt(network_name: &str) -> Vec<u8> {
    let digest = blake2b_simd::Params::new().hash_length(32).hash(network_name.as_bytes());
    let mut salt = b"zkas_v2_shared_secret".to_vec();
    salt.extend_from_slice(&digest.as_bytes()[0..4]);
    salt
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// HKDF-Expand for a single 32-byte block: `T(1) = HMAC(prk, info || 0x01)`.
fn hkdf_expand32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[1u8]);
    mac.finalize().into_bytes().into()
}

/// Everything BIP 324 derives from the ECDH secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionKeys {
    pub initiator_l: [u8; 32],
    pub initiator_p: [u8; 32],
    pub responder_l: [u8; 32],
    pub responder_p: [u8; 32],
    pub initiator_garbage_terminator: [u8; 16],
    pub responder_garbage_terminator: [u8; 16],
    pub session_id: [u8; 32],
}

impl SessionKeys {
    pub fn derive(ecdh_secret: &[u8; 32], salt: &[u8]) -> Self {
        let prk = hkdf_extract(salt, ecdh_secret);
        let terminators = hkdf_expand32(&prk, b"garbage_terminators");
        let mut initiator_garbage_terminator = [0u8; 16];
        let mut responder_garbage_terminator = [0u8; 16];
        initiator_garbage_terminator.copy_from_slice(&terminators[..16]);
        responder_garbage_terminator.copy_from_slice(&terminators[16..]);
        Self {
            initiator_l: hkdf_expand32(&prk, b"initiator_L"),
            initiator_p: hkdf_expand32(&prk, b"initiator_P"),
            responder_l: hkdf_expand32(&prk, b"responder_L"),
            responder_p: hkdf_expand32(&prk, b"responder_P"),
            initiator_garbage_terminator,
            responder_garbage_terminator,
            session_id: hkdf_expand32(&prk, b"session_id"),
        }
    }
}

fn epoch_nonce(prefix: u32, epoch: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix.to_le_bytes());
    nonce[4..].copy_from_slice(&epoch.to_le_bytes());
    nonce
}

/// FSChaCha20: the forward-secure stream cipher for packet lengths.
///
/// The keystream runs continuously across chunks within a rekey epoch (nonce = `0u32 || epoch`,
/// block counter from 0). After every [`REKEY_INTERVAL`] chunks the next 32 keystream bytes become
/// the new key. With 3-byte chunks an epoch uses exactly 224 * 3 + 32 = 704 = 11 * 64 bytes, so
/// starting the new key at block 0 matches the reference's buffered keystream exactly.
pub struct FsChaCha20 {
    cipher: ChaCha20,
    chunk_counter: u64,
}

impl FsChaCha20 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { cipher: Self::epoch_cipher(&key, 0), chunk_counter: 0 }
    }

    fn epoch_cipher(key: &[u8; 32], epoch: u64) -> ChaCha20 {
        ChaCha20::new(key.into(), &epoch_nonce(0, epoch).into())
    }

    /// Encrypts or decrypts `chunk` in place (the same operation).
    pub fn crypt(&mut self, chunk: &mut [u8]) {
        self.cipher.apply_keystream(chunk);
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            let mut key = [0u8; 32];
            self.cipher.apply_keystream(&mut key);
            self.cipher = Self::epoch_cipher(&key, (self.chunk_counter + 1) / REKEY_INTERVAL);
        }
        self.chunk_counter += 1;
    }
}

/// FSChaCha20Poly1305: the rekeying AEAD for packet contents.
pub struct FsChaCha20Poly1305 {
    key: [u8; 32],
    aead: ChaCha20Poly1305,
    packet_counter: u64,
}

/// The AEAD tag did not verify: the stream was modified, or the peer is not who sent the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ZKT2 packet authentication failed")]
pub struct AuthError;

impl FsChaCha20Poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { aead: ChaCha20Poly1305::new(&key.into()), key, packet_counter: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        epoch_nonce((self.packet_counter % REKEY_INTERVAL) as u32, self.packet_counter / REKEY_INTERVAL)
    }

    fn advance(&mut self) {
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            // New key = first 32 bytes of the ChaCha20 block with counter 1 under the rekey nonce
            // (equivalently: AEAD-encrypt 32 zero bytes with that nonce and take the ciphertext).
            let rekey_nonce = epoch_nonce(u32::MAX, self.packet_counter / REKEY_INTERVAL);
            let mut stream = ChaCha20::new(&self.key.into(), &rekey_nonce.into());
            stream.seek(64u64);
            let mut key = [0u8; 32];
            stream.apply_keystream(&mut key);
            self.key = key;
            self.aead = ChaCha20Poly1305::new(&key.into());
        }
        self.packet_counter += 1;
    }

    /// Encrypts `buf` in place and returns the tag.
    pub fn encrypt(&mut self, aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
        let nonce = self.nonce();
        let tag = self.aead.encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buf).expect("ChaCha20Poly1305 encrypt cannot fail");
        self.advance();
        tag.into()
    }

    /// Decrypts `buf` in place if `tag` verifies. The packet counter advances either way: a failed
    /// packet ends the connection, so there is no state to keep consistent after it.
    pub fn decrypt(&mut self, aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), AuthError> {
        let nonce = self.nonce();
        let res = self.aead.decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buf, Tag::from_slice(tag)).map_err(|_| AuthError);
        self.advance();
        res
    }
}

/// One direction's packet encoder.
pub struct PacketEncryptor {
    length: FsChaCha20,
    contents: FsChaCha20Poly1305,
}

impl PacketEncryptor {
    pub fn new(l_key: [u8; 32], p_key: [u8; 32]) -> Self {
        Self { length: FsChaCha20::new(l_key), contents: FsChaCha20Poly1305::new(p_key) }
    }

    /// Appends the encrypted packet for `contents` to `out` (`v2_enc_packet` in BIP 324).
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool, out: &mut Vec<u8>) {
        assert!(contents.len() <= MAX_CONTENTS_LEN, "a ZKT2 packet holds at most 2^24 - 1 bytes");
        let start = out.len();
        let len = contents.len() as u32;
        out.extend_from_slice(&len.to_le_bytes()[..LENGTH_FIELD_LEN]);
        out.push(if ignore { IGNORE_BIT } else { 0 });
        out.extend_from_slice(contents);
        let (length_field, rest) = out[start..].split_at_mut(LENGTH_FIELD_LEN);
        // BIP 324 encrypts the contents first, then the length; the two ciphers are independent, so
        // only the order of each cipher's own calls matters, but keep the reference order anyway.
        let tag = self.contents.encrypt(aad, rest);
        self.length.crypt(length_field);
        out.extend_from_slice(&tag);
    }
}

/// One direction's packet decoder. The length is decrypted first, on its own, because the receiver
/// needs it to know how many bytes to wait for.
pub struct PacketDecryptor {
    length: FsChaCha20,
    contents: FsChaCha20Poly1305,
}

impl PacketDecryptor {
    pub fn new(l_key: [u8; 32], p_key: [u8; 32]) -> Self {
        Self { length: FsChaCha20::new(l_key), contents: FsChaCha20Poly1305::new(p_key) }
    }

    /// Decrypts the 3-byte length field. Call exactly once per packet, before `decrypt_contents`.
    pub fn decrypt_length(&mut self, field: [u8; LENGTH_FIELD_LEN]) -> usize {
        let mut field = field;
        self.length.crypt(&mut field);
        u32::from_le_bytes([field[0], field[1], field[2], 0]) as usize
    }

    /// Decrypts `header || contents || tag` in place; on success returns (ignore bit, contents
    /// range within `buf`).
    pub fn decrypt_contents(&mut self, aad: &[u8], buf: &mut [u8]) -> Result<bool, AuthError> {
        if buf.len() < HEADER_LEN + TAG_LEN {
            return Err(AuthError);
        }
        let split = buf.len() - TAG_LEN;
        let (body, tag) = buf.split_at_mut(split);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().expect("split at TAG_LEN");
        self.contents.decrypt(aad, body, &tag)?;
        Ok(body[0] & IGNORE_BIT != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fschacha20_rekeys_after_224_chunks_and_round_trips() {
        let key = [7u8; 32];
        let mut enc = FsChaCha20::new(key);
        let mut dec = FsChaCha20::new(key);
        let mut seen = std::collections::HashSet::new();
        for i in 0..(3 * REKEY_INTERVAL as usize + 5) {
            let plain = [(i % 251) as u8, 1, 2];
            let mut c = plain;
            enc.crypt(&mut c);
            seen.insert(c);
            dec.crypt(&mut c);
            assert_eq!(c, plain, "chunk {i}");
        }
        // Distinct ciphertexts for almost every chunk (a keystream reuse after rekey would repeat).
        assert!(seen.len() > 3 * REKEY_INTERVAL as usize - 3);
    }

    #[test]
    fn aead_rejects_a_flipped_bit_and_rekeys() {
        let mut a = FsChaCha20Poly1305::new([9u8; 32]);
        let mut b = FsChaCha20Poly1305::new([9u8; 32]);
        for i in 0..(REKEY_INTERVAL as usize * 2 + 1) {
            let mut buf = vec![i as u8; 40];
            let tag = a.encrypt(b"aad", &mut buf);
            b.decrypt(b"aad", &mut buf, &tag).unwrap();
            assert_eq!(buf, vec![i as u8; 40]);
        }
        let mut buf = vec![1u8; 10];
        let tag = a.encrypt(b"", &mut buf);
        buf[3] ^= 1;
        assert_eq!(b.decrypt(b"", &mut buf, &tag), Err(AuthError));
    }

    #[test]
    fn zkas_salt_differs_per_network_and_from_bitcoin() {
        let main = zkas_salt("zkas-mainnet");
        let dev = zkas_salt("zkas-devnet");
        assert_ne!(main, dev);
        assert!(main.starts_with(b"zkas_v2_shared_secret"));
        assert_eq!(main.len(), b"zkas_v2_shared_secret".len() + 4);
        assert_ne!(main, bitcoin_salt([0xf9, 0xbe, 0xb4, 0xd9]));
    }
}
