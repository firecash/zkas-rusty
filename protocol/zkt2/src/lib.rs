//! ZKT2 — the ZKas p2p encrypted transport (spec 06 §3.1).
//!
//! The BIP 324 v2 transport (ElligatorSwift ECDH, HKDF-SHA256 key schedule, FSChaCha20 length
//! encryption, FSChaCha20Poly1305 packets, garbage and garbage terminators, decoys, rekeying every
//! 224 packets) carried as a byte stream *under* the HTTP/2 connection tonic runs. The only change
//! from BIP 324 is the HKDF salt, `b"zkas_v2_shared_secret" || BLAKE2b-256(network_name)[0..4]`,
//! which makes ZKas and Bitcoin sessions, and ZKas networks among themselves, non-interoperable.
//!
//! What it gives (spec 06 G1): a passive observer reads nothing and sees uniformly random bytes
//! from the first byte on; there is no fixed handshake pattern for DPI to match. What it does not
//! give: authentication. An active man in the middle can sit between two nodes that have never
//! met; the optional pinned-key check in the p2p layer (T-8) closes that for operator links.

pub mod cipher;
pub mod stream;

pub use cipher::{bitcoin_salt, zkas_salt};
pub use stream::{
    H2_PREFACE_PREFIX, HandshakeConfig, HandshakeError, MAX_PACKET_CONTENTS, SNIFF_LEN, Zkt2Stream, looks_like_h2_server_preface,
};
