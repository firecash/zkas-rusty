#![cfg_attr(not(feature = "std"), no_std)]

//!
//! Kaspa [`Address`] implementation.
//!
//! In it's string form, the Kaspa [`Address`] is represented by a `bech32`-encoded
//! address string combined with a network type. The `bech32` string encoding is
//! comprised of a public key, the public key version and the resulting checksum.
//!

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::{
    cmp,
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    str,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smallvec::SmallVec;
use thiserror::Error;

#[cfg(feature = "wasm32-sdk")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm32-sdk")]
use workflow_wasm::convert::CastFromJs;

#[cfg(feature = "wasm32-sdk")]
mod wasm;
#[cfg(feature = "wasm32-sdk")]
pub use self::wasm::*;

mod bech32;

/// Error type produced by [`Address`] operations.
#[derive(Error, PartialEq, Eq, Debug, Clone)]
pub enum AddressError {
    #[error("The address has an invalid prefix {0}")]
    InvalidPrefix(String),
    #[error("The address prefix is missing")]
    MissingPrefix,
    #[error("The address has an invalid version {0}")]
    InvalidVersion(u8),
    #[error("The address has an invalid version {0}")]
    InvalidVersionString(String),
    #[error("The address contains an invalid character {0}")]
    DecodingError(char),
    #[error("The address checksum is invalid (must be exactly 8 bytes)")]
    BadChecksumSize,
    #[error("The address checksum is invalid")]
    BadChecksum,
    #[error("The address payload is invalid")]
    BadPayload,
    #[error("The address is invalid")]
    InvalidAddress,
    #[error("The address array is invalid")]
    InvalidAddressArray,
    #[error("{0}")]
    WASM(String),
}

/// Address prefix identifying the network type this address belongs to (such as `kaspa`, `kaspatest`, `kaspasim`, `kaspadev`).
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
pub enum Prefix {
    #[serde(rename = "zkas", alias = "firecash")]
    Mainnet,
    #[serde(rename = "zkastest", alias = "firecashtest")]
    Testnet,
    #[serde(rename = "zkassim", alias = "firecashsim")]
    Simnet,
    #[serde(rename = "zkasdev", alias = "firecashdev")]
    Devnet,
    /// Upstream **Kaspa** mainnet. Not a ZKas network: it exists only so
    /// merged mining can name the parent chain's coinbase recipient, since the
    /// Kaspa block we mine on top of must pay a real `kaspa:` address. Never
    /// returned by any ZKas network's `Params`, so it cannot be mistaken for
    /// one of our own networks.
    #[serde(rename = "kaspa")]
    KaspaMainnet,
    #[cfg(test)]
    A,
    #[cfg(test)]
    B,
}

impl Prefix {
    fn as_str(&self) -> &'static str {
        match self {
            Prefix::Mainnet => "zkas",
            Prefix::Testnet => "zkastest",
            Prefix::Simnet => "zkassim",
            Prefix::Devnet => "zkasdev",
            Prefix::KaspaMainnet => "kaspa",
            #[cfg(test)]
            Prefix::A => "a",
            #[cfg(test)]
            Prefix::B => "b",
        }
    }

    #[inline(always)]
    fn is_test(&self) -> bool {
        #[cfg(not(test))]
        return false;
        #[cfg(test)]
        matches!(self, Prefix::A | Prefix::B)
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Prefix {
    type Error = AddressError;

    fn try_from(prefix: &str) -> Result<Self, Self::Error> {
        match prefix {
            // ZKas is the canonical HRP; the pre-rebrand "firecash" HRPs remain
            // accepted forever so every address string issued before the rename
            // (miner payout configs, saved addresses) keeps parsing. Bech32
            // checksums are computed over the HRP actually present in the
            // string, so both spellings of the same key are valid, distinct
            // encodings of the same address.
            "zkas" | "firecash" => Ok(Prefix::Mainnet),
            "zkastest" | "firecashtest" => Ok(Prefix::Testnet),
            "zkassim" | "firecashsim" => Ok(Prefix::Simnet),
            "zkasdev" | "firecashdev" => Ok(Prefix::Devnet),
            "kaspa" => Ok(Prefix::KaspaMainnet),
            #[cfg(test)]
            "a" => Ok(Prefix::A),
            #[cfg(test)]
            "b" => Ok(Prefix::B),
            _ => Err(AddressError::InvalidPrefix(prefix.to_string())),
        }
    }
}

///
///  Kaspa `Address` version (`PubKey`, `PubKey ECDSA`, `ScriptHash`)
///
/// @category Address
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
#[cfg_attr(feature = "wasm32-sdk", wasm_bindgen(js_name = "AddressVersion"))]
pub enum Version {
    /// PubKey addresses always have the version byte set to 0
    PubKey = 0,
    /// PubKey ECDSA addresses always have the version byte set to 1
    PubKeyECDSA = 1,
    /// ScriptHash addresses always have the version byte set to 8
    ScriptHash = 8,
    /// ZKas shielded (Orchard) addresses have the version byte set to 9.
    /// The payload is the 43-byte raw Orchard address (diversifier ‖ pk_d). Such
    /// an address is never spent through a transparent script — it is the
    /// recipient of a shielded (Orchard) output — so it maps to no standard
    /// script class (PLAN §2.10).
    ShieldedOrchard = 9,
}

impl TryFrom<&str> for Version {
    type Error = AddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "PubKey" => Ok(Version::PubKey),
            "PubKeyECDSA" => Ok(Version::PubKeyECDSA),
            "ScriptHash" => Ok(Version::ScriptHash),
            "ShieldedOrchard" => Ok(Version::ShieldedOrchard),
            _ => Err(AddressError::InvalidVersionString(value.to_string())),
        }
    }
}

impl Version {
    pub fn public_key_len(&self) -> usize {
        match self {
            Version::PubKey => 32,
            Version::PubKeyECDSA => 33,
            Version::ScriptHash => 32,
            Version::ShieldedOrchard => 43,
        }
    }

    /// Whether this is a ZKas shielded (Orchard) address, which is paid via
    /// a shielded output rather than a transparent script.
    pub fn is_shielded(&self) -> bool {
        matches!(self, Version::ShieldedOrchard)
    }
}

impl TryFrom<u8> for Version {
    type Error = AddressError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::PubKey),
            1 => Ok(Version::PubKeyECDSA),
            8 => Ok(Version::ScriptHash),
            9 => Ok(Version::ShieldedOrchard),
            _ => Err(AddressError::InvalidVersion(value)),
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Version::PubKey => write!(f, "PubKey"),
            Version::PubKeyECDSA => write!(f, "PubKeyECDSA"),
            Version::ScriptHash => write!(f, "ScriptHash"),
            Version::ShieldedOrchard => write!(f, "ShieldedOrchard"),
        }
    }
}

/// Size of the payload vector of an address.
///
/// This size is the smallest SmallVec supported backing store size greater or equal to the largest
/// possible payload, which is 43 for [`Version::ShieldedOrchard`].
pub const PAYLOAD_VECTOR_SIZE: usize = 43;

/// Used as the underlying type for address payload, optimized for the largest version length (33).
pub type PayloadVec = SmallVec<[u8; PAYLOAD_VECTOR_SIZE]>;

/// Kaspa [`Address`] struct that serializes to and from an address format string: `kaspa:qz0s...t8cv`.
///
/// @category Address
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
#[cfg_attr(feature = "wasm32-sdk", derive(CastFromJs), wasm_bindgen(inspectable))]
pub struct Address {
    #[cfg_attr(feature = "wasm32-sdk", wasm_bindgen(skip))]
    pub prefix: Prefix,
    #[cfg_attr(feature = "wasm32-sdk", wasm_bindgen(skip))]
    pub version: Version,
    #[cfg_attr(feature = "wasm32-sdk", wasm_bindgen(skip))]
    pub payload: PayloadVec,
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.version == Version::PubKey {
            write!(f, "{}", String::from(self))
        } else {
            write!(f, "{} ({})", String::from(self), self.version)
        }
    }
}

impl Address {
    pub fn new(prefix: Prefix, version: Version, payload: &[u8]) -> Self {
        if !prefix.is_test() {
            assert_eq!(payload.len(), version.public_key_len());
        }
        Self { prefix, payload: PayloadVec::from_slice(payload), version }
    }

    pub fn short(&self, n: usize) -> String {
        let payload = self.encode_payload();
        let n = cmp::min(n, payload.len() / 4);
        format!("{}:{}....{}", self.prefix, &payload[0..n], &payload[payload.len() - n..])
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

//
// Borsh serializers need to be manually implemented for `Address` since
// smallvec does not currently support Borsh
//

impl BorshSerialize for Address {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.prefix, writer)?;
        borsh::BorshSerialize::serialize(&self.version, writer)?;
        // Vectors and slices are all serialized internally the same way
        borsh::BorshSerialize::serialize(&self.payload.as_slice(), writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Address {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let prefix: Prefix = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let version: Version = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let payload: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self::new(prefix, version, &payload))
    }
}

impl From<Address> for String {
    fn from(address: Address) -> Self {
        (&address).into()
    }
}

impl From<&Address> for String {
    fn from(address: &Address) -> Self {
        format!("{}:{}", address.prefix, address.encode_payload())
    }
}

impl TryFrom<String> for Address {
    type Error = AddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for Address {
    type Error = AddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.split_once(':') {
            Some((prefix, payload)) => Self::decode_payload(prefix.try_into()?, prefix, payload),
            None => Err(AddressError::MissingPrefix),
        }
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Default)]
        pub struct AddressVisitor<'de> {
            marker: PhantomData<Address>,
            lifetime: PhantomData<&'de ()>,
        }

        impl<'de> serde::de::Visitor<'de> for AddressVisitor<'de> {
            type Value = Address;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                write!(formatter, "string-type: string, str; bytes-type: slice of bytes, vec of bytes; map; number-type - pointer")
            }

            // TODO: see related comment in script_public_key.rs
            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u32(v as u32)
            }

            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u32(v as u32)
            }

            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u32(v as u32)
            }

            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u32(v as u32)
            }

            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use wasm_bindgen::convert::RefFromWasmAbi;

                let instance_ref = unsafe { Self::Value::ref_from_abi(v) }; // TODO: add checks for safecast
                Ok(instance_ref.clone())
            }

            #[cfg(all(feature = "wasm32-sdk", target_arch = "wasm32"))]
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u32(v as u32)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::try_from(v).map_err(serde::de::Error::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::try_from(v).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::try_from(v).map_err(serde::de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let str = str::from_utf8(v).map_err(serde::de::Error::custom)?;
                Address::try_from(str).map_err(serde::de::Error::custom)
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let str = str::from_utf8(v).map_err(serde::de::Error::custom)?;
                Address::try_from(str).map_err(serde::de::Error::custom)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let str = str::from_utf8(&v).map_err(serde::de::Error::custom)?;
                Address::try_from(str).map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut prefix: Option<String> = None;
                let mut payload: Option<String> = None;

                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    match key.as_ref() {
                        "prefix" => {
                            prefix = Some(value);
                        }
                        "payload" => {
                            payload = Some(value);
                        }
                        "version" => continue,
                        unknown_field => {
                            return Err(serde::de::Error::unknown_field(unknown_field, &["prefix", "payload", "version"]));
                        }
                    }
                    if prefix.is_some() && payload.is_some() {
                        break;
                    }
                }
                let (prefix, payload) = match (prefix, payload) {
                    (Some(prefix), Some(payload)) => (prefix, payload),
                    (None, _) => return Err(serde::de::Error::missing_field("prefix")),
                    (_, None) => return Err(serde::de::Error::missing_field("payload")),
                };
                Address::decode_payload(prefix.as_str().try_into().map_err(serde::de::Error::custom)?, prefix.as_str(), &payload)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(AddressVisitor::default())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::*;
    use alloc::vec;

    fn cases() -> Vec<(Address, &'static str)> {
        // cspell:disable
        vec![
            (Address::new(Prefix::A, Version::PubKey, b""), "a:qqeq69uvrh"),
            (Address::new(Prefix::A, Version::ScriptHash, b""), "a:pq99546ray"),
            (Address::new(Prefix::B, Version::ScriptHash, b" "), "b:pqsqzsjd64fv"),
            (Address::new(Prefix::B, Version::ScriptHash, b"-"), "b:pqksmhczf8ud"),
            (Address::new(Prefix::B, Version::ScriptHash, b"0"), "b:pqcq53eqrk0e"),
            (Address::new(Prefix::B, Version::ScriptHash, b"1"), "b:pqcshg75y0vf"),
            (Address::new(Prefix::B, Version::ScriptHash, b"-1"), "b:pqknzl4e9y0zy"),
            (Address::new(Prefix::B, Version::ScriptHash, b"11"), "b:pqcnzt888ytdg"),
            (Address::new(Prefix::B, Version::ScriptHash, b"abc"), "b:ppskycc8txxxn2w"),
            (Address::new(Prefix::B, Version::ScriptHash, b"1234598760"), "b:pqcnyve5x5unsdekxqeusxeyu2"),
            (Address::new(Prefix::B, Version::ScriptHash, b"abcdefghijklmnopqrstuvwxyz"), "b:ppskycmyv4nxw6rfdf4kcmtwdac8zunnw36hvamc09aqtpppz8lk"),
            (Address::new(Prefix::B, Version::ScriptHash, b"000000000000000000000000000000000000000000"), "b:pqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrq7ag684l3"),
            (Address::new(Prefix::Testnet, Version::PubKey, &[0u8; 32]),      "zkastest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq45699ch8"),
            (Address::new(Prefix::Testnet, Version::PubKeyECDSA, &[0u8; 33]), "zkastest:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz98werzk"),
            (Address::new(Prefix::Testnet, Version::PubKeyECDSA, b"\xba\x01\xfc\x5f\x4e\x9d\x98\x79\x59\x9c\x69\xa3\xda\xfd\xb8\x35\xa7\x25\x5e\x5f\x2e\x93\x4e\x93\x22\xec\xd3\xaf\x19\x0a\xb0\xf6\x0e"), "zkastest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrsvxgjus7t"),
            (Address::new(Prefix::Mainnet, Version::PubKey, &[0u8; 32]),      "zkas:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7fwd2pgv"),
            (Address::new(Prefix::Mainnet, Version::PubKey, b"\x5f\xff\x3c\x4d\xa1\x8f\x45\xad\xcd\xd4\x99\xe4\x46\x11\xe9\xff\xf1\x48\xba\x69\xdb\x3c\x4e\xa2\xdd\xd9\x55\xfc\x46\xa5\x95\x22"), "zkas:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jygc4lzm58"),
        ]
        // cspell:enable
    }

    /// Pre-rebrand `zkas:` strings (with checksums computed over the old
    /// HRP) must keep decoding to the same addresses forever — miner payout
    /// configs and saved addresses in the wild use them.
    fn legacy_decode_cases() -> Vec<(Address, &'static str)> {
        // cspell:disable
        vec![
            (Address::new(Prefix::Testnet, Version::PubKey, &[0u8; 32]),      "firecashtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp3032w74"),
            (Address::new(Prefix::Testnet, Version::PubKeyECDSA, &[0u8; 33]), "firecashtest:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5gf74dqw"),
            (Address::new(Prefix::Testnet, Version::PubKeyECDSA, b"\xba\x01\xfc\x5f\x4e\x9d\x98\x79\x59\x9c\x69\xa3\xda\xfd\xb8\x35\xa7\x25\x5e\x5f\x2e\x93\x4e\x93\x22\xec\xd3\xaf\x19\x0a\xb0\xf6\x0e"), "firecashtest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrs6txzs7un"),
            (Address::new(Prefix::Mainnet, Version::PubKey, &[0u8; 32]),      "firecash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqquzn95rkl"),
            (Address::new(Prefix::Mainnet, Version::PubKey, b"\x5f\xff\x3c\x4d\xa1\x8f\x45\xad\xcd\xd4\x99\xe4\x46\x11\xe9\xff\xf1\x48\xba\x69\xdb\x3c\x4e\xa2\xdd\xd9\x55\xfc\x46\xa5\x95\x22"), "firecash:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jy2nghue25"),
        ]
        // cspell:enable
    }

    #[test]
    fn check_legacy_firecash_hrp_still_decodes() {
        for (expected_address, address_str) in legacy_decode_cases() {
            let address: Address = address_str.to_string().try_into().expect("legacy zkas: address must decode");
            assert_eq!(address, expected_address);
            // Re-encoding emits the canonical zkas HRP, not the legacy one.
            let reencoded: String = address.into();
            assert!(reencoded.starts_with("zkas"), "re-encode must use the zkas HRP: {reencoded}");
        }
    }

    #[test]
    fn check_into_string() {
        for (address, expected_address_str) in cases() {
            let address_str: String = address.into();
            assert_eq!(address_str, expected_address_str);
        }
    }

    #[test]
    fn check_from_string() {
        for (expected_address, address_str) in cases() {
            let address: Address = address_str.to_string().try_into().expect("Test failed");
            assert_eq!(address, expected_address);
        }
    }

    /// A shielded (Orchard) address carries a 43-byte payload and round-trips
    /// through the string form under the zkas HRP, decoding back to the
    /// same version and payload.
    #[test]
    fn shielded_orchard_address_roundtrip() {
        let raw: [u8; 43] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let address = Address::new(Prefix::Mainnet, Version::ShieldedOrchard, &raw);
        assert_eq!(address.version, Version::ShieldedOrchard);
        assert!(address.version.is_shielded());
        assert_eq!(address.version.public_key_len(), 43);
        assert_eq!(address.payload.as_slice(), &raw[..]);

        // Encodes under the mainnet HRP and decodes back identically.
        let s: String = (&address).into();
        assert!(s.starts_with("zkas:"), "shielded address uses the zkas HRP: {s}");
        let decoded: Address = s.clone().try_into().expect("shielded address must decode");
        assert_eq!(decoded, address);
        assert_eq!(decoded.payload.as_slice(), &raw[..]);

        // The version byte and string tag are the shielded ones.
        assert_eq!(Version::ShieldedOrchard as u8, 9);
        assert_eq!(Version::try_from(9u8).unwrap(), Version::ShieldedOrchard);
        assert_eq!(Version::try_from("ShieldedOrchard").unwrap(), Version::ShieldedOrchard);
        assert!(!Version::PubKey.is_shielded());
    }

    #[test]
    fn test_errors() {
        // cspell:disable
        let address_str: String = "zkas:qqqqqqqqqqqqq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e".to_string();
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::DecodingError('1')), address);

        let invalid_char = 124u8 as char;
        let address_str: String = format!("zkas:qqqqqqqqqqqqq{invalid_char}qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e");
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::DecodingError(invalid_char)), address);

        let invalid_char = 129u8 as char;
        let address_str: String = format!("zkas:qqqqqqqqqqqqq{invalid_char}qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e");
        let address: Result<Address, AddressError> = address_str.try_into();
        assert!(matches!(address, Err(AddressError::DecodingError(_))));

        let address_str: String = "kaspa1:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e".to_string();
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::InvalidPrefix("kaspa1".into())), address);

        let address_str: String = "kaspaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e".to_string();
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::MissingPrefix), address);

        let address_str: String = "zkas:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4l".to_string();
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::BadChecksum), address);

        let address_str: String = "zkas:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e".to_string();
        let address: Result<Address, AddressError> = address_str.try_into();
        assert_eq!(Err(AddressError::BadChecksum), address);
        // cspell:enable
    }
}
