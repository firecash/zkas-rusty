use alloc::{string::String, vec, vec::Vec};

use crate::{Address, AddressError, Prefix};

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const REV_CHARSET: [u8; 123] = [
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 15, 100, 10, 17, 21,
    20, 26, 30, 7, 5, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 29, 100, 24, 13, 25, 9, 8, 23, 100, 18, 22,
    31, 27, 19, 100, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2,
];

// Checksome for bech32
// https://bch.info/en/specifications
fn polymod<I>(values: I) -> u64
where
    I: Iterator<Item = u8>,
{
    let mut c = 1u64;
    for d in values {
        let c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ (d as u64);

        if c0 & 0x01 != 0 {
            c ^= 0x98f2bc8e61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x79b76d99e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0xf33e5fb3c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0xae2eabe2a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x1e4f43e470;
        }
    }
    c ^ 1
}

fn checksum<I>(payload: &[u8], prefix: I) -> u64
where
    I: Iterator<Item = u8>,
{
    polymod(prefix.chain([0u8]).chain(payload.iter().copied()).chain([0u8; 8]))
}

// Convert 8bit array to 5bit array with right padding
fn conv8to5(payload: &[u8]) -> Vec<u8> {
    let padding = match payload.len().is_multiple_of(5) {
        true => 0,
        false => 1,
    };
    let mut five_bit = vec![0u8; payload.len() * 8 / 5 + padding];
    let mut current_idx = 0;

    let mut buff = 0u16;
    let mut bits = 0;
    for c in payload.iter() {
        buff = (buff << 8) | *c as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five_bit[current_idx] = (buff >> bits) as u8;
            buff &= (1 << bits) - 1;
            current_idx += 1;
        }
    }
    if bits > 0 {
        five_bit[current_idx] = (buff << (5 - bits)) as u8;
    }
    five_bit
}

// Convert 5 bit array to 8 bit array, ignore right side padding
fn conv5to8(payload: &[u8]) -> Vec<u8> {
    let mut eight_bit = vec![0u8; payload.len() * 5 / 8];
    let mut current_idx = 0;

    let mut buff = 0u16;
    let mut bits = 0;
    for c in payload.iter() {
        buff = (buff << 5) | *c as u16;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            eight_bit[current_idx] = (buff >> bits) as u8;
            buff &= (1 << bits) - 1;
            current_idx += 1;
        }
    }
    eight_bit
}

impl Address {
    pub(crate) fn encode_payload(&self) -> String {
        // Convert into 5 bits vector
        let fivebit_payload = conv8to5(&[[self.version as u8].as_slice(), self.payload.as_slice()].concat());
        let fivebit_prefix = self.prefix.as_str().as_bytes().iter().copied().map(|c| c & 0x1fu8);

        let checksum = checksum(fivebit_payload.as_slice(), fivebit_prefix);

        String::from_utf8(
            [fivebit_payload, conv8to5(&checksum.to_be_bytes()[3..])].concat().iter().map(|c| CHARSET[*c as usize]).collect(),
        )
        .expect("All character are valid utf-8")
    }

    /// `hrp` is the prefix string as it literally appears in the encoded
    /// address. The bech32 checksum is computed over that literal HRP, so a
    /// legacy `firecash:` string (which maps to the same [`Prefix`] as
    /// `zkas:`) verifies against its original checksum, not the canonical
    /// spelling's.
    pub(crate) fn decode_payload(prefix: Prefix, hrp: &str, address: &str) -> Result<Self, AddressError> {
        // From letters to bytes
        let mut err = Ok(());
        let address_u5 = address
            .as_bytes()
            .iter()
            .scan(&mut err, |err, b| match *REV_CHARSET.get(*b as usize).unwrap_or(&100) {
                100 => {
                    **err = Err(AddressError::DecodingError(*b as char));
                    None
                }
                i => Some(i),
            })
            .collect::<Vec<u8>>();
        err?;
        if address.len() < 8 {
            return Err(AddressError::BadPayload);
        }

        let (payload_u5, checksum_u5) = address_u5.split_at(address.len() - 8);
        let fivebit_prefix = hrp.as_bytes().iter().copied().map(|c| c & 0x1fu8);

        // Convert to number
        let checksum_ =
            u64::from_be_bytes([vec![0u8; 3], conv5to8(checksum_u5)].concat().try_into().map_err(|_| AddressError::BadChecksumSize)?);

        if checksum(payload_u5, fivebit_prefix) != checksum_ {
            return Err(AddressError::BadChecksum);
        }

        let payload_u8 = conv5to8(payload_u5);

        // A checksum is not authentication: anyone can compute one over any
        // payload, so the version byte and the payload length still have to agree
        // here. `Address::new` *asserts* that length, and the process-wide panic
        // hook turns any panic into `exit(1)` — so without these two checks every
        // caller that parses an address string (`getBalanceByAddress`,
        // `getUtxosByAddresses`, walletd's send path, the explorer's search box)
        // hands an unauthenticated peer a one-packet node kill.
        let (&version_byte, payload) = payload_u8.split_first().ok_or(AddressError::BadPayload)?;
        Self::try_new(prefix, version_byte.try_into()?, payload)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::Version;
    use alloc::{format, vec, vec::Vec};

    /// Build an address string with a VALID checksum over an arbitrary 5-bit
    /// payload — everything an attacker needs is the public charset.
    fn forge(prefix: Prefix, payload_u5: &[u8]) -> String {
        let fivebit_prefix = prefix.as_str().as_bytes().iter().copied().map(|c| c & 0x1fu8);
        let cs = checksum(payload_u5, fivebit_prefix);
        let body: Vec<u8> = payload_u5
            .iter()
            .copied()
            .chain(conv8to5(&cs.to_be_bytes()[3..]))
            .map(|c| CHARSET[c as usize])
            .collect();
        format!("{}:{}", prefix.as_str(), String::from_utf8(body).unwrap())
    }

    /// A checksum-valid string whose payload does not match its version byte is
    /// an ERROR, never a panic: the panic hook exits the process, so a panic here
    /// is a remote kill of every address-parsing service.
    #[test]
    fn checksum_valid_but_malformed_payload_is_an_error() {
        // No payload at all: the string is nothing but its checksum.
        assert_eq!(Address::try_from(forge(Prefix::Mainnet, &[]).as_str()), Err(AddressError::BadPayload));

        let bad_length = |payload_u5: &[u8]| {
            matches!(Address::try_from(forge(Prefix::Mainnet, payload_u5).as_str()), Err(AddressError::InvalidPayloadLength { .. }))
        };

        // Known version byte, payload too short (PubKey wants 32 bytes).
        let short = conv8to5(&[Version::PubKey as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(bad_length(&short), "payload too short");

        // Known version byte, payload too long (PubKeyECDSA wants 33 bytes).
        let long = conv8to5(&[vec![Version::PubKeyECDSA as u8], vec![7u8; 64]].concat());
        assert!(bad_length(&long), "payload too long");

        // A shielded payload under a transparent version byte (43 vs 32).
        let crossed = conv8to5(&[vec![Version::PubKey as u8], vec![3u8; 43]].concat());
        assert!(bad_length(&crossed), "shielded payload under a transparent version");

        // An unknown version byte keeps reporting the version error.
        let bad_version = conv8to5(&[vec![7u8], vec![0u8; 32]].concat());
        assert_eq!(Address::try_from(forge(Prefix::Mainnet, &bad_version).as_str()), Err(AddressError::InvalidVersion(7)));

        // The legacy HRP is no shortcut around the same checks.
        assert_eq!(Address::try_from(format!("firecash:{}", &forge(Prefix::Mainnet, &short)[5..]).as_str()).is_err(), true);
    }

    /// Every well-formed version still round-trips, so the length check cannot
    /// have been tightened past the real addresses.
    #[test]
    fn well_formed_addresses_still_decode() {
        for (version, len) in
            [(Version::PubKey, 32), (Version::PubKeyECDSA, 33), (Version::ScriptHash, 32), (Version::ShieldedOrchard, 43)]
        {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11).wrapping_add(3)).collect();
            let address = Address::new(Prefix::Mainnet, version, &payload);
            let encoded: String = (&address).into();
            assert_eq!(Address::try_from(encoded.as_str()).expect("round-trip"), address);
        }
    }
}
