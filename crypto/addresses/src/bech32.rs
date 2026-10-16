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
        forge_hrp(prefix.as_str(), payload_u5)
    }

    /// [`forge`] under a literal HRP, so a legacy `firecash:` string carries a checksum valid for
    /// `firecash` (the checksum covers the HRP as written, not the canonical spelling).
    fn forge_hrp(hrp: &str, payload_u5: &[u8]) -> String {
        let fivebit_prefix = hrp.as_bytes().iter().copied().map(|c| c & 0x1fu8);
        let cs = checksum(payload_u5, fivebit_prefix);
        let body: Vec<u8> = payload_u5
            .iter()
            .copied()
            .chain(conv8to5(&cs.to_be_bytes()[3..]))
            .map(|c| CHARSET[c as usize])
            .collect();
        format!("{}:{}", hrp, String::from_utf8(body).unwrap())
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

        // The legacy HRP is no shortcut around the same checks. The forged checksum is valid for
        // `firecash` (a well-formed payload forged the same way decodes), so the refusal can only be
        // the length check, not the checksum.
        let well_formed = conv8to5(&[vec![Version::PubKey as u8], vec![0u8; 32]].concat());
        assert_eq!(
            Address::try_from(forge_hrp("firecash", &well_formed).as_str()),
            Ok(Address::new(Prefix::Mainnet, Version::PubKey, &[0u8; 32])),
            "the legacy forge carries a valid checksum"
        );
        assert!(
            matches!(Address::try_from(forge_hrp("firecash", &short).as_str()), Err(AddressError::InvalidPayloadLength { .. })),
            "a legacy-HRP payload of the wrong length is refused by the length check"
        );
    }

    /// TOTALITY. The two tests above pin the classes that were known to panic; this one
    /// pins the property, which is what a regression oracle has to do: for a checksum-valid
    /// string, `try_from` RETURNS -- `Ok` or `Err`, never a panic -- for every version byte
    /// and every payload length, and anything it accepts satisfies the length invariant.
    ///
    /// A panic here is not a failed parse, it is a dead node: the process-wide hook turns any
    /// panic into `exit(1)`, and this decoder sits behind unauthenticated input on the public
    /// gRPC node, walletd and the explorer. The sweep is exhaustive rather than random
    /// because the bug class was a length, and lengths are enumerable: 256 version bytes x
    /// 65 payload lengths is the whole space that mattered.
    ///
    /// The shape of the generator is adapted from the Phase-II closure harness in the
    /// third-party audit's POC collection (`regression/f2_bech32_closure.rs`), which ran the
    /// same oracle over 200,000 cases; the encoder here is the crate's own, so the inputs are
    /// exactly what the real encode path would produce.
    #[test]
    fn every_version_byte_and_payload_length_returns_rather_than_panics() {
        let mut decoded = 0usize;
        for version_byte in 0u8..=255 {
            for len in 0usize..=64 {
                let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(1)).collect();
                let u5 = conv8to5(&[vec![version_byte], payload].concat());
                let encoded = forge(Prefix::Mainnet, &u5);
                // The assertion is that this call RETURNS at all.
                if let Ok(address) = Address::try_from(encoded.as_str()) {
                    assert_eq!(
                        address.payload.len(),
                        address.version.public_key_len(),
                        "accepted an address whose payload contradicts its version: {encoded}"
                    );
                    decoded += 1;
                }
            }
        }
        // Sanity: the sweep really does reach the accepting path, so a decoder that rejected
        // everything could not pass this test by refusing to work.
        assert!(decoded >= 4, "the sweep should decode one address per known version, got {decoded}");
    }

    /// The same oracle over strings nobody generated on purpose: arbitrary charset noise, with
    /// and without a valid checksum, at every length around the 8-character checksum boundary
    /// where the first panic lived. Deterministic xorshift, so a failure is reproducible.
    #[test]
    fn arbitrary_strings_return_rather_than_panic() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000u32 {
            let len = (next() % 70) as usize;
            let body: Vec<u8> = (0..len).map(|_| CHARSET[(next() % 32) as usize]).collect();
            let body = String::from_utf8(body).expect("charset is ascii");
            // Raw noise: most of these fail the checksum, which is the point -- the early
            // paths (length, charset, checksum split) are where the indexing lived.
            let _ = Address::try_from(format!("zkas:{body}").as_str());
            let _ = Address::try_from(format!("zkastest:{body}").as_str());
            // And the same payload made checksum-VALID, which is how an attacker reaches the
            // code that assumes well-formedness.
            let u5: Vec<u8> = body.as_bytes().iter().map(|b| REV_CHARSET[*b as usize]).collect();
            let _ = Address::try_from(forge(Prefix::Mainnet, &u5).as_str());
        }
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
