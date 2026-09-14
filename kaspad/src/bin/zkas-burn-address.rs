//! zkas-burn-address — derive the canonical, trustless NUMS burn address.
//!
//! The transmission key `pk_d` is a hash output, so no private key for it can
//! exist (recovering the key = discrete log on Pallas; back-dooring it = second
//! preimage on BLAKE2b). Anyone can recompute this address from the two domain
//! strings below and confirm it byte-for-byte. Coins sent here are unspendable
//! by everyone, forever.

use blake2b_simd::Params;
use kaspa_addresses::{Address as KAddr, Prefix, Version};
use orchard::Address;

fn blake2b_prefix(domain: &[u8], counter: u64, n: usize) -> Vec<u8> {
    let h = Params::new()
        .hash_length(32)
        .to_state()
        .update(domain)
        .update(&counter.to_le_bytes())
        .finalize();
    h.as_bytes()[..n].to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    const PKD_DOMAIN: &[u8] = b"ZKas:burn:v1:pkd";
    const DIV_DOMAIN: &[u8] = b"ZKas:burn:v1:div";

    for i in 0u64..100_000 {
        let pk_d = blake2b_prefix(PKD_DOMAIN, i, 32);
        for j in 0u64..4_096 {
            let d = blake2b_prefix(DIV_DOMAIN, j, 11);
            let mut raw = [0u8; 43];
            raw[..11].copy_from_slice(&d);
            raw[11..].copy_from_slice(&pk_d);
            if bool::from(Address::from_raw_address_bytes(&raw).is_some()) {
                let kaddr = KAddr::new(Prefix::Mainnet, Version::ShieldedOrchard, &raw);
                let s: String = (&kaddr).into();
                println!("ZKas trustless NUMS burn address");
                println!("=================================");
                println!("  address : {s}");
                println!("  pk_d    : {} (pkd counter i={i})", hex(&pk_d));
                println!("  d       : {} (div counter j={j})", hex(&d));
                println!("  raw43   : {}", hex(&raw));
                println!();
                println!("Recompute recipe (fully deterministic, anyone can verify):");
                println!("  1. pk_d = smallest i>=0 such that blake2b256(\"ZKas:burn:v1:pkd\" || u64_le(i))[..32]");
                println!("            is a valid Orchard diversified transmission key (a point on Pallas).");
                println!("  2. d    = smallest j>=0 such that blake2b256(\"ZKas:burn:v1:div\" || u64_le(j))[..11]");
                println!("            forms a valid Orchard address together with that pk_d.");
                println!("  3. address = bech32(hrp=\"zkas\", version=9 ShieldedOrchard, payload = d(11) || pk_d(32)).");
                println!();
                println!("Why no key can exist:");
                println!("  pk_d is a BLAKE2b output, so its discrete log (the ivk needed to spend) is unknown");
                println!("  to everyone; and you cannot pick a string whose hash lands on a known-key point");
                println!("  (second preimage). The chain accepts it as a normal recipient, but no one can spend it.");
                return;
            }
        }
    }
    eprintln!("no valid address found within search bound (unexpected)");
    std::process::exit(1);
}
