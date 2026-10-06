//! Cross-version proof corpus for Orchard dependency upgrades (the Zakura crates).
//!
//! A verifier difference between two versions splits the network, so an upgrade is accepted only
//! if both versions agree on the same proofs, in both directions:
//!
//! ```text
//! cargo run --release -p kaspa-shielded-core --features circuit --example proof_corpus -- make <n> <out>
//! cargo run --release -p kaspa-shielded-core --features circuit --example proof_corpus -- verify <file>...
//! ```
//!
//! A corpus line is `network_domain_hex tx_context_hex bundle_wire_hex`. `make` proves fresh bundles
//! with this build; `verify` checks every line with this build and also checks that each line fails
//! once tampered (a wrong sighash, and one flipped byte in each third of the wire). Exit status is
//! non-zero on any disagreement.

use kaspa_shielded_core::{bundle::ShieldedBundle, verify};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn check(net: &[u8; 32], ctx: &[u8], wire: &[u8]) -> bool {
    match ShieldedBundle::from_bytes(wire) {
        Ok(b) => verify::verify_bundle(&b, &verify::sighash(&b, net, ctx)).is_ok(),
        Err(_) => false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("make") => {
            let n: usize = args[2].parse().expect("count");
            let mut out = String::new();
            let net = [0x5au8; 32];
            for i in 0..n {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([0x77; 32]).expect("address");
                let ctx = format!("synthetic-{i}").into_bytes();
                let value = 1_000_000 + i as u64 * 7_919;
                // Alternate with and without a named anchor block, so both sighash shapes are covered.
                let anchor_block = (i % 2 == 1).then_some([i as u8; 32]);
                let wire = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend_anchored(
                    seed,
                    [i as u8; 32],
                    (i % 3) as u32,
                    value,
                    recipient,
                    value - 2_000,
                    &net,
                    &ctx,
                    anchor_block,
                )
                .expect("build");
                assert!(check(&net, &ctx, &wire), "a bundle this build just proved must verify with this build");
                out.push_str(&format!("{} {} {}\n", hex(&net), hex(&ctx), hex(&wire)));
            }
            std::fs::write(&args[3], out).expect("write corpus");
            println!("made {n} bundles -> {}", args[3]);
        }
        Some("verify") => {
            let (mut ok, mut bad, mut tamper_accepted, mut lines) = (0usize, 0usize, 0usize, 0usize);
            for file in &args[2..] {
                for line in std::fs::read_to_string(file).expect("read corpus").lines().filter(|l| !l.trim().is_empty()) {
                    lines += 1;
                    let mut parts = line.split_whitespace();
                    let net: [u8; 32] = unhex(parts.next().unwrap()).try_into().expect("32-byte domain");
                    let ctx = unhex(parts.next().unwrap());
                    let wire = unhex(parts.next().unwrap());
                    if check(&net, &ctx, &wire) {
                        ok += 1;
                    } else {
                        bad += 1;
                        println!("REJECTED honest line {lines} in {file}");
                    }
                    let mut wrong_ctx = ctx.clone();
                    wrong_ctx.push(0);
                    if check(&net, &wrong_ctx, &wire) {
                        tamper_accepted += 1;
                        println!("ACCEPTED wrong sighash, line {lines}");
                    }
                    for at in [wire.len() / 6, wire.len() / 2, wire.len() * 5 / 6] {
                        let mut t = wire.clone();
                        t[at] ^= 0x01;
                        if check(&net, &ctx, &t) {
                            tamper_accepted += 1;
                            println!("ACCEPTED flipped byte {at}, line {lines}");
                        }
                    }
                }
            }
            println!("lines={lines} verified={ok} rejected={bad} tampered_accepted={tamper_accepted}");
            if bad > 0 || tamper_accepted > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: proof_corpus make <n> <out> | verify <file>...");
            std::process::exit(2);
        }
    }
}
