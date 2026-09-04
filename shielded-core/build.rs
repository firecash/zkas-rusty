//! Bakes the identity of the Orchard / halo2 crates this build links into the
//! binary, read from the workspace `Cargo.lock` (name, version, crates.io sha256).
//!
//! `verify::CIRCUIT_VERSION` selects the circuit variant; these crates supply the
//! circuit itself. Together they determine the verifying key. Recording them
//! lets an operator (or a peer) check what a running node verifies against
//! without rebuilding it, and lets `verify::tests::orchard_stack_is_pinned`
//! fail loudly on any dependency bump that was not made on purpose.

use std::{env, fs, path::Path};

const CRATES: [(&str, &str); 2] = [("zakura-orchard", "ZKAS_ORCHARD_CRATE"), ("zakura-halo2-gadgets", "ZKAS_HALO2_GADGETS_CRATE")];

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let lock_path = Path::new(&manifest_dir).join("..").join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(&lock_path).unwrap_or_default();

    for (name, var) in CRATES {
        // Locate the `[[package]]` block whose `name` matches and read its
        // `version` and `checksum`. Line-based so CRLF checkouts parse too.
        let mut lines = lock.lines().map(str::trim_end).peekable();
        let mut ident = None;
        while let Some(line) = lines.next() {
            if line != format!("name = \"{name}\"") {
                continue;
            }
            let (mut version, mut checksum) = ("unknown".to_string(), "unknown".to_string());
            while let Some(&next) = lines.peek() {
                if next == "[[package]]" {
                    break;
                }
                let next = lines.next().unwrap();
                if let Some(v) = next.strip_prefix("version = \"") {
                    version = v.trim_end_matches('"').to_string();
                } else if let Some(c) = next.strip_prefix("checksum = \"") {
                    checksum = c.trim_end_matches('"').to_string();
                }
            }
            ident = Some(format!("{name} {version} {checksum}"));
            break;
        }
        println!("cargo:rustc-env={var}={}", ident.unwrap_or_else(|| format!("{name} unresolved")));
    }
}
