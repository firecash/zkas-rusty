//! The frontier almanac: one note-commitment tree frontier per DAA day, from genesis.
//!
//! A wallet starts its scan from the tree frontier just below its birthday. A pruned node
//! places that frontier only inside the window of history it validated itself; for an older
//! birthday it refuses ("lies in peer-supplied history"), and the wallet used to fall back to
//! scanning from genesis. Measured on the public node (2026-10-31): it places birthdays only
//! ~10.8 days back, and the genesis scan a 14-day-old phone wallet then ran took ~25 minutes,
//! ~2.6 GB of RAM and a ~745 MB checkpoint. That is restore, add account, rescan and every
//! switch to "run on this phone" for any wallet more than a week and a half old.
//!
//! The pruned node's refusal is about block BOUNDARIES (which leaves belong to which block are
//! unbound in history it took from a peer), not about the leaf SEQUENCE, which is complete and
//! verified. A frontier taken from a node that validated that history itself — an archival
//! node synced from genesis — is therefore a correct start, and the wallet still sees every
//! leaf after it from whatever node it talks to.
//!
//! The almanac is built into the binary (`almanac/frontier-almanac-mainnet.jsonl`, written by
//! `src/bin/frontier_almanac.rs`), so a phone needs no configuration. An old almanac is never
//! wrong, only less tight: the newest entry below a birthday is always a valid start, so a
//! release built weeks ago costs a slightly longer scan, never a genesis scan. An operator can
//! supply a fresher file with `ZKAS_FRONTIER_ALMANAC`.
//!
//! Trust: an entry is a claim about the public chain, carried by the same binary that already
//! holds the consensus rules. A wrong entry cannot move funds — a wallet whose tree diverges
//! fails closed at its first spend — and the caller confirms the entry's block is on the
//! node's selected chain before using it. Next step (not here): each entry carries the other
//! fields of the PoW-committed state root, so the wallet checks `R(frontier)` itself.
use kaspa_rpc_core::RpcHash;
use serde::Deserialize;
use std::sync::OnceLock;

/// Built-in almanac for mainnet. Refresh with `frontier_almanac <archival node>`.
const MAINNET: &str = include_str!("../almanac/frontier-almanac-mainnet.jsonl");

/// A scan start: `(chain block, its DAA score, tree size, last leaf, ommers)`, the shape
/// the birthday walk already returns.
pub(crate) type Start = (RpcHash, u64, u64, RpcHash, Vec<RpcHash>);

#[derive(Deserialize)]
struct Header {
    zkas_frontier_almanac: u32,
    genesis: String,
}

#[derive(Deserialize)]
struct Line {
    block: String,
    daa: u64,
    size: u64,
    leaf: String,
    ommers: Vec<String>,
}

pub(crate) struct Almanac {
    genesis: RpcHash,
    entries: Vec<Start>,
}

/// Parse an almanac. Strict: any malformed, out-of-order or foreign line rejects the whole
/// file, so a corrupted override can never supply a start.
pub(crate) fn parse(text: &str) -> Result<Almanac, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Header = serde_json::from_str(lines.next().ok_or("empty almanac")?).map_err(|e| format!("header: {e}"))?;
    if header.zkas_frontier_almanac != 1 {
        return Err(format!("unsupported almanac version {}", header.zkas_frontier_almanac));
    }
    let genesis: RpcHash = header.genesis.parse().map_err(|_| "header: bad genesis hash".to_string())?;
    let mut entries: Vec<Start> = Vec::new();
    for (i, text) in lines.enumerate() {
        let e: Line = serde_json::from_str(text).map_err(|err| format!("entry {i}: {err}"))?;
        let hash = |s: &str| s.parse::<RpcHash>().map_err(|_| format!("entry {i}: bad hash"));
        let ommers = e.ommers.iter().map(|o| hash(o)).collect::<Result<Vec<_>, _>>()?;
        // A frontier of a depth-32 tree has at most 32 ommers.
        if ommers.len() > 32 {
            return Err(format!("entry {i}: {} ommers", ommers.len()));
        }
        if let Some(&(_, prev_daa, prev_size, _, _)) = entries.last() {
            if e.daa <= prev_daa || e.size < prev_size {
                return Err(format!("entry {i}: not after the previous entry"));
            }
        }
        entries.push((hash(&e.block)?, e.daa, e.size, hash(&e.leaf)?, ommers));
    }
    if entries.is_empty() {
        return Err("no entries".into());
    }
    Ok(Almanac { genesis, entries })
}

impl Almanac {
    /// The newest entry strictly below `birthday`, if this almanac is for `genesis`'s network.
    /// Strictly below: the scan resumes AFTER the start block, so a note received in the
    /// birthday block itself is still seen.
    pub(crate) fn below(&self, genesis: &RpcHash, birthday: u64) -> Option<Start> {
        if &self.genesis != genesis {
            return None;
        }
        self.entries.iter().rev().find(|e| e.1 < birthday && e.2 > 0).cloned()
    }
}

fn loaded() -> &'static [Almanac] {
    static ALMANACS: OnceLock<Vec<Almanac>> = OnceLock::new();
    ALMANACS.get_or_init(|| {
        let mut v = Vec::new();
        if let Ok(file) = std::env::var("ZKAS_FRONTIER_ALMANAC") {
            match std::fs::read_to_string(&file).map_err(|e| e.to_string()).and_then(|t| parse(&t)) {
                Ok(a) => {
                    log::info!("frontier almanac: {} entries from ZKAS_FRONTIER_ALMANAC", a.entries.len());
                    v.push(a);
                }
                Err(e) => log::warn!("frontier almanac from ZKAS_FRONTIER_ALMANAC ignored: {e}"),
            }
        }
        match parse(MAINNET) {
            Ok(a) => v.push(a),
            Err(e) => log::error!("the built-in frontier almanac is invalid: {e}"),
        }
        v
    })
}

/// The newest almanac start strictly below `birthday` on `genesis`'s network, across the
/// built-in almanac and any operator-supplied one.
pub(crate) fn frontier_below(genesis: &RpcHash, birthday: u64) -> Option<Start> {
    loaded().iter().filter_map(|a| a.below(genesis, birthday)).max_by_key(|s| s.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_shielded_core::tree::FrontierState;
    use kaspa_shielded_core::walletdb::WalletDb;

    fn mainnet_genesis() -> RpcHash {
        RpcHash::from_bytes(kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes())
    }

    fn mini(lines: &[&str]) -> String {
        let g = mainnet_genesis();
        let mut s = format!("{{\"zkas_frontier_almanac\":1,\"genesis\":\"{g}\"}}\n");
        for l in lines {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    fn entry(daa: u64, size: u64, b: u8) -> String {
        let h = |x: u8| RpcHash::from_bytes([x; 32]);
        format!("{{\"block\":\"{}\",\"daa\":{daa},\"size\":{size},\"leaf\":\"{}\",\"ommers\":[]}}", h(b), h(b.wrapping_add(1)))
    }

    #[test]
    fn the_built_in_almanac_is_valid_and_for_mainnet() {
        let a = parse(MAINNET).expect("built-in almanac parses");
        assert_eq!(a.genesis, mainnet_genesis());
        assert!(a.entries.len() >= 90, "{} entries", a.entries.len());
    }

    /// Every entry must be a frontier a wallet can actually be built from — a malformed one
    /// would fail the restore it exists to rescue.
    #[test]
    fn every_built_in_entry_starts_a_wallet() {
        let a = parse(MAINNET).unwrap();
        for (i, (_, daa, size, leaf, ommers)) in a.entries.iter().enumerate() {
            let fs = FrontierState {
                size: *size,
                leaf: (*size > 0).then(|| leaf.as_bytes()),
                ommers: ommers.iter().map(|o| o.as_bytes()).collect(),
            };
            assert!(WalletDb::from_frontier([7u8; 32], &fs).is_some(), "entry {i} (daa {daa}) is not a valid frontier");
        }
    }

    #[test]
    fn lookup_takes_the_newest_entry_strictly_below_the_birthday() {
        let a = parse(&mini(&[&entry(100, 10, 1), &entry(200, 20, 2), &entry(300, 30, 3)])).unwrap();
        let g = mainnet_genesis();
        assert_eq!(a.below(&g, 250).map(|s| s.1), Some(200));
        assert_eq!(a.below(&g, 200).map(|s| s.1), Some(100), "strictly below: the birthday block itself is scanned");
        assert_eq!(a.below(&g, u64::MAX).map(|s| s.1), Some(300));
        assert!(a.below(&g, 100).is_none());
        assert!(a.below(&g, 0).is_none());
    }

    #[test]
    fn another_network_never_uses_it() {
        let a = parse(MAINNET).unwrap();
        assert!(a.below(&RpcHash::from_bytes([1u8; 32]), u64::MAX).is_none());
    }

    #[test]
    fn malformed_almanacs_are_rejected_whole() {
        assert!(parse("").is_err());
        assert!(parse(&mini(&[])).is_err(), "no entries");
        assert!(parse(&mini(&[&entry(200, 20, 2), &entry(100, 10, 1)])).is_err(), "out of order");
        assert!(parse(&mini(&[&entry(100, 20, 2), &entry(200, 10, 1)])).is_err(), "tree shrinks");
        assert!(parse(&mini(&[&entry(100, 10, 1), "{\"block\":\"zz\",\"daa\":5,\"size\":1,\"leaf\":\"00\",\"ommers\":[]}"])).is_err());
        let wrong_version = mini(&[&entry(100, 10, 1)]).replacen("\"zkas_frontier_almanac\":1", "\"zkas_frontier_almanac\":2", 1);
        assert!(parse(&wrong_version).is_err());
        let too_many: Vec<String> = (0..33).map(|i| format!("\"{}\"", RpcHash::from_bytes([i as u8; 32]))).collect();
        let big = format!(
            "{{\"block\":\"{}\",\"daa\":1,\"size\":1,\"leaf\":\"{}\",\"ommers\":[{}]}}",
            RpcHash::from_bytes([1; 32]),
            RpcHash::from_bytes([2; 32]),
            too_many.join(",")
        );
        assert!(parse(&mini(&[&big])).is_err());
    }
}
