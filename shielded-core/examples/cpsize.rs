//! Measure what checkpoint v10 removes, on REAL checkpoint files.
//!
//! Reads each `.scan` given on the command line, strips walletd's 77-byte header and
//! 8-byte blob length, restores the `WalletDb` under a throwaway key (a checkpoint holds
//! no key material — only public chain-derived state — so any valid seed restores the
//! public half), then re-serialises it both ways and reports the difference.
use kaspa_shielded_core::walletdb::WalletDb;

fn main() {
    let dummy = [0x11u8; 32];
    let (mut tot_old, mut tot_new, mut n) = (0u64, 0u64, 0u64);
    for path in std::env::args().skip(1) {
        let buf = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("{path}: unreadable: {e}");
                continue;
            }
        };
        if buf.len() < 85 || &buf[0..4] != b"FCWS" {
            println!("{path}: not a checkpoint");
            continue;
        }
        let db_len = u64::from_le_bytes(buf[77..85].try_into().unwrap()) as usize;
        let blob = &buf[85..85 + db_len];
        let Some(db) = WalletDb::from_checkpoint(dummy, blob) else {
            println!("{path}: does not restore");
            continue;
        };
        let old = db.to_checkpoint().len() as u64;
        let new = db.to_checkpoint_sharing(Some(db.nf_len())).len() as u64;
        println!(
            "{:<34} size={:<9} base={:<9} notes={:<6} nfs={:<9} blob {:>6.1} MB -> {:>6.1} MB  ({:.1}% smaller)",
            path.rsplit('/').next().unwrap(),
            db.size(),
            db.base_size(),
            db.notes().len(),
            db.nf_len(),
            old as f64 / 1048576.0,
            new as f64 / 1048576.0,
            100.0 * (old - new) as f64 / old as f64
        );
        tot_old += old;
        tot_new += new;
        n += 1;
    }
    println!(
        "\n{n} checkpoints: {:.2} GB -> {:.2} GB, saved {:.2} GB ({:.1}%)",
        tot_old as f64 / 1073741824.0,
        tot_new as f64 / 1073741824.0,
        (tot_old - tot_new) as f64 / 1073741824.0,
        100.0 * (tot_old - tot_new) as f64 / tot_old as f64
    );
}
