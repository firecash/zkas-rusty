//! `zkas-ckpt-rollback` — convert wallet checkpoints between the self-contained **v9**
//! form and the shared-nullifier **v10** form, offline.
//!
//! # Why this exists
//!
//! A v10 checkpoint references the chain-global spent-nullifier set instead of
//! embedding it, which is 103 GB of the 264 GB the live wallet directory holds. The
//! catch is that `WalletDb::restore` accepts only `V3..=CHECKPOINT_VERSION`, so a v10
//! file is *unreadable* to a pre-v10 binary. Without this tool, rolling the storage
//! change back — a bad deploy, a regression found a week later, a change of mind —
//! means every wallet rescans from scratch, and 2,000 simultaneous rescans is itself an
//! outage. This makes the rollback a file rewrite instead.
//!
//! It also runs the other way (`--to v10`), so re-applying the change after a rollback
//! does not mean waiting for the daemon to rewrite each wallet in its own time.
//!
//! # What it will not do
//!
//! - **It never writes to its input.** Inputs are opened read-only; output goes to a
//!   separate name (`<token>.scan.v9` / `<token>.scan.v10`) that can never collide with
//!   a live checkpoint, even if `--out-dir` is pointed at the live directory. Putting a
//!   converted file into service is an `mv` the operator runs, sees, and can reverse.
//! - **It never claims success it has not checked.** Every converted checkpoint is
//!   loaded back and must reproduce the input's `state_digest()` — same notes,
//!   positions, nullifier set, balance, stream size, anchor, history, pending spends —
//!   before the file is written. `to_checkpoint()` is not byte-deterministic, so bytes
//!   are not what is compared.
//! - **It never stops halfway in silence.** One wallet failing is reported by token and
//!   the run continues; the exit status and the summary say exactly what was converted.
//! - **It writes nothing without `--apply`.** The default run does the whole rewrite and
//!   the whole verification in memory and tells you what it would have done.
//!
//! It needs no node, no RPC and no running daemon — point it at a stopped daemon's
//! directory or at a copy.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use kaspa_shielded_core::walletdb::{RewriteError, WalletDb, checkpoint_nf_span, checkpoint_to_v9, checkpoint_to_v10};
use zkas_walletd::{ScanLayout, scan_layout, scan_with_blob};

/// The shared artefact's own token. Its checkpoint IS the artefact, so it is never
/// converted: a reference inside it would have nothing left to resolve against.
const CHAIN_TREE_FILE: &str = "__chain.tree__.scan";

#[derive(Parser, Debug)]
#[command(
    name = "zkas-ckpt-rollback",
    about = "Convert wallet checkpoints between v9 (self-contained) and v10 (shared nullifiers), offline and additively"
)]
struct Cli {
    /// Directory holding `<token>.scan` checkpoints. Read-only: nothing is ever
    /// written here unless you also point `--out-dir` at it, and even then only under
    /// a `.scan.v9` / `.scan.v10` name.
    #[arg(long)]
    dir: String,
    /// Direction: `v9` re-materialises the shared nullifiers (the rollback);
    /// `v10` sheds them again (the re-apply).
    #[arg(long, value_parser = ["v9", "v10"])]
    to: String,
    /// The shared artefact. Defaults to `<dir>/__chain.tree__.scan`.
    #[arg(long)]
    shared: Option<String>,
    /// Convert only these tokens (repeatable). Default: every `.scan` in `--dir`.
    #[arg(long = "token")]
    tokens: Vec<String>,
    /// Where converted files are written. Required by `--apply`; without it the run is
    /// a dry run whatever else is passed.
    #[arg(long)]
    out_dir: Option<String>,
    /// Actually write the converted files. Without this the tool does the entire
    /// rewrite and verification and writes nothing.
    #[arg(long)]
    apply: bool,
    /// Replace an existing output file of the same name. Never applies to a `.scan`.
    #[arg(long)]
    replace_output: bool,
    /// Wallets converted in parallel. Each one needs roughly 2.5x the checkpoint's
    /// size in RAM, and the biggest live checkpoint is ~500 MB.
    #[arg(long, default_value_t = 2)]
    jobs: usize,
    /// Header-only pass: what each checkpoint is and what it would cost, with no
    /// restore and no verification. For sizing a run, never for deciding one.
    #[arg(long)]
    survey: bool,
    /// Print `<token> <state digest>` for every checkpoint and stop. Converts nothing.
    /// Run it over the directory before a swap and over the directory after one: if the
    /// two listings are identical, no wallet lost anything, whatever the bytes did.
    #[arg(long)]
    digest_only: bool,
    /// Write the per-wallet outcome table here as JSON.
    #[arg(long)]
    json: Option<String>,
}

/// What happened to one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Rewritten and verified. (`applied` is false on a dry run.)
    Converted { applied: bool },
    /// Deliberately left alone, with the reason. Not an error.
    Skipped(String),
    /// Could not be converted. Reported and counted; the run continues.
    Failed(String),
}

impl Outcome {
    fn word(&self) -> &'static str {
        match self {
            Self::Converted { applied: true } => "CONVERTED",
            Self::Converted { applied: false } => "WOULD-CONVERT",
            Self::Skipped(_) => "SKIPPED",
            Self::Failed(_) => "FAILED",
        }
    }
    fn detail(&self) -> &str {
        match self {
            Self::Converted { .. } => "",
            Self::Skipped(r) | Self::Failed(r) => r,
        }
    }
}

#[derive(Debug, Clone)]
struct Row {
    token: String,
    in_version: Option<u8>,
    in_bytes: u64,
    out_bytes: u64,
    nullifiers: u64,
    notes: usize,
    balance: u128,
    size: u64,
    blind_below: u64,
    out_path: Option<String>,
    outcome: Outcome,
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(failed) => std::process::exit(if failed > 0 { 1 } else { 0 }),
        Err(e) => {
            eprintln!("zkas-ckpt-rollback: {e}");
            std::process::exit(2);
        }
    }
}

fn run(cli: &Cli) -> Result<usize, String> {
    let to_v10 = cli.to == "v10";
    let suffix = if to_v10 { ".scan.v10" } else { ".scan.v9" };
    let dir = Path::new(&cli.dir);
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", cli.dir));
    }
    let out_dir = match (&cli.out_dir, cli.apply) {
        (Some(d), _) => {
            let p = PathBuf::from(d);
            if !p.is_dir() {
                return Err(format!("{d} is not a directory"));
            }
            Some(p)
        }
        (None, true) => return Err("--apply needs --out-dir: say where the converted files go".into()),
        (None, false) => None,
    };
    let apply = cli.apply && out_dir.is_some();

    let targets = collect_targets(dir, &cli.tokens)?;
    if targets.is_empty() {
        return Err(format!("no .scan checkpoints in {}", cli.dir));
    }

    println!("zkas-ckpt-rollback: {} checkpoint(s) in {} -> {}", targets.len(), cli.dir, cli.to);
    if cli.survey {
        return survey(&targets, to_v10);
    }

    // The shared artefact, loaded once. Everything else is compared against it.
    let shared_path = cli.shared.clone().unwrap_or_else(|| dir.join(CHAIN_TREE_FILE).to_string_lossy().into_owned());
    let (shared, shared_genesis, shared_ordered) = load_shared(&shared_path)?;
    println!("shared artefact: {} — {} nullifiers ({:.2} GB if embedded per wallet)", shared_path, shared.len(), (shared.len() as f64 * 32.0) / 1e9);
    println!("                 genesis {}", hex(&shared_genesis));
    if !shared_ordered {
        println!();
        println!("NOTE: this artefact was written by a pre-v10 binary, so its nullifier log is NOT");
        println!("      in chain order. Only a wallet holding EXACTLY its whole set can be matched;");
        println!("      a wallet that is merely behind it cannot, and is reported as SKIPPED.");
        println!("      The cure is one keyless pass: rebuild the shared chain tree, then re-run.");
        if to_v10 {
            println!("      (This affects --to v10 only. --to v9 checks a recorded digest, not an order.)");
        }
    }
    if cli.digest_only {
        return digest_listing(&targets, &shared, cli.jobs.max(1));
    }
    if apply {
        println!("mode: APPLY — converted files are written to {} as <token>{}", out_dir.as_ref().expect("checked").display(), suffix);
    } else {
        println!("mode: DRY RUN — every checkpoint is rewritten and verified in memory; nothing is written");
    }
    println!();

    let next = AtomicUsize::new(0);
    let rows: Mutex<Vec<Row>> = Mutex::new(Vec::with_capacity(targets.len()));
    let jobs = cli.jobs.max(1);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((token, path)) = targets.get(i) else { break };
                    let out_path = out_dir.as_ref().map(|d| d.join(format!("{token}{suffix}")));
                    let row = convert_one(token, path, out_path.as_deref(), &shared, &shared_genesis, shared_ordered, to_v10, apply, cli.replace_output);
                    println!("{:>13}  {:<34} {}", row.outcome.word(), row.token, describe(&row));
                    let _ = std::io::stdout().flush();
                    rows.lock().expect("row lock").push(row);
                }
            });
        }
    });

    let mut rows = rows.into_inner().expect("row lock");
    rows.sort_by(|a, b| a.token.cmp(&b.token));
    summarise(&rows, apply, suffix);
    if let Some(p) = &cli.json {
        write_json(p, &rows).map_err(|e| format!("writing {p}: {e}"))?;
        println!("per-wallet table: {p}");
    }
    Ok(rows.iter().filter(|r| matches!(r.outcome, Outcome::Failed(_))).count())
}

/// Every `<token>.scan` in `dir`, minus the shared artefact itself.
fn collect_targets(dir: &Path, only: &[String]) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out = Vec::new();
    if !only.is_empty() {
        for t in only {
            out.push((t.clone(), dir.join(format!("{t}.scan"))));
        }
        return Ok(out);
    }
    for e in std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let name = e.file_name().to_string_lossy().into_owned();
        // Exactly `<token>.scan`. A quarantined `.scan.bak` / `.scan.stale-*` is not a
        // live checkpoint and is left alone; so is this tool's own output.
        let Some(token) = name.strip_suffix(".scan") else { continue };
        if name == CHAIN_TREE_FILE {
            continue;
        }
        out.push((token.to_string(), e.path()));
    }
    out.sort();
    Ok(out)
}

/// The shared nullifier set, in the artefact's own order, plus its genesis and whether
/// that order is chain order.
///
/// Only a **v10** artefact's log is in chain order. A v3-v9 one was written by a binary
/// that iterated a `HashSet`, so its first `n` entries are an arbitrary n-element subset
/// — which means a wallet that is merely *behind* it can never match, however healthy
/// both files are. Knowing this up front is the difference between "SKIPPED: rebuild the
/// chain tree once" and 1,998 lines of FAILED at 3am.
fn load_shared(path: &str) -> Result<(Vec<[u8; 32]>, [u8; 32], bool), String> {
    let buf = std::fs::read(path).map_err(|e| format!("reading shared artefact {path}: {e}"))?;
    let layout = scan_layout(&buf).ok_or_else(|| format!("{path} is not a readable .scan file"))?;
    let blob = layout.blob(&buf);
    let span = checkpoint_nf_span(blob).ok_or_else(|| format!("{path}'s body does not parse"))?;
    let db = WalletDb::from_checkpoint(verify_seed(), blob).ok_or_else(|| format!("{path} does not restore"))?;
    if db.nf_pending().is_some() {
        return Err(format!("{path} itself references a shared nullifier set — it cannot be the artefact"));
    }
    let n = db.nf_len();
    if n == 0 {
        return Err(format!("{path} holds no nullifiers"));
    }
    let nfs = db.nf_prefix(n).ok_or("shared artefact would not yield its own set")?;
    Ok((nfs, layout.genesis, span.version >= 10))
}

/// Convert one checkpoint, verify it, and (with `apply`) write it beside the original.
#[allow(clippy::too_many_arguments)]
fn convert_one(
    token: &str,
    path: &Path,
    out_path: Option<&Path>,
    shared: &[[u8; 32]],
    shared_genesis: &[u8; 32],
    shared_ordered: bool,
    to_v10: bool,
    apply: bool,
    replace_output: bool,
) -> Row {
    let mut row = Row {
        token: token.to_string(),
        in_version: None,
        in_bytes: 0,
        out_bytes: 0,
        nullifiers: 0,
        notes: 0,
        balance: 0,
        size: 0,
        blind_below: 0,
        out_path: out_path.map(|p| p.to_string_lossy().into_owned()),
        outcome: Outcome::Failed("not started".into()),
    };
    let buf = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            row.outcome = Outcome::Failed(format!("read {}: {e}", path.display()));
            return row;
        }
    };
    row.in_bytes = buf.len() as u64;
    let Some(layout) = scan_layout(&buf) else {
        row.outcome = Outcome::Failed("not a readable .scan file".into());
        return row;
    };
    row.blind_below = layout.blind_below;
    if &layout.genesis != shared_genesis {
        row.outcome = Outcome::Failed(format!("genesis {} does not match the shared artefact's {}", hex(&layout.genesis), hex(shared_genesis)));
        return row;
    }
    let blob = layout.blob(&buf);
    let Some(span) = checkpoint_nf_span(blob) else {
        row.outcome = Outcome::Failed("checkpoint body does not parse".into());
        return row;
    };
    row.in_version = Some(span.version);

    // Cheap refusals first, so the reason an operator reads is the useful one rather
    // than a digest mismatch three minutes later.
    if to_v10 {
        if span.version == 10 {
            row.outcome = Outcome::Skipped("already v10".into());
            return row;
        }
        if span.version != 9 {
            row.outcome = Outcome::Skipped(RewriteError::NotV9 { version: span.version }.to_string());
            return row;
        }
        if layout.blind_below > 0 {
            // One of the 11 fast-synced wallets whose view starts above the shared
            // base. Its set is a subset of the chain's, not a prefix, so the digest
            // check below would refuse it anyway — this just says so in plain words.
            row.outcome = Outcome::Skipped(format!("blind_below={}: this view is not a prefix of the shared set", layout.blind_below));
            return row;
        }
    } else if span.version != 10 {
        row.outcome = Outcome::Skipped(format!("already v{} — nothing to re-materialise", span.version));
        return row;
    }

    // The input's state, as the daemon would see it.
    let digest_in = {
        let Some(mut db) = WalletDb::from_checkpoint(verify_seed(), blob) else {
            row.outcome = Outcome::Failed("input does not restore".into());
            return row;
        };
        if db.nf_pending().is_some() && !db.install_shared_nullifiers(shared) {
            row.outcome = Outcome::Failed("input references a shared set this artefact does not reproduce".into());
            return row;
        }
        row.nullifiers = db.nf_len();
        row.notes = db.notes().len();
        row.balance = db.balance();
        row.size = db.size();
        db.state_digest()
        // `db` is dropped here: the output is restored on its own, so only one
        // multi-hundred-megabyte wallet is resident per job at a time.
    };

    let out_blob = match if to_v10 { checkpoint_to_v10(blob, shared) } else { checkpoint_to_v9(blob, shared) } {
        Ok(b) => b,
        Err(e @ (RewriteError::WalletAheadOfArtefact { .. } | RewriteError::NothingToShare)) => {
            // Normal, temporary, and nothing is wrong: not a failure.
            row.outcome = Outcome::Skipped(e.to_string());
            return row;
        }
        Err(RewriteError::DigestMismatch { count }) if to_v10 && !shared_ordered => {
            // Expected against a pre-v10 artefact and not this wallet's fault: its set
            // is fine, the artefact's ORDER is arbitrary, so only a wallet level with it
            // could ever have matched. Rebuild the chain tree once and re-run.
            row.outcome = Outcome::Skipped(format!("artefact is not in chain order (pre-v10 writer); cannot match a wallet at {count} — rebuild the chain tree first"));
            return row;
        }
        Err(e) => {
            row.outcome = Outcome::Failed(e.to_string());
            return row;
        }
    };

    // Everything outside the nullifier section must be the bytes we were given.
    let Some(out_span) = checkpoint_nf_span(&out_blob) else {
        row.outcome = Outcome::Failed("rewritten body does not parse".into());
        return row;
    };
    let want_version = if to_v10 { 10 } else { 9 };
    if out_span.version != want_version {
        row.outcome = Outcome::Failed(format!("rewritten body is v{}, expected v{want_version}", out_span.version));
        return row;
    }
    if out_blob[1..out_span.start] != blob[1..span.start] || out_blob[out_span.end..] != blob[span.end..] {
        row.outcome = Outcome::Failed("rewrite changed bytes outside the nullifier section".into());
        return row;
    }

    let out_buf = scan_with_blob(&buf, &layout, &out_blob);
    row.out_bytes = out_buf.len() as u64;
    // The envelope has to survive too: genesis, cursor, the matured ring, the blind
    // trailer. A wrong length prefix shows up here and nowhere else.
    match scan_layout(&out_buf) {
        Some(l2) if envelope_matches(&layout, &l2) => {}
        Some(_) => {
            row.outcome = Outcome::Failed("rewritten file's envelope differs from the original".into());
            return row;
        }
        None => {
            row.outcome = Outcome::Failed("rewritten file is not a readable .scan".into());
            return row;
        }
    }

    // And the whole point: it has to come back as the same wallet.
    {
        let Some(mut db) = WalletDb::from_checkpoint(verify_seed(), &out_blob) else {
            row.outcome = Outcome::Failed("rewritten checkpoint does not restore".into());
            return row;
        };
        if db.nf_pending().is_some() && !db.install_shared_nullifiers(shared) {
            row.outcome = Outcome::Failed("rewritten checkpoint's reference does not resolve against this artefact".into());
            return row;
        }
        if db.nf_len() != row.nullifiers {
            row.outcome = Outcome::Failed(format!("nullifier count {} != {}", db.nf_len(), row.nullifiers));
            return row;
        }
        if db.notes().len() != row.notes || db.balance() != row.balance || db.size() != row.size {
            row.outcome = Outcome::Failed(format!(
                "state differs: notes {}!={}, balance {}!={}, size {}!={}",
                db.notes().len(),
                row.notes,
                db.balance(),
                row.balance,
                db.size(),
                row.size
            ));
            return row;
        }
        let digest_out = db.state_digest();
        if digest_out != digest_in {
            row.outcome = Outcome::Failed(format!("state digest {} != {}", hex(&digest_out), hex(&digest_in)));
            return row;
        }
    }

    if !apply {
        row.outcome = Outcome::Converted { applied: false };
        return row;
    }
    let Some(out_path) = out_path else {
        row.outcome = Outcome::Converted { applied: false };
        return row;
    };
    match write_output(out_path, path, &out_buf, replace_output) {
        Ok(()) => row.outcome = Outcome::Converted { applied: true },
        Err(e) => row.outcome = Outcome::Failed(e),
    }
    row
}

/// Everything a `.scan` envelope carries except the blob's length.
fn envelope_matches(a: &ScanLayout, b: &ScanLayout) -> bool {
    a.scan_version == b.scan_version
        && a.genesis == b.genesis
        && a.low == b.low
        && a.scanned == b.scanned
        && a.boundaries == b.boundaries
        && a.sink_blue == b.sink_blue
        && a.blind_below == b.blind_below
}

/// Write the converted file: unique temp, fsync, rename, fsync the directory.
///
/// The name is checked here as well as built here. A bug that produced a bare `.scan`
/// path would overwrite a live wallet, so the one thing this function will not do is
/// write to a path that does not carry the tool's own suffix, or to its own input.
fn write_output(out_path: &Path, in_path: &Path, bytes: &[u8], replace: bool) -> Result<(), String> {
    let name = out_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !(name.ends_with(".scan.v9") || name.ends_with(".scan.v10")) {
        return Err(format!("refusing to write {name}: not a .scan.v9/.scan.v10 name"));
    }
    if out_path == in_path {
        return Err("refusing to write over the input".into());
    }
    if out_path.exists() && !replace {
        return Err(format!("{} already exists (pass --replace-output to replace it)", out_path.display()));
    }
    let tmp = PathBuf::from(format!("{}.tmp.{}", out_path.to_string_lossy(), std::process::id()));
    let cleanup = || {
        let _ = std::fs::remove_file(&tmp);
    };
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(bytes).inspect_err(|_| cleanup()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    f.sync_all().inspect_err(|_| cleanup()).map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, out_path).inspect_err(|_| cleanup()).map_err(|e| format!("rename to {}: {e}", out_path.display()))?;
    if let Some(d) = out_path.parent() {
        if let Ok(dh) = std::fs::File::open(d) {
            let _ = dh.sync_all();
        }
    }
    Ok(())
}

/// `<token> v<n> <state digest> notes=<n> bal=<n> size=<n> nfs=<n>` for every
/// checkpoint, sorted. Two of these listings are how an operator proves a swap did not
/// change any wallet: the digests must match line for line, even though the bytes will
/// not.
fn digest_listing(targets: &[(String, PathBuf)], shared: &[[u8; 32]], jobs: usize) -> Result<usize, String> {
    let next = AtomicUsize::new(0);
    let lines: Mutex<Vec<String>> = Mutex::new(Vec::with_capacity(targets.len()));
    let bad = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((token, path)) = targets.get(i) else { break };
                    let line = match digest_one(path, shared) {
                        Ok(l) => format!("{token}  {l}"),
                        Err(e) => {
                            bad.fetch_add(1, Ordering::Relaxed);
                            format!("{token}  UNREADABLE  {e}")
                        }
                    };
                    lines.lock().expect("lock").push(line);
                }
            });
        }
    });
    let mut lines = lines.into_inner().expect("lock");
    lines.sort();
    for l in &lines {
        println!("{l}");
    }
    Ok(bad.load(Ordering::Relaxed))
}

fn digest_one(path: &Path, shared: &[[u8; 32]]) -> Result<String, String> {
    let buf = std::fs::read(path).map_err(|e| e.to_string())?;
    let layout = scan_layout(&buf).ok_or("not a readable .scan")?;
    let blob = layout.blob(&buf);
    let span = checkpoint_nf_span(blob).ok_or("body does not parse")?;
    let mut db = WalletDb::from_checkpoint(verify_seed(), blob).ok_or("does not restore")?;
    if db.nf_pending().is_some() && !db.install_shared_nullifiers(shared) {
        return Err("references a shared set this artefact does not reproduce".into());
    }
    Ok(format!(
        "v{}  {}  notes={} bal={} size={} nfs={} anchor={}",
        span.version,
        hex(&db.state_digest()),
        db.notes().len(),
        db.balance(),
        db.size(),
        db.nf_len(),
        hex(&db.anchor())
    ))
}

/// What a survey needs from one checkpoint: its form, its size, and how many nullifier
/// bytes are in it.
struct SurveyRow {
    version: u8,
    blind_below: u64,
    file_bytes: u64,
    nf_bytes: u64,
    shared: bool,
}

/// Read a checkpoint's shape by **seeking** over its leaf stream rather than reading it.
///
/// A survey of the live directory is 264 GB if it reads every byte, on a box that is
/// also serving wallets. So this walks only the fixed-size prefix. It is a second reader
/// of a format this tool otherwise insists on having exactly one reader for, so it is
/// confined to the reporting path: it never decides a conversion and never produces a
/// byte. Everything that writes goes through `scan_layout` + `checkpoint_nf_span`.
fn survey_one(path: &Path) -> std::io::Result<Option<SurveyRow>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let file_bytes = f.metadata()?.len();
    let mut hdr = [0u8; 85];
    if f.read_exact(&mut hdr).is_err() || &hdr[0..4] != b"FCWS" || !matches!(hdr[4], 3 | 4) {
        return Ok(None);
    }
    let scan_version = hdr[4];
    let u64_at = |f: &mut std::fs::File| -> std::io::Result<u64> {
        let mut b = [0u8; 8];
        f.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    };
    let byte_at = |f: &mut std::fs::File| -> std::io::Result<u8> {
        let mut b = [0u8; 1];
        f.read_exact(&mut b)?;
        Ok(b[0])
    };
    let version = byte_at(&mut f)?;
    let _base_size = u64_at(&mut f)?;
    match byte_at(&mut f)? {
        0 => {}
        1 => {
            f.seek(SeekFrom::Current(32))?;
            let n_ommers = u64_at(&mut f)?;
            f.seek(SeekFrom::Current(n_ommers.min(1 << 20) as i64 * 32))?;
        }
        _ => return Ok(None),
    }
    let _size = u64_at(&mut f)?;
    let n_leaves = u64_at(&mut f)?;
    f.seek(SeekFrom::Current(n_leaves as i64 * 32))?;
    let n_notes = u64_at(&mut f)?;
    f.seek(SeekFrom::Current(n_notes as i64 * 155))?;
    let n = u64_at(&mut f)?;
    let (inline, shared) = if version >= 10 && n == u64::MAX {
        let _count = u64_at(&mut f)?;
        f.seek(SeekFrom::Current(32))?;
        (u64_at(&mut f)?, true)
    } else if n == u64::MAX {
        return Ok(None);
    } else {
        (n, false)
    };
    let blind_below = if scan_version == 4 && file_bytes >= 8 {
        f.seek(SeekFrom::End(-8))?;
        u64_at(&mut f)?
    } else {
        0
    };
    Ok(Some(SurveyRow { version, blind_below, file_bytes, nf_bytes: inline.saturating_mul(32), shared }))
}

/// Header-only pass: what is here and what a run would move, with no restore.
fn survey(targets: &[(String, PathBuf)], to_v10: bool) -> Result<usize, String> {
    let mut by_version: BTreeMap<String, (usize, u64, u64)> = BTreeMap::new();
    for (_, path) in targets {
        let (key, bytes, nf_bytes) = match survey_one(path) {
            Ok(Some(r)) => {
                let mut k = format!("v{}", r.version);
                if r.shared {
                    k.push_str(" shared");
                }
                if r.blind_below > 0 {
                    k.push_str(" blind");
                }
                (k, r.file_bytes, r.nf_bytes)
            }
            Ok(None) => ("unparsable".into(), std::fs::metadata(path).map(|m| m.len()).unwrap_or(0), 0),
            Err(_) => ("unreadable".into(), 0, 0),
        };
        let e = by_version.entry(key).or_insert((0, 0, 0));
        e.0 += 1;
        e.1 += bytes;
        e.2 += nf_bytes;
    }
    println!();
    println!("{:<14} {:>7} {:>14} {:>16}", "form", "files", "bytes", "nullifier bytes");
    for (k, (n, bytes, nf)) in &by_version {
        println!("{k:<14} {n:>7} {:>13.1}G {:>15.1}G", *bytes as f64 / 1e9, *nf as f64 / 1e9);
    }
    let movable: u64 = by_version.iter().filter(|(k, _)| k.starts_with(if to_v10 { "v9" } else { "v10" }) && !k.contains("blind")).map(|(_, v)| v.2).sum();
    println!();
    println!("a --to {} run would move about {:.1} GB of nullifier bytes", if to_v10 { "v10" } else { "v9" }, movable as f64 / 1e9);
    println!("(survey only: nothing was restored, nothing was verified)");
    Ok(0)
}

fn describe(row: &Row) -> String {
    let d = row.outcome.detail();
    if !d.is_empty() {
        return format!("v{}  {}", row.in_version.map(|v| v.to_string()).unwrap_or_else(|| "?".into()), d);
    }
    let delta = row.out_bytes as i64 - row.in_bytes as i64;
    format!(
        "v{} -> {}  {:.1}M -> {:.1}M ({}{:.1}M)  nfs {}  notes {}  bal {}",
        row.in_version.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        if row.in_version == Some(9) { "v10" } else { "v9" },
        row.in_bytes as f64 / 1e6,
        row.out_bytes as f64 / 1e6,
        if delta > 0 { "+" } else { "" },
        delta as f64 / 1e6,
        row.nullifiers,
        row.notes,
        row.balance
    )
}

fn summarise(rows: &[Row], apply: bool, suffix: &str) {
    let converted: Vec<&Row> = rows.iter().filter(|r| matches!(r.outcome, Outcome::Converted { .. })).collect();
    let skipped: Vec<&Row> = rows.iter().filter(|r| matches!(r.outcome, Outcome::Skipped(_))).collect();
    let failed: Vec<&Row> = rows.iter().filter(|r| matches!(r.outcome, Outcome::Failed(_))).collect();
    let in_bytes: u64 = converted.iter().map(|r| r.in_bytes).sum();
    let out_bytes: u64 = converted.iter().map(|r| r.out_bytes).sum();
    println!();
    println!("────────────────────────────────────────────────────────────────");
    println!("{:<12} {}", if apply { "converted" } else { "would convert" }, converted.len());
    println!("{:<12} {}", "skipped", skipped.len());
    println!("{:<12} {}", "failed", failed.len());
    println!("{:<12} {:.2} GB -> {:.2} GB  ({}{:.2} GB)", "bytes", in_bytes as f64 / 1e9, out_bytes as f64 / 1e9, if out_bytes > in_bytes { "+" } else { "-" }, (out_bytes as i64 - in_bytes as i64).abs() as f64 / 1e9);
    if !skipped.is_empty() {
        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        let keys: Vec<String> = skipped.iter().map(|r| r.outcome.detail().split_whitespace().take(4).collect::<Vec<_>>().join(" ")).collect();
        for k in &keys {
            *reasons.entry(k.as_str()).or_default() += 1;
        }
        println!();
        println!("skipped, by reason:");
        for (why, n) in reasons {
            println!("  {n:>5}  {why}");
        }
    }
    if !failed.is_empty() {
        println!();
        println!("FAILED — these wallets were NOT converted and their checkpoints are untouched:");
        for r in &failed {
            println!("  {}  {}", r.token, r.outcome.detail());
        }
    }
    println!();
    if apply && !converted.is_empty() {
        let d = converted[0].out_path.as_deref().unwrap_or("");
        let dir = Path::new(d).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        println!("The converted files are written and verified. NOTHING IS IN SERVICE YET.");
        println!("To put them in service (daemon stopped), from the wallet directory:");
        println!("  for f in {dir}/*{suffix}; do t=$(basename \"$f\" {suffix});");
        println!("    mv \"$t.scan\" \"$t.scan.pre-rollback\" && cp \"$f\" \"$t.scan\"; done");
        println!("To undo that, the original is still there under its own name:");
        println!("  for f in *.scan.pre-rollback; do mv \"$f\" \"${{f%.pre-rollback}}\"; done");
    } else if !apply {
        println!("Dry run: nothing was written. Re-run with --out-dir <DIR> --apply to write.");
    }
}

fn write_json(path: &str, rows: &[Row]) -> std::io::Result<()> {
    let mut s = String::from("[\n");
    for (i, r) in rows.iter().enumerate() {
        let (state, detail) = match &r.outcome {
            Outcome::Converted { applied } => (if *applied { "converted" } else { "would_convert" }, String::new()),
            Outcome::Skipped(d) => ("skipped", d.clone()),
            Outcome::Failed(d) => ("failed", d.clone()),
        };
        s.push_str(&format!(
            "  {{\"token\":\"{}\",\"state\":\"{}\",\"detail\":\"{}\",\"in_version\":{},\"in_bytes\":{},\"out_bytes\":{},\"nullifiers\":{},\"notes\":{},\"balance\":{},\"size\":{},\"blind_below\":{}}}{}\n",
            r.token,
            state,
            detail.replace('\\', "\\\\").replace('"', "\\\""),
            r.in_version.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            r.in_bytes,
            r.out_bytes,
            r.nullifiers,
            r.notes,
            r.balance,
            r.size,
            r.blind_below,
            if i + 1 == rows.len() { "" } else { "," }
        ));
    }
    s.push_str("]\n");
    std::fs::write(path, s)
}

/// A fixed, arbitrary spending key used only to hold a restored checkpoint.
///
/// A checkpoint carries **no key material** — notes are read back from their stored
/// raw parts, never decrypted — so any valid key restores the same public state. That
/// is what lets this tool verify a wallet it has no seed for, which is every wallet on
/// a hosted daemon.
fn verify_seed() -> [u8; 32] {
    static SEED: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        let mut seed = *b"zkas-ckpt-rollback-verify-seed-1";
        // Vanishingly unlikely, but a spending key that will not parse would take the
        // whole run down; walk to the next one rather than assume.
        for _ in 0..64 {
            if WalletDb::from_seed(seed).is_some() {
                return seed;
            }
            seed[31] = seed[31].wrapping_add(1);
        }
        panic!("no usable verification key");
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
