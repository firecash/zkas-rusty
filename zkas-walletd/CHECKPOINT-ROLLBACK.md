# Rolling the shared-nullifier checkpoint change back (and forward)

**For the person who has just decided the v10 storage change has to go. It is 3am.
Read the two paragraphs under "The one thing to know", then start at step 0.**

## The one thing to know

A **v10** checkpoint does not carry the chain-global spent-nullifier set; it carries a
48-byte reference to the daemon's shared chain tree, which is why the wallet directory
drops ~103 GB. A **pre-v10 binary refuses to load it** — `WalletDb::restore` accepts only
`V3..=CHECKPOINT_VERSION`. So rolling the daemon back without rewriting the checkpoints
means every wallet rescans from genesis, and ~2,000 simultaneous rescans is a worse
outage than whatever you are rolling back.

`zkas-ckpt-rollback` rewrites the checkpoints instead. It re-materialises the nullifier
bytes from the shared artefact, verifies that the rewritten file restores to **the same
wallet**, and writes it **beside** the original under a new name. It never touches its
input, it writes nothing without `--apply`, and one bad wallet does not stop the run.

## Step 0 — do not skip this

```
systemctl stop zkas-walletd            # the checkpoint on disk IS the wallet
df -h /                                # you need room for a second copy of what you convert
```

The daemon rewrites checkpoints while it runs. Converting underneath a live daemon gives
you files it will overwrite a minute later. Stop it first.

Keep the shared artefact safe before anything else — everything below depends on it:

```
cd /root/firecash/wallets
ln __chain.tree__.scan __chain.tree__.scan.keep-$(date +%Y%m%d-%H%M%S)   # hardlink: free, and pins the inode
```

## Step 1 — look, before you touch anything

```
zkas-ckpt-rollback --dir /root/firecash/wallets --to v9 --survey
```

Header-only: how many checkpoints there are, of which version, and how many bytes the
run would move. Nothing is restored and nothing is verified — this is for sizing, never
for deciding.

## Step 2 — the dry run (this is the real check)

```
zkas-ckpt-rollback --dir /root/firecash/wallets --to v9 --jobs 4 \
    --json /root/rollback-dryrun.json | tee /root/rollback-dryrun.log
```

This does **the entire conversion and the entire verification in memory** and writes
nothing. Every line is one wallet:

- `WOULD-CONVERT` — rewritten, loaded back, and proved to hold the same notes,
  positions, nullifier set, balance, stream size and anchor as the input.
- `SKIPPED` — deliberately left alone, with the reason. Not a problem.
- `FAILED` — could **not** be converted. The wallet's checkpoint is untouched. Read the
  reason; the common ones are in "When it refuses" below.

Read the summary at the bottom. **If the failed count is not zero, stop and read them
before you apply anything.** A handful of failures is survivable — those wallets stay on
v10 and you deal with them individually. A wall of them means the artefact is wrong, and
applying would convert nothing anyway.

Take the "before" fingerprint now, while the old files are still in place:

```
zkas-ckpt-rollback --dir /root/firecash/wallets --to v9 --digest-only --jobs 4 \
    > /root/before.digests
```

## Step 3 — write the converted files

```
mkdir -p /root/rollback-out
zkas-ckpt-rollback --dir /root/firecash/wallets --to v9 --jobs 4 \
    --out-dir /root/rollback-out --apply --json /root/rollback-apply.json \
    | tee /root/rollback-apply.log
```

Files land as `/root/rollback-out/<token>.scan.v9`. **Nothing is in service yet.** The
live directory is exactly as it was. `--out-dir` may be the live directory if you are
short of disk — the `.scan.v9` suffix means the tool still cannot collide with a live
checkpoint — but a separate directory is easier to reason about at 3am.

## Step 4 — put them in service

```
cd /root/firecash/wallets
for f in /root/rollback-out/*.scan.v9; do
  t=$(basename "$f" .scan.v9)
  mv "$t.scan" "$t.scan.pre-rollback" && cp "$f" "$t.scan"
done
```

The original v10 file is still there, under `<token>.scan.pre-rollback`. Nothing was
deleted. **To undo this step**, from the same directory:

```
for f in *.scan.pre-rollback; do mv "$f" "${f%.pre-rollback}"; done
```

## Step 5 — prove nothing was lost, then start

```
zkas-ckpt-rollback --dir /root/firecash/wallets --to v9 --digest-only --jobs 4 \
    > /root/after.digests
diff /root/before.digests /after.digests    # expect: only the v9/v10 column changes
```

Each line is `<token> v<n> <state digest> notes= bal= size= nfs= anchor=`. **The digests
must match line for line.** They will, even though the files are not byte-identical: a
checkpoint's nullifier section is written in a `HashSet`'s iteration order, which is not
reproducible, so bytes are not the thing to compare and never were.

Then:

```
systemctl start zkas-walletd
journalctl -u zkas-walletd -f | grep -iE "parked|divergent|rescan"
```

Expect **no** `parked` lines: a v9 checkpoint references nothing, so there is nothing
left to resolve. `rejecting divergent wallet checkpoint` on a wallet means that wallet
does not match the node's frontier at its cursor — unrelated to this rewrite, but if it
appears on *many* wallets at once, put the `.scan.pre-rollback` files back (step 4's
undo) and stop.

Only once the daemon is healthy, and not before:

```
cd /root/firecash/wallets && rm -f *.scan.pre-rollback    # optional, and irreversible
```

## Going the other way (re-applying the change)

Same shape, `--to v10`. It is how you re-apply the storage saving after a rollback
without waiting for the daemon to rewrite each wallet in its own time.

```
zkas-ckpt-rollback --dir /root/firecash/wallets --to v10 --jobs 4          # dry run
zkas-ckpt-rollback --dir /root/firecash/wallets --to v10 --jobs 4 \
    --out-dir /root/reapply-out --apply
```

**It will convert almost nothing until the shared chain tree has been rebuilt once.** A
chain tree restored from a pre-v10 checkpoint has its nullifier log in whatever order a
`HashSet` iterated, so its "first n" entries are an arbitrary subset and no wallet that
is merely *behind* it can match. The tool detects this from the artefact's version byte
and says so at the top of the run, and reports those wallets as `SKIPPED`, not `FAILED`.
The cure is one keyless pass — let the chain tree rebuild from genesis under a v10
binary — and then re-run. Individual wallets never need a rebuild: their side of the
comparison is a whole-set digest, which is order-independent.

## When it refuses

| It says | What it means | What to do |
|---|---|---|
| `no nullifiers to share` | The wallet has spent nothing yet. A 48-byte reference would be bigger than the nothing it replaces. | Nothing. |
| `checkpoint is v7, not v9` | A v7/v8 checkpoint. It is **not** re-tagged, on purpose: the history section is parsed differently at and above v9, so bumping the version byte would misread it. | Nothing. Those wallets are already self-contained. |
| `blind_below=N: this view is not a prefix of the shared set` | One of the 11 fast-synced wallets whose view starts above the shared base. Its nullifiers are a subset of the chain's, not a prefix. | Nothing. They keep their own copy, as they always have. |
| `artefact is not in chain order (pre-v10 writer)` | The `--to v10` case above. | Rebuild the chain tree, re-run. |
| `wallet holds N nullifiers, the shared set only M` | The wallet has run ahead of the artefact. | Nothing — the artefact catches up within a pass. Re-run later. |
| `shared set does not reproduce this wallet's own digest at N` (on `--to v9`) | **Real failure.** The artefact is not the set this checkpoint referenced: truncated, from another scan, or bit-rotted. | Do not proceed. Get the right `__chain.tree__.scan` (the hardlink from step 0, or a backup). This wallet cannot be rolled back without it. |
| `genesis X does not match the shared artefact's Y` | Wallet and artefact are from different chains. | You are pointing at the wrong directory or the wrong artefact. |
| `state digest ... != ...` | **Should never happen.** The rewrite produced a file that does not restore to the input's state. | Nothing was written for that wallet. Keep the log and the token; do not hand-edit the file. |

## Cost, measured on real checkpoints

| | |
|---|---|
| 496 MB checkpoint, 5.06 M nullifiers, 9 notes | 16 s to v10, 34 s back to v9; peak 2.1 GB RSS |
| 175 MB checkpoint, 5.06 M nullifiers, 3 notes | 175 MB → 13 MB (−92%) |
| 196 MB checkpoint, 1.39 M nullifiers, **274,013 notes** | 292 s — note-heavy wallets are dominated by Orchard note decompression in `restore`, not by the rewrite |

Budget roughly **2.5× the checkpoint's size in RAM per `--jobs` slot**, and plan on the
order of a minute per large wallet. `--jobs 4` on the 12-core box is comfortable; the
biggest checkpoint is ~500 MB, so `--jobs 8` is ~16 GB and not worth it.

## What the tool will not do

- It never writes to its input, and it refuses to write to any path that is not
  `<token>.scan.v9` / `<token>.scan.v10`.
- It writes nothing without `--apply`, and `--apply` without `--out-dir` is an error
  rather than a guess.
- It never claims a conversion it has not loaded back and checked.
- It never stops halfway: one wallet's failure is one line and the run continues.
- It never talks to a node. Point it at a stopped daemon's directory or at a copy.
