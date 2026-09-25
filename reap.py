#!/usr/bin/env python3
"""Reap checkpoint orphans left by the from-birthday rescan loop (fixed 2026-09-24).

Deletes ONLY what is provably redundant:
  * .scan.bak whose live .scan has an equal or greater cursor — the bak has nothing to
    give back. A bak that is still AHEAD, or whose wallet has no live .scan at all, is
    kept: it is the only copy of that state.
  * .partial-* from the 2026-09-23 restore, where the live .scan IS the restored bak and
    is far ahead by construction.
  * .stale-*/.divergent-* quarantine older than 7 days — forensic copies that have
    outlived their purpose.

Nothing here is referenced by the running daemon; these names are all outside the
`token.scan` pattern it loads.
"""
import os, glob, struct, time, sys
D = "/root/firecash/wallets"
now = time.time()
apply = "--apply" in sys.argv

def cursor(p):
    try:
        with open(p, "rb") as f:
            b = f.read(77)
        return struct.unpack("<Q", b[69:77])[0] if len(b) >= 77 else None
    except OSError:
        return None

doomed = []
for f in glob.glob(f"{D}/*.scan.bak"):
    tok = os.path.basename(f)[:-len(".scan.bak")]
    live = f"{D}/{tok}.scan"
    if not os.path.exists(live):
        continue
    cb, cl = cursor(f), cursor(live)
    if cb is not None and cl is not None and cl >= cb:
        doomed.append(f)
doomed += glob.glob(f"{D}/*.partial-*")
doomed += [p for p in glob.glob(f"{D}/*.stale-*") + glob.glob(f"{D}/*.divergent-*")
           if now - os.path.getmtime(p) > 7 * 86400]

total = sum(os.path.getsize(p) for p in doomed)
print(f"{'REAPING' if apply else 'DRY RUN'}: {len(doomed)} files, {total/1024**3:.1f} GB")
freed = 0
for p in doomed:
    if apply:
        try:
            sz = os.path.getsize(p); os.remove(p); freed += sz
        except OSError as e:
            print(f"  skip {os.path.basename(p)}: {e}")
if apply:
    print(f"freed {freed/1024**3:.1f} GB")
