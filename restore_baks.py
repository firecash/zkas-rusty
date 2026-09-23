#!/usr/bin/env python3
"""Give back the checkpoints the from-birthday rescan loop threw away.

For each wallet whose .scan.bak is far AHEAD of its live .scan, put the .bak back and
keep the partial rescan beside it. Nothing is deleted: the partial becomes
.scan.partial-<stamp>, so this is reversible in both directions.

Safe by construction even if a .bak is wrong — walletd verifies every restored
checkpoint against the node's frontier at its own cursor on load, and quarantines one
that does not match, exactly as it does for any other checkpoint. The worst case is the
wallet rebuilds, which is what it is doing right now anyway.
"""
import os, struct, glob, shutil, sys, time

D = '/root/firecash/wallets'
MIN_GAP = 50_000
stamp = time.strftime('%Y%m%d-%H%M%S')
apply = '--apply' in sys.argv

def hdr(path):
    try:
        with open(path, 'rb') as f:
            b = f.read(77)
        if len(b) < 77 or b[0:4] != b'SCAN':
            # magic is checked by the daemon; read the cursor regardless
            pass
        return {'ver': b[4], 'genesis': b[5:37], 'scanned': struct.unpack('<Q', b[69:77])[0]}
    except Exception:
        return None

restored, skipped = [], []
for bak in sorted(glob.glob(f'{D}/*.scan.bak')):
    token = os.path.basename(bak)[:-len('.scan.bak')]
    cur = f'{D}/{token}.scan'
    hb = hdr(bak)
    if not hb:
        continue
    hc = hdr(cur) if os.path.exists(cur) else None
    gap = hb['scanned'] - (hc['scanned'] if hc else 0)
    if gap < MIN_GAP:
        continue
    if hc and hb['genesis'] != hc['genesis']:
        skipped.append((token, 'genesis differs'))
        continue
    if hc and hb['ver'] != hc['ver']:
        skipped.append((token, f"format {hc['ver']} vs {hb['ver']}"))
        continue
    live = hc['scanned'] if hc else 0
    if apply:
        if hc:
            os.replace(cur, f'{cur}.partial-{stamp}')
        shutil.copy2(bak, cur)
    restored.append((token, live, hb['scanned'], gap))

print(f"{'RESTORED' if apply else 'DRY RUN — would restore'}: {len(restored)} wallet(s)")
for t, live, bakv, gap in sorted(restored, key=lambda r: -r[3]):
    print(f'  {t[:12]}…  {live:>9} -> {bakv:>9}   (+{gap:,} blocks)')
if skipped:
    print(f'skipped {len(skipped)}:')
    for t, why in skipped:
        print(f'  {t[:12]}…  {why}')
print(f'\ntotal blocks of rescanning avoided: {sum(r[3] for r in restored):,}')
if apply:
    print(f'partials kept as *.scan.partial-{stamp}')
