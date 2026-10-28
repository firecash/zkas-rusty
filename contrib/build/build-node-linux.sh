#!/usr/bin/env bash
# Linux x86_64 node release archive, built on the 142 build box from one exact commit.
#
#   contrib/build/build-node-linux.sh <tag> [<commit>]      e.g. zkas-v1.0.13
#
# Windows: build-node-windows.sh (cross-built on 142). macOS: codemagic.yaml, workflow
# "macOS node". These replace the release:* jobs in .gitlab-ci.yml, which can no longer run:
# GitLab blocked the account in October 2026.
#
# 142 is Ubuntu 22.04 (glibc 2.35), so the archive runs on glibc 2.34+. Output, under
# $CI_ROOT/out/node-<version>/: zkas-<tag>-linux-amd64.zip (bin/<binaries> + bin/README.txt)
# and SHA256SUMS-linux-amd64.
#
# House rules for 142 (a shared box that also runs the live walletd): nice 19, bounded jobs,
# one heavy job at a time under /root/zkas/HEAVY.lock, a fresh work dir, no apt from here.
set -euo pipefail

TAG="${1:?usage: build-node-linux.sh <tag> [<commit>]}"
REF="${2:-$TAG}"
REPO="${REPO:-https://zkas.info/code/rusty.git}"
CI_ROOT="${CI_ROOT:-/root/zkas/ci}"
JOBS="${JOBS:-6}"
VER="${TAG#zkas-v}"
BINS=(kaspad:kaspad kaspa-shielded-pay:shielded-pay kaspa-stratum-bridge:stratum-bridge zkas-api:zkas-api kaspa-miner:zkas-miner zkas-walletd:zkas-walletd)

export PATH="/root/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$CI_ROOT/target-node-linux"

exec 9>/root/zkas/HEAVY.lock
flock 9

WORK="$CI_ROOT/node-linux-$(date -u +%Y%m%d-%H%M%S)"
git clone -q "$REPO" "$WORK"
git -C "$WORK" checkout -q "$REF"
SHA="$(git -C "$WORK" rev-parse HEAD)"
echo "building $TAG = $SHA"

cd "$WORK"
for pb in "${BINS[@]}"; do
  nice -n 19 cargo build --locked --release -j "$JOBS" -p "${pb%%:*}" --bin "${pb##*:}"
done

OUT="$CI_ROOT/out/node-$VER"
PKG="$OUT/linux-amd64"
rm -rf "$PKG" && mkdir -p "$PKG/bin"
for pb in "${BINS[@]}"; do cp "$CARGO_TARGET_DIR/release/${pb##*:}" "$PKG/bin/"; done
cp docs/RELEASE_README.txt "$PKG/bin/README.txt"
"$PKG/bin/kaspad" --version
echo "glibc floor: $(objdump -T "$PKG/bin/kaspad" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)"

ARCHIVE="zkas-$TAG-linux-amd64.zip"
python3 - "$PKG" "$OUT/$ARCHIVE" <<'PY'
import os, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    for n in sorted(os.listdir(os.path.join(src, "bin"))):
        p = os.path.join(src, "bin", n)
        i = zipfile.ZipInfo.from_file(p, "bin/" + n)
        i.compress_type = zipfile.ZIP_DEFLATED
        with open(p, "rb") as f:
            z.writestr(i, f.read())
PY
( cd "$OUT" && sha256sum "$ARCHIVE" | tee "SHA256SUMS-linux-amd64" )
echo "done: $OUT/$ARCHIVE ($TAG = $SHA)"
