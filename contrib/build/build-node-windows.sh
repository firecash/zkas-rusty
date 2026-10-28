#!/usr/bin/env bash
# Windows x86_64 node release archive, cross-compiled on the 142 build box from one exact commit.
#
# NOT the release path: releases build natively with MSVC on Codemagic (codemagic.yaml,
# workflow "Windows node"), as the GitLab release:win64 job did. This cross-build currently stops at
# the link step (risc0-zkvm-platform references sys_alloc_aligned, which only a zkVM guest defines);
# kept for development.
#
#   contrib/build/build-node-windows.sh <tag> [<commit>]      e.g. zkas-v1.0.13
#
# Target x86_64-pc-windows-msvc through cargo-xwin (Microsoft's CRT and SDK headers, linked
# with lld-link), the same toolchain as the wallet's Windows build. MSVC, not MinGW: no
# libstdc++/libgcc/winpthread DLL can end up in an exe; the DLL check at the end enforces it.
# kaspa-hashes is built with `no-asm` (pure-Rust keccak, identical output): its MSVC assembly
# needs ml64.exe, which does not exist on Linux.
#
# One-time host setup (done 2026-10-27): apt nsis lld-14 llvm-14; rustup target
# x86_64-pc-windows-msvc; cargo install --locked cargo-xwin.
#
# Output, under $CI_ROOT/out/node-<version>/: zkas-<tag>-win64.zip (bin/*.exe + bin/README.txt)
# and SHA256SUMS-win64. Same house rules as build-node-linux.sh.
set -euo pipefail

TAG="${1:?usage: build-node-windows.sh <tag> [<commit>]}"
REF="${2:-$TAG}"
REPO="${REPO:-https://zkas.info/code/rusty.git}"
CI_ROOT="${CI_ROOT:-/root/zkas/ci}"
JOBS="${JOBS:-6}"
VER="${TAG#zkas-v}"
RUST_TARGET=x86_64-pc-windows-msvc
BINS=(kaspad:kaspad kaspa-shielded-pay:shielded-pay kaspa-stratum-bridge:stratum-bridge zkas-api:zkas-api kaspa-miner:zkas-miner zkas-walletd:zkas-walletd)

export PATH="/root/.cargo/bin:/usr/lib/llvm-14/bin:$PATH"
export CARGO_TARGET_DIR="$CI_ROOT/target-node-windows"
# aws-lc-sys: use its bundled pre-assembled objects instead of needing nasm.
export AWS_LC_SYS_PREBUILT_NASM=1
# The Visual Studio 2019 (16) CRT/STL headers: the current ones (17) refuse any Clang older than 19
# ("STL1000: Unexpected compiler version"), and the box has Clang 14. Only C++ dependencies
# (RocksDB) notice; a separate cache dir keeps the wallet build's v17 download untouched.
export XWIN_VERSION=16 XWIN_CACHE_DIR="${XWIN_CACHE_DIR:-/root/.cache/cargo-xwin-16}"

missing=""
command -v cargo-xwin >/dev/null || missing="$missing cargo-xwin"
command -v llvm-readobj >/dev/null || missing="$missing llvm-14"
rustup target list --installed | grep -qx "$RUST_TARGET" || missing="$missing rustup-target:$RUST_TARGET"
[ -z "$missing" ] || { echo "missing build dependencies:$missing (install deliberately, then re-run)" >&2; exit 3; }

exec 9>/root/zkas/HEAVY.lock
flock 9

WORK="$CI_ROOT/node-windows-$(date -u +%Y%m%d-%H%M%S)"
git clone -q "$REPO" "$WORK"
git -C "$WORK" checkout -q "$REF"
SHA="$(git -C "$WORK" rev-parse HEAD)"
echo "building $TAG = $SHA for $RUST_TARGET"

cd "$WORK"
for pb in "${BINS[@]}"; do
  nice -n 19 cargo xwin build --locked --release -j "$JOBS" --target "$RUST_TARGET" \
    -p "${pb%%:*}" --bin "${pb##*:}" --features kaspa-hashes/no-asm
done

OUT="$CI_ROOT/out/node-$VER"
PKG="$OUT/win64"
rm -rf "$PKG" && mkdir -p "$PKG/bin"
for pb in "${BINS[@]}"; do cp "$CARGO_TARGET_DIR/$RUST_TARGET/release/${pb##*:}.exe" "$PKG/bin/"; done
cp docs/RELEASE_README.txt "$PKG/bin/README.txt"

# Every exe must import only system DLLs (and the MSVC runtime), nothing we would have to ship.
for exe in "$PKG"/bin/*.exe; do
  DLLS="$(llvm-readobj --coff-imports "$exe" | sed -n 's/^ *Name: //p' | sort -u)"
  BAD="$(echo "$DLLS" | grep -i -v -E '^(kernel32|user32|gdi32|advapi32|shell32|ole32|oleaut32|ws2_32|ntdll|bcrypt|bcryptprimitives|pdh|crypt32|secur32|userenv|shlwapi|version|winmm|iphlpapi|setupapi|cfgmgr32|dbghelp|powrprof|psapi|rpcrt4|wininet|winhttp|dnsapi|ncrypt|mswsock|api-ms-win-[a-z0-9-]+|vcruntime140(_1)?|msvcp140|ucrtbase)\.dll$' || true)"
  [ -z "$BAD" ] || { echo "UNEXPECTED DLL imports in $(basename "$exe"):"; echo "$BAD"; exit 4; }
  echo "$(basename "$exe"): $(echo "$DLLS" | tr '\n' ' ')"
done

ARCHIVE="zkas-$TAG-win64.zip"
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
( cd "$OUT" && sha256sum "$ARCHIVE" | tee "SHA256SUMS-win64" )
echo "done: $OUT/$ARCHIVE ($TAG = $SHA)"
