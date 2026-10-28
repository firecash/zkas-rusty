# Building the Windows release (MinGW cross-compile)

How the `zkas-windows-x86_64-*.zip` release asset is produced, why it is built
this way, and the one linker pitfall that will silently break the binaries if
the setup below is ever removed.

## Two ways to build for Windows

1. **MSVC cross-build on the build box (what releases use).**
   `contrib/build/build-node-windows.sh <tag>` builds `x86_64-pc-windows-msvc` with
   cargo-xwin and lld-link, and refuses an exe that imports a non-system DLL. MSVC links
   against the Windows C++ runtime, so the entire libstdc++ problem below does not exist
   there. (The GitLab CI job it replaces no longer runs: GitLab blocked the account in
   October 2026.)
2. **Local cross-compile from Linux (what v0.3.0 shipped).** Used when CI is
   not available. Target `x86_64-pc-windows-gnu` with the MinGW-w64 toolchain.
   Everything in this document is about this path.

## Prerequisites (Debian/Ubuntu build host)

```bash
apt install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
```

Use the **-posix** variants of the toolchain (`x86_64-w64-mingw32-g++-posix`):
the win32-thread variants lack the pthread support tokio/std need.

## The one command

All target-specific configuration is persisted in `.cargo/config.toml`
(`[target.x86_64-pc-windows-gnu]`: linker + rustflags), so a release build is
just:

```bash
cargo build --release --target x86_64-pc-windows-gnu \
  --bin kaspad --bin zkas-miner --bin zkas-walletd --bin zkas-api --bin shielded-pay
```

On a shared/production host, wrap it in `nice -n 19` and cap parallelism
(`-j 2`) so live services aren't starved, and run it inside tmux so it
survives an SSH drop.

**Do not set `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS` in the
environment.** Env vars override `.cargo/config.toml` (dropping the fix
below), and any change to effective RUSTFLAGS invalidates cargo's fingerprints
for the whole target — turning a 2-minute relink into a 30+ minute full
recompile.

## The libstdc++-6.dll pitfall (read before touching the linker flags)

Symptom: `kaspad.exe` (or any RocksDB-linking binary) builds fine but dies on
a user's machine with *"libstdc++-6.dll was not found"*.

Cause, step by step:

- `librocksdb-sys`'s build script emits `cargo:rustc-link-lib=stdc++`, i.e. an
  explicit `-lstdc++` on the final link line. Only binaries that link RocksDB
  (`kaspad`, `stratum-bridge`) are affected.
- MinGW ships libstdc++ twice: `libstdc++.a` (static) and `libstdc++.dll.a`
  (import library → runtime dependency on `libstdc++-6.dll`). GNU ld prefers
  the import library.
- The usual fixes don't work here: `-static-libstdc++` is a *g++ driver* flag
  (it only affects the C++ runtime the driver adds implicitly, not an explicit
  `-l`), and `-Clink-arg=-static` is *positional* — rustc appends link-args
  after the `-lstdc++` it already placed, which is too late.

The fix that works — a **static-only search path**: a directory containing
*only* `libstdc++.a` (no `.dll.a`), passed via `-L`. Library search directories
are position-independent and searched before the toolchain defaults, so
`-lstdc++` physically cannot resolve to the import library.

This is wired into `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-g++-posix"
rustflags = ["-Clink-arg=-static", "-Clink-arg=-static-libstdc++",
             "-Clink-arg=-static-libgcc", "-L", "/root/work/winlibs"]
```

and `/root/work/winlibs/` holds a single file copied from the toolchain:

```bash
mkdir -p /root/work/winlibs
cp /usr/lib/gcc/x86_64-w64-mingw32/13-posix/libstdc++.a /root/work/winlibs/
```

(On a new build host, recreate that directory from whatever gcc-mingw version
is installed — adjust the `13-posix` path.)

## Verification gate — run before shipping ANY zip

Every exe must import only Windows system DLLs (KERNEL32, ws2_32, bcrypt, …).
Any MinGW runtime DLL means do not ship:

```bash
for f in *.exe; do
  x86_64-w64-mingw32-objdump -p "$f" | grep -i "DLL Name" \
    | grep -iE "libstdc|libgcc|winpthread" && echo "DIRTY: $f" || echo "CLEAN: $f"
done
```

This gate exists because the v0.3.0 zip originally shipped with a dirty
`kaspad.exe` and had to be rebuilt and re-uploaded.

## Packaging

Layout used by the published asset (and expected by users):

```
zkas-windows-x86_64-<tag>/
  kaspad.exe  zkas-miner.exe  zkas-walletd.exe  zkas-api.exe
  shielded-pay.exe  stratum-bridge.exe  RUN-WINDOWS.txt
```

```bash
zip -r zkas-windows-x86_64-<tag>.zip zkas-windows-x86_64-<tag>
# then publish it under https://zkas.info/downloads/node/<version>/ with its SHA256SUMS
```

## Note on the pool bridge

The `stratum-bridge` in *this* repo has no shielded-proof dependency and
cross-compiles cleanly. The pool repo's bridge additionally needs
`/root/work/winlibs/risc0_host_stubs.o` (already in that repo's
`.cargo/config.toml` rustflags) because its risc0 host library does not build
for windows-gnu; the stubs make it link, so stratum bridging works but the
shielded-proof path is untested on Windows — production pools run the Linux
build.
