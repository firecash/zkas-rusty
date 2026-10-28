# Building ZKas from source

Tested on **Ubuntu 24.04 (x86-64)**. Any recent Linux with a Rust toolchain works.

## Do you need to build?

Prebuilt Linux x86-64 binaries are on the
[Releases](https://zkas.info/downloads/node/) page. They are built on Ubuntu
24.04 and therefore need **glibc ≥ 2.38**, so they run on Ubuntu 24.04+ and other current
distros. On anything older — Ubuntu 22.04 (glibc 2.35), Debian 12 — they fail with
`GLIBC_2.38 not found`. Build from source there; it works on any recent Linux.

Windows: see [BUILDING-WINDOWS.md](BUILDING-WINDOWS.md).

## 1. System dependencies

```bash
sudo apt-get update
sudo apt-get install -y curl git build-essential pkg-config libssl-dev protobuf-compiler clang
```

`protobuf-compiler` is not optional — the gRPC crates generate their client at build time
and fail with `Could not find protoc` without it.

## 2. Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

The repo pins its toolchain in `rust-toolchain.toml`, so rustup selects the right version
on first build. Don't override it.

## 3. Clone and compile

```bash
git clone https://zkas.info/code/rusty.git
cd zkas-rusty

# node-side binaries only:
cargo build --release -p kaspad -p miner -p zkas-walletd -p zkas-api

# or everything:
cargo build --release
```

Binaries land in `target/release/`.

The first build compiles every dependency — RocksDB, Halo 2, the Orchard circuit — and
takes **10–20 minutes**. Later builds are incremental and much faster.

## 4. Tests

```bash
cargo test --release
```

Release profile is deliberate: several consensus and shielded tests build real Halo 2
proofs, and a debug build makes them slow enough to look hung.

## Notes

- **Memory.** A release build wants roughly 8 GB. On a smaller machine, limit parallelism
  with `cargo build --release -j 2` rather than letting the linker get OOM-killed.
- **Disk.** `target/` reaches several GB. Don't build on a partition that also holds node
  data unless you have room for both.
- **Don't build on a machine running a live node.** Compiling competes for the cores the
  node needs to keep up with the tip, and the disk it needs to write to.
