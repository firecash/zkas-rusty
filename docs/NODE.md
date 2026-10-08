# Running a ZKas node

`kaspad` is the ZKas node. Binaries are on the
[Releases](https://github.com/firecash/zkas-rusty/releases) page; to compile instead see
[docs/BUILDING.md](BUILDING.md).

```bash
./kaspad --appdir=./zkas-node --rpclisten=127.0.0.1:16810 --utxoindex
```

The node resolves the mainnet DNS seeder `seed.zkas.info`, dials every address it returns on
p2p port 16111, syncs, and follows the tip; once connected it discovers the rest of the
network through gossip. `--connect=<ip>:16111` pins it to specific peers instead (this
skips the seeder); `--addpeer` adds peers on top of it. Keep the RPC bound to `127.0.0.1`:
it is a control interface, not something to expose.

**DNS seeder (mainnet):** `seed.zkas.info` · currently resolves to `185.147.157.125` and
`160.187.211.153` (p2p `16111`)

### Ports

The current mainnet runs on the `161xx` block:

| Purpose | Port |
|---|---|
| RPC (gRPC) | **16810** (bind to loopback) |
| p2p | **16111** |

Only outbound access to a peer's **p2p** port (`16111`) is required to sync; inbound p2p is
optional (it lets others sync from you).

**Running ZKas and Kaspa on one host.** The RPC ports differ (ZKas `16810` vs Kaspa
`16110`), so those never clash. For p2p, ZKas separates the two things `16111` used to mean:
the node **listens on and advertises `16811`** by default (the free "8" block, no Kaspa
clash), while the port it **dials seed/peer addresses on stays `16111`** — that is where the
seed nodes and `seed.zkas.info` are, and the DNS seeder appends it to each bootstrap IP.
So a current-release node coexists with a Kaspa parent out of the box and still bootstraps.

Older binaries (≤ v1.0.7) defaulted p2p to `16111` for both, which collided with Kaspa. On
those, bind ZKas's p2p to a free port yourself — this changes only inbound; outbound
discovery still dials `16111`, so the node syncs normally:

```bash
./kaspad --appdir=./zkas-node --rpclisten=127.0.0.1:16810 --listen=0.0.0.0:16811 --utxoindex
```

---

## Pruned, archival, or shielded-history — which node do you need?

This is the part people get wrong, because ZKas keeps **two** kinds of history — the public
block data and the shielded note history — and they are pruned independently.

| | Pruned (default) | Pruned + `--shielded-history=off` | `--archival` |
|---|---|---|---|
| Public block bodies below the pruning point | discarded | discarded | **kept** |
| Notes/history from **before** the node first synced | **fetched + verified + kept** | **not fetched** | **fetched + verified + kept** |
| Notes/history from the node's **first sync onward** | **all kept forever** | all kept forever | all kept forever |
| Can fully validate the chain & every spend | ✅ | ✅ | ✅ |
| Serves wallet balances complete **since first sync** | ✅ | ✅ | ✅ |
| Serves wallet balances complete **back to genesis** | ✅ | ❌ | ✅ |
| Serves an explorer old **public** blocks/txs | ❌ | ❌ | ✅ |
| Disk | light + note archive | light | **heavy** |

### 1. Pruned node — the default, and what most people should run

A pruned node discards public block **bodies** below the pruning point, but it keeps two
shielded things **forever**:

- the **shielded consensus state** — the note-commitment tree frontier and the nullifier
  set — everything needed to fully validate the chain and every future spend; and
- the **per-block shielded scan archive** — the compact note/coinbase records a wallet
  replays to recover its balance.

The pruner **never touches the scan archive or the nullifier set**. Pruning deletes block
bodies, UTXO state and acceptance data; the scan archive is deliberately retained (ZKas
diverges from upstream here — "the reason is user funds"), along with a compact chain
index so the records can still be enumerated in chain order after the blocks themselves are
gone. So **from the moment a node first syncs, it writes and keeps the notes of every block
it processes, and never prunes them.** A restore-from-seed against a plain pruned node
returns a **complete** balance for everything at or after that node's first sync — wallet
recovery does not depend on an archival node existing somewhere on the network.

The one gap is history from **before** the node ever synced. IBD seeds a fresh node with
only the aggregate shielded state (a frontier plus a nullifier MuHash), which reveal no
one's notes, so a pruned node has no per-note archive below its **initial** pruning point.
A wallet that needs notes older than the node's first sync reads a **silently partial**
balance there — the number looks final but is a lower bound. That window, and only that
window, is what `--shielded-history` backfills — and it is **on by default** (see 2). A fresh
non-archival node still syncs genesis→tip to byte-identical state; archival is **not**
required for validation or mining.

### 2. `--shielded-history` — on by default, so a pruned node serves complete history

`--shielded-history=on|off` controls whether the node **fetches the shielded note history
below its pruning point** from peers during IBD. Since v1.0.7 it is **on for every node**,
pruned or archival — it is no longer tied to `--archival`. The fetched records survive
pruning like the rest of the scan archive, so a default pruned node serves wallets
**complete** history — full, correct balances back to genesis — while still pruning the
bulky public block bodies. That makes a plain pruned node the right shape for a wallet
backend (`zkas-walletd`) or a hosted wallet that does not also need to serve an explorer;
no extra flag is needed. The archive costs about 500 MB per ~1M chain blocks.

The fetched history is **verified before any of it is served**: the node replays it and
checks that it reproduces the node's own proof-of-work-committed shielded state, so a
dishonest peer cannot make wallets report wrong balances. At startup the node logs
`Shielded history: from DAA <n>, complete=<true|false>`; until the backfill logs
`shielded history: VERIFIED`, wallets born before the node's first sync see a partial
balance.

Turn it off only on a node that will never serve wallets:

```bash
./kaspad --appdir=./zkas-node --utxoindex --shielded-history=off
```

`--verify-shielded-history` is a separate, manual check, not needed for the p2p backfill:
on startup it replays the whole scan archive on disk against the node's anchored frontier
and reports the result (it deletes nothing). Use it after restoring an archive offline with
`zkas-scan-import`.

### 3. `--archival` — keep everything (explorers, full history)

```bash
./kaspad --appdir=./zkas-node --utxoindex --archival --rocksdb-preset=hdd
```

`--archival` stops the node from deleting **public** block data when the pruning point
advances, so it retains the complete block/transaction history — what a block explorer
needs. Shielded history is on here too, as on every node, so an archival node serves both
public and shielded history in full.

Two caveats worth knowing:

- **Archival only retains from now forward.** Enabling it on an already-pruned node does
  not backfill the blocks that were pruned before — it keeps everything from this point on.
  For a complete archive you must enable it on a node syncing from genesis (or import a
  full-history snapshot).
- It is **heavy on disk**. On spinning disks add `--rocksdb-preset=hdd` (larger write
  buffers, BlobDB, aggressive cold-data compression, an I/O rate limiter). See
  [docs/archival.md](archival.md) for the full RocksDB tuning.

---

## Flags reference

| Flag (env) | What it does |
|---|---|
| `--appdir=<dir>` (`KASPAD_APPDIR`) | Data directory. |
| `--rpclisten=<ip:port>` | Bind the gRPC RPC. Keep on `127.0.0.1`. |
| `--connect=<ip:port>` | Connect **only** to these peers (repeatable); skips the DNS seeder. Not needed to bootstrap. |
| `--addpeer=<ip:port>` | Add a persistent peer but still discover others (repeatable). |
| `--utxoindex` (`KASPAD_UTXOINDEX`) | Build the UTXO index (needed for some RPCs and address queries). |
| `--archival` (`KASPAD_ARCHIVAL`) | Retain old public block data past the pruning point. Heavy disk. |
| `--shielded-history=on\|off` | Fetch (and verify) shielded note history below the pruning point. Default: on for every node; `off` only for a node that will never serve wallets. |
| `--verify-shielded-history` | On startup, re-verify the whole scan archive on disk; reports only. For archives restored with `zkas-scan-import` — the p2p backfill always verifies itself. |
| `--rocksdb-preset=default\|hdd` | Storage tuning; `hdd` for archival nodes on spinning disks. |
| `--ram-scale=<f>` | Scale in-memory caches (e.g. `2.0` on a large box). |

Run `./kaspad --help` for the complete list.

---

## Recovery basics

- **Node won't start / corrupt DB:** stop the node, move the appdir aside, resync from a
  peer. A pruned node resyncs quickly; an archival node is slow — snapshot it instead of
  resyncing where possible.
- **Wallet balances look low for old coins after a resync:** the node lacks note history
  from *before it first synced* — it runs with `--shielded-history=off`, its backfill has
  not logged `VERIFIED` yet or stopped short of genesis, or it is older than v1.0.7, where
  the backfill was off by default on pruned nodes. Coins received since its first sync are
  complete; older ones read as a lower bound. Check the startup `Shielded history: ...
  complete=` line, let the backfill finish (one that stopped short is retried on a later
  IBD) or point the wallet at a node with complete history, and let the wallet rescan.
- **A node with `--shielded-history=off` is still fine for wallets whose coins are all newer
  than the node's first sync** — it keeps every note from that point on. Only balances
  reaching below its initial pruning point are partial.
