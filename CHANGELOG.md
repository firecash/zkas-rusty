# ZKas node changelog

Releases of [zkas-rusty](https://zkas.info/code/rusty) (node, wallet daemon, miner, explorer API,
CLI wallet, Stratum bridge). Downloads and checksums: <https://zkas.info/downloads/node/>.
Every tag is on Radicle (`zkas-v<version>`). **Mainnet requires zkas-v1.0.11 or newer**: the
security fork activated at DAA 6,983,500 on 15 October 2026, and older nodes cannot follow it.

## zkas-v1.0.13 — 2026-10-28

Commit `7d892c81`. No consensus change: runs alongside v1.0.11 and v1.0.12 nodes. Recommended for
every node and wallet operator. **Windows and macOS builds are back** (Linux x86_64, Windows
x86_64, macOS Apple Silicon and Intel); the earlier ones were lost with the GitHub account.

**Node**
- Initial sync moves less data: a peer can serve the pruning-point proof deduplicated (on mainnet
  79,453 headers of which 13,410 are unique); old peers still get the full form.
- The pruning-point nullifier import has no count cap: streamed to disk, range-split across peers
  and resumable after a restart.
- Shielded transactions: the fee is checked before the proof; relayed batches are verified in one
  pass; per-peer and node-wide verification budgets; a peer that relays an invalid proof is banned
  by default (`--no-ban-shielded` turns it off). The batched verifier rejected every post-fork
  bundle; it now shares the single path's checks.
- One host can no longer hold every nullifier-export slot and stall shielded sync for others: one
  export per address, four slots, a slot is released while waiting for the peer, and a peer reading
  slower than ~11 KB/s is dropped.
- On small machines a large shielded transaction from an inbound peer is no longer dropped forever
  (a cost above a verification burst is admitted into debt).
- Spent nullifiers are tagged with their tree era (prepares a future era sunset; nothing migrates).
- The node says which ZKas release it is: `kaspad --version` prints `2.0.1 (zkas-v1.0.13)`, the
  startup log names it, and peers see `zkas:1.0.13` in the user agent. The newer-release
  exemptions (fork-reject auto-ban, invalid-proof ban) now read it.
- Windows: the node links (risc0-zkvm-platform's `export-syscalls` defines `sys_alloc_aligned`);
  binaries import only Windows system DLLs, with a static C runtime.

**Wallet daemon**
- Wallets stuck on "cannot verify checkpoint cursor… keeping checkpoint and retrying" after the
  v1.0.11 update now open: on a node with complete, verified history the checkpoint resumes; on a
  node still filling history the wallet waits with a clear message, never showing a partial
  balance. (Reported on Discord.)
- Memory protection works on Windows and macOS (free memory read from the OS). (Reported on Discord.)
- ZKAS-WALLETD-2026-001 (reported by an independent security researcher): a token re-registered
  under another viewing key can no longer serve the old key's checkpoint, through any writer, twin
  adoption, quarantine restore or the multi-wallet engine. Operators: rescan tokens that were
  re-keyed before this release.
- Multi-wallet scan engine (`--shared-scan-engine`) and Stage W uniform sends (`--uniform-v1`),
  both off by default.
- Contributors: CryptoOdie (the three fixes above).

**Bridge, docs and builds**
- The bundled `stratum-bridge` defaults to the ZKas node's RPC port 16810, not Kaspa's 16110.
- The release README no longer suggests `shielded-pay address --seed-byte 1` (a publicly known
  seed); it creates a wallet with `shielded-pay new`. Docs use ZKas ports and `zkas:` addresses.
- Releases build on the build box (Linux, Windows) and Codemagic (macOS); every binary must link
  only system libraries and report the tagged release before it is packaged.
- Compatibility: wRPC Borsh clients built before v1.0.13 cannot decode `GetShieldedTreeState` from
  a v1.0.13 node (gRPC and JSON clients are unaffected). No public node serves Borsh wRPC.

## zkas-v1.0.12 — 2026-10-27

**Node security**
- Closed three unauthenticated remote node kills the earlier sweeps missed; address, script and
  transaction decoders refuse bad input instead of panicking; imported scores near u64::MAX,
  malformed trusted-ghostdag rows and proofless pruning proofs are refused.
- A fresh node adopts a pruning proof only if its block levels attest real work (mainnet work floor).
- P2P: 256 MB decode cap, bounded pending handshakes, bounded header/UTXO/trusted-entry chunks,
  serving flows wait for the peer to read, block requests capped, operator bans actually ban,
  `--enablebanning` for malformed wire fields and post-fork invalid-PoW rejects, never fork-ban a
  peer on a newer release, global bound on pruning-proof serving.
- Chunked pruning-point proof transfer (negotiated by a services bit; old peers get one message);
  shielded-history chunks bounded in bytes (sent at most ~32 MiB).
- Mempool stops verifying a relayed batch at the first invalid shielded proof; RPC bounds concurrent
  proof pre-verification; a diverged shielded state refuses submissions and stops serving wallets.
- Consensus: the shielded IBD import is staged and swapped in under the virtual write lock; the
  nullifier set records and repairs from the chain block it reflects; a dropped shielded batch no
  longer leaves writes in the caches; unreadable stores are not treated as pruned data.
- Dependencies: h2 0.4.20, rustls 0.23.46 (RUSTSEC-2026-0258, RUSTSEC-2026-0285).

**Wallet daemon**
- A non-ASCII `X-Wallet-Token` is refused instead of being read as the shared default wallet.
- Tokens never appear in logs (8-hex pseudonym); `/api/checkpoint` flushes only the caller's wallet,
  at most every 30 s; admin routes answer loopback only.
- Memory: leaf stream held once (-23.6 GiB measured), applied-nullifier bitsets (-18.7 GiB),
  resident-wallet cap with byte budget and load admission, cgroup-aware free memory.
- O(1) per-action note bookkeeping; a client that gives up no longer cancels the wallet load; a
  correct scan is no longer deleted because the node could not verify it yet.

**Other**
- `zkas-api`: `/info/miners`, `/info/work-history`, `/info/reorgs`.
- Code moved to Radicle (`zkas.info/code`), downloads to `zkas.info/downloads`.

## zkas-v1.0.11 — 2026-10-11 — security fork (mandatory)

- **Security fork at mainnet DAA 6,983,500** (activated 15 October 2026, 09:29 UTC); the dev fee
  ends on the same block. Testnet runs the post-fork rules from genesis.
  - Merged mining binds one Kaspa parent to exactly one ZKas block (`ZKM1`, genesis-bound
    commitment over the nonce-free header hash) and a ZKas coinbase may not carry a merge-mining
    tag: one solution can no longer pay two blocks (ZK-01).
  - Shielded spends name their anchor block; the anchor window, the dev-fee balance and the miner
    reward accrual slot are committed in `zkas_state_root1`.
  - Miner rewards to the same address in back-to-back chain blocks accrue in one slot, paid every
    100 DAA or when the address changes.
- Proving stack Zakura 2.2.0: faster proving and verification with a byte-identical circuit, k11
  parameters and proof vectors; the node pins the verifying-key fingerprint and refuses to start on
  a mismatch.
- Hardening: invalid shielded proofs penalised, staged pruning-point import, aux witness size cap,
  multiparty submit checks, burn bound, startup nullifier self-check; three IBD trust holes and a
  remote zero-PoW node kill closed. Audit rounds 2 and 3 fixed; adversarial fuzz and property tests.
- Wallet daemon: spends the smallest covering note; atomic two-party settlement (behind a flag);
  payment proofs; OVK-encrypted, readable history always on; memory returned under pressure.

## zkas-v1.0.10 — 2026-09-18

- RocksDB bloom filter + LRU cache for nullifier lookups; WAL-less bulk pruning deletes.
- Relay no longer logs each block's source (miner deanonymisation).
- gRPC per-IP connection cap.
- Wallet daemon derives the coinbase note commitment itself and rejects a wrong node value.

## zkas-v1.0.9 — 2026-09-17

- Merged mining: a `kaspa-` network prefix from the Kaspa parent is accepted (fixes a parent stuck
  at "Starting").
- Wallet birthdays anywhere in history in one call (DAA locator for `GetShieldedTreeState`, served
  below the pruning point from the archive); fast sync for any birthday on an archival node.
- Wallet daemon: optional SOCKS5 (Tor) node connection; per-customer deposit addresses
  (`/api/wallet/address?index=N`); view keys recover send details; checkpoint writes off the
  wallet lock; quarantined checkpoints restored.
- Orchard stack identity pinned; the obsolete anchor-override mechanism removed; anchor indexes
  bounded and garbage-collected.
- Documentation: trust model, exchange deposits, trustless burn address.

## zkas-v1.0.8 — 2026-09-01

- P2P listens on 16811 by default (16111 collided with Kaspa) while still dialling 16111 seeds.
- Archival nodes drop unmergeable side-branch tips.
- Wallet daemon: the shared chain tree no longer resets to genesis on a node without history.

## zkas-v1.0.7 — 2026-08-31

- Orchard stack moved to Zakura Common: proving 3x, scanning 4x, Merkle hashing 10x faster.
- Shielded history on by default; backfilled nodes can serve others; `history_complete` requires a
  verified verdict; mainnet seeder `seed.zkas.info`.
- Consensus: mempool anchors judged by the virtual's blue score; spends the transition would drop
  are refused; a bundle paying the recipient more than once is refused.
- Wallet daemon: next-page prefetch, warm sweep, consolidation sized to the prover, many fixes for
  stuck or slow wallets; releases build `--locked`.

## zkas-v1.0.6 — 2026-08-09

- Shielded history backfill completes, is verified and reports so; `--archival` obtains all notes
  over P2P; offline export/import.
- Wallet daemon: one shared chain tree for all wallets, checkpoint v8, idle-wallet eviction,
  adaptive page size, batched trial decryption, optional CUDA-assisted decryption.

## zkas-v1.0.5 — 2026-08-03

- ZKAS-NU1 scheduled at DAA 757,000: dev-fee accrual, coinbase seed fix, shielded snapshot retention.
- RPC exposes the turnstile, a pool income view and why a block was rejected.
- RocksDB: LZ4 + bottommost ZSTD by default; consensus divergence diagnostics.

## zkas-v1.0.4 — 2026-07-31

- Shielded IBD transfers the in-window anchor index; anchors read from the index.

## zkas-v1.0.3 — 2026-07-31

- Fixed a silent shielded-IBD wedge and the scan-archive hole; pruned nodes serve full wallet history.

## zkas-v1.0.2 — 2026-07-31

- Wallet scans anchored at genesis; explorer circulating supply from the emission schedule; CI fixes.

## zkas-v1.0.1 — 2026-07-30

- First tagged mainnet release (Bitcoin-anchored genesis, block 959,713).
