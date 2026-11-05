# `zkas-walletd` — shielded wallet daemon

`zkas-walletd` turns the ZKas shielded pool into a conventional wallet API. It follows the
chain, recognises the notes that belong to the keys it serves, keeps the Merkle witnesses a
shielded spend needs, and builds, proves and broadcasts payments — over plain REST and JSON.

The same daemon backs every ZKas wallet surface, and how it is deployed decides who holds
which key:

| Consumer | How it runs | Spend key held by | Viewing key seen by |
| --- | --- | --- | --- |
| Web and mobile wallet, *Public service* (`wallet.zkas.info`) | hosted; `watch` → `prepare` → `submit` | **the user's device** | the service (it can watch, never spend) |
| Desktop wallet | **embedded in-process** on loopback | the user's machine | the user only |
| Android wallet, *Run on this phone* | **embedded in-process** through the `zkas-walletd-mobile` library (`walletd-mobile/` in the `zkas-signer` repository), on loopback | the phone | the user only — nodes and the chain-file CDN serve public data and see an IP address (or not, over Tor) |
| Pool, exchange or payout service | operator-run; `send`, `send_many`, `consolidate` | **the daemon** (custodial) | the operator |

`main.rs` is only flag parsing: the daemon is a library (`lib.rs`), so the desktop and Android
apps embed it and expose the identical REST API on `127.0.0.1:<port>`. A wallet interface does
not change between hosted and local operation.

**Contents**

0. [Payments are sized in notes, not coins](#0-read-this-first-payments-are-sized-in-notes-not-coins)
1. [Running it](#1-running-it)
2. [Authentication and access](#2-authentication-and-access)
3. [Endpoints](#3-endpoints)
4. [Reliable payments: request ids and outcomes](#4-reliable-payments-request-ids-and-outcomes)
5. [Performance — what actually costs time](#5-performance--what-actually-costs-time)
6. [Sync model and chain data](#6-sync-model-and-chain-data)
7. [Integration playbooks](#7-integration-playbooks)
8. [Operations](#8-operations)

---

## 0. Read this first: payments are sized in **notes**, not coins

Most operator questions trace back to one fact:

> **A transaction can spend at most 38 notes. That is a count of notes, not an amount of
> ZKAS.** How much value one transaction can move is `38 × your average note size`.

Two wallets holding the same balance therefore behave very differently:

| Wallet | Avg. note | Max per transaction | Moving 100 000 ZKAS |
| --- | --- | --- | --- |
| Pool treasury, raw coinbase notes | ~57 ZKAS | **~2 166 ZKAS** | 1 754 notes → **47 transactions** |
| Same treasury, consolidated | ~2 166 ZKAS | **~82 300 ZKAS** | 47 notes → **2 transactions** |

Proving cost follows the note count, not the amount:

```
wall time  =  2.4 core-seconds  ×  notes spent  ÷  effective cores
```

A fragmented wallet is slow *however small the payment*, and consolidating is the one change
that moves the result by an order of magnitude. That is why `--auto-consolidate` is **on by
default** (§5).

### Where 38 comes from

It is a **size** limit, not an economic one. Transient mass is charged at 4 per serialized
byte and a standard transaction is capped at 500 000 mass, so the bundle must fit
`500 000 / 4 − 256 = 124 744` bytes. Each Orchard action costs:

| Part | Bytes per action |
| --- | --- |
| Action data (`ActionWire`) | 884 |
| Its share of the Halo 2 proof | 2 272 |
| **Total** | **3 156** |

Plus a fixed 117-byte header and a 2 720-byte proof preamble, so
`wire_len(n) = 2 837 + 3 156 n`:

- `n = 38` → 122 765 bytes ✓
- `n = 39` → 125 921 bytes ✗

Hence **38**. Raising it would need a consensus change to the mass cap and would gain nothing:
proving cost per spend is flat from 4 to 38 spends, so the same notes cost the same whether
they travel in one transaction or four (§5).

### The three caps, and which one applies

| Cap | Value | Applies to |
| --- | --- | --- |
| `max_spends_per_tx()` | **38** | notes consumed (inputs) |
| `max_actions_per_tx()` | **38** | `max(spends, outputs)` — what mass is charged on |
| `max_payees_per_tx()` | **37** | recipients in one `send_many` transaction (+1 output for change) |

A bundle carries `max(spends, outputs)` actions, so one transaction can spend 38 notes to pay
one recipient, **or** spend 2 notes to pay 37 recipients — the same size ceiling, very
different proving cost, because cost tracks *spends*.

### Fees are priced per byte, so per action

The minimum relay fee is charged on size, which means on action count:

| Actions | Minimum relay fee |
| --- | --- |
| 1–2 | 1 855 400 sompi (0.0186 ZKAS) |
| 38 | 24 578 600 sompi (0.2458 ZKAS) |

The daemon raises any fee you pass to this floor automatically (`chunk_fee`). Passing a lower
`fee` does not save money; it is corrected.

---

## 1. Running it

```bash
./zkas-walletd \
  --network mainnet \
  --rpc-server 127.0.0.1:16810 \
  --listen 127.0.0.1:8501 \
  --wallet-dir /var/lib/zkas/wallets \
  --wallet-secret "$ZKAS_WALLET_SECRET"
```

### Core

| Flag | Default | Notes |
| --- | --- | --- |
| `-s, --rpc-server` | `127.0.0.1:16810` | Node gRPC endpoint. **Run the daemon next to its node**; every request to the node is on the sync and payment path. |
| `-l, --listen` | `127.0.0.1:8501` | Loopback by default, deliberately. |
| `--wallet-dir` | `~/.ZKas/wallets` | One wallet file and one `<token>.scan` checkpoint per wallet. |
| `--network` | `mainnet` | `mainnet` \| `testnet` \| `devnet` \| `simnet` |
| `--idle-timeout MINUTES` | *(run forever)* | Stop after N minutes without a wallet API request. Intended for a daemon temporarily exposed to pair a phone. |

### Security, access and custody

| Flag | Default | Notes |
| --- | --- | --- |
| `--wallet-secret` | *(none)* | Encrypts seeds at rest (XChaCha20-Poly1305, Argon2 key). Also `ZKAS_WALLET_SECRET`. **Without it seeds are stored in plaintext** (mode 0600) and startup warns. |
| `--no-custodial` | `false` | Disable every seed-holding endpoint (`create`, `import`, `send`, `send_many`, `reveal`, `consolidate`, `sign` return 403). The daemon then holds no seeds at all and serves only `watch` → `prepare` → `submit`. **Recommended for any public, watch-only service.** |
| `--allow-origin ORIGIN` | *(none — same-origin only)* | Repeatable CORS allow-list. With none set, cross-origin browser calls are refused, which is what stops an arbitrary web page from reaching a daemon on the user's machine. |
| `--allow-default-token` | `false` | Lets a request **without** `X-Wallet-Token` use the "default" wallet. For a trusted single-user localhost only. |
| `--allow-remote` | `false` | Bind a non-loopback address directly. Prefer a TLS reverse proxy. |
| `--serve-public ADDR:PORT` | — | Self-hosting: auto-provisioned TLS plus a pairing QR for the mobile wallet. No proxy, domain or certificate setup. Implies a bearer token on every route. |
| `--insecure` | `false` | With `--serve-public`, plaintext HTTP. **Only** behind a VPN or Tailscale — viewing keys and balances would otherwise cross the wire in clear. |
| `--public-host`, `--api-token` | — | With `--serve-public`: the host baked into the pairing URI and TLS SAN, and a fixed bearer token instead of a generated one. |
| `--enable-multiparty` | `false` | Serve the multi-party bundle endpoints (`/api/bundle/*`), for atomic settlement between several parties in one Orchard bundle. |

### Consolidation and proving

| Flag | Default | Notes |
| --- | --- | --- |
| `--auto-consolidate MAX_NOTES` | `500` | **On by default.** Keeps custodial wallets under `MAX_NOTES` by merging their oldest notes in the background. Wallets below the ceiling are never touched. See §5. |
| `--no-auto-consolidate` | `false` | Turn background consolidation off. |
| `--proof-threads N` | *(every core)* | A **throttle**, not a tuning knob: caps the threads Halo 2 proving may use, so the daemon cannot starve a co-located node. Lowering it makes payments slower. See §5. |
| `--max-concurrent-proves N` | `min(2, cores)` | Global admission limit for `/api/wallet/prepare` proofs. |
| `--runtime-threads N` | `2 × cores` | Tokio workers for HTTP, RPC and coordination. |

### Scale, memory and sync

| Flag | Default | Notes |
| --- | --- | --- |
| `--sync-wallets N` | `cores − 1` (1–8) | Wallet scans advanced concurrently; live free memory can reduce it further. |
| `--sync-wallet-memory-mb MIB` | `512` | Free memory charged to each concurrent scan. |
| `--load-wallets N` | `cores − 2` (1–4) | Concurrent checkpoint loads. |
| `--warm-wallets N` | `1` | Concurrent one-time cold witness warm-ups. |
| `--warm-always N` | `0` | Keep the N most recently active wallets resident and fully prepared (~100–190 MiB each), so reopening one is instant. |
| `--warm-budget PCT` | `60` | Load-average ceiling (per core, %) above which the background warm sweep starts no new cold work. |
| `--page-decode-threads N` | `cores − 2` (1–8) | Shared block-page decoder threads. |
| `--page-cache-entries N`, `--page-cache-ttl SECONDS` | `64`, `10` | Size and lifetime of the shared decoded-page cache. |
| `--prefetch-depth N` | `1` | Block pages fetched concurrently ahead of the ingest cursor during a deep scan. Page fetch dominates sync time, so a remote node benefits from a higher value. |
| `--active-sync-window SECONDS` | `90` | Keep syncing a wallet this long after its last API request. |
| `--idle-evict SECONDS` | `1800` | Remove an idle wallet's checkpoint from RAM (never from disk). |
| `--max-resident-wallets N` | `MemAvailable ÷ 192 MiB` (4–256) | **Soft** cap on resident wallets: its overflow rule never evicts a wallet touched within the active-sync window. |
| `--hard-max-resident-wallets N` | `0` (none) | **Hard** cap: a load first evicts the least recently used idle wallet, otherwise it is deferred. |
| `--resident-budget-mb MIB` | `0` = 70 % of the cgroup's `memory.high`/`memory.max` | Byte budget for resident wallets; `--no-resident-budget` disables it. |
| `--subtree-free-floor-mb MIB` | `1200` | Defer optional subtree-cache builds while `MemAvailable` is below this floor. |
| `--checkpoint-interval SECONDS` | `60` | Time rule for checkpointing a wallet that has advanced. |
| `--catchup-checkpoint-interval SECONDS` | same as above | The same rule for wallets still far behind the tip, where most write volume is. |

### Chain data

| Flag | Default | Notes |
| --- | --- | --- |
| `--chain-files URL_OR_DIR[,…]` | *(none)* | Read the history covered by published chain files from them instead of from the node: `https://` base URLs (tried in order) or a local directory with `manifest.json`. Every file is checked against the node before it is trusted (§6). |
| `--no-shared-tree` | `false` | Do not build the daemon-wide shared chain tree; every wallet keeps its own, as the on-device engines do. |
| `--compact-nullifiers` | `false` | Persist the shared nullifier table once (`__nullifiers__.nfs`) and store a compact bitset per wallet instead of every nullifier: much smaller and faster checkpoints. Without it checkpoints keep the full form; both forms load. |
| `--shared-leaf-store` | `false` | Checkpoint format v11: wallets reference the shared tree's leaf stream instead of embedding a copy. **One-way**: builds that predate v11 cannot read these checkpoints. |

### Offline tools (run with the daemon stopped)

| Flag | Notes |
| --- | --- |
| `--diagnose` | Print each wallet's note, base and **stranded-note** report, then exit. |
| `--graft TOKEN:/path/older.scan` | Repair a stranded wallet from an older snapshot of the same wallet. |

### Optional and experimental

| Flag | Notes |
| --- | --- |
| `--uniform-v1`, `--uniform-hold immediate\|standard\|private`, `--uniform-internal-change`, `--uniform-merge` | Uniform transactions: every send, payout and merge takes one public shape (4 actions, fixed fee 0.031178 ZKAS, epoch anchor) and is released at a scheduled random time. Opt-in; changes fees and latency of the standard endpoints. The `/api/wallet/uniform/*` endpoints work without it. |
| `--shared-scan-engine`, `--engine-*` | The multi-wallet scan engine (one trial-decryption pass for a cohort of wallets). Under evaluation; leave off in production. |

The runtime deliberately oversubscribes worker threads (2 × cores): trial decryption and
witness work are CPU-bound, and with only one worker per core a large rescan could occupy all
of them and delay `/api/status` and health checks.

### Reverse proxy

Proving takes tens of seconds, and a broadcast whose connection to the node fails is resent
for up to about a minute and a half before the daemon answers (§4). Give the proxy a read
timeout to match, or clients will give up on a payment that is still progressing:

```nginx
location /daemon/ {
    proxy_pass http://127.0.0.1:8501/;
    proxy_read_timeout 300s;
    proxy_connect_timeout 5s;
}
```

---

## 2. Authentication and access

Every wallet request carries `X-Wallet-Token`, which selects the wallet. Mint one once and keep
it — **it is the credential**; whoever holds it controls that wallet.

```bash
TOK=$(head -c16 /dev/urandom | xxd -p)
curl -X POST -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/wallet/create
```

- A token is 1–128 characters of `[A-Za-z0-9_-]`. A malformed header is refused rather than
  treated as absent.
- With `--serve-public` (or a configured bearer token) every route except `/health`
  additionally requires `Authorization: Bearer <token>`.
- **Operator routes** (`/api/admin/*`) are served only to callers on the daemon's own host
  (loopback), in addition to the wallet token.
- `/health` and `/api/proof/verify` need no token.
- Watch-only spending (`prepare`) is authorised by possession of the full viewing key; the
  resulting transaction is worthless until the seed holder signs it (§3).

---

## 3. Endpoints

### Status

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness. No token. |
| `GET` | `/api/status` | The wallet's sync and balance picture (fields below). |
| `GET` | `/api/wallet/balance` | Balance and notes; `?notes=1` adds the per-note array. |
| `POST` | `/api/checkpoint` | Write this wallet's checkpoint now. The mobile app calls it when it goes to the background. |

Key `/api/status` fields (amounts are decimal strings in sompi, with `_fc` twins in ZKAS):

| Field | Meaning |
| --- | --- |
| `synced`, `spend_ready` | Caught up, and able to build a payment now (§6). |
| `warming`, `warming_pct`, `warming_eta_secs` | A one-time witness preparation is running; payments work but the first may be slower. |
| `scanned_blocks`, `chain_len`, `blocks_behind` | Scan progress against the node tip. |
| `balance_sompi` | Everything the wallet has seen. |
| `spendable_sompi` | Notes past the maturity anchor — what a payment can use now. |
| `maturing_sompi` | Received but not yet past the anchor (~10 minutes). |
| `pending_in_sompi`, `pending_out_sompi`, `pending_change_sompi` | Mempool previews and change still in flight. |
| `note_count` | Notes held — the number that decides payment cost (§0). |
| `loading`, `loading_reason` | The wallet exists but is still being opened; `address` is already present. |
| `watch_only`, `node_connected`, `error`, `chain_files` | Mode, node reachability, the last error, chain-file statistics. |

### Wallet lifecycle

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/wallet/create` | New wallet, born at the current tip. **Returns the seed once** — store it. |
| `POST` | `/api/wallet/import` | Import `{ "seed_hex", "birthday" }`. `birthday` is a DAA score; scanning starts there instead of at genesis. |
| `POST` | `/api/wallet/watch` | Register a **watch-only** wallet from a full viewing key. Re-registering the same key never moves its birthday later. |
| `GET` | `/api/wallet/address` | Shielded `zkas:` receive address. `?index=N` returns the N-th **diversified** address — a distinct, unlinkable address paying into the same wallet (§7b). |
| `GET` | `/api/wallet/reveal` | Return the seed (custodial wallets only). |
| `GET` | `/api/wallet/history` | Chain-derived history, newest first (`limit` ≤ 5 000, `offset`, `total`): mints, receipts and own sends. Each row's `credits[]` lists every output with its address, amount and memo — attribute payments from it (§7b). `pendingOutgoing` lists sends not yet seen on chain. |
| `POST` | `/api/wallet/rescan` | Retire the checkpoint and rescan from the birthday. Refused unless the node can serve the chain from genesis (§8). |
| `POST` | `/api/wallet/settings` | Retained for older clients; history is always recorded. |
| `POST` | `/api/wallet/warm` | Mark the wallet active and start any witness preparation now, so the send path is fast when the user reaches it. Returns readiness. |
| `GET` / `POST` | `/api/wallet/scan-receipt` | Export a synced wallet's notes and witnesses as a small receipt, or adopt one, so a wallet moves between daemons in kilobytes instead of a rescan. An imported receipt must match this wallet's key and the node's own tree at its anchor. |

### Paying — custodial (the daemon holds the seed)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/wallet/send` | Pay **one** recipient. Splits into several transactions when it needs more than 38 notes. |
| `POST` | `/api/wallet/send_many` | Pay **many** recipients, up to 37 per transaction. **Use this for payouts** (§7a). |
| `POST` | `/api/wallet/consolidate` | Merge notes into one, paid to yourself. `{"heal": true}` selects the *oldest* notes rather than the smallest. |

`send` body:

| Field | Type | Notes |
| --- | --- | --- |
| `to` | string | `zkas:` shielded address. |
| `amount_sompi` / `amount_fc` | integer / number | One of the two; prefer `amount_sompi`. Must be positive. |
| `fee` | integer | Optional floor; raised to the byte-priced minimum. |
| `max_total_fee` | integer | Optional ceiling on the whole payment's fees; refused (409) before any proving if the plan would exceed it. **Recommended for automated callers.** |
| `memo` | string | Up to 512 bytes UTF-8, encrypted to the recipient. Carried on **every** transaction of a split payment. |
| `request_id` | string | Idempotency key, 1–128 characters (§4). **Recommended for every automated payment.** |

`send_many` takes `payees: [{ to, amount_sompi | amount_fc, memo? }]` plus the same `fee`,
`max_total_fee` and `request_id`.

### Paying — non-custodial (the device holds the seed)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/wallet/prepare` | The daemon selects notes, builds and **proves** the bundle with the viewing key only, and returns a sighash plus one randomizer per spend. It cannot authorise the spend. |
| `POST` | `/api/wallet/submit` | The device returns its spend-authorisation signatures; the daemon finalises and broadcasts. |

`prepare` takes `fvk_hex`, `to`, `amount_sompi` / `amount_fc`, and optionally `fee`, `memo`,
`allow_partial` (permit a payment larger than one transaction can carry, delivered in parts),
`replace_session` (release the holds of an earlier, abandoned session) and `request_id`. It
returns a `session` that stays valid for **5 minutes**; the notes it selected are held for
that session so a concurrent payment prefers other notes. `submit` takes
`{ "session", "sigs": [{ "index", "sig" }] }`.

The spend-authorisation key `ask` cannot be derived from the viewing key, so a proven bundle is
worthless until the seed holder signs it. The device independently verifies the recipient,
amount and fee before signing, so a dishonest service cannot redirect funds. See
`docs/NON_CUSTODIAL_WALLET.md`.

### Proofs and signatures

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/wallet/proof` | Proof of payment for one of this wallet's sends: what it paid, to whom, verifiable against the chain without revealing anything else. |
| `POST` | `/api/proof/verify` | Verify a payment proof against the chain. No wallet or token needed. |
| `POST` | `/api/wallet/sign` | Prove control of an address without spending. |
| `POST` | `/api/verify` | Verify such a signature. |

### Uniform transactions and multi-party bundles (optional)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/wallet/uniform/send`, `/uniform/send_many`, `/uniform/consolidate` | Uniform-shape payments released at a scheduled time. |
| `GET` | `/api/wallet/uniform/scheduled`, `/api/uniform/anchor` | Scheduled releases and the wallet's current uniform anchor. |
| `GET` / `POST` | `/api/bundle/offer`, `/api/bundle/prepare`, `/api/bundle/submit` | Multi-party atomic bundles; served only with `--enable-multiparty`. |

### Operator (loopback only)

Two operator routes pre-build the O(depth) witness caches, so that consolidations and spends
of old notes never pay a full O(chain) climb the first time. They move no funds and are safe
to call repeatedly — after a fresh start, a long backfill, or before a wallet with old notes
consolidates.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/admin/warm_chain_tree` | Drive the **shared chain tree** forward (up to 90 s per call) and start its subtree-cache build. Once built, every wallet the shared tree covers witnesses in O(depth). |
| `POST` | `/api/admin/warm_wallet` | Build **this token's** subtree cache now and persist it, for a wallet the shared tree cannot serve (its notes predate the tree's base). |

`warm_chain_tree` reports progress; the build continues in the background:

```jsonc
{ "leaves_before": 2061000, "leaves_after": 2061450, "leaves_gained": 450,
  "caught_up": true,                 // tree reached the node tip within this call
  "subtree_cache_ready": false,      // true once the background build has installed
  "subtree_cache_state": "started",  // "ready" | "building" | "started"
  "chunks": 3, "chain_tip_daa": 2061450, "seconds": 41.2 }
```

Call it again to advance further or to retry a build that reported `stream moved`. A call
that returns `caught_up` with `subtree_cache_ready: true` needs no follow-up. `warm_wallet`
builds inline and returns `{ subtree_cache_ready, notes, matured, seconds }`.

### Examples

```bash
# Receive address
curl -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/wallet/address

# Pay one recipient, idempotently
curl -X POST -H "X-Wallet-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"to":"zkas:<recipient>","amount_sompi":500000000,"memo":"invoice 42",
       "request_id":"invoice-42","max_total_fee":5000000}' \
  http://127.0.0.1:8501/api/wallet/send

# Pay many recipients — one proof per batch of up to 37
curl -X POST -H "X-Wallet-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"request_id":"payout-2026-11-05","payees":[
        {"to":"zkas:<miner1>","amount_sompi":1500000000},
        {"to":"zkas:<miner2>","amount_fc":12.5,"memo":"payout"},
        {"to":"zkas:<miner3>","amount_sompi":900000000}]}' \
  http://127.0.0.1:8501/api/wallet/send_many
```

`send` returns `{ txid, txids, tx_count, amount_sompi, fee_sompi, amount_sompi_exact,
fee_sompi_exact }`; `send_many` returns `{ txids, tx_count, payees, payee_txids, paid_sompi,
fee_sompi, … }`. A bad address, a zero amount, insufficient funds or a fee over
`max_total_fee` fail **before any proving**, in milliseconds.

---

## 4. Reliable payments: request ids and outcomes

A payment API must make one guarantee above all others: **a retry never pays twice**, and an
answer always says truthfully whether money moved. The daemon provides both.

### Request ids

Give every payment a `request_id` (1–128 characters, unique per payment). The daemon records
each broadcast under it — per wallet, persisted across restarts (`__sent_requests__.jsonl`),
kept for 24 hours — and answers a repeat accordingly. A repeat is the same id **for the same
payment** (same recipient or recipients, same amounts): an id reused for a different payment is
treated as a new payment, never answered with the old one.

| Situation | Answer |
| --- | --- |
| The payment was already broadcast | **409** `{ "error", "already_sent": { txid, txids, amount_sompi, fee_sompi, … } }` — record it as paid; nothing new is built. |
| The same request is still being sent | **409** `{ "error", "in_progress": true }` — wait and check again. |
| A custodial retry arrives while the original is running | It waits for the original (payments on one wallet run one at a time), then receives the 409 above. |

For the non-custodial flow the key is the `request_id` passed to `prepare`; the same id on a
later `prepare` is answered from the record.

### What each answer means

| Status | Meaning | Did money move? |
| --- | --- | --- |
| **200** | Accepted by the node. `txids` lists every transaction. | Yes. |
| **400** | Invalid request, or (non-custodial) signatures that do not match the session. | No. |
| **404** (`submit`) | No such session: it expired (5 minutes) or was already submitted. | No new payment; check history if it was already submitted. |
| **409** | `already_sent`, `in_progress`, a fee over `max_total_fee`, or a wallet not yet ready (§8). | See the body. |
| **502** | The node refused the transaction. | **No** — unless the body carries `txids` (a later part of a split payment was refused): those parts were paid. |
| **503** | The daemon cannot reach its node; nothing was broadcast. | No. |
| **504** `{ "outcome_unknown": true, "txid" }` | See below. | **Unknown — treat as possibly paid.** |

### When the outcome is unknown

A network connection can fail after the node has received a transaction but before it has
answered. The daemon never reports that case as a failure. It resends the **identical**
transaction — same id, same nullifiers, so a resend can never pay twice — up to three more
times on a fresh connection; a node answer that the transaction is already in its mempool or
already accepted counts as success. Only if no answer settles it does the daemon return
**504** with `outcome_unknown` and the transaction id. In that case:

- The notes it spends stay set aside, so no other payment can use them.
- The `request_id` is recorded as sent, so a retry is answered with `already_sent` instead of
  paying again.
- If the transaction never lands, the daemon notices on its own (below), returns the notes to
  the spendable balance and forgets the record, so a later retry pays normally.

### Payments that do not confirm

A submitted payment's notes are parked until the chain shows the spend. If an hour of chain
time passes without it, the daemon first asks the node: a transaction **still in the node's
mempool** keeps its notes parked (the node keeps pending transactions for up to 24 hours);
only one the node no longer has is declared lost and its notes returned. A spend the chain
did apply but this wallet's scan missed is recognised from the shared nullifier set and kept
as spent.

---

## 5. Performance — what actually costs time

Worth understanding before sizing a deployment, because the intuitive answer is wrong.

**The proof is the cost; the Merkle witness no longer is.** Nodes keep only the tree's
~32-node frontier, so wallets hold their own witnesses. Producing one used to mean replaying
the note-commitment stream with Sinsemilla at ~150–260 µs per leaf — on a ~200 K-leaf chain,
~30–50 s per send, growing with the chain.

`WalletDb` instead retains **complete subtree roots** (`SubtreeCache`,
`shielded-core/src/walletdb.rs`). For a note at position `p` witnessed at anchor `S`, every
authentication sibling is a subtree either entirely below `S` (complete, therefore immutable)
or entirely above it (the empty root), with exactly **one** exception: the subtree straddling
`S`. All but one sibling is therefore computed once and kept; the straddler costs `O(depth)`
per anchor. On a hosted daemon the **shared chain tree** holds this cache once for every
wallet it serves.

Measured on a production daemon, same wallet (62 K notes, ~150 K-leaf span):

| Witness build | Replay | Subtree cache |
| --- | --- | --- |
| 1 note | 38.8 s | — |
| 2 notes | 94.7 s | **58.5 ms** |
| 22 notes | — | **243.9 ms** |
| 38 notes | — | **538.8 ms** |

Benchmarked at 200 K leaves: **29.36 s → 0.357 s (82×)** per send. Every paying endpoint —
`send`, `send_many`, `consolidate`, `prepare` — witnesses through the same
`WalletDb::witness_paths_at`.

Three independent safety layers protect it:

1. A freshly built cache must reproduce the root of the tip mirror — maintained by a wholly
   separate code path — or it is **discarded** and the wallet keeps replaying.
2. Every path served is verified against the anchor root before use.
3. A rejected build is remembered, so an `O(chain)` build is never repeated per tick.

A wrong cache can only *decline to help*. It cannot produce a wrong witness.

### Proving: the cost model

With witnessing solved, Halo 2 proving is the cost of a payment, and it follows one measured
rule:

> **~2.4 core-seconds of CPU per note spent — however it is scheduled.**

Total CPU is flat across thread counts (91.7 s at 1 thread, 93.4 s at 4, for 38 spends), so:

```
wall time  =  2.4 s  ×  notes spent  /  effective cores
```

Measured (`bench_proof_scaling_and_parallelism` in `shielded-core/src/walletdb.rs`, run with
`--ignored`), 4 cores of an EPYC 9654:

| Spends | Wall | CPU | Cores used | s/spend |
| --- | --- | --- | --- | --- |
| 1 | 4.3 s | 10.4 s | 2.42× | (includes one-time setup) |
| 4 | 3.4 s | 10.7 s | 3.14× | 0.85 |
| 12 | 9.6 s | 30.2 s | 3.15× | 0.80 |
| 38 | 30.0 s | 93.8 s | 3.13× | 0.79 |

Consequences:

- **A larger per-transaction spend cap would gain nothing.** Cost per spend is flat from 4 to
  38 spends.
- **More cores on a *single* proof have diminishing returns** (77 % efficiency at 4 threads).
  Proving several transactions at once recovers part of it (1.21×, below).
- **`RUSTFLAGS=-C target-cpu=native` gains nothing** (33.3 s vs 32.3 s at 38 spends);
  `pasta_curves` is already hand-optimised.
- **Release-profile tuning is already in place** (`[profile.release.package.*]` for
  `halo2_proofs`, `pasta_curves`, `halo2_gadgets`, `orchard`, `ff`, `group`).

The formula has three terms, so there are three levers:

| Lever | Realistic gain | Cost |
| --- | --- | --- |
| **Fewer, larger notes** (`--auto-consolidate`) | **up to 38×** | free, on by default |
| **More cores** | ~8× going 4 → 64 | hardware |
| **GPU proving** | 3.8–7.2× (published, Halo 2 on BN254) | Orchard uses Pasta/IPA, where GPU support is still immature |

A pool treasury receives **one coinbase note per block** — at 1 BPS up to 86 400 notes a
day, each ~57 ZKAS. Moving 513 484 ZKAS from such a wallet takes 9 006 spends: **237
transactions and ~2 hours of proving**, measured. Consolidated to the 500-note ceiling, the
same payment is a handful of spends.

### Keeping note count down: `--auto-consolidate` (on by default)

```bash
zkas-walletd ...                          # ceiling 500, already active
zkas-walletd ... --auto-consolidate 200   # tighter
zkas-walletd ... --no-auto-consolidate    # off
```

The daemon merges each over-ceiling custodial wallet's **oldest** notes, up to 38 at a time,
at most one transaction per minute, **and only while nothing else is proving**.

Merging does not reduce total proof work; it *moves* it. Each merge makes one note worth ~38×
more, so the eventual payment spends ~38× fewer notes, and the cost is paid ~30 s at a time
in the background. Oldest-first (`heal`) also lets the fast-sync base roll forward past the
spent notes, shortening later witness work.

**Why it is on by default.** A wallet receiving a note per block degrades without visible
symptoms until someone tries to spend; there is no cheaper moment to start than early.

**Why it is safe on a shared daemon:**

- The ceiling does the work: an ordinary wallet holds a handful of notes and is **never
  touched**. Only wallets far past normal usage — treasuries and exchange hot wallets — are
  merged, at roughly **0.05 % of the merged value** in fees.
- **Watch-only wallets are skipped**: the daemon holds no seed for them.
- **It converges and stops**: each merge removes 37 notes, so once a wallet is under the
  ceiling no further merges happen.
- **Bounded CPU**: one merge (~30 core-seconds) per 60 s cooldown, standing down completely
  while any payment is proving.
- **No races**: a payment holds `PROVING_IN_FLIGHT` across its select → submit span, so no
  merge starts during it, and a payment arriving mid-merge waits on `CONSOLIDATING` before it
  selects notes.

`POST /api/wallet/consolidate` performs exactly one such merge on demand through the same
code path (`consolidate_once`).

### Proving several transactions at once

A payment split into several transactions proves them in groups, each proof in its own rayon
pool of `PROOF_THREADS_EACH` (2) threads, because a single proof's parallel efficiency is
sublinear:

| Threads given to one proof | Wall (38 spends) | Efficiency |
| --- | --- | --- |
| 1 | 91.7 s | 100 % |
| 2 | 50.1 s | 91.5 % |
| 3 | 37.6 s | 81 % |
| 4 | 29.7 s | 77 % |

Two 38-spend proofs take **63.9 s sequentially** (each on all 4 cores) and **52.9 s grouped**
(2 × 2 threads) — **1.21×**, widening with core count. A single-transaction payment keeps
the global pool and is unaffected. Group size is bounded by cores **and** free memory
(`PROOF_MEM_PER_EXTRA_MB`), so a constrained machine falls back to the sequential path.

### Runtime resource controls

| Knob | Where | Default | Flag |
| --- | --- | --- | --- |
| Halo 2 proving threads | rayon global pool | every core | `--proof-threads N` (or `RAYON_NUM_THREADS`) |
| Proof admission | prepare semaphore | min(2, cores) | `--max-concurrent-proves N` |
| Tokio worker threads | runtime | 2 × cores | `--runtime-threads N` |
| Wallet sync concurrency | sync scheduler | cores − 1, memory-capped | `--sync-wallets N`, `--sync-wallet-memory-mb MIB` |
| Checkpoint load / cold warm concurrency | semaphores | cores − 2 (1–4) / 1 | `--load-wallets N`, `--warm-wallets N` |
| Shared page decode threads | dedicated rayon pool | cores − 2 | `--page-decode-threads N` |
| Shared block-page cache | one fetch serves every wallet on the same page | 64 entries, 10 s | `--page-cache-entries N`, `--page-cache-ttl SECS` |
| Resident wallets | evicts idle wallets, checkpoint flushed first | memory-derived | `--max-resident-wallets`, `--hard-max-resident-wallets`, `--resident-budget-mb`, `--idle-evict` |
| Active-sync window | only recently used wallets are swept | 90 s | `--active-sync-window SECS` |
| Subtree-cache memory floor | defers cache builds when memory is tight | 1 200 MiB | `--subtree-free-floor-mb MIB` |

**The page cache is shared, not per wallet.** Wallets are swept in cursor order so laggards
land on the same page and share one fetch and one decode. Raise the TTL if many wallets of
the same key arrive minutes apart.

**Resident wallets are bounded by RAM, not CPU.** The resident caps are what keep a public
daemon with thousands of tokens out of swap. A wallet whose payment is waiting for the
device's signatures is never evicted.

**One wallet cannot hold up the others.** A sync round has a time budget; a wallet that
overruns finishes on its own while the next round proceeds.

**`--proof-threads` only ever costs time.** It decides how many cores divide a fixed amount
of work:

| `--proof-threads` | 38-spend proof |
| --- | --- |
| 4 | 29.7 s |
| 3 | 37.6 s |
| 2 | 50.1 s |
| 1 | 91.7 s |

Use it when the daemon shares a machine with something that must not be starved — for example
`--proof-threads $(( $(nproc) - 2 ))` next to a node. Tokio workers do not bound proving:
proofs run on `spawn_blocking` threads and inside the rayon pool.

### Sizing

- **Subtree cache memory:** ~11 MB per 200 K-leaf wallet while building (32 B per leaf stored
  plus 32 B per leaf decoded). Builds are deferred while `MemAvailable` is under
  `--subtree-free-floor-mb` and retried on a later pass.
- **Built only where it pays:** wallets with a span below `SUBTREE_CACHE_MIN_SPAN` (20 000
  leaves) replay quickly and skip it.
- **One-time build:** 20–60 s of CPU per large wallet, off the wallet lock.
- **Give the daemon cores.** Proving scales at ~3.1/4 efficiency, so a 16-core machine proves
  the same 38-spend transaction in roughly a quarter of the time. For a payout service this is
  the most cost-effective upgrade.
- Background cache builds stand down entirely while any payment is proving
  (`PROVING_IN_FLIGHT`), so they never lengthen a user's payment.

---

## 6. Sync model and chain data

- **Wallets sync in the background.** A status request never waits for a wallet to open: a
  wallet that exists but is still loading answers with `loading: true` **and its address**,
  read from the wallet file.
- **`import` with a `birthday`** skips chain older than the wallet — the difference between a
  ~45-minute restore and ~20 seconds. A fresh `create` is born at the tip.
- **The matured anchor.** A spend roots at the anchor `DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK`
  = 630 blue blocks below the sink, so received funds become spendable after ~10 minutes.
  This is consensus policy, not a sync delay.
- **The tip margin.** A wallet never ingests the newest `SYNC_TIP_MARGIN` (200) blue units,
  because blocks that close to the sink can still be reorganised; they are previewed instead.
  A fully caught-up wallet therefore rests ~200 blocks behind the tip, and its applied state
  never has to be rolled back.
- **Spendability is decided by the anchor, not the tip.** `spend_ready` is true once the
  wallet reaches the anchor depth with a usable commitment tree, so a wallet a few hundred
  blocks behind can still pay. `blocks_behind` reports the gap.
- **Progress is continuous.** A scan republishes its snapshot every couple of seconds, so
  `scanned_blocks` advances while work happens.
- **Node calls have deadlines.** Requests to the node are bounded (30 s; the node-health
  probe 10 s), and a connection that stops answering is replaced after three failed probes —
  within about a minute. A broadcast is resent rather than abandoned (§4).

### Chain files

With `--chain-files`, the history covered by published chain files is read from static files
— a CDN and/or a local directory — instead of from the node, which removes most of the
node's load from a restore or a long catch-up. The node remains the authority:

- **Any file page that changes the wallet** (a received or spent note) is re-fetched from the
  node and compared before it is kept.
- **The wallet's tree is checked against the node's** frontier as soon as the node can place
  one at the wallet's position, and periodically until it matches.
- **A mismatch disables the files** for the daemon and rebuilds the wallet from the node.

A tampered or stale file can therefore cost time, never correctness: it cannot create a
payment the chain does not contain, nor hide one indefinitely.

### Shared chain tree

On a multi-wallet daemon the public commitment stream is identical for every wallet, so it is
held once: the **shared chain tree** follows the chain and witnesses spends for every wallet it
covers, and wallets keep only their own notes and witnesses. `--no-shared-tree` turns it off;
the embedded (phone and desktop) daemons each serve a single user and run without it.

---

## 7. Integration playbooks

Two operator shapes dominate and they want opposite things. A **mining pool** has one
fragmenting treasury and pays many recipients at once. An **exchange** has many customer
balances, pays one recipient at a time, and must be consistently fast at it. Both are
governed by §0 — cost tracks **notes spent** — and both should follow §4: **a `request_id`
on every payment**.

### Key material: a raw seed, not a mnemonic

ZKas has **no BIP-39 seed phrase** anywhere — not in `zkas-walletd`, `shielded-core`, the SDK
or the wallet apps. The unit of key material is a **raw 32-byte seed, hex-encoded**:

```jsonc
POST /api/wallet/create            // daemon generates 32 random bytes (OsRng)
POST /api/wallet/import            // { "seed_hex": "<64 hex chars>", "birthday": <DAA score> }
GET  /api/wallet/reveal            // returns seed_hex — treat it as the private key it is
```

You **can** derive that seed from a BIP-39 mnemonic on your own side and import the result as
`seed_hex`, which gives a human-transcribable cold backup. ZKas defines no derivation standard,
so the mnemonic is **your own convention** and the official wallet cannot restore from it.
Document the derivation and test the round trip before funding anything.

`birthday` is the DAA score to start scanning from. Use the tip for a new wallet; `0` scans
the whole chain for funds an imported seed may already hold.

---

### 7a. Mining pool / payout service

Paying N miners with N calls to `send` means N bundles: **N Halo 2 proofs, N witness sets,
N relay fees**, one after another. An Orchard bundle carries `max(spends, outputs)` actions,
so one bundle holds many payees plus change. **Use `send_many`:**

```jsonc
{ "request_id": "payout-2026-11-05",
  "payees": [ {"to": "zkas:...", "amount_sompi": 1500000000},
              {"to": "zkas:...", "amount_sompi": 2500000000} ],
  "fee": 3000000 }            // optional floor; raised to the node's byte minimum
```

- Batches are split automatically at `max_payees_per_tx()` (37).
- Note selection runs **once, under one lock, across all batches**, so two batches never
  select the same note, and all witnesses come from one pass at one anchor.
- Each transaction's fee is priced on its action count (`max(spends, payees + 1)`).
- If a later batch is refused, the answer lists `txids`, `paid_sompi` and `payee_txids` —
  exactly which payees were paid — and the `request_id` record makes a retry return that
  result instead of paying again.

Also:

- **Leave `--auto-consolidate` on.** It is the single most important setting for a pool: a
  treasury accrues a note per block, and proving costs ~2.4 core-seconds *per note spent*.
  On an already fragmented treasury expect a grind-down period (47 000 → 500 notes is ~1 250
  merges, about a day of background work and ~0.3 % of the treasury in fees); payments
  benefit long before it finishes, because selection draws on the merged notes first.
- **Run the daemon next to the node.**
- **Give it cores.** After note count, this is the lever that matters.
- **Do not issue payout calls concurrently.** Payments on one wallet run one at a time, and
  proving is already parallel inside the daemon.

#### Recommended pool configuration

```bash
zkas-walletd \
  --network mainnet \
  --rpc-server 127.0.0.1:16810 \
  --listen 127.0.0.1:8501 \
  --wallet-dir /var/lib/zkas/wallets \
  --wallet-secret "$ZKAS_WALLET_SECRET" \
  --auto-consolidate 300
```

The default ceiling is 500; 300 suits a treasury that receives notes continuously.

#### Worked example: paying 500 miners, 100 000 ZKAS in total

From raw coinbase notes (~57 ZKAS each), 100 000 ZKAS needs **1 754 notes**, and that count
decides everything:

| Approach | Transactions | Proving (4 cores) | Fees |
| --- | --- | --- | --- |
| 500 × `send`, one call per miner | 500+ | 500+ proofs, serial | 500 × 0.019–0.246 ZKAS |
| 1 × `send_many`, unconsolidated | **47** (spend-bound: 1 754 ÷ 38) | 1 754 spends ≈ **70 min** | 47 × 0.246 ≈ 11.6 ZKAS |
| 1 × `send_many`, **consolidated** | **14** (payee-bound: 500 ÷ 37) | ~47 spends ≈ **2 min** | 14 × 0.246 ≈ 3.4 ZKAS |

Consolidated, the batch becomes payee-bound — the inexpensive direction, since cost tracks
spends rather than outputs.

#### One large send, or several small ones?

Always **one call for the full amount**; the daemon splits it itself. Sending 5 000 ZKAS from
~57 ZKAS coinbase notes needs **88 notes** whichever way it is done:

| Approach | Notes spent | Txs | Proving (4 cores) | Fees |
| --- | --- | --- | --- | --- |
| **1 call, 5 000 ZKAS** | **88** | 3 (38 + 38 + 12) | **~60 s** | **0.573 ZKAS** |
| 3 calls of ~1 667 | 90 | 3 (30 each) | ~70 s | 0.586 ZKAS |
| 88 calls of one note each | 88 | 88 | ~68 s + 88 round trips | 1.63 ZKAS |

One call wins because selection runs once across the whole amount (separate calls each round
up their own change), its transaction proofs are grouped (1.21×), it makes one witness pass at
one anchor, and fees are per transaction. All three rows are within ~15 % because they all
spend ~88 notes; consolidated, the same payment is **3 notes, 1 transaction, ~7 seconds**.
Note size is what matters.

#### Pool health checks

```bash
# the number that decides payout time
curl -s -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/status | jq '.note_count'

grep "auto-consolidate: merged" walletd.log | tail -5      # merging keeping up?
grep -E "send: (building|tx .* proven)" walletd.log | tail  # payout in progress
```

If `note_count` climbs steadily while `auto-consolidate: merged` lines are rare, merging is
being starved — look for a payment that is permanently in flight.

---

### 7b. Exchange / custodial service

An exchange needs four things from a wallet backend: deposits attributed to the right
customer, withdrawals that are never paid twice, a hot balance that stays small and fast to
spend, and an audit trail it can show a customer or an auditor. This section is a launch guide
for exactly that.

#### Choose where the spend key lives

| | **A. Custodial daemon** | **B. Split key** |
| --- | --- | --- |
| Spend key | encrypted on the daemon host (`ZKAS_WALLET_SECRET`) | on a separate signing host; the daemon runs `--no-custodial` and holds **viewing keys only** |
| Withdrawal path | `send` / `send_many` | `prepare` → signer verifies and signs → `submit` |
| Signer | the daemon | `@zkas/sdk` with the ZKas signer (TypeScript), or the `zkas-signer` crate (Rust) |
| Batched payouts | `send_many`: up to 37 recipients per transaction, one proof | one recipient per `prepare` |
| Consolidation | automatic (`--auto-consolidate`) | performed by the signer as a payment to the wallet's own address; the daemon cannot merge a wallet it holds no seed for |
| If the daemon host is compromised | the hot balance can be spent | wallet activity is visible; **no funds can move** — the signer independently checks recipient, amount and fee before every signature |

**B** keeps the spend key off the networked host entirely and is the stronger design. **A** is
simpler to operate. With **A**, keep the hot balance small and sweep the rest to cold storage.

#### Wallet topology

- **One hot wallet** receives every deposit — one diversified address per customer — and pays
  withdrawals. Deposits fund withdrawals directly, with no per-deposit sweep: one key, one
  scan, one backup.
- **One cold wallet**, generated offline and never imported into a networked daemon.
  Register its viewing key watch-only (`POST /api/wallet/watch`) to monitor its balance.
- **Additional hot wallets** only for throughput: payments from one wallet run one at a time,
  while separate wallets pay in parallel.

#### The node

- Run your **own node** on the same host or private network, and point `--rpc-server` at it.
  Every scan page, broadcast and proof check is a request to it.
- Prefer a node that keeps the **full shielded history and block bodies**. The daemon refuses
  a rescan against a node that cannot serve the chain from genesis, and payment proofs and memo
  reads need the body of the block that carried the transaction. A pruned node serves recent
  bodies only.

#### Launch configuration — A (custodial daemon)

```ini
# /etc/zkas/walletd.env  (owner root, mode 0600; never put the secret on the command line)
ZKAS_WALLET_SECRET=<long random secret, stored in your secrets manager>
```

```ini
# /etc/systemd/system/zkas-walletd.service
[Unit]
Description=ZKas wallet daemon
After=network-online.target zkas-node.service
Wants=zkas-node.service

[Service]
User=zkas
EnvironmentFile=/etc/zkas/walletd.env
ExecStart=/usr/local/bin/zkas-walletd \
  --network mainnet \
  --rpc-server 127.0.0.1:16810 \
  --listen 127.0.0.1:8501 \
  --wallet-dir /var/lib/zkas/wallets \
  --auto-consolidate 200 \
  --warm-always 3
KillSignal=SIGTERM
TimeoutStopSec=120
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

| Setting | Why |
| --- | --- |
| `--listen 127.0.0.1:8501` | The API is reachable only from the host. Put your own authenticated service in front of it; never expose the daemon itself. |
| `ZKAS_WALLET_SECRET` (environment file) | Seeds are encrypted at rest. Without it they are stored in plaintext. Passed through the environment, it never appears in the process list or shell history. |
| `--auto-consolidate 200` | Every deposit is a note; the ceiling keeps withdrawals at 1–3 spends (~2–7 s) instead of drifting into minutes (§0). |
| `--warm-always 3` | The hot wallet (and the watch-only cold wallet) stay resident and fully prepared, so the first withdrawal after a quiet period does not wait for the wallet to reopen. ~100–190 MiB each. |
| `--rpc-server 127.0.0.1:16810` | Your own node, next to the daemon. |
| `TimeoutStopSec=120` | A stop flushes every wallet's checkpoint; give it time to finish. |

If the node shares the machine, add `--proof-threads $(( $(nproc) - 2 ))` so proving never
starves it. Everything else stays at its default.

**Never pass** on an exchange daemon: `--allow-remote`, `--allow-origin`, `--serve-public`,
`--allow-default-token`, `--no-auto-consolidate`, `--enable-multiparty`, `--uniform-v1`,
`--idle-timeout`, or the one-way `--shared-leaf-store`.

#### Launch configuration — B (split key)

The daemon is configured as in **A**, plus `--no-custodial`, and without
`ZKAS_WALLET_SECRET` — it holds no seeds:

```bash
zkas-walletd \
  --network mainnet \
  --rpc-server 127.0.0.1:16810 \
  --listen 127.0.0.1:8501 \
  --wallet-dir /var/lib/zkas/wallets \
  --no-custodial \
  --warm-always 3
```

Register each wallet with its viewing key (`POST /api/wallet/watch` with `fvk_hex` and a
`birthday`). The signing host holds the seed, accepts no inbound connections, and runs the
withdrawal loop: `prepare` on the daemon with the withdrawal's `request_id`, verify and sign
locally (the signer rebuilds the transaction from the disclosure, confirms it pays exactly
the approved recipient and amount with everything else returned as change, and refuses any
fee above its ceiling), then `submit`. The SDK's `send()` implements this loop, including
split payments, request ids and unknown outcomes.

#### Before going live

1. The node is synced and `GET /health` answers.
2. Create the hot wallet (`POST /api/wallet/create`, born at the tip) and back up the returned
   `seed_hex` offline **before** funding it — or, for **B**, register its viewing key.
3. Register the cold wallet watch-only.
4. Wait for `synced: true` and `spend_ready: true` in `/api/status`.
5. Rehearse with small amounts: a deposit to a per-customer address appears in history under
   that address; a withdrawal returns `txids`; repeating it with the same `request_id` returns
   **409 `already_sent`** and pays nothing; its payment proof verifies.
6. Back up the wallet directory and the tokens.

#### Deposit attribution

A wallet has one key but **unlimited addresses**. `GET /api/wallet/address?index=N` returns the
wallet's N-th Orchard *diversified* address. Every diversified address pays into the same
wallet and is found by the same scan — trial decryption is keyed on the incoming viewing key,
independent of the diversifier — so scanning costs the same for ten customers or ten million.
On chain the addresses are unlinkable. An address is bound into each note's commitment, so the
address a deposit reports is the address it was actually paid to; it cannot be forged.

| Design | How | Verdict |
| --- | --- | --- |
| **One wallet, one diversified address per customer** | `address?index=<customer index>` at signup; attribute each deposit by the address it paid | **Recommended.** Nothing for the customer to type, nothing to get wrong. |
| **One wallet per customer** | a token and seed per customer, swept to a hot wallet | Works for hundreds of customers; beyond that it is the design above with extra scans, backups and a proof per sweep. |
| **Memo references** | one address; the customer must enter a reference | Possible, but a forgotten or mistyped reference becomes a support case. Use addresses. |

```bash
# at signup: customer 4711's own deposit address
curl -H "X-Wallet-Token: $TOK" "http://127.0.0.1:8501/api/wallet/address?index=4711"
```

Rules for the address book:

- **Store the exact address string** returned for each index, mapped to its customer. Derivation
  is deterministic: the same index always returns the same address.
- **Reserve indexes for the exchange itself** — for example `0` for top-ups from cold storage —
  and never issue them to a customer. Payments into the hot wallet from your own cold wallet
  arrive as ordinary receipts; issued to a customer, a top-up would be credited to them.
- **A deposit to an address you never issued** (or a reserved one you did not expect) is held
  for review, never credited automatically.

#### Crediting deposits

Read deposits from `GET /api/wallet/history`, rows of `kind: "received"`. Each row is one
transaction; its **`credits[]`** array has one entry per output that paid this wallet:
`recipient`, `amountSompiExact`, `memo`.

1. **Attribute from `credits[]`, never from the row's top-level fields.** One transaction can
   pay several of your customers (a payer settling two invoices, another exchange's batched
   payout); the row's `amountSompi` is then their **sum** and its `recipient` only the
   **first** address.
2. **Use `amountSompiExact`** (a decimal string). The numeric `amountSompi` is a JSON number,
   which JavaScript and many JSON libraries round above 2^53 sompi.
3. **Check the row before crediting it:** the credits must sum to the row's `amountSompiExact`.
   A received row with an **empty** `credits[]` (written by a daemon older than the breakdown)
   or with a sum that does not match is held for **manual review**, never credited from its
   top-level fields.
4. **Credit each entry exactly once.** Key it on `(txid, index in credits[])` and store the key
   with the ledger entry. The order of `credits[]` never changes once a row exists.
5. **`coinbase` rows are not deposits.** A mining payout directed to a deposit address arrives as
   a `coinbase` row with no address and cannot be attributed; tell customers not to mine to a
   deposit address.

```bash
# one object per received transaction: its total and each credit with its key
curl -s -H "X-Wallet-Token: $TOK" "http://127.0.0.1:8501/api/wallet/history?limit=500" | jq -c '
  .rows[] | select(.kind == "received") | .txid as $t
  | { txid: $t, daaScore, totalSompi: .amountSompiExact,
      credits: [ .credits | to_entries[] | { key: "\($t):\(.key)", address: .value.recipient, sompi: .value.amountSompiExact, memo: .value.memo } ] }'
```

Do the sum check and all amounts in integer arithmetic in your own code (`jq` uses floating
point).

**When a deposit is final.** The daemon writes a row only once its block is at least
`SYNC_TIP_MARGIN` (200 blue units, about three minutes) below the tip, and only for
transactions the chain actually **applied** — the node's shielded records exclude any spend
consensus dropped (an immature anchor, an already-spent nullifier). A row is therefore safe to
credit when it appears. For large deposits you may require more depth:
`/api/status.chain_len − row.daaScore ≥` your threshold.

Never credit from anything else. A shielded transaction can be mined, carry a txid and gain
confirmations while having moved nothing — consensus drops the spend during the state
transition instead of rejecting the block. Block or txid inclusion, an explorer, or
"N confirmations" do not show that; the daemon's history does. If you read the chain directly
(`GetShieldedBlocks`), its records are the applied set, but you must apply the settlement depth
yourself.

**Polling.** History is newest first: `GET /api/wallet/history?limit=<≤5000>&offset=<n>`.
Keep a watermark: the highest `daaScore` you have fully processed.

1. Read pages from `offset=0` until a page's oldest row has a `daaScore` below the watermark (or
   the history ends).
2. Process every received row at or above the watermark, idempotently (rule 4 above); rows you
   have already credited are skipped by their keys.
3. Set the watermark to the highest `daaScore` processed.

New rows arriving while you page only shift later pages, which the keys make harmless. Do not
track progress by `total`: history keeps the most recent 20 000 rows and drops the oldest
10 000 in one step when it reaches that size, so `total` is not monotonic. Poll at least every
few minutes, far inside that window.

**Reconciliation.** Once an hour, with `/api/status` showing `synced: true` and
`missing_history: false`, read the complete history and check that every key you credited at
or above the oldest row's `daaScore` is still present. A credited deposit that is missing is a
reorganisation deeper than the settlement margin — the wallet rebuilds itself after one — and
must go to review. Do not reconcile while the wallet is rebuilding (`synced: false`): its
history is incomplete until it catches up.

**Credited is not yet spendable.** A received note can be spent once it is past the matured
anchor (~10 minutes). Customer balances can be credited at once; what the exchange can pay out
is `spendable_sompi` in `/api/status`, with recent deposits in `maturing_sompi`.

The mempool preview (`pending_in_sompi`) shows an incoming payment about a second after the
sender presses send. Use it for a "deposit detected" notice, never for credit.

**Memos.** Each credit carries the memo the payer attached to that output, read from the full
transaction just after the row is written — normally within the same sync pass. A received row
shows `feeKnown: false` until that read is done (retried every 10 minutes if the node does not
answer). Memos are written by the payer and prove nothing about who sent the payment; if you
attribute by memo, wait for `feeKnown: true`.

#### Withdrawals

Book a withdrawal on your ledger **before** sending it, and settle it from the answer:

1. Debit the customer and mark the withdrawal *pending* under a unique, never-reused id.
2. **If the destination is one of your own deposit addresses, do not broadcast.** Settle it as
   an internal transfer on your ledger. A payment from your hot wallet to your own address is
   recorded as your own send, so the receiving customer would never see a `received` credit.
3. Send it with that id as `request_id`:

```bash
curl -X POST -H "X-Wallet-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"to":"zkas:...customer...","amount_sompi":25000000000,"memo":"withdrawal 88213",
       "request_id":"withdrawal-88213","max_total_fee":50000000}' \
  http://127.0.0.1:8501/api/wallet/send
```

4. Settle it from the status (§4):

| Answer | Withdrawal state |
| --- | --- |
| **200** | **Paid.** Record every id in `txids` (a payment needing more than 38 notes is split; `tx_count` > 1). |
| **409 `already_sent`** | **Paid earlier** by this same request. Compare `already_sent.amount_sompi_exact` with the amount: if it is lower, an earlier attempt paid only part of it (the listed transactions); settle the remainder as a new withdrawal with a new id. |
| **409 `in_progress`** | **Pending.** The same request is still being sent; retry later with the same id. |
| **400, 503, or 502 without `txids`** | **Not paid.** Return the funds to the customer or retry. |
| **502 with `txids`** | **Partly paid**: the listed transactions went out; settle the remainder as a new withdrawal with a new id. |
| **504 `outcome_unknown`**, a timeout, or no answer | **Possibly paid.** Keep it pending and retry with the **same** `request_id` until you get one of the answers above. Never re-issue it under a new id, and never return the funds on a timeout. |

- **Request ids are unique per payment, forever** — your withdrawal id is ideal. The daemon
  answers a repeated id from its record only when the recipient and amount also match, so an
  id accidentally reused for a different payment is treated as a new payment rather than
  reported as already paid. Records survive restarts for 24 hours; retry within that window.
- **`max_total_fee`** caps what one withdrawal may pay in fees; a plan above it is refused
  before proving.
- **Invalid or non-shielded addresses** are refused (400) before any work is done.
- **Throughput.** Payments from one wallet run one at a time, so a consolidated hot wallet
  handles a withdrawal every few seconds. For more volume, batch queued withdrawals with
  `send_many` (up to 37 per transaction, one proof; each payee keeps its own memo, and
  `payee_txids` reports which transaction paid whom), or run several hot wallets.
- **Prefer `amount_sompi`** (an integer) to `amount_fc` (a floating-point number).

#### Proof of payment for disputes

When a customer says a withdrawal never arrived, produce a proof:

```bash
curl -s -H "X-Wallet-Token: $TOK" "http://127.0.0.1:8501/api/wallet/proof?txid=<txid>"   # → { "proofs": [ … ] }
```

Each proof discloses one output — recipient, amount, memo — and nothing else about the
transaction or the wallet. Anyone can check one against the chain with
`POST /api/proof/verify`, which needs no wallet or token and answers `valid`, the recipient,
amount, memo and confirmations. Generate and store the proof when the withdrawal settles: it
needs the node to still hold that block's body. Sends are provable because the daemon encrypts
each payment's details to the wallet's own outgoing key; leave `private_sends` off (the
default) on exchange wallets.

#### Cold storage and sweeps

Sweep the hot wallet's excess to the cold address with an ordinary `send`, using a
`request_id` such as `sweep-2026-11-05`. Keep the hot wallet consolidated: sweeping a large
balance out of a fragmented wallet is the most expensive operation in the system. Back up the
cold seed as `seed_hex` (or your own mnemonic encoding of it) and verify the restore before
funding.

#### Monitoring

| Signal | Alert when |
| --- | --- |
| `GET /health` | not 200 |
| `/api/status` → `node_connected`, `error` | false / set |
| `/api/status` → `synced`, `blocks_behind` | not synced, or behind for more than a few minutes |
| `/api/status` → `missing_history` | true: the node could not serve part of the wallet's history; its balance and history are incomplete — pause automated crediting decisions |
| `/api/status` → `note_count` | climbing steadily (consolidation is not keeping up) |
| `/api/status` → `spendable_sompi` | below your withdrawal float |
| `/api/wallet/history` → `pendingOutgoing` | a withdrawal pending for more than an hour |
| log: `OUTCOME UNKNOWN` | always (reconcile that withdrawal) |
| log: `auto-consolidate: merge failed`, `tree does NOT equal the node's` | always |
| reconciliation (above) | a credited deposit missing from history |
| a received row with empty or mismatched `credits[]`, or an unknown address | always (manual review) |

Reconcile daily: the sum of credited deposits minus withdrawals and fees, against the hot
wallet's `balance_sompi` plus the cold wallet's.

#### Backups and recovery

Back up `--wallet-dir` — it holds each wallet's (encrypted) seed file, its scan checkpoint and
the request-id records — together with the tokens, and keep `ZKAS_WALLET_SECRET` in a separate
secrets store: the encrypted seed files are unreadable without it. The seed alone always
recovers the funds: import it with a `birthday` before the wallet's first deposit, and the
daemon rebuilds balance and history from the chain.

---

## 8. Operations

### Log lines worth knowing

```
prepare: batch-witnessed 38/38 notes in 538.8ms        # witness phase — expect milliseconds
prepare: Halo2 proof took 5.1s                         # proving — expect seconds
subtree cache complete for … in 38.1s                  # one-time, per wallet
subtree cache build for … did not install …            # INVESTIGATE: falling back to replay
subtree cache deferred …: only N MB free               # add RAM, or accept replay on that wallet
tree verified: equals the node's at block …            # chain-file data confirmed by the node
auto-consolidate: merged 38 notes into one …           # healthy; treasury staying compact
auto-consolidate: merge failed …                       # INVESTIGATE: treasury will fragment
submit: transaction … transport failure …; sending the same transaction again   # resend in progress
submit: transaction …: OUTCOME UNKNOWN …               # a 504 was returned; reconcile
submitted spend … is still in the node's mempool …; kept pending   # slow confirmation, not lost
submitted spend … never appeared on-chain …; note returned         # lost transaction, funds restored
```

### Troubleshooting

**`409 wallet checkpoint is being repaired after a reorg`** — transient; retry.

**`409 wallet has not established a matured anchor yet`** — initial sync is still in
progress. This is not a tip-proximity check: a wallet slightly behind the tip can still pay.

**`insufficient matured funds`** — usually notes received within the last ~10 minutes
(`maturing_sompi`) rather than an empty wallet; the error reports what is available. If it
mentions stranded notes, run `--diagnose`.

**Stranded notes** (`no witness path`) — a note below the compaction base. Diagnose with
`--diagnose`; repair with `--graft TOKEN:/path/to/older.scan` from an older snapshot of the
same wallet. Keep `.scan.bak` files.

**A payment appears slow** — look for `batch-witnessed` / `Halo2 proof took` in the log. If
proving is running, the payment is progressing; check that the proxy read timeout is long
enough (§1). Avoid restarting the daemon repeatedly while diagnosing: each restart reloads
every active wallet.

**The first consolidation or old-note spend is slow** — the O(depth) witness cache is cold.
Pre-warm it with `POST /api/admin/warm_chain_tree` (covers most wallets) and
`POST /api/admin/warm_wallet` for a wallet whose notes predate the shared tree's base; poll
until `subtree_cache_ready: true`.

**Rescanning.** `POST /api/wallet/rescan` rebuilds a wallet from whatever the node can serve,
so the daemon first confirms that the node serves the chain **from genesis** and refuses
otherwise; a rescan against a node that cannot would silently omit older notes. Override with
`{"force": true}` only when you know the wallet holds nothing older than the node's history.
Prefer a node that keeps the full shielded history.

### Backups

Back up `--wallet-dir` (a wallet file and a `<token>.scan` checkpoint per wallet) **and** the
tokens — a token is the credential. Seeds are encrypted only when `--wallet-secret` is set.
For wallets whose seed lives on the user's device (the web, mobile and desktop wallets), the
daemon's files cannot spend: recovery always uses the user's own seed.
