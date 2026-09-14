# Trustless Burn

*Destroying ZKAS verifiably — even by an entity nobody trusts — with no way for that entity to
secretly retain a spend key or to lie about the burn.*

Status: design note. The address construction and the OVK-based verification work today with no
consensus change (the note-binding reuses `shielded-core::payment_check`). A *supply-reducing* burn
(the turnstile total actually dropping) needs the small consensus change in §6.

---

## 1. Problem

We want some entity — a fee router, treasury, bridge, oracle guild, service — to **burn** ZKAS, and
we do **not** trust it. Two things must be impossible for that entity:

1. **Retain a spend key.** It must not be able to hand out a "burn address" that is really an address
   it controls, so it could quietly spend the "burned" coins later.
2. **Lie / hide.** Its burns must be independently verifiable, not taken on its word — and it must not
   be able to *withhold* a burn or quietly divert the funds instead.

Constraints of the substrate:

- ZKas is **shielded by default** — there is no transparent "send-to-nowhere" address, and a note's
  recipient is encrypted, so a payment is not publicly visible.
- **No VM / no covenants on notes** — an entity cannot be *forced* by on-chain logic to burn; only
  whoever holds a note's spend key can move it.
- A standalone consensus burn does not exist yet: the `burn::ExitReceipt` + `BurnAccumulator` +
  turnstile `burns` machinery is present but gated behind `BRIDGE_ENABLED = false` and wired only to
  peg-out (see §6).

---

## 2. High level

The scheme has two independent halves:

1. **A canonical NUMS burn address** — a normal ZKas address whose public key is the output of a
   public hash, so *no private key for it exists* and *anyone can recompute it*. The untrusted entity
   never generates it, so it cannot substitute one it controls.
2. **A published OVK on a dedicated burn account** — the entity runs one ZIP-32 account used *only*
   for burning, and publishes that account's **outgoing viewing key (OVK)**. Because the OVK decrypts
   every note the account *sends*, anyone can enumerate and verify **all** of the entity's burns,
   continuously, with no further action from the entity — and can see any attempt to send funds
   somewhere other than the canonical burn address.

Trust properties this achieves:

| Property | Guaranteed? | Why |
|---|---|---|
| Entity knows a spend key for the burn address | **No** | recovering it = discrete-log on Pallas; back-dooring it = 2nd-preimage on the hash; and the address is protocol-fixed, so the entity has no freedom |
| Anyone can verify the address is the genuine burn address | **Yes** | it is a deterministic function of a public string |
| Entity can forge a fake burn | **No** | every disclosed note is bound to the on-chain note commitment and value commitment |
| Entity can hide a burn, or divert funds elsewhere from the account | **No** | the published OVK decrypts *every* outgoing note of the account, so both burns and any diversion-send are visible |
| Coins are gone forever | **Yes (no-fork)** | the note is unspendable by anyone |
| Recorded/turnstile supply drops | **No-fork: no. Fork: yes** | supply accounting is consensus state (§6) |

---

## 3. Low level — the canonical burn address

A ZKas address is Orchard's `Address`: a **43-byte raw form** = `d ‖ pk_d`

- `d` — 11-byte diversifier,
- `pk_d` — 32-byte Pallas point (the diversified transmission key),

encoded as a `zkas1…` bech32 string. (`orchard::Address::to_raw_address_bytes()` /
`Address::from_raw_address_bytes()` in `shielded-core`.)

A **normal** address sets `pk_d = [ivk]·g_d`, where `g_d = DiversifyHash(d)` and `ivk` comes from a
spending key. To spend a note sent there you must know that `ivk` (and the full spending key).

A **burn** address skips the key entirely:

```
pk_d = GroupHash^Pallas( domain = "ZKas:burn:v1", msg = "" )
```

`GroupHash^Pallas` is Orchard's hash-to-curve on Pallas — the same primitive that derives `g_d` and
the value-commitment generators — so its output is a valid prime-order Pallas point whose **discrete
log is unknown to everyone.** Then:

```
for i = 0, 1, 2, …:
    d = BLAKE2b-256("ZKas:burn:v1:div" ‖ i)[..11]
    if Address::from_raw_address_bytes(d ‖ pk_d) is Some:   # validates d and pk_d
        burn_address = that
        break
```

Publish the two domain strings + this procedure. Anyone recomputes `pk_d`, finds the same first valid
`d`, re-derives the identical `zkas1…`, and confirms it matches the address the entity used.

Why the entity cannot cheat the address:

- **No key can be recovered.** Spending needs `ivk = dlog_{g_d}(pk_d)`. `pk_d` is a hash output ⇒
  finding it is discrete-log on Pallas ⇒ infeasible. (You cannot "keep a backdoor" to a key that
  does not exist.)
- **No key can be back-doored via string choice.** To pick a string whose hash lands on a point whose
  key it *does* know, the entity would compute a known-key point first and then find a preimage string
  — a second-preimage on the group hash ⇒ infeasible.
- **The entity has no freedom anyway.** The domain strings are fixed by the protocol/spec, not chosen
  by the entity. It may only *send to* the resulting fixed address.
- **The chain accepts it like any address.** Consensus and senders never check `pk_d = [ivk]·g_d`;
  `from_raw_address_bytes` only checks `pk_d` is a valid point and `d` a valid diversifier. So the burn
  address is *payable-to* exactly like a normal one — and *payable-from* by no one.

---

## 4. Low level — the burn transaction and how it is verified via the OVK

**The burn tx** is an ordinary shielded spend from the entity's dedicated burn account: input note(s)
→ one output note to the canonical burn address carrying value `V`, with change back to the same
account. On-chain it is indistinguishable from a normal payment (recipient encrypted).

**Verification via the published OVK.** In Orchard, every action carries an `out_ciphertext`
encrypted under a key derived from the sender's **OVK**, containing the note's `(recipient, value,
rseed)`. So a verifier who holds the account's OVK can, for every outgoing note that account ever
produced:

1. Decrypt `out_ciphertext` with the OVK → recover `(recipient, value, rseed)`; `rho` is that action's
   nullifier, taken from the bundle itself.
2. Reconstruct `note = Note::from_parts(recipient, value, rho, rseed, V2)` and check
   `ExtractedNoteCommitment(note) == act.cmx` — the on-chain note commitment. `cmx` is a *binding*
   commitment, so the recovered plaintext **is** that note; recipient, value and `rho` are pinned.
3. Check `ValueCommitment::derive(spend_value − value, rcv) == act.cv_net`, pinning the amount.
4. Check `recipient == CANONICAL_BURN_ADDRESS` (the §3 constant).

Steps 2–3 are exactly the binding logic already implemented in `shielded-core::payment_check`
(`check_prepared_payment` / `ActionDisclosure`); the burn verifier is that logic driven from
OVK-decrypted plaintexts, plus step 4. An output whose recipient is the canonical address and whose
`cmx`/`cv_net` match the chain is a proven burn of exactly `V`; any output to a *different* recipient
is a proven diversion. Neither can be faked, because both are bound to on-chain data.

---

## 5. What the entity reveals: the OVK of a dedicated burn account

**Reveal the account's OVK — on an account used only for burning.** This is the disclosure primitive.

- The OVK is the **outgoing** viewing key: it decrypts the `out_ciphertext` of every note *this
  account sent*, letting anyone recover `(recipient, value, rseed)` for each and run the §4 checks. It
  reveals **all outgoing notes of that one account** — and nothing else: it does **not** grant spend
  authority, and it does **not** reveal the account's incoming notes (that is the IVK).
- **Use a dedicated burn account.** Because the OVK exposes *every* send of the account it belongs to,
  it must be an account the entity uses *only* to receive-then-burn. On such an account the OVK
  discloses exactly the burns and nothing sensitive. **Never publish the OVK of a general-purpose
  account** — that would reveal every unrelated payment the account ever made.
- **Why the OVK beats a one-off per-tx disclosure here.** With the OVK published once, burns become
  *continuously and publicly auditable with no action from the entity*, and the entity **cannot
  withhold**: it can neither hide a burn nor quietly divert funds — any send that is *not* to the
  canonical burn address is decrypted by every OVK holder and visible as a diversion. A per-tx
  disclosure only ever proves the burns the entity chooses to reveal; the OVK proves the *whole*
  outgoing history of the account.
- **If you also need full in/out reconciliation** ("everything that entered the account was burned,
  nothing is merely being held"), publish the account's **FVK** instead — that adds visibility of
  *incoming* notes too, at the cost of revealing them. The OVK alone proves the burns and rules out
  send-diversions; the FVK additionally rules out silent holds.

Summary: **publish the OVK of a dedicated burn account** (or its FVK for full in/out accounting) —
never a general account's keys, and never the spending key.

---

## 6. The residual gap, and the fork that closes it fully

**No-fork residual.** Publishing the OVK removes the withholding/diversion problem for that account,
but the burn still does not reduce the *recorded* supply — the coins are frozen (unspendable forever),
not subtracted from the turnstile total. And the guarantee only extends to the account whose OVK was
published; you rely on the entity having routed the funds through that account (make routing-through-
the-burn-account, and publishing its OVK, a required condition of whatever the burn is *for* — a fee
credit, a mint, a reward — so a non-compliant entity simply gets no credit).

**Fork = fully trustless, supply-reducing.** The primitive already exists: `burn::ExitReceipt`,
`burn::BurnAccumulator`, and the turnstile invariant `pool = coinbase + pegged_in − fees − burns`,
whose burn root is folded into the shielded state root (`consensus/src/processes/shielded.rs`). It is
gated behind `BRIDGE_ENABLED = false` and today only serves peg-out. A **standalone consensus burn**:

- accept an output that pays the **canonical burn address** (or a dedicated burn-output type),
- have consensus verify it (the §4 checks) and add `V` to the `BurnAccumulator` ⇒ subtract from the
  turnstile,

makes the node itself enforce the burn: any non-canonical "burn" is rejected, supply visibly drops for
everyone, and even withholding is impossible — **zero trust in the entity, no OVK needed.** This is a
small, coordinated hardfork (it relaxes tx validity and changes supply accounting, so old nodes would
reject the new blocks), reusing the accumulator that is already present.

---

## 7. Summary

| | No-fork (today) | Fork (small) |
|---|---|---|
| Burn address | canonical NUMS, publicly recomputable | same |
| Spend key exists for it | no (DLP + 2nd-preimage) | no |
| Entity can substitute its own address | no (recomputable) | no (consensus checks canonical) |
| What the entity reveals | the OVK of a dedicated burn account | nothing (consensus enforces) |
| Entity can forge a burn | no (`payment_check` binding) | no |
| Entity can hide a burn / divert funds | no (OVK shows all sends) | no (consensus) |
| Coins unspendable forever | yes | yes |
| Recorded supply drops | **no** | **yes** |
| Publicly visible without any disclosure | no (needs the OVK) | yes (turnstile total) |

**Bottom line:** a canonical hash-derived burn address (no key recoverable — DLP-hard; anyone recomputes it) plus a
**published OVK on a dedicated burn account** (every burn, and every diversion, publicly and
continuously verifiable, unforgeable) gives a trustless, auditable burn **today with no fork** — the
coins are provably gone and the entity cannot hide or fake. Turning that into a *supply-reducing* burn
is the small consensus change in §6, reusing the existing `BurnAccumulator`.

---

## 8. The canonical `v1` burn address (generated)

Generated by the deterministic process below and committed here as the canonical `ZKas:burn:v1`
address:

```
zkas:p8wetdtxmkh0zfg0hkxylhcws7eyn8utcz4vjvfs5p5zedgr9yeszppnxkx928aadqfaetqz3ppmpsu
```

- `pk_d` = `4fdf0e87b2499f8bc0aac93130a0682cb5032933010433358c551fbd6813dcac`
- `d`    = `dd95b566ddaef1250fbd8c`
- raw (43 bytes, `d ‖ pk_d`) = `dd95b566ddaef1250fbd8c4fdf0e87b2499f8bc0aac93130a0682cb5032933010433358c551fbd6813dcac`

### Exact process — anyone reproduces the identical address

1. **`pk_d`** — the smallest integer `i ≥ 0` for which
   `BLAKE2b-256("ZKas:burn:v1:pkd" ‖ u64_le(i))[..32]` is a valid Orchard diversified
   transmission key (a point on Pallas). Result: **`i = 1`**.
2. **`d`** — the smallest integer `j ≥ 0` for which
   `BLAKE2b-256("ZKas:burn:v1:div" ‖ u64_le(j))[..11]` forms a valid Orchard address together
   with that `pk_d`. Result: **`j = 0`**.
3. **encode** — bech32 with HRP `zkas`, version byte `9` (`ShieldedOrchard`), payload `d(11) ‖ pk_d(32)`
   — i.e. exactly
   `String::from(&kaspa_addresses::Address::new(Prefix::Mainnet, Version::ShieldedOrchard, &raw))`,
   the **same call wallets use for every shielded address**, so a sender pays it like any normal
   address.

`u64_le(x)` is the little-endian 8-byte encoding of the counter. Both domain strings are fixed,
public, pre-committed constants — nobody chooses them per burn.

### The generator (in-tree, reproduces the address byte-for-byte)

Committed as `kaspad/src/bin/zkas-burn-address.rs`; run with
`cargo build --release -p kaspad --bin zkas-burn-address && ./target/release/zkas-burn-address`.
The core of it:

```rust
use blake2b_simd::Params;
use kaspa_addresses::{Address as KAddr, Prefix, Version};
use orchard::Address;

fn h(domain: &[u8], counter: u64, n: usize) -> Vec<u8> {
    Params::new().hash_length(32).to_state()
        .update(domain).update(&counter.to_le_bytes()).finalize()
        .as_bytes()[..n].to_vec()
}

fn main() {
    for i in 0u64.. {
        let pk_d = h(b"ZKas:burn:v1:pkd", i, 32);
        for j in 0u64..4096 {
            let d = h(b"ZKas:burn:v1:div", j, 11);
            let mut raw = [0u8; 43];
            raw[..11].copy_from_slice(&d);
            raw[11..].copy_from_slice(&pk_d);
            if bool::from(Address::from_raw_address_bytes(&raw).is_some()) {
                let s: String =
                    (&KAddr::new(Prefix::Mainnet, Version::ShieldedOrchard, &raw)).into();
                println!("{s}");
                return;
            }
        }
    }
}
```

### What this guarantees — precise wording

- **Unspendable in practice.** Pallas is a *prime-order* curve, so a spend key `ivk` with
  `pk_d = [ivk]·g_d` does exist mathematically — but recovering it is a discrete log on Pallas, i.e.
  computationally infeasible. Nobody can ever spend coins sent here. (This is the standard NUMS
  "provably unspendable" guarantee. Read the shorthand "no key can exist" elsewhere in this doc as
  "no key is *recoverable*.")
- **Un-backdoorable.** Because `"ZKas:burn:v1…"` is a fixed, pre-committed public domain, no one could
  have ground a string onto a point whose key they know — that is a second-preimage on BLAKE2b.
- **Recomputable by anyone**, deterministically, from the two domain strings above — no operator input,
  no trust.
