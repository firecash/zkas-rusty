# Trustless Burn

*Destroying ZKAS verifiably — even by an entity nobody trusts — with no way for that entity to
secretly retain a spend key or to lie about the burn.*

Status: design note. The address construction and the burn **proof** work today with no consensus
change (they reuse `shielded-core::payment_check`). A *supply-reducing* burn (the turnstile total
actually dropping) needs the small consensus change in §6.

---

## 1. Problem

We want some entity — a fee router, treasury, bridge, oracle guild, service — to **burn** ZKAS, and
we do **not** trust it. Two things must be impossible for that entity:

1. **Retain a spend key.** It must not be able to hand out a "burn address" that is really an address
   it controls, so it could quietly spend the "burned" coins later.
2. **Lie.** Its claim "I burned V ZKAS" must be independently verifiable, not taken on its word.

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
2. **A per-transaction burn proof** — a single-note disclosure that binds "output X of tx T paid
   value V to the canonical burn address" to on-chain data. It is cryptographically unforgeable and
   reveals *only that one note* — never a viewing key.

Trust properties this achieves:

| Property | Guaranteed? | Why |
|---|---|---|
| Entity knows a spend key for the burn address | **No** | recovering it = discrete-log on Pallas; back-dooring it = 2nd-preimage on the hash; and the address is protocol-fixed, so the entity has no freedom |
| Anyone can verify the address is the genuine burn address | **Yes** | it is a deterministic function of a public string |
| Entity can forge a fake burn proof | **No** | the proof is bound to the on-chain note commitment and value commitment |
| Coins are gone forever | **Yes (no-fork)** | the note is unspendable by anyone |
| Recorded/turnstile supply drops | **No-fork: no. Fork: yes** | supply accounting is consensus state (§6) |
| Entity can be *forced* to burn / to disclose | **No-fork: no** | close by gating the incentive on the proof, or by the consensus burn (§6) |

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

## 4. Low level — the burn transaction and its proof

**The burn tx** is an ordinary shielded spend: input note(s) → one output note to the canonical burn
address carrying value `V`, with change back to the burner. On-chain it is indistinguishable from a
normal payment (recipient encrypted).

**The burn proof** is a single-note disclosure that reuses the verifier ZKas already ships,
`shielded-core::payment_check` (`check_prepared_payment` + `ActionDisclosure`). For the burn output
action the burner discloses:

```
ActionDisclosure {
    out_recipient : [u8; 43],   // MUST equal the canonical burn address raw bytes
    out_value     : u64,        // = V
    out_rseed     : [u8; 32],
    rcv           : [u8; 32],   // value-commitment trapdoor
    spend_value   : u64,
}
```

Verification (all already implemented in `payment_check.rs`, plus one burn-specific line):

1. `rho` = **that action's nullifier**, read from the bundle itself — not asserted by the prover.
2. `rseed = RandomSeed::from_bytes(out_rseed, rho)`; `recipient = Address::from_raw_address_bytes(out_recipient)`.
3. `note = Note::from_parts(recipient, out_value, rho, rseed, V2)`.
4. **Commitment bind:** `ExtractedNoteCommitment::from(note.commitment()) == act.cmx` (the on-chain
   note commitment). `cmx` is a *binding* commitment, so a disclosure that recomputes to the on-chain
   `cmx` **is** that note — the recipient, value and `rho` are pinned; no other plaintext can match.
5. **Value bind:** `ValueCommitment::derive(spend_value − out_value, rcv) == act.cv_net`, pinning the
   amounts to the on-chain value commitment.
6. **Burn check (the added line):** `out_recipient == CANONICAL_BURN_ADDRESS` (the §3 constant).

If all pass, the proof establishes, against on-chain data the entity cannot alter, that **this output
burned exactly `V` to the canonical unspendable address.** A forged disclosure produces a mismatch at
step 4 or 5, so the entity cannot lie.

A burn-specific wrapper (e.g. `check_burn(wire, disclosure, height) -> V`) is just
`check_prepared_payment` with `to = CANONICAL_BURN_ADDRESS` and no `fvk`/change accounting — a thin
addition, not new cryptography.

---

## 5. Should the user share the per-tx proof, or a viewing key?

**The per-transaction (single-note) `ActionDisclosure` — never a viewing key.**

- A burn only needs to prove **one** fact: "this specific on-chain output burned `V` to the canonical
  address." The `ActionDisclosure` above proves exactly that and nothing else.
- Sharing **OVK / FVK / IVK** would expose **all** of the entity's transactions — every incoming
  and/or outgoing note, past and future — which is catastrophic over-disclosure and destroys the
  privacy of everything unrelated to the burn.
- The burner uses its **OVK locally** to recover its own output's plaintext (that is what OVK is for),
  but publishes only the recovered per-note fields, **not the OVK itself.**

So: minimal, sufficient, privacy-preserving, and unforgeable. One burn = one `ActionDisclosure`.

---

## 6. The residual gap, and the fork that closes it fully

**No-fork residual.** Because recipients are encrypted, a burn is invisible until the entity
discloses, and no-fork logic cannot *compel* an untrusted entity to burn or to publish the proof. It
can only make a *false* proof impossible. Close the gap by design: make a valid burn proof a
**required precondition** of whatever the burn is *for* (a fee credit, a mint, a reward, a listing).
No valid proof ⇒ no credit ⇒ no incentive to fake or to withhold. The recorded supply still does not
change — the coins are frozen, not subtracted.

**Fork = fully trustless, supply-reducing.** The primitive already exists: `burn::ExitReceipt`,
`burn::BurnAccumulator`, and the turnstile invariant `pool = coinbase + pegged_in − fees − burns`,
whose burn root is folded into the shielded state root (`consensus/src/processes/shielded.rs`). It is
gated behind `BRIDGE_ENABLED = false` and today only serves peg-out. A **standalone consensus burn**:

- accept an output that pays the **canonical burn address** (or a dedicated burn-output type),
- have consensus verify it (the §4 checks) and add `V` to the `BurnAccumulator` ⇒ subtract from the
  turnstile,

makes the node itself enforce the burn: any non-canonical "burn" is rejected, supply visibly drops for
everyone, and even withholding is impossible — **zero trust in the entity.** This is a small,
coordinated hardfork (it relaxes tx validity and changes supply accounting, so old nodes would reject
the new blocks), reusing the accumulator that is already present.

---

## 7. Summary

| | No-fork (today) | Fork (small) |
|---|---|---|
| Burn address | canonical NUMS, publicly recomputable | same |
| Spend key exists for it | no (DLP + 2nd-preimage) | no |
| Entity can substitute its own address | no (recomputable) | no (consensus checks canonical) |
| Entity can forge a burn proof | no (`payment_check` binding) | no |
| Coins unspendable forever | yes | yes |
| Recorded supply drops | **no** | **yes** |
| Entity can withhold / not burn | yes — gate the incentive on the proof | no — consensus enforces |
| Publicly visible without disclosure | no (shielded) | yes (turnstile total) |

**Bottom line:** a canonical hash-derived burn address (no key can exist, anyone recomputes it) plus a
per-note `payment_check` disclosure (no forgeable lie) gives a trustless, verifiable burn **today with
no fork** — the coins are provably gone. Turning that into a *supply-reducing* burn an untrusted entity
cannot even withhold is the small consensus change in §6, reusing the existing `BurnAccumulator`.
