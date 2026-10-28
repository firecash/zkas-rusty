# `shielded-pay` — CLI wallet

Quick offline/CLI operations against a running node. For everyday use prefer the wallet
daemon ([WALLETD.md](WALLETD.md)) or the web/mobile wallet — this tool takes seeds as a
single repeated byte (`[byte; 32]`) for test convenience and exists for testing and
scripted checks, not for holding real balances.

**Never put real funds on a `--seed-byte` wallet.** `--seed-byte N` builds the seed
`[N; 32]`, which anyone can reproduce and spend from. It exists for tests only. Create a
real wallet with `new`, keep the seed it prints secret, and pass it as `--seed-hex`.

```bash
# Create a wallet: a fresh random seed and its shielded address (give the address to a
# sender or the miner's -a; keep the seed secret)
./shielded-pay new --network mainnet

# Obtain the address of an existing seed
./shielded-pay address --seed-hex <your-64-hex-seed> --network mainnet

# Check spendable balance + owned notes (scans the chain via the node RPC)
./shielded-pay balance -s 127.0.0.1:16810 --seed-hex <your-64-hex-seed>

# Send a private payment (amount/fee in sompi; change returns to you)
./shielded-pay send -s 127.0.0.1:16810 --owner-seed-hex <your-64-hex-seed> \
  --to zkas:<recipient-address> --amount 500000000 --fee 3000000

# Prove you control an address without spending (offline; discloses viewing key)
./shielded-pay sign   --seed-stdin --network mainnet --message "gm"
./shielded-pay verify --address zkas:<addr> --message "gm" --signature <hex>
```

## Export a full viewing key without putting a seed in argv

`sign` prints `full-viewing-key || signature` as hexadecimal. The first 192 hexadecimal
characters are the full viewing key (FVK), which can be used by a watch-only wallet to
detect incoming notes but cannot spend them.

For a real seed, use `--seed-stdin` rather than `--seed-hex`: command-line arguments
can be visible to other local processes. This option is deliberately available only to
the offline `sign` command; it is mutually exclusive with `--seed-hex` and
`--seed-byte`, and cannot make an RPC payment.

Run this only on a trusted local machine. It avoids argv, environment, and shell-history
exposure, but cannot protect a compromised machine or privileged local process from
reading memory.

```bash
read -rsp 'Seed (64 hex): ' SEED; echo
SIG=$(printf '%s' "$SEED" | ./shielded-pay sign \
  --seed-stdin --network mainnet --message zkas-watch-export-v1)
unset SEED
FVK=$(printf '%s\n' "$SIG" | awk '/^signature:/ {print substr($2, 1, 192)}')
unset SIG
printf '%s\n' "$FVK"
```
