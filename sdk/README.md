# ZKas SDK

The SDK is the reusable foundation underneath ZKas wallets and integrations.
Rust is the canonical implementation; browser, Node.js, mobile, and other
language packages are bindings around the same reviewed code.

## Layout

- `wallet-engine/` — transport-independent wallet policy and, incrementally,
  synchronization, storage, transaction lifecycle, and history.
- `signer/` — reusable key custody and anti-blind payment authorization.
- `core/` — public `zkas-sdk` facade, BlockDAG sync API, stores, addresses,
  prepared-payment format, and examples.
- `bindings/` — pointers to out-of-tree bindings; the TypeScript package lives
  at <https://gitlab.com/zkas-group/zkas-sdk>.
- `docs/ARCHITECTURE.md` — target architecture and phased implementation plan.
- `docs/RESEARCH.md` — external SDK and wallet designs reviewed for this work.
- `docs/USAGE.md` — integration and security guide.
- `docs/STATUS.md` — implemented v1 scope and remaining platform work.

The production `zkas-walletd` consumes these crates. Existing wallet behavior is
moved here incrementally and tested; it is not replaced with an unrelated wallet.
