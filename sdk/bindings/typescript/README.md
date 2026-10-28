# @zkas/sdk (TypeScript)

The TypeScript SDK moved to its own repository so integrators get a clean
package without the node workspace:

    https://zkas.info/code/sdk

It has no Rust build dependency (it talks to `zkas-walletd` over HTTP and takes
the WASM signer by injection), so nothing here needs it at build time. The wire
contract it consumes — `PreparedPaymentEnvelope` version 2 — is pinned by the
golden-vector test in `sdk/core/src/prepared.rs`; changing that format means
updating `src/types.ts` in the SDK repo in the same breath.
