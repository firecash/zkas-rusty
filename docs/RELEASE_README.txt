===============================================================================
 ZKas — release binaries
===============================================================================

This archive contains statically-linked ZKas binaries. ZKas is a
shielded-by-default (Orchard / Halo 2) fork of rusty-kaspa; kHeavyHash PoW,
1 block/second, ticker $ZKAS. 1 ZKAS = 100,000,000 sompi.

-------------------------------------------------------------------------------
 What's in here
-------------------------------------------------------------------------------
  kaspad           ZKas full node. Run with --utxoindex.
  zkas-miner       Built-in CPU miner (kHeavyHash). Enough to bootstrap /
                   solo-mine; for real hashrate use an ASIC or GPU (see below).
  shielded-pay     CLI shielded wallet: derive a zkas: address, check
                   balance, send private payments, and sign/verify address
                   ownership. Offline-capable for address + sign/verify.
  zkas-walletd     Local wallet daemon (REST) that powers the web/mobile wallet.
  zkas-api         Explorer / network-stats API server.
  stratum-bridge   Stratum bridge for pointing ASICs/pools at a ZKas node.

-------------------------------------------------------------------------------
 GPU / ASIC mining
-------------------------------------------------------------------------------
There is NO bundled GPU miner. ZKas's proof-of-work is kHeavyHash,
BYTE-IDENTICAL to Kaspa, so any existing Kaspa kHeavyHash miner works unchanged:

  - GPU:  bzminer, lolMiner, Rigel, etc. — point them at a ZKas node's
          stratum (or the pool at pool.zkas.info) with a
          zkas: address as the username.
  - ASIC: IceRiver / Bitmain / Goldshell kHeavyHash units work as-is.

The bundled zkas-miner is CPU-only and intended for bootstrapping or solo
low-difficulty mining, not competitive hashrate.

-------------------------------------------------------------------------------
 Wallets
-------------------------------------------------------------------------------
  - CLI:    shielded-pay  (in this archive)
  - Web:    https://wallet.zkas.info   (also has on-device "Local" tools)
  - Paper:  https://zkas.info/paper-wallet.html  — an OFFLINE,
            single-file cold-storage wallet. Save it, go offline, generate.
            Source: https://gitlab.com/zkas-group/zkas-paper-wallet

Quick start:
  ./kaspad --utxoindex
  ./shielded-pay address --seed-byte 1 --network mainnet
  ./zkas-miner -s 127.0.0.1:16810 -a zkas:<your-address> -t 4
===============================================================================
