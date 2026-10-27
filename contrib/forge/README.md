# Code hosting, CI and release infrastructure

GitHub (2026-10-23) and GitLab (2026-10-24) both blocked the ZKas account. Since then
the source of truth is **Radicle**; nothing depends on a forge account.

## Where things are

| What | Where |
|---|---|
| All repos, browsable | https://zkas.info/code (one page) and `zkas.info/code/<name>` |
| Clone | `git clone https://zkas.info/code/<name>.git` or `rad clone <RID>` |
| Wallet releases | https://zkas.info/downloads/wallet/ (+ `releases.json`, the in-app update feed) |
| Seed node | 207.241.172.71: `radicle-node` (:8776) and `radicle-httpd` behind nginx at https://207-241-172-71.sslip.io |

Names for `zkas.info/code/<name>`: rusty (node), wallet, signer, explorer, sdk,
gateway, website, blog, paper-wallet, vprogs, bridge.

## Files here

- `rad-publish`: the only way commits reach a repo's canonical `main`. A box pushes to
  `refs/heads/incoming/<branch>` on the seed's checkout, then `rad-publish <repo> <branch>`
  fast-forwards (and refuses anything else), pushes to Radicle signed by the maintainer
  key, and announces to the seeds.
- `rad-canon-tags`: re-pushes every tag so the `refs/tags/*` canonical rule applies to
  tags that existed before the rule.
- `radicle-node.service`, `radicle-httpd.service`: systemd units on the seed (one
  `--alias` per repo gives the short names).
- `nginx-radicle-seed.conf`: the seed's nginx (certificate from Let's Encrypt via certbot).
- `nginx-zkas-code-map.conf`, `nginx-zkas.info-locations.conf`: on VPS1, the
  `/code/...` short links and clone proxy, and `/downloads/...` (CORS on the feed).

## Governance

Each repo's identity lists its delegates (maintainer keys) and a threshold. Today it is
1-of-1; the plan is 2-of-3, so no single key can move `main` or a release tag:
`rad id update --delegate <did> --delegate <did> --threshold 2`.

## Builds (no hosted CI)

Wallet: Linux and Windows on the 142 box (`scripts/build-linux-142.sh`,
`scripts/build-windows-142.sh` in zkas-wallet), Android and web with `scripts/release.sh`,
macOS on Codemagic (`codemagic.yaml`, repo added by URL). Files are published with
`scripts/publish-downloads.py`.
