#!/usr/bin/env python3
"""Rewrite gitlab.com/zkas-group (and leftover github.com/firecash) links to zkas.info.

    python3 relink-zkas.py [--dry] FILE...

Every target is a zkas.info name, never the seed's address: zkas.info/code/<name>[/...]
is resolved by nginx on VPS1 (conf.d/zkas-code-map.conf + sites-enabled/zkas.info), so
moving the code again means changing nginx only.
"""
import re
import sys

SHORT = {
    "zkas-rusty": "rusty", "firecash-rusty": "rusty", "zkas-wallet": "wallet", "firecash-wallet": "wallet",
    "zkas-signer": "signer", "firecash-signer": "signer", "zkas-explorer": "explorer",
    "zkas-sdk": "sdk", "zkas-payment-gateway": "gateway", "zkas-website": "website",
    "zkas-blog": "blog", "zkas-paper-wallet": "paper-wallet", "vprogs-zkas": "vprogs",
    "solo-dual-mode": "bridge",
}
PKG = {  # GitLab generic-package downloads we mirrored byte-for-byte
    "zkas-node": "https://zkas.info/downloads/node/",
    "solo-dual-mode": "https://zkas.info/downloads/bridge/",
    "zkas-wallet": "https://zkas.info/downloads/wallet/",
}
END = r"(?=[\s\"'`<>)\]},;|]|&quot;|$)"

URL = re.compile(
    r"https?://(?:gitlab\.com/zkas-group|github\.com/firecash)/([A-Za-z0-9._-]+?)"
    r"(\.git|/-/[A-Za-z0-9._~%/#?=&+-]*|/(?:tree|blob|issues|releases|commits?)[A-Za-z0-9._~%/#?=&+-]*|#[A-Za-z0-9_-]*)?"
    r"(/)?" + END)
PKG_URL = re.compile(
    r"https://gitlab\.com/api/v4/projects/[A-Za-z0-9%._-]+/packages/generic/([a-z-]+)/v?([0-9][0-9A-Za-z.-]*)/([A-Za-z0-9._-]+)" + END)
RELEASES_API = re.compile(r"https://gitlab\.com/api/v4/projects/[A-Za-z0-9%._-]+/releases[A-Za-z0-9?=&_]*" + END)


def code_url(repo, rest):
    name = SHORT.get(repo)
    if not name:
        return None
    base = "https://zkas.info/code/" + name
    rest = rest or ""
    if rest == ".git":
        return base + ".git"
    if rest.startswith("#"):
        return base
    rest = rest.replace("/-/", "/", 1)
    if rest.startswith("/releases"):
        if name == "wallet":
            return "https://zkas.info/downloads/wallet/"
        if name == "rusty":
            return "https://zkas.info/downloads/node/"
        return base + "/releases"
    if rest.startswith("/blob/"):
        rest = "/tree/" + rest[len("/blob/"):]
    if rest.startswith("/issues/new"):
        rest = "/issues"
    if rest.startswith("/merge_requests"):
        rest = "/patches"
    return base + rest.rstrip("/")


def fix(text):
    n = [0]

    def sub_url(m):
        new = code_url(m.group(1), m.group(2))
        if new is None:
            return m.group(0)
        n[0] += 1
        return new

    def sub_pkg(m):
        pkg, ver, f = m.groups()
        if pkg not in PKG:
            return m.group(0)
        n[0] += 1
        ver = ver if pkg != "solo-dual-mode" else "v" + ver.lstrip("v")
        return f"{PKG[pkg]}{ver}/{f}"

    text = PKG_URL.sub(sub_pkg, text)
    text, k = RELEASES_API.subn("https://zkas.info/downloads/wallet/releases.json", text)
    n[0] += k
    text = URL.sub(sub_url, text)
    return text, n[0]


def main():
    args = sys.argv[1:]
    dry = "--dry" in args
    files = [a for a in args if a != "--dry"]
    total = 0
    for p in files:
        try:
            s = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, IsADirectoryError):
            continue
        new, k = fix(s)
        if k:
            total += k
            print(f"{k:4d}  {p}")
            if not dry:
                open(p, "w", encoding="utf-8").write(new)
    print(f"{total} link(s) {'would change' if dry else 'changed'}")


if __name__ == "__main__":
    main()
