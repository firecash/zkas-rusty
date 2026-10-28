pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn name() -> &'static str {
    "kaspad"
}

/// The ZKas release this build is, as in the `zkas-v<release>` tag. [`version`] is upstream
/// rusty-kaspa's crate version and stays the same across ZKas releases (v1.0.10 to v1.0.12 all
/// said `2.0.1`), so this is the number that tells releases apart: in `kaspad --version`, the
/// startup log, and the p2p user agent (`/kaspad:<version>/zkas:<release>/`), where the
/// newer-release exemptions read it. Bump it in the commit a release tag points at.
pub fn zkas_release() -> &'static str {
    "1.0.13"
}

/// The user-agent name [`zkas_release`] is advertised under.
pub fn zkas_name() -> &'static str {
    "zkas"
}

/// Both numbers, for `kaspad --version` and the startup log: `2.0.1 (zkas-v1.0.13)`.
pub fn full_version() -> String {
    format!("{} (zkas-v{})", version(), zkas_release())
}
