//! Opt-in automatic banning (`--enablebanning`): which addresses it may name, and how often.
//!
//! WHAT qualifies is decided by `ProtocolError::is_auto_ban_eligible` in the p2p crate. This module
//! holds the two limits on acting on it, kept apart from `FlowContext` so they can be tested
//! without a node.

use kaspa_utils::networking::IpAddress;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Length of one auto-ban budget window.
pub(crate) const AUTO_BAN_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Automatic bans allowed per window.
///
/// Every ban is a row in the persisted ban store, and a row is only reclaimed when that same IP is
/// looked up again after it expires. Without a ceiling, a peer with an IPv6 prefix to spend could
/// make this node write rows at the rate it can open connections, unbounded. Past the ceiling the
/// peer is still disconnected, it just is not remembered.
pub(crate) const MAX_AUTO_BANS_PER_WINDOW: usize = 256;

/// Whether an automatic ban may name this address at all.
///
/// Only publicly routable addresses qualify. Loopback, private, link-local, CGNAT and similar
/// ranges are where a port forwarder shows up instead of the peer: `socat` rewrites every remote
/// to 127.0.0.1, and Docker's userland proxy rewrites them to the bridge gateway. Auto-banning such
/// an address bans every peer behind it at once -- the same trap the gRPC per-IP cap fell into with
/// loopback. An operator can still ban one by hand.
///
/// The address is canonicalized first: on a dual-stack listener an IPv4 peer arrives as
/// `::ffff:a.b.c.d`, and `::ffff:127.0.0.1` is not `is_loopback()` until it is.
pub(crate) fn auto_ban_may_target(ip: IpAddr) -> bool {
    IpAddress::new(ip.to_canonical()).is_publicly_routable()
}

/// A fixed-window count of automatic bans, see `MAX_AUTO_BANS_PER_WINDOW`.
#[derive(Debug, Default)]
pub(crate) struct AutoBanBudget {
    window_start: Option<Instant>,
    used: usize,
}

impl AutoBanBudget {
    /// Takes one ban from the budget if any is left in the window containing `now`.
    pub(crate) fn try_take(&mut self, now: Instant) -> bool {
        let in_window = self.window_start.is_some_and(|start| now.saturating_duration_since(start) < AUTO_BAN_WINDOW);
        if !in_window {
            self.window_start = Some(now);
            self.used = 0;
        }
        if self.used >= MAX_AUTO_BANS_PER_WINDOW {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn forwarder_and_private_addresses_are_never_auto_banned() {
        let never: [IpAddr; 10] = [
            Ipv4Addr::LOCALHOST.into(),
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(172, 17, 0, 1).into(), // Docker bridge gateway
            Ipv4Addr::new(192, 168, 1, 1).into(),
            Ipv4Addr::new(100, 64, 0, 1).into(), // CGNAT
            Ipv4Addr::new(169, 254, 0, 1).into(),
            Ipv6Addr::LOCALHOST.into(),
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).into(),
            // IPv4 loopback as a dual-stack listener reports it
            Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
        ];
        for ip in never {
            assert!(!auto_ban_may_target(ip), "{ip} must never be auto-banned");
        }
    }

    #[test]
    fn public_addresses_may_be_auto_banned() {
        let public: [IpAddr; 3] = [
            Ipv4Addr::new(8, 8, 8, 8).into(),
            Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped().into(),
            Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, 1).into(),
        ];
        for ip in public {
            assert!(auto_ban_may_target(ip), "{ip} should be bannable");
        }
    }

    #[test]
    fn budget_is_bounded_per_window_and_refills() {
        let mut budget = AutoBanBudget::default();
        let t0 = Instant::now();
        for _ in 0..MAX_AUTO_BANS_PER_WINDOW {
            assert!(budget.try_take(t0));
        }
        assert!(!budget.try_take(t0));
        assert!(!budget.try_take(t0 + AUTO_BAN_WINDOW - Duration::from_secs(1)));
        assert!(budget.try_take(t0 + AUTO_BAN_WINDOW));
    }
}
