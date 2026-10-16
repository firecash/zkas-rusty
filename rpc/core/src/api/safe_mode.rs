//! What `--unsaferpc` gates, where the gate cannot live inside a single `RpcApi` method.
//!
//! Request methods are gated in `RpcCoreService`, which both public transports call. Subscriptions
//! are not: the gRPC and wRPC servers each run their own notifier and subscribe it to the core
//! notifier directly, so `RpcCoreService::start_notify` is never on a remote client's path. A
//! subscription rule therefore has to be applied by every transport, and this is the one copy of
//! it they share.

use crate::{RpcError, RpcResult};
use kaspa_notify::scope::Scope;

/// Refuse a subscription that safe mode (the default, no `--unsaferpc`) does not allow.
///
/// Today that is a blanket `UtxosChanged` (no address filter): it streams every UTXO change on the
/// chain to the subscriber, which is the most resource-intensive thing a client can ask the UTXO
/// index for. Scoped subscriptions, every other event type, and every unsubscribe are allowed.
pub fn check_subscription_allowed(unsafe_rpc: bool, scope: &Scope) -> RpcResult<()> {
    match scope {
        Scope::UtxosChanged(utxos_changed) if !unsafe_rpc && utxos_changed.addresses.is_empty() => {
            Err(RpcError::UnavailableInSafeMode)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::check_subscription_allowed;
    use kaspa_addresses::{Address, Prefix, Version};
    use kaspa_notify::scope::{BlockAddedScope, Scope, UtxosChangedScope};

    #[test]
    fn blanket_utxos_changed_needs_unsafe_rpc() {
        let blanket: Scope = UtxosChangedScope::new(vec![]).into();
        assert!(check_subscription_allowed(false, &blanket).is_err());
        assert!(check_subscription_allowed(true, &blanket).is_ok());
    }

    #[test]
    fn scoped_and_other_subscriptions_are_allowed_in_safe_mode() {
        let address = Address::new(Prefix::Mainnet, Version::PubKey, &[7u8; 32]);
        let scoped: Scope = UtxosChangedScope::new(vec![address]).into();
        assert!(check_subscription_allowed(false, &scoped).is_ok());
        let block_added: Scope = BlockAddedScope::default().into();
        assert!(check_subscription_allowed(false, &block_added).is_ok());
    }
}
