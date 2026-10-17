use crate::connection::{Connection, ConnectionId};
use kaspa_core::{debug, info, warn};
use kaspa_notify::connection::Connection as ConnectionT;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry::Occupied},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::oneshot::Sender as OneshotSender;
use tokio::{sync::mpsc::Receiver as MpscReceiver, time::sleep};

#[derive(Debug, Error)]
pub(crate) enum RegistrationError {
    #[error("reached connection capacity of {0}")]
    CapacityReached(usize),
    #[error("reached per-IP connection cap of {1} for {0}")]
    PerIpCapacityReached(std::net::IpAddr, usize),
}
pub(crate) type RegistrationResult = Result<(), RegistrationError>;

pub(crate) struct RegistrationRequest {
    connection: Connection,
    response_sender: OneshotSender<RegistrationResult>,
}

impl RegistrationRequest {
    pub fn new(connection: Connection, response_sender: OneshotSender<RegistrationResult>) -> Self {
        Self { connection, response_sender }
    }
}

pub(crate) enum ManagerEvent {
    NewConnection(RegistrationRequest),
    ConnectionClosing(Connection),
}

#[derive(Clone, Debug)]
pub struct Manager {
    connections: Arc<RwLock<HashMap<ConnectionId, Connection>>>,
    max_connections: usize,
    // Per-IP concurrent-connection cap: stops a single source from filling all
    // slots (the socat-leak DoS class). Loopback is exempt so local self-hosted
    // clients (walletd, pool, tooling) are never throttled.
    max_per_ip: usize,
}

impl Manager {
    pub fn new(max_connections: usize) -> Self {
        let max_per_ip = std::cmp::max(max_connections / 8, 8);
        Self { connections: Default::default(), max_connections, max_per_ip }
    }

    /// Starts a loop for receiving central manager events from all connections. This mechanism is used for
    /// managing a collection of active connections.
    pub(crate) fn start_event_loop(self, mut manager_receiver: MpscReceiver<ManagerEvent>) {
        debug!("GRPC, Manager event loop starting");
        tokio::spawn(async move {
            while let Some(new_event) = manager_receiver.recv().await {
                match new_event {
                    ManagerEvent::NewConnection(RegistrationRequest { connection, response_sender }) => {
                        match response_sender.send(self.register(connection.clone())) {
                            Ok(()) => {}
                            Err(_) => {
                                warn!("GRPC, registration of incoming connection {} failed", connection);
                                self.unregister(connection);
                            }
                        }
                    }
                    ManagerEvent::ConnectionClosing(connection) => {
                        self.unregister(connection);
                    }
                }
            }
            debug!("GRPC, Manager event loop exiting");
        });
    }

    fn register(&self, connection: Connection) -> RegistrationResult {
        let mut connections_write = self.connections.write();
        let ip = connection.net_address().ip();
        let registered = connections_write.len();
        self.check_capacity(ip, registered, || connections_write.values().filter(|c| c.net_address().ip() == ip).count())?;

        debug!("GRPC, Registering a new connection from {connection}");
        let previous_connection = connections_write.insert(connection.identity(), connection.clone());
        info!("GRPC, new incoming connection {} #{}", connection, connections_write.len());

        // Release the write lock to prevent a deadlock if a previous connection exists and must be closed
        drop(connections_write);

        // A previous connection with the same id is VERY unlikely to occur but just in case, we close it cleanly
        if let Some(previous_connection) = previous_connection {
            previous_connection.close();
            warn!("GRPC, removing connection with duplicate identity: {}", previous_connection.identity());
        }

        Ok(())
    }

    /// Whether a connection from `ip` may be registered next to `registered` existing ones, of which
    /// `from_ip()` share its address.
    fn check_capacity(&self, ip: IpAddr, registered: usize, from_ip: impl FnOnce() -> usize) -> RegistrationResult {
        // Check if there is room for a new connection
        if registered >= self.max_connections {
            return Err(RegistrationError::CapacityReached(self.max_connections));
        }
        // Per-IP cap: prevent one source from exhausting the slot pool. Loopback is exempt.
        //
        // That exemption is deliberate, and a per-loopback cap (tried in 13d874d) is worse. Behind a
        // port forwarder every public client arrives as 127.0.0.1, so a loopback cap does not single
        // out one source: it caps the whole public at that number and makes the node's own local
        // services (walletd, the explorer backend, the pool bridge) race the public for what is left.
        // On a forwarded node the bound that matters lives in the forwarder: keep its child limit
        // below `--rpcmaxclients` (e.g. `socat ... max-children=480` with `--rpcmaxclients=512`), and
        // the difference is reserved for local services by construction.
        // Canonical first: on a dual-stack listener an IPv4 forwarder arrives as `::ffff:127.0.0.1`,
        // which is not `is_loopback()` until it is.
        if !ip.to_canonical().is_loopback() && from_ip() >= self.max_per_ip {
            return Err(RegistrationError::PerIpCapacityReached(ip, self.max_per_ip));
        }
        Ok(())
    }

    fn unregister(&self, connection: Connection) {
        let mut connections_write = self.connections.write();
        let connection_count = connections_write.len();
        if let Occupied(entry) = connections_write.entry(connection.identity()) {
            // We search for the connection by identity, but make sure to delete it only if it's actually the same object.
            // This is extremely important in cases of duplicate connection rejection etc.
            if Connection::ptr_eq(entry.get(), &connection) {
                entry.remove_entry();
                info!("GRPC, end connection {} #{}", connection, connection_count);
            }
        }
    }

    /// Terminate all connections
    pub async fn terminate_all_connections(&self) {
        let mut closed_connections = HashSet::with_capacity(self.connections.read().len());
        loop {
            if let Some((id, connection)) = self
                .connections
                .read()
                .iter()
                .filter(|(id, _)| !closed_connections.contains(*id))
                .map(|(id, cx)| (*id, cx.clone()))
                .next()
            {
                closed_connections.insert(id);
                connection.close();
                continue;
            } else if self.connections.read().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Returns a list of all currently active connections (for unit tests only)
    #[cfg(test)]
    pub(crate) fn active_connections(&self) -> Vec<std::net::SocketAddr> {
        self.connections.read().values().map(|r| r.net_address()).collect()
    }

    /// Returns whether there are currently active connections (for unit tests only)
    #[cfg(test)]
    pub(crate) fn has_connections(&self) -> bool {
        !self.connections.read().is_empty()
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        debug!("GRPC, Dropping Manager, refs count {}", Arc::strong_count(&self.connections));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Registers `ip` next to `registered` through the same decision `Manager::register` makes.
    fn admit(manager: &Manager, registered: &mut Vec<IpAddr>, ip: IpAddr) -> RegistrationResult {
        manager.check_capacity(ip, registered.len(), || registered.iter().filter(|r| **r == ip).count())?;
        registered.push(ip);
        Ok(())
    }

    /// Loopback is exempt from the per-IP cap (behind a forwarder every public client is 127.0.0.1;
    /// see `check_capacity`), so it fills every slot up to `max_connections`; a public address is
    /// held to `max_per_ip`, and the global capacity still binds everyone.
    #[test]
    fn loopback_is_exempt_from_the_per_ip_cap_and_public_addresses_are_not() {
        let manager = Manager::new(64);
        assert_eq!(manager.max_per_ip, 8);
        let v4_loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let mut registered = Vec::new();
        for i in 0..manager.max_per_ip {
            admit(&manager, &mut registered, public).unwrap_or_else(|e| panic!("public connection {i}: {e}"));
        }
        assert!(matches!(
            admit(&manager, &mut registered, public),
            Err(RegistrationError::PerIpCapacityReached(ip, 8)) if ip == public
        ));
        // Another public address is counted on its own.
        admit(&manager, &mut registered, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))).unwrap();

        // Loopback (v4 and v6) takes every remaining slot, far past the per-IP cap.
        let mut loopback = 0;
        while registered.len() < manager.max_connections {
            let ip = if loopback % 2 == 0 { v4_loopback } else { IpAddr::V6(Ipv6Addr::LOCALHOST) };
            admit(&manager, &mut registered, ip).unwrap_or_else(|e| panic!("loopback connection {loopback}: {e}"));
            loopback += 1;
        }
        assert_eq!(loopback, manager.max_connections - manager.max_per_ip - 1);
        assert!(loopback / 2 > manager.max_per_ip, "each loopback address went past the per-IP cap");

        // Full: loopback is not exempt from the global capacity.
        assert!(matches!(admit(&manager, &mut registered, v4_loopback), Err(RegistrationError::CapacityReached(64))));
        assert!(matches!(
            admit(&manager, &mut registered, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            Err(RegistrationError::CapacityReached(64))
        ));
    }
}
