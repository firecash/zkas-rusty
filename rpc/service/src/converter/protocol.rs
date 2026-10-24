use std::sync::Arc;

use kaspa_p2p_flows::flow_context::FlowContext;
use kaspa_p2p_lib::{Peer, PeerKey};
use kaspa_rpc_core::RpcPeerInfo;

pub struct ProtocolConverter {
    flow_context: Arc<FlowContext>,
}

impl ProtocolConverter {
    pub fn new(flow_context: Arc<FlowContext>) -> Self {
        Self { flow_context }
    }

    fn get_peer_info(&self, peer: &Peer, ibd_peer_key: &Option<PeerKey>) -> RpcPeerInfo {
        let properties = peer.properties();
        RpcPeerInfo {
            id: peer.identity(),
            address: peer.net_address().into(),
            is_outbound: peer.is_outbound(),
            is_ibd_peer: ibd_peer_key.is_some() && peer.key() == *ibd_peer_key.as_ref().unwrap(),
            last_ping_duration: peer.last_ping_duration(),
            time_offset: properties.time_offset,
            user_agent: properties.user_agent.clone(),
            advertised_protocol_version: properties.advertised_protocol_version,
            time_connected: peer.time_connected(),
            blocks_relayed: self.flow_context.relay_credit(&peer.key()),
            transport: peer.transport().kind.to_string(),
            session_id: peer.transport().session_id.map(hex::encode).unwrap_or_default(),
        }
    }

    pub fn get_peers_info(&self, peers: &[Peer]) -> Vec<RpcPeerInfo> {
        let ibd_peer_key = self.flow_context.ibd_peer_key();
        // Reading the peer list is also the only regular signal of who is still
        // connected, so take the chance to drop tallies for peers that are gone.
        self.flow_context.prune_relay_credit(&peers.iter().map(|p| p.key()).collect::<Vec<_>>());
        peers.iter().map(|x| self.get_peer_info(x, &ibd_peer_key)).collect()
    }
}
