use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_utils::networking::{ContextualNetAddress, IpAddress, NetAddress, PeerId};
use serde::{Deserialize, Serialize};

pub type RpcNodeId = PeerId;
pub type RpcIpAddress = IpAddress;
pub type RpcPeerAddress = NetAddress;
pub type RpcContextualPeerAddress = ContextualNetAddress;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RpcPeerInfo {
    pub id: RpcNodeId,
    pub address: RpcPeerAddress,
    pub last_ping_duration: u64, // NOTE: i64 in gRPC protowire

    pub is_outbound: bool,
    pub time_offset: i64,
    pub user_agent: String,

    pub advertised_protocol_version: u32,
    pub time_connected: u64, // NOTE: i64 in gRPC protowire
    pub is_ibd_peer: bool,

    /// Blocks this peer was the FIRST to relay to us, since the node started.
    ///
    /// Gossip is a race: a block reaches several of our peers, and whichever one
    /// wins the request for its body gets the credit here. So this measures who
    /// keeps us supplied with blocks first — not who produced them. On a shielded
    /// chain the producer is deliberately unidentifiable.
    pub blocks_relayed: u64,

    /// `v1` (plaintext) or `v2` (ZKT2 encrypted transport, spec 06 §3.1)
    pub transport: String,
    /// Hex BIP 324 session id of a `v2` connection, empty for `v1`. Two operators who read the
    /// same id on both ends know no man in the middle split the connection (spec 06 T-7).
    pub session_id: String,
}
