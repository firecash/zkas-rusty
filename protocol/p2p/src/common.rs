use crate::{KaspadMessagePayloadType, convert::error::ConversionError, core::peer::PeerKey};
use kaspa_consensus_core::errors::{block::RuleError, consensus::ConsensusError, pruning::PruningImportError};
use kaspa_mining_errors::manager::MiningManagerError;
use std::time::Duration;
use thiserror::Error;

/// Default P2P communication timeout
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes

#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    #[error("timeout expired after {0:?}")]
    Timeout(Duration),

    #[error("P2P protocol version mismatch - local: {0}, remote: {1}")]
    VersionMismatch(u32, u32),

    #[error("Network mismatch - local: {0}, remote: {1}")]
    WrongNetwork(String, String),

    #[error("expected message type/s {0} but got {1:?}")]
    UnexpectedMessage(&'static str, Option<KaspadMessagePayloadType>),

    #[error("{0}")]
    ConversionError(#[from] ConversionError),

    #[error("{0}")]
    RuleError(#[from] RuleError),

    #[error("{0}")]
    PruningImportError(#[from] PruningImportError),

    #[error("{0}")]
    ConsensusError(#[from] ConsensusError),

    // TODO: discuss if such an error type makes sense here
    #[error("{0}")]
    MiningManagerError(#[from] MiningManagerError),

    #[error("{0}")]
    IdentityError(#[from] uuid::Error),

    #[error("{0}")]
    Other(&'static str),

    #[error("{0}")]
    OtherOwned(String),

    #[error("misbehaving peer: {0}")]
    MisbehavingPeer(String),

    #[error("peer connection is closed")]
    ConnectionClosed,

    #[error("incoming route capacity for message type {0:?} has been reached (peer: {1})")]
    IncomingRouteCapacityReached(KaspadMessagePayloadType, String),

    #[error("outgoing route capacity has been reached (peer: {0})")]
    OutgoingRouteCapacityReached(String),

    #[error("no flow has been registered for message type {0:?}")]
    NoRouteForMessageType(KaspadMessagePayloadType),

    #[error("peer {0} already exists")]
    PeerAlreadyExists(PeerKey),

    #[error("loopback connection - node is connecting to itself")]
    LoopbackConnection(PeerKey),

    #[error("got reject message: {0}")]
    Rejected(String),

    #[error("got reject message: {0}")]
    IgnorableReject(String),
}

/// String used as a P2P convention to signal connection is rejected because we are connecting to ourselves
const LOOPBACK_CONNECTION_MESSAGE: &str = "LOOPBACK_CONNECTION";

/// String used as a P2P convention to signal connection is rejected because the peer already exists
const DUPLICATE_CONNECTION_MESSAGE: &str = "DUPLICATE_CONNECTION";

/// Maximum reject reason length retained for processing and logging.
const MAX_REJECT_REASON_LEN: usize = 2048;

impl ProtocolError {
    pub fn is_connection_closed_error(&self) -> bool {
        matches!(self, Self::ConnectionClosed)
    }

    pub fn can_send_outgoing_message(&self) -> bool {
        !matches!(self, Self::ConnectionClosed | Self::OutgoingRouteCapacityReached(_))
    }

    /// Whether this error proves the peer broke the wire protocol itself -- something no honest
    /// peer of ANY version can do -- rather than disagreeing with us. Only these may end in an
    /// automatic ban (`--enablebanning`); every other error disconnects and nothing more.
    ///
    /// The bar is "no honest peer of any version", not "probably malicious", because of what the
    /// excluded errors look like on a live network:
    ///
    /// * Consensus rejections (`RuleError`, `ConsensusError`, `PruningImportError`, and the
    ///   `MisbehavingPeer` sites in tx relay, which fire on a mempool rule rejection or a failed
    ///   shielded proof) are exactly what an honest peer on the other side of a rule change sends.
    ///   After a fork that is most of the network for a while, and banning them turns a transient
    ///   partition into a permanent one. This is why tx relay carries its "discuss a banning
    ///   process" TODO rather than a ban.
    /// * Size and pacing limits (`IncomingRouteCapacityReached`, the shielded-history byte and
    ///   record bounds) move between versions -- the history chunk bound was tightened in this
    ///   release, so an un-upgraded server can exceed it honestly -- and a full route is as often our
    ///   own slowness as the peer's flooding.
    /// * Unknown or unroutable message types (`NoRouteForMessageType`, an empty payload, an
    ///   `UnexpectedMessage`) are what a NEWER peer's messages look like to an older node.
    /// * Timeouts, rejects, version and network mismatches are not misbehaviour at all.
    ///
    /// What is left is a fixed-width field at the wrong width (see
    /// `ConversionError::is_malformed_fixed_width_field`). The match is exhaustive on purpose, so a
    /// new variant cannot become ban-eligible -- or escape this decision -- without being read here.
    pub fn is_auto_ban_eligible(&self) -> bool {
        match self {
            Self::ConversionError(err) => err.is_malformed_fixed_width_field(),
            Self::IdentityError(_) => true,
            Self::Timeout(_)
            | Self::VersionMismatch(_, _)
            | Self::WrongNetwork(_, _)
            | Self::UnexpectedMessage(_, _)
            | Self::RuleError(_)
            | Self::PruningImportError(_)
            | Self::ConsensusError(_)
            | Self::MiningManagerError(_)
            | Self::Other(_)
            | Self::OtherOwned(_)
            | Self::MisbehavingPeer(_)
            | Self::ConnectionClosed
            | Self::IncomingRouteCapacityReached(_, _)
            | Self::OutgoingRouteCapacityReached(_)
            | Self::NoRouteForMessageType(_)
            | Self::PeerAlreadyExists(_)
            | Self::LoopbackConnection(_)
            | Self::Rejected(_)
            | Self::IgnorableReject(_) => false,
        }
    }

    pub fn to_reject_message(&self) -> String {
        match self {
            Self::LoopbackConnection(_) => LOOPBACK_CONNECTION_MESSAGE.to_owned(),
            Self::PeerAlreadyExists(_) => DUPLICATE_CONNECTION_MESSAGE.to_owned(),
            err => err.to_string(),
        }
    }

    pub fn from_reject_message(mut reason: String) -> Self {
        reason.truncate(reason.floor_char_boundary(MAX_REJECT_REASON_LEN));
        reason.shrink_to_fit();
        if reason == LOOPBACK_CONNECTION_MESSAGE || reason == DUPLICATE_CONNECTION_MESSAGE {
            ProtocolError::IgnorableReject(reason)
        } else if reason.contains("cannot find full block") {
            let hint = "Hint: This is expected to be handled by pruning catch-up.";
            let detailed_reason = format!("{}. {}", reason, hint);
            ProtocolError::Rejected(detailed_reason)
        } else {
            ProtocolError::Rejected(reason)
        }
    }
}

/// Wraps an inner payload message into a valid `KaspadMessage`.
/// Usage:
/// ```ignore
/// let msg = make_message!(Payload::Verack, verack_msg)
/// ```
#[macro_export]
macro_rules! make_message {
    ($pattern:path, $msg:expr) => {{
        $crate::pb::KaspadMessage {
            payload: Some($pattern($msg)),
            response_id: $crate::BLANK_ROUTE_ID,
            request_id: $crate::BLANK_ROUTE_ID,
        }
    }};

    ($pattern:path, $msg:expr, $response_id:expr, $request_id: expr) => {{ $crate::pb::KaspadMessage { payload: Some($pattern($msg)), response_id: $response_id, request_id: $request_id } }};
}

#[macro_export]
macro_rules! make_response {
    ($pattern:path, $msg:expr, $response_id:expr) => {{ $crate::pb::KaspadMessage { payload: Some($pattern($msg)), response_id: $response_id, request_id: 0 } }};
}

#[macro_export]
macro_rules! make_request {
    ($pattern:path, $msg:expr, $request_id:expr) => {{ $crate::pb::KaspadMessage { payload: Some($pattern($msg)), response_id: 0, request_id: $request_id } }};
}

/// Macro to extract a specific payload type from an `Option<pb::KaspadMessage>`.
/// Usage:
/// ```ignore
/// let res = unwrap_message!(op, Payload::Verack)
/// ```
#[macro_export]
macro_rules! unwrap_message {
    ($op:expr, $pattern:path) => {{
        if let Some(msg) = $op {
            if let Some($pattern(inner_msg)) = msg.payload {
                Ok(inner_msg)
            } else {
                Err($crate::common::ProtocolError::UnexpectedMessage(stringify!($pattern), msg.payload.as_ref().map(|v| v.into())))
            }
        } else {
            Err($crate::common::ProtocolError::ConnectionClosed)
        }
    }};
}

#[macro_export]
macro_rules! unwrap_message_with_request_id {
    ($op:expr, $pattern:path) => {{
        if let Some(msg) = $op {
            if let Some($pattern(inner_msg)) = msg.payload {
                Ok((inner_msg, msg.request_id))
            } else {
                Err($crate::common::ProtocolError::UnexpectedMessage(stringify!($pattern), msg.payload.as_ref().map(|v| v.into())))
            }
        } else {
            Err($crate::common::ProtocolError::ConnectionClosed)
        }
    }};
}

/// Macro to await a channel `Receiver<pb::KaspadMessage>::recv` call with a default/specified timeout and expect a specific payload type.
/// Usage:
/// ```ignore
/// let res = dequeue_with_timeout!(receiver, Payload::Verack) // Uses the default timeout
/// // or:
/// let res = dequeue_with_timeout!(receiver, Payload::Verack, Duration::from_secs(30))
/// ```
#[macro_export]
macro_rules! dequeue_with_timeout {
    ($receiver:expr, $pattern:path) => {{
        match tokio::time::timeout($crate::common::DEFAULT_TIMEOUT, $receiver.recv()).await {
            Ok(op) => {
                $crate::unwrap_message!(op, $pattern)
            }
            Err(_) => Err($crate::common::ProtocolError::Timeout($crate::common::DEFAULT_TIMEOUT)),
        }
    }};
    ($receiver:expr, $pattern:path, $timeout_duration:expr) => {{
        match tokio::time::timeout($timeout_duration, $receiver.recv()).await {
            Ok(op) => {
                $crate::unwrap_message!(op, $pattern)
            }
            Err(_) => Err($crate::common::ProtocolError::Timeout($timeout_duration)),
        }
    }};
}

/// Macro to indefinitely await a channel `Receiver<pb::KaspadMessage>::recv` call and expect a specific payload type (without a timeout).
/// Usage:
/// ```ignore
/// let res = dequeue!(receiver, Payload::Verack)
/// ```
#[macro_export]
macro_rules! dequeue {
    ($receiver:expr, $pattern:path) => {{ $crate::unwrap_message!($receiver.recv().await, $pattern) }};
}

#[macro_export]
macro_rules! dequeue_with_request_id {
    ($receiver:expr, $pattern:path) => {{ $crate::unwrap_message_with_request_id!($receiver.recv().await, $pattern) }};
}

#[cfg(test)]
mod tests {
    use super::ProtocolError;
    use crate::{KaspadMessagePayloadType, convert::error::ConversionError};
    use kaspa_consensus_core::{
        errors::{block::RuleError, tx::TxRuleError},
        subnets::SubnetworkConversionError,
        tx::TransactionId,
    };
    use kaspa_mining_errors::{manager::MiningManagerError, mempool::RuleError as MempoolRuleError};
    use std::time::Duration;

    fn slice_error() -> std::array::TryFromSliceError {
        <[u8; 32]>::try_from(&[0u8; 31][..]).unwrap_err()
    }

    fn uuid_error() -> uuid::Error {
        uuid::Uuid::from_slice(&[0u8; 15]).unwrap_err()
    }

    #[test]
    fn wrong_width_fixed_fields_are_ban_eligible() {
        let eligible = [
            ProtocolError::ConversionError(ConversionError::ArrayBytesSizeError(slice_error())),
            ProtocolError::ConversionError(ConversionError::UintBytesSizeError(kaspa_math::uint::TryFromSliceError)),
            ProtocolError::ConversionError(ConversionError::IllegalIPLength(5)),
            ProtocolError::ConversionError(ConversionError::IdentityError(uuid_error())),
            ProtocolError::ConversionError(ConversionError::SubnetParsingError(SubnetworkConversionError::SliceError(slice_error()))),
            ProtocolError::IdentityError(uuid_error()),
        ];
        for err in eligible {
            assert!(err.is_auto_ban_eligible(), "{err} must be ban-eligible");
        }
    }

    /// The errors an honest peer DOES send -- across a rule change, across a version gap, or just
    /// under load -- must never be ban-eligible. The first three are the live-network cases this
    /// gate exists for: a consensus rejection after the fork, and the two tx-relay
    /// `MisbehavingPeer` sites, which fire on mempool rule rejections.
    #[test]
    fn honest_disagreement_is_never_ban_eligible() {
        let not_eligible = [
            ProtocolError::RuleError(RuleError::NoParents),
            ProtocolError::MisbehavingPeer(format!("rejected invalid transaction {}", TransactionId::from_bytes([1; 32]))),
            ProtocolError::MisbehavingPeer("relayed a shielded transaction with an invalid proof: x".to_string()),
            ProtocolError::MiningManagerError(MiningManagerError::MempoolError(MempoolRuleError::RejectInvalid(
                TransactionId::from_bytes([2; 32]),
            ))),
            ProtocolError::MiningManagerError(MiningManagerError::MempoolError(MempoolRuleError::RejectTxRule(
                TxRuleError::InvalidShieldedProof("x".to_string()),
            ))),
            ProtocolError::ConversionError(ConversionError::NoneValue),
            ProtocolError::ConversionError(ConversionError::General),
            ProtocolError::ConversionError(ConversionError::IntCastingError(u8::try_from(256u16).unwrap_err())),
            ProtocolError::ConversionError(ConversionError::AuxPowDecodeError("x".to_string())),
            ProtocolError::Timeout(Duration::from_secs(1)),
            ProtocolError::VersionMismatch(10, 9),
            ProtocolError::WrongNetwork("a".to_string(), "b".to_string()),
            ProtocolError::UnexpectedMessage("Verack", Some(KaspadMessagePayloadType::Version)),
            ProtocolError::UnexpectedMessage("Verack", None),
            ProtocolError::NoRouteForMessageType(KaspadMessagePayloadType::Version),
            ProtocolError::IncomingRouteCapacityReached(KaspadMessagePayloadType::Block, "p".to_string()),
            ProtocolError::OutgoingRouteCapacityReached("p".to_string()),
            ProtocolError::Other("received kaspad p2p message with empty payload"),
            ProtocolError::OtherOwned("history chunk exceeds byte bound".to_string()),
            ProtocolError::ConnectionClosed,
            ProtocolError::Rejected("x".to_string()),
            ProtocolError::IgnorableReject("x".to_string()),
        ];
        for err in not_eligible {
            assert!(!err.is_auto_ban_eligible(), "{err} must not be ban-eligible");
        }
    }
}
