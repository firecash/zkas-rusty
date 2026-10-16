use kaspa_consensus_core::subnets::SubnetworkConversionError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum ConversionError {
    #[error("General p2p conversion error")]
    General,

    #[error("Optional field is None while expected to be Some")]
    NoneValue,

    #[error("IP has illegal length {0}")]
    IllegalIPLength(usize),

    #[error("Bytes size mismatch error {0}")]
    ArrayBytesSizeError(#[from] std::array::TryFromSliceError),

    #[error("Bytes size mismatch error {0}")]
    UintBytesSizeError(#[from] kaspa_math::uint::TryFromSliceError),

    #[error("Integer parsing error: {0}")]
    IntCastingError(#[from] std::num::TryFromIntError),

    #[error(transparent)]
    AddressParsingError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    IdentityError(#[from] uuid::Error),

    #[error(transparent)]
    SubnetParsingError(#[from] SubnetworkConversionError),

    #[error(transparent)]
    CompressedParentsError(#[from] kaspa_consensus_core::errors::header::CompressedParentsError),

    // `ConversionError` derives `Clone`, but `std::io::Error` is not `Clone`, so we
    // carry the borsh decode failure as a string rather than `#[from]`.
    #[error("AuxPoW borsh decode error: {0}")]
    AuxPowDecodeError(String),
}

impl ConversionError {
    /// Whether the peer sent a field of a FIXED wire width at some other width: a hash or
    /// transaction id that is not 32 bytes, a subnetwork id that is not 20, an IP that is neither 4
    /// nor 16, a peer id that is not a 16-byte UUID, a blue work wider than 192 bits.
    ///
    /// These widths are the same in every protocol version this network has ever spoken, and every
    /// one of these fields reaches the wire from a typed value, so no honest encoder -- of any
    /// version, relaying anyone's data -- can produce a wrong one. That is what makes this the one
    /// conversion failure `ProtocolError::is_auto_ban_eligible` may act on.
    ///
    /// Everything else here is deliberately `false`. A missing field (`NoneValue`) is how a newer
    /// version that stopped sending a field looks to an older one; an integer that does not fit
    /// (`IntCastingError`) is how a widened domain (a new tx or script version) looks; header-parent
    /// compression and the AuxPoW encoding are this fork's own and have changed before. A peer can
    /// send any of those in good faith, so they disconnect and nothing more.
    ///
    /// The match is exhaustive on purpose: a new variant must be classified here before it compiles.
    pub fn is_malformed_fixed_width_field(&self) -> bool {
        match self {
            Self::IllegalIPLength(_) | Self::ArrayBytesSizeError(_) | Self::UintBytesSizeError(_) | Self::IdentityError(_) => true,
            Self::SubnetParsingError(SubnetworkConversionError::SliceError(_)) => true,
            Self::SubnetParsingError(_) => false,
            Self::General
            | Self::NoneValue
            | Self::IntCastingError(_)
            | Self::AddressParsingError(_)
            | Self::CompressedParentsError(_)
            | Self::AuxPowDecodeError(_) => false,
        }
    }
}
