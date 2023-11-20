//! Verification Errors

use alloc::fmt;
use core::convert::Infallible;
use der::asn1::ObjectIdentifier;

/// X.509 verify error types
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Verification Error
    Verification,

    /// Invalid Key
    InvalidKey,

    /// Invalid Signature
    InvalidSignature,

    /// Unknown OID
    UnknownOid(ObjectIdentifier),

    /// Decoding Error
    Decode,

    /// Encoding Error
    Encode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Verification => write!(f, "Verification failure"),
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::UnknownOid(oid) => write!(f, "Unknown OID: {}", oid),
            Error::Decode => write!(f, "Decode failure"),
            Error::Encode => write!(f, "Encode failure"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
