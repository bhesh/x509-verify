//! Verification Errors

use alloc::string::String;
use der::asn1::ObjectIdentifier;

#[derive(Clone, Debug)]
pub enum Error {
    /// Verification Error
    Verification,

    /// Invalid Key
    InvalidKey,

    /// Invalid Signature
    InvalidSignature,

    /// Unknown OID
    UnknownOid(ObjectIdentifier),

    /// Encoding Error
    Encoding,

    /// Unknown
    Unknown(String),
}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Error::Encoding
    }
}

impl From<spki::Error> for Error {
    fn from(error: spki::Error) -> Self {
        match error {
            spki::Error::OidUnknown { oid } => Error::UnknownOid(oid),
            _ => Error::Encoding,
        }
    }
}
