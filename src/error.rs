//! Verification errors

use der::asn1::ObjectIdentifier;

pub enum Error {
    /// Invalid Signature
    InvalidKey,

    /// Invalid Signature
    InvalidSignature,

    /// Verification Error
    Verification,

    /// Unknown OID
    UnknownOid(ObjectIdentifier),

    /// DER/ASN.1 Encoding Error
    Encoding,
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
