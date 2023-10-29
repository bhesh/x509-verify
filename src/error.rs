//! Verification Errors

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

    /// Decoding Error
    Decode,

    /// Encoding Error
    Encode,
}
