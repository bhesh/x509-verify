//! Generic X.509 Signature

use alloc::vec::Vec;
use der::{asn1::ObjectIdentifier, referenced::OwnedToRef};
use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};

/// Generic X.509 signature structure
#[derive(Copy, Clone, Debug)]
pub struct Signature<'a, S>
where
    S: AsRef<[u8]>,
{
    algorithm: AlgorithmIdentifierRef<'a>,
    data: S,
}

impl<'a, S> Signature<'a, S>
where
    S: AsRef<[u8]>,
{
    /// Builds a new signature object given the `AlgorithmIdentifier` and the signature data
    pub fn new(algorithm: &'a AlgorithmIdentifierOwned, data: S) -> Self {
        Self {
            algorithm: algorithm.owned_to_ref(),
            data,
        }
    }

    /// Builds a new signature object given the `AlgorithmIdentifier` and the signature data
    pub fn from_ref(algorithm: AlgorithmIdentifierRef<'a>, data: S) -> Self {
        Self { algorithm, data }
    }

    /// Returns the AlgorithmIdentifier
    pub fn algorithm(&self) -> AlgorithmIdentifierRef<'a> {
        self.algorithm
    }

    /// Returns a reference to the `ObjectIdentifier`
    pub fn oid(&self) -> &ObjectIdentifier {
        &self.algorithm.oid
    }

    /// Returns a reference to the signature data
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Signature with a reference to the signature bytes
pub type SignatureRef<'a, 'b> = Signature<'a, &'b [u8]>;

impl<'a, 'b> From<&SignatureRef<'a, 'b>> for SignatureRef<'a, 'b> {
    fn from(other: &SignatureRef<'a, 'b>) -> Self {
        *other
    }
}

/// Signature which owns the signature bytes
pub type SignatureOwned<'a> = Signature<'a, Vec<u8>>;

impl<'a, 'b> From<&'b SignatureOwned<'a>> for SignatureRef<'a, 'b> {
    fn from(other: &'b SignatureOwned<'a>) -> Self {
        SignatureRef::from_ref(other.algorithm, &other.data)
    }
}
