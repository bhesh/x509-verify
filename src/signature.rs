//! Generic X.509 Signature

use der::{asn1::ObjectIdentifier, referenced::OwnedToRef};
use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};

/// Generic X.509 signature structure
pub struct X509Signature<'a, 'b> {
    algorithm: AlgorithmIdentifierRef<'a>,
    data: &'b [u8],
}

impl<'a, 'b> X509Signature<'a, 'b> {
    /// Builds a new signature object given the `AlgorithmIdentifier` and the signature data
    pub fn new(algorithm: &'a AlgorithmIdentifierOwned, data: &'b [u8]) -> Self {
        Self {
            algorithm: algorithm.owned_to_ref(),
            data,
        }
    }

    /// Builds a new signature object given the `AlgorithmIdentifier` and the signature data
    pub fn from_ref(algorithm: AlgorithmIdentifierRef<'a>, data: &'b [u8]) -> Self {
        Self { algorithm, data }
    }

    /// Asserts the `AlgorithmIdentifer` matches an expected `ObjectIdentifier`
    pub fn assert_algorithm_oid(
        &self,
        expected_oid: ObjectIdentifier,
    ) -> Result<ObjectIdentifier, spki::Error> {
        self.algorithm.assert_algorithm_oid(expected_oid)
    }

    /// Returns a reference to the `ObjectIdentifier`
    pub fn oid(&self) -> &ObjectIdentifier {
        &self.algorithm.oid
    }

    /// Returns a reference to the raw signature data
    pub fn data(&self) -> &[u8] {
        self.data
    }
}
