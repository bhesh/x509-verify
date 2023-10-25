//! Generic X.509 Signature

use der::asn1::ObjectIdentifier;
use spki::AlgorithmIdentifierOwned;

/// Generic X.509 signature structure
pub struct X509Signature<'a> {
    algorithm: AlgorithmIdentifierOwned,
    data: &'a [u8],
}

impl<'a> X509Signature<'a> {
    /// Builds a new signature object given the `AlgorithmIdentifier` and the signature data
    pub fn new(algorithm: AlgorithmIdentifierOwned, data: &'a [u8]) -> Self {
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
