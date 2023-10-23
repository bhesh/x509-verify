//! Generic X.509 Signature

use core::marker::PhantomData;
use der::asn1::ObjectIdentifier;
use spki::AlgorithmIdentifierOwned;

pub struct X509Signature<'a> {
    algorithm: AlgorithmIdentifierOwned,
    data: &'a [u8],
}

impl<'a> X509Signature<'a> {
    pub fn new(algorithm: AlgorithmIdentifierOwned, data: &'a [u8]) -> Self {
        Self { algorithm, data }
    }

    pub fn assert_algorithm_oid(
        &self,
        expected_oid: ObjectIdentifier,
    ) -> Result<ObjectIdentifier, spki::Error> {
        self.algorithm.assert_algorithm_oid(expected_oid)
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        &self.algorithm.oid
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}
