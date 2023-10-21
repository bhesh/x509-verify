//! Generic X.509 Signature

use core::marker::PhantomData;
use der::asn1::ObjectIdentifier;

pub struct X509Signature<'a> {
    oid: ObjectIdentifier,
    data: &'a [u8],
}

impl<'a> X509Signature<'a> {
    pub fn new(oid: ObjectIdentifier, data: &'a [u8]) -> Self {
        Self { oid, data }
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        &self.oid
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}
