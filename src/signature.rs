//! Generic X.509 Signature

use core::marker::PhantomData;
use der::asn1::ObjectIdentifier;
use signature::digest::Digest;

pub struct X509Signature<'a, D>
where
    D: Digest,
{
    oid: ObjectIdentifier,
    data: &'a [u8],
    phantom: PhantomData<D>,
}

impl<'a, D> X509Signature<'a, D>
where
    D: Digest,
{
    pub fn new(oid: ObjectIdentifier, data: &'a [u8]) -> Self {
        Self {
            oid,
            data,
            phantom: Default::default(),
        }
    }
}
