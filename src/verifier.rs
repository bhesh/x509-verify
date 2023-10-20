//! Underlying X.509 Verifier

use crate::X509Signature;
use core::result::Result;
use der::{asn1::BitString, Any};
use signature::{digest::Digest, hazmat::PrehashVerifier, DigestVerifier, Verifier};
use spki::SubjectPublicKeyInfo;

pub struct X509Verifier<'a> {
    key_info: &'a SubjectPublicKeyInfo<Any, BitString>,
}

impl<'a> PrehashVerifier<X509Signature<'_>> for X509Verifier<'a> {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &X509Signature<'_>,
    ) -> Result<(), signature::Error> {
        unimplemented!()
    }
}

impl<'a, D> DigestVerifier<D, X509Signature<'_>> for X509Verifier<'a>
where
    D: Digest,
{
    fn verify_digest(
        &self,
        digest: D,
        signature: &X509Signature<'_>,
    ) -> Result<(), signature::Error> {
        self.verify_prehash(&digest.finalize(), signature)
    }
}

impl<'a> Verifier<X509Signature<'_>> for X509Verifier<'a> {
    fn verify(&self, msg: &[u8], signature: &X509Signature<'_>) -> Result<(), signature::Error> {
        unimplemented!()
    }
}
