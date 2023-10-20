//! Underlying X.509 Verifier

use crate::X509Signature;
use core::result::Result;
use signature::{digest::Digest, hazmat::PrehashVerifier, DigestVerifier, Verifier};

pub struct X509Verifier {
    key: [u8],
}

impl<D> PrehashVerifier<X509Signature<'_, D>> for X509Verifier
where
    D: Digest,
{
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &X509Signature<'_, D>,
    ) -> Result<(), signature::Error> {
        unimplemented!()
    }
}

impl<D> DigestVerifier<D, X509Signature<'_, D>> for X509Verifier
where
    D: Digest,
{
    fn verify_digest(
        &self,
        digest: D,
        signature: &X509Signature<'_, D>,
    ) -> Result<(), signature::Error> {
        self.verify_prehash(&digest.finalize(), signature)
    }
}

impl<D> Verifier<X509Signature<'_, D>> for X509Verifier
where
    D: Digest,
{
    fn verify(&self, msg: &[u8], signature: &X509Signature<'_, D>) -> Result<(), signature::Error> {
        self.verify_digest(D::new_with_prefix(msg), signature)
    }
}
