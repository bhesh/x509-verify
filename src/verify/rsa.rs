//! RSA Verifier

use der::Encode;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use signature::{digest::Digest, Verifier};
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

pub struct X509RsaVerifier {
    key: RsaPublicKey,
}

impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for X509RsaVerifier {
    type Error = signature::Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'a>) -> Result<X509RsaVerifier, Self::Error> {
        Ok(Self {
            key: RsaPublicKey::from_public_key_der(
                &other.to_der().or(Err(signature::Error::default()))?,
            )
            .or(Err(signature::Error::default()))?,
        })
    }
}

impl<'a> Verifier<X509Signature<'_>> for X509RsaVerifier<'a> {
    fn verify(&self, msg: &[u8], signature: &X509Signature<'_>) -> Result<(), signature::Error> {

    }
}
