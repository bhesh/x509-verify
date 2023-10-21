//! Generic X.509 Verifier

use crate::X509Signature;
use core::result::Result;
use der::{
    asn1::{BitString, ObjectIdentifier},
    Any,
};
use signature::{digest::Digest, hazmat::PrehashVerifier, DigestVerifier, Verifier};
use spki::SubjectPublicKeyInfo;

#[cfg(feature = "md2")]
use md2::Md2;

#[cfg(feature = "md5")]
use md5::Md5;

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(all(feature = "rsa", feature = "md2"))]
use const_oid::db::rfs5912::MD_2_WITH_RSA_ENCRYPTION;

#[cfg(all(feature = "rsa", feature = "md5"))]
use const_oid::db::rfs5912::MD_5_WITH_RSA_ENCRYPTION;

#[cfg(all(feature = "rsa", feature = "sha1"))]
use const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;

#[cfg(all(feature = "rsa", feature = "sha2"))]
use const_oid::db::rfc5912::{
    SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
    SHA_512_WITH_RSA_ENCRYPTION,
};

#[cfg(all(feature = "dsa", feature = "sha1"))]
use const_oid::db::rfc5912::DSA_WITH_SHA_1;

#[cfg(feature = "sha2")]
#[cfg(any(
    feature = "k256",
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384"
))]
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
};

#[cfg(any(
    feature = "k256",
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384"
))]
use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;

#[cfg(feature = "k256")]
const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[cfg(feature = "p192")]
const SECP_192_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1");

#[cfg(feature = "p224")]
use const_oid::db::rfc5912::SECP_224_R_1;

#[cfg(feature = "p256")]
use const_oid::db::rfc5912::SECP_256_R_1;

#[cfg(feature = "p384")]
use const_oid::db::rfc5912::SECP_384_R_1;

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
        match signature.oid() {
            #[cfg(all(feature = "rsa", feature = "md2"))]
            &MD_2_WITH_RSA_ENCRYPTION => self.verify_prehash(&Md2::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "md5"))]
            &MD_5_WITH_RSA_ENCRYPTION => self.verify_prehash(&Md5::digest(msg), signature),

            #[cfg(all(feature = "dsa", feature = "sha1"))]
            &DSA_WITH_SHA_1 => self.verify_prehash(&Sha1::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "sha1"))]
            &SHA_1_WITH_RSA_ENCRYPTION => self.verify_prehash(&Sha1::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_224_WITH_RSA_ENCRYPTION => self.verify_prehash(&Sha224::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_256_WITH_RSA_ENCRYPTION => self.verify_prehash(&Sha256::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_384_WITH_RSA_ENCRYPTION => self.verify_prehash(&Sha384::digest(msg), signature),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_512_WITH_RSA_ENCRYPTION => self.verify_prehash(&Sha512::digest(msg), signature),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_224 => self.verify_prehash(&Sha224::digest(msg), signature),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_256 => self.verify_prehash(&Sha256::digest(msg), signature),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_384 => self.verify_prehash(&Sha384::digest(msg), signature),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_512 => self.verify_prehash(&Sha512::digest(msg), signature),

            // Deliberately empty error by signature crate...
            _ => Err(signature::Error::default()),
        }
    }
}
