//! DSA Verifier

use crate::X509Signature;
use core::result::Result;
use der::asn1::ObjectIdentifier;
use signature::{digest::Digest, hazmat::PrehashVerifier, DigestVerifier, Verifier};
use spki::SubjectPublicKeyInfoRef;

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

pub struct X509RsaVerifier<'a> {
    
}

impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for X509RsaVerifier {
    type Error = signature::Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'a>) -> Result<X509RsaVerifier, Self::Error> {
        
    }
}
