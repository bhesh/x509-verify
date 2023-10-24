//! Generic digest implementation

use crate::error::Error;
use alloc::boxed::Box;
use core::result::Result;
use der::asn1::ObjectIdentifier;
use signature::digest::{Digest, DynDigest};

#[cfg(feature = "md2")]
use md2::Md2;

#[cfg(feature = "md5")]
use md5::Md5;

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(all(feature = "rsa", feature = "md2"))]
use const_oid::db::rfc5912::MD_2_WITH_RSA_ENCRYPTION;

#[cfg(all(feature = "rsa", feature = "md5"))]
use const_oid::db::rfc5912::MD_5_WITH_RSA_ENCRYPTION;

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

/// Generic digest
pub struct X509Digest {
    inner: Box<dyn DynDigest>,
}

impl TryFrom<&ObjectIdentifier> for X509Digest {
    type Error = Error;

    fn try_from(oid: &ObjectIdentifier) -> Result<Self, Self::Error> {
        Self::new(oid)
    }
}

impl TryFrom<ObjectIdentifier> for X509Digest {
    type Error = Error;

    fn try_from(oid: ObjectIdentifier) -> Result<Self, Self::Error> {
        Self::new(&oid)
    }
}

impl X509Digest {
    pub fn new(oid: &ObjectIdentifier) -> Result<Self, Error> {
        match oid {
            #[cfg(all(feature = "rsa", feature = "md2"))]
            &MD_2_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Md2::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "md5"))]
            &MD_5_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Md5::new()),
            }),

            #[cfg(all(feature = "dsa", feature = "sha1"))]
            &DSA_WITH_SHA_1 => Ok(Self {
                inner: Box::from(Sha1::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "sha1"))]
            &SHA_1_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Sha1::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_224_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Sha224::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_256_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Sha256::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_384_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Sha384::new()),
            }),

            #[cfg(all(feature = "rsa", feature = "sha2"))]
            &SHA_512_WITH_RSA_ENCRYPTION => Ok(Self {
                inner: Box::from(Sha512::new()),
            }),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_224 => Ok(Self {
                inner: Box::from(Sha224::new()),
            }),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_256 => Ok(Self {
                inner: Box::from(Sha256::new()),
            }),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_384 => Ok(Self {
                inner: Box::from(Sha384::new()),
            }),

            #[cfg(feature = "sha2")]
            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &ECDSA_WITH_SHA_512 => Ok(Self {
                inner: Box::from(Sha512::new()),
            }),

            _ => Err(Error::UnknownOid(oid.clone())),
        }
    }

    pub fn digest(&mut self, msg: &[u8]) -> Box<[u8]> {
        self.inner.update(msg);
        self.inner.finalize_reset()
    }
}
