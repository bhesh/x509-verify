//! RSA VerifyingKey

use crate::{Error, Signature};
use const_oid::AssociatedOid;
use der::{asn1::ObjectIdentifier, Encode};
use rsa::RsaPublicKey;
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

#[cfg(any(feature = "md2", feature = "md5", feature = "sha1", feature = "sha2"))]
use rsa::Pkcs1v15Sign;

#[cfg(any(feature = "sha1", feature = "sha2"))]
use ::signature::digest::Digest;

#[cfg(feature = "md2")]
use md2::Md2;

#[cfg(feature = "md2")]
const MD_2_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.2");

#[cfg(feature = "md5")]
use md5::Md5;

#[cfg(feature = "md5")]
const MD_5_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4");

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha1")]
const SHA_1_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(feature = "sha2")]
const SHA_224_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");

#[cfg(feature = "sha2")]
const SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

#[cfg(feature = "sha2")]
const SHA_384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

#[cfg(feature = "sha2")]
const SHA_512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct RsaVerifyingKey {
    key: RsaPublicKey,
}

impl AssociatedOid for RsaVerifyingKey {
    // RSA_ENCRYPTION
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for RsaVerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: RsaPublicKey::from_public_key_der(&other.to_der().or(Err(Error::Encode))?)
                .or(Err(Error::InvalidKey))?,
        })
    }
}

impl RsaVerifyingKey {
    #[allow(unused_variables)]
    pub fn verify<S>(&self, msg: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        match signature.oid() {
            #[cfg(feature = "md2")]
            &MD_2_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Md2>(),
                    &Md2::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "md5")]
            &MD_5_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Md5>(),
                    &Md5::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha1")]
            &SHA_1_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha1>(),
                    &Sha1::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_224_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha224>(),
                    &Sha224::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_256_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_384_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha384>(),
                    &Sha384::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_512_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha512>(),
                    &Sha512::digest(msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }
}
