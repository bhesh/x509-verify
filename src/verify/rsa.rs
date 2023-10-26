//! RSA VerifyKey

use crate::{verify::OidVerifyKey, Error, X509Message, X509Signature};
use const_oid::AssociatedOid;
use der::{asn1::ObjectIdentifier, Encode};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use signature::digest::Digest;
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

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

pub struct X509RsaVerifyKey {
    key: RsaPublicKey,
}

impl AssociatedOid for X509RsaVerifyKey {
    // RSA_ENCRYPTION
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for X509RsaVerifyKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: RsaPublicKey::from_public_key_der(&other.to_der()?)?,
        })
    }
}

impl OidVerifyKey for X509RsaVerifyKey {
    fn verify(&self, msg: &X509Message, signature: &X509Signature<'_, '_>) -> Result<(), Error> {
        match signature.oid() {
            #[cfg(feature = "md2")]
            &MD_2_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Md2>(),
                    &Md2::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "md5")]
            &MD_5_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Md5>(),
                    &Md5::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha1")]
            &SHA_1_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha1>(),
                    &Sha1::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_224_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha224>(),
                    &Sha224::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_256_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_384_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha384>(),
                    &Sha384::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &SHA_512_WITH_RSA_ENCRYPTION => self
                .key
                .verify(
                    Pkcs1v15Sign::new::<Sha512>(),
                    &Sha512::digest(&msg),
                    signature.data(),
                )
                .or(Err(Error::Verification)),

            oid => Err(Error::UnknownOid(oid.clone())),
        }
    }
}
