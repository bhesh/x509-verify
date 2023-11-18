//! ECDSA VerifyingKey

use crate::{Error, Signature};
use const_oid::AssociatedOid;
use der::asn1::ObjectIdentifier;
use ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use spki::SubjectPublicKeyInfoRef;

#[cfg(feature = "sha2")]
use ::signature::{digest::Digest, hazmat::PrehashVerifier};

#[cfg(feature = "k256")]
const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[cfg(feature = "p192")]
const SECP_192_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1");

#[cfg(feature = "p224")]
const SECP_224_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.33");

#[cfg(feature = "p256")]
const SECP_256_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[cfg(feature = "p384")]
const SECP_384_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(feature = "sha2")]
const ECDSA_WITH_SHA_224: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1");

#[cfg(feature = "sha2")]
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[cfg(feature = "sha2")]
const ECDSA_WITH_SHA_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

#[cfg(feature = "sha2")]
const ECDSA_WITH_SHA_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

#[derive(Clone, Debug)]
pub enum EcdsaVerifyingKey {
    #[cfg(feature = "k256")]
    K256(VerifyingKey<k256::Secp256k1>),

    #[cfg(feature = "p192")]
    P192(VerifyingKey<p192::NistP192>),

    #[cfg(feature = "p224")]
    P224(VerifyingKey<p224::NistP224>),

    #[cfg(feature = "p256")]
    P256(VerifyingKey<p256::NistP256>),

    #[cfg(feature = "p384")]
    P384(VerifyingKey<p384::NistP384>),
}

impl EcdsaVerifyingKey {
    fn verify_prehash<S>(&self, prehash: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        match &self {
            #[cfg(feature = "k256")]
            Self::K256(pk) => {
                let sig = EcdsaSignature::<k256::Secp256k1>::from_der(signature.data())
                    .or(Err(Error::InvalidSignature))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                pk.verify_prehash(prehash, &sig)
                    .or(Err(Error::Verification))
            }

            #[cfg(feature = "p192")]
            Self::P192(pk) => {
                let sig = EcdsaSignature::<p192::NistP192>::from_der(signature.data())
                    .or(Err(Error::InvalidSignature))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                pk.verify_prehash(prehash, &sig)
                    .or(Err(Error::Verification))
            }

            #[cfg(feature = "p224")]
            Self::P224(pk) => {
                let sig = EcdsaSignature::<p224::NistP224>::from_der(signature.data())
                    .or(Err(Error::InvalidSignature))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                pk.verify_prehash(prehash, &sig)
                    .or(Err(Error::Verification))
            }

            #[cfg(feature = "p256")]
            Self::P256(pk) => {
                let sig = EcdsaSignature::<p256::NistP256>::from_der(signature.data())
                    .or(Err(Error::InvalidSignature))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                pk.verify_prehash(prehash, &sig)
                    .or(Err(Error::Verification))
            }

            #[cfg(feature = "p384")]
            Self::P384(pk) => {
                let sig = EcdsaSignature::<p384::NistP384>::from_der(signature.data())
                    .or(Err(Error::InvalidSignature))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                pk.verify_prehash(prehash, &sig)
                    .or(Err(Error::Verification))
            }
        }
    }
}

impl AssociatedOid for EcdsaVerifyingKey {
    // ID_EC_PUBLIC_KEY
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for EcdsaVerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        let oid = ObjectIdentifier::from_bytes(
            other
                .algorithm
                .parameters
                .as_ref()
                .ok_or(Error::InvalidKey)?
                .value(),
        )
        .or(Err(Error::Decode))?;
        match &oid {
            #[cfg(feature = "k256")]
            &SECP_256_K_1 => Ok(Self::K256(
                VerifyingKey::from_sec1_bytes(other.subject_public_key.raw_bytes())
                    .or(Err(Error::InvalidKey))?,
            )),

            #[cfg(feature = "p192")]
            &SECP_192_R_1 => Ok(Self::P192(
                VerifyingKey::from_sec1_bytes(other.subject_public_key.raw_bytes())
                    .or(Err(Error::InvalidKey))?,
            )),

            #[cfg(feature = "p224")]
            &SECP_224_R_1 => Ok(Self::P224(
                VerifyingKey::from_sec1_bytes(other.subject_public_key.raw_bytes())
                    .or(Err(Error::InvalidKey))?,
            )),

            #[cfg(feature = "p256")]
            &SECP_256_R_1 => Ok(Self::P256(
                VerifyingKey::from_sec1_bytes(other.subject_public_key.raw_bytes())
                    .or(Err(Error::InvalidKey))?,
            )),

            #[cfg(feature = "p384")]
            &SECP_384_R_1 => Ok(Self::P384(
                VerifyingKey::from_sec1_bytes(other.subject_public_key.raw_bytes())
                    .or(Err(Error::InvalidKey))?,
            )),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }
}

impl EcdsaVerifyingKey {
    pub fn verify<S>(&self, msg: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        match signature.oid() {
            #[cfg(feature = "sha2")]
            &ECDSA_WITH_SHA_224 => self.verify_prehash(&Sha224::digest(msg), signature),

            #[cfg(feature = "sha2")]
            &ECDSA_WITH_SHA_256 => self.verify_prehash(&Sha256::digest(msg), signature),

            #[cfg(feature = "sha2")]
            &ECDSA_WITH_SHA_384 => self.verify_prehash(&Sha384::digest(msg), signature),

            #[cfg(feature = "sha2")]
            &ECDSA_WITH_SHA_512 => self.verify_prehash(&Sha512::digest(msg), signature),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }
}
