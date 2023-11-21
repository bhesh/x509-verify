//! DSA VerifyingKey

use crate::{Error, Signature};
use const_oid::{db::rfc5912::ID_DSA, AssociatedOid};
use der::{asn1::ObjectIdentifier, Encode};
use dsa::{Signature as DsaSignature, VerifyingKey};
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

#[cfg(any(feature = "sha1", feature = "sha2"))]
use ::signature::{digest::Digest, hazmat::PrehashVerifier};

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha1")]
use const_oid::db::rfc5912::DSA_WITH_SHA_1;

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256};

#[cfg(feature = "sha2")]
use const_oid::db::rfc5912::DSA_WITH_SHA_224;

#[cfg(feature = "sha2")]
use const_oid::db::rfc5912::DSA_WITH_SHA_256;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DsaVerifyingKey {
    key: VerifyingKey,
}

impl AssociatedOid for DsaVerifyingKey {
    const OID: ObjectIdentifier = ID_DSA;
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for DsaVerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: VerifyingKey::from_public_key_der(&other.to_der().or(Err(Error::Decode))?)
                .or(Err(Error::InvalidKey))?,
        })
    }
}

impl DsaVerifyingKey {
    #[allow(unused_variables)]
    pub fn verify<S>(&self, msg: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        let sig = DsaSignature::try_from(signature.data()).or(Err(Error::InvalidSignature))?;
        match signature.oid() {
            #[cfg(feature = "sha1")]
            &DSA_WITH_SHA_1 => self
                .key
                .verify_prehash(&Sha1::digest(msg), &sig)
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &DSA_WITH_SHA_224 => self
                .key
                .verify_prehash(&Sha224::digest(msg), &sig)
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &DSA_WITH_SHA_256 => self
                .key
                .verify_prehash(&Sha256::digest(msg), &sig)
                .or(Err(Error::Verification)),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }
}
