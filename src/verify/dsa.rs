//! DSA Verifier

use crate::{verify::OidVerifier, Error, X509Signature};
use const_oid::AssociatedOid;
use der::{asn1::ObjectIdentifier, Encode};
use dsa::{Signature, VerifyingKey};
use signature::{digest::Digest, hazmat::PrehashVerifier};
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha1")]
const DSA_WITH_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.3");

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256};

#[cfg(feature = "sha2")]
const DSA_WITH_SHA_224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.1");

#[cfg(feature = "sha2")]
const DSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.2");

pub struct X509DsaVerifier {
    key: VerifyingKey,
}

impl AssociatedOid for X509DsaVerifier {
    // ID_DSA
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for X509DsaVerifier {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: VerifyingKey::from_public_key_der(&other.to_der()?)?,
        })
    }
}

impl OidVerifier for X509DsaVerifier {
    fn verify(&self, msg: &[u8], signature: &X509Signature<'_>) -> Result<(), Error> {
        let sig = Signature::try_from(signature.data()).or(Err(Error::InvalidSignature))?;
        match signature.oid() {
            #[cfg(feature = "sha1")]
            &DSA_WITH_SHA_1 => self
                .key
                .verify_prehash(&Sha1::digest(&msg), &sig)
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &DSA_WITH_SHA_224 => self
                .key
                .verify_prehash(&Sha224::digest(&msg), &sig)
                .or(Err(Error::Verification)),

            #[cfg(feature = "sha2")]
            &DSA_WITH_SHA_256 => self
                .key
                .verify_prehash(&Sha256::digest(&msg), &sig)
                .or(Err(Error::Verification)),

            oid => Err(Error::UnknownOid(oid.clone())),
        }
    }
}
