//! EdDSA VerifyingKey

use crate::{Error, Signature};
use const_oid::AssociatedOid;
use der::asn1::ObjectIdentifier;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use signature::Verifier;
use spki::SubjectPublicKeyInfoRef;

// 1.3.6.1.4.1.11591.15.1 Another ed25519?
#[cfg(feature = "ed25519")]
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Clone, Debug)]
pub struct Ed25519VerifyingKey {
    key: VerifyingKey,
}

impl AssociatedOid for Ed25519VerifyingKey {
    // ID_EC_PUBLIC_KEY
    const OID: ObjectIdentifier = ID_ED25519;
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for Ed25519VerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(other.subject_public_key.raw_bytes());
        Ok(Self {
            key: VerifyingKey::from_bytes(&bytes).or(Err(Error::InvalidKey))?,
        })
    }
}

impl Ed25519VerifyingKey {
    pub fn verify<S>(&self, msg: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        self.key
            .verify(
                msg,
                &Ed25519Signature::from_slice(signature.data()).or(Err(Error::InvalidSignature))?,
            )
            .or(Err(Error::Verification))
    }

    pub fn verify_strict<S>(&self, msg: &[u8], signature: &Signature<'_, S>) -> Result<(), Error>
    where
        S: AsRef<[u8]>,
    {
        self.key
            .verify_strict(
                msg,
                &Ed25519Signature::from_slice(signature.data()).or(Err(Error::InvalidSignature))?,
            )
            .or(Err(Error::Verification))
    }
}
