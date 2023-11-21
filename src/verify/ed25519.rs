//! EdDSA VerifyingKey

use crate::{Error, Signature};
use const_oid::{db::rfc8410::ID_ED_25519, AssociatedOid};
use der::asn1::ObjectIdentifier;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use signature::Verifier;
use spki::SubjectPublicKeyInfoRef;

#[derive(Clone, Debug)]
pub struct Ed25519VerifyingKey {
    key: VerifyingKey,
}

impl AssociatedOid for Ed25519VerifyingKey {
    const OID: ObjectIdentifier = ID_ED_25519;
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
