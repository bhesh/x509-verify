//! Generic X.509 VerifyingKey

use crate::{Error, X509Message, X509Signature};
use const_oid::AssociatedOid;
use core::result::Result;
use der::referenced::OwnedToRef;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

#[cfg(feature = "dsa")]
mod dsa;

#[cfg(feature = "rsa")]
mod rsa;

#[cfg(any(
    feature = "k256",
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384"
))]
mod ecdsa;

#[cfg(feature = "ed25519")]
mod ed25519;

/// Structure for concatenating message and signature information
#[derive(Clone, Debug)]
pub struct X509VerifyInfo<'a, 'b, T>
where
    T: AsRef<[u8]>,
{
    msg: X509Message<T>,
    sig: X509Signature<'a, 'b>,
}

impl<'a, 'b, T> X509VerifyInfo<'a, 'b, T>
where
    T: AsRef<[u8]>,
{
    pub fn new(msg: X509Message<T>, sig: X509Signature<'a, 'b>) -> Self {
        Self { msg, sig }
    }

    pub fn message(&self) -> &[u8] {
        self.msg.as_ref()
    }

    /// Returns a reference to the raw signature data
    pub fn signature(&self) -> &X509Signature<'_, '_> {
        &self.sig
    }
}

/// Structure used to verify a signature
#[derive(Clone, Debug)]
pub enum X509VerifyingKey {
    #[cfg(feature = "dsa")]
    Dsa(self::dsa::X509DsaVerifyingKey),

    #[cfg(feature = "rsa")]
    Rsa(self::rsa::X509RsaVerifyingKey),

    #[cfg(any(
        feature = "k256",
        feature = "p192",
        feature = "p224",
        feature = "p256",
        feature = "p384"
    ))]
    Ecdsa(self::ecdsa::X509EcdsaVerifyingKey),

    #[cfg(feature = "ed25519")]
    Ed25519(self::ed25519::X509Ed25519VerifyingKey),
}

impl X509VerifyingKey {
    /// Creates a new [`X509VerifyingKey`] given the `SubjectPublicKeyInfo`
    pub fn new(key_info: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Error> {
        match &key_info.algorithm.oid {
            #[cfg(feature = "dsa")]
            &self::dsa::X509DsaVerifyingKey::OID => Ok(Self::Dsa(
                self::dsa::X509DsaVerifyingKey::try_from(key_info)?,
            )),

            #[cfg(feature = "rsa")]
            &self::rsa::X509RsaVerifyingKey::OID => Ok(Self::Rsa(
                self::rsa::X509RsaVerifyingKey::try_from(key_info)?,
            )),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &self::ecdsa::X509EcdsaVerifyingKey::OID => Ok(Self::Ecdsa(
                self::ecdsa::X509EcdsaVerifyingKey::try_from(key_info)?,
            )),

            #[cfg(feature = "ed25519")]
            &self::ed25519::X509Ed25519VerifyingKey::OID => Ok(Self::Ed25519(
                self::ed25519::X509Ed25519VerifyingKey::try_from(key_info)?,
            )),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }

    /// Verifies the signature given the message and [`X509Signature`]
    pub fn verify<'a, 'b, T>(&self, verify_info: &X509VerifyInfo<'a, 'b, T>) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        match self {
            #[cfg(feature = "dsa")]
            X509VerifyingKey::Dsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(feature = "rsa")]
            X509VerifyingKey::Rsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            X509VerifyingKey::Ecdsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(feature = "ed25519")]
            X509VerifyingKey::Ed25519(k) => {
                k.verify(verify_info.message(), verify_info.signature())
            }
        }
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for X509VerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Self::new(other)
    }
}

impl TryFrom<SubjectPublicKeyInfoOwned> for X509VerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        Self::new(other.owned_to_ref())
    }
}
