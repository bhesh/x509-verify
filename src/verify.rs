//! Generic X.509 VerifyKey

use crate::{Error, X509Message, X509Signature};
use alloc::boxed::Box;
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

/// Trait used by [`X509VerifyKey`] internally
pub(crate) trait OidVerifyKey {
    fn verify(&self, msg: &X509Message, signature: &X509Signature<'_, '_>) -> Result<(), Error>;
}

/// Structure used to verify a signature
pub struct X509VerifyKey {
    inner: Box<dyn OidVerifyKey>,
}

impl X509VerifyKey {
    /// Creates a new [`X509VerifyKey`] given the `SubjectPublicKeyInfo`
    pub fn new(key_info: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Error> {
        match &key_info.algorithm.oid {
            #[cfg(feature = "dsa")]
            &self::dsa::X509DsaVerifyKey::OID => Ok(Self {
                inner: Box::from(self::dsa::X509DsaVerifyKey::try_from(key_info)?),
            }),

            #[cfg(feature = "rsa")]
            &self::rsa::X509RsaVerifyKey::OID => Ok(Self {
                inner: Box::from(self::rsa::X509RsaVerifyKey::try_from(key_info)?),
            }),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &self::ecdsa::X509EcdsaVerifyKey::OID => Ok(Self {
                inner: Box::from(self::ecdsa::X509EcdsaVerifyKey::try_from(key_info)?),
            }),

            oid => Err(Error::UnknownOid(oid.clone())),
        }
    }

    /// Verifies the signature given the message and [`X509Signature`]
    pub fn verify<'a>(
        &self,
        msg: &X509Message,
        signature: &X509Signature<'a, 'a>,
    ) -> Result<(), Error> {
        self.inner.verify(msg, signature)
    }

    /// Verifies the signature given the message and [`X509Signature`]
    #[cfg(feature = "x509")]
    pub fn x509_verify<'a, M, S>(&self, msg: M, signature: S) -> Result<(), Error>
    where
        M: TryInto<X509Message>,
        S: TryInto<X509Signature<'a, 'a>>,
    {
        self.inner.verify(
            &msg.try_into().or(Err(Error::Encoding))?,
            &signature.try_into().or(Err(Error::Encoding))?,
        )
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for X509VerifyKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Self::new(other)
    }
}

impl TryFrom<SubjectPublicKeyInfoOwned> for X509VerifyKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        Self::new(other.owned_to_ref())
    }
}
