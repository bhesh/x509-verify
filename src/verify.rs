//! Generic X.509 VerifyKey

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

/// Structure used to verify a signature
#[derive(Clone, Debug)]
pub enum X509VerifyKey {
    #[cfg(feature = "dsa")]
    Dsa(self::dsa::X509DsaVerifyKey),

    #[cfg(feature = "rsa")]
    Rsa(self::rsa::X509RsaVerifyKey),

    #[cfg(any(
        feature = "k256",
        feature = "p192",
        feature = "p224",
        feature = "p256",
        feature = "p384"
    ))]
    Ecdsa(self::ecdsa::X509EcdsaVerifyKey),
}

impl X509VerifyKey {
    /// Creates a new [`X509VerifyKey`] given the `SubjectPublicKeyInfo`
    pub fn new(key_info: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Error> {
        match &key_info.algorithm.oid {
            #[cfg(feature = "dsa")]
            &self::dsa::X509DsaVerifyKey::OID => {
                Ok(Self::Dsa(self::dsa::X509DsaVerifyKey::try_from(key_info)?))
            }

            #[cfg(feature = "rsa")]
            &self::rsa::X509RsaVerifyKey::OID => {
                Ok(Self::Rsa(self::rsa::X509RsaVerifyKey::try_from(key_info)?))
            }

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &self::ecdsa::X509EcdsaVerifyKey::OID => Ok(Self::Ecdsa(
                self::ecdsa::X509EcdsaVerifyKey::try_from(key_info)?,
            )),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }

    /// Verifies the signature given the message and [`X509Signature`]
    pub fn verify<'a, 'b, M, B, S>(&self, msg: M, signature: S) -> Result<(), Error>
    where
        M: TryInto<X509Message<B>>,
        B: AsRef<[u8]>,
        S: TryInto<X509Signature<'a, 'b>>,
    {
        match self {
            #[cfg(feature = "dsa")]
            X509VerifyKey::Dsa(k) => k.verify(
                msg.try_into().or(Err(Error::Encoding))?.as_ref(),
                &signature.try_into().or(Err(Error::Encoding))?,
            ),

            #[cfg(feature = "rsa")]
            X509VerifyKey::Rsa(k) => k.verify(
                msg.try_into().or(Err(Error::Encoding))?.as_ref(),
                &signature.try_into().or(Err(Error::Encoding))?,
            ),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            X509VerifyKey::Ecdsa(k) => k.verify(
                msg.try_into().or(Err(Error::Encoding))?.as_ref(),
                &signature.try_into().or(Err(Error::Encoding))?,
            ),
        }
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
