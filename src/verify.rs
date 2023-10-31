//! Generic X.509 VerifyingKey

use crate::{Error, Message, Signature};
use alloc::vec::Vec;
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
#[derive(Copy, Clone, Debug)]
pub struct VerifyInfo<'a, M, S>
where
    M: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    msg: Message<M>,
    sig: Signature<'a, S>,
}

impl<'a, M, S> VerifyInfo<'a, M, S>
where
    M: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    /// Creates the [`VerifyInfo`] given the [`Message`] and [`Signature`]
    pub fn new(msg: Message<M>, sig: Signature<'a, S>) -> Self {
        Self { msg, sig }
    }

    /// Returns a reference to the message bytes
    fn message(&self) -> &[u8] {
        self.msg.as_ref()
    }

    /// Returns a reference to the [`Signature`]
    fn signature(&self) -> &Signature<'a, S> {
        &self.sig
    }
}

/// [`VerifyInfo`] with references to both message bytes and signature data
pub type VerifyInfoRef<'a, 'b, 'c> = VerifyInfo<'a, &'c [u8], &'b [u8]>;

impl<'a, 'b, 'c> From<&VerifyInfoRef<'a, 'b, 'c>> for VerifyInfoRef<'a, 'b, 'c> {
    fn from(other: &VerifyInfoRef<'a, 'b, 'c>) -> Self {
        *other
    }
}

impl<'a, 'b, 'c> From<&'c VerifyInfo<'a, Vec<u8>, &'b [u8]>> for VerifyInfoRef<'a, 'b, 'c> {
    /// Converts the owned [`Message`] in [`VerifyInfo`] to a referenced [`Message`]
    ///
    /// Under normal circumstances, [`Message`] will own the encoded DER of the X.509 structure
    /// being verified. This trait converts it to a reference which allows [`VerifyInfo`] to
    /// inherit a relatively cheap `Copy` trait.
    ///
    /// On the other hand, the internal [`Signature`] is typically referenced as the signature
    /// data itself lives in the X.509 structure.
    fn from(other: &'c VerifyInfo<'a, Vec<u8>, &'b [u8]>) -> Self {
        VerifyInfo::new(other.message().into(), other.signature().into())
    }
}

/// Structure used to verify a signature
#[derive(Clone, Debug)]
pub enum VerifyingKey {
    /// DSA Keys
    #[cfg(feature = "dsa")]
    Dsa(self::dsa::DsaVerifyingKey),

    /// RSA Keys
    #[cfg(feature = "rsa")]
    Rsa(self::rsa::RsaVerifyingKey),

    /// ECDSA Keys
    #[cfg(any(
        feature = "k256",
        feature = "p192",
        feature = "p224",
        feature = "p256",
        feature = "p384"
    ))]
    Ecdsa(self::ecdsa::EcdsaVerifyingKey),

    /// ED25519 Keys
    #[cfg(feature = "ed25519")]
    Ed25519(self::ed25519::Ed25519VerifyingKey),
}

impl VerifyingKey {
    /// Creates a new [`VerifyingKey`] given the `SubjectPublicKeyInfo`
    pub fn new(key_info: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Error> {
        match &key_info.algorithm.oid {
            #[cfg(feature = "dsa")]
            &self::dsa::DsaVerifyingKey::OID => {
                Ok(Self::Dsa(self::dsa::DsaVerifyingKey::try_from(key_info)?))
            }

            #[cfg(feature = "rsa")]
            &self::rsa::RsaVerifyingKey::OID => {
                Ok(Self::Rsa(self::rsa::RsaVerifyingKey::try_from(key_info)?))
            }

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &self::ecdsa::EcdsaVerifyingKey::OID => Ok(Self::Ecdsa(
                self::ecdsa::EcdsaVerifyingKey::try_from(key_info)?,
            )),

            #[cfg(feature = "ed25519")]
            &self::ed25519::Ed25519VerifyingKey::OID => Ok(Self::Ed25519(
                self::ed25519::Ed25519VerifyingKey::try_from(key_info)?,
            )),

            oid => Err(Error::UnknownOid(*oid)),
        }
    }

    /// Verifies the signature given the [`VerifyInfo`]
    pub fn verify<'a, V, M, S>(&self, verify_info: V) -> Result<(), Error>
    where
        V: TryInto<VerifyInfo<'a, M, S>>,
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
        Error: From<V::Error>,
    {
        let verify_info = verify_info.try_into()?;
        match self {
            #[cfg(feature = "dsa")]
            VerifyingKey::Dsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(feature = "rsa")]
            VerifyingKey::Rsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            VerifyingKey::Ecdsa(k) => k.verify(verify_info.message(), verify_info.signature()),

            #[cfg(feature = "ed25519")]
            VerifyingKey::Ed25519(k) => k.verify(verify_info.message(), verify_info.signature()),
        }
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Self::new(other)
    }
}

impl TryFrom<SubjectPublicKeyInfoOwned> for VerifyingKey {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        Self::new(other.owned_to_ref())
    }
}
