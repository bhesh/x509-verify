//! Generic X.509 VerifyingKey

use crate::{Error, Message, Signature};
use alloc::vec::Vec;
use core::result::Result;
use der::referenced::OwnedToRef;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

#[cfg(any(
    feature = "dsa",
    feature = "rsa",
    feature = "k256",
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384",
    feature = "ed25519"
))]
use const_oid::AssociatedOid;

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
pub type VerifyInfoRef<'a, 'b, 'c> = VerifyInfo<'a, &'b [u8], &'c [u8]>;

impl<'a, 'b, 'c> From<&VerifyInfoRef<'a, 'b, 'c>> for VerifyInfoRef<'a, 'b, 'c> {
    fn from(other: &VerifyInfoRef<'a, 'b, 'c>) -> Self {
        *other
    }
}

impl<'a, 'b, 'c> From<&'b VerifyInfo<'a, Vec<u8>, &'c [u8]>> for VerifyInfoRef<'a, 'b, 'c> {
    /// Converts the owned [`Message`] in [`VerifyInfo`] to a referenced [`Message`]
    ///
    /// Under normal circumstances, [`Message`] will own the encoded DER of the X.509 structure
    /// being verified. This trait converts it to a reference which allows [`VerifyInfo`] to
    /// inherit a relatively cheap `Copy` trait.
    ///
    /// On the other hand, the internal [`Signature`] is typically referenced as the signature
    /// data itself lives in the X.509 structure.
    fn from(other: &'b VerifyInfo<'a, Vec<u8>, &'c [u8]>) -> Self {
        VerifyInfo::new(other.message().into(), other.signature().into())
    }
}

impl<'a, 'b> From<&'b VerifyInfo<'a, Vec<u8>, Vec<u8>>> for VerifyInfoRef<'a, 'b, 'b> {
    fn from(other: &'b VerifyInfo<'a, Vec<u8>, Vec<u8>>) -> Self {
        VerifyInfo::new(other.message().into(), other.signature().into())
    }
}

impl<'a> From<&'a VerifyInfo<'a, &'a [u8], Vec<u8>>> for VerifyInfoRef<'a, 'a, 'a> {
    /// Rust compiler did not accept the appropriate lifetimes.
    ///
    /// I believe lifetimes should be:
    ///
    /// ```text
    /// 'a: self.sig.algorithm        (AlgorithmIdentifierRef<'a>)
    /// 'b: self.msg.0                (Borrowed &'b [u8])
    /// 'c: &'c self.sig.data         (Owned Vec<u8>)
    /// ```
    #[must_use = "possible bad lifetimes"]
    fn from(other: &'a VerifyInfo<'a, &'a [u8], Vec<u8>>) -> Self {
        VerifyInfo::new(other.message().into(), other.signature().into())
    }
}

/// Structure used to verify a signature
#[derive(Clone, Debug)]
#[allow(unused_qualifications)]
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

    /// No usable features...
    #[cfg(not(any(
        feature = "dsa",
        feature = "rsa",
        feature = "k256",
        feature = "p192",
        feature = "p224",
        feature = "p256",
        feature = "p384",
        feature = "ed25519"
    )))]
    Fail,
}

impl VerifyingKey {
    /// Creates a new [`VerifyingKey`] given the `SubjectPublicKeyInfo`
    #[allow(unused_qualifications)]
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
    #[allow(unused_variables, clippy::useless_conversion)]
    pub fn verify<'a, V, M, S>(&self, verify_info: V) -> Result<(), Error>
    where
        V: TryInto<VerifyInfo<'a, M, S>>,
        V::Error: Into<Error>,
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let verify_info = verify_info.try_into().map_err(|e| e.into())?;
        match self {
            #[cfg(feature = "dsa")]
            VerifyingKey::Dsa(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(feature = "rsa")]
            VerifyingKey::Rsa(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            VerifyingKey::Ecdsa(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(feature = "ed25519")]
            VerifyingKey::Ed25519(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(not(any(
                feature = "dsa",
                feature = "rsa",
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384",
                feature = "ed25519"
            )))]
            VerifyingKey::Fail => unreachable!(),
        }
    }

    /// Verifies the signature given the [`VerifyInfo`]. Does not normalize ECDSA and EdDSA
    /// signatures prior to verification.
    #[allow(unused_variables, clippy::useless_conversion)]
    pub fn verify_strict<'a, V, M, S>(&self, verify_info: V) -> Result<(), Error>
    where
        V: TryInto<VerifyInfo<'a, M, S>>,
        V::Error: Into<Error>,
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let verify_info = verify_info.try_into().map_err(|e| e.into())?;
        match self {
            #[cfg(feature = "dsa")]
            VerifyingKey::Dsa(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(feature = "rsa")]
            VerifyingKey::Rsa(k) => k
                .verify(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            VerifyingKey::Ecdsa(k) => k
                .verify_strict(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(feature = "ed25519")]
            VerifyingKey::Ed25519(k) => k
                .verify_strict(verify_info.message(), verify_info.signature())
                .map_err(|e| e.into()),

            #[cfg(not(any(
                feature = "dsa",
                feature = "rsa",
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384",
                feature = "ed25519"
            )))]
            VerifyingKey::Fail => unreachable!(),
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
