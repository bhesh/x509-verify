//! X.509 Structure Conversions

use crate::{Error, MessageOwned, SignatureRef, VerifyInfo, VerifyingKey};
use alloc::vec::Vec;
use core::result::Result;
use der::{referenced::OwnedToRef, Encode};
use ocsp_x509::{BasicOcspResponse, OcspRequest};
use x509_cert::{crl::CertificateList, request::CertReq, Certificate};

macro_rules! impl_as_message {
    ($from:ty, $msg:ident) => {
        impl TryFrom<&$from> for MessageOwned {
            type Error = Error;

            fn try_from(other: &$from) -> Result<Self, Self::Error> {
                Ok(Self::from(other.$msg.to_der().or(Err(Error::Encode))?))
            }
        }
    };
}

macro_rules! impl_as_signature {
    ($from:ty, $sig:ident, $alg:ident) => {
        impl<'a> TryFrom<&'a $from> for SignatureRef<'a, 'a> {
            type Error = Error;

            fn try_from(other: &'a $from) -> Result<Self, Self::Error> {
                Ok(SignatureRef::new(
                    &other.$sig,
                    other.$alg.as_bytes().ok_or(Error::Decode)?,
                ))
            }
        }
    };
}

macro_rules! impl_as_verify_info {
    ($from:ty) => {
        impl<'a> TryFrom<&'a $from> for VerifyInfo<'a, Vec<u8>, &'a [u8]> {
            type Error = Error;

            fn try_from(other: &'a $from) -> Result<Self, Self::Error> {
                Ok(VerifyInfo::new(other.try_into()?, other.try_into()?))
            }
        }
    };
}

impl TryFrom<&Certificate> for VerifyingKey {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.tbs_certificate
            .subject_public_key_info
            .owned_to_ref()
            .try_into()
    }
}

impl TryFrom<Certificate> for VerifyingKey {
    type Error = Error;
    fn try_from(other: Certificate) -> Result<Self, Self::Error> {
        VerifyingKey::try_from(&other)
    }
}

// Certificate
impl_as_message!(Certificate, tbs_certificate);
impl_as_signature!(Certificate, signature_algorithm, signature);
impl_as_verify_info!(Certificate);

// CertificateList
impl_as_message!(CertificateList, tbs_cert_list);
impl_as_signature!(CertificateList, signature_algorithm, signature);
impl_as_verify_info!(CertificateList);

// CertReq
impl_as_message!(CertReq, info);
impl_as_signature!(CertReq, algorithm, signature);
impl_as_verify_info!(CertReq);

// OcspRequest
impl_as_message!(OcspRequest, tbs_request);
impl<'a> TryFrom<&'a OcspRequest> for SignatureRef<'a, 'a> {
    type Error = Error;

    fn try_from(req: &'a OcspRequest) -> Result<Self, Self::Error> {
        let signature = req.optional_signature.as_ref().ok_or(Error::Decode)?;
        Ok(SignatureRef::new(
            &signature.signature_algorithm,
            signature.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}
impl_as_verify_info!(OcspRequest);

// BasicOcspResponse
impl_as_message!(BasicOcspResponse, tbs_response_data);
impl_as_signature!(BasicOcspResponse, signature_algorithm, signature);
impl_as_verify_info!(BasicOcspResponse);
