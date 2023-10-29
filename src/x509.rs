//! X.509 Structure Conversions

use crate::{Error, X509MessageOwned, X509Signature, X509VerifyInfo, X509VerifyingKey};
use alloc::vec::Vec;
use core::result::Result;
use der::{referenced::OwnedToRef, Encode};
use ocsp_x509::{BasicOcspResponse, OcspRequest};
use x509_cert::{crl::CertificateList, request::CertReq, Certificate};

macro_rules! impl_as_message {
    ($from:ty, $where:ident) => {
        impl TryFrom<&$from> for X509MessageOwned {
            type Error = Error;

            fn try_from(obj: &$from) -> Result<Self, Self::Error> {
                Ok(Self::from(obj.$where.to_der().or(Err(Error::Encode))?))
            }
        }
    };
}

macro_rules! impl_as_verify_info {
    ($from:ty) => {
        impl<'a> TryFrom<&'a $from> for X509VerifyInfo<'a, 'a, Vec<u8>> {
            type Error = Error;

            fn try_from(obj: &'a $from) -> Result<Self, Self::Error> {
                Ok(X509VerifyInfo::new(obj.try_into()?, obj.try_into()?))
            }
        }
    };
}

impl TryFrom<&Certificate> for X509VerifyingKey {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.tbs_certificate
            .subject_public_key_info
            .owned_to_ref()
            .try_into()
    }
}

impl TryFrom<Certificate> for X509VerifyingKey {
    type Error = Error;
    fn try_from(other: Certificate) -> Result<Self, Self::Error> {
        X509VerifyingKey::try_from(&other)
    }
}

impl<'a> TryFrom<&'a Certificate> for X509Signature<'a, 'a> {
    type Error = Error;

    fn try_from(cert: &'a Certificate) -> Result<Self, Self::Error> {
        Ok(X509Signature::new(
            &cert.signature_algorithm,
            cert.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}

impl_as_message!(Certificate, tbs_certificate);
impl_as_verify_info!(Certificate);

impl<'a> TryFrom<&'a CertificateList> for X509Signature<'a, 'a> {
    type Error = Error;

    fn try_from(crl: &'a CertificateList) -> Result<Self, Self::Error> {
        Ok(X509Signature::new(
            &crl.signature_algorithm,
            crl.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}

impl_as_message!(CertificateList, tbs_cert_list);
impl_as_verify_info!(CertificateList);

impl<'a> TryFrom<&'a CertReq> for X509Signature<'a, 'a> {
    type Error = Error;

    fn try_from(req: &'a CertReq) -> Result<Self, Self::Error> {
        Ok(X509Signature::new(
            &req.algorithm,
            req.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}

impl_as_message!(CertReq, info);
impl_as_verify_info!(CertReq);

impl<'a> TryFrom<&'a OcspRequest> for X509Signature<'a, 'a> {
    type Error = Error;

    fn try_from(req: &'a OcspRequest) -> Result<Self, Self::Error> {
        let signature = req.optional_signature.as_ref().ok_or(Error::Decode)?;
        Ok(X509Signature::new(
            &signature.signature_algorithm,
            signature.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}

impl_as_message!(OcspRequest, tbs_request);
impl_as_verify_info!(OcspRequest);

impl<'a> TryFrom<&'a BasicOcspResponse> for X509Signature<'a, 'a> {
    type Error = Error;

    fn try_from(res: &'a BasicOcspResponse) -> Result<Self, Self::Error> {
        Ok(X509Signature::new(
            &res.signature_algorithm,
            res.signature.as_bytes().ok_or(Error::Decode)?,
        ))
    }
}

impl_as_message!(BasicOcspResponse, tbs_response_data);
impl_as_verify_info!(BasicOcspResponse);
