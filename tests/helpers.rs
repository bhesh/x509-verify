#![allow(dead_code)]
use der::{referenced::OwnedToRef, DecodePem, Encode};
use std::fmt::Debug;
use x509_cert::Certificate;
use x509_verify::{Error, X509Signature, X509VerifyInfo, X509VerifyingKey};

#[macro_export]
macro_rules! read_der {
    ($into:ty, $file:tt) => {{
        let mut f = std::fs::File::open($file).expect("error opening file");
        let mut data = Vec::new();
        f.read_to_end(&mut data).expect("error reading file");
        <$into>::from_der(&data).expect("error formatting der")
    }};
}

#[macro_export]
macro_rules! read_pem {
    ($into:ty, $file:tt) => {
        <$into>::from_pem(&std::fs::read_to_string($file).expect("error reading file"))
            .expect("error formatting pem")
    };
}

pub fn self_signed_good(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let msg = cert
        .tbs_certificate
        .to_der()
        .expect("error encoding message");
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    let key: X509VerifyingKey = cert
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .expect("error making key");
    key.verify(&X509VerifyInfo::new(msg.into(), sig))
        .expect("verify failed");
}

pub fn self_signed_bad(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    let key: X509VerifyingKey = cert
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .expect("error making key");
    match key.verify(&X509VerifyInfo::new("".as_bytes().into(), sig)) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}

pub fn self_signed_bad_oid(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    match X509VerifyingKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref()) {
        Ok(v) => match v.verify(&X509VerifyInfo::new("".as_bytes().into(), sig)) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::UnknownOid(_)) => {}
            Err(e) => panic!("{:?}", e),
        },
        Err(Error::UnknownOid(_)) => {}
        Err(e) => panic!("{:?}", e),
    }
}

pub fn x509_verify_good<'a, K, V, B>(key: K, verify_info: V)
where
    K: TryInto<X509VerifyingKey>,
    K::Error: Debug,
    V: TryInto<X509VerifyInfo<'a, 'a, B>>,
    V::Error: Debug,
    B: AsRef<[u8]>,
{
    let key: X509VerifyingKey = key.try_into().expect("error making key");
    let verify_info = verify_info
        .try_into()
        .expect("error making message or signature");
    key.verify(&verify_info).expect("error verifying");
}

pub fn x509_verify_bad<'a, K, S>(key: K, signature: S)
where
    K: TryInto<X509VerifyingKey>,
    K::Error: Debug,
    S: TryInto<X509Signature<'a, 'a>>,
    S::Error: Debug,
{
    let key: X509VerifyingKey = key.try_into().expect("error making key");
    let verify_info = X509VerifyInfo::new(
        "".as_bytes().into(),
        signature.try_into().expect("error making signature"),
    );
    match key.verify(&verify_info) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}
