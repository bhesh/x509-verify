use der::{referenced::OwnedToRef, DecodePem, Encode};
use std::fmt::Debug;
use x509_cert::Certificate;
use x509_verify::{Error, X509Message, X509Signature, X509VerifyingKey};

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

#[allow(dead_code)]
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
    key.verify(&msg, &sig).expect("verify failed");
}

#[allow(dead_code)]
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
    match key.verify("".as_bytes(), &sig) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[allow(dead_code)]
pub fn self_signed_bad_oid(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    match X509VerifyingKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref()) {
        Ok(v) => match v.verify("".as_bytes(), &sig) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::UnknownOid(_)) => {}
            Err(e) => panic!("{:?}", e),
        },
        Err(Error::UnknownOid(_)) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[allow(dead_code)]
pub fn x509_verify_good<'a, K, M, B, S>(key: K, msg: M, signature: S)
where
    K: TryInto<X509VerifyingKey>,
    K::Error: Debug,
    M: TryInto<X509Message<B>>,
    M::Error: Debug,
    B: AsRef<[u8]>,
    S: TryInto<X509Signature<'a, 'a>>,
    S::Error: Debug,
{
    let key: X509VerifyingKey = key.try_into().expect("error making key");
    key.verify(msg, signature).expect("error verifying");
}

#[allow(dead_code)]
pub fn x509_verify_bad<'a, K, S>(key: K, signature: S)
where
    K: TryInto<X509VerifyingKey>,
    K::Error: Debug,
    S: TryInto<X509Signature<'a, 'a>>,
    S::Error: Debug,
{
    let key: X509VerifyingKey = key.try_into().expect("error making key");
    match key.verify("".as_bytes(), signature) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}
