#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "k256")]
mod k256_tests {
    use crate::{helpers::*, *};
    use der::{Decode, DecodePem, Encode};
    use x509_cert::Certificate;
    use x509_verify::{Error, Signature, VerifyInfo, VerifyingKey};

    #[cfg(feature = "sha2")]
    #[test]
    fn k256_with_sha256_good() {
        let cert = read_pem!(Certificate, "testdata/secp256k1-sha256-crt.pem");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = Signature::new(
            &cert.signature_algorithm,
            cert.signature
                .as_bytes()
                .expect("signature is not octet-aligned"),
        );
        let key: VerifyingKey = cert
            .tbs_certificate
            .subject_public_key_info
            .try_into()
            .expect("error making key");
        let verify_info = VerifyInfo::new(msg.into(), sig);
        let res = key.verify(&verify_info);
        assert_eq!(res, Ok(()));
        let res = key.verify_strict(&verify_info);
        assert_eq!(res, Err(Error::Verification));
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn k256_with_sha256_bad() {
        self_signed_bad("testdata/secp256k1-sha256-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_k256_with_sha256_good() {
        let cert = read_pem!(Certificate, "testdata/secp256k1-sha256-crt.pem");
        let key = VerifyingKey::try_from(&cert).unwrap();
        let res = key.verify(&cert);
        assert_eq!(res, Ok(()));
        let res = key.verify_strict(&cert);
        assert_eq!(res, Err(Error::Verification));
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_k256_with_sha256_bad() {
        let cert = read_pem!(Certificate, "testdata/secp256k1-sha256-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "k256"))]
#[test]
fn k256_with_sha256_bad_oid1() {
    self_signed_bad_oid("testdata/secp256k1-sha256-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn k256_with_sha256_bad_oid2() {
    self_signed_bad_oid("testdata/secp256k1-sha256-crt.pem");
}
