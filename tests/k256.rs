#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "k256")]
mod k256_tests {
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha2")]
    #[test]
    fn k256_with_sha256_good() {
        self_signed_good("testdata/secp256k1-sha256-crt.pem");
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
        x509_verify_good(&cert, &cert);
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
