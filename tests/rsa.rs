#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "rsa")]
mod rsa_tests {
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha1")]
    #[test]
    fn rsa_with_sha1_good() {
        self_signed_good("testdata/rsa2048-sha1-crt.pem");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn rsa_with_sha1_bad() {
        self_signed_bad("testdata/rsa2048-sha1-crt.pem");
    }

    #[cfg(all(feature = "sha1", feature = "x509"))]
    #[test]
    fn x509_rsa_with_sha1_good() {
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha1-crt.pem");
        x509_verify_good(&cert, &cert);
    }

    #[cfg(all(feature = "sha1", feature = "x509"))]
    #[test]
    fn x509_rsa_with_sha1_bad() {
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha1-crt.pem");
        x509_verify_bad(&cert, &cert);
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn rsa_with_sha256_good() {
        self_signed_good("testdata/rsa2048-sha256-crt.pem");
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn rsa_with_sha256_bad() {
        self_signed_bad("testdata/rsa2048-sha256-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_rsa_with_sha256_good() {
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha256-crt.pem");
        x509_verify_good(&cert, &cert);
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_rsa_with_sha256_bad() {
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha256-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "rsa"))]
#[test]
fn rsa_with_sha1_bad_oid1() {
    self_signed_bad_oid("testdata/rsa2048-sha1-crt.pem");
}

#[cfg(not(feature = "sha1"))]
#[test]
fn rsa_with_sha1_bad_oid2() {
    self_signed_bad_oid("testdata/rsa2048-sha1-crt.pem");
}

#[cfg(not(feature = "rsa"))]
#[test]
fn rsa_with_sha256_bad_oid1() {
    self_signed_bad_oid("testdata/rsa2048-sha256-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn rsa_with_sha256_bad_oid2() {
    self_signed_bad_oid("testdata/rsa2048-sha256-crt.pem");
}
