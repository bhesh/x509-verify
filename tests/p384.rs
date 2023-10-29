#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "p384")]
mod p384_tests {
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha2")]
    #[test]
    fn p384_with_sha384_good() {
        self_signed_good("testdata/secp384r1-sha384-crt.pem");
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn p384_with_sha384_bad() {
        self_signed_bad("testdata/secp384r1-sha384-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p384_with_sha384_good() {
        let cert = read_pem!(Certificate, "testdata/secp384r1-sha384-crt.pem");
        x509_verify_good(&cert, &cert);
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p384_with_sha384_bad() {
        let cert = read_pem!(Certificate, "testdata/secp384r1-sha384-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "p384"))]
#[test]
fn p384_with_sha384_bad_oid1() {
    self_signed_bad_oid("testdata/secp384r1-sha384-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn p384_with_sha384_bad_oid2() {
    self_signed_bad_oid("testdata/secp384r1-sha384-crt.pem");
}
