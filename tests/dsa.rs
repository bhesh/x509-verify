#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "dsa")]
mod dsa_tests {
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha1")]
    #[test]
    fn dsa_with_sha1_good() {
        self_signed_good("testdata/dsa1024-sha1-crt.pem");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn dsa_with_sha1_bad() {
        self_signed_bad("testdata/dsa1024-sha1-crt.pem");
    }

    #[cfg(all(feature = "sha1", feature = "x509"))]
    #[test]
    fn x509_dsa_with_sha1_good() {
        let cert = read_pem!(Certificate, "testdata/dsa1024-sha1-crt.pem");
        x509_verify_good(&cert, &cert);
    }

    #[cfg(all(feature = "sha1", feature = "x509"))]
    #[test]
    fn x509_dsa_with_sha1_bad() {
        let cert = read_pem!(Certificate, "testdata/dsa1024-sha1-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "dsa"))]
#[test]
fn dsa_with_sha1_bad_oid1() {
    self_signed_bad_oid("testdata/dsa1024-sha1-crt.pem");
}

#[cfg(not(feature = "sha1"))]
#[test]
fn dsa_with_sha1_bad_oid2() {
    self_signed_bad_oid("testdata/dsa1024-sha1-crt.pem");
}
