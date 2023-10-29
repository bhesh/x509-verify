#![allow(unused_imports)]
mod helpers;
use helpers::*;

#[cfg(feature = "ed25519")]
mod ed25519_tests {
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha2")]
    #[test]
    fn ed25519_with_sha512_good() {
        self_signed_good("testdata/ed25519-sha512-crt.pem");
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn ed25519_with_sha512_bad() {
        self_signed_bad("testdata/ed25519-sha512-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_ed25519_with_sha512_good() {
        let cert = read_pem!(Certificate, "testdata/ed25519-sha512-crt.pem");
        x509_verify_good(&cert, &cert);
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_ed25519_with_sha512_bad() {
        let cert = read_pem!(Certificate, "testdata/ed25519-sha512-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "ed25519"))]
#[test]
fn ed25519_with_sha512_bad_oid1() {
    self_signed_bad_oid("testdata/ed25519-sha512-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn ed25519_with_sha512_bad_oid2() {
    self_signed_bad_oid("testdata/ed25519-sha512-crt.pem");
}
