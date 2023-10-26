#[allow(unused_imports)]
mod helpers;
#[allow(unused_imports)]
use helpers::*;

#[cfg(feature = "p256")]
mod p256_tests {
    #[allow(unused_imports)]
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha2")]
    #[test]
    fn p256_with_sha256_good() {
        self_signed_good("testdata/prime256v1-sha256-crt.pem");
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn p256_with_sha256_bad() {
        self_signed_bad("testdata/prime256v1-sha256-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p256_with_sha256_good() {
        let cert = read_pem!(Certificate, "testdata/prime256v1-sha256-crt.pem");
        x509_verify_good(&cert, &cert, &cert);
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p256_with_sha256_bad() {
        let cert = read_pem!(Certificate, "testdata/prime256v1-sha256-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "p256"))]
#[test]
fn p256_with_sha256_bad_oid1() {
    self_signed_bad_oid("testdata/prime256v1-sha256-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn p256_with_sha256_bad_oid2() {
    self_signed_bad_oid("testdata/prime256v1-sha256-crt.pem");
}
