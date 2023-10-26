#[allow(unused_imports)]
mod helpers;
#[allow(unused_imports)]
use helpers::*;

#[cfg(feature = "p224")]
mod p224_tests {
    #[allow(unused_imports)]
    use crate::{helpers::*, *};

    #[cfg(feature = "x509")]
    use der::DecodePem;

    #[cfg(feature = "x509")]
    use x509_cert::Certificate;

    #[cfg(feature = "sha2")]
    #[test]
    fn p224_with_sha224_good() {
        self_signed_good("testdata/secp224r1-sha224-crt.pem");
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn p224_with_sha224_bad() {
        self_signed_bad("testdata/secp224r1-sha224-crt.pem");
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p224_with_sha224_good() {
        let cert = read_pem!(Certificate, "testdata/secp224r1-sha224-crt.pem");
        x509_verify_good(&cert, &cert, &cert);
    }

    #[cfg(all(feature = "sha2", feature = "x509"))]
    #[test]
    fn x509_p224_with_sha224_bad() {
        let cert = read_pem!(Certificate, "testdata/secp224r1-sha224-crt.pem");
        x509_verify_bad(&cert, &cert);
    }
}

#[cfg(not(feature = "p224"))]
#[test]
fn p224_with_sha224_bad_oid1() {
    self_signed_bad_oid("testdata/secp224r1-sha224-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn p224_with_sha224_bad_oid2() {
    self_signed_bad_oid("testdata/secp224r1-sha224-crt.pem");
}
