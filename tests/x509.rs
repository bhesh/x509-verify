#![allow(unused_imports)]
mod helpers;

#[cfg(feature = "x509")]
mod x509_tests {
    use crate::{helpers::*, *};
    use der::{Decode, DecodePem};
    use std::io::Read;
    use x509_cert::{crl::CertificateList, request::CertReq, Certificate};
    use x509_ocsp::{BasicOcspResponse, OcspResponse};

    #[cfg(all(feature = "rsa", feature = "sha1"))]
    #[test]
    fn x509_rsa_sha1_req_verify_good() {
        let req = read_pem!(CertReq, "testdata/rsa2048-sha1-req.pem");
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha1-crt.pem");
        x509_verify_good(&cert, &req);
    }

    #[cfg(all(feature = "rsa", feature = "sha1"))]
    #[test]
    fn x509_rsa_sha1_req_verify_bad() {
        let req = read_pem!(CertReq, "testdata/rsa2048-sha1-req.pem");
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha1-crt.pem");
        x509_verify_bad(&cert, &req);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_rsa_sha256_req_verify_good() {
        let req = read_pem!(CertReq, "testdata/rsa2048-sha256-req.pem");
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha256-crt.pem");
        x509_verify_good(&cert, &req);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_rsa_sha256_req_verify_bad() {
        let req = read_pem!(CertReq, "testdata/rsa2048-sha256-req.pem");
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha256-crt.pem");
        x509_verify_bad(&cert, &req);
    }

    #[cfg(all(feature = "dsa", feature = "sha1"))]
    #[test]
    fn x509_dsa_sha1_req_verify_good() {
        let req = read_pem!(CertReq, "testdata/dsa1024-sha1-req.pem");
        let cert = read_pem!(Certificate, "testdata/dsa1024-sha1-crt.pem");
        x509_verify_good(&cert, &req);
    }

    #[cfg(all(feature = "dsa", feature = "sha1"))]
    #[test]
    fn x509_dsa_sha1_req_verify_bad() {
        let req = read_pem!(CertReq, "testdata/dsa1024-sha1-req.pem");
        let cert = read_pem!(Certificate, "testdata/dsa1024-sha1-crt.pem");
        x509_verify_bad(&cert, &req);
    }

    #[cfg(all(feature = "p384", feature = "sha2"))]
    #[test]
    fn x509_p384_sha384_req_verify_good() {
        let req = read_pem!(CertReq, "testdata/secp384r1-sha384-req.pem");
        let cert = read_pem!(Certificate, "testdata/secp384r1-sha384-crt.pem");
        x509_verify_good(&cert, &req);
    }

    #[cfg(all(feature = "p384", feature = "sha2"))]
    #[test]
    fn x509_p384_sha384_req_verify_bad() {
        let req = read_pem!(CertReq, "testdata/secp384r1-sha384-req.pem");
        let cert = read_pem!(Certificate, "testdata/secp384r1-sha384-crt.pem");
        x509_verify_bad(&cert, &req);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_cert_verify_good() {
        let issuer = read_pem!(Certificate, "testdata/digicert-ca.pem");
        let cert = read_pem!(Certificate, "testdata/amazon-crt.pem");
        x509_verify_good(&issuer, &cert);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_cert_verify_bad() {
        let issuer = read_pem!(Certificate, "testdata/digicert-ca.pem");
        let cert = read_pem!(Certificate, "testdata/amazon-crt.pem");
        x509_verify_bad(&issuer, &cert);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_crl_verify_good() {
        let crl = read_der!(CertificateList, "testdata/GoodCACRL.crl");
        let ca = read_pem!(Certificate, "testdata/GoodCACert.pem");
        x509_verify_good(&ca, &crl);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_crl_verify_bad() {
        let crl = read_der!(CertificateList, "testdata/GoodCACRL.crl");
        let ca = read_pem!(Certificate, "testdata/GoodCACert.pem");
        x509_verify_bad(&ca, &crl);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_ocsp_resp_verify_good() {
        let res = read_der!(OcspResponse, "testdata/ocsp-amazon-resp.der");
        let res = BasicOcspResponse::from_der(
            res.response_bytes
                .expect("no response data")
                .response
                .as_bytes(),
        )
        .expect("error decoding BasicOcspResponse");
        let ca = read_pem!(Certificate, "testdata/digicert-ca.pem");
        x509_verify_good(&ca, &res);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn x509_ocsp_resp_verify_bad() {
        let res = read_der!(OcspResponse, "testdata/ocsp-amazon-resp.der");
        let res = BasicOcspResponse::from_der(
            res.response_bytes
                .expect("no response data")
                .response
                .as_bytes(),
        )
        .expect("error decoding BasicOcspResponse");
        let ca = read_pem!(Certificate, "testdata/digicert-ca.pem");
        x509_verify_bad(&ca, &res);
    }
}
