use der::{referenced::OwnedToRef, DecodePem, Encode};
use std::{fmt::Debug, fs};
use x509_cert::Certificate;
use x509_verify::{Error, X509Message, X509Signature, X509VerifyKey};

macro_rules! read_pem {
    ($into:ty, $file:tt) => {
        <$into>::from_pem(&fs::read_to_string($file).expect("error reading file"))
            .expect("error formatting der")
    };
}

#[allow(dead_code)]
fn verify_good(key: &X509VerifyKey, msg: &X509Message, signature: &X509Signature) {
    key.verify(msg, signature).expect("error verifying");
}

#[allow(dead_code)]
fn verify_bad(key: &X509VerifyKey, msg: &X509Message, signature: &X509Signature) {
    match key.verify(msg, signature) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[allow(dead_code)]
fn verify_bad_oid(cert: &Certificate, msg: &X509Message, signature: &X509Signature) {
    match X509VerifyKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref()) {
        Ok(v) => match v.verify(msg, signature) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::UnknownOid(_)) => {}
            Err(e) => panic!("{:?}", e),
        },
        Err(Error::UnknownOid(_)) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[allow(dead_code)]
fn self_signed_good(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let msg = X509Message::new(
        cert.tbs_certificate
            .to_der()
            .expect("error encoding message"),
    );
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    let key: X509VerifyKey = cert
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .expect("error making key");
    verify_good(&key, &msg.into(), &sig);
}

#[allow(dead_code)]
fn self_signed_bad(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    let key: X509VerifyKey = cert
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .expect("error making key");
    verify_bad(&key, &"Bad message".as_bytes().into(), &sig);
}

#[allow(dead_code)]
fn self_signed_bad_oid(filename: &str) {
    let cert = read_pem!(Certificate, filename);
    let sig = X509Signature::new(
        &cert.signature_algorithm,
        cert.signature
            .as_bytes()
            .expect("signature is not octet-aligned"),
    );
    verify_bad_oid(&cert, &"".as_bytes().into(), &sig);
}

#[allow(dead_code)]
fn x509_verify_good<'a, K, M, S>(key: K, msg: M, signature: S)
where
    K: TryInto<X509VerifyKey>,
    K::Error: Debug,
    M: TryInto<X509Message>,
    M::Error: Debug,
    S: TryInto<X509Signature<'a, 'a>>,
    S::Error: Debug,
{
    let key: X509VerifyKey = key.try_into().expect("error making key");
    key.x509_verify(msg, signature).expect("error verifying");
}

#[allow(dead_code)]
fn x509_verify_bad<'a, K, M, S>(key: K, msg: M, signature: S)
where
    K: TryInto<X509VerifyKey>,
    K::Error: Debug,
    M: TryInto<X509Message>,
    M::Error: Debug,
    S: TryInto<X509Signature<'a, 'a>>,
    S::Error: Debug,
{
    let key: X509VerifyKey = key.try_into().expect("error making key");
    match key.x509_verify(msg, signature) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[cfg(all(feature = "dsa", feature = "sha1"))]
#[test]
fn dsa_with_sha1_good() {
    self_signed_good("testdata/dsa1024-sha1-crt.pem");
}

#[cfg(all(feature = "dsa", feature = "sha1"))]
#[test]
fn dsa_with_sha1_bad() {
    self_signed_bad("testdata/dsa1024-sha1-crt.pem");
}

#[cfg(all(feature = "dsa", feature = "sha1", feature = "x509"))]
#[test]
fn x509_dsa_with_sha1_good() {
    let cert = read_pem!(Certificate, "testdata/dsa1024-sha1-crt.pem");
    x509_verify_good(&cert, &cert, &cert);
}

#[cfg(all(feature = "dsa", feature = "sha1", feature = "x509"))]
#[test]
fn x509_dsa_with_sha1_bad() {
    self_signed_bad("testdata/dsa1024-sha1-crt.pem");
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

#[cfg(all(feature = "rsa", feature = "sha1"))]
#[test]
fn rsa_with_sha1_good() {
    self_signed_good("testdata/rsa2048-sha1-crt.pem");
}

#[cfg(all(feature = "rsa", feature = "sha1"))]
#[test]
fn rsa_with_sha1_bad() {
    self_signed_bad("testdata/rsa2048-sha1-crt.pem");
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

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn rsa_with_sha256_good() {
    self_signed_good("testdata/rsa2048-sha256-crt.pem");
}

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn rsa_with_sha256_bad() {
    self_signed_bad("testdata/rsa2048-sha256-crt.pem");
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

#[cfg(all(feature = "k256", feature = "sha2"))]
#[test]
fn k256_with_sha256_good() {
    self_signed_good("testdata/secp256k1-sha256-crt.pem");
}

#[cfg(all(feature = "k256", feature = "sha2"))]
#[test]
fn k256_with_sha256_bad() {
    self_signed_bad("testdata/secp256k1-sha256-crt.pem");
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

#[cfg(all(feature = "p192", feature = "sha2"))]
#[test]
fn p192_with_sha224_good() {
    self_signed_good("testdata/secp192r1-sha224-crt.pem");
}

#[cfg(all(feature = "p192", feature = "sha2"))]
#[test]
fn p192_with_sha224_bad() {
    self_signed_bad("testdata/secp192r1-sha224-crt.pem");
}

#[cfg(not(feature = "p192"))]
#[test]
fn p192_with_sha224_bad_oid1() {
    self_signed_bad_oid("testdata/secp192r1-sha224-crt.pem");
}

#[cfg(not(feature = "sha2"))]
#[test]
fn p192_with_sha224_bad_oid2() {
    self_signed_bad_oid("testdata/secp192r1-sha224-crt.pem");
}

#[cfg(all(feature = "p224", feature = "sha2"))]
#[test]
fn p224_with_sha224_good() {
    self_signed_good("testdata/secp224r1-sha224-crt.pem");
}

#[cfg(all(feature = "p224", feature = "sha2"))]
#[test]
fn p224_with_sha224_bad() {
    self_signed_bad("testdata/secp224r1-sha224-crt.pem");
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

#[cfg(all(feature = "p256", feature = "sha2"))]
#[test]
fn p256_with_sha256_good() {
    self_signed_good("testdata/prime256v1-sha256-crt.pem");
}

#[cfg(all(feature = "p256", feature = "sha2"))]
#[test]
fn p256_with_sha256_bad() {
    self_signed_bad("testdata/prime256v1-sha256-crt.pem");
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

#[cfg(all(feature = "p384", feature = "sha2"))]
#[test]
fn p384_with_sha384_good() {
    self_signed_good("testdata/secp384r1-sha384-crt.pem");
}

#[cfg(all(feature = "p384", feature = "sha2"))]
#[test]
fn p384_with_sha384_bad() {
    self_signed_bad("testdata/secp384r1-sha384-crt.pem");
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
