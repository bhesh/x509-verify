x509-verify [![](https://img.shields.io/crates/v/x509-verify.svg)](https://crates.io/crates/x509-verify) [![](https://docs.rs/x509-verify/badge.svg)](https://docs.rs/x509-verify) [![](https://github.com/bhesh/x509-verify/actions/workflows/x509-verify.yml/badge.svg?branch=master)](https://github.com/bhesh/x509-verify/actions/workflows/x509-verify.yml)
===========

A pure Rust, no standard library implementation of X.509 verification. Makes use of
[RustCrypto](https://github.com/RustCrypto) implementations of
[X.509 formats](https://github.com/RustCrypto/formats),
[DSA](https://github.com/RustCrypto/signatures/tree/master/dsa),
[RSA](https://github.com/RustCrypto/RSA), and
[ECDSA](https://github.com/RustCrypto/signatures/tree/master/ecdsa). And
[dalek](https://github.com/dalek-cryptography) 's version of
[Ed25519](https://github.com/dalek-cryptography/curve25519-dalek).

The goal of this crate is to provide a general means of verification for common X.509 algorithm identifiers.
It aims to abstract away some of the verification nuances of signatures within X.509 structures. Such as:

- Extracting the public key of a certificate and mapping it to the appropriate key container
- Extracting the raw message of the signature and running it through the appropriate digest algorithm
- Extracting the signature bytes and structuring them into the expected format required of the identified algorithm

This crate relies heavily on external implementations of the underlying algorithms. These algorithms will all be
included as optional features so the user can pick and choose whatever is relevant to their use-case.

## Security Warning

Some of the features of this crate are in an early, experimental phase. Use at your own risk.

## Currently supported

### DSA

- `DSA_WITH_SHA_1`
- `DSA_WITH_SHA_224`
- `DSA_WITH_SHA_256`

### EdDSA

- `ED25519`

### RSA

- `MD_2_WITH_RSA_ENCRYPTION`
- `MD_5_WITH_RSA_ENCRYPTION`
- `SHA_1_WITH_RSA_ENCRYPTION`
- `SHA_224_WITH_RSA_ENCRYPTION`
- `SHA_256_WITH_RSA_ENCRYPTION`
- `SHA_384_WITH_RSA_ENCRYPTION`
- `SHA_512_WITH_RSA_ENCRYPTION`

### ECDSA

- `ECDSA_WITH_SHA_224`
- `ECDSA_WITH_SHA_256`
- `ECDSA_WITH_SHA_384`
- `ECDSA_WITH_SHA_512`

### EC Curves

- [k256](https://github.com/RustCrypto/elliptic-curves/tree/master/k256)
- [p192](https://github.com/RustCrypto/elliptic-curves/tree/master/p192)
- [p224](https://github.com/RustCrypto/elliptic-curves/tree/master/p224)
- [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256)
- [p384](https://github.com/RustCrypto/elliptic-curves/tree/master/p384)
- [p521](https://github.com/RustCrypto/elliptic-curves/tree/master/p521)

## Verification

```rust
#[cfg(all(feature = "rsa", feature = "sha2"))]
{
    use der::{DecodePem, Encode};
    use std::fs;
    use x509_cert::Certificate;
    use x509_verify::{Signature, VerifyInfo, VerifyingKey};

    // Self-signed certificate
    let cert = fs::read_to_string("testdata/rsa2048-sha256-crt.pem").unwrap();
    let cert = Certificate::from_pem(&cert).unwrap();

    let verify_info = VerifyInfo::new(
        cert.tbs_certificate
            .to_der()
            .unwrap()
            .into(),
        Signature::new(
            &cert.signature_algorithm,
            cert.signature
                .as_bytes()
                .unwrap(),
        ),
    );

    let key: VerifyingKey = cert
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .unwrap();

    // Keeps ownership
    key.verify(&verify_info).unwrap();

    // Throws away ownership
    key.verify(verify_info).unwrap();
}
```

## x509 feature

```rust
#[cfg(all(feature = "rsa", feature = "sha2", feature = "x509", feature = "pem"))]
{
    use der::{Decode, DecodePem, Encode};
    use std::{io::Read, fs};
    use x509_verify::{
        x509_cert::{crl::CertificateList, Certificate},
        x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus},
        VerifyingKey,
    };

    // CA-signed certificate

    let ca = fs::read_to_string("testdata/digicert-ca.pem").unwrap();
    let ca = Certificate::from_pem(&ca).unwrap();

    let cert = fs::read_to_string("testdata/amazon-crt.pem").unwrap();
    let cert = Certificate::from_pem(&cert).unwrap();

    let key = VerifyingKey::try_from(&ca).unwrap();
    key.verify(&cert).unwrap();

    // CA-signed CRL

    let ca = fs::read_to_string("testdata/GoodCACert.pem").unwrap();
    let ca = Certificate::from_pem(&ca).unwrap();

    let crl = fs::read("testdata/GoodCACRL.crl").unwrap();
    let crl = CertificateList::from_der(&crl).unwrap();

    let key = VerifyingKey::try_from(&ca).unwrap();
    key.verify(&crl).unwrap();

    // CA-signed OCSP response

    let ca = fs::read_to_string("testdata/digicert-ca.pem").unwrap();
    let ca = Certificate::from_pem(&ca).unwrap();

    let res = fs::read("testdata/ocsp-amazon-resp.der").unwrap();
    let res = OcspResponse::from_der(&res).unwrap();
    assert_eq!(res.response_status, OcspResponseStatus::Successful);
    let res = BasicOcspResponse::from_der(
        res.response_bytes
            .unwrap()
            .response
            .as_bytes(),
    )
    .unwrap();

    let key = VerifyingKey::try_from(&ca).unwrap();
    key.verify(&res).unwrap();
}
```

## Optional features

| **feature** | **default** | **description** |
|-------------|:-----------:|-----------------|
| md2 | | MD-2 digests |
| md5 | | MD-5 digests |
| sha1 | | SHA-1 digests |
| sha2 | ✔️ | SHA-2 digests |
| dsa | | DSA signatures |
| rsa | ✔️ | RSA signatures |
| k256 | ✔️ | secp256k1 ECDSA signatures |
| p192 | | secp192r1 ECDSA signatures |
| p224 | | secp224r1 ECDSA signatures |
| p256 | ✔️ | secp256r1 ECDSA signatures |
| p384 | ✔️ | secp384r1 ECDSA signatures |
| p521 | ✔️ | secp521r1 ECDSA signatures |
| ecdsa | | k256, p192, p224, p256, p384, and p521 |
| ed25519 | ✔️ | Ed25519 signatures |
| x509 | | enables X.509 structure conversion |
| pem | | adds the `DecodePem` trait to X.509 reimports |
| std | | |

## License

At your discretion:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)
