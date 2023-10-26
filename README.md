x509-verify
===========

A pure Rust implementation of X.509 verification. Makes use of [RustCrypto](https://github.com/RustCrypto)
library implementations of [X.509 formats](https://github.com/RustCrypto/formats),
[DSA](https://github.com/RustCrypto/signatures/tree/master/dsa), [RSA](https://github.com/RustCrypto/RSA),
and [ECDSA](https://github.com/RustCrypto/signatures/tree/master/ecdsa).

## Currently supported

### DSA

- `DSA_WITH_SHA_1` (features: `dsa`, `sha1`)
- `DSA_WITH_SHA_224` (feature: `dsa`)
- `DSA_WITH_SHA_256` (feature: `dsa`)

### RSA

- `MD_2_WITH_RSA_ENCRYPTION` (feature: `md2`)
- `MD_5_WITH_RSA_ENCRYPTION` (feature: `md5`)
- `SHA_1_WITH_RSA_ENCRYPTION` (feature: `sha1`)
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
- [p192](https://github.com/RustCrypto/elliptic-curves/tree/master/p192) (feature: `p192`)
- [p224](https://github.com/RustCrypto/elliptic-curves/tree/master/p224) (feature: `p224`)
- [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256)
- [p384](https://github.com/RustCrypto/elliptic-curves/tree/master/p384)

## Verification

```rust
#[cfg(all(feature = "rsa", feature = "sha2"))]
{
    use der::{DecodePem, Encode};
    use std::fs;
    use x509_cert::Certificate;
    use x509_verify::{X509Message, X509Signature, X509VerifyKey};

    // Self-signed certificate
    let pem = fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error reading file");
    let cert = Certificate::from_pem(&pem).expect("error formatting signing cert");

    let msg = cert.tbs_certificate
        .to_der()
        .expect("error encoding message");
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
    key.verify(&msg, &sig).expect("error verifying");
}
```

## x509 feature

```rust
#[cfg(all(feature = "rsa", feature = "sha2", feature = "x509"))]
{
    use der::{Decode, DecodePem, Encode};
    use std::{io::Read, fs};
    use x509_verify::{
        x509_cert::{crl::CertificateList, Certificate},
        x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus},
        X509Message, X509Signature, X509VerifyKey,
    };

    // CA-signed certificate
    let pem = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading file");
    let ca = Certificate::from_pem(&pem).expect("error decoding signing cert");
    let pem = fs::read_to_string("testdata/amazon-crt.pem").expect("error reading file");
    let cert = Certificate::from_pem(&pem).expect("error decoding signing cert");

    // Verify
    let key = X509VerifyKey::try_from(&ca).expect("error making key");
    key.verify(&cert, &cert).expect("error verifying");

    // CA-signed CRL
    let mut f = fs::File::open("testdata/GoodCACRL.crl").expect("error opening file");
    let mut data = Vec::new();
    f.read_to_end(&mut data).expect("error reading file");
    let crl = CertificateList::from_der(&data).expect("error decoding CRL");
    let pem = fs::read_to_string("testdata/GoodCACert.pem").expect("error reading file");
    let ca = Certificate::from_pem(&pem).expect("error decoding signing cert");

    // Verify
    let key = X509VerifyKey::try_from(&ca).expect("error making key");
    key.verify(&crl, &crl).expect("error verifying");

    // CA-signed OCSP response
    let mut f = fs::File::open("testdata/ocsp-amazon-resp.der").expect("error opening file");
    let mut data = Vec::new();
    f.read_to_end(&mut data).expect("error reading file");
    let res = OcspResponse::from_der(&data).expect("error decoding OcspRequest");
    assert_eq!(res.response_status, OcspResponseStatus::Successful);
    let res = BasicOcspResponse::from_der(
        res.response_bytes
            .expect("no response data")
            .response
            .as_bytes(),
    )
    .expect("error decoding BasicOcspResponse");
    let pem = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading file");
    let ca = Certificate::from_pem(&pem).expect("error decoding signing cert");

    // Verify
    let key = X509VerifyKey::try_from(&ca).expect("error making key");
    key.verify(&res, &res).expect("error verifying");
}
```

## Optional features

- default: sha2, rsa, k256, p256, p384
- md2
- md5
- sha1
- sha2
- dsa
- rsa
- ecc: k256, p192, p224, p256, p384
- k256
- p192
- p224
- p256
- p384
- x509
- all: md2, md5, sha1, sha2, dsa, rsa, ecc, x509

## License

Per [RustCrypto](https://github.com/RustCrypto/formats), licensed under:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

