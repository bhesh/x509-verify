x509-verify
===========

A pure rust implementation of X.509 verification. Makes use of [RustCrypto](https://github.com/RustCrypto/formats)
library implementations of X.509 formats, DSA, RSA, and ECDSA.

## Verification

```rust
use der::{DecodePem, Encode};
use std::fs;
use x509_cert::Certificate;
use x509_verify::{X509Signature, X509Verifier};

// Self-signed certificate
let pem = fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error opening file");
let cert = Certificate::from_pem(&pem).expect("error formatting signing cert");

let msg = cert
    .tbs_certificate
    .to_der()
    .expect("error encoding message");
let sig = X509Signature::new(
    cert.signature_algorithm,
    cert.signature
        .as_bytes()
        .expect("signature is not octet-aligned"),
);

let verifier: X509Verifier = cert
    .tbs_certificate
    .subject_public_key_info
    .try_into()
    .expect("error making key");

verifier.verify(&msg, &sig).expect("error verifying");
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
- all: md2, md5, sha1, sha2, dsa, rsa, ecc

## License

Per [RustCrypto](https://github.com/RustCrypto/formats), licensed under:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

