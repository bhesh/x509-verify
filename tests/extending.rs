#![allow(unused_imports)]
mod helpers;

#[cfg(all(feature = "rsa", feature = "sha2"))]
mod extending_tests {
    use crate::{helpers::*, *};
    use der::{DecodePem, Encode};
    use x509_cert::Certificate;
    use x509_verify::{Error, Message, SignatureRef, VerifyInfo, VerifyingKey};

    #[derive(Debug)]
    struct NewError;

    impl Into<Error> for NewError {
        fn into(self) -> Error {
            Error::InvalidSignature
        }
    }

    struct NewType<'a, 'b> {
        pub message: Vec<u8>,
        pub signature: SignatureRef<'a, 'b>,
    }

    impl<'a, 'b> TryInto<VerifyInfo<'a, Vec<u8>, &'b [u8]>> for NewType<'a, 'b> {
        type Error = NewError;

        fn try_into(self) -> Result<VerifyInfo<'a, Vec<u8>, &'b [u8]>, Self::Error> {
            Ok(VerifyInfo::new(Message::new(self.message), self.signature))
        }
    }

    #[test]
    fn extending_verify_info() {
        let cert = read_pem!(Certificate, "testdata/rsa2048-sha256-crt.pem");
        let new_type = NewType {
            message: cert.tbs_certificate.to_der().unwrap(),
            signature: SignatureRef::new(
                &cert.signature_algorithm,
                cert.signature
                    .as_bytes()
                    .expect("signature is not octet-aligned"),
            ),
        };
        let key: VerifyingKey = cert
            .tbs_certificate
            .subject_public_key_info
            .try_into()
            .unwrap();
        key.verify(new_type).expect("verification failed");
    }
}
