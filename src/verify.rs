//! Generic X.509 Verifier

use crate::{error::Error, X509Signature};
use alloc::boxed::Box;
use const_oid::AssociatedOid;
use core::result::Result;
use der::referenced::OwnedToRef;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

#[cfg(feature = "dsa")]
mod dsa;

#[cfg(feature = "rsa")]
mod rsa;

#[cfg(any(
    feature = "k256",
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384"
))]
mod ecdsa;

pub trait OidVerifier {
    fn verify(&self, msg: &[u8], signature: &X509Signature<'_>) -> Result<(), Error>;
}

pub struct X509Verifier {
    inner: Box<dyn OidVerifier>,
}

impl X509Verifier {
    pub fn new(key_info: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Error> {
        match &key_info.algorithm.oid {
            #[cfg(feature = "dsa")]
            &self::dsa::X509DsaVerifier::OID => Ok(Self {
                inner: Box::from(self::dsa::X509DsaVerifier::try_from(key_info)?),
            }),

            #[cfg(feature = "rsa")]
            &self::rsa::X509RsaVerifier::OID => Ok(Self {
                inner: Box::from(self::rsa::X509RsaVerifier::try_from(key_info)?),
            }),

            #[cfg(any(
                feature = "k256",
                feature = "p192",
                feature = "p224",
                feature = "p256",
                feature = "p384"
            ))]
            &self::ecdsa::X509EcdsaVerifier::OID => Ok(Self {
                inner: Box::from(self::ecdsa::X509EcdsaVerifier::try_from(key_info)?),
            }),

            oid => Err(Error::UnknownOid(oid.clone())),
        }
    }

    pub fn verify(&self, msg: &[u8], signature: &X509Signature<'_>) -> Result<(), Error> {
        self.inner.verify(msg, signature)
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for X509Verifier {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        Self::new(other)
    }
}

impl TryFrom<SubjectPublicKeyInfoOwned> for X509Verifier {
    type Error = Error;

    fn try_from(other: SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
        Self::new(other.owned_to_ref())
    }
}

#[cfg(test)]
mod tests {

    use crate::{error::Error, X509Signature, X509Verifier};
    use der::{DecodePem, Encode};
    use x509_cert::Certificate;

    #[allow(dead_code)]
    const PUBLIC_DSA_WITH_SHA1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC3zCCAo+gAwIBAgIUW5QcM75NT1tlmWNHto6ripqNLfQwCQYHKoZIzjgEAzAX
MRUwEwYDVQQDDAxkc2ExMDI0LXNoYTEwHhcNMjMxMDIzMjM1NTU0WhcNMjYxMDIy
MjM1NTU0WjAXMRUwEwYDVQQDDAxkc2ExMDI0LXNoYTEwggG+MIIBMwYHKoZIzjgE
ATCCASYCgYEApj9FbCbGtUJmmPItS1pb/d7YlOF/03+sYoW6LP1GijQNkCFd/oJd
eE/p6edmVq+SVo0wxp95ciT0YOFvQIrBtxzTEReysBNPHlcKRAq7LjL4kp5qQ7uC
NrJEQ2XGOXN49A/AyGgdYIpjDv+F40X6U2wWsuSwXfI7x3GtEc8/u1cCHQCEcpAa
kdpHwCygwJbswxIUV3/S16Bo5InpND97AoGAY6mXOI9wYst/ptZo0NtJCdTRz/0d
EQ67TRITn8pXco0F8q1ZMCu/SvZOb/EHlIphQJsbIe/rxQVQCWGKtEoVAXlJYo9c
k/OQ3utGKV+S/ZI3ZANXVoK60eFbgGdRoSPNY6V5lguGAJlhI7Bm04u03wYwZpoI
Vldfo/tQOWRXmn4DgYQAAoGAGeTWi4hw30/o0rhb3RKaBDFVnvVVOrX3YJibJ501
Wph5wTJwsVHR+/uvysp//C7cMVEMvpahwTCOWRrAUOv1kiAVn/LqkHeJBhYFwXiK
wy0R26eBzAUT1b46vTLfdpcSh4cPlRNKZEQ0uDFwldsEd9q/dOWya6qEFC4VuNlJ
5f+jUzBRMB0GA1UdDgQWBBRhaS16sliQ2KwwNDUZdX4uLnd3bzAfBgNVHSMEGDAW
gBRhaS16sliQ2KwwNDUZdX4uLnd3bzAPBgNVHRMBAf8EBTADAQH/MAkGByqGSM44
BAMDPwAwPAIcIpYMZ+03auXzGAJcxlErcDDjbSePciuEYvYKOQIcPk+qP0houutW
X2U0Br/jMKcV2v1gQrmceaYw8g==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_RSA_WITH_SHA1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUDgYvXt2fxvm0dZ2mpo2dKso/N9kwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMB4XDTIzMTAyMzIzNTU1NFoXDTI2
MTAyMjIzNTU1NFowFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0bcwH3hqpWkDJ//DpLFb4lx+WmgaD4A40Olh
OuzqTxhJYbSJExCEB6S55gaTISxiW9PeSpkSoJDRlHaRC4PGiq+rdwoO7zdN6NlJ
n8BKGTvSQR/4+ABNaVLTn9kxofa6Jcxer6LV1ewA5+RsO9cP4Ozn8fviPkYwyuXB
TgVSOCt93E7vJ/4V+iaZAV0ao5NxwPes1IbHMLApQZEjugWchzRQxPohahOpyrEe
O76Wm1bJJoWEgYF8J+5N2g+RIr+2uKnZP5moc8lhKbcyVJyjBMz/Ss+Z3x+3JOAT
5RFs3K/USeQVcVit9g40qeXuIQILrfQuePIzPpoLYPYAHiqAOQIDAQABo1MwUTAd
BgNVHQ4EFgQUOCiaqJOsbief6oBOl34xwd3Z8aMwHwYDVR0jBBgwFoAUOCiaqJOs
bief6oBOl34xwd3Z8aMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC
AQEAeLxlmFpB4K921osjJR5ABd+nUGDwH+612kEO8nd0xiV7WDj+rVDa5QD15GuH
Mq/FV6BqS+c+/XIxESgnDb2H8HQCVyglA7UkZIoNeiXsYdiBLKWsWI3gPEtr85dU
b6IhFg9Vk/1gPLQ1v6DZ7ci6ep6Kt/7O1pMrtQZ7RGMesh5yrWrvn07T3G7xhq/N
bSrXO/OdtSEsvslext9w1vZlDM8X6tGc8rto/oxjBBNz3hz3aoi/pDztTuOFOpcV
7EsxvIVzelY8oVk734jJHs2HVi9Rv3h1RcRMCP6H3sD0bD8Zf4Fe/jo7eDuTVPB6
t6J21yhJIFoII5wpZnQnR/gNDw==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_RSA_WITH_SHA256_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUV34hXTRkPVGDECxGfAtUxv0mGEgwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOcnNhMjA0OC1zaGEyNTYwHhcNMjMxMDIzMjM1NTU0WhcN
MjYxMDIyMjM1NTU0WjAZMRcwFQYDVQQDDA5yc2EyMDQ4LXNoYTI1NjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAIh6/32L7lnScThXsxnub+ATmL4HRxIl
ad//hlwerxLzXpYKvik8tIMb3gYiy83sU1PNXdCVegoMxi4+Di0deV9CX1VAUFeG
SAZRp5Ib5ZtsfgoyuqEHc4U/WzX6V5XdxJfwP6spI/rUsjBEY2g+ltRWWXQGSr/v
iOiNKwhx1rrXIsqCaFb39zIGYlyi/bpQwwmfkXgIEhkezbDdPWyqRT9XstWElOaV
clxMFoPLmWfPeQJF250c6GxAIZKN5B+qVvGC/THy928+RGZpsriOf0Izkdd2iiF/
kkmcmRAe9TFdEOPgLOHdjhyCC2rVjX65vQkRUeWn+mke1MrtZKePsY8CAwEAAaNT
MFEwHQYDVR0OBBYEFBkcFiSUOy5O4PnQ3lB87P1Uo16jMB8GA1UdIwQYMBaAFBkc
FiSUOy5O4PnQ3lB87P1Uo16jMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBADJS5s5PecrU3X78vDjG4QuKpBPwku2T/FwbXKKfyqkvJk57QsSNQAgg
AifxRlesSb2EUzGq3J1ASbZ/5ugbb4kBTw8vWjXDy0KRThiDdRKAwBIUwUSvy0lz
r/C/dbewwravsHR/CQ75s5x1vXWPM+N3MxZXxXDQgHTjbfdOQBR8X8jB58JcdaTq
5aPU44orbGkdBMkrFKehjYgF7aplARv/DPP/TKkgj32nf4dEHSo8rHOKFu54PSo9
a78XBsuMSK19ruWu+0EPF28s7nym58cRRWGvfPSQlVwXPnW93DzEvSY/vYLZGoO3
+dI7qJxzRjGT/2nqT2bnYmp21GQ8n0A=
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_K256_WITH_SHA256_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS6gAwIBAgIUNaJNxCBlhK0x+rh2fp+Fop3Zb2kwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQc2VjcDI1NmsxLXNoYTI1NjAeFw0yMzEwMjMyMzU1NTVaFw0y
NjEwMjIyMzU1NTVaMBsxGTAXBgNVBAMMEHNlY3AyNTZrMS1zaGEyNTYwVjAQBgcq
hkjOPQIBBgUrgQQACgNCAAS8cvVDW8lH87eRMtq3lGFZsovlGQaJYM+xAwDHEkd2
2Yq1y3Ain5nhScPGlcMB1gS60V6E7h7Qq7uMW46Xgv2wo1MwUTAdBgNVHQ4EFgQU
Q5hTAlql2smm4GAurVD/sPANumQwHwYDVR0jBBgwFoAUQ5hTAlql2smm4GAurVD/
sPANumQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBA+8W2WOcJ
r9sH4h1I/fV50o3U7PzqixRfw5Cgjrv4FwIgKQQ++WJQH741nKpacR24ASJKsqdA
El6yNJKlH092eyw=
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_P192_WITH_SHA224_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBazCCASGgAwIBAgIUM6tSp2g4oihE5sVyf4acIlxERzQwCgYIKoZIzj0EAwEw
GzEZMBcGA1UEAwwQc2VjcDE5MnIxLXNoYTIyNDAeFw0yMzEwMjMyMzU1NTVaFw0y
NjEwMjIyMzU1NTVaMBsxGTAXBgNVBAMMEHNlY3AxOTJyMS1zaGEyMjQwSTATBgcq
hkjOPQIBBggqhkjOPQMBAQMyAATSf20qxObw85wz7aqRXCwr+V9lzngYzOkljfoQ
M63519mfSSAwHK6GjaAkEMFh9T2jUzBRMB0GA1UdDgQWBBSz3F5dRzXwuzPER2Ar
6XV+GUC5DTAfBgNVHSMEGDAWgBSz3F5dRzXwuzPER2Ar6XV+GUC5DTAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMBAzgAMDUCGHWW94/TwdL1QVzZFYDEW5/Lr7+T
9gY9aAIZAOUgpD35Uku9ZUdDEstB1GUAS2d1FWfxnQ==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_P224_WITH_SHA224_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBdzCCASagAwIBAgIUYEnzP6enrwE1YlhMzNm8377vF0UwCgYIKoZIzj0EAwEw
GzEZMBcGA1UEAwwQc2VjcDIyNHIxLXNoYTIyNDAeFw0yMzEwMjMyMzU1NTVaFw0y
NjEwMjIyMzU1NTVaMBsxGTAXBgNVBAMMEHNlY3AyMjRyMS1zaGEyMjQwTjAQBgcq
hkjOPQIBBgUrgQQAIQM6AAT8++n3WXDwvZJ7BN43BwNx93xoEw+6gNq1UEPdBUb7
pdrzjxMpt/9J5PVjQMj/Pw4apL4FiPtq5KNTMFEwHQYDVR0OBBYEFP6gAuyFkYm8
fowTBk/UAraTi7SfMB8GA1UdIwQYMBaAFP6gAuyFkYm8fowTBk/UAraTi7SfMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwEDPwAwPAIcLXnXm1WLPqoVUzSOfeWe
EG55AYKK0psHOspZ2wIcfhdo1Rdz9s9swl0mig5X5ebq0qZrKUeQC9Ye+w==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_P256_WITH_SHA256_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBjDCCATOgAwIBAgIUD0hnV4dQTvEgNqY94vdYSdDtOaswCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRcHJpbWUyNTZ2MS1zaGEyNTYwHhcNMjMxMDIzMjM1NTU0WhcN
MjYxMDIyMjM1NTU0WjAcMRowGAYDVQQDDBFwcmltZTI1NnYxLXNoYTI1NjBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLglB6XI74Zgw5oGbj9ZruTyi1QDX0IoLOfs
VGU9HEK+3HhedD/OotoW+gK/TGTsFSd8gs6i7DJ6prLWT6flK++jUzBRMB0GA1Ud
DgQWBBTMS7AELri6/SOCLM6j+7F5+rRCfjAfBgNVHSMEGDAWgBTMS7AELri6/SOC
LM6j+7F5+rRCfjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAOH
Njtrr5nItA67cFOSvGM/Ctr1bvYifKZychENW6fmAiAe782xlc/68PLjUGfEECTS
yY0RYLQ79tmNNk76SQ20GA==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    const PUBLIC_P384_WITH_SHA384_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIByDCCAU6gAwIBAgIUTseuBhvcGrLI5IRmmZVQdLkQJaYwCgYIKoZIzj0EAwMw
GzEZMBcGA1UEAwwQc2VjcDM4NHIxLXNoYTM4NDAeFw0yMzEwMjMyMzU1NTVaFw0y
NjEwMjIyMzU1NTVaMBsxGTAXBgNVBAMMEHNlY3AzODRyMS1zaGEzODQwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQzu64YQGBuu09dY+62Skfa3FTT7mmirIRJOJxM6zHi
dbbNRNLgymDZB1Iabs6qmj7GoH5MTxVreXWdtCE8Mv+ilXbPZ+6OZievEpL+MM3b
PPbzOyBClnI8OYGFaRzAo+ajUzBRMB0GA1UdDgQWBBTiPayVyjuWoO+kQSgn1n0H
mZe62DAfBgNVHSMEGDAWgBTiPayVyjuWoO+kQSgn1n0HmZe62DAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMDA2gAMGUCMQDSu/3rbKHuit9Tt5tXTgzarBMxhVhS
JQanPOuJxlQQTZgmy39RD3oT3Z1mcMY2b3wCMFxsSlFVZUhBkI6gCVlux+33iSFE
ay4nBaFbWFxsrCIz5mjiyAkKm2dyPYzXKakLlA==
-----END CERTIFICATE-----";

    #[allow(dead_code)]
    fn verify_good(pem: &str) {
        let cert = Certificate::from_pem(pem).expect("error parsing certificate");
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
    }

    #[allow(dead_code)]
    fn verify_bad(pem: &str) {
        let cert = Certificate::from_pem(pem).expect("error parsing certificate");
        let msg = "Bad message";
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
        match verifier.verify(msg.as_bytes(), &sig) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[allow(dead_code)]
    fn verify_bad_oid(pem: &str) {
        let cert = Certificate::from_pem(pem).expect("error parsing certificate");
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
        match X509Verifier::try_from(cert.tbs_certificate.subject_public_key_info) {
            Ok(v) => match v.verify(&msg, &sig) {
                Ok(_) => panic!("should not have been good"),
                Err(Error::UnknownOid(_)) => {}
                Err(e) => panic!("{:?}", e),
            },
            Err(Error::UnknownOid(_)) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[cfg(all(feature = "dsa", feature = "sha1"))]
    #[test]
    fn dsa_with_sha1_good() {
        verify_good(&PUBLIC_DSA_WITH_SHA1_PEM);
    }

    #[cfg(all(feature = "dsa", feature = "sha1"))]
    #[test]
    fn dsa_with_sha1_bad() {
        verify_bad(&PUBLIC_DSA_WITH_SHA1_PEM);
    }

    #[cfg(not(feature = "dsa"))]
    #[test]
    fn dsa_with_sha1_bad_oid1() {
        verify_bad_oid(&PUBLIC_DSA_WITH_SHA1_PEM);
    }

    #[cfg(not(feature = "sha1"))]
    #[test]
    fn dsa_with_sha1_bad_oid2() {
        verify_bad_oid(&PUBLIC_DSA_WITH_SHA1_PEM);
    }

    #[cfg(all(feature = "rsa", feature = "sha1"))]
    #[test]
    fn rsa_with_sha1_good() {
        verify_good(&PUBLIC_RSA_WITH_SHA1_PEM);
    }

    #[cfg(all(feature = "rsa", feature = "sha1"))]
    #[test]
    fn rsa_with_sha1_bad() {
        verify_bad(&PUBLIC_RSA_WITH_SHA1_PEM);
    }

    #[cfg(not(feature = "rsa"))]
    #[test]
    fn rsa_with_sha1_bad_oid1() {
        verify_bad_oid(&PUBLIC_RSA_WITH_SHA1_PEM);
    }

    #[cfg(not(feature = "sha1"))]
    #[test]
    fn rsa_with_sha1_bad_oid2() {
        verify_bad_oid(&PUBLIC_RSA_WITH_SHA1_PEM);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn rsa_with_sha256_good() {
        verify_good(&PUBLIC_RSA_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn rsa_with_sha256_bad() {
        verify_bad(&PUBLIC_RSA_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "rsa"))]
    #[test]
    fn rsa_with_sha256_bad_oid1() {
        verify_bad_oid(&PUBLIC_RSA_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn rsa_with_sha256_bad_oid2() {
        verify_bad_oid(&PUBLIC_RSA_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "k256", feature = "sha2"))]
    #[test]
    fn k256_with_sha256_good() {
        verify_good(&PUBLIC_K256_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "k256", feature = "sha2"))]
    #[test]
    fn k256_with_sha256_bad() {
        verify_bad(&PUBLIC_K256_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "k256"))]
    #[test]
    fn k256_with_sha256_bad_oid1() {
        verify_bad_oid(&PUBLIC_K256_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn k256_with_sha256_bad_oid2() {
        verify_bad_oid(&PUBLIC_K256_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "p192", feature = "sha2"))]
    #[test]
    fn p192_with_sha224_good() {
        verify_good(&PUBLIC_P192_WITH_SHA224_PEM);
    }

    #[cfg(all(feature = "p192", feature = "sha2"))]
    #[test]
    fn p192_with_sha224_bad() {
        verify_bad(&PUBLIC_P192_WITH_SHA224_PEM);
    }

    #[cfg(not(feature = "p192"))]
    #[test]
    fn p192_with_sha224_bad_oid1() {
        verify_bad_oid(&PUBLIC_P192_WITH_SHA224_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn p192_with_sha224_bad_oid2() {
        verify_bad_oid(&PUBLIC_P192_WITH_SHA224_PEM);
    }

    #[cfg(all(feature = "p224", feature = "sha2"))]
    #[test]
    fn p224_with_sha224_good() {
        verify_good(&PUBLIC_P224_WITH_SHA224_PEM);
    }

    #[cfg(all(feature = "p224", feature = "sha2"))]
    #[test]
    fn p224_with_sha224_bad() {
        verify_bad(&PUBLIC_P224_WITH_SHA224_PEM);
    }

    #[cfg(not(feature = "p224"))]
    #[test]
    fn p224_with_sha224_bad_oid1() {
        verify_bad_oid(&PUBLIC_P224_WITH_SHA224_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn p224_with_sha224_bad_oid2() {
        verify_bad_oid(&PUBLIC_P224_WITH_SHA224_PEM);
    }

    #[cfg(all(feature = "p256", feature = "sha2"))]
    #[test]
    fn p256_with_sha256_good() {
        verify_good(&PUBLIC_P256_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "p256", feature = "sha2"))]
    #[test]
    fn p256_with_sha256_bad() {
        verify_bad(&PUBLIC_P256_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "p256"))]
    #[test]
    fn p256_with_sha256_bad_oid1() {
        verify_bad_oid(&PUBLIC_P256_WITH_SHA256_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn p256_with_sha256_bad_oid2() {
        verify_bad_oid(&PUBLIC_P256_WITH_SHA256_PEM);
    }

    #[cfg(all(feature = "p384", feature = "sha2"))]
    #[test]
    fn p384_with_sha384_good() {
        verify_good(&PUBLIC_P384_WITH_SHA384_PEM);
    }

    #[cfg(all(feature = "p384", feature = "sha2"))]
    #[test]
    fn p384_with_sha384_bad() {
        verify_bad(&PUBLIC_P384_WITH_SHA384_PEM);
    }

    #[cfg(not(feature = "p384"))]
    #[test]
    fn p384_with_sha384_bad_oid1() {
        verify_bad_oid(&PUBLIC_P384_WITH_SHA384_PEM);
    }

    #[cfg(not(feature = "sha2"))]
    #[test]
    fn p384_with_sha384_bad_oid2() {
        verify_bad_oid(&PUBLIC_P384_WITH_SHA384_PEM);
    }
}
