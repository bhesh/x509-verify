#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod error;
pub use error::Error;

mod message;
pub use message::{Message, MessageOwned, MessageRef};

mod signature;
pub use crate::signature::{Signature, SignatureOwned, SignatureRef};

mod verify;
pub use verify::{VerifyInfo, VerifyInfoRef, VerifyingKey};

pub use der;
pub use spki;

#[cfg(feature = "x509")]
mod x509;

#[cfg(feature = "x509")]
pub use ocsp_x509 as x509_ocsp;

#[cfg(feature = "x509")]
pub use x509_cert;
