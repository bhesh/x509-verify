#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod error;
pub use error::Error;

mod message;
pub use message::X509Message;

mod signature;
pub use signature::X509Signature;

mod verify;
pub use verify::X509VerifyKey;

#[cfg(feature = "x509")]
mod x509;
