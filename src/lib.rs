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

pub mod error;

mod digest;
pub use digest::X509Digest;

mod signature;
pub use signature::X509Signature;

mod verify;
pub use verify::X509Verifier;
