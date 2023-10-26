//! Generic X.509 Message

use alloc::vec::Vec;

/// Generic X.509 message structure
#[derive(Clone, Debug)]
pub struct X509Message<T>(T)
where
    T: AsRef<[u8]>;

impl<T> AsRef<[u8]> for X509Message<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Generic X.509 message structure as a reference
pub type X509MessageRef<'a> = X509Message<&'a [u8]>;

impl<'a> From<&'a [u8]> for X509MessageRef<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> From<&'a Vec<u8>> for X509MessageRef<'a> {
    fn from(data: &'a Vec<u8>) -> Self {
        Self(data)
    }
}

/// Generic X.509 message structure owned
pub type X509MessageOwned = X509Message<Vec<u8>>;

impl From<Vec<u8>> for X509MessageOwned {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
