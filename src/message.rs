//! Generic X.509 Message

use alloc::vec::Vec;

/// Generic X.509 message structure
pub struct X509Message {
    data: Vec<u8>,
}

impl X509Message {
    /// Creates an X509Message object with the provided message data
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    /// Returns a reference to the raw message data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl From<&[u8]> for X509Message {
    fn from(data: &[u8]) -> Self {
        X509Message::new(data)
    }
}

impl AsRef<[u8]> for X509Message {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
