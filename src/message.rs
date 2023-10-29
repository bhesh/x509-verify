//! Generic X.509 Message

use alloc::vec::Vec;

/// Generic X.509 message structure
#[derive(Copy, Clone, Debug)]
pub struct Message<B>(B)
where
    B: AsRef<[u8]>;

impl<B> Message<B>
where
    B: AsRef<[u8]>,
{
    /// Creates a [`Message`] with the provided bytes
    pub fn new(bytes: B) -> Self {
        Self(bytes)
    }
}

impl<B> AsRef<[u8]> for Message<B>
where
    B: AsRef<[u8]>,
{
    /// Returns a reference to the message bytes
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Generic X.509 message structure as a reference
pub type MessageRef<'a> = Message<&'a [u8]>;

impl<'a> From<&'a [u8]> for MessageRef<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> From<&'a Vec<u8>> for MessageRef<'a> {
    fn from(data: &'a Vec<u8>) -> Self {
        Self(data)
    }
}

impl<'a> From<&'a MessageOwned> for MessageRef<'a> {
    fn from(other: &'a MessageOwned) -> Self {
        Self(other.as_ref())
    }
}

/// Generic X.509 message structure owned
pub type MessageOwned = Message<Vec<u8>>;

impl From<Vec<u8>> for MessageOwned {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
