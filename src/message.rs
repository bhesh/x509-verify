//! Generic X.509 Message

use alloc::vec::Vec;

/// Generic X.509 message structure
#[derive(Copy, Clone, Debug)]
pub struct Message<M>(M)
where
    M: AsRef<[u8]>;

impl<M> Message<M>
where
    M: AsRef<[u8]>,
{
    /// Creates a [`Message`] with the provided bytes
    pub fn new(bytes: M) -> Self {
        Self(bytes)
    }
}

impl<M> AsRef<[u8]> for Message<M>
where
    M: AsRef<[u8]>,
{
    /// Returns a reference to the message bytes
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// [`Message`] with a reference to the message bytes
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
    /// Converts an owned [`Message`] to a referenced [`Message`]
    fn from(other: &'a MessageOwned) -> Self {
        Self(other.as_ref())
    }
}

/// [`Message`] which owns the message bytes
pub type MessageOwned = Message<Vec<u8>>;

impl From<Vec<u8>> for MessageOwned {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
