/*!
Types for working with Dynata signatures
*/

use std::sync::Arc;

use zeroize::Zeroizing;

pub use crate::hash::InvalidKeyLength;
use crate::hash::{Sha256, ToHmac};
use crate::time::Timestamp;

/// Holds a Dynata access/secret key pair.
#[derive(Debug, Default, Clone)]
pub struct Key(Arc<(Zeroizing<String>, Zeroizing<String>)>);

impl Key {
    /// Creates a new `Key` from a pair of `String`.
    pub fn new(access: String, secret: String) -> Self {
        Key(Arc::new((access.into(), secret.into())))
    }

    /// Returns the access key portion of the `Key`.
    pub fn access_key(&self) -> &str {
        self.0.0.as_ref()
    }

    /// Returns the secret key portion of the `Key`.
    pub fn secret_key(&self) -> &str {
        self.0.1.as_ref()
    }
}

impl From<(String, String)> for Key {
    fn from(k: (String, String)) -> Self {
        Key::new(k.0, k.1)
    }
}

/// Dynata signature parts
#[derive(Debug, Clone)]
pub struct Signature {
    /// Expiration portion of signature
    pub expiration: String,

    /// Access Key portion of signature
    pub access_key: String,

    /// Signing String portion of signature
    pub signing_string: String,

    /// Value of signature
    pub value: String,
}

/// Trait for applying a given value to Self
pub trait Apply<T> {
    /// Applies subject to Self
    fn apply(self, subject: T) -> Self;
}

/// Represents a type that can be signed using the Dynata signature algorithm.
pub trait Signer {
    /// Signs self using the Dynata signature algorithm.
    fn sign(&self, key: &Key, ttl: &Timestamp) -> Result<Signature, InvalidKeyLength>;
}

impl<S: AsRef<str>> Signer for S {
    fn sign(&self, key: &Key, ttl: &Timestamp) -> Result<Signature, InvalidKeyLength> {
        let exp = ttl.to_string();
        let first = self.as_ref().as_bytes().to_hmac::<Sha256>(exp.as_bytes())?;
        let second = first.to_hmac::<Sha256>(key.access_key().as_bytes())?;
        let sig = second.to_hmac::<Sha256>(key.secret_key().as_bytes())?;

        Ok(Signature {
            expiration: exp,
            access_key: key.access_key().to_string(),
            signing_string: self.as_ref().to_string(),
            value: sig,
        })
    }
}
