/*!
Types for working with hashes
*/

use data_encoding::HEXLOWER;
use digest::block_buffer::Eager;
use digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore};
use digest::typenum::{IsLess, Le, NonZero, U256};
use digest::{Digest, HashMarker, Mac};
use hmac::Hmac;
pub use hmac::digest::InvalidLength as InvalidKeyLength;
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

/// Simple trait for hashing
pub trait ToHash {
    /// Produces a hex encoded (lowercase) string using the given hash algorithm
    fn to_hash<D: Digest>(&self) -> String;
}

impl<T: AsRef<[u8]>> ToHash for T {
    fn to_hash<D: Digest>(&self) -> String {
        let mut hasher = D::new();
        hasher.update(self);
        HEXLOWER.encode(&hasher.finalize())
    }
}

impl ToHash for dyn AsRef<[u8]> {
    fn to_hash<D: Digest>(&self) -> String {
        let mut hasher = D::new();
        hasher.update(self.as_ref());
        HEXLOWER.encode(&hasher.finalize())
    }
}

/// Simple trait for producing an HMAC digest
pub trait ToHmac {
    /// Produces a hex encoded (lowercase) string using the given hash algorithm
    fn to_hmac<D>(&self, key: &[u8]) -> Result<String, InvalidKeyLength>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero;
}

impl<T: AsRef<[u8]>> ToHmac for T {
    fn to_hmac<D>(&self, key: &[u8]) -> Result<String, InvalidKeyLength>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut mac = Hmac::<D>::new_from_slice(key)?;
        mac.update(self.as_ref());
        Ok(HEXLOWER.encode(&mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn str_expected_hash() {
        let hash = "some string".to_hash::<Sha256>();

        assert_eq!(
            "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc",
            hash
        );
    }

    #[test]
    fn str_expected_hash_512() {
        let hash = "some string".to_hash::<Sha512>();

        assert_eq!(
            "14925e01a7a0cf0801aa95fe52d542b578af58ae7997ada66db3a6eae68a329d50600a5b7b442eabf4ea77ea8ef5fe40acf2ab31d47311b2a232c4f64009aac1",
            hash
        );
    }
}
