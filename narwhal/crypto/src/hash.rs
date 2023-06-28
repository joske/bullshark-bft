use crate::CurrentNetwork;

use std::fmt;

use base64ct::{Base64, Encoding};
use bitvec::prelude::{BitVec, Lsb0};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use snarkvm_console::{algorithms::BHP256, prelude::Hash as _, prelude::ToBytes};

pub const DIGEST_LENGTH: usize = snarkvm_console::types::Field::<CurrentNetwork>::SIZE_IN_BYTES;

/// The default hash function used throughout the codebase. Currently backed by BHP256.
pub struct DefaultHashFunction {
    /// The hasher.
    bhp: BHP256<CurrentNetwork>,
    /// The bytes accumulator. SnarkVM's implemenation of the BHP hash isn't a running hash.
    /// This collection concatenates the bytes passed in with `update` until `finalized` is called,
    /// in which case the hash is computed.
    accumulator: Vec<u8>,
}

impl DefaultHashFunction {
    pub fn new() -> Self {
        Self {
            bhp: BHP256::setup("AleoBHP256").expect("Failed to setup BHP256"),
            accumulator: vec![],
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.accumulator.extend_from_slice(data.as_ref())
    }

    pub fn finalize(self) -> Digest {
        let bits = BitVec::<_, Lsb0>::from_vec(self.accumulator);
        let bools: Vec<bool> = bits.into_iter().collect();
        let digest = self
            .bhp
            .hash(&bools)
            .expect("Couldn't finalize the BHP256 hash")
            .to_bytes_le()
            .expect("Couldn't convert field element to le bytes")
            .try_into()
            .expect("Digest wasn't DIGEST_LENGTH long");

        Digest(digest)
    }

    pub fn digest<D: AsRef<[u8]>>(data: D) -> Digest {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    pub fn digest_iterator<D: AsRef<[u8]>, I: Iterator<Item = D>>(iter: I) -> Digest {
        let mut hasher = Self::new();
        for data in iter {
            hasher.update(data)
        }

        hasher.finalize()
    }
}

impl Default for DefaultHashFunction {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Arbitrary,
    Default,
)]
pub struct Digest([u8; DIGEST_LENGTH]);

impl Digest {
    pub fn new(inner: [u8; DIGEST_LENGTH]) -> Self {
        Self(inner)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size() -> usize {
        DIGEST_LENGTH
    }

    pub fn to_inner(&self) -> [u8; DIGEST_LENGTH] {
        self.0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note: same impl as in `fastcrypto`.
        write!(
            f,
            "{}",
            Base64::encode_string(&self.0).get(..DIGEST_LENGTH).unwrap()
        )
    }
}
