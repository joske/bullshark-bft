// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use fastcrypto::{
    ed25519,
    hash::{Blake2b256, Digest, HashFunction},
};

// This re-export allows using the trait-defined APIs
pub use fastcrypto::traits;

////////////////////////////////////////////////////////////////////////
/// Type aliases selecting the signature algorithm for the code base.
////////////////////////////////////////////////////////////////////////
// Here we select the types that are used by default in the code base.
// The whole code base should only:
// - refer to those aliases and not use the individual scheme implementations
// - not use the schemes in a way that break genericity (e.g. using their Struct impl functions)
// - swap one of those aliases to point to another type if necessary
//
// Beware: if you change those aliases to point to another scheme implementation, you will have
// to change all four aliases to point to concrete types that work with each other. Failure to do
// so will result in a ton of compilation errors, and worse: it will not make sense!

// pub type OldPublicKey = bls12381::min_sig::BLS12381PublicKey;
// pub type OldSignature = bls12381::min_sig::BLS12381Signature;
// pub type OldAggregateSignature = bls12381::min_sig::BLS12381AggregateSignature;
// pub type OldPrivateKey = bls12381::min_sig::BLS12381PrivateKey;
// pub type KeyPair = bls12381::min_sig::BLS12381KeyPair;

pub type NetworkPublicKey = ed25519::Ed25519PublicKey;
pub type NetworkKeyPair = ed25519::Ed25519KeyPair;

////////////////////////////////////////////////////////////////////////

// Type alias selecting the default hash function for the code base.
pub type DefaultHashFunction = Blake2b256;
pub const DIGEST_LENGTH: usize = DefaultHashFunction::OUTPUT_SIZE;

use base64ct::Base64;
use base64ct::Encoding;
use eyre::eyre;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use serde::Deserialize;
use serde::Serialize;
use snarkvm_console::account::Address;
use snarkvm_console::network::Testnet3;
use snarkvm_console::prelude::Compare;
use snarkvm_console::prelude::Equal;
use snarkvm_console::prelude::FromBytes;
use snarkvm_console::prelude::ToBytes;
use std::ops::Deref;
use std::{cmp::Ordering, fs::File, io};
use std::{fmt::Display, io::Write};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

type CurrentNetwork = Testnet3;

pub trait EncodeDecodeBase64: Sized {
    fn encode_base64(&self) -> String;
    fn decode_base64(value: &str) -> Result<Self, eyre::Report>;
}

#[derive(Eq, PartialEq, Clone, Serialize, Deserialize, Debug, Hash)]
pub struct PublicKey(Address<CurrentNetwork>);

impl Default for PublicKey {
    fn default() -> Self {
        #[allow(deprecated)] // this is only used in tests
        Self(snarkvm_console::account::Address::<CurrentNetwork>::zero())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if *self.0.is_equal(&other.0) {
            Ordering::Equal
        } else if *self.0.is_less_than(&other.0) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for PublicKey {
    type Target = Address<CurrentNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl EncodeDecodeBase64 for PublicKey {
    fn encode_base64(&self) -> String {
        Base64::encode_string(&self.0.to_bytes_le().unwrap())
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode_vec(s).map_err(|e| eyre!(e))?;
        Ok(Self(Address::from_bytes_le(&bytes).map_err(|e| eyre!(e))?))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, eyre::Report> {
        Ok(Self(Address::from_bytes_le(bytes).map_err(|e| eyre!(e))?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_le().unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PrivateKey(snarkvm_console::account::PrivateKey<CurrentNetwork>);

impl Default for PrivateKey {
    fn default() -> Self {
        let mut rng = StdRng::seed_from_u64(1234567890);
        Self(snarkvm_console::account::PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap())
    }
}

impl Deref for PrivateKey {
    type Target = snarkvm_console::account::PrivateKey<CurrentNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EncodeDecodeBase64 for PrivateKey {
    fn encode_base64(&self) -> String {
        Base64::encode_string(&self.0.to_bytes_le().unwrap())
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode_vec(s).map_err(|e| eyre!(e))?;
        Ok(Self(
            snarkvm_console::account::PrivateKey::<CurrentNetwork>::from_bytes_le(&bytes)
                .map_err(|e| eyre!(e))?,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    public: PublicKey,
    private: PrivateKey,
}

impl EncodeDecodeBase64 for KeyPair {
    fn encode_base64(&self) -> String {
        self.private.encode_base64()
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let private = PrivateKey::decode_base64(s)?;
        let public = PublicKey(Address::try_from(private.0).map_err(|e| eyre!(e))?);

        Ok(Self { public, private })
    }
}

impl KeyPair {
    pub fn export(&self, path: &str) -> io::Result<()> {
        let ba64 = self.encode_base64();
        let mut file = File::create(path)?;
        file.write_all(ba64.as_bytes())?;
        Ok(())
    }
}

use rand::CryptoRng;
use rand::Rng;

impl KeyPair {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, eyre::Report> {
        let private = snarkvm_console::account::PrivateKey::new(rng).map_err(|e| eyre!(e))?;
        let public = PublicKey(Address::try_from(private).map_err(|e| eyre!(e))?);
        let private = PrivateKey(private);

        Ok(Self { public, private })
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn private(&self) -> &PrivateKey {
        &self.private
    }
}

pub type Signature = snarkvm_console::account::Signature<CurrentNetwork>;

// This code is based on the fastcrypto implementation.
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest<DIGEST_LENGTH>, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(pk: PrivateKey) -> Self {
        let (tx, mut rx): (
            Sender<(Digest<DIGEST_LENGTH>, oneshot::Sender<Signature>)>,
            _,
        ) = channel(100);
        tokio::spawn(async move {
            while let Some((msg, sender)) = rx.recv().await {
                // TODO: can we do better with the rng here?
                let mut rng = thread_rng();

                // Note: fastcrypto also uses infallible signing in their impl of the signature
                // service.
                let signature = pk
                    .sign_bytes(msg.as_ref(), &mut rng)
                    .expect("signing failed");
                let _ = sender.send(signature);
            }
        });

        Self { channel: tx }
    }

    pub async fn request_signature(&self, msg: Digest<DIGEST_LENGTH>) -> Signature {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.channel.send((msg, tx)).await {
            panic!("failed to send message to signature service: {e}");
        }

        rx.await
            .expect("failed to receive signature from signature service")
    }
}

// (we just concat signatures)
// pub type AggregateSignature = Vec<snarkvm_console::account::Signature<CurrentNetwork>>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AggregateSignature(pub Vec<snarkvm_console::account::Signature<CurrentNetwork>>);

// type KeyPair = IDK, depends what functionality they use of it, seems unnecessary;
//
// type NetworkPublicKey = snarkvm_console::account::Address; (check if theres a reason they had to make a different PublicKey for the Network);
// type NetworkKeyPair = IDK, similar to above not sure what functionality they need;

// pub type DefaultHashFunction = snarkvm_console::algorithms::BHP256<CurrentEnvironment>;
// pub const DIGEST_LENGTH: usize = snarkvm_console::types::Field::<CurrentEnvironment>::SIZE_IN_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Base64;

    #[test]
    fn test_public_key_default() {
        let pk = PublicKey::default();
        assert_eq!(
            pk.encode_base64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn test_private_key_default() {
        let pk = PrivateKey::default();
        assert_eq!(
            pk.encode_base64(),
            "7uijHRAnvMWh4H7OC56fHehHBbR76oHmmD37dLYQLQg="
        );
    }

    #[tokio::test]
    async fn test_signature_service() {
        let pk = PrivateKey::default();
        let signature_service = SignatureService::new(pk);
        let sig = signature_service
            .request_signature(Digest::new([0u8; 32]))
            .await;
        let _b64 = Base64::encode_string(&sig.to_bytes_le().unwrap());
    }
}
