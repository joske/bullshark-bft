// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use fastcrypto::ed25519;

mod hash;
pub use hash::*;

mod keypair;
pub use keypair::*;

mod signature;
pub use signature::*;

mod traits;
pub use traits::*;

// TODO(nkls): switch to snarkVM construction when ready.
// type NetworkPublicKey = snarkvm_console::account::Address; (check if theres a reason they had to make a different PublicKey for the Network);
// type NetworkKeyPair = IDK, similar to above not sure what functionality they need;
pub type NetworkPublicKey = ed25519::Ed25519PublicKey;
pub type NetworkKeyPair = ed25519::Ed25519KeyPair;

use snarkvm_console::network::Testnet3;

// Used to version snarkVM cryptography primitives.
type CurrentNetwork = Testnet3;
