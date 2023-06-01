// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

mod hash;
pub use hash::*;

mod keypair;
pub use keypair::*;

mod network_keypair;
pub use network_keypair::*;

mod signature;
pub use signature::*;

mod traits;
pub use traits::*;

use snarkvm_console::network::Testnet3;

// Used to version snarkVM cryptography primitives.
type CurrentNetwork = Testnet3;
