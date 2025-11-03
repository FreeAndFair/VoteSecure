// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Hashing utilities

use sha3::digest::FixedOutput;
use sha3::{Digest, Sha3_256, Sha3_512};

use crate::utils::error::Error;
use crate::utils::serialization::{VDeserializable, VSerializable};

/**
 * Hashing cryptographic [group][`crate::traits::groups::CryptographicGroup`] dependency.
 *
 * Allows retrieving a hasher instance in some [Context][`crate::context::Context`].
 */
pub trait Hasher: Digest + FixedOutput {
    /// Returns a hasher instance.
    fn hasher() -> Self;
}

/**
 * Implement the hashing group dependency with `Sha3_512`.
 */
impl Hasher for Sha3_512 {
    fn hasher() -> Self {
        Sha3_512::new()
    }
}

/**
 * Implement the hashing group dependency with `Sha3_256`.
 */
impl Hasher for Sha3_256 {
    fn hasher() -> Self {
        Sha3_256::new()
    }
}

/// Hashing to 512 bits provided by sha3
pub type Hasher512 = Sha3_512;

/// Hashing to 256 bits provided by sha3
pub type Hasher256 = Sha3_256;

/// Update the hasher with the given data slices and their corresponding tags.
///
/// This function is used to derive challenges via random oracles.
pub fn update_hasher(hasher: &mut impl Digest, data_slices: &[&[u8]], ds_tags: &[&[u8]]) {
    for (i, slice) in data_slices.iter().enumerate() {
        hasher.update(slice);
        if ds_tags.len() > i {
            hasher.update(ds_tags[i]);
        }
    }
}

/// Implement `VSerializable` for sha3 512-bit digests.
///
/// This is necessary to support serialization of messages
/// that contain hash digests.
impl VSerializable for sha3::digest::Output<Sha3_512> {
    fn ser(&self) -> Vec<u8> {
        self.to_vec()
    }
}

/// Implement `VDeserializable` for sha3 512-bit digests.
///
/// This is necessary to support serialization of messages
/// that contain hash digests.
impl VDeserializable for sha3::digest::Output<Sha3_512> {
    fn deser(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
            Error::DeserializationError("Invalid length for Sha3_512 digest".to_string())
        })?;

        Ok(bytes.into())
    }
}
