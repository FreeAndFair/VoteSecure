// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! GroupElement implementations for Ristrett255 group

use crate::groups::ristretto255::scalar::RistrettoScalar;
use crate::traits::groups::GroupElement;
use crate::utils::error::Error as CryptographyError;
use crate::utils::rng;
use core::fmt::Debug;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use sha3::digest::Digest;
use sha3::digest::typenum::U64;

/**
 * A [`GroupElement`] implementation for the [Ristretto](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html) group.
 */
#[derive(Copy, Clone, Debug)]
pub struct RistrettoElement(pub RistrettoPoint);

impl RistrettoElement {
    /// Create a new `RistrettoElement` from a [`RistrettoPoint`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/struct.RistrettoPoint.html).
    #[must_use]
    pub fn new(point: RistrettoPoint) -> Self {
        RistrettoElement(point)
    }

    /// Create a new `RistrettoElement` from a hash.
    ///
    /// See [`RistrettoPoint::hash_from_bytes`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/struct.RistrettoPoint.html#method.hash_from_bytes) for details
    pub fn from_hash<D: Digest<OutputSize = U64> + Default>(hasher: D) -> Self {
        RistrettoElement(RistrettoPoint::from_hash::<D>(hasher))
    }
}

impl GroupElement for RistrettoElement {
    type Scalar = RistrettoScalar;

    #[inline]
    fn one() -> Self {
        RistrettoElement(RistrettoPoint::identity())
    }

    #[inline]
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        let ret = RistrettoPoint::random(rng);
        RistrettoElement(ret)
    }

    #[inline]
    fn mul(&self, other: &Self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoElement(self.0 + other.0)
    }

    #[inline]
    fn inv(&self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoElement(-self.0)
    }

    #[inline]
    fn exp(&self, scalar: &Self::Scalar) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoElement(self.0 * scalar.0)
    }

    #[inline]
    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq for RistrettoElement {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}
impl Eq for RistrettoElement {}
impl std::hash::Hash for RistrettoElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.compress().hash(state);
    }
}

use crate::utils::serialization::{VDeserializable, VSerializable};

impl VSerializable for RistrettoElement {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.compress().to_bytes();
        bytes.to_vec()
    }
}

impl VDeserializable for RistrettoElement {
    fn deser(buffer: &[u8]) -> Result<Self, CryptographyError> {
        let array = <[u8; 32]>::try_from(buffer).map_err(|_| {
            CryptographyError::DeserializationError(
                "Failed to convert Vec<u8> to [u8; 32]".to_string(),
            )
        })?;
        CompressedRistretto(array)
            .decompress()
            .map(RistrettoElement)
            .ok_or(CryptographyError::DeserializationError(
                "Failed to parse Ristretto point bytes".to_string(),
            ))
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};

impl FSerializable for RistrettoElement {
    fn size_bytes() -> usize {
        32
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let point = self.0.compress();
        let bytes = point.as_bytes();
        buffer.extend_from_slice(bytes);
    }
}

impl FDeserializable for RistrettoElement {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptographyError> {
        Self::deser(buffer)
    }
}
