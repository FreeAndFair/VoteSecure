// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! GroupScalar implementations for the Ristretto255 group

use crate::traits::groups::GroupScalar;
use crate::utils::error::Error as CryptographyError;
use crate::utils::rng;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use sha3::digest::Digest;
use sha3::digest::typenum::U64;

/**
 * A [`GroupScalar`] implementation for the [Ristretto](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html) group.
 */
#[derive(Copy, Clone, Debug)]
pub struct RistrettoScalar(pub DalekScalar);

impl RistrettoScalar {
    /// Create a new `RistrettoScalar` from a hash.
    ///
    /// See [`DalekScalar::from_hash`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/scalar/struct.Scalar.html#method.from_hash) for details.
    pub fn from_hash<D: Digest<OutputSize = U64>>(hasher: D) -> Self {
        RistrettoScalar(DalekScalar::from_hash::<D>(hasher))
    }
}

impl GroupScalar for RistrettoScalar {
    #[inline]
    fn zero() -> Self {
        RistrettoScalar(DalekScalar::ZERO)
    }

    #[inline]
    fn one() -> Self {
        RistrettoScalar(DalekScalar::ONE)
    }

    #[inline]
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        let ret = DalekScalar::random(rng);
        RistrettoScalar(ret)
    }

    #[inline]
    fn add(&self, other: &Self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoScalar(self.0 + other.0)
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoScalar(self.0 - other.0)
    }

    #[inline]
    fn mul(&self, other: &Self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoScalar(self.0 * other.0)
    }

    #[inline]
    fn neg(&self) -> Self {
        // curve arithmetic
        #[allow(clippy::arithmetic_side_effects)]
        RistrettoScalar(-self.0)
    }

    #[inline]
    fn inv(&self) -> Option<Self> {
        if self.0 == DalekScalar::ZERO {
            None
        } else {
            Some(RistrettoScalar(self.0.invert()))
        }
    }

    #[inline]
    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<u32> for RistrettoScalar {
    fn from(u: u32) -> RistrettoScalar {
        let scalar: DalekScalar = u.into();

        RistrettoScalar(scalar)
    }
}

impl PartialEq for RistrettoScalar {
    fn eq(&self, other: &Self) -> bool {
        GroupScalar::equals(self, other)
    }
}

impl Eq for RistrettoScalar {}

use crate::utils::serialization::{VDeserializable, VSerializable};

impl VSerializable for RistrettoScalar {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        bytes.to_vec()
    }
}

impl VDeserializable for RistrettoScalar {
    fn deser(buffer: &[u8]) -> Result<Self, CryptographyError> {
        let bytes = <[u8; 32]>::try_from(buffer).map_err(|_| {
            CryptographyError::DeserializationError(
                "Failed to convert Vec<u8> to [u8; 32]".to_string(),
            )
        })?;
        let opt: Option<RistrettoScalar> = DalekScalar::from_canonical_bytes(bytes)
            .map(RistrettoScalar)
            .into();
        opt.ok_or(CryptographyError::DeserializationError(
            "Failed to convert parse Ristretto scalar bytes".to_string(),
        ))
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};

impl FSerializable for RistrettoScalar {
    fn size_bytes() -> usize {
        32
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.0.as_bytes();
        buffer.extend_from_slice(bytes);
    }
}

impl FDeserializable for RistrettoScalar {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptographyError> {
        Self::deser(buffer)
    }
}
