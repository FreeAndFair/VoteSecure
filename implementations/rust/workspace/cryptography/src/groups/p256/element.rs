// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! GroupElement implementations for P-256 group

use crate::groups::p256::scalar::P256Scalar;
use crate::traits::groups::GroupElement;
use crate::utils::error::Error as CryptographyError;
use crate::utils::rng;
use core::fmt::Debug;
use p256::elliptic_curve::Group;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::subtle::CtOption;
use p256::{EncodedPoint, ProjectivePoint};

/**
 * A [`GroupElement`] implementation for the P-256 curve.
 */
#[derive(Debug, Clone, Copy)]
pub struct P256Element(pub ProjectivePoint);

impl P256Element {
    /// Create a new `P256Element` from a [`ProjectivePoint`](https://docs.rs/p256/latest/p256/type.ProjectivePoint.html).
    #[must_use]
    pub fn new(point: ProjectivePoint) -> Self {
        P256Element(point)
    }
}

#[allow(clippy::arithmetic_side_effects)]
impl GroupElement for P256Element {
    type Scalar = P256Scalar;

    fn one() -> Self {
        P256Element(ProjectivePoint::IDENTITY)
    }

    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        P256Element::new(ProjectivePoint::random(rng))
    }

    fn mul(&self, other: &Self) -> Self {
        P256Element(self.0 + other.0)
    }

    fn inv(&self) -> Self {
        P256Element(-self.0)
    }

    fn exp(&self, scalar: &Self::Scalar) -> Self {
        P256Element(self.0 * scalar.0)
    }

    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq for P256Element {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}
impl Eq for P256Element {}
impl std::hash::Hash for P256Element {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_affine().to_encoded_point(true).hash(state);
    }
}

use crate::utils::serialization::{VDeserializable, VSerializable};

impl VSerializable for P256Element {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.to_affine().to_encoded_point(true).to_bytes();
        if bytes.len() == 33 {
            bytes.to_vec()
        } else {
            [0u8; 33].to_vec()
        }
    }
}

impl VDeserializable for P256Element {
    fn deser(buffer: &[u8]) -> Result<Self, CryptographyError> {
        let bytes = <[u8; 33]>::try_from(buffer).map_err(|_| {
            CryptographyError::DeserializationError(
                "Failed to convert Vec<u8> to [u8; 33]".to_string(),
            )
        })?;
        if bytes == [0u8; 33] {
            return Ok(P256Element::one());
        }

        let point = EncodedPoint::from_bytes(bytes).map_err(|_| {
            CryptographyError::DeserializationError(
                "Failed to parse P256 encoded point".to_string(),
            )
        })?;
        let point: CtOption<P256Element> =
            ProjectivePoint::from_encoded_point(&point).map(P256Element);

        if point.is_some().into() {
            Ok(point.expect("point.is_some() == true"))
        } else {
            Err(CryptographyError::DeserializationError(
                "Failed to parse P256 point bytes".to_string(),
            ))
        }
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};

impl FSerializable for P256Element {
    fn size_bytes() -> usize {
        33
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let point = self.0.to_affine().to_encoded_point(true);
        let bytes = point.as_bytes();
        if bytes.len() == 33 {
            buffer.extend_from_slice(bytes);
        } else {
            buffer.extend_from_slice(&[0u8; 33]);
        }
    }
}

impl FDeserializable for P256Element {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptographyError> {
        Self::deser(buffer)
    }
}
