// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Group over curve P-256

pub use element::P256Element;
pub use group::P256Group;
pub use scalar::P256Scalar;

/// P-256 implementation of [`GroupElement`](crate::traits::groups::GroupElement)
pub mod element;

/// P-256 implementation of [`CryptographicGroup`](crate::traits::groups::CryptographicGroup)
pub mod group;

/// P-256 implementation of [`GroupScalar`](crate::traits::groups::GroupScalar)
pub mod scalar;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
