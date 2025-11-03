// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Group over the Ristretto group (over curve25519)

pub use element::RistrettoElement;
pub use group::Ristretto255Group;
pub use scalar::RistrettoScalar;

/// Ristretto implementation of [`GroupElement`](crate::traits::groups::GroupElement)
pub mod element;

/// Ristretto implementation of [`CryptographicGroup`](crate::traits::groups::CryptographicGroup)
pub mod group;

/// Ristretto implementation of [`GroupScalar`](crate::traits::groups::GroupScalar)
pub mod scalar;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
