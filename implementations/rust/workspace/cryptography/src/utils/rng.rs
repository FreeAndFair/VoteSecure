// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Random number generation

use rand::rngs::OsRng;

/**
 * Marker trait to require a cryptographically secure random number generator.
 */
pub trait CRng: rand::RngCore + rand::CryptoRng {}

/**
 * `OsRng` is a cryptographically secure random number generator.
 */
impl CRng for OsRng {}

/**
 * Random number generation [context][`crate::context::Context`] dependency.
 *
 * Allows retrieving an rng instance in some [Context][`crate::context::Context`].
 */
pub trait Rng: CRng {
    /// Returns an rng instance.
    fn rng() -> Self;
}

/**
 * Implements the random number generation [context][`crate::context::Context`] dependency with [`OsRng`].
 */
impl Rng for OsRng {
    fn rng() -> OsRng {
        rand::rngs::OsRng
    }
}
