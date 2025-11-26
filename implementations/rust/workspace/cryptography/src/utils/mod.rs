// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Utilities: hashing, rng, serialization, signatures, error handling

/// Error handling.
pub mod error;

/// Hashing utilities and [context][`crate::context::Context`] dependency.
pub mod hash;

/// Random number generation utilities and [context][`crate::context::Context`] dependency.
pub mod rng;

#[deny(clippy::indexing_slicing)]
pub mod serialization;

pub mod signatures;

pub use error::Error;
