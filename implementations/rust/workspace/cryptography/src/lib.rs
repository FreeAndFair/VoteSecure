// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Cryptography library for the VoteSecure project

#![allow(dead_code)]
// Only necessary for custom_warning_macro
#![feature(stmt_expr_attributes)]
// Only necessary for custom_warning_macro
#![feature(proc_macro_hygiene)]
#![doc = include_str!("../README.md")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

// final pass
// #![warn(clippy::restriction)]

/// Defines implementation choices for key cryptographic functionalities.
pub mod context;
pub mod cryptosystem;
#[crate::warning("This module is not optimized.")]
pub mod dkgd;
pub mod groups;
/// Abstractions for curve arithmetic, groups, elements and scalars.
pub mod traits;
/// Utilities such as random number generation, hashing, signatures and serialization.
pub mod utils;
pub mod zkp;

pub use custom_warning_macro::warning;
pub use vser_derive::VSerializable;

/// Create the `cryptography` alias that points to `crate`
///
/// This alias allows applying the vser_derive macro within this crate:
///
/// `vser_derive` refers to its target traits with `cryptography::`, but
/// _within_ this crate, that reference will not resolve to anything
/// unless we add this alias. Other crates will resolve correctly
/// as they will be importing `cryptography` as a dependency.
#[doc(hidden)]
extern crate self as cryptography;
