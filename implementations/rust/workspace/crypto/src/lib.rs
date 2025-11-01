/*!
 * Cryptography library for the Vote Secure project
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */
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
#[crate::warning("Asserts are present in this module. Not optimized.")]
pub mod dkgd;
pub mod groups;
/// Abstractions for curve arithmetic, groups, elements and scalars.
pub mod traits;
/// Utilities such as random number generation, hashing, signatures and serialization.
pub mod utils;
pub mod zkp;

pub use custom_warning_macro::warning;
pub use vser_derive::VSerializable;

/// Create the `crypto` alias that points to `crate`
///
/// This alias allows applying the vser_derive macro within this crate:
///
/// `vser_derive` refers to its target traits with `crypto::`, but
/// _within_ this crate, that reference will not resolve to anything
/// unless we add this alias. Other crate will resolve correctly
/// as they will be importing `crypto` as a dependency.
#[doc(hidden)]
extern crate self as crypto;
