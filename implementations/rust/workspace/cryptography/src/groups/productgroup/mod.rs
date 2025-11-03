// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Generic product groups for elements and scalars

/// Product group for elements
pub mod element;

/// Product group for scalars
pub mod scalar;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
