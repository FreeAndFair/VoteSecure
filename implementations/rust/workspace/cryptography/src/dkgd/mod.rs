// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Distributed key generation and decryption
//!
//! * NOTE: this API does not represent private shares as encrypted values.
//!   In the messaging layer, private shares should be encrypted with the recipient's
//!   public key.
//!
//! This module models distributed key generation and decryption with
//! two main abstractions:
//!
//! - [`dealer::Dealer`][`crate::dkgd::dealer::Dealer`]
//!
//!   A participant in the protocol fulfilling the role of dealer. A dealer
//!   generates secret information and distributes shares of it privately to every
//!   participant, including itself (acting as a recipient). The distribution takes
//!   the form of pairwise shares of type [`VerifiableShare`][`crate::dkgd::dealer::VerifiableShare`].
//!
//! - [`recipient::Recipient`][`crate::dkgd::recipient::Recipient`]
//!
//!   A participant in the protocol fulfilling the role of share recipient.
//!   A recipient collects shares from every participant, including itself
//!   (acting as a dealer), and verifies them. Each recipient can then construct
//!
//!   1) The joint public key from public share information
//!   2) Their private share of the joint secret, from pairwise shares
//!      received privately
//!
//!   Recipients can compute partially decryptions of ciphertexts producing
//!   instances of type [`DecryptionFactor`][`crate::dkgd::recipient::DecryptionFactor`],
//!   that contain decryption factors and corresponding [proofs][`crate::zkp::dlogeq`] of correctness.
//!
//! # Distributed key generation
//!
//! Comprises the steps where dealers generate secrets and distribute them,
//! and recipients receive shares, verify them, and construct the joint public
//! key and their secrete shares.
//!
//! # Distributed decryption
//!
//! Comprises the steps where recipients compute partial decryptions of
//! some input ciphertexts, collect all such partial decryptions, verify them
//! and combine them to produce the decrypted plaintexts.
//!
//! Distributed decryption requires two external pieces of information
//!
//! 1) The ciphertexts to be decrypted
//! 2) The choice of participants to compute partial decryptions

/// Distributed key generation functionality.
pub mod dealer;

/// Distributed key generation and decryption functionality.
pub mod recipient;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[crate::warning("Need more threshold parameter combinations")]
mod tests;
