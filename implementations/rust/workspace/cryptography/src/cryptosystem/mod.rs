// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Public key cryptosystems.
//!
//! # [`ElGamal`][`crate::cryptosystem::elgamal`]
//!
//! The `ElGamal` cryptosystem.
//!
//! See `EVS`: Definition 11.15
//!
//! # [`Naor-Yung`][`crate::cryptosystem::naoryung`]
//!
//! The Naor-Yung cryptosystem. This is an augmentation of `ElGamal`
//! that achieves CCA security by providing two ciphertexts of the encrypted
//! plaintext and a proof of plaintext equality for them. In this implementation
//! a Naor-Yung key pair is obtained by augmenting an `ElGamal` key pair with
//! an additional public key for which the secret is never computed. This additional
//! public key is derived from publicly available information, through a hash
//! function, see [`KeyPair::generate`][`crate::cryptosystem::naoryung::KeyPair::generate`]
//! and [`KeyPair::new`][`crate::cryptosystem::naoryung::KeyPair::new`].
//!
//! Naor-Yung ciphertexts are validated by checking their associated proofs, after
//! which they yield plain `ElGamal` ciphertexts, see [`PublicKey::strip`][`crate::cryptosystem::naoryung::PublicKey::strip`].
//!
//! See `EVS`: Definition 11.31
//!
//! # Examples
//!
//! ```
//! use cryptography::cryptosystem::naoryung::KeyPair as NYKeyPair;
//! use cryptography::cryptosystem::elgamal::KeyPair as EGKeyPair;
//! use cryptography::cryptosystem::elgamal;
//! use cryptography::context::Context;
//! use cryptography::context::RistrettoCtx as RCtx;
//!
//! // Set to some relevant context value
//! let keypair_context = &[];
//!
//! // generate an `ElGamal` key pair
//! let eg_keypair: EGKeyPair<RCtx> = EGKeyPair::generate();
//! // augment it to a `Naor-Yung` key pair
//! let ny_keypair: NYKeyPair<RCtx> = NYKeyPair::augment(&eg_keypair, keypair_context).unwrap();
//! let message = [RCtx::random_element(); 2];
//! // Set to some relevant context value
//! let encryption_context = &[];
//! // computes a `Naor-Yung` ciphertext
//! let ciphertext = ny_keypair.encrypt(&message, encryption_context).unwrap();
//!
//! // stripping a `Naor-Yung` ciphertexts verifies its proof and returns an
//! // `ElGamal` ciphertext
//! let stripped: elgamal::Ciphertext<RCtx, 2> = ny_keypair.strip(ciphertext, encryption_context).unwrap();
//!
//! // decrypt using plain `ElGamal` decryption
//! let decrypted = eg_keypair.decrypt(&stripped);
//! assert_eq!(message, decrypted);
//! ```

/// `ElGamal` cryptosystem.
pub mod elgamal;

/// Naor-Yung cryptosystem.
pub mod naoryung;
