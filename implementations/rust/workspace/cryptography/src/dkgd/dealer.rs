// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Joint-Feldman distributed key generation: dealer

use std::array;

use crate::context::Context;
use crate::dkgd::recipient::ParticipantPosition;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use vser_derive::VSerializable;

/**
 * A dealer in the Joint-Feldman distributed key generation (DKG) protocol.
 *
 * * NOTE: this API does not represent private shares as encrypted values.
 *   In the messaging layer, private shares should be encrypted with the recipient's
 *   public key.
 *
 * In the Joint-Feldman DKG, the dealer generates a random polynomial `f` of degree
 * `T - 1` and distributes `P` shares of its secret, `f(0)`, to all participants,
 * including itself. The dealer also publishes `T` checking values that allow the
 * participants to verify their shares.
 *
 * In the Joint-Feldman DKG:
 *
 * - Only the recipients can compute their secret share of the joint public key with
 *   their `P` private shares.
 *
 * - Anyone can compute the joint public key from public data.
 *
 * - Anyone can compute the recipients' verification keys from public data.
 *
 * At least `T` of the `P` participants are needed to decrypt ciphertexts encrypted
 * with the joint public key.
 *
 * See `EVS`: Protocol 16.20
 *
 * See also [Recipient][`crate::dkgd::recipient::Recipient`]
 *
 * # Examples
 *
 * ```
 * use std::array;
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::dkgd::dealer::{VerifiableShare, Dealer};
 * use cryptography::dkgd::recipient::{combine, Recipient, DkgPublicKey, ParticipantPosition, DecryptionFactor};
 *
 * const P: usize = 3;
 * const T: usize = 2;
 * const W: usize = 2;
 *
 * // Simulates the DKG protocol
 *
 * let dealers: [Dealer<RCtx, T, P>; P] = array::from_fn(|_| Dealer::generate());
 *
 * let recipients: [(Recipient<RCtx, T, P>, DkgPublicKey<RCtx, T>); P] = array::from_fn(|i| {
 *     let position = ParticipantPosition::from_usize(i + 1);
 *
 *     let verifiable_shares: [VerifiableShare<RCtx, T>; P] = dealers
 *         .clone()
 *         .map(|d| d.get_verifiable_shares().for_recipient(&position));
 *
 *     Recipient::from_shares(position, &verifiable_shares).unwrap()
 * });
 *
 * // Simulates distributed decryption
 *
 * // the joint public key is returned from Recipient::from_shares, but can also
 * // be obtained via [`Recipient::joint_public_key`]
 * let (recipient, pk) = &recipients[0];
 * // encrypt a message of width `W
 * let message: [RistrettoElement; W] = array::from_fn(|_| RCtx::random_element());
 * let encrypted = vec![pk.encrypt(&message)];
 *
 * // in a real protocol execution, verification keys can be obtained via Recipient::verification_key
 * let verification_keys: [RistrettoElement; T] =
 *     array::from_fn(|i| recipients[i].0.get_verification_key().clone());
 *
 * // partial decryption
 * let dfactors: [Vec<DecryptionFactor<RCtx, P, W>>; P] =
 *     recipients.map(|r| r.0.decryption_factor(&encrypted, &vec![]).unwrap());
 *
 * let threshold: &[Vec<DecryptionFactor<RCtx, P, W>>; T] =
 *     dfactors[0..T].try_into().expect("slice matches array: T == T");
 *
 * // combine the decryption factors into the plaintext
 * let decrypted = combine(&encrypted, &threshold, &verification_keys, &vec![]).unwrap();
 *
 * assert!(message == decrypted[0]);
 * ```
 */

#[derive(Clone)]
pub struct Dealer<C: Context, const T: usize, const P: usize> {
    /// The polynomial used by this dealer to share their secret.
    pub(crate) polynomial: Polynomial<C, T>,
}

impl<C: Context, const T: usize, const P: usize> Dealer<C, T, P> {
    /// compile-time checks for dealer const parameters
    const CHECK: () = {
        assert!(P < 100);
        assert!(P > 0);
        assert!(T <= P);
        assert!(T > 0);
    };

    /// Construct a new [`Dealer`] by randomly generating a `T - 1` degree polynomial.
    ///
    /// At least `T` of the `P` participants will be needed to decrypt ciphertexts
    /// encrypted with the joint public key.
    #[must_use]
    pub fn generate() -> Self {
        #[allow(path_statements)]
        Self::CHECK;

        let polynomial = Polynomial::<C, T>::generate();
        Self { polynomial }
    }

    /// Compute the `P` shares distributed by this dealer, and its `T` checking values.
    ///
    /// Returns a [`DealerShares`] instance containing the shares and checking values.
    pub fn get_verifiable_shares(&self) -> DealerShares<C, T, P> {
        let shares = self.get_shares();

        DealerShares::new(shares, self.get_checking_values())
    }

    /// Compute the `P` shares distributed by this dealer.
    ///
    /// Each share is computed as `f(i)` for `i = 1, ..., P`.
    /// Use [`Self::get_verifiable_shares`] to obtain the shares [along
    /// with][`DealerShares`] their checking values.
    pub(crate) fn get_shares(&self) -> [C::Scalar; P] {
        array::from_fn(|p| {
            // p + 1 cannot overflow, P < 100 is compile-time checked
            #[allow(clippy::arithmetic_side_effects)]
            let recipient: u32 = (p + 1).try_into().expect("P < 100 < u32::MAX");
            let recipient: C::Scalar = recipient.into();
            self.polynomial.eval(&recipient)
        })
    }

    /// Compute the `T` checking values for this dealer's polynomial.
    ///
    /// Each checking value is computed as `g^polynomial_coefficient`.
    /// Use [`Self::get_verifiable_shares`] to obtain the shares [along
    /// with][`DealerShares`] their checking values.
    pub(crate) fn get_checking_values(&self) -> [C::Element; T] {
        let g = C::generator();
        self.polynomial.0.clone().map(|v| g.exp(&v))
    }
}

/**
 * A polynomial of degree `T - 1` over the scalar field of the elliptic curve group, `C::G`.
 *
 * This polynomial is used by the dealer to generate shares and checking values
 * for the participants in the DKG protocol. The polynomial is defined by `T` coefficients
 * of type `C::Scalar`, as are its arguments `x` and values `f(x)`.
 */
#[derive(Clone)]
pub struct Polynomial<C: Context, const T: usize>(pub(crate) [C::Scalar; T]);

impl<C: Context, const T: usize> Polynomial<C, T> {
    /// Generate a random polynomial of degree `T - 1` with `T` coefficients.
    ///
    /// Returns a new [`Polynomial`] instance, with inner type `[C::Scalar; T]`.
    #[must_use]
    pub fn generate() -> Self {
        let coefficients: [C::Scalar; T] = array::from_fn(|_| C::random_scalar());

        Self(coefficients)
    }

    /// Evaluate the polynomial at a given point `x`.
    ///
    /// Returns the scalar `k`, where `k = f(x)`.
    pub fn eval(&self, x: &C::Scalar) -> C::Scalar {
        let mut sum: C::Scalar = self.0[0].clone();
        let mut power = C::Scalar::one();

        for v in self.0.iter().skip(1) {
            power = power.mul(x);
            sum = sum.add(&v.mul(&power));
        }

        sum
    }
}

/**
 * The set of verifiable shares produced by one dealer in the DKG protocol.
 *
 * A [`DealerShares`] contains `P` shares for each of the `P` participants, together
 * with the dealer's `T` checking values. The set of *all* shares and checking
 * values for a protocol execution would be of type `[DealerShares; P]`
 *
 * # Examples
 *
 * ```
 * use std::array;
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::dkgd::dealer::{Dealer, DealerShares};
 *
 * const P: usize = 3;
 * const T: usize = 2;
 * const W: usize = 2;
 *
 * // Generates `P` shares for threshold `T`
 * let dealer: Dealer<RCtx, T, P> = Dealer::generate();
 * let shares = dealer.get_verifiable_shares();
 * ```
 */
#[derive(Debug, Clone, VSerializable, PartialEq)]
pub struct DealerShares<C: Context, const T: usize, const P: usize> {
    /// The shares distributed to each participant, offset by -1.
    /// For example, the share for participant 1 is stored at index 0.
    pub shares: [C::Scalar; P],
    /// The checking values for the dealer's shares.
    pub checking_values: [C::Element; T],
}

impl<C: Context, const T: usize, const P: usize> DealerShares<C, T, P> {
    /// Construct a new [`DealerShares`] instance from the given values.
    ///
    /// The standard way to compute the shares distributed by a [`Dealer`] is
    /// through the [`Dealer::get_verifiable_shares`] method.
    pub(crate) fn new(shares: [C::Scalar; P], checking_values: [C::Element; T]) -> Self {
        Self {
            shares,
            checking_values,
        }
    }

    /// Return the shares for the requested recipient as specified by the given [`ParticipantPosition`].
    ///
    /// This method will select the shares assigned to the required recipient from the set
    /// of all shares computed by the [`Dealer`].
    #[allow(clippy::missing_panics_doc)]
    pub fn for_recipient(&self, recipient: &ParticipantPosition<P>) -> VerifiableShare<C, T> {
        // ParticipantPosition value is guaranteed to be in the range 1..=P
        #[allow(clippy::arithmetic_side_effects)]
        let index: usize = (recipient.0 - 1)
            .try_into()
            .expect("ParticipantPosition(u32) < usize::MAX");
        VerifiableShare::new(self.shares[index].clone(), self.checking_values.clone())
    }
}

/**
 * One verifiable share distributed by one dealer to one recipient, in the DKG protocol.
 *
 * A [`VerifiableShare`] contains a secret scalar and the dealer's `T` checking values
 * necessary to verify the correctness of the share. The secret share of the joint public
 * key held by a recipient is the sum of the `P` secret scalars it receives from all
 * dealers (participants), including itself.
 *
 * * # Examples
 *
 * ```
 * use std::array;
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::dkgd::dealer::{Dealer, DealerShares, VerifiableShare};
 * use cryptography::dkgd::recipient::ParticipantPosition;
 *
 * const P: usize = 3;
 * const T: usize = 2;
 * const W: usize = 2;
 *
 * // Generates `P` shares for threshold `T`
 * let dealer: Dealer<RCtx, T, P> = Dealer::generate();
 * let shares = dealer.get_verifiable_shares();
 * // Get the shares for participant 1
 * let position = ParticipantPosition(1);
 * let shares: VerifiableShare<RCtx, T> = shares.for_recipient(&position);
 * ```
 */
#[derive(Debug, VSerializable)]
pub struct VerifiableShare<C: Context, const T: usize> {
    /// the secret share as a raw scalar
    pub value: C::Scalar,
    /// the checking values for the dealer's shares
    pub checking_values: [C::Element; T],
}

impl<C: Context, const T: usize> VerifiableShare<C, T> {
    /// Construct a new [`VerifiableShare`] from the given values.
    ///
    /// The standard way to obtain verifiable shares for some recipient `P` is through
    /// the [`Dealer::get_verifiable_shares`] method combined with the [`DealerShares::for_recipient`]
    /// method.
    pub fn new(value: C::Scalar, checking_values: [C::Element; T]) -> Self {
        Self {
            value,
            checking_values,
        }
    }
}
