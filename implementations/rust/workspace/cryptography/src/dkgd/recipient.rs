// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Joint-Feldman distributed key generation: recipient

#![allow(clippy::type_complexity)]
use crate::context::Context;
use crate::cryptosystem::elgamal::PublicKey;
use crate::cryptosystem::elgamal::{Ciphertext, KeyPair};
use crate::dkgd::dealer::VerifiableShare;
use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::utils::error::Error;
use crate::zkp::dlogeq::DlogEqProof;
use std::array;
use vser_derive::VSerializable;

/**
 * A recipient in the Joint-Feldman distributed key generation (DKG) protocol.
 *
 * * NOTE: this API does not represent private shares as encrypted values.
 *   In the messaging layer, private shares should be encrypted with the recipient's
 *   public key.
 *
 * In the Joint-Feldman DKG, a recipient receives a secret share from each of the
 * `P` participants, including itself. The recipient must verify that these shares
 * are correct using the dealer's public checking values.
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
 * At least `T` of the `P` recipients are needed to decrypt ciphertexts encrypted
 * with the joint public key. To do this, each recipient computes a partial decryption
 * of the ciphertext using their secret. These partial values are then combined.
 * Recipients can prove correctness of their partial decryptions with respect to their
 * verification key, using an equality of discrete logs proof. The correctness of the
 * aggregated decrypted value is verifiable from the partial decryptions, which
 * are public data.
 *
 * See `EVS`: Protocol 16.20
 *
 * See also [Dealer][`crate::dkgd::dealer::Dealer`]
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
 * // encrypt a message of width `W`
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
pub struct Recipient<C: Context, const T: usize, const P: usize> {
    /// This recipient's position in the protocol, from 1 to `P`
    position: ParticipantPosition<P>,
    /// This recipient's verification key, used to prove correctness of partial decryptions
    verification_key: C::Element,
    /// This recipient's share of the secret key, used to partially decrypt ciphertexts
    sk: C::Scalar,
}

impl<C: Context, const T: usize, const P: usize> Recipient<C, T, P> {
    /// compile-time checks for recipient const parameters
    const CHECK: () = {
        assert!(P < 100);
        assert!(P > 0);
        assert!(T <= P);
        assert!(T > 0);
    };

    /// Construct a `Recipient` with the given values.
    ///
    /// The standard way to create a `Recipient` is through the
    /// [`from_shares`][`Self::from_shares`] function, passing in this recipient's
    /// [shares][VerifiableShare] which are then verified. Use this constructor
    /// instead if the required argument values are available from a previously
    /// created `Recipient` as a result of a call to [`from_shares`][`Self::from_shares`].
    pub(crate) fn new(
        position: ParticipantPosition<P>,
        verification_key: C::Element,
        sk: C::Scalar,
    ) -> Self {
        #[allow(path_statements)]
        Self::CHECK;

        Self {
            position,
            verification_key,
            sk,
        }
    }

    /// Returns a reference to this recipient's verification key.
    pub fn get_verification_key(&self) -> &C::Element {
        &self.verification_key
    }

    /// Construct a `Recipient` from its shares.
    ///
    /// The supplied shares will be verified by this function, using
    /// the [dealer's][`crate::dkgd::dealer::Dealer`] checking values.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::dkgd::recipient::{Recipient, DkgPublicKey, ParticipantPosition};
    /// use cryptography::dkgd::dealer::{VerifiableShare, Dealer, DealerShares};
    /// use cryptography::context::RistrettoCtx as RCtx;
    /// use std::array;
    ///
    /// const P: usize = 3;
    /// const T: usize = 2;
    ///
    /// // simulates P dealers with threshold T
    /// let dealers: [Dealer<RCtx, T, P>; P] = array::from_fn(|_| Dealer::generate());
    ///
    //  // simulates P recipients with threshold T
    /// let recipients: [(Recipient<RCtx, T, P>, DkgPublicKey<RCtx, T>); P] = array::from_fn(|i| {
    ///     let position = ParticipantPosition::from_usize(i + 1);
    ///
    ///     // gather the shares for recipient at position from all dealers
    ///     let verifiable_shares: [VerifiableShare<RCtx, T>; P] = dealers
    ///         .clone()
    ///         .map(|d| d.get_verifiable_shares().for_recipient(&position));
    ///
    ///     // constructs the recipient, this includes verifying its shares
    ///     Recipient::from_shares(position, &verifiable_shares).unwrap()
    /// });
    ///
    /// ```
    /// Returns a tuple with the constructed `Recipient` and the protocol's joint public key
    ///
    /// # Parameters
    ///
    /// - `position`: the position of the recipient
    /// - `shares`: the set of shares assigned to this participant from all `P` dealers, in any order
    ///
    /// # Errors
    ///
    /// - `ShareVerificationFailed` if the shares do not verify.
    pub fn from_shares(
        position: ParticipantPosition<P>,
        shares: &[VerifiableShare<C, T>; P],
    ) -> Result<(Self, DkgPublicKey<C, T>), Error> {
        let (joint_pk, verification_key, sk) = Self::verify_shares(&position, shares)?;
        let inner = PublicKey { y: joint_pk };
        let joint_pk_ret = DkgPublicKey::from_public_key(&inner);

        let recipient = Self::new(position, verification_key, sk);

        Ok((recipient, joint_pk_ret))
    }

    /// Verify the given shares for a `Recipient` at `position`.
    ///
    /// The supplied shares will be verified by this function, using
    /// the [dealer's][`crate::dkgd::dealer::Dealer`] checking values.
    ///
    /// Returns a tuple with the protocol's [joint public key][`DkgPublicKey`], the
    /// recipient's verification key, and their secret key. If you are constructing
    /// a `Recipient` using [`from_shares`][`Self::from_shares`], you do
    /// not need to separately call this function, it is called automatically.
    ///
    /// # Parameters
    ///
    /// - `position`: the position of the recipient
    /// - `shares`: the set of shares assigned to this participant from all `P` dealers, in any order
    ///
    /// # Errors
    ///
    /// - `ShareVerificationFailed` if the shares do not verify.
    pub fn verify_shares(
        position: &ParticipantPosition<P>,
        shares: &[VerifiableShare<C, T>; P],
    ) -> Result<(C::Element, C::Element, C::Scalar), Error> {
        let mut verification_key = C::Element::one();
        let mut joint_pk = C::Element::one();
        let mut sk = C::Scalar::zero();

        for verifiable_share in shares {
            let (pk_factor, vk_factor, sk_summand) =
                Self::verify_share(verifiable_share, position)?;
            joint_pk = joint_pk.mul(&pk_factor);
            verification_key = verification_key.mul(&vk_factor);
            sk = sk.add(&sk_summand);
        }

        Ok((joint_pk, verification_key, sk))
    }

    /// Compute the verification key for a `Recipient` at `position`.
    ///
    /// # Parameters
    ///
    /// - `position`: the position of the recipient
    /// - `all_checking_values`: an array of checking values provided by each of `P` dealers, in any dealer order
    ///
    /// Allows computing a verification key without constructing a `Recipient`,
    /// using the checking values for all dealers.
    pub fn verification_key(
        position: &ParticipantPosition<P>,
        all_checking_values: &[[C::Element; T]; P],
    ) -> C::Element {
        let mut verification_key = C::Element::one();

        for cv in all_checking_values {
            let vk_factor = Self::vk_factor(cv, position);
            verification_key = verification_key.mul(&vk_factor);
        }

        verification_key
    }

    /// Compute the joint public key.
    ///
    /// # Parameters
    ///
    /// - `all_checking_values`: an array of checking values provided by each of `P` dealers, in any dealer order
    ///
    /// Allows computing the joint public key without constructing a `Recipient`,
    /// using the checking values for all dealers.
    pub fn joint_public_key(all_checking_values: &[[C::Element; T]; P]) -> DkgPublicKey<C, T> {
        let mut joint_public_key = C::Element::one();

        for cv in all_checking_values {
            joint_public_key = joint_public_key.mul(&cv[0]);
        }
        let inner = PublicKey::new(joint_public_key);
        DkgPublicKey::from_public_key(&inner)
    }

    /// Compute this recipient's partial decryptions for the given ciphertexts.
    ///
    /// At least `T` partial decryptions are needed to decrypt ciphertexts encrypted with the
    /// DKG's joint public key. Partial decryptions can be combined to compute the plaintext using the
    /// [`combine`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::array;
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    /// use cryptography::groups::ristretto255::RistrettoElement;
    /// use cryptography::dkgd::dealer::{VerifiableShare, Dealer};
    /// use cryptography::dkgd::recipient::{combine, Recipient, DkgPublicKey, ParticipantPosition, DecryptionFactor};
    ///
    /// const P: usize = 3;
    /// const T: usize = 2;
    /// const W: usize = 2;
    ///
    /// let dealers: [Dealer<RCtx, T, P>; P] = array::from_fn(|_| Dealer::generate());
    ///
    /// let recipients: [(Recipient<RCtx, T, P>, DkgPublicKey<RCtx, T>); P] = array::from_fn(|i| {
    ///    let position = ParticipantPosition::from_usize(i + 1);
    ///
    ///    let verifiable_shares: [VerifiableShare<RCtx, T>; P] = dealers
    ///        .clone()
    ///        .map(|d| d.get_verifiable_shares().for_recipient(&position));
    ///
    ///    Recipient::from_shares(position, &verifiable_shares).unwrap()
    /// });
    ///
    /// let (recipient, pk) = &recipients[0];
    /// let message: [RistrettoElement; W] = array::from_fn(|_| RCtx::random_element());
    /// let encrypted = vec![pk.encrypt(&message)];
    ///
    /// let verification_keys: [RistrettoElement; T] =
    ///     array::from_fn(|i| recipients[i].0.get_verification_key().clone());
    ///
    /// // each recipient computes their partial decryption, which includes a proof of correctness
    /// let dfactors: [Vec<DecryptionFactor<RCtx, P, W>>; P] =
    ///     recipients.map(|r| r.0.decryption_factor(&encrypted, &vec![]).unwrap());
    ///
    /// // select the first T decryption factors
    /// let threshold: &[Vec<DecryptionFactor<RCtx, P, W>>; T] =
    ///     dfactors[0..T].try_into().expect("slice matches array: T == T");
    ///
    /// // combine the decryption factors into the plaintext
    /// let decrypted = combine(&encrypted, &threshold, &verification_keys, &vec![]).unwrap();
    ///
    /// assert!(message == decrypted[0]);
    /// ```
    ///
    /// # Parameters
    ///
    /// - `ciphertexts`: the ciphertexts to decrypt
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`DlogEqProof`] computation returns error
    ///
    /// Returns a vector of [`DecryptionFactor`]'s corresponding to the input ciphertexts; this
    /// struct contains this recipient's partial decryption together with a proof of correctness.
    pub fn decryption_factor<const W: usize>(
        &self,
        ciphertexts: &[DkgCiphertext<C, W, T>],
        proof_context: &[u8],
    ) -> Result<Vec<DecryptionFactor<C, P, W>>, Error> {
        let ret: Result<Vec<DecryptionFactor<C, P, W>>, Error> = ciphertexts
            .iter()
            .map(|c| {
                let dfactor = c.u().dist_exp(&self.sk);

                let g = C::generator();
                let proof = DlogEqProof::<C, W>::prove(
                    &self.sk,
                    &g,
                    &self.verification_key,
                    c.u(),
                    &dfactor,
                    proof_context,
                )?;

                Ok(DecryptionFactor::new(dfactor, proof, self.position.clone()))
            })
            .collect();

        ret
    }

    /// Compute a factor of the verification key for a `Recipient` at `position`.
    ///
    /// # Parameters
    ///
    /// - `checking_values`: the checking values provided by the dealer
    /// - `position`: the position of the recipient
    ///
    /// This function is used during share [verification][`Self::verify_share`].
    fn vk_factor(
        checking_values: &[C::Element; T],
        position: &ParticipantPosition<P>,
    ) -> C::Element {
        let exponents: [C::Scalar; T] = array::from_fn(|i| {
            let exp: u32 = i.try_into().expect("T <= P < 100 < u32::MAX");
            let exp = position.0.pow(exp);
            exp.into()
        });
        let big_a_n_j = checking_values.exp(&exponents);

        big_a_n_j
            .iter()
            .fold(C::Element::one(), |acc, next| acc.mul(next))
    }

    /// Verify a single share for a `Recipient` at `position`.
    ///
    /// Returns a tuple with the public key factor, verification key factor,
    /// and secret key summand if the share is valid.
    ///
    /// # Parameters
    ///
    /// - `verifiable_share`: the share to verify
    /// - `position`: the position of the recipient
    ///
    /// # Errors
    ///
    /// - `ShareVerificationFailed` if the shares do not verify.
    fn verify_share(
        verifiable_share: &VerifiableShare<C, T>,
        position: &ParticipantPosition<P>,
    ) -> Result<(C::Element, C::Element, C::Scalar), Error> {
        let g = C::generator();
        let share = &verifiable_share.value;
        let checking_values = &verifiable_share.checking_values;
        let lhs = g.exp(share);
        let rhs = Self::vk_factor(checking_values, position);

        if lhs != rhs {
            return Err(Error::ShareVerificationFailed(
                "Failed to verify share".into(),
            ));
        }

        // pk_factor, vk_factor, sk_summand
        Ok((checking_values[0].clone(), rhs, share.clone()))
    }
}

/**
 * A partial decryption of an `ElGamal` ciphertext.
 *
 * Contains the partial decryption of the ciphertext together with a
 * proof of correctness. At least `T` [`DecryptionFactor`]'s are needed
 * to decrypt ciphertexts encrypted with the joint public key. These
 * decryption factors are combined to compute the plaintext using the
 * [`combine`] function.
 */
#[derive(Debug, Clone, VSerializable, PartialEq)]
pub struct DecryptionFactor<C: Context, const P: usize, const W: usize> {
    /// The partial decryption of the ciphertext
    pub value: [C::Element; W],
    /// The proof of decryption correctness
    pub proof: DlogEqProof<C, W>,
    /// The position of the participant who computed this partial decryption
    pub source: ParticipantPosition<P>,
}

impl<C: Context, const P: usize, const W: usize> DecryptionFactor<C, P, W> {
    /// Constructs a new [`DecryptionFactor`] from the given values.
    ///
    /// The standard way to compute decryption factors is through the [`Recipient::decryption_factor`] method,
    /// passing in the ciphertext to be partially decrypted.
    pub(crate) fn new(
        value: [C::Element; W],
        proof: DlogEqProof<C, W>,
        source: ParticipantPosition<P>,
    ) -> Self {
        Self {
            value,
            proof,
            source,
        }
    }
}

/**
 * The joint public key computed as output of the Joint-Feldman DKG protocol.
 *
 * This type is a newtype wrapper around a plain `ElGamal` public key, parameterized by
 * the threshold `T`. Ciphertexts encrypted with this joint public key will require
 * a threshold `T` of participants to decrypt.
 */
#[derive(Debug, VSerializable, PartialEq, Clone)]
pub struct DkgPublicKey<C: Context, const T: usize> {
    /// the underlying `ElGamal` public key
    pub inner: PublicKey<C>,
}

impl<C: Context, const T: usize> DkgPublicKey<C, T> {
    /// Constructs a new [`DkgPublicKey`] from the given `ElGamal` public key.
    pub fn from_public_key(public_key: &PublicKey<C>) -> Self {
        let inner = public_key.clone();
        Self { inner }
    }

    /// Constructs a new [`DkgPublicKey`] from the given `ElGamal` keypair.
    pub fn from_keypair(keypair: &KeyPair<C>) -> Self {
        let inner = PublicKey {
            y: keypair.pkey.y.clone(),
        };
        Self { inner }
    }

    /// Encrypts a message and returns a [`DkgCiphertext`], a ciphertext parameterized by `T`.
    ///
    /// See [`elgamal::PublicKey::encrypt`][`crate::cryptosystem::elgamal::PublicKey::encrypt`]
    pub fn encrypt<const W: usize>(&self, message: &[C::Element; W]) -> DkgCiphertext<C, W, T> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; W]>::random(&mut rng);
        self.encrypt_with_r(message, &r)
    }

    /// Encrypts a message into a [`DkgCiphertext`], a ciphertext parameterized by `T`.
    ///
    /// See [`elgamal::PublicKey::encrypt_with_r`][`crate::cryptosystem::elgamal::PublicKey::encrypt_with_r`]
    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> DkgCiphertext<C, W, T> {
        DkgCiphertext::<C, W, T>(self.inner.encrypt_with_r(message, r))
    }
}

/**
 * A newtype around a plain `ElGamal` ciphertext, parameterized by the threshold `T`.
 *
 * Ciphertexts can be partially decrypted using the [`Recipient::decryption_factor`] method,
 * which will partially decrypt this ciphertext to produce a [`DecryptionFactor`]. Given
 * `T` decryption factors, the plaintext can be computed using the [`combine`]
 * function.
 */
#[derive(Debug, VSerializable, PartialEq)]
pub struct DkgCiphertext<C: Context, const W: usize, const T: usize>(pub Ciphertext<C, W>);
impl<C: Context, const W: usize, const T: usize> DkgCiphertext<C, W, T> {
    /// Returns the `u` component of the ciphertext.
    pub fn u(&self) -> &[C::Element; W] {
        self.0.u()
    }
    /// Returns the `v` component of the ciphertext.
    pub fn v(&self) -> &[C::Element; W] {
        self.0.v()
    }
}

/**
 * A participant's position in the DKG protocol.
 *
 * Participants of the DKG protocol play both the role of [Dealer][`crate::dkgd::dealer::Dealer`]
 * and [Recipient][`Recipient`]. Each participant is assigned a 1-based index;
 * the first participant is assigned position 1, and so on up to participant `P`.
 */
#[derive(Clone, Debug, VSerializable, PartialEq)]
pub struct ParticipantPosition<const P: usize>(pub u32);

impl<const P: usize> ParticipantPosition<P> {
    /// Creates a new [`ParticipantPosition`] with the given 1-based index
    /// as a u32.
    ///
    /// The supplied position must be an integer greater than zero and
    /// smaller than or equal to `P`.
    ///
    /// # Panics
    ///
    /// Panics if the position is not in the range [1, P].
    #[must_use]
    pub fn new(position: u32) -> Self {
        #[crate::warning("Panics")]
        assert!(position > 0);
        assert!(position as usize <= P);

        ParticipantPosition(position)
    }
    /// Creates a new [`ParticipantPosition`] with the given 1-based index
    /// as a usize.
    ///
    /// The supplied position must be an integer greater than zero.
    /// The number of participants in a DKG protocol is usually below 10,
    /// and never exceeds the capacity of a u32; the conversion from
    /// usize to u32 cannot fail unless this assumption is violated.
    ///
    /// # Panics
    ///
    /// Panics if the position is not in the range [1, P].
    #[must_use]
    pub fn from_usize(position: usize) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        Self::new(position as u32)
    }
}

/// Combine the decryption factors and apply them to the ciphertext
/// to yield the plaintext.
///
/// # Parameters
///
/// - `ciphertexts`: the ciphertexts to decrypt, marked with matching `T` parameters
/// - `dfactors`: the decryption factors (partial decryptions) for the `T` participants
/// - `verification_keys`: the verification keys for the `T` participants
/// - `context`: proof context label (ZKP CONTEXT)
///
/// NOTE: It is the callers responsibility to ensure that the `dfactors` and `verification_keys`
/// correspond to each other at the same indices: the dfactor at index `i` must be computed by the
/// participant whose verification key is at index `i`.
///
/// This function includes verification of partial decryptions correctness.
///
/// # Errors
///
/// - `HashToElementError` if any challenge generation for [`DlogEqProof`] verification returns error
/// - `DecryptProofFailed` if any of the decryption proofs fail to verify.
pub fn combine<C: Context, const T: usize, const P: usize, const W: usize>(
    ciphertexts: &[DkgCiphertext<C, W, T>],
    dfactors: &[Vec<DecryptionFactor<C, P, W>>; T],
    verification_keys: &[C::Element; T],
    proof_context: &[u8],
) -> Result<Vec<[C::Element; W]>, Error> {
    // get the participants
    let present: [ParticipantPosition<P>; T] = array::from_fn(|i| dfactors[i][0].source.clone());
    let mut divisors_acc: Vec<[C::Element; W]> = vec![<[C::Element; W]>::one(); ciphertexts.len()];

    // ensure uniqueness for dfactors and verification_keys
    // let vk_set = HashSet::<C::Element>::from_iter(verification_keys.clone().into_iter());
    // It is not easy to construct a set for [Vec<DecryptionFactor<C, P, W>>]
    // let dfactors_set = HashSet::<Vec<DecryptionFactor<C, P, W>>>::from_iter(dfactors.clone().into_iter());
    #[crate::warning("Ensure that both dfactors and verification_keys are unique.")]
    for (i, dfactor) in dfactors.iter().enumerate() {
        let iter = dfactor.iter().zip(ciphertexts.iter());
        let lagrange = lagrange::<C, T, P>(&dfactor[0].source, &present);

        let c_lambda = iter.map(|(df, c)| {
            let g = C::generator();
            let proof_ok =
                df.proof
                    .verify(&g, &verification_keys[i], c.u(), &df.value, proof_context)?;

            if proof_ok {
                Ok(df.value.dist_exp(&lagrange))
            } else {
                Err(Error::DecryptProofFailed(
                    "Failed to verify decryption proof".into(),
                ))
            }
        });

        let next: Result<Vec<[C::Element; W]>, Error> = divisors_acc
            .iter()
            .zip(c_lambda)
            .map(|(divisor, c_lambda)| {
                let c_lambda = c_lambda?;

                Ok(c_lambda.mul(divisor))
            })
            .collect();

        divisors_acc = next?;
    }

    let ret: Result<Vec<[C::Element; W]>, Error> = divisors_acc
        .iter()
        .zip(ciphertexts.iter())
        .map(|(d, c)| {
            let ret = c.v().mul(&d.inv());

            Ok(ret)
        })
        .collect();

    ret
}

#[crate::warning("Rustdoc needs a reference to lagrange coeff. calculation")]
/// Compute the Lagrange coefficient for the given participant.
///
/// # Parameters
///
/// - `position`: the participant for whom to compute the Lagrange coefficient
/// - `present`: the set of participants currently present (those selected for decryption), in any order
///
/// For participant j in a set of participants K, the Lagrange coefficient
/// is computed as:
///
/// `lambda_j` = \prod_{j \neq K} \frac{k}{k - j}
pub(crate) fn lagrange<C: Context, const T: usize, const P: usize>(
    position: &ParticipantPosition<P>,
    present: &[ParticipantPosition<P>; T],
) -> C::Scalar {
    let mut numerator = C::Scalar::one();
    let mut denominator = C::Scalar::one();
    let position_exp: C::Scalar = position.0.into();

    for p in present {
        if p.0 == position.0 {
            continue;
        }

        let present_exp: C::Scalar = p.0.into();
        let diff_exp = present_exp.sub(&position_exp);

        numerator = numerator.mul(&present_exp);
        denominator = denominator.mul(&diff_exp);
    }

    numerator.mul(
        &denominator
            .inv()
            .expect("denominator != 0: the denominator is a product of non-zero elements"),
    )
}
