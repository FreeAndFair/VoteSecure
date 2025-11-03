// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! A cryptographic context instantiates a set of interdependent functionalities
//! suitable for some application.

use rand::rngs::OsRng;

use crate::groups::P256Group;
use crate::groups::Ristretto255Group;
use crate::traits::groups::CryptographicGroup;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::utils::hash::Hasher;
use crate::utils::rng::Rng;
use crate::utils::serialization::{FSer, VSer};
use crate::utils::signatures::Ed25519;
use crate::utils::signatures::SignatureScheme;

/**
 * A cryptographic context instantiates a set of interdependent functionalities
 * suitable for some application.
 *
 * Provides
 * - An underlying [curve arithmetic group][`crate::traits::groups::CryptographicGroup`],
 *   with [elements][`crate::traits::groups::GroupElement`] and
 *   [scalars][`crate::traits::groups::GroupScalar`] and their respective
 *   [products][`crate::groups::productgroup`].
 *
 * - A [hashing function][`crate::utils::hash`], as instantiated by the curve group.
 *
 * - A [random number generator][`crate::utils::rng`].
 *
 * - A [digital signature scheme][`crate::utils::signatures`].
 *
 * Cryptographic functionalities such as [public key cryptosystems][`crate::cryptosystem`],
 * [zero knowledge proofs][`crate::zkp`] and [distributed key generation][`crate::dkgd`]
 * are built on top of this context.
 *
 * # Examples
 *
 * ```ignore
 * // Defines the Ristretto context, with
 * // - Ristreto255 as the underlying group
 * // - Sha512 as the hashing function
 * // - OsRng as the random number generator
 * // - Ed25519 as the digital signature scheme
 * pub struct RistrettoCtx;
 * impl Context for RistrettoCtx {
 *   type Element = <Self::G as CryptographicGroup>::Element;
 *   type Scalar = <Self::G as CryptographicGroup>::Scalar;
 *   type Hasher = <Self::G as CryptographicGroup>::Hasher;
 *   type Rng = OsRng;
 *   type SignatureScheme = Ed25519<Self::R>;
 *
 *   type G = Ristretto255Group;
 * }
 * ```
 */
pub trait Context: private::Sealed + std::fmt::Debug + PartialEq + Clone + 'static {
    /// The group element type.
    type Element: GroupElement<Scalar = Self::Scalar> + FSer + VSer + Clone + Send + Sync;

    /// The group scalar type.
    type Scalar: GroupScalar + FSer + VSer + Clone + Send + Sync + From<u32>;

    /// The hashing function.
    type Hasher: Hasher;

    /// The random number generator.
    type Rng: Rng;

    /// The digital signature scheme.
    type SignatureScheme: SignatureScheme<Self::Rng>;

    /// The underlying curve group.
    type G: CryptographicGroup<Element = Self::Element, Scalar = Self::Scalar, Hasher = Self::Hasher>;

    /// Returns a random number generator.
    #[inline]
    #[must_use]
    fn get_rng() -> Self::Rng {
        Self::Rng::rng()
    }

    /// Returns a hasher instance.
    #[inline]
    #[must_use]
    fn get_hasher() -> Self::Hasher {
        Self::Hasher::hasher()
    }

    /// Returns a random group element.
    #[inline]
    #[must_use]
    fn random_element() -> Self::Element {
        let mut rng = Self::get_rng();
        Self::G::random_element(&mut rng)
    }

    /// Returns a random scalar.
    #[inline]
    #[must_use]
    fn random_scalar() -> Self::Scalar {
        let mut rng = Self::get_rng();
        Self::G::random_scalar(&mut rng)
    }

    /// Returns the default group generator.
    #[inline]
    #[must_use]
    fn generator() -> Self::Element {
        Self::G::generator()
    }

    /// Returns a newly generated [signing key][`crate::utils::signatures::SignatureScheme::Signer`]
    /// to compute digital signatures.
    #[inline]
    #[must_use]
    fn gen_signing_key() -> <Self::SignatureScheme as SignatureScheme<Self::Rng>>::Signer {
        let mut rng = Self::get_rng();
        Self::SignatureScheme::gen_signing_key(&mut rng)
    }
}

/**
 * Defines the P256 context.
 *
 * Sets
 * - `p256` as the underlying curve.
 * - `Sha3-256` as the hashing function.
 * - `OsRng` as the random number generator.
 * - `Ed25519` as the digital signature scheme.
 */
#[derive(Debug, PartialEq, Clone, Hash)]
pub struct P256Ctx;

impl Context for P256Ctx {
    type Element = <Self::G as CryptographicGroup>::Element;
    type Scalar = <Self::G as CryptographicGroup>::Scalar;
    type Hasher = <Self::G as CryptographicGroup>::Hasher;
    type Rng = OsRng;
    type SignatureScheme = Ed25519<Self::Rng>;

    type G = P256Group;
}
/**
 * Defines the Ristretto context.
 *
 * Sets
 * - `Ristretto255` as the underlying group.
 * - `Sha3-512` as the hashing function.
 * - `OsRng` as the random number generator.
 * - `Ed25519` as the digital signature scheme.
 */
#[derive(Debug, PartialEq, Clone, Hash)]
pub struct RistrettoCtx;

impl Context for RistrettoCtx {
    type Element = <Self::G as CryptographicGroup>::Element;
    type Scalar = <Self::G as CryptographicGroup>::Scalar;
    type Hasher = <Self::G as CryptographicGroup>::Hasher;
    type Rng = OsRng;
    type SignatureScheme = Ed25519<Self::Rng>;

    type G = Ristretto255Group;
}

/// Seals the [Context] trait to prevent external implementations.
mod private {
    /// Sealed traits implement this.
    #[allow(unnameable_types)]
    pub trait Sealed {}
}

impl private::Sealed for RistrettoCtx {}
impl private::Sealed for P256Ctx {}
