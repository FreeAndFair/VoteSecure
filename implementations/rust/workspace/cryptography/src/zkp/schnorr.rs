// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Schnorr proof of knowledge of discrete logarithm.

use crate::context::Context;
use crate::traits::groups::CryptographicGroup;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::utils::error::Error;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable;

/**
 * Schnorr proof of knowledge of discrete logarithm.
 *
 * Given public values `y` and `g`, and a secret `secret_x`
 * proves knowledge of `secret_x` such that `y = g^secret_x`
 *
 * See `EVS`: Protocol 10.1
 *
 * # Examples
 * ```
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::traits::groups::GroupElement;
 * use cryptography::zkp::schnorr::SchnorrProof;
 *
 * let g = RCtx::generator();
 * let secret_x = RCtx::random_scalar();
 * let public_y = g.exp(&secret_x);
 *
 * // Set to some relevant context value
 * let proof_context = &[];
 * let proof = SchnorrProof::<RCtx>::prove(&g, &public_y, &secret_x, proof_context).unwrap();
 *
 * let ok = proof.verify(&g, &public_y, proof_context).unwrap();
 * assert!(ok);
 * ```
 *
 */
#[derive(Debug, VSerializable, PartialEq)]
pub struct SchnorrProof<C: Context> {
    /// Prover commitment
    pub(crate) big_a: C::Element,
    /// Challenge response
    pub(crate) k: C::Scalar,
}

impl<C: Context> SchnorrProof<C> {
    /// Construct a Schnorr proof from the given values.
    pub(crate) fn new(big_a: C::Element, k: C::Scalar) -> Self {
        Self { big_a, k }
    }

    /// Prove knowledge of the discrete logarithm `secret_x` for `y = g^secret_x`
    ///
    /// # Parameters
    ///
    /// - `g`: The group element base, public
    /// - `y`: The group element `y` = `g^secret_x`, public
    /// - `secret_x`: The secret scalar
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns a [`SchnorrProof`] instance.
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        g: &C::Element,
        y: &C::Element,
        secret_x: &C::Scalar,
        proof_context: &[u8],
    ) -> Result<SchnorrProof<C>, Error> {
        let a = C::random_scalar();
        let big_a = g.exp(&a);

        let (input, dsts) = Self::challenge_input(g, y, &big_a, proof_context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let k = a.add(&v.mul(secret_x));

        Ok(Self::new(big_a, k))
    }

    /// Verify this Schnorr proof of knowledge
    ///
    /// # Parameters
    ///
    /// - `g`: The group element base
    /// - `y`: The group element value
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        &self,
        g: &C::Element,
        y: &C::Element,
        proof_context: &[u8],
    ) -> Result<bool, Error> {
        let big_a = &self.big_a;
        let k = &self.k;

        let (input, dsts) = Self::challenge_input(g, y, big_a, proof_context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let g_k = C::G::generator().exp(k);
        let y_v = y.exp(&v);
        let y_v_big_a = y_v.mul(big_a);

        Ok(y_v_big_a.equals(&g_k))
    }

    /// Domain separation tags for the challenge input
    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS: [&[u8]; 4] = [b"g", b"public_y", b"big_a", b"schnorr_context"];
    /// Computes the challenge input for the Schnorr proof
    ///
    /// # Params
    ///
    /// - `g`: The group element base
    /// - `y`: The group element value
    /// - `big_a`: The group element commitment
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// Returns byte arrays for input values and domain separation tags.
    /// These values will be passed to the hash function to compute
    /// the challenge.
    fn challenge_input(
        g: &C::Element,
        y: &C::Element,
        big_a: &C::Element,
        context: &[u8],
    ) -> ([Vec<u8>; 4], [&'static [u8]; 4]) {
        let a = [g.ser(), y.ser(), big_a.ser(), context.to_vec()];

        (a, Self::DS_TAGS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_schnorr_proof_valid_ristretto() {
        test_schnorr_proof_valid::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_invalid_ristretto() {
        test_schnorr_proof_invalid::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_serialization_ristretto() {
        test_schnorr_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_valid_p256() {
        test_schnorr_proof_valid::<PCtx>();
    }

    #[test]
    fn test_schnorr_proof_serialization_p256() {
        test_schnorr_proof_serialization::<PCtx>();
    }

    #[test]
    fn test_schnorr_proof_invalid_p256() {
        test_schnorr_proof_invalid::<PCtx>();
    }

    fn test_schnorr_proof_valid<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x, &[]).unwrap();
        assert!(
            proof.verify(&g, &public_y, &[]).unwrap(),
            "Verification of a valid proof should succeed"
        );
    }

    fn test_schnorr_proof_serialization<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x, &[]).unwrap();

        let proof_bytes = proof.ser_f();
        assert_eq!(proof_bytes.len(), SchnorrProof::<Ctx>::size_bytes());

        let parsed_proof_result = SchnorrProof::<Ctx>::deser_f(&proof_bytes);
        assert!(parsed_proof_result.is_ok());
        let parsed_proof = parsed_proof_result.unwrap();

        assert!(
            parsed_proof.verify(&g, &public_y, &[]).unwrap(),
            "Verification of a parsed valid proof should succeed"
        );

        assert_eq!(proof.big_a, parsed_proof.big_a);
        assert_eq!(proof.k, parsed_proof.k);
    }

    fn test_schnorr_proof_invalid<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x, &[]).unwrap();

        let original_k = proof.k;
        let one = <Ctx as Context>::Scalar::one();
        let tampered_k = original_k.add(&one);

        let tampered_proof = SchnorrProof::<Ctx>::new(proof.big_a, tampered_k);

        assert!(
            !tampered_proof.verify(&g, &public_y, &[]).unwrap(),
            "Verification of a proof with tampered 's' should fail"
        );
    }
}
