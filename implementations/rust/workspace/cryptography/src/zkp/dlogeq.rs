// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Proof of equality of discrete logarithms.

use crate::context::Context;
use crate::traits::groups::CryptographicGroup;
use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::utils::error::Error;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

/**
 * Proof of equality of discrete logarithms.
 *
 * Given public values `y_0`, `g_0`, `y_1`, `g_1`, and a secret
 * `secret_x` proves equality of logarithms such that `y_0 = g_0^secret_x`
 * and `y_1 = g_1^secret_x`. The values `y_0` and `g_0` are of width 1,
 * whereas the values `y_1` and `g_1` are of arbitrary width `W`. This
 * is required to prove correctness of decryption in the Joint-Feldman
 * distributed [decryption][`crate::dkgd::recipient::Recipient::decryption_factor`]
 * protocol.
 *
 * See `EVS`: Protocol 10.3
 *
 * See [`Recipient::decryption_factor`][`crate::dkgd::recipient::Recipient::decryption_factor`]
 *
 * # Examples
 * ```
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::traits::groups::GroupElement;
 * use cryptography::traits::groups::DistGroupOps;
 * use cryptography::zkp::dlogeq::DlogEqProof;
 *
 * let mut rng = RCtx::get_rng();
 * let g = RCtx::generator();
 * let g_1 = <[RistrettoElement; 2]>::random(&mut rng);
 * let secret_x = RCtx::random_scalar();
 * let public_y_0 = g.exp(&secret_x);
 * let public_y_1 = g_1.dist_exp(&secret_x);
 *
 * // Set to some relevant context value
 * let proof_context = &[];
 * let proof = DlogEqProof::<RCtx, 2>::prove(&secret_x, &g, &public_y_0, &g_1, &public_y_1, proof_context).unwrap();
 *
 * let ok = proof.verify(&g, &public_y_0, &g_1, &public_y_1, proof_context).unwrap();
 * assert!(ok);
 * ```
 *
 */
#[derive(Debug, Clone, VSer, PartialEq)]
pub struct DlogEqProof<C: Context, const W: usize> {
    /// Commitment 1
    pub big_a_0: C::Element,
    /// Commitment 2, of width `W`
    pub big_a_1: [C::Element; W],
    /// Challenge response
    pub k: C::Scalar,
}

impl<C: Context, const W: usize> DlogEqProof<C, W> {
    /// Construct a discrete log equality proof from the given values.
    pub fn new(big_a_0: C::Element, big_a_1: [C::Element; W], k: C::Scalar) -> Self {
        DlogEqProof {
            big_a_0,
            big_a_1,
            k,
        }
    }

    /// Prove equality of discrete logarithms such that `y_0 = g_0^secret_x`
    /// and `y_1 = g_1^secret_x`.
    ///
    /// # Parameters
    ///
    /// - `g0`: The first group element base, public
    /// - `y0`: The first group element `y0` = `g0^secret_x`, public
    /// - `g1`: The second group element bases of width `W`, public
    /// - `y1`: The second group elements `y1` = `g1^secret_x` of width `W`, public
    /// - `secret_x`: The secret scalar
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// See also [`Recipient::decryption_factor`][`crate::dkgd::recipient::Recipient::decryption_factor`]
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns a [`DlogEqProof`] instance.
    pub fn prove(
        secret_x: &C::Scalar,
        g0: &C::Element,
        y0: &C::Element,
        g1: &[C::Element; W],
        y1: &[C::Element; W],
        proof_context: &[u8],
    ) -> Result<DlogEqProof<C, W>, Error> {
        let a = C::random_scalar();
        let big_a_0 = g0.exp(&a);
        let big_a_1 = g1.dist_exp(&a);

        let (input, dsts) =
            Self::challenge_input(g0, g1, y0, y1, &big_a_0, &big_a_1, proof_context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let vx = v.mul(secret_x);
        let k = a.add(&vx);
        Ok(Self::new(big_a_0, big_a_1, k))
    }

    /// Verify this proof of equality of discrete logarithms.
    ///
    /// # Parameters
    ///
    /// - `g0`: The first group element base
    /// - `y0`: The first group element value
    /// - `g1`: The second group element bases of width `W`
    /// - `y1`: The second group elements of width `W`
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// See also [`Recipient::decryption_factor`][`crate::dkgd::recipient::Recipient::decryption_factor`]
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        &self,
        g0: &C::Element,
        y0: &C::Element,
        g1: &[C::Element; W],
        y1: &[C::Element; W],
        proof_context: &[u8],
    ) -> Result<bool, Error> {
        let k = &self.k;

        let (input, dsts) =
            Self::challenge_input(g0, g1, y0, y1, &self.big_a_0, &self.big_a_1, proof_context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let y0_v = y0.exp(&v);
        let y0_v_big_a_0 = y0_v.mul(&self.big_a_0);
        let g0_k = g0.exp(k);
        let check1 = y0_v_big_a_0.equals(&g0_k);

        let y1_v = y1.dist_exp(&v);
        let y1_v_big_a_1 = y1_v.mul(&self.big_a_1);
        let g1_k = g1.dist_exp(k);
        let check2 = y1_v_big_a_1.equals(&g1_k);

        Ok(check1 && check2)
    }

    /// Domain separation tags for the challenge input
    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS: [&[u8]; 7] = [
        b"g0",
        b"g1",
        b"y0",
        b"y1",
        b"big_a_0",
        b"big_a_1",
        b"dlogeq_proof_context",
    ];

    /// Compute the challenge input for the discrete logarithm equality proof.
    ///
    /// # Params
    ///
    /// - `g0`: The first group element base
    /// - `y0`: The first group element value
    /// - `g1`: The second group element bases of width `W`
    /// - `y1`: The second group elements of width `W`
    /// - `big_a_0`: The first group element commitment
    /// - `big_a_1`: The second group element commitments of width `W`
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// Returns byte arrays for input values and domain separation tags.
    /// These values will be passed to the hash function to compute
    /// the challenge.
    fn challenge_input(
        g0: &C::Element,
        g1: &[C::Element; W],
        y0: &C::Element,
        y1: &[C::Element; W],
        big_a_0: &C::Element,
        big_a_1: &[C::Element; W],
        proof_context: &[u8],
    ) -> ([Vec<u8>; 7], [&'static [u8]; 7]) {
        let a = [
            g0.ser(),
            g1.ser(),
            y0.ser(),
            y1.ser(),
            big_a_0.ser(),
            big_a_1.ser(),
            proof_context.to_vec(),
        ];

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
    fn test_dlogeq_proof_valid_ristretto() {
        test_dlogeq_proof_valid::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_serialization_ristretto() {
        test_dlogeq_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_invalid_ristretto() {
        test_dlogeq_proof_invalid::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_valid_p256() {
        test_dlogeq_proof_valid::<PCtx>();
    }

    #[test]
    fn dlogeq_proof_serialization_p256() {
        test_dlogeq_proof_serialization::<PCtx>();
    }

    #[test]
    fn test_dlogeq_proof_invalid_p256() {
        test_dlogeq_proof_invalid::<PCtx>();
    }

    fn test_dlogeq_proof_valid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let g2 = Ctx::random_element();
        let g3 = Ctx::random_element();

        let public_y1 = g1.exp(&secret_x);
        let public_y2 = g2.exp(&secret_x);
        let public_y3 = g3.exp(&secret_x);

        let gn = [g2, g3];
        let public_yn = [public_y2, public_y3];

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::<Ctx, 2>::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![])
                .unwrap();
        assert!(
            proof
                .verify(&g1, &public_y1, &gn, &public_yn, &vec![])
                .unwrap(),
            "Verification of a valid DlogEqProof proof should succeed"
        );
    }

    fn test_dlogeq_proof_serialization<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let gn = [Ctx::random_element(), Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.dist_exp(&secret_x);

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]).unwrap();
        let proof_bytes = proof.ser_f();
        assert_eq!(proof_bytes.len(), DlogEqProof::<Ctx, 2>::size_bytes());

        let parsed_proof = DlogEqProof::<Ctx, 2>::deser_f(&proof_bytes).unwrap();
        assert!(
            parsed_proof
                .verify(&g1, &public_y1, &gn, &public_yn, &vec![])
                .unwrap(),
            "Verification of a parsed valid Chaum-Pedersen proof should succeed"
        );

        assert_eq!(proof.big_a_0, parsed_proof.big_a_0, "c1 should match");
        assert_eq!(proof.big_a_1, parsed_proof.big_a_1, "c1 should match");
        assert_eq!(proof.k, parsed_proof.k, "s should match");
    }

    fn test_dlogeq_proof_invalid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let gn = [Ctx::random_element(), Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.dist_exp(&secret_x);

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]).unwrap();

        let original_s = proof.k;
        let tampered_k = original_s.add(&Ctx::Scalar::one());
        let tampered_proof = DlogEqProof::<Ctx, 2>::new(proof.big_a_0, proof.big_a_1, tampered_k);
        assert!(
            !tampered_proof
                .verify(&g1, &public_y1, &gn, &public_yn, &vec![])
                .unwrap(),
            "Verification of a DlogEq proof with a tampered response 's' should fail"
        );
    }
}
