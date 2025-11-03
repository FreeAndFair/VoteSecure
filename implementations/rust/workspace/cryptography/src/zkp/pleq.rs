// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Proof of equality plaintexts.

use crate::context::Context;
use crate::traits::groups::CryptographicGroup;
use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::traits::groups::ReplGroupOps;
use crate::traits::groups::ReplScalarOps;
use crate::utils::error::Error;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

/**
 * Proof of equality plaintexts.
 *
 * Given public values `y`, `g`, `z`, `u_b`, `v_b` `u_a` and
 * secrets `p` and `r` proves equality of plaintexts (`u_b`, `v_b`)
 * and (`u_a`, `v_b`). This proof is applied to ciphertexts
 * in the Naor-Yung encryption scheme.
 *
 * See `EVS`: Protocol 10.8
 *
 * See [`crate::cryptosystem::naoryung`]
 *
 * # Examples
 * ```
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::groups::ristretto255::RistrettoScalar;
 * use cryptography::traits::groups::GroupElement;
 * use cryptography::traits::groups::DistGroupOps;
 * use cryptography::zkp::dlogeq::DlogEqProof;
 * use cryptography::cryptosystem::naoryung::KeyPair;
 * use cryptography::zkp::pleq::PlEqProof;
 * use cryptography::traits::groups::GroupScalar;
 *
 * // This context that will be used to derive
 * // the Naor-Yung second public key, `z`
 * let keypair_context = &[];
 * let ny: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
 *
 * let msg = [RCtx::random_element(), RCtx::random_element()];
 * let mut rng = RCtx::get_rng();
 * let r = <[RistrettoScalar; 2]>::random(&mut rng);
 * // in a real application, the plaintext equality proof would be
 * // computed automatically by this function, here we compute
 * // the proof manually as well to demonstrate its usage
 * let ciphertext = ny.encrypt_with_r(&msg, &r, &[]).unwrap();
 * // Set to some relevant context value
 * let proof_context = &[];
 * let proof = PlEqProof::<RCtx, 2>::prove(
 *    &ny.pkey.pk_b,
 *    &ny.pkey.pk_a,
 *    &ciphertext.u_b,
 *    &ciphertext.v_b,
 *    &ciphertext.u_a,
 *    &r,
 *    proof_context).unwrap();
 *
 * let ok = proof.verify(&ny.pkey.pk_b,
 *    &ny.pkey.pk_a,
 *    &ciphertext.u_b,
 *    &ciphertext.v_b,
 *    &ciphertext.u_a,
 *    proof_context).unwrap();
 *
 * assert!(ok);
 * ```
 */
#[derive(Debug, Clone, VSer, PartialEq)]
pub struct PlEqProof<C: Context, const W: usize> {
    /// Prover commitment
    pub big_a: [[C::Element; W]; 2],
    /// Challenge response
    pub k: [C::Scalar; W],
}

impl<C: Context, const W: usize> PlEqProof<C, W> {
    /// Construct a proof of equality of plaintexts from the given values.
    pub fn new(big_a: [[C::Element; W]; 2], k: [C::Scalar; W]) -> Self {
        PlEqProof { big_a, k }
    }

    /// Prove equality of plaintexts for a Naor-Yung ciphertext.
    ///
    /// # Parameters
    ///
    /// - `y`: The Naor-Yung public key `y`
    /// - `z`: The Naor-Yung public key `z`
    /// - `u_b`: The Naor-Yung ciphertext component `u_b`, of width `W`
    /// - `v_b`: The Naor-Yung ciphertext component `v_b`, of width `W`
    /// - `u_a`: The Naor-Yung ciphertext component `u_a`, of width `W`
    /// - `r`: The random scalar used in the encryption, of width `W`
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns a [`PlEqProof`] instance.
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; W],
        v_b: &[C::Element; W],
        u_a: &[C::Element; W],
        r: &[C::Scalar; W],
        proof_context: &[u8],
    ) -> Result<PlEqProof<C, W>, Error> {
        let g = C::generator();
        let mut rng = C::get_rng();
        let a_prime = <[C::Scalar; W]>::random(&mut rng);
        let a = a_prime.mul(r);
        let big_a_g = g.repl_exp(&a);
        let big_a_z = z.repl_exp(&a);

        let big_a = [big_a_g, big_a_z];

        let (input, dsts) = Self::challenge_input(&g, y, z, u_b, v_b, u_a, &big_a, proof_context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let vr = v.repl_mul(r);
        let k = vr.add(&a);

        Ok(PlEqProof::new(big_a, k))
    }

    /// Verify this Schnorr proof of knowledge.
    ///
    /// - `y`: The Naor-Yung public key `y`
    /// - `z`: The Naor-Yung public key `z`
    /// - `u_b`: The Naor-Yung ciphertext component `u_b`, of width `W`
    /// - `v_b`: The Naor-Yung ciphertext component `v_b`, of width `W`
    /// - `u_a`: The Naor-Yung ciphertext component `u_a`, of width `W`
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation returns error
    ///
    /// Returns `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        &self,
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; W],
        v_b: &[C::Element; W],
        u_a: &[C::Element; W],
        context: &[u8],
    ) -> Result<bool, Error> {
        let g = C::generator();
        let (input, dsts) = Self::challenge_input(&g, y, z, u_b, v_b, u_a, &self.big_a, context);
        let input: Vec<&[u8]> = input.iter().map(Vec::as_slice).collect();
        let v = C::G::hash_to_scalar(&input, &dsts)?;

        let f_k = [g, z.clone()].map(|e| e.repl_exp(&self.k));

        let u_v = [u_b, u_a].map(|e| e.dist_exp(&v));

        let u_v_big_a = u_v.mul(&self.big_a);

        Ok(u_v_big_a.equals(&f_k))
    }

    /// Domain separation tags for the challenge input
    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS: [&[u8]; 8] = [
        b"g",
        b"y",
        b"z",
        b"u_b",
        b"v_b",
        b"u_a",
        b"big_a",
        b"pleq_context",
    ];

    /// Computes the challenge input for the plaintext equality proof.
    ///
    /// # Params
    ///
    /// - `g`: The generator element
    /// - `y`: The Naor-Yung public key `y`
    /// - `z`: The Naor-Yung public key `z`
    /// - `u_b`: The Naor-Yung ciphertext component `u_b`, of width `W`
    /// - `v_b`: The Naor-Yung ciphertext component `v_b`, of width `W`
    /// - `u_a`: The Naor-Yung ciphertext component `u_a`, of width `W`
    /// - `big_a`: The prover commitments, of width `W`
    /// - `proof_context`: proof context label (ZKP CONTEXT)
    ///
    /// Returns byte arrays for input values and domain separation tags.
    /// These values will be passed to the hash function to compute
    /// the challenge.
    #[allow(clippy::too_many_arguments)]
    fn challenge_input(
        g: &C::Element,
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; W],
        v_b: &[C::Element; W],
        u_a: &[C::Element; W],
        big_a: &[[C::Element; W]; 2],
        context: &[u8],
    ) -> ([Vec<u8>; 8], [&'static [u8]; 8]) {
        let a = [
            g.ser(),
            y.ser(),
            z.ser(),
            u_b.ser(),
            v_b.ser(),
            u_a.ser(),
            big_a.ser(),
            context.to_vec(),
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
    use crate::cryptosystem::naoryung::KeyPair;
    use crate::traits::groups::DistScalarOps;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_pleq_proof_valid_ristretto() {
        test_pleq_proof_valid::<RCtx>();
    }

    #[test]
    fn test_pleq_proof_valid_p256() {
        test_pleq_proof_valid::<PCtx>();
    }

    #[test]
    fn test_pleq_proof_serialization_ristretto() {
        test_pleq_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_pleq_proof_serialization_p256() {
        test_pleq_proof_serialization::<PCtx>();
    }

    fn test_pleq_proof_valid<Ctx: Context>() {
        let ny: KeyPair<Ctx> = KeyPair::generate(&vec![]).unwrap();

        let msg = [Ctx::random_element(), Ctx::random_element()];
        let mut rng = Ctx::get_rng();
        let r = <[Ctx::Scalar; 2]>::random(&mut rng);
        let ciphertext = ny.encrypt_with_r(&msg, &r, &vec![]).unwrap();

        let proof = PlEqProof::<Ctx, 2>::prove(
            &ny.pkey.pk_b,
            &ny.pkey.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
            &r,
            &vec![],
        )
        .unwrap();

        let ok = proof
            .verify(
                &ny.pkey.pk_b,
                &ny.pkey.pk_a,
                &ciphertext.u_b,
                &ciphertext.v_b,
                &ciphertext.u_a,
                &vec![],
            )
            .unwrap();

        assert!(ok);

        let original_k = proof.k;
        let tampered_k = original_k.dist_add(&Ctx::Scalar::one());

        let tampered_proof = PlEqProof::<Ctx, 2>::new(proof.big_a, tampered_k);

        let not_ok = tampered_proof
            .verify(
                &ny.pkey.pk_b,
                &ny.pkey.pk_a,
                &ciphertext.u_b,
                &ciphertext.v_b,
                &ciphertext.u_a,
                &vec![],
            )
            .unwrap();

        assert!(!not_ok);
    }

    fn test_pleq_proof_serialization<Ctx: Context>() {
        let ny: KeyPair<Ctx> = KeyPair::generate(&vec![]).unwrap();

        let msg = [Ctx::random_element(), Ctx::random_element()];
        let mut rng = Ctx::get_rng();
        let r = <[Ctx::Scalar; 2]>::random(&mut rng);
        let ciphertext = ny.encrypt_with_r(&msg, &r, &vec![]).unwrap();

        let proof = PlEqProof::<Ctx, 2>::prove(
            &ny.pkey.pk_b,
            &ny.pkey.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
            &r,
            &vec![],
        )
        .unwrap();
        let bytes = proof.ser_f();
        let proof_d = PlEqProof::<Ctx, 2>::deser_f(&bytes).unwrap();

        let ok = proof_d
            .verify(
                &ny.pkey.pk_b,
                &ny.pkey.pk_a,
                &ciphertext.u_b,
                &ciphertext.v_b,
                &ciphertext.u_a,
                &vec![],
            )
            .unwrap();

        assert!(ok);
    }
}
