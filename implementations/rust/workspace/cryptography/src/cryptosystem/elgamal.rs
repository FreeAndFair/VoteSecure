// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! ElGamal cryptosystem

use crate::context::Context;
use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::traits::groups::ReplGroupOps;
use crate::utils::Error;
use vser_derive::VSerializable;

/**
 * An `ElGamal` key pair.
 *
 * This struct represents a key pair in the `ElGamal` encryption scheme,
 * including the secret scalar value and public group element.
 *
 * See `EVS`: Definition 11.15
 *
 * # Examples
 *
 * ```
 * use cryptography::cryptosystem::elgamal::KeyPair;
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 *
 * let keypair: KeyPair<RCtx> = KeyPair::generate();
 * let message = [RCtx::random_element(); 2];
 * let ciphertext = keypair.encrypt(&message);
 *
 * let decrypted = keypair.decrypt(&ciphertext);
 *
 * assert_eq!(message, decrypted);
 * ```
 */

#[derive(Debug, PartialEq, Clone, VSerializable)]
pub struct KeyPair<C: Context> {
    /// the private key as a raw group scalar
    pub skey: C::Scalar,
    /// the public key
    pub pkey: PublicKey<C>,
}

impl<C: Context> KeyPair<C> {
    /// Construct a new key pair with the given secret and public values.
    ///
    /// Use this function to create a key pair from existing secret and public keys.
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair.
    pub fn new(skey: C::Scalar, pkey: C::Element) -> KeyPair<C> {
        let pkey = PublicKey::new(pkey);
        KeyPair { skey, pkey }
    }
}

impl<C: Context> KeyPair<C> {
    /// Construct a new key pair, generating fresh key material.
    ///
    /// Use this function to generate a fresh key pair.
    /// Use [`KeyPair::new`] to instead create a key pair from existing secret and public keys.
    #[must_use]
    pub fn generate() -> Self {
        let skey = C::random_scalar();
        let pkey = C::generator().exp(&skey);
        let pkey = PublicKey::new(pkey);
        KeyPair { skey, pkey }
    }

    /// Encrypt the given message with this key pair and the given randomness.
    ///
    /// The message can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::KeyPair;
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// let ciphertext = keypair.encrypt_with_r(&message, &r);
    /// ```
    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> Ciphertext<C, W> {
        self.pkey.encrypt_with_r(message, r)
    }

    /// Encrypt the given message with this key pair.
    ///
    /// The message can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::KeyPair;
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// let ciphertext = keypair.encrypt(&message);
    /// ```
    pub fn encrypt<const W: usize>(&self, message: &[C::Element; W]) -> Ciphertext<C, W> {
        self.pkey.encrypt(message)
    }

    /// Decrypt the given ciphertext with this key pair.
    ///
    /// The input ciphertext can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::KeyPair;
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// let ciphertext = keypair.encrypt(&message);
    /// let decrypted = keypair.decrypt(&ciphertext);
    ///
    /// assert_eq!(message, decrypted);
    /// ```
    pub fn decrypt<const W: usize>(&self, message: &Ciphertext<C, W>) -> [C::Element; W] {
        decrypt::<C, W>(message.u(), message.v(), &self.skey)
    }

    /// Decrypt the given ciphertext with this key pair and the given randomness.
    ///
    /// The input ciphertext can have arbitrary width `W`.
    ///
    /// # Errors
    ///
    /// Decryption fails if the supplied randomness is not the exponent of the
    /// first part of the ciphertext.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::KeyPair;
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// let ciphertext = keypair.encrypt_with_r(&message, &r);
    ///
    /// let decrypted = keypair.decrypt_with_r(&ciphertext, &r).unwrap();
    /// assert_eq!(message, decrypted);
    /// ```
    pub fn decrypt_with_r<const W: usize>(
        &self,
        ciphertext: &Ciphertext<C, W>,
        r: &[C::Scalar; W],
    ) -> Result<[C::Element; W], Error> {
        self.pkey.decrypt_with_r(ciphertext, r)
    }
}

/**
 * An `ElGamal` public key.
 *
 * This struct represents a public key in the `ElGamal` encryption scheme.
 * It contains the group element 'y', which is used in the encryption
 * process.
 *
 * See `EVS`: Definition 11.15
 *
 * # Examples
 *
 * ```
 * use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 *
 * let keypair: KeyPair<RCtx> = KeyPair::generate();
 * let public_key: PublicKey<RCtx> = keypair.pkey;
 * let message = [RCtx::random_element(); 2];
 * let ciphertext = public_key.encrypt(&message);
 *
 * ```
 */
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicKey<C: Context> {
    /// the public key as a raw group element
    pub y: C::Element,
}
impl<C: Context> PublicKey<C> {
    /// Construct a new public key with the given public value.
    ///
    /// Use this function to create a public key from existing public value.
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair, including a public key.
    pub fn new(y: C::Element) -> Self {
        Self { y }
    }

    /// Encrypt the given message with this public key and the given randomness.
    ///
    /// The message can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// let ciphertext = public_key.encrypt_with_r(&message, &r);
    /// ```
    pub fn encrypt<const W: usize>(&self, message: &[C::Element; W]) -> Ciphertext<C, W> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; W]>::random(&mut rng);

        self.encrypt_with_r(message, &r)
    }

    /// Encrypt the given message with this public key and the given randomness.
    ///
    /// The message can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// let ciphertext = public_key.encrypt_with_r(&message, &r);
    /// ```
    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> Ciphertext<C, W> {
        let g = C::generator();

        let u = g.repl_exp(r);
        let v = self.y.repl_exp(r);
        let v = message.mul(&v);

        Ciphertext([u, v])
    }

    /// Decrypt the given ciphertext with this public key and the given randomness.
    ///
    /// The message can have arbitrary width `W`.
    ///
    /// # Errors
    ///
    /// Decryption fails if the supplied randomness is not the exponent of the
    /// first part of the ciphertext.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// let ciphertext = public_key.encrypt_with_r(&message, &r);
    ///
    /// let decrypted = keypair.decrypt_with_r(&ciphertext, &r).unwrap();
    /// assert_eq!(message, decrypted);
    /// ```
    pub fn decrypt_with_r<const W: usize>(
        &self,
        ciphertext: &Ciphertext<C, W>,
        r: &[C::Scalar; W],
    ) -> Result<[C::Element; W], Error> {
        let generator = C::generator();
        if generator.repl_exp(r) != *ciphertext.u() {
            return Err(Error::DecryptionError(
                "Invalid randomness for decryption".to_string(),
            ));
        }

        let v = self.y.repl_exp(r);
        let div = v.inv();

        Ok(ciphertext.0[1].mul(&div))
    }
}

/**
 * Decrypt a ciphertext using the given secret key.
 *
 * Computes the plaintext as `p = v * (u^-x) = v / u^x`.
 * This function operates on raw arrays. See also [`KeyPair::decrypt`] to
 * operate on [`Ciphertext`].
 */
#[inline]
pub fn decrypt<C: Context, const W: usize>(
    u: &[C::Element; W],
    v: &[C::Element; W],
    sk: &C::Scalar,
) -> [C::Element; W] {
    let u_pow_neg_x = u.dist_exp(&sk.neg());

    v.mul(&u_pow_neg_x)
}

/**
 * An `ElGamal` ciphertext.
 *
 * This struct represents a ciphertext in the `ElGamal` encryption scheme
 * as a pair of values (u, v). Each element of the ciphertext pair has an
 * arbitrary length of W group elements.
 *
 * See `EVS`: Definition 11.15
 *
 * # Examples
 *
 * ```
 * use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 *
 * let keypair: KeyPair<RCtx> = KeyPair::generate();
 * let public_key: &PublicKey<RCtx> = &keypair.pkey;
 * let message = [RCtx::random_element(); 2];
 * let ciphertext = public_key.encrypt(&message);
 *
 * // re-encryption leaves the ciphertext unchanged
 * let re_encrypted = ciphertext.re_encrypt(&[RCtx::random_scalar(); 2], &public_key.y);
 *
 * let decrypted = keypair.decrypt(&re_encrypted);
 *
 * assert_eq!(message, decrypted);
 * ```
 */
#[derive(Debug, PartialEq, Clone, VSerializable)]
pub struct Ciphertext<C: Context, const W: usize>(pub [[C::Element; W]; 2]);
impl<C: Context, const W: usize> Ciphertext<C, W> {
    /// Construct a ciphertext with given values `u` and `v`.
    ///
    /// Use [`KeyPair::encrypt`] or [`PublicKey::encrypt`] to encrypt
    /// a ciphertext from a message.
    pub fn new(u: [C::Element; W], v: [C::Element; W]) -> Self {
        Ciphertext([u, v])
    }

    /// Re-encrypt the ciphertext using a new randomness value `r_n` and a public key `pk`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair};
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// let message = [RCtx::random_element(); 2];
    /// let ciphertext = keypair.encrypt(&message);
    /// let re_encrypted = ciphertext.re_encrypt(&[RCtx::random_scalar(); 2], &public_key.y);
    /// let decrypted = keypair.decrypt(&re_encrypted);
    /// assert_eq!(message, decrypted);
    /// ```
    #[must_use]
    pub fn re_encrypt(&self, r_n: &[C::Scalar; W], pk: &C::Element) -> Self {
        let g = C::generator();
        // (g, y)^r
        let one = [g, pk.clone()].map(|v| v.repl_exp(r_n));
        let re_encrypted = self.0.mul(&one);

        Self(re_encrypted)
    }

    /// Obtain a reference to the first element of the ciphertext, `u`.
    pub fn u(&self) -> &[C::Element; W] {
        &self.0[0]
    }

    /// Obtain a reference to the second element of the ciphertext, `v`.
    pub fn v(&self) -> &[C::Element; W] {
        &self.0[1]
    }

    /// Apply the given function to each element of the ciphertext.
    ///
    /// Returns the values as raw arrays. Consumes this value.
    #[crate::warning("This function is not used")]
    pub fn map<F, U>(self, f: F) -> [U; 2]
    where
        F: FnMut([C::Element; W]) -> U,
    {
        self.0.map(f)
    }

    /// Apply the given function to each element of the ciphertext.
    ///
    /// Returns the values as raw arrays.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptography::cryptosystem::elgamal::{PublicKey, KeyPair, Ciphertext};
    /// use cryptography::context::Context;
    /// use cryptography::context::RistrettoCtx as RCtx;
    /// use cryptography::groups::ristretto255::RistrettoElement;
    /// use crate::cryptography::traits::groups::GroupElement;
    ///
    /// let keypair: KeyPair<RCtx> = KeyPair::generate();
    /// let message = [RCtx::random_element(); 2];
    /// let ciphertext = keypair.encrypt(&message);
    /// // multiply both values by the identity
    /// let identical = ciphertext.map_ref(|uv| {
    ///     uv.mul(&<[RistrettoElement; 2]>::one())
    /// });
    /// let identical = Ciphertext(identical);
    /// let decrypted = keypair.decrypt(&identical);
    /// assert_eq!(message, decrypted);
    /// ```
    pub fn map_ref<F, U>(&self, mut f: F) -> [U; 2]
    where
        F: FnMut(&[C::Element; W]) -> U,
    {
        std::array::from_fn(|i| {
            let uv = &self.0[i];
            f(uv)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::cryptosystem::elgamal;
    use crate::cryptosystem::elgamal::{Ciphertext, KeyPair};
    use crate::groups::Ristretto255Group;
    use crate::traits::groups::CryptographicGroup;
    use crate::traits::groups::GroupElement;
    use crate::traits::groups::GroupScalar;
    use crate::traits::groups::ReplGroupOps;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_keypair_serialization_ristretto() {
        test_keypair_serialization::<RCtx>();
    }

    #[test]
    fn test_keypair_serialization_p256() {
        test_keypair_serialization::<PCtx>();
    }

    #[test]
    fn test_elgamal_ristretto() {
        test_elgamal::<RCtx>();
    }

    #[test]
    fn test_elgamal_p256() {
        test_elgamal::<PCtx>();
    }

    #[test]
    fn test_elgamal_serialization_and_decryption_ristretto() {
        test_elgamal_serialization_and_decryption::<RCtx>();
    }

    #[test]
    fn test_elgamal_serialization_and_decryption_p256() {
        test_elgamal_serialization_and_decryption::<PCtx>();
    }

    fn test_keypair_serialization<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();

        let serialized = keypair.ser_f();
        assert_eq!(serialized.len(), KeyPair::<Ctx>::size_bytes());

        let deserialized = KeyPair::<Ctx>::deser_f(&serialized).unwrap();
        assert_eq!(keypair.pkey, deserialized.pkey);
        assert_eq!(keypair.skey, deserialized.skey);
    }

    fn test_elgamal<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);
        let decrypted_message = keypair.decrypt(&ciphertext);
        assert_eq!(message, decrypted_message);

        let x = Ctx::random_scalar();
        let pk = Ctx::G::g_exp(&x);
        let keypair = KeyPair::<Ctx>::new(x.clone(), pk.clone());
        let r = [Ctx::random_scalar(), Ctx::random_scalar()];

        let ciphertext = keypair.encrypt_with_r(&message, &r);
        let decrypted_message = keypair.decrypt(&ciphertext);
        assert_eq!(message, decrypted_message);

        // decrypt with standalone function
        let decrypted_message = elgamal::decrypt::<Ctx, 2>(ciphertext.u(), ciphertext.v(), &x);
        assert_eq!(message, decrypted_message);

        // decrypt with r
        let decrypted_message = keypair.decrypt_with_r(&ciphertext, &r).unwrap();
        assert_eq!(message, decrypted_message);

        // decrypt with wrong r
        let wrong_r = [Ctx::random_scalar(), Ctx::random_scalar()];
        let decrypted_message = keypair.decrypt_with_r(&ciphertext, &wrong_r);
        assert!(decrypted_message.is_err());

        // decrypt with r, manually
        let divisor = pk.repl_exp(&r).inv();
        let decrypted_message = divisor.mul(ciphertext.v());
        assert_eq!(message, decrypted_message);

        // decrypt with r * r2
        let one = [Ctx::Element::one(), Ctx::Element::one()];
        // g^r, pk^r
        let one_c = keypair.encrypt_with_r(&one, &r);
        let r2 = [Ctx::random_scalar(), Ctx::random_scalar()];
        // (g^r)^r2, (pk^r)^r2
        let one_c = one_c.map(|uv| uv.exp(&r2));
        // 1 / pk^(r * r2)
        let divisor: [<Ctx as Context>::Element; 2] = pk.repl_exp(&r.mul(&r2)).inv();
        let decrypted_message = divisor.mul(&one_c[1]);
        assert_eq!(one, decrypted_message);
    }

    #[test]
    fn test_elgamal_r_encryption() {
        let keypair = KeyPair::<RCtx>::generate();
        let message = [RCtx::random_element(), RCtx::random_element()];

        let r = [RCtx::random_scalar(), RCtx::random_scalar()];
        let ciphertext = keypair.encrypt_with_r(&message, &r);

        let encoded_rs = r.map(|s| Ristretto255Group::encode_scalar(&s).unwrap());

        let keypair2 = KeyPair::<RCtx>::generate();

        let encrypted_rs = encoded_rs.map(|es| keypair2.encrypt(&es));
        let decrypted_rs = encrypted_rs.map(|ct| keypair2.decrypt(&ct));
        let decoded_rs = decrypted_rs.map(|es| Ristretto255Group::decode_scalar(&es).unwrap());

        let decrypted_message = keypair.decrypt_with_r(&ciphertext, &decoded_rs).unwrap();
        assert_eq!(message, decrypted_message);
    }

    fn test_elgamal_serialization_and_decryption<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);

        let serialized_ct = ciphertext.ser_f();
        assert_eq!(serialized_ct.len(), Ciphertext::<Ctx, 2>::size_bytes());

        let deserialized_ct = Ciphertext::<Ctx, 2>::deser_f(&serialized_ct).unwrap();

        assert_eq!(ciphertext, deserialized_ct);

        let decrypted_message = keypair.decrypt(&deserialized_ct);
        assert_eq!(message, decrypted_message);
    }
}
