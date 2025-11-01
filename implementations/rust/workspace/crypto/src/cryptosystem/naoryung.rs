/*
 * Naor-Yung cryptosystem
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

use crate::context::Context;
use crate::cryptosystem::elgamal;
use crate::cryptosystem::elgamal::KeyPair as EGKeyPair;
use crate::traits::groups::CryptoGroup;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::traits::groups::ReplGroupOps;
use crate::utils::error::Error;
use crate::zkp::pleq::PlEqProof;
use vser_derive::VSerializable;

/**
 * A Naor-Yung key pair.
 *
 * This struct represents a key pair in the Naor-Yung encryption scheme,
 * including the secret scalar value and the two public group elements.
 * The secret key `w` for `pk_a = pk_b^w` is never computed; instead, the
 * value `pk_a` is derived from a random oracle, `pk_a = H(context)`.
 *
 * In the Naor-Yung encryption scheme, ciphertexts include a proof of
 * well-formedness. This proof must be verified before decryption.
 *
 * See `EVS`: Definition 11.31
 *
 * # Examples
 *
 * ```
 * use crypto::cryptosystem::naoryung::KeyPair;
 * use crypto::context::Context;
 * use crypto::context::RistrettoCtx as RCtx;
 *
 * // Set to some relevant context value
 * let keypair_context = &[];
 * let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
 * let message = [RCtx::random_element(); 2];
 * // Set to some relevant context value
 * let encryption_context = &[];
 * let ciphertext = keypair.encrypt(&message, encryption_context).unwrap();
 *
 * let decrypted = keypair.decrypt(&ciphertext, encryption_context).unwrap();
 *
 * assert_eq!(message, decrypted);
 * ```
 */
#[derive(Debug, PartialEq, VSerializable)]
pub struct KeyPair<C: Context> {
    /// the secret key x, for y = g^x
    pub sk_b: C::Scalar,
    /// the public values, y, z, for z = y^w
    ///
    /// The value w is never constructed, z is derived from a random oracle.
    pub pkey: PublicKey<C>,
}

impl<C: Context> KeyPair<C> {
    /// Construct a new key pair from an `ElGamal` key pair and a public key element.
    ///
    /// Use this function to create a key pair from an existing `ElGamal` key pair
    /// and public value.
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair.
    pub fn new(elgamal_keypair: &EGKeyPair<C>, pk_a: C::Element) -> Self {
        let sk_b = elgamal_keypair.skey.clone();
        let pk_b = elgamal_keypair.pkey.y.clone();
        let pkey = PublicKey { pk_b, pk_a };
        KeyPair { sk_b, pkey }
    }

    /// Augment an `ElGamal` key pair into a `Naor-Yung` key pair.
    ///
    /// Use this function to create a key pair from an existing `ElGamal` key pair;
    /// the value `pk_a` is derived from a random oracle, `pk_a = H(context)`.
    ///
    /// # Parameters
    ///
    /// - `elgamal_keypair`: The `ElGamal` keypair to augment
    /// - `context`: The context that will be used as input to the hash function to
    ///   derive `pk_a` (PK CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if hashing to an element to compute `pk_a` returns error
    ///
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair.
    pub fn augment(elgamal_keypair: &EGKeyPair<C>, context: &[u8]) -> Result<Self, Error> {
        let sk_b = elgamal_keypair.skey.clone();
        let pk_b = elgamal_keypair.pkey.y.clone();
        let pk_a = C::G::hash_to_element(&[context], &[b"naor_yung_public_key_a"]);
        let pk_a = pk_a?;
        let pkey = PublicKey { pk_b, pk_a };

        Ok(KeyPair { sk_b, pkey })
    }

    /// Construct a new key pair generating fresh key material.
    ///
    /// The value `pk_a` is derived from a random oracle, `pk_a = H(context)`.
    ///
    /// Use this function to generate a fresh key pair.
    /// Use [`KeyPair::new`] to instead create a key pair from an existing
    /// `ElGamal` key pair and public value.
    ///
    /// # Parameters
    ///
    /// - `context`: The context that will be used as input to the hash function to
    ///   derive `pk_a` (PK CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if hashing to an element to compute `pk_a` returns error
    pub fn generate(context: &[u8]) -> Result<Self, Error> {
        let elgamal_keypair = EGKeyPair::<C>::generate();
        let sk_b = elgamal_keypair.skey.clone();
        let pk_b = elgamal_keypair.pkey.y.clone();
        let pk_a = C::G::hash_to_element(&[context], &[b"naor_yung_public_key_a"]);
        let pk_a = pk_a?;
        let pkey = PublicKey { pk_b, pk_a };
        Ok(KeyPair { sk_b, pkey })
    }

    /// Encrypt the given message with this key pair and the given randomness.
    ///
    /// This function also computes the proof of well-formedness. The input message
    /// can have arbitrary width `W`.
    ///
    /// See `EVS`: Definition 11.31
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::KeyPair;
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = keypair.encrypt_with_r(&message, &r, encryption_context).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] computation returns error
    ///
    ///  # Parameters
    ///
    /// - `message`: The message to encrypt, of width `W`
    /// - `r`: The random values for the encryption, of width `W`
    /// - `context`: proof context label (ZKP CONTEXT)
    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
        context: &[u8],
    ) -> Result<Ciphertext<C, W>, Error> {
        self.pkey.encrypt_with_r(message, r, context)
    }

    /// Encrypt the given message with this key pair.
    ///
    /// This function also computes the proof of well-formedness. The input message
    /// can have arbitrary width `W`.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::KeyPair;
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = keypair.encrypt(&message, encryption_context).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] computation returns error
    ///
    ///  # Parameters
    ///
    /// - `message`: The message to encrypt, of width `W`
    /// - `context`: proof context label (ZKP CONTEXT)
    pub fn encrypt<const W: usize>(
        &self,
        message: &[C::Element; W],
        context: &[u8],
    ) -> Result<Ciphertext<C, W>, Error> {
        self.pkey.encrypt(message, context)
    }

    /// Strip this Naor-Yung ciphertext, returning the underlying plain `ElGamal` ciphertext.
    ///
    /// The strip function verifies the proof of well-formedness and returns
    /// the underlying plain `ElGamal` ciphertext, with only the encrypted message.
    ///
    /// See `EVS`: Definition 11.31
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::KeyPair;
    /// use crypto::cryptosystem::elgamal;
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = keypair.encrypt(&message, encryption_context).unwrap();
    ///
    /// // strip the Naor-Yung ciphertext to get the underlying elgamal ciphertext
    /// let stripped: elgamal::Ciphertext<RCtx, 2> = keypair.strip(ciphertext, encryption_context).unwrap();
    ///
    /// // decrypt using plain ElGamal decryption
    /// let decrypted = elgamal::decrypt::<RCtx, 2>(&stripped.u(), &stripped.v(), &keypair.sk_b);
    /// assert_eq!(message, decrypted);
    /// ```
    ///
    /// # Parameters
    ///
    /// - `c`: The ciphertext to strip.
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] verification returns error
    /// - `NaorYungStripError` if the proof of well-formedness fails.
    pub fn strip<const W: usize>(
        &self,
        c: Ciphertext<C, W>,
        context: &[u8],
    ) -> Result<elgamal::Ciphertext<C, W>, Error> {
        self.pkey.strip(c, context)
    }

    /// Decrypt the given ciphertext with this key pair.
    ///
    /// This function verifies the proof of well-formedness before decrypting.
    /// The ciphertext can have arbitrary width `W`.
    ///
    /// See `EVS`: Definition 11.31
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::KeyPair;
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = keypair.encrypt(&message, encryption_context).unwrap();
    /// // includes proof verification
    /// let decrypted = keypair.decrypt(&ciphertext, encryption_context).unwrap();
    ///
    /// assert_eq!(message, decrypted);
    /// ```
    ///
    /// # Parameters
    ///
    /// - `c`: The ciphertext to decrypt.
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] verification returns error
    /// - `NaorYungStripError` if the proof of well-formedness fails.
    pub fn decrypt<const W: usize>(
        &self,
        c: &Ciphertext<C, W>,
        context: &[u8],
    ) -> Result<[C::Element; W], Error> {
        let proof_ok = c.proof.verify(
            &self.pkey.pk_b,
            &self.pkey.pk_a,
            &c.u_b,
            &c.v_b,
            &c.u_a,
            context,
        )?;

        if proof_ok {
            let decrypted_element = elgamal::decrypt::<C, W>(&c.u_b, &c.v_b, &self.sk_b);

            Ok(decrypted_element)
        } else {
            Err(Error::NaorYungStripError(
                "Proof failed to validate for Naor-Yung ciphertext".into(),
            ))
        }
    }
}

/**
 * A Naor-Yung public key.
 *
 * This struct represents a public key in the Naor-Yung encryption scheme,
 * including the two public group elements.
 * The secret key `w` for `pk_a = pk_b^w` is never computed, instead the
 * value `pk_a` is derived from a random oracle, `pk_a = H(context)`.
 *
 * In the Naor-Yung encryption scheme, ciphertexts include a proof of
 * well-formedness. This proof must be verified before decryption.
 *
 * See `EVS`: Definition 11.31
 *
 * # Examples
 *
 * ```
 * use crypto::cryptosystem::naoryung::{PublicKey, KeyPair};
 * use crypto::context::Context;
 * use crypto::context::RistrettoCtx as RCtx;
 *
 * // Set to some relevant context value
 * let keypair_context = &[];
 * let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
 * let public_key: &PublicKey<RCtx> = &keypair.pkey;
 * let message = [RCtx::random_element(); 2];
 * // Set to some relevant context value
 * let encryption_context = &[];
 * let ciphertext = public_key.encrypt(&message, encryption_context).unwrap();
 *
 * let decrypted = keypair.decrypt(&ciphertext, encryption_context).unwrap();
 *
 * assert_eq!(message, decrypted);
 * ```
 */
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicKey<C: Context> {
    /// The public value, `y` for `y = g^x`
    pub pk_b: C::Element,
    /// The public value `z`, for `z = y^w`
    ///
    /// The value `w` is never constructed, `z` is derived from a random oracle.
    pub pk_a: C::Element,
}
impl<C: Context> PublicKey<C> {
    /// Constructs a new public key with the given public values.
    ///
    /// Use this function to create a public key from existing public values.
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair, including a public key.
    pub fn from_elgamal(elgamal_pk: &elgamal::PublicKey<C>, pk_a: C::Element) -> Self {
        PublicKey {
            pk_b: elgamal_pk.y.clone(),
            pk_a,
        }
    }

    /// Augment an `ElGamal` public key into a `Naor-Yung` public key.
    ///
    /// Use this function to create a public key from an existing `ElGamal` public key;
    /// the value `pk_a` is derived from a random oracle, `pk_a = H(context)`.
    ///
    /// # Parameters
    ///
    /// - `elgamal_pk`: The `ElGamal` public key to augment
    /// - `context`: The context that will be used as input to the hash function to
    ///   derive `pk_a` (PK CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if hashing to an element to compute `pk_a` returns error
    ///
    /// Use [`KeyPair::generate`] to instead generate a fresh key pair.
    pub fn augment(elgamal_pk: &elgamal::PublicKey<C>, context: &[u8]) -> Result<Self, Error> {
        let pk_a = C::G::hash_to_element(&[context], &[b"naor_yung_public_key_a"]);
        let ret = Self::from_elgamal(elgamal_pk, pk_a?);
        Ok(ret)
    }

    /// Encrypt the given message with this public key.
    ///
    /// This function also computes the proof of well-formedness, using
    /// the [`PlEqProof`][`crate::zkp::pleq::PlEqProof`] zkp. The input message
    /// can have arbitrary width `W`.
    ///
    /// See `EVS`: Definition 11.31
    ///
    /// See [`PlEqProof::prove`][`crate::zkp::pleq::PlEqProof::prove`].
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::{PublicKey, KeyPair};
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // Set to some relevant contextvalue
    /// let encryption_context = &[];
    /// let ciphertext = public_key.encrypt(&message, encryption_context).unwrap();
    /// ```
    ///
    /// # Parameters
    ///
    /// - `message`: The message to encrypt, of width `W`
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] computation returns error
    pub fn encrypt<const W: usize>(
        &self,
        message: &[C::Element; W],
        context: &[u8],
    ) -> Result<Ciphertext<C, W>, Error> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; W]>::random(&mut rng);

        self.encrypt_with_r(message, &r, context)
    }

    /// Encrypt the given message with this public key and the given randomness.
    ///
    /// This function also computes the proof of well-formedness, using
    /// the [`PlEqProof`][`crate::zkp::pleq::PlEqProof`] zkp. The input message
    /// can have arbitrary width `W`.
    ///
    /// See `EVS`: Definition 11.31
    ///
    /// See [`PlEqProof::prove`][`crate::zkp::pleq::PlEqProof::prove`].
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::{PublicKey, KeyPair};
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // generate random values for the encryption
    /// let r = [RCtx::random_scalar(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = public_key.encrypt_with_r(&message, &r, encryption_context).unwrap();
    /// ```
    ///
    ///  # Parameters
    ///
    /// - `message`: The message to encrypt, of width `W`
    /// - `r`: The random values for the encryption, of width `W`
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] computation returns error
    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
        context: &[u8],
    ) -> Result<Ciphertext<C, W>, Error> {
        let g = C::generator();

        let u_b = g.repl_exp(r);
        let v_b = self.pk_b.repl_exp(r);
        let v_b = message.mul(&v_b);
        let u_a = self.pk_a.repl_exp(r);

        let proof = PlEqProof::<C, W>::prove(&self.pk_b, &self.pk_a, &u_b, &v_b, &u_a, r, context)?;

        let ret = Ciphertext::new(u_b, v_b, u_a, proof);

        Ok(ret)
    }

    /// Strip this Naor-Yung ciphertext, returning the underlying plain `ElGamal` ciphertext.
    ///
    /// The strip function verifies the proof of well-formedness and returns
    /// the underlying plain `ElGamal` ciphertext, with only the encrypted message.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto::cryptosystem::naoryung::{PublicKey, KeyPair};
    /// use crypto::cryptosystem::elgamal;
    /// use crypto::context::Context;
    /// use crypto::context::RistrettoCtx as RCtx;
    ///
    /// // Set to some relevant context value
    /// let keypair_context = &[];
    /// let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
    /// let public_key: &PublicKey<RCtx> = &keypair.pkey;
    /// // encrypt a message of width 2
    /// let message = [RCtx::random_element(); 2];
    /// // Set to some relevant context value
    /// let encryption_context = &[];
    /// let ciphertext = public_key.encrypt(&message, encryption_context).unwrap();
    ///
    /// // strip the Naor-Yung ciphertext to get the underlying elgamal ciphertext
    /// let stripped: elgamal::Ciphertext<RCtx, 2> = public_key.strip(ciphertext, encryption_context).unwrap();
    ///
    /// // decrypt using plain ElGamal decryption
    /// let decrypted = elgamal::decrypt::<RCtx, 2>(&stripped.u(), &stripped.v(), &keypair.sk_b);
    /// assert_eq!(message, decrypted);
    /// ```
    ///
    /// # Parameters
    ///
    /// - `c`: The ciphertext to strip.
    /// - `context`: proof context label (ZKP CONTEXT)
    ///
    /// # Errors
    ///
    /// - `HashToElementError` if challenge generation for [`PlEqProof`] verification returns error
    /// - `NaorYungStripError` if the proof of well-formedness fails.
    pub fn strip<const W: usize>(
        &self,
        c: Ciphertext<C, W>,
        context: &[u8],
    ) -> Result<elgamal::Ciphertext<C, W>, Error> {
        let proof_ok = c
            .proof
            .verify(&self.pk_b, &self.pk_a, &c.u_b, &c.v_b, &c.u_a, context)?;

        if proof_ok {
            Ok(elgamal::Ciphertext::<C, W>::new(c.u_b, c.v_b))
        } else {
            Err(Error::NaorYungStripError(
                "Proof failed to validate for Naor-Yung ciphertext".into(),
            ))
        }
    }
}

/**
 * A Naor-Yung ciphertext.
 *
 * This struct represents a ciphertext in the Naor-Yung encryption scheme
 * as a triple of values `(u_b, v_b, u_a)` together with a proof of well-formedness.
 * Each element of the ciphertext encryption triple has an arbitrary length of `W`
 * group elements.
 *
 * See `EVS`: Definition 11.31
 *
 * # Examples
 *
 * ```
 * use crypto::cryptosystem::naoryung::{PublicKey, KeyPair};
 * use crypto::context::Context;
 * use crypto::context::RistrettoCtx as RCtx;
 *
 * // Set to some relevant context value
 * let keypair_context = &[];
 * let keypair: KeyPair<RCtx> = KeyPair::generate(keypair_context).unwrap();
 * let public_key: &PublicKey<RCtx> = &keypair.pkey;
 * let message = [RCtx::random_element(); 2];
 * // Set to some relevant context value
 * let encryption_context = &[];
 * let ciphertext = public_key.encrypt(&message, encryption_context).unwrap();
 *
 * let decrypted = keypair.decrypt(&ciphertext, encryption_context).unwrap();
 *
 * assert_eq!(message, decrypted);
 * ```
 */
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct Ciphertext<C: Context, const W: usize> {
    /// The value `u_b = g^r`
    pub u_b: [C::Element; W],
    /// The value `v_b = my^r` where `pk_b = y`
    pub v_b: [C::Element; W],
    /// The value `u_a = z^r` where `pk_a = z`
    pub u_a: [C::Element; W],
    /// The proof of well-formedness is a proof of equality of plaintexts
    pub proof: PlEqProof<C, W>,
}

impl<C: Context, const W: usize> Ciphertext<C, W> {
    /// Construct a ciphertext with given values and proof.
    ///
    /// Use [`KeyPair::encrypt`] or [`PublicKey::encrypt`] to encrypt
    /// a ciphertext from a message.
    pub fn new(
        u_b: [C::Element; W],
        v_b: [C::Element; W],
        u_a: [C::Element; W],
        proof: PlEqProof<C, W>,
    ) -> Self {
        Ciphertext {
            u_b,
            v_b,
            u_a,
            proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::cryptosystem::elgamal;
    use crate::cryptosystem::elgamal::KeyPair as EGKeyPair;
    use crate::cryptosystem::naoryung::KeyPair as NYKeyPair;
    use crate::cryptosystem::naoryung::PublicKey as NYPublicKey;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_naoryung_from_elgamal_ristretto() {
        test_naoryung_from_elgamal::<RCtx>();
    }

    #[test]
    fn test_naoryung_from_elgamal_p256() {
        test_naoryung_from_elgamal::<PCtx>();
    }

    #[test]
    fn test_naoryung_augment_ristretto() {
        test_naoryung_augment::<RCtx>();
    }

    #[test]
    fn test_naoryung_augment_p256() {
        test_naoryung_augment::<PCtx>();
    }

    #[test]
    fn test_keypair_serialization_ristretto() {
        test_keypair_serialization::<RCtx>();
    }

    #[test]
    fn test_keypair_serialization_p256() {
        test_keypair_serialization::<PCtx>();
    }

    #[test]
    fn test_encryption_ristretto() {
        test_encryption::<RCtx>();
    }

    #[test]
    fn test_encryption_p256() {
        test_encryption::<PCtx>();
    }

    #[test]
    fn test_serialization_and_decryption_ristretto() {
        test_serialization_and_decryption::<RCtx>();
    }

    #[test]
    fn test_serialization_and_decryption_p256() {
        test_serialization_and_decryption::<PCtx>();
    }

    fn test_naoryung_from_elgamal<Ctx: Context>() {
        let keypair_context = &[];

        let eg_keypair: EGKeyPair<Ctx> = EGKeyPair::generate();

        let ny_keypair: NYKeyPair<Ctx> = NYKeyPair::augment(&eg_keypair, keypair_context).unwrap();
        let pk_a = ny_keypair.pkey.pk_a.clone();

        let ny_keypair_2: NYKeyPair<Ctx> = NYKeyPair::new(&eg_keypair, pk_a.clone());
        assert_eq!(ny_keypair, ny_keypair_2);

        let pk_2 = PublicKey::from_elgamal(&eg_keypair.pkey, pk_a);

        assert_eq!(ny_keypair.pkey, pk_2);

        let message = [Ctx::random_element(), Ctx::random_element()];
        // Set to some relevant context value
        let encryption_context = &[];
        // computes a `Naor-Yung` ciphertext
        let ciphertext = ny_keypair.encrypt(&message, encryption_context).unwrap();
        // stripping a `Naor-Yung` ciphertexts verifies its proof and returns an
        // `ElGamal` ciphertext
        let stripped: elgamal::Ciphertext<Ctx, 2> =
            ny_keypair.strip(ciphertext, encryption_context).unwrap();
        // decrypt using plain `ElGamal` decryption
        let decrypted = eg_keypair.decrypt(&stripped);
        assert_eq!(message, decrypted);
    }

    fn test_naoryung_augment<Ctx: Context>() {
        let context = &[];
        let eg_keypair: EGKeyPair<Ctx> = EGKeyPair::generate();
        let eg_pk = &eg_keypair.pkey;

        let ny_pk: NYPublicKey<Ctx> = NYPublicKey::augment(&eg_pk, context).unwrap();

        let ny_keypair: NYKeyPair<Ctx> = NYKeyPair::augment(&eg_keypair, context).unwrap();
        let ny_pk2: NYPublicKey<Ctx> = ny_keypair.pkey.clone();
        // augmenting the keypair or the public key produces the same result
        assert_eq!(ny_pk, ny_pk2);

        let message = [Ctx::random_element(), Ctx::random_element()];
        // Set to some relevant context value
        let encryption_context = &[];
        // computes a `Naor-Yung` ciphertext
        let ciphertext = ny_pk.encrypt(&message, encryption_context).unwrap();
        // stripping a `Naor-Yung` ciphertexts verifies its proof and returns an
        // `ElGamal` ciphertext
        let stripped: elgamal::Ciphertext<Ctx, 2> =
            ny_pk.strip(ciphertext.clone(), encryption_context).unwrap();
        // decrypt using plain `ElGamal` decryption
        let decrypted = eg_keypair.decrypt(&stripped);
        assert_eq!(message, decrypted);

        let stripped: elgamal::Ciphertext<Ctx, 2> =
            ny_pk2.strip(ciphertext, encryption_context).unwrap();
        // decrypt using plain `ElGamal` decryption
        let decrypted = eg_keypair.decrypt(&stripped);
        assert_eq!(message, decrypted);
    }

    fn test_keypair_serialization<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate(&vec![]).unwrap();

        let serialized = keypair.ser_f();
        assert_eq!(serialized.len(), KeyPair::<Ctx>::size_bytes());

        let deserialized = KeyPair::<Ctx>::deser_f(&serialized).unwrap();
        assert_eq!(keypair, deserialized);
    }

    fn test_encryption<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate(&vec![]).unwrap();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message, &vec![]).unwrap();
        let decrypted_message = keypair.decrypt(&ciphertext, &vec![]).unwrap();
        assert_eq!(message, decrypted_message);
    }

    fn test_serialization_and_decryption<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate(&vec![]).unwrap();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message, &vec![]).unwrap();
        let serialized_ct = ciphertext.ser_f();
        assert_eq!(serialized_ct.len(), Ciphertext::<Ctx, 2>::size_bytes());

        let deserialized_ct = Ciphertext::<Ctx, 2>::deser_f(&serialized_ct).unwrap();

        assert_eq!(ciphertext, deserialized_ct);

        let decrypted_message = keypair.decrypt(&deserialized_ct, &vec![]).unwrap();
        assert_eq!(message, decrypted_message);
    }
}
