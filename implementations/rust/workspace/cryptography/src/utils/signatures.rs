// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Digital signature utilities and [context][`crate::context::Context`] dependency.
//!
//! # Examples
//! ```
//! use cryptography::context::Context;
//! use cryptography::context::RistrettoCtx as RCtx;
//! use cryptography::utils::signatures::{SignatureScheme, Signer, Verifier};
//!
//! let sk = RCtx::gen_signing_key();
//! let vk = sk.verifying_key();
//!
//! let message: &[u8] = b"message";
//! let signature = sk.sign(message);
//!
//! let vk = sk.verifying_key();
//! let ok = vk.verify(message, &signature);
//! assert!(ok.is_ok());
//! ```

use std::marker::PhantomData;

pub use ed25519::signature::{Error, Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519};

use crate::utils::Error as CryptographyError;
use crate::utils::{
    rng::CRng,
    serialization::{FDeserializable, FSer, FSerializable, VDeserializable, VSer, VSerializable},
};

/**
 * A digital signature scheme.
 *
 * This trait defines the types and methods required for a digital signature
 * scheme, such as [`Ed25519`].
 */
#[crate::warning(
    "There is no explicit handling of contexts here, they must be provided by the caller as part of the message"
)]

pub trait SignatureScheme<R: CRng> {
    /// The signer type, a private key used for signing.
    type Signer: Signer<Self::Signature> + FSer + VSer;
    /// The verifier type, a public key used to verify signatures.
    type Verifier: Verifier<Self::Signature> + FSer + VSer;
    /// The signature type, a digital signature on some data.
    type Signature: FSer + VSer;

    /// Generates a new private signing key.
    ///
    /// The corresponding public verification key can be obtained with `signing_key.verifying_key()`.
    fn gen_signing_key(rng: &mut R) -> Self::Signer;
}

/**
 * Ed25519 digital signature scheme.
 *
 * This implementation uses the [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) crate.
 *
 * # Examples
 * ```
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx as RCtx;
 * use cryptography::utils::signatures::{SignatureScheme, Signer, Verifier};
 *
 * let sk = RCtx::gen_signing_key();
 * let vk = sk.verifying_key();
 *
 * let message: &[u8] = b"message";
 * let signature = sk.sign(message);
 *
 * let vk = sk.verifying_key();
 * let ok = vk.verify(message, &signature);
 * assert!(ok.is_ok());
 * ```
 */
pub struct Ed25519<R: CRng>(PhantomData<R>);
impl<R: CRng> SignatureScheme<R> for Ed25519<R> {
    type Signer = ed25519_dalek::SigningKey;
    type Verifier = ed25519_dalek::VerifyingKey;
    type Signature = ed25519_dalek::Signature;

    fn gen_signing_key(rng: &mut R) -> ed25519_dalek::SigningKey {
        Self::Signer::generate(rng)
    }
}

impl FSerializable for SigningKey {
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.as_bytes();
        buffer.extend_from_slice(bytes);
    }
    fn size_bytes() -> usize {
        ed25519_dalek::SECRET_KEY_LENGTH
    }
}
impl FDeserializable for SigningKey {
    fn deser_f(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 32] = bytes.try_into()?;
        let ret = SigningKey::from_bytes(&bytes);

        Ok(ret)
    }
}

impl FSerializable for VerifyingKey {
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.as_bytes();
        buffer.extend_from_slice(bytes);
    }
    fn size_bytes() -> usize {
        ed25519_dalek::PUBLIC_KEY_LENGTH
    }
}
impl FDeserializable for VerifyingKey {
    fn deser_f(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 32] = bytes.try_into()?;
        let ret = VerifyingKey::from_bytes(&bytes)?;

        Ok(ret)
    }
}

impl FSerializable for Signature {
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.to_bytes();
        buffer.extend_from_slice(&bytes);
    }
    fn size_bytes() -> usize {
        ed25519_dalek::SIGNATURE_LENGTH
    }
}
impl FDeserializable for Signature {
    fn deser_f(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 64] = bytes.try_into()?;
        let ret = Signature::from_bytes(&bytes);

        Ok(ret)
    }
}

impl VSerializable for SigningKey {
    fn ser(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl VDeserializable for SigningKey {
    fn deser(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 32] = bytes.try_into()?;
        let ret = SigningKey::from_bytes(&bytes);

        Ok(ret)
    }
}

impl VSerializable for VerifyingKey {
    fn ser(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl VDeserializable for VerifyingKey {
    fn deser(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 32] = bytes.try_into()?;
        let ret = VerifyingKey::from_bytes(&bytes)?;

        Ok(ret)
    }
}

impl VSerializable for Signature {
    fn ser(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl VDeserializable for Signature {
    fn deser(bytes: &[u8]) -> Result<Self, CryptographyError> {
        let bytes: [u8; 64] = bytes.try_into()?;
        let ret = Signature::from_bytes(&bytes);

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_signatures_context() {
        use crate::context::Context;
        use crate::context::RistrettoCtx;

        let sk = RistrettoCtx::gen_signing_key();
        let vk = sk.verifying_key();

        let mut csprng = RistrettoCtx::get_rng();
        let message: &[u8] = &csprng.next_u64().to_be_bytes();
        let signature = sk.sign(message);
        let ok = vk.verify(message, &signature);
        assert!(ok.is_ok());

        let signature = sk.sign(&[]);
        let ok = vk.verify(&[], &signature);

        assert!(ok.is_ok());
    }

    #[test]
    fn test_signatures_serialization() {
        use crate::context::Context;
        use crate::context::RistrettoCtx;

        let sk = RistrettoCtx::gen_signing_key();
        let vk = sk.verifying_key();

        let mut csprng = RistrettoCtx::get_rng();
        let message: &[u8] = &csprng.next_u64().to_be_bytes();
        let signature = sk.sign(message);

        let sk_bytes = sk.ser();
        let vk_bytes = vk.ser();
        let sig_bytes = signature.ser();

        let sk = SigningKey::deser(&sk_bytes).unwrap();
        let vk = VerifyingKey::deser(&vk_bytes).unwrap();
        let signature = Signature::deser(&sig_bytes).unwrap();

        let ok = vk.verify(message, &signature);
        assert!(ok.is_ok());

        let sk_bytes = sk.ser_f();
        let vk_bytes = vk.ser_f();
        let sig_bytes = signature.ser_f();

        let sk = SigningKey::deser_f(&sk_bytes).unwrap();
        let vk = VerifyingKey::deser_f(&vk_bytes).unwrap();
        let signature = Signature::deser_f(&sig_bytes).unwrap();

        let ok = vk.verify(message, &signature);
        assert!(ok.is_ok());

        let signature = sk.sign(&[]);
        let ok = vk.verify(&[], &signature);

        assert!(ok.is_ok());
    }
}
