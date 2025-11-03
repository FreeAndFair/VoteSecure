// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Serde implementations built on VSerializable, FSerializable

use crate::context::{Context, P256Ctx, RistrettoCtx};
use crate::cryptosystem::{elgamal, naoryung};
use crate::dkgd::dealer::{DealerShares, VerifiableShare};
use crate::dkgd::recipient::{DecryptionFactor, DkgCiphertext, DkgPublicKey};
use crate::utils::serialization::{FDeserializable, FSerializable};
use crate::utils::serialization::{VDeserializable, VSerializable};
use crate::zkp::{
    dlogeq::DlogEqProof,
    pleq::PlEqProof,
    schnorr::SchnorrProof,
    shuffle::{Responses, ShuffleCommitments, ShuffleProof},
};
use serde::{self, Deserializer, Serializer, de::Error};

/// Implement serde serialization for [variable][`crate::utils::serialization::variable`] length serializable types.
macro_rules! implement_serde_v {
    ($type:ty $(, const $param:ident : usize)* $(, $lifetime:lifetime)?) => {
        impl<'de, C: Context $(, const $param: usize)*> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
                Self::deser(&bytes).map_err(D::Error::custom)
            }
        }

        impl<C: Context $(, const $param: usize)*> serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.ser())
            }
        }
    };
}

/// Implement serde serialization for [fixed][`crate::utils::serialization::fixed`] length serializable types.
macro_rules! implement_serde_f {
    ($type:ty $(, const $param:ident : usize)* $(, $lifetime:lifetime)?) => {
        impl<'de, C: Context $(, const $param: usize)*> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
                Self::deser_f(&bytes).map_err(D::Error::custom)
            }
        }

        impl<C: Context $(, const $param: usize)*> serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.ser_f())
            }
        }
    };
}

// elgamal::PublicKey
implement_serde_f!(elgamal::PublicKey<C>);

// elgamal::KeyPair
implement_serde_f!(elgamal::KeyPair<C>);

// elgamal::Ciphertext
implement_serde_f!(elgamal::Ciphertext<C, W>, const W: usize);

// naoryung::KeyPair
implement_serde_f!(naoryung::KeyPair<C>);

// naoryung::Ciphertext
implement_serde_f!(naoryung::Ciphertext<C, N>, const N: usize);

// DlogEqProof
implement_serde_f!(DlogEqProof<C, N>, const N: usize);

// PlEqProof
implement_serde_f!(PlEqProof<C, N>, const N: usize);

// SchnorrProof
implement_serde_f!(SchnorrProof<C>);

// DkgPublicKey
implement_serde_f!(DkgPublicKey<C, T>, const T: usize);

// DkgCiphertext
implement_serde_f!(DkgCiphertext<C, W, T>, const W: usize, const T: usize);

// VerifiableShare
implement_serde_f!(VerifiableShare<C, T>, const T: usize);

// DecryptionFactor
implement_serde_f!(DecryptionFactor<C, P, W>, const P: usize, const W: usize);

// dkgd::DealerShares
implement_serde_f!(DealerShares<C, T, P>, const T: usize, const P: usize);

// naoryung::PublicKey
implement_serde_f!(naoryung::PublicKey<C>);

// ShuffleProof
implement_serde_v!(ShuffleProof<C, W>, const W: usize);

// Responses
implement_serde_v!(Responses<C, W>, const W: usize);

// ShuffleCommitments
implement_serde_v!(ShuffleCommitments<C, W>, const W: usize);

// RistrettoCtx
impl<'de> serde::Deserialize<'de> for RistrettoCtx {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(RistrettoCtx)
    }
}

impl serde::Serialize for RistrettoCtx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&[])
    }
}

// P256Ctx
impl<'de> serde::Deserialize<'de> for P256Ctx {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(P256Ctx)
    }
}

impl serde::Serialize for P256Ctx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&[])
    }
}

#[cfg(test)]
mod tests {

    use crate::context::{Context, P256Ctx, RistrettoCtx as RCtx};
    use crate::cryptosystem::{elgamal, naoryung};
    use crate::dkgd::{DkgCiphertext, DkgPublicKey};
    use crate::traits::groups::CryptographicGroup;
    use crate::traits::groups::DistGroupOps;
    use crate::traits::groups::GroupElement;
    use crate::zkp::{dlogeq, pleq, schnorr, shuffle};

    #[test]
    fn test_serde_elgamal_public_key() {
        let pk = elgamal::KeyPair::generate().pkey;
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::PublicKey<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_serde_naoryung_public_key() {
        let pk = elgamal::KeyPair::generate().pkey;
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::PublicKey<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_serde_elgamal_key_pair() {
        let kp = elgamal::KeyPair::<P256Ctx>::generate();
        let serialized = bincode::serde::encode_to_vec(&kp, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::KeyPair<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(kp, deserialized);
    }

    #[test]
    fn test_serde_elgamal_ciphertext() {
        let kp = elgamal::KeyPair::<P256Ctx>::generate();
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct = kp.encrypt(&m);

        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::Ciphertext<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }

    #[test]
    fn test_serde_naoryung_key_pair() {
        let eg_kp = elgamal::KeyPair::<P256Ctx>::generate();
        let kp = naoryung::KeyPair::new(&eg_kp, P256Ctx::random_element());
        let serialized = bincode::serde::encode_to_vec(&kp, bincode::config::standard()).unwrap();
        let (deserialized, _): (naoryung::KeyPair<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(kp, deserialized);
    }

    #[test]
    fn test_serde_naoryung_ciphertext() {
        let eg_kp = elgamal::KeyPair::<P256Ctx>::generate();
        let kp = naoryung::KeyPair::new(&eg_kp, P256Ctx::random_element());
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct = kp.encrypt(&m, &vec![]);

        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (naoryung::Ciphertext<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }

    #[test]
    fn test_serde_dlogeq_proof() {
        let secret_x = P256Ctx::random_scalar();
        let g1 = P256Ctx::random_element();
        let gn = [P256Ctx::random_element(), P256Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.dist_exp(&secret_x);

        let proof: dlogeq::DlogEqProof<P256Ctx, 2> =
            dlogeq::DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]);
        let serialized =
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (dlogeq::DlogEqProof<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_pleq_proof() {
        let eg_kp = elgamal::KeyPair::<RCtx>::generate();
        let ny_kp = naoryung::KeyPair::new(&eg_kp, RCtx::random_element());
        let m = [RCtx::random_element(), RCtx::random_element()];
        let r = [RCtx::random_scalar(), RCtx::random_scalar()];
        let ct = ny_kp.encrypt_with_r(&m, &r, &vec![]);

        let proof: pleq::PlEqProof<RCtx, 2> = pleq::PlEqProof::prove(
            &ny_kp.pkey.pk_b,
            &ny_kp.pkey.pk_a,
            &ct.u_b,
            &ct.v_b,
            &ct.u_a,
            &r,
            &vec![],
        );
        let serialized =
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (pleq::PlEqProof<RCtx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_schnorr_proof() {
        let g = P256Ctx::generator();
        let secret_x = P256Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = schnorr::SchnorrProof::<P256Ctx>::prove(&g, &public_y, &secret_x);
        let serialized =
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (schnorr::SchnorrProof<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_shuffle_proof() {
        const W: usize = 2;
        let count = 2;
        let keypair: elgamal::KeyPair<P256Ctx> = elgamal::KeyPair::generate();

        let messages: Vec<[<P256Ctx as crate::context::Context>::Element; W]> = (0..count)
            .map(|_| std::array::from_fn(|_| P256Ctx::random_element()))
            .collect();

        let ciphertexts: Vec<elgamal::Ciphertext<P256Ctx, W>> =
            messages.iter().map(|m| keypair.encrypt(m)).collect();

        let generators = <P256Ctx as Context>::G::ind_generators(count, &vec![]);
        let shuffler = shuffle::Shuffler::<P256Ctx, W>::new(generators, keypair.pkey);

        let (_, proof) = shuffler.shuffle(&ciphertexts, &vec![]);
        let serialized =
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (shuffle::ShuffleProof<P256Ctx, W>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_dkg_public_key() {
        let keypair = elgamal::KeyPair::<P256Ctx>::generate();
        let pk = DkgPublicKey::<P256Ctx, 2>::from_keypair(&keypair);
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (DkgPublicKey<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_serde_dkg_ciphertext() {
        let keypair = elgamal::KeyPair::<P256Ctx>::generate();
        let pk = DkgPublicKey::<P256Ctx, 2>::from_keypair(&keypair);
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct: DkgCiphertext<P256Ctx, 2, 2> = pk.encrypt(&m);
        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (DkgCiphertext<P256Ctx, 2, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }
}
