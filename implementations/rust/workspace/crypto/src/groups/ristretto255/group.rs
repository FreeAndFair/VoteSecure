/*
 * CryptoGroup implementations for the Ristretto group
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

use crate::traits::groups::CryptoGroup;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;

use crate::groups::ristretto255::element::RistrettoElement;
use crate::groups::ristretto255::scalar::RistrettoScalar;

use crate::utils::error::Error;
use crate::utils::hash;
use crate::utils::hash::Hasher;
use crate::utils::rng;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar as DalekScalar, constants as dalek_constants};
use sha3::Digest;

use rayon::prelude::*;

/// Ristretto implementation of [`CryptoGroup`]
#[derive(Debug, Clone)]
pub struct Ristretto255Group;

impl CryptoGroup for Ristretto255Group {
    type Element = RistrettoElement;
    type Scalar = RistrettoScalar;
    type Hasher = hash::Hasher512;

    #[inline]
    fn generator() -> Self::Element {
        RistrettoElement::new(dalek_constants::RISTRETTO_BASEPOINT_POINT)
    }

    #[inline]
    fn g_exp(scalar: &Self::Scalar) -> Self::Element {
        RistrettoElement::new(RistrettoPoint::mul_base(&scalar.0))
    }

    /// # Errors
    ///
    /// Infallible
    fn hash_to_scalar(input_slices: &[&[u8]], ds_tags: &[&[u8]]) -> Result<Self::Scalar, Error> {
        let mut hasher = Self::Hasher::hasher();
        hash::update_hasher(&mut hasher, input_slices, ds_tags);

        let ret = RistrettoScalar::from_hash::<Self::Hasher>(hasher);

        Ok(ret)
    }

    /// # Errors
    ///
    /// Infallible
    fn hash_to_element(input_slices: &[&[u8]], ds_tags: &[&[u8]]) -> Result<Self::Element, Error> {
        let mut hasher = Self::Hasher::hasher();
        hash::update_hasher(&mut hasher, input_slices, ds_tags);

        let ret = RistrettoElement::from_hash::<Self::Hasher>(hasher);

        Ok(ret)
    }

    #[inline]
    fn random_element<R: rng::CRng>(rng: &mut R) -> Self::Element {
        Self::Element::random(rng)
    }

    #[inline]
    fn random_scalar<R: rng::CRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    /// Encode bytes into the given number of Ristretto elements
    ///
    /// # Errors
    ///
    /// - `EncodingError` if a point was not found for the input, with negligible probability
    fn encode_bytes<const I: usize, const O: usize>(
        bytes: &[u8; I],
    ) -> Result<[RistrettoElement; O], Error> {
        let split_arrays = Codec::<I, O>::split(bytes);
        Self::encode_array(&split_arrays)
    }

    /// Decode bytes from the given number of Ristretto elements
    ///
    /// # Errors
    ///
    /// Infallible
    fn decode_bytes<const I: usize, const O: usize>(
        element: &[RistrettoElement; I],
    ) -> Result<[u8; O], Error> {
        let decoded_arrays = Self::decode_array(element)?;
        let joined = Codec::<O, I>::join(&decoded_arrays);
        Ok(joined)
    }

    /// # Errors
    ///
    /// Infallible
    fn ind_generators(count: usize, label: &[u8]) -> Result<Vec<Self::Element>, Error> {
        let mut hasher = Self::Hasher::hasher();
        hasher.update(label);
        hasher.update(b"independent_generators_ristretto");

        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        let ret: Vec<RistrettoElement> = (0..count)
            .into_par_iter()
            .map(|i| {
                let mut hasher = hasher.clone();
                hasher.update(i.to_be_bytes());
                let point = RistrettoPoint::from_hash(hasher);
                RistrettoElement(point)
            })
            .collect();

        Ok(ret)
    }
}

impl Ristretto255Group {
    /// # Errors
    ///
    /// - `EncodingError` if any point was not found for the input, with negligible probability
    ///
    /// # Panics
    ///
    /// - Panics if the length of the resulting Vec does not match W, which should not happen
    pub fn encode_array<const W: usize>(p: &[[u8; 30]; W]) -> Result<[RistrettoElement; W], Error> {
        // Collect into Vec first, then convert to array - consistent with productgroup pattern
        let results: Result<Vec<RistrettoElement>, Error> =
            p.iter().map(Self::encode_30_bytes).collect();
        let vec = results?;
        Ok(vec.try_into().expect("vec.len() == W"))
    }

    /// Decode an array of 'Plaintext' types from an array of 'Message' types.
    ///
    /// # Errors
    ///
    /// Infallible
    ///
    /// # Panics
    ///
    /// - `decode_30_bytes` panics if a slice length is not 30, which should not happen
    pub fn decode_array<const W: usize>(p: &[RistrettoElement; W]) -> Result<[[u8; 30]; W], Error> {
        // Since decode is infallible, we can use array::map directly
        Ok(p.map(|message| Self::decode_30_bytes(&message).expect("decode is infallible")))
    }

    // see https://github.com/dalek-cryptography/curve25519-dalek/issues/322
    // see https://github.com/hdevalence/ristretto255-data-encoding/blob/master/src/main.rs
    /// Encode 30 bytes into an `Element`.
    ///
    /// # Errors
    ///
    /// - `EncodingError` if a point was not found for the input, with negligible probability
    pub fn encode_30_bytes(input: &[u8; 30]) -> Result<RistrettoElement, Error> {
        let mut bytes = [0u8; 32];
        bytes[1..=input.len()].copy_from_slice(input);
        for j in 0..64u8 {
            bytes[31] = j;
            for i in 0..128u8 {
                // cannot overflow, 127 * 2 < u8::MAX
                #[allow(clippy::arithmetic_side_effects)]
                let byte = 2 * i;
                bytes[0] = byte;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return Ok(RistrettoElement(point));
                }
            }
        }
        Err(Error::EncodingError(
            "Failed to encode into ristretto point".to_string(),
        ))
    }

    /// Decodes a 30 bytes from an 'Element'.
    ///
    /// # Errors
    ///
    /// Infallible
    ///
    /// # Panics
    ///
    /// - Panics if the slice length is not 30, which should not happen
    pub fn decode_30_bytes(message: &RistrettoElement) -> Result<[u8; 30], Error> {
        let compressed = message.0.compress();
        // the 30 bytes of data are placed in the range 1-30
        let slice = &compressed.as_bytes()[1..31];
        let ret: [u8; 30] = slice.try_into().expect("slice.len() == 30");

        Ok(ret)
    }

    /// Encode a 'Scalar' into two 'Element's.
    ///
    /// # Errors
    ///
    /// - `EncodingError` if a point was not found for the input, with negligible probability
    pub fn encode_scalar(scalar: &RistrettoScalar) -> Result<[RistrettoElement; 2], Error> {
        let bytes = scalar.0.to_bytes();

        Self::encode_bytes(&bytes)
    }

    /// Decode a 'Scalar' from two 'Element's.
    ///
    /// # Errors
    ///
    /// - `ScalarDecodeError` if the bytes could not be parsed into a Ristretto scalar
    pub fn decode_scalar(element: &[RistrettoElement; 2]) -> Result<RistrettoScalar, Error> {
        let bytes = Self::decode_bytes(element)?;
        let opt: Option<RistrettoScalar> = DalekScalar::from_canonical_bytes(bytes)
            .map(RistrettoScalar)
            .into();

        opt.ok_or(Error::ScalarDecodeError(
            "Failed to parse Ristretto scalar bytes".to_string(),
        ))
    }
}

/// Chunk size for encoding, Ristretto points can hold 30 bytes of data
const CHUNK_SIZE: usize = 30;

/// Generic encoding/decoding of byte arrays into fixed-size element arrays
struct Codec<const BYTES: usize, const ELEMENTS: usize> {}

impl<const BYTES: usize, const ELEMENTS: usize> Codec<BYTES, ELEMENTS> {
    /// Split input into chunks
    const CHECK: () = {
        assert!(CHUNK_SIZE > 0);
        assert!(ELEMENTS > 0);
        assert!(BYTES > 0);
        assert!(ELEMENTS == BYTES.div_ceil(CHUNK_SIZE));
        let max = ELEMENTS.checked_mul(CHUNK_SIZE);
        assert!(max.is_some());
    };

    /// Split an array into chunks
    ///
    /// Fills each chunk sequentially up to the `CHUNK_SIZE`
    fn split(input: &[u8; BYTES]) -> [[u8; CHUNK_SIZE]; ELEMENTS] {
        #[allow(path_statements)]
        Self::CHECK;

        let mut result = [[0u8; CHUNK_SIZE]; ELEMENTS];
        let mut input_pos = 0;

        for chunk in &mut result {
            let remaining = BYTES.checked_sub(input_pos).expect("input_pos <= BYTES");
            let to_copy = remaining.min(CHUNK_SIZE);
            let upper = input_pos
                .checked_add(to_copy)
                .expect("ELEMENTS * CHUNK_SIZE <= usize::MAX");
            chunk[0..to_copy].copy_from_slice(&input[input_pos..upper]);
            input_pos = input_pos
                .checked_add(to_copy)
                .expect("ELEMENTS * CHUNK_SIZE <= usize::MAX");
        }

        result
    }

    /// Join chunks back into original byte array
    ///
    /// Takes data sequentially from each chunk to reconstruct the original input
    fn join(chunks: &[[u8; CHUNK_SIZE]; ELEMENTS]) -> [u8; BYTES] {
        #[allow(path_statements)]
        Self::CHECK;

        let mut result = [0u8; BYTES];
        let mut output_pos = 0;

        for chunk in chunks {
            let remaining = BYTES.checked_sub(output_pos).expect("output_pos <= BYTES");
            let to_copy = remaining.min(CHUNK_SIZE);
            let upper = output_pos
                .checked_add(to_copy)
                .expect("ELEMENTS * CHUNK_SIZE <= usize::MAX");
            result[output_pos..upper].copy_from_slice(&chunk[0..to_copy]);
            output_pos = output_pos
                .checked_add(to_copy)
                .expect("ELEMENTS * CHUNK_SIZE <= usize::MAX");
        }

        result
    }
}
