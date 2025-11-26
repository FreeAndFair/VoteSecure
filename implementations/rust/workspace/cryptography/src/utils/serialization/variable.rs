// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Variable length serialization
//!
//! # Traits
//!
//! This module defines the traits
//!
//! - [`VSerializable`]: variable length serialization
//! - [`VDeserializable`]: variable length deserialization
//! - [`TFTuple`]: conversion to and from tuples
//!
//! # Implementations
//!
//! This module provides variable length serialization
//! implementations for
//!
//! - Generic structs/tuples annotated with `vser` macro derives
//! - Array[N; T]
//! - Vec<T>
//! - Option<T>
//! - [`LargeVector`] (for performant serialization on large data)
//! - u8, u16, u32, u64, u128
//! - String
//!
//! # Derive macro implementations
//!
//! The `VSerializable` macro derives the following implementations on annotated structs:
//!
//! - [`VSerializable`], [`VDeserializable`]
//! - [`TFTuple`]
//! - [`std::hash::Hash`]

use crate::utils::error::Error;
use crate::utils::serialization::get_slice;
use crate::utils::serialization::{FDeserializable, FSerializable};
use std::collections::BTreeMap;

/// Type for byte length prefixes
// Ensures that usize can fit in LengthU, for LengthU = 64
// This justifies code of the form 'expect("usize::MAX <= LengthU::MAX")'
#[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
pub type LengthU = u64;

/// Number of bytes prepended to specify length of serialized data
pub const LENGTH_BYTES: usize = size_of::<LengthU>();

/**
 * Types that can be serialized into variable length byte sequences
 */
pub trait VSerializable: Sized {
    /// Serialize this type into a vector of bytes
    fn ser(&self) -> Vec<u8>;
}

/**
 * Types that can be deserialized from variable length byte sequences
 */
pub trait VDeserializable: Sized {
    /// Deserialize this type from a vector of bytes
    ///
    /// # Errors
    ///
    /// - If this type cannot be deserialized from the input bytes
    fn deser(buffer: &[u8]) -> Result<Self, Error>;
}

/**
 * Types that can be converted to and from tuple forms
 *
 * See `vser` macro.
 */
pub trait TFTuple: Sized {
    /// The tuple type into which this type can be converted
    type TupleRef<'a>: VSerializable
    where
        Self: 'a;
    /// The tuple type from which this type can be constructed
    type Tuple: VDeserializable;

    /// Converts this type into a tuple of type `TupleRef`
    fn as_tuple(&self) -> Self::TupleRef<'_>;
    /// Constructs this type from a tuple of type `Tuple`
    fn from_tuple(tuple: Self::Tuple) -> Self;
}

impl<T: VSerializable> VSerializable for Vec<T> {
    /// Serialize a vector of variable length serializable types.
    ///
    /// Returns a byte vector with an `N` length prefix
    ///
    /// <`N Length Prefix`>
    ///
    /// followed by `N` values of type `T` serialized as `N` consecutive byte sequences
    /// (in the same order), each of of the form
    ///
    /// <`Length Prefix`><`Value Bytes`>
    ///
    /// Where
    ///
    /// - `Length Prefix` is the big endian representation of the `LengthU`
    ///   value corresponding to the number of bytes in `Value Bytes`
    /// - `Value Bytes` is the byte representation the correponding instance of `T`
    ///   resulting from calling `T::ser` on that instance
    ///
    /// The number of items in the vector, `N` is prefixed on the entire
    /// byte sequence, giving
    ///
    /// <`N Length Prefix`><`Length Prefix1`><`Value Bytes1`>...
    ///
    /// as the complete byte sequence.
    ///
    /// # Panics
    ///
    /// - If the number of elements is larger than `LengthU::MAX`
    ///
    /// Returns the vector of bytes
    fn ser(&self) -> Vec<u8> {
        let items: LengthU = self.len().try_into().expect("usize::MAX <= LengthU::MAX");
        let mut ret = items.to_be_bytes().to_vec();
        for item in self {
            let bytes = item.ser();
            let len: LengthU = bytes.len().try_into().expect("usize::MAX <= LengthU::MAX");
            ret.extend_from_slice(&len.to_be_bytes());
            ret.extend(bytes);
        }

        ret
    }
}

impl<T: VDeserializable> VDeserializable for Vec<T> {
    /// Deserialize a vector of variable length serializable types.
    ///
    /// See [`Vec::<T>::ser()`]
    ///
    /// # Errors
    ///
    /// - If any of the length prefix slices cannot be converted to array form
    /// - If any of the length prefix arrays cannot be converted to `LengthU`
    /// - If any of the `T` instances cannot be individually deserialized
    ///
    /// Returns the vector of `n` instances of `T`
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let mut bytes = buffer;
        let mut ret: Vec<Result<T, Error>> = vec![];
        let items_bytes: [u8; LENGTH_BYTES] = get_slice(bytes, 0..LENGTH_BYTES)?.try_into()?;
        let items: usize = LengthU::from_be_bytes(items_bytes).try_into()?;
        bytes = get_slice(bytes, LENGTH_BYTES..bytes.len())?;

        for _ in 0..items {
            let len_bytes: [u8; LENGTH_BYTES] = get_slice(bytes, 0..LENGTH_BYTES)?.try_into()?;
            let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

            let upper_limit = checked_add(LENGTH_BYTES, len)?;
            let value = T::deser(get_slice(bytes, LENGTH_BYTES..upper_limit)?);
            ret.push(value);
            let tail = upper_limit..bytes.len();
            bytes = get_slice(bytes, tail)?;
        }

        let ret: Result<Vec<T>, Error> = ret.into_iter().collect::<Result<Vec<T>, Error>>();
        ret
    }
}

/// Serialize an array of variable length serializable types.
///
/// An array of `N` values of type `T` is serialized as `N` consecutive
/// byte sequences (in the same order), each of the form
///
/// <`Length Prefix`><`Value Bytes`>
///
/// Where
///
/// - `Length Prefix` is the big endian representation of the `LengthU`
///   value corresponding to the number of bytes in `Value Bytes`
/// - `Value Bytes` is the byte representation of an instance of `T`
///   resulting from calling `T::ser` on that instance
///
/// # Panics
///
/// - If the number of elements is larger than `LengthU::MAX`
///
/// Returns the array of bytes
impl<T: VSerializable, const N: usize> VSerializable for [T; N] {
    fn ser(&self) -> Vec<u8> {
        let mut ret = vec![];

        for v in self {
            let bytes = v.ser();
            let len: LengthU = bytes.len().try_into().expect("usize::MAX <= LengthU::MAX");
            ret.extend_from_slice(&len.to_be_bytes());
            ret.extend(bytes);
        }

        ret
    }
}

/// Deserialize an array of variable length serializable types.
///
/// See [`<[T; N]>::ser()`]
///
/// # Errors
///
/// Returns an error if
///
/// - Any of the length prefix slices cannot be converted to array form
/// - Any of the length prefix arrays cannot be converted to `LengthU`
/// - Any of the `T` instances cannot be individually deserialized
/// - The deserialization did not result in exactly `N` values of `T`
/// - The intermediate deserialized vector `Vec<T>` could not be converted into `[T; N]`
///
/// Returns the vector of `n` instances of `T`
impl<T: VDeserializable, const N: usize> VDeserializable for [T; N] {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let mut bytes = buffer;
        let mut results: Vec<Result<T, Error>> = vec![];

        for _ in 0..N {
            let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
            let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

            let upper_limit = checked_add(LENGTH_BYTES, len)?;
            let slice = get_slice(bytes, LENGTH_BYTES..upper_limit)?;
            results.push(T::deser(slice));
            let tail_range = upper_limit..bytes.len();
            bytes = get_slice(bytes, tail_range)?;
        }

        if !bytes.is_empty() {
            return Err(Error::DeserializationError(
                "Input bytes did factor to N chunks".to_string(),
            ));
        }

        let ts: Vec<T> = results.into_iter().collect::<Result<Vec<T>, Error>>()?;
        let ret: Result<[T; N], Error> = ts.try_into().map_err(|_| {
            Error::DeserializationError("Failed converting Vec<T> to [T; N]".to_string())
        });

        ret
    }
}

/**
 * Vector specialized for serializing a large number of fixed size objects
 *
 * A `LargeVector` contains a variable number of fixed length elements of type `T`, and
 * therefore implements [`VSerializable`]. However, because each element is of fixed
 * length, only one length prefix is necessary for the entire serialized bytes sequence;
 * this length  prefix is the _number of serialized elements_, unlike other serializable
 * structures where length prefixes specify the _number of serialized bytes_.
 *
 * The serialization performance of `LargeVector` benefits from
 *
 * - The use of preallocated buffers into which a chunk of elements is serialized.
 *   This avoids having to allocate a vector of bytes for each element, which could allocate
 *   a very large number of intermediate vectors.
 * - The use of rayon parallel iterators to serialize each chunk of elements in parallel.
 *
 * The chunking size for both these mechanisms is set by the `CHUNK_SIZE` constant.
 *
 * Deserialization performance benefits from
 *
 * - The use of rayon parallel iterators to deserialize elements in parallel, with chunking
 *   managed solely by the rayon scheduler.
 *
 * Due to `LargeVector`'s fixed size elements, the input byte length must factor exactly
 * into `N` * `T::size_bytes`
 *
 * # Examples
 *
 * ```
 * use cryptography::context::Context;
 * use cryptography::context::RistrettoCtx;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::utils::serialization::variable::LargeVector;
 * use cryptography::utils::serialization::{VSerializable, FSerializable};
 * use cryptography::utils::serialization::variable::LENGTH_BYTES;
 *
 *
 * let values: Vec<RistrettoElement> = (0..5).map(|_| RistrettoCtx::random_element()).collect();
 * let lv = LargeVector(values);
 *
 * let bytes = lv.ser();
 * let expected_length = lv.len() * RistrettoElement::size_bytes();
 * let expected_length = LENGTH_BYTES + expected_length;
 * assert_eq!(bytes.len(), expected_length);
 * ```
 */
#[derive(Debug, PartialEq)]
pub struct LargeVector<T: FSerializable>(pub Vec<T>);

impl<T: FSerializable> LargeVector<T> {
    /// Push a new value into the underlying vector
    pub fn push(&mut self, item: T) {
        self.0.push(item);
    }
    /// Returns the length of the underlying vector
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether the underlying vector is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

use rayon::prelude::*;

/// Size of `LargeVector` serialization chunks
const LARGEVECTOR_CHUNK_SIZE: usize = 256;

/// Serialize this `LargeVector` into a byte vector.
///
/// For a `LargeVector` with `N` elements of type `T`, the
/// number of serialized bytes is
///
/// `LENGTH_BYTES` + `N * T::size_bytes`
///
/// # Panics
///
/// - If the number of elements `N` is larger than `LengthU::MAX`
impl<T: FSerializable + Sync> VSerializable for LargeVector<T> {
    fn ser(&self) -> Vec<u8> {
        let items = self.0.len();
        let length = items * T::size_bytes();
        let mut ret = Vec::with_capacity(LENGTH_BYTES + length);
        // for LargeVector, the length tag is the number of elements in the vector, not the length of the serialized data
        let len: LengthU = self.0.len().try_into().expect("usize::MAX <= LengthU::MAX");
        ret.extend_from_slice(&len.to_be_bytes());

        let list_of_chunk_buffers: Vec<Vec<u8>> = self
            .0
            .par_chunks(LARGEVECTOR_CHUNK_SIZE)
            .map(|chunk| {
                let mut buffer = Vec::with_capacity(chunk.len() * T::size_bytes());
                for item in chunk {
                    item.ser_into(&mut buffer);
                }
                buffer
            })
            .collect();

        for chunk_buffer in list_of_chunk_buffers {
            ret.extend_from_slice(&chunk_buffer);
        }

        ret
    }
}

/// Deserialize this `LargeVector` from a byte vector.
///
/// # Errors
///
/// Returns an error if
///
/// - The length prefix slice cannot be converted to array form
/// - The length prefix array cannot be converted to `LengthU`
/// - Any of the `T` instances cannot be individually deserialized
/// - The number of data bytes is not equal to `N * T::size_bytes`
impl<T: FSerializable + FDeserializable + Send> VDeserializable for LargeVector<T> {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
        // for LargeVector, the length tag is the number of elements in the vector, not the length of the serialized data
        let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

        let bytes = get_slice(buffer, LENGTH_BYTES..buffer.len())?;
        let each = checked_div(bytes.len(), len)?;

        if each != T::size_bytes() {
            return Err(Error::DeserializationError(
                "Unexpected chunk size for LargeVector".to_string(),
            ));
        }

        let chunks = bytes.par_chunks_exact(each);
        let chunks = chunks.map(|e| T::deser_f(e));
        let ret: Result<Vec<T>, Error> = chunks.collect();
        ret.map(|v| LargeVector(v))
    }
}

/// Can serialize a type through its reference
///
/// This implementation is necessary to leverage tuple conversions,
/// because `as_tuple` returns a tuple of references.
impl<T: VSerializable> VSerializable for &T {
    fn ser(&self) -> Vec<u8> {
        T::ser(self)
    }
}

/// Implements [`VSerializable`] for bool
impl VSerializable for bool {
    fn ser(&self) -> Vec<u8> {
        if *self { vec![1u8] } else { vec![0u8] }
    }
}

/// Implements [`VDeserializable`] for bool
impl VDeserializable for bool {
    fn deser(buffer: &[u8]) -> Result<bool, Error> {
        let byte: [u8; 1] = buffer.try_into()?;
        Ok(byte[0] == 1u8)
    }
}

/// Implements [`VSerializable`] for u32
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl VSerializable for u32 {
    fn ser(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

/// Implements [`VDeserializable`] for u32
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl VDeserializable for u32 {
    fn deser(buffer: &[u8]) -> Result<u32, Error> {
        let bytes: [u8; 4] = buffer.try_into()?;

        let value = u32::from_be_bytes(bytes);

        Ok(value)
    }
}

/// Implements [`VSerializable`] for u64
impl VSerializable for u64 {
    fn ser(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

/// Implements [`VDeserializable`] for u64
impl VDeserializable for u64 {
    fn deser(buffer: &[u8]) -> Result<u64, Error> {
        let bytes: [u8; 8] = buffer.try_into()?;

        let value = u64::from_be_bytes(bytes);

        Ok(value)
    }
}

/// Implements [`VSerializable`] for u16
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl VSerializable for u16 {
    fn ser(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

/// Implements [`VDeserializable`] for u64
impl VDeserializable for u16 {
    fn deser(buffer: &[u8]) -> Result<u16, Error> {
        let bytes: [u8; 2] = buffer.try_into()?;

        let value = u16::from_be_bytes(bytes);

        Ok(value)
    }
}

/// Implements [`VSerializable`] for u8
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl VSerializable for u8 {
    fn ser(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

/// Implements [`VDeserializable`] for u8
impl VDeserializable for u8 {
    fn deser(buffer: &[u8]) -> Result<u8, Error> {
        let bytes: [u8; 1] = buffer.try_into()?;

        let value = u8::from_be_bytes(bytes);

        Ok(value)
    }
}

/// Implements [`VSerializable`] for u128
impl VSerializable for u128 {
    fn ser(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

/// Implements [`VDeserializable`] for u128
impl VDeserializable for u128 {
    fn deser(buffer: &[u8]) -> Result<u128, Error> {
        let bytes: [u8; 16] = buffer.try_into()?;

        let value = u128::from_be_bytes(bytes);

        Ok(value)
    }
}

/// Special case implementation of `VSerializable` for 1-tuple
impl<A: VSerializable> VSerializable for (A,) {
    fn ser(&self) -> Vec<u8> {
        let head = self.0.ser();
        let len: LengthU = head.len().try_into().expect("usize::MAX <= LengthU::MAX");
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.extend(head);
        bytes
    }
}

/// Special case implementation of `VDeserializable` for 1-tuple
impl<A: VDeserializable> VDeserializable for (A,) {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

        let bytes = get_slice(buffer, LENGTH_BYTES..buffer.len())?;
        if bytes.len() != len {
            return Err(Error::DeserializationError(
                "Unexpected byte length for (A,)".into(),
            ));
        }

        let a = A::deser(bytes)?;

        Ok((a,))
    }
}

/// Base case implementation of `VSerializable` for `generate_tuple_impl` macro
impl<A: VSerializable, B: VSerializable> VSerializable for (A, B) {
    fn ser(&self) -> Vec<u8> {
        let head = self.0.ser();
        let len: LengthU = head.len().try_into().expect("usize::MAX <= LengthU::MAX");
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.extend(head);
        let tail = self.1.ser();
        bytes.extend(tail);
        bytes
    }
}

/// Base case implementation of `VDeserializable` for `generate_tuple_impl` macro
impl<A: VDeserializable, B: VDeserializable> VDeserializable for (A, B) {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

        let upper_limit = checked_add(LENGTH_BYTES, len)?;
        let a_bytes = get_slice(buffer, LENGTH_BYTES..upper_limit)?;
        let b_range = upper_limit..buffer.len();
        let b_bytes = get_slice(buffer, b_range)?;
        let a = A::deser(a_bytes)?;
        let b = B::deser(b_bytes)?;
        Ok((a, b))
    }
}

/**
 * Generate [`VSerializable`] and [`VDeserializable`] implementations for the given tuple.
 *
 * The tuple element types must already implement [`VSerializable`] and [`VDeserializable`].
 * In combination with [`TFTuple`], these macros allow deriving serialization implementations
 * for arbitrary structs, provided the leaf types already have suitable implementations.
 *
 * See also [`TFTuple`]
 *
 * # Params
 *
 * - `head_ty, tail_tys`: Unique placeholder indentifiers for the tuple's generic types.
 *   For example: for a 4-tuple these could be `A, B, C, D`
 * - `tail_indices`: Indices for the tail tuple elements, staring at 1.
 *   For example: for a 4-tuple these would be `1, 2, 3`
 * - `tail_access`: Indices for the tail tuple elements, start at 0 and ending at arity - 1.
 *   For example: for a 4-tuple these would be `0, 1, 2`
 *
 * # Examples
 *
 * Note: the below example can only run within this project, as `generate_tuple_impl` is an
 * internal macro, so it is marked `ignore`.
 *
 * ```ignore
 * use cryptography::utils::serialization::variable::generate_tuple_impl;
 * use cryptography::utils::serialization::VSerializable;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::groups::p256::P256Element;
 * use cryptography::traits::groups::GroupElement;
 *
 * // Generate variable length serialization implementations for a 3-tuple:
 * generate_tuple_impl!(A, B, C; 1, 2; 0, 1);
 *
 * // We can call this because RistrettoElement, P256Element, String already implement VSerializable
 * let x = (RistrettoElement::one(), P256Element::one(), "Hello World".to_string()).ser();
 * ```
 *
 * # Panics
 *
 * Generated implementation of `VSerializable` panics:
 *
 * - If the number of elements is larger than `LengthU::MAX`
 */
macro_rules! generate_tuple_impl {
    // `$head` is the first generic type (e.g., A).
    // `$($tail_tys)` is a sequence of the remaining generic types (e.g., B, C, D).
    // `$($tail_indices)` is a sequence of the tuple indices for the tail (e.g., 1, 2, 3).
    // `$($tail_access)` is a sequence of the tuple indices to access the deserialized tail (e.g., 0, 1, 2).
    ($head_ty:ident, $($tail_tys:ident),+; $($tail_indices:tt),+; $($tail_access:tt),+) => {

        // Implementation for VSerializable
        impl<$head_ty: VSerializable, $($tail_tys: VSerializable),+> VSerializable for ($head_ty, $($tail_tys),+) {
            fn ser(&self) -> Vec<u8> {
                let head = self.0.ser();
                let len: LengthU = head.len().try_into().expect("usize::MAX <= LengthU::MAX");
                let mut bytes = len.to_be_bytes().to_vec();
                bytes.extend(head);
                // Recursively serialize the rest of the tuple.
                // The `( $( &self.$tail_indices ),+ )` part constructs the tail tuple, e.g., (&self.1, &self.2).
                let tail = ( $( &self.$tail_indices ),+ ).ser();
                bytes.extend(tail);
                bytes
            }
        }

        // Implementation for VDeserializable
        impl<$head_ty: VDeserializable, $($tail_tys: VDeserializable),+> VDeserializable for ($head_ty, $($tail_tys),+) {
            fn deser(buffer: &[u8]) -> Result<Self, Error> {
                let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
                let len: usize = LengthU::from_be_bytes(len_bytes)
                    .try_into()?;

                let upper_limit = checked_add(LENGTH_BYTES, len)?;
                let head_bytes = get_slice(buffer, LENGTH_BYTES..upper_limit)?;
                let tail_range = upper_limit..buffer.len();
                let tail_bytes = get_slice(buffer, tail_range)?;

                let head = $head_ty::deser(&head_bytes.to_vec())?;
                // Recursively deserialize the rest of the tuple.
                // The `<( $($tail_tys),+ )>` part constructs the tail's type, e.g., <(B, C)>.
                let tail = <( $($tail_tys),+ )>::deser(&tail_bytes.to_vec())?;

                // The `(head, $( tail.$tail_access ),+ )` part reconstructs the final tuple, e.g., (head, tail.0, tail.1).
                Ok((head, $( tail.$tail_access ),+))
            }
        }
    };
}

/**
 * Generate [`VSerializable`] and [`VDeserializable`] implementations for a fixed set of tuple types.
 *
 * Calls the [`generate_tuple_impl`] macro for tuples of arity up to 7. Add additional
 * calls as needed for newly defined structs.
 */
macro_rules! impl_vser_for_tuples {
    () => {

        generate_tuple_impl!(A, B, C; 1, 2; 0, 1);

        generate_tuple_impl!(A, B, C, D; 1, 2, 3; 0, 1, 2);

        generate_tuple_impl!(A, B, C, D, E; 1, 2, 3, 4; 0, 1, 2, 3);

        generate_tuple_impl!(A, B, C, D, E, F; 1, 2, 3, 4, 5; 0, 1, 2, 3, 4);

        generate_tuple_impl!(A, B, C, D, E, F, G; 1, 2, 3, 4, 5, 6; 0, 1, 2, 3, 4, 5);
    };
}

impl_vser_for_tuples!();

/// Marker trait for types implementing `VSerializable` and `VDeserializable`
pub trait VSer: VSerializable + VDeserializable {}

impl<T: VSerializable + VDeserializable> VSer for T {}

/// Implements [`VSerializable`] for String
impl VSerializable for String {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.as_bytes();
        let len: LengthU = bytes.len().try_into().expect("usize::MAX <= LengthU::MAX");
        let mut ret = len.to_be_bytes().to_vec();
        ret.extend_from_slice(bytes);

        ret
    }
}

/// Implements [`VDeserializable`] for String
impl VDeserializable for String {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = get_slice(buffer, 0..LENGTH_BYTES)?.try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

        let upper_limit = checked_add(LENGTH_BYTES, len)?;
        let bytes = get_slice(buffer, LENGTH_BYTES..upper_limit)?;

        let string = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::DeserializationError("Failed to deserialize String".into()))?;
        Ok(string)
    }
}

/// Implements [`VSerializable`] for [`Option<T>`]
impl<T: VSerializable> VSerializable for Option<T> {
    fn ser(&self) -> Vec<u8> {
        let mut bytes = self.is_some().ser();
        if let Some(value) = self {
            bytes.extend_from_slice(value.ser().as_slice());
        }
        bytes
    }
}

/// Implements [`VDeserializable`] for [`Option<T>`]
impl<T: VDeserializable> VDeserializable for Option<T> {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let discriminator = get_slice(buffer, 0..1)?;
        let is_some = bool::deser(discriminator)?;
        if is_some {
            let tail = get_slice(buffer, 1..buffer.len())?;
            let value = T::deser(tail)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
}

/// Helper for checked addition of usize values
fn checked_add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or_else(|| Error::DeserializationError("Length overflow".into()))
}
/// Helper for checked division of usize values
fn checked_div(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_div(b)
        .ok_or_else(|| Error::DeserializationError("Division by zero".into()))
}

/// Implements [`VSerializable`] for `BTreeMap<K, V>`.
/// A `BTreeMap` is just a sorted map from K to V; we implement this
/// naively by converting the `BTreeMap` into a vector of (K, V) pairs
/// sorted in the same order as the `BTreeMap` and serializing it.
#[crate::warning("This might need optimization")]
impl<K: VSerializable, V: VSerializable> VSerializable for BTreeMap<K, V> {
    fn ser(&self) -> Vec<u8> {
        let converted_vec: Vec<(&K, &V)> = self.iter().collect();
        let bytes = converted_vec.ser();
        let len: LengthU = bytes.len().try_into().expect("usize::MAX <= LengthU::MAX");
        let mut ret = len.to_be_bytes().to_vec();
        ret.extend_from_slice(&bytes);

        ret
    }
}

/// Implements [`VDeserializable`] for `BTreeMap<K, V>`.
#[crate::warning("This might need optimization")]
impl<K: VDeserializable + Ord, V: VDeserializable> VDeserializable for BTreeMap<K, V> {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = buffer
            .get(0..LENGTH_BYTES)
            .ok_or_else(|| Error::DeserializationError("Buffer too short for length".into()))?
            .try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes).try_into()?;

        let bytes = buffer
            .get(LENGTH_BYTES..checked_add(LENGTH_BYTES, len)?)
            .ok_or_else(|| Error::DeserializationError("Buffer too short for data".into()))?;
        let vec: Vec<(K, V)> = Vec::deser(bytes)?;
        let mut res: BTreeMap<K, V> = BTreeMap::new();
        for (k, v) in vec {
            res.insert(k, v);
        }

        Ok(res)
    }
}
