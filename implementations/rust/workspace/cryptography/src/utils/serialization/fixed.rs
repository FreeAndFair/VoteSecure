// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Fixed length serialization
//!
//! # Traits
//!
//! This module defines the traits
//!
//! - [`FSerializable`]: fixed length serialization
//! - [`FDeserializable`]: fixed length deserialization
//!
//! # Implementations
//!
//! This module provides fixed length serialization
//! implementations for
//!
//! - Generic structs/tuples annotated with `vser` macro derives
//! - Array[N; T]

use crate::utils::error::Error;
use crate::utils::serialization::{TFTuple, get_slice};

/**
 * Types that can be serialized into fixed length byte sequences
 *
 * The `ser_into` function writes bytes to a provided
 * buffer, delegating allocation to the caller. Serialization
 * of large composite structures can avoid allocation
 * overhead by using a single contiguous buffer.
 *
 * The alternate `ser_f` is a convenience function that
 * does the allocation itself.
 *
 * Note that `size_bytes` is an associated function, not
 * a method; the serialization length is tied to the type, not
 * an instance.
 */
pub trait FSerializable {
    /// The number of bytes this type serializes into
    fn size_bytes() -> usize;
    /// Serialize this type into a buffer, writing length [`FSerializable::size_bytes`] bytes
    fn ser_into(&self, buffer: &mut Vec<u8>);
    /// Serialize this type into a vector of bytes of length [`FSerializable::size_bytes`]
    fn ser_f(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::size_bytes());
        self.ser_into(&mut buffer);

        buffer
    }
}

/**
 * Types that can be serialized from fixed length byte sequences
 *
 * See [`FSerializable`]
 */
pub trait FDeserializable: Sized {
    /// Deserialize this type from the given buffer, reading [`FSerializable::size_bytes`] bytes
    ///
    /// # Errors
    ///
    /// - If this type cannot be deserialized from the input bytes
    fn deser_f(buffer: &[u8]) -> Result<Self, Error>;
}

/// [`FSerializable`] implementation via tuples
///
/// Implements [`FSerializable`] for a type T if
///
/// 1) it has a tuple conversion
/// 2) its tuple serialization has a fixed length
impl<T> FSerializable for T
where
    T: TFTuple,
    // We use TupleRef instead of Tuple here because serialization
    // code is implemented on the tuple of _references_, preventing
    // unnecessary allocations.
    // The Tuple type is used for deserialization as in Tuple::deser...
    for<'a> T::TupleRef<'a>: FSerializable,
{
    fn size_bytes() -> usize {
        T::TupleRef::size_bytes()
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        self.as_tuple().ser_into(buffer);
    }
}

/// [`FDeserializable`] implementation via tuples
///
/// Implements [`FDeserializable`] for a type T if
///
/// 1) it has a tuple conversion
/// 2) its tuple serialization has a fixed length
/// 3) its tuple deserialization has a fixed length
///
/// # Errors
///
/// - If the input number of bytes does not match the expected size
/// - If the underlying tuple deserialization returns an error
impl<T> FDeserializable for T
where
    T: TFTuple,
    for<'a> T::TupleRef<'a>: FSerializable,
    T::Tuple: FDeserializable,
{
    fn deser_f(buffer: &[u8]) -> Result<T, Error> {
        let expected = T::TupleRef::size_bytes();
        if buffer.len() != expected {
            return Err(Error::DeserializationError(
                "Unexpected number of bytes for struct tuple".to_string(),
            ));
        }
        let tuple = T::Tuple::deser_f(buffer)?;
        Ok(T::from_tuple(tuple))
    }
}

/// [`FSerializable`] implementation for arrays
///
/// An array of `N` values of type `T` is serialized as `N` consecutive
/// byte sequences each of length `T::size_bytes` corresponding to each
/// element's individual serialization. The total size in bytes is
/// therefore `N * T::size_bytes()`
impl<T: FSerializable, const N: usize> FSerializable for [T; N] {
    fn size_bytes() -> usize {
        N * T::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        for v in self {
            v.ser_into(buffer);
        }
    }
}

/// [`FDeserializable`] implementation for arrays
///
/// See `<[T; N]>::ser_into()`
///
/// # Errors
///
/// - If the number of input bytes does not equal the expected size
/// - If any of the `T` instances cannot be individually deserialized
/// - If the intermediate deserialized vector `Vec<T>` could not be converted into `[T; N]`
impl<T: FSerializable + FDeserializable, const N: usize> FDeserializable for [T; N] {
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let expected = T::size_bytes() * N;
        if buffer.len() != expected {
            return Err(Error::DeserializationError(
                "Unexpected byte size for [T; N]".to_string(),
            ));
        }

        let each = T::size_bytes();
        let chunks = buffer.chunks_exact(each);
        let chunks = chunks.map(|e| T::deser_f(e));

        let ts: Vec<T> = chunks.collect::<Result<Vec<T>, Error>>()?;
        let ret: Result<[T; N], Error> = ts.try_into().map_err(|_| {
            Error::DeserializationError("Failed converting Vec<T> to [T; N]".to_string())
        });

        ret
    }
}

/// Special case implementation of `FSerializable` for 1-tuple
impl<A: FSerializable> FSerializable for (&A,) {
    fn size_bytes() -> usize {
        A::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        self.0.ser_into(buffer);
    }
}

/// Special case implementation of `FDeserializable` for 1-tuple
impl<A: FSerializable + FDeserializable> FDeserializable for (A,) {
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let length_a = A::size_bytes();
        if buffer.len() != length_a {
            return Err(Error::DeserializationError(
                "Unexpected byte length for (A,)".into(),
            ));
        }
        let a = A::deser_f(buffer)?;
        Ok((a,))
    }
}

/// Base case implementation of `FSerializable` for `generate_tuple_impl` macro
impl<A: FSerializable, B: FSerializable> FSerializable for (&A, &B) {
    fn size_bytes() -> usize {
        A::size_bytes() + B::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        // Serialize head
        self.0.ser_into(buffer);
        // Serialize the tail
        self.1.ser_into(buffer);
    }
}

/// Base case implementation of `FDeserializable` for `generate_tuple_impl` macro
#[crate::warning(
    "Tuple FDeserializable implementations (+ macro) do not validate total size with size_bytes()"
)]
impl<A: FSerializable + FDeserializable, B: FSerializable + FDeserializable> FDeserializable
    for (A, B)
{
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let length_a = A::size_bytes();

        let a_bytes = get_slice(buffer, 0..length_a)?;
        let b_bytes = get_slice(buffer, length_a..buffer.len())?;
        let a = A::deser_f(a_bytes)?;
        let b = B::deser_f(b_bytes)?;
        Ok((a, b))
    }
}

/**
 * Generates [`FSerializable`] and [`FDeserializable`] implementations for the given tuple.
 *
 * The tuple element types must already implement [`FSerializable`] and [`FDeserializable`].
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
 * use cryptography::utils::serialization::fixed::generate_tuple_impl;
 * use cryptography::utils::serialization::FSerializable;
 * use cryptography::groups::ristretto255::RistrettoElement;
 * use cryptography::groups::p256::P256Element;
 * use cryptography::groups::p256::P256Scalar;
 * use cryptography::traits::groups::GroupElement;
 * use crate::cryptographytraits::groups::GroupScalar;
 *
 * // Generate fixed length serialization implementations for a 3-tuple:
 * generate_tuple_impl!(A, B, C; 1, 2; 0, 1);
 * ```
 */
macro_rules! generate_tuple_impl {
    // $head_ty: The first generic type (e.g., A)
    // $($tail_tys): The rest of the generic types (e.g., B, C, D)
    // $($tail_indices): The tuple indices for the tail (e.g., 1, 2, 3)
    ($head_ty:ident, $($tail_tys:ident),+; $($tail_indices:tt),+; $($tail_access:tt),+) => {
        impl<$head_ty: FSerializable, $($tail_tys: FSerializable),+> FSerializable for (&$head_ty, $(&$tail_tys),+) {

            /// size = `size_of_head + size_of_tail_tuple`
            fn size_bytes() -> usize {
                // $head_ty::size_bytes() + <( $(&$tail_tys),+ )>::size_bytes()
                $head_ty::size_bytes() + <( $(&$tail_tys),+ )>::size_bytes()
            }

            fn ser_into(&self, buffer: &mut Vec<u8>) {
                // Serialize head
                self.0.ser_into(buffer);
                // This constructs the tail tuple, e.g., (&self.1, &self.2), and calls ser_into on it.
                let tail = ( $( self.$tail_indices ),+ );
                tail.ser_into(buffer);
            }
        }

        impl<
            $head_ty: FSerializable + FDeserializable,
            $($tail_tys: FSerializable + FDeserializable),+
        > FDeserializable for ($head_ty, $($tail_tys),+) {
            fn deser_f(buffer: &[u8]) -> Result<Self, Error> {

                // Determine the slice for the head element using its fixed length.
                let head_len = $head_ty::size_bytes();

                let head_bytes = get_slice(buffer, 0..head_len)?;
                let tail_bytes = get_slice(buffer, head_len..buffer.len())?;

                // Deserialize the head and the tail recursively.
                let head = $head_ty::deser_f(head_bytes)?;
                // The <(...)> syntax specifies the type for the recursive call.
                let tail = <( $($tail_tys),+ )>::deser_f(tail_bytes)?;

                // Reconstruct the final tuple from the deserialized parts.
                // The `tail.$tail_access` part expands to tail.0, tail.1, etc.
                Ok((head, $( tail.$tail_access ),+))
            }
        }
    };
}

/**
 * Generates [`FSerializable`] and [`FDeserializable`] implementations for a fixed set of tuple types.
 *
 * Calls the [`generate_tuple_impl`] macro for tuples of arity up to 7. Add additional
 * calls as needed for newly defined structs.
 */
macro_rules! impl_for_tuples {
    () => {

        generate_tuple_impl!(A, B, C; 1, 2; 0, 1);

        generate_tuple_impl!(A, B, C, D; 1, 2, 3; 0, 1, 2);

        generate_tuple_impl!(A, B, C, D, E; 1, 2, 3, 4; 0, 1, 2, 3);

        generate_tuple_impl!(A, B, C, D, E, F; 1, 2, 3, 4, 5; 0, 1, 2, 3, 4);

        generate_tuple_impl!(A, B, C, D, E, F, G; 1, 2, 3, 4, 5, 6; 0, 1, 2, 3, 4, 5);
    };
}

impl_for_tuples!();

/// Implements [`FSerializable`] for u32
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl FSerializable for u32 {
    fn size_bytes() -> usize {
        4
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.to_be_bytes();
        buffer.extend_from_slice(&bytes);
    }
}

/// Implements [`FDeserializable`] for u32
///
/// Required by [`ParticipantPosition`][`crate::dkgd::recipient::ParticipantPosition`]
impl FDeserializable for u32 {
    fn deser_f(bytes: &[u8]) -> Result<u32, Error> {
        let bytes: [u8; 4] = bytes.try_into()?;
        Ok(u32::from_be_bytes(bytes))
    }
}

/// Implements [`FSerializable`] for u64
impl FSerializable for u64 {
    fn size_bytes() -> usize {
        8
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.to_be_bytes();
        buffer.extend_from_slice(&bytes);
    }
}

/// Implements [`FDeserializable`] for u64
impl FDeserializable for u64 {
    fn deser_f(bytes: &[u8]) -> Result<u64, Error> {
        let bytes: [u8; 8] = bytes.try_into()?;
        Ok(u64::from_be_bytes(bytes))
    }
}

/// Marker trait for types implementing `FSerializable` and `FDeserializable`
pub trait FSer: FSerializable + FDeserializable {}
impl<T: FSerializable + FDeserializable> FSer for T {}
