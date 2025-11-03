// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Challenge and transport serialization.
//!
//! This module defines and implements serialization traits
//! suitable for challenge generation and data transfer. Two
//! variants of serialization are defined
//!
//! - [`fixed`][`crate::utils::serialization::fixed`]: types that can be serialized into fixed length byte sequences
//!
//!   A type that implements `fixed` traits requires that all its instances serialize to
//!   a sequence of bytes of equal and fixed length.
//!
//! - [`variable`][`crate::utils::serialization::variable`]: types that can be serialized into variable length byte sequences
//!
//!   A type that implements `variable` traits does _not_ require that all its instances serialize to
//!   a sequence of bytes of equal and fixed length.
//!
//! * NOTE: It is the responsibility of the implementor to ensure consistency across builds. Changes
//!   to implementations can break challenge and data transfer functionality entirely. **In particular, serialization
//!   inconsistencies can cause otherwise valid proofs to fail.**
//!
//! # Using the `VSerializable` macro
//!
//! The `VSerializable` derive macro from the `vser_derive` crate can be used to automatically
//! generate `VSerializable` and `VDeserializable` implementations for structs. Additionally, if all
//! the members of the target structs implement `FSerializable` and `FDeserializable`, the struct itself
//! will support fixed length serialization.
//!
//! The following composite types are supported generically, provided that their elements implement
//! the required traits:
//!
//! - Structs
//! - Tuples
//! - Arrays
//! - Vectors
//!
//! Enums are not supported by the derive macro, and must be implemented manually.
//!
//! # Examples
//! ```
//! use cryptography::cryptosystem::elgamal::Ciphertext;
//! use cryptography::cryptosystem::elgamal::KeyPair;
//! use cryptography::context::Context;
//! use cryptography::context::RistrettoCtx as Ctx;
//! use cryptography::utils::serialization::fixed::{FDeserializable, FSerializable};
//! use cryptography::utils::serialization::variable::{VDeserializable, VSerializable};
//! // The macro is exported by the cryptography crate at its root
//! use cryptography::VSerializable as VSer;
//!
//! // A struct containing a keypair, a message, a ciphertext and an integer.
//! // Deriving the implementation works because all the members already
//! // implement VSerializable and VDeserializable.
//! //
//! // Note that
//! // - KeyPair and Ciphertext are themselves structs on which the derive macro has been applied.
//! // - [Ctx::Element; 2] is an array of `Ctx::Element`, which is constrained to implement
//! //   VSerializable and VDeserializable.
//! // - u32 is a primitive type that has a manual implementation of the traits.
//! #[derive(Debug, VSer, PartialEq)]
//! struct MyStruct<Ctx: Context>{
//!   keypair: KeyPair<Ctx>,
//!   message: [Ctx::Element; 2],
//!   ciphertext: Ciphertext<Ctx, 2>,
//!   my_number: u32
//! };
//!
//! // Create some sample data to instantiate our struct
//! let keypair = KeyPair::<Ctx>::generate();
//! let message = [Ctx::random_element(), Ctx::random_element()];
//! let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);
//! let my_struct = MyStruct{ keypair, message: message.clone(), ciphertext, my_number: 1 };
//!
//! // The variable length serialization functions are derived automatically
//! let serialized = my_struct.ser();
//! let back = MyStruct::<Ctx>::deser(&serialized).unwrap();
//! assert_eq!(my_struct, back);
//! let decrypted = back.keypair.decrypt(&back.ciphertext);
//! assert_eq!(message, decrypted);
//!
//! // Because all the member types of MyStruct implement FSerializable/FDeserializable, we
//! // can also use fixed length serialization.
//! //
//! // Note that the VSerializable derive macro does not implement
//! // FSerializable/FDeserializable directly; instead, the generic implementations
//! // within `fixed.rs` leverage the internal tuple conversions provided by the
//! // VSerializable macro to provide FSerializable/FDeserializable implementations.
//! let fixed_serialized = my_struct.ser_f();
//! let fixed_back = MyStruct::<Ctx>::deser_f(&fixed_serialized).unwrap();
//! assert_eq!(my_struct, fixed_back);
//!
//! // If we defined this struct instead..
//! #[derive(Debug, VSer, PartialEq)]
//! struct MyStruct2<Ctx: Context>{
//!   my_list: Vec<Ctx::Element>,
//! };
//!
//! let my_list = vec![Ctx::random_element(), Ctx::random_element()];
//! let my_struct2: MyStruct2<Ctx> = MyStruct2{ my_list };
//!
//! // ..the variable length serialization functions are still derived automatically..
//! let serialized2 = my_struct2.ser();
//! let back2 = MyStruct2::<Ctx>::deser(&serialized2).unwrap();
//! assert_eq!(my_struct2, back2);
//! // .. but fixed length serialization is not available, because Vec<T> does not
//! // implement FSerializable:
//! // let fixed_serialized2 = my_struct2.ser_f(); // This line would not compile
//!
//! // Lastly, this will not compile because u128 does not implement VSerializable,
//! // in which case we would need to implement the trait for `u128` manually.
//! // #[derive(Debug, VSer, PartialEq)]
//! // struct MyStruct3(u128);
//! ```
//!
//! If the `serde` feature is enabled this module also provides an
//! adapter implementation of serde traits, based on variable length
//! serialization implementations.
//!

pub use fixed::{FDeserializable, FSer, FSerializable};
pub use variable::{LargeVector, TFTuple, VDeserializable, VSer, VSerializable};

#[deny(clippy::indexing_slicing)]
#[crate::warning(
    "arithmetic side effects lints is disabled in this module (though this has been addressed for deserialization functions, pending fuzzing)."
)]
#[allow(clippy::arithmetic_side_effects)]
pub mod fixed;
#[cfg(feature = "serde")]
/// Serde implementations built on `V/FSerializable` traits
#[crate::warning("Missing ristretto serialization tests and some structs.")]
pub mod serde;
#[deny(clippy::indexing_slicing)]
#[crate::warning(
    "arithmetic side effects lints is disabled in this module (though this has been addressed for deserialization functions, pending fuzzing)."
)]
#[allow(clippy::arithmetic_side_effects)]
pub mod variable;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::utils::error::Error;
/// Helper to get a slice from a buffer, returning an error if the range is out of bounds
///
/// If we were to instead use raw slice indexing (e.g., `&buffer[start..end]`) it would panic
/// if the range is out of bounds. This function returns a proper error instead.
pub(crate) fn get_slice(buffer: &[u8], range: std::ops::Range<usize>) -> Result<&[u8], Error> {
    buffer.get(range).ok_or_else(|| {
        Error::DeserializationError("Input bytes too short to contain length prefix".into())
    })
}
