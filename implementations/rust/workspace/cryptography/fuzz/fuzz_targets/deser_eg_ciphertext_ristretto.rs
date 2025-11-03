// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Fuzz target for ciphertext deserialization.

#![no_main]

use cryptography::context::RistrettoCtx;
use cryptography::cryptosystem::elgamal::Ciphertext;
use cryptography::utils::serialization::VDeserializable;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Ciphertext::<RistrettoCtx, 2>::deser(&data);
});
