// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Fuzz target for Ristretto255 encoding and decoding.

#![no_main]

use cryptography::groups::ristretto255::group::Ristretto255Group;
use cryptography::traits::groups::CryptographicGroup;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 90]| {
    let encoded = Ristretto255Group::encode_bytes::<90, 3>(&data);
    let decoded = Ristretto255Group::decode_bytes::<3, 90>(&encoded.unwrap()).unwrap();
    assert_eq!(data, decoded);
});
