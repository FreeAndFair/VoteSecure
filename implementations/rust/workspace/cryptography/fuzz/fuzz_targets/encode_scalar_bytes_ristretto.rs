// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Fuzz target for 32-byte array encoding and decoding

#![no_main]

use cryptography::groups::ristretto255::group::Ristretto255Group;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let encoded = Ristretto255Group::encode_32_bytes(&data);
    let decoded = Ristretto255Group::decode_32_bytes(&encoded.unwrap()).unwrap();
    assert_eq!(data, decoded);
});
