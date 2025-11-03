// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Fuzz target example

#![no_main]

use cryptography::utils::serialization::VDeserializable;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = u32::deser(&data);
});
