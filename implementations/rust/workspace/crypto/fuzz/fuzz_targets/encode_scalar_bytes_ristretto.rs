/*
 * Fuzz target for 32-byte array encoding and decoding
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

#![no_main]

use crypto::groups::ristretto255::group::Ristretto255Group;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let encoded = Ristretto255Group::encode_32_bytes(&data);
    let decoded = Ristretto255Group::decode_32_bytes(&encoded.unwrap()).unwrap();
    assert_eq!(data, decoded);
});
