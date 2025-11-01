/*
 * Fuzz target for Ristretto255 encoding and decoding.
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

#![no_main]

use crypto::groups::ristretto255::group::Ristretto255Group;
use crypto::traits::groups::CryptoGroup;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 30]| {
    let encoded = Ristretto255Group::encode(&data);
    let decoded = Ristretto255Group::decode(&encoded.unwrap()).unwrap();
    assert_eq!(data, decoded);
});
