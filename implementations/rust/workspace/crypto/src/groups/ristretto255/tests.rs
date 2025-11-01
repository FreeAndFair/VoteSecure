/*
 * Ristretto255 module tests
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

use super::*;
use crate::context::Context;
use crate::context::RistrettoCtx as Ctx;
use crate::groups::ristretto255::Ristretto255Group as RGroup;
use crate::traits::groups::CryptoGroup;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::utils::serialization::{VDeserializable, VSerializable};

#[test]
fn test_ristretto_scalar_from_u32() {
    use rand::Rng;
    let u: u32 = Ctx::get_rng().r#gen();

    let _scalar: RistrettoScalar = u.into();
    let one: RistrettoScalar = 1u32.into();
    assert_eq!(one, RistrettoScalar::one());
}

#[test]
fn test_ristretto_scalar_negation() {
    let s1 = Ctx::random_scalar();
    let s_neg = s1.neg();

    assert_eq!(
        s_neg.add(&s1),
        RistrettoScalar::zero(),
        "Negation property s + (-s) = 0 failed"
    );
}

#[test]
fn test_ristretto_scalar_inversion() {
    let s = Ctx::random_scalar();

    if s != RistrettoScalar::zero() {
        let s_inv = s.inv().unwrap();
        let product = s.mul(&s_inv);
        assert_eq!(
            product,
            RistrettoScalar::one(),
            "s * s_inv = 1 property failed"
        );
    }

    let zero = RistrettoScalar::zero();
    assert!(zero.inv().is_none(), "Inversion of zero must be None");
}

#[test]
fn test_ristretto_power_product() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();
    let g = Ctx::generator();

    let e1 = g.exp(&s1);
    let e2 = g.exp(&s2);
    let e3_sum = e1.mul(&e2);

    let s_sum = s1.add(&s2);
    let e3_expected = g.exp(&s_sum);

    assert_eq!(
        e3_sum, e3_expected,
        "Element addition failed: e1+e2 != (s1+s2)*G"
    );
}

#[test]
fn test_ristretto_element_inv() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e = g.exp(&s);

    let e_neg = e.inv();
    let e_plus_e_neg = e.mul(&e_neg);

    assert_eq!(
        e_plus_e_neg,
        RistrettoElement::one(),
        "Element negation failed: e + (-e) != Id"
    );

    let s_neg = s.neg();
    let e_neg_expected = g.exp(&s_neg);
    assert_eq!(
        e_neg, e_neg_expected,
        "Element negation failed: (-s)*G != -(s*G)"
    );
}

#[test]
fn test_ristretto_power_power() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();
    let g = Ctx::generator();

    let e1 = g.exp(&s1);
    let e2 = e1.exp(&s2);

    let s_prod = s1.mul(&s2);
    let e_expected = g.exp(&s_prod);

    assert_eq!(e2, e_expected, "Element scalar multiplication failed");
}

#[test]
fn test_ristretto_element_identity_properties() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e = g.exp(&s);
    let id = RistrettoElement::one();

    assert_eq!(e.mul(&id), e, "e + Id != e");
    assert_eq!(id.mul(&e), e, "Id + e != e");

    let zero_scalar = RistrettoScalar::zero();
    assert_eq!(g.exp(&zero_scalar), id, "G^0 != Id");
}

#[test]
fn test_ristretto_element_mul_commutativity() {
    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();

    let sum1 = e1.mul(&e2);
    let sum2 = e2.mul(&e1);

    assert_eq!(sum1, sum2, "Element multiplication is not commutative");
}

#[test]
fn test_ristretto_element_mul_associativity() {
    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();
    let e3 = Ctx::random_element();

    let sum_left_assoc = (e1.mul(&e2)).mul(&e3);
    let sum_right_assoc = e1.mul(&(e2.mul(&e3)));

    assert_eq!(
        sum_left_assoc, sum_right_assoc,
        "Element multiplication is not associative"
    );
}

#[test]
fn test_ristretto_scalar_element_exp_distributivity() {
    let s_op = Ctx::random_scalar();

    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();

    // (e1 * e2)^s
    let sum_elements = e1.mul(&e2);
    let lhs = sum_elements.exp(&s_op);

    // (e1^s) * (e2^s)
    let term1 = e1.exp(&s_op);
    let term2 = e2.exp(&s_op);
    let rhs = term1.mul(&term2);

    assert_eq!(lhs, rhs, "Distributivity (e1*e2)^s = e1^s * e2^s failed");
}

#[test]
fn test_ristretto_scalar_element_mul_distributivity() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();

    let e = Ctx::random_element();

    let sum_scalars = s1.add(&s2);
    let lhs = e.exp(&sum_scalars);

    let term1 = e.exp(&s1);
    let term2 = e.exp(&s2);
    let rhs = term1.mul(&term2);

    assert_eq!(lhs, rhs, "Distributivity e^(s1+s2) = e^s1 + e^s2 failed");
}

#[test]
fn test_ristretto_g_exp() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();

    let lhs = g.exp(&s);
    let rhs = Ristretto255Group::g_exp(&s);

    assert_eq!(lhs, rhs);
}

#[test]
fn test_ristretto_encode_decode_30_bytes() {
    use rand::Rng;

    let mut rng = Ctx::get_rng();
    let mut lhs = [0u8; 30];
    rng.fill(&mut lhs[..]);

    let element = Ristretto255Group::encode_30_bytes(&lhs).unwrap();
    let rhs = Ristretto255Group::decode_30_bytes(&element).unwrap();

    assert_eq!(lhs, rhs);
}

#[test]
fn test_ristretto_encode_decode_array() {
    use rand::Rng;

    let mut rng = Ctx::get_rng();

    // Test with array of size 3
    let mut lhs: [[u8; 30]; 3] = [[0u8; 30]; 3];
    for plaintext in &mut lhs {
        rng.fill(&mut plaintext[..]);
    }

    let elements = Ristretto255Group::encode_array(&lhs).unwrap();
    let rhs = Ristretto255Group::decode_array(&elements).unwrap();

    assert_eq!(lhs, rhs);
}

#[test]
fn test_ristretto_group_hash_to_scalar() {
    let input1 = b"some input data";
    let input2 = b"other input data";
    let ds_tag = b"ds tag";

    let s1 = Ristretto255Group::hash_to_scalar(&[input1], &[ds_tag]).unwrap();
    // Same input, same output
    let s2 = Ristretto255Group::hash_to_scalar(&[input1], &[ds_tag]).unwrap();
    // Different input, different output
    let s3 = Ristretto255Group::hash_to_scalar(&[input2], &[ds_tag]).unwrap();

    assert_eq!(s1, s2, "Hash to scalar not equal for equal input");
    assert_ne!(
        s1, s3,
        "Hash to scalar produces same output for different inputs"
    );
}

#[test]
fn test_ristretto_element_serialization() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e_orig = g.exp(&s);

    let serialized_e = e_orig.ser();
    assert_eq!(serialized_e.len(), 32, "Serialized element length mismatch");

    let e_deserialized = RistrettoElement::deser(&serialized_e).unwrap();
    assert_eq!(
        e_orig, e_deserialized,
        "Original and deserialized elements do not match"
    );

    // Test identity
    let e_id = RistrettoElement::one();
    let ser_id = e_id.ser();
    let des_id = RistrettoElement::deser(&ser_id).unwrap();
    assert_eq!(e_id, des_id);

    // test wrong length
    let bytes = [0u8; 40];
    let result = RistrettoElement::deser(&bytes);
    assert!(result.is_err());

    // test bad data
    // this array of bytes does not correspond to a point
    let bytes = [1u8; 32];
    let result = RistrettoElement::deser(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_ristretto_scalar_serialization() {
    let s_orig = Ctx::random_scalar();

    let serialized_s = s_orig.ser();
    assert_eq!(serialized_s.len(), 32, "Serialized scalar length mismatch");

    let s_deserialized = RistrettoScalar::deser(&serialized_s).unwrap();
    assert_eq!(
        s_orig, s_deserialized,
        "Original and deserialized scalars do not match"
    );

    let s_zero = RistrettoScalar::zero();
    let ser_zero = s_zero.ser();
    let des_zero = RistrettoScalar::deser(&ser_zero).unwrap();
    assert_eq!(s_zero, des_zero);

    let s_one = RistrettoScalar::one();
    let ser_one = s_one.ser();
    let des_one = RistrettoScalar::deser(&ser_one).unwrap();
    assert_eq!(s_one, des_one);

    // test wrong length
    let bytes = [0u8; 40];
    let result = RistrettoScalar::deser(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_ristretto_hash_to_element_different_inputs() {
    let input1 = b"hello";
    let input2 = b"world";
    let tag = b"ristretto_tag";

    let elem1 = RGroup::hash_to_element(&[input1], &[tag]).unwrap();
    let elem2 = RGroup::hash_to_element(&[input2], &[tag]).unwrap();
    let elem3 = RGroup::hash_to_element(&[input1], &[tag]).unwrap();

    assert_ne!(elem1, elem2);
    assert_eq!(elem1, elem3);
}

#[test]
fn test_ristretto_hash_to_element_different_tags() {
    let input = b"same input";
    let tag1 = b"tagA";
    let tag2 = b"tagB";

    let elem1 = RGroup::hash_to_element(&[input], &[tag1]).unwrap();
    let elem2 = RGroup::hash_to_element(&[input], &[tag2]).unwrap();

    assert_ne!(elem1, elem2);
}

#[test]
fn test_ristretto_hash_to_element_empty_input() {
    let _ = RGroup::hash_to_element(&[], &[]);
}

#[test]
fn test_ristretto_hash_to_scalar_empty_input() {
    let _ = RGroup::hash_to_scalar(&[], &[]);
}

#[test]
fn test_ristretto_scalar_encode() {
    let s = Ctx::random_scalar();
    let elements = RGroup::encode_scalar(&s).unwrap();

    let s_decoded = RGroup::decode_scalar(&elements).unwrap();
    assert_eq!(s, s_decoded, "Decoded scalar does not match original");
}

#[test]
fn test_ristretto_encode_decode_generic() {
    // 10 bytes -> should require 1 element (10 <= 30)
    let original_data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    let encoded: [RistrettoElement; 1] = RGroup::encode_bytes(&original_data).unwrap();
    let decoded: [u8; 10] = RGroup::decode_bytes(&encoded).unwrap();

    assert_eq!(original_data, decoded);

    // exactly 30 bytes -> should require exactly 1 element
    let original_data = [42u8; 30];

    let encoded: [RistrettoElement; 1] = RGroup::encode_bytes(&original_data).unwrap();
    let decoded: [u8; 30] = RGroup::decode_bytes(&encoded).unwrap();

    assert_eq!(original_data, decoded);

    // 31 bytes -> should require 2 elements (31 > 30, so ceil(31/30) = 2)
    let mut original_data = [0u8; 31];
    for (i, byte) in original_data.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    let encoded: [RistrettoElement; 2] = RGroup::encode_bytes(&original_data).unwrap();
    let decoded: [u8; 31] = RGroup::decode_bytes(&encoded).unwrap();

    assert_eq!(original_data, decoded);

    // 60 bytes -> should require exactly 2 elements (60/30 = 2)
    let mut original_data = [0u8; 60];
    for (i, byte) in original_data.iter_mut().enumerate() {
        *byte = ((i * 7) % 256) as u8; // Some pattern to make it interesting
    }

    let encoded: [RistrettoElement; 2] = RGroup::encode_bytes(&original_data).unwrap();
    let decoded: [u8; 60] = RGroup::decode_bytes(&encoded).unwrap();

    assert_eq!(original_data, decoded);

    // 61 bytes -> should require 3 elements (ceil(61/30) = 3)
    let mut original_data = [0u8; 61];
    for (i, byte) in original_data.iter_mut().enumerate() {
        *byte = ((i * 13) % 256) as u8;
    }

    let encoded: [RistrettoElement; 3] = RGroup::encode_bytes(&original_data).unwrap();
    let decoded: [u8; 61] = RGroup::decode_bytes(&encoded).unwrap();

    assert_eq!(original_data, decoded);

    // fails to compile: 31 bytes needs 2 elements, not 1
    // let data = [0u8; 31];
    // let _encoded = RGroup::encode_bytes::<31, 1>(&data).unwrap();

    // fails to compile: 10 bytes only needs 1 element, not 2
    // let data = [0u8; 10];
    // let _encoded = RGroup::encode_bytes::<10, 2>(&data).unwrap();

    // fails to compile: trying to decode 2 elements into 10 bytes
    // let elements = [RistrettoElement::one(); 2];
    // let _decoded = RGroup::decode_bytes::<2, 10>(&elements).unwrap();

    // fails to compile: 0 is not allowed
    // let data = [0u8; 0];
    // let _encoded: [RistrettoElement; 0] = RGroup::encode_bytes (&data).unwrap();
}
