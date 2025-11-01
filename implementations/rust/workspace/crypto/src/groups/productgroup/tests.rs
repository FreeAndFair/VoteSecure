/*
 * Product group module tests
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

use crate::context::Context;
use crate::context::P256Ctx as PCtx;
use crate::context::RistrettoCtx as RCtx;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use crate::traits::groups::{DistGroupOps, ReplGroupOps};
use crate::traits::groups::{DistScalarOps, ReplScalarOps};

#[test]
fn test_element_inv_ristretto() {
    test_element_inv::<RCtx>();
}

#[test]
fn test_element_inv_p256() {
    test_element_inv::<PCtx>();
}

fn test_element_inv<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let val = <[C::Element; W]>::random(&mut rng);

    let op_inv = val.inv();
    let op = val.clone().map(|x| x.inv());

    assert_eq!(op_inv, op);

    // Test property: x * x.inv() == one()
    let one_product = val.mul(&op_inv);
    assert_eq!(one_product, <[C::Element; W]>::one());
}

#[test]
fn test_element_mul_ristretto() {
    test_element_mul::<RCtx>();
}

#[test]
fn test_element_mul_p256() {
    test_element_mul::<PCtx>();
}

fn test_element_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Element; W]>::random(&mut rng);
    let rhs = <[C::Element; W]>::random(&mut rng);

    let op_product = lhs.mul(&rhs);
    let op = lhs.iter().zip(rhs.iter());
    let op = op.map(|(l, r)| l.mul(&r));
    let op: [C::Element; W] = op.collect::<Vec<C::Element>>().try_into().unwrap();

    assert_eq!(op_product, op);
}

#[test]
fn test_element_one_ristretto() {
    test_element_one::<RCtx>();
}

#[test]
fn test_element_one_p256() {
    test_element_one::<PCtx>();
}

fn test_element_one<C: Context>() {
    const W: usize = 3;
    let one_array = <[C::Element; W]>::one();
    let expected_array = std::array::from_fn(|_| C::Element::one());
    assert_eq!(one_array, expected_array);
}

#[test]
fn test_element_dist_mul_ristretto() {
    test_element_dist_mul::<RCtx>();
}

#[test]
fn test_element_dist_mul_p256() {
    test_element_dist_mul::<PCtx>();
}

fn test_element_dist_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Element; W]>::random(&mut rng);
    let rhs = C::Element::random(&mut rng);

    let op_dist = lhs.dist_mul(&rhs);
    let op = lhs.map(|l| l.mul(&rhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_element_repl_mul_ristretto() {
    test_element_repl_mul::<RCtx>();
}

#[test]
fn test_element_repl_mul_p256() {
    test_element_repl_mul::<PCtx>();
}

fn test_element_repl_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = C::Element::random(&mut rng);
    let rhs = <[C::Element; W]>::random(&mut rng);

    let op_dist = lhs.repl_mul(&rhs);
    let op = rhs.map(|l| l.mul(&lhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_element_exp_ristretto() {
    test_element_exp::<RCtx>();
}

#[test]
fn test_element_exp_p256() {
    test_element_exp::<PCtx>();
}

fn test_element_exp<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let base = <[C::Element; W]>::random(&mut rng);
    let scalar = <[C::Scalar; W]>::random(&mut rng);

    let op_product = base.exp(&scalar);
    let op = base.iter().zip(scalar.iter());
    let op = op.map(|(b, s)| b.exp(s));
    let op: [C::Element; W] = op.collect::<Vec<C::Element>>().try_into().unwrap();

    assert_eq!(op_product, op);
}

#[test]
fn test_element_dist_exp_ristretto() {
    test_element_dist_exp::<RCtx>();
}

#[test]
fn test_element_dist_exp_p256() {
    test_element_dist_exp::<PCtx>();
}

fn test_element_dist_exp<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let base = <[C::Element; W]>::random(&mut rng);
    let scalar = C::Scalar::random(&mut rng);

    let op_dist = base.dist_exp(&scalar);
    let op = base.map(|b| b.exp(&scalar));

    assert_eq!(op_dist, op);
}

#[test]
fn test_element_repl_exp_ristretto() {
    test_element_repl_exp::<RCtx>();
}

#[test]
fn test_element_repl_exp_p256() {
    test_element_repl_exp::<PCtx>();
}

fn test_element_repl_exp<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let base = C::Element::random(&mut rng);
    let scalar = <[C::Scalar; W]>::random(&mut rng);

    let op_repl = base.repl_exp(&scalar);
    let op = scalar.map(|s| base.exp(&s));

    assert_eq!(op_repl, op);
}

#[test]
fn test_element_equals_ristretto() {
    test_element_equals::<RCtx>();
}

#[test]
fn test_element_equals_p256() {
    test_element_equals::<PCtx>();
}

fn test_element_equals<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let val1 = <[C::Element; W]>::random(&mut rng);
    let val2 = val1.clone();
    let mut val3 = val1.clone();
    val3[0] = C::Element::random(&mut rng);

    // Case 1: Identical arrays should be equal
    assert!(val1.equals(&val2));
    assert!(val2.equals(&val1));

    // Case 2: Different arrays should not be equal
    assert!(!val1.equals(&val3));
    assert!(!val3.equals(&val1));

    // Case 3: Array compared to itself
    assert!(val1.equals(&val1));
}

#[test]
fn test_element_dist_equals_ristretto() {
    test_element_dist_equals::<RCtx>();
}

#[test]
fn test_element_dist_equals_p256() {
    test_element_dist_equals::<PCtx>();
}

fn test_element_dist_equals<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let common_element = C::Element::random(&mut rng);
    let array_all_common: [C::Element; W] = std::array::from_fn(|_| common_element.clone());

    let mut array_one_different = array_all_common.clone();
    array_one_different[0] = C::Element::random(&mut rng);

    // Case 1: Array where all elements are equal to the single element
    assert!(array_all_common.dist_equals(&common_element));

    // Case 2: Array where one element is different
    assert!(!array_one_different.dist_equals(&common_element));

    // Case 3: Test with an element that should not match any
    let distinct_element = C::Element::random(&mut rng);
    assert!(!array_all_common.dist_equals(&distinct_element));
}

#[test]
fn test_element_repl_equals_ristretto() {
    test_element_repl_equals::<RCtx>();
}

#[test]
fn test_element_repl_equals_p256() {
    test_element_repl_equals::<PCtx>();
}

fn test_element_repl_equals<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let common_element = C::Element::random(&mut rng);
    let array_all_common: [C::Element; W] = std::array::from_fn(|_| common_element.clone());

    let mut array_one_different = array_all_common.clone();
    array_one_different[0] = C::Element::random(&mut rng);

    // Case 1: Single element equals all elements in the array
    assert!(common_element.repl_equals(&array_all_common));

    // Case 2: Single element does not equal all elements in the array
    assert!(!common_element.repl_equals(&array_one_different));

    // Case 3: Test with an element that should not match
    let distinct_element = C::Element::random(&mut rng);
    assert!(!distinct_element.repl_equals(&array_all_common));
}

#[test]
fn test_scalar_add_ristretto() {
    test_scalar_add::<RCtx>();
}

#[test]
fn test_scalar_add_p256() {
    test_scalar_add::<PCtx>();
}

fn test_scalar_add<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_product = lhs.add(&rhs);
    let op = lhs.iter().zip(rhs.iter());
    let op = op.map(|(l, r)| l.add(&r));
    let op: [C::Scalar; W] = op.collect::<Vec<C::Scalar>>().try_into().unwrap();

    assert_eq!(op_product, op);
}

#[test]
fn test_scalar_dist_add_ristretto() {
    test_scalar_dist_add::<RCtx>();
}

#[test]
fn test_scalar_dist_add_p256() {
    test_scalar_dist_add::<PCtx>();
}

fn test_scalar_dist_add<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = C::Scalar::random(&mut rng);

    let op_dist = lhs.dist_add(&rhs);
    let op = lhs.map(|l| l.add(&rhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_scalar_repl_add_ristretto() {
    test_scalar_repl_add::<RCtx>();
}

#[test]
fn test_scalar_repl_add_p256() {
    test_scalar_repl_add::<PCtx>();
}

fn test_scalar_repl_add<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = C::Scalar::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_dist = lhs.repl_add(&rhs);
    let op = rhs.map(|l| l.add(&lhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_sub_ristretto() {
    test_sub::<RCtx>();
}

#[test]
fn test_sub_p256() {
    test_sub::<PCtx>();
}

fn test_sub<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_product = lhs.sub(&rhs);
    let op = lhs.iter().zip(rhs.iter());
    let op = op.map(|(l, r)| l.sub(&r));
    let op: [C::Scalar; W] = op.collect::<Vec<C::Scalar>>().try_into().unwrap();

    assert_eq!(op_product, op);
}

#[test]
fn test_scalar_dist_sub_ristretto() {
    test_scalar_dist_sub::<RCtx>();
}

#[test]
fn test_scalar_dist_sub_p256() {
    test_scalar_dist_sub::<PCtx>();
}

fn test_scalar_dist_sub<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = C::Scalar::random(&mut rng);

    let op_dist = lhs.dist_sub(&rhs);
    let op = lhs.map(|l| l.sub(&rhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_scalar_repl_sub_ristretto() {
    test_scalar_repl_sub::<RCtx>();
}

#[test]
fn test_scalar_repl_sub_p256() {
    test_scalar_repl_sub::<PCtx>();
}

fn test_scalar_repl_sub<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = C::Scalar::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_dist = lhs.repl_sub(&rhs);
    let op = rhs.map(|l| lhs.sub(&l));

    assert_eq!(op_dist, op);
}

#[test]
fn test_mul_ristretto() {
    test_mul::<RCtx>();
}

#[test]
fn test_mul_p256() {
    test_mul::<PCtx>();
}

fn test_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_product = lhs.mul(&rhs);
    let op = lhs.iter().zip(rhs.iter());
    let op = op.map(|(l, r)| l.mul(&r));
    let op: [C::Scalar; W] = op.collect::<Vec<C::Scalar>>().try_into().unwrap();

    assert_eq!(op_product, op);
}

#[test]
fn test_scalar_dist_mul_ristretto() {
    test_scalar_dist_mul::<RCtx>();
}

#[test]
fn test_scalar_dist_mul_p256() {
    test_scalar_dist_mul::<PCtx>();
}

fn test_scalar_dist_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = <[C::Scalar; W]>::random(&mut rng);
    let rhs = C::Scalar::random(&mut rng);

    let op_dist = lhs.dist_mul(&rhs);
    let op = lhs.map(|l| l.mul(&rhs));

    assert_eq!(op_dist, op);
}

#[test]
fn test_scalar_repl_mul_ristretto() {
    test_scalar_repl_mul::<RCtx>();
}

#[test]
fn test_scalar_repl_mul_p256() {
    test_scalar_repl_mul::<PCtx>();
}

fn test_scalar_repl_mul<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let lhs = C::Scalar::random(&mut rng);
    let rhs = <[C::Scalar; W]>::random(&mut rng);

    let op_dist = lhs.repl_mul(&rhs);
    let op = rhs.map(|l| lhs.mul(&l));

    assert_eq!(op_dist, op);
}

#[test]
fn test_neg_ristretto() {
    test_neg::<RCtx>();
}

#[test]
fn test_neg_p256() {
    test_neg::<PCtx>();
}

fn test_neg<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let val = <[C::Scalar; W]>::random(&mut rng);

    let op_neg = val.neg();
    let op = val.clone().map(|x| x.neg());

    assert_eq!(op_neg, op);

    let zero_sum = val.add(&op_neg);
    assert_eq!(zero_sum, <[C::Scalar; W]>::zero());
}

#[test]
fn test_inv_ristretto() {
    test_inv::<RCtx>();
}

#[test]
fn test_inv_p256() {
    test_inv::<PCtx>();
}

fn test_inv<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();
    let val = <[C::Scalar; W]>::random(&mut rng);

    let op_inv = val.inv();
    let op: Option<[C::Scalar; W]> = val
        .iter()
        .map(|x| x.inv())
        .collect::<Option<Vec<C::Scalar>>>()
        .map(|v| v.try_into().unwrap());

    assert_eq!(op_inv, op);

    // Test property: x * x.inv() == one() (if inv is Some)
    if let Some(op_inv_val) = op_inv {
        let one_product = val.mul(&op_inv_val);
        assert_eq!(one_product, <[C::Scalar; W]>::one());
    }
}

#[test]
fn test_zero_ristretto() {
    test_zero::<RCtx>();
}

#[test]
fn test_zero_p256() {
    test_zero::<PCtx>();
}

fn test_zero<C: Context>() {
    const W: usize = 3;
    let zero_array = <[C::Scalar; W]>::zero();
    let expected_array = std::array::from_fn(|_| C::Scalar::zero());
    assert_eq!(zero_array, expected_array);
}

#[test]
fn test_one_scalar_ristretto() {
    test_one_scalar::<RCtx>();
}

#[test]
fn test_one_scalar_p256() {
    test_one_scalar::<PCtx>();
}

fn test_one_scalar<C: Context>() {
    const W: usize = 3;
    let one_array = <[C::Scalar; W]>::one();
    let expected_array = std::array::from_fn(|_| C::Scalar::one());
    assert_eq!(one_array, expected_array);
}

#[test]
fn test_equals_scalar_ristretto() {
    test_equals_scalar::<RCtx>();
}

#[test]
fn test_equals_scalar_p256() {
    test_equals_scalar::<PCtx>();
}

fn test_equals_scalar<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let val1 = <[C::Scalar; W]>::random(&mut rng);
    let val2 = val1.clone();
    let mut val3 = val1.clone();
    val3[0] = C::Scalar::random(&mut rng);

    // Case 1: Identical arrays should be equal
    assert!(val1.equals(&val2));
    assert!(val2.equals(&val1));

    // Case 2: Different arrays should not be equal
    assert!(!val1.equals(&val3));
    assert!(!val3.equals(&val1));
}

#[test]
fn test_scalar_dist_equals_scalar_ristretto() {
    test_scalar_dist_equals_scalar::<RCtx>();
}

#[test]
fn test_scalar_dist_equals_scalar_p256() {
    test_scalar_dist_equals_scalar::<PCtx>();
}

fn test_scalar_dist_equals_scalar<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let common_element = C::Scalar::random(&mut rng);
    let array_all_common: [C::Scalar; W] = std::array::from_fn(|_| common_element.clone());

    let mut array_one_different = array_all_common.clone();
    array_one_different[0] = C::Scalar::random(&mut rng);

    // Case 1: Array where all elements are equal to the single element
    assert!(array_all_common.dist_equals(&common_element));

    // Case 2: Array where one element is different
    assert!(!array_one_different.dist_equals(&common_element));

    // Case 3: Test with an element that should not match
    let distinct_element = C::Scalar::random(&mut rng);
    assert!(!array_all_common.dist_equals(&distinct_element));
}

#[test]
fn test_scalar_repl_equals_scalar_ristretto() {
    test_scalar_repl_equals_scalar::<RCtx>();
}

#[test]
fn test_scalar_repl_equals_scalar_p256() {
    test_scalar_repl_equals_scalar::<PCtx>();
}

fn test_scalar_repl_equals_scalar<C: Context>() {
    const W: usize = 3;
    let mut rng = C::get_rng();

    let common_element = C::Scalar::random(&mut rng);
    let array_all_common: [C::Scalar; W] = std::array::from_fn(|_| common_element.clone());

    let mut array_one_different = array_all_common.clone();
    array_one_different[0] = C::Scalar::random(&mut rng);

    // Case 1: Single element equals all elements in the array
    assert!(common_element.repl_equals(&array_all_common));

    // Case 2: Single element does not equal all elements in the array
    assert!(!common_element.repl_equals(&array_one_different));

    // Case 3: Test with an element that should not match
    let distinct_element = C::Scalar::random(&mut rng);
    assert!(!distinct_element.repl_equals(&array_all_common));
}
