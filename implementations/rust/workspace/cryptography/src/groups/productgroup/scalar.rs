// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! GroupScalar implementations for products

use crate::traits::groups::DistScalarOps;
use crate::traits::groups::GroupScalar;
use crate::traits::groups::ReplScalarOps;

use crate::utils::rng;
use std::array;

impl<T: GroupScalar, const N: usize> GroupScalar for [T; N] {
    fn zero() -> Self {
        array::from_fn(|_| T::zero())
    }

    fn one() -> Self {
        array::from_fn(|_| T::one())
    }

    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        array::from_fn(|_| T::random(rng))
    }

    fn add(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].add(&other[i]))
    }

    fn sub(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].sub(&other[i]))
    }

    fn mul(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].mul(&other[i]))
    }

    fn neg(&self) -> Self {
        array::from_fn(|i| self[i].neg())
    }

    fn inv(&self) -> Option<Self> {
        let ret: Option<Vec<T>> = self.iter().map(GroupScalar::inv).collect();

        ret.map(|v| v.try_into().expect("v.len() == N"))
    }

    fn equals(&self, other: &Self) -> bool {
        for i in 0..self.len() {
            if self[i] != other[i] {
                return false;
            }
        }
        true
    }
}

impl<T: GroupScalar, const N: usize> ReplScalarOps<[T; N]> for T {
    type Output = [T; N];

    fn repl_add(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.add(&other[i]))
    }

    fn repl_sub(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.sub(&other[i]))
    }

    fn repl_mul(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.mul(&other[i]))
    }

    fn repl_equals(&self, other: &[T; N]) -> bool {
        for item in other {
            if !item.equals(self) {
                return false;
            }
        }
        true
    }
}

impl<T: GroupScalar, const N: usize> DistScalarOps<T> for [T; N] {
    type Output = Self;

    fn dist_add(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].add(other))
    }

    fn dist_sub(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].sub(other))
    }

    fn dist_mul(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].mul(other))
    }

    fn dist_equals(&self, other: &T) -> bool {
        for item in self {
            if !item.equals(other) {
                return false;
            }
        }
        true
    }
}
