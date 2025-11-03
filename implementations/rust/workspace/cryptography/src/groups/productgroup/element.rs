// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! GroupElement implementations for products

use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::ReplGroupOps;

use crate::utils::rng;
use std::array;

impl<T: GroupElement, const N: usize> GroupElement for [T; N] {
    type Scalar = [T::Scalar; N];

    fn one() -> Self {
        array::from_fn(|_| T::one())
    }

    fn mul(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].mul(&other[i]))
    }

    fn inv(&self) -> Self {
        array::from_fn(|i| self[i].inv())
    }

    fn exp(&self, other: &Self::Scalar) -> Self {
        array::from_fn(|i| self[i].exp(&other[i]))
    }

    fn equals(&self, other: &Self) -> bool {
        for (i, item) in self.iter().enumerate() {
            let other: &T = &other[i];
            if !item.equals(other) {
                return false;
            }
        }
        true
    }

    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        array::from_fn(|_| T::random(rng))
    }
}

impl<T: GroupElement, const N: usize> ReplGroupOps<[T; N]> for T {
    type Result = [T; N];

    fn repl_mul(&self, other: &[T; N]) -> Self::Result {
        std::array::from_fn(|i| self.mul(&other[i]))
    }

    fn repl_exp(&self, other: &[T::Scalar; N]) -> Self::Result {
        std::array::from_fn(|i| self.exp(&other[i]))
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

impl<T: GroupElement, const N: usize> DistGroupOps<T> for [T; N] {
    type Result = Self;

    fn dist_mul(&self, other: &T) -> Self::Result {
        std::array::from_fn(|i| self[i].mul(other))
    }

    fn dist_exp(&self, other: &T::Scalar) -> Self::Result {
        std::array::from_fn(|i| self[i].exp(other))
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
