// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Hash accumulator

use super::types::TrusteeIndex;
use core::panic;
use std::collections::BTreeSet;
use std::hash::Hash;

const MAX_TRUSTEES: usize = 24;

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct AccumulatorSet<T> {
    values: [Option<T>; MAX_TRUSTEES],
    value_set: BTreeSet<T>,
}
impl<T: Ord + std::fmt::Debug + Clone> AccumulatorSet<T> {
    pub fn new(init: T) -> Self {
        AccumulatorSet {
            values: std::array::from_fn(|_| None),
            value_set: BTreeSet::new(),
        }
        .add(init, 1)
    }
    pub(crate) fn add(&self, rhs: T, index: TrusteeIndex) -> Self {
        let existing = self.values[index].clone();
        // If the value at the index is already set, is must match the supplied value
        if let Some(existing) = existing {
            if existing != rhs {
                panic!(
                    "Attempted to add different value at index {}: existing {:?}, new {:?}",
                    index, existing, rhs
                );
            } else {
                // We already have this value at the index, no change needed
                return self.clone();
            }
        }
        // If the value at the index is _not_ set, it must not match any other value
        // at a different index
        else if self.value_set.contains(&rhs) {
            panic!(
                "Attempted to add duplicate value {:?} at index {}",
                rhs, index
            );
        }

        // At this point, the addition is valid
        let mut ret = AccumulatorSet {
            values: self.values.clone(),
            value_set: self.value_set.clone(),
        };
        ret.value_set.insert(rhs.clone());
        ret.values[index] = Some(rhs.clone());

        ret
    }

    pub(crate) fn extract(&self) -> Vec<T> {
        let some = self.values.iter().filter(|t| t.is_some());
        some.map(|t| t.clone().expect("t.is_some() == true"))
            .collect()
    }
}
