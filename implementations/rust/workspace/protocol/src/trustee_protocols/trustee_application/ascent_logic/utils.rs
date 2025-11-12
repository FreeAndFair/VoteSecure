/*
 * Hash accumulator
 *
 * @author David Ruescas (david@sequentech.io)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

use super::types::TrusteeIndex;
use crate::crypto::CryptoHash;
use rand::Rng;
use std::collections::BTreeSet;
use std::hash::Hash as HashTrait;

const MAX_TRUSTEES: usize = 24;

#[derive(Clone, HashTrait, PartialEq, Eq, Debug)]
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
        let mut ret = AccumulatorSet {
            values: self.values.clone(),
            value_set: self.value_set.clone(),
        };

        if !ret.value_set.contains(&rhs) && ret.values[index].is_none() {
            ret.value_set.insert(rhs.clone());
            ret.values[index] = Some(rhs.clone());
        }

        ret
    }
    pub(crate) fn is_complete(&self, trustee_count: usize) -> bool {
        self.value_set.len() == trustee_count
    }

    pub(crate) fn extract(&self) -> Vec<T> {
        let some = self.values.iter().filter(|t| t.is_some());
        some.map(|t| t.clone().expect("impossible")).collect()
    }
}

/// Utility function used in stateright tests
pub(crate) fn empty_hash() -> CryptoHash {
    [0u8; 64].into()
}
/// Utility function used in stateright tests
pub(crate) fn random_hash() -> CryptoHash {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill(&mut bytes);
    bytes.into()
}
