// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Distributed key generation and decryption module tests

use crate::cryptosystem::elgamal::Ciphertext;
use crate::dkgd::dealer::{Dealer, VerifiableShare};
use crate::dkgd::recipient::combine;
use crate::dkgd::recipient::{DecryptionFactor, DkgPublicKey, ParticipantPosition, Recipient};
use crate::traits::groups::DistGroupOps;
use crate::traits::groups::GroupElement;
use crate::traits::groups::GroupScalar;
use std::array;

use crate::context::Context;
use crate::context::RistrettoCtx as RCtx;
use crate::context::RistrettoCtx as PCtx;
use rand::seq::SliceRandom;

#[test]
fn test_joint_pkey_ristretto() {
    test_joint_pkey::<RCtx, 2, 2, 2>();
    test_joint_pkey::<RCtx, 2, 3, 2>();
    test_joint_pkey::<RCtx, 3, 4, 2>();
}

#[test]
fn test_joint_pkey_p256() {
    test_joint_pkey::<PCtx, 2, 2, 2>();
    test_joint_pkey::<PCtx, 2, 3, 2>();
    test_joint_pkey::<PCtx, 3, 4, 2>();
}

#[test]
fn test_dkgd_ristretto() {
    test_dkgd::<RCtx, 2, 2, 2>();
    test_dkgd::<RCtx, 2, 3, 2>();
    test_dkgd::<RCtx, 3, 4, 2>();
    test_dkgd_non_t::<RCtx, 1, 1, 2>();
}

#[test]
fn test_dkgd_p256() {
    test_dkgd::<PCtx, 2, 2, 2>();
    test_dkgd::<PCtx, 2, 3, 2>();
    test_dkgd::<PCtx, 3, 4, 2>();
    test_dkgd_non_t::<PCtx, 1, 1, 2>();
}

#[test]
fn test_dkgd_non_t_ristretto() {
    test_dkgd_non_t::<RCtx, 2, 2, 2>();
    test_dkgd_non_t::<RCtx, 2, 3, 2>();
    test_dkgd_non_t::<RCtx, 3, 3, 2>();
    test_dkgd_non_t::<RCtx, 3, 4, 2>();
    test_dkgd_non_t::<RCtx, 1, 1, 2>();
}

#[test]
fn test_dkgd_non_t_p256() {
    test_dkgd_non_t::<PCtx, 2, 2, 2>();
    test_dkgd_non_t::<PCtx, 2, 3, 2>();
    test_dkgd_non_t::<PCtx, 3, 3, 2>();
    test_dkgd_non_t::<PCtx, 3, 4, 2>();
    test_dkgd_non_t::<PCtx, 1, 1, 2>();
}

fn test_dkgd<C: Context, const T: usize, const P: usize, const W: usize>() {
    assert!(T <= P);

    let dealers: [Dealer<C, T, P>; P] = array::from_fn(|_| Dealer::generate());

    let mut recipients: [(Recipient<C, T, P>, DkgPublicKey<C, T>); P] = array::from_fn(|i| {
        let position = ParticipantPosition::from_usize(i + 1);

        let verifiable_shares: [VerifiableShare<C, T>; P] = dealers
            .clone()
            .map(|d| d.get_verifiable_shares().for_recipient(&position));

        Recipient::from_shares(position, &verifiable_shares).unwrap()
    });

    // check different ways of computing verification keys match
    let verification_keys: [C::Element; T] =
        array::from_fn(|i| recipients[i].0.get_verification_key().clone());

    let all_checking_values: [[<C as Context>::Element; T]; P] =
        dealers.clone().map(|d| d.get_checking_values());
    let verification_keys_2: [C::Element; T] = array::from_fn(|i| {
        let position: ParticipantPosition<P> = ParticipantPosition::from_usize(i + 1);
        Recipient::<C, T, P>::verification_key(&position, &all_checking_values)
    });
    assert_eq!(verification_keys, verification_keys_2);

    let mut rng = C::get_rng();
    recipients.shuffle(&mut rng);

    let pk: &DkgPublicKey<C, T> = &recipients[0].1;

    let message: [C::Element; W] = array::from_fn(|_| C::random_element());
    let encrypted = vec![pk.encrypt(&message)];

    // we need to do this again, because recipients have been shuffled
    let verification_keys: [C::Element; T] =
        array::from_fn(|i| recipients[i].0.get_verification_key().clone());

    let dfactors: [Vec<DecryptionFactor<C, P, W>>; P] =
        recipients.map(|r| r.0.decryption_factor(&encrypted, &vec![]).unwrap());

    let threshold: &[Vec<DecryptionFactor<C, P, W>>; T] = dfactors[0..T]
        .try_into()
        .expect("slice matches array: T == T");
    let decrypted = combine(&encrypted, &threshold, &verification_keys, &vec![]);
    assert!(message == decrypted.unwrap()[0]);
}

fn test_dkgd_non_t<C: Context, const T: usize, const P: usize, const W: usize>() {
    assert!(T <= P);

    let dealers: [Dealer<C, T, P>; P] = array::from_fn(|_| Dealer::generate());

    let recipients: [(Recipient<C, T, P>, DkgPublicKey<C, T>); P] = array::from_fn(|i| {
        let position = ParticipantPosition::from_usize(i + 1);

        let verifiable_shares: [VerifiableShare<C, T>; P] = dealers
            .clone()
            .map(|d| d.get_verifiable_shares().for_recipient(&position));

        Recipient::from_shares(position, &verifiable_shares).unwrap()
    });

    let pk: &DkgPublicKey<C, T> = &recipients[0].1;

    let message: [C::Element; W] = array::from_fn(|_| C::random_element());
    let encrypted = vec![pk.encrypt(&message)];

    let mut dfactors: [Vec<DecryptionFactor<C, P, W>>; P] =
        recipients.map(|r| r.0.decryption_factor(&encrypted, &vec![]).unwrap());
    let mut rng = C::get_rng();
    dfactors.shuffle(&mut rng);

    // using all participants, not just T of them
    assert_eq!(dfactors.len(), P);

    let encrypted: Vec<Ciphertext<C, W>> = encrypted.iter().map(|e| e.0.clone()).collect();
    let decrypted = untyped_combine(&encrypted, &dfactors);
    assert!(message == decrypted[0]);
}

fn test_joint_pkey<C: Context, const T: usize, const P: usize, const W: usize>() {
    assert!(T <= P);

    let dealers: [Dealer<C, T, P>; P] = array::from_fn(|_| Dealer::generate());

    let recipients: [(Recipient<C, T, P>, DkgPublicKey<C, T>); P] = array::from_fn(|i| {
        let position = ParticipantPosition::from_usize(i + 1);

        let verifiable_shares: [VerifiableShare<C, T>; P] = dealers
            .clone()
            .map(|d| d.get_verifiable_shares().for_recipient(&position));

        Recipient::from_shares(position, &verifiable_shares).unwrap()
    });

    // all computed joint public keys are equal
    let equal = recipients.windows(2).all(|w| w[0].1 == w[1].1);
    assert!(equal);

    let lhs = Recipient::<C, T, P>::joint_public_key(&dealers.map(|d| d.get_checking_values()));
    let rhs: DkgPublicKey<C, T> = recipients[0].1.clone();

    assert_eq!(lhs, rhs);
}

fn untyped_combine<C: Context, const P: usize, const W: usize>(
    ciphertexts: &[Ciphertext<C, W>],
    dfactors: &[Vec<DecryptionFactor<C, P, W>>],
) -> Vec<[C::Element; W]> {
    // get the participants
    let present: Vec<ParticipantPosition<P>> =
        dfactors.iter().map(|df| df[0].source.clone()).collect();

    let mut divisors_acc = vec![<[C::Element; W]>::one(); ciphertexts.len()];

    for dfactor in dfactors {
        let iter = dfactor.iter();
        let lagrange = untyped_lagrange::<C, P>(&dfactor[0].source, &present);

        let raised = iter.map(|df| df.value.dist_exp(&lagrange));

        divisors_acc = divisors_acc
            .iter()
            .zip(raised)
            .map(|(r, divisor)| r.mul(&divisor))
            .collect();
    }

    let ret: Vec<[C::Element; W]> = divisors_acc
        .iter()
        .zip(ciphertexts.iter())
        .map(|(d, c)| c.v().mul(&d.inv()))
        .collect();

    ret
}

fn untyped_lagrange<C: Context, const P: usize>(
    trustee: &ParticipantPosition<P>,
    present: &[ParticipantPosition<P>],
) -> C::Scalar {
    let mut numerator = C::Scalar::one();
    let mut denominator = C::Scalar::one();
    let trustee_exp: C::Scalar = trustee.0.into();

    for p in present {
        if p.0 == trustee.0 {
            continue;
        }

        let present_exp: C::Scalar = p.0.into();
        let diff_exp = present_exp.sub(&trustee_exp);

        numerator = numerator.mul(&present_exp);
        denominator = denominator.mul(&diff_exp);
    }

    numerator.mul(&denominator.inv().unwrap())
}
