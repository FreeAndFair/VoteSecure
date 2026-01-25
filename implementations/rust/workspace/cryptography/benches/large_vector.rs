// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! LargeVector benchmark
//!
//! This benchmark measures the performance of [`LargeVector`][`cryptography::utils::serialization::variable::LargeVector`]
//! serialization under two implementations
//!
//! 1) This library's custom serialization
//!
//! 2) [Serde](https://docs.rs/serde/latest/serde/) serialization paired with [ciborium](https://docs.rs/ciborium/latest/ciborium/)
//!
//! The benchmark will print timings for serialization functions. There are
//! also manual printouts of serialized byte sizes, for comparison.
//!
//! This benchmark can be run with
//!
//! `cargo bench large_vector -- --nocapture`
#![feature(test)]

extern crate test;
use test::Bencher;

use cryptography::context::Context;
use cryptography::context::RistrettoCtx as RCtx;
use cryptography::cryptosystem::elgamal::Ciphertext;
use cryptography::utils::serialization::LargeVector;
use cryptography::utils::serialization::{FSerializable, VSerializable};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Serializer};

impl serde::Serialize for Element {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.compress().to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

/// The serde analog of an ElGamal ciphertext
#[derive(Serialize)]
struct EG {
    gr: Element,
    mhr: Element,
}
/// The serde analog of a group element
struct Element(RistrettoPoint);

/// The serde analog of `LargeVector`
#[derive(Serialize)]
struct SerdeVector(Vec<EG>);

/// Serialize the vector using serde + ciborium.
fn lvserde(lv: &SerdeVector) {
    let mut bytes = Vec::new();
    ciborium::into_writer(&lv, &mut bytes).unwrap();
}

/// Serialize the [`LargeVector`] using our custom serialization.
fn lvser<Ctx: Context>(lv: &LargeVector<Ciphertext<Ctx, 1>>)
where
    Ctx::Element: FSerializable,
{
    let _bytes = lv.ser();
}

/// Custom serialization benchmark.
///
/// Includes printout of resulting byte vector size.
#[bench]
fn bench_large_vector(b: &mut Bencher) {
    let mut lv = LargeVector(vec![]);
    let count = 1000;

    for _ in 0..count {
        let gr = [RCtx::random_element()];
        let mhr = [RCtx::random_element()];

        let ciphertext = Ciphertext::<RCtx, 1>::new(gr, mhr);
        lv.0.push(ciphertext);
    }

    let bytes = lv.ser();
    println!("large_vector size = {} bytes", bytes.len());

    b.iter(|| lvser::<RCtx>(&lv));
}

/// Serde + ciborium serialization benchmark.
///
/// Includes printout of resulting byte vector size.
#[bench]
fn bench_large_vector_serde_ciborium(b: &mut Bencher) {
    let mut lv = SerdeVector(vec![]);
    let count = 1000;

    for _ in 0..count {
        let gr = RCtx::random_element();
        let mhr = RCtx::random_element();
        let gr = Element(gr.0);
        let mhr = Element(mhr.0);

        let ciphertext = EG { gr, mhr };
        lv.0.push(ciphertext);
    }

    let mut bytes = Vec::new();
    ciborium::into_writer(&lv, &mut bytes).unwrap();
    println!("large_vector_serde_ciborium size = {} bytes", bytes.len());

    b.iter(|| lvserde(&lv));
}
