# VoteSecure Core Cryptographic Library

Cryptographic primitives required for implementation of the VoteSecure protocol.

## Overview

This library contains the primitives necessary to implement an end-to-end verifiable Internet voting protocol:

- Curve arithmetic abstractions for groups and product groups
- Curve arithmetic implementations (eg [curve25519](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek), [p-256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256))
- ElGamal and Naor-Yung cryptosystems
- Distributed key generation and decryption
- Zero-knowledge proofs
- Miscellaneous utilities (e.g., digital signatures, hashing, and serialization)

## Usage

For example, to generate a keypair, encrypt an ElGamal ciphertext of width 3, and then decrypt it:

```rust,ignore
use std::array;

use crate::context::Context;
use crate::context::RistrettoCtx as Ctx;
use crate::cryptosystem::elgamal::{KeyPair, Ciphertext};

const W: usize = 3;
let keypair = KeyPair::<Ctx>::generate();
let message = array::from_fn(|_| Ctx::random_element());

let ciphertext: Ciphertext<Ctx, W> = keypair.encrypt(&message);
let decrypted_message = keypair.decrypt(&ciphertext);
assert_eq!(message, decrypted_message);
```
