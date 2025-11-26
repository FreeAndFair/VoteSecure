// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Root module for ascent protocol logic

#![allow(dead_code)]
pub mod decrypt;
pub mod dkg;
pub mod messages;
pub mod mix;
pub mod protocol;
pub mod utils;

use crate::cryptography::CryptographicHash;
use utils::AccumulatorSet;

// Re-export Message as AscentMsg for the top-level actor
pub(crate) use self::messages::Message as AscentMsg;

/// All types used in ascent logic implement std::hash::Hash
/// so that they can be used in stateright relations. However
/// the computations of _input_ hash values are carried
/// out by the CryptographyContext hasher. Stateright will
/// later compute its own hashes internally, but these are
/// not used outside of stateright.
#[crate::warning("Should use typesafe newtypes instead of type aliases")]
pub(crate) mod types {
    use super::AccumulatorSet;
    use super::CryptographicHash;

    pub(crate) type CfgHash = CryptographicHash;
    pub(crate) type TrusteeSharesHash = CryptographicHash;
    pub(crate) type PublicKeyHash = CryptographicHash;
    pub(crate) type CiphertextsHash = CryptographicHash;
    pub(crate) type SharesHashesAcc = AccumulatorSet<TrusteeSharesHash>;
    pub(crate) type SharesHashes = Vec<TrusteeSharesHash>;
    pub(crate) type Sender = TrusteeIndex;
    pub(crate) type TrusteeIndex = usize;
    pub(crate) type TrusteeCount = usize;
    pub(crate) type PartialDecryptionsHash = CryptographicHash;
    pub(crate) type PartialDecryptionsHashesAcc = AccumulatorSet<PartialDecryptionsHash>;
    pub(crate) type PartialDecryptionsHashes = Vec<PartialDecryptionsHash>;
    pub(crate) type PlaintextsHash = CryptographicHash;
}
use types::*;

/// Actions that a trustee can take during protocol execution
///
/// Action variants correspond to computations that a trustee
/// must perform during the protocol. They are triggered
/// by ascent logic rules. Actions produce messages that
/// are posted to the trustee bulletin board, advancing
/// the protocol state.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub(crate) enum Action {
    ComputeShares(CfgHash, TrusteeIndex),
    ComputePublicKey(CfgHash, SharesHashes, TrusteeIndex),
    ComputeMix(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex),
    SignMix(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        CiphertextsHash,
        TrusteeIndex,
    ),
    ComputePartialDecryptions(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex),
    ComputePlaintexts(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        PartialDecryptionsHashes,
        TrusteeIndex,
    ),
    ComputeBallots(CfgHash, PublicKeyHash),
}

// Defines relations and rules that are prior to and common to all
// protocol phases.
//
// Relations are of three broad kinds:
//
// 1) Input relations: facts received from the outside world, in the form of messages, injected into the ascent logic
//
// 2) Intermediate relations: facts derived by ascent logic rules, used as further inputs to other rules
//
// 3) Output relations: facts derived by ascent logic rules that are read by the trustee application,
// guiding its protocol execution. These are either actions or errors.
//
// There are three corresponding rule kinds:
//
// 1) Input rules: map messages to input relations
//
// 2) Intermediate rules: derive intermediate relations from input and other intermediate relations
//
// 3) Output rules: derive output relations, actions and errors, from input and intermediate relations
//
#[crate::warning(
    "Error relations should be generic, but error condition relations should be specific (eg `relation pk_mismatch(...)')"
)]
ascent::ascent_source! { prelude:

    // Corresponds to messages received from the bulletin board
    // Messages serve to inject facts from the ouside world into
    // the ascent logic program.
    relation message(Message);

    // Actions are computations that a trustee must perform
    // Actions produce side effects in the outside world, by computing
    // messages that are posted to the bulletin board, advancing the protocol state.
    relation action(Action);

    // Signals that an error has ocurred. If an error condition is raised by the
    // ascent logic, protocol execution should halt.
    relation error(String);

    // Asserts that the given trustee accepts the given configuration (hash) as valid,
    // and that said configuration has the given threshold and trustee count.
    relation configuration_valid(CfgHash, TrusteeCount, TrusteeCount, TrusteeIndex);

    // Message to relation mapping for configuration_valid
    configuration_valid(cfg_hash, threshold, trustee_count, self_index) <--
        message(m),
        if let Message::ConfigurationValid(cfg_hash, threshold, trustee_count, self_index) = m;

    // It is an error if two distict messages attempt to occupy the same slot.
    // Two messages are distinct if they are not equal.
    // See Message::collides
    error(format!("duplicate message {:?}, {:?}", m1, m2)) <--
        message(m1),
        message(m2),
        if m1.collides(m2);

    // It is an error if a message's cfg hash does not match
    // the context configuration, as established by the
    // configuration_valid fact. This fact is derived
    // from the bootstrapping Message::ConfigurationValid message.
    error(format!("message cfg does not match context {:?}", m1)) <--
        message(m1),
        configuration_valid(cfg_hash, _, _, _),
        if m1.get_cfg() != *cfg_hash;

    // FIXME: this relation is used for stateright tests and should be
    // moved elsewhere
    relation active(TrusteeIndex);
}

pub(crate) mod stateright {
    use super::messages::Message;
    use super::types::*;
    use crate::cryptography::CryptographicHash;
    use cryptography::context::Context;
    use rand::Rng;
    use std::array;
    use std::fmt::Formatter;
    use std::marker::PhantomData;

    #[derive(Clone, Hash, PartialEq)]
    pub(crate) struct HashBoard<C: Context, const W: usize, const T: usize, const P: usize> {
        pub(crate) messages: Vec<Message>,
        pub(crate) cfg_hash: CfgHash,
        pub(crate) pk_hash: PublicKeyHash,
        pub(crate) ballots_hash: CiphertextsHash,
        pub(crate) mix_hashes: [CiphertextsHash; T],
        pub(crate) mixing_trustees: [TrusteeIndex; T],
        phantom_c: PhantomData<C>,
    }
    impl<C: Context, const W: usize, const T: usize, const P: usize> HashBoard<C, W, T, P> {
        pub(crate) fn new(cfg_hash: CfgHash) -> Self {
            let messages: [Message; P] =
                array::from_fn(|i| Message::ConfigurationValid(cfg_hash, T, P, i + 1));
            let messages = messages.to_vec();
            let pk_hash = empty_hash();
            let ballots_hash = empty_hash();
            let mix_hashes = [empty_hash(); T];
            let mixing_trustees = [0; T];

            Self {
                messages,
                cfg_hash,
                pk_hash,
                ballots_hash,
                mix_hashes,
                mixing_trustees,
                phantom_c: PhantomData,
            }
        }

        pub(crate) fn add_pk(&mut self, pk_hash: PublicKeyHash, sender: TrusteeIndex) {
            let message = Message::PublicKey(self.cfg_hash, pk_hash, sender + 1);
            self.pk_hash = pk_hash;
            self.messages.push(message);
        }

        pub(crate) fn add_ballots(
            &mut self,
            ballots_hash: CiphertextsHash,
            trustees: [TrusteeIndex; T],
        ) {
            let pk_hash = self.pk_hash;
            let message = Message::Ballots(self.cfg_hash, pk_hash, ballots_hash, trustees.to_vec());
            self.mixing_trustees = trustees;
            self.ballots_hash = ballots_hash;
            self.messages.push(message);
        }

        pub(crate) fn add_mix(
            &mut self,
            input_hash: CiphertextsHash,
            mix_hash: CiphertextsHash,
            sender: TrusteeIndex,
        ) {
            let sender = sender + 1;
            let message = Message::Mix(self.cfg_hash, self.pk_hash, input_hash, mix_hash, sender);
            self.mix_hashes[sender - 1] = mix_hash;
            self.messages.push(message);

            for i in 1..=T {
                if i != sender && self.mixing_trustees.contains(&i) {
                    let message =
                        Message::MixSignature(self.cfg_hash, self.pk_hash, input_hash, mix_hash, i);
                    self.messages.push(message);
                }
            }
        }
    }

    impl<C: Context, const W: usize, const T: usize, const P: usize> std::fmt::Debug
        for HashBoard<C, W, T, P>
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
            let as_strings: Vec<String> =
                self.messages.iter().map(|m| format!("{:?}", m)).collect();

            write!(f, "{}", as_strings.join(", "))
        }
    }

    /// Utility function used in stateright tests
    pub(crate) fn empty_hash() -> CryptographicHash {
        [0u8; 64].into()
    }
    /// Utility function used in stateright tests
    pub(crate) fn random_hash() -> CryptographicHash {
        let mut bytes = [0u8; 64];
        rand::thread_rng().fill(&mut bytes);
        bytes.into()
    }
}
