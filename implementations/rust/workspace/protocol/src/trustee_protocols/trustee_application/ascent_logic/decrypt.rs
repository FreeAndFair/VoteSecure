// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Protocol decryption phase

pub(crate) mod infer {

    ascent::ascent_source! { decrypt_infer:

        // Input relations /////////////////////////////////////////

        // Asserts that the given trustee has computed the given partial decryptions
        // based on the given input ciphertexts, for the given configuration and public key context.
        relation partial_decryptions(CfgHash, PublicKeyHash, CiphertextsHash, PartialDecryptionsHash, Sender);
        // Asserts that the given trustee has verified all partial decryptions and used them to compute the
        // given plaintexts from the given input ciphertexts, for the given configuration and public key context.
        relation plaintexts(CfgHash, PublicKeyHash, CiphertextsHash, PlaintextsHash, Sender);

        // message mappings

        partial_decryptions(cfg_hash, pk_hash, ciphertexts_hash, partial_decryptions, sender) <--
            message(m),
            if let Message::PartialDecryptions(cfg_hash, pk_hash, ciphertexts_hash, partial_decryptions, sender) = m;

        plaintexts(cfg_hash, pk_hash, ciphertexts_hash, plaintexts_hash, sender) <--
            message(m),
            if let Message::Plaintexts(cfg_hash, pk_hash, ciphertexts_hash, plaintexts_hash, sender) = m;

        // Intermediate relations //////////////////////////////////

        // Asserts that the given partial decryptions corresponding to the given trustees
        // have been computed up to the given trustee index, for the given
        // configuration context.
        //
        // Partial decryption-trustee correspondence is given by the AccumulatorSet indices.
        // Note that this predicate does not assert partial decryption validity.
        relation partial_decryptions_acc(CfgHash, PartialDecryptionsHashesAcc, Sender);
        // Asserts that the given partial decryptions computed by the given corresponding trustees
        // constitute all the necessary partial decryptions, for the given configuration context.
        //
        // Note that this predicate does not assert partial decryption validity.
        relation partial_decryptions_all(CfgHash, PartialDecryptionsHashesAcc);

        // Protocol rules //////////////////////////////////////////

        // The given trustee should compute partial decryptions of the given ciphertexts if
        //  - it accepts the configuration as valid
        //  - it is part of the participating trustees
        //  - the given ciphertexts to decrypt are the ballot ciphertexts
        //  - a completed mix chain exists with start matching the ballot ciphertexts and
        //    end with the given ciphertexts to partially decrypt
        //  - it has not yet posted its partial decryptions
        // for the given configuration and public key context.
        action(Action::ComputePartialDecryptions(*cfg_hash, *pk_hash, *out_ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            mix_complete(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, _, self_index),
            !partial_decryptions(cfg_hash, pk_hash, _, _, self_index);

        // We have partial decryptions up to trustee 1 if we have the partial decryptions from trustee at position 1
        partial_decryptions_acc(cfg_hash, AccumulatorSet::new(*partial_decryptions), 1) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, trustee),
            partial_decryptions(cfg_hash, pk_hash, _, partial_decryptions, trustee);

        // We have partial decryptions up to trustee n if
        //  - we have partial decryptions up to trustee n - 1, and
        //  - we have the partial decryptions from trustee n
        partial_decryptions_acc(cfg_hash, partial_decryptions_hashes.add(*partial_decryptions, *position), position) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position, trustee),
            partial_decryptions_acc(cfg_hash, partial_decryptions_hashes, position - 1),
            partial_decryptions(cfg_hash, pk_hash, _, partial_decryptions, trustee);

        // All partial decryptions have been received when we have partial decryptions up to the threshold
        partial_decryptions_all(cfg_hash, partial_decryptions) <--
            partial_decryptions_acc(cfg_hash, partial_decryptions, threshold),
            configuration_valid(cfg_hash, threshold, _, self_index);

        // The given trustee should compute the plaintexts from the given ciphertexts and partial decryptions if
        //  - it accepts the configuration as valid
        //  - it is part of the participating trustees
        //  - a completed mix chain exists with end at the given ciphertexts to decrypt
        //  - all the partial decryptions have been received
        //  - it has not yet posted its computed plaintexts
        // for the given configuration and public key context.
        action(Action::ComputePlaintexts(*cfg_hash, *pk_hash, *ciphertexts_hash, partial_decryptions.extract(), *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            // uncomment this if we only want selected trustees to compute plaintexts
            mixing_position(cfg_hash, pk_hash, _, _, self_index),
            partial_decryptions_all(cfg_hash, partial_decryptions),
            mix_complete(cfg_hash, pk_hash, _, ciphertexts_hash),
            !plaintexts(cfg_hash, pk_hash, ciphertexts_hash, _, self_index);

        // Errors //////////////////////////////////////////////////

        // A plaintext input ciphertexts mismatch error condition occurs if
        //  - a plaintexts message with its given input ciphertexts exists
        //  - a plaintexts message with its given input ciphertexts exists
        //  - the ciphertexts differ
        // for the given configuration and public key context.
        error(format!("ciphertexts mismatch {:?} != {:?} ({} {})", ciphertexts_hash1, ciphertexts_hash2, sender1, sender2)) <--
            plaintexts(cfg_hash, pk_hash, ciphertexts_hash1, _, sender1),
            plaintexts(cfg_hash, pk_hash, ciphertexts_hash2, _, sender2),
            if ciphertexts_hash1 != ciphertexts_hash2;

        // A plaintext unexpected input ciphertexts mismatch error condition occurs if
        //  - a plaintexts message with the given input ciphertexts exists
        //  - a completed mix chain exists with the given end ciphertexts
        //  - the ciphertexts differ
        // for the given configuration and public key context.
        error(format!("unexpected input ciphertexts {:?} != {:?}", ciphertexts_hash1, end_ciphertexts_hash)) <--
            plaintexts(cfg_hash, pk_hash, ciphertexts_hash1, _, sender1),
            mix_complete(cfg_hash, pk_hash, _, end_ciphertexts_hash),
            if ciphertexts_hash1 != end_ciphertexts_hash;

        // A plaintext mismatch error condition occurs if
        //  - a plaintexts message with its given plaintexts exists
        //  - a plaintexts message with its given plaintexts exists
        //  - the plaintexts differ
        // for the given configuration and public key context.
        error(format!("plaintexts mismatch {:?} != {:?} ({} {})", plaintexts_hash1, plaintexts_hash2, sender1, sender2)) <--
            plaintexts(cfg_hash, pk_hash, _, plaintexts_hash1, sender1),
            plaintexts(cfg_hash, pk_hash, _, plaintexts_hash2, sender2),
            if plaintexts_hash1 != plaintexts_hash2;

    }
}

mod stateright {

    use crate::trustee_protocols::trustee_application::ascent_logic;
    use ascent_logic::Action;
    use ascent_logic::messages::Message;
    use ascent_logic::stateright::HashBoard;
    use ascent_logic::stateright::random_hash;
    use stateright::{Model, Property};
    use std::marker::PhantomData;

    use cryptography::context::Context;

    mod composed_infer {
        use crate::trustee_protocols::trustee_application::ascent_logic;
        use ascent_logic::types::*;
        use ascent_logic::utils::AccumulatorSet;
        use ascent_logic::{Action, messages::Message};

        ascent::ascent! {
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::prelude);
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::dkg::infer::dkg_infer);
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::mix::infer::mix_infer);
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::decrypt::infer::decrypt_infer);
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }
    }

    pub(crate) mod execute {

        ascent::ascent_source! { decrypt_execute:

            message(Message::PartialDecryptions(*cfg_hash, *pk_hash, *ciphertexts_hash, partial_decryptions_stub(*trustee, ciphertexts_hash), *trustee)) <--
                action(compute_partial_decryptions),
                if let Action::ComputePartialDecryptions(cfg_hash, pk_hash, ciphertexts_hash, trustee) = compute_partial_decryptions,
                active(trustee);

            // we use the fixed value of 1, because honest trustees will compute the same public key
            message(Message::Plaintexts(*cfg_hash, *pk_hash, *ciphertexts_hash, plaintexts_stub(*trustee, partial_decryptions), *trustee)) <--
                action(compute_plaintexts),
                if let Action::ComputePlaintexts(cfg_hash, pk_hash, ciphertexts_hash, partial_decryptions, trustee) = compute_plaintexts,
                active(trustee);
        }
    }

    pub(crate) mod execute_functions {
        use crate::trustee_protocols::trustee_application::ascent_logic;
        use ascent_logic::types::*;

        pub(crate) fn partial_decryptions_stub(
            trustee: usize,
            input: &CiphertextsHash,
        ) -> CiphertextsHash {
            input
                .into_iter()
                .map(|i| (i % 240) + trustee as u8)
                .collect()
        }

        pub(crate) fn plaintexts_stub(
            _trustee: usize,
            input: &PartialDecryptionsHashes,
        ) -> PlaintextsHash {
            input[0].into_iter().map(|i| (i % 254) + 1).collect()
        }
    }

    mod composed_execute {
        use super::execute_functions::*;
        use crate::trustee_protocols::trustee_application::ascent_logic;
        use ascent_logic::Action;
        use ascent_logic::messages::Message;
        use ascent_logic::types::*;

        ascent::ascent! {
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::prelude);
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::decrypt::stateright::execute::decrypt_execute);
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }
    }

    // stateright test harness
    struct Harness<C: Context, const W: usize, const T: usize, const P: usize> {
        phantom_c: PhantomData<C>,
    }
    impl<C: Context, const W: usize, const T: usize, const P: usize> Harness<C, W, T, P> {
        pub(crate) fn new() -> Self {
            Self {
                phantom_c: PhantomData,
            }
        }
        pub(crate) fn get_bb() -> HashBoard<C, W, T, P> {
            let mut ret = ascent_logic::mix::stateright::Harness::get_bb();

            for i in 0..T {
                let hash = if i == 0 {
                    ret.ballots_hash
                } else {
                    ret.mix_hashes[i - 1]
                };
                let mix_hash = random_hash();
                ret.add_mix(hash, mix_hash, i);
            }

            ret
        }
    }
    impl<C: Context, const W: usize, const T: usize, const P: usize> Model for Harness<C, W, T, P> {
        type State = HashBoard<C, W, T, P>;
        type Action = Action;

        fn init_states(&self) -> Vec<Self::State> {
            let init = Self::get_bb();

            vec![init]
        }

        fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
            let mut prog = composed_infer::program();

            let messages: Vec<(Message,)> = state.messages.iter().map(|m| (m.clone(),)).collect();
            prog.message = messages;
            prog.run();
            let mut actions_: Vec<Action> = prog.action.into_iter().map(|a| a.0).collect();

            if !prog.error.is_empty() {
                println!("* actions: found errors: {:?}", prog.error);
                return;
            }

            if actions_.is_empty() {
                // println!("** End state **");
            } else {
                // println!("* actions {:?} => {:?}", state.0, actions_);
                // println!("* current_messages {:?} => actions {:?}", state.messages.len(), actions_);
                actions.append(&mut actions_);
            }
        }

        fn next_state(
            &self,
            last_state: &Self::State,
            action: Self::Action,
        ) -> Option<Self::State> {
            let mut prog = composed_execute::program();

            prog.action = vec![(action.clone(),)];
            let active: Vec<(usize,)> = (1..=P).map(|i| (i,)).collect();
            prog.active = active;
            prog.run();
            let mut messages_: Vec<Message> = prog.message.into_iter().map(|m| m.0).collect();

            if !messages_.is_empty() {
                let mut ret = last_state.clone();
                ret.messages.append(&mut messages_);

                Some(ret)
            } else {
                None
            }
        }

        fn properties(&self) -> Vec<Property<Self>> {
            let decrypt_complete = Property::<Self>::eventually("decrypt complete", |_, state| {
                state.messages.iter().any(|m| {
                    let cfg_: generic_array::GenericArray<u8, _> =
                        ascent_logic::dkg::stateright::DUMMY_CFG.into();
                    matches!(m, Message::Plaintexts(cfg, _, _, _, _) if *cfg == cfg_)
                })
            });

            vec![decrypt_complete]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cryptography::context::RistrettoCtx;
        use stateright::Checker;

        #[test]
        fn check_decrypt() {
            let harness = Harness::<RistrettoCtx, 2, 2, 3>::new();
            let checker = harness.checker().spawn_bfs().join();
            checker.assert_properties();
        }

        #[ignore]
        #[test]
        fn serve_decrypt() {
            let harness = Harness::<RistrettoCtx, 2, 2, 3>::new();

            let _ = harness.checker().serve("127.0.0.1:8080");
        }
    }
}
