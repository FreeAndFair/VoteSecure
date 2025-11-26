// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Protocol mixing phase

pub(crate) mod infer {

    ascent::ascent_source! { mix_infer:

        // Input relations /////////////////////////////////////////

        // Asserts that the the given ciphertexts are valid input ballot ciphertexts,
        // and that the given trustees are selected to perform mixing, for the given
        // configuration and public key context. It is unspecified in this predicate
        // which party has made the original assertion, only that the executing trustee
        // accepts it.
        relation ballots(CfgHash, PublicKeyHash, CiphertextsHash, Vec<TrusteeIndex>);
        // Asserts that the given trustee has computed the given mixed ciphertexts
        // based on the given input ciphertexts, for the given configuration and public key context.
        relation mix(CfgHash, PublicKeyHash, /* input hash */ CiphertextsHash, /* output hash */ CiphertextsHash, Sender);
        // Asserts that the given trustee has verified the given mixed ciphertexts
        // based on the given input ciphertexts, for the given configuration and public key context.
        relation mix_signature(CfgHash, PublicKeyHash, /* input hash */ CiphertextsHash, /* output hash */ CiphertextsHash, Sender);

        // message mappings

        ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees) <--
            message(m),
            if let Message::Ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees) = m;

        mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) <--
            message(m),
            if let Message::Mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) = m;

        mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) <--
            message(m),
            if let Message::MixSignature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) = m;

        // Intermediate relations //////////////////////////////////

        // Asserts that the mixing position of the trustee at the given index is given by the
        // first value of the given trustee list, as defined by the ballots message with given
        // ciphertexts, for the given configuration and public key context
        relation mixing_position_acc(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex, Vec<TrusteeIndex>);
        // Asserts that given trustee is assigned to the given mixing position, as defined by the
        // ballot message with given ciphertexts, for for the given configuration and public key context
        relation mixing_position(CfgHash, PublicKeyHash, CiphertextsHash, /* mixing position */ TrusteeIndex, /* trustee */ TrusteeIndex);
        // Asserts that the mix with given input and output ciphertexts has been verified by
        // the all participating trustees up to the given participating trustee, for the given
        // configuration and public key context.
        //
        // Note that participant trustee indices correspond to the trustee list as present in
        // the ballots message.
        relation mix_signatures_acc(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);
        // Asserts that the mix with given input and output ciphertexts has been verified by
        // all the participating trustees, for the given configuration and public key context
        //
        // Note that participant trustee indices correspond to the trustee list as present in
        // the ballots message.
        relation mix_signatures_all(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash);
        // Asserts that the mix chain, with the given endpoints, extends up to the given trustee
        // position, for the given configuration and public key context.
        //
        // A mix chain extends up to a given postion and given endpoints if it starts with the
        // given input ciphertexts, ends with the given output ciphertexts, and each intermediate
        // mix is performed by the trustee assigned to the corresponding mixing position, and each
        // mix has been verified by all participating trustees.
        relation mix_chain(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);
        // Asserts that the mix chain, with the given input ciphertexts, has been completed
        // for the given configuration and public key context.
        //
        // A mix chain is complete if it extends up to the last participant position (threshold).
        relation mix_complete(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash);

        // Protocol rules //////////////////////////////////////////

        // Initializes the mixing positions from the ballots into the mixing_position_acc relation
        mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, 0, mixing_trustees) <--
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees)
            if mixing_trustees.len() > 0;

        // Unpacks the mixing positions from the ballots into the mixing_position_acc relation,
        // one by one
        mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index + 1, mixing_trustees[1..].to_vec()) <--
            mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index, mixing_trustees),
            if mixing_trustees.len() > 1;

        // The nth trustee as specified in the ballots message is assigned to position n
        mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index + 1, mixing_trustees[0]) <--
            mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index, mixing_trustees);

        // The given trustee should compute a mix with the given input ciphertexts if
        //  - it accepts the configuration as valid
        //  - its assigned position is 1
        //  - the given ciphertexts are the ballot ciphertexts
        //  - it has not yet posted its mix
        // for the given configuration and public key context.
        action(Action::ComputeMix(*cfg_hash, *pk_hash, *ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, self_index),
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, _),
            !mix(cfg_hash, pk_hash, ciphertexts_hash, _, self_index);

        // The given trustee should compute a mix with the given input ciphertexts if
        //  - it accepts the configuration as valid
        //  - it is assigned the given position
        //  - the given ciphertexts are the output ciphertexts at the previous position
        //  - all participating trustees have signed the previous mix
        //  - it has not yet posted its mix
        // for the given configuration and public key context.
        action(Action::ComputeMix(*cfg_hash, *pk_hash, *out_ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            public_keys_all(cfg_hash, pk_hash),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position, self_index),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, previous),
            // only selected trustees compute mixes
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position - 1, previous),
            mix_signatures_all(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash),
            !mix(cfg_hash, pk_hash, out_ciphertexts_hash, _, self_index);

        // We have mix signature values up to trustee 1 if we have the mix signature value from trustee 1
        mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, 1) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, trustee),
            mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, trustee);

        // We have mix signatures up to trustee at position n if
        //  - we have mix signatures up to trustee at position n - 1, and
        //  - we have the mix signature value from trustee at position n
        mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position, trustee),
            mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, trustee),
            mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position - 1);

        // All mix signatures have been received when we have mix signatures up to the threshold
        mix_signatures_all(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash) <--
            configuration_valid(cfg_hash, threshold, _, _),
            mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, threshold);

        // A mix computed by a trustee is already a mix signature for that mix
        mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index) <--
             mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index);

        // The given trustee should verify a mix with the given input and output ciphertexts if
        //  - it accepts the configuration as valid
        //  - it is part of the participating trustees
        //  - a mix with the given input and output ciphertexts has been computed
        //   it has not yet verified this mix
        // for the given configuration and public key context.
        action(Action::SignMix(*cfg_hash, *pk_hash, *in_ciphertexts_hash, *out_ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            public_keys_all(cfg_hash, pk_hash),
            // only selected trustees sign mixes
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, _, self_index),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, _),
            !mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index);

        // The mix chain extends up to position 1 with the given ciphertexts if
        //  - the trustee at position 1 has computed a mix with given input and output ciphertexts,
        //  - the input ciphertexts are the ballot ciphertexts,
        //  - all participating trustees have signed the mix
        // for the given configuration and public key context.
        mix_chain(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, 1) <--
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, trustee),
            mix(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, trustee),
            mix_signatures_all(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash);

        // The mix chain extends up to 'position2' with the endpoints 'in_ciphertexts_hash' and 'out_ciphertexts_hash2' if
        //  - the mix chain extends up to 'position1' with input 'in_ciphertexts_hash' and output 'out_ciphertexts_hash',
        //  - the trustee at position 'position2' has computed a mix with input 'out_ciphertexts_hash' and output 'out_ciphertexts_hash2',
        //  - all participating trustees have signed the mix
        //  - 'position2' follows 'position1'
        // for the given configuration and public key context.
        mix_chain(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash2, position2) <--
            mix_chain(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position1),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position2, trustee),
            mix(cfg_hash, pk_hash, out_ciphertexts_hash, out_ciphertexts_hash2, trustee),
            mix_signatures_all(cfg_hash, pk_hash, out_ciphertexts_hash, out_ciphertexts_hash2),
            if *position2 == position1 + 1;

        // The mix is complete for the given endpoints if
        //  - the mix chain extends up to the threshold
        //  - the mix chain has the given endpoints
        //  - the start endpoint matches the ballot ciphertexts
        // for the given configuration and public key context.
        mix_complete(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash) <--
            configuration_valid(cfg_hash, threshold, _, _),
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            mix_chain(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, threshold);

        // Errors //////////////////////////////////////////////////

        // A mix chain multiple mixing position error condition occurs if
        //  - a trustee has been assigned the given position
        //  - a trustee has been assigned the given position
        //  - the two positions differ
        // for the given configuration and public key context.
        error(format!("Multiple mixing positions for trustee {:?}: {:?}, {:?}", trustee, position1, position2)) <--
            mixing_position(cfg_hash, pk_hash, _, position1, trustee),
            mixing_position(cfg_hash, pk_hash, _, position2, trustee),
            if position1 != position2;

        // A mix chain repeated end error condition occurs if
        //  - a mix chain with the given end has the given position
        //  - a mix chain with the given end has the given position
        //  - the two positions differ
        // for the given configuration and public key context.
        error(format!("Repeated mix chain end for lengths {:?}, {:?}", position1, position2)) <--
            mix_chain(cfg_hash, pk_hash, _, out_ciphertexts_hash, position1),
            mix_chain(cfg_hash, pk_hash, _, out_ciphertexts_hash, position2),
            if position1 != position2;

        // A mix chain non-ballots chain start error condition occurs if
        //  - a mix chain with the given start ciphertexts exists
        //  - a ballots message with the given ciphertexts exists
        //  - the the mix chain start ciphertexts differ from the ballot ciphertexts
        // for the given configuration and public key context.
        error(format!("Non-ballots mix chain start {:?}", in_ciphertexts_hash)) <--
            mix_chain(cfg_hash, pk_hash, in_ciphertexts_hash, _, _),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            if in_ciphertexts_hash != ciphertexts_hash;

        // A mix chain unexpected ballots ciphertexts error condition occurs if
        //  - a mix chain with the given end ciphertexts exists
        //  - a ballots message with the given ciphertexts exists
        //  - the mix chain end ciphertexts match the ballot ciphertexts
        // for the given configuration and public key context.
        error(format!("Unexpected ballots ciphertexts in chain end")) <--
            mix_chain(cfg_hash, pk_hash, _, out_ciphertexts_hash, _),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            if out_ciphertexts_hash == ciphertexts_hash;

        // A mix chain multiple trustee with mix input error condition occurs if
        //  - a mix with the given input has been computed by the given trustee
        //  - a mix with the given input has been computed by the given trustee
        //  - the two trustees differ
        // for the given configuration and public key context.
        error(format!("Multiple trustees with mix input, {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, _, sender1),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, _, sender2),
            if sender1 != sender2;

        // A mix chain multiple trustee with mix output error condition occurs if
        //  - a mix with the given output has been computed by the given trustee
        //  - a mix with the given output has been computed by the given trustee
        //  - the two trustees differ
        // for the given configuration and public key context.
        error(format!("Multiple trustees with mix output, {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender1),
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender2),
            if sender1 != sender2;

        // A mix chain repeated trustee error condition occurs if
        //  - a mix with the given input and output has been computed by the given trustee
        //  - a mix with the given input and output has been computed by the given trustee
        //  - the two trustees match
        //  - any of the input or output ciphertexts differ
        // for the given configuration and public key context.
        error(format!("Repeated trustee in mix chain {:?}", sender1)) <--
            mix(cfg_hash, pk_hash, in_ciphertexts_hash1, out_ciphertexts_hash1, sender1),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash2, out_ciphertexts_hash2, sender2),
            if sender1 == sender2,
            if in_ciphertexts_hash1 != in_ciphertexts_hash2 || out_ciphertexts_hash1 != out_ciphertexts_hash2;

        // A mix chain non-consecutive mixers error condition occurs if
        //  - a mix with the given output was computed by a trustee at the given position
        //  - a mix with the given input was computed by a trustee at the given position
        //  - the input and output ciphertexts match
        //  - the two positions are not consecutive
        // for the given configuration and public key context.
        error(format!("Non-consecutive mix chain participants {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender1),
            mix(cfg_hash, pk_hash, out_ciphertexts_hash, _, sender2),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index1, sender1),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index2, sender2),
            if index1 + 1 != *index2;
    }
}

pub(crate) mod stateright {

    use stateright::{Model, Property};
    use std::marker::PhantomData;

    use crate::trustee_protocols::trustee_application::ascent_logic;
    use ascent_logic::Action;
    use ascent_logic::dkg;
    use ascent_logic::messages::Message;
    use ascent_logic::stateright::HashBoard;
    use ascent_logic::stateright::random_hash;
    use ascent_logic::types::*;

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
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }
    }

    pub(crate) mod execute {

        ascent::ascent_source! { mix_execute:

            message(Message::Mix(*cfg_hash, *pk_hash, *ciphertexts_hash, mix_stub(*cfg_hash, *pk_hash, *trustee, ciphertexts_hash), *trustee)) <--
                action(compute_mix),
                if let Action::ComputeMix(cfg_hash, pk_hash, ciphertexts_hash, trustee) = compute_mix,
                active(trustee);

            message(Message::MixSignature(*cfg_hash, *pk_hash, *in_ciphertexts_hash, *out_ciphertexts_hash, *trustee)) <--
                action(sign_mix),
                if let Action::SignMix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, trustee) = sign_mix,
                active(trustee),
                if mix_signature_stub(*trustee) == true;
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
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::mix::stateright::execute::mix_execute);
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }
    }

    pub(crate) mod execute_functions {
        use crate::trustee_protocols::trustee_application::ascent_logic::types::*;

        pub(crate) fn mix_stub(
            cfg: CfgHash,
            _pk: PublicKeyHash,
            _trustee: usize,
            _input: &CiphertextsHash,
        ) -> CiphertextsHash {
            cfg
        }

        pub(crate) fn mix_signature_stub(_trustee: usize) -> bool {
            true
        }

        pub(crate) fn chain_signature_stub(_trustee: usize) -> bool {
            true
        }
    }

    pub(crate) struct Harness<C: Context, const W: usize, const T: usize, const P: usize> {
        phantom_c: PhantomData<C>,
    }
    impl<C: Context, const W: usize, const T: usize, const P: usize> Harness<C, W, T, P> {
        pub(crate) fn new() -> Self {
            Self {
                phantom_c: PhantomData,
            }
        }
        pub(crate) fn get_bb() -> HashBoard<C, W, T, P> {
            let mut ret = dkg::stateright::Harness::get_bb();

            let pk_hash = random_hash();
            for i in 0..P {
                ret.add_pk(pk_hash, i);
            }

            let all_trustees: [TrusteeIndex; T] = std::array::from_fn(|i| i + 1);
            ret.add_ballots(random_hash(), all_trustees);

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
                // println!("* actions {:?} => {:?}", state.messages, actions_);
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
            let mix_complete = Property::<Self>::eventually("mix chain complete", |_, state| {
                let mixes: Vec<&Message> = state
                    .messages
                    .iter()
                    .filter(|m| {
                        let cfg_: generic_array::GenericArray<u8, _> =
                            ascent_logic::dkg::stateright::DUMMY_CFG.into();
                        matches!(m, Message::Mix(cfg, _, _, _, _) if *cfg == cfg_)
                    })
                    .collect();

                mixes.len() == T
            });

            vec![mix_complete]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cryptography::context::RistrettoCtx;
        use stateright::Checker;

        #[test]
        fn check_mix() {
            let harness = Harness::<RistrettoCtx, 2, 2, 3>::new();
            let checker = harness.checker().spawn_bfs().join();
            checker.assert_properties();
        }

        #[ignore]
        #[test]
        fn serve_mix() {
            let harness = Harness::<RistrettoCtx, 2, 2, 3>::new();

            let _ = harness.checker().serve("127.0.0.1:8080");
        }
    }
}
