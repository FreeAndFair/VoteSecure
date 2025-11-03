// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Protocol mixing phase

use std::array;
use std::marker::PhantomData;

use crate::trustee_protocols::trustee_application::ascent_logic::utils::random_hash;

use super::HashBoard;
use super::types::*;
use super::{Action, messages::Message};
use cryptography::context::Context;
use stateright::{Model, Property};

pub(crate) mod infer {

    ascent::ascent_source! { mix_infer:

        relation ballots(CfgHash, PublicKeyHash, CiphertextsHash, Vec<TrusteeIndex>);
        ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees) <--
            message(m),
            if let Message::Ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees) = m;

        relation mixing_position(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex, TrusteeIndex);
        relation mixing_position_acc(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex, Vec<TrusteeIndex>);

        mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, 0, mixing_trustees) <--
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees)
            if mixing_trustees.len() > 0;

        mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index + 1, mixing_trustees[1..].to_vec()) <--
            mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index, mixing_trustees),
            if mixing_trustees.len() > 1;

        mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index + 1, mixing_trustees[0]) <--
            mixing_position_acc(cfg_hash, pk_hash, ciphertexts_hash, index, mixing_trustees);

        error(format!("Duplicate mixing positions for trustee {:?}: {:?}, {:?}", trustee, position1, position2)) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position1, trustee),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position2, trustee),
            if position1 != position2;

        // cfg hash, pk hash, mix input hash, mix output hash, sender
        relation mix(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);
        mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) <--
            message(m),
            if let Message::Mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) = m;

        // cfg hash, pk hash, mix input hash, mix output hash, sender
        relation mix_signature(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);
        mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) <--
            message(m),
            if let Message::MixSignature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, sender) = m;

        action(Action::ComputeMix(*cfg_hash, *pk_hash, *ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, self_index),
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, _),
            !mix(cfg_hash, pk_hash, ciphertexts_hash, _, self_index);

        action(Action::ComputeMix(*cfg_hash, *pk_hash, *out_ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            public_keys_all(cfg_hash, pk_hash),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index, self_index),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, previous),
            // only selected trustees compute mixes
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index - 1, previous),
            mix_signatures_all(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash),
            !mix(cfg_hash, pk_hash, out_ciphertexts_hash, _, self_index);

        relation mix_signatures_all(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash);
        relation mix_signatures_acc(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);

        mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, 1) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, trustee),
            mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, trustee);

        mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position) <--
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position, trustee),
            mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, trustee),
            mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position - 1);

        mix_signatures_all(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash) <--
            configuration_valid(cfg_hash, threshold, _, _),
            mix_signatures_acc(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, threshold);

        mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index) <--
             mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index);

        action(Action::SignMix(*cfg_hash, *pk_hash, *in_ciphertexts_hash, *out_ciphertexts_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            public_keys_all(cfg_hash, pk_hash),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, _),
            // only selected trustees sign mixes
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, _, self_index),
            !mix_signature(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, self_index);

        relation mix_chain(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash, Sender);

        mix_chain(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, 1) <--
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, 1, trustee),
            mix(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, trustee),
            mix_signatures_all(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash);

        mix_chain(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash2, position2) <--
            mix_chain(cfg_hash, pk_hash, in_ciphertexts_hash, out_ciphertexts_hash, position1),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, position2, trustee),
            mix(cfg_hash, pk_hash, out_ciphertexts_hash, out_ciphertexts_hash2, trustee),
            mix_signatures_all(cfg_hash, pk_hash, out_ciphertexts_hash, out_ciphertexts_hash2);

        relation mix_complete(CfgHash, PublicKeyHash, CiphertextsHash, CiphertextsHash);

        mix_complete(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash) <--
            configuration_valid(cfg_hash, threshold, _, _),
            public_keys_all(cfg_hash, pk_hash),
            ballots(cfg_hash, pk_hash, ciphertexts_hash, mixing_trustees),
            mix_chain(cfg_hash, pk_hash, ciphertexts_hash, out_ciphertexts_hash, threshold);

        error(format!("Repeated mix source for senders {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, _, sender1),
            mix(cfg_hash, pk_hash, in_ciphertexts_hash, _, sender2),
            if sender1 != sender2;

        error(format!("Repeated mix target for senders {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender1),
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender2),
            if sender1 != sender2;

        error(format!("Unexpected mix chain participants {:?}, {:?}", sender1, sender2)) <--
            mix(cfg_hash, pk_hash, _, out_ciphertexts_hash, sender1),
            mix(cfg_hash, pk_hash, out_ciphertexts_hash, _, sender2),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index1, sender1),
            mixing_position(cfg_hash, pk_hash, ciphertexts_hash, index2, sender2),
            if index1 + 1 != *index2;

    }
}

mod composed_infer {
    use super::super::types::*;
    use super::super::utils::AccumulatorSet;
    use super::super::{Action, messages::Message};

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
    use super::super::types::*;
    use super::super::{Action, messages::Message};
    use super::execute_functions::*;

    ascent::ascent! {
        include_source!(crate::trustee_protocols::trustee_application::ascent_logic::prelude);
        include_source!(crate::trustee_protocols::trustee_application::ascent_logic::mix::execute::mix_execute);
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
        let mut ret = super::dkg::Harness::get_bb();

        let pk_hash = random_hash();
        for i in 0..P {
            ret.add_pk(pk_hash, i);
        }

        let all_trustees: [TrusteeIndex; T] = array::from_fn(|i| i + 1);
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

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut prog = composed_execute::program();

        // println!("* next_state action {:?}", action);
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
            // println!("* next_state: No next state *");
            None
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mix_complete = Property::<Self>::eventually("mix chain complete", |_, state| {
            let mixes: Vec<&Message> = state
                .messages
                .iter()
                .filter(|m| {
                    let cfg_: generic_array::GenericArray<u8, _> = super::dkg::DUMMY_CFG.into();
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
