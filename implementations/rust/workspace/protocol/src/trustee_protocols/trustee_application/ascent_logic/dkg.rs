// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Protocol distributed key generation phase

pub(crate) mod infer {

    ascent::ascent_source! { dkg_infer:

        // Input relations /////////////////////////////////////////

        // Asserts that the given trustee has computed the given shares
        // for the given configuration context.
        relation shares(CfgHash, TrusteeSharesHash, Sender);
        // Asserts that
        // - the given trustee has computed the given public key,
        // - the given tustee has validated the shares with which the given public
        //   key value value computed,
        // for the given configuration context.
        relation public_key(CfgHash, PublicKeyHash, Sender);

        // message mappings

        shares(cfg_hash, shares, sender) <--
            message(m),
            if let Message::Shares(cfg_hash, shares, sender) = m;

        public_key(cfg_hash, pk_hash, sender) <--
            message(m),
            if let Message::PublicKey(cfg_hash, pk_hash, sender) = m;

        // Intermediate relations //////////////////////////////////

        // Asserts that the given shares corresponding to the given trustees
        // have been computed up to the given trustee index, for the given
        // configuration context.
        //
        // Share-trustee correspondence is given by the AccumulatorSet indices.
        // Note that this predicate does not assert share validity.
        relation shares_acc(CfgHash, SharesHashesAcc, Sender);
        // Asserts that the given shares corresponding to the given trustees constitute
        // all the required shares, for the given configuration context.
        //
        // Note that this predicate does not assert share validity.
        relation shares_all(CfgHash, SharesHashesAcc);
        // Asserts that the given public key values corresponding to the given trustees have
        // been computed, from verified shares, up to the given trustee index, for the given
        // configuration context.
        //
        // In a valid dkg phase all trustees compute the same public key.
        // Share-public key correspondence is given by the AccumulatorSet indices.
        // Note that this predicate does not assert public key value validity.
        relation public_keys_acc(CfgHash, PublicKeyHash, Sender);
        // Asserts that the given public key values computed by the given corresponding trustees
        // constitute all the necessary public key values, for the given configuration context.
        //
        // In a valid dkg phase all trustees compute the same public key.
        // Note that this predicate does not assert public key validity.
        relation public_keys_all(CfgHash, PublicKeyHash);

        // Protocol rules //////////////////////////////////////////

        // The given trustee should compute shares if
        //  - it accepts the configuration as valid
        //  - it has not yet posted its shares
        // for the given configuration context.
        action(Action::ComputeShares(*cfg_hash, *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            !shares(cfg_hash, _, self_index);

        // We have shares up to trustee 1 if we have the shares from trustee 1
        shares_acc(cfg_hash, AccumulatorSet::new(*shares), 1) <--
            shares(cfg_hash, shares, 1);

        // We have shares up to trustee n if
        //  - we have shares up to trustee n - 1, and
        //  - we have the shares from trustee n
        shares_acc(cfg_hash, shares_hashes.add(*shares, *sender), sender) <--
            shares(cfg_hash, shares, sender),
            shares_acc(cfg_hash, shares_hashes, sender - 1);

        // All shares have been received when we have shares up to trustee_count
        shares_all(cfg_hash, shares) <--
            configuration_valid(cfg_hash, _, trustee_count, self_index),
            shares_acc(cfg_hash, shares, trustee_count);

        // The given trustee should compute the public key if
        //  - it accepts the configuration as valid
        //  - all shares have been received
        //  - it has not yet posted its computation of the public key
        // for the given configuration context.
        action(Action::ComputePublicKey(*cfg_hash, shares.extract(), *self_index)) <--
            configuration_valid(cfg_hash, _, _, self_index),
            shares_all(cfg_hash, shares),
            !public_key(cfg_hash, _, self_index);

        // We have public keys values up to trustee 1 if we have the public key value from trustee 1
        public_keys_acc(cfg_hash, pk_hash, 1) <--
            public_key(cfg_hash, pk_hash, 1);

        // We have public keys values up to trustee n if
        //  - we have public keys values up to trustee n - 1, and
        //  - we have the public key value from trustee n
        public_keys_acc(cfg_hash, pk_hash, sender) <--
            public_key(cfg_hash, pk_hash, sender),
            public_keys_acc(cfg_hash, pk_hash, sender - 1);

        // All public key values have been received when we have public keys up to trustee_count
        public_keys_all(cfg_hash, pk_hash) <--
            public_keys_acc(cfg_hash, pk_hash, trustee_count),
            configuration_valid(cfg_hash, _, trustee_count, self_index);

        // Errors //////////////////////////////////////////////////

        // A pk mismatch error condition occurs if
        //  - a trustee has computed the given public key value,
        //  - a trustee has computed the given public key value,
        //  - the two public keys values differ
        // for the given configuration context.
        error(format!("pk mismatch {:?} != {:?} ({} {})", pk_hash1, pk_hash2, sender1, sender2)) <--
            public_key(cfg_hash, pk_hash1, sender1),
            public_key(cfg_hash, pk_hash2, sender2),
            if pk_hash1 != pk_hash2;

    }
}

pub(crate) mod stateright {

    const HASH_SIZE: usize = 64;
    pub(crate) const DUMMY_CFG: [u8; HASH_SIZE] = [0u8; HASH_SIZE];

    use stateright::{Model, Property};
    use std::marker::PhantomData;

    use crate::trustee_protocols::trustee_application::ascent_logic;
    use ascent_logic::Action;
    use ascent_logic::messages::Message;
    use ascent_logic::stateright::HashBoard;
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
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }
    }

    pub(crate) mod execute {

        ascent::ascent_source! { dkg_execute:

            message(Message::Shares(*cfg_hash, share_stub(*trustee), *trustee)) <--
                action(compute_shares),
                if let Action::ComputeShares(cfg_hash, trustee) = compute_shares,
                active(trustee);

            // pass cfg_hash so all trustees compute the same value of public key
            message(Message::PublicKey(*cfg_hash, pk_stub(*cfg_hash), *trustee)) <--
                action(compute_public_key),
                if let Action::ComputePublicKey(cfg_hash, shares, trustee) = compute_public_key,
                active(trustee);
        }
    }

    mod composed_execute {
        use crate::trustee_protocols::trustee_application::ascent_logic;
        use ascent_logic::Action;
        use ascent_logic::messages::Message;
        use ascent_logic::types::*;

        ascent::ascent! {
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::prelude);
            include_source!(crate::trustee_protocols::trustee_application::ascent_logic::dkg::stateright::execute::dkg_execute);
        }

        pub(crate) fn program() -> AscentProgram {
            AscentProgram::default()
        }

        pub(crate) fn share_stub(trustee: usize) -> TrusteeSharesHash {
            [trustee as u8; 64].into()
        }

        pub(crate) fn pk_stub(cfg_hash: CfgHash) -> TrusteeSharesHash {
            cfg_hash
        }
    }

    pub(crate) struct Harness<C: Context, const W: usize, const T: usize, const P: usize> {
        pub cfg_hash: CfgHash,
        phantom_c: PhantomData<C>,
    }
    impl<C: Context, const W: usize, const T: usize, const P: usize> Harness<C, W, T, P> {
        pub(crate) fn new(cfg_hash: CfgHash) -> Self {
            Self {
                cfg_hash,
                phantom_c: PhantomData,
            }
        }
        pub(crate) fn get_bb() -> HashBoard<C, W, T, P> {
            HashBoard::new(DUMMY_CFG.into())
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
                // println!("* actions {:?} => {:?}", state, actions_);
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
            let cfg_present = Property::<Self>::always("cfg present", |_, state| {
                state.messages.iter().any(|m| {
                    let cfg_: generic_array::GenericArray<u8, _> = DUMMY_CFG.into();
                    matches!(m, Message::ConfigurationValid(cfg, _, _, _) if *cfg == cfg_)
                })
            });

            let shares_completed = Property::<Self>::eventually("shares completed", |_, state| {
                let shares: Vec<&Message> = state
                    .messages
                    .iter()
                    .filter(|m| {
                        let cfg_: generic_array::GenericArray<u8, _> = DUMMY_CFG.into();
                        matches!(m, Message::Shares(cfg, _, _) if *cfg == cfg_)
                    })
                    .collect();

                shares.len() == P
            });

            let pks_completed =
                Property::<Self>::eventually("public keys completed", |_, state| {
                    let pks: Vec<&Message> = state
                        .messages
                        .iter()
                        .filter(|m| {
                            let cfg_: generic_array::GenericArray<u8, _> = DUMMY_CFG.into();
                            matches!(m, Message::Shares(cfg, _, _) if *cfg == cfg_)
                        })
                        .collect();

                    pks.len() == P
                });

            vec![cfg_present, shares_completed, pks_completed]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use stateright::Checker;

        use cryptography::context::RistrettoCtx;

        #[test]
        fn check_dkg() {
            let checker = Harness::<RistrettoCtx, 2, 2, 3>::new(DUMMY_CFG.into())
                .checker()
                .spawn_bfs()
                .join();
            checker.assert_properties();
        }

        #[ignore]
        #[test]
        fn serve_dkg() {
            let harness = Harness::<RistrettoCtx, 2, 2, 3>::new(DUMMY_CFG.into());

            let _ = harness.checker().serve("127.0.0.1:8080");
        }
    }
}
