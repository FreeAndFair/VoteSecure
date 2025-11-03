// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the state handler for the `Idle` state.

use crate::trustee_protocols::trustee_application::top_level_actor::ProcessedTrusteeMsg;

use super::*;

impl TrusteeStateHandler for Idle {
    fn handle_stop(
        &self,
        _input: &Stop,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        // We are already idle, so we can't stop.
        (
            None,
            Some(TrusteeOutput::InvalidInput(
                actor.failure_data("Trustee is already idle".to_string()),
            )),
            None,
        )
    }

    fn handle_start_keygen(
        &self,
        _input: &StartKeyGen,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        // Run the Ascent logic. If we've already generated our keys,
        // it will return no actions and this will be a no-op (we return
        // "invalid input" in that case because it's bad to call KeyGen
        // when the keys have already been generated). If we haven't,
        // we will generate our keys, send out our key shares, and
        // transition to KeyGen. If the Ascent logic returns an error,
        // so do we.
        match actor.execute_ascent_logic() {
            Ok(None) => {
                // Nothing for us to do, as we've already generated keys
                (
                    None,
                    Some(TrusteeOutput::InvalidInput(actor.failure_data(
                        "Attempted to start KeyGen after it had already run.".to_string(),
                    ))),
                    None,
                )
            }

            Ok(Some(msg)) => {
                // Change state and send the message.
                (Some(TrusteeState::KeyGen(KeyGen)), None, Some(msg))
            }

            Err(error_msg) => (
                None,
                Some(TrusteeOutput::Failed(actor.failure_data(error_msg))),
                None,
            ),
        }
    }

    fn determine_next_state_and_output(
        &self,
        actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // Transitions from Idle to ElectionSetup and Mixing are based
        // on the state of the board, with no trustee message (necessarily)
        // being sent; the transition from Idle to KeyGen is handled
        // by `handle_start_keygen()`. There are no other transitions
        // from Idle (except failures handled elsewhere).

        // We transition to ElectionSetup if and only if there is
        // a setup message from trustee 0 on the trustee board _and_
        // we have no protocol state data.

        let setup_msgs: Vec<&SetupMsg> = actor
            .processed_board
            .iter()
            .filter_map(|m| match m {
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::Setup(setup_msg),
                    ascent_msg: _,
                } => Some(setup_msg),
                _ => None,
            })
            .collect();
        if !setup_msgs.is_empty() && actor.protocol_state_data.is_none() {
            // Get the first setup message on the board. It must be from
            // trustee 0, and must be sane; if it isn't, we fail the protocol.
            match setup_msgs[0].sanity_check(&actor.trustee_info) {
                Err(msg) => {
                    // The setup message failed the sanity check, so we fail
                    // the protocol.
                    return (
                        Some(TrusteeState::Failed(Failed)),
                        Some(TrusteeOutput::Failed(actor.failure_data(format!(
                            "Invalid setup message ({:?}): {}.",
                            setup_msgs[0], msg
                        )))),
                    );
                }

                Ok(_) => {
                    return (
                        Some(TrusteeState::ElectionSetup(ElectionSetup)),
                        Some(TrusteeOutput::RequestSetupApproval(setup_msgs[0].clone())),
                    );
                }
            }
        }

        // We transition to Mixing if and only if there is a mixing
        // initialization message on the trustee board, there are no
        // partial decryptions on the board, and we are in the list
        // of active trustees.
        let mix_init_msg = actor.processed_board.iter().find(|m| {
            matches!(
                m,
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::MixInitialization(_),
                    ascent_msg: _
                }
            )
        });
        let pd_msg = actor.processed_board.iter().find(|m| {
            matches!(
                m,
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::PartialDecryptions(_),
                    ascent_msg: _
                }
            )
        });
        if mix_init_msg.is_some()
            && pd_msg.is_none()
            && actor
                .protocol_state()
                .active_trustees
                .contains(&actor.trustee_info)
        {
            // Transition to Mixing. The active trustees list was
            // populated before this function was called.
            return (Some(TrusteeState::Mixing(Mixing)), None);
        }

        // Stay in Idle
        (None, None)
    }
}
