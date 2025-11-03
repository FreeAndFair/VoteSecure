// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the TAS state handler for the `AwaitingSetupMsgs`
//! state. It handles only one type of message (`SetupMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingSetupMsgs {
    fn handle_message_setup(
        &self,
        msg: &SetupMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // Check the setup message for reasonability (properly signed,
        // matches our data, etc.); if it's not reasonable, fail the
        // protocol.
        match actor.check_setup_msg(msg) {
            Err(err) => (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            ),
            Ok(()) => {
                let trustee_msg = TrusteeMsg::Setup(msg.clone());
                // Post the setup message to the board and save the update message.
                let update_msg = actor.add_to_board(trustee_msg.clone());
                // Check to see if we're done and, if so, transition to idle.
                let (new_state, result) = if actor.setup_complete() {
                    (
                        Some(TASState::Idle(Idle)),
                        Some(TASOutput::SetupSuccessful(actor.checkpoint())),
                    )
                } else {
                    (None, None)
                };

                (new_state, result, update_msg)
            }
        }
    }
}
