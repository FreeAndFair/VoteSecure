//! This file contains the TAS state handler for the `Idle`
//! state. It handles many types of message, most of which cause
//! the actor to enter other states.

use super::*;

use std::collections::HashSet;

impl TASStateHandler for Idle {
    fn handle_setup(
        &self,
        _input: &StartSetup,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        if actor
            .checkpoint
            .board
            .iter()
            .any(|m| matches!(m, TrusteeMsg::Setup(_)))
        {
            // note explicit subprotocol here because we don't get to start it
            (
                None,
                Some(TASOutput::Failed(actor.failure_data(
                    "Trustee board already contains setup messages.".to_string(),
                ))),
                None,
            )
        } else {
            // Create the initial setup message to post to the trustee board.
            let initial_setup_message = actor.create_initial_setup_msg();
            // And the update message that tells the trustees it's there.
            let update_msg = actor.add_to_board(initial_setup_message);

            // Transition to the `AwaitingSetupMsgs` state, generate no output and an update message.
            (
                Some(TASState::AwaitingSetupMsgs(AwaitingSetupMsgs)),
                None,
                update_msg,
            )
        }
    }

    fn handle_keygen(
        &self,
        _input: &StartKeyGen,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // If any key share or election public key messages appear on the board, we bail out.
        if actor.checkpoint.board.iter().any(|m| {
            matches!(
                m,
                TrusteeMsg::KeyShares(_) | TrusteeMsg::ElectionPublicKey(_)
            )
        }) {
            // Note explicit subprotocol here because we don't get to start it.
            (
                None,
                Some(TASOutput::Failed(actor.failure_data(
                    "Trustee board already contains key generation messages.".to_string(),
                ))),
                None,
            )
        } else {
            // Transition to the `AwaitingKeyShareMsgs` state, generate no output.
            (
                Some(TASState::AwaitingKeySharesMsgs(AwaitingKeySharesMsgs)),
                None,
                None,
            )
        }
    }

    fn handle_mixing(
        &self,
        StartMixing(mixing_parameters): &StartMixing,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // Ensure that the number of active trustees in the mix parameters
        // matches the threshold (can't go over because of type constraints
        // on the decryption).
        if mixing_parameters.active_trustees.len() != actor.checkpoint.threshold as usize {
            return (
                None,
                Some(TASOutput::InvalidInput(actor.failure_data(format!(
                    "Expected {} active trustees, got {}.",
                    actor.checkpoint.threshold,
                    mixing_parameters.active_trustees.len()
                )))),
                None,
            );
        }

        // Create the initial message to post to the trustee board for mixing.
        let initial_mix_message = actor.create_initial_mix_msg(mixing_parameters);
        // Update the actor state to have the active trustee set from the
        // mixing parameters.
        actor.checkpoint.active_trustees =
            HashSet::from_iter(mixing_parameters.active_trustees.iter().cloned());

        // And the update message that tells the trustees it's there.
        let update_msg = actor.add_to_board(initial_mix_message);

        // Transition to the `AwaitingEGCryptogramMsgs` state, generate no output and an update message.
        (
            Some(TASState::AwaitingEGCryptogramsMsgs(
                AwaitingEGCryptogramsMsgs,
            )),
            None,
            update_msg,
        )
    }

    fn handle_stop(
        &self,
        _input: &Stop,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // Cannot stop when we're idle or failed, since we're already stopped.
        (
            None,
            Some(TASOutput::Failed(
                actor.failure_data("TAS is already stopped.".to_string()),
            )),
            None,
        )
    }
}
