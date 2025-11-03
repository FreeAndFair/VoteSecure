// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the TAS state handler for the `AwaitingElectionPublicKeyMsgs`
//! state. It handles only one type of message (`ElectionPublicKeyMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingElectionPublicKeyMsgs {
    fn handle_message_electionpk(
        &self,
        msg: &ElectionPublicKeyMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // Check that the message is properly signed, and that if we
        // have already gotten one election public key message, all the
        // others that come in match that one.
        match actor.check_election_public_key_msg(msg) {
            Err(err) => (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            ),
            Ok(()) => {
                let trustee_msg = TrusteeMsg::ElectionPublicKey(msg.clone());
                // Post the public key message to the board and save the update message;
                // also store the public key (if we've stored it before, that's OK, since
                // we know it's identical or the protocol would have failed).
                actor.checkpoint.election_public_key = Some(msg.data.election_public_key.clone());
                let update_msg = actor.add_to_board(trustee_msg.clone());
                // Check to see if we've got enough public key messages and, if so,
                // this subprotocol is done.
                if actor.election_public_keys_complete() {
                    (
                        Some(TASState::Idle(Idle)),
                        Some(TASOutput::KeyGenSuccessful(actor.checkpoint())),
                        update_msg,
                    )
                } else {
                    (None, None, update_msg)
                }
            }
        }
    }
}
