//! This file contains the TAS state handler for the `AwaitingDecryptedBallots`
//! state. It handles only one type of message (`DecryptedBallotsMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingDecryptedBallots {
    fn handle_message_decryptedballots(
        &self,
        input: &DecryptedBallotsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        #[custom_warning::warning("Potentially expensive clone")]
        let trustee_msg = TrusteeMsg::DecryptedBallots(input.clone());

        // Check that the message is properly signed; we don't check anything
        // else about decrypted ballots, as that would duplicate trustee work
        // and they'll flag an error if there is one.
        if let Err(err) = actor.trustee_signature_ok(&trustee_msg) {
            return (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            );
        }

        // Post the decrypted ballots message to the board and
        // save the update message.
        let update_msg = actor.add_to_board(trustee_msg);

        // Check to see if we've got enough decrypted ballots and,
        // if so, declare the subprotocol complete and return them.
        let complete = actor.decrypted_ballots_complete();

        if let Err(err) = complete {
            return (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            );
        }

        let ok = complete.expect("complete.is_ok()");
        if ok {
            (
                Some(TASState::Idle(Idle)),
                Some(TASOutput::DecryptionSuccessful(actor.decryption_data())),
                update_msg,
            )
        } else {
            (None, None, update_msg)
        }
    }
}
