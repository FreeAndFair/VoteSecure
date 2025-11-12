//! This file contains the TAS state handler for the `AwaitingPartialDecryptions`
//! state. It handles only one type of message (`PartialDecryptionsMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingPartialDecryptions {
    fn handle_message_partialdecryptions(
        &self,
        input: &PartialDecryptionsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        #[custom_warning::warning("Potentially expensive clone")]
        let trustee_msg = TrusteeMsg::PartialDecryptions(input.clone());

        // Check that the message is properly signed; we don't check anything
        // else about partial decryptions, as that would duplicate trustee work
        // and they'll flag an error if there is one.
        match actor.trustee_signature_ok(&trustee_msg) {
            Err(err) => (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            ),
            Ok(()) => {
                // Post the partial decryptions message to the board and save the
                // update message.
                let update_msg = actor.add_to_board(trustee_msg);
                // Check to see if we've got enough partial decryptions and, if so,
                // transition to `AwaitingDecryptedBallots`.
                if actor.partial_decryptions_complete() {
                    (
                        Some(TASState::AwaitingDecryptedBallots(AwaitingDecryptedBallots)),
                        None,
                        update_msg,
                    )
                } else {
                    (None, None, update_msg)
                }
            }
        }
    }
}
