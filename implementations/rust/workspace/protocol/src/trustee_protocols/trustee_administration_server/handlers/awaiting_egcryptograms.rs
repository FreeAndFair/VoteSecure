//! This file contains the TAS state handler for the `AwaitingEGCryptogramsMsgs`
//! state. It handles only one type of message (`EGCryptogramsMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingEGCryptogramsMsgs {
    fn handle_message_egcryptograms(
        &self,
        input: &EGCryptogramsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        #[custom_warning::warning("Potentially expensive clone")]
        let trustee_msg = TrusteeMsg::EGCryptograms(input.clone());

        // Check that the message comes from an active trustee.

        // Check that the message is properly signed; we don't check anything
        // else about ElGamal cryptograms, as that would duplicate trustee work
        // and they'll flag an error if there is one.
        match actor.trustee_signature_ok(&trustee_msg) {
            Err(err) => (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            ),
            Ok(()) => {
                // Post the ElGamal cryptograms message to the board and save
                // the update message.
                let update_msg = actor.add_to_board(trustee_msg);
                // Check to see if we've got enough ElGamal cryptogram messages
                // and, if so, transition to `AwaitingPartialDecryptions`.
                if actor.eg_cryptograms_complete() {
                    (
                        // We transition directly to decryption from mixing,
                        Some(TASState::AwaitingPartialDecryptions(
                            AwaitingPartialDecryptions,
                        )),
                        Some(TASOutput::MixingSuccessful(actor.checkpoint())),
                        update_msg,
                    )
                } else {
                    (None, None, update_msg)
                }
            }
        }
    }
}
