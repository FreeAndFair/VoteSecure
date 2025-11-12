//! This file contains the TAS state handler for the `AwaitingKeySharesMsgs`
//! state. It handles only one type of message (`KeySharesMsg`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for AwaitingKeySharesMsgs {
    fn handle_message_keygen(
        &self,
        trustee_msg: &KeySharesMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        let trustee_msg = TrusteeMsg::KeyShares(trustee_msg.clone());

        // Check that the message is properly signed; we don't check anything
        // else about key shares messages, as that would duplicate trustee work
        // and they'll flag an error if there is one.
        match actor.trustee_signature_ok(&trustee_msg) {
            Err(err) => (
                Some(TASState::Failed(Failed)),
                Some(TASOutput::Failed(actor.failure_data(err))),
                None,
            ),
            Ok(()) => {
                // Post the key shares message to the board and save
                // the update message.
                let update_msg = actor.add_to_board(trustee_msg);
                // Check to see if we've got enough key shares and, if so,
                // transition to `AwaitingElectionPublicKeyMsgs`.
                if actor.key_shares_complete() {
                    (
                        Some(TASState::AwaitingElectionPublicKeyMsgs(
                            AwaitingElectionPublicKeyMsgs,
                        )),
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
