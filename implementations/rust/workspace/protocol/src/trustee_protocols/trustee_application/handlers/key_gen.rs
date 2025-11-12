//! This file contains the state handler for the `KeyGen` state.

use crate::trustee_protocols::trustee_application::top_level_actor::ProcessedTrusteeMsg;
use crate::trustee_protocols::trustee_messages::{CheckSignature, TrusteeID};

use std::collections::HashSet;

use super::*;

impl TrusteeStateHandler for KeyGen {
    fn determine_next_state_and_output(
        &self,
        actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // KeyGen is complete when we have ElectionPublicKey
        // messages sent by all trustees. We don't need to
        // check that they're identical, because the Ascent
        // logic did that for us.
        let mut originator_set: HashSet<TrusteeID> = HashSet::new();
        let pk_msgs: Vec<&ElectionPublicKeyMsg> = actor
            .processed_board
            .iter()
            .filter_map(|m| match m {
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::ElectionPublicKey(pk_msg),
                    ascent_msg: _,
                } => Some(pk_msg),
                _ => None,
            })
            .collect();

        for m in &pk_msgs {
            let originator_id = m
                .originator_id()
                .expect("Impossible with a public key message.");
            originator_set.insert(originator_id);
        }

        match &actor.protocol_state_data {
            Some(p) => {
                // We don't count the TAS here, as it doesn't generate keys.
                if originator_set.len() < p.trustees.len() - 1 {
                    // Not enough public keys, we stay in KeyGen state.
                    (None, None)
                } else {
                    // Enough public keys, we transition back to idle.
                    (
                        Some(TrusteeState::Idle(Idle)),
                        Some(TrusteeOutput::KeyGenComplete(actor.checkpoint())),
                    )
                }
            }

            None => {
                // This should be impossible if we're in KeyGen state, so
                // fail the protocol.
                (
                    Some(TrusteeState::Failed(Failed)),
                    Some(TrusteeOutput::Failed(actor.failure_data(
                        "Internal error; could not find setup data in KeyGen state.".to_string(),
                    ))),
                )
            }
        }
    }
}
