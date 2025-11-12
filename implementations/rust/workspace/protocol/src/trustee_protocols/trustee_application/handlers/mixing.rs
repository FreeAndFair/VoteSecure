//! This file contains the state handler for the `Mixing` state.

use crate::trustee_protocols::trustee_application::top_level_actor::ProcessedTrusteeMsg;
use crate::trustee_protocols::trustee_messages::{CheckSignature, TrusteeID};

use std::collections::{HashMap, HashSet};

use super::*;

impl TrusteeStateHandler for Mixing {
    fn determine_next_state_and_output(
        &self,
        actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // Mixing is complete when we have signed mix messages
        // from all active trustees for mixes by all active
        // trustees. We don't need to check that the messages
        // for each mix are equivalent, becauase the Ascent
        // logic did that for us.

        let mut mix_map: HashMap<TrusteeID, HashSet<TrusteeID>> = HashMap::new();

        let mix_msgs: Vec<&EGCryptogramsMsg> = actor
            .processed_board
            .iter()
            .filter_map(|m| match m {
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::EGCryptograms(mix_msg),
                    ascent_msg: _,
                } => Some(mix_msg),
                _ => None,
            })
            .collect();

        for m in &mix_msgs {
            let originator_id = m.originator_id().expect("Impossible with a mix message.");
            let signer_id = m.signer_id().expect("Impossible with a mix message.");
            if let Some(signer_set) = mix_map.get_mut(&originator_id) {
                signer_set.insert(signer_id);
            } else {
                let mut new_set: HashSet<TrusteeID> = HashSet::new();
                new_set.insert(signer_id);
                mix_map.insert(originator_id, new_set);
            }
        }

        match &actor.protocol_state_data {
            Some(p) => {
                if mix_map.len() < p.active_trustees.len()
                    || mix_map.values().any(|s| s.len() < p.active_trustees.len())
                {
                    // Not enough mixes, we stay in mixing state
                    (None, None)
                } else {
                    // Enough mixes, we transition to decryption.
                    (
                        Some(TrusteeState::Decryption(Decryption)),
                        Some(TrusteeOutput::MixingComplete),
                    )
                }
            }

            None => {
                // This should be impossible if we're in Mixing state, so
                // fail the protocol.
                (
                    Some(TrusteeState::Failed(Failed)),
                    Some(TrusteeOutput::Failed(actor.failure_data(
                        "Internal error; could not find setup data in Mixing state.".to_string(),
                    ))),
                )
            }
        }
    }
}
