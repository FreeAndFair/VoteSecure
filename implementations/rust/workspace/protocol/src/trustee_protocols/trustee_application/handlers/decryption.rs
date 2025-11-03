// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the state handler for the `Decryption` state.

use crate::trustee_protocols::trustee_application::top_level_actor::ProcessedTrusteeMsg;
use crate::trustee_protocols::trustee_messages::{CheckSignature, TrusteeID};

use std::collections::HashSet;

use super::*;

impl TrusteeStateHandler for Decryption {
    fn determine_next_state_and_output(
        &self,
        actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // Decryption is complete when the board contains decrypted
        // ballots from all active trustees (including us).
        // We don't need to check that they're identical, because
        // the Ascent logic did that for us.

        let mut signer_set: HashSet<TrusteeID> = HashSet::new();
        let db_msgs: Vec<&DecryptedBallotsMsg> = actor
            .processed_board
            .iter()
            .filter_map(|m| match m {
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::DecryptedBallots(db_msg),
                    ascent_msg: _,
                } => Some(db_msg),
                _ => None,
            })
            .collect();

        for m in &db_msgs {
            let signer_id = m
                .signer_id()
                .expect("Impossible with a decrypted ballots message");
            signer_set.insert(signer_id);
        }

        match &actor.protocol_state_data {
            Some(p) => {
                if signer_set.len() < p.active_trustees.len() {
                    // Not enough public keys, we stay in Decryption state.
                    (None, None)
                } else {
                    // Enough public keys, we transition back to idle.
                    (
                        Some(TrusteeState::Idle(Idle)),
                        Some(TrusteeOutput::DecryptionComplete(actor.checkpoint())),
                    )
                }
            }

            None => {
                // This should be impossible if we're in Decryption state, so
                // fail the protocol.
                (
                    Some(TrusteeState::Failed(Failed)),
                    Some(TrusteeOutput::Failed(
                        actor.failure_data(
                            "Internal error; could not find setup data in Decryption state."
                                .to_string(),
                        ),
                    )),
                )
            }
        }
    }
}
