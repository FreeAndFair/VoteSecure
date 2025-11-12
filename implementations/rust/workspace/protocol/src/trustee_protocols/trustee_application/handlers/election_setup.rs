//! This file contains the state handler for the `ElectionSetup` state.

use super::*;
use crate::crypto::VSerializable;
use crate::elections::string_to_election_hash;
use crate::trustee_protocols::trustee_messages::{CheckSignature, TrusteeID};
use std::collections::HashSet;

impl TrusteeStateHandler for ElectionSetup {
    fn handle_approve_setup(
        &self,
        input: &ApproveSetup,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        // Setup has been approved, so sign and post the setup message.
        match input {
            ApproveSetup(setup_msg) => {
                // Sanity check: we must not already have protocol state data;
                // if we do, we need not fail the protocol, but we should
                // report an invalid input.
                if actor.protocol_state_data.is_some() {
                    return (
                        None,
                        Some(TrusteeOutput::InvalidInput(actor.failure_data(
                            "Cannot approve setup more than once.".to_string(),
                        ))),
                        None,
                    );
                }

                // Sanity check: the setup message must be from trustee 0; if not,
                // we fail the protocol.
                if setup_msg.data.originator != setup_msg.data.trustees[0].trustee_id() {
                    return (
                        Some(TrusteeState::Failed(Failed)),
                        Some(TrusteeOutput::Failed(actor.failure_data(format!(
                            "Attempted to approve setup ({:?}) that was not from trustee 0.",
                            setup_msg
                        )))),
                        None,
                    );
                }

                // Since we're approving the setup, initialize the actor state data
                // with its information.
                actor.cfg_hash = TrusteeActor::setup_msg_to_cfg_hash(setup_msg);
                actor.protocol_state_data = Some(ProtocolStateData {
                    election_hash: string_to_election_hash(&setup_msg.data.manifest),
                    threshold: setup_msg.data.threshold,
                    trustees: setup_msg.data.trustees.clone(),
                    active_trustees: vec![],
                });

                // Sign and return the setup message.
                let mut signed_setup_msg = setup_msg.clone();
                // Update the signer to be this trustee.
                signed_setup_msg.data.signer = actor.trustee_info.trustee_id();
                // Sign with this trustee's signing key.
                signed_setup_msg.signature =
                    crate::crypto::sign_data(&signed_setup_msg.data.ser(), &actor.signing_key);

                (None, None, Some(TrusteeMsg::Setup(signed_setup_msg)))
            }
        }
    }

    fn determine_next_state_and_output(
        &self,
        actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // Setup is done if we have identical setup messages signed
        // by all trustees (including the TAS).
        let mut signer_set: HashSet<TrusteeID> = HashSet::new();
        let mut setup_data: Option<SetupMsgData> = None;

        for m in &actor.processed_board {
            match (&m.trustee_msg, &m.trustee_msg.signer_id()) {
                (TrusteeMsg::Setup(sm), Ok(id)) => {
                    signer_set.insert(id.clone());

                    // Save the setup data if this is the first message, or
                    // compare it if it's a subsequent one.
                    match setup_data {
                        None => {
                            // It's the first one.
                            setup_data = Some(sm.data.clone());
                        }

                        Some(d) if !sm.data.equal_except_signer(&d) => {
                            // It's not equal to the first one, so fail the protocol.
                            return (
                                Some(TrusteeState::Failed(Failed)),
                                Some(TrusteeOutput::Failed(actor.failure_data(format!(
                                    "Setup data {:?} is not equal to initial setup data {:?}",
                                    d, sm.data
                                )))),
                            );
                        }

                        Some(_) => { /* It's equal to the first one. */ }
                    }
                }
                (TrusteeMsg::Setup(_), Err(_)) => { /* impossible, we wouldn't have posted the message */
                }
                _ => { /* ignore, it isn't a setup message */ }
            }
        }

        match &actor.protocol_state_data {
            Some(p) => {
                // We count the TAS as a trustee for this purpose (it signs
                // its own setup message).
                if signer_set.len() < p.trustees.len() {
                    // Not enough signatures, we stay in ElectionSetup state.
                    (None, None)
                } else {
                    // Enough signatures, we transition back to Idle.
                    (
                        Some(TrusteeState::Idle(Idle)),
                        Some(TrusteeOutput::SetupComplete(actor.checkpoint())),
                    )
                }
            }

            None => {
                // This should be impossible if we're in ElectionSetup state, so
                // fail the protocol.
                (
                    Some(TrusteeState::Failed(Failed)),
                    Some(TrusteeOutput::Failed(
                        actor.failure_data(
                            "Internal error; could not find setup data in ElectionSetup state."
                                .to_string(),
                        ),
                    )),
                )
            }
        }
    }
}
