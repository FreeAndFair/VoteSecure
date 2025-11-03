// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

pub mod decryption;
pub mod election_setup;
pub mod failed;
pub mod idle;
pub mod key_gen;
pub mod mixing;

use enum_dispatch::enum_dispatch;

use super::top_level_actor::{ProtocolStateData, TrusteeActor, TrusteeOutput, TrusteeState};
use crate::trustee_protocols::trustee_messages::{
    DecryptedBallotsMsg, EGCryptogramsMsg, ElectionPublicKeyMsg, KeySharesMsg,
    MixInitializationMsg, PartialDecryptionsMsg, SetupMsg, SetupMsgData, TrusteeBBUpdateMsg,
    TrusteeBBUpdateRequestMsg, TrusteeMsg,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Idle;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ElectionSetup;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyGen;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Mixing;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Decryption;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Failed;

#[enum_dispatch]
pub(crate) trait TrusteeStateHandler {
    /// Handle an unhandled combination of input and message; this
    /// results in an "invalid input" response, but does not stop
    /// protocol execution, as it is recoverable and doesn't
    /// affect the state in any way.
    fn unhandled(
        &self,
        actor: &mut TrusteeActor,
        input: String,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        (
            None,
            Some(TrusteeOutput::InvalidInput(actor.failure_data(format!(
                "Invalid input ({:?}) for subprotocol",
                input
            )))),
            None,
        )
    }

    // Default handlers for non-message inputs.
    #[allow(dead_code)]
    fn handle_approve_setup(
        &self,
        input: &ApproveSetup,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_start_keygen(
        &self,
        input: &StartKeyGen,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_stop(
        &self,
        input: &Stop,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }

    // Default handlers for message types. Note that the vast
    // majority of these are never used by the Trustee because
    // it only ever receives messages wrapped in board updates.

    fn handle_message_setup(
        &self,
        input: &SetupMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_keygen(
        &self,
        input: &KeySharesMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_electionpk(
        &self,
        input: &ElectionPublicKeyMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_nycryptograms(
        &self,
        input: &MixInitializationMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_egcryptograms(
        &self,
        input: &EGCryptogramsMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_partialdecryptions(
        &self,
        input: &PartialDecryptionsMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_decryptedballots(
        &self,
        input: &DecryptedBallotsMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_bb_update_request(
        &self,
        input: &TrusteeBBUpdateRequestMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_bb_update(
        &self,
        input: &TrusteeBBUpdateMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        // In all states other than `Failed`, a bulletin board update
        // message causes the following to happen:
        //
        // (1) The messages in the update are added to the bulletin
        // board; if there is an error, or messages are missing,
        // an appropriate output and message is returned.
        // (2) The Ascent logic is run on the updated bulletin board
        // to generate a list of actions that need to be taken.
        // (3) The actions are taken, and the resulting message (if
        // any) for the other trustees is produced.
        // (4) `determine_next_state_and_output` is called to determine
        // the next state and output.
        //
        // This all happens in the `process_board_update` function of
        // the top-level actor.`

        actor.process_board_update(input)
    }

    /// Determine the next state and output given the message being sent.
    /// This is called by process_board_update after actions are executed.
    /// States can override this to provide state-specific logic.
    ///
    /// The message to send to the other trustees (if any) indicates what
    /// action was just taken, which helps determine protocol completion
    ///and state transitions.
    fn determine_next_state_and_output(
        &self,
        _actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        // By default, we don't change the state or generate an output
        (None, None)
    }
}

/// TrusteeBoomerang trait for double dispatch on inputs.
#[enum_dispatch]
pub(crate) trait TrusteeBoomerang {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    );
}

// Input wrapper structs for TrusteeBoomerang pattern
#[derive(Debug, Clone, PartialEq)]
pub struct ApproveSetup(pub SetupMsg);
impl TrusteeBoomerang for ApproveSetup {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_approve_setup(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartKeyGen;
impl TrusteeBoomerang for StartKeyGen {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_start_keygen(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stop;
impl TrusteeBoomerang for Stop {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_stop(self, actor)
    }
}

impl TrusteeBoomerang for SetupMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_message_setup(self, actor)
    }
}

impl TrusteeBoomerang for KeySharesMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_message_keygen(self, actor)
    }
}

impl TrusteeBoomerang for ElectionPublicKeyMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_message_electionpk(self, actor)
    }
}

impl TrusteeBoomerang for MixInitializationMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_nycryptograms(self, actor)
    }
}

impl TrusteeBoomerang for EGCryptogramsMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_egcryptograms(self, actor)
    }
}

impl TrusteeBoomerang for PartialDecryptionsMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_partialdecryptions(self, actor)
    }
}

impl TrusteeBoomerang for DecryptedBallotsMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_decryptedballots(self, actor)
    }
}

impl TrusteeBoomerang for TrusteeBBUpdateRequestMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_bb_update_request(self, actor)
    }
}

impl TrusteeBoomerang for TrusteeBBUpdateMsg {
    fn boomerang(
        &self,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        actor.state.clone().handle_message_bb_update(self, actor)
    }
}
