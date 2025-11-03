// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

pub mod awaiting_decrypted_ballots;
pub mod awaiting_egcryptograms;
pub mod awaiting_election_pk;
pub mod awaiting_partial_decryptions;
pub mod awaiting_setup;
pub mod awaiting_shares;
pub mod failed;
pub mod idle;

use crate::trustee_protocols::trustee_messages::{
    DecryptedBallotsMsg, EGCryptogramsMsg, ElectionPublicKeyMsg, KeySharesMsg,
    MixInitializationMsg, PartialDecryptionsMsg, SetupMsg, TrusteeBBUpdateMsg,
    TrusteeBBUpdateRequestMsg, TrusteeMsg,
};

use super::top_level_actor::{MixingParameters, TASActor, TASOutput, TASState};

use custom_warning_macro as custom_warning;
use enum_dispatch::enum_dispatch;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Idle;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingSetupMsgs;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingKeySharesMsgs;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingElectionPublicKeyMsgs;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingEGCryptogramsMsgs;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingPartialDecryptions;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AwaitingDecryptedBallots;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Failed;

#[enum_dispatch]
pub(crate) trait TASStateHandler {
    /// Handle an unhandled combination of state and input; this
    /// results in an "invalid input" response, but does not stop
    /// protocol execution, as it is recoverable and doesn't
    /// affect the state in any way.
    fn unhandled(
        &self,
        actor: &mut TASActor,
        input: String,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        (
            None,
            Some(TASOutput::InvalidInput(actor.failure_data(format!(
                "Invalid input ({:?}) for subprotocol",
                input
            )))),
            None,
        )
    }

    // Default handlers for states.
    fn handle_setup(
        &self,
        input: &StartSetup,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_keygen(
        &self,
        input: &StartKeyGen,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_mixing(
        &self,
        input: &StartMixing,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_checkpoint(
        &self,
        _input: &GetCheckpoint,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        (
            None,
            Some(TASOutput::Checkpointed(actor.checkpoint())),
            None,
        )
    }
    fn handle_stop(
        &self,
        _input: &Stop,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // We handle stop at this level because it's shared across states, but
        // handled differently (by other functions) if we're already idle
        // or stopped.
        (
            Some(TASState::Idle(Idle)),
            Some(TASOutput::Stopped(actor.checkpoint.clone())),
            None,
        )
    }

    // Default handlers for message types.
    fn handle_message_setup(
        &self,
        input: &SetupMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_keygen(
        &self,
        input: &KeySharesMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_electionpk(
        &self,
        input: &ElectionPublicKeyMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_nycryptograms(
        &self,
        input: &MixInitializationMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_egcryptograms(
        &self,
        input: &EGCryptogramsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_partialdecryptions(
        &self,
        input: &PartialDecryptionsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_decryptedballots(
        &self,
        input: &DecryptedBallotsMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
    fn handle_message_update_request(
        &self,
        input: &TrusteeBBUpdateRequestMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // We handle this here, since update requests can be handled in
        // any state.
        (
            None,
            Some(TASOutput::UpdateTrustee(
                actor.trustee_update(input.clone()),
            )),
            None,
        )
    }
    fn handle_message_update(
        &self,
        input: &TrusteeBBUpdateMsg,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        self.unhandled(actor, format!("{:?}", input))
    }
}

#[enum_dispatch]
pub(crate) trait TASBoomerang {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    );
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartSetup;
impl TASBoomerang for StartSetup {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_setup(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartKeyGen;
impl TASBoomerang for StartKeyGen {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_keygen(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartMixing(pub MixingParameters);
impl TASBoomerang for StartMixing {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_mixing(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetCheckpoint;
impl TASBoomerang for GetCheckpoint {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_checkpoint(self, actor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stop;
impl TASBoomerang for Stop {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_stop(self, actor)
    }
}

impl TASBoomerang for SetupMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_message_setup(self, actor)
    }
}

impl TASBoomerang for KeySharesMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_message_keygen(self, actor)
    }
}

impl TASBoomerang for ElectionPublicKeyMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_message_electionpk(self, actor)
    }
}

impl TASBoomerang for MixInitializationMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_nycryptograms(self, actor)
    }
}

impl TASBoomerang for EGCryptogramsMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_egcryptograms(self, actor)
    }
}

impl TASBoomerang for PartialDecryptionsMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_partialdecryptions(self, actor)
    }
}

impl TASBoomerang for DecryptedBallotsMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_decryptedballots(self, actor)
    }
}

impl TASBoomerang for TrusteeBBUpdateRequestMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor
            .state
            .clone()
            .handle_message_update_request(self, actor)
    }
}

impl TASBoomerang for TrusteeBBUpdateMsg {
    fn boomerang(
        &self,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        actor.state.clone().handle_message_update(self, actor)
    }
}
