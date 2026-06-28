// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-26 Free & Fair
// See LICENSE.md for details

//! Top-level actor for the Ballot Check Application.
//!
//! Note that the Ballot Check Application (BCA) does not interact with the
//! Voter Application (VA) directly but uses the Digital Ballot Box (DBB)
//! as intermediary to talk to the Voter Application. There is really only
//! one sub-actor behavior, corresponding to the execution of the ballot
//! check protocol for a particular submitted ballot. While the DBB has to
//! deal with concurrent requests and responses from the BCA and VA, the
//! BCA itself performs ballot checking in a strictly sequential manner.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed.
#![allow(clippy::large_enum_variant)]

use super::sub_actors::ballot_check::BallotCheckActor;
use super::sub_actors::ballot_check::{BallotCheckInput, BallotCheckOutput};

use crate::cryptography::ElectionKey;
use crate::cryptography::VerifyingKey;
use crate::cryptography::verify_signature;

use crate::elections::BallotTracker;
use crate::elections::ElectionHash;

use crate::messages::SignedBallotMsg;

use cryptography::utils::serialization::VSerializable;

// =============================================================================
// Commands and I/O Types
// =============================================================================

/// Commands that can be sent to the Ballot Check Application.
#[derive(Debug, Clone)]
pub enum Command {
    /// Abort the currently active subprotocol and return to the idle state.
    AbortSubprotocol,

    /// Start a ballot check for a submitted ballot.
    ///
    /// The BCA verifies the signed ballot and then runs the ballot check
    /// sub-actor to completion before accepting another request.
    StartBallotCheck(BallotTracker, SignedBallotMsg),
}

/// Direct subprotocol inputs - no generic conversion needed.
#[derive(Debug, Clone)]
pub enum SubprotocolInput {
    /// Input for the ballot check sub-actor.
    BallotCheck(BallotCheckInput),
}

/// Input to the Ballot Check Application actor.
#[derive(Debug, Clone)]
pub enum ActorInput {
    /// A command from the host application.
    Command(Command),

    /// Input forwarded to the currently active sub-actor.
    SubprotocolInput(SubprotocolInput),
}

// =============================================================================
// Output Types
// =============================================================================

/// Output from the Ballot Check Application actor's active subprotocol.
#[derive(Debug, Clone)]
pub enum SubprotocolOutput {
    /// Output from the ballot check sub-actor.
    BallotCheck(BallotCheckOutput),
}

// =============================================================================
// Session Management Types
// =============================================================================

/// Tracks which subprotocol the BCA is currently executing.
///
/// The BCA operates sequentially: it is either idle or running a single
/// ballot check. No concurrent sessions are supported.
#[derive(Clone, Debug, Default)]
pub enum ActiveSubprotocol {
    /// No subprotocol is currently active.
    #[default]
    Idle,

    /// A ballot check subprotocol is in progress.
    BallotCheck(BallotCheckActor),
}

// =============================================================================
// Top-Level Actor
// =============================================================================

/// The top-level Ballot Check Application actor.
///
/// This actor manages the lifecycle of a single ballot check subprotocol.
/// It verifies the signed ballot supplied by the host, delegates to the
/// [`BallotCheckActor`] sub-actor, and resets to idle once the check
/// completes (successfully or not).
#[derive(Clone, Debug)]
pub struct BallotCheckApplicationActor {
    /// The currently active subprotocol (or idle if none is running).
    active_subprotocol: ActiveSubprotocol,

    /// The election hash for this election.
    election_hash: ElectionHash,

    /// The election public key used to verify encrypted ballots.
    election_public_key: ElectionKey,

    /// The DBB's verifying key used to validate signed ballots.
    dbb_verifying_key: VerifyingKey,
}

impl BallotCheckApplicationActor {
    /// Create a new Ballot Check Application actor.
    ///
    /// # Arguments
    /// * `election_hash` - The election hash for this election
    /// * `election_public_key` - The election public key
    /// * `dbb_verifying_key` - The DBB's verifying key for validating signed ballots
    ///
    /// # Returns
    /// A new `BallotCheckApplicationActor` in the `Idle` state.
    pub fn new(
        election_hash: ElectionHash,
        election_public_key: ElectionKey,
        dbb_verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            active_subprotocol: ActiveSubprotocol::Idle,
            election_hash,
            election_public_key,
            dbb_verifying_key,
        }
    }

    /// Process an input to the Ballot Check Application.
    ///
    /// This is the main entry point for all interactions with the BCA.
    ///
    /// # Arguments
    /// * `input` - The input to process
    ///
    /// # Returns
    /// * `Ok(Some(output))` - Subprotocol output produced by processing the input
    /// * `Ok(None)` - The input was handled but produced no subprotocol output
    /// * `Err(msg)` - If an error occurs
    pub fn process_input(
        &mut self,
        input: ActorInput,
    ) -> Result<Option<SubprotocolOutput>, String> {
        match input {
            ActorInput::Command(command) => self.handle_command(command),
            ActorInput::SubprotocolInput(subprotocol_input) => {
                self.handle_subprotocol_input(subprotocol_input)
            }
        }
    }

    /// Processes a command for the top-level actor.
    fn handle_command(&mut self, command: Command) -> Result<Option<SubprotocolOutput>, String> {
        match command {
            Command::AbortSubprotocol => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
                Ok(None)
            }

            Command::StartBallotCheck(ballot_tracker, ballot) => {
                // Verify integrity of the (signed) ballot ...
                self.check_signed_ballot(&ballot)?;

                // ... so that BallotCheckActor::new(...) can rely upon it!
                let mut actor = BallotCheckActor::new(
                    self.election_hash, // implements Copy
                    self.election_public_key.clone(),
                    self.dbb_verifying_key, // implements Copy
                    ballot_tracker.clone(),
                    ballot.clone(),
                );

                // Initiate protocol with the sub-actor (send Start input).
                let output = actor.process_input(BallotCheckInput::Start);
                let result = Some(SubprotocolOutput::BallotCheck(output));

                self.active_subprotocol = ActiveSubprotocol::BallotCheck(actor);

                self.handle_state_updates(&result);

                Ok(result)
            }
        }
    }

    /// Forwards subprotocol input to the ballot check sub-actor.
    fn handle_subprotocol_input(
        &mut self,
        subprotocol_input: SubprotocolInput,
    ) -> Result<Option<SubprotocolOutput>, String> {
        match (&mut self.active_subprotocol, subprotocol_input) {
            (ActiveSubprotocol::Idle, _) => {
                Err("no active subprotocol - subprotocol input ignored".to_string())
            }

            (ActiveSubprotocol::BallotCheck(actor), SubprotocolInput::BallotCheck(input)) => {
                let output = actor.process_input(input);
                let result = Some(SubprotocolOutput::BallotCheck(output));
                self.handle_state_updates(&result);
                Ok(result)
            }
        }
    }

    /// Handles state updates and transitions based on subprotocol outputs.
    fn handle_state_updates(&mut self, output: &Option<SubprotocolOutput>) {
        match output {
            Some(SubprotocolOutput::BallotCheck(BallotCheckOutput::Success())) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            Some(SubprotocolOutput::BallotCheck(BallotCheckOutput::Failure(_))) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            // Non-terminal outputs do not change the state.
            Some(_) => {}

            // An absent output does not change the state.
            None => {}
        }
    }

    /// Validate a signed ballot before handing it to the ballot check sub-actor.
    ///
    /// Though checking the ballot obtained from the Public Bulletin Board (PBB)
    /// is not explicitly required by the protocol, we do it anyway to perform
    /// basic integrity checks. If any of these fail the protocol immediately
    /// bails out with an error during execution of the
    /// [`Command::StartBallotCheck`] command.
    ///
    /// # Arguments
    /// * `msg` - The signed ballot message to validate
    ///
    /// # Returns
    /// * `Ok(())` - If the ballot passes all integrity checks
    /// * `Err(msg)` - If the ballot fails any integrity check
    pub fn check_signed_ballot(&self, msg: &SignedBallotMsg) -> Result<(), String> {
        if verify_signature(
            &msg.data.ser(),
            &msg.signature,
            &msg.data.voter_authorization.data.voter_verifying_key,
        )
        .is_err()
        {
            return Err("signature of ballot to be checked is invalid".to_string());
        }
        if msg.data.voter_authorization.data.election_hash != self.election_hash {
            return Err("wrong election hash of ballot to be checked".to_string());
        }

        // @note After discussion with Dan Zimmerman, we do not need to carry
        // out more checks here; e.g., that the tracker matches the hash of
        // the signed ballot.
        Ok(())
    }
}
