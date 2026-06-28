// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-26 Free & Fair
// See LICENSE.md for details

//! Top-level actor for the Voting Application.
//!
//! This actor manages the voter's session lifecycle, sequencing the
//! authentication, submission, casting, and ballot check subprotocols.
//! It also maintains the cross-subprotocol state (session keys, pseudonym,
//! ballot tracker, and randomizers) that must persist between steps.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use super::sub_actors::{
    authentication::{AuthenticationActor, AuthenticationInput, AuthenticationOutput},
    casting::{CastingActor, CastingInput, CastingOutput},
    checking::{CheckingActor, CheckingInput, CheckingOutput},
    submission::{SubmissionActor, SubmissionInput, SubmissionOutput},
};
use crate::cryptography::{ElectionKey, RandomizersStruct, SigningKey, VerifyingKey};
use crate::elections::{Ballot, BallotTracker, ElectionHash, VoterAuthorization};

// =============================================================================
// Commands and I/O Types
// =============================================================================

/// Commands that can be sent to the Voting Application.
#[derive(Debug, Clone)]
pub enum Command {
    /// Reset the actor to the idle state, discarding any active subprotocol.
    SetIdle,

    /// Begin the voter authentication subprotocol.
    StartAuthentication,

    /// Begin the ballot submission subprotocol with the given ballot.
    ///
    /// Requires that authentication has already completed successfully.
    StartSubmission(Ballot),

    /// Begin the ballot casting subprotocol.
    ///
    /// Requires that submission has already completed successfully.
    StartCasting,

    /// Begin the ballot checking subprotocol.
    ///
    /// Requires that submission has already completed successfully so that
    /// the ballot tracker and randomizers are available.
    StartBallotCheck,
}

/// Direct subprotocol inputs — no generic conversion needed.
#[derive(Debug, Clone)]
pub enum SubprotocolInput {
    /// Input for the authentication sub-actor.
    Authentication(AuthenticationInput),

    /// Input for the ballot submission sub-actor.
    Submission(SubmissionInput),

    /// Input for the ballot casting sub-actor.
    Casting(CastingInput),

    /// Input for the ballot checking sub-actor.
    Checking(CheckingInput),
}

/// Input to the Voting Application actor.
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

/// Output from the Voting Application actor's active subprotocol.
#[derive(Debug, Clone)]
pub enum SubprotocolOutput {
    /// Output from the authentication sub-actor.
    Authentication(AuthenticationOutput),

    /// Output from the ballot submission sub-actor.
    Submission(SubmissionOutput),

    /// Output from the ballot casting sub-actor.
    Casting(CastingOutput),

    /// Output from the ballot checking sub-actor.
    Checking(CheckingOutput),
}

// Re-export for public API
pub use super::sub_actors::{
    authentication::VoterAuthenticationResult, casting::BallotCastingSuccess,
    checking::BallotCheckOutcome, submission::BallotSubmissionSuccess,
};

// =============================================================================
// Session Management Types
// =============================================================================

/// Tracks which subprotocol the Voting Application is currently executing.
///
/// The VA operates sequentially: at most one subprotocol is active at a time.
#[derive(Clone, Debug)]
pub enum ActiveSubprotocol {
    /// No subprotocol is currently active.
    Idle,

    /// The voter authentication subprotocol is in progress.
    Authentication(AuthenticationActor),

    /// The ballot submission subprotocol is in progress.
    Submission(SubmissionActor),

    /// The ballot casting subprotocol is in progress.
    Casting(CastingActor),

    /// The ballot checking subprotocol is in progress.
    Checking(CheckingActor),
}

// =============================================================================
// Top-Level Actor
// =============================================================================

/// The top-level Voting Application actor.
///
/// This actor sequences the voter's protocol steps (authentication,
/// submission, casting, ballot check) and carries cross-step state
/// — session keys, voter pseudonym, ballot tracker, and randomizers —
/// between subprotocols.
#[derive(Clone, Debug)]
pub struct VotingApplicationActor {
    /// The currently active subprotocol (or idle if none is running).
    active_subprotocol: ActiveSubprotocol,

    // --- Configuration ---
    /// The election hash for this election.
    election_hash: ElectionHash,

    /// The EAS's verifying key for validating authorization messages.
    eas_verifying_key: VerifyingKey,

    /// The DBB's verifying key for validating DBB-signed messages.
    dbb_verifying_key: VerifyingKey,

    /// The election public key used to encrypt the ballot.
    election_public_key: ElectionKey,

    // --- Cross-Subprotocol Session State ---
    /// The voter's ephemeral session signing key, set after successful authentication.
    voter_session_signing_key: Option<SigningKey>,

    /// The voter's ephemeral session verifying key, set after successful authentication.
    voter_session_verifying_key: Option<VerifyingKey>,

    /// The voter authorization token issued by the EAS, set after successful
    /// authentication. Carried in later ballot submission and cast messages.
    voter_authorization: Option<VoterAuthorization>,

    /// The ballot tracker returned by the DBB after successful submission.
    ballot_tracker: Option<BallotTracker>,

    /// The encryption randomizers from ballot submission, needed for ballot checking.
    ballot_randomizers: Option<RandomizersStruct>,
}

impl VotingApplicationActor {
    /// Create a new [`VotingApplicationActor`].
    ///
    /// # Arguments
    /// * `election_hash` - The election hash for this election
    /// * `eas_verifying_key` - The EAS's verifying key for authorization messages
    /// * `dbb_verifying_key` - The DBB's verifying key for signed messages
    /// * `election_public_key` - The election public key for ballot encryption
    ///
    /// # Returns
    /// A new `VotingApplicationActor` in the `Idle` state.
    pub fn new(
        election_hash: ElectionHash,
        eas_verifying_key: VerifyingKey,
        dbb_verifying_key: VerifyingKey,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            active_subprotocol: ActiveSubprotocol::Idle,
            election_hash,
            eas_verifying_key,
            dbb_verifying_key,
            election_public_key,
            voter_session_signing_key: None,
            voter_session_verifying_key: None,
            voter_authorization: None,
            ballot_tracker: None,
            ballot_randomizers: None,
        }
    }

    /// Process an input to the Voting Application.
    ///
    /// This is the main entry point for all interactions with the VA.
    ///
    /// # Arguments
    /// * `input` - The input to process
    ///
    /// # Returns
    /// * `Ok(output)` - The output from processing the input
    /// * `Err(msg)` - If an error occurs
    pub fn process_input(&mut self, input: ActorInput) -> Result<SubprotocolOutput, String> {
        match input {
            ActorInput::Command(command) => self.handle_command(command),
            ActorInput::SubprotocolInput(subprotocol_input) => {
                self.handle_subprotocol_input(subprotocol_input)
            }
        }
    }

    /// Handle a command from the host application.
    fn handle_command(&mut self, command: Command) -> Result<SubprotocolOutput, String> {
        match command {
            Command::SetIdle => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
                Err("Actor is now idle - send a start command to begin a subprotocol".to_string())
            }

            Command::StartAuthentication => {
                let mut actor =
                    AuthenticationActor::new(self.election_hash, self.eas_verifying_key);
                let output = actor.process_input(AuthenticationInput::Start);
                self.active_subprotocol = ActiveSubprotocol::Authentication(actor);
                let result = SubprotocolOutput::Authentication(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            Command::StartSubmission(ballot) => {
                let voter_authorization = match &self.voter_authorization {
                    Some(auth) => auth.clone(),
                    None => {
                        return Ok(SubprotocolOutput::Submission(SubmissionOutput::Failure(
                            "Cannot submit ballot without prior authentication".to_string(),
                        )));
                    }
                };

                let mut actor = SubmissionActor::new(
                    self.election_hash,
                    self.dbb_verifying_key,
                    voter_authorization,
                    self.election_public_key.clone(),
                );

                // Set the signing key if available
                if let Some(signing_key) = &self.voter_session_signing_key {
                    actor.set_voter_signing_key(signing_key.clone());
                }
                let output = actor.process_input(SubmissionInput::Start(ballot));
                self.active_subprotocol = ActiveSubprotocol::Submission(actor);
                let result = SubprotocolOutput::Submission(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            Command::StartCasting => {
                let (voter_authorization, signing_key) =
                    match (&self.voter_authorization, &self.voter_session_signing_key) {
                        (Some(auth), Some(sk)) => (auth.clone(), sk.clone()),
                        _ => {
                            return Ok(SubprotocolOutput::Casting(CastingOutput::Failure(
                                "Cannot cast ballot without prior authentication".to_string(),
                            )));
                        }
                    };

                let tracker = match &self.ballot_tracker {
                    Some(t) => t.clone(),
                    None => {
                        return Ok(SubprotocolOutput::Casting(CastingOutput::Failure(
                            "Cannot cast ballot without prior submission".to_string(),
                        )));
                    }
                };

                let mut actor = CastingActor::new(
                    self.election_hash,
                    self.dbb_verifying_key,
                    voter_authorization,
                    signing_key,
                );
                let output = actor.process_input(CastingInput::Start(tracker));
                self.active_subprotocol = ActiveSubprotocol::Casting(actor);
                let result = SubprotocolOutput::Casting(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            Command::StartBallotCheck => {
                let (signing_key, verifying_key) = match (
                    &self.voter_session_signing_key,
                    &self.voter_session_verifying_key,
                ) {
                    (Some(sk), Some(vk)) => (sk.clone(), *vk),
                    _ => {
                        return Ok(SubprotocolOutput::Checking(CheckingOutput::Failure(
                            "Cannot start ballot check without prior authentication".to_string(),
                        )));
                    }
                };

                let randomizers = match &self.ballot_randomizers {
                    Some(r) => r.clone(),
                    None => {
                        return Ok(SubprotocolOutput::Checking(CheckingOutput::Failure(
                            "Cannot start ballot check without randomizers from prior submission"
                                .to_string(),
                        )));
                    }
                };

                if let Some(ref ballot_tracker) = self.ballot_tracker {
                    let mut actor = CheckingActor::new(
                        self.election_hash,
                        self.dbb_verifying_key,
                        signing_key,
                        verifying_key,
                        ballot_tracker.clone(),
                        randomizers,
                    );

                    let output = actor.process_input(CheckingInput::Start);
                    self.active_subprotocol = ActiveSubprotocol::Checking(actor);
                    let result = SubprotocolOutput::Checking(output);
                    Ok(result)
                } else {
                    Err("No ballot tracker found when starting ballot check".to_string())
                }
            }
        }
    }

    /// Forward a subprotocol input to the currently active sub-actor.
    fn handle_subprotocol_input(
        &mut self,
        subprotocol_input: SubprotocolInput,
    ) -> Result<SubprotocolOutput, String> {
        match (&mut self.active_subprotocol, subprotocol_input) {
            (ActiveSubprotocol::Idle, _) => {
                Err("No active subprotocol - send a start command first".to_string())
            }

            (ActiveSubprotocol::Authentication(actor), SubprotocolInput::Authentication(input)) => {
                let output = actor.process_input(input);
                let result = SubprotocolOutput::Authentication(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            (ActiveSubprotocol::Submission(actor), SubprotocolInput::Submission(input)) => {
                let output = actor.process_input(input);
                let result = SubprotocolOutput::Submission(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            (ActiveSubprotocol::Casting(actor), SubprotocolInput::Casting(input)) => {
                let output = actor.process_input(input);
                let result = SubprotocolOutput::Casting(output);
                self.handle_state_updates(&result);
                Ok(result)
            }

            (ActiveSubprotocol::Checking(actor), SubprotocolInput::Checking(input)) => {
                let output = actor.process_input(input);
                let result = SubprotocolOutput::Checking(output);
                Ok(result)
            }

            // Mismatched subprotocol input and active state
            _ => Err("Input does not match the currently active subprotocol".to_string()),
        }
    }

    /// Handle state updates and transitions based on subprotocol outputs.
    fn handle_state_updates(&mut self, output: &SubprotocolOutput) {
        match output {
            SubprotocolOutput::Authentication(AuthenticationOutput::Success(result)) => {
                // Whether authentication succeeded or failed, this assignment still works
                // (because the value is guaranteed by subactor checks to be None if it failed).
                self.voter_authorization = result.voter_authorization.clone();
                // Extract keys from the authentication actor if authentication was successful
                if result.result.0
                    && let ActiveSubprotocol::Authentication(auth_actor) = &self.active_subprotocol
                {
                    self.voter_session_signing_key = Some(auth_actor.session_signing_key.clone());
                    self.voter_session_verifying_key = Some(auth_actor.session_verifying_key);
                }
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }
            SubprotocolOutput::Authentication(AuthenticationOutput::Failure(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            SubprotocolOutput::Submission(SubmissionOutput::Success(success)) => {
                self.ballot_tracker = Some(success.tracker.clone());
                // Store randomizers from submission for later checking
                self.ballot_randomizers = Some(success.randomizers.clone());
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }
            SubprotocolOutput::Submission(SubmissionOutput::Failure(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            SubprotocolOutput::Casting(CastingOutput::Success(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }
            SubprotocolOutput::Casting(CastingOutput::Failure(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            SubprotocolOutput::Checking(CheckingOutput::Success(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }
            SubprotocolOutput::Checking(CheckingOutput::Failure(_)) => {
                self.active_subprotocol = ActiveSubprotocol::Idle;
            }

            // Non-terminal outputs don't change state
            _ => {}
        }
    }

    // --- Getter Methods (Integration Testing) ---

    /// Returns the voter authorization token if authentication completed successfully.
    #[cfg(test)]
    pub(crate) fn voter_authorization(&self) -> Option<&VoterAuthorization> {
        self.voter_authorization.as_ref()
    }

    /// Returns the ballot tracker if a ballot was successfully submitted.
    #[cfg(test)]
    pub(crate) fn ballot_tracker(&self) -> Option<&BallotTracker> {
        self.ballot_tracker.as_ref()
    }

    /// Returns the ballot randomizers if a ballot was successfully submitted.
    #[cfg(test)]
    pub(crate) fn ballot_randomizers(&self) -> Option<&RandomizersStruct> {
        self.ballot_randomizers.as_ref()
    }
}
