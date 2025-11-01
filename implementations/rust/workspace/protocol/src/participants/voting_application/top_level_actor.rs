// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use super::sub_actors::{
    authentication::{AuthenticationActor, AuthenticationInput, AuthenticationOutput},
    casting::{CastingActor, CastingInput, CastingOutput},
    checking::{CheckingActor, CheckingInput, CheckingOutput},
    submission::{SubmissionActor, SubmissionInput, SubmissionOutput},
};
use crate::crypto::{ElectionKey, RandomizersStruct, SigningKey, VerifyingKey};
use crate::elections::{Ballot, BallotStyle, BallotTracker, ElectionHash, VoterPseudonym};

// --- I/O Types ---

#[derive(Debug, Clone)]
pub enum Command {
    SetIdle,
    StartAuthentication,
    StartSubmission(Ballot),
    StartCasting,
    StartBallotCheck,
}

/// Direct subprotocol inputs - no generic conversion needed
#[derive(Debug, Clone)]
pub enum SubprotocolInput {
    Authentication(AuthenticationInput),
    Submission(SubmissionInput),
    Casting(CastingInput),
    Checking(CheckingInput),
}

#[derive(Debug, Clone)]
pub enum ActorInput {
    Command(Command),
    SubprotocolInput(SubprotocolInput),
}

// --- Direct Subprotocol Output ---

#[derive(Debug, Clone)]
pub enum SubprotocolOutput {
    Authentication(AuthenticationOutput),
    Submission(SubmissionOutput),
    Casting(CastingOutput),
    Checking(CheckingOutput),
}

// Re-export for public API
pub use super::sub_actors::{
    authentication::VoterAuthenticationSuccess, casting::BallotCastingSuccess,
    checking::BallotCheckOutcome, submission::BallotSubmissionSuccess,
};

// --- Active Subprotocol Enum ---

pub enum ActiveSubprotocol {
    Idle,
    Authentication(AuthenticationActor),
    Submission(SubmissionActor),
    Casting(CastingActor),
    Checking(CheckingActor),
}

// --- Top-Level Actor ---

pub struct TopLevelActor {
    active_subprotocol: ActiveSubprotocol,
    election_hash: ElectionHash,
    eas_verifying_key: VerifyingKey,
    dbb_verifying_key: VerifyingKey,
    election_public_key: ElectionKey,
    voter_session_signing_key: Option<SigningKey>,
    voter_session_verifying_key: Option<VerifyingKey>,
    voter_pseudonym: Option<VoterPseudonym>,
    voter_ballot_style: Option<BallotStyle>,
    ballot_tracker: Option<BallotTracker>,
    ballot_randomizers: Option<RandomizersStruct>,
}

impl TopLevelActor {
    /// Creates a new `TopLevelActor`.
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
            voter_pseudonym: None,
            voter_ballot_style: None,
            ballot_tracker: None,
            ballot_randomizers: None,
        }
    }

    pub fn process_input(&mut self, input: ActorInput) -> Result<SubprotocolOutput, String> {
        match input {
            ActorInput::Command(command) => self.handle_command(command),
            ActorInput::SubprotocolInput(subprotocol_input) => {
                self.handle_subprotocol_input(subprotocol_input)
            }
        }
    }

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
                let (pseudonym, verifying_key, ballot_style) =
                    match (
                        &self.voter_pseudonym,
                        &self.voter_session_verifying_key,
                        &self.voter_ballot_style,
                    ) {
                        (Some(p), Some(vk), Some(bs)) => (p.clone(), *vk, *bs),
                        _ => return Ok(SubprotocolOutput::Submission(SubmissionOutput::Failure(
                            "Cannot submit ballot without prior authentication and ballot style"
                                .to_string(),
                        ))),
                    };

                let mut actor = SubmissionActor::new(
                    self.election_hash,
                    self.dbb_verifying_key,
                    pseudonym,
                    verifying_key,
                    ballot_style,
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
                let (pseudonym, signing_key, verifying_key) = match (
                    &self.voter_pseudonym,
                    &self.voter_session_signing_key,
                    &self.voter_session_verifying_key,
                ) {
                    (Some(p), Some(sk), Some(vk)) => (p.clone(), sk.clone(), *vk),
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
                    pseudonym,
                    signing_key,
                    verifying_key,
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

                let mut actor = CheckingActor::new(
                    self.election_hash,
                    self.dbb_verifying_key,
                    signing_key,
                    verifying_key,
                    randomizers,
                );

                // Set voter pseudonym if available
                if let Some(ref pseudonym) = self.voter_pseudonym {
                    actor.set_voter_pseudonym(pseudonym.clone());
                }

                let output = actor.process_input(CheckingInput::Start);
                self.active_subprotocol = ActiveSubprotocol::Checking(actor);
                let result = SubprotocolOutput::Checking(output);
                Ok(result)
            }
        }
    }

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

    /// Handle state updates and transitions based on subprotocol outputs
    fn handle_state_updates(&mut self, output: &SubprotocolOutput) {
        match output {
            SubprotocolOutput::Authentication(AuthenticationOutput::Success(success)) => {
                self.voter_pseudonym = Some(success.voter_pseudonym.clone());
                // Extract keys from the authentication actor
                if let ActiveSubprotocol::Authentication(auth_actor) = &self.active_subprotocol {
                    self.voter_session_signing_key = Some(auth_actor.session_signing_key.clone());
                    self.voter_session_verifying_key = Some(auth_actor.session_verifying_key);
                }
                self.voter_ballot_style = Some(success.ballot_style);
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
}
