// Note that the Ballot Check Application (BCA) does not interact with the
// Voter Application (VA) directly but uses the Digital Ballot Box (DBB)
// as intermediary to talk to the Voter Application. There is really only
// one sub-actor behavior, corresponding to the execution of the ballot
// check protocol for a particular submitted ballot. While the DBB has to
// deal with concurrent requests and responses from the BCA and VA, the
// BCA itself performs ballot checking in a strictly sequential manner.

// Currently ignored for code simplicity until performance data is analyzed.
// @todo Consider boxing structs in large enum variants to improve performance.
#![allow(clippy::large_enum_variant)]

use super::sub_actors::ballot_check::BallotCheckActor;
use super::sub_actors::ballot_check::{BallotCheckInput, BallotCheckOutput};

use crate::crypto::ElectionKey;
use crate::crypto::VerifyingKey;
use crate::crypto::verify_signature;

use crate::elections::BallotTracker;
use crate::elections::ElectionHash;

use crate::messages::SignedBallotMsg;

use crypto::utils::serialization::VSerializable;

// --- I/O Types ---

#[derive(Debug, Clone)]
pub enum Command {
    AbortSubprotocol,
    StartBallotCheck(BallotTracker, SignedBallotMsg),
}

/// Direct subprotocol inputs - no generic conversion needed
#[derive(Debug, Clone)]
pub enum SubprotocolInput {
    BallotCheck(BallotCheckInput),
}

#[derive(Debug, Clone)]
pub enum ActorInput {
    Command(Command),
    SubprotocolInput(SubprotocolInput),
}

// --- Direct Subprotocol Output ---

#[derive(Debug, Clone)]
pub enum SubprotocolOutput {
    BallotCheck(BallotCheckOutput),
}

// --- Active Subprotocol Enum ---

#[derive(Default)]
pub enum ActiveSubprotocol {
    #[default]
    Idle,
    BallotCheck(BallotCheckActor),
}

// --- Top-Level Actor ---

pub struct TopLevelActor {
    active_subprotocol: ActiveSubprotocol,
    election_hash: ElectionHash,
    election_public_key: ElectionKey,
    dbb_verifying_key: VerifyingKey,
}

impl TopLevelActor {
    /// Creates a new top-level actor for the BCA.
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

    /// Processes an input to the top-level actor.
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
            Some(SubprotocolOutput::BallotCheck(BallotCheckOutput::PlaintextBallot(_))) => {
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

    /*******************************/
    /* Signed Ballot Message Check */
    /*******************************/

    // Though checking the ballot obtained from the Public Bulletin Board (PBB)
    // is not explicitly required by the protocol, we shall do it nonetheless,
    // at least carrying out some basic integrity checks. If any of these fail,
    // the protocol immediately bails out with an error during execution of the
    // [`Command::StartBallotCheck`] command.
    pub fn check_signed_ballot(&self, msg: &SignedBallotMsg) -> Result<(), String> {
        if verify_signature(
            &msg.data.ser(),
            &msg.signature,
            &msg.data.voter_verifying_key,
        )
        .is_err()
        {
            return Err("signature of ballot to be checked is invalid".to_string());
        }
        if msg.data.election_hash != self.election_hash {
            return Err("wrong election hash of ballot to be checked".to_string());
        }

        // @note After discussion with Dan Zimmerman, we do not need to carry
        // out more checks here; e.g., that the tracker matches the hash of
        // the signed ballot.
        Ok(())
    }
}
