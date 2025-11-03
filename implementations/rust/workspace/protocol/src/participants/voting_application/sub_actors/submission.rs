// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Implementation of the `SubmissionActor` for the Ballot Submission subprotocol.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::Bulletin;

use crate::cryptography::{ElectionKey, RandomizersStruct};
use crate::elections::{Ballot, BallotStyle, ElectionHash, VoterPseudonym};
use crate::messages::{ProtocolMessage, SignedBallotMsg, TrackerMsg};

// Import cryptography library types directly

use crate::cryptography::{Signature, SigningKey, VerifyingKey};
use cryptography::utils::serialization::VSerializable;

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `SubmissionActor` can process.
#[derive(Debug, Clone)]
pub enum SubmissionInput {
    /// Starts the submission protocol with a ballot.
    Start(Ballot),
    /// A network message intended for this subprotocol.
    NetworkMessage(ProtocolMessage),
    /// The bulletin data fetched from the PBB.
    PBBData(Bulletin),
}

/// The set of outputs that the `SubmissionActor` can produce.
#[derive(Debug, Clone)]
pub enum SubmissionOutput {
    /// A message that needs to be sent over the network.
    SendMessage(ProtocolMessage),
    /// A request for the host to fetch a bulletin from the PBB using its tracker.
    FetchBulletin(String),
    /// The protocol has completed successfully.
    Success(BallotSubmissionSuccess),
    /// The protocol has failed.
    Failure(String),
}

/// Contains the data resulting from a successful ballot submission.
#[derive(Debug, Clone)]
pub struct BallotSubmissionSuccess {
    pub tracker: String,
    /// Randomizers used during encryption, stored for potential ballot checking
    pub randomizers: RandomizersStruct,
}

// --- II. Actor Implementation ---

/// The sub-states for the Ballot Submission protocol.
#[derive(Clone, Debug)]
enum SubState {
    ReadyToStart,
    AwaitingTracker,
    AwaitingBulletin { tracker_msg: TrackerMsg },
}

/// The actor for the Ballot Submission subprotocol.
#[derive(Clone, Debug)]
pub struct SubmissionActor {
    state: SubState,
    // --- Injected State from TopLevelActor ---
    election_hash: ElectionHash,
    dbb_verifying_key: VerifyingKey,
    voter_pseudonym: VoterPseudonym,
    voter_verifying_key: VerifyingKey,
    // --- Additional state needed for spec compliance ---
    ballot_style: BallotStyle,
    election_public_key: ElectionKey,
    // --- State generated and used only within this protocol ---
    sent_ballot: Option<SignedBallotMsg>,
    generated_randomizers: Option<RandomizersStruct>, // Store randomizers for checking
    // --- Cryptographic components ---
    voter_signing_key: Option<SigningKey>,
}

impl SubmissionActor {
    /// Creates a new `SubmissionActor`.
    pub fn new(
        election_hash: ElectionHash,
        dbb_verifying_key: VerifyingKey,
        voter_pseudonym: VoterPseudonym,
        voter_verifying_key: VerifyingKey,
        ballot_style: BallotStyle,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            state: SubState::ReadyToStart,
            election_hash,
            dbb_verifying_key,
            voter_pseudonym,
            voter_verifying_key,
            ballot_style,
            election_public_key,
            sent_ballot: None,
            generated_randomizers: None,
            voter_signing_key: None,
        }
    }

    /// Set the voter's signing key (should be called after authentication)
    pub fn set_voter_signing_key(&mut self, signing_key: SigningKey) {
        self.voter_signing_key = Some(signing_key);
    }

    /// Initialize cryptographic components
    pub fn initialize_crypto_components(&mut self) -> Result<(), String> {
        // In a real implementation, the signing key would be loaded from secure storage
        // For now, generate a key pair and ensure the verifying key matches
        if self.voter_signing_key.is_none() {
            let (signing_key, _verifying_key) = crate::cryptography::generate_signature_keypair();

            // In production, we would validate that the signing key corresponds to
            // the stored verifying key, but for this implementation we'll just use
            // the generated pair
            self.voter_signing_key = Some(signing_key);
        }
        Ok(())
    }

    /// Processes an input for the Ballot Submission subprotocol.
    pub fn process_input(&mut self, input: SubmissionInput) -> SubmissionOutput {
        // Initialize cryptography components if not already done
        if self.voter_signing_key.is_none()
            && let Err(e) = self.initialize_crypto_components()
        {
            return SubmissionOutput::Failure(format!("Cryptography initialization failed: {}", e));
        }

        match (self.state.clone(), input) {
            (SubState::ReadyToStart, SubmissionInput::Start(ballot)) => {
                use crate::messages::{SignedBallotMsg, SignedBallotMsgData};

                // Encrypt the complete ballot using encrypt_ballot function
                let (ballot_cryptogram, randomizers) = match crate::cryptography::encrypt_ballot(
                    ballot,
                    &self.election_public_key,
                    &self.election_hash,
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        return SubmissionOutput::Failure(format!(
                            "Failed to encrypt ballot: {}",
                            e
                        ));
                    }
                };

                // Store randomizers for return in success response
                self.generated_randomizers = Some(randomizers);

                // Construct SignedBallotMsgData
                let data = SignedBallotMsgData {
                    election_hash: self.election_hash,
                    voter_pseudonym: self.voter_pseudonym.clone(),
                    voter_verifying_key: self.voter_verifying_key,
                    ballot_style: self.ballot_style,
                    ballot_cryptogram,
                };

                // Sign the ballot data using Ed25519
                let signing_key = match &self.voter_signing_key {
                    Some(key) => key,
                    None => {
                        return SubmissionOutput::Failure(
                            "Voter signing key not initialized".to_string(),
                        );
                    }
                };

                let serialized_data = data.ser();
                let signature = crate::cryptography::sign_data(&serialized_data, signing_key);

                let signed_ballot = SignedBallotMsg { data, signature };

                self.sent_ballot = Some(signed_ballot.clone());
                self.state = SubState::AwaitingTracker;
                SubmissionOutput::SendMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot))
            }

            (
                SubState::AwaitingTracker,
                SubmissionInput::NetworkMessage(ProtocolMessage::ReturnBallotTracker(tracker_msg)),
            ) => {
                // Perform Return Ballot Tracker Checks before proceeding
                if let Err(error) = self.perform_return_ballot_tracker_checks(&tracker_msg) {
                    return SubmissionOutput::Failure(error);
                }

                if tracker_msg.data.submission_result.0 {
                    let tracker = tracker_msg
                        .data
                        .tracker
                        .clone()
                        .expect("tracker must exist in successful submission reply");
                    self.state = SubState::AwaitingBulletin { tracker_msg };
                    SubmissionOutput::FetchBulletin(tracker)
                } else {
                    // The submission failed for a specific reason.
                    SubmissionOutput::Failure(tracker_msg.data.submission_result.1)
                }
            }

            (SubState::AwaitingBulletin { tracker_msg }, SubmissionInput::PBBData(bulletin)) => {
                // Perform final verification that the bulletin contains our ballot
                match self.perform_bulletin_verification_checks(&bulletin) {
                    Ok(_) => SubmissionOutput::Success(BallotSubmissionSuccess {
                        tracker: tracker_msg
                            .data
                            .tracker
                            .expect("tracker must exist if we are waiting for a bulletin"),
                        randomizers: self
                            .generated_randomizers
                            .clone()
                            .expect("Randomizers should be generated"),
                    }),
                    Err(failure_reason) => SubmissionOutput::Failure(failure_reason),
                }
            }

            _ => SubmissionOutput::Failure("Invalid input for current state".to_string()),
        }
    }

    // --- Return Ballot Tracker Checks (as referenced in spec) ---

    /// Performs all "Return Ballot Tracker Checks" from the spec.
    fn perform_return_ballot_tracker_checks(&self, tracker_msg: &TrackerMsg) -> Result<(), String> {
        self.check_tracker_election_hash(&tracker_msg.data.election_hash)?;
        self.check_tracker_signature(&tracker_msg.data, &tracker_msg.signature)?;
        Ok(())
    }

    /// Check #1: The election_hash is the hash of the election configuration item for the current election.
    fn check_tracker_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("Tracker message has incorrect election hash".to_string());
        }
        Ok(())
    }

    /// Check #3: The signature is a valid signature over the contents of the message by the digital ballot box signing key.
    fn check_tracker_signature(
        &self,
        data: &crate::messages::TrackerMsgData,
        signature: &Signature,
    ) -> Result<(), String> {
        // Serialize data for verification using VSerializable
        let serialized_data = data.ser();

        // Verify signature using cryptography utilities
        crate::cryptography::verify_signature(&serialized_data, signature, &self.dbb_verifying_key)
            .map_err(|_| "Tracker message has invalid signature from DBB".to_string())?;

        Ok(())
    }

    /// Check #2: The tracker corresponds to a BallotSubBulletin on the public bulletin board
    /// which contains the previously submitted SignedBallotMsg.
    fn perform_bulletin_verification_checks(&self, bulletin: &Bulletin) -> Result<(), String> {
        match bulletin {
            Bulletin::BallotSubmission(ballot_bulletin) => {
                // Verify the bulletin contains our exact ballot
                if let Some(ref sent_ballot) = self.sent_ballot {
                    if &ballot_bulletin.data.ballot != sent_ballot {
                        return Err(
                            "Bulletin from PBB does not contain the correct ballot".to_string()
                        );
                    }
                } else {
                    return Err("No sent ballot to compare against bulletin".to_string());
                }

                // TODO: Additional verification that could be performed (but are
                // redundant since they were performed before posting the bulletin):
                // - Verify ballot_bulletin.data.election_hash matches our election
                // - Verify ballot_bulletin.signature is valid from DBB
                // - Verify ballot_bulletin.data.timestamp is reasonable
                // - Verify ballot_bulletin.data.previous_bb_msg_hash is valid

                Ok(())
            }
            _ => Err(
                "Received incorrect bulletin type from PBB - expected BallotSubmission".to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_actor_creation() {
        let (_, dbb_verifying_key) = crate::cryptography::generate_signature_keypair();
        let (_, voter_verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        let actor = SubmissionActor::new(
            crate::elections::string_to_election_hash("test_election_hash"),
            dbb_verifying_key,
            "test_pseudonym".to_string(),
            voter_verifying_key,
            1,
            election_keypair.pkey,
        );

        assert_eq!(
            actor.election_hash,
            crate::elections::string_to_election_hash("test_election_hash")
        );
        assert_eq!(actor.ballot_style, 1);
    }

    #[test]
    fn test_crypto_initialization() {
        let (_, dbb_verifying_key) = crate::cryptography::generate_signature_keypair();
        let (_, voter_verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        let mut actor = SubmissionActor::new(
            crate::elections::string_to_election_hash("test_election_hash"),
            dbb_verifying_key,
            "test_pseudonym".to_string(),
            voter_verifying_key,
            1,
            election_keypair.pkey,
        );

        // This should succeed
        let result = actor.initialize_crypto_components();
        assert!(result.is_ok());
        assert!(actor.voter_signing_key.is_some());
    }

    #[test]
    fn test_ballot_encryption() {
        let (_, dbb_verifying_key) = crate::cryptography::generate_signature_keypair();
        let (voter_signing_key, voter_verifying_key) =
            crate::cryptography::generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        let mut actor = SubmissionActor::new(
            crate::elections::string_to_election_hash("test_election_hash"),
            dbb_verifying_key,
            "test_pseudonym".to_string(),
            voter_verifying_key,
            1,
            election_keypair.pkey.clone(),
        );

        actor.set_voter_signing_key(voter_signing_key.clone());

        // Create a test ballot
        let ballot = Ballot::test_ballot(1);

        // Test ballot encryption using the new approach
        use crate::messages::{SignedBallotMsg, SignedBallotMsgData};

        let (ballot_cryptogram, randomizers) = crate::cryptography::encrypt_ballot(
            ballot,
            &election_keypair.pkey,
            &crate::elections::string_to_election_hash("test_election_hash"),
        )
        .unwrap();

        // Test that the ballot cryptogram is structured correctly
        // With single ciphertext structure, verify the ciphertext exists and has correct width
        assert_eq!(
            ballot_cryptogram.ciphertext.u_b.len(),
            crate::cryptography::BALLOT_CIPHERTEXT_WIDTH
        );
        assert_eq!(
            ballot_cryptogram.ciphertext.v_b.len(),
            crate::cryptography::BALLOT_CIPHERTEXT_WIDTH
        );
        assert_eq!(
            ballot_cryptogram.ciphertext.u_a.len(),
            crate::cryptography::BALLOT_CIPHERTEXT_WIDTH
        );

        // Test that randomizers are generated correctly
        assert_eq!(
            randomizers.randomizers.len(),
            crate::cryptography::BALLOT_CIPHERTEXT_WIDTH
        );

        // Test constructing the signed ballot message directly
        let data = SignedBallotMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election_2024"),
            voter_pseudonym: "test_pseudonym".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        let serialized_data = data.ser();
        let signature = crate::cryptography::sign_data(&serialized_data, &voter_signing_key);
        let signed_ballot = SignedBallotMsg { data, signature };

        // Verify the signed ballot structure - single ciphertext with fixed width
        assert_eq!(
            signed_ballot.data.ballot_cryptogram.ciphertext.u_b.len(),
            crate::cryptography::BALLOT_CIPHERTEXT_WIDTH
        );
    }

    #[test]
    fn test_vserializable_submission_messages() {
        // Test that VSerializable works correctly for submission message serialization
        let (_, verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_hash = crate::elections::string_to_election_hash("test_election_2024");
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        // Test SignedBallotMsgData serialization
        let test_ballot = crate::elections::Ballot::test_ballot(1);
        let (ballot_cryptogram, _) = crate::cryptography::encrypt_ballot(
            test_ballot,
            &election_keypair.pkey,
            &election_hash,
        )
        .unwrap();

        let signed_ballot_data = crate::messages::SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized_signed_ballot = signed_ballot_data.ser();
        assert!(
            !serialized_signed_ballot.is_empty(),
            "SignedBallotMsgData serialization should not be empty"
        );

        // Test TrackerMsgData serialization
        let tracker_data = crate::messages::TrackerMsgData {
            election_hash,
            tracker: Some("tracker_123".to_string()),
            submission_result: (true, "".to_string()),
        };
        let serialized_tracker = tracker_data.ser();
        assert!(
            !serialized_tracker.is_empty(),
            "TrackerMsgData serialization should not be empty"
        );
    }

    #[test]
    fn test_submission_actor_signature_compatibility() {
        // Test that the submission actor can create and verify signatures using VSerializable
        let (_, dbb_verifying_key) = crate::cryptography::generate_signature_keypair();
        let (voter_signing_key, voter_verifying_key) =
            crate::cryptography::generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();
        let election_hash = crate::elections::string_to_election_hash("test_election_2024");

        let mut submission_actor = SubmissionActor::new(
            election_hash,
            dbb_verifying_key,
            "voter_123".to_string(),
            voter_verifying_key,
            1,
            election_keypair.pkey.clone(),
        );
        submission_actor.set_voter_signing_key(voter_signing_key.clone());

        // Create a test ballot
        let ballot = Ballot::test_ballot(1);

        // Test that we can create a SignedBallotMsg directly using encrypt_ballot
        use crate::messages::{SignedBallotMsg, SignedBallotMsgData};

        let (ballot_cryptogram, _randomizers) =
            crate::cryptography::encrypt_ballot(ballot, &election_keypair.pkey, &election_hash)
                .unwrap();

        let data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        let serialized_data = data.ser();
        let signature = crate::cryptography::sign_data(&serialized_data, &voter_signing_key);
        let signed_ballot_msg = SignedBallotMsg { data, signature };

        // Verify that the signature can be verified using VSerializable
        let serialized = signed_ballot_msg.data.ser();
        let verification_result = crate::cryptography::verify_signature(
            &serialized,
            &signed_ballot_msg.signature,
            &voter_verifying_key,
        );
        assert!(
            verification_result.is_ok(),
            "Signature verification should succeed"
        );

        // Test that verification fails with wrong data
        let mut wrong_data = signed_ballot_msg.data.clone();
        wrong_data.voter_pseudonym = "wrong_voter".to_string();
        let wrong_serialized = wrong_data.ser();
        let wrong_verification_result = crate::cryptography::verify_signature(
            &wrong_serialized,
            &signed_ballot_msg.signature,
            &signed_ballot_msg.data.voter_verifying_key,
        );
        assert!(
            wrong_verification_result.is_err(),
            "Signature verification should fail with wrong data"
        );
    }
}
