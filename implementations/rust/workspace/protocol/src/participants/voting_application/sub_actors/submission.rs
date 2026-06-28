// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-26 Free & Fair
// See LICENSE.md for details

//! Implementation of the `SubmissionActor` for the Ballot Submission subprotocol.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::{BallotSubContents, Bulletin};

use crate::cryptography::{ElectionKey, RandomizersStruct};
use crate::elections::{Ballot, ElectionHash, VoterAuthorization};
use crate::messages::{ProtocolMsg, SignedBallotMsg, TrackerMsg};

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
    NetworkMessage(ProtocolMsg),
    /// The bulletin data fetched from the PBB.
    PBBData(Bulletin),
}

/// The set of outputs that the `SubmissionActor` can produce.
#[derive(Debug, Clone)]
pub enum SubmissionOutput {
    /// A message that needs to be sent over the network.
    SendMessage(ProtocolMsg),
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
    /// Randomizers used during encryption, stored for potential ballot checking.
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
    // --- Injected State from VotingApplicationActor ---
    election_hash: ElectionHash,
    dbb_verifying_key: VerifyingKey,
    voter_authorization: VoterAuthorization,
    election_public_key: ElectionKey,
    // --- State generated and used only within this protocol ---
    sent_ballot: Option<SignedBallotMsg>,
    generated_randomizers: Option<RandomizersStruct>, // Store randomizers for checking
    // --- Cryptographic components ---
    voter_signing_key: Option<SigningKey>,
}

impl SubmissionActor {
    /// Creates a new `SubmissionActor`.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `dbb_verifying_key` - The DBB's verifying key for validating response signatures.
    /// * `voter_authorization` - The voter authorization token issued by the EAS,
    ///   embedded in the submitted ballot.
    /// * `election_public_key` - The election public key used to encrypt ballots.
    ///
    /// # Returns
    /// A new `SubmissionActor` in the `ReadyToStart` state.
    pub fn new(
        election_hash: ElectionHash,
        dbb_verifying_key: VerifyingKey,
        voter_authorization: VoterAuthorization,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            state: SubState::ReadyToStart,
            election_hash,
            dbb_verifying_key,
            voter_authorization,
            election_public_key,
            sent_ballot: None,
            generated_randomizers: None,
            voter_signing_key: None,
        }
    }

    /// Set the voter's signing key (should be called after authentication)
    ///
    /// # Arguments
    /// * `signing_key` - The voter's signing key for signing ballot submission messages.
    pub fn set_voter_signing_key(&mut self, signing_key: SigningKey) {
        self.voter_signing_key = Some(signing_key);
    }

    /// Initialize cryptographic components.
    ///
    /// # Returns
    /// `Ok(())` if cryptographic components are ready, or `Err(msg)` if initialization fails.
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
    ///
    /// # Arguments
    /// * `input` - The input to process.
    ///
    /// # Returns
    /// A `SubmissionOutput` describing the result of processing the input.
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
                    &self.voter_authorization.data.voter_pseudonym,
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
                    voter_authorization: self.voter_authorization.clone(),
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
                SubmissionOutput::SendMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot))
            }

            (
                SubState::AwaitingTracker,
                SubmissionInput::NetworkMessage(ProtocolMsg::ReturnBallotTracker(tracker_msg)),
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
        let sub = bulletin
            .data
            .contents
            .as_any()
            .downcast_ref::<BallotSubContents>()
            .ok_or_else(|| {
                "Received incorrect bulletin type from PBB - expected BallotSubmission".to_string()
            })?;

        // Verify the bulletin contains our exact ballot
        if let Some(ref sent_ballot) = self.sent_ballot {
            if &sub.ballot != sent_ballot {
                return Err("Bulletin from PBB does not contain the correct ballot".to_string());
            }
        } else {
            return Err("No sent ballot to compare against bulletin".to_string());
        }

        // TODO: Additional verification that could be performed (but are
        // redundant since they were performed before posting the bulletin):
        // - Verify bulletin.data.election_hash matches our election
        // - Verify bulletin.signature is valid from DBB
        // - Verify bulletin.data.timestamp is reasonable
        // - Verify bulletin.data.previous_bb_msg_hash is valid

        Ok(())
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
        let election_hash = crate::elections::string_to_election_hash("test_election_hash");

        let actor = SubmissionActor::new(
            election_hash,
            dbb_verifying_key,
            VoterAuthorization::test_voter_authorization(
                election_hash,
                "test_pseudonym",
                1,
                voter_verifying_key,
            ),
            election_keypair.pkey,
        );

        assert_eq!(actor.election_hash, election_hash);
        assert_eq!(actor.voter_authorization.data.ballot_style, 1);
    }

    #[test]
    fn test_crypto_initialization() {
        let (_, dbb_verifying_key) = crate::cryptography::generate_signature_keypair();
        let (_, voter_verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();
        let election_hash = crate::elections::string_to_election_hash("test_election_hash");

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_verifying_key,
            VoterAuthorization::test_voter_authorization(
                election_hash,
                "test_pseudonym",
                1,
                voter_verifying_key,
            ),
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
        let election_hash = crate::elections::string_to_election_hash("test_election_hash");
        let voter_authorization = VoterAuthorization::test_voter_authorization(
            election_hash,
            "test_pseudonym",
            1,
            voter_verifying_key,
        );

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_verifying_key,
            voter_authorization.clone(),
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
            &election_hash,
            &"test_pseudonym".to_string(),
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
            voter_authorization,
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
        let voter_pseudonym = "test_pseudonym".to_string();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        // Test SignedBallotMsgData serialization
        let test_ballot = crate::elections::Ballot::test_ballot(1);
        let (ballot_cryptogram, _) = crate::cryptography::encrypt_ballot(
            test_ballot,
            &election_keypair.pkey,
            &election_hash,
            &voter_pseudonym,
        )
        .unwrap();

        let signed_ballot_data = crate::messages::SignedBallotMsgData {
            voter_authorization: VoterAuthorization::test_voter_authorization(
                election_hash,
                "voter_123",
                1,
                verifying_key,
            ),
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
        let voter_pseudonym = "test_pseudonym".to_string();
        let voter_authorization = VoterAuthorization::test_voter_authorization(
            election_hash,
            "voter_123",
            1,
            voter_verifying_key,
        );

        let mut submission_actor = SubmissionActor::new(
            election_hash,
            dbb_verifying_key,
            voter_authorization.clone(),
            election_keypair.pkey.clone(),
        );
        submission_actor.set_voter_signing_key(voter_signing_key.clone());

        // Create a test ballot
        let ballot = Ballot::test_ballot(1);

        // Test that we can create a SignedBallotMsg directly using encrypt_ballot
        use crate::messages::{SignedBallotMsg, SignedBallotMsgData};

        let (ballot_cryptogram, _randomizers) = crate::cryptography::encrypt_ballot(
            ballot,
            &election_keypair.pkey,
            &election_hash,
            &voter_pseudonym,
        )
        .unwrap();

        let data = SignedBallotMsgData {
            voter_authorization,
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
        wrong_data.voter_authorization.data.voter_pseudonym = "wrong_voter".to_string();
        let wrong_serialized = wrong_data.ser();
        let wrong_verification_result = crate::cryptography::verify_signature(
            &wrong_serialized,
            &signed_ballot_msg.signature,
            &signed_ballot_msg
                .data
                .voter_authorization
                .data
                .voter_verifying_key,
        );
        assert!(
            wrong_verification_result.is_err(),
            "Signature verification should fail with wrong data"
        );
    }
}
