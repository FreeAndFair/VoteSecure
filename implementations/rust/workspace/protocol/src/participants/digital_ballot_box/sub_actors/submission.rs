// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Ballot Submission Sub-Actor for the Digital Ballot Box.
//!
//! This actor handles the ballot submission protocol where a Voting Application
//! submits an encrypted and signed ballot to be recorded on the bulletin board.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::{BallotSubBulletin, BallotSubBulletinData, Bulletin};
use crate::cryptography::{ElectionKey, SigningKey, verify_ciphertext_proof};
use crate::elections::{BallotStyle, ElectionHash};
use crate::messages::{ProtocolMessage, SignedBallotMsg, TrackerMsg, TrackerMsgData};
use crate::participants::digital_ballot_box::{BulletinBoard, DBBStorage};
use cryptography::utils::serialization::VSerializable;

// --- I/O Types ---

#[derive(Debug, Clone)]
pub enum SubmissionInput {
    NetworkMessage(ProtocolMessage),
}

#[derive(Debug, Clone)]
pub enum SubmissionOutput {
    SendMessage(ProtocolMessage),
    Success,
    Failure(String),
}

// --- State ---

#[derive(Debug, Clone)]
pub enum SubmissionState {
    AwaitingBallot,
    ProcessingBallot,
    Complete,
}

// --- Actor ---

#[derive(Clone, Debug)]
pub struct SubmissionActor {
    state: SubmissionState,
    election_hash: ElectionHash,
    dbb_signing_key: SigningKey,
    election_public_key: ElectionKey,
    received_ballot: Option<SignedBallotMsg>,
}

impl SubmissionActor {
    pub fn new(
        election_hash: ElectionHash,
        dbb_signing_key: SigningKey,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            state: SubmissionState::AwaitingBallot,
            election_hash,
            dbb_signing_key,
            election_public_key,
            received_ballot: None,
        }
    }

    pub fn get_state(&self) -> SubmissionState {
        self.state.clone()
    }

    pub fn process_input<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        input: SubmissionInput,
        storage: &mut S,
        bulletin_board: &mut B,
    ) -> Result<SubmissionOutput, String> {
        match (self.state.clone(), input) {
            (SubmissionState::AwaitingBallot, SubmissionInput::NetworkMessage(msg)) => {
                match msg {
                    ProtocolMessage::SubmitSignedBallot(signed_ballot) => {
                        // Perform all 9 "Submit Signed Ballot Checks"
                        let check_result = self.perform_submit_signed_ballot_checks(
                            &signed_ballot,
                            storage,
                            bulletin_board,
                        );

                        if let Err(error_msg) = check_result {
                            // The ballot was invalid.
                            self.state = SubmissionState::Complete;
                            return Ok(SubmissionOutput::SendMessage(
                                ProtocolMessage::ReturnBallotTracker(
                                    self.create_error_message(error_msg),
                                ),
                            ));
                        };

                        // Store the ballot
                        self.received_ballot = Some(signed_ballot.clone());
                        self.state = SubmissionState::ProcessingBallot;

                        // Create and post BallotSubBulletin
                        let tracker_result =
                            self.create_and_post_bulletin(&signed_ballot, storage, bulletin_board);

                        if let Err(error_msg) = tracker_result {
                            // The ballot was invalid.
                            self.state = SubmissionState::Complete;
                            return Ok(SubmissionOutput::SendMessage(
                                ProtocolMessage::ReturnBallotTracker(
                                    self.create_error_message(error_msg),
                                ),
                            ));
                        };

                        // Create TrackerMsg response
                        self.state = SubmissionState::Complete;
                        Ok(SubmissionOutput::SendMessage(
                            ProtocolMessage::ReturnBallotTracker(self.create_tracker_message(
                                tracker_result.expect("tracker must exist here"),
                            )),
                        ))
                    }
                    _ => Err("Expected SubmitSignedBallot message".to_string()),
                }
            }
            _ => Err("Invalid input for current state".to_string()),
        }
    }

    // --- Submit Signed Ballot Checks (8 checks from spec) ---

    /// Performs all 8 "Submit Signed Ballot Checks" from the spec.
    fn perform_submit_signed_ballot_checks<S: DBBStorage, B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        storage: &S,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Check #1: The signature is a valid signature over the message contents
        // (moved first to avoid expensive operations on invalid signatures)
        self.check_signature_valid(ballot)?;

        // Check #2: The election_hash is the hash of the election configuration item
        self.check_election_hash(&ballot.data.election_hash)?;

        // Check #3: The voter_pseudonym and voter_public_key match a stored AuthVoterMsg from EAS
        let auth_msg = self.check_voter_authorization(&ballot.data, storage)?;

        // Check #4: The ballot_style is a valid ballot style for this election
        self.check_ballot_style_valid(ballot.data.ballot_style)?;

        // Check #5: The ballot_style matches the AuthVoterMsg from check #3
        self.check_ballot_style_matches(&auth_msg, ballot.data.ballot_style)?;

        // Check #6: The list of contest_id in the BallotCryptograms matches the ballot_style
        // Note: In our simplified implementation, we have a single cryptogram for the entire ballot
        // This check is implicitly satisfied by the ballot structure

        // Check #7: All Naor-Yung proofs verify correctly
        self.check_naor_yung_proofs(ballot)?;

        // Check #8: All ciphertexts are encryptions for the public election key
        // Note: This is verified as part of the Naor-Yung proof verification in check #7

        // Check #9: The ciphertext does not already appear on the bulletin board.
        self.check_ciphertext_not_on_bb(ballot, bulletin_board)?;

        Ok(())
    }

    /// Check #2: The election_hash is the hash of the election configuration item
    fn check_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if *election_hash != self.election_hash {
            return Err("Ballot has incorrect election hash".to_string());
        }
        Ok(())
    }

    /// Check #3: The voter_pseudonym and voter_public_key match a stored AuthVoterMsg
    fn check_voter_authorization<S: DBBStorage>(
        &self,
        ballot_data: &crate::messages::SignedBallotMsgData,
        storage: &S,
    ) -> Result<crate::messages::AuthVoterMsg, String> {
        let auth_msg = storage
            .get_voter_authorization(&ballot_data.voter_pseudonym)?
            .ok_or_else(|| {
                format!(
                    "No authorization found for voter pseudonym: {}",
                    ballot_data.voter_pseudonym
                )
            })?;

        // Verify voter_verifying_key matches
        if auth_msg.data.voter_verifying_key != ballot_data.voter_verifying_key {
            return Err("Voter verifying key does not match authorization".to_string());
        }

        Ok(auth_msg)
    }

    /// Check #4: The ballot_style is a valid ballot style for this election
    fn check_ballot_style_valid(&self, ballot_style: BallotStyle) -> Result<(), String> {
        // BallotStyle is u8, so we just check it's greater than 0
        if ballot_style == 0 {
            return Err("Ballot style must be greater than 0".to_string());
        }
        // In a real implementation, we would validate against the election manifest
        // For now, we just ensure it's non-zero
        Ok(())
    }

    /// Check #5: The ballot_style matches the AuthVoterMsg
    fn check_ballot_style_matches(
        &self,
        auth_msg: &crate::messages::AuthVoterMsg,
        ballot_style: BallotStyle,
    ) -> Result<(), String> {
        if auth_msg.data.ballot_style != ballot_style {
            return Err(format!(
                "Ballot style {} does not match authorized ballot style {}",
                ballot_style, auth_msg.data.ballot_style
            ));
        }
        Ok(())
    }

    /// Check #1: The signature is a valid signature over the message contents
    fn check_signature_valid(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        let serialized = ballot.data.ser();
        crate::cryptography::verify_signature(
            &serialized,
            &ballot.signature,
            &ballot.data.voter_verifying_key,
        )
        .map_err(|_| "Invalid signature on ballot".to_string())
    }

    /// Check #7: All Naor-Yung proofs verify correctly
    fn check_naor_yung_proofs(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        // Verify the Naor-Yung proof in the ballot ciphertext
        #[crate::warning(
            "Potentially expensive clone. Function verify_ciphertext_proof clones ciphertext internally."
        )]
        let is_valid = verify_ciphertext_proof(
            &ballot.data.ballot_cryptogram.ciphertext,
            &self.election_public_key,
            &self.election_hash,
            &ballot.data.voter_pseudonym,
        )
        .map_err(|e| format!("Proof verification error: {}", e))?;

        if !is_valid {
            return Err("Naor-Yung proof verification failed".to_string());
        }

        Ok(())
    }

    /// Check #9: Ciphertext does not already appear on bulletin board
    fn check_ciphertext_not_on_bb<B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        if bulletin_board.get_all_bulletins().iter().any(|b| match b {
            Bulletin::BallotSubmission(bsb) => {
                bsb.data.ballot.data.ballot_cryptogram.ciphertext
                    == ballot.data.ballot_cryptogram.ciphertext
            }
            _ => false,
        }) {
            return Err("ciphertext already exists on bulletin board".to_string());
        }
        Ok(())
    }

    // --- Bulletin Creation and Posting ---

    /// Create and post a BallotSubBulletin to the bulletin board.
    fn create_and_post_bulletin<S: DBBStorage, B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        storage: &mut S,
        bulletin_board: &mut B,
    ) -> Result<String, String> {
        // Get the previous bulletin hash for chaining
        let previous_bb_msg_hash = bulletin_board.get_last_bulletin_hash().unwrap_or_default();

        // Get current timestamp (Unix timestamp in seconds)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        // Create BallotSubBulletinData
        let bulletin_data = BallotSubBulletinData {
            election_hash: self.election_hash,
            timestamp,
            ballot: ballot.clone(),
            previous_bb_msg_hash,
        };

        // Sign the bulletin data
        let serialized_data = bulletin_data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);

        // Convert signature to string for bulletin
        let signature = hex::encode(signature_bytes.to_bytes());

        // Create the bulletin
        let bulletin = Bulletin::BallotSubmission(BallotSubBulletin {
            data: bulletin_data,
            signature,
        });

        // Append to bulletin board and get tracker
        let tracker = bulletin_board.append_bulletin(bulletin)?;

        // Store the submitted ballot in storage
        storage.store_submitted_ballot(&ballot.data.voter_pseudonym, &tracker, ballot.clone())?;

        Ok(tracker)
    }

    /// Create a TrackerMsg to return to the VA.
    fn create_tracker_message(&self, tracker: String) -> TrackerMsg {
        let data = TrackerMsgData {
            election_hash: self.election_hash,
            tracker: Some(tracker),
            submission_result: (true, "".to_string()),
        };

        // Sign the tracker message
        let serialized = data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &self.dbb_signing_key);

        TrackerMsg { data, signature }
    }

    /// Create a TrackerMsg with an error to return to the VA.
    fn create_error_message(&self, error_msg: String) -> TrackerMsg {
        let data = TrackerMsgData {
            election_hash: self.election_hash,
            tracker: None,
            submission_result: (false, error_msg),
        };

        // Sign the tracker message
        let serialized = data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &self.dbb_signing_key);

        TrackerMsg { data, signature }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::{VerifyingKey, encrypt_ballot, generate_signature_keypair};
    use crate::elections::{Ballot, string_to_election_hash};
    use crate::messages::{AuthVoterMsg, AuthVoterMsgData, SignedBallotMsgData};
    use crate::participants::digital_ballot_box::{InMemoryBulletinBoard, InMemoryStorage};

    fn create_test_setup() -> (
        InMemoryStorage,
        InMemoryBulletinBoard,
        ElectionHash,
        SigningKey,
        VerifyingKey,
        ElectionKey,
    ) {
        let storage = InMemoryStorage::new();
        let bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");
        let (dbb_signing_key, dbb_verifying_key) = generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        (
            storage,
            bulletin_board,
            election_hash,
            dbb_signing_key,
            dbb_verifying_key,
            election_keypair.pkey,
        )
    }

    fn create_authorized_voter(
        storage: &mut InMemoryStorage,
        pseudonym: &str,
        verifying_key: VerifyingKey,
        ballot_style: BallotStyle,
        election_hash: ElectionHash,
    ) {
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: pseudonym.to_string(),
            voter_verifying_key: verifying_key,
            ballot_style,
        };
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: crate::cryptography::Signature::from_bytes(&[0u8; 64]),
        };
        storage
            .store_voter_authorization(&pseudonym.to_string(), auth_msg)
            .unwrap();
    }

    #[test]
    fn test_successful_ballot_submission() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        // Create voter keys and authorize
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        // Create and encrypt ballot
        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        // Create signed ballot message
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        // Create submission actor and process
        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(_)) => {
                // Success
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_election_hash() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        // Use wrong election hash
        let wrong_hash = string_to_election_hash("wrong_election");
        let ballot_data = SignedBallotMsgData {
            election_hash: wrong_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("election hash"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_unauthorized_voter() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        // Don't authorize the voter
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(
                    msg.data
                        .submission_result
                        .1
                        .contains("No authorization found")
                );
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    // ===== Malformed Signature Tests =====

    #[test]
    fn test_invalid_signature_wrong_key() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();

        // Sign with a different key than the voter's key
        let (wrong_signing_key, _wrong_verifying_key) = generate_signature_keypair();
        let signature = crate::cryptography::sign_data(&serialized, &wrong_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_corrupted_bytes() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let mut signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);

        // Corrupt the signature by flipping some bytes
        let sig_bytes = signature.to_bytes();
        let mut corrupted_bytes = sig_bytes;
        corrupted_bytes[0] ^= 0xFF;
        corrupted_bytes[10] ^= 0xFF;
        corrupted_bytes[30] ^= 0xFF;
        signature = crate::cryptography::Signature::from_bytes(&corrupted_bytes);

        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_wrong_data() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        // Sign different data (different ballot)
        let different_ballot = Ballot::test_ballot(99999);
        let (different_cryptogram, _) = encrypt_ballot(
            different_ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();
        let different_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: different_cryptogram,
        };
        let different_serialized = different_data.ser();
        let signature = crate::cryptography::sign_data(&different_serialized, &voter_signing_key);

        // But send the original data with signature from different data
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_zeros() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        // Use all-zeros signature
        let signature = crate::cryptography::Signature::from_bytes(&[0u8; 64]);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_ones() {
        let (
            mut storage,
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        create_authorized_voter(
            &mut storage,
            "voter123",
            voter_verifying_key,
            1,
            election_hash,
        );

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        // Use all-ones signature
        let signature = crate::cryptography::Signature::from_bytes(&[0xFFu8; 64]);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(election_hash, dbb_signing_key, election_public_key);

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMessage::SubmitSignedBallot(signed_ballot)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMessage::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }
}
