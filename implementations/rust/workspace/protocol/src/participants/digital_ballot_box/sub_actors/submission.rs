// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-26 Free & Fair
// See LICENSE.md for details

//! Ballot Submission Sub-Actor for the Digital Ballot Box.
//!
//! This actor handles the ballot submission protocol where a Voting Application
//! submits an encrypted and signed ballot to be recorded on the bulletin board.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::{BALLOT_CAST_BULLETIN, BallotSubContents, Bulletin, BulletinData};
use crate::cryptography::{ElectionKey, SigningKey, VerifyingKey, verify_ciphertext_proof};
use crate::elections::ElectionHash;
use crate::messages::{ProtocolMsg, SignedBallotMsg, TrackerMsg, TrackerMsgData};
use crate::participants::digital_ballot_box::BulletinBoard;
use cryptography::utils::serialization::VSerializable;

/// Inputs accepted by the submission sub-actor.
#[derive(Debug, Clone)]
pub enum SubmissionInput {
    /// A protocol message received over the network.
    NetworkMessage(ProtocolMsg),
}

/// Outputs produced by the submission sub-actor.
#[derive(Debug, Clone)]
pub enum SubmissionOutput {
    /// A protocol message that should be sent onward.
    SendMessage(ProtocolMsg),
    /// The submission protocol completed successfully.
    Success,
    /// The submission protocol failed with an error message.
    Failure(String),
}

/// Submission sub-actor states.
#[derive(Debug, Clone)]
pub enum SubmissionState {
    /// Waiting for a signed ballot.
    AwaitingBallot,
    /// Validating and publishing the ballot.
    ProcessingBallot,
    /// Protocol execution is complete.
    Complete,
}

/// Ballot submission sub-actor for the DBB.
#[derive(Clone, Debug)]
pub struct SubmissionActor {
    state: SubmissionState,
    election_hash: ElectionHash,
    dbb_signing_key: SigningKey,
    eas_verifying_key: VerifyingKey,
    election_public_key: ElectionKey,
    received_ballot: Option<SignedBallotMsg>,
}

impl SubmissionActor {
    /// Create a new submission sub-actor.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `dbb_signing_key` - The DBB's signing key for signing bulletins.
    /// * `eas_verifying_key` - The EAS's verifying key, for validating the
    ///   voter authorization token embedded in the submitted ballot.
    /// * `election_public_key` - The election public key for verifying Naor-Yung proofs.
    ///
    /// # Returns
    /// A new `SubmissionActor` in the `AwaitingBallot` state.
    pub fn new(
        election_hash: ElectionHash,
        dbb_signing_key: SigningKey,
        eas_verifying_key: VerifyingKey,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            state: SubmissionState::AwaitingBallot,
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
            received_ballot: None,
        }
    }

    /// Get the current submission state.
    ///
    /// # Returns
    /// A clone of the current `SubmissionState`.
    pub fn get_state(&self) -> SubmissionState {
        self.state.clone()
    }

    /// Process an input for the submission subprotocol.
    ///
    /// # Arguments
    /// * `input` - The input to process.
    /// * `bulletin_board` - Mutable reference to the bulletin board.
    ///
    /// # Returns
    /// `Ok(output)` describing the result, or `Err(msg)` if a bulletin board error occurs.
    pub fn process_input<B: BulletinBoard>(
        &mut self,
        input: SubmissionInput,
        bulletin_board: &mut B,
    ) -> Result<SubmissionOutput, String> {
        match (self.state.clone(), input) {
            (SubmissionState::AwaitingBallot, SubmissionInput::NetworkMessage(msg)) => {
                match msg {
                    ProtocolMsg::SubmitSignedBallot(signed_ballot) => {
                        // Perform checks #1-#4, which don't depend on bulletin board state.
                        let check_result = self.perform_pre_board_checks(&signed_ballot);

                        if let Err(error_msg) = check_result {
                            // The ballot was invalid.
                            self.state = SubmissionState::Complete;
                            return Ok(SubmissionOutput::SendMessage(
                                ProtocolMsg::ReturnBallotTracker(
                                    self.create_error_message(error_msg),
                                ),
                            ));
                        };

                        // Store the ballot
                        self.received_ballot = Some(signed_ballot.clone());
                        self.state = SubmissionState::ProcessingBallot;

                        // Atomically perform checks #5 and #6 (which do depend on
                        // bulletin board state) and post the resulting bulletin.
                        let actor = &*self;
                        let tracker_result = bulletin_board.append_bulletin_atomic(|bb| {
                            actor.build_submission_bulletin(&signed_ballot, bb)
                        });

                        if let Err(error_msg) = tracker_result {
                            // The ballot was invalid.
                            self.state = SubmissionState::Complete;
                            return Ok(SubmissionOutput::SendMessage(
                                ProtocolMsg::ReturnBallotTracker(
                                    self.create_error_message(error_msg),
                                ),
                            ));
                        };

                        // Create TrackerMsg response
                        self.state = SubmissionState::Complete;
                        Ok(SubmissionOutput::SendMessage(
                            ProtocolMsg::ReturnBallotTracker(self.create_tracker_message(
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

    // --- Submit Signed Ballot Checks (from ballot-submission-spec.md) ---

    /// Performs checks #1–#4 of the "Submit Signed Ballot Checks" from the
    /// spec, which don't depend on bulletin board state. Checks #5 and #6
    /// (which do) are performed in [`Self::build_submission_bulletin`],
    /// atomically with posting the resulting bulletin; see that method's
    /// documentation for more information.
    fn perform_pre_board_checks(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        // Check #1: The signature is a valid signature over the message contents
        // (moved first to avoid expensive operations on invalid signatures)
        self.check_signature_valid(ballot)?;

        // Check #2: The voter_authorization is valid (EAS signature, election hash,
        // and timestamp).
        ballot
            .data
            .voter_authorization
            .validate(&self.eas_verifying_key, &self.election_hash)?;

        // Check #3: All Naor-Yung proofs verify correctly; this also verifies that all
        // ciphertexts are encryptions for the election public key.
        self.check_naor_yung_proofs(ballot)?;

        // Check #4: The ballot_style in the ballot_cryptogram matches the ballot_style
        // in the voter_authorization.
        self.check_ballot_style_matches(ballot)?;

        Ok(())
    }

    /// Check #1: The signature is a valid signature over the message contents.
    fn check_signature_valid(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        let serialized = ballot.data.ser();
        crate::cryptography::verify_signature(
            &serialized,
            &ballot.signature,
            &ballot.data.voter_authorization.data.voter_verifying_key,
        )
        .map_err(|_| "Invalid signature on ballot".to_string())
    }

    /// Check #3: All Naor-Yung proofs verify correctly.
    fn check_naor_yung_proofs(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        // Verify the Naor-Yung proof in the ballot ciphertext
        #[crate::warning(
            "Potentially expensive clone. Function verify_ciphertext_proof clones ciphertext internally."
        )]
        let is_valid = verify_ciphertext_proof(
            &ballot.data.ballot_cryptogram.ciphertext,
            &self.election_public_key,
            &self.election_hash,
            &ballot.data.voter_authorization.data.voter_pseudonym,
        )
        .map_err(|e| format!("Proof verification error: {}", e))?;

        if !is_valid {
            return Err("Naor-Yung proof verification failed".to_string());
        }

        Ok(())
    }

    /// Check #4: The ballot_style in the ballot_cryptogram matches the ballot_style
    /// in the voter_authorization.
    fn check_ballot_style_matches(&self, ballot: &SignedBallotMsg) -> Result<(), String> {
        let cryptogram_style = ballot.data.ballot_cryptogram.ballot_style;
        let authorized_style = ballot.data.voter_authorization.data.ballot_style;
        if cryptogram_style != authorized_style {
            return Err(format!(
                "Ballot style {} does not match authorized ballot style {}",
                cryptogram_style, authorized_style
            ));
        }
        Ok(())
    }

    /// Check #5: No cast ballot appears on the bulletin board with the voter
    /// pseudonym in the voter_authorization.
    fn check_no_previous_cast<B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        let voter_pseudonym = ballot.data.voter_authorization.data.voter_pseudonym.clone();
        if bulletin_board
            .get_bulletins_by_type_and_pseudonym(BALLOT_CAST_BULLETIN, voter_pseudonym)
            .is_empty()
        {
            Ok(())
        } else {
            Err("voter has already cast a ballot".to_string())
        }
    }

    /// Check #6: Ciphertext does not already appear on bulletin board.
    fn check_ciphertext_not_on_bb<B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        if bulletin_board.has_ciphertext(&ballot.data.ballot_cryptogram.ciphertext)? {
            Err("ciphertext already exists on bulletin board".to_string())
        } else {
            Ok(())
        }
    }

    // --- Bulletin Creation and Posting ---

    /// Performs checks #5 and #6 of the "Submit Signed Ballot Checks" and
    /// builds the resulting signed ballot submission bulletin, ready to
    /// post.
    ///
    /// This function is meant to be passed as the `build` closure to
    /// [`BulletinBoard::append_bulletin_atomic`]: checks #5 and #6 read
    /// bulletin board state ("no cast ballot exists for this pseudonym",
    /// "this ciphertext doesn't already exist"), so they have to be
    /// evaluated atomically with the append to prevent race conditions.
    fn build_submission_bulletin<B: BulletinBoard>(
        &self,
        ballot: &SignedBallotMsg,
        bulletin_board: &B,
    ) -> Result<Bulletin, String> {
        // Check #5: No cast ballot appears on the bulletin board with the voter
        // pseudonym in the voter_authorization.
        self.check_no_previous_cast(ballot, bulletin_board)?;

        // Check #6: The ciphertext does not already appear on the bulletin board.
        self.check_ciphertext_not_on_bb(ballot, bulletin_board)?;

        // Get the previous bulletin hash for chaining
        let previous_bb_msg_hash = bulletin_board.get_last_bulletin_hash().unwrap_or_default();

        // Get current timestamp (Unix timestamp in seconds)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        // Create the bulletin data
        let bulletin_data = BulletinData {
            election_hash: self.election_hash,
            contents: Box::new(BallotSubContents {
                ballot: ballot.clone(),
            }),
            timestamp,
            previous_bb_msg_hash,
        };

        // Sign the bulletin data
        let serialized_data = bulletin_data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);

        // Convert signature to string for bulletin
        let signature = hex::encode(signature_bytes.to_bytes());

        Ok(Bulletin {
            data: bulletin_data,
            signature,
        })
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
    use crate::bulletins::BallotCastContents;
    use crate::cryptography::{VerifyingKey, encrypt_ballot, generate_signature_keypair};
    use crate::elections::{
        Ballot, VoterAuthorization, VoterAuthorizationTimestamp, string_to_election_hash,
    };
    use crate::messages::{CastReqMsg, CastReqMsgData, SignedBallotMsgData};
    use crate::participants::digital_ballot_box::InMemoryBulletinBoard;

    fn create_test_setup() -> (
        InMemoryBulletinBoard,
        ElectionHash,
        SigningKey,
        SigningKey,
        VerifyingKey,
        ElectionKey,
    ) {
        let bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, eas_verifying_key) = generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        (
            bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_keypair.pkey,
        )
    }

    #[test]
    fn test_successful_ballot_submission() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        // Create and encrypt ballot
        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot.clone(),
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        // Create voter keys and an authorization signed by the EAS, matching
        // the ballot's (pseudo-randomly generated) ballot style.
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            ballot.ballot_style,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        // Create signed ballot message
        let ballot_data = SignedBallotMsgData {
            voter_authorization,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        // Create submission actor and process
        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(msg.data.submission_result.0, "submission should succeed");
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_election_hash() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        // Authorization signed for a different election than the actor's.
        let wrong_hash = string_to_election_hash("wrong_election");
        let voter_authorization = VoterAuthorization::new(
            wrong_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("election hash"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_unauthorized_voter() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            _eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        // Authorization signed by a key other than the EAS's: the embedded
        // voter_authorization is self-consistent but not trusted by the DBB.
        let (untrusted_signing_key, _untrusted_verifying_key) = generate_signature_keypair();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &untrusted_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(
                    msg.data
                        .submission_result
                        .1
                        .contains("Invalid signature on voter authorization")
                );
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    // ===== Malformed Signature Tests =====

    #[test]
    fn test_invalid_signature_wrong_key() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
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

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_corrupted_bytes() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
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

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_wrong_data() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization: voter_authorization.clone(),
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
            voter_authorization,
            ballot_cryptogram: different_cryptogram,
        };
        let different_serialized = different_data.ser();
        let signature = crate::cryptography::sign_data(&different_serialized, &voter_signing_key);

        // But send the original data with signature from different data
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_zeros() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
            ballot_cryptogram,
        };

        // Use all-zeros signature
        let signature = crate::cryptography::Signature::from_bytes(&[0u8; 64]);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_ones() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
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
            voter_authorization,
            ballot_cryptogram,
        };

        // Use all-ones signature
        let signature = crate::cryptography::Signature::from_bytes(&[0xFFu8; 64]);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }

    #[test]
    fn test_submit_after_cast_rejected() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        // Construct a fresh, otherwise-valid ballot for the same pseudonym.
        let ballot = Ballot::test_ballot(12345);

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            ballot.ballot_style,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        // Append a BallotCast bulletin from this voter to the bulletin board,
        // simulating a previous cast ballot.
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization: voter_authorization.clone(),
            ballot_tracker: "existing_tracker".to_string(),
        };
        let cast_req_signature =
            crate::cryptography::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_intent = CastReqMsg {
            data: cast_req_data,
            signature: cast_req_signature,
        };
        let existing_ballot_data = SignedBallotMsgData {
            voter_authorization: voter_authorization.clone(),
            ballot_cryptogram: {
                let ballot = Ballot::test_ballot(1);
                encrypt_ballot(
                    ballot,
                    &election_public_key,
                    &election_hash,
                    &"voter123".to_string(),
                )
                .unwrap()
                .0
            },
        };
        let existing_ballot_signature =
            crate::cryptography::sign_data(&existing_ballot_data.ser(), &voter_signing_key);
        let cast_bulletin_data = BulletinData {
            election_hash,
            contents: Box::new(BallotCastContents {
                ballot: SignedBallotMsg {
                    data: existing_ballot_data,
                    signature: existing_ballot_signature,
                },
                cast_intent,
            }),
            timestamp: 1000,
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let cast_bulletin_signature =
            crate::cryptography::sign_data(&cast_bulletin_data.ser(), &dbb_signing_key);
        bulletin_board
            .append_bulletin_atomic(|_| {
                Ok(Bulletin {
                    data: cast_bulletin_data.clone(),
                    signature: hex::encode(cast_bulletin_signature.to_bytes()),
                })
            })
            .unwrap();

        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_data = SignedBallotMsgData {
            voter_authorization,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );

        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("cast"));
            }
            _ => panic!("Expected ReturnBallotTracker"),
        }
    }

    #[test]
    fn test_duplicate_ciphertext_rejected() {
        let (
            mut bulletin_board,
            election_hash,
            dbb_signing_key,
            eas_signing_key,
            eas_verifying_key,
            election_public_key,
        ) = create_test_setup();

        let ballot = Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot.clone(),
            &election_public_key,
            &election_hash,
            &"voter123".to_string(),
        )
        .unwrap();

        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            ballot.ballot_style,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        let ballot_data = SignedBallotMsgData {
            voter_authorization,
            ballot_cryptogram,
        };
        let serialized = ballot_data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &voter_signing_key);
        let signed_ballot = SignedBallotMsg {
            data: ballot_data,
            signature,
        };

        // First submission succeeds.
        let mut actor = SubmissionActor::new(
            election_hash,
            dbb_signing_key.clone(),
            eas_verifying_key,
            election_public_key.clone(),
        );
        let result = actor.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot.clone())),
            &mut bulletin_board,
        );
        assert!(result.is_ok());
        match result.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(
                    msg.data.submission_result.0,
                    "first submission should succeed"
                );
            }
            _ => panic!("Expected TrackerMsg"),
        }

        // Second submission with the same ciphertext is rejected.
        let mut actor2 = SubmissionActor::new(
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            election_public_key,
        );
        let result2 = actor2.process_input(
            SubmissionInput::NetworkMessage(ProtocolMsg::SubmitSignedBallot(signed_ballot)),
            &mut bulletin_board,
        );
        assert!(result2.is_ok());
        match result2.unwrap() {
            SubmissionOutput::SendMessage(ProtocolMsg::ReturnBallotTracker(msg)) => {
                assert!(!msg.data.submission_result.0);
                assert!(msg.data.submission_result.1.contains("ciphertext"));
            }
            _ => panic!("Expected TrackerMsg"),
        }
    }
}
