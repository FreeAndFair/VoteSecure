// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Ballot Casting Sub-Actor for the Digital Ballot Box.
//!
//! This actor handles the ballot casting protocol where a Voting Application
//! requests that a previously submitted ballot be officially cast.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::{
    BALLOT_CAST_BULLETIN, BALLOT_SUBMISSION_BULLETIN, BallotCastContents, BallotSubContents,
    Bulletin, BulletinData,
};
use crate::cryptography::{SigningKey, VerifyingKey, verify_signature};
use crate::elections::{BulletinTracker, ElectionHash, VoterAuthorization};
use crate::messages::{CastConfMsg, CastConfMsgData, CastReqMsg, ProtocolMsg, SignedBallotMsg};
use crate::participants::digital_ballot_box::bulletin_board::BulletinBoard;
use cryptography::utils::serialization::VSerializable;

/// Inputs accepted by the casting sub-actor.
#[derive(Debug, Clone)]
pub enum CastingInput {
    /// A protocol message received over the network.
    NetworkMessage(ProtocolMsg),
}

/// Outputs produced by the casting sub-actor.
#[derive(Debug, Clone)]
pub enum CastingOutput {
    /// A protocol message that should be sent onward.
    SendMessage(ProtocolMsg),
    /// The casting protocol completed successfully.
    Success,
    /// The casting protocol failed with an error message.
    Failure(String),
}

/// Casting sub-actor states.
#[derive(Debug, Clone)]
pub enum CastingState {
    /// Waiting for an incoming cast request.
    AwaitingCastRequest,
    /// Publishing the ballot-cast bulletin.
    PublishingBallotCast,
    /// Protocol execution is complete.
    Complete,
}

/// Ballot casting sub-actor for the DBB.
#[derive(Clone, Debug)]
pub struct CastingActor {
    state: CastingState,
    election_hash: ElectionHash,
    dbb_signing_key: SigningKey,
    eas_verifying_key: VerifyingKey,
    // Store intermediate data needed between state transitions
    cast_request: Option<CastReqMsg>,
    ballot_sub_tracker: Option<BulletinTracker>,
}

impl CastingActor {
    /// Create a new casting sub-actor.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `dbb_signing_key` - The DBB's signing key for signing bulletins.
    /// * `eas_verifying_key` - The EAS's verifying key, for validating the
    ///   voter authorization token embedded in the cast request.
    ///
    /// # Returns
    /// A new `CastingActor` in the `AwaitingCastRequest` state.
    pub fn new(
        election_hash: ElectionHash,
        dbb_signing_key: SigningKey,
        eas_verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            state: CastingState::AwaitingCastRequest,
            election_hash,
            dbb_signing_key,
            eas_verifying_key,
            cast_request: None,
            ballot_sub_tracker: None,
        }
    }

    /// Get the current casting state.
    ///
    /// # Returns
    /// A clone of the current `CastingState`.
    pub fn get_state(&self) -> CastingState {
        self.state.clone()
    }

    /// Process an input for the casting subprotocol.
    ///
    /// # Arguments
    /// * `input` - The input to process.
    /// * `bulletin_board` - Mutable reference to the bulletin board.
    ///
    /// # Returns
    /// `Ok(output)` describing the result, or `Err(msg)` if a bulletin board error occurs.
    pub fn process_input<B: BulletinBoard>(
        &mut self,
        input: CastingInput,
        bulletin_board: &mut B,
    ) -> Result<CastingOutput, String> {
        match input {
            CastingInput::NetworkMessage(message) => {
                if let ProtocolMsg::CastReq(cast_req) = message {
                    self.handle_cast_request(cast_req, bulletin_board)
                } else {
                    Err(format!(
                        "Unexpected message type in casting actor: {:?}",
                        message
                    ))
                }
            }
        }
    }

    fn handle_cast_request<B: BulletinBoard>(
        &mut self,
        cast_req: CastReqMsg,
        bulletin_board: &mut B,
    ) -> Result<CastingOutput, String> {
        // Store the cast request and ballot tracker for later use;
        // we do this before error reporting because we need the ballot
        // tracker from the message for error reporting, but there will
        // be no later use then.
        let ballot_tracker = cast_req.data.ballot_tracker.clone();
        self.ballot_sub_tracker = Some(ballot_tracker.clone());
        self.cast_request = Some(cast_req.clone());

        // Perform all validation checks; on success, this also returns the
        // submitted ballot being cast, fetched from the bulletin board.
        let ballot = match self.perform_cast_request_checks(&cast_req, bulletin_board) {
            Ok(ballot) => ballot,
            Err(error_msg) => {
                self.state = CastingState::Complete;
                return Ok(CastingOutput::SendMessage(ProtocolMsg::CastConf(
                    self.create_error_message(error_msg),
                )));
            }
        };

        // Publish the ballot cast bulletin
        let ballot_cast_tracker =
            self.publish_ballot_cast(ballot, cast_req.clone(), bulletin_board);

        if let Err(error_msg) = ballot_cast_tracker {
            // The cast bulletin couldn't be published.
            self.state = CastingState::Complete;
            return Ok(CastingOutput::SendMessage(ProtocolMsg::CastConf(
                self.create_error_message(error_msg),
            )));
        }

        // Create and send the confirmation message
        let conf_msg = self.create_confirmation_message(
            ballot_tracker,
            ballot_cast_tracker.expect("cast tracker must exist at this point"),
        );

        self.state = CastingState::Complete;

        Ok(CastingOutput::SendMessage(ProtocolMsg::CastConf(conf_msg)))
    }

    // =============================================================================
    // Validation Checks (from ballot-cast-spec.md)
    // =============================================================================

    fn perform_cast_request_checks<B: BulletinBoard>(
        &self,
        cast_req: &CastReqMsg,
        bulletin_board: &B,
    ) -> Result<SignedBallotMsg, String> {
        // Check #1: signature is valid (moved first to avoid expensive operations on invalid signatures)
        self.check_signature_valid(cast_req)?;

        // Check #2: voter_authorization is valid (EAS signature, election hash,
        // and timestamp).
        cast_req
            .data
            .voter_authorization
            .validate(&self.eas_verifying_key, &self.election_hash)?;

        // Check #3: ballot_tracker matches a BallotSubBulletin entry whose
        // voter_authorization is identical to this message's.
        let ballot = self.check_ballot_tracker_valid(&cast_req.data, bulletin_board)?;

        // Check #4: no previously published BallotCastBulletin for this voter
        self.check_no_previous_cast(&cast_req.data.voter_authorization, bulletin_board)?;

        // Check #5: the BallotSubBulletin being cast is the most recent
        // submitted ballot for this voter
        self.check_most_recent_submission(&cast_req.data, &ballot, bulletin_board)?;

        Ok(ballot)
    }

    /// Check #3: The ballot_tracker matches a `BallotSubBulletin` entry, and
    /// the `voter_authorization` in the cast request is identical to the one
    /// in that submission.
    fn check_ballot_tracker_valid<B: BulletinBoard>(
        &self,
        cast_req_data: &crate::messages::CastReqMsgData,
        bulletin_board: &B,
    ) -> Result<SignedBallotMsg, String> {
        // Get the bulletin by its tracker (hash)
        let bulletin = bulletin_board
            .get_bulletin(&cast_req_data.ballot_tracker)?
            .ok_or("Ballot tracker does not match any submitted ballot")?;

        // Verify it's a ballot submission bulletin and the voter_authorization matches
        let sub = bulletin
            .data
            .contents
            .as_any()
            .downcast_ref::<BallotSubContents>()
            .ok_or_else(|| "Tracker does not refer to a ballot submission".to_string())?;

        if sub.ballot.data.voter_authorization != cast_req_data.voter_authorization {
            return Err(
                "Cast request voter_authorization does not match the ballot submission".to_string(),
            );
        }

        Ok(sub.ballot.clone())
    }

    /// Check #4: No previously published BallotCastBulletin for this voter.
    fn check_no_previous_cast<B: BulletinBoard>(
        &self,
        voter_authorization: &VoterAuthorization,
        bulletin_board: &B,
    ) -> Result<(), String> {
        let voter_pseudonym = voter_authorization.data.voter_pseudonym.clone();
        if bulletin_board
            .get_bulletins_by_type_and_pseudonym(BALLOT_CAST_BULLETIN, voter_pseudonym)
            .is_empty()
        {
            Ok(())
        } else {
            Err("Voter has already cast a ballot".to_string())
        }
    }

    /// Check #5: The ballot being cast is the most recent submission on the
    /// bulletin board with the voter pseudonym in the voter_authorization.
    fn check_most_recent_submission<B: BulletinBoard>(
        &self,
        cast_req_data: &crate::messages::CastReqMsgData,
        ballot: &SignedBallotMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        let voter_pseudonym = cast_req_data
            .voter_authorization
            .data
            .voter_pseudonym
            .clone();
        let submissions = bulletin_board
            .get_bulletins_by_type_and_pseudonym(BALLOT_SUBMISSION_BULLETIN, voter_pseudonym);
        let most_recent = submissions
            .last()
            .and_then(|b| b.data.contents.as_any().downcast_ref::<BallotSubContents>())
            .ok_or_else(|| "No submission found for voter".to_string())?;

        if &most_recent.ballot != ballot {
            return Err(
                "Cast request does not reference the most recent ballot submission".to_string(),
            );
        }

        Ok(())
    }

    /// Check #1: The signature is valid.
    fn check_signature_valid(&self, cast_req: &CastReqMsg) -> Result<(), String> {
        let serialized_data = cast_req.data.ser();
        verify_signature(
            &serialized_data,
            &cast_req.signature,
            &cast_req.data.voter_authorization.data.voter_verifying_key,
        )
    }

    // =============================================================================
    // Bulletin Publishing
    // =============================================================================

    /// Publish the ballot cast bulletin to the bulletin board.
    fn publish_ballot_cast<B: BulletinBoard>(
        &self,
        ballot: crate::messages::SignedBallotMsg,
        cast_intent: CastReqMsg,
        bulletin_board: &mut B,
    ) -> Result<BulletinTracker, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        let previous_hash = bulletin_board.get_last_bulletin_hash().unwrap_or_default();

        let bulletin_data = BulletinData {
            election_hash: self.election_hash,
            contents: Box::new(BallotCastContents {
                ballot,
                cast_intent,
            }),
            timestamp,
            previous_bb_msg_hash: previous_hash,
        };

        // Sign the bulletin data
        let serialized_data = bulletin_data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = hex::encode(signature_bytes.to_bytes());

        let bulletin = Bulletin {
            data: bulletin_data,
            signature,
        };

        let tracker = bulletin_board.append_bulletin(bulletin)?;
        Ok(tracker)
    }

    /// Create the confirmation message to send back to the VA.
    fn create_confirmation_message(
        &self,
        ballot_sub_tracker: BulletinTracker,
        ballot_cast_tracker: BulletinTracker,
    ) -> CastConfMsg {
        let data = CastConfMsgData {
            election_hash: self.election_hash,
            ballot_sub_tracker,
            ballot_cast_tracker: Some(ballot_cast_tracker),
            cast_result: (true, "".to_string()),
        };

        // Sign the confirmation message
        let serialized_data = data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = crate::cryptography::Signature::from_bytes(&signature_bytes.to_bytes());

        CastConfMsg { data, signature }
    }

    /// Create a CastConfMsg with an error to return to the VA.
    fn create_error_message(&self, error_msg: String) -> CastConfMsg {
        let data = CastConfMsgData {
            election_hash: self.election_hash,
            ballot_sub_tracker: self
                .ballot_sub_tracker
                .clone()
                .expect("submit tracker must exist at this point"),
            ballot_cast_tracker: None,
            cast_result: (false, error_msg),
        };

        // Sign the tracker message
        let serialized = data.ser();
        let signature = crate::cryptography::sign_data(&serialized, &self.dbb_signing_key);

        CastConfMsg { data, signature }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletins::{BallotCastContents, BallotSubContents, BulletinData};
    use crate::cryptography::{
        BallotCryptogram, Signature, VerifyingKey, generate_signature_keypair,
    };
    use crate::elections::{BallotStyle, VoterAuthorizationTimestamp, string_to_election_hash};
    use crate::messages::{CastReqMsgData, SignedBallotMsg, SignedBallotMsgData};
    use crate::participants::digital_ballot_box::bulletin_board::InMemoryBulletinBoard;

    // Helper to create a test ballot cryptogram
    fn create_test_ballot_cryptogram(ballot_style: BallotStyle) -> BallotCryptogram {
        // Create a test keypair and encrypt a placeholder message
        let keypair = crate::cryptography::generate_encryption_keypair(b"test").unwrap();
        // Create dummy group elements (identity elements work for testing)
        use cryptography::groups::ristretto255::RistrettoElement;
        use cryptography::traits::groups::GroupElement;
        let identity = RistrettoElement::one();
        let message = [identity];
        let ciphertext = keypair
            .encrypt(&message, b"test_context")
            .expect("Failed to encrypt");
        BallotCryptogram {
            ballot_style,
            ciphertext,
        }
    }

    fn setup_test_environment() -> (
        InMemoryBulletinBoard,
        SigningKey,
        VerifyingKey,
        SigningKey,
        VerifyingKey,
    ) {
        let bulletin_board = InMemoryBulletinBoard::new();
        let (dbb_signing_key, dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, eas_verifying_key) = generate_signature_keypair();

        (
            bulletin_board,
            dbb_signing_key,
            dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        )
    }

    /// Build and sign a ballot submission for `voter_authorization`.
    fn make_signed_ballot(
        voter_authorization: VoterAuthorization,
        voter_signing_key: &SigningKey,
        ballot_style: BallotStyle,
    ) -> SignedBallotMsg {
        let data = SignedBallotMsgData {
            voter_authorization,
            ballot_cryptogram: create_test_ballot_cryptogram(ballot_style),
        };
        let signature = crate::cryptography::sign_data(&data.ser(), voter_signing_key);
        SignedBallotMsg { data, signature }
    }

    /// Append a ballot submission bulletin to the bulletin board and return its tracker.
    fn publish_ballot_sub(
        bulletin_board: &mut InMemoryBulletinBoard,
        election_hash: ElectionHash,
        dbb_signing_key: &SigningKey,
        ballot: SignedBallotMsg,
    ) -> BulletinTracker {
        let bulletin_data = BulletinData {
            election_hash,
            contents: Box::new(BallotSubContents { ballot }),
            timestamp: 1000,
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let signature_bytes = crate::cryptography::sign_data(&bulletin_data.ser(), dbb_signing_key);
        bulletin_board
            .append_bulletin(Bulletin {
                data: bulletin_data,
                signature: hex::encode(signature_bytes.to_bytes()),
            })
            .unwrap()
    }

    #[test]
    fn test_successful_cast() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        // Create and publish a submitted ballot
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Create cast request
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::cryptography::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        // Process the cast request
        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(conf)) => {
                assert_eq!(conf.data.election_hash, election_hash);
                assert_eq!(conf.data.ballot_sub_tracker, tracker);
                assert!(conf.data.cast_result.0);
            }
            _ => panic!("Expected CastConf message"),
        }

        // Verify the voter is marked as cast on the bulletin board.
        assert!(
            !bulletin_board
                .get_bulletins_by_type_and_pseudonym(BALLOT_CAST_BULLETIN, "voter123".to_string())
                .is_empty()
        );
    }

    #[test]
    fn test_invalid_election_hash() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");
        let wrong_election_hash = string_to_election_hash("wrong_election");

        // Authorization signed for a different election than the actor's.
        let voter_authorization = VoterAuthorization::new(
            wrong_election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: "tracker_123".to_string(),
        };
        let cast_req_signature_bytes =
            crate::cryptography::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        // Process the cast request
        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("election hash"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    #[test]
    fn test_already_cast() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );

        // Create and publish a submitted ballot
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker = publish_ballot_sub(
            &mut bulletin_board,
            election_hash,
            &dbb_signing_key,
            ballot.clone(),
        );

        // Publish a ballot cast bulletin for this voter, simulating a previous cast.
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization: voter_authorization.clone(),
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature =
            crate::cryptography::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_intent = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature.to_bytes()),
        };
        let cast_bulletin_data = BulletinData {
            election_hash,
            contents: Box::new(BallotCastContents {
                ballot,
                cast_intent,
            }),
            timestamp: 1001,
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let cast_bulletin_signature =
            crate::cryptography::sign_data(&cast_bulletin_data.ser(), &dbb_signing_key);
        bulletin_board
            .append_bulletin(Bulletin {
                data: cast_bulletin_data,
                signature: hex::encode(cast_bulletin_signature.to_bytes()),
            })
            .unwrap();

        // Now try to cast again.
        let cast_req_data2 = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let cast_req_signature2 =
            crate::cryptography::sign_data(&cast_req_data2.ser(), &voter_signing_key);
        let cast_req2 = CastReqMsg {
            data: cast_req_data2,
            signature: Signature::from_bytes(&cast_req_signature2.to_bytes()),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req2)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("already cast"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    // ===== Malformed Signature Tests =====

    #[test]
    fn test_invalid_signature_wrong_key() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let ballot = make_signed_ballot(voter_authorization.clone(), &_voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Create cast request data and sign with WRONG key
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let (wrong_signing_key, _wrong_verifying_key) = generate_signature_keypair();
        let cast_req_signature_bytes =
            crate::cryptography::sign_data(&cast_req_data.ser(), &wrong_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_corrupted_bytes() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Create cast request data with CORRUPTED signature
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let cast_req_signature_bytes =
            crate::cryptography::sign_data(&cast_req_data.ser(), &voter_signing_key);

        // Corrupt the signature bytes
        let mut corrupted_bytes = cast_req_signature_bytes.to_bytes();
        corrupted_bytes[0] ^= 0xFF;
        corrupted_bytes[15] ^= 0xFF;
        corrupted_bytes[32] ^= 0xFF;

        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&corrupted_bytes),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_wrong_data() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Sign DIFFERENT data than what we're sending (a different pseudonym's authorization)
        let different_voter_authorization = VoterAuthorization::new(
            election_hash,
            "different_voter".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let different_cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization: different_voter_authorization,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::cryptography::sign_data(&different_cast_req_data.ser(), &voter_signing_key);

        // But send the original data with mismatched signature
        let actual_cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let cast_req = CastReqMsg {
            data: actual_cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_zeros() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Use all-zeros signature
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }

    #[test]
    fn test_invalid_signature_all_ones() {
        let (
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let voter_authorization = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        let ballot = make_signed_ballot(voter_authorization.clone(), &voter_signing_key, 1);
        let tracker =
            publish_ballot_sub(&mut bulletin_board, election_hash, &dbb_signing_key, ballot);

        // Use all-ones signature
        let cast_req_data = CastReqMsgData {
            election_hash,
            voter_authorization,
            ballot_tracker: tracker,
        };
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&[0xFFu8; 64]),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key, eas_verifying_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMsg::CastReq(cast_req)),
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMsg::CastConf(msg)) => {
                assert!(!msg.data.cast_result.0);
                assert!(msg.data.cast_result.1.contains("Invalid signature"));
            }
            _ => panic!("Expected CastConfMsg"),
        }
    }
}
