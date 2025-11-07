/*!
Ballot Casting Sub-Actor for the Digital Ballot Box.

This actor handles the ballot casting protocol where a Voting Application
requests that a previously submitted ballot be officially cast.
*/

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::bulletins::{
    BallotCastBulletin, BallotCastBulletinData, Bulletin, VoterAuthBulletin, VoterAuthBulletinData,
};
use crate::crypto::{SigningKey, verify_signature};
use crate::elections::{BallotTracker, ElectionHash};
use crate::messages::{CastConfMsg, CastConfMsgData, CastReqMsg, ProtocolMessage};
use crate::participants::digital_ballot_box::{bulletin_board::BulletinBoard, storage::DBBStorage};
use crypto::utils::serialization::VSerializable;

// --- I/O Types ---

#[derive(Debug, Clone)]
pub enum CastingInput {
    NetworkMessage(ProtocolMessage),
}

#[derive(Debug, Clone)]
pub enum CastingOutput {
    SendMessage(ProtocolMessage),
    Success,
    Failure(String),
}

// --- State ---

#[derive(Debug, Clone)]
pub enum CastingState {
    AwaitingCastRequest,
    PublishingVoterAuth,
    PublishingBallotCast,
    Complete,
}

// --- Actor ---

#[derive(Clone, Debug)]
pub struct CastingActor {
    state: CastingState,
    election_hash: ElectionHash,
    dbb_signing_key: SigningKey,
    // Store intermediate data needed between state transitions
    cast_request: Option<CastReqMsg>,
    ballot_sub_tracker: Option<BallotTracker>,
}

impl CastingActor {
    pub fn new(election_hash: ElectionHash, dbb_signing_key: SigningKey) -> Self {
        Self {
            state: CastingState::AwaitingCastRequest,
            election_hash,
            dbb_signing_key,
            cast_request: None,
            ballot_sub_tracker: None,
        }
    }

    pub fn get_state(&self) -> CastingState {
        self.state.clone()
    }

    pub fn process_input<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        input: CastingInput,
        storage: &mut S,
        bulletin_board: &mut B,
    ) -> Result<CastingOutput, String> {
        match input {
            CastingInput::NetworkMessage(message) => {
                if let ProtocolMessage::CastReq(cast_req) = message {
                    self.handle_cast_request(cast_req, storage, bulletin_board)
                } else {
                    Err(format!(
                        "Unexpected message type in casting actor: {:?}",
                        message
                    ))
                }
            }
        }
    }

    fn handle_cast_request<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        cast_req: CastReqMsg,
        storage: &mut S,
        bulletin_board: &mut B,
    ) -> Result<CastingOutput, String> {
        // Perform all 6 validation checks
        self.perform_cast_request_checks(&cast_req, storage, bulletin_board)?;

        // Store the cast request and ballot tracker for later use
        let ballot_tracker = cast_req.data.ballot_tracker.clone();
        self.ballot_sub_tracker = Some(ballot_tracker.clone());
        self.cast_request = Some(cast_req.clone());

        // Get the authorization message that was validated during checks
        let auth_msg = storage
            .get_voter_authorization(&cast_req.data.voter_pseudonym)?
            .ok_or_else(|| "Voter authorization not found after validation".to_string())?;

        // Get the submitted ballot
        let ballot = storage
            .get_ballot_by_tracker(&ballot_tracker)?
            .ok_or_else(|| "Ballot not found after validation".to_string())?;

        // Publish the voter authorization bulletin
        self.publish_voter_authorization(auth_msg, bulletin_board)?;

        // Publish the ballot cast bulletin
        let ballot_cast_tracker =
            self.publish_ballot_cast(ballot, cast_req.clone(), bulletin_board)?;

        // Mark the ballot as cast in storage
        storage.store_cast_ballot(&cast_req.data.voter_pseudonym, &ballot_tracker)?;

        // Create and send the confirmation message
        let conf_msg = self.create_confirmation_message(ballot_tracker, ballot_cast_tracker)?;

        self.state = CastingState::Complete;

        Ok(CastingOutput::SendMessage(ProtocolMessage::CastConf(
            conf_msg,
        )))
    }

    // =============================================================================
    // Validation Checks (from ballot-cast-spec.md)
    // =============================================================================

    fn perform_cast_request_checks<S: DBBStorage, B: BulletinBoard>(
        &self,
        cast_req: &CastReqMsg,
        storage: &S,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Check #1: signature is valid (moved first to avoid expensive operations on invalid signatures)
        self.check_signature_valid(cast_req)?;

        // Check #2: election_hash is correct
        self.check_election_hash(&cast_req.data.election_hash)?;

        // Check #3: voter_pseudonym and voter_public_key match current AuthVoterMsg
        self.check_voter_authorization(&cast_req.data, storage)?;

        // Check #4: ballot_tracker matches a BallotSubBulletin with matching fields
        self.check_ballot_tracker_valid(&cast_req.data, bulletin_board)?;

        // Check #5: no previously published BallotCastBulletin for this voter
        self.check_no_previous_cast(&cast_req.data.voter_pseudonym, storage)?;

        // Check #6: BallotSubBulletin is the most recent for this voter
        self.check_most_recent_submission(&cast_req.data, storage)?;

        Ok(())
    }

    /// Check #2: The election_hash matches the current election.
    fn check_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("Election hash mismatch".to_string());
        }
        Ok(())
    }

    /// Check #3: The voter_pseudonym and voter_public_key match a current AuthVoterMsg.
    fn check_voter_authorization<S: DBBStorage>(
        &self,
        cast_req_data: &crate::messages::CastReqMsgData,
        storage: &S,
    ) -> Result<crate::messages::AuthVoterMsg, String> {
        let auth_msg = storage
            .get_voter_authorization(&cast_req_data.voter_pseudonym)?
            .ok_or_else(|| "No authorization found for voter".to_string())?;

        // Verify the voter_verifying_key matches
        if auth_msg.data.voter_verifying_key != cast_req_data.voter_verifying_key {
            return Err("Voter verifying key does not match authorization".to_string());
        }

        Ok(auth_msg)
    }

    /// Check #4: The ballot_tracker matches a BallotSubBulletin and fields match.
    fn check_ballot_tracker_valid<B: BulletinBoard>(
        &self,
        cast_req_data: &crate::messages::CastReqMsgData,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Get the bulletin by its tracker (hash)
        let bulletin = bulletin_board
            .get_bulletin(&cast_req_data.ballot_tracker)?
            .ok_or("Ballot tracker does not match any submitted ballot")?;

        // Verify it's a ballot submission bulletin
        if let Bulletin::BallotSubmission(ballot_sub) = bulletin {
            // Verify fields match
            if ballot_sub.data.ballot.data.election_hash != cast_req_data.election_hash {
                return Err("Ballot election_hash does not match cast request".to_string());
            }
            if ballot_sub.data.ballot.data.voter_pseudonym != cast_req_data.voter_pseudonym {
                return Err("Ballot voter_pseudonym does not match cast request".to_string());
            }
            if ballot_sub.data.ballot.data.voter_verifying_key != cast_req_data.voter_verifying_key
            {
                return Err("Ballot voter_verifying_key does not match cast request".to_string());
            }
            Ok(())
        } else {
            Err("Tracker does not refer to a ballot submission".to_string())
        }
    }

    /// Check #5: No previously published BallotCastBulletin for this voter.
    fn check_no_previous_cast<S: DBBStorage>(
        &self,
        voter_pseudonym: &String,
        storage: &S,
    ) -> Result<(), String> {
        if storage.has_voter_cast(voter_pseudonym)? {
            return Err("Voter has already cast a ballot".to_string());
        }
        Ok(())
    }

    /// Check #6: The BallotSubBulletin is the most recent for this voter.
    fn check_most_recent_submission<S: DBBStorage>(
        &self,
        cast_req_data: &crate::messages::CastReqMsgData,
        storage: &S,
    ) -> Result<(), String> {
        let most_recent = storage
            .get_most_recent_submission(&cast_req_data.voter_pseudonym)?
            .ok_or_else(|| "No submission found for voter".to_string())?;

        if most_recent.0 != cast_req_data.ballot_tracker {
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
            &cast_req.data.voter_verifying_key,
        )
    }

    // =============================================================================
    // Bulletin Publishing
    // =============================================================================

    /// Publish the voter authorization bulletin to the bulletin board.
    fn publish_voter_authorization<B: BulletinBoard>(
        &self,
        auth_msg: crate::messages::AuthVoterMsg,
        bulletin_board: &mut B,
    ) -> Result<BallotTracker, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        let previous_hash = bulletin_board.get_last_bulletin_hash().unwrap_or_default();

        let bulletin_data = VoterAuthBulletinData {
            election_hash: self.election_hash,
            timestamp,
            authorization: auth_msg,
            previous_bb_msg_hash: previous_hash,
        };

        // Sign the bulletin data
        let serialized_data = bulletin_data.ser();
        let signature_bytes = crate::crypto::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = hex::encode(signature_bytes.to_bytes());

        let bulletin = Bulletin::VoterAuthorization(VoterAuthBulletin {
            data: bulletin_data,
            signature,
        });

        let tracker = bulletin_board.append_bulletin(bulletin)?;
        Ok(tracker)
    }

    /// Publish the ballot cast bulletin to the bulletin board.
    fn publish_ballot_cast<B: BulletinBoard>(
        &self,
        ballot: crate::messages::SignedBallotMsg,
        cast_intent: CastReqMsg,
        bulletin_board: &mut B,
    ) -> Result<BallotTracker, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        let previous_hash = bulletin_board.get_last_bulletin_hash().unwrap_or_default();

        let bulletin_data = BallotCastBulletinData {
            election_hash: self.election_hash,
            timestamp,
            ballot,
            cast_intent,
            previous_bb_msg_hash: previous_hash,
        };

        // Sign the bulletin data
        let serialized_data = bulletin_data.ser();
        let signature_bytes = crate::crypto::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = hex::encode(signature_bytes.to_bytes());

        let bulletin = Bulletin::BallotCast(BallotCastBulletin {
            data: bulletin_data,
            signature,
        });

        let tracker = bulletin_board.append_bulletin(bulletin)?;
        Ok(tracker)
    }

    /// Create the confirmation message to send back to the VA.
    fn create_confirmation_message(
        &self,
        ballot_sub_tracker: BallotTracker,
        ballot_cast_tracker: BallotTracker,
    ) -> Result<CastConfMsg, String> {
        let data = CastConfMsgData {
            election_hash: self.election_hash,
            ballot_sub_tracker,
            ballot_cast_tracker,
        };

        // Sign the confirmation message
        let serialized_data = data.ser();
        let signature_bytes = crate::crypto::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = crate::crypto::Signature::from_bytes(&signature_bytes.to_bytes());

        Ok(CastConfMsg { data, signature })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletins::{BallotSubBulletin, BallotSubBulletinData};
    use crate::crypto::{BallotCryptogram, Signature, VerifyingKey, generate_signature_keypair};
    use crate::elections::string_to_election_hash;
    use crate::messages::{AuthVoterMsg, AuthVoterMsgData, SignedBallotMsg, SignedBallotMsgData};
    use crate::participants::digital_ballot_box::{
        bulletin_board::InMemoryBulletinBoard, storage::InMemoryStorage,
    };

    // Helper to create a test ballot cryptogram
    fn create_test_ballot_cryptogram(ballot_style: u8) -> BallotCryptogram {
        // Create a test keypair and encrypt a placeholder message
        let keypair = crate::crypto::generate_encryption_keypair(b"test").unwrap();
        // Create dummy group elements (identity elements work for testing)
        use crypto::groups::ristretto255::RistrettoElement;
        use crypto::traits::groups::GroupElement;
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
        InMemoryStorage,
        InMemoryBulletinBoard,
        SigningKey,
        VerifyingKey,
        SigningKey,
        VerifyingKey,
    ) {
        let storage = InMemoryStorage::new();
        let bulletin_board = InMemoryBulletinBoard::new();
        let (dbb_signing_key, dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, eas_verifying_key) = generate_signature_keypair();

        (
            storage,
            bulletin_board,
            dbb_signing_key,
            dbb_verifying_key,
            eas_signing_key,
            eas_verifying_key,
        )
    }

    #[test]
    fn test_successful_cast() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create and store a submitted ballot
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        // Publish ballot submission bulletin
        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Store the ballot in storage
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot.clone())
            .unwrap();

        // Create cast request
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        // Process the cast request
        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CastingOutput::SendMessage(ProtocolMessage::CastConf(conf)) => {
                assert_eq!(conf.data.election_hash, election_hash);
                assert_eq!(conf.data.ballot_sub_tracker, tracker);
            }
            _ => panic!("Expected CastConf message"),
        }

        // Verify voter is marked as cast
        assert!(storage.has_voter_cast(&"voter123".to_string()).unwrap());
    }

    #[test]
    fn test_invalid_election_hash() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            _eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");
        let wrong_election_hash = string_to_election_hash("wrong_election");

        // Create cast request with wrong election hash
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash: wrong_election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: "tracker_123".to_string(),
        };
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        // Process the cast request
        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Election hash mismatch"));
    }

    #[test]
    fn test_already_cast() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create and submit a ballot first
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Store the ballot in storage
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Mark voter as already cast
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker)
            .unwrap();

        // Create cast request
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&cast_req_data.ser(), &voter_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        // Process the cast request
        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already cast"));
    }

    // ===== Malformed Signature Tests =====

    #[test]
    fn test_invalid_signature_wrong_key() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create a ballot and publish bulletin
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &_voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Create cast request data and sign with WRONG key
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let (wrong_signing_key, _wrong_verifying_key) = generate_signature_keypair();
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&cast_req_data.ser(), &wrong_signing_key);
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_invalid_signature_corrupted_bytes() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create a ballot and publish bulletin
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Create cast request data with CORRUPTED signature
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&cast_req_data.ser(), &voter_signing_key);

        // Corrupt the signature bytes
        let mut corrupted_bytes = cast_req_signature_bytes.to_bytes();
        corrupted_bytes[0] ^= 0xFF;
        corrupted_bytes[15] ^= 0xFF;
        corrupted_bytes[32] ^= 0xFF;

        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&corrupted_bytes),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_invalid_signature_wrong_data() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create a ballot and publish bulletin
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Sign DIFFERENT data than what we're sending
        let different_cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "different_voter".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req_signature_bytes =
            crate::crypto::sign_data(&different_cast_req_data.ser(), &voter_signing_key);

        // But send the original data with mismatched signature
        let actual_cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req = CastReqMsg {
            data: actual_cast_req_data,
            signature: Signature::from_bytes(&cast_req_signature_bytes.to_bytes()),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_invalid_signature_all_zeros() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create a ballot and publish bulletin
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Use all-zeros signature
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_invalid_signature_all_ones() {
        let (
            mut storage,
            mut bulletin_board,
            dbb_signing_key,
            _dbb_verifying_key,
            eas_signing_key,
            _eas_verifying_key,
        ) = setup_test_environment();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        // Set up voter authorization
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes = crate::crypto::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Create a ballot and publish bulletin
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::crypto::sign_data(&ballot_data.ser(), &voter_signing_key);
        let ballot = SignedBallotMsg {
            data: ballot_data,
            signature: Signature::from_bytes(&ballot_signature_bytes.to_bytes()),
        };

        let ballot_sub_bulletin_data = BallotSubBulletinData {
            election_hash,
            timestamp: 1000,
            ballot: ballot.clone(),
            previous_bb_msg_hash: bulletin_board.get_last_bulletin_hash().unwrap_or_default(),
        };
        let ballot_sub_signature_bytes =
            crate::crypto::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();

        // Use all-ones signature
        let cast_req_data = crate::messages::CastReqMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_tracker: tracker.clone(),
        };
        let cast_req = CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&[0xFFu8; 64]),
        };

        let mut actor = CastingActor::new(election_hash, dbb_signing_key);
        let result = actor.process_input(
            CastingInput::NetworkMessage(ProtocolMessage::CastReq(cast_req)),
            &mut storage,
            &mut bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }
}
