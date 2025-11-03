// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Ballot Checking Sub-Actor for the Digital Ballot Box.
//!
//! This actor handles the ballot checking protocol where the DBB forwards
//! messages between a Ballot Check Application (BCA) and a Voting Application (VA).
//!
//! The DBB acts as an intermediary, validating messages from both parties before
//! forwarding them. This prevents malicious requests from reaching the VA and
//! ensures only valid randomizers are forwarded to the BCA.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::cryptography::{SigningKey, verify_signature};
use crate::elections::{BallotTracker, ElectionHash};
use crate::messages::{
    CheckReqMsg, FwdCheckReqMsg, FwdCheckReqMsgData, FwdRandomizerMsg, FwdRandomizerMsgData,
    ProtocolMessage, RandomizerMsg,
};
use crate::participants::digital_ballot_box::{bulletin_board::BulletinBoard, storage::DBBStorage};
use cryptography::utils::serialization::VSerializable;

// --- I/O Types ---

#[derive(Debug, Clone)]
pub enum CheckingInput {
    NetworkMessage {
        connection_id: u64,
        message: ProtocolMessage,
    },
    VAConnectionProvided(u64),
}

#[derive(Debug, Clone)]
pub enum CheckingOutput {
    SendMessage {
        connection_id: u64,
        message: ProtocolMessage,
    },
    RequestVAConnection(BallotTracker),
    Success,
    Failure(String),
}

// --- State ---

#[derive(Debug, Clone, PartialEq)]
pub enum CheckingState {
    AwaitingCheckRequest,
    AwaitingVAConnection,
    AwaitingRandomizers,
    Complete,
}

// --- Actor ---

#[derive(Clone, Debug)]
pub struct CheckingActor {
    bca_connection_id: u64,
    va_connection_id: Option<u64>,
    state: CheckingState,
    election_hash: ElectionHash,
    dbb_signing_key: SigningKey,
    // Store the check request for later validation
    check_request: Option<CheckReqMsg>,
}

impl CheckingActor {
    pub fn new(
        bca_connection_id: u64,
        election_hash: ElectionHash,
        dbb_signing_key: SigningKey,
    ) -> Self {
        Self {
            bca_connection_id,
            va_connection_id: None,
            state: CheckingState::AwaitingCheckRequest,
            election_hash,
            dbb_signing_key,
            check_request: None,
        }
    }

    pub fn get_state(&self) -> CheckingState {
        self.state.clone()
    }

    pub fn process_input<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        input: CheckingInput,
        storage: &S,
        bulletin_board: &B,
    ) -> Result<CheckingOutput, String> {
        match input {
            CheckingInput::NetworkMessage {
                connection_id: _,
                message,
            } => self.handle_network_message(message, storage, bulletin_board),
            CheckingInput::VAConnectionProvided(va_conn_id) => {
                self.handle_va_connection_provided(va_conn_id)
            }
        }
    }

    // =============================================================================
    // Message Handling
    // =============================================================================

    fn handle_network_message<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        message: ProtocolMessage,
        storage: &S,
        bulletin_board: &B,
    ) -> Result<CheckingOutput, String> {
        match message {
            ProtocolMessage::CheckReq(check_req) => {
                self.handle_check_request(check_req, bulletin_board)
            }
            ProtocolMessage::Randomizer(randomizer) => {
                self.handle_randomizer_message(randomizer, storage, bulletin_board)
            }
            _ => Err(format!(
                "Unexpected message type in checking actor: {:?}",
                message
            )),
        }
    }

    fn handle_check_request<B: BulletinBoard>(
        &mut self,
        check_req: CheckReqMsg,
        bulletin_board: &B,
    ) -> Result<CheckingOutput, String> {
        if self.state != CheckingState::AwaitingCheckRequest {
            return Err("Not awaiting check request".to_string());
        }

        // Perform all 4 validation checks for CheckReqMsg
        self.perform_check_request_checks(&check_req, bulletin_board)?;

        // Store the check request for later use
        self.check_request = Some(check_req.clone());

        // Request the VA connection ID from the host
        self.state = CheckingState::AwaitingVAConnection;
        Ok(CheckingOutput::RequestVAConnection(
            check_req.data.tracker.clone(),
        ))
    }

    fn handle_va_connection_provided(&mut self, va_conn_id: u64) -> Result<CheckingOutput, String> {
        if self.state != CheckingState::AwaitingVAConnection {
            return Err("Not awaiting VA connection".to_string());
        }

        // Store the VA connection ID
        self.va_connection_id = Some(va_conn_id);

        // Create and send the forwarded check request to the VA
        let check_req = self
            .check_request
            .as_ref()
            .ok_or("Check request not found")?;

        let fwd_check_req = self.create_forwarded_check_request(check_req.clone())?;

        self.state = CheckingState::AwaitingRandomizers;
        Ok(CheckingOutput::SendMessage {
            connection_id: va_conn_id,
            message: ProtocolMessage::FwdCheckReq(fwd_check_req),
        })
    }

    fn handle_randomizer_message<S: DBBStorage, B: BulletinBoard>(
        &mut self,
        randomizer: RandomizerMsg,
        _storage: &S,
        bulletin_board: &B,
    ) -> Result<CheckingOutput, String> {
        if self.state != CheckingState::AwaitingRandomizers {
            return Err("Not awaiting randomizers".to_string());
        }

        // Perform all 6 validation checks for RandomizerMsg
        self.perform_randomizer_checks(&randomizer, bulletin_board)?;

        // Create and send the forwarded randomizer message to the BCA
        let fwd_randomizer = self.create_forwarded_randomizer(randomizer)?;

        self.state = CheckingState::Complete;
        Ok(CheckingOutput::SendMessage {
            connection_id: self.bca_connection_id,
            message: ProtocolMessage::FwdRandomizer(fwd_randomizer),
        })
    }

    // =============================================================================
    // Validation Checks for CheckReqMsg
    // =============================================================================

    fn perform_check_request_checks<B: BulletinBoard>(
        &self,
        check_req: &CheckReqMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Check #1: signature is valid (moved first to avoid expensive operations on invalid signatures)
        self.check_check_request_signature(check_req)?;

        // Check #2: election_hash is correct
        self.check_election_hash(&check_req.data.election_hash)?;

        // Check #3: tracker corresponds to a valid BallotSubBulletin
        self.check_tracker_valid(&check_req.data.tracker, bulletin_board)?;

        // Check #4: public keys are valid (implicit in type system - ElectionKey and VerifyingKey)
        // The Rust type system ensures these are valid keys

        Ok(())
    }

    /// Check #2: The election_hash matches the current election.
    fn check_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("Election hash mismatch".to_string());
        }
        Ok(())
    }

    /// Check #3: The tracker corresponds to a valid BallotSubBulletin.
    fn check_tracker_valid<B: BulletinBoard>(
        &self,
        tracker: &BallotTracker,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Try to get the bulletin by its tracker (hash)
        let bulletin = bulletin_board
            .get_bulletin(tracker)?
            .ok_or("Tracker does not correspond to a valid ballot submission")?;

        // Verify it's a ballot submission bulletin
        if !matches!(bulletin, crate::bulletins::Bulletin::BallotSubmission(_)) {
            return Err("Tracker does not refer to a ballot submission".to_string());
        }

        Ok(())
    }

    /// Check #1: The signature is valid.
    fn check_check_request_signature(&self, check_req: &CheckReqMsg) -> Result<(), String> {
        let serialized_data = check_req.data.ser();
        verify_signature(
            &serialized_data,
            &check_req.signature,
            &check_req.data.public_sign_key,
        )
    }

    // =============================================================================
    // Validation Checks for RandomizerMsg
    // =============================================================================

    fn perform_randomizer_checks<B: BulletinBoard>(
        &self,
        randomizer: &RandomizerMsg,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Check #1: signature is valid (moved first to avoid expensive operations on invalid signatures)
        self.check_randomizer_signature(randomizer)?;

        // Check #2: election_hash is correct
        self.check_election_hash(&randomizer.data.election_hash)?;

        // Check #3: message is a valid CheckReqMsg
        self.check_randomizer_message_valid(&randomizer.data.message)?;

        // Check #4: ciphertexts are valid Naor-Yung ciphertexts (implicit in type system)
        // The RandomizersCryptogram type ensures this

        // Check #5: encrypted_randomizers length matches ballot style
        self.check_randomizers_length(&randomizer.data, bulletin_board)?;

        // Check #6: public_key matches the ballot submission
        self.check_public_key_matches(&randomizer.data, bulletin_board)?;

        Ok(())
    }

    /// Check #3: The embedded message is a valid CheckReqMsg.
    fn check_randomizer_message_valid(
        &self,
        embedded_check_req: &CheckReqMsg,
    ) -> Result<(), String> {
        // Verify it matches the original check request
        let original = self
            .check_request
            .as_ref()
            .ok_or("No check request stored")?;

        if embedded_check_req.data.tracker != original.data.tracker {
            return Err("Randomizer message does not match original check request".to_string());
        }

        if embedded_check_req.data.election_hash != original.data.election_hash {
            return Err("Randomizer message election hash does not match original".to_string());
        }

        Ok(())
    }

    /// Check #5: The encrypted_randomizers length matches the ballot style.
    fn check_randomizers_length<B: BulletinBoard>(
        &self,
        randomizer_data: &crate::messages::RandomizerMsgData,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Get the ballot submission bulletin by tracker
        let bulletin = bulletin_board
            .get_bulletin(&randomizer_data.message.data.tracker)?
            .ok_or("Could not find ballot submission for tracker")?;

        if let crate::bulletins::Bulletin::BallotSubmission(ballot_sub) = bulletin {
            // Get the ballot style from the ballot
            let ballot_style = ballot_sub.data.ballot.data.ballot_style;

            // Verify the ballot style matches between the submission and randomizers
            if randomizer_data.encrypted_randomizers.ballot_style != ballot_style {
                return Err(format!(
                    "Randomizers ballot style {} does not match ballot submission style {}",
                    randomizer_data.encrypted_randomizers.ballot_style, ballot_style
                ));
            }

            Ok(())
        } else {
            Err("Tracker does not refer to a ballot submission".to_string())
        }
    }

    /// Check #6: The public_key matches the ballot submission.
    fn check_public_key_matches<B: BulletinBoard>(
        &self,
        randomizer_data: &crate::messages::RandomizerMsgData,
        bulletin_board: &B,
    ) -> Result<(), String> {
        // Get the ballot submission bulletin by tracker
        let bulletin = bulletin_board
            .get_bulletin(&randomizer_data.message.data.tracker)?
            .ok_or("Could not find ballot submission for tracker")?;

        if let crate::bulletins::Bulletin::BallotSubmission(ballot_sub) = bulletin {
            // Verify the public key matches
            if ballot_sub.data.ballot.data.voter_verifying_key != randomizer_data.public_key {
                return Err("Randomizer public key does not match ballot submission".to_string());
            }
            Ok(())
        } else {
            Err("Tracker does not refer to a ballot submission".to_string())
        }
    }

    /// Check #1: The signature is valid.
    fn check_randomizer_signature(&self, randomizer: &RandomizerMsg) -> Result<(), String> {
        let serialized_data = randomizer.data.ser();
        verify_signature(
            &serialized_data,
            &randomizer.signature,
            &randomizer.data.public_key,
        )
    }

    // =============================================================================
    // Message Creation
    // =============================================================================

    /// Create a forwarded check request message for the VA.
    fn create_forwarded_check_request(
        &self,
        check_req: CheckReqMsg,
    ) -> Result<FwdCheckReqMsg, String> {
        let data = FwdCheckReqMsgData {
            election_hash: self.election_hash,
            message: check_req,
        };

        // Sign the forwarded message
        let serialized_data = data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = crate::cryptography::Signature::from_bytes(&signature_bytes.to_bytes());

        Ok(FwdCheckReqMsg { data, signature })
    }

    /// Create a forwarded randomizer message for the BCA.
    fn create_forwarded_randomizer(
        &self,
        randomizer: RandomizerMsg,
    ) -> Result<FwdRandomizerMsg, String> {
        let data = FwdRandomizerMsgData {
            election_hash: self.election_hash,
            message: randomizer,
        };

        // Sign the forwarded message
        let serialized_data = data.ser();
        let signature_bytes =
            crate::cryptography::sign_data(&serialized_data, &self.dbb_signing_key);
        let signature = crate::cryptography::Signature::from_bytes(&signature_bytes.to_bytes());

        Ok(FwdRandomizerMsg { data, signature })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletins::{BallotSubBulletin, BallotSubBulletinData, Bulletin};
    use crate::cryptography::{
        BallotCryptogram, Signature, VerifyingKey, generate_encryption_keypair,
        generate_signature_keypair,
    };
    use crate::elections::{BallotStyle, string_to_election_hash};
    use crate::messages::{
        AuthVoterMsg, AuthVoterMsgData, CheckReqMsgData, RandomizerMsgData, SignedBallotMsg,
        SignedBallotMsgData,
    };
    use crate::participants::digital_ballot_box::{
        bulletin_board::InMemoryBulletinBoard, storage::InMemoryStorage,
    };

    // Helper to create a test ballot cryptogram
    fn create_test_ballot_cryptogram(ballot_style: BallotStyle) -> BallotCryptogram {
        let keypair = generate_encryption_keypair(b"test").unwrap();
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

    // Helper to create test randomizers cryptogram
    fn create_test_randomizers_cryptogram(
        ballot_style: BallotStyle,
    ) -> crate::cryptography::RandomizersCryptogram {
        let keypair = generate_encryption_keypair(b"test").unwrap();
        use cryptography::groups::ristretto255::RistrettoElement;
        use cryptography::traits::groups::GroupElement;
        let identity = RistrettoElement::one();
        let message = [identity, identity]; // 2 elements for randomizers
        let ciphertext = keypair
            .encrypt(&message, b"test_context")
            .expect("Failed to encrypt");
        crate::cryptography::RandomizersCryptogram {
            ballot_style,
            ciphertext,
        }
    }

    fn create_test_actor() -> (CheckingActor, SigningKey, VerifyingKey) {
        let (dbb_signing_key, dbb_verifying_key) = generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let actor = CheckingActor::new(1, election_hash, dbb_signing_key.clone());

        (actor, dbb_signing_key, dbb_verifying_key)
    }

    #[test]
    fn test_successful_check_flow() {
        let (mut actor, dbb_signing_key, _dbb_verifying_key) = create_test_actor();
        let storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Create a ballot submission bulletin
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Create a check request from BCA
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        // Process the check request
        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req.clone()),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CheckingOutput::RequestVAConnection(t) => {
                assert_eq!(t, tracker);
            }
            _ => panic!("Expected RequestVAConnection"),
        }

        // Provide VA connection
        let result = actor.process_input(
            CheckingInput::VAConnectionProvided(2),
            &storage,
            &bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CheckingOutput::SendMessage {
                connection_id,
                message,
            } => {
                assert_eq!(connection_id, 2);
                assert!(matches!(message, ProtocolMessage::FwdCheckReq(_)));
            }
            _ => panic!("Expected SendMessage with FwdCheckReq"),
        }

        // Create and send randomizer message
        let randomizer_data = RandomizerMsgData {
            election_hash,
            message: check_req.clone(),
            encrypted_randomizers: create_test_randomizers_cryptogram(1),
            public_key: voter_verifying_key,
        };
        let randomizer_signature_bytes =
            crate::cryptography::sign_data(&randomizer_data.ser(), &voter_signing_key);
        let randomizer = RandomizerMsg {
            data: randomizer_data,
            signature: Signature::from_bytes(&randomizer_signature_bytes.to_bytes()),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 2,
                message: ProtocolMessage::Randomizer(randomizer),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_ok());
        match result.unwrap() {
            CheckingOutput::SendMessage {
                connection_id,
                message,
            } => {
                assert_eq!(connection_id, 1); // BCA connection
                assert!(matches!(message, ProtocolMessage::FwdRandomizer(_)));
            }
            _ => panic!("Expected SendMessage with FwdRandomizer"),
        }
    }

    #[test]
    fn test_invalid_election_hash() {
        let (mut actor, _, _) = create_test_actor();
        let storage = InMemoryStorage::new();
        let bulletin_board = InMemoryBulletinBoard::new();
        let wrong_election_hash = string_to_election_hash("wrong_election");

        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash: wrong_election_hash,
            tracker: "tracker_123".to_string(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Election hash mismatch"));
    }

    #[test]
    fn test_invalid_tracker() {
        let (mut actor, _, _) = create_test_actor();
        let storage = InMemoryStorage::new();
        let bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: "invalid_tracker".to_string(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("does not correspond to a valid ballot submission")
        );
    }

    // ===== Malformed Signature Tests =====

    #[test]
    fn test_check_req_invalid_signature_wrong_key() {
        let (mut actor, _, _) = create_test_actor();
        let storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Create a valid ballot submission first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &_voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Create check request but sign with WRONG key
        let (_bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let (wrong_signing_key, _wrong_verifying_key) = generate_signature_keypair();
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &wrong_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_check_req_invalid_signature_corrupted_bytes() {
        let (mut actor, _, _) = create_test_actor();
        let storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Create a valid ballot submission first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &_voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Create check request with CORRUPTED signature
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);

        // Corrupt the signature bytes
        let mut corrupted_bytes = check_req_signature_bytes.to_bytes();
        corrupted_bytes[5] ^= 0xFF;
        corrupted_bytes[20] ^= 0xFF;
        corrupted_bytes[50] ^= 0xFF;

        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&corrupted_bytes),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_randomizer_invalid_signature_wrong_key() {
        let (mut actor, _, _) = create_test_actor();
        let mut storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Set up complete flow first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, _eas_verifying_key) = generate_signature_keypair();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        // Authorize voter
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes =
            crate::cryptography::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Submit ballot
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &_voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Cast ballot
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker)
            .unwrap();

        // Send check request
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        actor
            .process_input(
                CheckingInput::NetworkMessage {
                    connection_id: 1,
                    message: ProtocolMessage::CheckReq(check_req.clone()),
                },
                &storage,
                &bulletin_board,
            )
            .unwrap();
        actor
            .process_input(
                CheckingInput::VAConnectionProvided(2),
                &storage,
                &bulletin_board,
            )
            .unwrap();

        // Create randomizer message with WRONG signing key
        let randomizer_data = RandomizerMsgData {
            election_hash,
            message: check_req.clone(),
            encrypted_randomizers: create_test_randomizers_cryptogram(1),
            public_key: voter_verifying_key,
        };
        let (wrong_signing_key, _wrong_verifying_key) = generate_signature_keypair();
        let randomizer_signature_bytes =
            crate::cryptography::sign_data(&randomizer_data.ser(), &wrong_signing_key);
        let randomizer = RandomizerMsg {
            data: randomizer_data,
            signature: Signature::from_bytes(&randomizer_signature_bytes.to_bytes()),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 2,
                message: ProtocolMessage::Randomizer(randomizer),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_randomizer_invalid_signature_corrupted_bytes() {
        let (mut actor, _, _) = create_test_actor();
        let mut storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Set up complete flow first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, _eas_verifying_key) = generate_signature_keypair();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        // Authorize voter
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes =
            crate::cryptography::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Submit ballot
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Cast ballot
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker)
            .unwrap();

        // Send check request
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        actor
            .process_input(
                CheckingInput::NetworkMessage {
                    connection_id: 1,
                    message: ProtocolMessage::CheckReq(check_req.clone()),
                },
                &storage,
                &bulletin_board,
            )
            .unwrap();
        actor
            .process_input(
                CheckingInput::VAConnectionProvided(2),
                &storage,
                &bulletin_board,
            )
            .unwrap();

        // Create randomizer message with CORRUPTED signature
        let randomizer_data = RandomizerMsgData {
            election_hash,
            message: check_req.clone(),
            encrypted_randomizers: create_test_randomizers_cryptogram(1),
            public_key: voter_verifying_key,
        };
        let randomizer_signature_bytes =
            crate::cryptography::sign_data(&randomizer_data.ser(), &voter_signing_key);

        // Corrupt the signature bytes
        let mut corrupted_bytes = randomizer_signature_bytes.to_bytes();
        corrupted_bytes[3] ^= 0xFF;
        corrupted_bytes[25] ^= 0xFF;
        corrupted_bytes[45] ^= 0xFF;

        let randomizer = RandomizerMsg {
            data: randomizer_data,
            signature: Signature::from_bytes(&corrupted_bytes),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 2,
                message: ProtocolMessage::Randomizer(randomizer),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_check_req_invalid_signature_all_zeros() {
        let (mut actor, _, _) = create_test_actor();
        let storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Create a valid ballot submission first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &_voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Create check request with all-zeros signature
        let (_bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 1,
                message: ProtocolMessage::CheckReq(check_req),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_randomizer_invalid_signature_all_ones() {
        let (mut actor, _, _) = create_test_actor();
        let mut storage = InMemoryStorage::new();
        let mut bulletin_board = InMemoryBulletinBoard::new();
        let election_hash = string_to_election_hash("test_election");

        // Set up complete flow first
        let (dbb_signing_key, _dbb_verifying_key) = generate_signature_keypair();
        let (eas_signing_key, _eas_verifying_key) = generate_signature_keypair();
        let (_voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        // Authorize voter
        let auth_data = AuthVoterMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
        };
        let auth_signature_bytes =
            crate::cryptography::sign_data(&auth_data.ser(), &eas_signing_key);
        let auth_msg = AuthVoterMsg {
            data: auth_data,
            signature: Signature::from_bytes(&auth_signature_bytes.to_bytes()),
        };
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg)
            .unwrap();

        // Submit ballot
        let ballot_data = SignedBallotMsgData {
            election_hash,
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key,
            ballot_style: 1,
            ballot_cryptogram: create_test_ballot_cryptogram(1),
        };
        let ballot_signature_bytes =
            crate::cryptography::sign_data(&ballot_data.ser(), &_voter_signing_key);
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
            crate::cryptography::sign_data(&ballot_sub_bulletin_data.ser(), &dbb_signing_key);
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_bulletin_data,
            signature: hex::encode(ballot_sub_signature_bytes.to_bytes()),
        };
        let tracker = bulletin_board
            .append_bulletin(Bulletin::BallotSubmission(ballot_sub_bulletin))
            .unwrap();

        // Cast ballot
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot)
            .unwrap();
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker)
            .unwrap();

        // Send check request
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();
        let bca_enc_keypair =
            generate_encryption_keypair(b"bca_context").expect("Failed to generate keypair");
        let check_req_data = CheckReqMsgData {
            election_hash,
            tracker: tracker.clone(),
            public_enc_key: bca_enc_keypair.pkey,
            public_sign_key: bca_verifying_key,
        };
        let check_req_signature_bytes =
            crate::cryptography::sign_data(&check_req_data.ser(), &bca_signing_key);
        let check_req = CheckReqMsg {
            data: check_req_data,
            signature: Signature::from_bytes(&check_req_signature_bytes.to_bytes()),
        };

        actor
            .process_input(
                CheckingInput::NetworkMessage {
                    connection_id: 1,
                    message: ProtocolMessage::CheckReq(check_req.clone()),
                },
                &storage,
                &bulletin_board,
            )
            .unwrap();
        actor
            .process_input(
                CheckingInput::VAConnectionProvided(2),
                &storage,
                &bulletin_board,
            )
            .unwrap();

        // Create randomizer message with all-ones signature
        let randomizer_data = RandomizerMsgData {
            election_hash,
            message: check_req.clone(),
            encrypted_randomizers: create_test_randomizers_cryptogram(1),
            public_key: voter_verifying_key,
        };
        let randomizer = RandomizerMsg {
            data: randomizer_data,
            signature: Signature::from_bytes(&[0xFFu8; 64]),
        };

        let result = actor.process_input(
            CheckingInput::NetworkMessage {
                connection_id: 2,
                message: ProtocolMessage::Randomizer(randomizer),
            },
            &storage,
            &bulletin_board,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }
}
