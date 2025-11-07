//! Implementation of the `CastingActor` for the Ballot Casting subprotocol.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::crypto::{Signature, SigningKey, VerifyingKey};
use crate::elections::{BallotTracker, ElectionHash, VoterPseudonym};
use crate::messages::{CastConfMsg, CastReqMsg, CastReqMsgData, ProtocolMessage};
use crypto::utils::serialization::VSerializable;

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `CastingActor` can process.
#[derive(Debug, Clone)]
pub enum CastingInput {
    /// Starts the casting protocol with the ballot submission tracker.
    Start(String),
    /// A network message intended for this subprotocol.
    NetworkMessage(ProtocolMessage),
}

/// The set of outputs that the `CastingActor` can produce.
#[derive(Debug, Clone)]
pub enum CastingOutput {
    /// A message that needs to be sent over the network.
    SendMessage(ProtocolMessage),
    /// The protocol has completed successfully.
    Success(BallotCastingSuccess),
    /// The protocol has failed.
    Failure(String),
}

/// Contains the data resulting from a successful ballot casting.
#[derive(Debug, Clone)]
pub struct BallotCastingSuccess {
    pub cast_tracker: BallotTracker,
}

// --- II. Actor Implementation ---

/// The sub-states for the Ballot Casting protocol.
#[derive(Clone)]
enum SubState {
    ReadyToStart,
    AwaitingConfirmation,
}

/// The actor for the Ballot Casting subprotocol.
pub struct CastingActor {
    state: SubState,
    // --- Injected State from TopLevelActor ---
    election_hash: ElectionHash,
    dbb_verifying_key: VerifyingKey,
    voter_pseudonym: VoterPseudonym,
    voter_signing_key: SigningKey,
    voter_verifying_key: VerifyingKey,
    // --- State generated and used only within this protocol ---
    sent_cast_request: Option<CastReqMsg>,
}

impl CastingActor {
    /// Creates a new `CastingActor`.
    pub fn new(
        election_hash: ElectionHash,
        dbb_verifying_key: VerifyingKey,
        voter_pseudonym: VoterPseudonym,
        voter_signing_key: SigningKey,
        voter_verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            state: SubState::ReadyToStart,
            election_hash,
            dbb_verifying_key,
            voter_pseudonym,
            voter_signing_key,
            voter_verifying_key,
            sent_cast_request: None,
        }
    }

    /// Processes an input for the Ballot Casting subprotocol.
    pub fn process_input(&mut self, input: CastingInput) -> CastingOutput {
        match (self.state.clone(), input) {
            (SubState::ReadyToStart, CastingInput::Start(tracker)) => {
                let data = CastReqMsgData {
                    election_hash: self.election_hash,
                    voter_pseudonym: self.voter_pseudonym.clone(),
                    voter_verifying_key: self.voter_verifying_key,
                    ballot_tracker: tracker,
                };

                // Create cryptographic signature over the message data using VSerializable
                let serialized = data.ser();
                let signature = crate::crypto::sign_data(&serialized, &self.voter_signing_key);

                let cast_req_msg = CastReqMsg { data, signature };

                self.sent_cast_request = Some(cast_req_msg.clone());
                self.state = SubState::AwaitingConfirmation;
                CastingOutput::SendMessage(ProtocolMessage::CastReq(cast_req_msg))
            }

            (
                SubState::AwaitingConfirmation,
                CastingInput::NetworkMessage(ProtocolMessage::CastConf(conf_msg)),
            ) => {
                // Perform Cast Confirmation Checks from the spec
                if let Err(reason) = self.perform_cast_confirmation_checks(&conf_msg) {
                    return CastingOutput::Failure(reason);
                }

                CastingOutput::Success(BallotCastingSuccess {
                    cast_tracker: conf_msg.data.ballot_cast_tracker.clone(),
                })
            }

            _ => CastingOutput::Failure("Invalid input for current state".to_string()),
        }
    }

    // --- Cast Confirmation Checks (Phase 2) ---

    /// Performs all checks on the CastConfMsg received from the DBB
    /// These correspond to the error conditions shown in the VA process diagram:
    /// - Timeout Exceeded Error (handled at higher level)
    /// - Invalid Signature Error
    /// - Incorrect BallotID Error
    /// - Invalid Message Locator Error
    fn perform_cast_confirmation_checks(&self, conf_msg: &CastConfMsg) -> Result<(), String> {
        self.check_conf_election_hash(&conf_msg.data.election_hash)?;
        self.check_conf_ballot_sub_tracker(&conf_msg.data.ballot_sub_tracker)?;
        self.check_conf_message_locator(&conf_msg.data.ballot_cast_tracker)?;
        self.check_conf_signature(&conf_msg.data, &conf_msg.signature)?;

        Ok(())
    }

    /// Check: The election_hash is for the current election
    fn check_conf_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("CastConfMsg has incorrect election hash".to_string());
        }
        if election_hash.is_empty() {
            return Err("CastConfMsg election_hash cannot be empty".to_string());
        }
        Ok(())
    }

    /// Check: The ballot_sub_tracker matches the tracker we sent
    /// This corresponds to the "Incorrect BallotID Error" in the spec diagram
    fn check_conf_ballot_sub_tracker(
        &self,
        ballot_sub_tracker: &BallotTracker,
    ) -> Result<(), String> {
        if let Some(ref sent_request) = self.sent_cast_request {
            if sent_request.data.ballot_tracker != *ballot_sub_tracker {
                return Err(
                    "CastConfMsg has incorrect ballot_sub_tracker - does not match sent request"
                        .to_string(),
                );
            }
        } else {
            return Err("No cast request was sent to validate confirmation against".to_string());
        }

        if ballot_sub_tracker.is_empty() {
            return Err("CastConfMsg ballot_sub_tracker cannot be empty".to_string());
        }

        Ok(())
    }

    /// Check: The ballot_cast_tracker is a valid message locator
    /// This corresponds to the "Invalid Message Locator Error" in the spec diagram
    fn check_conf_message_locator(
        &self,
        ballot_cast_tracker: &BallotTracker,
    ) -> Result<(), String> {
        if ballot_cast_tracker.is_empty() {
            return Err("CastConfMsg ballot_cast_tracker cannot be empty".to_string());
        }

        // Basic format validation for message locator
        if ballot_cast_tracker.len() < 8 {
            return Err("CastConfMsg ballot_cast_tracker appears to be too short".to_string());
        }

        // TODO: Additional validation of message locator format if required
        // Could verify it's a proper hash format, check length constraints, etc.
        // The format would depend on the PBB implementation
        Ok(())
    }

    /// Check: The signature is a valid signature from the DBB
    /// This corresponds to the "Invalid Signature Error" in the spec diagram
    fn check_conf_signature(
        &self,
        data: &crate::messages::CastConfMsgData,
        signature: &Signature,
    ) -> Result<(), String> {
        let serialized = data.ser();
        crate::crypto::verify_signature(&serialized, signature, &self.dbb_verifying_key)
            .map_err(|_| "CastConfMsg has invalid signature from DBB".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signature_keypair;

    #[test]
    fn test_casting_actor_creation() {
        let election_hash = "test_election_hash".to_string();
        let (_, dbb_verifying_key) = generate_signature_keypair();
        let voter_pseudonym = "voter123".to_string();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        let actor = CastingActor::new(
            crate::elections::string_to_election_hash(&election_hash),
            dbb_verifying_key,
            voter_pseudonym,
            voter_signing_key,
            voter_verifying_key,
        );

        // Verify initial state
        assert!(matches!(actor.state, SubState::ReadyToStart));
        assert!(actor.sent_cast_request.is_none());
    }

    #[test]
    fn test_cast_request_signature_creation() {
        let election_hash = "test_election_hash".to_string();
        let (_, dbb_verifying_key) = generate_signature_keypair();
        let voter_pseudonym = "voter123".to_string();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        let mut actor = CastingActor::new(
            crate::elections::string_to_election_hash(&election_hash),
            dbb_verifying_key,
            voter_pseudonym,
            voter_signing_key,
            voter_verifying_key,
        );

        let ballot_tracker = "ballot_tracker_123".to_string();

        // Process start input
        let output = actor.process_input(CastingInput::Start(ballot_tracker));

        // Should get a SendMessage output
        match output {
            CastingOutput::SendMessage(ProtocolMessage::CastReq(cast_req)) => {
                // Verify signature by re-creating the serialized data using VSerializable
                let serialized = cast_req.data.ser();
                let verification_result = crate::crypto::verify_signature(
                    &serialized,
                    &cast_req.signature,
                    &cast_req.data.voter_verifying_key,
                );
                assert!(verification_result.is_ok(), "Signature should be valid");
            }
            _ => panic!("Expected SendMessage output with CastReq"),
        }
    }

    #[test]
    fn test_message_serialization() {
        let election_hash = "test_election_hash".to_string();
        let (_, dbb_verifying_key) = generate_signature_keypair();
        let voter_pseudonym = "voter123".to_string();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        let _actor = CastingActor::new(
            crate::elections::string_to_election_hash(&election_hash),
            dbb_verifying_key,
            voter_pseudonym.clone(),
            voter_signing_key,
            voter_verifying_key,
        );

        let data = CastReqMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            voter_pseudonym: voter_pseudonym.clone(),
            voter_verifying_key,
            ballot_tracker: "test_tracker".to_string(),
        };

        // Serialize data using VSerializable
        let serialized = data.ser();

        // Should contain serialized data
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_vserializable_casting_messages() {
        // Test that VSerializable works correctly for casting message serialization
        let (_, verifying_key) = generate_signature_keypair();
        let election_hash = "test_election_2024".to_string();

        // Test CastReqMsgData serialization
        let cast_req_data = CastReqMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_tracker: "tracker_123".to_string(),
        };
        let serialized_cast_req = cast_req_data.ser();
        assert!(
            !serialized_cast_req.is_empty(),
            "CastReqMsgData serialization should not be empty"
        );

        // Test CastConfMsgData serialization
        let cast_conf_data = crate::messages::CastConfMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            ballot_sub_tracker: "sub_tracker_123".to_string(),
            ballot_cast_tracker: "cast_tracker_456".to_string(),
        };
        let serialized_cast_conf = cast_conf_data.ser();
        assert!(
            !serialized_cast_conf.is_empty(),
            "CastConfMsgData serialization should not be empty"
        );
    }

    #[test]
    fn test_casting_actor_signature_compatibility() {
        // Test that the casting actor can create and verify signatures using VSerializable
        let election_hash = "test_election_2024".to_string();
        let (_, dbb_verifying_key) = generate_signature_keypair();
        let voter_pseudonym = "voter_pseudonym".to_string();
        let (voter_signing_key, voter_verifying_key) = generate_signature_keypair();

        let mut casting_actor = CastingActor::new(
            crate::elections::string_to_election_hash(&election_hash),
            dbb_verifying_key,
            voter_pseudonym.clone(),
            voter_signing_key,
            voter_verifying_key,
        );

        let ballot_tracker = "test_tracker_456".to_string();

        // Test that we can create a CastReqMsg (this internally uses .ser() for signatures)
        let result = casting_actor.process_input(CastingInput::Start(ballot_tracker.clone()));

        match result {
            CastingOutput::SendMessage(ProtocolMessage::CastReq(cast_req_msg)) => {
                // Verify that the message was created successfully
                assert_eq!(
                    cast_req_msg.data.election_hash,
                    crate::elections::string_to_election_hash(&election_hash)
                );
                assert_eq!(cast_req_msg.data.voter_pseudonym, voter_pseudonym);
                assert_eq!(cast_req_msg.data.ballot_tracker, ballot_tracker);
                assert_eq!(
                    cast_req_msg.data.voter_verifying_key,
                    casting_actor.voter_verifying_key
                );

                // Verify that the signature can be verified using VSerializable
                let serialized = cast_req_msg.data.ser();
                let verification_result = crate::crypto::verify_signature(
                    &serialized,
                    &cast_req_msg.signature,
                    &cast_req_msg.data.voter_verifying_key,
                );
                assert!(
                    verification_result.is_ok(),
                    "Signature verification should succeed"
                );

                // Test that signature verification fails with wrong data
                let mut modified_data = cast_req_msg.data.clone();
                modified_data.ballot_tracker = "wrong_tracker".to_string();
                let wrong_serialized = modified_data.ser();
                let wrong_verification = crate::crypto::verify_signature(
                    &wrong_serialized,
                    &cast_req_msg.signature,
                    &cast_req_msg.data.voter_verifying_key,
                );
                assert!(
                    wrong_verification.is_err(),
                    "Signature verification should fail with wrong data"
                );
            }
            _ => panic!("Expected SendMessage with CastReq, got: {:?}", result),
        }
    }
}
