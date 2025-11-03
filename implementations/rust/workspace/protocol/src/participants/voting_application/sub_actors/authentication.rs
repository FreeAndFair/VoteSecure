// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Implementation of the `AuthenticationActor` for the Voter Authentication subprotocol.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::cryptography::{Signature, SigningKey, VerifyingKey};
use crate::elections::{BallotStyle, ElectionHash, VoterPseudonym};
use crate::messages::{
    AuthFinishMsg, AuthFinishMsgData, AuthReqMsg, ConfirmAuthorizationMsg, HandTokenMsg,
    ProtocolMessage,
};
use cryptography::utils::serialization::VSerializable;

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `AuthenticationActor` can process.
#[derive(Debug, Clone)]
pub enum AuthenticationInput {
    /// Starts the authentication protocol.
    Start,
    /// A network message intended for this subprotocol.
    NetworkMessage(ProtocolMessage),
    /// A command from the host UI indicating that the third-party
    /// authentication process has been completed.
    Finish,
}

/// The set of outputs that the `AuthenticationActor` can produce.
#[derive(Debug, Clone)]
pub enum AuthenticationOutput {
    /// A message that needs to be sent over the network.
    SendMessage(ProtocolMessage),
    /// A request for the host UI to initiate the third-party authentication
    /// process using the provided token.
    RequestThirdPartyAuth(String),
    /// The protocol has completed successfully, with the specified result.
    Success(VoterAuthenticationResult),
    /// The protocol has failed.
    Failure(String),
}

/// Contains the data resulting from a successful authentication protocol
/// run (this is not necessarily a successful authentication).
#[derive(Debug, Clone)]
pub struct VoterAuthenticationResult {
    /// The authentication result.
    pub result: (bool, String),
    /// The voter pseudonym (if authentication was successful).
    pub voter_pseudonym: Option<VoterPseudonym>,
    /// The session-specific public key generated during this protocol.
    pub session_public_key: VerifyingKey,
    /// The ballot style for this voter from the AuthVoterMsg.
    pub ballot_style: Option<BallotStyle>,
}

// --- II. Actor Implementation ---

/// The sub-states for the Voter Authentication protocol.
#[derive(Clone, Debug)]
enum SubState {
    ReadyToStart,
    AwaitingToken,
    AwaitingFinishCommand { token: String },
    AwaitingAuthorization,
}

/// The actor for the Voter Authentication subprotocol.
#[derive(Clone, Debug)]
pub struct AuthenticationActor {
    state: SubState,
    // --- Injected State from TopLevelActor ---
    election_hash: ElectionHash,
    eas_verifying_key: VerifyingKey,
    // --- State generated and used only within this protocol ---
    pub session_signing_key: SigningKey,
    pub session_verifying_key: VerifyingKey,
    // --- Stored for validation ---
    sent_auth_req: Option<AuthReqMsg>,
    sent_auth_finish: Option<AuthFinishMsg>,
}

impl AuthenticationActor {
    /// Creates a new `AuthenticationActor`.
    pub fn new(election_hash: ElectionHash, eas_verifying_key: VerifyingKey) -> Self {
        // Generate session keys for this authentication session
        let (session_signing_key, session_verifying_key) =
            crate::cryptography::generate_signature_keypair();

        Self {
            state: SubState::ReadyToStart,
            election_hash,
            eas_verifying_key,
            session_signing_key,
            session_verifying_key,
            sent_auth_req: None,
            sent_auth_finish: None,
        }
    }

    /// Processes an input for the Voter Authentication subprotocol.
    pub fn process_input(&mut self, input: AuthenticationInput) -> AuthenticationOutput {
        match (self.state.clone(), input) {
            (SubState::ReadyToStart, AuthenticationInput::Start) => {
                // Session keypair was already generated in the constructor

                let data = crate::messages::AuthReqMsgData {
                    election_hash: self.election_hash,
                    voter_verifying_key: self.session_verifying_key,
                };

                // Create signature using VSerializable
                let serialized = data.ser();

                let signature =
                    crate::cryptography::sign_data(&serialized, &self.session_signing_key);

                let auth_req_msg = AuthReqMsg { data, signature };

                self.sent_auth_req = Some(auth_req_msg.clone());
                self.state = SubState::AwaitingToken;
                AuthenticationOutput::SendMessage(ProtocolMessage::AuthReq(auth_req_msg))
            }

            (
                SubState::AwaitingToken,
                AuthenticationInput::NetworkMessage(ProtocolMessage::HandToken(token_msg)),
            ) => {
                // Perform "Voter Token Return Checks" from the spec
                if let Err(reason) = self.perform_voter_token_return_checks(&token_msg) {
                    return AuthenticationOutput::Failure(reason);
                }

                let token = token_msg.data.token.clone();
                self.state = SubState::AwaitingFinishCommand {
                    token: token.clone(),
                };
                AuthenticationOutput::RequestThirdPartyAuth(token)
            }

            (SubState::AwaitingFinishCommand { token }, AuthenticationInput::Finish) => {
                let data = AuthFinishMsgData {
                    election_hash: self.election_hash,
                    token: token.clone(),
                    public_key: self.session_verifying_key,
                };

                // Create signature using VSerializable
                let serialized = data.ser();

                let signature =
                    crate::cryptography::sign_data(&serialized, &self.session_signing_key);

                let auth_finish_msg = AuthFinishMsg { data, signature };

                self.sent_auth_finish = Some(auth_finish_msg.clone());
                self.state = SubState::AwaitingAuthorization;
                AuthenticationOutput::SendMessage(ProtocolMessage::AuthFinish(auth_finish_msg))
            }

            (
                SubState::AwaitingAuthorization,
                AuthenticationInput::NetworkMessage(ProtocolMessage::ConfirmAuthorization(
                    auth_msg,
                )),
            ) => {
                // Perform "Confirm Authorization Checks" from the spec
                if let Err(reason) = self.perform_confirm_authorization_checks(&auth_msg) {
                    return AuthenticationOutput::Failure(reason);
                }

                AuthenticationOutput::Success(VoterAuthenticationResult {
                    result: auth_msg.data.authentication_result,
                    voter_pseudonym: auth_msg.data.voter_pseudonym,
                    session_public_key: self.session_verifying_key,
                    ballot_style: auth_msg.data.ballot_style,
                })
            }

            _ => AuthenticationOutput::Failure("Invalid input for current state".to_string()),
        }
    }

    // --- Voter Token Return Checks (Phase 1 Response) ---

    /// Performs all "Voter Token Return Checks" from the specification
    fn perform_voter_token_return_checks(&self, token_msg: &HandTokenMsg) -> Result<(), String> {
        self.check_token_election_hash(&token_msg.data.election_hash)?;
        self.check_token_voter_verifying_key(&token_msg.data.voter_verifying_key)?;
        self.check_token_signature(&token_msg.data, &token_msg.signature)?;
        self.check_token_validity(&token_msg.data.token)?;

        Ok(())
    }

    /// Check #1: The election_hash is the hash for the current election
    fn check_token_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("HandTokenMsg has incorrect election hash".to_string());
        }
        Ok(())
    }

    /// Check #2: The voter_verifying_key matches the voter_verifying_key sent in the AuthReqMsg
    fn check_token_voter_verifying_key(
        &self,
        voter_verifying_key: &VerifyingKey,
    ) -> Result<(), String> {
        if *voter_verifying_key != self.session_verifying_key {
            return Err("HandTokenMsg has incorrect voter_verifying_key".to_string());
        }
        Ok(())
    }

    /// Check #3: The signature is a valid signature from the EAS
    fn check_token_signature(
        &self,
        data: &crate::messages::HandTokenMsgData,
        signature: &Signature,
    ) -> Result<(), String> {
        // Serialize the data for signature verification using VSerializable
        let serialized = data.ser();

        // Verify signature using EAS verifying key
        crate::cryptography::verify_signature(&serialized, signature, &self.eas_verifying_key)
    }

    /// Additional check: The token should be non-empty and properly formatted
    fn check_token_validity(&self, token: &str) -> Result<(), String> {
        if token.is_empty() {
            return Err("HandTokenMsg token cannot be empty".to_string());
        }
        // TODO: Additional token format validation if needed
        Ok(())
    }

    // --- Confirm Authorization Checks (Phase 4) ---

    /// Performs all "Confirm Authorization Checks" from the specification
    fn perform_confirm_authorization_checks(
        &self,
        auth_msg: &ConfirmAuthorizationMsg,
    ) -> Result<(), String> {
        self.check_auth_voter_election_hash(&auth_msg.data.election_hash)?;
        self.check_auth_voter_verifying_key(&auth_msg.data.voter_verifying_key)?;
        self.check_auth_voter_signature(&auth_msg.data, &auth_msg.signature)?;
        match auth_msg.data.authentication_result {
            (true, _) => {
                self.check_auth_voter_pseudonym(
                    auth_msg
                        .data
                        .voter_pseudonym
                        .as_ref()
                        .expect("pseudonym must exist in successful authorization"),
                )?;
                self.check_auth_voter_ballot_style(
                    auth_msg
                        .data
                        .ballot_style
                        .as_ref()
                        .expect("ballot style must exist in successful authorization"),
                )?;
            }

            (false, _) => {
                if auth_msg.data.voter_pseudonym.is_some() {
                    return Err(
                        "pseudonym must not exist in unsuccessful authorization".to_string()
                    );
                };
                if auth_msg.data.ballot_style.is_some() {
                    return Err(
                        "ballot style must not exist in unsuccessful authorization".to_string()
                    );
                };
            }
        }

        Ok(())
    }

    /// Check #1: The election_hash is the hash for the current election
    fn check_auth_voter_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            return Err("AuthVoterMsg has incorrect election hash".to_string());
        }
        Ok(())
    }

    /// Check #2: The voter_verifying_key matches the voter_verifying_key for the current session
    fn check_auth_voter_verifying_key(
        &self,
        voter_verifying_key: &VerifyingKey,
    ) -> Result<(), String> {
        if *voter_verifying_key != self.session_verifying_key {
            return Err("AuthVoterMsg has incorrect voter_verifying_key".to_string());
        }
        Ok(())
    }

    /// Check #3: The signature is a valid signature from the EAS
    fn check_auth_voter_signature(
        &self,
        data: &crate::messages::ConfirmAuthorizationMsgData,
        signature: &Signature,
    ) -> Result<(), String> {
        // Serialize the data for signature verification using VSerializable
        let serialized = data.ser();

        // Verify signature using EAS verifying key
        crate::cryptography::verify_signature(&serialized, signature, &self.eas_verifying_key)
    }

    /// Additional check: Voter pseudonym should be valid
    fn check_auth_voter_pseudonym(&self, voter_pseudonym: &VoterPseudonym) -> Result<(), String> {
        if voter_pseudonym.is_empty() {
            return Err("AuthVoterMsg voter_pseudonym cannot be empty".to_string());
        }
        // TODO: Additional validation of pseudonym format if required
        Ok(())
    }

    /// Additional check: Ballot style should be valid
    fn check_auth_voter_ballot_style(&self, ballot_style: &BallotStyle) -> Result<(), String> {
        // BallotStyle is a u8, so validate it's greater than 0
        if *ballot_style > 0 {
            Ok(())
        } else {
            Err("AuthVoterMsg ballot_style must be greater than 0".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::utils::serialization::VSerializable;

    #[test]
    fn test_vserializable_authentication_messages() {
        // Test that VSerializable works correctly for authentication message serialization
        let (_, verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_hash = "test_election_2024".to_string();

        // Test AuthReqMsgData serialization
        let auth_req_data = crate::messages::AuthReqMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            voter_verifying_key: verifying_key,
        };
        let serialized_auth_req = auth_req_data.ser();
        assert!(
            !serialized_auth_req.is_empty(),
            "AuthReqMsgData serialization should not be empty"
        );

        // Test HandTokenMsgData serialization
        let hand_token_data = crate::messages::HandTokenMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            token: "test_token_12345".to_string(),
            voter_verifying_key: verifying_key,
        };
        let serialized_hand_token = hand_token_data.ser();
        assert!(
            !serialized_hand_token.is_empty(),
            "HandTokenMsgData serialization should not be empty"
        );

        // Test AuthFinishMsgData serialization
        let auth_finish_data = crate::messages::AuthFinishMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            token: "test_token_12345".to_string(),
            public_key: verifying_key,
        };
        let serialized_auth_finish = auth_finish_data.ser();
        assert!(
            !serialized_auth_finish.is_empty(),
            "AuthFinishMsgData serialization should not be empty"
        );

        // Test AuthVoterMsgData serialization
        let auth_voter_data = crate::messages::AuthVoterMsgData {
            election_hash: crate::elections::string_to_election_hash(&election_hash),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
        };
        let serialized_auth_voter = auth_voter_data.ser();
        assert!(
            !serialized_auth_voter.is_empty(),
            "AuthVoterMsgData serialization should not be empty"
        );
        assert!(!serialized_auth_voter.is_empty());
    }

    #[test]
    fn test_authentication_actor_signature_compatibility() {
        // Test that the authentication actor can create and verify signatures using VSerializable
        let election_hash = "test_election_2024".to_string();
        let (_eas_signing_key, eas_verifying_key) =
            crate::cryptography::generate_signature_keypair();

        let mut auth_actor = AuthenticationActor::new(
            crate::elections::string_to_election_hash(&election_hash),
            eas_verifying_key,
        );

        // Test that we can create an AuthReqMsg (this internally uses .ser() for signatures)
        let result = auth_actor.process_input(AuthenticationInput::Start);

        match result {
            AuthenticationOutput::SendMessage(ProtocolMessage::AuthReq(auth_req_msg)) => {
                // Verify that the message was created successfully
                assert_eq!(
                    auth_req_msg.data.election_hash,
                    crate::elections::string_to_election_hash(&election_hash)
                );
                assert_eq!(
                    auth_req_msg.data.voter_verifying_key,
                    auth_actor.session_verifying_key
                );

                // Verify that the signature can be verified using VSerializable
                let serialized = auth_req_msg.data.ser();
                let verification_result = crate::cryptography::verify_signature(
                    &serialized,
                    &auth_req_msg.signature,
                    &auth_actor.session_verifying_key,
                );
                assert!(
                    verification_result.is_ok(),
                    "Signature verification should succeed"
                );
            }
            _ => panic!("Expected SendMessage with AuthReq, got: {:?}", result),
        }
    }
}
