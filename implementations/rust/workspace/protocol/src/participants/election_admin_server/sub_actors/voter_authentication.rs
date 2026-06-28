// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the implementation of the `VoterAuthenticationActor`,
//! which is responsible for handling the Voter Authentication subprotocol
//! executed by the Election Administration Server (EAS) according to the
//! hierarchical I/O model and the voter-authentication-spec.md specification.

#![allow(unused_imports)]
// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed.
#![allow(clippy::large_enum_variant)]

use crate::auth_service::{AuthServiceMsg, AuthSessionRecord};
use crate::auth_service::{
    AuthServiceQueryMsg, AuthServiceReportMsg, InitAuthReqMsg, TokenReturnMsg,
};

use crate::cryptography::{SigningKey, VerifyingKey};
use crate::cryptography::{sign_data, verify_signature};

use crate::elections::BallotStyle;
use crate::elections::ElectionHash;
use crate::elections::VoterPseudonym;
use crate::elections::{VoterAuthorization, VoterAuthorizationTimestamp};

use crate::messages::ProtocolMsg;
use crate::messages::ProtocolMsg::{AuthFinish, AuthReq, ConfirmAuthorization};
use crate::messages::{AuthFinishMsg, AuthFinishMsgData};
use crate::messages::{AuthReqMsg, AuthReqMsgData};
use crate::messages::{AuthServiceTokenMsg, AuthServiceTokenMsgData};
use crate::messages::{ConfirmAuthorizationMsg, ConfirmAuthorizationMsgData};

use crate::participants::election_admin_server::top_level_actor::AuthReqId;

use cryptography::utils::serialization::VSerializable;

use std::time::Instant;

/* We assume that the sub-actor input has been correctly routed to this
 * sub-actor based on its [`AuthReqId`]. Therefore, it is not necessary
 * to include the authentication request id into the constructors of
 * [`VoterAuthenticationInput`] enumeruation variants or otherwise the
 * [`VoterAuthenticationActor`] state.
 */
/// Inputs to the voter authentication sub-actor.
#[derive(Debug, Clone)]
pub enum VoterAuthenticationInput {
    /// A protocol message received over the network.
    NetworkMessage(ProtocolMsg),

    /// A message received from the Authentication Service (AS).
    AuthServiceMessage(AuthServiceMsg),

    /// Indicates that biographical information checks succeeded and
    /// forwards the voter pseudonym and ballot style to the sub-actor.
    BiographicalInfoOk {
        voter_pseudonym: String,
        ballot_style: BallotStyle,
    },

    /// Indicates that biographical information checks failed.
    ///
    /// The payload contains an error message.
    BiographicalInfoInvalid(String),
}

/// Outputs from the voter authentication sub-actor.
#[derive(Debug, Clone)]
pub enum VoterAuthenticationOutput {
    /// A protocol message to be sent over the network.
    NetworkMessage(ProtocolMsg),

    /// A message to be sent to the Authentication Service (AS).
    AuthServiceMessage(AuthServiceMsg),

    /// Ask the protocol driver to validate returned biographical information
    /// against the voter registration database.
    CheckBiographicalInfo(AuthServiceReportMsg),

    /// The protocol has failed.
    Failure(String),
}

/// The sub-states for the Voter Authentication protocol.
#[derive(Debug, Copy, Clone, PartialEq, Default)]
enum SubState {
    /// Initial state: wait for an [`AuthReqMsg`] message from the Voting
    /// Application (VA) to start the authentication request subprotocol.
    #[default]
    ReceiveAuthRequest,

    /// We have sent an [`InitAuthReqMsg`] to the Authentication Service (AS)
    /// and are waiting for a [`TokenReturnMsg`].
    ReceiveTokenFromAS,

    /// We received voter confirmation and are now querying the AS to verify
    /// successful authentication.
    ReceiveAuthFinishMsg,

    /// We received an AS reply and now produce either failure output or
    /// success output for VA/DBB follow-up.
    CheckReplyFromAS,

    /// The AS has acknowledged authentication. The protocol driver must now
    /// validate biographical data and provide pseudonym/ballot-style inputs.
    VerifyBiographicalInfo,

    /// The protocol has completed, either successfully or with failure.
    Completed,
}

/// State of the [`VoterAuthenticationActor`].
#[derive(Debug, Clone)]
/// Voter authentication sub-actor state and injected configuration.
pub struct VoterAuthenticationActor {
    // Symbolic state of the sub-actor
    state: SubState,

    // Injected state from ElectionAdminServerActor (constant for the
    // lifetime of the sub-actor)
    election_hash: ElectionHash,
    eas_signing_key: SigningKey,
    as_project_id: String,
    as_api_key: String,
    auth_timestamp: VoterAuthorizationTimestamp,

    /// Records the time of the last input received by this sub-actor.
    ///
    /// Used by the top-level actor to purge timed-out sub-actors.
    time_of_last_input: Instant,

    /// Signature verification key of the authenticating voter.
    ///
    /// Stored temporarily from the initial request until copied into
    /// [`AuthSessionRecord`].
    voter_verifying_key: Option<VerifyingKey>,

    /// Authentication session record including AS token and session id.
    auth_record: Option<AuthSessionRecord>,
}

/// Behavior of the [`VoterAuthenticationActor`].
impl VoterAuthenticationActor {
    /// Create a new voter authentication sub-actor.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `eas_signing_key` - The EAS's signing key for issuing authorization messages.
    /// * `as_project_id` - The project ID for the authentication service.
    /// * `as_api_key` - The API key for the authentication service.
    /// * `auth_timestamp` - How to timestamp issued voter
    ///   authorizations; see [`VoterAuthorizationTimestamp`].
    ///
    /// # Returns
    /// A new `VoterAuthenticationActor` ready to receive the voter's initial auth request.
    pub fn new(
        election_hash: ElectionHash,
        eas_signing_key: SigningKey,
        as_project_id: String,
        as_api_key: String,
        auth_timestamp: VoterAuthorizationTimestamp,
    ) -> Self {
        Self {
            state: SubState::default(),
            election_hash,
            eas_signing_key,
            as_project_id,
            as_api_key,
            auth_timestamp,
            time_of_last_input: Instant::now(),
            voter_verifying_key: None,
            auth_record: None,
        }
    }

    /// Processes an input for the Voter Authentication subprotocol.
    ///
    /// # Arguments
    /// * `input` - The input to process.
    ///
    /// # Returns
    /// A `VoterAuthenticationOutput` describing the result of processing the input.
    pub fn process_input(&mut self, input: VoterAuthenticationInput) -> VoterAuthenticationOutput {
        match (self.state, input) {
            (
                SubState::ReceiveAuthRequest,
                VoterAuthenticationInput::NetworkMessage(AuthReq(msg)),
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                // Verify AuthReqMsg before sending request to AS.
                if let Err(cause) = self.check_auth_req_msg(&msg) {
                    self.state = SubState::Completed;

                    return VoterAuthenticationOutput::Failure(cause);
                }

                // Remember signature verification key of the voter.
                // We need it later for setting the AuthSessionRecord.
                self.voter_verifying_key = Some(msg.data.voter_verifying_key);

                self.state = SubState::ReceiveTokenFromAS;

                // Send Initiate Authentication Request Message to AS.
                VoterAuthenticationOutput::AuthServiceMessage(AuthServiceMsg::InitAuthReq(
                    InitAuthReqMsg {
                        project_id: self.as_project_id.clone(),
                        api_key: self.as_api_key.clone(),
                    },
                ))
            }

            (
                SubState::ReceiveTokenFromAS,
                VoterAuthenticationInput::AuthServiceMessage(AuthServiceMsg::TokenReturn(msg)),
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                // Guaranteed by the state machine logic.
                assert!(self.voter_verifying_key.is_some());

                // Create AuthSessionRecord for the request.
                self.auth_record = Some(AuthSessionRecord {
                    election_hash: self.election_hash,
                    voter_verifying_key: self.voter_verifying_key.unwrap(),
                    token: msg.token.clone(),
                    session_id: msg.session_id.clone(),
                });

                // Create AuthServiceTokenMsg data
                let hand_token_msg_data = AuthServiceTokenMsgData {
                    election_hash: self.election_hash,
                    token: msg.token.clone(),
                    voter_verifying_key: self.voter_verifying_key.unwrap(),
                };

                // Create AuthServiceTokenMsg signature
                let hand_token_msg_signature =
                    sign_data(hand_token_msg_data.ser().as_slice(), &self.eas_signing_key);

                // Create AuthServiceTokenMsg signed by the EAS
                let hand_token_msg = AuthServiceTokenMsg {
                    data: hand_token_msg_data,
                    signature: hand_token_msg_signature,
                };

                self.state = SubState::ReceiveAuthFinishMsg;

                // Return network protocol message to hand token to VA.
                VoterAuthenticationOutput::NetworkMessage(ProtocolMsg::AuthServiceToken(
                    hand_token_msg,
                ))
            }

            (
                SubState::ReceiveAuthFinishMsg,
                VoterAuthenticationInput::NetworkMessage(AuthFinish(msg)),
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                // Check integrity of AuthFinishMsg before proceeding.
                if let Err(cause) = self.check_auth_finish_msg(&msg) {
                    self.state = SubState::Completed;

                    return VoterAuthenticationOutput::Failure(cause);
                }

                self.state = SubState::CheckReplyFromAS;

                // Send Initiate Authentication Request Message to AS.
                VoterAuthenticationOutput::AuthServiceMessage(AuthServiceMsg::AuthServiceQuery(
                    AuthServiceQueryMsg {
                        session_id: self.auth_record.as_ref().unwrap().session_id.clone(),
                        api_key: self.as_api_key.clone(),
                    },
                ))
            }

            (
                SubState::CheckReplyFromAS,
                VoterAuthenticationInput::AuthServiceMessage(AuthServiceMsg::AuthServiceReport(
                    msg,
                )),
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                if let Err(cause) = self.check_auth_service_report_msg(&msg) {
                    // Declare local for voter_verifying_key for convenience
                    let voter_verifying_key =
                        self.auth_record.as_ref().unwrap().voter_verifying_key;

                    // Authentication failure message
                    let failure_msg = format!("Authentication Failed: {cause}");

                    // Create ConfirmAuthorizationMsg data
                    let confirm_auth_msg_data = ConfirmAuthorizationMsgData {
                        election_hash: self.election_hash,
                        voter_authorization: None,
                        voter_verifying_key,
                        authentication_result: (false, failure_msg),
                    };

                    // Create ConfirmAuthorizationMsg signature
                    let confirm_auth_msg_signature = sign_data(
                        confirm_auth_msg_data.ser().as_slice(),
                        &self.eas_signing_key,
                    );

                    // Create ConfirmAuthorizationMsg signed by the EAS
                    let confirm_auth_msg = ConfirmAuthorizationMsg {
                        data: confirm_auth_msg_data,
                        signature: confirm_auth_msg_signature,
                    };

                    self.state = SubState::Completed;

                    // Return a single network protocol message to inform
                    // the voter that authentication has failed. No message
                    // is sent to the Digital Ballot Box (DBB) in that case.
                    VoterAuthenticationOutput::NetworkMessage(ConfirmAuthorization(
                        confirm_auth_msg,
                    ))
                } else {
                    self.state = SubState::VerifyBiographicalInfo;

                    // Return network protocol messages to confirm voter
                    // authentication with the Digital Ballot Box (DBB)
                    // and Voter Application (VA).
                    VoterAuthenticationOutput::CheckBiographicalInfo(msg)
                }
            }

            (
                SubState::VerifyBiographicalInfo,
                VoterAuthenticationInput::BiographicalInfoOk {
                    voter_pseudonym,
                    ballot_style,
                },
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                // Voter authentication and biographical info check both
                // succeeded. Create messages to notify both the DBB and VA.

                // Declare local for voter_verifying_key for convenience
                let voter_verifying_key = self.auth_record.as_ref().unwrap().voter_verifying_key;

                // Create the voter authorization token, included in the
                // ballot submission and ballot cast messages the VA will
                // later send to the DBB.
                let voter_authorization = VoterAuthorization::new(
                    self.election_hash,
                    voter_pseudonym.clone(),
                    ballot_style,
                    voter_verifying_key,
                    &self.eas_signing_key,
                    self.auth_timestamp,
                );

                // Create ConfirmAuthorizationMsg data
                let confirm_auth_msg_data = ConfirmAuthorizationMsgData {
                    election_hash: self.election_hash,
                    voter_authorization: Some(voter_authorization),
                    voter_verifying_key,
                    authentication_result: (true, "Authentication Successful".to_string()),
                };

                // Create ConfirmAuthorizationMsg signature
                let confirm_auth_msg_signature = sign_data(
                    confirm_auth_msg_data.ser().as_slice(),
                    &self.eas_signing_key,
                );

                // Create ConfirmAuthorizationMsg signed by the EAS
                let confirm_auth_msg = ConfirmAuthorizationMsg {
                    data: confirm_auth_msg_data,
                    signature: confirm_auth_msg_signature,
                };

                self.state = SubState::Completed;

                // Return a network protocol message to confirm voter
                // authentication with the Voter Application (VA). The EAS no
                // longer sends a message to the Digital Ballot Box (DBB).
                VoterAuthenticationOutput::NetworkMessage(ConfirmAuthorization(confirm_auth_msg))
            }

            (
                SubState::VerifyBiographicalInfo,
                VoterAuthenticationInput::BiographicalInfoInvalid(cause),
            ) => {
                // Update time of last input occurrence for this sub-actor.
                self.time_of_last_input = Instant::now();

                self.state = SubState::Completed;

                // Declare local for voter_verifying_key for convenience
                let voter_verifying_key = self.auth_record.as_ref().unwrap().voter_verifying_key;

                // Authentication failure message
                let failure_msg = format!("Authentication Failed: {cause}");

                // Create ConfirmAuthorizationMsg data
                let confirm_auth_msg_data = ConfirmAuthorizationMsgData {
                    election_hash: self.election_hash,
                    voter_authorization: None,
                    voter_verifying_key,
                    authentication_result: (false, failure_msg),
                };

                // Create ConfirmAuthorizationMsg signature
                let confirm_auth_msg_signature = sign_data(
                    confirm_auth_msg_data.ser().as_slice(),
                    &self.eas_signing_key,
                );

                // Create ConfirmAuthorizationMsg signed by the EAS
                let confirm_auth_msg = ConfirmAuthorizationMsg {
                    data: confirm_auth_msg_data,
                    signature: confirm_auth_msg_signature,
                };

                self.state = SubState::Completed;

                // Return a single network protocol message to inform
                // the voter that authentication has failed. No message
                // is sent to the Digital Ballot Box (DBB) in that case.
                VoterAuthenticationOutput::NetworkMessage(ConfirmAuthorization(confirm_auth_msg))
            }

            // Catch-all pattern for all other state/message combinations.
            _ => {
                self.state = SubState::Completed;

                VoterAuthenticationOutput::Failure(
                    "invalid input for current state of the protocol".to_string(),
                )
            }
        }
    }

    /// Determine whether this request is in a completed state.
    ///
    /// Completion may occur due to successful authentication or failure
    /// during protocol execution.
    ///
    /// # Returns
    /// `true` if the sub-actor has reached a terminal state, `false` otherwise.
    pub fn has_completed(&self) -> bool {
        self.state == SubState::Completed
    }

    /// Returns the time when the last input was processed by the sub-actor.
    ///
    /// # Returns
    /// The `Instant` at which the most recent input was processed.
    pub fn get_time_of_last_input(&self) -> Instant {
        self.time_of_last_input
    }

    // --- Initial Request Checks ---

    // Performs Initial Request Checks per protocol specification.
    fn check_auth_req_msg(&self, msg: &AuthReqMsg) -> Result<(), String> {
        // 1. The election_hash is the hash of the election configuration
        //    item for the current election.
        if msg.data.election_hash != self.election_hash {
            return Err(
                "wrong election hash in initial authentication request message".to_string(),
            );
        }

        // 2. The signature is a valid signature over the message contents
        //    signed by the voter_verifying_key.
        // This is not explicitly mentioned in the Initial Request Checks
        // of the protocol description in voter-authentication-spec.md.
        // @review Does the protocol layer need to verify message signatures?
        if verify_signature(
            &msg.data.ser(),
            &msg.signature,
            &msg.data.voter_verifying_key,
        )
        .is_err()
        {
            return Err(
                "verification of signature of initial authentication request message failed"
                    .to_string(),
            );
        }

        Ok(()) // All checks passed!
    }

    // --- Validation Request Checks ---

    // Performs Validation Request Checks per protocol specification.
    fn check_auth_finish_msg(&self, msg: &AuthFinishMsg) -> Result<(), String> {
        // 1. The election_hash is the hash of the election configuration
        //    item for the current election.
        if msg.data.election_hash != self.election_hash {
            return Err("wrong election hash in validation request message".to_string());
        }

        // 2. The token matches one AuthSessionRecord.token.
        if msg.data.token != self.auth_record.as_ref().unwrap().token {
            return Err("wrong authentication token in validation request message".to_string());
        }

        // 3. The public_key matches the AuthSessionRecord.public_key from
        //    check #2.
        if msg.data.public_key != self.auth_record.as_ref().unwrap().voter_verifying_key {
            return Err("wrong public key in validation request message".to_string());
        }

        // 4. The signature is a valid signature over the message contents
        //    signed by the public_key.
        if verify_signature(&msg.data.ser(), &msg.signature, &msg.data.public_key).is_err() {
            return Err("signature of validation request message is invalid".to_string());
        }

        Ok(()) // All checks passed!
    }

    // --- Authorization Checks ---

    // 1. Biographical information from the Authentication Service Report
    //    Message match a registered voter in the voter registration database.
    // 2. The token in the Authentication Service Report Message matches one
    //    AuthSessionRecord.token.

    // Performs Authorization Checks per protocol specification.
    // If all checks passed, returns an Ok(()) result. This implies
    // that the voter has successfully authenticated with the AS.
    fn check_auth_service_report_msg(&self, msg: &AuthServiceReportMsg) -> Result<(), String> {
        // 0. First check whether the AS confirms authentication of the voter.
        // @todo This check is not included in voter-authentication-spec.md.
        // Talk to Luke Myers and the team whether it should be carried out.
        if !msg.authenticated {
            return Err(
                "The voter seems not to have authenticated with the Authentication Service"
                    .to_string(),
            );
        }

        // 1. Biographical information from the Authentication Service Report
        //    Message match a registered voter in the voter registration database.
        // @note This check cannot be performed here but must be carried out by
        // the protocol driver which will have access to the voter registration
        // database. Specific sub-actor inputs and outputs are used to delegate
        // this check to the protocol driver / executive and obtain the result.

        // 2. The token in the Authentication Service Report Message matches
        //    one AuthSessionRecord.token.
        if msg.token != self.auth_record.as_ref().unwrap().token {
            return Err("Token in authentication service report does not match the one associated with the session id".to_string());
        }

        // 3. The session id in the Authentication Service Report Message
        //    matches one AuthSessionRecord.session_id.
        // @todo This check is not included in voter-authentication-spec.md.
        // Talk to Luke Myers and the team whether it should be carried out.
        if msg.session_id != self.auth_record.as_ref().unwrap().session_id {
            return Err("Session ID in authentication service report does not match the one sent in the query".to_string());
        }

        Ok(()) // The Voter has authenticated with the AS.
    }
}
