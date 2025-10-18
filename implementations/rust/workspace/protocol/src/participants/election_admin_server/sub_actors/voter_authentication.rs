//! This file contains the implementation of the VoterAuthenticationActor`,
//! which is responsible for handling the Voter Authentication subprotocol
//! executed by the Election Administration Server (EAS) according to the
//! hierarchical I/O model and the voter-authentication-spec.md specification.
#![allow(unused_imports)]
// Currently ignored for code simplicity until performance data is analyzed.
// @todo Consider boxing structs in large enum variants to improve performance.
#![allow(clippy::large_enum_variant)]

use crate::auth_service::{AuthServiceMessage, AuthSessionRecord};
use crate::auth_service::{
    AuthServiceQueryMsg, AuthServiceReportMsg, InitAuthReqMsg, TokenReturnMsg,
};

use crate::crypto::{SigningKey, VerifyingKey};
use crate::crypto::{sign_data, verify_signature};

use crate::elections::BallotStyle;
use crate::elections::ElectionHash;
use crate::elections::VoterPseudonym;

use crate::messages::ProtocolMessage;
use crate::messages::ProtocolMessage::{AuthFinish, AuthReq, AuthVoter, ConfirmAuthorization};
use crate::messages::{AuthFinishMsg, AuthFinishMsgData};
use crate::messages::{AuthReqMsg, AuthReqMsgData};
use crate::messages::{AuthVoterMsg, AuthVoterMsgData};
use crate::messages::{ConfirmAuthorizationMsg, ConfirmAuthorizationMsgData};
use crate::messages::{HandTokenMsg, HandTokenMsgData};

use super::super::top_level_actor::AuthReqId;

use crypto::utils::serialization::VSerializable;

use std::time::Instant;

/* We assume that the sub-actor input has been correctly routed to this
 * sub-actor based on its [`AuthReqId`]. Therefore, it is not necessary
 * to include the authentication request id into the constructors of
 * [`VoterAuthenticationInput`] enumeruation variants or otherwise the
 * [`VoterAuthenticationActor`] state.
 */
#[derive(Debug, Clone)]
pub enum VoterAuthenticationInput {
    /**
     * A protocol message received over the network.
     */
    NetworkMessage(ProtocolMessage),

    /**
     * Messages received from the Authentication Service (AS)
     */
    AuthServiceMessage(AuthServiceMessage),

    /**
     * Indicates that the requested check of biographical information
     * succeeded and forwards the voter pseudonym and ballot style to
     * the sub-actor.
     */
    BiographicalInfoOk {
        voter_pseudonym: String,
        ballot_style: BallotStyle,
    },

    /**
     * Indicates that the requested check of biographical information
     * failed. The argument of the variant provides an error message.
     */
    BiographicalInfoInvalid(String),
}

#[derive(Debug, Clone)]
pub enum VoterAuthenticationOutput {
    /**
     * Protocol messages to be sent over the network
     */
    NetworkMessage(Vec<ProtocolMessage>),

    /**
     * A Message to be sent to the Authentication Service (AS)
     */
    AuthServiceMessage(AuthServiceMessage),

    /**
     * Asks the protocol driver to check the provided biographical
     * information of the voter in its database of registered voters.
     */
    CheckBiographicalInfo(AuthServiceReportMsg),

    /**
     * The protocol has failed.
     */
    Failure(String),
}

/// The sub-states for the Voter Authentication protocol.
#[derive(Debug, Copy, Clone, PartialEq, Default)]
enum SubState {
    /**
     * Initial state of the sub-actor: We are waiting for an [`AuthReqMsg`]
     * message from the Voting Application (VA) to start the authentication
     * request subprotocol.
     */
    #[default]
    ReceiveAuthRequest,

    /**
     * We have sent an [`InitAuthReqMsg`] message to the Authentication
     * Service (AS) and are waiting for a [`TokenReturnMsg`] from the AS
     * that contains the token to be sent to the voter for using the AS.
     * We are sending that token to the Voting Application (VA).
     */
    ReceiveTokenFromAS,

    /**
     * We have received a confirmation from the voter that her/his
     * authentication session with the Authentication Service (AS) has
     * completed. We are sending a query to the AS the verify that the
     * voter has indeed successfully authenticated with the AS.
     */
    ReceiveAuthFinishMsg,

    /**
     * We received a reply from the Authentication Service (AS) to our
     * query and output either `VoterAuthenticationOutput::Failure(...)`
     * in case of a failed authentication, or a pair of network messages
     * that confirm to the VA and DBB that authentication was successful.
     */
    CheckReplyFromAS,

    /**
     * The Authentication Serivce (AS) has acknowledged that the voter
     * is now authenticated. We still have to check the biographical
     * information returned by the AS for the voter against the database
     * of registered voters, and generate a voter pseudonym and suitable
     * ballot style. These tasks are not carried out by the protocol
     * implementation here but some higher-level executive / driver.
     */
    VerifyBiographicalInfo,

    /**
     * The protocol has completed, either in orderly or erroneous fashion.
     */
    Completed,
}

/// State of the [`VoterAuthenticationActor`].
#[derive(Debug, Clone)]
pub struct VoterAuthenticationActor {
    // Symbolic state of the sub-actor
    state: SubState,

    // Injected state from TopLevelActor
    election_hash: ElectionHash,
    eas_signing_key: SigningKey,
    as_project_id: String,
    as_api_key: String,

    /**
     * Records the time of the last input received by this sub-actor.
     *
     * This is used by the top-level actor to purge sub-actors that
     * have time-out.
     */
    time_of_last_input: Instant,

    /**
     * Signature verification key of the authenticating voter.
     *
     * Stored temporarily from the initial request until copied into
     * [`AuthSessionRecord`].
     */
    voter_verifying_key: Option<VerifyingKey>,

    /**
     * Authentication Session Record including AS token and session id.
     */
    auth_record: Option<AuthSessionRecord>,
}

/// Behavior of the [`VoterAuthenticationActor`].
impl VoterAuthenticationActor {
    pub fn new(
        election_hash: ElectionHash,
        eas_signing_key: SigningKey,
        as_project_id: String,
        as_api_key: String,
    ) -> Self {
        Self {
            state: SubState::default(),
            election_hash,
            eas_signing_key,
            as_project_id,
            as_api_key,
            time_of_last_input: Instant::now(),
            voter_verifying_key: None,
            auth_record: None,
        }
    }

    /// Processes an input for the Voter Authentication subprotocol.
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
                VoterAuthenticationOutput::AuthServiceMessage(AuthServiceMessage::InitAuthReq(
                    InitAuthReqMsg {
                        project_id: self.as_project_id.clone(),
                        api_key: self.as_api_key.clone(),
                    },
                ))
            }

            (
                SubState::ReceiveTokenFromAS,
                VoterAuthenticationInput::AuthServiceMessage(AuthServiceMessage::TokenReturn(msg)),
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

                // Create HandTokenMsg data
                let hand_token_msg_data = HandTokenMsgData {
                    election_hash: self.election_hash,
                    token: msg.token.clone(),
                    voter_verifying_key: self.voter_verifying_key.unwrap(),
                };

                // Create HandTokenMsg signature
                let hand_token_msg_signature =
                    sign_data(hand_token_msg_data.ser().as_slice(), &self.eas_signing_key);

                // Create HandTokenMsg signed by the EAS
                let hand_token_msg = HandTokenMsg {
                    data: hand_token_msg_data,
                    signature: hand_token_msg_signature,
                };

                self.state = SubState::ReceiveAuthFinishMsg;

                // Return network protocol message to hand token to VA.
                VoterAuthenticationOutput::NetworkMessage(vec![ProtocolMessage::HandToken(
                    hand_token_msg,
                )])
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
                VoterAuthenticationOutput::AuthServiceMessage(AuthServiceMessage::AuthServiceQuery(
                    AuthServiceQueryMsg {
                        session_id: self.auth_record.as_ref().unwrap().session_id.clone(),
                        api_key: self.as_api_key.clone(),
                    },
                ))
            }

            (
                SubState::CheckReplyFromAS,
                VoterAuthenticationInput::AuthServiceMessage(
                    AuthServiceMessage::AuthServiceReport(msg),
                ),
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
                        voter_pseudonym: None,
                        voter_verifying_key,
                        ballot_style: None,
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
                    VoterAuthenticationOutput::NetworkMessage(vec![ConfirmAuthorization(
                        confirm_auth_msg,
                    )])
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

                // Create AuthVoterMsg data
                let auth_voter_msg_data = AuthVoterMsgData {
                    election_hash: self.election_hash,
                    voter_pseudonym: voter_pseudonym.clone(),
                    voter_verifying_key,
                    ballot_style,
                };

                // Create AuthVoterMsg signature
                let auth_voter_msg_signature =
                    sign_data(auth_voter_msg_data.ser().as_slice(), &self.eas_signing_key);

                // Create AuthVoterMsg signed by the EAS
                let auth_voter_msg = AuthVoterMsg {
                    data: auth_voter_msg_data,
                    signature: auth_voter_msg_signature,
                };

                // Create ConfirmAuthorizationMsg data
                let confirm_auth_msg_data = ConfirmAuthorizationMsgData {
                    election_hash: self.election_hash,
                    voter_pseudonym: Some(voter_pseudonym.clone()),
                    voter_verifying_key,
                    ballot_style: Some(ballot_style),
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

                // Return network protocol messages to confirm voter
                // authentication with the Digital Ballot Box (DBB)
                // and Voter Application (VA).
                VoterAuthenticationOutput::NetworkMessage(vec![
                    AuthVoter(auth_voter_msg),
                    ConfirmAuthorization(confirm_auth_msg),
                ])
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
                    voter_pseudonym: None,
                    voter_verifying_key,
                    ballot_style: None,
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
                VoterAuthenticationOutput::NetworkMessage(vec![ConfirmAuthorization(
                    confirm_auth_msg,
                )])
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

    /**
     * Determines if this request is in a compeleted state.
     *
     * Compeletion may occur due to successful voter authentication
     * or otherwise some failure during execution of the protocol.
     */
    pub fn has_completed(&self) -> bool {
        self.state == SubState::Completed
    }

    /// Returns the time when the last input was processed by the sub-actor.
    pub fn get_time_of_last_input(&self) -> Instant {
        self.time_of_last_input
    }

    /**************************/
    /* Initial Request Checks */
    /**************************/

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

    /*****************************/
    /* Validation Request Checks */
    /*****************************/

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

    /************************/
    /* Authorization Checks */
    /************************/

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
