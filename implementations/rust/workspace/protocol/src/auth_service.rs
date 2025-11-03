// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module includes messages and functions pertaining to interacting
//! with the Authentication Service (AS).

use crate::cryptography::VerifyingKey;
use crate::elections::ElectionHash;

// Authentication Session Record
#[derive(Debug, Clone)]
pub struct AuthSessionRecord {
    /**
     * Hash of the unique election configuration item.
     */
    pub election_hash: ElectionHash,

    /**
     * Public key from the Initial Request Message
     */
    pub voter_verifying_key: VerifyingKey,

    /**
     * Token from the Token Return Message.
     */
    pub token: String,

    /**
     * Session identifier from the Token Return Message.
     */
    pub session_id: String,
}

// Initiate Authentication Request Message
#[derive(Debug, Clone)]
pub struct InitAuthReqMsg {
    /**
     * An identifier specific to the voting system infrastructure
     * used by the third-party authentication service to determine
     * the verification flow for the authentication sessions we create.
     */
    pub project_id: String,

    /**
     * The third-party authentication service API key specific to the EAS.
     */
    pub api_key: String,
}

// Token Return Message
#[derive(Debug, Clone)]
pub struct TokenReturnMsg {
    /**
     * Token to be used by the client to start an authentication session.
     */
    pub token: String,

    /**
     * A session identifier to be used by the server to request
     * authentication session information tied to the associated token.
     */
    pub session_id: String,
}

// Authentication Service Query Message
#[derive(Debug, Clone)]
pub struct AuthServiceQueryMsg {
    /**
     * The session ID retrieved from EAS storage based on the public key
     * used to sign the Validation Request Message.
     */
    pub session_id: String,

    /**
     * The third-party authentication service API key specific to the EAS.
     */
    pub api_key: String,
}

/**
 * Authentication Service Report Message
 *
 * Note that the protocol description in voter-authentication-spec.md
 * provides a tentative JSON format but the precise format will depend
 * on the Authentication Service provider. Hence, we abstract biographical
 * data into a single String whose precise format we leave unspecified.
 * Also, we use a single boolean to determine whether authentication
 * has been carried out by the voter and was successful.
 */
#[derive(Debug, Clone)]
pub struct AuthServiceReportMsg {
    /**
     * Token to be used by the client to start an authentication session.
     */
    pub token: String,

    /**
     * The session ID used in the Authentication Service Query Message.
     */
    pub session_id: String,

    /**
     * Biographical information associated with the authenticated voter.
     *
     * May be [`None`] if [`AuthServiceReportMsg::authenticated`] is false.
     */
    pub biographical_info: Option<String>,

    /**
     * Determines if the user has successfully authenticated.
     */
    pub authenticated: bool,
}

// Enumeration of possible Authentication Service messages
#[derive(Debug, Clone)]
pub enum AuthServiceMessage {
    InitAuthReq(InitAuthReqMsg),
    TokenReturn(TokenReturnMsg),
    AuthServiceQuery(AuthServiceQueryMsg),
    AuthServiceReport(AuthServiceReportMsg),
}
