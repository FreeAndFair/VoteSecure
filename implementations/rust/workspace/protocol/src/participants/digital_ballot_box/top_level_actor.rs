// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Top-level actor for the Digital Ballot Box.
//!
//! This actor manages concurrent sessions and routes messages to the appropriate
//! sub-actors. It also handles EAS authorization messages and maintains persistent
//! state through the storage and bulletin board traits.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use super::bulletin_board::BulletinBoard;
use super::storage::DBBStorage;
use super::sub_actors::{
    casting::{CastingActor, CastingInput, CastingOutput, CastingState},
    checking::{CheckingActor, CheckingInput, CheckingOutput, CheckingState},
    submission::{SubmissionActor, SubmissionInput, SubmissionOutput, SubmissionState},
};

use crate::cryptography::{ElectionKey, SigningKey, VerifyingKey};
use crate::elections::{BallotTracker, ElectionHash};
use crate::messages::{AuthVoterMsg, ProtocolMessage};
use cryptography::utils::serialization::VSerializable;

use std::collections::HashMap;

// =============================================================================
// Message Wrappers
// =============================================================================

/// Incoming message with connection routing information.
///
/// The host application wraps protocol messages with a connection ID
/// so the DBB knows which session to route the message to.
#[derive(Debug, Clone)]
pub struct DBBIncomingMessage {
    pub connection_id: u64,
    pub message: ProtocolMessage,
}

/// Outgoing message with connection routing information.
///
/// The DBB wraps protocol messages with a connection ID so the host
/// application knows which connection to send the message on.
#[derive(Debug, Clone)]
pub struct DBBOutgoingMessage {
    pub connection_id: u64,
    pub message: ProtocolMessage,
}

/// Message from the Election Administration Server.
///
/// EAS messages don't need a connection ID because there's only one EAS
/// and these messages are stored directly without creating a session.
#[derive(Debug, Clone)]
pub struct EASMessage {
    pub message: AuthVoterMsg,
}

// =============================================================================
// Commands and I/O Types
// =============================================================================

/// Commands that can be sent to the Digital Ballot Box.
#[derive(Debug, Clone)]
pub enum Command {
    /// Process an authorization message from the EAS.
    ///
    /// This is stored directly in the voter authorization table
    /// without creating a session.
    ProcessEASAuthorization(AuthVoterMsg),

    /// Close a specific session by connection ID.
    ///
    /// This is used by the host to clean up sessions that are no
    /// longer needed (timeout, error, etc.).
    CloseSession(u64),

    /// List all active sessions.
    ///
    /// Returns information about all currently active sessions.
    ListSessions,

    /// Provide the VA connection ID for a ballot checking session.
    ///
    /// When the DBB receives a ballot check request from a BCA, it asks
    /// the host which VA connection should receive the forwarded request.
    /// The host responds with this command.
    ProvideVAConnection {
        checking_session_id: u64,
        va_connection_id: u64,
    },
}

/// Input to the Digital Ballot Box actor.
#[derive(Debug, Clone)]
pub enum ActorInput {
    /// A command from the host application.
    Command(Command),

    /// An incoming message from a connection.
    IncomingMessage(DBBIncomingMessage),

    /// A message from the Election Administration Server.
    EASMessage(EASMessage),
}

/// Output from the Digital Ballot Box actor.
#[derive(Debug, Clone)]
pub enum ActorOutput {
    /// A message to send on a specific connection.
    OutgoingMessage(DBBOutgoingMessage),

    /// Request the host to provide a VA connection ID for ballot checking.
    ///
    /// The DBB needs to know which VA connection to forward a ballot
    /// check request to. The host should respond with a ProvideVAConnection command.
    RequestVAConnection {
        tracker: BallotTracker,
        bca_connection_id: u64,
    },

    /// A session has been closed.
    SessionClosed(u64),

    /// List of all active sessions (response to ListSessions command).
    SessionList(Vec<SessionInfo>),

    /// An error occurred.
    Error(String),
}

// =============================================================================
// Session Management Types
// =============================================================================

/// Information about an active session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub connection_id: u64,
    pub session_type: SessionType,
    pub state: SessionState,
    pub voter_pseudonym: Option<String>,
    pub created_at: u64,
}

/// Type of session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Submission,
    Casting,
    Checking,
}

/// State of a session (wraps the actual sub-actor state enums).
#[derive(Debug, Clone)]
pub enum SessionState {
    Submission(SubmissionState),
    Casting(CastingState),
    Checking(CheckingState),
}

/// Active session variants.
///
/// Note: Only CheckingActor is stored as a session because it requires
/// multi-step protocol with waiting for host input (VA connection ID).
/// CastingActor and SubmissionActor are one-shot operations that complete
/// immediately without storing session state.
#[derive(Clone, Debug)]
pub enum ActiveSession {
    Checking(CheckingActor),
}

impl ActiveSession {
    /// Get the session type.
    pub fn session_type(&self) -> SessionType {
        match self {
            ActiveSession::Checking(_) => SessionType::Checking,
        }
    }

    /// Get the session state.
    pub fn session_state(&self) -> SessionState {
        match self {
            ActiveSession::Checking(actor) => SessionState::Checking(actor.get_state()),
        }
    }
}

// =============================================================================
// Top-Level Actor
// =============================================================================

/// The top-level Digital Ballot Box actor.
///
/// This actor manages concurrent sessions using a HashMap and routes messages
/// to the appropriate sub-actors. It also maintains persistent state through
/// the storage and bulletin board traits.
///
/// # Generic Parameters
/// * `S` - Storage implementation (must implement DBBStorage trait)
/// * `B` - Bulletin board implementation (must implement BulletinBoard trait)
#[derive(Clone, Debug)]
pub struct DigitalBallotBoxActor<S: DBBStorage, B: BulletinBoard> {
    // --- Session Management ---
    /// Maps connection IDs to active sessions.
    active_sessions: HashMap<u64, ActiveSession>,

    // --- Persistent State ---
    /// Storage for voter authorizations, submitted ballots, and cast ballots.
    storage: S,

    /// The public bulletin board containing the tamper-evident chain.
    bulletin_board: B,

    // --- Configuration ---
    /// The election hash for this election.
    election_hash: ElectionHash,

    /// The DBB's signing key for signing bulletins.
    dbb_signing_key: SigningKey,

    /// The DBB's verifying key (public key).
    _dbb_verifying_key: VerifyingKey,

    /// The EAS's verifying key for validating authorization messages.
    eas_verifying_key: VerifyingKey,

    /// The election public key for encrypting ballots.
    election_public_key: ElectionKey,
}

impl<S: DBBStorage, B: BulletinBoard> DigitalBallotBoxActor<S, B> {
    /// Create a new Digital Ballot Box actor.
    ///
    /// # Arguments
    /// * `storage` - Storage implementation
    /// * `bulletin_board` - Bulletin board implementation
    /// * `election_hash` - The election hash
    /// * `dbb_signing_key` - The DBB's signing key
    /// * `dbb_verifying_key` - The DBB's verifying key
    /// * `eas_verifying_key` - The EAS's verifying key
    /// * `election_public_key` - The election public key
    pub fn new(
        storage: S,
        bulletin_board: B,
        election_hash: ElectionHash,
        dbb_signing_key: SigningKey,
        dbb_verifying_key: VerifyingKey,
        eas_verifying_key: VerifyingKey,
        election_public_key: ElectionKey,
    ) -> Self {
        Self {
            active_sessions: HashMap::new(),
            storage,
            bulletin_board,
            election_hash,
            dbb_signing_key,
            _dbb_verifying_key: dbb_verifying_key,
            eas_verifying_key,
            election_public_key,
        }
    }

    /// Process an input to the Digital Ballot Box.
    ///
    /// This is the main entry point for all interactions with the DBB.
    ///
    /// # Arguments
    /// * `input` - The input to process
    ///
    /// # Returns
    /// * `Ok(output)` - The output from processing the input
    /// * `Err(msg)` - If an error occurs
    pub fn process_input(&mut self, input: ActorInput) -> Result<ActorOutput, String> {
        match input {
            ActorInput::Command(command) => self.handle_command(command),
            ActorInput::IncomingMessage(msg) => self.handle_incoming_message(msg),
            ActorInput::EASMessage(msg) => self.handle_eas_message(msg),
        }
    }

    // --- Command Handling ---

    /// Handle a command from the host application.
    fn handle_command(&mut self, command: Command) -> Result<ActorOutput, String> {
        match command {
            Command::ProcessEASAuthorization(_auth_msg) => {
                // This is handled via EASMessage input, not as a command
                Err("Use EASMessage input for authorization messages".to_string())
            }

            Command::CloseSession(connection_id) => {
                self.active_sessions.remove(&connection_id);
                Ok(ActorOutput::SessionClosed(connection_id))
            }

            Command::ListSessions => {
                let sessions = self.list_sessions();
                Ok(ActorOutput::SessionList(sessions))
            }

            Command::ProvideVAConnection {
                checking_session_id,
                va_connection_id,
            } => {
                // Forward the VA connection ID to the checking session
                // We need to temporarily remove the session to avoid borrow checker issues
                let mut session = self.active_sessions.remove(&checking_session_id);

                if let Some(ActiveSession::Checking(actor)) = &mut session {
                    let output = actor.process_input(
                        CheckingInput::VAConnectionProvided(va_connection_id),
                        &self.storage,
                        &self.bulletin_board,
                    )?;
                    let result = self.handle_checking_output(checking_session_id, output);

                    // Put the session back if not complete
                    if !matches!(result, Ok(ActorOutput::SessionClosed(_)))
                        && let Some(s) = session
                    {
                        self.active_sessions.insert(checking_session_id, s);
                    }

                    result
                } else {
                    // Put the session back if it exists but isn't a checking session
                    if let Some(s) = session {
                        self.active_sessions.insert(checking_session_id, s);
                    }
                    Err(format!(
                        "No checking session found with ID {}",
                        checking_session_id
                    ))
                }
            }
        }
    }

    /// Handle an EAS authorization message.
    fn handle_eas_message(&mut self, msg: EASMessage) -> Result<ActorOutput, String> {
        // Validate the authorization message signature
        let serialized = msg.message.data.ser();
        crate::cryptography::verify_signature(
            &serialized,
            &msg.message.signature,
            &self.eas_verifying_key,
        )
        .map_err(|_| "Invalid EAS signature on authorization message".to_string())?;

        // Validate the election hash
        if msg.message.data.election_hash != self.election_hash {
            return Err("Authorization message has incorrect election hash".to_string());
        }

        // Store the authorization directly (no session needed)
        let voter_pseudonym = msg.message.data.voter_pseudonym.clone();
        self.storage
            .store_voter_authorization(&voter_pseudonym, msg.message)?;

        // No output - this is a fire-and-forget operation
        Ok(ActorOutput::SessionClosed(0)) // Use 0 as a sentinel for "no connection"
    }

    /// Handle an incoming message from a connection.
    fn handle_incoming_message(&mut self, msg: DBBIncomingMessage) -> Result<ActorOutput, String> {
        // Check if there's an existing session for this connection
        if self.active_sessions.contains_key(&msg.connection_id) {
            // Route to existing session
            self.route_to_existing_session(msg.connection_id, msg.message)
        } else {
            // Create new session based on message type
            self.create_new_session(msg.connection_id, msg.message)
        }
    }

    /// Route a message to an existing session.
    ///
    /// Only CheckingActor sessions are stored, as they require multi-step
    /// protocols. Casting and Submission are one-shot operations.
    fn route_to_existing_session(
        &mut self,
        connection_id: u64,
        message: ProtocolMessage,
    ) -> Result<ActorOutput, String> {
        // We need to take the session out temporarily to avoid borrow checker issues
        let mut session = self
            .active_sessions
            .remove(&connection_id)
            .ok_or("Session not found")?;

        let result = match &mut session {
            ActiveSession::Checking(actor) => {
                let output = actor.process_input(
                    CheckingInput::NetworkMessage {
                        connection_id,
                        message,
                    },
                    &self.storage,
                    &self.bulletin_board,
                )?;
                self.handle_checking_output(connection_id, output)
            }
        };

        // Put the session back if it's not complete
        if !matches!(result, Ok(ActorOutput::SessionClosed(_))) {
            self.active_sessions.insert(connection_id, session);
        }

        result
    }

    /// Create a new session based on the first message received.
    ///
    /// Submission and Casting operations are one-shot and complete immediately
    /// without storing session state. Only Checking operations require multi-step
    /// protocol and are stored as active sessions.
    fn create_new_session(
        &mut self,
        connection_id: u64,
        message: ProtocolMessage,
    ) -> Result<ActorOutput, String> {
        match &message {
            ProtocolMessage::SubmitSignedBallot(_) => {
                // One-shot operation: create actor, process, return result
                // No session storage needed
                let mut actor = SubmissionActor::new(
                    self.election_hash,
                    self.dbb_signing_key.clone(),
                    self.election_public_key.clone(),
                );

                let output = actor.process_input(
                    SubmissionInput::NetworkMessage(message),
                    &mut self.storage,
                    &mut self.bulletin_board,
                )?;

                self.handle_submission_output(connection_id, output)
            }

            ProtocolMessage::CastReq(_) => {
                // One-shot operation: create actor, process, return result
                // No session storage needed
                let mut actor = CastingActor::new(self.election_hash, self.dbb_signing_key.clone());

                let output = actor.process_input(
                    CastingInput::NetworkMessage(message),
                    &mut self.storage,
                    &mut self.bulletin_board,
                )?;

                self.handle_casting_output(connection_id, output)
            }

            ProtocolMessage::CheckReq(_) => {
                // Multi-step operation: create actor, process, store session if not complete
                let mut actor = CheckingActor::new(
                    connection_id,
                    self.election_hash,
                    self.dbb_signing_key.clone(),
                );

                let output = actor.process_input(
                    CheckingInput::NetworkMessage {
                        connection_id,
                        message,
                    },
                    &self.storage,
                    &self.bulletin_board,
                )?;
                let result = self.handle_checking_output(connection_id, output)?;

                // Store session if not complete
                if !matches!(result, ActorOutput::SessionClosed(_)) {
                    self.active_sessions
                        .insert(connection_id, ActiveSession::Checking(actor));
                }

                Ok(result)
            }

            _ => Err(format!(
                "Cannot create session for message type: {:?}",
                message
            )),
        }
    }

    // --- Sub-Actor Output Handling ---

    /// Handle output from submission actor (one-shot operation, no session storage).
    fn handle_submission_output(
        &mut self,
        connection_id: u64,
        output: SubmissionOutput,
    ) -> Result<ActorOutput, String> {
        match output {
            SubmissionOutput::SendMessage(msg) => {
                Ok(ActorOutput::OutgoingMessage(DBBOutgoingMessage {
                    connection_id,
                    message: msg,
                }))
            }
            SubmissionOutput::Success => Ok(ActorOutput::SessionClosed(connection_id)),
            SubmissionOutput::Failure(err) => Err(err),
        }
    }

    /// Handle output from casting actor (one-shot operation, no session storage).
    fn handle_casting_output(
        &mut self,
        connection_id: u64,
        output: CastingOutput,
    ) -> Result<ActorOutput, String> {
        match output {
            CastingOutput::SendMessage(msg) => {
                Ok(ActorOutput::OutgoingMessage(DBBOutgoingMessage {
                    connection_id,
                    message: msg,
                }))
            }
            CastingOutput::Success => Ok(ActorOutput::SessionClosed(connection_id)),
            CastingOutput::Failure(err) => Err(err),
        }
    }

    fn handle_checking_output(
        &mut self,
        connection_id: u64,
        output: CheckingOutput,
    ) -> Result<ActorOutput, String> {
        match output {
            CheckingOutput::SendMessage {
                connection_id: target_conn_id,
                message,
            } => Ok(ActorOutput::OutgoingMessage(DBBOutgoingMessage {
                connection_id: target_conn_id,
                message,
            })),
            CheckingOutput::RequestVAConnection(tracker) => Ok(ActorOutput::RequestVAConnection {
                tracker,
                bca_connection_id: connection_id,
            }),
            CheckingOutput::Success => {
                self.active_sessions.remove(&connection_id);
                Ok(ActorOutput::SessionClosed(connection_id))
            }
            CheckingOutput::Failure(err) => {
                self.active_sessions.remove(&connection_id);
                Err(err)
            }
        }
    }

    // --- Session Information ---

    fn list_sessions(&self) -> Vec<SessionInfo> {
        self.active_sessions
            .iter()
            .map(|(conn_id, session)| {
                let voter_pseudonym = None; // TODO: Extract from session state if available
                SessionInfo {
                    connection_id: *conn_id,
                    session_type: session.session_type(),
                    state: session.session_state(),
                    voter_pseudonym,
                    created_at: 0, // TODO: Add timestamp tracking
                }
            })
            .collect()
    }

    // --- Test API ---

    /// Returns a reference to the bulletin board for testing purposes,
    /// to allow tests to verify predicates about its contents.
    #[cfg(test)]
    pub(crate) fn bulletin_board(&self) -> &B {
        &self.bulletin_board
    }

    /// Returns a reference to the storage for testing purposes,
    /// to allow tests to verify predicates about stored data.
    #[cfg(test)]
    pub(crate) fn storage(&self) -> &S {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::generate_signature_keypair;
    use crate::elections::string_to_election_hash;
    use crate::participants::digital_ballot_box::{InMemoryBulletinBoard, InMemoryStorage};

    fn create_test_dbb() -> DigitalBallotBoxActor<InMemoryStorage, InMemoryBulletinBoard> {
        let storage = InMemoryStorage::new();
        let bulletin_board = InMemoryBulletinBoard::new();
        let (dbb_signing_key, dbb_verifying_key) = generate_signature_keypair();
        let (_, eas_verifying_key) = generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();

        DigitalBallotBoxActor::new(
            storage,
            bulletin_board,
            string_to_election_hash("test_election"),
            dbb_signing_key,
            dbb_verifying_key,
            eas_verifying_key,
            election_keypair.pkey,
        )
    }

    #[test]
    fn test_dbb_creation() {
        let dbb = create_test_dbb();
        assert_eq!(dbb.active_sessions.len(), 0);
    }

    #[test]
    fn test_list_empty_sessions() {
        let mut dbb = create_test_dbb();
        let result = dbb.process_input(ActorInput::Command(Command::ListSessions));
        assert!(result.is_ok());
        if let Ok(ActorOutput::SessionList(sessions)) = result {
            assert_eq!(sessions.len(), 0);
        } else {
            panic!("Expected SessionList output");
        }
    }

    #[test]
    fn test_close_nonexistent_session() {
        let mut dbb = create_test_dbb();
        let result = dbb.process_input(ActorInput::Command(Command::CloseSession(999)));
        assert!(result.is_ok());
        if let Ok(ActorOutput::SessionClosed(conn_id)) = result {
            assert_eq!(conn_id, 999);
        } else {
            panic!("Expected SessionClosed output");
        }
    }
}
