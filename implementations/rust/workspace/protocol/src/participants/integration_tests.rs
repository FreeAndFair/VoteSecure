// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Stateright-based integration tests for voter-facing protocol actors.
//!
//! This module uses Stateright model checking to exhaustively test the
//! interactions among the Internet-facing protocols.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]
#[cfg(test)]
mod tests {
    const TRACE: bool = false;

    /// Trace helper; only prints when TRACE is true.
    fn trace_print(msg: impl std::fmt::Display) {
        if TRACE {
            eprintln!("{}", msg);
        }
    }

    use crate::auth_service::{
        AuthServiceMessage, AuthServiceQueryMsg, AuthServiceReportMsg, InitAuthReqMsg,
        TokenReturnMsg,
    };
    use crate::bulletins::Bulletin;
    use crate::cryptography::{
        Context, CryptographyContext, ElectionKey, SigningKey, VerifyingKey,
    };
    use crate::elections::{
        Ballot, BallotStyle, ElectionHash, VoterPseudonym, string_to_election_hash,
    };
    use crate::messages::ProtocolMessage;
    use crate::participants::ballot_check_application::sub_actors::ballot_check::{
        BallotCheckInput, BallotCheckOutput,
    };
    use crate::participants::ballot_check_application::top_level_actor::{
        ActorInput as BCAInput, Command as BCACommand, SubprotocolInput as BCASubprotocolInput,
        SubprotocolOutput as BCASubprotocolOutput, TopLevelActor as BCAActor,
    };
    use crate::participants::digital_ballot_box::{
        ActorInput as DBBInput, ActorOutput as DBBOutput, BulletinBoard, Command as DBBCommand,
        DBBIncomingMessage, DigitalBallotBoxActor, EASMessage, InMemoryBulletinBoard,
        InMemoryStorage,
    };
    use crate::participants::election_admin_server::sub_actors::voter_authentication::{
        VoterAuthenticationInput, VoterAuthenticationOutput,
    };
    use crate::participants::election_admin_server::top_level_actor::{
        ActorInput as EASInput, AuthReqId, Command as EASCommand,
        SubprotocolInput as EASSubprotocolInput, SubprotocolOutput as EASSubprotocolOutput,
        TopLevelActor as EASActor,
    };
    use crate::participants::voting_application::sub_actors::authentication::{
        AuthenticationInput, AuthenticationOutput,
    };
    use crate::participants::voting_application::sub_actors::casting::{
        CastingInput, CastingOutput,
    };
    use crate::participants::voting_application::sub_actors::checking::{
        BallotCheckOutcome, CheckingInput, CheckingOutput,
    };
    use crate::participants::voting_application::sub_actors::submission::{
        SubmissionInput, SubmissionOutput,
    };
    use crate::participants::voting_application::top_level_actor::{
        ActorInput as VAInput, Command as VACommand, SubprotocolInput as VASubprotocolInput,
        SubprotocolOutput as VASubprotocolOutput, TopLevelActor as VAActor,
    };
    use stateright::{Checker, Model, Property};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::hash::{Hash, Hasher};

    const MANIFEST: &str = "test_election_manifest";

    /// Get the number of threads to use for Stateright model checking.
    /// Returns the number of available CPUs, or 1 if that cannot be determined.
    fn get_thread_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    /// Configuration parameters for the Stateright model
    #[derive(Clone, Debug)]
    struct ModelConfig {
        /// Maximum number of concurrent voter sessions
        max_concurrent_sessions: usize,
        /// Number of voters who must successfully cast a ballot (completion goal)
        num_voters_to_complete: usize,
        /// Total number of voter IDs in the registration database
        num_registered_voters: usize,
        /// Maximum total number of ballot checks across all voters
        max_total_checks: usize,
        /// Maximum total number of resubmissions across all voters
        max_total_resubmissions: usize,
        /// Maximum number of sessions that can be abandoned
        max_abandoned_sessions: usize,
        /// Maximum number of authentication failures
        max_auth_failures: usize,
        /// Maximum number of eligibility failures
        max_eligibility_failures: usize,
        /// Maximum number of "already voted" attempts (sessions that try to vote after already voting)
        max_already_voted_attempts: usize,
    }

    /// Unique ID for a voter session in the model
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    struct SessionId(usize);

    /// Predetermined profile for a voter session that determines its execution path.
    /// This eliminates the combinatorial explosion from branching at EAS authorization
    /// by deciding session outcomes at creation time.
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
    enum SessionProfile {
        /// Successful authentication and authorization, voter will cast ballot.
        /// Uses deterministically assigned voter_id (first unallocated, not already voted).
        SuccessfulVoter,
        /// Successful authentication and authorization, but voter has already voted.
        /// Uses deterministically assigned voter_id (first one that has already voted).
        AlreadyVotedVoter,
        /// Authentication fails at AS (AS rejects auth request).
        AuthenticationFailed,
        /// Authentication succeeds but authorization fails at EAS.
        AuthorizationFailed,
    }

    /// Messages that can be in a VA's inbox
    #[derive(Clone, Debug)]
    enum VAMessage {
        Command(VACommand),
        SubprotocolInput(VASubprotocolInput),
    }

    /// Messages that can be in a BCA's inbox
    #[derive(Clone, Debug)]
    enum BCAMessage {
        Command(BCACommand),
        SubprotocolInput(BCASubprotocolInput),
    }

    /// Messages pending delivery to mock actors
    #[derive(Clone, Debug)]
    struct PendingMessages {
        /// Messages from VA/BCA that need to be delivered to EAS
        /// Each session has its own FIFO queue to preserve message ordering within that session
        to_eas: BTreeMap<SessionId, VecDeque<ProtocolMessage>>,
        /// Messages from VA/BCA that need to be delivered to DBB
        /// Each session has its own FIFO queue to preserve message ordering within that session
        to_dbb: BTreeMap<SessionId, VecDeque<ProtocolMessage>>,
        /// AuthService messages from EAS that need AS response
        to_as_service: Vec<(AuthReqId, AuthServiceMessage)>,
        /// Biographical info checks from EAS that need protocol driver decision
        bio_info_checks: Vec<(AuthReqId, AuthServiceReportMsg)>,
    }

    impl PendingMessages {
        fn new() -> Self {
            Self {
                to_eas: BTreeMap::new(),
                to_dbb: BTreeMap::new(),
                to_as_service: Vec::new(),
                bio_info_checks: Vec::new(),
            }
        }

        #[allow(dead_code)]
        fn is_empty(&self) -> bool {
            self.to_eas.is_empty()
                && self.to_dbb.is_empty()
                && self.to_as_service.is_empty()
                && self.bio_info_checks.is_empty()
        }

        /// Check if there are any pending messages for a specific voter
        fn has_messages_for(
            &self,
            session_id: SessionId,
            auth_req_to_voter: &std::collections::BTreeMap<AuthReqId, SessionId>,
        ) -> bool {
            self.to_eas.contains_key(&session_id)
                || self.to_dbb.contains_key(&session_id)
                || self
                    .to_as_service
                    .iter()
                    .any(|(auth_req_id, _)| auth_req_to_voter.get(auth_req_id) == Some(&session_id))
                || self
                    .bio_info_checks
                    .iter()
                    .any(|(auth_req_id, _)| auth_req_to_voter.get(auth_req_id) == Some(&session_id))
        }
    }

    /// Mock Authentication Server - handles voter authentication only
    #[derive(Clone, Debug)]
    struct MockAS {
        next_session_id: u64,
        /// Maps session_id -> (token, biographical_info, profile)
        sessions: BTreeMap<String, (String, String, SessionProfile)>,
    }

    impl MockAS {
        fn new() -> Self {
            Self {
                next_session_id: 0,
                sessions: BTreeMap::new(),
            }
        }

        /// Handle InitAuthReqMsg from EAS - create authentication session
        /// The profile determines how this session will be authenticated
        fn handle_init_auth_req(
            &mut self,
            _msg: InitAuthReqMsg,
            profile: SessionProfile,
        ) -> TokenReturnMsg {
            let session_id = format!("session_{}", self.next_session_id);
            let token = format!("token_{}", self.next_session_id);
            self.next_session_id += 1;

            // Store session with profile to determine authentication result later
            let biographical_info = format!("bio_info_for_{}", token);
            self.sessions.insert(
                session_id.clone(),
                (token.clone(), biographical_info, profile),
            );

            TokenReturnMsg { token, session_id }
        }

        /// Handle AuthServiceQueryMsg from EAS - return authentication results
        /// Returns authenticated=false for sessions with AuthenticationFailed profile
        fn handle_query(&self, msg: AuthServiceQueryMsg) -> Result<AuthServiceReportMsg, String> {
            let session_data = self
                .sessions
                .get(&msg.session_id)
                .ok_or_else(|| format!("Session {} not found", msg.session_id))?
                .clone();

            let token = session_data.0;
            let biographical_info = session_data.1;
            let profile = session_data.2;

            // Check profile to determine authentication result
            let authenticated = match profile {
                SessionProfile::AuthenticationFailed => false,
                _ => true,
            };

            Ok(AuthServiceReportMsg {
                token,
                session_id: msg.session_id,
                biographical_info: Some(biographical_info),
                authenticated,
            })
        }
    }

    /// Which VA subprotocol is currently active
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
    enum VASubprotocolState {
        Idle,
        Authenticating,
        Submitting,
        Casting,
        Checking,
    }

    /// State for a single voter session
    #[derive(Clone, Debug)]
    struct VoterSessionState {
        /// The VA actor for this voter
        va: VAActor,

        /// Optional BCA actor (created when voter checks ballot)
        bca: Option<BCAActor>,

        /// VA's message inbox
        va_inbox: Vec<VAMessage>,

        /// BCA's message inbox
        bca_inbox: Vec<BCAMessage>,

        /// Predetermined profile determining this session's execution path
        profile: SessionProfile,

        /// Which registered voter ID this session was assigned (after authorization)
        assigned_voter_id: Option<usize>,

        /// Number of times this voter has checked their ballot
        check_count: usize,

        /// Number of times this voter has resubmitted
        resubmission_count: usize,

        /// Whether this voter has successfully cast
        has_cast: bool,

        /// Whether this session was abandoned
        is_abandoned: bool,

        /// Whether authentication failed for this session
        auth_failed: bool,

        /// Whether eligibility check failed for this session
        eligibility_failed: bool,

        /// Whether submission failed because voter already voted
        already_voted_failure: bool,

        /// Whether submission failed due to missing authorization
        unauthorized_submission_failure: bool,

        /// Whether submission failed for other reasons
        other_failure: bool,

        /// Whether casting failed
        casting_failure: bool,

        /// Whether check approval is pending from user
        check_approval_pending: bool,

        /// Whether third-party auth completion is pending from user
        third_party_auth_pending: bool,

        /// Track which VA subprotocol is active for proper state hashing
        va_subprotocol_state: VASubprotocolState,

        /// Unique ID for this VA actor (incremented globally)
        _va_id: u64,

        /// Running hash of all inputs processed by this VA
        va_trace_hash: u64,

        /// Optional unique ID for BCA actor (when created)
        bca_id: Option<u64>,

        /// Running hash of all inputs processed by BCA (when it exists)
        bca_trace_hash: u64,
    }

    impl VoterSessionState {
        fn new(va: VAActor, va_id: u64, profile: SessionProfile) -> Self {
            Self {
                va,
                bca: None,
                va_inbox: Vec::new(),
                bca_inbox: Vec::new(),
                profile,
                assigned_voter_id: None,
                check_count: 0,
                resubmission_count: 0,
                has_cast: false,
                is_abandoned: false,
                auth_failed: false,
                eligibility_failed: false,
                already_voted_failure: false,
                unauthorized_submission_failure: false,
                other_failure: false,
                casting_failure: false,
                check_approval_pending: false,
                third_party_auth_pending: false,
                va_subprotocol_state: VASubprotocolState::Idle,
                _va_id: va_id,
                va_trace_hash: 0,
                bca_id: None,
                bca_trace_hash: 0,
            }
        }

        /// Check if this session is in a terminal state
        fn is_terminal(&self) -> bool {
            let terminal = self.has_cast
                || self.is_abandoned
                || self.auth_failed
                || self.eligibility_failed
                || self.already_voted_failure
                || self.unauthorized_submission_failure
                || self.other_failure
                || self.casting_failure;
            if terminal && self.va.ballot_tracker().is_some() {
                trace_print(format!(
                    "Session with tracker {:?} is NOW TERMINAL: has_cast={}, abandoned={}, auth_failed={}, elig_failed={}",
                    self.va.ballot_tracker(),
                    self.has_cast,
                    self.is_abandoned,
                    self.auth_failed,
                    self.eligibility_failed
                ));
            }
            terminal
        }
    }

    /// Global state for the Stateright model
    #[derive(Clone, Debug)]
    struct IntegrationState {
        config: ModelConfig,
        has_failure: bool,

        // Election parameters
        election_hash: ElectionHash,

        // Voter session states (map of SessionId -> session state)
        // Only active sessions are kept; terminal sessions are removed to save memory
        voter_sessions: BTreeMap<SessionId, VoterSessionState>,

        // Next session ID to assign when creating a new session
        next_session_id: usize,

        // Shared mock actors
        as_server: MockAS,
        eas: EASActor,

        // Real DBB
        dbb: DigitalBallotBoxActor<InMemoryStorage, InMemoryBulletinBoard>,

        // Connection routing infrastructure for DBB
        next_connection_id: u64,
        va_connection_ids: BTreeMap<SessionId, u64>,
        va_to_bca_session: BTreeMap<u64, u64>,

        // Pending messages to be delivered
        pending_messages: PendingMessages,

        // Map SessionId -> AuthReqId for tracking EAS authentication sessions
        pending_auth_requests: BTreeMap<SessionId, AuthReqId>,
        // Reverse map: AuthReqId -> SessionId for routing responses back
        auth_req_to_voter: BTreeMap<AuthReqId, SessionId>,

        // Resource usage counters
        total_checks_used: usize,
        total_resubmissions_used: usize,
        total_ballots_generated: usize, // Counter for deterministic ballot seed generation
        abandoned_sessions: usize,
        auth_failures: usize,
        eligibility_failures: usize,
        already_voted_attempts: usize,
        already_voted_failures: usize,
        unauthorized_submission_failures: usize,
        other_failures: usize,
        casting_failures: usize,
        completed_voters: usize,
        trackers_assigned: usize, // Debug: count how many trackers are assigned
        eas_authorize_attempts: usize, // Debug: count how many times EAS authorization is attempted

        // Keys
        election_key: ElectionKey,
        dbb_verifying_key: VerifyingKey,
        eas_verifying_key: VerifyingKey,

        // Actor ID tracking for unique identification
        next_actor_id: u64,
    }

    /// Implement Hash for IntegrationState
    impl Hash for IntegrationState {
        fn hash<H: Hasher>(&self, state: &mut H) {
            // Hash configuration
            self.config.num_voters_to_complete.hash(state);
            self.config.num_registered_voters.hash(state);

            // Hash resource counters
            self.total_checks_used.hash(state);
            self.total_resubmissions_used.hash(state);
            self.total_ballots_generated.hash(state);
            self.abandoned_sessions.hash(state);
            self.auth_failures.hash(state);
            self.eligibility_failures.hash(state);
            self.already_voted_attempts.hash(state);
            self.already_voted_failures.hash(state);
            self.unauthorized_submission_failures.hash(state);
            self.other_failures.hash(state);
            self.casting_failures.hash(state);
            self.completed_voters.hash(state);
            self.trackers_assigned.hash(state);
            self.eas_authorize_attempts.hash(state);

            // Hash bulletin board state (from DBB)
            // Hash semantically relevant bulletin contents (voter pseudonym and ballot style)
            // to distinguish states, not cryptographic/timing details
            let bulletins = self.dbb.bulletin_board().get_all_bulletins();
            bulletins.len().hash(state);
            for bulletin in bulletins {
                std::mem::discriminant(&bulletin).hash(state);
                match bulletin {
                    Bulletin::BallotSubmission(sub) => {
                        sub.data.ballot.data.voter_pseudonym.hash(state);
                        sub.data.ballot.data.ballot_style.hash(state);
                    }
                    Bulletin::VoterAuthorization(auth) => {
                        auth.data.authorization.data.voter_pseudonym.hash(state);
                        auth.data.authorization.data.ballot_style.hash(state);
                    }
                    Bulletin::BallotCast(cast) => {
                        cast.data.ballot.data.voter_pseudonym.hash(state);
                        cast.data.ballot.data.ballot_style.hash(state);
                    }
                }
            }

            // Hash AS state (session counter and active sessions)
            self.as_server.next_session_id.hash(state);
            self.as_server.sessions.len().hash(state);
            for (session_id, (token, bio_info, profile)) in &self.as_server.sessions {
                session_id.hash(state);
                token.hash(state);
                bio_info.hash(state);
                profile.hash(state);
            }

            // Hash DBB state (simplified - just counts and sets)
            self.dbb
                .storage()
                .test_count_authorized_voters()
                .hash(state);
            self.dbb
                .storage()
                .test_count_submitted_ballots()
                .hash(state);
            self.dbb.storage().test_voters_who_cast().hash(state);

            // Hash voter session states
            // Iterate over BTreeMap values in sorted order by SessionId
            for session in self.voter_sessions.values() {
                session.profile.hash(state);
                session.assigned_voter_id.hash(state);
                // Hash whether VA has completed authentication (via voter_pseudonym)
                session.va.voter_pseudonym().is_some().hash(state);
                // Hash whether tracker exists, not its value (tracker is cryptographically-derived and varies)
                session.va.ballot_tracker().is_some().hash(state);
                session.check_count.hash(state);
                session.resubmission_count.hash(state);
                session.has_cast.hash(state);
                session.is_abandoned.hash(state);
                session.auth_failed.hash(state);
                session.eligibility_failed.hash(state);
                session.already_voted_failure.hash(state);
                session.unauthorized_submission_failure.hash(state);
                session.other_failure.hash(state);
                session.casting_failure.hash(state);
                session.check_approval_pending.hash(state);
                session.third_party_auth_pending.hash(state);
                session.va_subprotocol_state.hash(state);
                // Hash whether VA has randomizers (via ballot_randomizers)
                session.va.ballot_randomizers().is_some().hash(state);
                // Note: va_id, va_trace_hash, bca_id, bca_trace_hash are intentionally NOT hashed.
                // These track execution history/order, not semantic state. States with the same
                // session flags, counters, and pending messages are functionally equivalent
                // regardless of actor IDs or the order in which actions were taken.

                // Hash VA inbox - both length and message types
                session.va_inbox.len().hash(state);
                for msg in &session.va_inbox {
                    std::mem::discriminant(msg).hash(state);
                    // Also hash inner discriminants for subprotocol inputs
                    if let VAMessage::SubprotocolInput(sub_input) = msg {
                        std::mem::discriminant(sub_input).hash(state);
                        // For submission inputs, hash the specific variant
                        if let VASubprotocolInput::Submission(s_input) = sub_input {
                            std::mem::discriminant(s_input).hash(state);
                        }
                    }
                }

                // Hash BCA inbox - both length and message types
                session.bca_inbox.len().hash(state);
                for msg in &session.bca_inbox {
                    std::mem::discriminant(msg).hash(state);
                }
            }

            // Hash pending messages - both length and message types
            // BTreeMap iteration is deterministic (ordered by SessionId)
            self.pending_messages.to_eas.len().hash(state);
            for (session_id, queue) in &self.pending_messages.to_eas {
                session_id.hash(state);
                queue.len().hash(state);
                for msg in queue {
                    Self::hash_protocol_message(msg, state);
                }
            }

            self.pending_messages.to_dbb.len().hash(state);
            for (session_id, queue) in &self.pending_messages.to_dbb {
                session_id.hash(state);
                queue.len().hash(state);
                for msg in queue {
                    Self::hash_protocol_message(msg, state);
                }
            }

            // Hash AS service messages
            self.pending_messages.to_as_service.len().hash(state);
            for (auth_req_id, as_msg) in &self.pending_messages.to_as_service {
                auth_req_id.hash(state);
                std::mem::discriminant(as_msg).hash(state);
            }

            // Hash biographical info checks
            self.pending_messages.bio_info_checks.len().hash(state);
            for (auth_req_id, _report) in &self.pending_messages.bio_info_checks {
                auth_req_id.hash(state);
                // Don't hash report details, just presence
            }

            // Hash auth request mappings
            self.pending_auth_requests.len().hash(state);
            for (session_id, auth_req_id) in &self.pending_auth_requests {
                session_id.hash(state);
                auth_req_id.hash(state);
            }

            // Hash reverse auth request mapping
            self.auth_req_to_voter.len().hash(state);
            for (auth_req_id, session_id) in &self.auth_req_to_voter {
                auth_req_id.hash(state);
                session_id.hash(state);
            }

            self.has_failure.hash(state);

            // Note: next_actor_id is intentionally NOT hashed - it's an implementation detail
            // that tracks actor creation order, not semantic state. Two states with different
            // next_actor_id values but otherwise identical structure are functionally equivalent.
        }
    }

    impl PartialEq for IntegrationState {
        fn eq(&self, other: &Self) -> bool {
            // Compare key state components including message queues
            self.completed_voters == other.completed_voters
                && self.total_checks_used == other.total_checks_used
                && self.total_resubmissions_used == other.total_resubmissions_used
                && self.total_ballots_generated == other.total_ballots_generated
                && self.abandoned_sessions == other.abandoned_sessions
                && self.auth_failures == other.auth_failures
                && self.eligibility_failures == other.eligibility_failures
                && self.already_voted_attempts == other.already_voted_attempts
                && self.already_voted_failures == other.already_voted_failures
                && self.unauthorized_submission_failures == other.unauthorized_submission_failures
                && self.other_failures == other.other_failures
                && self.casting_failures == other.casting_failures
                && self.trackers_assigned == other.trackers_assigned
                && self.eas_authorize_attempts == other.eas_authorize_attempts
                && self.as_server.next_session_id == other.as_server.next_session_id
                && self.as_server.sessions.len() == other.as_server.sessions.len()
                && self.as_server.sessions == other.as_server.sessions
                && self.dbb.storage().test_voters_who_cast() == other.dbb.storage().test_voters_who_cast()
                && self.dbb.bulletin_board().get_all_bulletins().len() == other.dbb.bulletin_board().get_all_bulletins().len()
                && self.bulletins_eq(&other)
                && self.voter_sessions.len() == other.voter_sessions.len()
                && self
                    .voter_sessions
                    .iter()
                    .all(|(session_id, a)| {
                        other.voter_sessions.get(session_id).is_some_and(|b| {
                        a.profile == b.profile
                            && a.assigned_voter_id == b.assigned_voter_id
                            // Compare VA authentication state via voter_pseudonym
                            && a.va.voter_pseudonym().is_some() == b.va.voter_pseudonym().is_some()
                            // Compare whether tracker exists, not its value (tracker is cryptographically-derived)
                            && a.va.ballot_tracker().is_some() == b.va.ballot_tracker().is_some()
                            && a.has_cast == b.has_cast
                            && a.is_abandoned == b.is_abandoned
                            && a.auth_failed == b.auth_failed
                            && a.eligibility_failed == b.eligibility_failed
                            && a.already_voted_failure == b.already_voted_failure
                            && a.unauthorized_submission_failure == b.unauthorized_submission_failure
                            && a.other_failure == b.other_failure
                            && a.casting_failure == b.casting_failure
                            && a.check_approval_pending == b.check_approval_pending
                            && a.third_party_auth_pending == b.third_party_auth_pending
                            && a.va_subprotocol_state == b.va_subprotocol_state
                            // Compare VA randomizers state
                            && a.va.ballot_randomizers().is_some() == b.va.ballot_randomizers().is_some()
                            // Note: va_id, va_trace_hash, bca_id, bca_trace_hash intentionally NOT compared.
                            // These track execution history, not semantic state equivalence.
                            && a.va_inbox.len() == b.va_inbox.len()
                            && a.bca_inbox.len() == b.bca_inbox.len()
                            && a.va_inbox.iter().zip(&b.va_inbox).all(|(ma, mb)| {
                                if std::mem::discriminant(ma) != std::mem::discriminant(mb) {
                                    return false;
                                }
                                // Also compare inner discriminants for subprotocol inputs
                                match (ma, mb) {
                                    (VAMessage::SubprotocolInput(sa), VAMessage::SubprotocolInput(sb)) => {
                                        if std::mem::discriminant(sa) != std::mem::discriminant(sb) {
                                            return false;
                                        }
                                        // For submission inputs, compare the specific variant
                                        match (sa, sb) {
                                            (VASubprotocolInput::Submission(ssa), VASubprotocolInput::Submission(ssb)) => {
                                                std::mem::discriminant(ssa) == std::mem::discriminant(ssb)
                                            }
                                            _ => true,
                                        }
                                    }
                                    _ => true,
                                }
                            })
                            && a.bca_inbox.iter().zip(&b.bca_inbox).all(|(ma, mb)| {
                                std::mem::discriminant(ma) == std::mem::discriminant(mb)
                            })
                        })
                    })
                && self.pending_messages.to_eas.len() == other.pending_messages.to_eas.len()
                && self
                    .pending_messages
                    .to_eas
                    .iter()
                    .all(|(session_id, queue_a)| {
                        other.pending_messages.to_eas.get(session_id).is_some_and(|queue_b| {
                            queue_a.len() == queue_b.len()
                                && queue_a.iter().zip(queue_b).all(|(ma, mb)| Self::protocol_messages_eq(ma, mb))
                        })
                    })
                && self.pending_messages.to_dbb.len() == other.pending_messages.to_dbb.len()
                && self
                    .pending_messages
                    .to_dbb
                    .iter()
                    .all(|(session_id, queue_a)| {
                        other.pending_messages.to_dbb.get(session_id).is_some_and(|queue_b| {
                            queue_a.len() == queue_b.len()
                                && queue_a.iter().zip(queue_b).all(|(ma, mb)| Self::protocol_messages_eq(ma, mb))
                        })
                    })
                && self.pending_messages.to_as_service.len()
                    == other.pending_messages.to_as_service.len()
                && self
                    .pending_messages
                    .to_as_service
                    .iter()
                    .zip(&other.pending_messages.to_as_service)
                    .all(|((ida, ma), (idb, mb))| {
                        ida == idb && std::mem::discriminant(ma) == std::mem::discriminant(mb)
                    })
                && self.pending_messages.bio_info_checks.len()
                    == other.pending_messages.bio_info_checks.len()
                && self
                    .pending_messages
                    .bio_info_checks
                    .iter()
                    .zip(&other.pending_messages.bio_info_checks)
                    .all(|((ida, _), (idb, _))| ida == idb)
                && self.pending_auth_requests.len() == other.pending_auth_requests.len()
                && self
                    .pending_auth_requests
                    .iter()
                    .zip(&other.pending_auth_requests)
                    .all(|((va, ida), (vb, idb))| va == vb && ida == idb)
                && self.auth_req_to_voter.len() == other.auth_req_to_voter.len()
                && self
                    .auth_req_to_voter
                    .iter()
                    .zip(&other.auth_req_to_voter)
                    .all(|((ida, va), (idb, vb))| ida == idb && va == vb)
            // Note: next_actor_id intentionally NOT compared - it's an implementation detail
            // tracking creation order, not semantic state equivalence.
        }
    }

    impl IntegrationState {
        /// Helper to hash a ProtocolMessage by its variant
        fn hash_protocol_message<H: std::hash::Hasher>(msg: &ProtocolMessage, state: &mut H) {
            std::mem::discriminant(msg).hash(state);
        }

        /// Helper to get an orderable value for a ProtocolMessage variant
        #[allow(dead_code)]
        fn message_variant_order(msg: &ProtocolMessage) -> u8 {
            match msg {
                ProtocolMessage::AuthReq(_) => 0,
                ProtocolMessage::AuthFinish(_) => 1,
                ProtocolMessage::SubmitSignedBallot(_) => 2,
                ProtocolMessage::CastReq(_) => 3,
                ProtocolMessage::CheckReq(_) => 4,
                ProtocolMessage::Randomizer(_) => 5,
                _ => 255,
            }
        }

        /// Helper to compare ProtocolMessages by their variant
        fn protocol_messages_eq(a: &ProtocolMessage, b: &ProtocolMessage) -> bool {
            std::mem::discriminant(a) == std::mem::discriminant(b)
        }

        /// Helper to compare bulletin boards by semantically relevant contents
        /// (voter pseudonyms and ballot styles, not cryptographic/timing details)
        fn bulletins_eq(&self, other: &Self) -> bool {
            let self_bulletins = self.dbb.bulletin_board().get_all_bulletins();
            let other_bulletins = other.dbb.bulletin_board().get_all_bulletins();

            if self_bulletins.len() != other_bulletins.len() {
                return false;
            }

            self_bulletins
                .iter()
                .zip(other_bulletins.iter())
                .all(|(a, b)| {
                    // First check if bulletin types match
                    if std::mem::discriminant(a) != std::mem::discriminant(b) {
                        return false;
                    }

                    // Then compare semantically relevant fields
                    match (a, b) {
                        (Bulletin::BallotSubmission(a_sub), Bulletin::BallotSubmission(b_sub)) => {
                            a_sub.data.ballot.data.voter_pseudonym
                                == b_sub.data.ballot.data.voter_pseudonym
                                && a_sub.data.ballot.data.ballot_style
                                    == b_sub.data.ballot.data.ballot_style
                        }
                        (
                            Bulletin::VoterAuthorization(a_auth),
                            Bulletin::VoterAuthorization(b_auth),
                        ) => {
                            a_auth.data.authorization.data.voter_pseudonym
                                == b_auth.data.authorization.data.voter_pseudonym
                                && a_auth.data.authorization.data.ballot_style
                                    == b_auth.data.authorization.data.ballot_style
                        }
                        (Bulletin::BallotCast(a_cast), Bulletin::BallotCast(b_cast)) => {
                            a_cast.data.ballot.data.voter_pseudonym
                                == b_cast.data.ballot.data.voter_pseudonym
                                && a_cast.data.ballot.data.ballot_style
                                    == b_cast.data.ballot.data.ballot_style
                        }
                        _ => false, // Different types (shouldn't happen due to discriminant check above)
                    }
                })
        }

        fn new(config: ModelConfig) -> Self {
            use crate::cryptography::generate_encryption_keypair;

            let election_hash = string_to_election_hash(MANIFEST);

            // Generate election key
            let keypair = generate_encryption_keypair(MANIFEST.as_bytes())
                .expect("Failed to generate election keypair");
            let election_key = keypair.pkey.clone();

            // Generate signing keys for mock actors
            let mut rng = CryptographyContext::get_rng();
            let _bb_signing_key = SigningKey::generate(&mut rng);
            let eas_signing_key = SigningKey::generate(&mut rng);
            let dbb_signing_key = SigningKey::generate(&mut rng);
            let eas_verifying_key = eas_signing_key.verifying_key();
            let dbb_verifying_key = dbb_signing_key.verifying_key();

            // Start with no voter sessions - they will be created on-demand
            let voter_sessions = BTreeMap::new();

            // Create real DBB with in-memory storage and bulletin board
            let storage = InMemoryStorage::new();
            let bulletin_board = InMemoryBulletinBoard::new();
            let dbb = DigitalBallotBoxActor::new(
                storage,
                bulletin_board.clone(),
                election_hash,
                dbb_signing_key.clone(),
                dbb_verifying_key,
                eas_verifying_key,
                election_key.clone(),
            );

            Self {
                config: config.clone(),
                voter_sessions,
                next_session_id: 0,
                as_server: MockAS::new(),
                eas: EASActor::new(
                    election_hash,
                    eas_signing_key,
                    std::time::Duration::MAX, // Use maximum duration for model checking to avoid non-deterministic timeouts
                    "test_project_id".to_string(),
                    "test_api_key".to_string(),
                ),
                dbb,
                next_connection_id: 1000,
                va_connection_ids: BTreeMap::new(),
                va_to_bca_session: BTreeMap::new(),
                pending_messages: PendingMessages::new(),
                pending_auth_requests: BTreeMap::new(),
                auth_req_to_voter: BTreeMap::new(),
                total_checks_used: 0,
                total_resubmissions_used: 0,
                total_ballots_generated: 0,
                abandoned_sessions: 0,
                auth_failures: 0,
                eligibility_failures: 0,
                already_voted_attempts: 0,
                already_voted_failures: 0,
                unauthorized_submission_failures: 0,
                other_failures: 0,
                casting_failures: 0,
                completed_voters: 0,
                trackers_assigned: 0,
                eas_authorize_attempts: 0,
                has_failure: false,
                election_hash,
                election_key,
                dbb_verifying_key,
                eas_verifying_key,
                next_actor_id: 0,
            }
        }

        /// Remove a terminal session from the state immediately.
        /// This should be called whenever a session becomes terminal (has_cast, abandoned, auth_failed, etc.)
        /// to prevent state explosion from sessions with different inbox contents.
        fn remove_terminal_session(state: &mut IntegrationState, session_id: SessionId) {
            state.voter_sessions.remove(&session_id);

            // Clean up pending messages for this session to prevent state explosion.
            // This is safe and deterministic: removing a session always removes its messages.
            state.pending_messages.to_eas.remove(&session_id);
            state.pending_messages.to_dbb.remove(&session_id);

            // Clean up auth request mappings
            if let Some(auth_req_id) = state.pending_auth_requests.remove(&session_id) {
                state.auth_req_to_voter.remove(&auth_req_id);
                state
                    .pending_messages
                    .to_as_service
                    .retain(|(arid, _)| *arid != auth_req_id);
            }
        }

        /// Handle VA processing its next inbox message
        fn handle_va_step(state: &mut IntegrationState, session_id: SessionId) -> Option<()> {
            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();

            // Debug: Log inbox size before pop
            if session.va.ballot_tracker().is_some() {
                trace_print(format!(
                    "VAStep: {:?} inbox size before pop: {}",
                    session_id,
                    session.va_inbox.len()
                ));
            }

            // Pop message from inbox
            if session.va_inbox.is_empty() {
                return None;
            }
            let msg = session.va_inbox.remove(0);

            let has_tracker = session.va.ballot_tracker().is_some();
            if has_tracker {
                let msg_type = match &msg {
                    VAMessage::Command(_) => "Command",
                    VAMessage::SubprotocolInput(sub) => match sub {
                        VASubprotocolInput::Submission(s) => match s {
                            SubmissionInput::Start(_) => "Submission::Start",
                            SubmissionInput::NetworkMessage(_) => "Submission::NetworkMessage",
                            SubmissionInput::PBBData(_) => "Submission::PBBData",
                        },
                        _ => "Other SubprotocolInput",
                    },
                };
                trace_print(format!(
                    "VAStep: Processing {} for {:?} with tracker {:?}, inbox remaining: {}",
                    msg_type,
                    session_id,
                    session.va.ballot_tracker(),
                    session.va_inbox.len()
                ));
            }

            // Update VA trace hash with discriminant of this message
            // Combine current hash with new message to preserve order
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            session.va_trace_hash.hash(&mut hasher);
            std::mem::discriminant(&msg).hash(&mut hasher);
            session.va_trace_hash = hasher.finish();

            // Convert VAMessage to VAInput
            let input = match msg {
                VAMessage::Command(cmd) => VAInput::Command(cmd),
                VAMessage::SubprotocolInput(sub_input) => VAInput::SubprotocolInput(sub_input),
            };

            // Process the input
            let result = session.va.process_input(input);
            if has_tracker && result.is_err() {
                trace_print(format!("VAStep: ERROR for {:?}: {:?}", session_id, result));
            }
            let output = result.ok()?;

            if has_tracker {
                trace_print(format!("VAStep: Success for {:?}", session_id));
            }

            // Handle the output - extract messages and route them
            Self::route_va_output(state, session_id, output);

            Some(())
        }

        /// Handle BCA processing its next inbox message
        fn handle_bca_step(state: &mut IntegrationState, session_id: SessionId) -> Option<()> {
            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();

            // BCA must exist to process messages
            let bca = session.bca.as_mut()?;

            // Pop message from inbox
            if session.bca_inbox.is_empty() {
                return None;
            }
            let msg = session.bca_inbox.remove(0);

            // Update BCA trace hash with discriminant of this message
            // Combine current hash with new message to preserve order
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            session.bca_trace_hash.hash(&mut hasher);
            std::mem::discriminant(&msg).hash(&mut hasher);
            session.bca_trace_hash = hasher.finish();

            // Convert BCAMessage to BCAInput
            let input = match msg {
                BCAMessage::Command(cmd) => BCAInput::Command(cmd),
                BCAMessage::SubprotocolInput(sub_input) => BCAInput::SubprotocolInput(sub_input),
            };

            // Process the input
            let output = bca.process_input(input).ok()?;

            // Handle the output - extract messages and route them
            if let Some(output) = output {
                Self::route_bca_output(state, session_id, output);
            }

            Some(())
        }

        /// Route BCA output to appropriate destinations
        fn route_bca_output(
            state: &mut IntegrationState,
            session_id: SessionId,
            output: BCASubprotocolOutput,
        ) {
            match output {
                BCASubprotocolOutput::BallotCheck(check_output) => match check_output {
                    BallotCheckOutput::SendMessage(msg) => {
                        // CheckReq message goes to DBB
                        state
                            .pending_messages
                            .to_dbb
                            .entry(session_id)
                            .or_default()
                            .push_back(msg);
                    }
                    BallotCheckOutput::PlaintextBallot(_ballot) => {
                        // Ballot check completed successfully
                        // In a real application, this would display the ballot to the user
                        // For the model, we just note that the check completed
                        // Clear the BCA actor as checking is done
                        let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                        session.bca = None;
                        session.bca_id = None;
                    }
                    BallotCheckOutput::Failure(_error) => {
                        // Ballot check failed
                        // For the model, we just note the failure
                        // Clear the BCA actor as checking is done
                        let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                        session.bca = None;
                        session.bca_id = None;
                    }
                },
            }
        }

        /// Route VA output to appropriate destinations
        fn route_va_output(
            state: &mut IntegrationState,
            session_id: SessionId,
            output: VASubprotocolOutput,
        ) {
            match output {
                VASubprotocolOutput::Authentication(auth_output) => {
                    // Track that we're in authentication subprotocol
                    state
                        .voter_sessions
                        .get_mut(&session_id)
                        .unwrap()
                        .va_subprotocol_state = VASubprotocolState::Authenticating;

                    match auth_output {
                        AuthenticationOutput::SendMessage(msg) => {
                            match &msg {
                                ProtocolMessage::AuthReq(_) | ProtocolMessage::AuthFinish(_) => {
                                    // Both AuthReq and AuthFinish go to EAS
                                    state
                                        .pending_messages
                                        .to_eas
                                        .entry(session_id)
                                        .or_default()
                                        .push_back(msg);
                                }
                                _ => {}
                            }
                        }
                        AuthenticationOutput::RequestThirdPartyAuth(_token) => {
                            // User needs to complete third-party auth
                            // Set flag so action can be generated
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.third_party_auth_pending = true;
                        }
                        AuthenticationOutput::Success(result) => {
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.third_party_auth_pending = false;
                            // Authentication protocol completed successfully - return to Idle
                            session.va_subprotocol_state = VASubprotocolState::Idle;

                            // If the authentication actually failed, we need to update our counters
                            // and state appropriately, and remove the session (since it's dead now).
                            if !result.result.0 {
                                session.auth_failed = true;
                                state.auth_failures += 1;
                                // Remove terminal session immediately to prevent state explosion
                                Self::remove_terminal_session(state, session_id);
                            }
                        }
                        AuthenticationOutput::Failure(_) => {
                            // Authentication protocol failed - return to Idle
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.third_party_auth_pending = false;
                            session.va_subprotocol_state = VASubprotocolState::Idle;

                            // Update our "other failures" counters because this is a protocol
                            // failure, not an authentication failure.
                            session.other_failure = true;
                            state.other_failures += 1;
                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }
                    }
                }
                VASubprotocolOutput::Submission(sub_output) => {
                    // Track that we're in submission subprotocol
                    state
                        .voter_sessions
                        .get_mut(&session_id)
                        .unwrap()
                        .va_subprotocol_state = VASubprotocolState::Submitting;

                    match sub_output {
                        SubmissionOutput::SendMessage(msg) => {
                            // SignedBallotMsg goes to DBB
                            state
                                .pending_messages
                                .to_dbb
                                .entry(session_id)
                                .or_default()
                                .push_back(msg);
                        }
                        SubmissionOutput::FetchBulletin(tracker) => {
                            // VA needs bulletin data from PBB to complete verification
                            trace_print(format!(
                                "SUBMISSION: {:?} fetching bulletin for tracker: {:?}",
                                session_id, tracker
                            ));

                            if let Some(bulletin) = state
                                .dbb
                                .bulletin_board()
                                .get_bulletin(&tracker)
                                .ok()
                                .flatten()
                            {
                                // Send bulletin back to VA for verification
                                let session =
                                    &mut state.voter_sessions.get_mut(&session_id).unwrap();
                                trace_print(format!(
                                    "SUBMISSION: {:?} found bulletin, VA inbox size before: {}",
                                    session_id,
                                    session.va_inbox.len()
                                ));
                                session.va_inbox.push(VAMessage::SubprotocolInput(
                                    VASubprotocolInput::Submission(SubmissionInput::PBBData(
                                        bulletin,
                                    )),
                                ));
                                trace_print(format!(
                                    "SUBMISSION: {:?} sent PBBData to VA inbox (new size: {})",
                                    session_id,
                                    session.va_inbox.len()
                                ));
                            } else {
                                trace_print(format!(
                                    "ERROR: Bulletin not found for tracker {:?}",
                                    tracker
                                ));
                            }
                        }
                        SubmissionOutput::Success(result) => {
                            // Submission completed - return to Idle
                            // VA actor now stores tracker and randomizers internally
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.va_subprotocol_state = VASubprotocolState::Idle;
                            trace_print(format!(
                                "SUBMISSION SUCCESS: {:?} received tracker: {:?}",
                                session_id, result.tracker
                            ));
                        }
                        SubmissionOutput::Failure(err) => {
                            // Submission failed - mark session as failed and terminal
                            trace_print(format!(
                                "SUBMISSION FAILURE: {:?} failed: {}",
                                session_id, err
                            ));

                            // Categorize the failure type
                            if err.contains("without prior authentication")
                                || err.contains("without prior authorization")
                            {
                                state
                                    .voter_sessions
                                    .get_mut(&session_id)
                                    .unwrap()
                                    .unauthorized_submission_failure = true;
                                state.unauthorized_submission_failures += 1;
                            } else {
                                state
                                    .voter_sessions
                                    .get_mut(&session_id)
                                    .unwrap()
                                    .other_failure = true;
                                state.other_failures += 1;
                                // Remove terminal session immediately to prevent state explosion
                                Self::remove_terminal_session(state, session_id);
                            }

                            // Only update VA state if session still exists (might be removed if terminal)
                            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                                session.va_subprotocol_state = VASubprotocolState::Idle;
                            }
                        }
                    }
                }
                VASubprotocolOutput::Casting(cast_output) => {
                    // Track that we're in casting subprotocol
                    state
                        .voter_sessions
                        .get_mut(&session_id)
                        .unwrap()
                        .va_subprotocol_state = VASubprotocolState::Casting;

                    let session_tracker = state
                        .voter_sessions
                        .get_mut(&session_id)
                        .unwrap()
                        .va
                        .ballot_tracker()
                        .cloned();

                    match cast_output {
                        CastingOutput::SendMessage(msg) => {
                            // CastReqMsg goes to DBB
                            trace_print(format!(
                                "CASTING: {:?} with tracker {:?} sending CastReq to DBB",
                                session_id, session_tracker
                            ));
                            state
                                .pending_messages
                                .to_dbb
                                .entry(session_id)
                                .or_default()
                                .push_back(msg);
                        }
                        CastingOutput::Success(_) => {
                            // Mark voter as having completed - return to Idle
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            trace_print(format!(
                                "CASTING SUCCESS: {:?} with tracker {:?} has successfully cast! completed_voters: {} -> {}",
                                session_id,
                                session_tracker,
                                state.completed_voters,
                                state.completed_voters + if !session.has_cast { 1 } else { 0 }
                            ));
                            if !session.has_cast {
                                session.has_cast = true;
                                state.completed_voters += 1;
                                // Remove terminal session immediately to prevent state explosion
                                Self::remove_terminal_session(state, session_id);
                            }
                            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                                session.va_subprotocol_state = VASubprotocolState::Idle;
                            }
                        }
                        CastingOutput::Failure(err) => {
                            // Casting failed - mark session as terminal
                            trace_print(format!(
                                "CASTING FAILURE: {:?} with tracker {:?} failed: {}",
                                session_id, session_tracker, err
                            ));

                            // Check if this is an "already voted" failure
                            if err.contains("already cast")
                                || err.contains("Voter has already cast")
                            {
                                state
                                    .voter_sessions
                                    .get_mut(&session_id)
                                    .unwrap()
                                    .already_voted_failure = true;
                                state.already_voted_failures += 1;
                            }

                            state
                                .voter_sessions
                                .get_mut(&session_id)
                                .unwrap()
                                .casting_failure = true;
                            state.casting_failures += 1;
                            state
                                .voter_sessions
                                .get_mut(&session_id)
                                .unwrap()
                                .va_subprotocol_state = VASubprotocolState::Idle;
                        }
                    }
                }
                VASubprotocolOutput::Checking(check_output) => {
                    // Track that we're in checking subprotocol
                    state
                        .voter_sessions
                        .get_mut(&session_id)
                        .unwrap()
                        .va_subprotocol_state = VASubprotocolState::Checking;

                    match check_output {
                        CheckingOutput::Success(outcome) => {
                            // Clear approval pending flag and return to Idle
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.check_approval_pending = false;
                            session.va_subprotocol_state = VASubprotocolState::Idle;

                            match outcome {
                                BallotCheckOutcome::RandomizersSent { randomizer_msg } => {
                                    // Randomizer message goes to DBB
                                    state
                                        .pending_messages
                                        .to_dbb
                                        .entry(session_id)
                                        .or_default()
                                        .push_back(randomizer_msg);
                                }
                                BallotCheckOutcome::RequestDenied => {
                                    // User denied the check request - nothing to do
                                }
                            }
                        }
                        CheckingOutput::InteractionRequired(_) => {
                            // User approval needed - set flag so actions can be generated
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.check_approval_pending = true;
                        }
                        CheckingOutput::Listening => {
                            // Waiting for network message - nothing to do
                        }
                        CheckingOutput::Failure(_) => {
                            // Check failed - clear approval pending flag and return to Idle
                            let session = &mut state.voter_sessions.get_mut(&session_id).unwrap();
                            session.check_approval_pending = false;
                            session.va_subprotocol_state = VASubprotocolState::Idle;
                        }
                    }
                }
            }
        }

        /// EAS processes AuthReq message from VA
        fn handle_eas_process_auth_req(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_eas
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_eas
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_eas.remove(&session_id);
            }

            // Extract AuthReq
            let auth_req = match msg {
                ProtocolMessage::AuthReq(req) => req,
                _ => return None,
            };

            // Send to EAS actor
            let eas_input = EASInput::Command(EASCommand::StartVoterAuthentication(auth_req));
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, auth_req_id) => {
                    // Store the mapping from auth_req_id to session_id
                    state.pending_auth_requests.insert(session_id, auth_req_id);
                    state.auth_req_to_voter.insert(auth_req_id, session_id);

                    match va_output {
                        VoterAuthenticationOutput::AuthServiceMessage(as_msg) => {
                            // Queue AS message for processing
                            state
                                .pending_messages
                                .to_as_service
                                .push((auth_req_id, as_msg));
                        }
                        VoterAuthenticationOutput::NetworkMessage(msgs) => {
                            // Deliver network messages to VA
                            // Skip if session was abandoned/removed
                            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                                for msg in msgs {
                                    session.va_inbox.push(VAMessage::SubprotocolInput(
                                        VASubprotocolInput::Authentication(
                                            AuthenticationInput::NetworkMessage(msg),
                                        ),
                                    ));
                                }
                            }
                        }
                        VoterAuthenticationOutput::Failure(_) => {
                            // EAS failed to process
                            // Skip if session was abandoned/removed
                            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                                session.auth_failed = true;
                                state.auth_failures += 1;
                                // Remove terminal session immediately to prevent state explosion
                                Self::remove_terminal_session(state, session_id);
                            }
                        }
                        _ => {
                            // Unexpected output type
                        }
                    }
                }
                _ => {
                    // Unexpected output type
                }
            }

            Some(())
        }

        /// EAS processes AuthFinish message from VA
        fn handle_eas_process_auth_finish(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_eas
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_eas
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_eas.remove(&session_id);
            }

            // Extract AuthFinish
            let auth_finish = match msg {
                ProtocolMessage::AuthFinish(finish) => finish,
                _ => return None,
            };

            // Get the auth_req_id for this voter
            let auth_req_id = *state.pending_auth_requests.get(&session_id)?;

            // Send to EAS actor
            let eas_input = EASInput::SubprotocolInput(
                EASSubprotocolInput::VoterAuthentication(VoterAuthenticationInput::NetworkMessage(
                    ProtocolMessage::AuthFinish(auth_finish),
                )),
                auth_req_id,
            );
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, _) => match va_output {
                    VoterAuthenticationOutput::AuthServiceMessage(as_msg) => {
                        // Queue AS message for processing
                        state
                            .pending_messages
                            .to_as_service
                            .push((auth_req_id, as_msg));
                    }
                    VoterAuthenticationOutput::NetworkMessage(msgs) => {
                        // Deliver network messages to VA
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            for msg in msgs {
                                session.va_inbox.push(VAMessage::SubprotocolInput(
                                    VASubprotocolInput::Authentication(
                                        AuthenticationInput::NetworkMessage(msg),
                                    ),
                                ));
                            }
                        }
                    }
                    VoterAuthenticationOutput::Failure(_) => {
                        // EAS failed to process
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            session.auth_failed = true;
                            state.auth_failures += 1;
                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }
                    }
                    _ => {
                        // Unexpected output type
                    }
                },
                _ => {
                    // Unexpected output type
                }
            }

            Some(())
        }

        /// AS returns successful authentication result
        fn handle_as_return_auth_success(
            state: &mut IntegrationState,
            auth_req_id: AuthReqId,
            registered_id: usize,
        ) -> Option<()> {
            // Find and remove the AS service message
            let msg_index = state
                .pending_messages
                .to_as_service
                .iter()
                .position(|(id, _)| *id == auth_req_id)?;
            let (_, as_msg) = state.pending_messages.to_as_service.remove(msg_index);

            // Get voter_id from auth_req_id
            let session_id = *state.auth_req_to_voter.get(&auth_req_id)?;

            // Get the session profile to pass to AS
            let profile = state.voter_sessions.get(&session_id)?.profile;

            // Process AS message based on type
            let as_response = match as_msg {
                AuthServiceMessage::InitAuthReq(init_msg) => {
                    // AS creates authentication session with the voter's profile
                    let token_return = state.as_server.handle_init_auth_req(init_msg, profile);
                    AuthServiceMessage::TokenReturn(token_return)
                }
                AuthServiceMessage::AuthServiceQuery(query_msg) => {
                    // AS returns authentication result (successful)
                    let report = state.as_server.handle_query(query_msg).ok()?;
                    AuthServiceMessage::AuthServiceReport(report)
                }
                _ => return None,
            };

            // Send AS response back to EAS
            let eas_input = EASInput::SubprotocolInput(
                EASSubprotocolInput::VoterAuthentication(
                    VoterAuthenticationInput::AuthServiceMessage(as_response),
                ),
                auth_req_id,
            );
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, _) => match va_output {
                    VoterAuthenticationOutput::NetworkMessage(msgs) => {
                        // Deliver network messages to VA
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            for msg in msgs {
                                session.va_inbox.push(VAMessage::SubprotocolInput(
                                    VASubprotocolInput::Authentication(
                                        AuthenticationInput::NetworkMessage(msg),
                                    ),
                                ));
                            }
                        }
                    }
                    VoterAuthenticationOutput::CheckBiographicalInfo(report) => {
                        // Queue biographical info check for protocol driver
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            state
                                .pending_messages
                                .bio_info_checks
                                .push((auth_req_id, report));
                            // Store the registered_id for this voter
                            session.assigned_voter_id = Some(registered_id);
                        }
                    }
                    VoterAuthenticationOutput::Failure(_) => {
                        // EAS failed to process
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            session.auth_failed = true;
                            state.auth_failures += 1;
                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }
                    }
                    _ => {
                        // Unexpected output type
                    }
                },
                _ => {
                    // Unexpected output type
                }
            }

            Some(())
        }

        /// AS returns failed authentication result
        /// Routes the AS message through MockAS, which will return authenticated=false
        fn handle_as_return_auth_failure(
            state: &mut IntegrationState,
            auth_req_id: AuthReqId,
        ) -> Option<()> {
            // Find and remove the AS service message
            let msg_index = state
                .pending_messages
                .to_as_service
                .iter()
                .position(|(id, _)| *id == auth_req_id)?;
            let (_, as_msg) = state.pending_messages.to_as_service.remove(msg_index);

            // Get voter_id from auth_req_id
            let session_id = *state.auth_req_to_voter.get(&auth_req_id)?;

            // Get the session profile to pass to AS
            let profile = state.voter_sessions.get(&session_id)?.profile;

            // Process AS message based on type - MockAS will return authenticated=false for AuthenticationFailed profile
            let as_response = match as_msg {
                AuthServiceMessage::InitAuthReq(init_msg) => {
                    // AS creates authentication session with the voter's profile
                    let token_return = state.as_server.handle_init_auth_req(init_msg, profile);
                    AuthServiceMessage::TokenReturn(token_return)
                }
                AuthServiceMessage::AuthServiceQuery(query_msg) => {
                    // AS returns authentication result (will be authenticated=false for this profile)
                    let report = state.as_server.handle_query(query_msg).ok()?;
                    AuthServiceMessage::AuthServiceReport(report)
                }
                _ => return None,
            };

            // Send AS response back to EAS
            let eas_input = EASInput::SubprotocolInput(
                EASSubprotocolInput::VoterAuthentication(
                    VoterAuthenticationInput::AuthServiceMessage(as_response),
                ),
                auth_req_id,
            );
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, _) => match va_output {
                    VoterAuthenticationOutput::NetworkMessage(msgs) => {
                        // Deliver network messages to VA
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            for msg in msgs {
                                session.va_inbox.push(VAMessage::SubprotocolInput(
                                    VASubprotocolInput::Authentication(
                                        AuthenticationInput::NetworkMessage(msg),
                                    ),
                                ));
                            }
                        }
                    }
                    VoterAuthenticationOutput::Failure(_) => {
                        // EAS processed authentication failure (expected for auth failures)
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            session.auth_failed = true;
                            state.auth_failures += 1;
                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }
                    }
                    _ => {
                        // Unexpected output type
                    }
                },
                _ => {
                    // Unexpected output type
                }
            }

            Some(())
        }

        /// Calculate ballot style from registered voter ID
        ///
        /// This function ensures consistent ballot style assignment across the system.
        /// The ballot style determines which contests the voter is eligible to vote in.
        fn ballot_style_for_registered_id(registered_id: usize) -> BallotStyle {
            ((registered_id % 3) + 1) as BallotStyle
        }

        /// Protocol Driver approves biographical info
        fn handle_protocol_driver_approve_bio(
            state: &mut IntegrationState,
            auth_req_id: AuthReqId,
            registered_id: usize,
        ) -> Option<()> {
            // Find and remove the bio check
            let msg_index = state
                .pending_messages
                .bio_info_checks
                .iter()
                .position(|(id, _)| *id == auth_req_id)?;
            let (_, _report) = state.pending_messages.bio_info_checks.remove(msg_index);

            // Get voter_id from auth_req_id
            let session_id = *state.auth_req_to_voter.get(&auth_req_id)?;

            // Generate voter pseudonym and ballot style based on registered_id
            let voter_pseudonym: VoterPseudonym = format!("voter_{}", registered_id);
            let ballot_style: BallotStyle = Self::ballot_style_for_registered_id(registered_id);

            // Send approval to EAS
            let eas_input = EASInput::SubprotocolInput(
                EASSubprotocolInput::VoterAuthentication(
                    VoterAuthenticationInput::BiographicalInfoOk {
                        voter_pseudonym: voter_pseudonym.clone(),
                        ballot_style,
                    },
                ),
                auth_req_id,
            );
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output - should send ConfirmAuthorization to VA and AuthVoter to DBB
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, _) => match va_output {
                    VoterAuthenticationOutput::NetworkMessage(msgs) => {
                        // Deliver messages to VA and DBB
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            for msg in msgs {
                                match &msg {
                                    ProtocolMessage::ConfirmAuthorization(_) => {
                                        // Send to VA
                                        session.va_inbox.push(VAMessage::SubprotocolInput(
                                            VASubprotocolInput::Authentication(
                                                AuthenticationInput::NetworkMessage(msg),
                                            ),
                                        ));
                                    }
                                    ProtocolMessage::AuthVoter(auth_voter_msg) => {
                                        // Send to DBB using EASMessage
                                        state
                                            .dbb
                                            .process_input(DBBInput::EASMessage(EASMessage {
                                                message: auth_voter_msg.clone(),
                                            }))
                                            .ok()?;
                                    }
                                    _ => {}
                                }
                            }
                            // Mark voter as assigned
                            session.assigned_voter_id = Some(registered_id);
                        }
                    }
                    VoterAuthenticationOutput::Failure(_) => {
                        // EAS failed
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            session.eligibility_failed = true;
                            state.eligibility_failures += 1;
                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }
                    }
                    _ => {
                        // Unexpected output type
                    }
                },
                _ => {
                    // Unexpected output type
                }
            }

            // Clean up tracking
            state.pending_auth_requests.remove(&session_id);
            state.auth_req_to_voter.remove(&auth_req_id);

            Some(())
        }

        /// Protocol Driver rejects biographical info
        fn handle_protocol_driver_reject_bio(
            state: &mut IntegrationState,
            auth_req_id: AuthReqId,
        ) -> Option<()> {
            // Find and remove the bio check
            let msg_index = state
                .pending_messages
                .bio_info_checks
                .iter()
                .position(|(id, _)| *id == auth_req_id)?;
            state.pending_messages.bio_info_checks.remove(msg_index);

            // Get voter_id from auth_req_id
            let session_id = *state.auth_req_to_voter.get(&auth_req_id)?;

            // Send rejection to EAS
            let eas_input = EASInput::SubprotocolInput(
                EASSubprotocolInput::VoterAuthentication(
                    VoterAuthenticationInput::BiographicalInfoInvalid(
                        "Biographical info rejected".to_string(),
                    ),
                ),
                auth_req_id,
            );
            let eas_output = state.eas.process_input(eas_input).ok()?;

            // Handle EAS output - should send ConfirmAuthorization with failure to VA
            match eas_output {
                EASSubprotocolOutput::VoterAuthentication(va_output, _) => match va_output {
                    VoterAuthenticationOutput::NetworkMessage(msgs) => {
                        // Deliver messages to VA
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            for msg in msgs {
                                if let ProtocolMessage::ConfirmAuthorization(_) = &msg {
                                    session.va_inbox.push(VAMessage::SubprotocolInput(
                                        VASubprotocolInput::Authentication(
                                            AuthenticationInput::NetworkMessage(msg),
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                    VoterAuthenticationOutput::Failure(_) => {
                        // EAS failed - session already becomes terminal here
                        // Skip if session was abandoned/removed
                        if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                            session.eligibility_failed = true;
                            state.eligibility_failures += 1;

                            // Clean up tracking
                            state.pending_auth_requests.remove(&session_id);
                            state.auth_req_to_voter.remove(&auth_req_id);

                            // Remove terminal session immediately to prevent state explosion
                            Self::remove_terminal_session(state, session_id);
                        }

                        // Early return - session is already handled
                        return Some(());
                    }
                    _ => {
                        // Unexpected output type
                    }
                },
                _ => {
                    // Unexpected output type
                }
            }

            // Mark session as failed (normal path when EAS sends ConfirmAuthorization with failure)
            // Skip if session was abandoned/removed
            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                session.eligibility_failed = true;
                state.eligibility_failures += 1;

                // Clean up tracking
                state.pending_auth_requests.remove(&session_id);
                state.auth_req_to_voter.remove(&auth_req_id);

                // Remove terminal session immediately to prevent state explosion
                Self::remove_terminal_session(state, session_id);
            }

            Some(())
        }

        /// DBB processes SignedBallotMsg and returns tracker
        fn handle_dbb_process_signed_ballot(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_dbb
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_dbb
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_dbb.remove(&session_id);
            }

            // Extract SignedBallotMsg
            let signed_ballot = match msg {
                ProtocolMessage::SubmitSignedBallot(ballot) => ballot,
                _ => return None,
            };

            // Assign or reuse connection ID for this VA session
            let connection_id = *state
                .va_connection_ids
                .entry(session_id)
                .or_insert_with(|| {
                    let id = state.next_connection_id;
                    state.next_connection_id += 1;
                    id
                });

            // DBB processes ballot submission
            let output = state
                .dbb
                .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                    connection_id,
                    message: ProtocolMessage::SubmitSignedBallot(signed_ballot.clone()),
                }));

            let tracker_msg = match output {
                Ok(DBBOutput::OutgoingMessage(outgoing)) => {
                    match outgoing.message {
                        ProtocolMessage::ReturnBallotTracker(tracker) => {
                            state.trackers_assigned += 1;
                            tracker
                        }
                        _ => return None, // Unexpected message from DBB
                    }
                }
                Err(error) => {
                    // DBB rejected submission - this shouldn't happen with real DBB since
                    // it returns errors via TrackerMsg, but handle it just in case
                    trace_print(format!(
                        "DBB returned error for {:?}: {}",
                        session_id, error
                    ));
                    return None;
                }
                _ => return None, // Unexpected output from DBB
            };

            // Deliver tracker (success or failure) to VA
            // Skip if session was abandoned/removed
            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                session
                    .va_inbox
                    .push(VAMessage::SubprotocolInput(VASubprotocolInput::Submission(
                        SubmissionInput::NetworkMessage(ProtocolMessage::ReturnBallotTracker(
                            tracker_msg,
                        )),
                    )));
            }

            Some(())
        }

        /// DBB processes CastReqMsg and returns confirmation
        fn handle_dbb_process_cast_req(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_dbb
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_dbb
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_dbb.remove(&session_id);
            }

            // Extract CastReqMsg
            let cast_req = match msg {
                ProtocolMessage::CastReq(req) => req,
                _ => return None,
            };

            // Reuse the VA connection ID that was assigned during submission
            let connection_id = state.va_connection_ids.get(&session_id).copied()?;

            // Skip if session was abandoned/removed
            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                let tracker = session.va.ballot_tracker().cloned();
                trace_print(format!(
                    "DBB: Processing CastReq for {:?} with tracker {:?}",
                    session_id, tracker
                ));

                // DBB processes cast request
                let output =
                    state
                        .dbb
                        .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                            connection_id,
                            message: ProtocolMessage::CastReq(cast_req.clone()),
                        }));

                let cast_conf = match output {
                    Ok(DBBOutput::OutgoingMessage(outgoing)) => {
                        match outgoing.message {
                            ProtocolMessage::CastConf(conf) => {
                                trace_print(format!(
                                    "DBB: CastReq SUCCESS for {:?} with tracker {:?}",
                                    session_id, tracker
                                ));
                                conf
                            }
                            _ => return None, // Unexpected message
                        }
                    }
                    Err(error) => {
                        trace_print(format!(
                            "DBB: CastReq FAILED for {:?} with tracker {:?}: {}",
                            session_id, tracker, error
                        ));
                        return None;
                    }
                    _ => return None, // Unexpected output
                };

                trace_print(format!(
                    "DBB: Sending CastConf to {:?} with tracker {:?}",
                    session_id, tracker
                ));

                // Deliver confirmation to VA
                session
                    .va_inbox
                    .push(VAMessage::SubprotocolInput(VASubprotocolInput::Casting(
                        CastingInput::NetworkMessage(ProtocolMessage::CastConf(cast_conf)),
                    )));
            }

            Some(())
        }

        /// DBB processes CheckReqMsg and forwards to VA
        fn handle_dbb_process_check_req(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_dbb
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_dbb
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_dbb.remove(&session_id);
            }

            // Extract CheckReqMsg
            let check_req = match msg {
                ProtocolMessage::CheckReq(req) => req,
                _ => return None,
            };

            // Assign BCA connection ID
            let bca_connection_id = state.next_connection_id;
            state.next_connection_id += 1;

            // Send CheckReq to DBB
            let output = state
                .dbb
                .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                    connection_id: bca_connection_id,
                    message: ProtocolMessage::CheckReq(check_req.clone()),
                }))
                .ok()?;

            // DBB will request VA connection
            let _tracker = match output {
                DBBOutput::RequestVAConnection {
                    tracker,
                    bca_connection_id: _,
                } => tracker,
                _ => return None, // Unexpected output
            };

            // Look up which VA connection corresponds to this tracker
            // The tracker was returned during ballot submission from the VA's session
            let va_connection_id = state.va_connection_ids.get(&session_id).copied()?;

            // Store the mapping: VA connection -> BCA checking session
            state
                .va_to_bca_session
                .insert(va_connection_id, bca_connection_id);

            // Provide the VA connection to DBB
            let provide_output = state
                .dbb
                .process_input(DBBInput::Command(DBBCommand::ProvideVAConnection {
                    checking_session_id: bca_connection_id,
                    va_connection_id,
                }))
                .ok()?;

            // Extract FwdCheckReq from output
            let fwd_check_req = match provide_output {
                DBBOutput::OutgoingMessage(outgoing) => match outgoing.message {
                    ProtocolMessage::FwdCheckReq(fwd) => fwd,
                    _ => return None,
                },
                _ => return None,
            };

            // Deliver to VA
            // Skip if session was abandoned/removed
            if let Some(session) = state.voter_sessions.get_mut(&session_id) {
                session
                    .va_inbox
                    .push(VAMessage::SubprotocolInput(VASubprotocolInput::Checking(
                        CheckingInput::NetworkMessage(ProtocolMessage::FwdCheckReq(fwd_check_req)),
                    )));
            }

            Some(())
        }

        /// DBB processes RandomizerMsg and forwards to BCA
        fn handle_dbb_process_randomizer(
            state: &mut IntegrationState,
            session_id: SessionId,
        ) -> Option<()> {
            // Remove message from pending (pop front of this session's queue)
            let msg = state
                .pending_messages
                .to_dbb
                .get_mut(&session_id)?
                .pop_front()?;

            // Clean up empty queue
            if state
                .pending_messages
                .to_dbb
                .get(&session_id)
                .unwrap()
                .is_empty()
            {
                state.pending_messages.to_dbb.remove(&session_id);
            }

            // Extract RandomizerMsg
            let randomizer = match msg {
                ProtocolMessage::Randomizer(rand) => rand,
                _ => return None,
            };

            // Look up the BCA session ID from the VA connection
            let va_connection_id = state.va_connection_ids.get(&session_id).copied()?;
            let bca_checking_session_id =
                state.va_to_bca_session.get(&va_connection_id).copied()?;

            // Route Randomizer to the correct BCA session via the mapping
            let output = state
                .dbb
                .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                    connection_id: bca_checking_session_id,
                    message: ProtocolMessage::Randomizer(randomizer),
                }))
                .ok()?;

            // Extract FwdRandomizer from output
            let fwd_randomizer = match output {
                DBBOutput::OutgoingMessage(outgoing) => match outgoing.message {
                    ProtocolMessage::FwdRandomizer(fwd) => fwd,
                    _ => return None,
                },
                _ => return None,
            };

            // Deliver to BCA
            // Skip if session was abandoned/removed
            if let Some(session) = state.voter_sessions.get_mut(&session_id)
                && session.bca.is_some()
            {
                session.bca_inbox.push(BCAMessage::SubprotocolInput(
                    BCASubprotocolInput::BallotCheck(BallotCheckInput::NetworkMessage(
                        ProtocolMessage::FwdRandomizer(fwd_randomizer),
                    )),
                ));
            }

            Some(())
        }
    }

    /// Actions that can be taken in the model
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum Action {
        // --- Session management ---
        /// Start a new voter session with a predetermined profile
        StartNewSession(SessionProfile),

        // --- Independent action processing ---
        /// Process all independent actions atomically: VA/BCA steps, EAS processing,
        /// AS responses, and Protocol Driver decisions. This collapses equivalent
        /// interleavings to dramatically reduce state explosion.
        ProcessAllIndependentActions,

        // --- User commands (queue commands in VA inbox) ---
        /// User starts authentication
        UserStartAuth(SessionId),
        /// User completes third-party authentication
        UserFinishAuth(SessionId),
        /// User starts ballot submission
        UserSubmitBallot(SessionId),
        /// User starts ballot check
        UserCheckBallot(SessionId),
        /// User approves check request (provides approval to VA)
        UserApproveCheck(SessionId),
        /// User casts ballot
        UserCastBallot(SessionId),
        /// User abandons session
        UserAbandonSession(SessionId),

        // --- DBB response actions (ordering matters for correctness testing) ---
        /// DBB processes SignedBallotMsg and delivers TrackerMsg to VA
        /// (processes the front message for this session_id)
        DBBProcessSignedBallot { session_id: SessionId },
        /// DBB processes CastReqMsg and delivers CastConfMsg to VA
        /// (processes the front message for this session_id)
        DBBProcessCastReq { session_id: SessionId },
        /// DBB processes CheckReqMsg and delivers FwdCheckReqMsg to VA
        /// (processes the front message for this session_id)
        DBBProcessCheckReq { session_id: SessionId },
        /// DBB processes RandomizerMsg and delivers FwdRandomizerMsg to BCA
        /// (processes the front message for this session_id)
        DBBProcessRandomizer { session_id: SessionId },
    }

    impl IntegrationState {
        /// Find the first available voter ID that hasn't cast a ballot yet,
        /// isn't currently assigned to a non-failed session, and isn't in the exclusion set.
        /// The exclusion set is used during action generation to avoid assigning the same
        /// voter ID to multiple concurrent auth requests in the same action batch.
        fn find_first_available_voter_id_excluding(
            state: &IntegrationState,
            exclude: &BTreeSet<usize>,
        ) -> Option<usize> {
            // Get all voter IDs currently assigned to active (non-failed) sessions
            // A session is "active" if it's not terminal (hasn't failed auth/eligibility/submission/casting)
            let assigned_ids: BTreeSet<usize> = state
                .voter_sessions
                .iter()
                .filter(|(_id, session)| {
                    !session.is_terminal() && session.assigned_voter_id.is_some()
                })
                .filter_map(|(_id, session)| session.assigned_voter_id)
                .collect();

            // Find the first registered voter that hasn't cast, isn't assigned to an active session,
            // and isn't in the exclusion set
            for session_id in 0..state.config.num_registered_voters {
                let pseudonym = format!("voter_{}", session_id);
                if !state
                    .dbb
                    .storage()
                    .test_voters_who_cast()
                    .contains(&pseudonym)
                    && !assigned_ids.contains(&session_id)
                    && !exclude.contains(&session_id)
                {
                    return Some(session_id);
                }
            }
            None
        }

        /// Find the first available voter ID that hasn't cast a ballot yet
        /// and isn't currently assigned to a non-failed session.
        fn find_first_available_voter_id(state: &IntegrationState) -> Option<usize> {
            Self::find_first_available_voter_id_excluding(state, &BTreeSet::new())
        }

        // TODO: For future testing of concurrent authentication scenarios:
        // fn find_first_active_voter_id(state: &IntegrationState) -> Option<usize> {
        //     // Return a voter ID that IS currently assigned to an active (non-terminal) session
        //     // This would be used to test "re-authentication while voting" scenarios
        //     state.voter_sessions
        //         .iter()
        //         .find(|s| !s.is_terminal() && s.assigned_voter_id.is_some())
        //         .and_then(|s| s.assigned_voter_id)
        // }

        /// Find the first voter ID that has already cast a ballot.
        fn find_first_voted_voter_id(state: &IntegrationState) -> Option<usize> {
            // Extract voter ID from first pseudonym in voters_who_cast (BTreeSet already sorted)
            if let Some(pseudonym) = state.dbb.storage().test_voters_who_cast().iter().next() {
                // Pseudonym format is "voter_{id}"
                if let Some(id_str) = pseudonym.strip_prefix("voter_")
                    && let Ok(voter_id) = id_str.parse::<usize>()
                {
                    return Some(voter_id);
                }
            }
            None
        }
    }

    impl Eq for IntegrationState {}

    /// Implement Stateright Model trait
    impl Model for IntegrationState {
        type State = Self;
        type Action = Action;

        fn init_states(&self) -> Vec<Self::State> {
            vec![IntegrationState::new(self.config.clone())]
        }

        fn properties(&self) -> Vec<Property<Self>> {
            vec![
                Property::always("no double voting", |_, state| no_double_voting(state)),
                Property::always("resource limits respected", |_, state| {
                    resource_limits_respected(state)
                }),
                Property::always("cast ballots on bulletin board", |_, state| {
                    all_cast_ballots_on_bulletin_board(state)
                }),
                Property::eventually("completion goal met", |_, state| completion_goal_met(state)),
                Property::sometimes("checks occur", |_, state: &IntegrationState| {
                    state.config.max_total_checks == 0 || state.total_checks_used > 0
                }),
                Property::sometimes("resubmissions occur", |_, state: &IntegrationState| {
                    state.config.max_total_resubmissions == 0 || state.total_resubmissions_used > 0
                }),
                Property::sometimes("abandons occur", |_, state: &IntegrationState| {
                    state.config.max_abandoned_sessions == 0 || state.abandoned_sessions > 0
                }),
                Property::sometimes("auth failures occur", |_, state: &IntegrationState| {
                    state.config.max_auth_failures == 0 || state.auth_failures > 0
                }),
                Property::sometimes(
                    "eligibility failures occur",
                    |_, state: &IntegrationState| {
                        state.config.max_eligibility_failures == 0 || state.eligibility_failures > 0
                    },
                ),
                Property::sometimes(
                    "double voting attempts occur",
                    |_, state: &IntegrationState| {
                        state.config.max_already_voted_attempts == 0
                            || state.already_voted_attempts > 0
                    },
                ),
                Property::sometimes(
                    "double voting failures occur",
                    |_, state: &IntegrationState| {
                        state.config.max_already_voted_attempts == 0
                            || state.already_voted_failures > 0
                    },
                ),
                Property::always(
                    "other failures do not occur",
                    |_, state: &IntegrationState| state.other_failures == 0,
                ),
            ]
        }

        fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
            // Stop generating actions if we've completed
            if state.completed_voters >= state.config.num_voters_to_complete {
                trace_print(format!(
                    "STOPPING: completed_voters ({}) >= num_voters_to_complete ({})",
                    state.completed_voters, state.config.num_voters_to_complete
                ));
                return;
            }

            // Allow starting a new session if we're below the concurrent limit
            // (counting only non-terminal sessions)
            let active_sessions = state
                .voter_sessions
                .iter()
                .filter(|(_id, session)| !session.is_terminal())
                .count();

            let actions_start_len = actions.len();

            // Debug: log action generation occasionally
            use std::sync::atomic::{AtomicU64, Ordering};
            static ACTION_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
            let count = ACTION_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
            let should_log = count.is_multiple_of(10000) || count < 100;
            if active_sessions < state.config.max_concurrent_sessions {
                // Generate session creation actions with different predetermined profiles
                // This creates branching at session creation rather than at EAS authorization

                // Can we create a successful voter session?
                // (need available voter IDs that haven't voted yet and aren't assigned)
                if Self::find_first_available_voter_id(state).is_some() {
                    actions.push(Action::StartNewSession(SessionProfile::SuccessfulVoter));
                }

                // Can we create an already-voted session?
                // (need at least one voter who has already cast)
                // Only test this if we haven't reached our limit
                if state.already_voted_attempts < state.config.max_already_voted_attempts
                    && state.completed_voters < state.config.num_voters_to_complete
                    && Self::find_first_voted_voter_id(state).is_some()
                {
                    actions.push(Action::StartNewSession(SessionProfile::AlreadyVotedVoter));
                }

                // Can we create an authentication failure session?
                // Count existing sessions plus completed failures
                let auth_fail_sessions = state
                    .voter_sessions
                    .values()
                    .filter(|s| matches!(s.profile, SessionProfile::AuthenticationFailed))
                    .count()
                    + state.auth_failures;
                if auth_fail_sessions < state.config.max_auth_failures {
                    actions.push(Action::StartNewSession(
                        SessionProfile::AuthenticationFailed,
                    ));
                }

                // Can we create an authorization failure session?
                // Count existing sessions plus completed failures
                let authz_fail_sessions = state
                    .voter_sessions
                    .values()
                    .filter(|s| matches!(s.profile, SessionProfile::AuthorizationFailed))
                    .count()
                    + state.eligibility_failures;
                if authz_fail_sessions < state.config.max_eligibility_failures {
                    actions.push(Action::StartNewSession(SessionProfile::AuthorizationFailed));
                }
            }

            // Check if ANY independent actions are pending
            // Independent actions: VA/BCA steps, EAS processing, AS responses, Protocol Driver decisions
            let has_independent_actions =
                // VA/BCA inbox messages (only for non-terminal sessions)
                state.voter_sessions.values().any(|session| {
                    !session.is_terminal() && (
                        !session.va_inbox.is_empty()
                        || (session.bca.is_some() && !session.bca_inbox.is_empty())
                    )
                })
                // EAS messages to process
                || !state.pending_messages.to_eas.is_empty()
                // AS messages to process
                || !state.pending_messages.to_as_service.is_empty()
                // Bio info checks to process
                || !state.pending_messages.bio_info_checks.is_empty();

            if has_independent_actions {
                actions.push(Action::ProcessAllIndependentActions);
            }

            // DBB messages - iterate over sessions with pending messages
            // Each action represents delivering the FRONT message from one session's queue
            // This explores all cross-session interleavings while maintaining FIFO within each session
            for (&session_id, queue) in &state.pending_messages.to_dbb {
                if let Some(msg) = queue.front() {
                    match msg {
                        ProtocolMessage::SubmitSignedBallot(_) => {
                            actions.push(Action::DBBProcessSignedBallot { session_id });
                        }
                        ProtocolMessage::CastReq(_) => {
                            let tracker = state
                                .voter_sessions
                                .get(&session_id)
                                .unwrap()
                                .va
                                .ballot_tracker()
                                .cloned();
                            trace_print(format!(
                                "Generating DBBProcessCastReq action for {:?} with tracker {:?}",
                                session_id, tracker
                            ));
                            actions.push(Action::DBBProcessCastReq { session_id });
                        }
                        ProtocolMessage::CheckReq(_) => {
                            actions.push(Action::DBBProcessCheckReq { session_id });
                        }
                        ProtocolMessage::Randomizer(_) => {
                            actions.push(Action::DBBProcessRandomizer { session_id });
                        }
                        _ => {
                            // Other message types to DBB
                        }
                    }
                }
            }

            // User commands (only when individual session is quiescent)
            for (&session_id, session) in &state.voter_sessions {
                if session.va.ballot_tracker().is_some() {
                    trace_print(format!(
                        "Session {:?} has tracker: {:?}, terminal: {}, has_cast: {}",
                        session_id,
                        session.va.ballot_tracker(),
                        session.is_terminal(),
                        session.has_cast
                    ));
                }

                // Skip terminal sessions
                if session.is_terminal() {
                    continue;
                }

                // Skip if this session has pending messages to process (in inbox or in pending_messages)
                if !session.va_inbox.is_empty()
                    || (session.bca.is_some() && !session.bca_inbox.is_empty())
                    || state
                        .pending_messages
                        .has_messages_for(session_id, &state.auth_req_to_voter)
                {
                    if session.va.ballot_tracker().is_some() && !session.has_cast {
                        trace_print(format!(
                            "Voter {:?} has tracker but skipping user commands - va_inbox len: {}, bca_inbox: {}, pending: {}",
                            session_id,
                            session.va_inbox.len(),
                            session.bca.is_some() && !session.bca_inbox.is_empty(),
                            state
                                .pending_messages
                                .has_messages_for(session_id, &state.auth_req_to_voter)
                        ));
                        if !session.va_inbox.is_empty() {
                            trace_print(format!(
                                "  VA inbox front: {:?}",
                                session.va_inbox.first()
                            ));
                        }
                    }
                    continue;
                }

                // Can abandon session (if within limit)
                if state.abandoned_sessions < state.config.max_abandoned_sessions {
                    actions.push(Action::UserAbandonSession(session_id));
                }

                // Start authentication (if not yet started)
                if session.assigned_voter_id.is_none()
                    && !session.auth_failed
                    && !session.eligibility_failed
                    && !session.third_party_auth_pending
                {
                    actions.push(Action::UserStartAuth(session_id));
                }

                // Complete third-party authentication (if pending)
                if session.third_party_auth_pending {
                    actions.push(Action::UserFinishAuth(session_id));
                }

                // Submit ballot (if VA authentication complete and no tracker yet)
                if session.va.voter_pseudonym().is_some() && session.va.ballot_tracker().is_none() {
                    actions.push(Action::UserSubmitBallot(session_id));
                }

                // Approve check request (if pending)
                if session.check_approval_pending {
                    actions.push(Action::UserApproveCheck(session_id));
                }

                // After submission - can check or cast
                if session.va.ballot_tracker().is_some() && !session.has_cast {
                    // If actively checking (BCA exists or approval pending), can't cast yet
                    let is_checking = session.bca.is_some() || session.check_approval_pending;

                    if !is_checking {
                        // Can check (if within limit)
                        if state.total_checks_used < state.config.max_total_checks {
                            trace_print(format!(
                                "Generating UserCheckBallot for voter {:?}, tracker: {:?}",
                                session_id,
                                session.va.ballot_tracker()
                            ));
                            actions.push(Action::UserCheckBallot(session_id));
                        }

                        // Can resubmit (if we've checked at least once and within global resubmission limit)
                        if session.check_count > 0
                            && state.total_resubmissions_used < state.config.max_total_resubmissions
                        {
                            actions.push(Action::UserSubmitBallot(session_id));
                        }

                        // Can cast (not checking)
                        actions.push(Action::UserCastBallot(session_id));
                    }
                    // If checking is in progress, no user actions until it completes or fails
                }
            }

            // Log action count and details
            if should_log {
                let num_actions = actions.len() - actions_start_len;
                trace_print(format!(
                    "actions() call {}: generated {} actions (completed={}, active={}/{}, total sessions={})",
                    count,
                    num_actions,
                    state.completed_voters,
                    active_sessions,
                    state.config.max_concurrent_sessions,
                    state.voter_sessions.len()
                ));

                // Log each action for the first few calls or when there are multiple actions
                if count < 50 || num_actions > 1 {
                    for (i, action) in actions.iter().skip(actions_start_len).enumerate() {
                        match action {
                            Action::StartNewSession(profile) => trace_print(format!(
                                "  Action {}: StartNewSession({:?})",
                                i, profile
                            )),
                            Action::ProcessAllIndependentActions => {
                                trace_print(format!("  Action {}: ProcessAllIndependentActions", i))
                            }
                            Action::UserStartAuth(vid) => {
                                trace_print(format!("  Action {}: UserStartAuth({:?})", i, vid))
                            }
                            Action::UserFinishAuth(vid) => {
                                trace_print(format!("  Action {}: UserFinishAuth({:?})", i, vid))
                            }
                            Action::UserSubmitBallot(vid) => {
                                trace_print(format!("  Action {}: UserSubmitBallot({:?})", i, vid))
                            }
                            Action::UserCheckBallot(vid) => {
                                trace_print(format!("  Action {}: UserCheckBallot({:?})", i, vid))
                            }
                            Action::UserApproveCheck(vid) => {
                                trace_print(format!("  Action {}: UserApproveCheck({:?})", i, vid))
                            }
                            Action::UserCastBallot(vid) => {
                                trace_print(format!("  Action {}: UserCastBallot({:?})", i, vid))
                            }
                            Action::UserAbandonSession(vid) => trace_print(format!(
                                "  Action {}: UserAbandonSession({:?})",
                                i, vid
                            )),
                            Action::DBBProcessSignedBallot { session_id, .. } => trace_print(
                                format!("  Action {}: DBBProcessSignedBallot({:?})", i, session_id),
                            ),
                            Action::DBBProcessCastReq { session_id, .. } => trace_print(format!(
                                "  Action {}: DBBProcessCastReq({:?})",
                                i, session_id
                            )),
                            Action::DBBProcessCheckReq { session_id, .. } => trace_print(format!(
                                "  Action {}: DBBProcessCheckReq({:?})",
                                i, session_id
                            )),
                            Action::DBBProcessRandomizer { session_id, .. } => trace_print(
                                format!("  Action {}: DBBProcessRandomizer({:?})", i, session_id),
                            ),
                        }
                    }
                }
            }
        }

        fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
            let mut next = state.clone();

            match action {
                // --- Session management ---
                Action::StartNewSession(profile) => {
                    // Track session creation for resource limits
                    if profile == SessionProfile::AlreadyVotedVoter {
                        next.already_voted_attempts += 1;
                    }

                    // Create a new voter session
                    let va = VAActor::new(
                        next.election_hash,
                        next.eas_verifying_key, // VA verifies messages from EAS
                        next.dbb_verifying_key,
                        next.election_key.clone(),
                    );
                    // Assign unique ID to this VA
                    let va_id = next.next_actor_id;
                    next.next_actor_id += 1;

                    // Assign new session ID and insert into map
                    let session_id = SessionId(next.next_session_id);
                    next.next_session_id += 1;
                    next.voter_sessions
                        .insert(session_id, VoterSessionState::new(va, va_id, profile));
                }

                // --- User command actions (queue commands in VA inbox) ---
                Action::UserStartAuth(session_id) => {
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();
                    session
                        .va_inbox
                        .push(VAMessage::Command(VACommand::StartAuthentication));
                }

                Action::UserFinishAuth(session_id) => {
                    // User has completed third-party auth
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();
                    session.va_inbox.push(VAMessage::SubprotocolInput(
                        VASubprotocolInput::Authentication(AuthenticationInput::Finish),
                    ));
                }

                Action::UserSubmitBallot(session_id) => {
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();

                    // Check if this is a resubmission (already has a tracker)
                    let is_resubmission = session.va.ballot_tracker().is_some();

                    if is_resubmission {
                        // Increment resubmission counters
                        session.resubmission_count += 1;
                        next.total_resubmissions_used += 1;
                    }

                    // Create a test ballot with a deterministic seed based on global counter
                    // This ensures ballots are deterministic regardless of session creation order
                    let seed = next.total_ballots_generated as u64;
                    next.total_ballots_generated += 1;
                    let mut ballot = Ballot::test_ballot(seed);

                    // Set the ballot style to match the voter's assigned ballot style
                    // to avoid unintended failures from ballot style mismatches
                    if let Some(assigned_id) = session.assigned_voter_id {
                        ballot.ballot_style = Self::ballot_style_for_registered_id(assigned_id);
                    }

                    session
                        .va_inbox
                        .push(VAMessage::Command(VACommand::StartSubmission(ballot)));
                }

                Action::UserCheckBallot(session_id) => {
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();

                    // Get the tracker for the current session
                    let tracker = session.va.ballot_tracker().cloned()?;

                    // Find the ballot on the bulletin board using the tracker
                    let bulletin = next
                        .dbb
                        .bulletin_board()
                        .get_bulletin(&tracker)
                        .ok()
                        .flatten()?;
                    let ballot = if let Bulletin::BallotSubmission(sub) = bulletin {
                        sub.data.ballot.clone()
                    } else {
                        return None;
                    };

                    // Create BCA actor with the ballot to check
                    let bca = BCAActor::new(
                        next.election_hash,
                        next.election_key.clone(),
                        next.dbb_verifying_key,
                    );

                    // Assign unique ID to this BCA
                    let bca_id = next.next_actor_id;
                    next.next_actor_id += 1;
                    session.bca = Some(bca);
                    session.bca_id = Some(bca_id);
                    session.bca_trace_hash = 0; // Reset trace hash for new BCA

                    // Send StartBallotCheck command to both VA and BCA
                    session
                        .va_inbox
                        .push(VAMessage::Command(VACommand::StartBallotCheck));
                    session
                        .bca_inbox
                        .push(BCAMessage::Command(BCACommand::StartBallotCheck(
                            tracker, ballot,
                        )));

                    session.check_count += 1;
                    next.total_checks_used += 1;
                }

                Action::UserApproveCheck(session_id) => {
                    // Send user approval to VA checking subprotocol
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();
                    session.va_inbox.push(VAMessage::SubprotocolInput(
                        VASubprotocolInput::Checking(CheckingInput::UserApproval(true)),
                    ));
                    // Note: check_approval_pending will be cleared when VA processes the approval
                }

                Action::UserCastBallot(session_id) => {
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();
                    session
                        .va_inbox
                        .push(VAMessage::Command(VACommand::StartCasting));
                }

                Action::UserAbandonSession(session_id) => {
                    let session = &mut next.voter_sessions.get_mut(&session_id).unwrap();
                    session.is_abandoned = true;
                    next.abandoned_sessions += 1;
                    // Remove terminal session immediately to prevent state explosion
                    Self::remove_terminal_session(&mut next, session_id);
                }

                // --- Process all independent actions atomically ---
                Action::ProcessAllIndependentActions => {
                    // Process VA/BCA steps
                    // Collect session IDs first to avoid borrow checker issues
                    // Only process non-terminal sessions
                    let session_ids: Vec<SessionId> = next.voter_sessions.keys().copied().collect();
                    for session_id in session_ids {
                        if let Some(session) = next.voter_sessions.get(&session_id) {
                            // Skip terminal sessions - they shouldn't have pending actions
                            if session.is_terminal() {
                                continue;
                            }
                            if !session.va_inbox.is_empty() {
                                Self::handle_va_step(&mut next, session_id)?;
                            }
                        }
                        if let Some(session) = next.voter_sessions.get(&session_id) {
                            if session.is_terminal() {
                                continue;
                            }
                            if session.bca.is_some() && !session.bca_inbox.is_empty() {
                                Self::handle_bca_step(&mut next, session_id)?;
                            }
                        }
                    }

                    // Process all EAS AuthReq messages
                    // Keep processing until no sessions have AuthReq at front of queue
                    loop {
                        // Find a session with AuthReq message at front of its queue
                        let session_id = next
                            .pending_messages
                            .to_eas
                            .iter()
                            .find(|(_, queue)| {
                                queue
                                    .front()
                                    .is_some_and(|msg| matches!(msg, ProtocolMessage::AuthReq(_)))
                            })
                            .map(|(session_id, _)| *session_id);

                        if let Some(session_id) = session_id {
                            Self::handle_eas_process_auth_req(&mut next, session_id)?;
                        } else {
                            break;
                        }
                    }

                    // Process all EAS AuthFinish messages
                    // Keep processing until no sessions have AuthFinish at front of queue
                    loop {
                        // Find a session with AuthFinish message at front of its queue
                        let session_id = next
                            .pending_messages
                            .to_eas
                            .iter()
                            .find(|(_, queue)| {
                                queue.front().is_some_and(|msg| {
                                    matches!(msg, ProtocolMessage::AuthFinish(_))
                                })
                            })
                            .map(|(session_id, _)| *session_id);

                        if let Some(session_id) = session_id {
                            Self::handle_eas_process_auth_finish(&mut next, session_id)?;
                        } else {
                            break;
                        }
                    }

                    // Process all AS responses
                    // Track allocated voter IDs to avoid collisions
                    let mut allocated_voter_ids = BTreeSet::new();
                    while !next.pending_messages.to_as_service.is_empty() {
                        let (auth_req_id, as_msg) = next.pending_messages.to_as_service[0].clone();

                        match as_msg {
                            AuthServiceMessage::InitAuthReq(_)
                            | AuthServiceMessage::AuthServiceQuery(_) => {
                                if let Some(session_id) = next.auth_req_to_voter.get(&auth_req_id) {
                                    let session = &next.voter_sessions.get_mut(session_id).unwrap();
                                    match session.profile {
                                        SessionProfile::AuthenticationFailed => {
                                            Self::handle_as_return_auth_failure(
                                                &mut next,
                                                auth_req_id,
                                            )?;
                                        }
                                        SessionProfile::AlreadyVotedVoter => {
                                            if let Some(registered_id) =
                                                Self::find_first_voted_voter_id(&next)
                                            {
                                                Self::handle_as_return_auth_success(
                                                    &mut next,
                                                    auth_req_id,
                                                    registered_id,
                                                )?;
                                            } else {
                                                break;
                                            }
                                        }
                                        _ => {
                                            if let Some(registered_id) =
                                                Self::find_first_available_voter_id_excluding(
                                                    &next,
                                                    &allocated_voter_ids,
                                                )
                                            {
                                                allocated_voter_ids.insert(registered_id);
                                                Self::handle_as_return_auth_success(
                                                    &mut next,
                                                    auth_req_id,
                                                    registered_id,
                                                )?;
                                            } else {
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    // Remove orphaned message (no session mapped to this auth_req_id)
                                    next.pending_messages.to_as_service.remove(0);
                                }
                            }
                            _ => {
                                // Remove unexpected message type
                                next.pending_messages.to_as_service.remove(0);
                            }
                        }
                    }

                    // Process all Protocol Driver bio decisions
                    while !next.pending_messages.bio_info_checks.is_empty() {
                        let (auth_req_id, _) = next.pending_messages.bio_info_checks[0];

                        if let Some(session_id) = next.auth_req_to_voter.get(&auth_req_id) {
                            let session = &next.voter_sessions.get_mut(session_id).unwrap();
                            match session.profile {
                                SessionProfile::AuthorizationFailed => {
                                    Self::handle_protocol_driver_reject_bio(
                                        &mut next,
                                        auth_req_id,
                                    )?;
                                }
                                _ => {
                                    if let Some(registered_id) = session.assigned_voter_id {
                                        Self::handle_protocol_driver_approve_bio(
                                            &mut next,
                                            auth_req_id,
                                            registered_id,
                                        )?;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        } else {
                            // Remove orphaned message
                            next.pending_messages.bio_info_checks.remove(0);
                        }
                    }

                    // Terminal sessions are now removed immediately when they become terminal,
                    // so no cleanup is needed here
                }

                // --- DBB response actions ---
                Action::DBBProcessSignedBallot { session_id } => {
                    Self::handle_dbb_process_signed_ballot(&mut next, session_id)?;
                }

                Action::DBBProcessCastReq { session_id } => {
                    Self::handle_dbb_process_cast_req(&mut next, session_id)?;
                }

                Action::DBBProcessCheckReq { session_id } => {
                    Self::handle_dbb_process_check_req(&mut next, session_id)?;
                }

                Action::DBBProcessRandomizer { session_id } => {
                    Self::handle_dbb_process_randomizer(&mut next, session_id)?;
                }
            }

            Some(next)
        }
    }

    // Property checking functions
    fn no_double_voting(state: &IntegrationState) -> bool {
        // Check the bulletin board to ensure no pseudonym has cast more than once
        let mut cast_pseudonyms = BTreeSet::new();

        for bulletin in state.dbb.bulletin_board().get_all_bulletins() {
            if let Bulletin::BallotCast(cast_bulletin) = bulletin {
                let pseudonym = &cast_bulletin.data.ballot.data.voter_pseudonym;
                if cast_pseudonyms.contains(pseudonym) {
                    // Found a duplicate cast!
                    return false;
                }
                cast_pseudonyms.insert(pseudonym.clone());
            }
        }

        true
    }

    fn resource_limits_respected(state: &IntegrationState) -> bool {
        state.total_checks_used <= state.config.max_total_checks
            && state.total_resubmissions_used <= state.config.max_total_resubmissions
            && state.abandoned_sessions <= state.config.max_abandoned_sessions
            && state.auth_failures <= state.config.max_auth_failures
            && state.eligibility_failures <= state.config.max_eligibility_failures
            && state.already_voted_attempts <= state.config.max_already_voted_attempts
    }

    fn all_cast_ballots_on_bulletin_board(state: &IntegrationState) -> bool {
        // Count cast ballots on bulletin board
        let bb_cast_count = state
            .dbb
            .bulletin_board()
            .get_all_bulletins()
            .iter()
            .filter(|b| matches!(b, Bulletin::BallotCast(_)))
            .count();

        // Check that internal counter matches bulletin board
        if state.dbb.storage().test_voters_who_cast().len() != bb_cast_count {
            return false;
        }

        // Check that every pseudonym in voters_who_cast appears on the BB
        for pseudonym in &state.dbb.storage().test_voters_who_cast() {
            let found = state
                .dbb
                .bulletin_board()
                .get_all_bulletins()
                .iter()
                .any(|b| {
                    if let Bulletin::BallotCast(cast) = b {
                        &cast.data.ballot.data.voter_pseudonym == pseudonym
                    } else {
                        false
                    }
                });
            if !found {
                return false;
            }
        }
        true
    }

    fn completion_goal_met(state: &IntegrationState) -> bool {
        // Check that the number of cast ballots on the bulletin board matches our goal
        let bb_cast_count = state
            .dbb
            .bulletin_board()
            .get_all_bulletins()
            .iter()
            .filter(|b| matches!(b, Bulletin::BallotCast(_)))
            .count();

        bb_cast_count >= state.config.num_voters_to_complete
    }

    #[test]
    fn test_2_2_no_failures() {
        // 2 voters completing with 2 concurrent sessions
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 0,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // this test is too large for CI
    fn test_4_2_no_failures() {
        // 4 voters completing with 2 concurrent sessions
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 4,
            num_registered_voters: 10,
            max_total_checks: 3,
            max_total_resubmissions: 2,
            max_abandoned_sessions: 0,
            max_auth_failures: 0,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    fn test_2_2_abandoned() {
        // 2 voters completing with 2 concurrent sessions, plus 1 abandoned session
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 0,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    fn test_2_2_auth() {
        // 2 voters completing with 2 concurrent sessions, plus 1 auth failure
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 1,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    fn test_2_2_eligibility() {
        // 2 voters completing with 2 concurrent sessions, plus 1 eligibility failure
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 0,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    fn test_2_2_already_voted() {
        // 2 voters completing with 2 concurrent sessions, plus 1 already voted attempt
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 0,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_abandoned_plus_auth() {
        // Test abandoned + auth failures together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 1,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_abandoned_plus_eligibility() {
        // Test abandoned + eligibility failures together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 0,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_abandoned_plus_already_voted() {
        // Test abandoned + already_voted together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 0,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_auth_plus_eligibility() {
        // Test auth + eligibility failures together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 1,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 0,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_auth_plus_already_voted() {
        // Test auth + already_voted together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 1,
            max_eligibility_failures: 0,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_2_2_eligibility_plus_already_voted() {
        // Test eligibility + already_voted together
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 10,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 0,
            max_auth_failures: 0,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // don't run combined tests in CI
    fn test_not_enough_voters() {
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 1,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 1,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        // the eventually property that enough voters vote should fail
        checker.assert_any_discovery("completion goal met");
    }

    #[test]
    #[ignore] // this test is too large for most machines
    fn test_2_2_all_failures() {
        // 2 voters completing with 2 concurrent sessions, plus all failure types
        let config = ModelConfig {
            max_concurrent_sessions: 2,
            num_voters_to_complete: 2,
            num_registered_voters: 4,
            max_total_checks: 2,
            max_total_resubmissions: 1,
            max_abandoned_sessions: 1,
            max_auth_failures: 1,
            max_eligibility_failures: 1,
            max_already_voted_attempts: 1,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }

    #[test]
    #[ignore] // this test is far too large for most machines
    fn test_3_6_all_failures() {
        // 6 voters completing wih 3 concurrent sessions, plus all failure types
        let config = ModelConfig {
            max_concurrent_sessions: 3,
            num_voters_to_complete: 6,
            num_registered_voters: 10,
            max_total_checks: 3,
            max_total_resubmissions: 3,
            max_abandoned_sessions: 3,
            max_auth_failures: 2,
            max_eligibility_failures: 3,
            max_already_voted_attempts: 3,
        };

        let model = IntegrationState::new(config);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();

        println!(
            "Model checking complete - explored {} states ({} unique)",
            checker.state_count(),
            checker.unique_state_count()
        );

        checker.assert_properties();
    }
}
