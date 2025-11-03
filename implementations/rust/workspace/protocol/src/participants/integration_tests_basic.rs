// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Basic end-to-end test of the Internet-facing protocols. This
//! test model the complete message-passing system between the VA, BCA,
//! EAS, and DBB, verifying that the protocols work correctly when
//! there is reliable, ordered message delivery. More complex tests are
//! performed by the Stateright model checker elsewhere.

#[cfg(test)]
mod tests {
    use crate::auth_service::{
        AuthServiceMessage, AuthServiceQueryMsg, AuthServiceReportMsg, InitAuthReqMsg,
        TokenReturnMsg,
    };
    use crate::bulletins::Bulletin;
    use crate::cryptography::{Context, CryptographyContext, ElectionKey, SigningKey};
    use crate::elections::{
        Ballot, BallotStyle, BallotTracker, ElectionHash, VoterPseudonym, string_to_election_hash,
    };
    use crate::messages::SignedBallotMsg;
    use crate::participants::ballot_check_application::top_level_actor::{
        ActorInput as BCAInput, TopLevelActor as BCAActor,
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
    use crate::participants::voting_application::top_level_actor::{
        ActorInput as VAInput, Command as VACommand, SubprotocolInput as VASubprotocolInput,
        SubprotocolOutput as VASubprotocolOutput, TopLevelActor as VAActor,
    };
    use std::collections::BTreeMap;

    const MANIFEST: &str = "test_election_manifest";

    // --- Mock Actors ---
    //
    // We use the real DBB implementation with in-memory storage and bulletin board.
    // Only the AS (Authentication Service) remains mocked as it's an external third-party service.

    /// Mock Authentication Service
    /// Simulates the external third-party authentication service
    #[derive(Clone, Debug)]
    struct MockAS {
        // Counter for generating unique tokens and session IDs
        next_session_id: u64,
        // Maps session_id to (token, biographical_info)
        sessions: BTreeMap<String, (String, String)>,
    }

    impl MockAS {
        fn new() -> Self {
            Self {
                next_session_id: 0,
                sessions: BTreeMap::new(),
            }
        }

        /// Handle InitAuthReqMsg from EAS - create a new session and return token
        fn handle_init_auth_req(&mut self, _msg: InitAuthReqMsg) -> TokenReturnMsg {
            // Generate unique session ID and token
            let session_id = format!("session_{}", self.next_session_id);
            let token = format!("token_{}", self.next_session_id);
            self.next_session_id += 1;

            // Store session with placeholder biographical info
            // In simple test, authentication always succeeds
            let biographical_info = format!("bio_info_for_{}", token);
            self.sessions
                .insert(session_id.clone(), (token.clone(), biographical_info));

            TokenReturnMsg { token, session_id }
        }

        /// Handle AuthServiceQueryMsg from EAS - return authentication result
        fn handle_query(&self, msg: AuthServiceQueryMsg) -> Result<AuthServiceReportMsg, String> {
            let (token, biographical_info) = self
                .sessions
                .get(&msg.session_id)
                .ok_or_else(|| "Session not found".to_string())?
                .clone();

            // In simple test, authentication always succeeds
            Ok(AuthServiceReportMsg {
                token,
                session_id: msg.session_id,
                biographical_info: Some(biographical_info),
                authenticated: true,
            })
        }
    }

    // --- Integration Test State ---

    /// Helper to create test election keys
    fn setup_election() -> (ElectionHash, ElectionKey, SigningKey, SigningKey) {
        use crate::cryptography::generate_encryption_keypair;

        let election_hash = string_to_election_hash(MANIFEST);
        let keypair = generate_encryption_keypair(MANIFEST.as_bytes())
            .expect("Failed to generate election keypair");
        let election_key = keypair.pkey.clone();

        let mut rng = CryptographyContext::get_rng();
        let eas_signing_key = SigningKey::generate(&mut rng);
        let dbb_signing_key = SigningKey::generate(&mut rng);

        (
            election_hash,
            election_key,
            eas_signing_key,
            dbb_signing_key,
        )
    }

    #[test]
    fn test_basic_happy_path() {
        test_voters_with_checks_and_resubmits(1, 1, 0);
    }

    #[test]
    fn test_multiple_voters_sequential() {
        test_voters_with_checks_and_resubmits(3, 1, 0);
    }

    #[test]
    fn test_voter_with_multiple_checks() {
        test_voters_with_checks_and_resubmits(1, 3, 0);
    }

    #[test]
    fn test_voter_with_checks_and_resubmits() {
        test_voters_with_checks_and_resubmits(1, 2, 2);
    }

    #[test]
    fn test_multiple_voters_with_checks_and_resubmits() {
        test_voters_with_checks_and_resubmits(3, 2, 2);
    }

    #[test]
    fn test_many_voters_with_checks_and_resubmits() {
        test_voters_with_checks_and_resubmits(100, 2, 1);
    }

    /// Test with multiple voters going through the full protocol flow sequentially.
    ///
    /// # Parameters
    /// - `num_voters`: Number of voters to process
    /// - `checks_per_submission`: How many times each voter checks their ballot before casting
    /// - `resubmissions`: How many times each voter resubmits (abandoning previous ballot)
    ///
    /// Each voter: authenticates -> (submit -> check* -> [resubmit])* -> submit -> check* -> cast
    fn test_voters_with_checks_and_resubmits(
        num_voters: usize,
        checks_per_submission: usize,
        resubmissions: usize,
    ) {
        println!("\n=== Internet-Facing Protocol Integration Test ===");
        println!(
            "Voters: {}, Checks per submission: {}, Resubmissions: {}",
            num_voters, checks_per_submission, resubmissions
        );

        // Setup
        let (election_hash, election_key, eas_signing_key, dbb_signing_key) = setup_election();

        let eas_verifying_key = eas_signing_key.verifying_key();
        let dbb_verifying_key = dbb_signing_key.verifying_key();

        // Create mock backend actors (shared across all voters)
        let mut mock_as = MockAS::new();
        let mut eas = EASActor::new(
            election_hash,
            eas_signing_key.clone(),
            std::time::Duration::from_secs(60), // 60 second timeout
            "test_project_id".to_string(),
            "test_api_key".to_string(),
        );

        // Create real DBB with in-memory storage and bulletin board
        let storage = InMemoryStorage::new();
        let mut dbb = DigitalBallotBoxActor::new(
            storage,
            InMemoryBulletinBoard::new(),
            election_hash,
            dbb_signing_key.clone(),
            dbb_verifying_key,
            eas_verifying_key,
            election_key.clone(),
        );

        // Connection ID management for the real DBB
        let mut next_connection_id: u64 = 1000;
        let mut va_connection_ids: BTreeMap<usize, u64> = BTreeMap::new(); // voter_num -> connection_id

        // Maps VA connection ID to BCA checking session ID for routing incoming VA messages
        // This simulates what a real networking application would maintain
        let mut va_to_bca_session: BTreeMap<u64, u64> = BTreeMap::new();

        // Maps AuthReqId to (voter_pseudonym, ballot_style) for biographical info verification
        let mut pending_auth_requests: BTreeMap<AuthReqId, (VoterPseudonym, BallotStyle)> =
            BTreeMap::new();

        // Process each voter sequentially
        for voter_num in 0..num_voters {
            println!("\n========== VOTER {} ==========", voter_num + 1);

            // Create a new VA for this voter
            let mut va = VAActor::new(
                election_hash,
                eas_verifying_key,
                dbb_verifying_key,
                election_key.clone(),
            );

            // Each voter gets their own pseudonym and can have different ballot styles
            let voter_pseudonym: VoterPseudonym = format!("voter{}_pseudonym", voter_num + 1);
            let ballot_style: BallotStyle = ((voter_num % 3) + 1) as BallotStyle; // Cycle through styles 1, 2, 3

            println!("\n--- Phase 1: Voter Authentication ---");

            // Start authentication
            let auth_result = va.process_input(VAInput::Command(VACommand::StartAuthentication));
            assert!(auth_result.is_ok(), "Failed to start authentication");

            let auth_output = auth_result.unwrap();
            println!("VA: Authentication started");

            // Extract the authentication request message to send to EAS
            if let VASubprotocolOutput::Authentication(auth_sub_output) = auth_output {
                use crate::participants::voting_application::sub_actors::authentication::AuthenticationOutput;

                match auth_sub_output {
                    AuthenticationOutput::SendMessage(msg) => {
                        if let crate::messages::ProtocolMessage::AuthReq(auth_req) = msg {
                            println!("VA -> EAS: AuthReq");

                            // EAS processes auth request (creates new sub-actor)
                            let eas_result = eas.process_input(EASInput::Command(
                                EASCommand::StartVoterAuthentication(auth_req),
                            ));

                            assert!(eas_result.is_ok(), "EAS should handle auth request");

                            if let Ok(EASSubprotocolOutput::VoterAuthentication(
                                eas_output,
                                auth_req_id,
                            )) = eas_result
                            {
                                // Store voter info for later biographical verification
                                pending_auth_requests
                                    .insert(auth_req_id, (voter_pseudonym.clone(), ballot_style));

                                // Process EAS output (should be InitAuthReq to AS)
                                if let VoterAuthenticationOutput::AuthServiceMessage(
                                    AuthServiceMessage::InitAuthReq(init_req),
                                ) = eas_output
                                {
                                    println!("EAS -> AS: InitAuthReq");

                                    // AS creates session and returns token
                                    let token_return = mock_as.handle_init_auth_req(init_req);
                                    println!("AS -> EAS: TokenReturn");

                                    // Send token back to EAS
                                    let token_result =
                                        eas.process_input(EASInput::SubprotocolInput(
                                            EASSubprotocolInput::VoterAuthentication(
                                                VoterAuthenticationInput::AuthServiceMessage(
                                                    AuthServiceMessage::TokenReturn(token_return),
                                                ),
                                            ),
                                            auth_req_id,
                                        ));

                                    assert!(token_result.is_ok(), "EAS should handle token");

                                    if let Ok(EASSubprotocolOutput::VoterAuthentication(
                                        VoterAuthenticationOutput::NetworkMessage(messages),
                                        _,
                                    )) = token_result
                                    {
                                        // EAS should send HandToken to VA
                                        assert_eq!(messages.len(), 1, "Expected 1 message");
                                        if let crate::messages::ProtocolMessage::HandToken(
                                            hand_token_msg,
                                        ) = &messages[0]
                                        {
                                            println!("EAS -> VA: HandToken");

                                            // VA receives token
                                            let token_result = va.process_input(
                                                VAInput::SubprotocolInput(
                                                    VASubprotocolInput::Authentication(
                                                        crate::participants::voting_application::sub_actors::authentication::AuthenticationInput::NetworkMessage(
                                                            crate::messages::ProtocolMessage::HandToken(hand_token_msg.clone())
                                                        )
                                                    )
                                                )
                                            );

                                            assert!(token_result.is_ok(), "VA should accept token");

                                            // Simulate user completing third-party authentication
                                            println!("User: Completes external authentication");

                                            let finish_result = va.process_input(
                                                VAInput::SubprotocolInput(
                                                    VASubprotocolInput::Authentication(
                                                        crate::participants::voting_application::sub_actors::authentication::AuthenticationInput::Finish
                                                    )
                                                )
                                            );

                                            assert!(
                                                finish_result.is_ok(),
                                                "VA should send finish message"
                                            );

                                            if let Ok(VASubprotocolOutput::Authentication(
                                                AuthenticationOutput::SendMessage(
                                                    crate::messages::ProtocolMessage::AuthFinish(
                                                        auth_finish_msg,
                                                    ),
                                                ),
                                            )) = finish_result
                                            {
                                                println!("VA -> EAS: AuthFinish");

                                                // EAS processes auth finish
                                                let finish_result = eas.process_input(
                                                    EASInput::SubprotocolInput(
                                                        EASSubprotocolInput::VoterAuthentication(
                                                            VoterAuthenticationInput::NetworkMessage(
                                                                crate::messages::ProtocolMessage::AuthFinish(
                                                                    auth_finish_msg,
                                                                ),
                                                            ),
                                                        ),
                                                        auth_req_id,
                                                    ),
                                                );

                                                assert!(
                                                    finish_result.is_ok(),
                                                    "EAS should handle auth finish"
                                                );

                                                if let Ok(EASSubprotocolOutput::VoterAuthentication(
                                                    VoterAuthenticationOutput::AuthServiceMessage(
                                                        AuthServiceMessage::AuthServiceQuery(query),
                                                    ),
                                                    _,
                                                )) = finish_result
                                                {
                                                    println!("EAS -> AS: AuthServiceQuery");

                                                    // AS returns authentication result
                                                    let report = mock_as
                                                        .handle_query(query)
                                                        .expect("AS should return report");
                                                    println!("AS -> EAS: AuthServiceReport");

                                                    // Send report to EAS
                                                    let report_result = eas.process_input(
                                                        EASInput::SubprotocolInput(
                                                            EASSubprotocolInput::VoterAuthentication(
                                                                VoterAuthenticationInput::AuthServiceMessage(
                                                                    AuthServiceMessage::AuthServiceReport(report),
                                                                ),
                                                            ),
                                                            auth_req_id,
                                                        ),
                                                    );

                                                    assert!(
                                                        report_result.is_ok(),
                                                        "EAS should handle report"
                                                    );

                                                    if let Ok(EASSubprotocolOutput::VoterAuthentication(
                                                        VoterAuthenticationOutput::CheckBiographicalInfo(_),
                                                        _,
                                                    )) = report_result
                                                    {
                                                        println!("EAS: Checking biographical info");

                                                        // In simple test, always approve
                                                        let (voter_pseudonym, ballot_style) =
                                                            pending_auth_requests
                                                                .get(&auth_req_id)
                                                                .expect("Should have pending request")
                                                                .clone();

                                                        let bio_ok_result = eas.process_input(
                                                            EASInput::SubprotocolInput(
                                                                EASSubprotocolInput::VoterAuthentication(
                                                                    VoterAuthenticationInput::BiographicalInfoOk {
                                                                        voter_pseudonym: voter_pseudonym.clone(),
                                                                        ballot_style,
                                                                    },
                                                                ),
                                                                auth_req_id,
                                                            ),
                                                        );

                                                        assert!(
                                                            bio_ok_result.is_ok(),
                                                            "EAS should handle bio ok"
                                                        );

                                                        if let Ok(EASSubprotocolOutput::VoterAuthentication(
                                                            VoterAuthenticationOutput::NetworkMessage(
                                                                messages,
                                                            ),
                                                            _,
                                                        )) = bio_ok_result
                                                        {
                                                            // EAS should send both AuthVoter (to DBB) and ConfirmAuthorization (to VA)
                                                            assert_eq!(
                                                                messages.len(),
                                                                2,
                                                                "Expected 2 messages"
                                                            );

                                                            // Find AuthVoter and ConfirmAuthorization messages
                                                            let mut auth_voter_msg = None;
                                                            let mut confirm_auth_msg = None;

                                                            for msg in &messages {
                                                                match msg {
                                                                    crate::messages::ProtocolMessage::AuthVoter(m) => {
                                                                        auth_voter_msg = Some(m.clone());
                                                                    }
                                                                    crate::messages::ProtocolMessage::ConfirmAuthorization(m) => {
                                                                        confirm_auth_msg = Some(m.clone());
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }

                                                            let auth_voter_msg = auth_voter_msg
                                                                .expect("Should have AuthVoter message");
                                                            let _confirm_auth_msg = confirm_auth_msg
                                                                .expect("Should have ConfirmAuthorization message");

                                                            println!("EAS -> DBB: AuthVoter");

                                                            // DBB records authorization
                                                            dbb.process_input(DBBInput::EASMessage(EASMessage {
                                                                message: auth_voter_msg.clone(),
                                                            }))
                                                                .expect("DBB should record authorization");

                                                            println!("EAS -> VA: ConfirmAuthorization");

                                                            // VA receives ConfirmAuthorization message
                                                            let auth_complete_result = va.process_input(
                                                                VAInput::SubprotocolInput(
                                                                    VASubprotocolInput::Authentication(
                                                                        crate::participants::voting_application::sub_actors::authentication::AuthenticationInput::NetworkMessage(
                                                                            crate::messages::ProtocolMessage::ConfirmAuthorization(_confirm_auth_msg)
                                                                        )
                                                                    )
                                                                )
                                                            );

                                                            assert!(
                                                                auth_complete_result.is_ok(),
                                                                "VA should complete authentication"
                                                            );
                                                            println!("✓ Authentication complete");

                                                            // Clean up pending request
                                                            pending_auth_requests.remove(&auth_req_id);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            panic!("Expected AuthReq message");
                        }
                    }
                    _ => panic!("Expected SendMessage output from authentication start"),
                }
            } else {
                panic!("Expected Authentication output");
            }

            // Voter may submit and check multiple times before final casting (resubmissions)
            // We track all submitted ballots, but only the final one will be cast
            let mut all_trackers: Vec<BallotTracker> = Vec::new();

            let mut last_signed_ballot: Option<SignedBallotMsg> = None;

            // Outer loop: submission attempts (initial + resubmissions)
            for submission_num in 0..=resubmissions {
                println!(
                    "\n--- Submission {} of {} ---",
                    submission_num + 1,
                    resubmissions + 1
                );

                println!("\n--- Phase 2: Ballot Submission ---");

                // Create a unique test ballot for this submission
                // Use voter_num and submission_num to generate unique ballots
                let ballot_seed = 42 + (voter_num * 100) + (submission_num * 10);
                let mut test_ballot = Ballot::test_ballot(ballot_seed as u64);
                // Override the ballot_style to match the voter's assigned ballot_style
                test_ballot.ballot_style = ballot_style;

                // Variable to store the ballot tracker for this submission
                let ballot_tracker: BallotTracker;

                // Start submission
                let submit_result = va.process_input(VAInput::Command(VACommand::StartSubmission(
                    test_ballot.clone(),
                )));
                assert!(submit_result.is_ok(), "Failed to start submission");

                println!("VA: Ballot submission started");

                // Extract and send the signed ballot to DBB
                if let Ok(VASubprotocolOutput::Submission(submission_output)) = submit_result {
                    use crate::participants::voting_application::sub_actors::submission::SubmissionOutput;

                    match submission_output {
                        SubmissionOutput::SendMessage(msg) => {
                            if let crate::messages::ProtocolMessage::SubmitSignedBallot(
                                signed_ballot,
                            ) = msg
                            {
                                println!("VA -> DBB: SignedBallot");

                                // Store the signed ballot for later checking
                                last_signed_ballot = Some(signed_ballot.clone());

                                // Assign connection ID for this VA if not already assigned
                                let connection_id =
                                    *va_connection_ids.entry(voter_num).or_insert_with(|| {
                                        let id = next_connection_id;
                                        next_connection_id += 1;
                                        id
                                    });

                                // DBB processes submission
                                let output = dbb
                                    .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                                        connection_id,
                                        message:
                                            crate::messages::ProtocolMessage::SubmitSignedBallot(
                                                signed_ballot,
                                            ),
                                    }))
                                    .expect("DBB should accept ballot");

                                // Extract tracker message from output
                                let tracker_msg = if let DBBOutput::OutgoingMessage(outgoing) =
                                    output
                                {
                                    if let crate::messages::ProtocolMessage::ReturnBallotTracker(
                                        tracker,
                                    ) = outgoing.message
                                    {
                                        tracker
                                    } else {
                                        panic!("Expected ReturnBallotTracker from DBB");
                                    }
                                } else {
                                    panic!("Expected OutgoingMessage from DBB");
                                };

                                println!("DBB -> VA: TrackerMsg");

                                // VA receives tracker
                                let tracker_result = va.process_input(VAInput::SubprotocolInput(
                            VASubprotocolInput::Submission(
                                crate::participants::voting_application::sub_actors::submission::SubmissionInput::NetworkMessage(
                                    crate::messages::ProtocolMessage::ReturnBallotTracker(tracker_msg.clone())
                                )
                            )
                        ));

                                // VA may request to fetch bulletin after receiving tracker
                                match tracker_result {
                                    Ok(VASubprotocolOutput::Submission(crate::participants::voting_application::sub_actors::submission::SubmissionOutput::FetchBulletin(bulletin_hash))) => {
                                        println!("VA requests bulletin: {}", bulletin_hash);

                                        // Fetch bulletin from the bulletin board
                                        let bulletin = dbb.bulletin_board().get_bulletin(&bulletin_hash)
                                            .expect("Failed to fetch bulletin")
                                            .expect("Bulletin should exist on DBB");

                                        // Provide bulletin to VA
                                        let bulletin_result = va.process_input(VAInput::SubprotocolInput(
                                            VASubprotocolInput::Submission(
                                                crate::participants::voting_application::sub_actors::submission::SubmissionInput::PBBData(bulletin)
                                            )
                                        ));

                                        // After receiving bulletin, VA should complete successfully
                                        if let Ok(VASubprotocolOutput::Submission(crate::participants::voting_application::sub_actors::submission::SubmissionOutput::Success(_))) = bulletin_result {
                                            ballot_tracker = tracker_msg
                                                .data
                                                .tracker
                                                .clone()
                                                .expect("tracker should always exist in this test");
                                            println!("✓ Ballot submission complete, tracker: {}", ballot_tracker);
                                        } else {
                                            panic!("Expected Success after bulletin fetch, got: {:?}", bulletin_result);
                                        }
                                    }
                                    Ok(VASubprotocolOutput::Submission(crate::participants::voting_application::sub_actors::submission::SubmissionOutput::Success(_))) => {
                                        // Direct success without bulletin fetch
                                        ballot_tracker = tracker_msg
                                            .data
                                            .tracker
                                            .clone()
                                            .expect("tracker should always exist in this test");
                                        println!("✓ Ballot submission complete, tracker: {}", ballot_tracker);
                                    }
                                    _ => panic!("Expected Success or FetchBulletin after tracker, got: {:?}", tracker_result)
                                }
                            } else {
                                panic!("Expected SubmitSignedBallot message");
                            }
                        }
                        _ => panic!("Expected SendMessage from submission"),
                    }
                } else {
                    panic!("Expected Submission output");
                }

                println!(
                    "\n--- Phase 3: Ballot Checking ({} times) ---",
                    checks_per_submission
                );

                // Perform multiple checks if requested
                for check_num in 0..checks_per_submission {
                    println!("\n  -- Check {} --", check_num + 1);

                    // Create a separate BCA instance for each check
                    let mut bca =
                        BCAActor::new(election_hash, election_key.clone(), dbb_verifying_key);

                    // BCA should fetch the ballot from the bulletin board using the tracker
                    let bulletin = dbb
                        .bulletin_board()
                        .get_bulletin(&ballot_tracker)
                        .expect("Failed to fetch bulletin")
                        .expect("Bulletin should exist on bulletin board");

                    // Extract the signed ballot from the bulletin
                    let check_ballot =
                        if let Bulletin::BallotSubmission(ballot_sub_bulletin) = bulletin {
                            ballot_sub_bulletin.data.ballot.clone()
                        } else {
                            panic!("Expected BallotSubmission bulletin");
                        };

                    let check_start = bca.process_input(BCAInput::Command(
            crate::participants::ballot_check_application::top_level_actor::Command::StartBallotCheck(
                ballot_tracker.clone(),
                check_ballot
            )
        ));

                    println!("BCA: Ballot check started");

                    if let Ok(Some(crate::participants::ballot_check_application::top_level_actor::SubprotocolOutput::BallotCheck(check_output))) = check_start {
            use crate::participants::ballot_check_application::sub_actors::ballot_check::BallotCheckOutput;

            match check_output {
                BallotCheckOutput::SendMessage(msg) => {
                    if let crate::messages::ProtocolMessage::CheckReq(check_req) = msg {
                        println!("BCA -> DBB: CheckReq");

                        // Assign connection ID for BCA
                        let bca_connection_id = next_connection_id;
                        next_connection_id += 1;

                        // Send CheckReq to DBB
                        let output = dbb
                            .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                                connection_id: bca_connection_id,
                                message: crate::messages::ProtocolMessage::CheckReq(check_req),
                            }))
                            .expect("DBB should accept check request");

                        // DBB will request VA connection - extract the forwarded check request
                        let fwd_check = if let DBBOutput::RequestVAConnection { tracker, bca_connection_id: _ } = output {
                            println!("DBB requests VA connection for tracker: {}", tracker);

                            // Use the voter's existing connection ID (same connection for submission and checking)
                            let va_connection_id = va_connection_ids[&voter_num];

                            // Store the mapping: when messages come from this VA connection, route them to the BCA checking session
                            va_to_bca_session.insert(va_connection_id, bca_connection_id);

                            let provide_output = dbb
                                .process_input(DBBInput::Command(DBBCommand::ProvideVAConnection {
                                    checking_session_id: bca_connection_id,
                                    va_connection_id,
                                }))
                                .expect("DBB should accept VA connection");

                            // Extract the forwarded check request
                            if let DBBOutput::OutgoingMessage(outgoing) = provide_output {
                                if let crate::messages::ProtocolMessage::FwdCheckReq(fwd_check) = outgoing.message {
                                    println!("DBB -> VA: FwdCheckReq");
                                    fwd_check
                                } else {
                                    panic!("Expected FwdCheckReq from DBB");
                                }
                            } else {
                                panic!("Expected OutgoingMessage after providing VA connection");
                            }
                        } else {
                            panic!("Expected RequestVAConnection from DBB, got: {:?}", output);
                        };

                        // VA needs to start checking subprotocol first
                        let start_check = va.process_input(VAInput::Command(VACommand::StartBallotCheck));
                        assert!(start_check.is_ok(), "VA should start checking");

                        // VA receives check request and user approves
                        let check_req_result = va.process_input(VAInput::SubprotocolInput(
                            VASubprotocolInput::Checking(
                                crate::participants::voting_application::sub_actors::checking::CheckingInput::NetworkMessage(
                                    crate::messages::ProtocolMessage::FwdCheckReq(fwd_check)
                                )
                            )
                        ));

                        // VA should request user approval
                        if let Ok(VASubprotocolOutput::Checking(
                            crate::participants::voting_application::sub_actors::checking::CheckingOutput::InteractionRequired(msg)
                        )) = check_req_result {
                            println!("VA: Request user approval for check: {}", msg);

                            // User approves the check request
                            let approve_result = va.process_input(VAInput::SubprotocolInput(
                                VASubprotocolInput::Checking(
                                    crate::participants::voting_application::sub_actors::checking::CheckingInput::UserApproval(true)
                                )
                            ));

                            if let Ok(VASubprotocolOutput::Checking(
                                crate::participants::voting_application::sub_actors::checking::CheckingOutput::Success(outcome)
                            )) = approve_result {
                                // Extract the randomizer message from the outcome
                                use crate::participants::voting_application::sub_actors::checking::BallotCheckOutcome;
                                if let BallotCheckOutcome::RandomizersSent { randomizer_msg } = outcome {
                                    if let crate::messages::ProtocolMessage::Randomizer(randomizer_msg) = randomizer_msg {
                                        println!("VA -> DBB: Randomizer");

                                        // Route the Randomizer to the correct BCA checking session
                                        // The application layer looks up which BCA session this VA connection maps to
                                        let va_connection_id = va_connection_ids[&voter_num];
                                        let bca_checking_session_id = va_to_bca_session[&va_connection_id];

                                        let output = dbb
                                            .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                                                connection_id: bca_checking_session_id,
                                                message: crate::messages::ProtocolMessage::Randomizer(randomizer_msg),
                                            }))
                                            .expect("DBB should accept randomizer");

                                        // Extract forwarded randomizer from output
                                        let fwd_randomizer = if let DBBOutput::OutgoingMessage(outgoing) = output {
                                            if let crate::messages::ProtocolMessage::FwdRandomizer(fwd_rand) = outgoing.message {
                                                fwd_rand
                                            } else {
                                                panic!("Expected FwdRandomizer from DBB");
                                            }
                                        } else {
                                            panic!("Expected OutgoingMessage from DBB");
                                        };

                                        println!("DBB -> BCA: FwdRandomizer");

                                        // BCA receives randomizers and completes check
                                        let check_complete = bca.process_input(BCAInput::SubprotocolInput(
                                            crate::participants::ballot_check_application::top_level_actor::SubprotocolInput::BallotCheck(
                                                crate::participants::ballot_check_application::sub_actors::ballot_check::BallotCheckInput::NetworkMessage(
                                                    crate::messages::ProtocolMessage::FwdRandomizer(fwd_randomizer)
                                                )
                                            )
                                        ));

                                        if let Ok(Some(crate::participants::ballot_check_application::top_level_actor::SubprotocolOutput::BallotCheck(
                                            BallotCheckOutput::PlaintextBallot(decrypted_ballot)
                                        ))) = check_complete {
                                            println!("✓ Ballot check complete - ballot decrypted");

                                            // Verify the decrypted ballot matches the original
                                            assert_eq!(decrypted_ballot, test_ballot, "Decrypted ballot should match original ballot");
                                            println!("✓ Verified: Decrypted ballot matches original ballot");
                                        } else {
                                            panic!("Expected PlaintextBallot, got: {:?}", check_complete);
                                        }
                                    } else {
                                        panic!("Expected Randomizer protocol message");
                                    }
                                } else {
                                    panic!("Expected RandomizersSent outcome");
                                }
                            } else {
                                panic!("Expected Success output after approval, got: {:?}", approve_result);
                            }
                        } else {
                            panic!("Expected InteractionRequired, got: {:?}", check_req_result);
                        }
                    } else {
                        panic!("Expected CheckReq message");
                    }
                }
                _ => panic!("Expected SendMessage from check start"),
            }
        } else {
            panic!("Expected BallotCheck output");
        }

                    println!("  ✓ Check {} complete", check_num + 1);
                } // End of check loop

                // Store this submission's tracker
                all_trackers.push(ballot_tracker.clone());
                println!(
                    "✓ Submission {} complete, tracker: {}",
                    submission_num + 1,
                    ballot_tracker
                );

                // If this is not the final submission, voter decides to resubmit
                if submission_num < resubmissions {
                    println!("Voter decides to abandon this ballot and resubmit a new one");
                }
            } // End of resubmission loop

            // The last tracker is the one we'll cast
            let final_tracker: BallotTracker = all_trackers.last().unwrap().clone();
            println!("\n--- Final ballot to cast: tracker {} ---", final_tracker);

            println!("\n--- Phase 4: Ballot Casting ---");

            // Start casting
            let cast_result = va.process_input(VAInput::Command(VACommand::StartCasting));
            assert!(
                cast_result.is_ok(),
                "Failed to start casting: {:?}",
                cast_result
            );

            println!("VA: Ballot casting started");

            // Extract and send cast request to DBB
            if let Ok(VASubprotocolOutput::Casting(casting_output)) = cast_result {
                use crate::participants::voting_application::sub_actors::casting::CastingOutput;

                match casting_output {
                    CastingOutput::Failure(err) => {
                        panic!("Casting failed: {}", err);
                    }
                    CastingOutput::SendMessage(msg) => {
                        if let crate::messages::ProtocolMessage::CastReq(cast_req) = msg {
                            println!("VA -> DBB: CastReq");

                            // Use the same connection ID that was assigned during submission
                            let connection_id = va_connection_ids[&voter_num];

                            // DBB processes cast request
                            let output = dbb
                                .process_input(DBBInput::IncomingMessage(DBBIncomingMessage {
                                    connection_id,
                                    message: crate::messages::ProtocolMessage::CastReq(cast_req),
                                }))
                                .expect("DBB should accept cast");

                            // Extract cast confirmation from output
                            let cast_conf = if let DBBOutput::OutgoingMessage(outgoing) = output {
                                if let crate::messages::ProtocolMessage::CastConf(conf) =
                                    outgoing.message
                                {
                                    conf
                                } else {
                                    panic!("Expected CastConf from DBB");
                                }
                            } else {
                                panic!("Expected OutgoingMessage from DBB");
                            };

                            println!("DBB -> VA: CastConf");

                            // VA receives confirmation
                            let cast_complete = va.process_input(VAInput::SubprotocolInput(
                            VASubprotocolInput::Casting(
                                crate::participants::voting_application::sub_actors::casting::CastingInput::NetworkMessage(
                                    crate::messages::ProtocolMessage::CastConf(cast_conf.clone())
                                )
                            )
                        ));

                            assert!(cast_complete.is_ok(), "VA should complete casting");
                            println!(
                                "✓ Voter {} ballot cast, cast tracker: {}",
                                voter_num + 1,
                                cast_conf
                                    .data
                                    .ballot_cast_tracker
                                    .expect("cast tracker must exist if cast succeeded")
                            );
                        } else {
                            panic!("Expected CastReq message");
                        }
                    }
                    _ => panic!("Expected SendMessage from casting"),
                }
            }

            println!("✓ Voter {} completed all phases", voter_num + 1);
        } // End of voter loop

        println!("\n=== Test Complete ({} voters) ===", num_voters);

        // Note: With the real DBB implementation, internal state is not directly accessible
        // for verification. The test validates correctness through the protocol flow itself -
        // all operations succeeded and produced expected messages/outputs.

        println!("✓ All voters completed: submissions, casting, and checking (where applicable)");
    }
}
