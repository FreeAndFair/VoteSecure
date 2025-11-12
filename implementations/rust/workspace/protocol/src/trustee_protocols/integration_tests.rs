//! Integration tests for trustee protocols using Stateright.
//!
//! These tests model the complete message-passing system between the TAS
//! and multiple trustee applications, verifying that the protocols work
//! correctly when actors communicate via the bulletin board.

#[cfg(test)]
mod tests {
    use crate::crypto::SigningKey;
    use crate::crypto::{
        BallotCryptogram, Context, CryptoContext, ElectionKey, Signature, VSerializable,
        encrypt_ballot, sign_data,
    };
    use crate::elections::{Ballot, BallotStyle, ElectionHash, string_to_election_hash};
    use crate::trustee_protocols::trustee_administration_server::handlers::{
        StartKeyGen as TASStartKeyGen, StartMixing, StartSetup,
    };
    use crate::trustee_protocols::trustee_administration_server::top_level_actor::{
        MixingParameters, TASActor, TASCheckpoint, TASInput, TASOutput,
    };
    use crate::trustee_protocols::trustee_application::handlers::{
        ApproveSetup, StartKeyGen as TrusteeStartKeyGen,
    };
    use crate::trustee_protocols::trustee_application::top_level_actor::{
        TrusteeActor, TrusteeInput, TrusteeOutput,
    };
    use crate::trustee_protocols::trustee_cryptography::TrusteeKeyPair;
    use crate::trustee_protocols::trustee_messages::{
        TAS_NAME, TrusteeBBUpdateMsg, TrusteeInfo, TrusteeMsg,
    };
    use crypto::cryptosystem::elgamal::PublicKey;
    use stateright::{Checker, Model, Property};
    use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
    use std::hash::{Hash, Hasher};

    const MANIFEST: &str = "test_election_manifest";

    /// Get the number of threads to use for Stateright model checking.
    /// Returns the number of available CPUs, or 1 if that cannot be determined.
    fn get_thread_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    // --- Test State ---

    /// Tracks which protocol phases have been completed.
    #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    enum Phase {
        Setup,
        KeyGen,
        Mixing,
        Decryption,
    }

    impl Phase {
        /// Returns the next phase after this one, or None if this is the last phase.
        fn next(&self) -> Option<Phase> {
            match self {
                Phase::Setup => Some(Phase::KeyGen),
                Phase::KeyGen => Some(Phase::Mixing),
                Phase::Mixing => Some(Phase::Decryption),
                Phase::Decryption => None,
            }
        }
    }

    /// Wrapper for TrusteeInput with metadata for tracking Byzantine modifications.
    #[derive(Clone, Debug, PartialEq)]
    struct TrackedTrusteeInput {
        input: TrusteeInput,
        /// Whether this message was Byzantine-modified.
        /// We use this to:
        /// 1. Prevent modifying the same message twice
        /// 2. Record which phase was affected when the message is actually delivered
        byzantine_modified: bool,
    }

    impl TrackedTrusteeInput {
        fn new(input: TrusteeInput) -> Self {
            Self {
                input,
                byzantine_modified: false,
            }
        }
    }

    /// Wrapper for TASInput. Currently just wraps the input with no metadata,
    /// but kept for symmetry with TrackedTrusteeInput and potential future use.
    #[derive(Clone, Debug, PartialEq)]
    struct TrackedTASInput {
        input: TASInput,
    }

    impl TrackedTASInput {
        fn new(input: TASInput) -> Self {
            Self { input }
        }
    }

    /// The state of the integration test, modeling a network of TAS + trustees.
    #[derive(Clone, Debug)]
    struct IntegrationState {
        /// The TAS actor.
        tas: TASActor,

        /// The trustee actors (indexed by their position in the trustees list).
        trustees: Vec<TrusteeActor>,

        /// The number of active trustees.
        active_trustee_count: usize,

        /// Input queue for the TAS.
        tas_inbox: VecDeque<TrackedTASInput>,

        /// Input queues for each trustee.
        trustee_inboxes: Vec<VecDeque<TrackedTrusteeInput>>,

        /// Phases that have been completed.
        completed_phases: BTreeSet<Phase>,

        /// Whether any actor has failed.
        has_failure: bool,

        /// Election key (available after KeyGen completes).
        election_key: Option<ElectionKey>,

        /// Encrypted ballots for mixing/decryption (generated after KeyGen).
        encrypted_ballots: Option<Vec<BallotCryptogram>>,

        /// Count of messages dropped so far (for testing message drop scenarios),
        /// tracked per trustee to ensure we don't drop all messages to any trustee.
        messages_dropped: Vec<usize>,

        /// Count of messages duplicated so far (for testing duplicate message handling),
        /// tracked per trustee to limit state space explosion.
        messages_duplicated: Vec<usize>,

        /// Count of TAS input messages duplicated (messages sent from trustees to TAS).
        tas_messages_duplicated: usize,

        /// Whether the TAS has completed each phase (emitted phase completion output).
        tas_completed_phases: BTreeSet<Phase>,

        /// Which trustees have completed each phase (emitted phase completion output).
        trustees_completed_phases: BTreeMap<Phase, BTreeSet<usize>>,

        /// Count of Byzantine actions (modified signatures, inconsistent
        /// messages sent to different trustees, modified and re-signed
        /// message content) that have been injected.
        byzantine_actions_count: usize,

        /// Set of phases that have been affected by Byzantine actions.
        /// A phase is affected if a Byzantine message for that phase was
        /// delivered to a trustee BEFORE the trustee completed that phase.
        byzantine_phases_affected: BTreeSet<Phase>,

        /// True if any Byzantine-modified message was ever delivered to any actor,
        /// regardless of timing. Used to check that failures only occur when
        /// Byzantine behavior happened.
        byzantine_message_delivered: bool,

        /// TAS signing key (needed for Byzantine actions that re-sign messages).
        tas_signing_key: SigningKey,

        /// Trustee signing keys (needed for Byzantine actions that re-sign messages).
        trustee_signing_keys: Vec<SigningKey>,
    }
    impl IntegrationState {
        fn byzantine_behavior_occurred(&self) -> bool {
            self.byzantine_message_delivered
        }

        /// Returns true if Byzantine behavior has affected the given phase
        /// or any earlier phase in the protocol.
        fn byzantine_affected_phase_or_earlier(&self, phase: &Phase) -> bool {
            self.byzantine_phases_affected.iter().any(|p| p <= phase)
        }
    }

    // Implement PartialEq and Hash for Stateright model checking.
    // We compare the actual actor states (their bulletin boards) rather than
    // just queue lengths, to properly explore different execution paths.
    impl PartialEq for IntegrationState {
        fn eq(&self, other: &Self) -> bool {
            // Compare completed phases.
            if self.completed_phases != other.completed_phases {
                return false;
            }

            // Compare failure flag.
            if self.has_failure != other.has_failure {
                return false;
            }

            // Compare TAS bulletin board contents directly.
            if self.tas.checkpoint.board != other.tas.checkpoint.board {
                return false;
            }

            // Compare each trustee's processed board contents.
            for (t1, t2) in self.trustees.iter().zip(&other.trustees) {
                if t1.processed_board != t2.processed_board {
                    return false;
                }
            }

            // Compare message queue contents.
            if self.tas_inbox.len() != other.tas_inbox.len() {
                return false;
            }
            for (input1, input2) in self.tas_inbox.iter().zip(&other.tas_inbox) {
                if input1 != input2 {
                    return false;
                }
            }
            for (inbox1, inbox2) in self.trustee_inboxes.iter().zip(&other.trustee_inboxes) {
                if inbox1.len() != inbox2.len() {
                    return false;
                }
                for (input1, input2) in inbox1.iter().zip(inbox2) {
                    if input1 != input2 {
                        return false;
                    }
                }
            }

            // Compare election key and ballots (we compare only availability,
            // as the generated cryptographic values in different states vary).
            if self.election_key.is_some() != other.election_key.is_some() {
                return false;
            }
            if self.encrypted_ballots.is_some() != other.encrypted_ballots.is_some() {
                return false;
            }

            // Compare message drop counts.
            if self.messages_dropped != other.messages_dropped {
                return false;
            }

            // Compare message duplicate counts.
            if self.messages_duplicated != other.messages_duplicated {
                return false;
            }

            // Compare TAS message duplicate count.
            if self.tas_messages_duplicated != other.tas_messages_duplicated {
                return false;
            }

            // Compare trustee phase completion.
            if self.trustees_completed_phases != other.trustees_completed_phases {
                return false;
            }

            // Compare Byzantine actions count.
            if self.byzantine_actions_count != other.byzantine_actions_count {
                return false;
            }

            // Compare Byzantine phases affected.
            if self.byzantine_phases_affected != other.byzantine_phases_affected {
                return false;
            }

            // Compare Byzantine message delivered flag.
            if self.byzantine_message_delivered != other.byzantine_message_delivered {
                return false;
            }

            true
        }
    }

    impl Eq for IntegrationState {}

    impl Hash for IntegrationState {
        fn hash<H: Hasher>(&self, state: &mut H) {
            // Hash completed phases.
            self.completed_phases.hash(state);

            // Hash failure flag.
            self.has_failure.hash(state);

            // Hash TAS board length and message types.
            self.tas.checkpoint.board.len().hash(state);
            for msg in &self.tas.checkpoint.board {
                std::mem::discriminant(msg).hash(state);
            }

            // Hash each trustee's processed board length and message types.
            for trustee in &self.trustees {
                trustee.processed_board.len().hash(state);
                for processed_msg in &trustee.processed_board {
                    // ProcessedTrusteeMsg is a struct containing TrusteeMsg (an enum)
                    std::mem::discriminant(&processed_msg.trustee_msg).hash(state);
                }
            }

            // Hash inbox queue contents by serializing the messages where possible.
            self.tas_inbox.len().hash(state);
            for tracked_input in &self.tas_inbox {
                // Use discriminant for input type
                std::mem::discriminant(&tracked_input.input).hash(state);
            }
            for inbox in &self.trustee_inboxes {
                inbox.len().hash(state);
                for tracked_input in inbox {
                    // Use discriminant for input type
                    std::mem::discriminant(&tracked_input.input).hash(state);
                    tracked_input.byzantine_modified.hash(state);
                }
            }

            // Hash election key and ballot availability.
            self.election_key.is_some().hash(state);
            self.encrypted_ballots.is_some().hash(state);

            // Hash message drop counts.
            self.messages_dropped.hash(state);

            // Hash message duplicate counts.
            self.messages_duplicated.hash(state);

            // Hash TAS message duplicate count.
            self.tas_messages_duplicated.hash(state);

            // Hash trustee phase completion.
            self.completed_phases.hash(state);

            // Hash Byzantine actions count.
            self.byzantine_actions_count.hash(state);

            // Hash Byzantine phases affected.
            self.byzantine_phases_affected.hash(state);

            // Hash Byzantine message delivered flag.
            self.byzantine_message_delivered.hash(state);
        }
    }

    // --- Test Actions ---

    /// Actions that can be taken in the integration test.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum IntegrationAction {
        /// The TAS processes the next message in its inbox.
        TASStep,
        /// Trustee i processes the next message in its inbox.
        TrusteeStep(usize),
        /// Inject StartKeyGen command to TAS and trustees
        /// (after Setup completes).
        InjectStartKeyGen,
        /// Inject StartMixing command to TAS (after KeyGen completes).
        InjectStartMixing,
        /// Drop the next board update message from trustee i's inbox.
        /// This simulates a dropped/lost message, forcing the trustee to
        /// request missing messages.
        DropBoardUpdate(usize),
        /// Duplicate a board update message to trustee i. This simulates
        /// the network/bulletin board delivering the same message twice.
        /// The trustee should handle this gracefully.
        DuplicateBoardUpdate(usize),
        /// Duplicate a message in the TAS inbox. This simulates the network
        /// delivering the same trustee message to the TAS multiple times.
        /// The TAS should handle this gracefully.
        DuplicateTASInput,
        /// Byzantine action: Corrupt the next board update broadcast.
        /// This simulates a Byzantine TAS sending a message with a bad
        /// signature. At least one honest trustee/actor should detect
        /// the bad signature and fail.
        CorruptNextBroadcastSignature,
        /// Byzantine action: Send inconsistent board updates to different
        /// trustees. This simulates a Byzantine TAS sending different
        /// messages to different trustees, causing them to see inconsistent
        /// boards. At least one trustee should detect the inconsistency
        /// when comparing with other trustees.
        SendInconsistentBoardUpdates,
    }

    // --- Stateright Model ---

    /// The Stateright model for integration testing.
    struct IntegrationModel {
        /// Number of trustees (not including TAS).
        num_trustees: usize,
        /// Threshold for protocols.
        threshold: usize,
        /// Test through this phase (inclusive). Phases are always tested
        /// in order: Setup → KeyGen → Mixing → Decryption.
        test_through_phase: Phase,
        /// Number of ballot styles to generate for mixing/decryption tests.
        num_ballot_styles: usize,
        /// Number of ballots per style to generate for mixing/decryption tests.
        num_ballots_per_style: usize,
        /// Whether to test with message drops.
        /// If false, all broadcast messages are reliably delivered.
        test_message_drops: bool,
        /// Maximum number of messages to drop per trustee. This ensures
        /// we don't drop all messages to any trustee, which would cause
        /// the trustee to never request missing messages.
        max_drops_per_trustee: usize,
        /// Whether to test Byzantine behavior (bad signatures,
        /// inconsistent broadcasts) and corresponding failure detection.
        test_byzantine_behavior: bool,
        /// Maximum number of Byzantine actions to inject.
        max_byzantine_actions: usize,
        /// Whether to test duplicate message delivery.
        /// If true, board update messages may be duplicated to simulate
        /// network delivering the same message multiple times.
        test_message_duplicates: bool,
        /// Maximum number of messages to duplicate per actor (trustee or TAS).
        /// This ensures we don't create infinite duplicates causing state space explosion.
        max_duplicates_per_actor: usize,
    }

    impl IntegrationModel {
        fn new(num_trustees: usize, threshold: usize) -> Self {
            Self {
                num_trustees,
                threshold,
                test_through_phase: Phase::Setup,
                num_ballot_styles: 2,     // Default
                num_ballots_per_style: 5, // Default
                test_message_drops: false,
                max_drops_per_trustee: 0, // Default
                test_message_duplicates: false,
                max_duplicates_per_actor: 0, // Default
                test_byzantine_behavior: false,
                max_byzantine_actions: 0, // Default
            }
        }

        fn through_phase(mut self, phase: Phase) -> Self {
            self.test_through_phase = phase;
            self
        }

        fn with_ballot_styles(mut self, styles: usize) -> Self {
            self.num_ballot_styles = styles;
            self
        }

        fn with_ballots_per_style(mut self, ballots: usize) -> Self {
            self.num_ballots_per_style = ballots;
            self
        }

        fn with_message_drops(mut self, max_drops: usize) -> Self {
            self.test_message_drops = max_drops > 0;
            self.max_drops_per_trustee = max_drops;
            self
        }

        fn with_message_duplicates(mut self, max_duplicates: usize) -> Self {
            self.test_message_duplicates = max_duplicates > 0;
            self.max_duplicates_per_actor = max_duplicates;
            self
        }

        fn with_byzantine_actions(mut self, max_actions: usize) -> Self {
            self.test_byzantine_behavior = max_actions > 0;
            self.max_byzantine_actions = max_actions;
            self
        }

        fn should_test_phase(&self, phase: &Phase) -> bool {
            self.test_through_phase >= *phase
        }

        /// Generate the plaintext ballots using a deterministic pattern.
        /// This function is used both to create ballots for encryption
        /// and to verify the correctness of decryption.
        fn generate_plaintext_ballots(
            num_styles: usize,
            num_ballots_per_style: usize,
        ) -> BTreeMap<BallotStyle, Vec<Ballot>> {
            let mut ballots_by_style = BTreeMap::new();

            for b in 0..num_styles {
                let ballot_style = b as BallotStyle;
                let mut ballots_for_style = Vec::new();

                for i in 0..num_ballots_per_style {
                    // Create a simple ballot with some dummy contest choices.
                    let ballot = Ballot {
                        ballot_style,
                        rank: (i % 5) as u128,
                    };
                    ballots_for_style.push(ballot);
                }

                ballots_by_style.insert(ballot_style, ballots_for_style);
            }

            ballots_by_style
        }

        /// Create dummy ballots for testing mixing/decryption by encrypting
        /// the plaintext ballots generated by generate_plaintext_ballots().
        fn create_ballots(
            election_key: &ElectionKey,
            election_hash: &ElectionHash,
            num_styles: usize,
            num_ballots_per_style: usize,
        ) -> Vec<BallotCryptogram> {
            let plaintext_ballots =
                Self::generate_plaintext_ballots(num_styles, num_ballots_per_style);
            let mut encrypted_ballots = Vec::new();

            for (_ballot_style, ballots) in plaintext_ballots {
                for ballot in ballots {
                    // Encrypt the ballot.
                    match encrypt_ballot(ballot.clone(), election_key, election_hash) {
                        Ok((cryptogram, _randomizers)) => {
                            encrypted_ballots.push(cryptogram);
                        }
                        Err(e) => {
                            panic!("Failed to encrypt ballot: {}", e);
                        }
                    }
                }
            }

            encrypted_ballots
        }

        /// Create the initial state with fresh actors ready to start setup.
        fn create_initial_state(&self) -> IntegrationState {
            let mut rng = CryptoContext::get_rng();

            // Generate signing keys for TAS and trustees.
            let tas_signing_key = SigningKey::generate(&mut rng);
            let trustee_signing_keys: Vec<SigningKey> = (0..self.num_trustees)
                .map(|_| SigningKey::generate(&mut rng))
                .collect();

            // Generate encryption key pairs for trustees.
            let trustee_encryption_keypairs: Vec<TrusteeKeyPair> = (0..self.num_trustees)
                .map(|_| TrusteeKeyPair::generate())
                .collect();

            // Create trustee info list (TAS is index 0).
            let mut trustees_info = vec![TrusteeInfo {
                name: TAS_NAME.to_string(),
                verifying_key: tas_signing_key.verifying_key(),
                public_enc_key: PublicKey::new(CryptoContext::random_element()), // Unused for TAS
            }];

            for (i, sk) in trustee_signing_keys.iter().enumerate() {
                trustees_info.push(TrusteeInfo {
                    name: format!("Trustee{}", i + 1),
                    verifying_key: sk.verifying_key(),
                    public_enc_key: trustee_encryption_keypairs[i].pkey.clone(),
                });
            }

            // Create TAS checkpoint.
            let tas_checkpoint = TASCheckpoint {
                manifest: MANIFEST.to_string(),
                election_hash: string_to_election_hash(MANIFEST),
                threshold: self.threshold as u32,
                trustees: trustees_info.clone(),
                board: vec![],
                election_public_key: None,
                active_trustees: HashSet::new(),
            };

            // Create TAS actor.
            let tas = TASActor::new(tas_signing_key.clone(), tas_checkpoint)
                .expect("Failed to create TAS");

            // Clone keys for storage (we need them for Byzantine actions).
            let trustee_signing_keys_clone = trustee_signing_keys.clone();
            let tas_signing_key_clone = tas_signing_key.clone();

            // Create trustee actors.
            let trustees: Vec<TrusteeActor> = trustee_signing_keys
                .into_iter()
                .zip(trustee_encryption_keypairs)
                .enumerate()
                .map(|(i, (sk, enc_kp))| {
                    TrusteeActor::new(trustees_info[i + 1].clone(), sk, enc_kp, None)
                        .expect(&format!("Failed to create trustee {}", i))
                })
                .collect();

            // Initialize with StartSetup in TAS inbox.
            let mut tas_inbox = VecDeque::new();
            tas_inbox.push_back(TrackedTASInput::new(TASInput::StartSetup(StartSetup)));
            let active_trustee_count = trustees.len();

            IntegrationState {
                tas,
                trustees,
                active_trustee_count,
                tas_inbox,
                trustee_inboxes: vec![VecDeque::new(); self.num_trustees],
                completed_phases: BTreeSet::new(),
                has_failure: false,
                election_key: None,
                encrypted_ballots: None,
                messages_dropped: vec![0; self.num_trustees],
                tas_completed_phases: BTreeSet::new(),
                trustees_completed_phases: BTreeMap::new(),
                byzantine_actions_count: 0,
                byzantine_phases_affected: BTreeSet::new(),
                byzantine_message_delivered: false,
                tas_signing_key: tas_signing_key_clone,
                trustee_signing_keys: trustee_signing_keys_clone,
                messages_duplicated: vec![0; self.num_trustees],
                tas_messages_duplicated: 0,
            }
        }

        /// Check if a phase should be marked complete and mark it if so.
        /// A phase is complete when all participating trustees (all
        /// trustees for Setup/KeyGen, active ones for Mixing/Decryption)
        /// and the TAS have completed it.
        fn check_and_mark_phase_complete(
            state: &mut IntegrationState,
            phase: Phase,
            required_trustees: usize,
        ) {
            let trustees_completed = state
                .trustees_completed_phases
                .get(&phase)
                .map(|set| set.len())
                .unwrap_or(0);

            let tas_completed = state.tas_completed_phases.get(&phase).is_some();

            // Only mark complete if TAS and required number of trustees have
            // completed the phase.
            if tas_completed && trustees_completed >= required_trustees {
                state.completed_phases.insert(phase);
            }
        }

        /// Deliver a TrusteeBBUpdateMsg to all trustees.
        fn broadcast_to_trustees(state: &mut IntegrationState, msg: TrusteeBBUpdateMsg) {
            // Broadcast only to active trustees.
            for i in 0..state.active_trustee_count {
                let inbox = &mut state.trustee_inboxes[i];
                inbox.push_back(TrackedTrusteeInput::new(TrusteeInput::HandleBoardUpdate(
                    msg.clone(),
                )));
            }
        }

        /// Handle a TAS step by processing one input from its inbox.
        fn handle_tas_step(
            state: &IntegrationState,
            num_styles: usize,
            num_ballots: usize,
        ) -> Option<IntegrationState> {
            if state.tas_inbox.is_empty() {
                return None;
            }

            let mut new_state = state.clone();
            let tracked_input = new_state.tas_inbox.pop_front().unwrap();

            let (output, board_update) = new_state.tas.handle_input(&tracked_input.input);

            // If the TAS produced a bulletin board update, broadcast it to all trustees.
            if let Some(update_msg) = board_update {
                Self::broadcast_to_trustees(&mut new_state, update_msg);
            }

            // Check output for completion or failure.
            if let Some(out) = output {
                match out {
                    TASOutput::SetupSuccessful(_) => {
                        new_state.tas_completed_phases.insert(Phase::Setup);
                    }
                    TASOutput::KeyGenSuccessful(ref keygen_data) => {
                        new_state.tas_completed_phases.insert(Phase::KeyGen);
                        // Capture the election key and generate ballots for mixing.
                        let election_key = keygen_data
                            .election_public_key
                            .as_ref()
                            .expect("KeyGenSuccessful should have election_public_key");
                        new_state.election_key = Some(election_key.clone());
                        let election_hash = &string_to_election_hash(MANIFEST);
                        new_state.encrypted_ballots = Some(Self::create_ballots(
                            election_key,
                            election_hash,
                            num_styles,
                            num_ballots,
                        ));
                    }
                    TASOutput::MixingSuccessful(_) => {
                        new_state.tas_completed_phases.insert(Phase::Mixing);
                    }
                    TASOutput::DecryptionSuccessful(_) => {
                        new_state.tas_completed_phases.insert(Phase::Decryption);
                    }
                    TASOutput::InvalidInput(_) => {
                        // InvalidInput is not a failure - it just means the input was
                        // invalid for the current state (e.g., duplicate message, wrong phase).
                        // The actor handles this gracefully, so we don't mark it as failed.
                    }
                    TASOutput::Failed(_) => {
                        new_state.has_failure = true;
                    }
                    TASOutput::UpdateTrustee(update_data) => {
                        // Handle specific trustee update (for missing message requests).
                        // Find the trustee by ID and deliver the update message.
                        if let Ok(update_msg) = &update_data.update {
                            if let Some(trustee_idx) = new_state
                                .trustees
                                .iter()
                                .position(|t| t.trustee_info.trustee_id() == update_data.trustee)
                            {
                                new_state.trustee_inboxes[trustee_idx].push_back(
                                    TrackedTrusteeInput::new(TrusteeInput::HandleBoardUpdate(
                                        update_msg.clone(),
                                    )),
                                );
                            }
                        } else {
                            // Missing message request failed.
                            new_state.has_failure = true;
                        }
                    }
                    _ => {}
                }
            }

            Some(new_state)
        }

        /// Handle a trustee step by processing one input from the trustee's inbox.
        fn handle_trustee_step(
            state: &IntegrationState,
            trustee_idx: usize,
            num_trustees: usize,
            threshold: usize,
        ) -> Option<IntegrationState> {
            if trustee_idx >= state.trustees.len() {
                return None;
            }

            if state.trustee_inboxes[trustee_idx].is_empty() {
                return None;
            }

            let mut new_state = state.clone();
            let tracked_input = new_state.trustee_inboxes[trustee_idx].pop_front().unwrap();

            // Check if this message was Byzantine-modified.
            if tracked_input.byzantine_modified {
                // Determine which phase we're currently in: it's the next phase after
                // the most recently completed phase (or Setup if no phases are completed).
                // If we've completed all phases, we're still in Decryption.
                let affected_phase = new_state
                    .completed_phases
                    .iter()
                    .max()
                    .map(|last_completed| last_completed.next().unwrap_or(Phase::Decryption))
                    .unwrap_or(Phase::Setup);

                // Record that a Byzantine message was delivered
                new_state.byzantine_message_delivered = true;

                // Track that a Byzantine message was delivered during this phase.
                // This is used for "sometimes" test coverage properties to verify
                // that Byzantine messages for each phase are actually generated and delivered.
                new_state.byzantine_phases_affected.insert(affected_phase);
            }

            let (output, trustee_msg) =
                new_state.trustees[trustee_idx].handle_input(tracked_input.input);

            // If the trustee produced a message, send it to the TAS.
            if let Some(msg) = &trustee_msg {
                new_state
                    .tas_inbox
                    .push_back(TrackedTASInput::new(TASInput::from(msg.clone())));
            }

            // Check output for special cases.
            if let Some(out) = output {
                match out {
                    TrusteeOutput::RequestSetupApproval(setup_msg) => {
                        // Auto-approve setup for testing purposes. The trustee
                        // does not process any other messages before the approval.
                        let approval_input = TrusteeInput::ApproveSetup(ApproveSetup(setup_msg));
                        let (approval_output, approval_msg) =
                            new_state.trustees[trustee_idx].handle_input(approval_input);

                        // If approval produced a message, send it to TAS.
                        if let Some(msg) = approval_msg {
                            new_state
                                .tas_inbox
                                .push_back(TrackedTASInput::new(TASInput::from(msg)));
                        }

                        // Check if approval produced a failure.
                        if let Some(approval_out) = approval_output {
                            match approval_out {
                                TrusteeOutput::InvalidInput(_) => {
                                    // Not a failure - just invalid input for current state.
                                }
                                TrusteeOutput::Failed(_) => {
                                    new_state.has_failure = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    TrusteeOutput::SetupComplete(_) => {
                        // Track that this trustee completed setup.
                        new_state
                            .trustees_completed_phases
                            .entry(Phase::Setup)
                            .or_insert_with(BTreeSet::new)
                            .insert(trustee_idx);
                        // Check if phase is complete.
                        Self::check_and_mark_phase_complete(
                            &mut new_state,
                            Phase::Setup,
                            num_trustees,
                        );
                    }
                    TrusteeOutput::KeyGenComplete(_) => {
                        // Track that this trustee completed KeyGen.
                        new_state
                            .trustees_completed_phases
                            .entry(Phase::KeyGen)
                            .or_insert_with(BTreeSet::new)
                            .insert(trustee_idx);
                        // Check if phase is complete.
                        Self::check_and_mark_phase_complete(
                            &mut new_state,
                            Phase::KeyGen,
                            num_trustees,
                        );
                    }
                    TrusteeOutput::MixingComplete => {
                        // Track that this trustee completed Mixing.
                        new_state
                            .trustees_completed_phases
                            .entry(Phase::Mixing)
                            .or_insert_with(BTreeSet::new)
                            .insert(trustee_idx);
                        // Check if phase is complete.
                        Self::check_and_mark_phase_complete(
                            &mut new_state,
                            Phase::Mixing,
                            threshold,
                        );
                    }
                    TrusteeOutput::DecryptionComplete(_) => {
                        // Track that this trustee completed Decryption.
                        new_state
                            .trustees_completed_phases
                            .entry(Phase::Decryption)
                            .or_insert_with(BTreeSet::new)
                            .insert(trustee_idx);
                        // Check if phase is complete.
                        Self::check_and_mark_phase_complete(
                            &mut new_state,
                            Phase::Decryption,
                            threshold,
                        );
                    }
                    TrusteeOutput::MissingMessages(request) => {
                        // Trustee detected missing messages and is requesting them.
                        // Wrap the request in a TrusteeMsg and send to TAS.
                        let msg = TrusteeMsg::TrusteeBBUpdateRequest(request);
                        new_state
                            .tas_inbox
                            .push_back(TrackedTASInput::new(TASInput::from(msg)));
                    }
                    TrusteeOutput::InvalidInput(_) => {
                        // Not a failure - just invalid input for current state.
                    }
                    TrusteeOutput::Failed(_f) => {
                        new_state.has_failure = true;
                    }
                    _ => {}
                }
            }

            Some(new_state)
        }
    }

    impl Model for IntegrationModel {
        type State = IntegrationState;
        type Action = IntegrationAction;

        fn init_states(&self) -> Vec<Self::State> {
            vec![self.create_initial_state()]
        }

        fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
            // TAS can step if it has messages in its inbox.
            if !state.tas_inbox.is_empty() {
                actions.push(IntegrationAction::TASStep);
            }

            // Can duplicate a message in the TAS inbox to test duplicate message handling.
            // Only allow duplicates if there's at least one trustee message in the queue.
            if self.test_message_duplicates
                && state.tas_messages_duplicated < self.max_duplicates_per_actor
            {
                let has_trustee_msg = state.tas_inbox.iter().any(|input| {
                    !matches!(
                        input.input,
                        TASInput::StartSetup(_)
                            | TASInput::StartKeyGen(_)
                            | TASInput::StartMixing(_)
                    )
                });
                if has_trustee_msg {
                    actions.push(IntegrationAction::DuplicateTASInput);
                }
            }

            // Each trustee can step if it has messages in its inbox.
            // Also, each trustee can have board update messages
            // dropped (simulating message loss). Trustees do not
            // step if they are not active (if we're in mixing or
            // decryption phases, only the first `threshold` trustees
            // are active).
            for i in 0..state.active_trustee_count {
                if !state.trustee_inboxes[i].is_empty() {
                    actions.push(IntegrationAction::TrusteeStep(i));
                }

                // Can drop board update messages to test missing message requests.
                // We only drop a message if there are at least 2 board update
                // messages in the queue. This ensures that after dropping message
                // N, the trustee will receive message N+1, which will trigger a
                // missing message request.
                if self.test_message_drops && state.messages_dropped[i] < self.max_drops_per_trustee
                {
                    let board_update_count = state.trustee_inboxes[i]
                        .iter()
                        .filter(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)))
                        .count();
                    if board_update_count >= 2 {
                        actions.push(IntegrationAction::DropBoardUpdate(i));
                    }
                }

                // Can duplicate a board update message to test duplicate message handling.
                if self.test_message_duplicates
                    && state.messages_duplicated[i] < self.max_duplicates_per_actor
                {
                    let has_board_update = state.trustee_inboxes[i]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));
                    if has_board_update {
                        actions.push(IntegrationAction::DuplicateBoardUpdate(i));
                    }
                }
            }

            // Inject phase transitions at appropriate times if testing those phases.
            // Only inject if all inboxes are empty, all trustees have caught up, and
            // all trustees have emitted completion output for the previous phase.
            // Don't inject if any actor has failed - the protocol should stop at that point.
            if !state.has_failure
                && state.tas_inbox.is_empty()
                && state.trustee_inboxes.iter().all(|q| q.is_empty())
            {
                // Check if all trustees have caught up.
                let all_trustees_caught_up = state.trustees.iter().all(|trustee| {
                    trustee.processed_board.len() == state.tas.checkpoint.board.len()
                });

                // Check if all trustees completed Setup.
                let all_trustees_completed_setup = state
                    .trustees_completed_phases
                    .get(&Phase::Setup)
                    .map(|set| set.len() == self.num_trustees)
                    .unwrap_or(false);

                // Inject StartKeyGen if appropriate.
                if state.completed_phases.contains(&Phase::Setup)
                    && !state.completed_phases.contains(&Phase::KeyGen)
                    && self.should_test_phase(&Phase::KeyGen)
                    && all_trustees_caught_up
                    && all_trustees_completed_setup
                {
                    actions.push(IntegrationAction::InjectStartKeyGen);
                }

                // Check if all trustees completed KeyGen.
                let all_trustees_completed_keygen = state
                    .trustees_completed_phases
                    .get(&Phase::KeyGen)
                    .map(|set| set.len() == self.num_trustees)
                    .unwrap_or(false);

                // Inject StartMixing if appropriate.
                if state.completed_phases.contains(&Phase::KeyGen)
                    && !state.completed_phases.contains(&Phase::Mixing)
                    && self.should_test_phase(&Phase::Mixing)
                    && state.election_key.is_some()
                    && state.encrypted_ballots.is_some()
                    && all_trustees_caught_up
                    && all_trustees_completed_keygen
                {
                    actions.push(IntegrationAction::InjectStartMixing);
                }
            }

            // Byzantine actions; inject if enabled and we haven't exceeded
            // the limit.
            if self.test_byzantine_behavior
                && state.byzantine_actions_count < self.max_byzantine_actions
            {
                // Can corrupt a signature if there's a board update queued for delivery.
                if !state.trustees.is_empty() {
                    let has_board_update = state.trustee_inboxes[0]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));

                    if has_board_update {
                        actions.push(IntegrationAction::CorruptNextBroadcastSignature);
                    }
                }

                // Can send inconsistent updates if there are at least 2 trustees with
                // queued updates.
                if state.trustees.len() >= 2 {
                    let has_update_0 = state.trustee_inboxes[0]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));
                    let has_update_1 = state.trustee_inboxes[1]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));

                    if has_update_0 && has_update_1 {
                        actions.push(IntegrationAction::SendInconsistentBoardUpdates);
                    }
                }
            }
        }

        fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
            match action {
                IntegrationAction::TASStep => {
                    Self::handle_tas_step(state, self.num_ballot_styles, self.num_ballots_per_style)
                }
                IntegrationAction::TrusteeStep(i) => {
                    Self::handle_trustee_step(state, i, self.num_trustees, self.threshold)
                }
                IntegrationAction::InjectStartKeyGen => {
                    let mut new_state = state.clone();
                    new_state
                        .tas_inbox
                        .push_back(TrackedTASInput::new(TASInput::StartKeyGen(TASStartKeyGen)));
                    // Also inject StartKeyGen into each trustee's inbox
                    for inbox in &mut new_state.trustee_inboxes {
                        inbox.push_back(TrackedTrusteeInput::new(TrusteeInput::StartKeyGen(
                            TrusteeStartKeyGen,
                        )));
                    }
                    Some(new_state)
                }
                IntegrationAction::InjectStartMixing => {
                    let mut new_state = state.clone();

                    // Set the number of active trustees in the new state to the threshold.
                    new_state.active_trustee_count = self.threshold;

                    // Build mixing parameters from the state.
                    if let (Some(ballots), Some(_election_key)) =
                        (&new_state.encrypted_ballots, &new_state.election_key)
                    {
                        // Use exactly threshold trustees as active trustees.
                        // TrusteeID is 1-indexed (0 is TAS).
                        let active_trustees: Vec<_> = (1..=self.threshold)
                            .map(|i| {
                                // Get the trustee info from the TAS checkpoint.
                                new_state.tas.checkpoint.trustees[i].trustee_id()
                            })
                            .collect();

                        let mixing_params = MixingParameters {
                            active_trustees,
                            cryptograms: ballots.clone(),
                        };

                        new_state
                            .tas_inbox
                            .push_back(TrackedTASInput::new(TASInput::StartMixing(StartMixing(
                                mixing_params,
                            ))));
                        Some(new_state)
                    } else {
                        // Can't inject mixing without ballots - this shouldn't happen.
                        None
                    }
                }
                IntegrationAction::DropBoardUpdate(trustee_idx) => {
                    // Drop a HandleBoardUpdate message from the trustee's inbox if
                    // one exists. This simulates message loss and forces the trustee
                    // to request missing messages.
                    //
                    // We only drop a message if there's at least one non-duplicate
                    // HandleBoardUpdate message after it in the inbox. This ensures
                    // the trustee will eventually receive a later message and request
                    // missing messages as necessary.
                    if trustee_idx >= state.trustees.len() {
                        return None;
                    }

                    let mut new_state = state.clone();
                    let inbox = &mut new_state.trustee_inboxes[trustee_idx];

                    // Find the first HandleBoardUpdate message that can be safely dropped.
                    // We can only drop a message if there's a later HandleBoardUpdate with
                    // higher indices that will trigger gap detection.
                    let droppable_pos = inbox.iter().enumerate().position(|(pos, input)| {
                        let TrusteeInput::HandleBoardUpdate(ref update_to_drop) = input.input
                        else {
                            return false;
                        };

                        // Get the maximum index in the update we're considering dropping
                        let Some(max_idx_to_drop) =
                            update_to_drop.msgs.last_key_value().map(|(k, _)| *k)
                        else {
                            return false;
                        };

                        // Check if there's a later HandleBoardUpdate that will trigger gap detection
                        inbox.iter().skip(pos + 1).any(|later_input| {
                            if let TrusteeInput::HandleBoardUpdate(ref later_update) =
                                later_input.input
                            {
                                if let Some((min_idx, _)) = later_update.msgs.first_key_value() {
                                    return *min_idx > max_idx_to_drop;
                                }
                            }
                            false
                        })
                    });

                    if let Some(pos) = droppable_pos {
                        inbox.remove(pos);
                        new_state.messages_dropped[trustee_idx] += 1;
                        Some(new_state)
                    } else {
                        // No board update message that can be safely dropped.
                        None
                    }
                }
                IntegrationAction::CorruptNextBroadcastSignature => {
                    // Byzantine action: Corrupt the signature of the next board update broadcast.
                    // This simulates a Byzantine TAS sending a message with an invalid signature.
                    // At least one honest actor should detect this and fail.
                    if state.trustees.is_empty() {
                        return None;
                    }

                    let mut new_state = state.clone();

                    // Find the first HandleBoardUpdate message.
                    if let Some(pos) = new_state.trustee_inboxes[0]
                        .iter()
                        .position(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)))
                    {
                        // Check if this message was already Byzantine-modified.
                        // If so, skip this action (don't corrupt the same message twice).
                        let message_to_corrupt = &new_state.trustee_inboxes[0][pos];
                        if message_to_corrupt.byzantine_modified {
                            // Already Byzantine-modified, skip.
                            return None;
                        }

                        // Extract the update, corrupt a signature, and replace it.
                        let mut tracked_msg = new_state.trustee_inboxes[0].remove(pos).unwrap();
                        if let TrusteeInput::HandleBoardUpdate(mut update) = tracked_msg.input {
                            // Corrupt the signature of the first message in the update.
                            if let Some((first_key, first_msg)) = update.msgs.iter().next() {
                                let first_key = *first_key;
                                // Clone the message to corrupt it.
                                let mut corrupted_msg = first_msg.clone();

                                // Corrupt the signature by flipping bits.
                                match &mut corrupted_msg {
                                    TrusteeMsg::Setup(setup_msg) => {
                                        let mut sig_bytes = setup_msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF; // Flip bits in first byte
                                        setup_msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::KeyShares(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::ElectionPublicKey(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::MixInitialization(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::EGCryptograms(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::PartialDecryptions(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    TrusteeMsg::DecryptedBallots(msg) => {
                                        let mut sig_bytes = msg.signature.to_bytes();
                                        sig_bytes[0] ^= 0xFF;
                                        msg.signature = Signature::from_bytes(&sig_bytes);
                                    }
                                    _ => {
                                        // For other message types, just return None (can't corrupt).
                                        tracked_msg.input = TrusteeInput::HandleBoardUpdate(update);
                                        new_state.trustee_inboxes[0].insert(pos, tracked_msg);
                                        return None;
                                    }
                                };

                                // Replace the message in the update's msgs map.
                                update.msgs.insert(first_key, corrupted_msg);

                                // Mark that this message was Byzantine-modified.
                                tracked_msg.byzantine_modified = true;
                            }

                            // Re-insert the corrupted update.
                            tracked_msg.input = TrusteeInput::HandleBoardUpdate(update);
                            new_state.trustee_inboxes[0].insert(pos, tracked_msg);
                            new_state.byzantine_actions_count += 1;

                            Some(new_state)
                        } else {
                            None
                        }
                    } else {
                        // No board update to corrupt.
                        None
                    }
                }
                IntegrationAction::SendInconsistentBoardUpdates => {
                    // Byzantine action: Send different board updates to different trustees.
                    // This simulates a Byzantine TAS showing different bulletin board states
                    // to different trustees, which they should detect during the protocol.
                    // For this action to be meaningful, we need at least 2 trustees and
                    // a board update queued for delivery.
                    if state.trustees.len() < 2 {
                        return None;
                    }

                    // Check if there's a board update queued for both trustees.
                    let has_update_0 = state.trustee_inboxes[0]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));
                    let has_update_1 = state.trustee_inboxes[1]
                        .iter()
                        .any(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)));

                    if !has_update_0 || !has_update_1 {
                        return None;
                    }

                    let mut new_state = state.clone();

                    // Find the board update for trustee 1 and modify one of its messages.
                    if let Some(pos) = new_state.trustee_inboxes[1]
                        .iter()
                        .position(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)))
                    {
                        // Check if this message was already Byzantine-modified - skip if so
                        if new_state.trustee_inboxes[1][pos].byzantine_modified {
                            return None;
                        }

                        if let Some(tracked_msg) = new_state.trustee_inboxes[1].get_mut(pos) {
                            if let TrusteeInput::HandleBoardUpdate(update) = &mut tracked_msg.input
                            {
                                // Try to modify any message in the update.
                                // We'll modify different fields depending on message type.
                                let mut modified = false;
                                for (_idx, msg) in update.msgs.iter_mut() {
                                    // Helper closure to get signing key for a signer name.
                                    let get_signing_key =
                                        |signer_name: &str| -> Option<&SigningKey> {
                                            if signer_name.starts_with("Trustee") {
                                                // Extract trustee number (e.g., "Trustee1" -> 1).
                                                if let Some(num_str) =
                                                    signer_name.strip_prefix("Trustee")
                                                {
                                                    if let Ok(trustee_num) =
                                                        num_str.parse::<usize>()
                                                    {
                                                        if trustee_num > 0
                                                            && trustee_num
                                                                <= new_state
                                                                    .trustee_signing_keys
                                                                    .len()
                                                        {
                                                            return Some(
                                                                &new_state.trustee_signing_keys
                                                                    [trustee_num - 1],
                                                            );
                                                        }
                                                    }
                                                }
                                            } else if signer_name == TAS_NAME {
                                                return Some(&new_state.tas_signing_key);
                                            }
                                            None
                                        };

                                    match msg {
                                        TrusteeMsg::Setup(setup_msg) => {
                                            let mut modified_data = setup_msg.data.clone();
                                            modified_data.manifest =
                                                format!("{}_BYZANTINE", modified_data.manifest);

                                            if let Some(signing_key) =
                                                get_signing_key(&setup_msg.data.signer.name)
                                            {
                                                let new_signature =
                                                    sign_data(&modified_data.ser(), signing_key);
                                                setup_msg.data = modified_data;
                                                setup_msg.signature = new_signature;
                                                modified = true;
                                                break;
                                            }
                                            continue;
                                        }
                                        TrusteeMsg::KeyShares(key_shares_msg) => {
                                            // Swap two pairwise shares to create inconsistency.
                                            let mut modified_data = key_shares_msg.data.clone();
                                            if modified_data.pairwise_shares.len() >= 2 {
                                                modified_data.pairwise_shares.swap(0, 1);

                                                if let Some(signing_key) = get_signing_key(
                                                    &key_shares_msg.data.signer.name,
                                                ) {
                                                    let new_signature = sign_data(
                                                        &modified_data.ser(),
                                                        signing_key,
                                                    );
                                                    key_shares_msg.data = modified_data;
                                                    key_shares_msg.signature = new_signature;
                                                    modified = true;
                                                    break;
                                                }
                                            }
                                        }
                                        TrusteeMsg::ElectionPublicKey(epk_msg) => {
                                            // ElectionPublicKey doesn't have easily modifiable cryptographic content,
                                            // so we modify the election hash.
                                            let mut modified_data = epk_msg.data.clone();
                                            modified_data.election_hash[0] =
                                                modified_data.election_hash[0] + 1;

                                            if let Some(signing_key) =
                                                get_signing_key(&epk_msg.data.signer.name)
                                            {
                                                let new_signature =
                                                    sign_data(&modified_data.ser(), signing_key);
                                                epk_msg.data = modified_data;
                                                epk_msg.signature = new_signature;
                                                modified = true;
                                                break;
                                            }
                                        }
                                        TrusteeMsg::EGCryptograms(eg_msg) => {
                                            // Reorder ciphertexts within a ballot style.
                                            let mut modified_data = eg_msg.data.clone();
                                            for (_style, ciphertexts) in
                                                modified_data.ciphertexts.iter_mut()
                                            {
                                                if ciphertexts.len() >= 2 {
                                                    ciphertexts.swap(0, 1);

                                                    if let Some(signing_key) =
                                                        get_signing_key(&eg_msg.data.signer.name)
                                                    {
                                                        let new_signature = sign_data(
                                                            &modified_data.ser(),
                                                            signing_key,
                                                        );
                                                        eg_msg.data = modified_data;
                                                        eg_msg.signature = new_signature;
                                                        modified = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        TrusteeMsg::PartialDecryptions(pd_msg) => {
                                            // Reorder partial decryptions within a ballot style.
                                            let mut modified_data = pd_msg.data.clone();
                                            for (_style, decryptions) in
                                                modified_data.partial_decryptions.iter_mut()
                                            {
                                                if decryptions.len() >= 2 {
                                                    decryptions.swap(0, 1);

                                                    if let Some(signing_key) =
                                                        get_signing_key(&pd_msg.data.signer.name)
                                                    {
                                                        let new_signature = sign_data(
                                                            &modified_data.ser(),
                                                            signing_key,
                                                        );
                                                        pd_msg.data = modified_data;
                                                        pd_msg.signature = new_signature;
                                                        modified = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        TrusteeMsg::DecryptedBallots(db_msg) => {
                                            // Reorder decrypted ballots within a ballot style.
                                            let mut modified_data = db_msg.data.clone();
                                            for (_style, ballots) in
                                                modified_data.ballots.iter_mut()
                                            {
                                                if ballots.len() >= 2 {
                                                    // Check if the two ballots being swapped are identical
                                                    if ballots[0] == ballots[1] {
                                                        continue; // Skip this message, try the next one
                                                    }
                                                    ballots.swap(0, 1);

                                                    if let Some(signing_key) =
                                                        get_signing_key(&db_msg.data.signer.name)
                                                    {
                                                        let new_signature = sign_data(
                                                            &modified_data.ser(),
                                                            signing_key,
                                                        );
                                                        db_msg.data = modified_data;
                                                        db_msg.signature = new_signature;
                                                        modified = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        TrusteeMsg::MixInitialization(mix_init_msg) => {
                                            // Reorder cryptograms to create inconsistency.
                                            let mut modified_data = mix_init_msg.data.clone();
                                            if modified_data.cryptograms.len() >= 2 {
                                                modified_data.cryptograms.swap(0, 1);

                                                if let Some(signing_key) =
                                                    get_signing_key(&mix_init_msg.data.signer.name)
                                                {
                                                    let new_signature = sign_data(
                                                        &modified_data.ser(),
                                                        signing_key,
                                                    );
                                                    mix_init_msg.data = modified_data;
                                                    mix_init_msg.signature = new_signature;
                                                    modified = true;
                                                    break;
                                                }
                                            }
                                        }
                                        TrusteeMsg::TrusteeBBUpdateRequest(_)
                                        | TrusteeMsg::TrusteeBBUpdate(_) => {
                                            // These are infrastructure messages, not protocol messages,
                                            // and cannot appear in board updates.
                                            continue;
                                        }
                                    }
                                }

                                if modified {
                                    // Mark that this message was Byzantine-modified.
                                    tracked_msg.byzantine_modified = true;

                                    new_state.byzantine_actions_count += 1;
                                    Some(new_state)
                                } else {
                                    // No suitable message to modify
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                IntegrationAction::DuplicateBoardUpdate(trustee_idx) => {
                    // Duplicate a board update message to a trustee.
                    // This simulates the network delivering the same message twice.
                    // The trustee should handle this gracefully with InvalidInput.
                    if trustee_idx >= state.trustees.len() {
                        return None;
                    }

                    // Find a HandleBoardUpdate message in the trustee's inbox
                    let board_update = state.trustee_inboxes[trustee_idx]
                        .iter()
                        .find(|input| matches!(input.input, TrusteeInput::HandleBoardUpdate(_)))
                        .cloned();

                    if let Some(update) = board_update {
                        let mut new_state = state.clone();
                        // Add the duplicate to the back of the queue
                        new_state.trustee_inboxes[trustee_idx].push_back(update);
                        // Increment the duplicate counter for this trustee
                        new_state.messages_duplicated[trustee_idx] += 1;
                        Some(new_state)
                    } else {
                        None
                    }
                }
                IntegrationAction::DuplicateTASInput => {
                    // Duplicate a message in the TAS inbox. This simulates the network
                    // delivering the same trustee message to the TAS multiple times.
                    // The TAS should handle this gracefully.

                    if state.tas_inbox.is_empty() {
                        return None;
                    }

                    // Find a message from a trustee (not a Start* command) to duplicate
                    let duplicate_msg = state
                        .tas_inbox
                        .iter()
                        .find(|input| matches!(input.input, TASInput::TrusteeMsg(_)))
                        .cloned();

                    if let Some(msg) = duplicate_msg {
                        let mut new_state = state.clone();
                        // Add the duplicate to the back of the queue
                        new_state.tas_inbox.push_back(msg);
                        // Increment the TAS duplicate counter
                        new_state.tas_messages_duplicated += 1;
                        Some(new_state)
                    } else {
                        None
                    }
                }
            }
        }

        fn properties(&self) -> Vec<Property<Self>> {
            let mut props = vec![
                // In non-Byzantine scenarios, no failures should occur.
                Property::<Self>::always(
                    "no failures unless Byzantine behavior occurred",
                    |_, state| {
                        if state.has_failure && !state.byzantine_behavior_occurred() {
                            println!("\n=== UNEXPECTED FAILURE (NO BYZANTINE BEHAVIOR) ===");
                            println!("Completed phases: {:?}", state.completed_phases);
                            println!("TAS inbox length: {}", state.tas_inbox.len());
                            println!("TAS board length: {}", state.tas.checkpoint.board.len());
                            for (i, trustee) in state.trustees.iter().enumerate() {
                                println!(
                                    "  Trustee {}: processed {} messages",
                                    i,
                                    trustee.processed_board.len()
                                );
                            }
                            for (i, inbox) in state.trustee_inboxes.iter().enumerate() {
                                println!("  Trustee {} inbox: {} messages", i, inbox.len());
                            }
                            false
                        } else {
                            true
                        }
                    },
                ),
                // Trustee boards are always prefixes of the TAS board (unless Byzantine
                // behavior occurred). This property holds even with message drops/reordering
                // because trustees fetch missing messages and won't process messages that
                // would leave gaps or create inconsistencies.
                Property::<Self>::always(
                    "trustee boards are prefixes of TAS board unless Byzantine behavior occurred",
                    |_, state| {
                        // If Byzantine behavior occurred, we allow prefix violations.
                        if state.byzantine_behavior_occurred() {
                            return true;
                        }

                        let tas_board = &state.tas.checkpoint.board;
                        for (i, trustee) in state.trustees.iter().enumerate() {
                            let trustee_board_len = trustee.processed_board.len();

                            // First check: trustee can't be ahead of TAS.
                            if trustee_board_len > tas_board.len() {
                                println!("\n=== INVARIANT VIOLATION ===");
                                println!(
                                    "Trustee {} has processed {} messages but TAS board only has {}",
                                    i,
                                    trustee_board_len,
                                    tas_board.len()
                                );
                                return false;
                            }

                            // Second check: every message in trustee's board must match the corresponding
                            // message in the TAS board (prefix property).
                            for (j, processed_msg) in trustee.processed_board.iter().enumerate() {
                                if processed_msg.trustee_msg != tas_board[j] {
                                    println!("\n=== INVARIANT VIOLATION ===");
                                    println!("Trustee {} has different message at index {}", i, j);
                                    println!("  Trustee message: {:?}", processed_msg.trustee_msg);
                                    println!("  TAS message: {:?}", tas_board[j]);
                                    return false;
                                }
                            }
                        }
                        true
                    },
                ),
                // Message queues should be bounded (prevent infinite growth).
                Property::<Self>::always("bounded message queues", |_, state| {
                    const MAX_QUEUE_SIZE: usize = 1000;
                    if state.tas_inbox.len() > MAX_QUEUE_SIZE {
                        println!("\n=== INVARIANT VIOLATION ===");
                        println!("TAS inbox too large: {}", state.tas_inbox.len());
                        return false;
                    }
                    for (i, inbox) in state.trustee_inboxes.iter().enumerate() {
                        if inbox.len() > MAX_QUEUE_SIZE {
                            println!("\n=== INVARIANT VIOLATION ===");
                            println!("Trustee {} inbox too large: {}", i, inbox.len());
                            return false;
                        }
                    }
                    true
                }),
                // Phase progression should be monotonic (can't go backwards).
                Property::<Self>::always("phases progress monotonically", |_, state| {
                    // If we've completed a later phase, earlier phases must also be complete
                    if state.completed_phases.contains(&Phase::KeyGen)
                        && !state.completed_phases.contains(&Phase::Setup)
                    {
                        println!("\n=== INVARIANT VIOLATION ===");
                        println!("KeyGen completed without Setup");
                        return false;
                    }
                    if state.completed_phases.contains(&Phase::Mixing)
                        && !state.completed_phases.contains(&Phase::KeyGen)
                    {
                        println!("\n=== INVARIANT VIOLATION ===");
                        println!("Mixing completed without KeyGen");
                        return false;
                    }
                    if state.completed_phases.contains(&Phase::Decryption)
                        && !state.completed_phases.contains(&Phase::Mixing)
                    {
                        println!("\n=== INVARIANT VIOLATION ===");
                        println!("Decryption completed without Mixing");
                        return false;
                    }
                    true
                }),
            ];

            // Active trustees should always have consistent boards after Decryption completes.
            // We only check after Decryption (the final phase) has completed successfully,
            // at which point all active trustees (those who participated in decryption)
            // should have identical boards. This property should hold whether or not Byzantine
            // behavior occurs - if Byzantine behavior creates undetected inconsistencies,
            // this property will fail.
            props.push(Property::<Self>::always(
                "Active trustees have consistent boards after Decryption completes",
                |model, state| {
                    // Only check when:
                    // - Decryption phase has completed
                    // - Protocol has quiesced (all inboxes empty)
                    // - No failures occurred (failures mean protocol detected a problem)
                    if !state.completed_phases.contains(&Phase::Decryption)
                        || !state.tas_inbox.is_empty()
                        || state.trustee_inboxes.iter().any(|inbox| !inbox.is_empty())
                        || state.has_failure
                    {
                        return true;
                    }

                    // After Decryption, only threshold trustees (indexed 0..threshold) participated.
                    let active_trustee_count = model.threshold;

                    // Check that all active trustees (0..active_trustee_count) have the same board
                    let reference_board = &state.trustees[0].processed_board;

                    for trustee_idx in 1..active_trustee_count {
                        let trustee_board = &state.trustees[trustee_idx].processed_board;
                        if trustee_board != reference_board {
                            println!("\n=== BOARD INCONSISTENCY DETECTED ===");
                            println!(
                                "After Decryption completed, active trustees have different boards"
                            );
                            println!("Trustee 0 board length: {}", reference_board.len());
                            println!(
                                "Trustee {} board length: {}",
                                trustee_idx,
                                trustee_board.len()
                            );
                            println!("Completed phases: {:?}", state.completed_phases);
                            println!("Active trustee count: {}", active_trustee_count);
                            println!(
                                "Byzantine behavior occurred: {}",
                                state.byzantine_behavior_occurred()
                            );
                            println!("has_failure: {}", state.has_failure);

                            // Show first difference
                            let min_len = reference_board.len().min(trustee_board.len());
                            for idx in 0..min_len {
                                if reference_board[idx].trustee_msg
                                    != trustee_board[idx].trustee_msg
                                {
                                    println!("First difference at board index {}", idx);
                                    println!(
                                        "Trustee 0 message: {:#?}",
                                        reference_board[idx].trustee_msg
                                    );
                                    println!(
                                        "Trustee {} message: {:#?}",
                                        trustee_idx, trustee_board[idx].trustee_msg
                                    );
                                    break;
                                }
                            }

                            return false;
                        }
                    }
                    true
                },
            ));

            // Add completion properties for each phase we're testing.
            if self.should_test_phase(&Phase::Setup) {
                props.push(Property::<Self>::sometimes(
                    "Setup sometimes completes.",
                    |_, state| state.completed_phases.contains(&Phase::Setup),
                ));

                if self.test_byzantine_behavior {
                    props.push(Property::<Self>::sometimes(
                        "Byzantine behavior sometimes affects setup.",
                        |_, state| state.byzantine_phases_affected.contains(&Phase::Setup),
                    ));
                }

                props.push(Property::<Self>::eventually(
                    "setup completes when no Byzantine behavior affects setup or earlier",
                    |_, state| {
                        state.completed_phases.contains(&Phase::Setup)
                            || state.byzantine_affected_phase_or_earlier(&Phase::Setup)
                    },
                ));

                // Stronger property: all trustees complete setup.
                props.push(Property::<Self>::eventually(
                    "all trustees complete setup when no Byzantine behavior affects setup or earlier",
                    |model, state| {
                        let trustees_completed_setup = state
                            .trustees_completed_phases
                            .get(&Phase::Setup)
                            .map(|set| set.len())
                            .unwrap_or(0);

                        trustees_completed_setup >= model.num_trustees
                            || state.byzantine_affected_phase_or_earlier(&Phase::Setup)
                    },
                ));
            }

            if self.should_test_phase(&Phase::KeyGen) {
                props.push(Property::<Self>::sometimes(
                    "KeyGen sometimes completes.",
                    |_, state| state.completed_phases.contains(&Phase::KeyGen),
                ));

                if self.test_byzantine_behavior {
                    props.push(Property::<Self>::sometimes(
                        "Byzantine behavior sometimes affects keygen.",
                        |_, state| state.byzantine_phases_affected.contains(&Phase::KeyGen),
                    ));
                }

                props.push(Property::<Self>::eventually(
                    "keygen completes when no Byzantine behavior affects keygen or earlier",
                    |_, state| {
                        state.completed_phases.contains(&Phase::KeyGen)
                            || state.byzantine_affected_phase_or_earlier(&Phase::KeyGen)
                    },
                ));

                // Stronger property: all trustees complete keygen.
                props.push(Property::<Self>::eventually(
                    "all trustees complete keygen when no Byzantine behavior affects keygen or earlier",
                    |model, state| {
                        let trustees_completed_keygen = state
                            .trustees_completed_phases
                            .get(&Phase::KeyGen)
                            .map(|set| set.len())
                            .unwrap_or(0);

                        trustees_completed_keygen >= model.num_trustees
                            || state.byzantine_affected_phase_or_earlier(&Phase::KeyGen)
                    },
                ));
            }

            if self.should_test_phase(&Phase::Mixing) {
                props.push(Property::<Self>::sometimes(
                    "Mixing sometimes completes.",
                    |_, state| state.completed_phases.contains(&Phase::Mixing),
                ));

                if self.test_byzantine_behavior {
                    props.push(Property::<Self>::sometimes(
                        "Byzantine behavior sometimes affects mixing.",
                        |_, state| state.byzantine_phases_affected.contains(&Phase::Mixing),
                    ));
                }

                props.push(Property::<Self>::eventually(
                    "mixing completes when no Byzantine behavior affects mixing or earlier",
                    |_, state| {
                        state.completed_phases.contains(&Phase::Mixing)
                            || state.byzantine_affected_phase_or_earlier(&Phase::Mixing)
                    },
                ));

                // Stronger property: threshold trustees complete mixing.
                props.push(Property::<Self>::eventually(
                    "threshold trustees complete mixing when no Byzantine behavior affects mixing or earlier",
                    |model, state| {
                        let trustees_completed_mixing = state
                            .trustees_completed_phases
                            .get(&Phase::Mixing)
                            .map(|set| set.len())
                            .unwrap_or(0);

                        trustees_completed_mixing >= model.threshold
                            || state.byzantine_affected_phase_or_earlier(&Phase::Mixing)
                    },
                ));
            }

            if self.should_test_phase(&Phase::Decryption) {
                props.push(Property::<Self>::sometimes(
                    "Decryption sometimes completes.",
                    |_, state| state.completed_phases.contains(&Phase::Decryption),
                ));

                if self.test_byzantine_behavior {
                    props.push(Property::<Self>::sometimes(
                        "Byzantine behavior sometimes affects decryption.",
                        |_, state| state.byzantine_phases_affected.contains(&Phase::Decryption),
                    ));
                }

                props.push(Property::<Self>::eventually(
                    "decryption completes when no Byzantine behavior affects decryption or earlier",
                    |_, state| {
                        state.completed_phases.contains(&Phase::Decryption)
                            || state.byzantine_affected_phase_or_earlier(&Phase::Decryption)
                    },
                ));

                // Stronger property: all threshold trustees complete decryption.
                props.push(Property::<Self>::eventually(
                    "threshold trustees complete decryption when no Byzantine behavior affects decryption or earlier",
                    |model, state| {
                        let trustees_completed_decryption = state
                            .trustees_completed_phases
                            .get(&Phase::Decryption)
                            .map(|set| set.len())
                            .unwrap_or(0);

                        trustees_completed_decryption >= model.threshold
                            || state.byzantine_affected_phase_or_earlier(&Phase::Decryption)
                    },
                ));

                // Correctness property: in any state where decryption is complete,
                // the decrypted ballots match the generated ballots.
                props.push(Property::<Self>::always(
                    "decrypted ballots match original plaintexts",
                    |model, state| {
                        // This property is satisfied when decryption completes and ballots match.
                        if !state.completed_phases.contains(&Phase::Decryption) {
                            return true; // Decryption is not yet complete.
                        }

                        // Get the decrypted ballots from the TAS.
                        let decrypted_ballots = state.tas.decryption_data().decrypted_ballots;

                        // Generate the expected plaintext ballots.
                        let expected_ballots = Self::generate_plaintext_ballots(
                            model.num_ballot_styles,
                            model.num_ballots_per_style,
                        );

                        // Compare decrypted ballots with expected plaintexts (as sorted vectors,
                        // since mixing shuffles the order).
                        let mut ballots_match = true; //
                        for (style, expected) in &expected_ballots {
                            if let Some(decrypted) = decrypted_ballots.get(style) {
                                if expected.len() != decrypted.len() {
                                    ballots_match = false;
                                    break;
                                }

                                let mut expected_sorted = expected.clone();
                                let mut decrypted_sorted = decrypted.clone();
                                expected_sorted.sort_by_key(|b| b.rank);
                                decrypted_sorted.sort_by_key(|b| b.rank);

                                if expected_sorted != decrypted_sorted {
                                    ballots_match = false;
                                    break;
                                }
                            } else {
                                ballots_match = false;
                                break;
                            }
                        }

                        if !ballots_match {
                            println!("\n=== INVARIANT VIOLATION ===");
                            println!("Decrypted ballots do not match original plaintexts!");
                            println!("Expected {} ballot styles", expected_ballots.len());
                            println!("Got {} ballot styles", decrypted_ballots.len());

                            for (style, expected) in &expected_ballots {
                                if let Some(decrypted) = decrypted_ballots.get(style) {
                                    let mut expected_sorted = expected.clone();
                                    let mut decrypted_sorted = decrypted.clone();
                                    expected_sorted.sort_by_key(|b| b.rank);
                                    decrypted_sorted.sort_by_key(|b| b.rank);

                                    if expected_sorted != decrypted_sorted {
                                        println!(
                                            "  Ballot style {}: expected {} ballots, got {}",
                                            style,
                                            expected.len(),
                                            decrypted.len()
                                        );
                                        for (i, (exp, dec)) in expected_sorted
                                            .iter()
                                            .zip(decrypted_sorted.iter())
                                            .enumerate()
                                        {
                                            if exp != dec {
                                                println!("    Ballot {}: mismatch", i);
                                                println!("      Expected: {:?}", exp);
                                                println!("      Got: {:?}", dec);
                                            }
                                        }
                                    }
                                } else {
                                    println!(
                                        "  Ballot style {}: missing in decrypted ballots",
                                        style
                                    );
                                }
                            }

                            return false;
                        }

                        true
                    },
                ));
            }

            props
        }
    }

    // --- Core Protocol Tests (No Faults) --

    #[test]
    fn test_full_protocol_3_trustees() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_ballot_styles(2)
            .with_ballots_per_style(5);
        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for full protocol (3 trustees, threshold 2)",
            checker.state_count()
        );
    }

    #[test]
    fn test_full_protocol_5_trustees() {
        let model = IntegrationModel::new(5, 3)
            .through_phase(Phase::Decryption)
            .with_ballot_styles(2)
            .with_ballots_per_style(5);
        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for full protocol (5 trustees, threshold 3)",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This test is far too large for most machines.
    fn test_setup_and_dkg_7_trustees() {
        // We only test through KeyGen here to keep the state space "reasonable".
        let model = IntegrationModel::new(7, 4).through_phase(Phase::KeyGen);
        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for setup+DKG (7 trustees, threshold 4)",
            checker.state_count()
        );
    }

    // --- Message Fault Tests ---

    #[test]
    fn test_drops_3_trustees() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for 3 trustees with drops",
            checker.state_count()
        );
    }

    #[test]
    fn test_multiple_drops_3_trustees() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(3); // Allow up to 3 drops per trustee

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for 3 trustees with multiple drops",
            checker.state_count()
        );
    }

    #[test]
    fn test_duplicates_3_trustees() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_duplicates(1); // Allow up to 1 duplicate per trustee

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for 3 trustees with duplicates",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This takes a while so only run it on request.
    fn test_drops_and_duplicates_3_trustees() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(1)
            .with_message_duplicates(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for 3 trustees with drops and duplicates",
            checker.state_count()
        );
    }

    // --- Byzantine Behavior Tests ---

    #[test]
    fn test_byzantine_small() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine small test",
            checker.state_count()
        );
    }

    #[test]
    fn test_byzantine_small_with_drops() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(1)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine small test with drops",
            checker.state_count()
        );
    }

    #[test]
    fn test_byzantine_small_with_duplicates() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_duplicates(1)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine small test with duplicates",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This takes a while so only run it on request.
    fn test_byzantine_small_with_drops_and_duplicates() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(1)
            .with_message_duplicates(1)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine small test with drops and duplicates",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This test takes a while so only run it on request.
    fn test_byzantine_medium() {
        let model = IntegrationModel::new(5, 3)
            .through_phase(Phase::Decryption)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine medium test",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This test is far too large for most machines.
    fn test_byzantine_medium_with_drops_and_duplicates() {
        let model = IntegrationModel::new(5, 3)
            .through_phase(Phase::Decryption)
            .with_message_drops(1)
            .with_message_duplicates(1)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine medium test with drops and duplicates",
            checker.state_count()
        );
    }

    #[test]
    #[ignore] // This test is far too large for most machines.
    fn test_byzantine_large() {
        let model = IntegrationModel::new(7, 4)
            .through_phase(Phase::Decryption)
            .with_byzantine_actions(1);

        let checker = model
            .checker()
            .threads(get_thread_count())
            .spawn_bfs()
            .join();
        checker.assert_properties();

        println!(
            "Explored {} states for Byzantine large test",
            checker.state_count()
        );
    }

    // --- Web UI for Interactive Exploration ---
    //
    // This test is marked #[ignore] because it starts a web server
    // and doesn't terminate automatically. To use it:
    //
    //   cargo test -p votesecure-protocol-library --lib explore_with_web_ui -- --ignored --nocapture
    //
    // Then open http://localhost:3000 to interactively explore
    // the state space, see execution paths, and verify properties.
    #[test]
    #[ignore]
    fn explore_with_web_ui() {
        let model = IntegrationModel::new(3, 2)
            .through_phase(Phase::Decryption)
            .with_message_drops(1)
            .with_message_duplicates(1)
            .with_byzantine_actions(1);

        println!("\nStarting Stateright web UI...");
        println!("Open http://localhost:3000 in your browser");
        println!("Press Ctrl+C to stop");

        // This will start a web server and block until Ctrl+C
        model.checker().serve("localhost:3000");
    }
}
