//! Top-level trustee actor that wraps all the trustee protocols.
//!
//! This actor maintains a local bulletin board with both full `TrusteeMsg`
//! objects and summaries of those messages to pass to the protocol logic,
//! which determines what actions to take with the data in the messages.
//! The exception to this is the setup protocol, which needs no real
//! computation; we simply sign the setup message if we are properly listed
//! in it as a trustee.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::crypto::{
    BALLOT_CIPHERTEXT_WIDTH, CryptoContext, ElectionKey, SelectionElement, SigningKey,
    VSerializable, decode_ballot, encryption_context, sign_data,
};
use crate::elections::{Ballot, BallotStyle, ElectionHash, string_to_election_hash};
use crate::trustee_protocols::trustee_application::ascent_logic::protocol::composed_ascent_logic;
use crate::trustee_protocols::trustee_application::ascent_logic::{Action, AscentMsg};
use crate::trustee_protocols::trustee_application::handlers::*;
use crate::trustee_protocols::trustee_cryptography::{
    CheckValue, Dealer, DecryptionFactor, MixRoundProof, ParticipantPosition, Recipient, Share,
    ShareCiphertext, StrippedBallotCiphertext, TrusteeKeyPair, VerifiableShare,
    combine_partial_decryptions, compute_partial_decryptions, decrypt_share, encrypt_share,
    shuffle_ciphertexts, verify_shuffle,
};
use crate::trustee_protocols::trustee_messages::{
    CheckSignature, DecryptedBallotsMsg, DecryptedBallotsMsgData, EGCryptogramsMsg,
    EGCryptogramsMsgData, ElectionPublicKeyMsg, ElectionPublicKeyMsgData, KeySharesMsg,
    KeySharesMsgData, MixInitializationMsg, PartialDecryption, PartialDecryptionsMsg,
    PartialDecryptionsMsgData, SetupMsg, TrusteeBBUpdateMsg, TrusteeBBUpdateRequestMsg, TrusteeID,
    TrusteeInfo, TrusteeMsg,
};
use enum_dispatch::enum_dispatch;
use std::collections::{BTreeMap, HashSet};

// This should be removed once we unify all hashing
use crate::crypto::CryptoHash;
use crate::crypto::hash_serializable;

// --- Helper Macros ---

/// Macro to dispatch runtime threshold/trustee count to the const
/// generics in the cryptography library. Currently it only includes
/// a small number of trustee combinations, all of which have the
/// property that threshold > trustee_count / 2.
///
/// Usage:
/// ```ignore
/// dispatch_threshold_trustees!(threshold, trustee_count, T, P, {
///     // code block that uses const T and P
///     let dealer: Dealer<CryptoContext, T, P> = Dealer::generate();
///     // ...
/// })
/// ```
macro_rules! dispatch_threshold_trustees {
    ($threshold:expr, $trustees:expr, $t:ident, $p:ident, $body:block) => {
        match ($threshold, $trustees) {
            // The currently-supported trustee configurations.
            (2, 3) => {
                const $t: usize = 2;
                const $p: usize = 3;
                $body
            }
            (3, 5) => {
                const $t: usize = 3;
                const $p: usize = 5;
                $body
            }
            (4, 7) => {
                const $t: usize = 4;
                const $p: usize = 7;
                $body
            }
            (5, 9) => {
                const $t: usize = 5;
                const $p: usize = 9;
                $body
            }
            (6, 11) => {
                const $t: usize = 6;
                const $p: usize = 11;
                $body
            }
            (7, 13) => {
                const $t: usize = 7;
                const $p: usize = 13;
                $body
            }
            (3, 4) => {
                const $t: usize = 3;
                const $p: usize = 4;
                $body
            }
            (4, 6) => {
                const $t: usize = 4;
                const $p: usize = 6;
                $body
            }
            (5, 8) => {
                const $t: usize = 5;
                const $p: usize = 8;
                $body
            }
            (6, 10) => {
                const $t: usize = 6;
                const $p: usize = 10;
                $body
            }
            (7, 12) => {
                const $t: usize = 7;
                const $p: usize = 12;
                $body
            }
            // Add more combinations as needed.
            _ => {
                return Err(format!(
                    "Unsupported threshold/trustee combination: {}/{}",
                    $threshold, $trustees
                ))
            }
        }
    };
}

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `TrusteeActor` can process.
#[enum_dispatch(TrusteeBoomerang)]
#[derive(Debug, Clone, PartialEq)]
pub enum TrusteeInput {
    /// Process a set of trustee board messages received from the TAS
    /// (if they are valid given our current board state).
    HandleBoardUpdate(TrusteeBBUpdateMsg),
    /// Approve the setup data (manual trustee action).
    ApproveSetup,
    /// Start the key generation protocol. We have an explicit trigger
    /// for this because, unlike setup and mixing/decryption, there is
    /// no incoming trustee board message that tells the trustee to do
    /// key generation.
    StartKeyGen,
    /// Stop and export a checkpoint for archival or analysis.
    Stop,
}

/// The set of outputs that the `TrusteeActor` can produce. Note that it
/// can also always return a TrusteeMsg to be sent to the TAS (and from
/// there to all trustees), in addition to this output.
#[derive(Debug, Clone, PartialEq)]
pub enum TrusteeOutput {
    /// Request trustee approval of setup information.
    RequestSetupApproval(SetupMsg),
    /// Setup protocol completed successfully.
    SetupComplete(TrusteeCheckpoint),
    /// Key generation completed successfully.
    KeyGenComplete(TrusteeCheckpoint),
    /// Mixing completed successfully.
    MixingComplete,
    /// Decryption completed successfully. The trustee protocols are now
    /// complete and the state data can be archived for later auditing.
    DecryptionComplete(TrusteeCheckpoint),
    /// One or more trustee board messages are missing and must be
    /// fetched from the TAS (using the specified message).
    MissingMessages(TrusteeBBUpdateRequestMsg),
    /// The running protocol has been stopped.
    Stopped(TrusteeCheckpoint),
    /// The current trustee subprotocol has failed.
    Failed(FailureData),
    /// The input passed was invalid for the current state.
    InvalidInput(FailureData),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessedTrusteeMsg {
    pub trustee_msg: TrusteeMsg,
    pub(crate) ascent_msg: AscentMsg,
}

/// Contains the protocol state exclusive of the board and
/// private information (trustee encryption keys).
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolStateData {
    pub election_hash: ElectionHash, // election hash computed from manifest string
    pub threshold: u32,
    pub trustees: Vec<TrusteeInfo>,
    pub active_trustees: Vec<TrusteeInfo>,
}

/// Contains a full checkpoint of the protocol state,
/// inclusive of the board but exclusive of private
/// information (trustee encryption keys).
#[derive(Debug, Clone, PartialEq)]
pub struct TrusteeCheckpoint {
    pub board: Vec<TrusteeMsg>,
    pub protocol_state: Option<ProtocolStateData>,
}

/// An enum identifying the subprotocols; this is used both
/// in the `FailureData` message and in the trustee state
/// (it is updated by the protocol wrapper based on the
/// trustee logic actions).
#[derive(Debug, Clone, PartialEq)]
pub enum TrusteeSubprotocol {
    Idle,
    ElectionSetup,
    KeyGen,
    Mixing,
    Decryption,
    Failed,
}

/// The data resulting from a failure, including sufficient
/// state to retry the operation or analyze the failure.
#[derive(Debug, Clone, PartialEq)]
pub struct FailureData {
    pub subprotocol: TrusteeSubprotocol,
    pub failure_msg: String,
    pub board: Vec<TrusteeMsg>,
    pub protocol_state: Option<ProtocolStateData>,
}

// --- II. Trustee State ---

/// The states for the Trustee actor.
#[enum_dispatch(TrusteeStateHandler)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TrusteeState {
    Idle,
    ElectionSetup,
    KeyGen,
    Mixing,
    Decryption,
    Failed,
}

// --- III. Trustee Actor ---

/// The Trustee actor.
#[derive(Clone, Debug)]
pub struct TrusteeActor {
    /// The current state.
    pub(crate) state: TrusteeState,

    /// This trustee's information.
    pub(crate) trustee_info: TrusteeInfo,

    /// This trustee's signing key.
    pub(crate) signing_key: SigningKey,

    /// This trustee's encryption key pair (the cryptography
    /// data structures do not allow us to store only the private
    /// key, as it can't be extracted from the key pair).
    pub(crate) encryption_key_pair: TrusteeKeyPair,

    /// The local trustee bulletin board with both full messages
    /// and protocol summaries.
    pub(crate) processed_board: Vec<ProcessedTrusteeMsg>,

    /// Protocol state data (from setup and mix parameters).
    pub(crate) protocol_state_data: Option<ProtocolStateData>,

    /// The computed configuration hash, stored for use with
    /// Ascent messages. This is necessary because there is no
    /// guarantee that the `election_manifest` string actually
    /// includes all the information necessary to ensure that
    /// setup messages are consistent, and we want to be sure
    /// that even if it doesn't, we still check for that
    /// consistency.
    pub(crate) cfg_hash: CryptoHash,

    /// Actions that this trustee has already completed. This
    /// prevents the trustee from executing them redundantly
    /// before its own messages generated as a result of the
    /// actions appear on the board.
    completed_actions: HashSet<Action>,
}

#[allow(dead_code)]
impl TrusteeActor {
    /// Create a new `TrusteeActor`. If a checkpoint is supplied,
    /// the trustee is "restored" to that checkpoint and ready
    /// to continue protocol execution from there; otherwise,
    /// it starts "fresh" and ready to execute the election
    /// setup protocol. Note that checkpoints are only made
    /// when the trustee is `Idle` (has successfully completed
    /// some subprotocol), and the new `TrusteeActor` always
    /// starts in the `Idle` state.
    pub fn new(
        trustee_info: TrusteeInfo,
        signing_key: SigningKey,
        encryption_key_pair: TrusteeKeyPair,
        checkpoint: Option<TrusteeCheckpoint>,
    ) -> Result<Self, String> {
        // obviously invalid configuration
        let cfg_hash = "".to_string();
        let cfg_hash = hash_serializable(&cfg_hash);

        let mut res = Self {
            state: TrusteeState::Idle(Idle),
            trustee_info,
            signing_key,
            encryption_key_pair,
            processed_board: Vec::new(),
            protocol_state_data: None,
            cfg_hash,
            completed_actions: HashSet::new(),
        };

        match checkpoint {
            Some(cp) => {
                // Update the state from the checkpoint.
                res.protocol_state_data = cp.protocol_state;

                // First pass: Find the Setup message and compute cfg_hash.
                // This must be done before converting messages after the
                // Setup phase to Ascent messages, because that conversion
                // requires cfg_hash to be stored. If there is an
                // inconsistency, it will be detected the first time the
                // Ascent logic is actually run.
                if let Some(setup_msg) = cp.board.iter().find_map(|tm| {
                    if let TrusteeMsg::Setup(setup) = tm {
                        Some(setup)
                    } else {
                        None
                    }
                }) {
                    res.cfg_hash = Self::setup_msg_to_cfg_hash(setup_msg);
                }

                // Second pass: Convert all messages to Ascent messages.
                for tm in cp.board {
                    let am = res.trustee_msg_to_ascent_msg(&tm)?;
                    res.processed_board.push(ProcessedTrusteeMsg {
                        trustee_msg: tm,
                        ascent_msg: am,
                    })
                }
            }

            None => { /* Don't do anything, there's no state to restore. */ }
        }
        Ok(res)
    }

    /// Handle an input to the trustee actor using enum_dispatch.
    pub fn handle_input(
        &mut self,
        input: TrusteeInput,
    ) -> (Option<TrusteeOutput>, Option<TrusteeMsg>) {
        let (new_state, output, message) = input.boomerang(self);

        self.state = new_state.unwrap_or(self.state);
        (output, message)
    }

    /// Process a board update from the TAS and return output and messages.
    /// This is a utility method called by state handlers, not a handler itself.
    /// State transitions are determined by the handlers after this returns.
    pub(crate) fn process_board_update(
        &mut self,
        update: &TrusteeBBUpdateMsg,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        // First, check for valid signatures on all messages in the update;
        // if any don't have them, fail the protocol because we should never
        // see badly signed messages.
        if update
            .msgs
            .iter()
            .any(|(_, m)| m.check_signature().is_err())
        {
            return (
                Some(TrusteeState::Failed(Failed)),
                Some(TrusteeOutput::Failed(self.failure_data(
                    "badly signed message in trustee board update".to_string(),
                ))),
                None,
            );
        }

        // Check that the message came from a known trustee. Until setup is approved,
        // there is no known trustee list, so we cannot check this until we have such
        // a list in our protocol state.
        if !self.protocol_state().trustees.is_empty()
            && !update.msgs.iter().all(|(_, m)| {
                self.protocol_state()
                    .trustees
                    .iter()
                    .any(|ti| ti.trustee_id() == m.signer_id().expect("message must be signed"))
            })
        {
            return (
                Some(TrusteeState::Failed(Failed)),
                Some(TrusteeOutput::Failed(self.failure_data(
                    "message signed by unknown trustee in trustee board update".to_string(),
                ))),
                None,
            );
        }

        // Next, check for gaps in the message sequence in the update message;
        // if there are any, it's an invalid update message and we fail the
        // protocol. Note that the data structure in the message guarantees
        // that the messages are sorted in ascending order by index.
        if let Some(gap_error) = self.check_board_update_for_gaps(update) {
            return (
                Some(TrusteeState::Failed(Failed)),
                Some(TrusteeOutput::Failed(self.failure_data(gap_error))),
                None,
            );
        }

        // Next, check for any conflicts (messages with the same index but
        // different contents) with messages already on our board. If there
        // are any, it's an invalid update message and we fail the protocol.
        let conflicts = self.check_board_update_for_conflicts(update);
        if !conflicts.is_empty() {
            return (
                Some(TrusteeState::Failed(Failed)),
                Some(TrusteeOutput::Failed(self.failure_data(format!(
                    "Conflicting messages: {:?}",
                    conflicts
                )))),
                None,
            );
        }

        let initial_expected_index = self.processed_board.len() as u64;

        // If the minimum index in the update is greater than our expected
        // index, we're missing messages and need to request them from the TAS.
        if let Some((min_index, _)) = update.msgs.first_key_value()
            && *min_index > initial_expected_index
        {
            // We're missing messages starting at initial_expected_index.
            // Request all messages from that point onwards (we don't know how many).
            let request = TrusteeBBUpdateRequestMsg {
                trustee: self.trustee_info.trustee_id(),
                start_index: initial_expected_index,
                end_index: u64::MAX,
            };
            // Return the message request as an output that the application layer
            // will wrap in a TrusteeMsg and send to the TAS
            return (
                None, // Don't change state
                Some(TrusteeOutput::MissingMessages(request)),
                None, // No direct message (application wraps the request)
            );
        }

        // Next, convert all the incoming messages to Ascent message summaries
        // and add them, and the summaries, to the board. We start at the
        // initial expected index and continue in sequence.
        for (_, msg) in update
            .msgs
            .iter()
            .filter(|(idx, _)| idx >= &&initial_expected_index)
        {
            // Convert TrusteeMsg to AscentMsg
            match self.trustee_msg_to_ascent_msg(msg) {
                Ok(ascent_msg) => {
                    let processed = ProcessedTrusteeMsg {
                        trustee_msg: msg.clone(),
                        ascent_msg,
                    };
                    self.processed_board.push(processed);
                }
                Err(e) => {
                    return (
                        Some(TrusteeState::Failed(Failed)),
                        Some(TrusteeOutput::Failed(
                            self.failure_data(format!("Failed to process message: {}", e)),
                        )),
                        None,
                    );
                }
            }
        }

        // If no new messages were processed (all duplicates), return early,
        // since there's nothing to do.
        if self.processed_board.len() == initial_expected_index as usize {
            return (None, None, None);
        }

        // Extract and populate active_trustees from a MixInitialization
        // message on the board, if one is present; if the active trustees
        // list has already been populated this is a no-op.
        if let Err(e) = self.populate_active_trustees_from_board() {
            return (
                Some(TrusteeState::Failed(Failed)),
                Some(TrusteeOutput::Failed(self.failure_data(e))),
                None,
            );
        }

        // Run the Ascent actions, if necessary.

        let message_to_send = match self.state {
            // If we're in the idle state with no protocol state yet, we don't
            // run Ascent logic, but we do need to check for state transitions
            // (e.g., to ElectionSetup when a SetupMsg arrives).
            TrusteeState::Idle(Idle) if self.protocol_state_data.is_none() => None,
            // In the setup state we also don't run Ascent logic, but we still
            // need to check for state transitions.
            TrusteeState::ElectionSetup(ElectionSetup) => None,
            // Otherwise, we run the Ascent logic on the up-to-date board
            // and (attempt to) take the actions it generates.
            _ => match self.execute_ascent_logic() {
                Ok(trustee_msg) => trustee_msg,
                Err(error_msg) => {
                    return (
                        Some(TrusteeState::Failed(Failed)),
                        Some(TrusteeOutput::Failed(self.failure_data(error_msg))),
                        None,
                    );
                }
            },
        };

        // Determine the next state and output, based on the board state.
        let (new_state, output) = self.determine_next_state_and_output();

        (new_state, output, message_to_send)
    }

    /// Extract and populate the active_trustees list from a MixInitialization
    /// message if one exists on the board and the active_trustees list is
    /// currently empty.
    fn populate_active_trustees_from_board(&mut self) -> Result<(), String> {
        // Check if there's a MixInitialization message on the board.
        let mix_init_msg = self.processed_board.iter().find_map(|m| match m {
            ProcessedTrusteeMsg {
                trustee_msg: TrusteeMsg::MixInitialization(msg),
                ascent_msg: _,
            } => Some(msg.clone()),
            _ => None,
        });

        if let Some(msg) = mix_init_msg {
            // We have a MixInitialization message, so we need protocol state data.
            let protocol_data = self.protocol_state_data.as_mut().ok_or_else(|| {
                "MixInitialization message found but no protocol state data exists".to_string()
            })?;

            // Only populate if the list is currently empt.
            if protocol_data.active_trustees.is_empty() {
                // Convert TrusteeID to TrusteeInfo by looking it up in the trustees list.
                let active_trustees: Vec<TrusteeInfo> = msg
                    .data
                    .active_trustees
                    .iter()
                    .filter_map(|tid| {
                        protocol_data
                            .trustees
                            .iter()
                            .find(|t| t.trustee_id() == *tid)
                            .cloned()
                    })
                    .collect();

                protocol_data.active_trustees = active_trustees;
            }
        }

        Ok(())
    }

    /// Check if the update message itself has gaps (malformed update).
    ///
    /// An update should contain a contiguous range of indices. For example,
    /// [9, 10, 11] is valid, but [9, 11, 12] is not.
    fn check_board_update_for_gaps(&self, update: &TrusteeBBUpdateMsg) -> Option<String> {
        if update.msgs.is_empty() {
            return None;
        }

        let min_index = *update.msgs.keys().min().unwrap();
        let max_index = *update.msgs.keys().max().unwrap();
        let expected_count = (max_index - min_index + 1) as usize;

        if update.msgs.len() != expected_count {
            return Some(format!(
                "Update message has gaps: contains {} messages but spans indices {} to {}",
                update.msgs.len(),
                min_index,
                max_index
            ));
        }

        None
    }

    /// Check for conflicts between update messages and existing board.
    ///
    /// This ensures our local board mirrors the TAS board correctly by verifying
    /// that any message at an index we already have is identical to the incoming
    /// message at that same index.
    fn check_board_update_for_conflicts(&self, update: &TrusteeBBUpdateMsg) -> Vec<String> {
        let mut conflicts = Vec::new();

        for (&index, msg) in &update.msgs {
            let idx = index as usize;

            // Check if we already have a message at this index
            if idx < self.processed_board.len() {
                // We have a message at this index - verify it's identical
                if &self.processed_board[idx].trustee_msg != msg {
                    conflicts.push(format!(
                        "Message at index {} differs from existing message",
                        index
                    ));
                }
            }
            // If we don't have a message at this index, there's no conflict
        }

        conflicts
    }

    /// Convert a TrusteeMsg to an AscentMsg summary. Note that, other than
    /// for Setup messages (from which configuration hashes are generated),
    /// we always use our stored configuration hash for Ascent messages,
    /// after verifying that the `election_hash` passed in the message
    /// matches our stored `election_hash` (also computed from Setup
    /// message data).
    fn trustee_msg_to_ascent_msg(&self, msg: &TrusteeMsg) -> Result<AscentMsg, String> {
        match msg {
            TrusteeMsg::Setup(msg) => {
                // Setup messages become ConfigurationValid Ascent messages; even if
                // the configuration isn't valid it doesn't matter, because we never
                // execute the Ascent logic until we have all matching configuration
                // messages. The TAS is included in the trustees list for setup (so it
                // can sign the configuration), but it doesn't participate in DKG, so
                // trustee_count excludes it.

                let cfg_hash = Self::setup_msg_to_cfg_hash(msg);
                let trustee_count = msg.data.trustees.len() - 1; // Exclude TAS.
                let threshold = msg.data.threshold as usize;

                // Trustee indices for setup messages are relative to the trustee list
                // in the setup message, because there is no agreed-upon list to use yet.
                // This is OK, though, beause we don't check the indices to see that
                // we've completed setup, we check the actual trustee IDs (and the Ascent
                // logic cannot be run with an inconsistent set of Setup messages).
                let signer_index = msg
                    .data
                    .trustees
                    .iter()
                    .position(|t| t.trustee_id() == msg.data.signer)
                    .ok_or_else(|| "Setup message signer not found in trustees list".to_string())?;

                Ok(AscentMsg::ConfigurationValid(
                    cfg_hash,
                    threshold,
                    trustee_count,
                    signer_index,
                ))
            }

            TrusteeMsg::KeyShares(msg) => {
                // KeyShares messages become Shares Ascent messages. Trustee indices
                // start at 1, but that's OK because the TAS is always trustee 0 (and is
                // ignored here).

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "Key shares election hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                // Serialize the shares data to compute hash (ShareCiphertext doesn't implement Hash)
                let shares_tuple = (&msg.data.check_values, &msg.data.pairwise_shares);
                let shares_hash = hash_serializable(&shares_tuple);

                // Sanity check: key shares messages must be originated and signed by the
                // same trustee.
                if msg.data.originator != msg.data.signer {
                    return Err(format!(
                        "Key shares message originator {:?} and signer {:?} do not match",
                        msg.data.originator, msg.data.signer
                    ));
                }

                // Find the sender index using the originator ID.
                let sender_index = self.get_trustee_index(&msg.data.originator)?;

                Ok(AscentMsg::Shares(self.cfg_hash, shares_hash, sender_index))
            }

            TrusteeMsg::ElectionPublicKey(msg) => {
                // ElectionPublicKey messages become PublicKey Ascent messages.
                // Trustee indices start at 1, but that's OK because the TAS is
                // always trustee 0 (and is ignored here).

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "Key shares election hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                // We package both the public key hash and the public shares hash
                // into pk_hash so the Ascent logic takes both into account.

                let mut bytes_to_hash = msg.data.check_values.ser();
                bytes_to_hash.extend(msg.data.election_public_key.ser());
                let pk_hash = hash_serializable(&bytes_to_hash);
                // let pk_hash = bytes_to_hash.get_hash();

                // Sanity check: election public key messages must be originated and
                // signed by the same trustee.
                if msg.data.originator != msg.data.signer {
                    return Err(format!(
                        "Election public key message originator {:?} and signer {:?} do not match",
                        msg.data.originator, msg.data.signer
                    ));
                }

                // Find the sender index using the originator ID.
                let sender_index = self.get_trustee_index(&msg.data.originator)?;

                Ok(AscentMsg::PublicKey(self.cfg_hash, pk_hash, sender_index))
            }

            TrusteeMsg::MixInitialization(msg) => {
                // The MixInitialization message becomes the Ballots Ascent message.

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "MixInitialization message hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                // Sanity check: it is impossible for threshold to be zero here.
                assert!(self.protocol_state().threshold != 0);

                // the number of participating active trustees must equal the threshold
                if msg.data.active_trustees.len() != self.protocol_state().threshold as usize {
                    return Err(format!(
                        "MixInitialization message has {} active trustees, but threshold is {}",
                        msg.data.active_trustees.len(),
                        self.protocol_state().threshold
                    ));
                }

                let pk_hash = self
                    .get_ascent_pk_hash()
                    .expect("pk_hash must exist at this point of the protocol");
                let ciphertexts_hash = hash_serializable(&msg.data.cryptograms);

                // For active trustees in mixing, we need to renumber them starting from 1
                // because Ascent expects mixing trustee indices to be 1-based
                let mixing_trustees: Vec<usize> = (1..=msg.data.active_trustees.len()).collect();

                Ok(AscentMsg::Ballots(
                    self.cfg_hash,
                    *pk_hash,
                    ciphertexts_hash,
                    mixing_trustees,
                ))
            }

            TrusteeMsg::EGCryptograms(msg) => {
                // EGCryptograms message become either Mix Ascent messages (if the
                // originator and signer are the same) or MixSignature Ascent messages
                // (if they differ).

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "Key shares election hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                let pk_hash = self
                    .get_ascent_pk_hash()
                    .expect("pk_hash must exist at this point of the protocol");

                // The active trustee index of the message signer.
                let sender_index = self.get_active_trustee_index(&msg.data.signer)?;

                // The active trustee index of the message originator.
                let originator_index = self.get_active_trustee_index(&msg.data.originator)?;

                // The input and output ciphertext hashes are based on the originator's round.
                let in_ciphertexts_hash = self.get_mix_round_output_hash(originator_index - 1)?;
                let out_ciphertexts_hash = hash_serializable(&msg.data.ciphertexts);

                // If the message was sent and signed by the same trustee, it's a Mix
                // message; otherwise, it's a MixSignature message.
                if msg.originator_id() == msg.signer_id() {
                    Ok(AscentMsg::Mix(
                        self.cfg_hash,
                        *pk_hash,
                        in_ciphertexts_hash,
                        out_ciphertexts_hash,
                        sender_index,
                    ))
                } else {
                    Ok(AscentMsg::MixSignature(
                        self.cfg_hash,
                        *pk_hash,
                        in_ciphertexts_hash,
                        out_ciphertexts_hash,
                        sender_index,
                    ))
                }
            }

            TrusteeMsg::PartialDecryptions(msg) => {
                // PartialDecryptions messages become PartialDecryptions Ascent
                // messages.

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "Key shares election hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                let pk_hash = self
                    .get_ascent_pk_hash()
                    .expect("pk_hash must exist at this point of the protocol");

                // The input ciphertexts hash is the output ciphertexts hash
                // of the last mix round.
                let ciphertexts_hash =
                    self.get_mix_round_output_hash(self.protocol_state().active_trustees.len())?;
                let pd_hash = hash_serializable(&msg.data.partial_decryptions);
                // The sender index here is the active trustee index of the
                // message signer.
                let sender_index = self.get_active_trustee_index(&msg.data.signer)?;

                Ok(AscentMsg::PartialDecryptions(
                    self.cfg_hash,
                    *pk_hash,
                    ciphertexts_hash,
                    pd_hash,
                    sender_index,
                ))
            }

            TrusteeMsg::DecryptedBallots(msg) => {
                // DecryptedBallots messages become Plaintexts Ascent messages.

                // Sanity check: the message election hash matches the one we have
                // stored.
                if msg.data.election_hash != self.protocol_state().election_hash {
                    return Err(format!(
                        "Key shares election hash {:?} doesn't match stored election hash {:?}",
                        msg.data.election_hash,
                        self.protocol_state().election_hash
                    ));
                }

                let pk_hash = self
                    .get_ascent_pk_hash()
                    .expect("pk_hash must exist at this point of the protocol");

                // The input ciphertexts hash is the output ciphertexts hash
                // of the last mix round.
                let ciphertexts_hash =
                    self.get_mix_round_output_hash(self.protocol_state().active_trustees.len())?;
                let plaintexts_hash = hash_serializable(&msg.data.ballots);
                // The sender index here is the active trustee index of the
                // message signer.
                let sender_index = self.get_active_trustee_index(&msg.data.signer)?;

                Ok(AscentMsg::Plaintexts(
                    self.cfg_hash,
                    *pk_hash,
                    ciphertexts_hash,
                    plaintexts_hash,
                    sender_index,
                ))
            }
            // Meta-messages about bulletin board state are not converted to Ascent
            // messages, and this function should never be called with them.
            TrusteeMsg::TrusteeBBUpdateRequest(_) | TrusteeMsg::TrusteeBBUpdate(_) => Err(
                "Bulletin board meta-messages cannot be converted to Ascent messages".to_string(),
            ),
        }
    }

    /// Helper function to get a configuration hash from a setup message.
    pub(crate) fn setup_msg_to_cfg_hash(msg: &SetupMsg) -> CryptoHash {
        let tuple = (
            &msg.data.originator,
            &msg.data.manifest,
            msg.data.threshold,
            &msg.data.trustees,
        );
        hash_serializable(&tuple)
    }

    /// Helper function to get a trustee's index from protocol state (for KeyGen phase).
    fn get_trustee_index(&self, trustee_id: &TrusteeID) -> Result<usize, String> {
        let protocol_state = self
            .protocol_state_data
            .as_ref()
            .ok_or_else(|| "Protocol state not initialized".to_string())?;

        protocol_state
            .trustees
            .iter()
            .position(|t| t.trustee_id() == *trustee_id)
            .ok_or_else(|| format!("Trustee {:?} not found in trustees list", trustee_id))
    }

    /// Helper function to get a trustee's index in the active trustees list (1-based, for Mix/Decrypt phases).
    fn get_active_trustee_index(&self, trustee_id: &TrusteeID) -> Result<usize, String> {
        let protocol_state = self
            .protocol_state_data
            .as_ref()
            .ok_or_else(|| "Protocol state not initialized".to_string())?;

        protocol_state
            .active_trustees
            .iter()
            .position(|t| t.trustee_id() == *trustee_id)
            .map(|pos| pos + 1) // Convert to 1-based for Ascent
            .ok_or_else(|| format!("Trustee {:?} not found in active trustees list", trustee_id))
    }

    /// Helper function to get the election public key, if it exists. It is
    /// extracted from the trustee board. Note that any election public key
    /// message on the board can be used, as the Ascent logic will error out
    /// if they don't all match.
    fn get_election_public_key(&self) -> Result<&ElectionKey, String> {
        match self
            .processed_board
            .iter()
            .find(|ptm| matches!(ptm.trustee_msg, TrusteeMsg::ElectionPublicKey(_)))
        {
            Some(ProcessedTrusteeMsg {
                trustee_msg: TrusteeMsg::ElectionPublicKey(pk_msg),
                ascent_msg: _,
            }) => Ok(&pk_msg.data.election_public_key),
            _ => Err("Election public key not found.".to_string()),
        }
    }

    /// Helper function to get the Ascent pk_hash. This is a hash of both
    /// the public check values and the election public key. We can take it
    /// from any Ascent public key message, because the Ascent logic will
    /// have crashed out if those don't all match.
    fn get_ascent_pk_hash(&self) -> Result<&CryptoHash, String> {
        match self
            .processed_board
            .iter()
            .find(|ptm| matches!(ptm.ascent_msg, AscentMsg::PublicKey(..)))
        {
            Some(ProcessedTrusteeMsg {
                trustee_msg: _,
                ascent_msg:
                    AscentMsg::PublicKey {
                        0: _,
                        1: pk_hash,
                        2: _,
                    },
            }) => Ok(pk_hash),
            _ => Err("Ascent pk_hash not found".to_string()),
        }
    }

    /// Helper function to get the output ciphertexts hash for a given mixing
    /// round. This finds the Ascent Mix message for the specified round
    /// and extracts the output ciphertexts hash from that message. Since the
    /// Ascent logic already checked that all the output ciphertexts from
    /// that round matched, we need not redundantly check that fact.
    ///
    /// It is OK to ask for the output hash of round 0; it is the hash of the
    /// ballots in the Ascent Ballots message (or an error if no such message
    /// exists on the board).
    fn get_mix_round_output_hash(&self, idx: usize) -> Result<CryptoHash, String> {
        match idx {
            i if 1 <= i && i <= self.protocol_state().active_trustees.len() => {
                // Find a mix message originated by the trustee at round idx.
                // Trustee indices in AscentMsg are 1-based, and idx is also 1-based (round number),
                // so we look for trustee_idx == idx.
                match self
                    .processed_board
                    .iter()
                    .find(|ptm| matches!(&ptm.ascent_msg, AscentMsg::Mix(_, _, _, _, trustee_idx) if *trustee_idx == idx))
                {
                    Some(ProcessedTrusteeMsg {
                        trustee_msg: _,
                        ascent_msg: AscentMsg::Mix(_, _, _, out_hash, _),
                    }) => Ok(*out_hash),
                    _ => Err(format!("Round {} output ciphertexts not found", idx)),
                }
            }
            0 => {
                // 0 is a special case; find the Ballots message from the board and
                // use its ciphertexts hash.
                match self
                    .processed_board
                    .iter()
                    .find(|ptm| matches!(&ptm.ascent_msg, AscentMsg::Ballots(..)))
                {
                    Some(ProcessedTrusteeMsg {
                        trustee_msg: _,
                        ascent_msg: AscentMsg::Ballots(_, _, out_hash, _),
                    }) => Ok(*out_hash),
                    _ => Err("Initial ciphertexts hash not found".to_string()),
                }
            }

            _ => Err(format!("Round {} output ciphertexts not found", idx)),
        }
    }

    /// Return the active trustee index of this trustee (1-based), or an error if
    /// it isn't active. The TAS is at position 0, so actual trustees start at position 1.
    fn my_active_trustee_index(&self) -> Result<usize, String> {
        let protocol_state = self.protocol_state();

        // If active_trustees is empty, we're in DKG phase where ALL trustees are active.
        // The trustees list already includes TAS at index 0, so the index we get IS the
        // 1-based position (e.g., Trustee 1 is at index 1, Trustee 2 at index 2, etc.)
        if protocol_state.active_trustees.is_empty() {
            match protocol_state
                .trustees
                .iter()
                .position(|tid| tid == &self.trustee_info)
            {
                Some(idx) => Ok(idx), // This is already 1-based (TAS is at 0)
                None => Err("This trustee is not in the trustees list.".to_string()),
            }
        } else {
            // We're in mixing/decryption phase - use the active_trustees list.
            // This list doesn't include the TAS, so we need to add 1 to convert to 1-based.
            match protocol_state
                .active_trustees
                .iter()
                .position(|tid| tid == &self.trustee_info)
            {
                Some(idx) => Ok(idx + 1), // Convert to 1-based (0 is reserved for TAS)
                None => Err("This trustee is not in the active trustees list.".to_string()),
            }
        }
    }

    /// Execute the Ascent logic on the current trustee board.
    pub(crate) fn execute_ascent_logic(&mut self) -> Result<Option<TrusteeMsg>, String> {
        let ascent_msgs: &Vec<AscentMsg> = &self
            .processed_board
            .iter()
            .map(|ptm| ptm.ascent_msg.clone())
            .collect();

        // Run the Ascent logic to compute possible actions
        let actions = composed_ascent_logic::run(ascent_msgs)?;

        // Execute the actions one by one, reporting the first error we
        // encounter (if any), and saving any messages that need to be sent
        // out to the trustees. There should never be a case where we need
        // to send more than one message to the trustees (after we send a
        // message, it is impossible for us to proceed without receiving that
        // message back), so if there is we report it as an error.
        let mut message_to_send: Option<TrusteeMsg> = None;
        for a in actions {
            match self.execute_action(a) {
                Err(err_msg) => {
                    return Err(err_msg.clone());
                }
                Ok(None) => {
                    // Action succeeded but produced no message
                    continue;
                }
                Ok(option_msg @ Some(_)) => {
                    // Action produced a message
                    if message_to_send.is_some() {
                        // We already have a message - this shouldn't happen
                        return Err("Multiple messages produced by action execution".to_string());
                    }
                    message_to_send = option_msg;
                }
            }
        }
        Ok(message_to_send)
    }

    /// Execute a single action.
    fn execute_action(&mut self, action: Action) -> Result<Option<TrusteeMsg>, String> {
        // Check if we've already completed this action. If so, skip it to avoid
        // duplicate execution before our message appears on the board.
        if self.completed_actions.contains(&action) {
            return Ok(None);
        }

        // Clone the action so we can save it later if it succeeds.
        let action_clone = action.clone();

        // Get our active trustee index. If we're not active (e.g., not in the
        // active_trustees list during mixing), we simply return without
        // taking any actions.
        let my_idx = match self.my_active_trustee_index() {
            Ok(idx) => idx,
            Err(_) => return Ok(None), // Not active, so no actions for us
        };

        let result = match action {
            Action::ComputeShares(_cfg_hash, idx) if idx == my_idx => self.action_compute_shares(),

            Action::ComputePublicKey(_cfg_hash, _shares_hashes, idx) if idx == my_idx => {
                self.action_compute_public_key(idx)
            }

            Action::ComputeMix(_, _, ciphertexts_hash, idx) if idx == my_idx => {
                self.action_compute_mix(ciphertexts_hash)
            }

            Action::SignMix(_, _, in_ciphertexts_hash, out_ciphertexts_hash, idx)
                if idx == my_idx =>
            {
                self.action_sign_mix(in_ciphertexts_hash, out_ciphertexts_hash)
            }

            Action::ComputePartialDecryptions(_, _, out_ciphertexts_hash, idx) if idx == my_idx => {
                self.action_compute_partial_decryptions(out_ciphertexts_hash)
            }

            Action::ComputePlaintexts(_, _, _, partial_decryptions_hashes, idx)
                if idx == my_idx =>
            {
                self.action_compute_plaintexts(partial_decryptions_hashes)
            }

            Action::ComputeBallots(..) => {
                // ComputeBallots is only for testing, and should never show up here.
                Err(
                    "ComputeBallots is for testing and should not be generated in an actual system run"
                        .to_string(),
                )
            }
            _ => {
                // Action is for a different trustee, so we ignore it.
                Ok(None)
            }
        };

        // If the action succeeded and produced a message, record it as completed
        // to prevent duplicate execution.
        if let Ok(Some(_)) = &result {
            self.completed_actions.insert(action_clone);
        }

        result
    }

    /// Execute the `ComputeShares` action.
    fn action_compute_shares(&self) -> Result<Option<TrusteeMsg>, String> {
        let threshold = self.protocol_state().threshold as usize;
        // The trustee count for share computation ignores the TAS.
        let trustee_count = self.protocol_state().trustees.len() - 1;

        dispatch_threshold_trustees!(threshold, trustee_count, T, P, {
            // Generate the dealer and get our verifiable shares.
            let dealer: Dealer<CryptoContext, T, P> = Dealer::generate();
            let dealer_shares = dealer.get_verifiable_shares();
            let check_values: Vec<CheckValue> = dealer_shares.checking_values.to_vec();

            let unencrypted_pairwise_shares: Vec<Share> = dealer_shares.shares.to_vec();

            // Encrypt the shares, each to its corresponding trustee.
            // The TAS is at index 0, so we encrypt share i to trustee at index i+1.
            let mut encrypted_pairwise_shares: Vec<ShareCiphertext> = Vec::new();
            for (i, s) in unencrypted_pairwise_shares.iter().enumerate() {
                let trustee_index = i + 1; // Skip TAS at index 0.
                let key = if self.protocol_state().trustees.len() > trustee_index {
                    &self.protocol_state().trustees[trustee_index].public_enc_key
                } else {
                    return Err(format!(
                        "Trustees list does not contain a trustee with index {}",
                        trustee_index
                    ));
                };
                let encrypted_share = encrypt_share(s, key)?;
                encrypted_pairwise_shares.push(encrypted_share.clone());
            }

            // Create the data for the KeyShares message.
            let data = KeySharesMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                check_values: check_values.clone(),
                pairwise_shares: encrypted_pairwise_shares,
            };

            // Sign the message data.
            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg = KeySharesMsg { data, signature };

            Ok(Some(TrusteeMsg::KeyShares(msg)))
        })
    }

    /// Execute the `ComputePublicKey` action.
    fn action_compute_public_key(&self, idx: usize) -> Result<Option<TrusteeMsg>, String> {
        // Compute election public key from shares
        let threshold = self.protocol_state().threshold as usize;
        // The trustee count for public key generation ignores the TAS.
        let trustee_count = self.protocol_state().trustees.len() - 1;

        dispatch_threshold_trustees!(threshold, trustee_count, T, P, {
            // Get my position in the key generation protocol.
            let my_position: ParticipantPosition<P> = ParticipantPosition::new(idx as u32);

            // Collect all KeyShares messages from the board.
            let key_shares_msgs: Vec<&KeySharesMsg> = self
                .processed_board
                .iter()
                .filter_map(|ptm| match &ptm.trustee_msg {
                    TrusteeMsg::KeyShares(msg) => Some(msg),
                    _ => None,
                })
                .collect();

            // We need exactly P shares (one from each trustee, including ourselves).
            if key_shares_msgs.len() != P {
                return Err(format!(
                    "Expected {} key share messages but found {}",
                    P,
                    key_shares_msgs.len()
                ));
            }

            // Reconstruct VerifiableShares from the KeyShares messages.
            let mut verifiable_shares: Vec<VerifiableShare<CryptoContext, T>> = Vec::new();

            // We'll collect the check values into a BTreeMap for sending later.
            let mut check_values_to_send: BTreeMap<TrusteeID, Vec<CheckValue>> = BTreeMap::new();

            for shares_msg in key_shares_msgs.iter() {
                // Get this dealer's checking values, and insert them
                check_values_to_send.insert(
                    shares_msg.data.originator.clone(),
                    shares_msg.data.check_values.clone(),
                );

                let checking_values: [_; T] = shares_msg
                    .data
                    .check_values
                    .to_vec()
                    .try_into()
                    .map_err(|_| format!("Expected {} checking values", T))?;

                // Decrypt my share from this dealer.
                if shares_msg.data.pairwise_shares.len() != P {
                    return Err(format!(
                        "Expected {} pairwise shares but found {}",
                        P,
                        shares_msg.data.pairwise_shares.len()
                    ));
                }

                let decrypted_share = decrypt_share(
                    &shares_msg.data.pairwise_shares[idx - 1],
                    &self.encryption_key_pair,
                )?;
                verifiable_shares.push(VerifiableShare::new(decrypted_share, checking_values));
            }

            let verifiable_shares_array: [VerifiableShare<CryptoContext, T>; P] = verifiable_shares
                .try_into()
                .map_err(|_| "Failed to convert shares to array")?;

            // Compute the recipient (includes both secret key and public key).
            let recipient = Recipient::from_shares(my_position, &verifiable_shares_array)
                .map_err(|e| format!("Failed to compute recipient from shares: {:?}", e))?;

            // Extract the (El Gamal) election public key (the second element
            // of the tuple).
            let eg_pk = recipient.1.inner;

            // Augment the election public key to a Naor-Yung public key, using the
            // hash of the election configuration from a key shares message as
            // the context.
            let context = key_shares_msgs[0].data.election_hash;
            let ny_pk = ElectionKey::augment(&eg_pk, &context).unwrap();

            // Create the data for the ElectionPublicKey message.
            let data = ElectionPublicKeyMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                check_values: check_values_to_send,
                election_public_key: ny_pk,
            };

            // Sign the message data.
            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg = ElectionPublicKeyMsg { data, signature };

            Ok(Some(TrusteeMsg::ElectionPublicKey(msg)))
        })
    }

    /// Execute the `ComputeMix` action.
    fn action_compute_mix(
        &self,
        ciphertexts_hash: CryptoHash,
    ) -> Result<Option<TrusteeMsg>, String> {
        let election_pk = self.get_election_public_key()?;
        let idx = self.get_active_trustee_index(&self.trustee_info.trustee_id())?;

        // Check to determine whether we're computing the first mix, or a
        // subsequent mix.
        if idx > 1 {
            // Not the first mix, so let's get the previous ciphertexts from
            // a previous mix message; they need to match the ciphertexts hash.
            let previous_mix_msg = self
                .processed_board
                .iter()
                .rev()
                .find_map(|ptm| match &ptm {
                    &ProcessedTrusteeMsg {
                        trustee_msg: TrusteeMsg::EGCryptograms(msg),
                        ascent_msg: AscentMsg::Mix(_, _, _, out_ct_hash, _),
                    } if msg.data.signer == msg.data.originator
                        && out_ct_hash == &ciphertexts_hash =>
                    {
                        Some(msg)
                    }
                    _ => None,
                })
                .ok_or("No mixed ciphertexts found that match provided ciphertext hash")?;

            let encryption_context = encryption_context(&previous_mix_msg.data.election_hash);

            // Mix the ciphertexts separately by ballot style.
            let mut mixed_ciphertexts: BTreeMap<BallotStyle, Vec<StrippedBallotCiphertext>> =
                BTreeMap::new();
            let mut proofs: BTreeMap<BallotStyle, MixRoundProof> = BTreeMap::new();

            for (ballot_style_id, ciphertexts) in &previous_mix_msg.data.ciphertexts {
                // Shuffle the ciphertexts for this ballot style
                #[crate::warning("Challenge inputs are incomplete.")]
                let (mixed, proof) =
                    shuffle_ciphertexts(ciphertexts, election_pk, &encryption_context)?;
                mixed_ciphertexts.insert(*ballot_style_id, mixed);
                proofs.insert(*ballot_style_id, proof);
            }

            // Create and sign the new mix message to send to the other trustees.
            let data = EGCryptogramsMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                ciphertexts: mixed_ciphertexts,
                proofs,
            };

            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg = EGCryptogramsMsg { data, signature };
            Ok(Some(TrusteeMsg::EGCryptograms(msg)))
        } else {
            // This is the first mix; get the ballot cryptograms from the mix
            // initialization message, strip the ciphertexts, and group them
            // (importantly, in the same sequence order) by ballot style.
            let mix_init_msg = self
                .processed_board
                .iter()
                .find_map(|ptm| match &ptm {
                    ProcessedTrusteeMsg {
                        trustee_msg: TrusteeMsg::MixInitialization(msg),
                        ascent_msg: AscentMsg::Ballots(_, _, ct_hash, _),
                    } if ct_hash == &ciphertexts_hash => Some(msg),
                    _ => None,
                })
                .ok_or("No mix initialization message found")?;

            // Group ballots by ballot style.
            let mut ballots_by_style: BTreeMap<BallotStyle, Vec<_>> = BTreeMap::new();
            for ballot_cryptogram in &mix_init_msg.data.cryptograms {
                ballots_by_style
                    .entry(ballot_cryptogram.ballot_style)
                    .or_default()
                    .push(ballot_cryptogram);
            }

            // For each ballot style, strip NY encryption and shuffle.
            let mut mixed_ciphertexts: BTreeMap<BallotStyle, Vec<StrippedBallotCiphertext>> =
                BTreeMap::new();
            let mut proofs: BTreeMap<BallotStyle, MixRoundProof> = BTreeMap::new();

            // Get the encryption context that was used to encrypt the ballots.
            // This must match what encrypt_ballot() uses in crypto.rs.
            let encryption_context = encryption_context(&mix_init_msg.data.election_hash);

            for (ballot_style, cryptograms) in ballots_by_style {
                // Strip NY encryption from each ballot to get EG ciphertext.
                let mut stripped_ciphertexts: Vec<StrippedBallotCiphertext> = Vec::new();
                for cryptogram in cryptograms {
                    let stripped = election_pk
                        .strip(cryptogram.ciphertext.clone(), &encryption_context)
                        .map_err(|e| format!("Failed to strip NY encryption: {:?}", e))?;
                    stripped_ciphertexts.push(stripped);
                }

                // Shuffle the ciphertexts for this ballot style.
                #[crate::warning("Challenge inputs are incomplete.")]
                let (mixed, proof) =
                    shuffle_ciphertexts(&stripped_ciphertexts, election_pk, &encryption_context)?;

                // Store the results.
                mixed_ciphertexts.insert(ballot_style, mixed);
                proofs.insert(ballot_style, proof);
            }

            // Create and sign the new mix message to send to the other trustees.
            let data = EGCryptogramsMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                ciphertexts: mixed_ciphertexts,
                proofs,
            };

            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg = EGCryptogramsMsg { data, signature };
            Ok(Some(TrusteeMsg::EGCryptograms(msg)))
        }
    }

    /// Execute the `SignMix` action.
    fn action_sign_mix(
        &self,
        in_ciphertexts_hash: CryptoHash,
        out_ciphertexts_hash: CryptoHash,
    ) -> Result<Option<TrusteeMsg>, String> {
        let election_pk = self.get_election_public_key()?;

        // Get the mix to verify (must match the provided hashes).
        let mix_to_verify = self
            .processed_board
            .iter()
            .rev()
            .find_map(|ptm| match &ptm {
                ProcessedTrusteeMsg {
                    trustee_msg: TrusteeMsg::EGCryptograms(msg),
                    ascent_msg: AscentMsg::Mix(_, _, in_ct_hash, out_ct_hash, _),
                } if in_ct_hash == &in_ciphertexts_hash && out_ct_hash == &out_ciphertexts_hash => {
                    Some(msg)
                }
                _ => None,
            })
            .ok_or("No matching mix message found to verify")?;

        // Get the trustee index of the mix to verify.
        let idx = self.get_active_trustee_index(&mix_to_verify.data.originator)?;

        if idx == 1 {
            // We're verifying the first mix, so we need to process the mix
            // initialization message the same way trustee 1 did in order
            // to get the input ciphertext lists.
            let mix_init_msg = self
                .processed_board
                .iter()
                .find_map(|ptm| match &ptm.trustee_msg {
                    TrusteeMsg::MixInitialization(msg) => Some(msg),
                    _ => None,
                })
                .ok_or("No mix initialization message found")?;

            // Get the encryption context that was used to encrypt the ballots.
            // This must match what encrypt_ballot() uses in crypto.rs.
            let encryption_context = encryption_context(&mix_init_msg.data.election_hash);

            // Group ballots by ballot style and strip NY encryption.
            let mut input_by_style: BTreeMap<BallotStyle, Vec<StrippedBallotCiphertext>> =
                BTreeMap::new();
            for ballot_cryptogram in &mix_init_msg.data.cryptograms {
                let stripped = election_pk
                    .strip(ballot_cryptogram.ciphertext.clone(), &encryption_context)
                    .map_err(|e| format!("Failed to strip NY encryption: {:?}", e))?;
                input_by_style
                    .entry(ballot_cryptogram.ballot_style)
                    .or_default()
                    .push(stripped);
            }

            // Verify the shuffle for each ballot style.
            for (ballot_style, input_ciphertexts) in &input_by_style {
                let output_ciphertexts = mix_to_verify
                    .data
                    .ciphertexts
                    .get(ballot_style)
                    .ok_or_else(|| format!("Mix output missing ballot style {}", ballot_style))?;

                let proof = mix_to_verify.data.proofs.get(ballot_style).ok_or_else(|| {
                    format!("Mix proof missing for ballot style {}", ballot_style)
                })?;

                #[crate::warning("Challenge inputs are incomplete.")]
                verify_shuffle(
                    input_ciphertexts,
                    output_ciphertexts,
                    proof,
                    election_pk,
                    &encryption_context,
                )?;
            }
        } else {
            // We're verifying a subsequent mix, so we need to get the ciphertexts
            // from the actual mix message.
            let previous_mix = self
                .processed_board
                .iter()
                .rev()
                .skip(1) // Skip the mix we're verifying
                .find_map(|ptm| match &ptm.trustee_msg {
                    TrusteeMsg::EGCryptograms(msg) => Some(msg),
                    _ => None,
                })
                .ok_or("No previous mix message found")?;

            let encryption_context = encryption_context(&previous_mix.data.election_hash);

            // Verify the shuffle for each ballot style.
            for (ballot_style, output_ciphertexts) in &mix_to_verify.data.ciphertexts {
                let input_ciphertexts = previous_mix
                    .data
                    .ciphertexts
                    .get(ballot_style)
                    .ok_or_else(|| format!("Previous mix missing ballot style {}", ballot_style))?;

                let proof = mix_to_verify.data.proofs.get(ballot_style).ok_or_else(|| {
                    format!("Mix proof missing for ballot style {}", ballot_style)
                })?;

                #[crate::warning("Challenge inputs are incomplete.")]
                verify_shuffle(
                    input_ciphertexts,
                    output_ciphertexts,
                    proof,
                    election_pk,
                    &encryption_context,
                )?;
            }
        }

        // All verifications passed - create and sign an EGCryptogramsMsg with the
        // same data but with our signature.
        let data = EGCryptogramsMsgData {
            originator: mix_to_verify.data.originator.clone(),
            signer: self.trustee_info.trustee_id(),
            election_hash: mix_to_verify.data.election_hash,
            ciphertexts: mix_to_verify.data.ciphertexts.clone(),
            proofs: mix_to_verify.data.proofs.clone(),
        };

        let signature = sign_data(&data.ser(), &self.signing_key);
        let msg = EGCryptogramsMsg { data, signature };

        Ok(Some(TrusteeMsg::EGCryptograms(msg)))
    }

    /// Execute the `ComputePartialDecryptions` action.
    fn action_compute_partial_decryptions(
        &self,
        ciphertexts_hash: CryptoHash,
    ) -> Result<Option<TrusteeMsg>, String> {
        let idx = self.get_active_trustee_index(&self.trustee_info.trustee_id())?;

        // Get the final mixed ciphertexts (the last EGCryptograms message);
        // we pick the one sent by us, because we know we signed it
        let (final_mix_ascent_msg, final_mix_msg) = self
            .processed_board
            .iter()
            .rev()
            .find_map(|ptm| match &ptm.trustee_msg {
                TrusteeMsg::EGCryptograms(msg)
                    if msg.data.signer == self.trustee_info.trustee_id() =>
                {
                    Some((ptm.ascent_msg.clone(), msg))
                }
                _ => None,
            })
            .ok_or("No mixed ciphertexts found")?;

        // Check the hash of the final mixed ciphertexts against the
        // passed-in ciphertexts hash, from the Ascent logic.
        if !matches!(final_mix_ascent_msg,
            AscentMsg::Mix(_, _, _, out_ct_hash, _) |
            AscentMsg::MixSignature(_, _, _, out_ct_hash, _ ) if out_ct_hash == ciphertexts_hash)
        {
            return Err("mix output ciphertexts do not match expected hash".to_string());
        }

        // Get all the key shares to reconstruct the necessary keys.
        let key_shares_msgs: Vec<&KeySharesMsg> = self
            .processed_board
            .iter()
            .filter_map(|ptm| match &ptm.trustee_msg {
                TrusteeMsg::KeyShares(msg) => Some(msg),
                _ => None,
            })
            .collect();

        let threshold = self.protocol_state().threshold as usize;
        // Trustee count for partial decryption ignores the TAS.
        let trustee_count = self.protocol_state().trustees.len() - 1;

        dispatch_threshold_trustees!(threshold, trustee_count, T, P, {
            // Wrap my position in the correct data structure for the DKG protocol.
            let pos: ParticipantPosition<P> = ParticipantPosition::new(idx as u32);

            // We need exactly P shares (one from each trustee, including ourselves).
            if key_shares_msgs.len() != P {
                return Err(format!(
                    "Expected {} key share messages but found {}",
                    P,
                    key_shares_msgs.len()
                ));
            }

            // Reconstruct VerifiableShares from the KeyShares messages.
            let mut verifiable_shares: Vec<VerifiableShare<CryptoContext, T>> = Vec::new();

            for shares_msg in key_shares_msgs.iter() {
                // Get this trustee's checking values.
                let checking_values: [_; T] = shares_msg
                    .data
                    .check_values
                    .to_vec()
                    .try_into()
                    .map_err(|_| format!("Expected {} checking values", T))?;

                // Decrypt my key share from this trustee.
                if shares_msg.data.pairwise_shares.len() != P {
                    return Err(format!(
                        "Expected {} pairwise shares but found {}",
                        P,
                        shares_msg.data.pairwise_shares.len()
                    ));
                }

                let decrypted_share = decrypt_share(
                    &shares_msg.data.pairwise_shares[idx - 1],
                    &self.encryption_key_pair,
                )?;

                verifiable_shares.push(VerifiableShare::new(decrypted_share, checking_values));
            }

            let verifiable_shares_array: [VerifiableShare<CryptoContext, T>; P] = verifiable_shares
                .try_into()
                .map_err(|_| "Failed to convert shares to array")?;

            // Compute the recipient (includes both secret key and public key).
            let (recipient, _joint_pk) = Recipient::from_shares(pos, &verifiable_shares_array)
                .map_err(|e| format!("Failed to compute recipient from shares: {:?}", e))?;

            // Compute partial decryptions by ballot style.
            let mut partial_decryptions_by_style: BTreeMap<BallotStyle, Vec<PartialDecryption>> =
                BTreeMap::new();

            // Get proof context once to avoid lifetime issues.
            let proof_context = key_shares_msgs[0].data.election_hash;

            for (ballot_style, ciphertexts) in &final_mix_msg.data.ciphertexts {
                // Compute decryption factors (partial decryptions) for this
                // ballot style.
                let decryption_factors =
                    compute_partial_decryptions::<T, P>(ciphertexts, &recipient, &proof_context)?;

                // Convert decryption factors to our PartialDecryption type
                // for inclusion in the trustee msesage.
                let mut partial_decs = Vec::new();
                for dfactor in decryption_factors {
                    partial_decs.push(PartialDecryption {
                        value: dfactor.value,
                        proof: dfactor.proof,
                        source: idx as u32,
                    });
                }

                partial_decryptions_by_style.insert(*ballot_style, partial_decs);
            }

            // Create and sign the partial decryptions message.
            let data = PartialDecryptionsMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                partial_decryptions: partial_decryptions_by_style.into_iter().collect(),
            };

            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg = PartialDecryptionsMsg { data, signature };

            Ok(Some(TrusteeMsg::PartialDecryptions(msg)))
        })
    }

    /// Execute the `ComputePlaintexts` action.
    fn action_compute_plaintexts(
        &self,
        partial_decryptions_hashes: Vec<CryptoHash>,
    ) -> Result<Option<TrusteeMsg>, String> {
        // Get the final mixed ciphertexts (the last EGCryptograms message);
        // we pick the one sent by us, because we know we signed it
        let final_mix_msg = self
            .processed_board
            .iter()
            .rev()
            .find_map(|ptm| match &ptm.trustee_msg {
                TrusteeMsg::EGCryptograms(msg)
                    if msg.data.signer == self.trustee_info.trustee_id() =>
                {
                    Some(msg)
                }
                _ => None,
            })
            .ok_or("No mixed ciphertexts found")?;

        // Get all partial decryption messages.
        let partial_decryption_msgs: Vec<(&PartialDecryptionsMsg, &CryptoHash)> = self
            .processed_board
            .iter()
            .filter_map(|ptm| match (&ptm.trustee_msg, &ptm.ascent_msg) {
                (
                    TrusteeMsg::PartialDecryptions(msg),
                    AscentMsg::PartialDecryptions(_, _, _, pd_hash, _),
                ) => Some((msg, pd_hash)),
                _ => None,
            })
            .collect();

        // Check that each of their computed hashes for Ascent logic matches
        // one of the hashes we were passed.
        if !partial_decryption_msgs
            .iter()
            .all(|(_, h)| partial_decryptions_hashes.contains(h))
        {
            return Err("partial decryption hashes do not match expected hashes".to_string());
        }

        // Get the key shares messages to extract verification keys.
        let key_shares_msgs: Vec<&KeySharesMsg> = self
            .processed_board
            .iter()
            .filter_map(|ptm| match &ptm.trustee_msg {
                TrusteeMsg::KeyShares(msg) => Some(msg),
                _ => None,
            })
            .collect();

        let threshold = self.protocol_state().threshold as usize;
        // Trustee count for plaintext computation ignores the TAS.
        let trustee_count = self.protocol_state().trustees.len() - 1;

        dispatch_threshold_trustees!(threshold, trustee_count, T, P, {
            // We need at least T partial decryption messages.
            if partial_decryption_msgs.len() < T {
                return Err(format!(
                    "Need at least {} partial decryptions but found {}",
                    T,
                    partial_decryption_msgs.len()
                ));
            }

            // Extract checking values from all P key shares messages,
            // T for each trustee.
            let mut checking_values_vec: Vec<[CheckValue; T]> = Vec::new();
            for ksm in &key_shares_msgs {
                if ksm.data.check_values.len() != T {
                    return Err(format!(
                        "Expected {} check values, got {}",
                        T,
                        ksm.data.check_values.len()
                    ));
                }
                let check_values_array: [CheckValue; T] = ksm
                    .data
                    .check_values
                    .clone()
                    .try_into()
                    .map_err(|_| "Failed to convert check values to array")?;
                checking_values_vec.push(check_values_array);
            }

            if checking_values_vec.len() != P {
                return Err(format!(
                    "Expected {} key shares messages, got {}",
                    P,
                    checking_values_vec.len()
                ));
            }

            let checking_values: [[CheckValue; T]; P] = checking_values_vec
                .try_into()
                .map_err(|_| "Failed to convert checking values to array")?;

            // Get the verification key for each of the T trustees that
            // sent partial decryptions.
            let partial_decryptions_to_use = &partial_decryption_msgs[0..T];
            let trustee_indices: [usize; T] = std::array::from_fn(|i| {
                let pd_msg = partial_decryptions_to_use[i];
                // This unwrap must succeed or else the message would have
                // failed during conversion to an Ascent message.
                self.get_trustee_index(&pd_msg.0.data.originator).unwrap()
            });

            let verification_keys: [_; T] = trustee_indices.map(|trustee_idx| {
                let position: ParticipantPosition<P> = ParticipantPosition::new(trustee_idx as u32);
                Recipient::<CryptoContext, T, P>::verification_key(&position, &checking_values)
            });

            let proof_context = key_shares_msgs[0].data.election_hash;

            let mut decrypted_ballots_by_style: BTreeMap<BallotStyle, Vec<Ballot>> =
                BTreeMap::new();

            // Process each ballot style.
            for (ballot_style, ciphertexts) in &final_mix_msg.data.ciphertexts {
                // Collect partial decryptions from T trustees for this ballot style.
                let partial_decryptions_to_use = &partial_decryption_msgs[0..T];
                let mut dfactors_by_trustee = Vec::new();

                for pd_msg in partial_decryptions_to_use {
                    if let Some(pds) = pd_msg.0.data.partial_decryptions.get(ballot_style) {
                        // Convert this trustee's partial decryptions to DecryptionFactors.
                        let dfactors: Vec<_> = pds
                            .iter()
                            .map(|pd| {
                                let source: ParticipantPosition<P> =
                                    ParticipantPosition::new(pd.source);
                                DecryptionFactor {
                                    value: pd.value,
                                    proof: pd.proof.clone(),
                                    source,
                                }
                            })
                            .collect();
                        dfactors_by_trustee.push(dfactors);
                    } else {
                        return Err(format!(
                            "Missing partial decryptions for ballot style {} from trustee",
                            ballot_style
                        ));
                    }
                }

                // Convert to array [Vec<DecryptionFactor>; T].
                let dfactors_array: [Vec<_>; T] = dfactors_by_trustee
                    .try_into()
                    .map_err(|_| "Failed to convert dfactors to array")?;

                // Combine partial decryptions to get ballot elements.
                let ballot_elements = combine_partial_decryptions::<T, P>(
                    ciphertexts,
                    &dfactors_array,
                    &verification_keys,
                    &proof_context,
                )?;

                // Decode the ballots (assuming we can).
                let maybe_ballots: Vec<(
                    &[SelectionElement; BALLOT_CIPHERTEXT_WIDTH],
                    Result<Ballot, String>,
                )> = ballot_elements
                    .iter()
                    .map(|be: &[SelectionElement; BALLOT_CIPHERTEXT_WIDTH]| (be, decode_ballot(be)))
                    .collect();

                match maybe_ballots.iter().find(|(_, b)| b.is_err()) {
                    Some((be, Err(err))) => {
                        // At least one ballot didn't decrypt, we error out.
                        return Err(format!(
                            "Unable to decrypt elements ({:?}) to a ballot: {:?}",
                            be, err
                        ));
                    }
                    _ => {
                        // All ballots decrypted successfully. Note that this
                        // technically is the Some(_, Ok(_)) arm as well, but the
                        // find call _cannot_ return an Ok.
                        let ballots = maybe_ballots
                            .iter()
                            .map(|(_, b)| b.clone().expect("all ballots must be ok at this point"))
                            .collect();
                        decrypted_ballots_by_style.insert(*ballot_style, ballots);
                    }
                }
            }

            // Create and sign the decrypted ballots message.
            let data = DecryptedBallotsMsgData {
                originator: self.trustee_info.trustee_id(),
                signer: self.trustee_info.trustee_id(),
                election_hash: self.protocol_state().election_hash,
                ballots: decrypted_ballots_by_style,
            };

            let signature = sign_data(&data.ser(), &self.signing_key);
            let msg =
                crate::trustee_protocols::trustee_messages::DecryptedBallotsMsg { data, signature };

            Ok(Some(TrusteeMsg::DecryptedBallots(msg)))
        })
    }

    /// Determine output and next state based on current board state.
    /// This delegates to the current state handler for
    /// state-specific logic.
    fn determine_next_state_and_output(&self) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        self.state.determine_next_state_and_output(self)
    }

    /// Get the current subprotocol.
    pub(crate) fn current_subprotocol(&self) -> TrusteeSubprotocol {
        match self.state {
            TrusteeState::Idle(_) => TrusteeSubprotocol::Idle,
            TrusteeState::ElectionSetup(_) => TrusteeSubprotocol::ElectionSetup,
            TrusteeState::KeyGen(_) => TrusteeSubprotocol::KeyGen,
            TrusteeState::Mixing(_) => TrusteeSubprotocol::Mixing,
            TrusteeState::Decryption(_) => TrusteeSubprotocol::Decryption,
            TrusteeState::Failed(_) => TrusteeSubprotocol::Failed,
        }
    }

    /// Get the protocol state; if it exists, the protocol state is
    /// unwrapped and returned, and if not, a default one with no
    /// actual state information is created. This is a a utility
    /// function for the state handlers; in any state except Idle
    /// and Failed it is guaranteed to return valid protocol state.
    pub(crate) fn protocol_state(&self) -> ProtocolStateData {
        self.protocol_state_data
            .clone()
            .unwrap_or(ProtocolStateData {
                election_hash: string_to_election_hash(""),
                threshold: 0,
                trustees: vec![],
                active_trustees: vec![],
            })
    }

    /// Get the trustee board without the Ascent messages,
    /// which are never communicated outside the actor.
    pub(crate) fn trustee_board(&self) -> Vec<TrusteeMsg> {
        self.processed_board
            .iter()
            .map(|ptm: &ProcessedTrusteeMsg| ptm.trustee_msg.clone())
            .collect()
    }

    /// Get a trustee checkpoint.
    pub(crate) fn checkpoint(&self) -> TrusteeCheckpoint {
        TrusteeCheckpoint {
            board: self.trustee_board(),
            protocol_state: self.protocol_state_data.clone(),
        }
    }

    /// Get failure data reflecting the current state, with
    /// the specified message.
    pub(crate) fn failure_data(&self, msg: String) -> FailureData {
        FailureData {
            subprotocol: self.current_subprotocol(),
            failure_msg: msg,
            board: self.trustee_board(),
            protocol_state: self.protocol_state_data.clone(),
        }
    }
}
