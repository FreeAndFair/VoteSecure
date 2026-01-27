// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the implementation of the `BallotCheckActor`, which is
//! responsible for handling the Ballot Check subprotocol according to the
//! hierarchical I/O model and the ballot-check-spec.md specification.
//!
//! We note that the interactive checking of the plaintext ballot is not
//! part of the protocol logic implemented by the sub-actor. This means
//! the sub-actor completes once the plaintext ballot is delivered to the
//! protocol driver.
#![allow(unused_imports)]
// Currently ignored for code simplicity until performance data is analyzed.
// @todo Consider boxing structs in large enum variants to improve performance.
#![allow(clippy::large_enum_variant)]

use crate::cryptography::ballot_check_context;
use crate::cryptography::decrypt_ballot;
use crate::cryptography::decrypt_randomizers;
use crate::cryptography::generate_encryption_keypair;
use crate::cryptography::generate_signature_keypair;
use crate::cryptography::{sign_data, verify_signature};

use crate::cryptography::ElectionKey;
use crate::cryptography::ElectionKeyPair;
use crate::cryptography::RandomizersStruct;
use crate::cryptography::{SigningKey, VerifyingKey};

use crate::elections::{Ballot, BallotTracker, CastOrNot, ElectionHash};

use crate::messages::ProtocolMessage;
use crate::messages::{CheckReqMsg, CheckReqMsgData};
use crate::messages::{FwdRandomizerMsg, FwdRandomizerMsgData};
use crate::messages::{RandomizerMsg, RandomizerMsgData};
use crate::messages::{SignedBallotMsg, SignedBallotMsgData};

use crate::bulletins::Bulletin;

use cryptography::utils::serialization::VSerializable;

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `BallotCheckActor` can process.
#[derive(Debug, Clone)]
pub enum BallotCheckInput {
    /**
     * Starts the checking protocol; from a the initial state, this
     * results in a [`CheckReqMsg`] message being sent over the network.
     */
    Start,

    /**
     * A message that is expected to be received from the network.
     *
     * The BCA only receives messages from the Digital Ballot Box (DBB).
     */
    NetworkMessage(ProtocolMessage),

    /**
     * The cast/not cast decision by the voter, and a list of bulletins
     * that voter's pseudonym has posted to the bulletin board in the
     * order in which they were posted.
     */
    CastDecision(CastOrNot, Vec<Bulletin>),
}

/// The set of outputs that the `AuthenticationActor` can produce.
#[derive(Debug, Clone)]
pub enum BallotCheckOutput {
    /**
     * A message that needs to be sent over the network.
     *
     * The BCA only sends messages to the Digital Ballot Box (DBB).
     */
    SendMessage(ProtocolMessage),

    /**
     * Plaintext ballot shown to the user for checking/verification purposes.
     */
    PlaintextBallot(Ballot),

    /**
     * The protocol has succeeded (the voter either indicated they cast
     * and we have verified that they cast in the set of bulletins we
     * received, or indicated they did not cast and we have verified
     * that they did not cast in the set of bulletins we received).
     */
    Success(),

    /**
     * The protocol has failed; the [`String`] argument described the error.
     */
    Failure(String),
}

/// The sub-states for the Ballot Checking protocol.
#[derive(Debug, Copy, Clone, Default)]
enum SubState {
    /**
     * We are sending a [`CheckReqMsg`] to the Digital Ballot Box (DBB)
     * from this state once the protocol starts.
     */
    #[default]
    SendCheckRequest,

    /**
     * We are waiting for the DBB's [`FwdRandomizerMsg`] response containing
     * the encrypted randomizers. With this, we decrypt the encrypted ballot
     * and display its content to the user for subsequent manual checking.
     */
    DecryptAndDisplayBallot,

    /**
     * We are waiting for the voter to indicate whether or not they
     * cast the ballot that they checked, so we can evaluate the list
     * of bulletin board entries for their pseudonym to determine if
     * their decision is correctly reflected there.
     *
     * This step is optional in the sense that no further protocol
     * communication with the DBB happens here; it is just a validation
     * mechanism for bulletin board entries. It could be implemented by
     * the ballot checking application outside of this actor model, or
     * could be implemented as a separate standalone application to
     * check the bulletin board against a cast/uncast ballot tracker.
     */
    CheckBallotCastOrNotStatus,

    /**
     * Protocol execution completed.
     *
     * Note that we cannot restart the protocol because dynamically generated
     * data such as the BCA encryption and signing keys cannot be reused.
     * Instead, the top-level actor must restart the protocol after creating
     * a new instance of [`BallotCheckActor`].
     */
    Completed,
}

/// The actor for the Ballot Checking subprotocol.
// @future By using Rust lifetimes, we could pass on state from the top-level
// actor _by reference_ which saves memory and increases performance. This is,
// however, not so critical here since individual BCA applications are not
// expected to handle a large number of ballot-checking requests.
#[derive(Clone, Debug)]
pub struct BallotCheckActor {
    state: SubState,
    // --- State injected from [`TopLevelActor`] ---
    election_hash: ElectionHash,
    election_public_key: ElectionKey,
    dbb_verifying_key: VerifyingKey,
    // --- Information obtained from the Public Bulletin Board ---
    ballot_tracker: BallotTracker,
    ballot: SignedBallotMsg,
    // --- Session keys freshly created for each protocol run ---
    bca_enc_context: String,
    bca_enc_keypair: ElectionKeyPair,
    bca_signing_key: SigningKey,
    bca_verifying_key: VerifyingKey,
    // --- Populated during protocol execution ---
    sent_check_req_msg: Option<CheckReqMsg>,
}

// Implementation of the [`BallotCheckActor`] behavior.
impl BallotCheckActor {
    /// Creates a new sub-actor for ballot checking.
    pub fn new(
        election_hash: ElectionHash,
        election_public_key: ElectionKey,
        dbb_verifying_key: VerifyingKey,
        ballot_tracker: BallotTracker,
        ballot: SignedBallotMsg,
    ) -> Self {
        // Note that the integrity of the ballot and its tracker is
        // guaranteed by checks carried out by the BCA [`TopLevelActor`].
        // So there is not need to verify the respective message here.
        // Hence, the below check does not need to be carried out here.
        // assert!(check_signed_ballot(&ballot_tracker, &ballot).is_ok());

        // Create fresh BCA signature key pair for each protocol run.
        let (bca_signing_key, bca_verifying_key) = generate_signature_keypair();

        // Use unified context creation for ballot checking
        // Both VA and BCA use the same context for randomizer encryption/decryption
        let context = ballot_check_context(&election_hash, &bca_verifying_key);

        // Create fresh BCA encrpytion key pair for each protocol run.
        // This enables the VA to securely transmit the randomizers.
        let bca_enc_keypair = generate_encryption_keypair(context.as_bytes()).unwrap();

        Self {
            state: SubState::default(), /* SendCheckRequest */
            election_hash,
            election_public_key,
            dbb_verifying_key,
            ballot_tracker,
            ballot,
            bca_enc_context: context,
            bca_enc_keypair,
            bca_signing_key,
            bca_verifying_key,
            sent_check_req_msg: None,
        }
    }

    /// Processes an input for the Ballot Check subprotocol.
    pub fn process_input(&mut self, input: BallotCheckInput) -> BallotCheckOutput {
        match (self.state, input) {
            (SubState::SendCheckRequest, BallotCheckInput::Start) => {
                // Session key pair was already generated by the constructor
                let check_req_msg_data = CheckReqMsgData {
                    election_hash: self.election_hash, // implements Copy
                    tracker: self.ballot_tracker.clone(),
                    public_enc_key: self.bca_enc_keypair.pkey.clone(),
                    public_sign_key: self.bca_verifying_key, // implements Copy
                };

                // Create signed CheckReqMsg message to be sent.
                let check_req_msg_data_ser = check_req_msg_data.ser();

                let check_req_msg_data_sign =
                    sign_data(&check_req_msg_data_ser, &self.bca_signing_key);

                let check_req_msg = CheckReqMsg {
                    data: check_req_msg_data,
                    signature: check_req_msg_data_sign,
                };

                self.sent_check_req_msg = Some(check_req_msg.clone());

                self.state = SubState::DecryptAndDisplayBallot;

                BallotCheckOutput::SendMessage(ProtocolMessage::CheckReq(check_req_msg))
            }

            (
                SubState::DecryptAndDisplayBallot,
                BallotCheckInput::NetworkMessage(ProtocolMessage::FwdRandomizer(msg)),
            ) => {
                // Check integrity of the forward randomizer message.
                if let Err(error) = self.check_fwd_randomizer_msg(&msg) {
                    self.state = SubState::Completed;

                    return BallotCheckOutput::Failure(format!(
                        "Forwarded randomizer message check failed: {error}"
                    ));
                }

                // Retrieve embedded RandomizerMsg message.
                let rnd_msg: &RandomizerMsg = &msg.data.message;

                // Note that the integrity check ensures that the below
                // ought never return with an error value (i.e. panic).
                let decrypted_randomizers: RandomizersStruct = decrypt_randomizers(
                    &rnd_msg.data.encrypted_randomizers,
                    &self.bca_enc_keypair,
                    self.bca_enc_context.as_str(),
                )
                .unwrap();

                // Decrypt ballot with the decrypted randomizers.
                let decrypted_ballot_result: Result<Ballot, String> = decrypt_ballot(
                    &self.ballot.data.ballot_cryptogram,
                    &decrypted_randomizers,
                    &self.election_public_key,
                    &self.election_hash,
                    &self.ballot.data.voter_pseudonym,
                );

                // Check whether ballot decryption was successful.
                if let Err(cause) = decrypted_ballot_result {
                    self.state = SubState::Completed;

                    return BallotCheckOutput::Failure(format!(
                        "failed to decrypt ballot with election public key and randomizers: {cause}"
                    ));
                }

                let decrypted_ballot: Ballot = decrypted_ballot_result.unwrap();

                self.state = SubState::CheckBallotCastOrNotStatus;

                // Return decrypted ballot for user verification.
                BallotCheckOutput::PlaintextBallot(decrypted_ballot)
            }

            (
                SubState::CheckBallotCastOrNotStatus,
                BallotCheckInput::CastDecision(cast_decision, bulletins),
            ) => {
                // Find the cast ballot bulletin, if one exists; there should
                // only be one in a well-formed set of bulletins.

                // We always go to the completed state from here, as there is
                // no reason to check this twice in the same ballot check.
                self.state = SubState::Completed;

                let num_casts = bulletins
                    .iter()
                    .filter(|b| matches!(b, Bulletin::BallotCast(_)))
                    .count();

                match (cast_decision, num_casts) {
                    (CastOrNot::Cast, 1) => {
                        // This could be a valid cast, let's get it and check.
                        let cast_ballot = bulletins
                            .iter()
                            .find(|b| matches!(b, Bulletin::BallotCast(_)));

                        // Compare the cast ballot with the one we checked.
                        match cast_ballot {
                            Some(Bulletin::BallotCast(bc)) => {
                                if bc.data.ballot == self.ballot {
                                    // The cast ballot matches the one we checked.
                                    BallotCheckOutput::Success()
                                } else {
                                    // The cast ballot doesn't match the one we checked.
                                    BallotCheckOutput::Failure(
                                        "Cast ballot does not match checked ballot".to_string(),
                                    )
                                }
                            }

                            _ => {
                                // This can't happen but we need a match case for it
                                BallotCheckOutput::Failure("Impossible type error".to_string())
                            }
                        }
                    }

                    (CastOrNot::Cast, 0) => {
                        // No ballot was cast, but the voter said one was.
                        BallotCheckOutput::Failure(
                            "No cast ballot found on the public bulletin board".to_string(),
                        )
                    }

                    (CastOrNot::NotCast, 0) => {
                        // No ballot was cast, and the voter said no ballot was cast.
                        BallotCheckOutput::Success()
                    }

                    (CastOrNot::NotCast, 1) => {
                        // A ballot was cast, and the voter said no ballot was cast.
                        BallotCheckOutput::Failure(
                            "Cast ballot found on the public bulletin board".to_string(),
                        )
                    }

                    (_, _) => {
                        // More than 1 ballot was cast; this is a failure regardless
                        // of what the voter said.
                        BallotCheckOutput::Failure(
                            "Multiple cast ballots found on the public bulletin board".to_string(),
                        )
                    }
                }
            }

            _ => BallotCheckOutput::Failure(
                "invalid input for current state of the protocol".to_string(),
            ),
        }
    }

    /**************************************************/
    /* Encrypted Randomizer Forwarding Message Checks */
    /**************************************************/

    /**
     * Checks the forwarding message containing the encrypted randomizers.
     */
    fn check_fwd_randomizer_msg(&self, msg: &FwdRandomizerMsg) -> Result<(), String> {
        self.check_election_hash(&msg.data.election_hash)?;
        self.check_randomizer_msg(&msg.data.message)?;
        self.check_fwd_randomizer_msg_signature(msg)?;
        Ok(())
    }

    /**
     * Check #1: The election_hash is the hash of the election configuration
     * item for the current election.
     */
    fn check_election_hash(&self, election_hash: &ElectionHash) -> Result<(), String> {
        if election_hash != &self.election_hash {
            Err("election hash in message is incorrect".to_string())
        } else {
            Ok(())
        }
    }

    /**
     * Check #2: 2. The message is a valid Encrypted Randomizer Forwarding
     * Message.
     */
    fn check_randomizer_msg(&self, msg: &RandomizerMsg) -> Result<(), String> {
        self.check_randomizer_msg_election_hash(msg)?;
        self.check_randomizer_msg_check_request(msg)?;
        self.check_randomizer_msg_enc_randomizers_valid(msg)?;
        self.check_randomizer_msg_public_key(msg)?;
        self.check_randomizer_msg_signature(msg)?;
        Ok(())
    }

    /**
     * Check #3: The signature is a valid signature by the digital ballot box
     * signing key over the contents of this message.
     */
    fn check_fwd_randomizer_msg_signature(&self, msg: &FwdRandomizerMsg) -> Result<(), String> {
        verify_signature(&msg.data.ser(), &msg.signature, &self.dbb_verifying_key)
    }

    /***************************************/
    /* Encrypted Randomizer Message Checks */
    /***************************************/

    /**
     * Check #1: The election_hash is the hash of the election configuration
     * item for the current election.
     */
    fn check_randomizer_msg_election_hash(&self, msg: &RandomizerMsg) -> Result<(), String> {
        if msg.data.election_hash != self.election_hash {
            Err("election hash in randomizer message is incorrect".to_string())
        } else {
            Ok(())
        }
    }

    /**
     * Check #2: The message is a valid Ballot Check Request Message.
     *
     * @note Instead of checking the validity of the [`CheckReqMsg`] message,
     * we merely verify that it is the same message that we initially sent
     * to the DBB. Thus we assume the initial message to be _a priori_ valid.
     */
    fn check_randomizer_msg_check_request(&self, msg: &RandomizerMsg) -> Result<(), String> {
        if self.sent_check_req_msg.as_ref().unwrap() != &msg.data.message {
            Err("randomizer message contains check request that does not match the one that the BCA initially sent".to_string())
        } else {
            Ok(())
        }
    }

    /*
     * Check #3: Each ciphertext in the encrypted_randomizers list is a valid
     * Naor-Yung ciphertext.
     *
     * @note To check validity of the encrypted randomizer cryptograms, we
     * decrypt them here. (Decryption raises an error, e.g., if the zero-
     * knowledge proof embedded in the cryptogram turn out to be invalid.)
     */
    fn check_randomizer_msg_enc_randomizers_valid(
        &self,
        msg: &RandomizerMsg,
    ) -> Result<(), String> {
        if let Err(_cause) = decrypt_randomizers(
            &msg.data.encrypted_randomizers,
            &self.bca_enc_keypair,
            self.bca_enc_context.as_str(),
        ) {
            // @note We could embedded _cause into the error message but
            // after discussion with Dan Zimmerman, this seems unnecessary.
            Err("received randomizers are not valid Naor-Yung encryptions".to_string())
        } else {
            Ok(())
        }
    }

    /* Check #4: The encrypted_randomizers list is equal in length to the
     * number of items in the ballot style of the tracker in the message.
     *
     * Note that this check is obsolete now, with a recent protocol change
     * to use use a single cryptogram for the ballot rather than a list. */

    /**
     * Check #5: The public_key matches the public_key in the Ballot Submission
     * Bulletin corresponding to the tracker in the message.
     */
    fn check_randomizer_msg_public_key(&self, msg: &RandomizerMsg) -> Result<(), String> {
        if msg.data.public_key != self.ballot.data.voter_verifying_key {
            Err("public signing key in the randomizer message does not match the voter's public key according to the ballot submission bulletin (tracker)".to_string())
        } else {
            Ok(())
        }
    }

    /**
     * Check #6: The signature is a valid signature over the contents of the
     * message signed by the public_key.
     */
    fn check_randomizer_msg_signature(&self, msg: &RandomizerMsg) -> Result<(), String> {
        verify_signature(&msg.data.ser(), &msg.signature, &msg.data.public_key)
    }
}
