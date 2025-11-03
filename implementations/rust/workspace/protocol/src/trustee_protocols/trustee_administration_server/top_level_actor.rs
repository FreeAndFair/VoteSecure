// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the implementation of the top-level (and only) actor for
//! the trustee administration server (TAS). There are no sub-actors for the TAS,
//! because its operation is extremely straightfoward and introducing sub-actors
//! would also introduce the need for special handling of the trustee board so
//! as to not unnecessarily duplicate large amounts of data.

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::cryptography::{BallotCryptogram, ElectionKey, SigningKey};
use crate::trustee_protocols::trustee_messages::{
    CheckSignature, DecryptedBallotsMsg, EGCryptogramsMsg, ElectionPublicKeyMsg, KeySharesMsg,
    MixInitializationMsg, MixInitializationMsgData, PartialDecryptionsMsg, SetupMsg, SetupMsgData,
    TAS_NAME, TrusteeBBUpdateMsg, TrusteeBBUpdateRequestMsg, TrusteeID, TrusteeInfo, TrusteeMsg,
};

use crate::elections::{Ballot, BallotStyle, ElectionHash};
use std::cmp::min;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::trustee_protocols::trustee_administration_server::handlers::*;
use crate::utils::serialization::VSerializable;
use enum_dispatch::enum_dispatch;

// --- I. Actor-Specific I/O ---

/// The set of inputs that the `TASActor` can process.
#[enum_dispatch(TASBoomerang)]
#[derive(Debug, Clone, PartialEq)]
pub enum TASInput {
    /// Start the setup protocol.
    StartSetup,
    /// Start the key generation protocol.
    StartKeyGen,
    /// Start the mixing protocol. Note that we currently require the
    /// same set of active trustees for the mixing and decryption, and
    /// there is no separate command to start the decryption subprotocol.
    /// This could be changed in a future version if there is some
    /// reason to decouple the mixing and decryption protocols.
    StartMixing,
    /// Handle an incoming message from a trustee.
    TrusteeMsg,
    /// Get a checkpoint for the current state of the TAS.
    GetCheckpoint,
    /// Stop the running protocol, if any, and export the trustee board
    /// and other state information for auditing and/or later protocol
    /// restart.
    Stop,
}

/// The set of outputs that the `TASActor` can produce. Note that it can
/// also always return a TrusteeMsg to be sent over the network to all
/// trustees, in addition to this output.
#[derive(Debug, Clone, PartialEq)]
pub enum TASOutput {
    /// The setup protocol has completed successfully. Note that no data
    /// needs to be returned, because all the setup data was supplied at
    /// initialization (the signed messages on the trustee board can be
    /// retrieved by stopping the protocol or requesting the board state).
    SetupSuccessful(TASCheckpoint),
    /// The key generation protocol has completed successfully. The
    /// election public key is stored in the returned checkpoint.
    KeyGenSuccessful(TASCheckpoint),
    /// The mixing protocol has completed successfully.
    MixingSuccessful(TASCheckpoint),
    /// The decryption protocol has completed successfully. Note that
    /// we do not supply the full checkpoint at this stage because the
    /// protocol is complete and there is no need for it (it can
    /// still be retrieved with the `GetCheckpoint` command).
    DecryptionSuccessful(DecryptionData),
    /// A checkpoint has been generated (upon request).
    Checkpointed(TASCheckpoint),
    /// The running protocol has been stopped.
    Stopped(TASCheckpoint),
    /// A message needs to be sent to a specific trustee (this occurs
    /// when a trustee requests to pull an update from the trustee board).
    UpdateTrustee(TrusteeUpdateData),
    /// The supplied input was invalid for the current state.
    InvalidInput(FailureData),
    /// The running protocol has failed.
    Failed(FailureData),
}

/// Contains the parameters to be passed to the mixing protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct MixingParameters {
    pub active_trustees: Vec<TrusteeID>,
    pub cryptograms: Vec<BallotCryptogram>,
}

/// Contains the data resulting from a successful key generation.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyGenData {
    pub election_public_key: ElectionKey,
    pub checkpoint: TASCheckpoint,
}

/// Contains the data resulting from a successful decryption. This consists
/// only of the final list of decrypted ballots. Intermediate results,
/// proofs of decryption, etc., can be extracted from a trustee board
/// snapshot or the final protocol state data.
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptionData {
    pub decrypted_ballots: BTreeMap<BallotStyle, Vec<Ballot>>,
}

/// Contains the entire protocol state. This is used both internally
/// and as a checkpointing mechanism.
#[derive(Debug, Clone, PartialEq)]
pub struct TASCheckpoint {
    /// The election manifest.
    pub manifest: String,
    /// The election hash.
    pub election_hash: ElectionHash,
    /// The threshold number of trustees.
    pub threshold: u32,
    /// The list of trustees (in order).
    pub trustees: Vec<TrusteeInfo>,
    /// The central trustee board.
    pub board: Vec<TrusteeMsg>,
    /// The election public key computed by the trustees (this
    /// could be retrieved from the board, but is cached for
    /// convenience).
    pub election_public_key: Option<ElectionKey>,
    /// The set of active trustees (this could be retrieved
    /// from the board, but is cached for convenience).
    pub active_trustees: HashSet<TrusteeID>,
}

/// Contains trustee board update information, along with the identity
/// of the trustee to whom it should be sent.
#[derive(Debug, Clone, PartialEq)]
pub struct TrusteeUpdateData {
    pub trustee: TrusteeID,
    pub update: Result<TrusteeBBUpdateMsg, String>,
}

/// An enum identifying the subprotocols; this is only used in the
/// FailureData message.
#[derive(Debug, Clone, PartialEq)]
pub enum TASSubprotocol {
    Idle,
    ElectionSetup,
    KeyGen,
    Mixing,
    Decryption,
    Failed,
}

/// Contains a message returned on failure and an indication of which
/// subprotocol was running at the time of failure (though the calling
/// application should know this already).
#[derive(Debug, Clone, PartialEq)]
pub struct FailureData {
    pub subprotocol: TASSubprotocol,
    pub failure_msg: String,
}

// --- II. Actor Implementation ---

/// The states for the EAS.
#[enum_dispatch(TASStateHandler)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TASState {
    Idle,
    AwaitingSetupMsgs,
    AwaitingKeySharesMsgs,
    AwaitingElectionPublicKeyMsgs,
    AwaitingEGCryptogramsMsgs,
    AwaitingPartialDecryptions,
    AwaitingDecryptedBallots,
    Failed,
}

/// The TAS actor.
#[derive(Clone, Debug)]
pub struct TASActor {
    // The current state machine state, including state-specific data.
    pub(crate) state: TASState,

    // Data shared across all state machine states.
    pub(crate) checkpoint: TASCheckpoint,

    // The TAS signing key.
    pub(crate) signing_key: SigningKey,
}

#[allow(dead_code)]
impl TASActor {
    /// Create a new `TASActor`. This must be done with a checkpoint,
    /// either from a previous partial run (e.g., the setup and key
    /// generation were completed before the election, and now it's
    /// time to run the mixing and decryption), or with initial data
    /// to be used for the setup protocol.
    pub fn new(signing_key: SigningKey, checkpoint: TASCheckpoint) -> Result<Self, String> {
        // Sanity check the initialization data.
        let mut local_checkpoint = checkpoint.clone();
        let trustee_check_result =
            TASActor::validate_checkpoint(&mut local_checkpoint, &signing_key);
        match trustee_check_result {
            Ok(()) => Ok(Self {
                state: TASState::Idle(Idle),
                checkpoint: local_checkpoint,
                signing_key,
            }),
            Err(err) => Err(err),
        }
    }

    /// Handle an input. This can be a command (start decryption, etc.),
    /// or an incoming message from a trustee. This function is, effectively,
    /// the state machine for the TAS.
    pub(crate) fn handle_input(
        &mut self,
        input: &TASInput,
    ) -> (Option<TASOutput>, Option<TrusteeBBUpdateMsg>) {
        let (new_state, output, posted_msg) = input.boomerang(self);

        // Change the state, and return the output and any trustee
        // board update message that was generated.
        self.state = new_state.unwrap_or(self.state);
        (output, posted_msg)
    }

    /// Checks that the initial data supplied to the TAS is reasonable. This
    /// includes it having correct signing/encryption keys for the TAS (matching
    /// the trustee list), having all unique trustees, having a reasonable
    /// (non-zero, less than the number of trustees) threshold, and having only
    /// valid messages on its board (if starting with a non-empty board).
    fn validate_checkpoint(
        checkpoint: &mut TASCheckpoint,
        signing_key: &SigningKey,
    ) -> Result<(), String> {
        // Check that the threshold is greater than 0.
        if checkpoint.threshold == 0 {
            return Err("trustee threshold is 0".to_string());
        }

        // Check that the number of trustees is at least 1 (the trustees
        // vec has length at least 2, including the TAS).
        if checkpoint.trustees.len() < 2 {
            return Err("No trustee information supplied.".to_string());
        }

        // Check that the threshold is <= the number of trustees
        // (which should be the length of the trustees vec minus 1
        // for the TAS, as trustees are 1-indexed).
        if checkpoint.threshold as usize >= checkpoint.trustees.len() {
            return Err(format!(
                "trustee threshold {} >= number of trustees {}",
                checkpoint.threshold,
                checkpoint.trustees.len()
            ));
        }

        // Check that the first trustee in the vector is the TAS, and
        // that its signing key matches. We ignore its encryption key;
        // it's never used, so it can be anything in the trustee list.
        let trustee0 = &checkpoint.trustees[0];
        if trustee0.name != TAS_NAME {
            return Err(format!(
                "trustee 0 name ({}) is not ({})",
                trustee0.name, TAS_NAME
            ));
        }
        if trustee0.verifying_key != signing_key.verifying_key() {
            return Err(format!(
                "TAS verifying key in list ({:?}) does not match supplied signing key.",
                trustee0.verifying_key
            ));
        }

        // Check that no two trustees in the list have the same name or
        // identical keys.
        for x in 0..checkpoint.trustees.len() {
            for y in 1..checkpoint.trustees.len() {
                if x != y
                    && (checkpoint.trustees[x].name == checkpoint.trustees[y].name
                        || checkpoint.trustees[x].public_enc_key
                            == checkpoint.trustees[y].public_enc_key
                        || checkpoint.trustees[x].verifying_key
                            == checkpoint.trustees[y].verifying_key)
                {
                    return Err(format!(
                        "Trustees {} ({:?}) and {} have ({:?}) have overlapping identity information.",
                        x, checkpoint.trustees[x], y, checkpoint.trustees[y]
                    ));
                }
            }
        }

        // Check that every message on the initial board is originated by and
        // signed by legitimate trustees.
        for m in checkpoint.board.iter() {
            // First, get the message signer and originator.
            let (sign_res, orig_res) = (m.signer_id(), m.originator_id());
            if sign_res.is_err() {
                return Err(format!(
                    "Could not get signer ID for trustee board message ({:?}).",
                    m
                ));
            }
            if orig_res.is_err() {
                return Err(format!(
                    "Could not get originator ID for trustee board message ({:?}).",
                    m
                ));
            }

            // This must not panic, because we just checked that the
            //results were OK.
            let (signer_id, originator_id) = (sign_res.unwrap(), orig_res.unwrap());

            // Then, check that it was signed by and originated by
            // a trustee in the list.
            if checkpoint
                .trustees
                .iter()
                .all(|t| t.trustee_id() != signer_id)
            {
                return Err(format!(
                    "Trustee board contains message ({:?}) signed by invalid trustee ({:?}).",
                    m, signer_id
                ));
            }

            if checkpoint
                .trustees
                .iter()
                .all(|t| t.trustee_id() != originator_id)
            {
                return Err(format!(
                    "Trustee board contains message ({:?}) originated by invalid trustee ({:?}).",
                    m, originator_id
                ));
            }

            // Finally, check that the signature is valid.
            if m.check_signature().is_err() {
                return Err(format!(
                    "Trustee board message ({:?}) has an invalid signature.",
                    m
                ));
            }
        }

        // If we've made it through all those checks, our TAS data is good to go.
        Ok(())
    }

    // Self Functions (non-protocol-specific) //

    /// Adds a message to the trustee board. This utility function simply
    /// adds the message to the board and generates an update message that
    /// contains a correct object (the right index, the right message) for
    /// the new message. It does not check the message's signature; where
    /// that's required, we assume it's done before this call.
    ///
    /// If the message is an exact duplicate of one already on the board,
    /// it is not added, and no update message is returned.
    pub(crate) fn add_to_board(&mut self, msg: TrusteeMsg) -> Option<TrusteeBBUpdateMsg> {
        match self.checkpoint.board.iter().position(|m| m == &msg) {
            None => {
                // Add the message to the board.
                self.checkpoint.board.push(msg.clone());
                let index = (self.checkpoint.board.len() - 1) as u64;
                let mut msgs = std::collections::BTreeMap::new();
                msgs.insert(index, msg);

                Some(TrusteeBBUpdateMsg { msgs })
            }

            Some(_) => None,
        }
    }

    /// Retrieves a range of messages from the trustee board in response to
    /// a trustee board update request message, generating a TrusteeUpdateData.
    pub(crate) fn trustee_update(&mut self, msg: TrusteeBBUpdateRequestMsg) -> TrusteeUpdateData {
        // Check the message range to see if it's valid; a lower bound higher
        // than the current board index results in an error, but upper bounds
        // higher than the current board index are ignored.
        let update = if msg.end_index < msg.start_index
            || msg.start_index > (self.checkpoint.board.len() - 1) as u64
        {
            Err(format!(
                "Invalid range ({}..{}), highest message index is {}",
                msg.start_index,
                msg.end_index,
                self.checkpoint.board.len() - 1
            ))
        } else {
            let mut msgs = std::collections::BTreeMap::new();
            (msg.start_index as usize
                ..=min(msg.end_index as usize, self.checkpoint.board.len() - 1))
                .for_each(|i| {
                    msgs.insert(i as u64, self.checkpoint.board[i].clone());
                });
            Ok(TrusteeBBUpdateMsg { msgs })
        };

        TrusteeUpdateData {
            trustee: msg.trustee.clone(),
            update,
        }
    }

    /// Returns the current subprotocol, based on our state.
    pub(crate) fn current_subprotocol(&self) -> TASSubprotocol {
        match self.state {
            TASState::Idle(_) => TASSubprotocol::Idle,
            TASState::Failed(_) => TASSubprotocol::Failed,
            TASState::AwaitingSetupMsgs(_) => TASSubprotocol::ElectionSetup,
            TASState::AwaitingKeySharesMsgs(_) | TASState::AwaitingElectionPublicKeyMsgs(_) => {
                TASSubprotocol::KeyGen
            }

            TASState::AwaitingEGCryptogramsMsgs(_) => TASSubprotocol::Mixing,
            TASState::AwaitingPartialDecryptions(_) | TASState::AwaitingDecryptedBallots(_) => {
                TASSubprotocol::Decryption
            }
        }
    }

    /// Checks the signature on a trustee message for validity and to
    /// ensure that it matches a known trustee.
    pub(crate) fn trustee_signature_ok(&self, msg: &TrusteeMsg) -> Result<(), String> {
        // First, check that setup_msg is properly signed (if it isn't,
        // we can throw it out regardless of who sent it).
        msg.check_signature()?;

        let trustee_id = msg.signer_id()?;
        if !self
            .checkpoint
            .trustees
            .iter()
            .any(|t| t.trustee_id() == trustee_id)
        {
            Err(format!(
                "Message signed by unknown trustee: {:?}",
                trustee_id
            ))
        } else {
            Ok(())
        }
    }

    /// Checks a specified set of messages to see if (1) all
    /// the trustees that are supposed to be active have originated
    /// messages in the set, and (2) optionally, all the trustees
    /// that are supposed to be active have signed a message from
    /// each originator.
    pub(crate) fn check_participants(&self, msgs: &[&TrusteeMsg], check_signers: bool) -> bool {
        // If this function is called when the active trustee list is
        // empty, it always returns false. This should never happen, but
        // if it does, returning false prevents any bad protocol actions
        // from being taken.
        if self.checkpoint.active_trustees.is_empty() {
            return false;
        }

        // Throw all of the originator IDs into a set to see how many
        // unique ones there are; we know they're all valid, because of
        // the checks we do before posting the messages to the board.
        let mut msg_data: HashMap<TrusteeID, HashSet<TrusteeID>> = HashMap::new();
        for m in msgs {
            let originator = m
                .originator_id()
                .expect("impossible, we wouldn't have posted the message");
            let signer = m
                .signer_id()
                .expect("impossible, we wouldn't have posted the message");

            if let Some(signer_set) = msg_data.get_mut(&originator) {
                signer_set.insert(signer);
            } else {
                let mut signer_set: HashSet<TrusteeID> = HashSet::new();
                signer_set.insert(signer);
                msg_data.insert(originator, signer_set);
            }
        }

        // If the set of originators doesn't match the active trustees
        // exactly, we don't have all the necessary messages.
        let originators: HashSet<TrusteeID> = msg_data.keys().cloned().collect();
        if originators != self.checkpoint.active_trustees {
            return false;
        }

        if check_signers {
            // We have all the necessary messages exactly when every
            // originator has a full set of signers.
            msg_data
                .iter()
                .all(|(_, signers)| *signers == self.checkpoint.active_trustees)
        } else {
            // We already know we have all the necessary messages.
            true
        }
    }

    // Setup Protocol Functions //

    /// Creates a board message from our state data, to begin the setup
    /// process.
    pub(crate) fn create_initial_setup_msg(&self) -> TrusteeMsg {
        let setup_msg_data = SetupMsgData {
            originator: self.checkpoint.trustees[0].trustee_id(),
            signer: self.checkpoint.trustees[0].trustee_id(),
            threshold: self.checkpoint.threshold,
            manifest: self.checkpoint.manifest.clone(),
            trustees: self.checkpoint.trustees.clone(),
        };
        let signature = crate::cryptography::sign_data(&setup_msg_data.ser(), &self.signing_key);

        TrusteeMsg::Setup(SetupMsg {
            data: setup_msg_data,
            signature,
        })
    }

    /// Check that a setup message can be posted to the trustee board. We
    /// perform a number of checks that we don't actually have to here, such
    /// as that the contents match the setup information we sent out,
    /// to allow us to determine the protocol's success or failure more
    /// easily later on.
    pub fn check_setup_msg(&self, msg: &SetupMsg) -> Result<(), String> {
        // First, check the message signature.
        let wrapped_msg = TrusteeMsg::Setup(msg.clone());
        self.trustee_signature_ok(&wrapped_msg)?;

        // Next, check that the data in setup_msg matches what we sent out.
        if self.checkpoint.manifest != msg.data.manifest {
            return Err(format!(
                "Manifest in message ({}) does not match distributed manifest ({}).",
                msg.data.manifest, self.checkpoint.manifest
            ));
        }
        if self.checkpoint.threshold != msg.data.threshold {
            return Err(format!(
                "Threshold in message ({}) does not match distributed threshold ({}).",
                msg.data.threshold, self.checkpoint.threshold
            ));
        }
        if self.checkpoint.trustees != msg.data.trustees {
            return Err(format!(
                "Trustee list in message ({:?}) does not match distributed trustee list ({:?}).",
                msg.data.trustees, self.checkpoint.trustees
            ));
        }

        // If everything matches, we're good to continue using this message.
        Ok(())
    }

    // Check that the setup protocol is complete (based on the trustee board).
    // This is the case when there is (at least) one setup message signed by
    // each trustee. We know they all have identical setup data because
    pub(crate) fn setup_complete(&self) -> bool {
        // Get all the setup messages from the board.
        let setup_msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::Setup(_)))
            .collect();

        // Throw all the trustee IDs into a set to see how many unique ones
        // there are; we know they're all valid, and the setup data is all
        // valid, because of the checks we do before posting the setup
        // messages to the board.
        let mut trustees: HashSet<TrusteeID> = HashSet::new();
        for m in setup_msgs {
            let id = m
                .signer_id()
                .expect("impossible, we wouldn't have posted the message");
            trustees.insert(id);
        }

        // If the number of unique trustees we got setup messages from is the
        // same as the number of trustees we know about, we're done with setup.
        trustees.len() == self.checkpoint.trustees.len()
    }

    // KeyGen Protocol Functions //

    /// Check that there is a key share on the board from each trustee.
    pub(crate) fn key_shares_complete(&self) -> bool {
        // Get all the key shares messages from the board.
        let key_shares_msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::KeyShares(_)))
            .collect();

        // Throw all the trustee IDs into a set to see how many unique ones
        // there are; we know they're all valid, and the setup data is all
        // valid, because of the checks we do before posting the setup
        // messages to the board.
        let mut trustees: HashSet<TrusteeID> = HashSet::new();
        for m in key_shares_msgs {
            let signer_id = m
                .signer_id()
                .expect("impossible, we wouldn't have posted the message");
            trustees.insert(signer_id);
        }

        // If the number of unique trustees we got key shares messages from
        // is the same as the number of trustees we know about (excluding
        // the TAS), we're done. If there are multiples, the trustees will
        // flag an error (we could check that all the ones from the same
        // trustee have identical data, but we currently don't).
        trustees.len() == self.checkpoint.trustees.len() - 1
    }

    /// Check that an election public key message can be posted to the
    /// trustee board. We check here that the public key matches any
    /// previous public keys we received (in addition to checking the
    /// message signature), and if not we fail the protocol.
    pub fn check_election_public_key_msg(&self, msg: &ElectionPublicKeyMsg) -> Result<(), String> {
        // First, check the message signature.
        let wrapped_msg = TrusteeMsg::ElectionPublicKey(msg.clone());
        self.trustee_signature_ok(&wrapped_msg)?;

        // Next, check that the election public key matches any we might have.
        match &self.checkpoint.election_public_key {
            None => Ok(()),
            Some(key) => {
                if *key != msg.data.election_public_key {
                    Err(format!(
                        "Public key in message ({:?}) does not match previously-received public key ({:?})",
                        msg.data.election_public_key, key
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Check that there is an election public key on the board from
    /// each trustee.
    // TODO: is there a way to parameterize this by enum variant? If so,
    // this function is identical to "key_shares_complete".
    pub(crate) fn election_public_keys_complete(&self) -> bool {
        // Get all the key shares messages from the board.
        let public_key_msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::ElectionPublicKey(_)))
            .collect();

        // Throw all the originator IDs into a set to see how many unique ones
        // there are; we know they're all valid, and the public keys are all
        // valid, because of the checks we do before posting the public key
        // messages to the board.
        let mut trustees: HashSet<TrusteeID> = HashSet::new();
        for m in public_key_msgs {
            let originator_id = m
                .originator_id()
                .expect("impossible, we wouldn't have posted the message");
            trustees.insert(originator_id);
        }

        // If the number of unique trustees we got public key messages from
        // is the same as the number of trustees we know about (excluding
        // the TAS), we're done. If there are multiples, the trustees will
        // flag an error (we could check that all the ones from the same
        // trustee have identical data, but we currently don't).
        trustees.len() == self.checkpoint.trustees.len() - 1
    }

    // Mix Protocol Functions //

    /// Creates a board message from the initial mixing parameters
    /// in order to bootstrap the mixing and decryption subprotocols.
    pub(crate) fn create_initial_mix_msg(
        &self,
        mixing_parameters: &MixingParameters,
    ) -> TrusteeMsg {
        let msg_data = MixInitializationMsgData {
            originator: self.checkpoint.trustees[0].trustee_id(),
            signer: self.checkpoint.trustees[0].trustee_id(),
            election_hash: self.checkpoint.election_hash,
            active_trustees: mixing_parameters.active_trustees.clone(),
            cryptograms: mixing_parameters.cryptograms.to_owned(),
        };
        let serialized_data = msg_data.ser();
        let mix_msg = MixInitializationMsg {
            data: msg_data,
            signature: crate::cryptography::sign_data(&serialized_data, &self.signing_key),
        };
        TrusteeMsg::MixInitialization(mix_msg)
    }

    /// Returns true if we have received enough ElGamal cryptogram
    /// messages to proceed to decryption, false otherwise. This counts
    /// the number of different originators for ElGamal cryptogram
    /// messages, and the number of unique signers for each originator,
    /// and declares it "enough" when there are at least the threshold
    /// number of originators, each with at least the threshold number of
    /// signers. Note that it does _not_ compare the actual contents of
    /// the signed messages, as that would be extremely expensive (it's
    /// all the ballot cryptograms), and is already being done by the
    /// trustees. It also does not check to make sure that the messages
    /// were created in the right order, etc.; another check already
    /// being done by the trustees.
    pub(crate) fn eg_cryptograms_complete(&self) -> bool {
        // Get all the ElGamal cryptogram messages from the board.
        let msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::EGCryptograms(_)))
            .collect();

        self.check_participants(&msgs, true)
    }

    // Decryption Protocol Functions //

    /// Returns true if we have received enough partial decryption
    /// messages for the trustees to complete decryption, false
    /// otherwise. This counts the number of different originators
    /// for partial decryption messages, and declares it "enough"
    /// when there are at least the threshold number of originators.
    /// Note that it does _not_ examine the actual contents of the
    /// messages, as that would be extremely expensive and is
    /// already being done by the trustees.
    pub(crate) fn partial_decryptions_complete(&self) -> bool {
        // Get all the partial decryption messages from the board.
        let msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::PartialDecryptions(_)))
            .collect();

        self.check_participants(&msgs, false)
    }

    /// Returns a result (true or false) depending on whether or
    /// not we have received decrypted ballots from a threshold
    /// number of trustees. Returns an error if there are decrypted
    /// ballots from a threshold number of trustees but they don't
    /// all match.
    pub(crate) fn decrypted_ballots_complete(&self) -> Result<bool, String> {
        // Get all the decrypted ballot messages from the board.
        let msgs: Vec<&TrusteeMsg> = self
            .checkpoint
            .board
            .iter()
            .filter(|m| matches!(m, TrusteeMsg::DecryptedBallots(_)))
            .collect();

        // Here, we only need one message from each originator, the
        // trustees don't sign each others' decrypted ballots.
        if self.check_participants(&msgs, false) {
            // We have enough lists of decrypted ballots, now we have to
            // compare them to make sure they're the same.
            let ballots = match msgs[0] {
                TrusteeMsg::DecryptedBallots(ballots_msg) => &ballots_msg.data.ballots,
                _ => {
                    // This can't happen because all the messages are in fact of type
                    // TrusteeMsg::DecryptedBallots. But we'll return false if it does,
                    // anyway.
                    return Err("Attempted to extract ballots from the wrong message type. This should never happen.".to_string());
                }
            };

            if msgs.iter().all(|m| match m {
                TrusteeMsg::DecryptedBallots(ballots_msg) => &ballots_msg.data.ballots == ballots,
                _ => {
                    // This can't happen because all the messages are in fact of type
                    // TrusteeMsg::DecryptedBallots. But we'll take value false if it
                    // does, anyway.
                    false
                }
            }) {
                // All the lists of ballots are equivalent.
                Ok(true)
            } else {
                Err(
                    "Some lists of decrypted ballots do not match, check the trustee board data."
                        .to_string(),
                )
            }
        } else {
            // We don't have enough messages.
            Ok(false)
        }
    }

    /// Returns the list of decrypted ballots. This assumes that the board
    /// has already been checked to ensure that all such lists are identical,
    /// and simply returns the first one. If it doesn't find a decrypted
    /// ballots message, it returns an empty vector of ballots.
    pub(crate) fn decryption_data(&self) -> DecryptionData {
        // Get the first decrypted ballot messages from the board.
        match self
            .checkpoint
            .board
            .iter()
            .find(|m| matches!(m, TrusteeMsg::DecryptedBallots(_)))
        {
            Some(TrusteeMsg::DecryptedBallots(ballots_msg)) => DecryptionData {
                decrypted_ballots: ballots_msg.data.ballots.clone(),
            },

            _ => DecryptionData {
                decrypted_ballots: BTreeMap::new(),
            },
        }
    }

    /// Get failure data reflecting the current state, with
    /// the specified message.
    pub(crate) fn failure_data(&self, msg: String) -> FailureData {
        FailureData {
            subprotocol: self.current_subprotocol(),
            failure_msg: msg,
        }
    }

    /// Get the current checkpoint. This simply returns a clone
    /// of our actual protocol state.
    pub(crate) fn checkpoint(&self) -> TASCheckpoint {
        self.checkpoint.clone()
    }
}
