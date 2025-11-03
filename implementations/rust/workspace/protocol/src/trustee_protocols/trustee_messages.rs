// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains all the message structures exchanged between trustees
//! and the trustee administration server. All individual message structs
//! are unified under the `TrusteeMessage` enum for type-safe handling.

use enum_dispatch::enum_dispatch;
use std::cmp::Ordering;
use std::collections::BTreeMap;

// Required to set up double dispatch for TAS message handling
use crate::trustee_protocols::trustee_administration_server::handlers::TASBoomerang;
use crate::trustee_protocols::trustee_administration_server::top_level_actor::{
    TASActor, TASOutput, TASState,
};

// Required to set up double dispatch for Trustee message handling
use crate::trustee_protocols::trustee_application::handlers::TrusteeBoomerang;
use crate::trustee_protocols::trustee_application::top_level_actor::{
    TrusteeActor, TrusteeOutput, TrusteeState,
};

use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable;

use crate::cryptography::{BallotCryptogram, ElectionKey, Signature, VerifyingKey};
use crate::elections::{Ballot, BallotStyle, ElectionHash};
use crate::trustee_protocols::trustee_cryptography::{
    CheckValue, MixRoundProof, PartialDecryptionProof, PartialDecryptionValue, ShareCiphertext,
    StrippedBallotCiphertext, TrusteePublicKey,
};

// --- Trustee Structures and Update Messages ---
// These occur across all four trustee subprotocols.

// A signature checking trait for messages, to encapsulate signature
// checking. Note that checking that the trustee is actually a real
// trustee needs to be done separately; this simply checks that
// a message's signature verifies using the purported signer's
// verifying key within the message.
#[enum_dispatch]
pub trait CheckSignature {
    fn internal_check_signature(
        &self,
        data: &[u8],
        signature: &Signature,
        verifying_key: &VerifyingKey,
    ) -> Result<(), String> {
        crate::cryptography::verify_signature(data, signature, verifying_key)
    }

    fn check_signature(&self) -> Result<(), String> {
        Err("Signature check not implemented for this struct.".to_string())
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Err("Signer ID not implemented for this struct.".to_string())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Err("Originator ID not implemented for this struct.".to_string())
    }
}

// The human-readable name that identifies the trustee administration
// server in messages posted to the trustee board.
pub const TAS_NAME: &str = "TrusteeAdministrationServer";

/// A trustee (or TAS) identity, represented by a public signing key
/// and a human-readable name (primarily for analysis/logging; this
/// could be the trustee's real name, or could be a well-known
/// identifier like "Trustee 1", depending on higher-level system
/// implementation). The TAS always has the fixed name defined by the
/// symbolic constant TAS_NAME.
#[derive(Debug, Clone, Eq, PartialEq, VSerializable)]
pub struct TrusteeID {
    pub name: String,
    pub verifying_key: VerifyingKey,
}
impl PartialOrd for TrusteeID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TrusteeID {
    fn cmp(&self, other: &Self) -> Ordering {
        let name_cmp = self.name.cmp(&other.name);
        if name_cmp == Ordering::Equal {
            // Names are the name, need to compare keys.
            self.verifying_key
                .as_bytes()
                .cmp(other.verifying_key.as_bytes())
        } else {
            name_cmp
        }
    }
}

/// Full information about a trustee, including the trustee's
/// human-readable name and both its public keys. This information is
/// known a priori by the election authority and distributed to the
/// trustees during setup,
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct TrusteeInfo {
    pub name: String,
    pub verifying_key: VerifyingKey,
    pub public_enc_key: TrusteePublicKey,
}

impl TrusteeInfo {
    // Convert a full TrusteeInfo to a TrusteeID.
    pub fn trustee_id(&self) -> TrusteeID {
        TrusteeID {
            name: self.name.clone(),
            verifying_key: self.verifying_key,
        }
    }
}

/// A message sent from a Trustee to the TAS to retrieve messages from
/// the trustee board, starting at message number `start_index` and
/// ending at message number `end_index` (or the highest-numbered
/// message, if its index is smaller than `end_index`), inclusive. It
/// is common to use `u64::MAX` as the value for `end_index`; it is
/// less common (though possible) to request the entire bulletin
/// board, so `start_index` is typically set to a non-zero value.
#[derive(Debug, Clone, PartialEq)]
pub struct TrusteeBBUpdateRequestMsg {
    pub trustee: TrusteeID,
    // We use u64 for these indices because it is clearly impossible
    // to exchange even close to that many messages on the trustee
    // board, even if we post a separate message for each part of each
    // protocol for each race on each ballot in a theoretical election
    // involving every individual on the planet; we could probably get
    // away with u32 or even u16, if we decide we need to for some reason.
    pub start_index: u64,
    pub end_index: u64,
}

/// A message sent from the TAS to a Trustee containing one or more
/// messages from the trustee board. This message is _not signed_
/// (this would be redundant, because all of the messages contained
/// within it must be signed in order to be valid).
///
/// The messages are stored in a BTreeMap keyed by their bulletin board
/// index, which guarantees they are sorted and makes gap detection trivial.
#[derive(Debug, Clone, PartialEq)]
pub struct TrusteeBBUpdateMsg {
    pub msgs: BTreeMap<u64, TrusteeMsg>,
}

// --- Trustee Protocol Messages ---
// Each trustee protocol message has four mandatory fields:
// - an `originator`, which is the trustee that originally generated
//   the message;
// - a `signer`, which is the trustee that signed this particular
//   message; note that some subprotocols don't actually require
//   re-signing of messages, but we still include this field
//   for uniformity;
// - message data (for whatever protocol is being carried out; this
//   may of course be more than one field); and
// - a `signature`, over all of the above; we handle this the
//   same way as in the other protocols, where the data being signed
//   is encapsulated in its own VSerializable struct.

// --- Setup Subprotocol ---

/// A setup message, containing the election manifest, the list
/// of trustees, and the trustee threshold. The election manifest
/// is encoded as an arbitrary String; the specific encoding will
/// be determined by the higher-level implementation (note that
/// the election manifest really should include all the trustee
/// information as well, and the mechanism for doing so is left
/// undefined here). The list of trustees always includes the
/// TAS as the first entry (element 0), leaving the actual
/// trustees 1-indexed.
/// TODO: determine whether String is the right type for this.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SetupMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub manifest: String,
    pub threshold: u32,
    pub trustees: Vec<TrusteeInfo>,
}
impl SetupMsgData {
    /// Utility function to allow comparison of the
    /// values in the struct other than the signer.
    pub fn equal_except_signer(&self, other: &SetupMsgData) -> bool {
        other.originator == self.originator
            && other.manifest == self.manifest
            && other.threshold == self.threshold
            && other.trustees == self.trustees
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetupMsg {
    pub data: SetupMsgData,
    pub signature: Signature,
}

impl CheckSignature for SetupMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

impl SetupMsg {
    /// Sanity checking function for setup messages. The
    /// `checking_trustee` parameter is the trustee that is
    /// performing the sanity check, so it must appear in the
    /// trustees list of the setup message.
    pub fn sanity_check(&self, checking_trustee: &TrusteeInfo) -> Result<(), String> {
        // Check that the threshold is greater than 0.
        if self.data.threshold == 0 {
            return Err("trustee threshold is 0".to_string());
        }

        // Check that the number of trustees is at least 1 (the trustees
        // vec has length at least 2, including the TAS).
        if self.data.trustees.len() < 2 {
            return Err("No trustee information supplied.".to_string());
        }

        // Check that the threshold is <= the number of trustees
        // (which should be the length of the trustees vec minus 1
        // for the TAS, as trustees are 1-indexed).
        if self.data.threshold as usize >= self.data.trustees.len() {
            return Err(format!(
                "trustee threshold {} >= number of trustees {}",
                self.data.threshold,
                self.data.trustees.len()
            ));
        }

        // Check that the first trustee in the vector is the TAS.
        let trustee0 = &self.data.trustees[0];
        if trustee0.name != TAS_NAME {
            return Err(format!(
                "trustee 0 name ({}) is not ({})",
                trustee0.name, TAS_NAME
            ));
        }

        // Check that no two trustees in the list have the same name or
        // identical keys.
        for x in 0..self.data.trustees.len() {
            for y in 1..self.data.trustees.len() {
                if x != y
                    && (self.data.trustees[x].name == self.data.trustees[y].name
                        || self.data.trustees[x].public_enc_key
                            == self.data.trustees[y].public_enc_key
                        || self.data.trustees[x].verifying_key
                            == self.data.trustees[y].verifying_key)
                {
                    return Err(format!(
                        "Trustees {} ({:?}) and {} have ({:?}) have overlapping identity information.",
                        x, self.data.trustees[x], y, self.data.trustees[y]
                    ));
                }
            }
        }

        // Check that the trustee passed in as a parameter actually appears
        // in the trustee list.
        if self.data.trustees.contains(checking_trustee) {
            Ok(())
        } else {
            Err(format!(
                "Trustee {:?} does not appear in trustees list.",
                checking_trustee
            ))
        }
    }
}

// --- Key Generation Subprotocol ---

/// A key generation message, containing all the pairwise shares
/// and public check values generated by a trustee. It is assumed
/// that the check values and pairwise shares are in the same trustee
/// order as in the setup data's `trustees` field.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct KeySharesMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub check_values: Vec<CheckValue>,
    pub pairwise_shares: Vec<ShareCiphertext>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeySharesMsg {
    pub data: KeySharesMsgData,
    pub signature: Signature,
}

impl CheckSignature for KeySharesMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

/// An election public key message, containing the election public
/// key as computed by the trustee that originated it.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ElectionPublicKeyMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub check_values: BTreeMap<TrusteeID, Vec<CheckValue>>,
    pub election_public_key: ElectionKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ElectionPublicKeyMsg {
    pub data: ElectionPublicKeyMsgData,
    pub signature: Signature,
}

impl CheckSignature for ElectionPublicKeyMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

// --- Mixing Subprotocol ---

/// A Naor-Yung cryptograms message, containing the list of Naor-Yung
/// cryptograms from the public bulletin board that need to be mixed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct MixInitializationMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub active_trustees: Vec<TrusteeID>,
    pub cryptograms: Vec<BallotCryptogram>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MixInitializationMsg {
    pub data: MixInitializationMsgData,
    pub signature: Signature,
}

impl CheckSignature for MixInitializationMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

/// An El-Gamal cryptograms message, containing a list of (possibly
/// shuffled) cryptograms, which are either stripped Naor-Yung
/// cryptograms (in the initial round) or re-encrypted shuffled
/// cryptograms (in subsequent rounds).
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct EGCryptogramsMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub ciphertexts: BTreeMap<BallotStyle, Vec<StrippedBallotCiphertext>>,
    pub proofs: BTreeMap<BallotStyle, MixRoundProof>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EGCryptogramsMsg {
    pub data: EGCryptogramsMsgData,
    pub signature: Signature,
}

impl CheckSignature for EGCryptogramsMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

// --- Decryption Subprotocol ---

// `DecryptionFactor`` (a partial decryption) in the cryptography library
// is parameterized by a context `C`, total number of trustees `P`, and
// width `W`. But we don't know `P` a priori here, so we're going to use
// a data structure that contains the same information as `DecryptionFactor`
// and convert it into a `DecryptionFactor` when it is received by a trustee.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PartialDecryption {
    pub value: PartialDecryptionValue,
    pub proof: PartialDecryptionProof,
    pub source: u32,
}

/// A message containing the partial decryptions generated by
/// a single trustee.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PartialDecryptionsMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub partial_decryptions: BTreeMap<BallotStyle, Vec<PartialDecryption>>, // data type will definitely change
}

/// A single enum to encapsulate all possible trustee message
/// data types.
/// P is the number of trustees initially participating in the protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct PartialDecryptionsMsg {
    pub data: PartialDecryptionsMsgData,
    pub signature: Signature,
}

impl CheckSignature for PartialDecryptionsMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}
/// A message containing the decrypted ballots, generated by
/// a single trustee from partial decryptions.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct DecryptedBallotsMsgData {
    pub originator: TrusteeID,
    pub signer: TrusteeID,
    pub election_hash: ElectionHash,
    pub ballots: BTreeMap<BallotStyle, Vec<Ballot>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedBallotsMsg {
    pub data: DecryptedBallotsMsgData,
    pub signature: Signature,
}

impl CheckSignature for DecryptedBallotsMsg {
    fn check_signature(&self) -> Result<(), String> {
        self.internal_check_signature(
            &self.data.ser(),
            &self.signature,
            &self.data.signer.verifying_key,
        )
    }

    fn signer_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.signer.clone())
    }

    fn originator_id(&self) -> Result<TrusteeID, String> {
        Ok(self.data.originator.clone())
    }
}

/// An enum that encapsulates all possible trustee messages.
/// P is the number of trustees initially participating in the protocol.
#[derive(Debug, Clone, PartialEq)]
#[enum_dispatch(TrusteeBoomerang, TASBoomerang, CheckSignature)]
#[allow(clippy::large_enum_variant)]
pub enum TrusteeMsg {
    // Election Setup
    Setup(SetupMsg),

    // Key Generation
    KeyShares(KeySharesMsg),
    ElectionPublicKey(ElectionPublicKeyMsg),

    // Mixing
    MixInitialization(MixInitializationMsg),
    EGCryptograms(EGCryptogramsMsg),

    // Ballot Checking
    PartialDecryptions(PartialDecryptionsMsg),
    DecryptedBallots(DecryptedBallotsMsg),

    // Bulletin Board Update Meta-Messages
    TrusteeBBUpdateRequest(TrusteeBBUpdateRequestMsg),
    TrusteeBBUpdate(TrusteeBBUpdateMsg),
}

// The default implementation will return an error when called on this struct
impl CheckSignature for TrusteeBBUpdateMsg {}
// The default implementation will return an error when called on this struct
impl CheckSignature for TrusteeBBUpdateRequestMsg {}
