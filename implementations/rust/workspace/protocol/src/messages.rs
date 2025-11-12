/*!
This file contains all the message structures exchanged between participants
in the e-voting protocol. All individual message structs
are unified under the `ProtocolMessage` enum for type-safe handling.
*/
// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use vser_derive::VSerializable;

use crate::crypto::{
    BallotCryptogram, ElectionKey, RandomizersCryptogram, Signature, VerifyingKey,
};
use crate::elections::{BallotStyle, BallotTracker, ElectionHash, VoterPseudonym};

// --- Voter Authentication Subprotocol Messages ---
// Defined in `voter-authentication-spec.md`

/// The data part of the `AuthReqMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthReqMsgData {
    pub election_hash: ElectionHash,
    pub voter_verifying_key: VerifyingKey,
}

/// Sent from VA to EAS to initiate an authentication session.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthReqMsg {
    pub data: AuthReqMsgData,
    pub signature: Signature,
}

/// The data part of the `HandTokenMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct HandTokenMsgData {
    pub election_hash: ElectionHash,
    pub token: String,
    pub voter_verifying_key: VerifyingKey,
}

/// Sent from EAS to VA to provide the token for third-party authentication.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct HandTokenMsg {
    pub data: HandTokenMsgData,
    pub signature: Signature,
}

/// The data part of the `AuthFinishMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthFinishMsgData {
    pub election_hash: ElectionHash,
    pub token: String,
    pub public_key: VerifyingKey,
}

/// Sent from VA to EAS to notify that third-party authentication is complete.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthFinishMsg {
    pub data: AuthFinishMsgData,
    pub signature: Signature,
}

/// The data part of the `AuthVoterMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthVoterMsgData {
    pub election_hash: ElectionHash,
    pub voter_pseudonym: VoterPseudonym,
    pub voter_verifying_key: VerifyingKey,
    pub ballot_style: BallotStyle,
}

/// Sent from EAS to DBB to authorize a voter to submit and cast ballots.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct AuthVoterMsg {
    pub data: AuthVoterMsgData,
    pub signature: Signature,
}

/// The data part of the `ConfirmAuthorizationMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfirmAuthorizationMsgData {
    pub election_hash: ElectionHash,
    pub voter_pseudonym: Option<VoterPseudonym>,
    pub voter_verifying_key: VerifyingKey,
    pub ballot_style: Option<BallotStyle>,
    pub authentication_result: (bool, String),
}

/// Sent from EAS to VA to inform the voter about the authorization result.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfirmAuthorizationMsg {
    pub data: ConfirmAuthorizationMsgData,
    pub signature: Signature,
}

// --- Ballot Submission Subprotocol Messages ---
// Defined in `ballot-submission-spec.md`

/// The data part of the `SignedBallotMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SignedBallotMsgData {
    pub election_hash: ElectionHash,
    pub voter_pseudonym: VoterPseudonym,
    pub voter_verifying_key: VerifyingKey,
    pub ballot_style: BallotStyle,
    pub ballot_cryptogram: BallotCryptogram,
}

/// Sent from VA to DBB to submit the encrypted and signed ballot.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SignedBallotMsg {
    pub data: SignedBallotMsgData,
    pub signature: Signature,
}

/// The data part of the `TrackerMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct TrackerMsgData {
    pub election_hash: ElectionHash,
    pub tracker: BallotTracker,
}

/// Sent from DBB to VA to confirm ballot submission with a unique tracker.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct TrackerMsg {
    pub data: TrackerMsgData,
    pub signature: Signature,
}

// --- Ballot Casting Subprotocol Messages ---
// Defined in `ballot-cast-spec.md`

/// The data part of the `CastReqMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CastReqMsgData {
    pub election_hash: ElectionHash,
    pub voter_pseudonym: VoterPseudonym,
    pub voter_verifying_key: VerifyingKey,
    pub ballot_tracker: BallotTracker,
}

/// Sent from VA to DBB to request that a submitted ballot be officially cast.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CastReqMsg {
    pub data: CastReqMsgData,
    pub signature: Signature,
}

/// The data part of the `CastConfMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CastConfMsgData {
    pub election_hash: ElectionHash,
    pub ballot_sub_tracker: BallotTracker,
    pub ballot_cast_tracker: BallotTracker,
}

/// Sent from DBB to VA to confirm that the ballot has been cast.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CastConfMsg {
    pub data: CastConfMsgData,
    pub signature: Signature,
}

// --- Ballot Checking Subprotocol Messages ---
// Defined in `ballot-check-spec.md`

/// The data part of the `CheckReqMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CheckReqMsgData {
    pub election_hash: ElectionHash,
    pub tracker: BallotTracker,
    pub public_enc_key: ElectionKey,
    pub public_sign_key: VerifyingKey,
}

/// Sent from BCA to DBB to request the randomizers for a given ballot.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct CheckReqMsg {
    pub data: CheckReqMsgData,
    pub signature: Signature,
}

/// The data part of the `FwdCheckReqMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct FwdCheckReqMsgData {
    pub election_hash: ElectionHash,
    pub message: CheckReqMsg,
}

/// Sent from DBB to VA, forwarding the BCA's request.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct FwdCheckReqMsg {
    pub data: FwdCheckReqMsgData,
    pub signature: Signature,
}

/// The data part of the `RandomizerMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RandomizerMsgData {
    pub election_hash: ElectionHash,
    pub message: CheckReqMsg,
    pub encrypted_randomizers: RandomizersCryptogram,
    pub public_key: VerifyingKey,
}

/// Sent from VA to DBB, containing randomizers encrypted for the BCA.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RandomizerMsg {
    pub data: RandomizerMsgData,
    pub signature: Signature,
}

/// The data part of the `FwdRandomizerMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct FwdRandomizerMsgData {
    pub election_hash: ElectionHash,
    pub message: RandomizerMsg,
}

/// Sent from DBB to BCA, forwarding the VA's encrypted randomizers.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct FwdRandomizerMsg {
    pub data: FwdRandomizerMsgData,
    pub signature: Signature,
}

// --- Unified Protocol Message Enum ---

/// A single enum to encapsulate all possible protocol messages.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolMessage {
    // Voter Authentication
    AuthReq(AuthReqMsg),
    HandToken(HandTokenMsg),
    AuthFinish(AuthFinishMsg),
    AuthVoter(AuthVoterMsg),
    ConfirmAuthorization(ConfirmAuthorizationMsg),

    // Ballot Submission
    SubmitSignedBallot(SignedBallotMsg),
    ReturnBallotTracker(TrackerMsg),

    // Ballot Casting
    CastReq(CastReqMsg),
    CastConf(CastConfMsg),

    // Ballot Checking
    CheckReq(CheckReqMsg),
    FwdCheckReq(FwdCheckReqMsg),
    Randomizer(RandomizerMsg),
    FwdRandomizer(FwdRandomizerMsg),
}

// --- Testing ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signature_keypair;
    use crate::crypto::{encrypt_ballot, generate_encryption_keypair};
    use crypto::utils::serialization::VSerializable;

    #[test]
    fn test_vserializable_derive_works() {
        // Test that our VSerializable derives actually work
        let (_, verifying_key) = generate_signature_keypair();

        // Create test data
        let auth_data = AuthReqMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election_2024"),
            voter_verifying_key: verifying_key,
        };

        // Test that we can serialize using the derived implementation
        let serialized = auth_data.ser();
        assert!(
            !serialized.is_empty(),
            "Serialized data should not be empty"
        );

        // Test that AuthReqMsg also works
        let auth_msg = AuthReqMsg {
            data: auth_data,
            signature: Signature::from_bytes(&[0u8; 64]), // Dummy signature for test
        };

        let msg_serialized = auth_msg.ser();
        assert!(
            !msg_serialized.is_empty(),
            "Message serialized data should not be empty"
        );
    }

    #[test]
    fn test_vserializable_comprehensive() {
        // Test that VSerializable works on multiple different struct types
        let (_, verifying_key) = generate_signature_keypair();

        // Test HandTokenMsgData
        let hand_token_data = HandTokenMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election_2024"),
            token: "authentication_token_123".to_string(),
            voter_verifying_key: verifying_key,
        };
        let serialized_hand_token = hand_token_data.ser();
        assert!(!serialized_hand_token.is_empty());

        // Test BallotCryptogram with crypto library types
        let context = b"test_election";
        let election_keypair = generate_encryption_keypair(context).unwrap();

        // Create a test ballot and encrypt it
        let ballot = crate::elections::Ballot::test_ballot(1);
        let (ballot_cryptogram, _) = encrypt_ballot(
            ballot,
            &election_keypair.pkey,
            &crate::elections::string_to_election_hash("test_election"),
        )
        .unwrap();
        let serialized_ballot = ballot_cryptogram.ser();
        assert!(!serialized_ballot.is_empty());

        // Test TrackerMsg
        let tracker_data = TrackerMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            tracker: "ballot_tracker_xyz789".to_string(),
        };
        let tracker_msg = TrackerMsg {
            data: tracker_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        let serialized_tracker = tracker_msg.ser();
        assert!(!serialized_tracker.is_empty());

        // Test more complex struct with vectors
        let signed_ballot_data = SignedBallotMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election_2024"),
            voter_pseudonym: "voter_12345".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let serialized_signed_ballot = signed_ballot_data.ser();
        assert!(!serialized_signed_ballot.is_empty());
    }
}
