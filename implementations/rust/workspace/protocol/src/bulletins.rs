/*!
This file defines the structures for all entries that can be posted to the
Public Bulletin Board (PBB).
*/

// TODO: consider boxing structs in large enum variants to improve performance
// currently ignored for code simplicity until performance data is analyzed
#![allow(clippy::large_enum_variant)]

use crate::elections::ElectionHash;
use crate::messages::{AuthVoterMsg, CastReqMsg, SignedBallotMsg};
use vser_derive::VSerializable;

// --- Bulletin Board Structures ---

/// The data part of the `BallotSubBulletin`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotSubBulletinData {
    pub election_hash: ElectionHash,
    /// Unix timestamp in seconds since epoch (SystemTime::UNIX_EPOCH).
    /// Created by the DBB when the bulletin is posted to the bulletin board.
    /// The DBB guarantees monotonic ordering of timestamps for "happened before" relationships.
    /// The protocol does not rely on wall clock times for security properties.
    pub timestamp: u64,
    pub ballot: SignedBallotMsg,
    pub previous_bb_msg_hash: String,
}

/// Represents the submission of an encrypted ballot to the bulletin board.
/// Defined in `ballot-submission-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotSubBulletin {
    pub data: BallotSubBulletinData,
    pub signature: String,
}

/// The data part of the `VoterAuthBulletin`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct VoterAuthBulletinData {
    pub election_hash: ElectionHash,
    pub timestamp: u64,
    pub authorization: AuthVoterMsg,
    pub previous_bb_msg_hash: String,
}

/// Represents the publication of a voter's authorization to the bulletin board.
/// Defined in `ballot-cast-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct VoterAuthBulletin {
    pub data: VoterAuthBulletinData,
    pub signature: String,
}

/// The data part of the `BallotCastBulletin`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotCastBulletinData {
    pub election_hash: ElectionHash,
    pub timestamp: u64,
    pub ballot: SignedBallotMsg,
    pub cast_intent: CastReqMsg,
    pub previous_bb_msg_hash: String,
}

/// Represents the official casting of a ballot on the bulletin board.
/// Defined in `ballot-cast-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotCastBulletin {
    pub data: BallotCastBulletinData,
    pub signature: String,
}

// --- Unified Bulletin Enum ---

/// A single enum to encapsulate all possible bulletin board entries.
#[derive(Debug, Clone, PartialEq)]
pub enum Bulletin {
    BallotSubmission(BallotSubBulletin),
    VoterAuthorization(VoterAuthBulletin),
    BallotCast(BallotCastBulletin),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signature_keypair;
    use crate::crypto::{BallotCryptogram, Signature};
    use crate::messages::{AuthVoterMsgData, CastReqMsgData, SignedBallotMsgData};
    use crypto::utils::serialization::VSerializable;

    #[test]
    fn test_bulletin_vserializable() {
        // Test that VSerializable works on bulletin structures
        let (_, verifying_key) = generate_signature_keypair();

        // Create test message data
        let auth_voter_data = AuthVoterMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
        };
        let auth_voter_msg = crate::messages::AuthVoterMsg {
            data: auth_voter_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let signed_ballot_data = SignedBallotMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram: BallotCryptogram {
                ballot_style: 1,
                // Create a dummy ciphertext for testing
                ciphertext: {
                    use crate::crypto::{BALLOT_CIPHERTEXT_WIDTH, CryptoContext};
                    use crypto::context::Context;
                    use crypto::cryptosystem::naoryung::Ciphertext as NYCiphertext;
                    use crypto::traits::groups::{GroupElement, GroupScalar};

                    // Create dummy components for the ciphertext
                    let dummy_element = <CryptoContext as Context>::Element::one();
                    let dummy_scalar = <CryptoContext as Context>::Scalar::zero();
                    let u_b = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];
                    let v_b = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];
                    let u_a = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];

                    // Create a dummy PlEq proof with correct width
                    let dummy_proof = {
                        use crypto::zkp::pleq::PlEqProof;
                        let big_a = [
                            [dummy_element; BALLOT_CIPHERTEXT_WIDTH],
                            [dummy_element; BALLOT_CIPHERTEXT_WIDTH],
                        ];
                        let k = [dummy_scalar; BALLOT_CIPHERTEXT_WIDTH];
                        PlEqProof::new(big_a, k)
                    };

                    NYCiphertext {
                        u_b,
                        v_b,
                        u_a,
                        proof: dummy_proof,
                    }
                },
            },
        };
        let signed_ballot_msg = crate::messages::SignedBallotMsg {
            data: signed_ballot_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let cast_req_data = CastReqMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_tracker: "tracker_123".to_string(),
        };
        let cast_req_msg = crate::messages::CastReqMsg {
            data: cast_req_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        // Test BallotSubBulletinData
        let ballot_sub_data = BallotSubBulletinData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            timestamp: 1640995200,
            ballot: signed_ballot_msg.clone(),
            previous_bb_msg_hash: "previous_hash_123".to_string(),
        };
        let serialized_ballot_sub = ballot_sub_data.ser();
        assert!(!serialized_ballot_sub.is_empty());

        // Test BallotSubBulletin
        let ballot_sub_bulletin = BallotSubBulletin {
            data: ballot_sub_data,
            signature: "bulletin_signature".to_string(),
        };
        let serialized_bulletin = ballot_sub_bulletin.ser();
        assert!(!serialized_bulletin.is_empty());

        // Test VoterAuthBulletinData
        let voter_auth_data = VoterAuthBulletinData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            timestamp: 1640995200,
            authorization: auth_voter_msg,
            previous_bb_msg_hash: "previous_hash_456".to_string(),
        };
        let serialized_voter_auth = voter_auth_data.ser();
        assert!(!serialized_voter_auth.is_empty());

        // Test BallotCastBulletinData
        let ballot_cast_data = BallotCastBulletinData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            timestamp: 1640995200,
            ballot: signed_ballot_msg,
            cast_intent: cast_req_msg,
            previous_bb_msg_hash: "previous_hash_789".to_string(),
        };
        let serialized_ballot_cast = ballot_cast_data.ser();
        assert!(!serialized_ballot_cast.is_empty());
    }
}
