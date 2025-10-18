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
    BallotCiphertext, BallotCryptogram, BallotProof, ElectionKey, PartialDecryption,
    RandomizersCryptogram, SelectionElement, Signature, VerifyingKey,
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

// --- Setup Subprotocol Messages ---
// Defined in `setup-spec.md`

/// The data part of the `ConfigDistMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfigDistMsgData {
    // We currently represent the election manifest as a String; its
    // contents are dependent upon the implementation using this
    // library.
    pub manifest: String,
    pub trustees: Vec<VerifyingKey>,
}

/// Sent from TAS to Trustee to distribute the election configuration.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfigDistMsg {
    pub data: ConfigDistMsgData,
    pub tas_signature: Signature,
}

/// The data part of the `ConfigEndorsMsg`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfigEndorsMsgData {
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to endorse the election configuration.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ConfigEndorsMsg {
    pub data: ConfigEndorsMsgData,
    pub signature: Signature,
}

// --- Election Key Generation Subprotocol Messages ---
// Defined in `election-key-gen-spec.md`

/// The data part of the `PairwiseShare`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseShareData {
    pub election_hash: ElectionHash,
    pub recipient_public_key: VerifyingKey,
    pub ciphertext: BallotCiphertext,
    pub proof_of_knowledge: BallotProof,
    pub sender_public_key: VerifyingKey,
}

/// Represents a secret share exchanged between two trustees during the
/// distributed key generation protocol.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseShare {
    pub data: PairwiseShareData,
    pub signature: Signature,
}

/// The data part of the `PublicShareSubmissionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicShareSubmissionMessageData {
    pub election_hash: ElectionHash,
    pub public_share: ElectionKey,
    pub proof_of_knowledge: BallotProof,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to submit their public key share.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicShareSubmissionMessage {
    pub data: PublicShareSubmissionMessageData,
    pub signature: Signature,
}

/// Sent from Trustee to TAS to request all submitted public shares.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicSharesRequestMessage {
    pub election_hash: ElectionHash,
    pub public_key: VerifyingKey,
}

/// The data part of the `PublicSharesDistributionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicSharesDistributionMessageData {
    pub election_hash: ElectionHash,
    pub share_list: Vec<PublicShareSubmissionMessage>,
}

/// Sent from TAS to Trustee to distribute all collected public shares.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PublicSharesDistributionMessage {
    pub data: PublicSharesDistributionMessageData,
    pub signature: Signature,
}

/// The data part of the `PairwiseSharesSubmissionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseSharesSubmissionMessageData {
    pub election_hash: ElectionHash,
    pub pairwise_shares: Vec<PairwiseShare>,
    pub sender_public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to submit encrypted pairwise shares for other trustees.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseSharesSubmissionMessage {
    pub data: PairwiseSharesSubmissionMessageData,
    pub signature: Signature,
}

/// Sent from Trustee to TAS to request their own set of pairwise shares.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseSharesRequestMessage {
    pub election_hash: ElectionHash,
    pub public_key: VerifyingKey,
}

/// The data part of the `PairwiseSharesDistributionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseSharesDistributionMessageData {
    pub election_hash: ElectionHash,
    pub recipient_public_key: VerifyingKey,
    pub pairwise_shares: Vec<PairwiseShare>,
}

/// Sent from TAS to Trustee to distribute the pairwise shares intended for them.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct PairwiseSharesDistributionMessage {
    pub data: PairwiseSharesDistributionMessageData,
    pub signature: Signature,
}

/// The data part of the `ElectionKeyConfirmationMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ElectionKeyConfirmationMessageData {
    pub election_hash: ElectionHash,
    pub election_public_key: ElectionKey,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to confirm and endorse the final election public key.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct ElectionKeyConfirmationMessage {
    pub data: ElectionKeyConfirmationMessageData,
    pub signature: Signature,
}

// --- Trustee Mixing Subprotocol Messages ---
// Defined in `trustee-mixing-spec.md`

/// The data part of the `RequestCryptogramsMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestCryptogramsMessageData {
    pub election_hash: ElectionHash,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to request the list of cryptograms to be mixed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestCryptogramsMessage {
    pub data: RequestCryptogramsMessageData,
    pub signature: Signature,
}

/// The data part of the `DistributeCryptogramsMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct DistributeCryptogramsMessageData {
    pub election_hash: ElectionHash,
    pub cryptograms: Vec<BallotCryptogram>,
}

/// Sent from TAS to Trustee to provide the list of cryptograms for mixing.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct DistributeCryptogramsMessage {
    pub data: DistributeCryptogramsMessageData,
    pub signature: Signature,
}

/// The data part of the `SubmitMixedCryptogramsMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitMixedCryptogramsMessageData {
    pub election_hash: ElectionHash,
    pub shuffled_cryptograms: Vec<BallotCryptogram>,
    pub proofs: Vec<BallotProof>, // Shuffle proofs
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS with the shuffled and re-encrypted cryptograms and proofs.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitMixedCryptogramsMessage {
    pub data: SubmitMixedCryptogramsMessageData,
    pub signature: Signature,
}

/// The data part of the `RequestMixedCryptogramsMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestMixedCryptogramsMessageData {
    pub election_hash: ElectionHash,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to request another trustee's mix for peer verification.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestMixedCryptogramsMessage {
    pub data: RequestMixedCryptogramsMessageData,
    pub signature: Signature,
}

/// The data part of the `DistributeMixedCryptogramsMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct DistributeMixedCryptogramsMessageData {
    pub election_hash: ElectionHash,
    pub mix_message: SubmitMixedCryptogramsMessage,
}

/// Sent from TAS to Trustee, distributing a mix for peer verification.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct DistributeMixedCryptogramsMessage {
    pub data: DistributeMixedCryptogramsMessageData,
    pub signature: Signature,
}

// --- Trustee Decryption Subprotocol Messages ---
// Defined in `trustee-decryption-spec.md`

/// The data part of the `RequestPartialDecryptionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestPartialDecryptionMessageData {
    pub election_hash: ElectionHash,
    pub cryptogram_list: Vec<BallotCryptogram>,
}

/// Sent from TAS to Trustee to request partial decryptions of all ballots.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestPartialDecryptionMessage {
    pub data: RequestPartialDecryptionMessageData,
    pub signature: Signature,
}

/// The data part of the `SubmitPartialDecryptionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitPartialDecryptionMessageData {
    pub election_hash: ElectionHash,
    pub partial_decryption_list: Vec<PartialDecryption>,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS with their partial decryptions and proofs.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitPartialDecryptionMessage {
    pub data: SubmitPartialDecryptionMessageData,
    pub signature: Signature,
}

/// The data part of the `RequestVerificationOfPartialDecryptionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestVerificationOfPartialDecryptionMessageData {
    pub election_hash: ElectionHash,
    pub partial_decryption_message_list: Vec<SubmitPartialDecryptionMessage>,
}

/// Sent from TAS to Trustee to distribute all partial decryptions for verification.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct RequestVerificationOfPartialDecryptionMessage {
    pub data: RequestVerificationOfPartialDecryptionMessageData,
    pub signature: Signature,
}

/// The data part of the `SubmitVerificationOfPartialDecryptionMessage`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitVerificationOfPartialDecryptionMessageData {
    pub election_hash: ElectionHash,
    pub ballot_plaintext_list: Vec<SelectionElement>,
    pub public_key: VerifyingKey,
}

/// Sent from Trustee to TAS to attest to the final plaintext results.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct SubmitVerificationOfPartialDecryptionMessage {
    pub data: SubmitVerificationOfPartialDecryptionMessageData,
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

    // Setup
    ConfigDist(ConfigDistMsg),
    ConfigEndors(ConfigEndorsMsg),

    // DKG
    PublicShareSubmission(PublicShareSubmissionMessage),
    PublicSharesRequest(PublicSharesRequestMessage),
    PublicSharesDistribution(PublicSharesDistributionMessage),
    PairwiseSharesSubmission(PairwiseSharesSubmissionMessage),
    PairwiseSharesRequest(PairwiseSharesRequestMessage),
    PairwiseSharesDistribution(PairwiseSharesDistributionMessage),
    ElectionKeyConfirmation(ElectionKeyConfirmationMessage),

    // Mixing
    RequestCryptograms(RequestCryptogramsMessage),
    DistributeCryptograms(DistributeCryptogramsMessage),
    SubmitMixedCryptograms(SubmitMixedCryptogramsMessage),
    RequestMixedCryptograms(RequestMixedCryptogramsMessage),
    DistributeMixedCryptograms(DistributeMixedCryptogramsMessage),

    // Decryption
    RequestPartialDecryption(RequestPartialDecryptionMessage),
    SubmitPartialDecryption(SubmitPartialDecryptionMessage),
    RequestVerificationOfPartialDecryption(RequestVerificationOfPartialDecryptionMessage),
    SubmitVerificationOfPartialDecryption(SubmitVerificationOfPartialDecryptionMessage),
}

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
            1,
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
