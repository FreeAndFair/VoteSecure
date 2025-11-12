/*!
This file defines the storage abstraction for the Digital Ballot Box.

The `DBBStorage` trait provides a storage-agnostic interface for persisting
voter authorizations, submitted ballots, and cast ballots. This allows for
different storage backends (in-memory, database, etc.) without changing
the DBB actor logic.
*/

use crate::elections::{BallotTracker, VoterPseudonym};
use crate::messages::{AuthVoterMsg, SignedBallotMsg};
use std::collections::HashMap;

// =============================================================================
// Storage Trait
// =============================================================================

/// Trait defining the storage interface for the Digital Ballot Box.
///
/// This trait abstracts away the storage implementation, allowing for
/// different backends (in-memory, SQLite, PostgreSQL, etc.) without
/// changing the DBB actor code.
pub trait DBBStorage: Clone + std::fmt::Debug {
    // --- Voter Authorization Operations ---

    /// Store a voter authorization message.
    ///
    /// This overwrites any previous authorization for the same pseudonym,
    /// which is intentional per the protocol - multiple authorizations
    /// can occur but only the most recent is valid.
    fn store_voter_authorization(
        &mut self,
        pseudonym: &VoterPseudonym,
        auth: AuthVoterMsg,
    ) -> Result<(), String>;

    /// Retrieve the current voter authorization for a given pseudonym.
    fn get_voter_authorization(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Option<AuthVoterMsg>, String>;

    // --- Submitted Ballot Operations ---

    /// Store a submitted ballot for a voter.
    ///
    /// Multiple ballots can be submitted by the same voter before casting.
    /// Each submission is stored with its unique tracker.
    fn store_submitted_ballot(
        &mut self,
        pseudonym: &VoterPseudonym,
        tracker: &BallotTracker,
        ballot: SignedBallotMsg,
    ) -> Result<(), String>;

    /// Get all submitted ballots for a voter pseudonym.
    ///
    /// Returns a vector of (tracker, ballot) pairs.
    fn get_submitted_ballots(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Vec<(BallotTracker, SignedBallotMsg)>, String>;

    /// Get the most recent ballot submission for a voter.
    ///
    /// Returns the last submitted ballot and its tracker, or None if
    /// no ballots have been submitted.
    fn get_most_recent_submission(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Option<(BallotTracker, SignedBallotMsg)>, String>;

    /// Get a specific ballot by its tracker.
    fn get_ballot_by_tracker(
        &self,
        tracker: &BallotTracker,
    ) -> Result<Option<SignedBallotMsg>, String>;

    /// Get the voter pseudonym associated with a ballot tracker.
    fn get_pseudonym_by_tracker(
        &self,
        tracker: &BallotTracker,
    ) -> Result<Option<VoterPseudonym>, String>;

    // --- Cast Ballot Operations ---

    /// Store a cast ballot for a voter.
    ///
    /// This can only be called once per voter. Attempting to cast again
    /// should result in an error at the validation layer.
    fn store_cast_ballot(
        &mut self,
        pseudonym: &VoterPseudonym,
        tracker: &BallotTracker,
    ) -> Result<(), String>;

    /// Check if a voter has already cast their ballot.
    fn has_voter_cast(&self, pseudonym: &VoterPseudonym) -> Result<bool, String>;

    /// Get the cast ballot tracker for a voter, if they have cast.
    fn get_cast_ballot(&self, pseudonym: &VoterPseudonym) -> Result<Option<BallotTracker>, String>;
}

// =============================================================================
// In-Memory Storage Implementation
// =============================================================================

/// In-memory implementation of DBBStorage.
///
/// This is the default implementation for development and testing.
/// All data is stored in HashMaps and will be lost when the program exits.
#[derive(Clone, Debug)]
pub struct InMemoryStorage {
    /// Maps voter pseudonyms to their current authorization.
    voter_authorizations: HashMap<VoterPseudonym, AuthVoterMsg>,

    /// Maps voter pseudonyms to their list of submitted ballots.
    /// Each ballot is stored as (tracker, ballot) tuple.
    /// The vector maintains insertion order, so the last element is the most recent.
    submitted_ballots: HashMap<VoterPseudonym, Vec<(BallotTracker, SignedBallotMsg)>>,

    /// Maps ballot trackers to the voter pseudonym that submitted them.
    /// This enables reverse lookup: tracker -> pseudonym.
    tracker_to_pseudonym: HashMap<BallotTracker, VoterPseudonym>,

    /// Maps voter pseudonyms to their cast ballot tracker.
    /// Each voter can only cast once, so this is a simple 1:1 mapping.
    cast_ballots: HashMap<VoterPseudonym, BallotTracker>,
}

impl InMemoryStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self {
            voter_authorizations: HashMap::new(),
            submitted_ballots: HashMap::new(),
            tracker_to_pseudonym: HashMap::new(),
            cast_ballots: HashMap::new(),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl DBBStorage for InMemoryStorage {
    fn store_voter_authorization(
        &mut self,
        pseudonym: &VoterPseudonym,
        auth: AuthVoterMsg,
    ) -> Result<(), String> {
        // Overwrite any existing authorization (this is intentional per the protocol)
        self.voter_authorizations.insert(pseudonym.clone(), auth);
        Ok(())
    }

    fn get_voter_authorization(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Option<AuthVoterMsg>, String> {
        Ok(self.voter_authorizations.get(pseudonym).cloned())
    }

    fn store_submitted_ballot(
        &mut self,
        pseudonym: &VoterPseudonym,
        tracker: &BallotTracker,
        ballot: SignedBallotMsg,
    ) -> Result<(), String> {
        // Add to the voter's list of submitted ballots
        self.submitted_ballots
            .entry(pseudonym.clone())
            .or_default()
            .push((tracker.clone(), ballot));

        // Add reverse mapping: tracker -> pseudonym
        self.tracker_to_pseudonym
            .insert(tracker.clone(), pseudonym.clone());

        Ok(())
    }

    fn get_submitted_ballots(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Vec<(BallotTracker, SignedBallotMsg)>, String> {
        Ok(self
            .submitted_ballots
            .get(pseudonym)
            .cloned()
            .unwrap_or_default())
    }

    fn get_most_recent_submission(
        &self,
        pseudonym: &VoterPseudonym,
    ) -> Result<Option<(BallotTracker, SignedBallotMsg)>, String> {
        Ok(self
            .submitted_ballots
            .get(pseudonym)
            .and_then(|ballots| ballots.last().cloned()))
    }

    fn get_ballot_by_tracker(
        &self,
        tracker: &BallotTracker,
    ) -> Result<Option<SignedBallotMsg>, String> {
        // First find the pseudonym for this tracker
        if let Some(pseudonym) = self.tracker_to_pseudonym.get(tracker) {
            // Then find the ballot in that pseudonym's submissions
            if let Some(ballots) = self.submitted_ballots.get(pseudonym) {
                for (t, ballot) in ballots {
                    if t == tracker {
                        return Ok(Some(ballot.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_pseudonym_by_tracker(
        &self,
        tracker: &BallotTracker,
    ) -> Result<Option<VoterPseudonym>, String> {
        Ok(self.tracker_to_pseudonym.get(tracker).cloned())
    }

    fn store_cast_ballot(
        &mut self,
        pseudonym: &VoterPseudonym,
        tracker: &BallotTracker,
    ) -> Result<(), String> {
        // Check if this voter has already cast
        if self.cast_ballots.contains_key(pseudonym) {
            return Err(format!("Voter {} has already cast a ballot", pseudonym));
        }

        self.cast_ballots.insert(pseudonym.clone(), tracker.clone());
        Ok(())
    }

    fn has_voter_cast(&self, pseudonym: &VoterPseudonym) -> Result<bool, String> {
        Ok(self.cast_ballots.contains_key(pseudonym))
    }

    fn get_cast_ballot(&self, pseudonym: &VoterPseudonym) -> Result<Option<BallotTracker>, String> {
        Ok(self.cast_ballots.get(pseudonym).cloned())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signature_keypair;
    use crate::elections::{BallotStyle, string_to_election_hash};
    use crate::messages::{AuthVoterMsgData, SignedBallotMsgData};

    fn create_test_auth_msg(pseudonym: &str, ballot_style: BallotStyle) -> AuthVoterMsg {
        let (_, verifying_key) = generate_signature_keypair();
        let data = AuthVoterMsgData {
            election_hash: string_to_election_hash("test_election"),
            voter_pseudonym: pseudonym.to_string(),
            voter_verifying_key: verifying_key,
            ballot_style,
        };
        let signature = crate::crypto::Signature::from_bytes(&[0u8; 64]);
        AuthVoterMsg { data, signature }
    }

    fn create_test_ballot(pseudonym: &str) -> SignedBallotMsg {
        let (_, verifying_key) = generate_signature_keypair();
        let election_keypair = crate::crypto::generate_encryption_keypair(b"test_context").unwrap();
        let ballot = crate::elections::Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = crate::crypto::encrypt_ballot(
            ballot,
            &election_keypair.pkey,
            &string_to_election_hash("test_election"),
        )
        .unwrap();

        let data = SignedBallotMsgData {
            election_hash: string_to_election_hash("test_election"),
            voter_pseudonym: pseudonym.to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };
        let signature = crate::crypto::Signature::from_bytes(&[0u8; 64]);
        SignedBallotMsg { data, signature }
    }

    #[test]
    fn test_voter_authorization_storage() {
        let mut storage = InMemoryStorage::new();
        let auth_msg = create_test_auth_msg("voter123", 1);

        // Store authorization
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg.clone())
            .unwrap();

        // Retrieve authorization
        let retrieved = storage
            .get_voter_authorization(&"voter123".to_string())
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data.voter_pseudonym, "voter123");
    }

    #[test]
    fn test_authorization_overwrite() {
        let mut storage = InMemoryStorage::new();
        let auth_msg1 = create_test_auth_msg("voter123", 1);
        let auth_msg2 = create_test_auth_msg("voter123", 2);

        // Store first authorization
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg1)
            .unwrap();

        // Overwrite with second authorization
        storage
            .store_voter_authorization(&"voter123".to_string(), auth_msg2.clone())
            .unwrap();

        // Should retrieve the second one
        let retrieved = storage
            .get_voter_authorization(&"voter123".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.data.ballot_style, 2);
    }

    #[test]
    fn test_submitted_ballot_storage() {
        let mut storage = InMemoryStorage::new();
        let ballot = create_test_ballot("voter123");
        let tracker = "tracker_abc".to_string();

        // Store ballot
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker, ballot.clone())
            .unwrap();

        // Retrieve by pseudonym
        let ballots = storage
            .get_submitted_ballots(&"voter123".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 1);
        assert_eq!(ballots[0].0, "tracker_abc");

        // Retrieve by tracker
        let retrieved = storage.get_ballot_by_tracker(&tracker).unwrap();
        assert!(retrieved.is_some());

        // Retrieve pseudonym by tracker
        let pseudonym = storage.get_pseudonym_by_tracker(&tracker).unwrap();
        assert_eq!(pseudonym.unwrap(), "voter123");
    }

    #[test]
    fn test_multiple_submissions() {
        let mut storage = InMemoryStorage::new();
        let ballot1 = create_test_ballot("voter123");
        let ballot2 = create_test_ballot("voter123");
        let tracker1 = "tracker_1".to_string();
        let tracker2 = "tracker_2".to_string();

        // Store two ballots
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker1, ballot1)
            .unwrap();
        storage
            .store_submitted_ballot(&"voter123".to_string(), &tracker2, ballot2)
            .unwrap();

        // Should have two submissions
        let ballots = storage
            .get_submitted_ballots(&"voter123".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 2);

        // Most recent should be the second one
        let most_recent = storage
            .get_most_recent_submission(&"voter123".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(most_recent.0, "tracker_2");
    }

    #[test]
    fn test_cast_ballot_storage() {
        let mut storage = InMemoryStorage::new();
        let tracker = "tracker_abc".to_string();

        // Store cast ballot
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker)
            .unwrap();

        // Check if voter has cast
        assert!(storage.has_voter_cast(&"voter123".to_string()).unwrap());

        // Retrieve cast ballot tracker
        let cast_tracker = storage
            .get_cast_ballot(&"voter123".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(cast_tracker, "tracker_abc");
    }

    #[test]
    fn test_cannot_cast_twice() {
        let mut storage = InMemoryStorage::new();
        let tracker1 = "tracker_1".to_string();
        let tracker2 = "tracker_2".to_string();

        // First cast succeeds
        storage
            .store_cast_ballot(&"voter123".to_string(), &tracker1)
            .unwrap();

        // Second cast should fail
        let result = storage.store_cast_ballot(&"voter123".to_string(), &tracker2);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonexistent_voter() {
        let storage = InMemoryStorage::new();

        // Should return None for nonexistent voter
        let auth = storage
            .get_voter_authorization(&"nonexistent".to_string())
            .unwrap();
        assert!(auth.is_none());

        let ballots = storage
            .get_submitted_ballots(&"nonexistent".to_string())
            .unwrap();
        assert!(ballots.is_empty());

        assert!(!storage.has_voter_cast(&"nonexistent".to_string()).unwrap());
    }

    // =============================================================================
    // Edge Case Tests
    // =============================================================================

    #[test]
    fn test_empty_string_pseudonym() {
        let mut storage = InMemoryStorage::new();
        let auth_msg = create_test_auth_msg("", 1);

        // Empty pseudonym should be valid (edge case)
        storage
            .store_voter_authorization(&"".to_string(), auth_msg.clone())
            .unwrap();

        let retrieved = storage.get_voter_authorization(&"".to_string()).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_very_long_pseudonym() {
        let mut storage = InMemoryStorage::new();
        let long_pseudonym = "a".repeat(10000);
        let auth_msg = create_test_auth_msg(&long_pseudonym, 1);

        storage
            .store_voter_authorization(&long_pseudonym, auth_msg)
            .unwrap();

        let retrieved = storage.get_voter_authorization(&long_pseudonym).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_special_characters_in_pseudonym() {
        let mut storage = InMemoryStorage::new();
        let special_pseudonym = "voter!@#$%^&*()_+-={}[]|:;<>?,./~`";
        let auth_msg = create_test_auth_msg(special_pseudonym, 1);

        storage
            .store_voter_authorization(&special_pseudonym.to_string(), auth_msg)
            .unwrap();

        let retrieved = storage
            .get_voter_authorization(&special_pseudonym.to_string())
            .unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_unicode_pseudonym() {
        let mut storage = InMemoryStorage::new();
        let unicode_pseudonym = "voter_日本語_🎉_αβγ";
        let auth_msg = create_test_auth_msg(unicode_pseudonym, 1);

        storage
            .store_voter_authorization(&unicode_pseudonym.to_string(), auth_msg)
            .unwrap();

        let retrieved = storage
            .get_voter_authorization(&unicode_pseudonym.to_string())
            .unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_get_ballot_by_nonexistent_tracker() {
        let storage = InMemoryStorage::new();
        let result = storage
            .get_ballot_by_tracker(&"nonexistent_tracker".to_string())
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_pseudonym_by_nonexistent_tracker() {
        let storage = InMemoryStorage::new();
        let result = storage
            .get_pseudonym_by_tracker(&"nonexistent_tracker".to_string())
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_most_recent_submission_with_no_submissions() {
        let storage = InMemoryStorage::new();
        let result = storage
            .get_most_recent_submission(&"voter123".to_string())
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_cast_ballot_for_uncasted_voter() {
        let storage = InMemoryStorage::new();
        let result = storage.get_cast_ballot(&"voter123".to_string()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_voters_concurrent_operations() {
        let mut storage = InMemoryStorage::new();

        // Store authorizations for multiple voters
        for i in 0..100 {
            let pseudonym = format!("voter_{}", i);
            let auth_msg = create_test_auth_msg(&pseudonym, 1);
            storage
                .store_voter_authorization(&pseudonym, auth_msg)
                .unwrap();
        }

        // Verify all authorizations exist
        for i in 0..100 {
            let pseudonym = format!("voter_{}", i);
            let auth = storage.get_voter_authorization(&pseudonym).unwrap();
            assert!(auth.is_some());
        }

        // Store ballots for each voter
        for i in 0..100 {
            let pseudonym = format!("voter_{}", i);
            let ballot = create_test_ballot(&pseudonym);
            let tracker = format!("tracker_{}", i);
            storage
                .store_submitted_ballot(&pseudonym, &tracker, ballot)
                .unwrap();
        }

        // Verify all ballots exist
        for i in 0..100 {
            let pseudonym = format!("voter_{}", i);
            let ballots = storage.get_submitted_ballots(&pseudonym).unwrap();
            assert_eq!(ballots.len(), 1);
        }
    }

    #[test]
    fn test_duplicate_tracker_different_voters() {
        let mut storage = InMemoryStorage::new();
        let ballot1 = create_test_ballot("voter1");
        let ballot2 = create_test_ballot("voter2");
        let tracker = "same_tracker".to_string();

        // First voter stores ballot with tracker
        storage
            .store_submitted_ballot(&"voter1".to_string(), &tracker, ballot1)
            .unwrap();

        // Second voter tries to store ballot with same tracker
        // This should succeed (different voters can theoretically have same tracker if bulletin board allows)
        // But get_ballot_by_tracker will return the first one
        storage
            .store_submitted_ballot(&"voter2".to_string(), &tracker, ballot2)
            .unwrap();

        // The tracker map only stores one mapping (last one wins)
        let pseudonym = storage.get_pseudonym_by_tracker(&tracker).unwrap();
        assert!(pseudonym.is_some());
    }

    #[test]
    fn test_ballot_style_boundary_values() {
        let mut storage = InMemoryStorage::new();

        // Test with ballot_style = 0
        let auth_msg_zero = create_test_auth_msg("voter_zero", 0);
        storage
            .store_voter_authorization(&"voter_zero".to_string(), auth_msg_zero)
            .unwrap();

        // Test with ballot_style = 255 (max u8)
        let auth_msg_max = create_test_auth_msg("voter_max", 255);
        storage
            .store_voter_authorization(&"voter_max".to_string(), auth_msg_max)
            .unwrap();

        let retrieved_zero = storage
            .get_voter_authorization(&"voter_zero".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_zero.data.ballot_style, 0);

        let retrieved_max = storage
            .get_voter_authorization(&"voter_max".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_max.data.ballot_style, 255);
    }

    #[test]
    fn test_many_submissions_same_voter() {
        let mut storage = InMemoryStorage::new();

        // Store 1000 ballot submissions for the same voter
        for i in 0..1000 {
            let ballot = create_test_ballot("prolific_voter");
            let tracker = format!("tracker_{}", i);
            storage
                .store_submitted_ballot(&"prolific_voter".to_string(), &tracker, ballot)
                .unwrap();
        }

        // Should have all 1000 submissions
        let ballots = storage
            .get_submitted_ballots(&"prolific_voter".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 1000);

        // Most recent should be the last one
        let most_recent = storage
            .get_most_recent_submission(&"prolific_voter".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(most_recent.0, "tracker_999");
    }

    // =============================================================================
    // Race Condition Tests
    // =============================================================================

    #[test]
    fn test_rapid_submission_updates_same_voter() {
        let mut storage = InMemoryStorage::new();
        let ballot1 = create_test_ballot("voter1");
        let ballot2 = create_test_ballot("voter1");
        let ballot3 = create_test_ballot("voter1");

        // Rapidly submit three ballots for the same voter
        storage
            .store_submitted_ballot(&"voter1".to_string(), &"tracker_1".to_string(), ballot1)
            .unwrap();
        storage
            .store_submitted_ballot(&"voter1".to_string(), &"tracker_2".to_string(), ballot2)
            .unwrap();
        storage
            .store_submitted_ballot(&"voter1".to_string(), &"tracker_3".to_string(), ballot3)
            .unwrap();

        // All three should be stored
        let ballots = storage
            .get_submitted_ballots(&"voter1".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 3);

        // Most recent should be tracker_3
        let most_recent = storage
            .get_most_recent_submission(&"voter1".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(most_recent.0, "tracker_3");
    }

    #[test]
    fn test_cast_after_multiple_submissions() {
        let mut storage = InMemoryStorage::new();

        // Submit multiple ballots
        for i in 0..5 {
            let ballot = create_test_ballot("voter_cast");
            let tracker = format!("tracker_{}", i);
            storage
                .store_submitted_ballot(&"voter_cast".to_string(), &tracker, ballot)
                .unwrap();
        }

        // Cast the most recent one
        storage
            .store_cast_ballot(&"voter_cast".to_string(), &"tracker_4".to_string())
            .unwrap();

        // Verify cast status
        assert!(storage.has_voter_cast(&"voter_cast".to_string()).unwrap());

        // All submissions should still be accessible
        let ballots = storage
            .get_submitted_ballots(&"voter_cast".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 5);
    }

    #[test]
    fn test_authorization_overwrite_scenario() {
        let mut storage = InMemoryStorage::new();

        // Initial authorization
        let auth1 = create_test_auth_msg("voter_auth", 1);
        storage
            .store_voter_authorization(&"voter_auth".to_string(), auth1)
            .unwrap();

        // Update authorization (simulating re-authorization with different ballot style)
        let auth2 = create_test_auth_msg("voter_auth", 2);
        storage
            .store_voter_authorization(&"voter_auth".to_string(), auth2)
            .unwrap();

        // Should have the updated authorization
        let retrieved = storage
            .get_voter_authorization(&"voter_auth".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.data.ballot_style, 2);
    }

    #[test]
    fn test_interleaved_operations_multiple_voters() {
        let mut storage = InMemoryStorage::new();

        // Interleave authorization and ballot operations for multiple voters
        let auth_a = create_test_auth_msg("voter_a", 1);
        storage
            .store_voter_authorization(&"voter_a".to_string(), auth_a)
            .unwrap();

        let ballot_a1 = create_test_ballot("voter_a");
        storage
            .store_submitted_ballot(&"voter_a".to_string(), &"tracker_a1".to_string(), ballot_a1)
            .unwrap();

        let auth_b = create_test_auth_msg("voter_b", 2);
        storage
            .store_voter_authorization(&"voter_b".to_string(), auth_b)
            .unwrap();

        let ballot_a2 = create_test_ballot("voter_a");
        storage
            .store_submitted_ballot(&"voter_a".to_string(), &"tracker_a2".to_string(), ballot_a2)
            .unwrap();

        let ballot_b1 = create_test_ballot("voter_b");
        storage
            .store_submitted_ballot(&"voter_b".to_string(), &"tracker_b1".to_string(), ballot_b1)
            .unwrap();

        storage
            .store_cast_ballot(&"voter_a".to_string(), &"tracker_a2".to_string())
            .unwrap();

        let auth_c = create_test_auth_msg("voter_c", 3);
        storage
            .store_voter_authorization(&"voter_c".to_string(), auth_c)
            .unwrap();

        storage
            .store_cast_ballot(&"voter_b".to_string(), &"tracker_b1".to_string())
            .unwrap();

        // Verify all state is correct
        assert!(storage.has_voter_cast(&"voter_a".to_string()).unwrap());
        assert!(storage.has_voter_cast(&"voter_b".to_string()).unwrap());
        assert!(!storage.has_voter_cast(&"voter_c".to_string()).unwrap());

        assert_eq!(
            storage
                .get_submitted_ballots(&"voter_a".to_string())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            storage
                .get_submitted_ballots(&"voter_b".to_string())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_double_cast_attempt() {
        let mut storage = InMemoryStorage::new();
        let ballot = create_test_ballot("voter_double");

        storage
            .store_submitted_ballot(
                &"voter_double".to_string(),
                &"tracker_double".to_string(),
                ballot,
            )
            .unwrap();

        // First cast should succeed
        storage
            .store_cast_ballot(&"voter_double".to_string(), &"tracker_double".to_string())
            .unwrap();
        assert!(storage.has_voter_cast(&"voter_double".to_string()).unwrap());

        // Second cast attempt should fail (storage validates this)
        let result =
            storage.store_cast_ballot(&"voter_double".to_string(), &"tracker_double".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already cast"));
    }

    #[test]
    fn test_submission_after_cast_flag_set() {
        let mut storage = InMemoryStorage::new();
        let ballot1 = create_test_ballot("voter_post_cast");

        // Submit and cast
        storage
            .store_submitted_ballot(
                &"voter_post_cast".to_string(),
                &"tracker_1".to_string(),
                ballot1,
            )
            .unwrap();
        storage
            .store_cast_ballot(&"voter_post_cast".to_string(), &"tracker_1".to_string())
            .unwrap();

        // Attempt to submit another ballot after cast flag is set
        // Storage layer allows this (validation is at actor level)
        let ballot2 = create_test_ballot("voter_post_cast");
        storage
            .store_submitted_ballot(
                &"voter_post_cast".to_string(),
                &"tracker_2".to_string(),
                ballot2,
            )
            .unwrap();

        // Should have two submissions and cast flag still set
        let ballots = storage
            .get_submitted_ballots(&"voter_post_cast".to_string())
            .unwrap();
        assert_eq!(ballots.len(), 2);
        assert!(
            storage
                .has_voter_cast(&"voter_post_cast".to_string())
                .unwrap()
        );
    }
}
