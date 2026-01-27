// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file defines the bulletin board abstraction for the Digital Ballot Box.
//!
//! The `BulletinBoard` trait provides a storage-agnostic interface for maintaining
//! the tamper-evident chain of bulletins. Each bulletin is linked to the previous
//! one via cryptographic hash, creating an immutable audit trail.

use crate::bulletins::Bulletin;
use crate::cryptography::{Digest, Hasher256, OldHasher, VSerializable};
use crate::elections::{BallotTracker, VoterPseudonym};
use std::collections::HashMap;

// =============================================================================
// Bulletin Board Trait
// =============================================================================

/// Trait defining the bulletin board interface for the Digital Ballot Box.
///
/// The bulletin board maintains a tamper-evident chain of bulletins where
/// each bulletin contains a hash of the previous bulletin, creating an
/// immutable audit trail.
pub trait BulletinBoard: Clone + std::fmt::Debug {
    /// Append a signed bulletin to the board.
    ///
    /// The DBB has already signed the bulletin before passing it here.
    /// This method validates the previous_hash matches the last bulletin,
    /// computes the hash of this bulletin (which becomes its tracker),
    /// stores the bulletin, and returns the tracker.
    ///
    /// # Arguments
    /// * `bulletin` - The signed bulletin to append
    ///
    /// # Returns
    /// * `Ok(tracker)` - The hash/tracker of the appended bulletin
    /// * `Err(msg)` - If validation fails
    fn append_bulletin(&mut self, bulletin: Bulletin) -> Result<BallotTracker, String>;

    /// Get a bulletin by its tracker (hash).
    ///
    /// # Arguments
    /// * `tracker` - The hash/tracker of the bulletin to retrieve
    ///
    /// # Returns
    /// * `Ok(Some(bulletin))` - If found
    /// * `Ok(None)` - If not found
    /// * `Err(msg)` - If an error occurs
    fn get_bulletin(&self, tracker: &BallotTracker) -> Result<Option<Bulletin>, String>;

    /// Get all bulletins in order.
    ///
    /// Returns a vector of all bulletins in the order they were appended.
    fn get_all_bulletins(&self) -> Vec<Bulletin>;

    /// Get bulletins of a specific type.
    ///
    /// # Arguments
    /// * `bulletin_type` - The type of bulletins to retrieve
    ///
    /// # Returns
    /// A vector of bulletins matching the specified type
    fn get_bulletins_by_type(&self, bulletin_type: BulletinType) -> Vec<Bulletin>;

    /// Get bulletins associated with a specific voter pseudonym.
    ///
    /// # Arguments
    /// * `voter_pseudonym` - The pseudonym to retrieve
    ///
    /// # Returns
    /// A vector of bulletins matching the specified pseudonym, in
    /// the order in which they appear on the bulletin board.
    fn get_bulletins_by_pseudonym(&self, voter_pseudonym: VoterPseudonym) -> Vec<Bulletin>;

    /// Get the hash of the most recent bulletin.
    ///
    /// This is used for chaining - the next bulletin should reference
    /// this hash in its previous_bb_msg_hash field.
    ///
    /// # Returns
    /// * `Some(hash)` - If there are any bulletins
    /// * `None` - If the board is empty
    fn get_last_bulletin_hash(&self) -> Option<String>;

    /// Validate the entire bulletin chain.
    ///
    /// Checks that each bulletin's previous_bb_msg_hash correctly
    /// matches the hash of the actual previous bulletin.
    ///
    /// # Returns
    /// * `Ok(())` - If the chain is valid
    /// * `Err(msg)` - If validation fails
    fn validate_chain(&self) -> Result<(), String>;
}

/// Types of bulletins that can be posted to the bulletin board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulletinType {
    BallotSubmission,
    VoterAuthorization,
    BallotCast,
}

// =============================================================================
// In-Memory Bulletin Board Implementation
// =============================================================================

/// In-memory implementation of the bulletin board.
///
/// This stores all bulletins in a vector (maintaining order) and
/// provides a hash index for fast lookup by tracker.
#[derive(Clone, Debug)]
pub struct InMemoryBulletinBoard {
    /// All bulletins in order
    bulletins: Vec<Bulletin>,

    /// Maps bulletin trackers (hashes) to their index in the bulletins vector
    bulletin_hashes: HashMap<BallotTracker, usize>,
}

impl InMemoryBulletinBoard {
    /// Create a new empty bulletin board.
    pub fn new() -> Self {
        Self {
            bulletins: Vec::new(),
            bulletin_hashes: HashMap::new(),
        }
    }

    /// Compute the SHA3-256 hash of a bulletin.
    ///
    /// This hash serves as the bulletin's unique tracker.
    ///
    /// # Arguments
    /// * `bulletin` - The bulletin to hash
    ///
    /// # Returns
    /// A hex-encoded SHA3-256 hash string
    fn compute_bulletin_hash(&self, bulletin: &Bulletin) -> String {
        let serialized = match bulletin {
            Bulletin::BallotSubmission(b) => b.ser(),
            Bulletin::VoterAuthorization(b) => b.ser(),
            Bulletin::BallotCast(b) => b.ser(),
        };

        let mut hasher = Hasher256::hasher();
        hasher.update(&serialized);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Get the previous_bb_msg_hash field from a bulletin.
    fn get_previous_hash<'a>(&self, bulletin: &'a Bulletin) -> &'a String {
        match bulletin {
            Bulletin::BallotSubmission(b) => &b.data.previous_bb_msg_hash,
            Bulletin::VoterAuthorization(b) => &b.data.previous_bb_msg_hash,
            Bulletin::BallotCast(b) => &b.data.previous_bb_msg_hash,
        }
    }
}

impl Default for InMemoryBulletinBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl BulletinBoard for InMemoryBulletinBoard {
    fn append_bulletin(&mut self, bulletin: Bulletin) -> Result<BallotTracker, String> {
        // Validate that previous_hash matches the last bulletin's hash
        let expected_previous_hash = self.get_last_bulletin_hash().unwrap_or_default();
        let actual_previous_hash = self.get_previous_hash(&bulletin);

        if *actual_previous_hash != expected_previous_hash {
            return Err(format!(
                "Previous bulletin hash mismatch: expected '{}', got '{}'",
                expected_previous_hash, actual_previous_hash
            ));
        }

        // Compute the hash of this bulletin (this becomes its tracker)
        let tracker = self.compute_bulletin_hash(&bulletin);

        // Store the bulletin
        let index = self.bulletins.len();
        self.bulletins.push(bulletin);
        self.bulletin_hashes.insert(tracker.clone(), index);

        Ok(tracker)
    }

    fn get_bulletin(&self, tracker: &BallotTracker) -> Result<Option<Bulletin>, String> {
        Ok(self
            .bulletin_hashes
            .get(tracker)
            .and_then(|&index| self.bulletins.get(index).cloned()))
    }

    fn get_all_bulletins(&self) -> Vec<Bulletin> {
        self.bulletins.clone()
    }

    fn get_bulletins_by_type(&self, bulletin_type: BulletinType) -> Vec<Bulletin> {
        self.bulletins
            .iter()
            .filter(|b| {
                matches!(
                    (bulletin_type, b),
                    (
                        BulletinType::BallotSubmission,
                        Bulletin::BallotSubmission(_)
                    ) | (
                        BulletinType::VoterAuthorization,
                        Bulletin::VoterAuthorization(_)
                    ) | (BulletinType::BallotCast, Bulletin::BallotCast(_))
                )
            })
            .cloned()
            .collect()
    }

    fn get_bulletins_by_pseudonym(&self, voter_pseudonym: VoterPseudonym) -> Vec<Bulletin> {
        self.bulletins
            .iter()
            .filter(|b| match b {
                Bulletin::BallotSubmission(bs) => {
                    bs.data.ballot.data.voter_pseudonym == voter_pseudonym
                }
                Bulletin::BallotCast(bc) => bc.data.ballot.data.voter_pseudonym == voter_pseudonym,
                Bulletin::VoterAuthorization(va) => {
                    va.data.authorization.data.voter_pseudonym == voter_pseudonym
                }
            })
            .cloned()
            .collect()
    }

    fn get_last_bulletin_hash(&self) -> Option<String> {
        self.bulletins
            .last()
            .map(|bulletin| self.compute_bulletin_hash(bulletin))
    }

    fn validate_chain(&self) -> Result<(), String> {
        if self.bulletins.is_empty() {
            return Ok(()); // Empty chain is valid
        }

        // First bulletin should have empty previous_hash
        let first_previous_hash = self.get_previous_hash(&self.bulletins[0]);
        if !first_previous_hash.is_empty() {
            return Err(format!(
                "First bulletin should have empty previous_hash, got '{}'",
                first_previous_hash
            ));
        }

        // Check each subsequent bulletin
        for i in 1..self.bulletins.len() {
            let expected_previous_hash = self.compute_bulletin_hash(&self.bulletins[i - 1]);
            let actual_previous_hash = self.get_previous_hash(&self.bulletins[i]);

            if *actual_previous_hash != expected_previous_hash {
                return Err(format!(
                    "Chain validation failed at index {}: expected previous_hash '{}', got '{}'",
                    i, expected_previous_hash, actual_previous_hash
                ));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletins::{BallotSubBulletin, BallotSubBulletinData};
    use crate::cryptography::{Signature, generate_signature_keypair};
    use crate::elections::string_to_election_hash;
    use crate::messages::SignedBallotMsgData;

    fn create_test_ballot_submission(previous_hash: String) -> Bulletin {
        let (_, verifying_key) = generate_signature_keypair();
        let election_keypair =
            crate::cryptography::generate_encryption_keypair(b"test_context").unwrap();
        let ballot = crate::elections::Ballot::test_ballot(12345);
        let (ballot_cryptogram, _) = crate::cryptography::encrypt_ballot(
            ballot,
            &election_keypair.pkey,
            &string_to_election_hash("test_election"),
            &"voter123".to_string(),
        )
        .unwrap();

        let ballot_msg_data = SignedBallotMsgData {
            election_hash: string_to_election_hash("test_election"),
            voter_pseudonym: "voter123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram,
        };

        let ballot_msg = crate::messages::SignedBallotMsg {
            data: ballot_msg_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let data = BallotSubBulletinData {
            election_hash: string_to_election_hash("test_election"),
            timestamp: 1640995200,
            ballot: ballot_msg,
            previous_bb_msg_hash: previous_hash,
        };

        Bulletin::BallotSubmission(BallotSubBulletin {
            data,
            signature: "test_signature".to_string(),
        })
    }

    #[test]
    fn test_empty_bulletin_board() {
        let board = InMemoryBulletinBoard::new();

        assert!(board.get_all_bulletins().is_empty());
        assert!(board.get_last_bulletin_hash().is_none());
        assert!(board.validate_chain().is_ok());
    }

    #[test]
    fn test_append_first_bulletin() {
        let mut board = InMemoryBulletinBoard::new();
        let bulletin = create_test_ballot_submission(String::new());

        let tracker = board.append_bulletin(bulletin.clone()).unwrap();

        assert!(!tracker.is_empty());
        assert_eq!(board.get_all_bulletins().len(), 1);
        assert_eq!(board.get_last_bulletin_hash().unwrap(), tracker);
    }

    #[test]
    fn test_append_multiple_bulletins() {
        let mut board = InMemoryBulletinBoard::new();

        // First bulletin with empty previous hash
        let bulletin1 = create_test_ballot_submission(String::new());
        let tracker1 = board.append_bulletin(bulletin1).unwrap();

        // Second bulletin with previous hash = tracker1
        let bulletin2 = create_test_ballot_submission(tracker1.clone());
        let tracker2 = board.append_bulletin(bulletin2).unwrap();

        // Third bulletin with previous hash = tracker2
        let bulletin3 = create_test_ballot_submission(tracker2.clone());
        let tracker3 = board.append_bulletin(bulletin3).unwrap();

        assert_eq!(board.get_all_bulletins().len(), 3);
        assert_eq!(board.get_last_bulletin_hash().unwrap(), tracker3);
    }

    #[test]
    fn test_get_bulletin_by_tracker() {
        let mut board = InMemoryBulletinBoard::new();
        let bulletin = create_test_ballot_submission(String::new());
        let tracker = board.append_bulletin(bulletin.clone()).unwrap();

        let retrieved = board.get_bulletin(&tracker).unwrap();
        assert!(retrieved.is_some());

        // Non-existent tracker should return None
        let nonexistent = board.get_bulletin(&"nonexistent".to_string()).unwrap();
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_invalid_previous_hash() {
        let mut board = InMemoryBulletinBoard::new();

        // First bulletin succeeds
        let bulletin1 = create_test_ballot_submission(String::new());
        board.append_bulletin(bulletin1).unwrap();

        // Second bulletin with wrong previous hash should fail
        let bulletin2 = create_test_ballot_submission("wrong_hash".to_string());
        let result = board.append_bulletin(bulletin2);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_validation() {
        let mut board = InMemoryBulletinBoard::new();

        // Build a valid chain
        let bulletin1 = create_test_ballot_submission(String::new());
        let tracker1 = board.append_bulletin(bulletin1).unwrap();

        let bulletin2 = create_test_ballot_submission(tracker1);
        board.append_bulletin(bulletin2).unwrap();

        // Chain should be valid
        assert!(board.validate_chain().is_ok());
    }

    #[test]
    fn test_get_bulletins_by_type() {
        let mut board = InMemoryBulletinBoard::new();

        // Add ballot submission bulletins
        let bulletin1 = create_test_ballot_submission(String::new());
        let tracker1 = board.append_bulletin(bulletin1).unwrap();

        let bulletin2 = create_test_ballot_submission(tracker1);
        board.append_bulletin(bulletin2).unwrap();

        // Get all ballot submission bulletins
        let submissions = board.get_bulletins_by_type(BulletinType::BallotSubmission);
        assert_eq!(submissions.len(), 2);

        // Get voter authorization bulletins (should be empty)
        let auths = board.get_bulletins_by_type(BulletinType::VoterAuthorization);
        assert_eq!(auths.len(), 0);
    }

    #[test]
    fn test_bulletin_hash_consistency() {
        let board = InMemoryBulletinBoard::new();
        let bulletin = create_test_ballot_submission(String::new());

        // Hash should be consistent
        let hash1 = board.compute_bulletin_hash(&bulletin);
        let hash2 = board.compute_bulletin_hash(&bulletin);
        assert_eq!(hash1, hash2);

        // Hash should be SHA3-256 (64 hex characters)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_different_bulletins_different_hashes() {
        let board = InMemoryBulletinBoard::new();
        let bulletin1 = create_test_ballot_submission(String::new());
        let bulletin2 = create_test_ballot_submission("different".to_string());

        let hash1 = board.compute_bulletin_hash(&bulletin1);
        let hash2 = board.compute_bulletin_hash(&bulletin2);

        // Different bulletins should have different hashes
        assert_ne!(hash1, hash2);
    }
}
