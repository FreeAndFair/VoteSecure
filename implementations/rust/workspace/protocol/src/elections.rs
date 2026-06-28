// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-26 Free & Fair
// See LICENSE.md for details

//! Election data structures and ballot representations.
//!
//! This module contains core data structures for representing elections,
//! ballots, and related concepts that are not cryptographic or
//! message-related.

// VSerializable derive macro import
use cryptography::utils::serialization::VSerializable;
use vser_derive::VSerializable;

// =============================================================================
// Core Election Data Structures
// =============================================================================

/// A simplified ballot containing a rank encoding.
///
/// # Structure
/// The ballot consists of a ballot style and a rank value that encodes
/// all ballot selections in a single u128 value.
///
/// # Rank Encoding
/// The rank is a u128 value that encodes all ballot selections. The specific
/// encoding format is handled at a higher level and is not interpreted at
/// this protocol level.
///
/// # Example
/// ```
/// use votesecure_protocol_library::elections::Ballot;
///
/// let ballot = Ballot {
///     ballot_style: 1,
///     rank: 12345678901234567890u128,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct Ballot {
    /// The ballot style identifier defining which contests this ballot contains.
    pub ballot_style: BallotStyle,
    /// The rank encoding of all ballot selections.
    pub rank: u128,
}

/// An enumeration for the cast/not cast decision used by the BCA.
#[derive(Debug, Clone, PartialEq)]
pub enum CastOrNot {
    Cast,
    NotCast,
}

// =============================================================================
// Election Identifiers and Metadata
// =============================================================================

/// Type alias for election hash arrays.
///
/// Election hashes uniquely identify an election and are used throughout
/// the protocol for verification and consistency checks.
/// Fixed-size 32-byte array (256 bits) compatible with SHA-256.
pub type ElectionHash = crate::cryptography::CryptographicHash;

/// Type alias for ballot style identifiers.
///
/// Ballot styles define which contests a voter is eligible to vote in,
/// typically based on their geographical location or voter registration.
pub type BallotStyle = u16;

/// Type alias for bulletin trackers.
///
/// A bulletin tracker is the hash of a [`crate::bulletins::Bulletin`] on the
/// Public Bulletin Board, used to uniquely identify and look up that bulletin.
pub type BulletinTracker = String;

/// Type alias for ballot trackers.
///
/// A ballot tracker is the voter-domain name for a [`BulletinTracker`]: it is
/// the hash of the bulletin that records the voter's ballot submission,
/// allowing the voter to verify their ballot was recorded correctly.
pub type BallotTracker = BulletinTracker;

/// Type alias for voter pseudonyms.
///
/// Pseudonyms provide voter privacy while enabling ballot verification
/// and preventing double-voting within an election.
pub type VoterPseudonym = String;

/// The data part of the `VoterAuthorization`, which is what is signed.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct VoterAuthorizationData {
    pub election_hash: ElectionHash,
    pub timestamp: u64,
    pub voter_pseudonym: VoterPseudonym,
    pub ballot_style: BallotStyle,
    pub voter_verifying_key: crate::cryptography::VerifyingKey,
}

/// Signed by the EAS and sent to the VA, which carries it in both the ballot
/// submission and ballot cast messages it sends to the DBB.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct VoterAuthorization {
    pub data: VoterAuthorizationData,
    pub signature: crate::cryptography::Signature,
}

/// How to set the timestamp when creating a [`VoterAuthorization`].
#[derive(Debug, Clone, Copy)]
pub enum VoterAuthorizationTimestamp {
    /// Use the current system time. This is the only value that should
    /// be used in production, to ensure that two VoterAuthorizations created
    /// for the same voter always have different timestamps and, therefore,
    /// different signatures.
    Now,
    /// Use this fixed Unix timestamp instead of the system time. The caller
    /// is responsible for ensuring it's actually in the past; this value is
    /// only for testing and model checking, where reading the system clock
    /// could make state transitions nondeterministic or where the timestamp
    /// could be checked against the current time fast enough to violate the
    /// requirement that authorization timestamps be in the past.
    Fixed(u64),
}

impl VoterAuthorization {
    /// Create and sign a new `VoterAuthorization`.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `voter_pseudonym` - The voter's pseudonym.
    /// * `ballot_style` - The ballot style the voter is authorized for.
    /// * `voter_verifying_key` - The voter's session verifying key.
    /// * `eas_signing_key` - The EAS signing key used to sign the token.
    /// * `timestamp` - How to set the token's timestamp; see [`VoterAuthorizationTimestamp`].
    ///
    /// # Returns
    /// A `VoterAuthorization` signed by `eas_signing_key`.
    pub fn new(
        election_hash: ElectionHash,
        voter_pseudonym: VoterPseudonym,
        ballot_style: BallotStyle,
        voter_verifying_key: crate::cryptography::VerifyingKey,
        eas_signing_key: &crate::cryptography::SigningKey,
        timestamp: VoterAuthorizationTimestamp,
    ) -> Self {
        let timestamp = match timestamp {
            VoterAuthorizationTimestamp::Now => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_secs(),
            VoterAuthorizationTimestamp::Fixed(t) => t,
        };
        let data = VoterAuthorizationData {
            election_hash,
            timestamp,
            voter_pseudonym,
            ballot_style,
            voter_verifying_key,
        };
        let signature = crate::cryptography::sign_data(&data.ser(), eas_signing_key);
        Self { data, signature }
    }

    /// Build a `VoterAuthorization` for testing, signed by a freshly
    /// generated, discarded EAS keypair, timestamped at the Unix epoch so
    /// it's always safely in the past.
    ///
    /// # Arguments
    /// * `election_hash` - The election configuration hash.
    /// * `voter_pseudonym` - The voter's pseudonym.
    /// * `ballot_style` - The ballot style the voter is authorized for.
    /// * `voter_verifying_key` - The voter's session verifying key.
    ///
    /// # Returns
    /// A `VoterAuthorization` timestamped at 0.
    #[cfg(test)]
    pub fn test_voter_authorization(
        election_hash: ElectionHash,
        voter_pseudonym: &str,
        ballot_style: BallotStyle,
        voter_verifying_key: crate::cryptography::VerifyingKey,
    ) -> Self {
        let (eas_signing_key, _) = crate::cryptography::generate_signature_keypair();
        Self::new(
            election_hash,
            voter_pseudonym.to_string(),
            ballot_style,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        )
    }

    /// Validate the signature, election hash, and timestamp of this
    /// `VoterAuthorization`. The signature is verified using the EAS
    /// verifying key; the election hash is compared to the provided election
    /// hash; and the timestamp is checked to ensure it is in the past.
    ///
    /// This does not check the ballot style; it is assumed that the ballot
    /// style will be checked at a higher application level, as the protocol
    /// does not enforce ballot style restrictions.
    ///
    /// # Arguments
    /// * `eas_verifying_key` - The EAS's verifying key for the current election.
    /// * `election_hash` - The hash of the election configuration item for the
    ///   current election.
    ///
    /// # Returns
    /// `Ok(())` if the token is valid, `Err` with a message otherwise.
    pub fn validate(
        &self,
        eas_verifying_key: &crate::cryptography::VerifyingKey,
        election_hash: &ElectionHash,
    ) -> Result<(), String> {
        crate::cryptography::verify_signature(&self.data.ser(), &self.signature, eas_verifying_key)
            .map_err(|_| "Invalid signature on voter authorization".to_string())?;

        if self.data.election_hash != *election_hash {
            return Err("Voter authorization has incorrect election hash".to_string());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();
        if self.data.timestamp >= now {
            return Err("Voter authorization timestamp is not in the past".to_string());
        }

        Ok(())
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Create an ElectionHash from a string using the context hasher.
///
/// This function creates a cryptographically secure hash using the
/// context hasher, set to `Sha3_512`. It can be used for both testing and production.
///
/// # Arguments
/// * `s` - The input string to hash
///
/// # Returns
/// A hash (64-byte Sha3_512) suitable for use as an ElectionHash.
pub fn string_to_election_hash(s: &str) -> ElectionHash {
    use crate::cryptography::hash_serializable;
    hash_serializable(&s.to_string())
}

impl Ballot {
    /// Creates a test ballot with randomly generated ballot style and rank based on a seed.
    ///
    /// Uses a pseudo-random number generator seeded with the provided value to generate
    /// deterministic but varied test ballots.
    ///
    /// # Arguments
    /// * `seed` - Seed value for the pseudo-random number generator.
    ///
    /// # Returns
    /// A `Ballot` with deterministically generated `ballot_style` and `rank` fields.
    ///
    /// # Example
    /// ```
    /// use votesecure_protocol_library::elections::Ballot;
    /// let ballot = Ballot::test_ballot(12345);
    /// // Generates a ballot with pseudo-random ballot_style and rank
    /// ```
    pub fn test_ballot(seed: u64) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Create a simple pseudo-random number generator using the seed
        let mut hasher1 = DefaultHasher::new();
        seed.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        (seed ^ 0xAAAAAAAAAAAAAAAA).hash(&mut hasher2);
        let hash2 = hasher2.finish();

        let mut hasher3 = DefaultHasher::new();
        (seed ^ 0x5555555555555555).hash(&mut hasher3);
        let hash3 = hasher3.finish();

        // Generate ballot style (1-65535, avoiding 0)
        let ballot_style = ((hash1 % 65535) + 1) as BallotStyle;

        // Generate rank using two hash values to get full u128 range
        let rank = ((hash2 as u128) << 64) | (hash3 as u128);

        Self { ballot_style, rank }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ballot_creation() {
        let ballot1 = Ballot::test_ballot(12345);
        let ballot2 = Ballot::test_ballot(12345);
        let ballot3 = Ballot::test_ballot(54321);

        // Same seed should produce same ballot
        assert_eq!(ballot1, ballot2);

        // Different seeds should produce different ballots
        assert_ne!(ballot1, ballot3);

        // Ballot style should be in valid range (1-255)
        assert!(ballot1.ballot_style >= 1);
        assert!(ballot1.ballot_style > 0);
    }

    #[test]
    fn test_voter_authorization_validation() {
        let (eas_signing_key, eas_verifying_key) =
            crate::cryptography::generate_signature_keypair();
        let (_, voter_verifying_key) = crate::cryptography::generate_signature_keypair();
        let election_hash = string_to_election_hash("test_election");

        let good = VoterAuthorization::new(
            election_hash,
            "voter123".to_string(),
            1,
            voter_verifying_key,
            &eas_signing_key,
            VoterAuthorizationTimestamp::Fixed(0),
        );
        assert!(good.validate(&eas_verifying_key, &election_hash).is_ok());

        // Wrong EAS verifying key: signature no longer matches.
        let (_, wrong_eas_verifying_key) = crate::cryptography::generate_signature_keypair();
        assert!(
            good.validate(&wrong_eas_verifying_key, &election_hash)
                .is_err()
        );

        // Wrong election hash.
        let wrong_election_hash = string_to_election_hash("wrong_election");
        assert!(
            good.validate(&eas_verifying_key, &wrong_election_hash)
                .is_err()
        );

        // Timestamp not in the past.
        let mut future = good.clone();
        future.data.timestamp = u64::MAX;
        future.signature = crate::cryptography::sign_data(&future.data.ser(), &eas_signing_key);
        assert!(future.validate(&eas_verifying_key, &election_hash).is_err());

        // Corrupted signature.
        let mut corrupted = good.clone();
        let mut sig_bytes = corrupted.signature.to_bytes();
        sig_bytes[0] ^= 0xFF;
        corrupted.signature = crate::cryptography::Signature::from_bytes(&sig_bytes);
        assert!(
            corrupted
                .validate(&eas_verifying_key, &election_hash)
                .is_err()
        );
    }

    #[test]
    fn test_deterministic_generation() {
        // Test that the same seed always produces the same result
        let seed = 987654321;
        let ballot1 = Ballot::test_ballot(seed);
        let ballot2 = Ballot::test_ballot(seed);

        assert_eq!(ballot1.ballot_style, ballot2.ballot_style);
        assert_eq!(ballot1.rank, ballot2.rank);
    }
}
