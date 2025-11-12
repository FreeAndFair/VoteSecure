//! Election data structures and ballot representations.
//!
//! This module contains core data structures for representing elections,
//! ballots, and related concepts that are not cryptographic or
//! message-related.

// VSerializable derive macro import
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

// =============================================================================
// Election Identifiers and Metadata
// =============================================================================

/// Type alias for election hash arrays.
///
/// Election hashes uniquely identify an election and are used throughout
/// the protocol for verification and consistency checks.
/// Fixed-size 32-byte array (256 bits) compatible with SHA-256.
pub type ElectionHash = [u8; 32];

/// Type alias for ballot style identifiers.
///
/// Ballot styles define which contests a voter is eligible to vote in,
/// typically based on their geographical location or voter registration.
pub type BallotStyle = u16;

/// Type alias for ballot trackers.
///
/// Trackers are unique identifiers assigned to submitted ballots that allow
/// voters to verify their ballot was recorded correctly.
pub type BallotTracker = String;

/// Type alias for voter pseudonyms.
///
/// Pseudonyms provide voter privacy while enabling ballot verification
/// and preventing double-voting within an election.
pub type VoterPseudonym = String;

// =============================================================================
// Utility Functions
// =============================================================================

/// Create an ElectionHash from a string using SHA3-256.
///
/// This function creates a cryptographically secure 32-byte hash using SHA3-256
/// from the crypto library. It can be used for both testing and production.
///
/// # Arguments
/// * `s` - The input string to hash
///
/// # Returns
/// A 32-byte SHA3-256 hash suitable for use as an ElectionHash
pub fn string_to_election_hash(s: &str) -> ElectionHash {
    use crypto::utils::hash::{Hasher, Hasher256};
    use sha3::Digest;

    let mut hasher = Hasher256::hasher();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();

    // Convert to [u8; 32] array
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

impl Ballot {
    /// Creates a test ballot with randomly generated ballot style and rank based on a seed.
    ///
    /// Uses a pseudo-random number generator seeded with the provided value to generate
    /// deterministic but varied test ballots.
    ///
    /// # Arguments
    /// * `seed` - Seed value for the pseudo-random number generator
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
    fn test_deterministic_generation() {
        // Test that the same seed always produces the same result
        let seed = 987654321;
        let ballot1 = Ballot::test_ballot(seed);
        let ballot2 = Ballot::test_ballot(seed);

        assert_eq!(ballot1.ballot_style, ballot2.ballot_style);
        assert_eq!(ballot1.rank, ballot2.rank);
    }
}
