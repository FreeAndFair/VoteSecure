// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file defines the structures for all entries that can be posted to the
//! Public Bulletin Board (PBB).

use crate::cryptography::VSerializable as VSerializableTrait;
use crate::elections::{BallotStyle, ElectionHash, VoterPseudonym};
use crate::messages::{AuthVoterMsg, CastReqMsg, SignedBallotMsg};
use cryptography::utils::serialization::VDeserializable;
use cryptography::utils::serialization::variable::{LENGTH_BYTES, LengthU};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug as DebugTrait;
use vser_derive::VSerializable;

// --- Type Name Constants ---

/// Type name for ballot submission bulletins, for use with
/// [`BulletinContents::type_name`] and [`BulletinBoard::get_bulletins_by_type`].
pub const BALLOT_SUBMISSION_BULLETIN: &str = "BallotSubmission";

/// Type name for voter authorization bulletins, for use with
/// [`BulletinContents::type_name`] and [`BulletinBoard::get_bulletins_by_type`].
pub const VOTER_AUTHORIZATION_BULLETIN: &str = "VoterAuthorization";

/// Type name for ballot cast bulletins, for use with
/// [`BulletinContents::type_name`] and [`BulletinBoard::get_bulletins_by_type`].
pub const BALLOT_CAST_BULLETIN: &str = "BallotCast";

/// All built-in bulletin type names, used by the DBB to reject attempts to
/// post built-in bulletin types via the external `PostBulletin` command.
pub const BUILTIN_BULLETINS: &[&str] = &[
    BALLOT_SUBMISSION_BULLETIN,
    VOTER_AUTHORIZATION_BULLETIN,
    BALLOT_CAST_BULLETIN,
];

// --- Bulletin Contents Trait ---

/// Trait implemented by all bulletin content types.
///
/// This trait is object-safe: bulletin contents can be stored as
/// `Box<dyn BulletinContents>` in a [`BulletinData`]. Integrators can define
/// additional bulletin types by implementing this trait, including a unique
/// (within their system) string for `type_name()`, and can then post
/// instances to the bulletin board via the DBB.
pub trait BulletinContents: DebugTrait + Send + Sync {
    /// Get the voter pseudonym associated with this bulletin, if applicable.
    ///
    /// # Returns
    /// - `Some(VoterPseudonym)` if this bulletin is associated with a specific voter.
    /// - `None` if this bulletin is not voter-specific (default).
    fn voter_pseudonym(&self) -> Option<VoterPseudonym> {
        None
    }

    /// Get the ballot style associated with this bulletin, if applicable.
    ///
    /// # Returns
    /// - `Some(BallotStyle)` if this bulletin is associated with a specific ballot style.
    /// - `None` if this bulletin is not ballot-style-specific (default).
    fn ballot_style(&self) -> Option<BallotStyle> {
        None
    }

    /// Serialize the contents to bytes, used for signing and hashing.
    fn serialize(&self) -> Vec<u8>;

    /// A unique string identifying the type of this bulletin.
    ///
    /// Built-in types use the `*_BULLETIN` constants defined in this module.
    /// Third-party types should use a unique, namespaced string to avoid
    /// collisions with built-in and other custom types.
    fn type_name(&self) -> &'static str;

    /// Support downcasting to a concrete content type.
    ///
    /// Implementations should return `self`:
    /// ```ignore
    /// fn as_any(&self) -> &dyn Any { self }
    /// ```
    fn as_any(&self) -> &dyn Any;

    /// Support cloning through a trait object.
    ///
    /// Implementations should box a clone of `self`:
    /// ```ignore
    /// fn clone_box(&self) -> Box<dyn BulletinContents> { Box::new(self.clone()) }
    /// ```
    fn clone_box(&self) -> Box<dyn BulletinContents>;
}

impl Clone for Box<dyn BulletinContents> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl PartialEq for Box<dyn BulletinContents> {
    fn eq(&self, other: &Self) -> bool {
        self.serialize() == other.serialize()
    }
}

impl VSerializableTrait for Box<dyn BulletinContents> {
    fn ser(&self) -> Vec<u8> {
        self.serialize()
    }
}

// --- Bulletin Board Structures ---

/// Split `bytes` at the first VSerializable length-prefix boundary, returning
/// `(inner, rest)` where `inner` is the payload bytes (without the prefix) and
/// `rest` is everything after.  Mirrors the per-field layout produced by the
/// tuple `VSerializable` implementations: each non-final field is preceded by a
/// `LENGTH_BYTES`-wide big-endian `LengthU` byte count.
fn split_next(bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if bytes.len() < LENGTH_BYTES {
        return Err("Unexpected end of bulletin data".to_string());
    }
    let n = LengthU::from_be_bytes(bytes[..LENGTH_BYTES].try_into().unwrap()) as usize;
    let end = LENGTH_BYTES
        .checked_add(n)
        .ok_or_else(|| "Length overflow".to_string())?;
    if end > bytes.len() {
        return Err("Unexpected end of bulletin data".to_string());
    }
    Ok((&bytes[LENGTH_BYTES..end], &bytes[end..]))
}

/// The data part of a bulletin (what the DBB signs).
///
/// Contains the shared fields common to all bulletin types, plus a type-erased
/// [`BulletinContents`] that holds the type-specific payload.
#[derive(Debug, Clone)]
pub struct BulletinData {
    pub election_hash: ElectionHash,
    pub contents: Box<dyn BulletinContents>,
    /// Unix timestamp in seconds since epoch (SystemTime::UNIX_EPOCH).
    /// Created by the DBB when the bulletin is posted to the bulletin board.
    /// The DBB guarantees monotonic ordering of timestamps for "happened before" relationships.
    /// The protocol does not rely on wall clock times for security properties.
    pub timestamp: u64,
    pub previous_bb_msg_hash: String,
}

impl PartialEq for BulletinData {
    fn eq(&self, other: &Self) -> bool {
        self.election_hash == other.election_hash
            && self.contents.eq(&other.contents)
            && self.timestamp == other.timestamp
            && self.previous_bb_msg_hash == other.previous_bb_msg_hash
    }
}

impl VSerializableTrait for BulletinData {
    /// Serializes as `type_name.ser()` followed by a 4-field tuple
    /// `(election_hash, contents, timestamp, previous_bb_msg_hash).ser()`.
    /// Putting the type discriminant first lets deserialization read it
    /// before delegating the rest to the registry's typed deserializer.
    fn ser(&self) -> Vec<u8> {
        let type_name = self.contents.type_name().to_string();
        let mut bytes = type_name.ser();
        bytes.extend(
            (
                &self.election_hash,
                &self.contents,
                &self.timestamp,
                &self.previous_bb_msg_hash,
            )
                .ser(),
        );
        bytes
    }
}

impl BulletinData {
    /// Deserialize a `BulletinData` from bytes, using `registry` to reconstruct
    /// the concrete content type identified by the embedded type name.
    pub fn from_bytes(bytes: &[u8], registry: &BulletinTypeRegistry) -> Result<Self, String> {
        let (type_name_raw, rest) = split_next(bytes)?;
        let type_name =
            std::str::from_utf8(type_name_raw).map_err(|e| format!("Invalid type name: {e}"))?;
        let (election_hash, contents, timestamp, previous_bb_msg_hash) =
            registry.deserialize_all(type_name, rest)?;
        Ok(Self {
            election_hash,
            contents,
            timestamp,
            previous_bb_msg_hash,
        })
    }
}

/// A signed entry on the Public Bulletin Board.
///
/// The `data` field contains the signed payload; `signature` is the DBB's
/// signature over `data.ser()`.
#[derive(Debug, Clone)]
pub struct Bulletin {
    pub data: BulletinData,
    pub signature: String,
}

impl PartialEq for Bulletin {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.signature == other.signature
    }
}

impl VSerializableTrait for Bulletin {
    /// Produces the same output as `#[derive(VSerializable)]` on a 2-field struct.
    fn ser(&self) -> Vec<u8> {
        (&self.data, &self.signature).ser()
    }
}

impl Bulletin {
    /// Deserialize a `Bulletin` from bytes, using `registry` to reconstruct
    /// the concrete content type.
    pub fn from_bytes(bytes: &[u8], registry: &BulletinTypeRegistry) -> Result<Self, String> {
        let (data_bytes, rest) = split_next(bytes)?;
        let data = BulletinData::from_bytes(data_bytes, registry)?;
        // rest is the tail of the 2-tuple and equals signature.ser(),
        // which is the full length-prefixed String that String::deser expects.
        let signature = String::deser(rest).map_err(|e| e.to_string())?;
        Ok(Self { data, signature })
    }
}

// --- Bulletin Registry ---

/// Function pointer type for bulletin data deserializers.
///
/// Takes the bytes of a 4-tuple `(election_hash, contents, timestamp,
/// previous_bb_msg_hash)` (i.e., everything after the type name in the
/// serialized format) and returns all four fields with the contents
/// type-erased.
type DeserializeFn =
    fn(&[u8]) -> Result<(ElectionHash, Box<dyn BulletinContents>, u64, String), String>;

/// Registry mapping bulletin type names to their deserializers.
///
/// Pre-populated with the three built-in bulletin types. Integrators add
/// their own types via [`BulletinTypeRegistry::register`] before constructing
/// their [`BulletinBoard`] implementation.
///
/// Built-in type names are protected: [`register`][BulletinTypeRegistry::register]
/// returns an error if called with a built-in name, and built-in deserializers
/// always take precedence during lookup regardless of what is in the custom map.
#[derive(Clone, Debug)]
pub struct BulletinTypeRegistry {
    builtin: HashMap<String, DeserializeFn>,
    custom: HashMap<String, DeserializeFn>,
}

impl BulletinTypeRegistry {
    /// Create a new registry pre-populated with the three built-in bulletin types.
    pub fn new() -> Self {
        let mut registry = Self {
            builtin: HashMap::new(),
            custom: HashMap::new(),
        };
        registry.register_builtin::<BallotSubContents>(BALLOT_SUBMISSION_BULLETIN);
        registry.register_builtin::<VoterAuthContents>(VOTER_AUTHORIZATION_BULLETIN);
        registry.register_builtin::<BallotCastContents>(BALLOT_CAST_BULLETIN);
        registry
    }

    fn register_builtin<T>(&mut self, type_name: &str)
    where
        T: BulletinContents + VDeserializable + 'static,
    {
        self.builtin.insert(type_name.to_string(), |bytes| {
            <(ElectionHash, T, u64, String)>::deser(bytes)
                .map(|(election_hash, t, timestamp, prev_hash)| {
                    (
                        election_hash,
                        Box::new(t) as Box<dyn BulletinContents>,
                        timestamp,
                        prev_hash,
                    )
                })
                .map_err(|e| e.to_string())
        });
    }

    /// Register a custom bulletin type for deserialization.
    ///
    /// # Errors
    /// Returns an error if `type_name` matches a built-in bulletin type name
    /// or has already been registered.
    pub fn register<T>(&mut self, type_name: &str) -> Result<(), String>
    where
        T: BulletinContents + VDeserializable + 'static,
    {
        if self.builtin.contains_key(type_name) {
            return Err(format!(
                "'{}' is a reserved built-in bulletin type name",
                type_name
            ));
        }
        if self.custom.contains_key(type_name) {
            return Err(format!(
                "Bulletin type '{}' is already registered",
                type_name
            ));
        }
        self.custom.insert(type_name.to_string(), |bytes| {
            <(ElectionHash, T, u64, String)>::deser(bytes)
                .map(|(election_hash, t, timestamp, prev_hash)| {
                    (
                        election_hash,
                        Box::new(t) as Box<dyn BulletinContents>,
                        timestamp,
                        prev_hash,
                    )
                })
                .map_err(|e| e.to_string())
        });
        Ok(())
    }

    /// Returns `true` if `type_name` is a built-in bulletin type.
    pub fn is_builtin(&self, type_name: &str) -> bool {
        self.builtin.contains_key(type_name)
    }

    /// Deserialize all four non-type-name fields of a `BulletinData` from
    /// `bytes` (the wire bytes after the type name has been consumed), using
    /// the deserializer registered for `type_name`.
    ///
    /// Built-in types take precedence over custom types with the same name.
    pub fn deserialize_all(
        &self,
        type_name: &str,
        bytes: &[u8],
    ) -> Result<(ElectionHash, Box<dyn BulletinContents>, u64, String), String> {
        self.builtin
            .get(type_name)
            .or_else(|| self.custom.get(type_name))
            .ok_or_else(|| format!("Unknown bulletin type: '{}'", type_name))
            .and_then(|f| f(bytes))
    }
}

impl Default for BulletinTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// --- Concrete Content Types ---

/// Contents of a ballot submission bulletin.
/// Defined in `ballot-submission-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotSubContents {
    pub ballot: SignedBallotMsg,
}

impl BulletinContents for BallotSubContents {
    fn voter_pseudonym(&self) -> Option<VoterPseudonym> {
        Some(self.ballot.data.voter_pseudonym.clone())
    }
    fn ballot_style(&self) -> Option<BallotStyle> {
        Some(self.ballot.data.ballot_style)
    }
    fn serialize(&self) -> Vec<u8> {
        self.ser()
    }
    fn type_name(&self) -> &'static str {
        BALLOT_SUBMISSION_BULLETIN
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn BulletinContents> {
        Box::new(self.clone())
    }
}

/// Contents of a voter authorization bulletin.
/// Defined in `ballot-cast-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct VoterAuthContents {
    pub authorization: AuthVoterMsg,
}

impl BulletinContents for VoterAuthContents {
    fn voter_pseudonym(&self) -> Option<VoterPseudonym> {
        Some(self.authorization.data.voter_pseudonym.clone())
    }
    fn ballot_style(&self) -> Option<BallotStyle> {
        Some(self.authorization.data.ballot_style)
    }
    fn serialize(&self) -> Vec<u8> {
        self.ser()
    }
    fn type_name(&self) -> &'static str {
        VOTER_AUTHORIZATION_BULLETIN
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn BulletinContents> {
        Box::new(self.clone())
    }
}

/// Contents of a ballot cast bulletin.
/// Defined in `ballot-cast-spec.md`.
#[derive(Debug, Clone, PartialEq, VSerializable)]
pub struct BallotCastContents {
    pub ballot: SignedBallotMsg,
    pub cast_intent: CastReqMsg,
}

impl BulletinContents for BallotCastContents {
    fn voter_pseudonym(&self) -> Option<VoterPseudonym> {
        Some(self.ballot.data.voter_pseudonym.clone())
    }
    fn ballot_style(&self) -> Option<BallotStyle> {
        Some(self.ballot.data.ballot_style)
    }
    fn serialize(&self) -> Vec<u8> {
        self.ser()
    }
    fn type_name(&self) -> &'static str {
        BALLOT_CAST_BULLETIN
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn BulletinContents> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::generate_signature_keypair;
    use crate::cryptography::{BallotCryptogram, Signature};
    use crate::messages::{AuthVoterMsgData, CastReqMsgData, SignedBallotMsgData};
    use cryptography::utils::serialization::VSerializable;

    fn make_signed_ballot(verifying_key: crate::cryptography::VerifyingKey) -> SignedBallotMsg {
        let signed_ballot_data = SignedBallotMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
            ballot_cryptogram: BallotCryptogram {
                ballot_style: 1,
                // Create a dummy ciphertext for casting.
                ciphertext: {
                    use crate::cryptography::{BALLOT_CIPHERTEXT_WIDTH, CryptographyContext};
                    use cryptography::context::Context;
                    use cryptography::cryptosystem::naoryung::Ciphertext as NYCiphertext;
                    use cryptography::traits::groups::{GroupElement, GroupScalar};

                    // Create dummy elements and scalars for the ciphertext and proof.
                    let dummy_element = <CryptographyContext as Context>::Element::one();
                    let dummy_scalar = <CryptographyContext as Context>::Scalar::zero();
                    let u_b = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];
                    let v_b = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];
                    let u_a = [dummy_element; BALLOT_CIPHERTEXT_WIDTH];

                    // Create a dummy proof with the correct structure but no real cryptographic validity.
                    let dummy_proof = {
                        use cryptography::zkp::pleq::PlEqProof;
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
        SignedBallotMsg {
            data: signed_ballot_data,
            signature: Signature::from_bytes(&[0u8; 64]),
        }
    }

    #[test]
    fn test_roundtrip_ballot_sub() {
        // Serialize and deserialize a BallotSubContents bulletin.
        let (_, verifying_key) = generate_signature_keypair();
        let original = Bulletin {
            data: BulletinData {
                election_hash: crate::elections::string_to_election_hash("test_election"),
                contents: Box::new(BallotSubContents {
                    ballot: make_signed_ballot(verifying_key),
                }),
                timestamp: 1640995200,
                previous_bb_msg_hash: "prev_hash".to_string(),
            },
            signature: "test_sig".to_string(),
        };
        let registry = BulletinTypeRegistry::new();
        let bytes = original.ser();
        let bytes2: Vec<u8> = original.ser();
        assert_eq!(bytes, bytes2); // Serialization is deterministic.
        let recovered = Bulletin::from_bytes(&bytes, &registry).unwrap();
        assert_eq!(original, recovered); // Round-tripping recovers the same bulletin.
    }

    #[test]
    fn test_roundtrip_voter_auth() {
        // Serialize and deserialize a VoterAuthContents bulletin.
        let (_, verifying_key) = generate_signature_keypair();
        let auth_data = AuthVoterMsgData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            voter_pseudonym: "voter_123".to_string(),
            voter_verifying_key: verifying_key,
            ballot_style: 1,
        };
        let original = Bulletin {
            data: BulletinData {
                election_hash: crate::elections::string_to_election_hash("test_election"),
                contents: Box::new(VoterAuthContents {
                    authorization: crate::messages::AuthVoterMsg {
                        data: auth_data,
                        signature: Signature::from_bytes(&[0u8; 64]),
                    },
                }),
                timestamp: 1640995200,
                previous_bb_msg_hash: "prev_hash".to_string(),
            },
            signature: "test_sig".to_string(),
        };
        let registry = BulletinTypeRegistry::new();
        let bytes = original.ser();
        let bytes2 = original.ser();
        assert_eq!(bytes, bytes2); // Serialization is deterministic.
        let recovered = Bulletin::from_bytes(&bytes, &registry).unwrap();
        assert_eq!(original, recovered); // Round-tripping recovers the same bulletin.
    }

    #[test]
    fn test_roundtrip_ballot_cast() {
        // Serialize and deserialize a BallotCastContents bulletin.
        let (_, verifying_key) = generate_signature_keypair();
        let signed_ballot = make_signed_ballot(verifying_key);
        let cast_req = crate::messages::CastReqMsg {
            data: CastReqMsgData {
                election_hash: crate::elections::string_to_election_hash("test_election"),
                voter_pseudonym: "voter_123".to_string(),
                voter_verifying_key: verifying_key,
                ballot_tracker: "tracker_123".to_string(),
            },
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        let original = Bulletin {
            data: BulletinData {
                election_hash: crate::elections::string_to_election_hash("test_election"),
                contents: Box::new(BallotCastContents {
                    ballot: signed_ballot,
                    cast_intent: cast_req,
                }),
                timestamp: 1640995200,
                previous_bb_msg_hash: "prev_hash".to_string(),
            },
            signature: "test_sig".to_string(),
        };
        let registry = BulletinTypeRegistry::new();
        let bytes = original.ser();
        let bytes2 = original.ser();
        assert_eq!(bytes, bytes2); // Serialization is deterministic.
        let recovered = Bulletin::from_bytes(&bytes, &registry).unwrap();
        assert_eq!(original, recovered); // Round-tripping recovers the same bulletin.
    }

    #[test]
    fn test_roundtrip_custom_type() {
        // Define a custom bulletin content type the way an integrator would.
        #[derive(Debug, Clone, PartialEq, VSerializable)]
        struct ElectionResultContents {
            pub result_summary: String,
            pub total_votes: u64,
        }
        impl BulletinContents for ElectionResultContents {
            fn serialize(&self) -> Vec<u8> {
                self.ser()
            }
            fn type_name(&self) -> &'static str {
                "example.ElectionResult"
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
            fn clone_box(&self) -> Box<dyn BulletinContents> {
                Box::new(self.clone())
            }
        }

        let mut registry = BulletinTypeRegistry::new();
        registry
            .register::<ElectionResultContents>("example.ElectionResult")
            .unwrap();

        let original = Bulletin {
            data: BulletinData {
                election_hash: crate::elections::string_to_election_hash("test_election"),
                contents: Box::new(ElectionResultContents {
                    result_summary: "Candidate A wins".to_string(),
                    total_votes: 42_000,
                }),
                timestamp: 1640995200,
                previous_bb_msg_hash: String::new(),
            },
            signature: "test_sig".to_string(),
        };

        let bytes = original.ser();
        let recovered = Bulletin::from_bytes(&bytes, &registry).unwrap();
        assert_eq!(original, recovered);

        // Verify that the concrete type survives the round-trip via downcast.
        let recovered_contents = recovered
            .data
            .contents
            .as_any()
            .downcast_ref::<ElectionResultContents>()
            .expect("should downcast to ElectionResultContents");
        let original_contents = original
            .data
            .contents
            .as_any()
            .downcast_ref::<ElectionResultContents>()
            .unwrap();
        assert_eq!(recovered_contents, original_contents);
    }

    #[test]
    fn test_deserialize_unknown_type_fails() {
        // Create bytes for a type that is not in the default registry.
        #[derive(Debug, Clone, VSerializable)]
        struct UnregisteredContents {
            pub value: u64,
        }
        impl BulletinContents for UnregisteredContents {
            fn serialize(&self) -> Vec<u8> {
                self.ser()
            }
            fn type_name(&self) -> &'static str {
                "example.Unregistered"
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
            fn clone_box(&self) -> Box<dyn BulletinContents> {
                Box::new(UnregisteredContents { value: self.value })
            }
        }

        let bulletin_data = BulletinData {
            election_hash: crate::elections::string_to_election_hash("test_election"),
            contents: Box::new(UnregisteredContents { value: 99 }),
            timestamp: 1640995200,
            previous_bb_msg_hash: String::new(),
        };
        let bytes = bulletin_data.ser();
        let bytes2 = bulletin_data.ser();
        assert_eq!(bytes, bytes2); // Serialization is deterministic.

        // Attempting to deserialize with the default registry should fail
        // since the type is unknown.
        let registry = BulletinTypeRegistry::new();
        let result = BulletinData::from_bytes(&bytes, &registry);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("example.Unregistered"));
    }

    #[test]
    fn test_registry_rejects_builtin_names() {
        let mut registry = BulletinTypeRegistry::new();
        // Attempting to register any type under a built-in name must fail.
        assert!(
            registry
                .register::<BallotSubContents>(BALLOT_SUBMISSION_BULLETIN)
                .is_err()
        );
        assert!(
            registry
                .register::<VoterAuthContents>(VOTER_AUTHORIZATION_BULLETIN)
                .is_err()
        );
        assert!(
            registry
                .register::<BallotCastContents>(BALLOT_CAST_BULLETIN)
                .is_err()
        );
        // Registering a new custom name succeeds; registering the same name twice fails.
        assert!(
            registry
                .register::<BallotSubContents>("example.CustomType")
                .is_ok()
        );
        assert!(
            registry
                .register::<BallotSubContents>("example.CustomType")
                .is_err()
        );
    }
}
