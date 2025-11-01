/*
 * Error type for this library
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */
use thiserror::Error;

/**
 * Error type for the crypto module.
 *
 * This error type is used to represent all possible errors that can occur
 * within the crypto module.
 */
#[derive(Error, Debug)]
pub enum Error {
    /// Deserialization error for [`crate::utils::serialization`] functionality
    #[error("{0}")]
    DeserializationError(String),

    /// Serialization error for [`crate::utils::serialization`] functionality
    #[error("{0}")]
    SerializationError(String),

    /// Occurs when deserializing with invalid length prefixes in [`crate::utils::serialization`] functionality
    #[error("Try from slice error: {0}")]
    DeserializationLengthError(#[from] std::array::TryFromSliceError),

    /// Occurs when deserializing with invalid length prefixes (`LengthU` conversion) in [`crate::utils::serialization`] functionality
    #[error("Try from int error: {0}")]
    DeserializationLengthIntError(#[from] std::num::TryFromIntError),

    /// Occurs when deserializing `ed2219_dalek` signatures or keys
    #[error("Signature error: {0}")]
    SignatureDeserError(#[from] ed25519_dalek::SignatureError),

    /// Occurs when [encoding][`crate::traits::groups::CryptoGroup::encode_bytes`] to the curve fails
    #[error("{0}")]
    EncodingError(String),

    /// Occurs when [Naor-Yung][`crate::cryptosystem::naoryung::Ciphertext`] well-formedness proofs fail to verify.
    #[error("{0}")]
    NaorYungStripError(String),

    /// Occurs when Joint-Feldman DKG [share verification][`crate::dkgd::dealer::VerifiableShare`] fails.
    #[error("{0}")]
    ShareVerificationFailed(String),

    /// Occurs when [decryption proofs][`crate::dkgd::recipient::DecryptionFactor`] fail to verify.
    #[error("{0}")]
    DecryptProofFailed(String),

    /// Occurs when a permutation is applied to a slice of mismatched length
    #[error("Mismatched permutation length")]
    MismatchedPermutationLength,

    /// Occurs when shuffling zero ciphertexts
    #[error("Empty shuffle")]
    EmptyShuffle,

    /// Occurs when there is a length mismatch in shuffle data
    #[error("Mismatched shuffle length")]
    MismatchedShuffleLength,

    /// Occurs when a hash to curve or hash to scalar error occurs in `p256`
    #[error("{0}")]
    HashToScalarError(#[from] p256::elliptic_curve::Error),

    /// Occurs when a hash to curve or hash to scalar error occurs in `p256`
    #[error("{0}")]
    HashToElementError(String),

    /// Occurs when a scalar cannot be decoded from two elements
    #[error("{0}")]
    ScalarDecodeError(String),
}
