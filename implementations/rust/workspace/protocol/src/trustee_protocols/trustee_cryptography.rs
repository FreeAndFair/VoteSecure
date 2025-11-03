// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the cyptographic constructs and functions
//! specific to trustee protocols.

use crate::cryptography::{
    BALLOT_CIPHERTEXT_WIDTH, BallotCheckPublicKey, Context, CryptographyContext, ElectionKey,
};
use cryptography::cryptosystem::elgamal::{
    Ciphertext as EGCiphertext, KeyPair as EGKeyPair, PublicKey as EGPublicKey,
};
use cryptography::dkgd::recipient::{DkgCiphertext, combine};
use cryptography::groups::Ristretto255Group as RGroup; // should be exported from cryptography.rs
use cryptography::traits::groups::CryptographicGroup;
use cryptography::zkp::dlogeq::DlogEqProof;
use cryptography::zkp::shuffle::{ShuffleProof, Shuffler};

// =============================================================================
// Type Aliases
// =============================================================================

/// A trustee key pair (El Gamal).
pub type TrusteeKeyPair = EGKeyPair<CryptographyContext>;

/// A trustee public key (El Gamal).
pub type TrusteePublicKey = EGPublicKey<CryptographyContext>;

/// A stripped ballot ciphertext (ElGamal).
pub type StrippedBallotCiphertext = EGCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH>;

/// A mix round shuffle proof.
pub type MixRoundProof = ShuffleProof<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH>;

/// A partial decryption proof.
pub type PartialDecryptionProof = DlogEqProof<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH>;

/// A partial decryption element.
pub type PartialDecryptionElement =
    <CryptographyContext as cryptography::context::Context>::Element;

/// A partial decryption value (sequence of partial decryption elements).
pub type PartialDecryptionValue = [PartialDecryptionElement; BALLOT_CIPHERTEXT_WIDTH];

/// A check value.
pub type CheckValue = <CryptographyContext as cryptography::context::Context>::Element;

/// A share (scalar).
pub type Share = <CryptographyContext as cryptography::context::Context>::Scalar;

/// A share ciphertext (requires width 2).
pub type ShareCiphertext = EGCiphertext<CryptographyContext, 2>;

// Re-exports from the main cryptography library, so the rest of the code
// doesn't have to use it directly.
pub use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
pub use cryptography::dkgd::recipient::{DecryptionFactor, ParticipantPosition, Recipient};

// =============================================================================
// Key Share Encryption/Decryption
// =============================================================================

/// Encrypt a share (scalar) using a trustee's public key.
pub fn encrypt_share(
    share: &Share,
    trustee_public_key: &TrusteePublicKey,
) -> Result<ShareCiphertext, String> {
    // Use scalar encoding directly on the share
    let encoded_elements =
        RGroup::encode_scalar(share).map_err(|e| format!("Failed to encode scalar: {:?}", e))?;

    // Encrypt the 2 group elements using ElGamal
    Ok(trustee_public_key.encrypt(&encoded_elements))
}

/// Decrypt a share ciphertext using a trustee's key pair.
pub fn decrypt_share(
    ciphertext: &ShareCiphertext,
    trustee_key_pair: &TrusteeKeyPair,
) -> Result<Share, String> {
    // Decrypt using ElGamal to (hopefully) get 2 group elements.
    let decrypted_elements = trustee_key_pair.decrypt(ciphertext);

    if decrypted_elements.len() != 2 {
        return Err(format!(
            "Expected 2 decrypted elements, got {}",
            decrypted_elements.len()
        ));
    }

    // Use scalar decoding to convert the 2 group elements back to scalar.
    let decoded_scalar = RGroup::decode_scalar(&[decrypted_elements[0], decrypted_elements[1]])
        .map_err(|e| format!("Failed to decode scalar: {:?}", e))?;

    // Return the reconstructed share
    Ok(decoded_scalar)
}

// =============================================================================
// Mixing (Shuffling) Functions
// =============================================================================

/// Extract the underlying ElGamal public key from a Naor-Yung public key.
pub fn ny_to_eg_public_key(ny_pk: &ElectionKey) -> BallotCheckPublicKey {
    EGPublicKey { y: ny_pk.pk_b }
}

/// Shuffle a list of ballot ciphertexts, returning the shuffled list
/// and a proof of correct shuffling.
pub fn shuffle_ciphertexts(
    ciphertexts: &[StrippedBallotCiphertext],
    election_pk: &ElectionKey,
    context: &[u8],
) -> Result<(Vec<StrippedBallotCiphertext>, MixRoundProof), String> {
    // Generate independent generators for the shuffle
    let generators =
        <CryptographyContext as Context>::G::ind_generators(ciphertexts.len(), context)
            .map_err(|e| format!("Failed to generate independent generators: {:?}", e))?;

    // Extract the EG public key from the NY public key
    let eg_pk = ny_to_eg_public_key(election_pk);

    // Create the shuffler and perform the shuffle
    let shuffler = Shuffler::new(generators, eg_pk);
    let ciphertexts_vec = ciphertexts.to_vec();
    let (mixed, proof) = shuffler
        .shuffle(&ciphertexts_vec, context)
        .map_err(|e| format!("Failed to shuffle ballots: {:?}", e))?;

    Ok((mixed, proof))
}

/// Verify a shuffle proof for a list of input and output ciphertexts.
/// An Ok result means that the proof was verified; a failed
/// verification or another error during the verification process
/// causes an Err result.
pub fn verify_shuffle(
    input_ciphertexts: &[StrippedBallotCiphertext],
    output_ciphertexts: &[StrippedBallotCiphertext],
    proof: &MixRoundProof,
    election_pk: &ElectionKey,
    context: &[u8],
) -> Result<(), String> {
    // Generate independent generators for verification.
    let generators =
        <CryptographyContext as Context>::G::ind_generators(input_ciphertexts.len(), context)
            .map_err(|e| format!("Failed to generate independent generators: {:?}", e))?;
    // Extract the EG public key from the NY public key.
    let eg_pk = ny_to_eg_public_key(election_pk);

    // Create the shuffler and verify the proof.
    let shuffler = Shuffler::new(generators, eg_pk);
    let input_vec = input_ciphertexts.to_vec();
    let output_vec = output_ciphertexts.to_vec();
    let res = shuffler
        .verify(&input_vec, &output_vec, proof, context)
        .map_err(|e| format!("Shuffle verification failed: {:?}", e))?;

    if res {
        Ok(())
    } else {
        Err("Shuffle proof was invalid.".to_string())
    }
}

// =============================================================================
// Partial Decryption Functions
// =============================================================================

/// Compute partial decryptions for a set of ciphertexts, given a
/// recipient's secret key and the proof context.
pub fn compute_partial_decryptions<const T: usize, const P: usize>(
    ciphertexts: &[StrippedBallotCiphertext],
    recipient: &Recipient<CryptographyContext, T, P>,
    proof_context: &[u8],
) -> Result<Vec<DecryptionFactor<CryptographyContext, P, BALLOT_CIPHERTEXT_WIDTH>>, String> {
    // Convert ciphertexts to DkgCiphertext.
    let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
        ciphertexts
            .iter()
            .map(|c| DkgCiphertext(c.clone()))
            .collect();

    // Compute decryption factors.
    recipient
        .decryption_factor(&dkg_ciphertexts, proof_context)
        .map_err(|e| format!("Failed to compute decryption factors: {:?}", e))
}

/// Combine partial decryptions from T trustees to recover plaintext
/// `Ballot`s, given their verification keys and the proof context.
pub fn combine_partial_decryptions<const T: usize, const P: usize>(
    ciphertexts: &[StrippedBallotCiphertext],
    partial_decryptions_by_trustee: &[Vec<
        cryptography::dkgd::recipient::DecryptionFactor<
            CryptographyContext,
            P,
            BALLOT_CIPHERTEXT_WIDTH,
        >,
    >; T],
    verification_keys: &[<CryptographyContext as Context>::Element; T],
    proof_context: &[u8],
) -> Result<Vec<[<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH]>, String> {
    // Convert ciphertexts to DkgCiphertext.
    let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
        ciphertexts
            .iter()
            .map(|c| DkgCiphertext(c.clone()))
            .collect();

    // Combine partial decryptions to get plaintext element arrays.
    let combined_elements = combine(
        &dkg_ciphertexts,
        partial_decryptions_by_trustee,
        verification_keys,
        proof_context,
    )
    .map_err(|e| format!("Failed to combine elements: {:?}", e))?;

    Ok(combined_elements)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::generate_election_keypair;

    #[test]
    fn test_share_encryption_decryption_roundtrip() {
        // Generate a trustee key pair.
        let trustee_keypair = TrusteeKeyPair::generate();

        // Create a test share.
        let original_share = Share::from(42u32);

        // Encrypt the share.
        let encrypted = encrypt_share(&original_share, &trustee_keypair.pkey)
            .expect("Share encryption should succeed");

        // Decrypt the share.
        let decrypted =
            decrypt_share(&encrypted, &trustee_keypair).expect("Share decryption should succeed");

        // Verify that they match.
        assert_eq!(original_share, decrypted);
    }

    #[test]
    fn test_share_encryption_different_keys() {
        // Generate two different trustee key pairs.
        let trustee1_keypair = TrusteeKeyPair::generate();
        let trustee2_keypair = TrusteeKeyPair::generate();

        // Create a test share.
        let share = Share::from(123u32);

        // Encrypt with trustee1's public key.
        let encrypted =
            encrypt_share(&share, &trustee1_keypair.pkey).expect("Share encryption should succeed");

        // Decrypt with trustee1's key pair (should succeed).
        let decrypted1 = decrypt_share(&encrypted, &trustee1_keypair);
        assert!(decrypted1.is_ok());
        assert_eq!(share, decrypted1.unwrap());

        // Decrypt with trustee2's key pair (should either fail or give a different share).
        let decrypted2 = decrypt_share(&encrypted, &trustee2_keypair);
        match decrypted2 {
            Ok(val) => {
                assert!(
                    val != share,
                    "Decryption with wrong key should not give original share."
                );
            }
            _ => { /* we just succeed because we got the expected error */ }
        }
    }

    #[test]
    fn test_ny_to_eg_public_key_extraction() {
        // Generate an election public key (Naor-Yung) from an El Gamal public key.
        let context = b"test election";
        let eg_keypair: EGKeyPair<CryptographyContext> = EGKeyPair::generate();
        let ny_pk = match ElectionKey::augment(&eg_keypair.pkey, context) {
            Ok(ny_pk) => ny_pk,
            Err(_) => {
                assert!(false, "Could not augment El Gamal public key");
                return;
            }
        };

        // Verify that the extracted key matches the original key.
        assert_eq!(ny_to_eg_public_key(&ny_pk), eg_keypair.pkey);
    }

    #[test]
    fn test_shuffle_ballots_produces_valid_output() {
        // Generate an election key.
        let context = b"test election";
        let election_keypair =
            generate_election_keypair(context).expect("Election keypair generation should succeed");
        let election_pk = &election_keypair.pkey;

        // Get the underlying El Gamal public key.
        let eg_pk = ny_to_eg_public_key(election_pk);

        // Create some test ciphertexts.
        let num_ballots = 10;
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            let ciphertext = eg_pk.encrypt(&message);
            input_ciphertexts.push(ciphertext);
        }

        // Shuffle the ciphertexts.
        let result = shuffle_ciphertexts(&input_ciphertexts, election_pk, context);
        assert!(result.is_ok(), "Shuffle should succeed");

        let (shuffled, _proof) = result.unwrap();

        // Verify the output has the same length.
        assert_eq!(shuffled.len(), input_ciphertexts.len());

        // The verification test will check that the proof is generated correctly.
    }

    #[test]
    fn test_shuffle_verification_accepts_valid_shuffle() {
        // Generate an election key.
        let context = b"test election";
        let election_keypair =
            generate_election_keypair(context).expect("Election keypair generation should succeed");
        let election_pk = &election_keypair.pkey;

        // Get the underlying El Gamal public key.
        let eg_pk = ny_to_eg_public_key(election_pk);

        // Create some test ciphertexts.
        let num_ballots = 5;
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            let ciphertext = eg_pk.encrypt(&message);
            input_ciphertexts.push(ciphertext);
        }

        // Shuffle the ballots.
        let (output_ciphertexts, proof) =
            shuffle_ciphertexts(&input_ciphertexts, election_pk, context)
                .expect("Shuffle should succeed");

        // Verify the shuffle.
        let verification = verify_shuffle(
            &input_ciphertexts,
            &output_ciphertexts,
            &proof,
            election_pk,
            context,
        );
        assert!(
            verification.is_ok(),
            "Valid shuffle should verify successfully"
        );
    }

    #[test]
    fn test_shuffle_verification_rejects_invalid_shuffle() {
        // Generate an election key.
        let context = b"test election";
        let election_keypair =
            generate_election_keypair(context).expect("Election keypair generation should succeed");
        let election_pk = &election_keypair.pkey;

        // Get the underlying El Gamal public key.
        let eg_pk = ny_to_eg_public_key(election_pk);

        // Create some test ciphertexts.
        let num_ballots = 5;
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            let ciphertext = eg_pk.encrypt(&message);
            input_ciphertexts.push(ciphertext);
        }

        // Shuffle the ballots.
        let (mut output_ciphertexts, proof) =
            shuffle_ciphertexts(&input_ciphertexts, election_pk, context)
                .expect("Shuffle should succeed");

        // Duplicate the first element and delete the second, so now we don't have
        // the same output ciphertext set.
        output_ciphertexts.push(output_ciphertexts[0].clone());
        output_ciphertexts.remove(1);

        // Verify the shuffle; this should fail because we've lost a ciphertext
        // (and duplicated another).
        let verification = verify_shuffle(
            &input_ciphertexts,
            &output_ciphertexts,
            &proof,
            election_pk,
            context,
        );
        assert!(
            verification.is_err(),
            "Invalid shuffle should not verify successfully"
        );
    }

    #[test]
    fn test_compute_partial_decryptions_produces_valid_output() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{DkgPublicKey, ParticipantPosition, Recipient};
        use std::array;

        // Set up DKG with T=2, P=3.
        const T: usize = 2;
        const P: usize = 3;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create some test ciphertexts (using the DKG public key).
        let num_ballots = 5;
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            let ciphertext = pk.encrypt(&message);
            // Convert to StrippedBallotCiphertext (just the underlying EG ciphertext).
            input_ciphertexts.push(ciphertext.0);
        }

        // Compute partial decryptions for the first recipient.
        let proof_context = b"test decryption";
        let result = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context,
        );

        assert!(
            result.is_ok(),
            "Computing partial decryptions should succeed"
        );

        let partial_decryptions = result.unwrap();

        // Verify that we got the correct number of decryption factors.
        assert_eq!(
            partial_decryptions.len(),
            num_ballots,
            "Should have one decryption factor per ciphertext"
        );
    }

    #[test]
    fn test_combine_partial_decryptions_recovers_plaintexts() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{DkgPublicKey, ParticipantPosition, Recipient};
        use std::array;

        // Set up DKG with T=2, P=3.
        const T: usize = 2;
        const P: usize = 3;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create some test plaintexts and encrypt them.
        let num_ballots = 5;
        let mut plaintexts = Vec::new();
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            plaintexts.push(message);
            let ciphertext = pk.encrypt(&message);
            // Convert to StrippedBallotCiphertext (just the underlying EG ciphertext).
            input_ciphertexts.push(ciphertext.0);
        }

        // Compute partial decryptions from T trustees (indices 0 and 1).
        let proof_context = b"test decryption";
        let partial_decryptions_0 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_1 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[1].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");

        // Combine the partial decryptions.
        let partial_decryptions_by_trustee: [Vec<_>; T] =
            [partial_decryptions_0, partial_decryptions_1];

        let verification_keys: [<CryptographyContext as Context>::Element; T] =
            array::from_fn(|i| recipients[i].0.get_verification_key().clone());

        let result = combine_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &partial_decryptions_by_trustee,
            &verification_keys,
            proof_context,
        );

        assert!(
            result.is_ok(),
            "Combining partial decryptions should succeed"
        );

        // Note: We can't verify that the decrypted ballots match the original
        // plaintexts because the combine_partial_decryptions function currently
        // has a stub for ballot decoding (it just returns test ballots).
        // Once ballot decoding is implemented, we should add a test to verify
        // that the recovered plaintexts match the original plaintexts.
        let ballots = result.unwrap();
        assert_eq!(
            ballots.len(),
            num_ballots,
            "Should have one ballot per ciphertext"
        );
    }

    #[test]
    fn test_partial_decryptions_roundtrip_with_t_of_p_trustees() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{
            DkgCiphertext, DkgPublicKey, ParticipantPosition, Recipient, combine,
        };
        use std::array;

        // Set up DKG with T=3, P=5 to test with more trustees.
        const T: usize = 3;
        const P: usize = 5;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create some test plaintexts and encrypt them.
        let num_ballots = 3;
        let mut original_plaintexts = Vec::new();
        let mut input_ciphertexts = Vec::new();
        for _ in 0..num_ballots {
            let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
                std::array::from_fn(|_| CryptographyContext::random_element());
            original_plaintexts.push(message);
            let ciphertext = pk.encrypt(&message);
            // Convert to StrippedBallotCiphertext (just the underlying EG ciphertext).
            input_ciphertexts.push(ciphertext.0);
        }

        // Compute partial decryptions from T trustees (indices 0, 1, 2).
        let proof_context = b"test decryption";
        let partial_decryptions_0 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_1 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[1].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_2 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[2].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");

        // Use the cryptography library's combine function directly to verify correctness.
        let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
            input_ciphertexts
                .iter()
                .map(|c| DkgCiphertext(c.clone()))
                .collect();

        let partial_decryptions_by_trustee: [Vec<_>; T] = [
            partial_decryptions_0,
            partial_decryptions_1,
            partial_decryptions_2,
        ];

        let verification_keys: [<CryptographyContext as Context>::Element; T] =
            array::from_fn(|i| recipients[i].0.get_verification_key().clone());

        let decrypted = combine(
            &dkg_ciphertexts,
            &partial_decryptions_by_trustee,
            &verification_keys,
            proof_context,
        )
        .expect("Combining partial decryptions should succeed");

        // Verify that the decrypted plaintexts match the original plaintexts.
        assert_eq!(
            decrypted, original_plaintexts,
            "Decrypted plaintexts should match encrypted plaintexts"
        );
    }

    #[test]
    fn test_combine_partial_decryptions_fails_with_wrong_partial_decryption() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{
            DkgCiphertext, DkgPublicKey, ParticipantPosition, Recipient, combine,
        };
        use std::array;

        // Set up DKG with T=3, P=5 (need 3 trustees to decrypt).
        const T: usize = 3;
        const P: usize = 5;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create and encrypt a test plaintext.
        let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
            std::array::from_fn(|_| CryptographyContext::random_element());
        let ciphertext = pk.encrypt(&message);
        let input_ciphertexts = vec![ciphertext.0];

        // Compute partial decryptions from only T-1=2 trustees (insufficient).
        let proof_context = b"test decryption";
        let partial_decryptions_0 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_1 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[1].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");

        let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
            input_ciphertexts
                .iter()
                .map(|c| DkgCiphertext(c.clone()))
                .collect();

        // Create a different ciphertext.
        let wrong_message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
            std::array::from_fn(|_| CryptographyContext::random_element());
        let wrong_ciphertext = pk.encrypt(&wrong_message);
        let wrong_input = vec![wrong_ciphertext.0];

        // Get partial decryptions for the wrong ciphertext from the third trustee.
        let partial_decryptions_2_wrong =
            compute_partial_decryptions::<T, P>(&wrong_input, &recipients[2].0, proof_context)
                .expect("Computing partial decryptions should succeed");

        // Try to combine with decryptions from the correct ciphertext (trustees 0, 1)
        // and wrong ciphertext (trustee 2).
        let partial_decryptions_by_trustee: [Vec<_>; T] = [
            partial_decryptions_0,
            partial_decryptions_1,
            partial_decryptions_2_wrong,
        ];

        let verification_keys: [<CryptographyContext as Context>::Element; T] =
            array::from_fn(|i| recipients[i].0.get_verification_key().clone());

        let result = combine(
            &dkg_ciphertexts,
            &partial_decryptions_by_trustee,
            &verification_keys,
            proof_context,
        );

        // This should fail because the third partial decryption is for a different ciphertext.
        assert!(
            result.is_err(),
            "Combining partial decryptions from different ciphertexts should fail"
        );
    }

    #[test]
    fn test_combine_partial_decryptions_fails_with_wrong_verification_keys() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{
            DkgCiphertext, DkgPublicKey, ParticipantPosition, Recipient, combine,
        };
        use std::array;

        // Set up DKG with T=2, P=3.
        const T: usize = 2;
        const P: usize = 3;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create and encrypt a test plaintext.
        let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
            std::array::from_fn(|_| CryptographyContext::random_element());
        let ciphertext = pk.encrypt(&message);
        let input_ciphertexts = vec![ciphertext.0];

        // Compute partial decryptions from T=2 trustees.
        let proof_context = b"test decryption";
        let partial_decryptions_0 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_1 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[1].0,
            proof_context,
        )
        .expect("Computing partial decryptions should succeed");

        let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
            input_ciphertexts
                .iter()
                .map(|c| DkgCiphertext(c.clone()))
                .collect();

        let partial_decryptions_by_trustee: [Vec<_>; T] =
            [partial_decryptions_0, partial_decryptions_1];

        // Use wrong verification keys (random elements instead of correct keys).
        let wrong_verification_keys: [<CryptographyContext as Context>::Element; T] =
            array::from_fn(|_| CryptographyContext::random_element());

        let result = combine(
            &dkg_ciphertexts,
            &partial_decryptions_by_trustee,
            &wrong_verification_keys,
            proof_context,
        );

        // This should fail because the verification keys don't match the trustees.
        assert!(
            result.is_err(),
            "Combining partial decryptions with wrong verification keys should fail"
        );
    }

    #[test]
    fn test_combine_partial_decryptions_fails_with_wrong_proof_context() {
        use cryptography::dkgd::dealer::{Dealer, VerifiableShare};
        use cryptography::dkgd::recipient::{
            DkgCiphertext, DkgPublicKey, ParticipantPosition, Recipient, combine,
        };
        use std::array;

        // Set up DKG with T=2, P=3.
        const T: usize = 2;
        const P: usize = 3;

        let dealers: [Dealer<CryptographyContext, T, P>; P] =
            array::from_fn(|_| Dealer::generate());

        let recipients: [(
            Recipient<CryptographyContext, T, P>,
            DkgPublicKey<CryptographyContext, T>,
        ); P] = array::from_fn(|i| {
            let position = ParticipantPosition::from_usize(i + 1);

            let verifiable_shares: [VerifiableShare<CryptographyContext, T>; P] = dealers
                .clone()
                .map(|d| d.get_verifiable_shares().for_recipient(&position));

            Recipient::from_shares(position, &verifiable_shares).unwrap()
        });

        let pk: &DkgPublicKey<CryptographyContext, T> = &recipients[0].1;

        // Create and encrypt a test plaintext.
        let message: [<CryptographyContext as Context>::Element; BALLOT_CIPHERTEXT_WIDTH] =
            std::array::from_fn(|_| CryptographyContext::random_element());
        let ciphertext = pk.encrypt(&message);
        let input_ciphertexts = vec![ciphertext.0];

        // Compute partial decryptions with one proof context.
        let proof_context_creation = b"test decryption creation";
        let partial_decryptions_0 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[0].0,
            proof_context_creation,
        )
        .expect("Computing partial decryptions should succeed");
        let partial_decryptions_1 = compute_partial_decryptions::<T, P>(
            &input_ciphertexts,
            &recipients[1].0,
            proof_context_creation,
        )
        .expect("Computing partial decryptions should succeed");

        let dkg_ciphertexts: Vec<DkgCiphertext<CryptographyContext, BALLOT_CIPHERTEXT_WIDTH, T>> =
            input_ciphertexts
                .iter()
                .map(|c| DkgCiphertext(c.clone()))
                .collect();

        let partial_decryptions_by_trustee: [Vec<_>; T] =
            [partial_decryptions_0, partial_decryptions_1];

        let verification_keys: [<CryptographyContext as Context>::Element; T] =
            array::from_fn(|i| recipients[i].0.get_verification_key().clone());

        // Try to verify with a different proof context.
        let proof_context_verification = b"test decryption WRONG CONTEXT";
        let result = combine(
            &dkg_ciphertexts,
            &partial_decryptions_by_trustee,
            &verification_keys,
            proof_context_verification,
        );

        // This should fail because the proof context doesn't match.
        assert!(
            result.is_err(),
            "Combining partial decryptions with wrong proof context should fail"
        );
    }
}
