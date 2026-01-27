// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Basic end-to-end test of the trustee protocols. This tests
//! that the protocols can complete when there is reliable,
//! ordered message delivery. More complex tests are performed
//! by the Stateright model checker elsewhere.

#[cfg(test)]
mod tests {
    use crate::cryptography::{
        Context, CryptographyContext, ElectionKey, PseudonymCryptogramPair, SigningKey,
        encrypt_ballot,
    };
    use crate::elections::{Ballot, BallotStyle, ElectionHash, string_to_election_hash};
    use crate::trustee_protocols::trustee_administration_server::handlers::{
        StartMixing, StartSetup,
    };
    use crate::trustee_protocols::trustee_administration_server::top_level_actor::{
        MixingParameters, TASActor, TASCheckpoint, TASInput, TASOutput,
    };
    use crate::trustee_protocols::trustee_application::handlers::ApproveSetup;
    use crate::trustee_protocols::trustee_application::top_level_actor::{
        TrusteeActor, TrusteeCheckpoint, TrusteeInput, TrusteeOutput,
    };
    use crate::trustee_protocols::trustee_cryptography::TrusteeKeyPair;
    use crate::trustee_protocols::trustee_messages::{TAS_NAME, TrusteeInfo, TrusteeMsg};
    use std::collections::{HashMap, HashSet};

    const MANIFEST: &str = "test_election_manifest";

    /// Helper to create initial test setup with TAS and trustees.
    /// If checkpoints and key material are provided, actors are
    /// restored from those checkpoints. Otherwise, fresh actors and
    /// keys are created.
    fn create_test_actors(
        num_trustees: usize,
        threshold: usize,
        tas_checkpoint_opt: Option<TASCheckpoint>,
        trustee_checkpoints_opt: Option<Vec<TrusteeCheckpoint>>,
        tas_signing_key_opt: Option<SigningKey>,
        trustee_signing_keys_opt: Option<Vec<SigningKey>>,
        trustee_encryption_keypairs_opt: Option<Vec<TrusteeKeyPair>>,
    ) -> (
        TASActor,
        Vec<TrusteeActor>,
        TASCheckpoint,
        SigningKey,
        Vec<SigningKey>,
        Vec<TrusteeKeyPair>,
    ) {
        let mut rng = CryptographyContext::get_rng();

        // Use provided keys or generate fresh ones.
        let tas_signing_key = tas_signing_key_opt.unwrap_or_else(|| SigningKey::generate(&mut rng));
        let trustee_signing_keys = trustee_signing_keys_opt.unwrap_or_else(|| {
            (0..num_trustees)
                .map(|_| SigningKey::generate(&mut rng))
                .collect()
        });
        let trustee_encryption_keypairs = trustee_encryption_keypairs_opt.unwrap_or_else(|| {
            (0..num_trustees)
                .map(|_| TrusteeKeyPair::generate())
                .collect()
        });

        // Generate a dummy encryption public key for TAS (it won't be used).
        let dummy_tas_enc_key = TrusteeKeyPair::generate().pkey;

        // Create trustee info list (TAS is index 0).
        let mut trustees_info = vec![TrusteeInfo {
            name: TAS_NAME.to_string(),
            verifying_key: tas_signing_key.verifying_key(),
            public_enc_key: dummy_tas_enc_key,
        }];

        for (i, (sk, enc_kp)) in trustee_signing_keys
            .iter()
            .zip(&trustee_encryption_keypairs)
            .enumerate()
        {
            trustees_info.push(TrusteeInfo {
                name: format!("Trustee{}", i + 1),
                verifying_key: sk.verifying_key(),
                public_enc_key: enc_kp.pkey.clone(),
            });
        }

        // Use provided TAS checkpoint or create a fresh one.
        let tas_checkpoint = tas_checkpoint_opt.unwrap_or_else(|| TASCheckpoint {
            manifest: MANIFEST.to_string(),
            election_hash: string_to_election_hash(MANIFEST),
            threshold: threshold as u32,
            trustees: trustees_info.clone(),
            board: vec![],
            election_public_key: None,
            active_trustees: HashSet::new(),
        });

        // Create TAS actor.
        let tas = TASActor::new(tas_signing_key.clone(), tas_checkpoint.clone())
            .expect("Failed to create TAS");

        // Create trustee actors, optionally restoring from checkpoints.
        // We need to clone the keys/keypairs for the return value,
        // since we transfer ownership when creating the actors.
        let trustee_signing_keys_clone = trustee_signing_keys.clone();
        let trustee_encryption_keypairs_clone: Vec<_> = trustee_encryption_keypairs
            .iter()
            .map(|kp| TrusteeKeyPair {
                pkey: kp.pkey.clone(),
                skey: kp.skey.clone(),
            })
            .collect();

        let trustees: Vec<TrusteeActor> = trustee_signing_keys
            .into_iter()
            .zip(trustee_encryption_keypairs.into_iter())
            .enumerate()
            .map(|(i, (sk, enc_kp))| {
                let checkpoint = trustee_checkpoints_opt
                    .as_ref()
                    .map(|checkpoints| checkpoints[i].clone());
                TrusteeActor::new(trustees_info[i + 1].clone(), sk, enc_kp, checkpoint)
                    .expect(&format!("Failed to create trustee {}", i))
            })
            .collect();

        (
            tas,
            trustees,
            tas_checkpoint,
            tas_signing_key,
            trustee_signing_keys_clone,
            trustee_encryption_keypairs_clone,
        )
    }

    /// Helper to create dummy encrypted ballots for testing.
    fn create_dummy_ballots(
        election_key: &ElectionKey,
        election_hash: &ElectionHash,
        count: usize,
    ) -> Vec<PseudonymCryptogramPair> {
        let mut ballots = Vec::new();

        for i in 0..count {
            let mut ballot = Ballot::test_ballot(i as u64);
            let voter_pseudonym = "voter".to_string() + &i.to_string();

            // we want a max of 3 ballot styles, so that we don't do a
            // bunch of shuffles each with a single ballot
            ballot.ballot_style = (i % 3 + 1) as BallotStyle;
            match encrypt_ballot(ballot, election_key, election_hash, &voter_pseudonym) {
                Ok((ballot_cryptogram, _randomizers)) => {
                    ballots.push(PseudonymCryptogramPair {
                        voter_pseudonym,
                        ballot_cryptogram,
                    });
                }
                Err(e) => {
                    panic!("Failed to encrypt ballot {}: {}", i, e);
                }
            }
        }

        ballots
    }

    #[test]
    fn test_end_to_end_3_2() {
        test_end_to_end(3, 2, 15, false);
    }

    #[test]
    fn test_end_to_end_9_5() {
        test_end_to_end(9, 5, 20, false);
    }

    #[test]
    fn test_end_to_end_3_2_with_checkpoint() {
        test_end_to_end(3, 2, 15, true);
    }

    #[test]
    fn test_end_to_end_9_5_with_checkpoint() {
        test_end_to_end(9, 5, 20, true);
    }

    // Test execution of the entire trustee protocol flow from setup
    // through decryption. It assumes every message is reliably delivered
    // in order, and is meant solely to smoke test the protocol. More
    // details/varied tests are performed by the Stateright harness.
    //
    // If `checkpoint_after_dkg` is true, the test will save checkpoints after
    // DKG completes, then restore fresh actors from those checkpoints before
    // continuing with mixing and decryption. This simulates the save-and-
    // restore that would normally happen between the before-election and
    // after-election trustee protocols.
    fn test_end_to_end(
        num_trustees: usize,
        threshold: usize,
        num_ballots: usize,
        checkpoint_after_dkg: bool,
    ) {
        let (
            mut tas,
            mut trustees,
            _checkpoint,
            tas_signing_key,
            trustee_signing_keys,
            trustee_encryption_keypairs,
        ) = create_test_actors(num_trustees, threshold, None, None, None, None, None);

        println!("\n=== End-to-End Trustee Protocol Test ===");
        println!("--- Setup Phase ---");

        let (_output, board_update) = tas.handle_input(&TASInput::StartSetup(StartSetup));
        let setup_update = board_update.expect("TAS should broadcast setup");

        // Deliver setup to trustees and collect approvals.
        let mut approval_messages = Vec::new();
        for trustee in &mut trustees {
            let (trustee_output, _) =
                trustee.handle_input(TrusteeInput::HandleBoardUpdate(setup_update.clone()));

            if let Some(TrusteeOutput::RequestSetupApproval(setup_msg)) = trustee_output {
                let (_approval_output, approval_msg) =
                    trustee.handle_input(TrusteeInput::ApproveSetup(ApproveSetup(setup_msg)));
                if let Some(msg) = approval_msg {
                    approval_messages.push(msg);
                }
            }
        }

        assert_eq!(
            approval_messages.len(),
            num_trustees,
            "All trustees should approve setup"
        );

        // Deliver approvals to TAS.
        let mut setup_complete = false;
        for approval in &approval_messages {
            let (tas_output, broadcast) = tas.handle_input(&TASInput::from(approval.clone()));
            if let Some(b) = broadcast {
                for trustee in &mut trustees {
                    trustee.handle_input(TrusteeInput::HandleBoardUpdate(b.clone()));
                }
            }
            if matches!(tas_output, Some(TASOutput::SetupSuccessful(_))) {
                setup_complete = true;
            }
        }

        assert!(setup_complete, "Setup should complete after all approvals");
        println!("✓ Setup complete");
        println!("--- DKG Phase ---");

        // Tell TAS to start key generation.
        let (_tas_output, tas_broadcast) = tas.handle_input(&TASInput::StartKeyGen(
            crate::trustee_protocols::trustee_administration_server::handlers::StartKeyGen,
        ));

        // Tell trustees to start key generation.
        if let Some(_broadcast) = tas_broadcast {
            panic!("TAS should not send a message to start key generation");
        }

        // Read key shares messages from trustees.
        let mut key_share_messages = Vec::new();
        for trustee in trustees.iter_mut() {
            if let (_, Some(msg)) = trustee.handle_input(TrusteeInput::StartKeyGen(
                crate::trustee_protocols::trustee_application::handlers::StartKeyGen,
            )) {
                key_share_messages.push(msg);
            }
        }

        assert_eq!(
            key_share_messages.len(),
            num_trustees,
            "All trustees should generate key shares"
        );

        // Deliver key shares and collect public keys.
        let mut public_key_messages = Vec::new();
        for key_share_msg in &key_share_messages {
            let (_, broadcast) = tas.handle_input(&TASInput::from(key_share_msg.clone()));
            if let Some(b) = broadcast {
                for trustee in trustees.iter_mut() {
                    if let (_, Some(msg @ TrusteeMsg::ElectionPublicKey(_))) =
                        trustee.handle_input(TrusteeInput::HandleBoardUpdate(b.clone()))
                    {
                        public_key_messages.push(msg);
                    }
                }
            }
        }

        assert_eq!(
            public_key_messages.len(),
            num_trustees,
            "All trustees should generate public keys"
        );

        // Deliver public keys to TAS and collect checkpoints.
        let mut election_key = None;
        let mut saved_tas_checkpoint = None;
        // Map from trustee indices to checkpoints.
        let mut trustee_checkpoints_map: HashMap<usize, TrusteeCheckpoint> = HashMap::new();

        for pk_msg in &public_key_messages {
            let (tas_output, broadcast) = tas.handle_input(&TASInput::from(pk_msg.clone()));
            if let Some(b) = broadcast {
                for (idx, trustee) in trustees.iter_mut().enumerate() {
                    let (trustee_output, _) =
                        trustee.handle_input(TrusteeInput::HandleBoardUpdate(b.clone()));

                    // Collect trustee checkpoints from KeyGenComplete outputs.
                    if let Some(TrusteeOutput::KeyGenComplete(checkpoint)) = trustee_output {
                        trustee_checkpoints_map.insert(idx, checkpoint);
                    }
                }
            }
            if let Some(TASOutput::KeyGenSuccessful(checkpoint)) = tas_output {
                election_key = checkpoint.election_public_key.clone();
                saved_tas_checkpoint = Some(checkpoint);
            }
        }

        let election_key = election_key.expect("DKG should produce an election key");

        println!("✓ DKG complete, election key established");

        // If checkpoint_after_dkg is true, ensure we have all checkpoints
        // and restore actors.
        if checkpoint_after_dkg {
            println!("--- Checkpoint & Restore ---");

            let tas_checkpoint =
                saved_tas_checkpoint.expect("Should have TAS checkpoint from KeyGenSuccessful");
            assert_eq!(
                trustee_checkpoints_map.len(),
                num_trustees,
                "Should have checkpoint from each trustee from KeyGenComplete"
            );

            println!("✓ Collected checkpoints from DKG completion messages");

            // Build ordered list of trustee checkpoints matching the trustee order.
            let saved_trustee_checkpoints: Vec<_> = (0..num_trustees)
                .map(|i| {
                    trustee_checkpoints_map
                        .get(&i)
                        .expect("Missing checkpoint")
                        .clone()
                })
                .collect();

            // Create fresh actors from checkpoints, reusing the same key material.
            let (restored_tas, restored_trustees, _, _, _, _) = create_test_actors(
                num_trustees,
                threshold,
                Some(tas_checkpoint),
                Some(saved_trustee_checkpoints),
                Some(tas_signing_key),
                Some(trustee_signing_keys),
                Some(trustee_encryption_keypairs),
            );

            // Replace the existing actors with restored ones.
            tas = restored_tas;
            trustees = restored_trustees;

            println!("✓ Restored actors from checkpoints");
        }

        println!("--- Mixing Phase ---");

        let election_hash: ElectionHash = string_to_election_hash(MANIFEST);
        let ballots = create_dummy_ballots(&election_key, &election_hash, num_ballots);
        println!("Created {} encrypted ballots", ballots.len());

        // Start mixing with threshold number of active trustees.
        let active_trustee_ids: Vec<_> = trustees
            .iter()
            .take(threshold as usize)
            .map(|t| t.trustee_info.trustee_id())
            .collect();

        println!(
            "Mixing with {} active trustees (threshold={})",
            active_trustee_ids.len(),
            threshold
        );

        let mixing_params = MixingParameters {
            active_trustees: active_trustee_ids.clone(),
            pseudonym_cryptograms: ballots.clone(),
        };

        let mixing_input = TASInput::from(StartMixing(mixing_params));
        let (_tas_output, tas_broadcast) = tas.handle_input(&mixing_input);
        let broadcast = tas_broadcast.expect("TAS should broadcast mixing initialization");

        // Deliver mixing initialization messages to active trustees.
        let mut initial_messages = Vec::new();
        for (i, trustee) in trustees.iter_mut().enumerate() {
            if !active_trustee_ids.contains(&trustee.trustee_info.trustee_id()) {
                continue;
            }

            let (output, msg_opt) =
                trustee.handle_input(TrusteeInput::HandleBoardUpdate(broadcast.clone()));

            if let Some(TrusteeOutput::Failed(f)) = output {
                panic!("Trustee {} failed during mixing init: {:?}", i + 1, f);
            }
            if let Some(msg) = msg_opt {
                initial_messages.push(msg);
            }
        }

        println!(
            "✓ Mixing initialized, {} trustees produced initial messages",
            initial_messages.len()
        );

        // Run mixing and decryption iterations.
        let mut iteration = 0;
        const MAX_ITERATIONS: usize = 50; // just to prevent endless runs
        let mut tas_mixing_complete = false;
        let mut trustees_mixing_complete = 0;
        let mut tas_decryption_complete = false;
        let mut trustees_decryption_complete = 0;

        while iteration < MAX_ITERATIONS {
            iteration += 1;

            let mut new_messages = Vec::new();
            for initial_msg in &initial_messages {
                println!(
                    "  TAS processing message: {:?}",
                    match initial_msg {
                        TrusteeMsg::EGCryptograms(_) => "EGCryptograms",
                        TrusteeMsg::PartialDecryptions(_) => "PartialDecryptions",
                        TrusteeMsg::DecryptedBallots(_) => "DecryptedBallots",
                        _ => "Other",
                    }
                );

                let (tas_output, broadcast) =
                    tas.handle_input(&TASInput::from(initial_msg.clone()));

                println!(
                    "    TAS output: {:?}, broadcast: {}",
                    tas_output
                        .as_ref()
                        .map(|o| format!("{:?}", o).chars().take(40).collect::<String>()),
                    if broadcast.is_some() { "Some" } else { "None" }
                );

                // Check TAS outputs.
                match tas_output {
                    Some(TASOutput::MixingSuccessful(_checkpoint)) => {
                        if !tas_mixing_complete {
                            tas_mixing_complete = true;
                            println!(
                                "✓ TAS reports mixing complete after {} iterations",
                                iteration
                            );
                        }
                    }
                    Some(TASOutput::DecryptionSuccessful(_checkpoint)) => {
                        tas_decryption_complete = true;
                        println!(
                            "✓ TAS reports decryption complete after {} iterations",
                            iteration
                        );
                    }
                    Some(TASOutput::Failed(f)) => {
                        panic!("TAS failed: {}", f.failure_msg);
                    }
                    Some(TASOutput::InvalidInput(f)) => {
                        panic!("TAS received invalid input: {}", f.failure_msg);
                    }
                    _ => {}
                }

                if let Some(b) = broadcast {
                    println!(
                        "  Broadcasting update with {} messages to active trustees",
                        b.msgs.len()
                    );
                    for (idx, msg) in &b.msgs {
                        println!(
                            "    Message at index {}: {:?}",
                            idx,
                            match msg {
                                TrusteeMsg::Setup(_) => "Setup",
                                TrusteeMsg::KeyShares(_) => "KeyShares",
                                TrusteeMsg::ElectionPublicKey(_) => "ElectionPublicKey",
                                TrusteeMsg::MixInitialization(_) => "MixInitialization",
                                TrusteeMsg::EGCryptograms(_) => "EGCryptograms",
                                TrusteeMsg::PartialDecryptions(_) => "PartialDecryptions",
                                TrusteeMsg::DecryptedBallots(_) => "DecryptedBallots",
                                TrusteeMsg::TrusteeBBUpdateRequest(_) => "BBUpdateRequest",
                                TrusteeMsg::TrusteeBBUpdate(_) => "BBUpdate",
                            }
                        );
                    }

                    for (i, trustee) in trustees.iter_mut().enumerate() {
                        if !active_trustee_ids.contains(&trustee.trustee_info.trustee_id()) {
                            continue;
                        }

                        println!(
                            "  Delivering to Trustee {}, current state: {:?}, board size: {}",
                            i + 1,
                            trustee.state,
                            trustee.processed_board.len()
                        );

                        let (output, msg_opt) =
                            trustee.handle_input(TrusteeInput::HandleBoardUpdate(b.clone()));

                        println!(
                            "    -> Output: {:?}, Message: {}",
                            output
                                .as_ref()
                                .map(|o| format!("{:?}", o).chars().take(50).collect::<String>()),
                            if msg_opt.is_some() { "Some" } else { "None" }
                        );

                        // Check trustee outputs.
                        match output {
                            Some(TrusteeOutput::Failed(f)) => {
                                panic!("Trustee {} failed: {}", i + 1, f.failure_msg);
                            }
                            Some(TrusteeOutput::MixingComplete) => {
                                println!("✓ Trustee {} reports mixing complete", i + 1);
                                trustees_mixing_complete += 1;
                            }
                            Some(TrusteeOutput::DecryptionComplete(_checkpoint)) => {
                                println!("✓ Trustee {} reports decryption complete", i + 1);
                                trustees_decryption_complete += 1;
                            }
                            _ => {}
                        }

                        if let Some(msg) = msg_opt {
                            println!(
                                "    -> Trustee {} produced message: {:?}",
                                i + 1,
                                match &msg {
                                    TrusteeMsg::EGCryptograms(_) => "EGCryptograms",
                                    TrusteeMsg::PartialDecryptions(_) => "PartialDecryptions",
                                    TrusteeMsg::DecryptedBallots(_) => "DecryptedBallots",
                                    _ => "Other",
                                }
                            );
                            new_messages.push(msg);
                        }
                    }
                }
            }

            // Stop when both mixing and decryption are done.
            if tas_mixing_complete && tas_decryption_complete {
                break;
            }

            initial_messages = new_messages;

            println!(
                "  End of iteration {}: {} messages queued for next iteration",
                iteration,
                initial_messages.len()
            );

            if initial_messages.is_empty() {
                println!("  No more messages, ending loop");
                break;
            }
        }

        // Assert mixing completed successfully at TAS.
        assert!(
            tas_mixing_complete,
            "Mixing should complete within {} iterations",
            MAX_ITERATIONS
        );

        println!("✓ Mixing complete at TAS");

        // Only active trustees should confirm mixing completion.
        assert_eq!(
            trustees_mixing_complete, threshold,
            "All {} active trustees should confirm mixing completion",
            threshold
        );

        println!(
            "✓ All {} active trustees confirmed mixing completion",
            threshold
        );

        println!("\n--- Decryption Phase ---");

        assert!(
            tas_decryption_complete,
            "TAS should complete decryption within {} iterations",
            MAX_ITERATIONS
        );
        println!("✓ TAS reports decryption complete");

        // Only active trustees should confirm decryption completion.
        assert_eq!(
            trustees_decryption_complete, threshold,
            "All {} active trustees should confirm decryption completion",
            threshold
        );

        println!(
            "✓ All {} active trustees confirmed decryption completion",
            threshold
        );

        println!("\n=== End-to-End Test Complete ===");
    }
}
