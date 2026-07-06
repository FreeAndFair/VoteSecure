/* Ballot Cast Subprotocol Rules */

/* Voter Application */

/*
  This rule is, effectively, the voter deciding to check a ballot after their
  submission is confirmed and their tracker is received. A "parallel" rule
  exists in the ballot cast subprotocol for the voter deciding to cast.

  Because the initiation of the check process occurs out of band, with
  the voter typing information into a BCA, this rule triggers a BCA to
  start its execution with (effectively) the information that a voter would
  type in, namely the ballot tracker, then puts the VA into a state where it
  awaits a message from the DBB requesting the randomizers.
 */
rule BallotCheck_VA_Check [role="VA"]:
  let pk_voter = pk(~sk_voter) in
    [ VA_State_CheckOrCast(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth_unused) ]
  --[ VA_CheckBallot_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker),
      IN_BALLOTCHECK_VA_CHECK(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker) ]->
    [ BCA_State_InitiateBallotCheck(~ec, tracker),
      VA_State_RequestRandomizers(~ec, ~va_id, $V, pseudo, ~ballot, cryptograms, ~r, tracker) ]

/*
  This rule receives a request from the DBB to encrypt the randomizers for
  a specific BCA and send them to the DBB for relay.

  Note that there is no error condition that explicitly occurs if a malformed
  request comes from the DBB (e.g., a BCA message whose signature doesn't
  verify or a message looking to check an incorrect tracker); such requests
  are simply ignored. In a real implementation, they might result in an
  incorrect value being displayed for the user to check; in the model, we
  assume that the user always performs that check correctly.

  Note also that we encrypt the randomizers to the BCA's public encryption
  key, and use "throwaway" randomness to do so - so only the BCA's secret
  encryption key can decrypt them.

  Validation checks performed implicitly:
    - the tracker in the signed ballot request message matches the tracker
      we are expecting to check (via pattern match)

  Validation checks performed explicitly via restrictions:
    - the signed ballot check request message is in fact signed by the key
      corresponding to the BCA public key in the message
 */
rule BallotCheck_VA_RequestRandomizers [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_bca_req = Msg_BCA_Check_Request(~ec, tracker, pk_bca_encrypt, pk_bca_sign)
      signed_msg_bca_req = <msg_bca_req, sig_bca_req>
      msg_dbb_req = Msg_DBB_Check_Request(~ec, signed_msg_bca_req)
      encrypted_randomizers = <ny_encrypt_c1(~r, pk_bca_encrypt, ~throwaway_r), ny_encrypt_c2(~r, pk_bca_encrypt, ~throwaway_r), ny_encrypt_p(~r, pk_bca_encrypt, ~throwaway_r)>
      msg_randomizers = Msg_VA_Check_Randomizers(~ec, signed_msg_bca_req, encrypted_randomizers, pk_voter) in
    [ VA_State_RequestRandomizers(~ec, ~va_id, $V, pseudo, ~ballot, cryptograms, ~r, tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~ballot_style, signed_voter_auth_unused),
      Fr(~throwaway_r),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_dbb_req) ]
  --[ VA_RequestRandomizers_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt),
      SignatureVerified(sig_bca_req, e1_sig(sig_bca_req), pk(e3_sig(sig_bca_req)), msg_bca_req,
                        pk_bca_sign, true), /* valid signature */
      IN_SECURE_RECEIVE(~cid, <~ec, 'DBB'>, ~va_id, msg_dbb_req),
      OUT_PSEUDO_TERM(sig_bca_req) ]->
    [ SecureSend(~cid, ~va_id, <~ec, 'DBB'>, <msg_randomizers, sign(msg_randomizers, '1', ~sk_voter)>),
      !VA_SentRandomizers(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt),
      VA_State_AwaitCheckResult(~ec, ~va_id, $V, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt) ]

/*
  This rule is one of two that determines what the VA does after sending out
  the randomizers. Since there is no user interaction in Tamarin, we simulate
  such by having two separate rules that can be chosen nondeterministically.
  This one simulates the voter being satisfied with the check result, which
  puts them back in the "check or cast" situation (they can always choose to
  "double check" with a different BCA).
 */
rule BallotCheck_VA_CheckResult_OK [role="VA"]:
    [ VA_State_AwaitCheckResult(~ec, ~va_id, $V, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~ballot_style, signed_voter_auth_unused) ]
  --[ VA_CheckResult_OK_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt),
      OUT_BALLOTCHECK_VA_CHECK(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker) ]->
    [ VA_State_CheckOrCast(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker) ]

/*
  This rule is one of two that determines what the VA does after sending out
  the randomizers. Since there is no user interaction in Tamarin, we simulate
  such by having two separate rules that can be chosen nondeterministically.
  This one simulates the voter being unsatisfied with the check result and
  wanting to cast another ballot. Since we presume that such a voter would
  likely choose to use a different VA (as they now don't trust the one they
  used, since the check wasn't OK), we end the protocol here and assume they
  will start over with another VA (including the authentication process).
 */
rule BallotCheck_VA_CheckResult_NotOK [role="VA"]:
    [ VA_State_AwaitCheckResult(~ec, ~va_id, $V, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~ballot_style, signed_voter_auth_unused),
      /* Fr(~new_va_id) */ ]
  --[ VA_CheckResult_NotOK_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker, pk_bca_encrypt) ]->
    [ /* protocol ends */ ]

/* Digital Ballot Box */

/*
  This rule receives a check request from a BCA and relays it to
  the relevant VA. Assuming that the requested tracker exists, we
  don't particularly care whether it's the most recent ballot for
  a given voter, or even whether it's already been cast; in situations
  where it is not the most recent ballot, or has already been cast,
  there won't be a VA waiting to receive the check message and the
  protocol will dead-end at that point.

  Validation checks performed explicitly (via restrictions):
    - the signature on the submitted check request is valid

  Validation checks performed implicitly:
    - the ballot that is to be cast exists on the bulletin board
      (via pattern match)
 */
rule BallotCheck_DBB_ReceiveCheckRequest [role="DBB"]:
  let msg_bca_req = Msg_BCA_Check_Request(~ec, tracker, pk_bca_encrypt, pk_bca_sign)
      signed_msg_bca_req = <msg_bca_req, sig_bca_req>
      msg_dbb_req = Msg_DBB_Check_Request(~ec, signed_msg_bca_req)
      ballot_bb_entry = BBEntry_Ballot_Submission(~ec, timestamp, signed_msg_submit_ballot) in
    [ !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, tracker, ballot_bb_entry, prev_unused),
      !DBB_Submitted_Ballot(~ec, ~va_id, ~cid_va, pseudo, signed_msg_submit_ballot),
      SecureReceive(~cid_bca, ~bca_id, <~ec, 'DBB'>, signed_msg_bca_req) ]
  --[ DBB_ReceiveCheckRequest_Trace(~ec, ~va_id, ~bca_id, msg_bca_req),
      SignatureVerified(sig_bca_req, e1_sig(sig_bca_req), pk(e3_sig(sig_bca_req)), msg_bca_req,
                        pk_bca_sign, true), /* valid signature */
      IN_SECURE_RECEIVE(~cid_bca, ~bca_id, <~ec, 'DBB'>, signed_msg_bca_req),
      OUT_PSEUDO_TERM(sig_bca_req) ]->
    [ SecureSend(~cid_va, <~ec, 'DBB'>, ~va_id, msg_dbb_req),
      !DBB_Randomizers_Requested(~ec, ~va_id, ~bca_id, tracker),
      DBB_State_ForwardRandomizers(~ec, ~va_id, ~cid_va, ~bca_id, ~cid_bca, signed_msg_bca_req) ]

/*
  This rule receives the randomizers from a VA and relays them
  to the corresponding BCA.

  Validation checks performed implicitly:
    - the VA is the one that submitted the original ballot being checked
    - the original check request is one that we forwarded previously

  Validation checks performed explicitly:
    - the signature on the randomizers message is valid (note that we could
      just as easily not check this, as the BCA will check it anyway, but
      it doesn't hurt to rule out traces where the signature is invalid)
 */
rule BallotCheck_DBB_ForwardRandomizers [role="DBB"]:
  let msg_bca_req = Msg_BCA_Check_Request(~ec, tracker, pk_bca_encrypt, pk_bca_sign)
      signed_msg_bca_req = <msg_bca_req, sig_bca_req>
      msg_randomizers = Msg_VA_Check_Randomizers(~ec, signed_msg_bca_req, encrypted_randomizers, pk_voter)
      signed_msg_randomizers = <msg_randomizers, sig_randomizers>
      msg_dbb_randomizers = Msg_DBB_Check_Randomizers(~ec, signed_msg_randomizers) in
    [ DBB_State_ForwardRandomizers(~ec, ~va_id, ~cid_va, ~bca_id, ~cid_bca, signed_msg_bca_req),
      SecureReceive(~cid_va, ~va_id, <~ec, 'DBB'>, signed_msg_randomizers) ]
  --[ DBB_ForwardRandomizers_Trace(~ec, ~va_id, ~bca_id, msg_randomizers),
      SignatureVerified(sig_randomizers, e1_sig(sig_randomizers),
                        pk(e3_sig(sig_randomizers)), msg_randomizers,
                        pk_voter, true), /* valid signature */
      IN_SECURE_RECEIVE(~cid_va, ~va_id, <~ec, 'DBB'>, signed_msg_randomizers),
      OUT_PSEUDO_TERM(sig_randomizers) ]->
    [ !DBB_Randomizers_Forwarded(~ec, ~va_id, ~bca_id, tracker, msg_randomizers),
      SecureSend(~cid_bca, <~ec, 'DBB'>, ~bca_id, msg_dbb_randomizers) ]

/* Ballot Check Application */

/*
  This rule starts an instance of the ballot check application. It is
  triggered by the VA, but does not have any knowledge of the VA or any
  ballot information (except the tracker) until it gets the information
  forwarded from the DBB.

  Validation checks performed implicitly:
    - there is a ballot submission entry on the bulletin board corresponding
      to the tracker (via pattern match)
 */
rule BallotCheck_BCA_InitiateBallotCheck [role="BCA"]:
  let pk_bca_encrypt = pk(~sk_bca_encrypt)
      pk_bca_sign = pk(~sk_bca_sign)
      msg_bca_req = Msg_BCA_Check_Request(~ec, tracker, pk_bca_encrypt, pk_bca_sign)
      auth_data_unused = VoterAuthorization(~ec, pseudo_unused, pk_voter_unused, ballot_style_unused, ts_unused)
      signed_voter_auth_unused = <auth_data_unused, sig_auth_unused>
      msg_submit_ballot_unused = Msg_VA_Submit_Ballot(~ec, cryptograms_unused, signed_voter_auth_unused)
      signed_msg_submit_ballot = <msg_submit_ballot_unused, sig_msg_submit_ballot_unused>
      ballot_bb_entry = BBEntry_Ballot_Submission(~ec, timestamp, signed_msg_submit_ballot) in
    [ BCA_State_InitiateBallotCheck(~ec, tracker),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, tracker, ballot_bb_entry, prev_unused),
      Fr(~sk_bca_encrypt),
      Fr(~sk_bca_sign),
      Fr(~bca_id),
      Fr(~cid) ]
  --[ BCA_InitiateBallotCheck_Trace(~ec, ~bca_id, tracker) ]->
    [ SecureSend(~cid, ~bca_id, <~ec, 'DBB'>, <msg_bca_req, sign(msg_bca_req, '1', ~sk_bca_sign)>),
      BCA_State_AwaitRandomizers(~ec, tracker, ~bca_id, ~cid, ~sk_bca_encrypt, ~sk_bca_sign, ballot_bb_entry) ]

/*
  This rule receives the randomizers and attempts to decrypt the ballot with
  them. Note that if the randomizers do not successfully decrypt the ballot,
  this rule doesn't execute (because the decryptions don't pattern match).

  We specify `no_derivcheck` for this rule, because it pattern-matches the
  original ballot rather than explicitly decrypting it using a destructor.

  Validation checks performed implicitly:
    - the randomizers are a response to the request message we originally sent
      (via pattern match)
    - the ballot cryptograms decrypt using the randomness we receive (via
      pattern match)
    - the ballot was signed with the same key as the randomizers (via pattern
      match)

  Validation checks performed explicitly (via restrictions):
    - the signature on the randomizers is valid
    - the proof of the encrypted randomizers verifies
 */
rule BallotCheck_BCA_ReceiveRandomizers [role="BCA", no_derivcheck]:
  let pk_bca_encrypt = pk(~sk_bca_encrypt)
      pk_bca_sign = pk(~sk_bca_sign)
      msg_bca_req = Msg_BCA_Check_Request(~ec, tracker, pk_bca_encrypt, pk_bca_sign)
      signed_msg_bca_req = <msg_bca_req, sign(msg_bca_req, '1', ~sk_bca_sign)>
      encrypted_randomizers = <c1_r, c2_r, p_r>
      valid_proof = ny_check(c1_r, c2_r, p_r)
      msg_randomizers = Msg_VA_Check_Randomizers(~ec, signed_msg_bca_req, encrypted_randomizers, pk_voter)
      signed_msg_randomizers = <msg_randomizers, sig_randomizers>
      msg_dbb_randomizers = Msg_DBB_Check_Randomizers(~ec, signed_msg_randomizers)
      randomizers = ny_decrypt(c1_r, c2_r, ~sk_bca_encrypt)
      cryptograms = <ny_encrypt_c1(~ballot, pk_election, randomizers), ny_encrypt_c2(~ballot, pk_election, randomizers), ny_encrypt_p(~ballot, pk_election, randomizers)>
      auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sig_msg_submit_ballot>
      ballot_bb_entry = BBEntry_Ballot_Submission(~ec, timestamp, signed_msg_submit_ballot) in
    [ BCA_State_AwaitRandomizers(~ec, tracker, ~bca_id, ~cid, ~sk_bca_encrypt, ~sk_bca_sign, ballot_bb_entry),
      !ElectionPublicKey(~ec, pk_election),
      SecureReceive(~cid, <~ec, 'DBB'>, ~bca_id, msg_dbb_randomizers) ]
  --[ BCA_ReceiveRandomizers_Trace(~ec, ~bca_id, tracker, randomizers),
      SignatureVerified(sig_randomizers, e1_sig(sig_randomizers),
                        pk(e3_sig(sig_randomizers)), msg_randomizers,
                        pk_voter, true), /* valid signature */
      Eq(valid_proof, true) /* valid randomizers proof */ ]->
    [ BCA_State_DisplayDecryptedBallot(~ec, tracker, ~bca_id, ~sk_bca_encrypt, ~sk_bca_sign, ~ballot)
      /*
        BCA displays the ballot to the voter;
        all other protocol action is out of band
      */ ]
