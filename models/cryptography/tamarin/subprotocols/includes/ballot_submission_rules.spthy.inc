/* Ballot Submission Subprotocol Rules */

/* Voter Application */

/*
  This rule encapsulates the part of the voter application that presents
  a ballot to the voter, gathers their choices, and submits it; it abstracts
  away all the user interaction, in favor of just creating a fresh ballot.
 */
rule BallotSubmission_VA_PresentBallot [role="VA"]:
  let pk_voter = pk(~sk_voter)
      cryptograms = <ny_encrypt_c1(~ballot, pk_election, ~r), ny_encrypt_c2(~ballot, pk_election, ~r), ny_encrypt_p(~ballot, pk_election, ~r)>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      sig_msg_submit_ballot = sign(msg_submit_ballot, '1', ~sk_voter)
      signed_msg_submit_ballot = <msg_submit_ballot, sig_msg_submit_ballot> in
    [ VA_State_PresentBallot(~ec, ~va_id, $V, ~sk_voter),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ballot_style, signed_voter_auth),
      !ElectionPublicKey(~ec, pk_election),
      Fr(~r), /* randomizer */
      Fr(~ballot), /* ballot choices */
      Fr(~cid) /* secure channel ID */ ]
  --[ VA_PresentBallot_Trace(~ec, ~va_id, $V, pseudo, ~sk_voter, ballot_style, ~ballot, cryptograms, ~r),
      OUT_PSEUDO_TERM(sig_msg_submit_ballot) ]->
    [ SecureSend(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_submit_ballot),
      VA_State_BallotSubmitResponse(~ec, ~va_id, ~cid, $V, ~ballot, cryptograms, ~r) ]

/*
  This rule receives a response from the DBB saying that a ballot was
  successfully submitted and posted to the public bulletin board, and
  providing the ballot tracker for use in the casting and checking
  subprotocols. The BB persistent facts here allow us to check that the
  tracker actually corresponds to a bulletin board entry, and that that
  bulletin board entry contains the ballot we submitted.

  In the nonce-based BB model, the tracker is the entry's `eid`, so we
  look up `!BB_Entry(~bbid, tracker, ballot_bb_entry, prev_unused)`.

  Validation checks performed implicitly:
    - the bulletin board entry corresponding to the tracker we received
      actually exists (via pattern match)
    - the signed ballot submission message we submitted is in the bulletin
      board entry corresponding to the tracker (via pattern match)
 */
rule BallotSubmission_VA_BallotSubmitResponse_BallotTracker_Success [role="VA"]:
  let msg_ballot_tracker = Msg_DBB_Ballot_Tracker(~ec, tracker)
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      sig_msg_submit_ballot = sign(msg_submit_ballot, '1', ~sk_voter)
      signed_msg_submit_ballot = <msg_submit_ballot, sig_msg_submit_ballot>
      ballot_bb_entry = BBEntry_Ballot_Submission(~ec, timestamp, signed_msg_submit_ballot) in
    [ VA_State_BallotSubmitResponse(~ec, ~va_id, ~cid, $V, ~ballot, cryptograms, ~r),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ballot_style, signed_voter_auth),
      !BB_Root(~ec, ~bbid, ~ec, root_eid_unused),
      !BB_Entry(~bbid, tracker, ballot_bb_entry, prev_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_ballot_tracker) ]
  --[ VA_BallotTracker_Trace(~ec, ~va_id, $V, pseudo, ~sk_voter, ballot_style, ~ballot, cryptograms, ~r, tracker),
      IN_PSEUDO_TERM(sig_msg_submit_ballot, pseudo),
      OUT_BALLOTCHECK_VA_CHECK(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker) ]->
    [ !VA_Submitted_Ballot(~ec, ~va_id, ~ballot, cryptograms, ~r, tracker),
      VA_State_CheckOrCast(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker) ]

/*
  This rule receives a response from the DBB saying that a ballot was
  submitted and posted to the public bulletin board, but the bulletin board
  entry doesn't match the submitted ballot, indicating an error condition.
  If our secure channels remain secure, this should never happen.
 */
rule BallotSubmission_VA_BallotSubmitResponse_BallotTracker_BallotMismatch [role="VA"]:
  let msg_ballot_tracker = Msg_DBB_Ballot_Tracker(~ec, tracker)
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sign(msg_submit_ballot, '1', ~sk_voter)>
      ballot_bb_entry = BBEntry_Ballot_Submission(~ec, timestamp, bb_entry_msg) in
    [ VA_State_BallotSubmitResponse(~ec, ~va_id, ~cid, $V, ~ballot, cryptograms, ~r),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ballot_style, signed_voter_auth),
      !BB_Root(~ec, ~bbid, ~ec, root_eid_unused),
      !BB_Entry(~bbid, tracker, ballot_bb_entry, prev_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_ballot_tracker) ]
  --[ VA_BallotTracker_BallotMismatch_Trace(~ec, ~va_id, $V, pseudo, ~sk_voter, ballot_style, ~ballot, cryptograms, ~r, tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if bb entry doesn't match */
      Neq(bb_entry_msg, signed_msg_submit_ballot) ]->
    [ VA_State_SubmissionError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  submitted and posted to the public bulletin board, but there is no
  matching bulletin board entry for the received ballot tracker, indicating
  an error condition. If our secure channels remain secure, this should
  never happen.
 */
rule BallotSubmission_VA_BallotSubmitResponse_BallotTracker_NoBBEntry [role="VA"]:
  let msg_ballot_tracker = Msg_DBB_Ballot_Tracker(~ec, tracker) in
    [ VA_State_BallotSubmitResponse(~ec, ~va_id, ~cid, $V, ~ballot, cryptograms, ~r),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ballot_style, signed_voter_auth_unused),
      !BB_Root(~ec, ~bbid, ~ec, root_eid_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_ballot_tracker) ]
  --[ VA_BallotTracker_NoBBEntry_Trace(~ec, ~va_id, $V, pseudo, ~sk_voter, ballot_style, ~ballot, cryptograms, ~r, tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if bb entry doesn't exist */
      NoBBEntry(~bbid, tracker) ]->
    [ VA_State_SubmissionError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that it was unable to
  post a submitted ballot to the bulletin board for some reason. In this
  model, the only reasons this should be able to happen are if the signature
  on the ballot submission doesn't verify, or if the voter public key used
  for the ballot submission is not authorized to cast a ballot because it
  was superceded by a later authentication with a different VA.
 */
rule BallotSubmission_VA_BallotSubmitResponse_Error [role="VA"]:
  let msg_ballot_error = Msg_DBB_Ballot_Error(~ec, error) in
    [ VA_State_BallotSubmitResponse(~ec, ~va_id, ~cid, $V, ~ballot, cryptograms, ~r),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_ballot_error) ]
  --[ VA_BallotTracker_Error_Trace(~ec, ~va_id, $V, error),
      VA_Error_Trace(~ec, ~va_id) ]->
    [ VA_State_SubmissionError(~ec, ~va_id) /* UI presents an error */ ]

/* Digital Ballot Box */

/*
  This rule receives a submitted ballot from an authorized voter
  successfully, then transitions to a state where it appends it to
  the bulletin board. Note that the fact that triggers appending
  to the bulletin board is persistent, because of the way the
  bulletin board works in Tamarin.

  Validation checks performed explicitly (via restrictions):
    - the EAS signature on the embedded VoterAuthorization is valid
    - the signature on the submitted ballot message is valid
    - the cryptogram's proof is valid

  Validation checks performed implicitly:
    - the voter's pseudonym, public key, and ballot style are embedded
      in the EAS-signed VoterAuthorization (via pattern matching)
 */
rule BallotSubmission_DBB_ReceiveSubmittedBallot [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      cryptograms = <c1, c2, p>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sig>
      valid_proof = ny_check(c1, c2, p) in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_submit_ballot) ]
  --[ DBB_ReceiveSubmittedBallot_Trace(~ec, ~va_id, msg_submit_ballot),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, true), /* valid EAS authorization signature */
      SignatureVerified(sig, e1_sig(sig), pk(e3_sig(sig)), msg_submit_ballot,
                        pk_voter, true), /* valid voter signature */
      Eq(valid_proof, true), /* valid cryptogram proof */
      OUT_PSEUDO_TERM(sig) ]->
    [ !DBB_Submitted_Ballot(~ec, ~va_id, ~cid, pseudo, signed_msg_submit_ballot) ]

/*
  This rule handles the error case where a submitted ballot fails its
  voter signature check.
 */
rule BallotSubmission_DBB_ReceiveSubmittedBallot_FailedSignature [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sig> in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_submit_ballot) ]
  --[ DBB_ReceiveSubmittedBallot_FailedSignature_Trace(~ec, ~va_id, msg_submit_ballot),
      DBB_Ballot_Error_Trace(~ec, ~va_id),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, true), /* valid EAS authorization signature */
      SignatureVerified(sig, e1_sig(sig), pk(e3_sig(sig)), msg_submit_ballot,
                        pk_voter, false) /* invalid voter signature */ ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, Msg_DBB_Ballot_Error(~ec, 'failed signature')) ]

/*
  This rule handles the error case where a submitted ballot fails its
  proof check.
 */
rule BallotSubmission_DBB_ReceiveSubmittedBallot_FailedProof [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      cryptograms = <c1, c2, p>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sig>
      valid_proof = ny_check(c1, c2, p) in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_submit_ballot) ]
  --[ DBB_ReceiveSubmittedBallot_FailedProof_Trace(~ec, ~va_id, msg_submit_ballot),
      DBB_Ballot_Error_Trace(~ec, ~va_id),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, true), /* valid EAS authorization signature */
      Neq(valid_proof, true) /* invalid cryptogram proof */ ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, Msg_DBB_Ballot_Error(~ec, 'failed proof')) ]

/*
  This rule handles the error case when the EAS signature on the voter
  authorization embedded in the submitted ballot is invalid.
 */
rule BallotSubmission_DBB_ReceiveSubmittedBallot_FailedAuthSignature [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sig> in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_submit_ballot) ]
  --[ DBB_ReceiveSubmittedBallot_Unauthorized_Trace(~ec, ~va_id, msg_submit_ballot),
      DBB_Ballot_Error_Trace(~ec, ~va_id),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, false) /* invalid EAS authorization signature */ ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, Msg_DBB_Ballot_Error(~ec, 'unauthorized voter')) ]

/*
  This rule publishes a successfully submitted ballot to the bulletin
  board. It needs to be a separate rule (as does the one that checks
  to make sure the published ballot is on the board) because of the
  way the bulletin board works in Tamarin (we have to guess which entry
  is the current tip of the board and if it isn't, the append will fail).

  The `bb_entry` content (containing fresh `~ts`) is stored in the state fact
  so the Confirm rule can discover the assigned `eid` by content-matching.
 */
rule BallotSubmission_DBB_AppendSubmittedBallot [role="DBB"]:
  let bb_entry = BBEntry_Ballot_Submission(~ec, ~ts, signed_msg_submit_ballot) in
    [ !DBB_Submitted_Ballot(~ec, ~va_id, ~cid, pseudo, signed_msg_submit_ballot),
      Fr(~ts),
      !BB_Root(~ec, bbid, r_unused, root_eid_unused),
      !BB_Entry(bbid, prev_eid, e_unused, prev_prev_unused) ]
  --[ DBB_AppendSubmittedBallot_Trace(~ec, ~va_id, signed_msg_submit_ballot, bbid, prev_eid),
      Unique(<'DBB_AppendSubmittedBallot', signed_msg_submit_ballot, prev_eid>),
      SubmissionNotOnBB(bbid, signed_msg_submit_ballot) ]->
    [ BB_Append_Request(bbid, bb_entry, prev_eid),
      DBB_State_ConfirmBallotPosting(~ec, ~va_id, ~cid, pseudo, bb_entry) ]

/*
  This rule waits for a submitted ballot to be successfully posted to
  the bulletin board, then sends an appropriate message back to the VA.
  The tracker (`eid`) is discovered by content-matching the known `bb_entry`
  against `!BB_Entry` — unique because `bb_entry` contains fresh `~ts`.

  Note that this _must_ succeed for some tracker, for any successful
  ballot submission, because there is no way in Tamarin for the bulletin
  board to fail.
 */
rule BallotSubmission_DBB_ConfirmBallotPosting [role="DBB"]:
  let msg_tracker = Msg_DBB_Ballot_Tracker(~ec, ~tracker) in
    [ DBB_State_ConfirmBallotPosting(~ec, ~va_id, ~cid, pseudo, bb_entry),
      !BB_Root(~ec, bbid, r_unused, root_eid_unused),
      !BB_Entry(bbid, ~tracker, bb_entry, prev_unused) ]
  --[ DBB_ConfirmBallotPosting_Trace(~ec, ~va_id, bb_entry, bbid, ~tracker) ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, msg_tracker) ]
