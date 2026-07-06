/* Ballot Cast Subprotocol Rules */

/* Voter Application */

/*
  This rule is, effectively, the voter deciding to cast a ballot after their
  submission is confirmed and their tracker is received. A "parallel" rule
  exists in the ballot check subprotocol for the voter deciding to check.
 */
rule BallotCast_VA_Cast [role="VA"]:
  let msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sign(msg_cast, '1', ~sk_voter)> in
    [ VA_State_CheckOrCast(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth),
      Fr(~cid) ]
  --[ VA_CastBallot_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, tracker) ]->
    [ SecureSend(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast),
      VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, tracker) ]

/*
  This rule receives a response from the DBB saying that a ballot was
  successfully cast and the cast message was posted to the public bulletin
  board, and providing the cast tracker for verification. The BB persistent
  facts here allow us to check that the tracker actually corresponds to a
  bulletin board entry, and that that bulletin board entry contains the
  correct ballot cast information.

  Validation checks performed implicitly:
    - the bulletin board entries corresponding to the trackers we received
      actually exist (via pattern match)
    - the signed ballot cast message we submitted, and the signed ballot
      message we originally submitted, are both in the bulletin board entry
      corresponding to the tracker (via pattern match)
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_Success [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, cast_tracker)
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit = <msg_submit, sign(msg_submit, '1', ~sk_voter)>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sign(msg_cast, '1', ~sk_voter)>
      cast_bb_entry = BBEntry_Ballot_Cast(~ec, ts_cast, signed_msg_submit, signed_msg_cast) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, sub_tracker, sub_bb_entry_unused, prev_sub_unused),
      !BB_Entry(~bbid, cast_tracker, cast_bb_entry, prev_cast_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker) ]->
    [ !VA_Cast_Ballot(~ec, ~va_id, sub_tracker, cast_tracker),
      VA_State_VotingComplete(~ec, ~va_id, sub_tracker, cast_tracker) ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but the ballot in the bulletin board
  cast entry doesn't match the submitted ballot, indicating an error condition.
  If our secure channels remain secure, this should never happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_BallotMismatch [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, cast_tracker)
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit = <msg_submit, sign(msg_submit, '1', ~sk_voter)>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sign(msg_cast, '1', ~sk_voter)>
      cast_bb_entry = BBEntry_Ballot_Cast(~ec, ts_cast, bb_entry_msg, signed_msg_cast) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, sub_tracker, sub_bb_entry_unused, prev_sub_unused),
      !BB_Entry(~bbid, cast_tracker, cast_bb_entry, prev_cast_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_BallotMismatch_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if bb entry's submitted ballot doesn't match ours */
      Neq(bb_entry_msg, signed_msg_submit) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but the cast request in the bulletin
  board cast entry doesn't match the submitted one, indicating an error
  condition. If our secure channels remain secure, this should never
  happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_CastReqMismatch [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, maybe_sub_tracker, cast_tracker)
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit = <msg_submit, sign(msg_submit, '1', ~sk_voter)>
      msg_cast = Msg_VA_Cast_Ballot(~ec, sub_tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sign(msg_cast, '1', ~sk_voter)>
      cast_bb_entry = BBEntry_Ballot_Cast(~ec, ts_cast, signed_msg_submit, bb_entry_msg) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, sub_tracker, sub_bb_entry_unused, prev_sub_unused),
      !BB_Entry(~bbid, cast_tracker, cast_bb_entry, prev_cast_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_BallotMismatch_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if bb entry's cast request doesn't match ours */
      Neq(bb_entry_msg, signed_msg_cast) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but neither message in the bulletin
  board entry matches the ones we sent, indicating an error condition. If
  our secure channels remain secure, this should never happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_BothMismatch [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, maybe_sub_tracker, cast_tracker)
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit = <msg_submit, sign(msg_submit, '1', ~sk_voter)>
      msg_cast = Msg_VA_Cast_Ballot(~ec, sub_tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sign(msg_cast, '1', ~sk_voter)>
      cast_bb_entry = BBEntry_Ballot_Cast(~ec, ts_cast, bb_entry_submit_msg, bb_entry_cast_msg) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, sub_tracker, sub_bb_entry_unused, prev_sub_unused),
      !BB_Entry(~bbid, cast_tracker, cast_bb_entry, prev_cast_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_BothMismatch_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if neither message matches ours */
      Neq(bb_entry_submit_msg, signed_msg_submit),
      Neq(bb_entry_cast_msg, signed_msg_cast) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but there is no matching bulletin
  board entry for the the received cast request tracker, indicating an
  error condition. If our secure channels remain secure, this should
  never happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_NoBBEntryForCast [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, cast_tracker) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth_unused),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, sub_tracker, sub_bb_entry_unused, prev_sub_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_NoBBEntryForCast_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if cast bb entry doesn't exist */
      NoBBEntry(~bbid, cast_tracker) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but there is no matching bulletin
  board entry for the the received submit request tracker, indicating an
  error condition. If our secure channels remain secure, this should
  never happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_NoBBEntryForSubmit [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, cast_tracker) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth_unused),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, cast_tracker, cast_bb_entry_unused, prev_cast_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_NoBBEntryForSubmit_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if submit bb entry doesn't exist */
      NoBBEntry(~bbid, sub_tracker) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that a ballot was
  cast on the public bulletin board, but there is no matching bulletin
  board entry for the either of the received trackers, indicating an
  error condition. If our secure channels remain secure, this should
  never happen.
 */
rule BallotCast_VA_BallotCastResponse_CastConfirmation_NoBBEntryForEither [role="VA"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, cast_tracker) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs_unused, signed_voter_auth_unused),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
  --[ VA_CastConfirmation_NoBBEntryForSubmit_Trace(~ec, ~va_id, pseudo, ~ballot, cryptograms, ~r, sub_tracker, cast_tracker),
      VA_Error_Trace(~ec, ~va_id),
      /* only execute if neither bb entry exists */
      NoBBEntry(~bbid, sub_tracker),
      NoBBEntry(~bbid, cast_tracker) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/*
  This rule receives a response from the DBB saying that it was unable to
  post a cast ballot to the bulletin board for some reason. In this
  model, the only reasons this should be able to happen are if the signature
  on the ballot cast doesn't verify, if the voter public key used
  for the ballot cast is not authorized to cast a ballot because it
  was superseded by a later authentication with a different VA, or if the
  tracker in the cast request refers to a nonexistent or non-matching (e.g.,
  submitted by a different voter) message on the bulletin board.
 */
rule BallotSubmission_VA_BallotCastResponse_Error [role="VA"]:
  let msg_cast_error = Msg_DBB_Cast_Error(~ec, error) in
    [ VA_State_BallotCastResponse(~ec, ~va_id, ~cid, pseudo, ~ballot, cryptograms, ~r, sub_tracker),
      SecureReceive(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_error) ]
  --[ VA_BallotTracker_Error_Trace(~ec, ~va_id, sub_tracker, error),
      VA_Error_Trace(~ec, ~va_id) ]->
    [ VA_State_CastError(~ec, ~va_id) /* UI presents an error */ ]

/* Digital Ballot Box */

/*
  This rule receives a cast request from an authorized voter
  successfully, then transitions to a state where it appends
  it to the bulletin board. Note that the fact that triggers
  appending to the bulletin board is persistent because of the
  way the bulletin board works in Tamarin.

  Validation checks performed explicitly (via restrictions):
    - the EAS signature on the VoterAuthorization embedded in the
      cast message is valid
    - the VoterAuthorization in the cast message is identical to the
      one in the referenced ballot submission bulletin entry
    - the signature on the submitted cast message is valid
    - the voter has not previously cast a ballot

  Validation checks performed implicitly:
    - the ballot that is to be cast exists on the bulletin board
      (via pattern match on !BB_Entry using the tracker as eid)
    - the ballot that is to be cast is the most recent one on the
      bulletin board for the voter (via restriction)
 */
rule BallotCast_DBB_ReceiveCastBallot [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sig_cast>
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit = <msg_submit, sig_submit>
      sub_bb_entry = BBEntry_Ballot_Submission(~ec, ts_sub, signed_msg_submit) in
    [ !EASPublicKey(~ec, pk_eas),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, tracker, sub_bb_entry, prev_unused),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_Trace(~ec, ~va_id, pseudo, msg_cast),
      NoPreviousCast(pseudo),
      MostRecentBallot(~bbid, pseudo, tracker),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, true), /* valid EAS authorization signature */
      SignatureVerified(sig_cast, e1_sig(sig_cast), pk(e3_sig(sig_cast)), msg_cast,
                        pk_voter, true), /* valid voter signature */
      OUT_PSEUDO_TERM(sig_cast) ]->
    [ !DBB_Cast_Ballot(~ec, ~va_id, ~cid, pseudo, tracker, signed_msg_submit, signed_msg_cast) ]

/*
  This rule handles the error case where a submitted cast request
  fails its voter signature check.
 */
rule BallotCast_DBB_ReceiveCastBallot_FailedSignature [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sig_cast> in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_FailedSignature_Trace(~ec, ~va_id, msg_cast),
      DBB_Cast_Error_Trace(~ec, ~va_id),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, true), /* valid EAS authorization signature */
      SignatureVerified(sig_cast, e1_sig(sig_cast), pk(e3_sig(sig_cast)), msg_cast,
                        pk_voter, false) /* invalid voter signature */ ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, Msg_DBB_Cast_Error(~ec, 'failed signature')) ]

/*
  This rule handles the error case where the VoterAuthorization in the
  cast message differs from the one in the ballot submission entry it
  references.
 */
rule BallotCast_DBB_ReceiveCastBallot_MismatchedAuthorization [role="DBB"]:
  let auth_data_cast = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts_cast)
      signed_voter_auth_cast = <auth_data_cast, sig_auth_cast>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth_cast)
      signed_msg_cast = <msg_cast, sig_cast>
      msg_submit = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth_submit)
      signed_msg_submit = <msg_submit, sig_submit>
      sub_bb_entry = BBEntry_Ballot_Submission(~ec, ts_sub, signed_msg_submit) in
    [ !EASPublicKey(~ec, pk_eas),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, tracker, sub_bb_entry, prev_unused),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_MismatchedAuthorization_Trace(~ec, ~va_id, pseudo, msg_cast),
      NoPreviousCast(pseudo),
      MostRecentBallot(~bbid, pseudo, tracker),
      SignatureVerified(sig_auth_cast, e1_sig(sig_auth_cast), pk(e3_sig(sig_auth_cast)),
                        auth_data_cast, pk_eas, true), /* valid EAS authorization signature */
      SignatureVerified(sig_cast, e1_sig(sig_cast), pk(e3_sig(sig_cast)), msg_cast,
                        pk_voter, true), /* valid voter signature */
      /* the error condition: authorization tokens don't match */
      Neq(signed_voter_auth_cast, signed_voter_auth_submit) ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id,
        Msg_DBB_Cast_Error(~ec, 'submission and cast authorizations do not match')) ]

/*
  This rule handles the error case when the EAS signature on the voter
  authorization embedded in the cast message is invalid.
 */
rule BallotCast_DBB_ReceiveCastBallot_FailedAuthSignature [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sig_cast> in
    [ !EASPublicKey(~ec, pk_eas),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_Unauthorized_Trace(~ec, ~va_id, msg_cast),
      DBB_Cast_Error_Trace(~ec, ~va_id),
      SignatureVerified(sig_auth, e1_sig(sig_auth), pk(e3_sig(sig_auth)), auth_data,
                        pk_eas, false) /* invalid EAS authorization signature */ ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id, Msg_DBB_Cast_Error(~ec, 'unauthorized voter')) ]

/*
  This rule handles the error case when the pseudonym has previously
  cast a ballot (we simply use the existing persistent fact).
 */
rule BallotCast_DBB_ReceiveCastBallot_PreviouslyCast [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sig_cast> in
    [ !DBB_Cast_Ballot(~some_ec, ~some_va_id, ~some_cid, pseudo, some_tracker, some_msg_submit, some_msg_cast),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_PreviouslyCast_Trace(~ec, ~va_id, msg_cast),
      DBB_Cast_Error_Trace(~ec, ~va_id) ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id,
        Msg_DBB_Cast_Error(~ec, 'voter previously cast a ballot')) ]

/*
  This rule handles the error case when the bulletin board entry for
  the submission that the cast request refers to does not exist.
 */
rule BallotCast_DBB_ReceiveCastBallot_NonexistentSubmission [role="DBB"]:
  let auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_cast = Msg_VA_Cast_Ballot(~ec, tracker, signed_voter_auth)
      signed_msg_cast = <msg_cast, sig_cast> in
    [ !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      SecureReceive(~cid, ~va_id, <~ec, 'DBB'>, signed_msg_cast) ]
  --[ DBB_ReceiveCastBallot_NonexistentSubmission_Trace(~ec, ~va_id, msg_cast),
      /* need this restriction to avoid conflict with the previous rule */
      NoPreviousCast(pseudo),
      NoBBEntry(~bbid, tracker),
      DBB_Cast_Error_Trace(~ec, ~va_id) ]->
    [ SecureSend(~cid, <~ec, 'DBB'>, ~va_id,
        Msg_DBB_Cast_Error(~ec, 'voter attempted to cast nonexistent ballot')) ]

/*
  This rule publishes the cast ballot to the bulletin board as a single
  entry. It needs to be a separate rule (as does the one that checks
  to make sure it was published) because of the way the bulletin board
  works in Tamarin (we have to guess which entry is the current tip and
  if it isn't, the append will fail).

  The `bb_entry_cast` content (containing fresh `~ts`) is stored in state so
  the Confirm rule can discover the assigned cast `eid` by content-matching.
 */
rule BallotCast_DBB_AppendCastBallot [role="DBB"]:
  let bb_entry_cast = BBEntry_Ballot_Cast(~ec, ~ts, signed_msg_submit, signed_msg_cast) in
    [ !DBB_Cast_Ballot(~ec, ~va_id, ~cid, pseudo, tracker, signed_msg_submit, signed_msg_cast),
      Fr(~ts),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, prev_eid, e_unused, prev_prev_unused) ]
  --[ DBB_AppendCastBallot_Trace(~ec, ~va_id, signed_msg_submit, signed_msg_cast, ~bbid, prev_eid),
      Unique(<'DBB_AppendCastBallot', signed_msg_submit, signed_msg_cast, prev_eid>),
      AtMostOneCastPerPseudonym(~bbid, pseudo) ]->
    [ BB_Append_Request(~bbid, bb_entry_cast, prev_eid),
      DBB_State_ConfirmCastPosting(~ec, ~va_id, ~cid, pseudo, tracker, bb_entry_cast) ]

/*
  This rule waits for a cast ballot to be successfully posted to the
  bulletin board, then sends an appropriate message back to the VA.
  The `cast_tracker` (`eid`) is discovered by content-matching `bb_entry_cast`
  against `!BB_Entry` — unique because `bb_entry_cast` contains fresh `~ts`.

  Note that this _must_ succeed for some `cast_tracker`, for any successful
  ballot cast, because there is no way in Tamarin for the bulletin board
  to fail.
 */
rule BallotCast_DBB_ConfirmCastPosting [role="DBB"]:
  let msg_cast_confirmation = Msg_DBB_Cast_Confirmation(~ec, sub_tracker, ~cast_tracker) in
    [ DBB_State_ConfirmCastPosting(~ec, ~va_id, ~cid, pseudo, sub_tracker, bb_entry_cast),
      !BB_Root(~ec, ~bbid, r_unused, root_eid_unused),
      !BB_Entry(~bbid, ~cast_tracker, bb_entry_cast, prev_unused) ]
  --[ DBB_ConfirmCastPosting_Trace(~ec, ~va_id, bb_entry_cast, ~bbid, ~cast_tracker) ]->
    [ !DBB_Posted_Cast(pseudo, bb_entry_cast, ~cast_tracker),
      SecureSend(~cid, <~ec, 'DBB'>, ~va_id, msg_cast_confirmation) ]
