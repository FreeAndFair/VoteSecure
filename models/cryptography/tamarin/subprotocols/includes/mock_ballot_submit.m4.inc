dnl
dnl This is the m4 input file for mocking ballot submission.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
include(common/voter_authorization.m4.inc)

/*
  Message definitions from ballot submission protocol.
 */
macros:
  Msg_VA_Submit_Ballot(ec_hash, cryptograms, signed_voter_auth) = <'VA_Submit_Ballot', ec_hash, cryptograms, signed_voter_auth>,
  Msg_DBB_Ballot_Tracker(ec_hash, tracker) = <'DBB_Ballot_Tracker', ec_hash, tracker>,
  BBEntry_Ballot_Submission(ec_hash, timestamp, ballot_msg) = <'BBEntry_Ballot_Submission', ec_hash, timestamp, ballot_msg>

/*
  Mock a ballot submission (step 1). This creates the persistent and
  linear facts that correspond to a ballot submission by the VA, and
  attempts to have the DBB accept that ballot and put it on the bulletin
  board.

  Note that this is triggered by the linear `VA_State_PresentBallot` fact;
  it can thus be re-triggered if that fact is re-established (e.g., if
  the voter decides to submit a new ballot), though this should not
  occur in this protocol in isolation.
 */
rule Mock_Ballot_Submission [role="Mock"]:
  let cryptograms = <ny_encrypt_c1(~ballot, pk_election, ~r), ny_encrypt_c2(~ballot, pk_election, ~r), ny_encrypt_p(~ballot, pk_election, ~r)>
      msg_submit_ballot = Msg_VA_Submit_Ballot(~ec, cryptograms, signed_voter_auth)
      signed_msg_submit_ballot = <msg_submit_ballot, sign(msg_submit_ballot, '1', ~sk_voter)> in
    [ VA_State_PresentBallot(~ec, ~va_id, $V, ~sk_voter),
      !ElectionPublicKey(~ec, pk_election),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs, signed_voter_auth),
      Fr(~ballot),
      Fr(~r),
      Fr(~cid) /* unused here but used in submission protocol */ ]
  --[ DBB_ReceiveSubmittedBallot_Trace(~ec, ~va_id, msg_submit_ballot) ]->
    [ !DBB_Submitted_Ballot(~ec, ~va_id, ~cid, pseudo, signed_msg_submit_ballot),
      !Mock_Submitted_Ballot(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, signed_msg_submit_ballot) ]

/*
  Mock a ballot submission (step 2). This publishes the ballot to the
  bulletin board, and needs to be its own rule because of how the
  bulletin board works in Tamarin (we have to pick some element of
  the bulletin board to append to and if it isn't the last one, the
  append fails). This rule is restricted to run only when the ballot
  has not been successfully appended to the bulletin board, and to
  run at most once for each board index.

  The `bb_entry` content (containing fresh `~ts`) is stored in state so
  the Confirm rule can discover the assigned `eid` by content-matching.
 */
rule Mock_AppendSubmittedBallot [role="Mock"]:
  let bb_entry = BBEntry_Ballot_Submission(~ec, ~ts, signed_msg_submit_ballot) in
    [ !DBB_Submitted_Ballot(~ec, ~va_id, ~cid, pseudo, signed_msg_submit_ballot),
      !Mock_Submitted_Ballot(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, signed_msg_submit_ballot),
      Fr(~ts),
      !BB_Root(~ec, bbid, r_unused, root_eid_unused),
      !BB_Entry(bbid, prev_eid, e_unused, prev_prev_unused) ]
  --[ DBB_AppendSubmittedBallot_Trace(~ec, ~va_id, signed_msg_submit_ballot, bbid, prev_eid),
      Unique(<'Mock_AppendSubmittedBallot', signed_msg_submit_ballot, prev_eid>),
      SubmissionNotOnBB(bbid, signed_msg_submit_ballot) ]->
    [ BB_Append_Request(bbid, bb_entry, prev_eid),
      DBB_State_ConfirmBallotPosting(~ec, ~va_id, ~cid, pseudo, bb_entry) ]

/*
  Mock a ballot submission (step 3). This checks that the ballot has been
  published and establishes the persistent and linear facts that simulate
  such publication having been confirmed to the VA, putting the VA into the
  "cast or check" state. The tracker (`eid`) is discovered by content-matching
  `bb_entry` against `!BB_Entry`, then stored for downstream use.
 */
rule Mock_ConfirmBallotPosting [role="Mock"]:
  let bb_entry = BBEntry_Ballot_Submission(~ec, ts, signed_msg_submit_ballot) in
    [ DBB_State_ConfirmBallotPosting(~ec, ~va_id, ~cid, pseudo, bb_entry),
      !Mock_Submitted_Ballot(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, signed_msg_submit_ballot),
      !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs, signed_voter_auth_unused),
      !BB_Root(~ec, bbid, r_unused, root_eid_unused),
      !BB_Entry(bbid, ~tracker, bb_entry, prev_unused) ]
  --[ DBB_ConfirmBallotPosting_Trace(~ec, ~va_id, bb_entry, bbid, ~tracker),
      VA_BallotTracker_Trace(~ec, ~va_id, $V, pseudo, ~sk_voter, ~bs, ~ballot, cryptograms, ~r, ~tracker) ]->
    [ !VA_Submitted_Ballot(~ec, ~va_id, ~ballot, cryptograms, ~r, ~tracker),
      VA_State_CheckOrCast(~ec, ~va_id, $V, ~ballot, cryptograms, ~r, ~tracker) ]
