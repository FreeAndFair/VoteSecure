/* Lemmas for ballot cast protocol. */

dnl
dnl We only include the sources lemma in the standalone version, as
dnl the necessary sources lemma is different for composed versions.
dnl
ifdef(<!STANDALONE!>, <!
/* No Sources Lemma Necessary (Yet) */
!>, <!!>)
/* Protocol Safety Lemmas */

/*
  TO DO (time permitting)

  Obvious ones are:
    - no pseudonym ever gets more than one cast vote onto the bulletin board
    - no cast vote is unauthorized
 */

/* Protocol Executability Lemmas

   Note that these are verified without reusing any lemmas that Tamarin
   cannot verify automatically or that do not have proof scripts.
 */

/*
  This lemma states that it is possible for the DBB to receive a mock ballot.
  Restricted to honest execution with a single VA session and ballot style to
  bound the search space.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Mock_Ballot_Submission.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Mock_Ballot_Submission:
  exists-trace
  "
    Ex ec va_id bs V msg #i #t_bs #t_v.
      DBB_ReceiveSubmittedBallot_Trace(ec, va_id, msg)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #r. Reveal(A, 'SecureChannel')@r)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #t.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
        ==>
          va_id_t = va_id)
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the DBB to append a mock ballot.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Mock_Ballot_Append.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Mock_Ballot_Append:
  exists-trace
  "
    Ex ec va_id bs V msg bbid prev_eid #i #t_bs #t_v.
      DBB_AppendSubmittedBallot_Trace(ec, va_id, msg, bbid, prev_eid)@i
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the DBB to confirm a mock ballot
  was posted.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Mock_Ballot_Confirm.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Mock_Ballot_Confirm:
  exists-trace
  "
    Ex ec va_id bs V msg bbid tracker #i #t_bs #t_v.
      DBB_ConfirmBallotPosting_Trace(ec, va_id, msg, bbid, tracker)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #r. Reveal(A, 'SecureChannel')@r)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #t.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for a voting application to reach
  a state where a voter has sent a valid cast request to the DBB.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Requested.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Requested:
  exists-trace
  "
    Ex ec va_id V pseudo sk_voter bs ballot cryptograms r tracker #i #j.
        VA_BallotTracker_Trace(ec, va_id, V, pseudo, sk_voter, bs, ballot, cryptograms, r, tracker)@i
      &
        VA_CastBallot_Trace(ec, va_id, pseudo, ballot, cryptograms, r, tracker)@j
      &
        /* restrict to honest execution (no secure channel compromise) */
        not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
      &
        /* bound voter authentication sessions to the named VA */
        (All ec_t va_id_t v_t sk_t #t.
            Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
          ==>
            va_id_t = va_id)
      &
        /* bound ballot submission append to the named VA */
        (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
            DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id)
      &
        /* bound election setup to exactly one ballot style */
        (All ec_t bs_t #t.
            BallotStyle_Trace(ec_t, bs_t)@t
          ==>
            ec_t = ec & bs_t = bs)
      &
        /* bound election setup to exactly one eligible voter */
        (All ec_t v_t bs_t #t.
            EligibleVoter_Trace(ec_t, v_t, bs_t)@t
          ==>
            ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the DBB to receive a cast
  request.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Received.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Received:
  exists-trace
  "
    Ex ec va_id bs V pseudo msg #i #t_bs #t_v.
      DBB_ReceiveCastBallot_Trace(ec, va_id, pseudo, msg)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #r. Reveal(A, 'SecureChannel')@r)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #t.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the DBB to post a cast
  request to the bulletin board.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Posted.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Posted:
  exists-trace
  "
    Ex ec va_id bs V bbe_c bbid cast_tracker #i #t_bs #t_v.
      DBB_ConfirmCastPosting_Trace(ec, va_id, bbe_c, bbid, cast_tracker)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #r. Reveal(A, 'SecureChannel')@r)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #t.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot cast append to the named VA */
      (All ec_t va_id_t msg1_t msg2_t bbid_t prev_eid_t #t.
          DBB_AppendCastBallot_Trace(ec_t, va_id_t, msg1_t, msg2_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the VA to receive a
  cast confirmation from the DBB.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Confirm.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Confirm:
  exists-trace
  "
    Ex ec va_id bs V pseudo ballot cryptograms r sub_tracker cast_tracker #i #t_bs #t_v.
      VA_CastConfirmation_Trace(ec, va_id, pseudo, ballot, cryptograms, r, sub_tracker, cast_tracker)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #t.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound ballot cast append to the named VA */
      (All ec_t va_id_t msg1_t msg2_t bbid_t prev_eid_t #t.
          DBB_AppendCastBallot_Trace(ec_t, va_id_t, msg1_t, msg2_t, bbid_t, prev_eid_t)@t
        ==>
          va_id_t = va_id)
    &
      /* bound cast confirmations to the named event */
      (All ec_t va_id_t pseudo_t ballot_t cryptograms_t r_t sub_t cast_t #t.
          VA_CastConfirmation_Trace(ec_t, va_id_t, pseudo_t, ballot_t, cryptograms_t, r_t, sub_t, cast_t)@t
        ==>
          #t = #i & ec_t = ec & va_id_t = va_id)
    &
      BallotStyle_Trace(ec, bs)@t_bs
    &
      EligibleVoter_Trace(ec, V, bs)@t_v
    &
      /* restrict to a single ballot style to reduce search space */
      (All ec_t bs_t #t.
          BallotStyle_Trace(ec_t, bs_t)@t
        ==>
          ec_t = ec & bs_t = bs)
    &
      /* restrict to a single eligible voter to reduce search space */
      (All ec_t v_t bs_t #t.
          EligibleVoter_Trace(ec_t, v_t, bs_t)@t
        ==>
          ec_t = ec & v_t = V)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for two VAs to each receive a cast
  confirmation from the DBB, for different voters in the same election, when
  both voters submit before either casts, and voter 1 casts before voter 2.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Confirm_Multiple_Concurrent.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Confirm_Multiple_Concurrent:
  exists-trace
  "
    Ex ec va_id1 va_id2 pseudo1 pseudo2 ballot1 ballot2
       cryptograms1 cryptograms2 r1 r2 sub_tracker1 sub_tracker2
       cast_tracker1 cast_tracker2 #i1 #i2.
        VA_CastConfirmation_Trace(ec, va_id1, pseudo1, ballot1, cryptograms1, r1, sub_tracker1, cast_tracker1)@i1
      &
        VA_CastConfirmation_Trace(ec, va_id2, pseudo2, ballot2, cryptograms2, r2, sub_tracker2, cast_tracker2)@i2
      &
        not (va_id1 = va_id2)
      &
        not (pseudo1 = pseudo2)
      &
        not (sub_tracker1 = sub_tracker2)
      &
        not (cast_tracker1 = cast_tracker2)
      &
        /* restrict to honest execution (no secure channel compromise) */
        not (Ex A #r. Reveal(A, 'SecureChannel')@r)
      &
        /* bound voter authentication sessions to exactly the two named VAs */
        (All ec_t va_id_t v_t sk_t #t.
            Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot submission appends to exactly the two named VAs */
        (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
            DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot cast appends to exactly the two named VAs */
        (All ec_t va_id_t msg1_t msg2_t bbid_t prev_eid_t #t.
            DBB_AppendCastBallot_Trace(ec_t, va_id_t, msg1_t, msg2_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound cast confirmations to exactly the two named events */
        (All ec_t va_id_t pseudo_t ballot_t cryptograms_t r_t sub_t cast_t #t.
            VA_CastConfirmation_Trace(ec_t, va_id_t, pseudo_t, ballot_t, cryptograms_t, r_t, sub_t, cast_t)@t
          ==>
            (#t = #i1 & ec_t = ec & va_id_t = va_id1) |
            (#t = #i2 & ec_t = ec & va_id_t = va_id2))
      &
        /* pin BB ordering: root → `sub_tracker1` → `sub_tracker2` → `cast_tracker1` → `cast_tracker2` */
        (Ex bbid root_eid root_msg #t_root #t_adv1 #t_adv2 #t_adv3 #t_adv4.
              BB_Trace_Entry(bbid, root_eid, root_msg, 'root')@t_root
            & BB_Advance(bbid, root_eid, sub_tracker1)@t_adv1
            & BB_Advance(bbid, sub_tracker1, sub_tracker2)@t_adv2
            & BB_Advance(bbid, sub_tracker2, cast_tracker1)@t_adv3
            & BB_Advance(bbid, cast_tracker1, cast_tracker2)@t_adv4)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for two VAs to each receive a cast
  confirmation from the DBB, for different voters in the same election, when
  both voters submit before either casts, but voter 2 casts before voter 1
  (i.e., cast order is reversed relative to submission order).

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Confirm_Multiple_Concurrent_Reversed.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Confirm_Multiple_Concurrent_Reversed:
  exists-trace
  "
    Ex ec va_id1 va_id2 pseudo1 pseudo2 ballot1 ballot2
       cryptograms1 cryptograms2 r1 r2 sub_tracker1 sub_tracker2
       cast_tracker1 cast_tracker2 #i1 #i2.
        VA_CastConfirmation_Trace(ec, va_id1, pseudo1, ballot1, cryptograms1, r1, sub_tracker1, cast_tracker1)@i1
      &
        VA_CastConfirmation_Trace(ec, va_id2, pseudo2, ballot2, cryptograms2, r2, sub_tracker2, cast_tracker2)@i2
      &
        not (va_id1 = va_id2)
      &
        not (pseudo1 = pseudo2)
      &
        not (sub_tracker1 = sub_tracker2)
      &
        not (cast_tracker1 = cast_tracker2)
      &
        /* restrict to honest execution (no secure channel compromise) */
        not (Ex A #r. Reveal(A, 'SecureChannel')@r)
      &
        /* bound voter authentication sessions to exactly the two named VAs */
        (All ec_t va_id_t v_t sk_t #t.
            Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot submission appends to exactly the two named VAs */
        (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
            DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot cast appends to exactly the two named VAs
           (voter 2 casts before voter 1) */
        (All ec_t va_id_t msg1_t msg2_t bbid_t prev_eid_t #t.
            DBB_AppendCastBallot_Trace(ec_t, va_id_t, msg1_t, msg2_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound cast confirmations to exactly the two named events */
        (All ec_t va_id_t pseudo_t ballot_t cryptograms_t r_t sub_t cast_t #t.
            VA_CastConfirmation_Trace(ec_t, va_id_t, pseudo_t, ballot_t, cryptograms_t, r_t, sub_t, cast_t)@t
          ==>
            (#t = #i1 & ec_t = ec & va_id_t = va_id1) |
            (#t = #i2 & ec_t = ec & va_id_t = va_id2))
      &
        /* enforce that voter 2 casts before voter 1 */
        #i2 < #i1
      &
        /* pin BB ordering: root → `sub_tracker1` → `sub_tracker2` → `cast_tracker2` → `cast_tracker1` */
        (Ex bbid root_eid root_msg #t_root #t_adv1 #t_adv2 #t_adv3 #t_adv4.
              BB_Trace_Entry(bbid, root_eid, root_msg, 'root')@t_root
            & BB_Advance(bbid, root_eid, sub_tracker1)@t_adv1
            & BB_Advance(bbid, sub_tracker1, sub_tracker2)@t_adv2
            & BB_Advance(bbid, sub_tracker2, cast_tracker2)@t_adv3
            & BB_Advance(bbid, cast_tracker2, cast_tracker1)@t_adv4)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for two VAs to each receive a cast
  confirmation from the DBB, for different voters in the same election, when
  voter 1 submits and casts entirely before voter 2 submits (sequential flows).

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCast_Cast_Confirm_Multiple_Sequential.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCast_Cast_Confirm_Multiple_Sequential:
  exists-trace
  "
    Ex ec va_id1 va_id2 pseudo1 pseudo2 ballot1 ballot2
       cryptograms1 cryptograms2 r1 r2 sub_tracker1 sub_tracker2
       cast_tracker1 cast_tracker2 #i1 #i2.
        VA_CastConfirmation_Trace(ec, va_id1, pseudo1, ballot1, cryptograms1, r1, sub_tracker1, cast_tracker1)@i1
      &
        VA_CastConfirmation_Trace(ec, va_id2, pseudo2, ballot2, cryptograms2, r2, sub_tracker2, cast_tracker2)@i2
      &
        not (va_id1 = va_id2)
      &
        not (pseudo1 = pseudo2)
      &
        not (sub_tracker1 = sub_tracker2)
      &
        not (cast_tracker1 = cast_tracker2)
      &
        /* restrict to honest execution (no secure channel compromise) */
        not (Ex A #r. Reveal(A, 'SecureChannel')@r)
      &
        /* bound voter authentication sessions to exactly the two named VAs */
        (All ec_t va_id_t v_t sk_t #t.
            Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot submission appends to exactly the two named VAs */
        (All ec_t va_id_t msg_t bbid_t prev_eid_t #t.
            DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound ballot cast appends to exactly the two named VAs */
        (All ec_t va_id_t msg1_t msg2_t bbid_t prev_eid_t #t.
            DBB_AppendCastBallot_Trace(ec_t, va_id_t, msg1_t, msg2_t, bbid_t, prev_eid_t)@t
          ==>
            va_id_t = va_id1 | va_id_t = va_id2)
      &
        /* bound cast confirmations to exactly the two named events */
        (All ec_t va_id_t pseudo_t ballot_t cryptograms_t r_t sub_t cast_t #t.
            VA_CastConfirmation_Trace(ec_t, va_id_t, pseudo_t, ballot_t, cryptograms_t, r_t, sub_t, cast_t)@t
          ==>
            (#t = #i1 & ec_t = ec & va_id_t = va_id1) |
            (#t = #i2 & ec_t = ec & va_id_t = va_id2))
      &
        /* enforce that voter 1 completes entirely before voter 2 receives confirmation */
        #i1 < #i2
      &
        /* pin BB ordering: root → `sub_tracker1` → `cast_tracker1` → `sub_tracker2` → `cast_tracker2` */
        (Ex bbid root_eid root_msg #t_root #t_adv1 #t_adv2 #t_adv3 #t_adv4.
              BB_Trace_Entry(bbid, root_eid, root_msg, 'root')@t_root
            & BB_Advance(bbid, root_eid, sub_tracker1)@t_adv1
            & BB_Advance(bbid, sub_tracker1, cast_tracker1)@t_adv2
            & BB_Advance(bbid, cast_tracker1, sub_tracker2)@t_adv3
            & BB_Advance(bbid, sub_tracker2, cast_tracker2)@t_adv4)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl
