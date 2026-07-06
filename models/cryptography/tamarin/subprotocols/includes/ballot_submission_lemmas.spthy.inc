/* Lemmas for ballot submission protocol. */

dnl
dnl We only include the sources lemma in the standalone version, as
dnl the necessary sources lemma is different for composed versions.
dnl
ifdef(<!STANDALONE!>, <!
/* No Sources Lemma Necessary (Yet) */
!>, <!!>)
/* Protocol Safety Lemmas */

/* TO DO (time permitting) */

/* Protocol Executability Lemmas

   Note that these are verified without reusing any lemmas that Tamarin
   cannot verify automatically or that do not have proof scripts.
*/

/*
  This lemma states that it is possible for a voting application to reach a
  state where a voter has submitted a ballot to the DBB.
 */
lemma Executability_BallotSubmission_Ballot_Submitted [heuristic=o "../oracle.py"]:
  exists-trace
  "
      Ex ec va_id V pseudo sk_voter ballot_style ballot cryptograms r #i.
        VA_PresentBallot_Trace(ec, va_id, V, pseudo, sk_voter, ballot_style, ballot, cryptograms, r)@i
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
        /* bound election setup to exactly one ballot style */
        (All ec_t bs_t #t.
            BallotStyle_Trace(ec_t, bs_t)@t
          ==>
            ec_t = ec & bs_t = ballot_style)
      &
        /* bound election setup to exactly one eligible voter */
        (All ec_t v_t bs_t #t.
            EligibleVoter_Trace(ec_t, v_t, bs_t)@t
          ==>
            ec_t = ec & v_t = V)
  "

/*
  This lemma states that it is possible for the DBB to receive a submitted
  ballot.
 */
lemma Executability_BallotSubmission_Ballot_Received [heuristic=o "../oracle.py"]:
  exists-trace
  "
      Ex ec va_id bs V msg #i #t_bs #t_v.
        DBB_ReceiveSubmittedBallot_Trace(ec, va_id, msg)@i
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

/*
  This lemma states that it is possible for the DBB to append a submitted
  ballot to the bulletin board.
 */
lemma Executability_BallotSubmission_Ballot_Posted [heuristic=o "../oracle.py"]:
  exists-trace
  "
      Ex ec va_id bs V msg bbid tracker #i #t_bs #t_v.
        DBB_ConfirmBallotPosting_Trace(ec, va_id, msg, bbid, tracker)@i
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

/*
  This lemma states that it is possible for a voting application to reach a
  state where a voter has received a tracker for a submitted ballot.
 */
lemma Executability_BallotSubmission_Tracker_Received [heuristic=o "../oracle.py"]:
  exists-trace
  "
      Ex ec va_id V pseudo sk_voter ballot_style ballot cryptograms r tracker #i.
        VA_BallotTracker_Trace(ec, va_id, V, pseudo, sk_voter, ballot_style, ballot, cryptograms, r, tracker)@i
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
            ec_t = ec & bs_t = ballot_style)
      &
        /* bound election setup to exactly one eligible voter */
        (All ec_t v_t bs_t #t.
            EligibleVoter_Trace(ec_t, v_t, bs_t)@t
          ==>
            ec_t = ec & v_t = V)
  "

/*
  This lemma states that it is possible for more than one voting application to
  reach a state where a voter has received a tracker for a submitted ballot in
  the same election, where the voters are different.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotSubmission_Multiple_Trackers_Received.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotSubmission_Multiple_Trackers_Received:
  exists-trace
  "
      Ex ec va_id1 va_id2 V1 V2 pseudo1 pseudo2 sk_voter1 sk_voter2
         ballot_style1 ballot_style2 ballot1 ballot2
         cryptograms1 cryptograms2 r1 r2 tracker1 tracker2 #i1 #i2.
          VA_BallotTracker_Trace(ec, va_id1, V1, pseudo1, sk_voter1, ballot_style1, ballot1, cryptograms1, r1, tracker1)@i1
        &
          VA_BallotTracker_Trace(ec, va_id2, V2, pseudo2, sk_voter2, ballot_style2, ballot2, cryptograms2, r2, tracker2)@i2
        &
          not (#i1 = #i2)
        &
          not (va_id1 = va_id2)
        &
          not (pseudo1 = pseudo2)
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
          /* bound election setup to exactly one ballot style per voter */
          (All ec_t bs_t #t.
              BallotStyle_Trace(ec_t, bs_t)@t
            ==>
              ec_t = ec & (bs_t = ballot_style1 | bs_t = ballot_style2))
        &
          /* bound election setup to exactly the two named eligible voters */
          (All ec_t v_t bs_t #t.
              EligibleVoter_Trace(ec_t, v_t, bs_t)@t
            ==>
              ec_t = ec & (v_t = V1 | v_t = V2))
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl
