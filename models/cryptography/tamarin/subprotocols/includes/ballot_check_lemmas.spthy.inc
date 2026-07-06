/* Lemmas for ballot check protocol. */

dnl
dnl We only include the sources lemma in the standalone version, as
dnl the necessary sources lemma is different for composed versions.
dnl
ifdef(<!STANDALONE!>, <!
/* Sources */

/*
  This lemma says that incoming secure channel messages have
  to come from the secure channel rule. It is odd that this
  is necessary as that rule is the only source for the
  relevant fact.

  Tamarin requires a proof script for this lemma; it is easy to prove
  interactively but it gets stuck when attempting to prove it automatically.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/Sources_BallotCheck.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_BallotCheck_Sources [sources]:
  "
      (
        All m1 m2 m3 m4 #i.
              IN_SECURE_RECEIVE(m1, m2, m3, m4)@i
          ==>
              Ex #j.
              (
                  SecureChannel_In(m1, m2, m3, m4)@j
                &
                  #j < #i
              )
      )
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl
!>, <!!>)
/* Protocol Safety Lemmas */

/*
  TO DO (time permitting)
 */

/* Protocol Executability Lemmas

   Note that these are verified without reusing any lemmas that Tamarin
   cannot verify automatically or that do not have proof scripts.
 */

/*
  This lemma states that it is possible for the DBB to receive a mock ballot.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_Mock_Ballot_Submission.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_Mock_Ballot_Submission:
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
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for the DBB to append a mock ballot.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_Mock_Ballot_Append.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_Mock_Ballot_Append:
  exists-trace
  "
    Ex ec va_id bs V msg bbid prev_eid #i #t_bs #t_v.
      DBB_AppendSubmittedBallot_Trace(ec, va_id, msg, bbid, prev_eid)@i
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
  This lemma states that it is possible for the DBB to confirm a mock ballot
  was posted.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_Mock_Ballot_Confirm.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_Mock_Ballot_Confirm:
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
  This lemma states that it is possible for the VA to initiate a
  ballot check.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_VA_Initiate_Check.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_VA_Initiate_Check:
  exists-trace
  "
    Ex ec va_id bs V p b c r t #i #t_bs #t_v.
      VA_CheckBallot_Trace(ec, va_id, p, b, c, r, t)@i
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
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
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
  This lemma states that it is possible for the BCA to request the randomizers
  from the DBB.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_BCA_Request_Randomizers.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_BCA_Request_Randomizers:
  exists-trace
  "
    Ex ec bca_id bs V t #i #t_bs #t_v.
      BCA_InitiateBallotCheck_Trace(ec, bca_id, t)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #r. Reveal(A, 'SecureChannel')@r)
    &
      /* bound ballot submission to the named election */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
        ==>
          ec_t = ec)
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
  This lemma states that it is possible for the DBB to receive the randomizer
  request from the BCA and forward it to the VA.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_DBB_Request_Randomizers.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_DBB_Request_Randomizers:
  exists-trace
  "
    Ex ec va_id bca_id bs V m #i #t_bs #t_v.
      DBB_ReceiveCheckRequest_Trace(ec, va_id, bca_id, m)@i
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
  This lemma states that it is possible for the VA to receive the randomizer
  request from the DBB and respond to it.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_VA_Send_Randomizers.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_VA_Send_Randomizers:
  exists-trace
  "
    Ex ec va_id bs V p b c r t pk #i #t_bs #t_v.
      VA_RequestRandomizers_Trace(ec, va_id, p, b, c, r, t, pk)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #tt.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@tt
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
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
  This lemma states that it is possible for the DBB to receive the randomizers
  from the VA and forward them.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_DBB_Forward_Randomizers.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_DBB_Forward_Randomizers:
  exists-trace
  "
    Ex ec va_id bca_id bs V m #i #t_bs #t_v.
      DBB_ForwardRandomizers_Trace(ec, va_id, bca_id, m)@i
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
  This lemma states that it is possible for the BCA to receive the randomizers
  and decrypt the ballot with them.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_BCA_Receive_Randomizers.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_BCA_Receive_Randomizers:
  exists-trace
  "
    Ex ec bca_id bs V t r #i #t_bs #t_v.
      BCA_ReceiveRandomizers_Trace(ec, bca_id, t, r)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
    &
      /* bound ballot submission to the named election */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
        ==>
          ec_t = ec)
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
  This lemma states that it is possible for the VA to "OK" a ballot check.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_VA_Result_OK.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_VA_Result_OK:
  exists-trace
  "
    Ex ec va_id bs V p b c r t pk #i #t_bs #t_v.
      VA_CheckResult_OK_Trace(ec, va_id, p, b, c, r, t, pk)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #tt.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@tt
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
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
  This lemma states that it is possible for the VA to "Not OK" a ballot check.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/BallotCheck_VA_Result_Not_OK.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_BallotCheck_VA_Result_Not_OK:
  exists-trace
  "
    Ex ec va_id bs V p b c r t pk #i #t_bs #t_v.
      VA_CheckResult_NotOK_Trace(ec, va_id, p, b, c, r, t, pk)@i
    &
      /* restrict to honest execution (no secure channel compromise) */
      not (Ex A #rr. Reveal(A, 'SecureChannel')@rr)
    &
      /* bound voter authentication sessions to the named VA */
      (All ec_t va_id_t v_t sk_t #tt.
          Voter_Authentication_Trace(ec_t, va_id_t, v_t, sk_t)@tt
        ==>
          va_id_t = va_id)
    &
      /* bound ballot submission append to the named VA */
      (All ec_t va_id_t msg_t bbid_t prev_eid_t #tt.
          DBB_AppendSubmittedBallot_Trace(ec_t, va_id_t, msg_t, bbid_t, prev_eid_t)@tt
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
