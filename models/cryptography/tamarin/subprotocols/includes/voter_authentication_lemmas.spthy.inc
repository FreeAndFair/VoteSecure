/* Lemmas for voter authentication protocol. */

dnl
dnl We only include the sources lemma in the standalone version, as
dnl the necessary sources lemma is different for composed versions.
dnl
ifdef(<!STANDALONE!>, <!
/* Sources Lemma */

/*
  Essentially, this lemma says "if a secure receive action happens,
  it must be preceded by a secure channel generating the corresponding
  linear fact."
 */
lemma Sources_VoterAuthentication [sources, heuristic=o "../oracle.py"]:
  "
    All cid S R m #i.
          IN_SECURE_RECEIVE(cid, S, R, m)@i
      ==>
          (Ex #j. SecureChannel_In(cid, S, R, m)@j & #j < #i)
  "
!>, <!!>)
/*
  These predicates state that values are distinct from each other.
 */
predicates:
      All3Distinct(t1, t2, t3)
  <=>
      not (t1 = t2 | t1 = t3 | t2 = t3),

      All6Distinct(t1, t2, t3, t4, t5, t6)
  <=>
      not (
          t1 = t2 | t1 = t3 | t1 = t4 | t1 = t5 | t1 = t6
        |
          t2 = t3 | t2 = t4 | t2 = t5 | t2 = t6
        |
          t3 = t4 | t3 = t5 | t3 = t6
        |
          t4 = t5 | t4 = t6
        |
          t5 = t6
      )

/* Protocol Safety Lemmas */

/*
  Each VA session processes the voter authentication session token at most
  once: the `VA_State_ReceiveAuthenticationSession` linear fact can only be
  consumed once per `~va_id` (produced fresh by `VA_Initialize`).  Used as a
  fast stepping-stone for `Helper_VA_Unique_Auth_Complete`.
 */
lemma Helper_VA_Unique_Auth_Session [reuse]:
  "
    All ec va_id tok1 tok2 #i1 #i2.
            VA_ReceiveAuthenticationSession_Trace(ec, va_id, tok1)@i1
          &
            VA_ReceiveAuthenticationSession_Trace(ec, va_id, tok2)@i2
      ==>
          #i1 = #i2 & tok1 = tok2
  "

/*
  Each VA session completes the voter authentication exchange at most once:
  the `VA_State_ReceiveAuthenticationComplete` linear fact can only be
  consumed once per `~va_id`.  Used as a fast stepping-stone for
  `Safety_VoterAuthentication_One_Outcome_Per_VA_Session`.
 */
lemma Helper_VA_Unique_Auth_Complete [reuse]:
  "
    All ec va_id tok1 tok2 #i1 #i2.
            VA_ReceiveAuthenticationComplete_Trace(ec, va_id, tok1)@i1
          &
            VA_ReceiveAuthenticationComplete_Trace(ec, va_id, tok2)@i2
      ==>
          #i1 = #i2 & tok1 = tok2
  "

/*
  This lemma states that any given voting application session can have only
  one result.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Safety_One_Outcome_Per_VA_Session.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Safety_VoterAuthentication_One_Outcome_Per_VA_Session [reuse]:
  "
    All ec va_id res1 res2 pseudo1 pseudo2 pk1 pk2 bs1 bs2 #i1 #i2.
            VA_ReceiveAuthenticationResult_Trace(ec, va_id, res1, pseudo1, pk1, bs1)@i1
          &
            VA_ReceiveAuthenticationResult_Trace(ec, va_id, res2, pseudo2, pk2, bs2)@i2
      ==>
          res1 = res2 & pseudo1 = pseudo2 & pk1 = pk2 & bs1 = bs2 & #i1 = #i2
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/* Protocol Executability Lemmas

   Note that these are verified without reusing any lemmas that Tamarin
   cannot verify automatically or that do not have proof scripts, so
   they are all valid despite some of the safety lemmas not having been
   verified.
*/

/*
  This lemma states that it is possible for a voting application to reach a
  state where a voter has successfully authenticated and been matched to a
  pseudonym and ballot style. Note that we significantly curtail the search
  space by eliminating the possibility of adversary action and restricting
  it to a single election configuration, a single authentication session,
  and a single voting application.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Successful_Eligible.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_VoterAuthentication_Successful_Eligible:
  exists-trace
  "
      Ex ec va_id session_id pseudo pk_voter ballot_style v #i #j #k.
        AS_ReportAuthenticationResult_Trace(session_id, 'successful')@i
      &
        EAS_ReceiveAuthenticationResult_Trace(session_id, v, pseudo, ballot_style)@j
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id, 'eligible', pseudo, pk_voter, ballot_style)@k
      &
        #i < #j & #j < #k
      &
        /* restrict to a single election to reduce search space */
        (
          All ec_t1 ec_t2 #t1 #t2.
                  Finalize_Election_Setup_Trace(ec_t1)@t1
                &
                  Finalize_Election_Setup_Trace(ec_t2)@t2
            ==>
                ec_t1 = ec_t2 & #t1 = #t2
        )
      &
        /* restrict to a single auth session to reduce search space */
        (
          All s_t1 s_t2 t_t1 t_t2 #t1 #t2.
                  AS_AuthenticationRequest_Trace(s_t1, t_t1)@t1
                &
                  AS_AuthenticationRequest_Trace(s_t2, t_t2)@t2
            ==>
                s_t1 = s_t2 & t_t1 = t_t2 & #t1 = #t2
        )
      &
        /* restrict to a single VA to reduce search space */
        (
          All ec_t va_id_t pk_voter_t v #t.
                VA_Initialize_Trace(ec_t, va_id_t, pk_voter_t, v)@t
            ==>
                ec_t = ec & va_id_t = va_id & pk_voter_t = pk_voter
        )
      &
        /* prevent message injection to reduce search space */
        not (Ex m #t. SecureChannel_InjectedMessage(m)@t)
      &
        /* prevent message interception to reduce search space */
        not (Ex m #t. SecureChannel_InterceptedMessage(m)@t)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for a voting application to reach a
  state where a voter has successfully authenticated but is not eligible to
  vote in the election. Note that we significantly curtail the search
  space by eliminating the possibility of adversary action and restricting
  it to a single election configuration, a single authentication session,
  and a single voting application.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Successful_Ineligible.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_VoterAuthentication_Successful_Ineligible:
  exists-trace
  "
      Ex ec va_id session_id pk_voter v #i #j #k.
        AS_ReportAuthenticationResult_Trace(session_id, 'successful')@i
      &
        EAS_ReceiveAuthenticationResult_Trace(session_id, v, 'ineligible', 'ineligible')@j
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id, 'ineligible', 'ineligible', pk_voter, 'ineligible')@k
      &
        #i < #j & #j < #k
      &
        /* restrict to a single election to reduce search space */
        (
          All ec_t1 ec_t2 #t1 #t2.
                  Finalize_Election_Setup_Trace(ec_t1)@t1
                &
                  Finalize_Election_Setup_Trace(ec_t2)@t2
            ==>
                ec_t1 = ec_t2 & #t1 = #t2
        )
      &
        /* restrict to a single auth session to reduce search space */
        (
          All s_t1 s_t2 t_t1 t_t2 #t1 #t2.
                  AS_AuthenticationRequest_Trace(s_t1, t_t1)@t1
                &
                  AS_AuthenticationRequest_Trace(s_t2, t_t2)@t2
            ==>
                s_t1 = s_t2 & t_t1 = t_t2 & #t1 = #t2
        )
      &
        /* restrict to a single VA to reduce search space */
        (
          All ec_t va_id_t pk_voter_t v #t.
                VA_Initialize_Trace(ec_t, va_id_t, pk_voter_t, v)@t
            ==>
                ec_t = ec & va_id_t = va_id & pk_voter_t = pk_voter
        )
      &
        /* prevent message injection to reduce search space */
        not (Ex m #t. SecureChannel_InjectedMessage(m)@t)
      &
        /* prevent message interception to reduce search space */
        not (Ex m #t. SecureChannel_InterceptedMessage(m)@t)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for a voting application to reach a
  state where a voter has unsuccessfully authenticated. Note that we
  significantly curtail the search space by eliminating the possibility of
  adversary action and restricting it to a single election configuration,
  a single authentication session, and a single voting application.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Unsuccessful.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_VoterAuthentication_Unsuccessful:
  exists-trace
  "
    Ex ec session_id va_id pk_voter #i #j #k.
        AS_ReportAuthenticationResult_Trace(session_id, 'unsuccessful')@i
      &
        EAS_ReceiveAuthenticationResult_Trace(session_id, 'unsuccessful', 'ineligible', 'ineligible')@j
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id, 'unsuccessful', 'ineligible', pk_voter, 'ineligible')@k
      &
        #i < #j & #j < #k
      &
        /* restrict to a single election to reduce search space */
        (
          All ec_t1 ec_t2 #t1 #t2.
                  Finalize_Election_Setup_Trace(ec_t1)@t1
                &
                  Finalize_Election_Setup_Trace(ec_t2)@t2
            ==>
                ec_t1 = ec_t2 & #t1 = #t2
        )
      &
        /* restrict to a single auth session to reduce search space */
        (
          All s_t1 s_t2 t_t1 t_t2 #t1 #t2.
                  AS_AuthenticationRequest_Trace(s_t1, t_t1)@t1
                &
                  AS_AuthenticationRequest_Trace(s_t2, t_t2)@t2
            ==>
                s_t1 = s_t2 & t_t1 = t_t2 & #t1 = #t2
        )
      &
        /* restrict to a single VA to reduce search space */
        (
          All ec_t va_id_t pk_voter_t v #t.
                VA_Initialize_Trace(ec_t, va_id_t, pk_voter_t, v)@t
            ==>
                ec_t = ec & va_id_t = va_id & pk_voter_t = pk_voter
        )
      &
        /* prevent message injection to reduce search space */
        not (Ex m #t. SecureChannel_InjectedMessage(m)@t)
      &
        /* prevent message interception to reduce search space */
        not (Ex m #t. SecureChannel_InterceptedMessage(m)@t)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for voting applications to reach
  states where voters have successfully authenticated (eligible and ineligible)
  and unsuccessfully authenticated for (at least) one distinct voter of each
  result.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Three.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_VoterAuthentication_Three:
  exists-trace
  "
    Ex ec va_id_se va_id_si va_id_u pseudo pk_se pk_si pk_u bs1
       s_se s_si s_u v_se v_si
       #i_se #i_si #i_u #j_se #j_si #j_u #k_se #k_si #k_u.
        AS_ReportAuthenticationResult_Trace(s_se, 'successful')@i_se
      &
        AS_ReportAuthenticationResult_Trace(s_si, 'successful')@i_si
      &
        AS_ReportAuthenticationResult_Trace(s_u, 'unsuccessful')@i_u
      &
        EAS_ReceiveAuthenticationResult_Trace(s_se, v_se, pseudo, bs1)@j_se
      &
        EAS_ReceiveAuthenticationResult_Trace(s_si, v_si, 'ineligible', 'ineligible')@j_si
      &
        EAS_ReceiveAuthenticationResult_Trace(s_u, 'unsuccessful', 'ineligible', 'ineligible')@j_u
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_se, 'eligible', pseudo, pk_se, bs1)@k_se
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_si, 'ineligible', 'ineligible', pk_si, 'ineligible')@k_si
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_u, 'unsuccessful', 'ineligible', pk_u, 'ineligible')@k_u
      &
        #i_se < #j_se & #j_se < #k_se
      &
        #i_si < #j_si & #j_si < #k_si
      &
        #i_u < #j_u & #j_u < #k_u
      &
        All3Distinct(s_se, s_si, s_u)
      &
        All3Distinct(va_id_se, va_id_si, va_id_u)
      &
        All3Distinct(pk_se, pk_si, pk_u)
      &
        All3Distinct(#i_se, #i_si, #i_u)
      &
        /* restrict to a single election to reduce search space */
        (
          All ec_j #j.
                Finalize_Election_Setup_Trace(ec_j)@j
            ==>
                ec_j = ec
        )
      &
        /* prevent message injection to reduce search space */
        not (Ex m #t. SecureChannel_InjectedMessage(m)@t)
      &
        /* prevent message interception to reduce search space */
        not (Ex m #t. SecureChannel_InterceptedMessage(m)@t)
      &
        /* bound auth sessions to exactly the three named ones */
        (All s_t t_t #t.
              AS_AuthenticationRequest_Trace(s_t, t_t)@t
          ==>
              s_t = s_se | s_t = s_si | s_t = s_u)
      &
        /* bound VA instances to exactly the three named ones */
        (All ec_t va_id_t pk_t v #t.
              VA_Initialize_Trace(ec_t, va_id_t, pk_t, v)@t
          ==>
              va_id_t = va_id_se | va_id_t = va_id_si | va_id_t = va_id_u)
      &
        /* fix canonical session ordering to eliminate AS-event permutation case-splits */
        #i_se < #i_si & #i_si < #i_u
      &
        /* fix canonical VA-receive ordering to match */
        #k_se < #k_si & #k_si < #k_u
      &
        /* restrict to a single ballot style to reduce search space */
        (All ec_t bs_t #t.
              BallotStyle_Trace(ec_t, bs_t)@t
          ==>
              ec_t = ec & bs_t = bs1)
      &
        /* restrict to a single eligible voter to reduce search space */
        (All ec_t v_t bs_t #t.
              EligibleVoter_Trace(ec_t, v_t, bs_t)@t
          ==>
              ec_t = ec & v_t = v_se)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible for voting applications to reach
  states where voters have successfully authenticated (eligible and ineligible)
  and unsuccessfully authenticated for (at least) two distinct voters of each
  result.

  Tamarin can prove this lemma automatically but takes considerable time;
  a proof script is included.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_Six.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_VoterAuthentication_Six:
  exists-trace
  "
    Ex ec va_id_se1 va_id_se2 va_id_si1 va_id_si2 va_id_u1 va_id_u2
       pseudo1 pseudo2 pk_se1 pk_se2 pk_si1 pk_si2 pk_u1 pk_u2 bs1 bs2
       s_se1 s_se2 s_si1 s_si2 s_u1 s_u2
       v_se1 v_se2 v_si1 v_si2
       #i_se1 #i_se2 #i_si1 #i_si2 #i_u1 #i_u2
       #j_se1 #j_se2 #j_si1 #j_si2 #j_u1 #j_u2
       #k_se1 #k_se2 #k_si1 #k_si2 #k_u1 #k_u2
       #t_sa_se1 #t_sa_se2 #t_sa_si1 #t_sa_si2 #t_ua_u1 #t_ua_u2.
        AS_ReportAuthenticationResult_Trace(s_se1, 'successful')@i_se1
      &
        AS_ReportAuthenticationResult_Trace(s_se2, 'successful')@i_se2
      &
        AS_ReportAuthenticationResult_Trace(s_si1, 'successful')@i_si1
      &
        AS_ReportAuthenticationResult_Trace(s_si2, 'successful')@i_si2
      &
        AS_ReportAuthenticationResult_Trace(s_u1, 'unsuccessful')@i_u1
      &
        AS_ReportAuthenticationResult_Trace(s_u2, 'unsuccessful')@i_u2
      &
        EAS_ReceiveAuthenticationResult_Trace(s_se1, v_se1, pseudo1, bs1)@j_se1
      &
        EAS_ReceiveAuthenticationResult_Trace(s_se2, v_se2, pseudo2, bs2)@j_se2
      &
        EAS_ReceiveAuthenticationResult_Trace(s_si1, v_si1, 'ineligible', 'ineligible')@j_si1
      &
        EAS_ReceiveAuthenticationResult_Trace(s_si2, v_si2, 'ineligible', 'ineligible')@j_si2
      &
        EAS_ReceiveAuthenticationResult_Trace(s_u1, 'unsuccessful', 'ineligible', 'ineligible')@j_u1
      &
        EAS_ReceiveAuthenticationResult_Trace(s_u2, 'unsuccessful', 'ineligible', 'ineligible')@j_u2
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_se1, 'eligible', pseudo1, pk_se1, bs1)@k_se1
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_se2, 'eligible', pseudo2, pk_se2, bs2)@k_se2
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_si1, 'ineligible', 'ineligible', pk_si1, 'ineligible')@k_si1
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_si2, 'ineligible', 'ineligible', pk_si2, 'ineligible')@k_si2
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_u1, 'unsuccessful', 'ineligible', pk_u1, 'ineligible')@k_u1
      &
        VA_ReceiveAuthenticationResult_Trace(ec, va_id_u2, 'unsuccessful', 'ineligible', pk_u2, 'ineligible')@k_u2
      &
        #i_se1 < #j_se1 & #j_se1 < #k_se1
      &
        #i_se2 < #j_se2 & #j_se2 < #k_se2
      &
        #i_si1 < #j_si1 & #j_si1 < #k_si1
      &
        #i_si2 < #j_si2 & #j_si2 < #k_si2
      &
        #i_u1 < #j_u1 & #j_u1 < #k_u1
      &
        #i_u2 < #j_u2 & #j_u2 < #k_u2
      &
        All6Distinct(s_se1, s_se2, s_si1, s_si2, s_u1, s_u2)
      &
        All6Distinct(va_id_se1, va_id_se2, va_id_si1, va_id_si2, va_id_u1, va_id_u2)
      &
        All6Distinct(pk_se1, pk_se2, pk_si1, pk_si2, pk_u1, pk_u2)
      &
        All6Distinct(#i_se1, #i_se2, #i_si1, #i_si2, #i_u1, #i_u2)
      &
        /* restrict to a single election to reduce search space */
        (
          All ec_j #j.
                Finalize_Election_Setup_Trace(ec_j)@j
            ==>
                ec_j = ec
        )
      &
        /* prevent message injection to reduce search space */
        not (Ex m #t. SecureChannel_InjectedMessage(m)@t)
      &
        /* prevent message interception to reduce search space */
        not (Ex m #t. SecureChannel_InterceptedMessage(m)@t)
      &
        /* bound auth sessions to exactly the six named ones */
        (All s_t t_t #t.
              AS_AuthenticationRequest_Trace(s_t, t_t)@t
          ==>
              s_t = s_se1 | s_t = s_se2 | s_t = s_si1 |
              s_t = s_si2 | s_t = s_u1  | s_t = s_u2)
      &
        /* bound VA instances to exactly the six named ones */
        (All ec_t va_id_t pk_t v #t.
              VA_Initialize_Trace(ec_t, va_id_t, pk_t, v)@t
          ==>
              va_id_t = va_id_se1 | va_id_t = va_id_se2 | va_id_t = va_id_si1 |
              va_id_t = va_id_si2 | va_id_t = va_id_u1  | va_id_t = va_id_u2)
      &
        /* fix canonical session ordering: eligible, ineligible, unsuccessful, repeat */
        #i_se1 < #i_si1 & #i_si1 < #i_u1 & #i_u1 < #i_se2 & #i_se2 < #i_si2 & #i_si2 < #i_u2
      &
        /* fix canonical VA-receive ordering to match */
        #k_se1 < #k_si1 & #k_si1 < #k_u1 & #k_u1 < #k_se2 & #k_se2 < #k_si2 & #k_si2 < #k_u2
      &
        /* pin AS authentication events to resolve `AS_State_AwaitAuthentication` ambiguity */
        AS_SuccessfulAuthentication_Trace(s_se1)@t_sa_se1
      &
        AS_SuccessfulAuthentication_Trace(s_si1)@t_sa_si1
      &
        AS_UnsuccessfulAuthentication_Trace(s_u1)@t_ua_u1
      &
        AS_SuccessfulAuthentication_Trace(s_se2)@t_sa_se2
      &
        AS_SuccessfulAuthentication_Trace(s_si2)@t_sa_si2
      &
        AS_UnsuccessfulAuthentication_Trace(s_u2)@t_ua_u2
      &
        #t_sa_se1 < #t_sa_si1 & #t_sa_si1 < #t_ua_u1 & #t_ua_u1 < #t_sa_se2 & #t_sa_se2 < #t_sa_si2 & #t_sa_si2 < #t_ua_u2
      &
        /* restrict to two ballot styles to reduce search space */
        (All ec_t bs_t #t.
              BallotStyle_Trace(ec_t, bs_t)@t
          ==>
              ec_t = ec & (bs_t = bs1 | bs_t = bs2))
      &
        /* restrict to two eligible voters to reduce search space */
        (All ec_t v_t bs_t #t.
              EligibleVoter_Trace(ec_t, v_t, bs_t)@t
          ==>
              ec_t = ec & (v_t = v_se1 | v_t = v_se2))
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl

/*
  This lemma states that it is possible to detect a protocol error where an
  incomplete authentication result is requested.

  The required trace involves an adversary who (1) intercepts the EAS-to-VA
  authentication-session message, thereby learning the token, voter public key,
  and channel ID, and (2) injects a fake VA-to-EAS authentication-complete
  message using the learned values. The AS never sees the voter authenticate,
  so it reports incomplete when the EAS requests the result.
 */
define(<!PROOF_SCRIPT!>, ifdef(<!INCLUDE_PROOF_SCRIPTS!>, ifdef(<!STANDALONE!>, <!subprotocols/includes/proofs/VoterAuthentication_EAS_Authentication_Incomplete.spthy.inc!>, <!/tmp/NOPROOFSCRIPT!>), <!/tmp/NOPROOFSCRIPT!>))dnl
syscmd(cat PROOF_SCRIPT > /dev/null 2>&1)dnl
lemma ifelse(sysval, <!0!>, <!ProofScript!>, <!NoProofScript!>)_Executability_EAS_Authentication_Incomplete_Error:
  exists-trace
  "
    Ex s ec va_id cid_int m_int m_inj pk_voter token
       #t_eas_session #t_intercept #t_inject #t_eas_cmplt #t_incomplete #i.
        EAS_ReceiveAuthenticationResult_Trace(s, 'incomplete', 'ineligible', 'ineligible')@i
      &
        /* EAS receives auth session from AS and sends it to VA (this is what gets intercepted) */
        EAS_ReceiveAuthenticationSession_Trace(va_id, pk_voter, s, token)@t_eas_session
      &
        /* adversary intercepts EAS-to-VA auth session (learns token, pk_voter, channel ID) */
        SecureChannel_Intercepted(cid_int, <ec, 'EAS'>, va_id, m_int)@t_intercept
      &
        /* adversary re-uses that channel ID to inject a fake auth-complete */
        SecureChannel_Injected(cid_int, va_id, <ec, 'EAS'>, m_inj)@t_inject
      &
        /* EAS processes the injected auth-complete and requests a result from AS */
        EAS_ReceiveAuthenticationComplete_Trace(va_id, pk_voter, s, token)@t_eas_cmplt
      &
        /* AS reports incomplete (never saw the voter authenticate) */
        AS_ReportIncompleteAuthenticationResult_Trace(s)@t_incomplete
      &
        #t_eas_session < #t_intercept & #t_intercept < #t_inject & #t_inject < #t_eas_cmplt
      &
        #t_eas_cmplt < #t_incomplete & #t_incomplete < #i
      &
        /* authentication never completes — AS only sees the incomplete session */
        not (Ex s2 #j. AS_SuccessfulAuthentication_Trace(s2)@j)
      &
        not (Ex s2 #j. AS_UnsuccessfulAuthentication_Trace(s2)@j)
      &
        /* restrict to a single election, VA instance, and AS session */
        (All ec_j #j. Finalize_Election_Setup_Trace(ec_j)@j ==> ec_j = ec)
      &
        (All ec_t va_id_t pk_t v #t.
              VA_Initialize_Trace(ec_t, va_id_t, pk_t, v)@t
          ==>
              va_id_t = va_id)
      &
        (All s_t t_t #t. AS_AuthenticationRequest_Trace(s_t, t_t)@t ==> s_t = s)
  "
dnl Include the proof script, if one exists.
sinclude(PROOF_SCRIPT)dnl
