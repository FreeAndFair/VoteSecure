dnl
dnl Restrictions shared by the various ballot handling subprotocols.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
ifelse(eval(!defined_bool(<!INCLUDED_NO_PREVIOUS_CAST!>) && defined_bool(<!USE_NO_PREVIOUS_CAST!>)), eval(1), <!
define(<!INCLUDED_NO_PREVIOUS_CAST!>)dnl
/*
  This restriction states that a particular pseudonym has not previously
  cast a ballot.
 */
restriction NoPreviousCast:
  "
    All pseudo #i.
          NoPreviousCast(pseudo)@i
      ==>
          not (Ex ec va_id m #j.
            (
                DBB_ReceiveCastBallot_Trace(ec, va_id, pseudo, m)@j
              &
                #j < #i
            )
          )
  "
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_MOST_RECENT_BALLOT!>) && defined_bool(<!USE_MOST_RECENT_BALLOT!>)), eval(1), <!
define(<!INCLUDED_MOST_RECENT_BALLOT!>)dnl
/*
  This restriction states that the ballot with entry id `sub_eid` is the
  most recent one submitted for a particular pseudonym `pseudo` on bulletin
  board `bbid`. The submission message inner pattern reflects the
  `VoterAuthorization` structure embedded within it; only `pseudo` needs to be
  bound, so the other fields are wildcarded.

  "Most recent" is expressed using trace ordering: the entry for `sub_eid`
  must exist, and no other submission for `pseudo` on the same board may
  appear later in the trace (chain order = trace order by `Safety_BB_Linear`).
 */
restriction MostRecentBallot:
  "
    All bbid pseudo sub_eid #i.
          MostRecentBallot(bbid, pseudo, sub_eid)@i
      ==>
            (Ex ec ts c auth_ts pk bs auth_sig sig prev #j.
                BB_Trace_Entry(bbid, sub_eid,
                               <'BBEntry_Ballot_Submission', ec, ts,
                                <<'VA_Submit_Ballot', ec, c,
                                  <<'VoterAuthorization', ec, pseudo, pk, bs, auth_ts>,
                                    auth_sig>>,
                                 sig>>,
                               prev)@j
              &
                #j < #i
            )
          &
            not (Ex ec2 ts2 c2 auth_ts2 pk2 bs2 auth_sig2 sig2 prev2
                    ec3 ts3 c3 auth_ts3 pk3 bs3 auth_sig3 sig3 prev3
                    eid2 #j1 #j2.
                   BB_Trace_Entry(bbid, sub_eid,
                                  <'BBEntry_Ballot_Submission', ec2, ts2,
                                   <<'VA_Submit_Ballot', ec2, c2,
                                     <<'VoterAuthorization', ec2, pseudo, pk2, bs2, auth_ts2>,
                                       auth_sig2>>,
                                    sig2>>,
                                  prev2)@j1
                 & BB_Trace_Entry(bbid, eid2,
                                  <'BBEntry_Ballot_Submission', ec3, ts3,
                                   <<'VA_Submit_Ballot', ec3, c3,
                                     <<'VoterAuthorization', ec3, pseudo, pk3, bs3, auth_ts3>,
                                       auth_sig3>>,
                                    sig3>>,
                                  prev3)@j2
                 & not (eid2 = sub_eid)
                 & #j1 < #j2
                 & #j2 < #i
            )
  "
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_SUBMISSION_NOT_ON_BB!>) && defined_bool(<!USE_SUBMISSION_NOT_ON_BB!>)), eval(1), <!
define(<!INCLUDED_SUBMISSION_NOT_ON_BB!>)dnl
/*
  This restriction prevents the same signed ballot message from being
  appended to a bulletin board as a ballot submission entry more than once.
  Firing `SubmissionNotOnBB(bbid, msg)` as an action fact asserts that
  `msg` has not previously appeared as the content of a
  `BBEntry_Ballot_Submission` entry on board `bbid`.
 */
restriction SubmissionNotOnBB:
  "
    All bbid msg #i.
          SubmissionNotOnBB(bbid, msg)@i
      ==>
          not (
            Ex ec ts eid prev #j.
            (
                BB_Trace_Entry(bbid, eid,
                               <'BBEntry_Ballot_Submission', ec, ts, msg>,
                               prev)@j
              &
                #j < #i
            )
          )
  "
!>, <!!>)dnl
dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_AT_MOST_ONE_CAST_PER_PSEUDONYM!>) && defined_bool(<!USE_AT_MOST_ONE_CAST_PER_PSEUDONYM!>)), eval(1), <!
define(<!INCLUDED_AT_MOST_ONE_CAST_PER_PSEUDONYM!>)dnl
/*
  This restriction enforces that a voter identified by pseudonym `pseudo`
  can append at most one cast ballot entry to bulletin board `bbid`.
  Firing `AtMostOneCastPerPseudonym(bbid, pseudo)` as an action fact
  asserts that no earlier instance of that same action exists for the same
  `(bbid, pseudo)` pair; if all rules that append cast ballot entries to the
  bulletin board have this restriction as an action fact, only one ballot
  ballot can be cast per `(bbid, pseudo)` pair.

  Note that this does not actually check the contents of the bulletin board;
  it functions effectively as a `Unique` fact, but specifically for ballot
  casting. This is significantly more efficient for Tamarin than modeling
  an actual check of the pseudonyms of every ballot cast on the bulletin
  board.
 */
restriction AtMostOneCastPerPseudonym:
  "
    All bbid pseudo #i.
          AtMostOneCastPerPseudonym(bbid, pseudo)@i
      ==>
          not (Ex #j. AtMostOneCastPerPseudonym(bbid, pseudo)@j & #j < #i)
  "
!>, <!!>)dnl
dnl
