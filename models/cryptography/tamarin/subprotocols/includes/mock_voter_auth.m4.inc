dnl
dnl This is the m4 input file for mocking voter authentication.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
include(common/voter_authorization.m4.inc)

/*
  Mock a voter authentication. This creates the persistent facts that
  authorize a voter with a particular public key to vote a ballot of a
  particular ballot style, embedding the signed `VoterAuthorization` token
  in the VA's state so it can be carried in later ballot submission and
  cast messages.
 */
rule Mock_Voter_Authentication [role="Mock"]:
  let pk_voter = pk(~sk_voter)
      pseudo = pseudonym($V)
      auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ~bs, ~ts)
      signed_voter_auth = <auth_data, sign(auth_data, '1', ~sk_eas)> in
    [ !BallotStyle(~ec, ~bs),
      !EligibleVoter(~ec, $V, ~bs),
      !EASSecretKey(~ec, ~sk_eas),
      Fr(~sk_voter),
      Fr(~va_id),
      Fr(~ts) ]
  --[ HonestSignatureKey(pk_voter),
      Voter_Authentication_Trace(~ec, ~va_id, $V, ~sk_voter) ]->
    [ !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ~bs, signed_voter_auth),
      VA_State_PresentBallot(~ec, ~va_id, $V, ~sk_voter) ]

/*
  This rule has `BB_Terminate_Request` on its right-hand side, so
  that we don't get a well-formedness warning when we don't use it.
  Note that we are requesting to terminate a bulletin board that
  doesn't actually exist, so this has no real effect on anything.
 */
rule Mock_BBTerminate [role="Mock"]:
    []
  --[ Unique('BallotSubmission_Mock_BB_Terminate') ]->
    [ BB_Terminate_Request('fake_bbid', 'fake_eid') ]
