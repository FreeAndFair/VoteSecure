simplify
solve( VA_State_CheckOrCast( ~ec, ~va_id, $V, ~ballot, c, ~r, t ) ▶₀ #i )
  case Mock_ConfirmBallotPosting_case_1
  solve( BB_Append_Request( ~bbid,
                            <'BBEntry_Ballot_Submission', ~ec, ~ts,
                             <'VA_Submit_Ballot', ~ec,
                              <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                              <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                               ~ballot_style, ~ts.1>,
                              sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                    ~ballot_style, ~ts.1>,
                                   '1', ~sk_eas)
                             >,
                             sign(<'VA_Submit_Ballot', ~ec,
                                   <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                    ~ballot_style, ~ts.1>,
                                   sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                         ~ballot_style, ~ts.1>,
                                        '1', ~sk_eas)
                                  >,
                                  '1', ~sk_voter.1)
                            >,
                            prev_unused
         ) ▶₂ #vr.5 )
    case Mock_AppendSubmittedBallot
    solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.5 )
      case BulletinBoard_Create
      solve( !VA_Eligible_Voter( ~ec, ~va_id, p, ~sk_voter, ~bs_unused,
                                 signed_voter_auth_unused
             ) ▶₁ #i )
        case Mock_Voter_Authentication
        SOLVED // trace found
      qed
    qed
  qed
qed
