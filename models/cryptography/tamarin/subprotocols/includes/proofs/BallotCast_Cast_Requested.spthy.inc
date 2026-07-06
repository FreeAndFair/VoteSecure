simplify
solve( !BB_Root( ~ec, bbid, r_unused, root_eid_unused ) ▶₃ #i )
  case BulletinBoard_Create
  solve( !BB_Entry( ~bbid, ~tracker,
                    <'BBEntry_Ballot_Submission', ~ec, ts, signed_msg_submit_ballot>,
                    prev_unused
         ) ▶₄ #i )
    case BulletinBoard_Append
    solve( BB_Append_Request( ~bbid,
                              <'BBEntry_Ballot_Submission', ~ec, ts, signed_msg_submit_ballot>,
                              prev_unused
           ) ▶₂ #vr.6 )
      case Mock_AppendSubmittedBallot_case_1
      solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.6 )
        case BulletinBoard_Create
        solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudo, ~sk_voter.1, ~bs,
                                   signed_voter_auth_unused
               ) ▶₂ #i )
          case Mock_Voter_Authentication
          solve( VA_State_CheckOrCast( ~ec, ~va_id, $V.1, ~ballot.1, cryptograms,
                                       ~r.1, ~tracker
                 ) ▶₀ #j )
            case Mock_ConfirmBallotPosting
            solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudonym($V), ~sk_voter.1,
                                       ~bs_unused, signed_voter_auth
                   ) ▶₁ #j )
              case Mock_Voter_Authentication
              solve( DBB_State_ConfirmBallotPosting( ~ec, ~va_id, ~cid, pseudonym($V),
                                                     <'BBEntry_Ballot_Submission', ~ec, ~ts,
                                                      <'VA_Submit_Ballot', ~ec,
                                                       <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                        ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                        ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                       <'VoterAuthorization', ~ec, pseudonym($V),
                                                        pk(~sk_voter), ~bs, ~ts.1>,
                                                       sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                             pk(~sk_voter), ~bs, ~ts.1>,
                                                            '1', ~sk_eas)
                                                      >,
                                                      sign(<'VA_Submit_Ballot', ~ec,
                                                            <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                             ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                             ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                            <'VoterAuthorization', ~ec, pseudonym($V),
                                                             pk(~sk_voter), ~bs, ~ts.1>,
                                                            sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                                  pk(~sk_voter), ~bs, ~ts.1>,
                                                                 '1', ~sk_eas)
                                                           >,
                                                           '1', ~sk_voter)
                                                     >
                     ) ▶₀ #i )
                case Mock_AppendSubmittedBallot
                SOLVED // trace found
              qed
            qed
          qed
        qed
      qed
    qed
  qed
qed
