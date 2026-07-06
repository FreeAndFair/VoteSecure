simplify
solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₂ #i )
  case BulletinBoard_Create
  solve( !BB_Entry( ~bbid, sub_tracker, sub_bb_entry_unused,
                    prev_sub_unused
         ) ▶₃ #i )
    case BulletinBoard_Append
    solve( !BB_Entry( ~bbid, cast_tracker,
                      <'BBEntry_Ballot_Cast', ts_cast,
                       <<'VA_Submit_Ballot', ~ec, cryptograms, signed_voter_auth>,
                        sign(<'VA_Submit_Ballot', ~ec, cryptograms, signed_voter_auth>, '1',
                             ~sk_voter)
                       >,
                       <'VA_Cast_Ballot', ~ec, tracker, signed_voter_auth>,
                       sign(<'VA_Cast_Ballot', ~ec, tracker, signed_voter_auth>, '1', ~sk_voter)
                      >,
                      prev_cast_unused
           ) ▶₄ #i )
      case BulletinBoard_Append
      solve( BB_Append_Request( ~bbid, sub_bb_entry_unused, prev_sub_unused
             ) ▶₂ #vr.4 )
        case Mock_AppendSubmittedBallot_case_1
        solve( BB_Append_Request( ~bbid,
                                  <'BBEntry_Ballot_Cast', ts_cast,
                                   <<'VA_Submit_Ballot', ~ec, cryptograms, signed_voter_auth>,
                                    sign(<'VA_Submit_Ballot', ~ec, cryptograms, signed_voter_auth>, '1',
                                         ~sk_voter)
                                   >,
                                   <'VA_Cast_Ballot', ~ec, tracker, signed_voter_auth>,
                                   sign(<'VA_Cast_Ballot', ~ec, tracker, signed_voter_auth>, '1', ~sk_voter)
                                  >,
                                  prev_cast_unused
               ) ▶₂ #vr.5 )
          case BallotCast_DBB_AppendCastBallot
          solve( BB_Trace_Entry( ~bbid, ~new_eid.2,
                                 <'BBEntry_Ballot_Submission', ~ec, ts_sub,
                                  <'VA_Submit_Ballot', ~ec, cryptograms,
                                   <'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style, ts>,
                                   sign(<'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style, ts>,
                                        x, ~sk_eas)
                                  >,
                                  sign(<'VA_Submit_Ballot', ~ec, cryptograms,
                                        <'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style, ts>,
                                        sign(<'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style, ts
                                             >,
                                             x, ~sk_eas)
                                       >,
                                       '1', ~sk_voter)
                                 >,
                                 prev_unused
                 ) @ #vr.12 )
            case BulletinBoard_Append
            solve( BB_Append_Request( ~bbid, e_unused, prev_prev_unused ) ▶₂ #vr.11 )
              case Mock_AppendSubmittedBallot_case_1
              solve( BB_Append_Request( ~bbid,
                                        <'BBEntry_Ballot_Submission', ~ec, ts_sub,
                                         <'VA_Submit_Ballot', ~ec, cryptograms,
                                          <'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style, ts>,
                                          sign(<'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style,
                                                ts>,
                                               x, ~sk_eas)
                                         >,
                                         sign(<'VA_Submit_Ballot', ~ec, cryptograms,
                                               <'VoterAuthorization', ~ec, pseudo.1, pk_voter, ballot_style,
                                                ts>,
                                               sign(<'VoterAuthorization', ~ec, pseudo.1, pk_voter,
                                                     ballot_style, ts>,
                                                    x, ~sk_eas)
                                              >,
                                              '1', ~sk_voter)
                                        >,
                                        prev_unused
                     ) ▶₂ #vr.11 )
                case Mock_AppendSubmittedBallot_case_1
                solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.4 )
                  case BulletinBoard_Create
                  solve( BB_Current( ~bbid, ~new_eid ) ▶₁ #vr.5 )
                    case BulletinBoard_Append
                    solve( VA_State_BallotCastResponse( ~ec, ~va_id, ~cid, pseudo, ~ballot,
                                                        <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r),
                                                         ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r),
                                                         ny_encrypt_p(~ballot.1, pk(~sk_election), ~r)>,
                                                        ~r.1, ~new_eid
                           ) ▶₀ #i )
                      case BallotCast_VA_Cast
                      solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudonym($V), ~sk_voter,
                                                 ~bs_unused,
                                                 <
                                                  <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                   ~ballot_style, ~ts>,
                                                  sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                        pk(~sk_voter), ~ballot_style, ~ts>,
                                                       '1', ~sk_eas)
                                                 >
                             ) ▶₁ #i )
                        case Mock_Voter_Authentication
                        solve( SecureReceive( ~cid, <~ec, 'DBB'>, ~va_id,
                                              <'DBB_Cast_Confirmation', ~ec, ~new_eid, ~new_eid.1>
                               ) ▶₅ #i )
                          case SecureChannel_Receive_case_1
                          solve( SecureReceive( ~cid, ~va_id, <~ec, 'DBB'>,
                                                <
                                                 <'VA_Cast_Ballot', ~ec, ~new_eid,
                                                  <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                   ~ballot_style, ~ts>,
                                                  sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                        pk(~sk_voter), ~ballot_style, ~ts>,
                                                       '1', ~sk_eas)
                                                 >,
                                                 sign(<'VA_Cast_Ballot', ~ec, ~new_eid,
                                                       <'VoterAuthorization', ~ec, pseudonym($V),
                                                        pk(~sk_voter), ~ballot_style, ~ts>,
                                                       sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                             pk(~sk_voter), ~ballot_style, ~ts>,
                                                            '1', ~sk_eas)
                                                      >,
                                                      '1', ~sk_voter)
                                                >
                                 ) ▶₃ #vr.10 )
                            case SecureChannel_Receive_case_1
                            SOLVED // trace found
                          qed
                        qed
                      qed
                    qed
                  qed
                qed
              qed
            qed
          qed
        qed
      qed
    qed
  qed
qed
